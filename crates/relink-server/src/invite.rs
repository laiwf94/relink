//! Invitations: how a person joins a workspace (migration 0009,
//! docs/DESIGN.md "Invitations").
//!
//! An admin or owner, signed in, invites someone by email address or by
//! member name with a role they manage ([`Role::manages`]): admins invite
//! editors and viewers, owners anyone. The answer carries a one-time link,
//! `/v1/invites/rli_<64 hex>`, shown only then; the database keeps only the
//! token's SHA-256. The link works until it expires (seven days unless the
//! inviter says otherwise, at most 30), is accepted or is revoked.
//!
//! Accepting needs more than the link: the person must be signed in and be
//! the one invited, with a verified email address equal to the invited one
//! or with exactly that member name, so a forwarded or leaked link is of no
//! use to anyone else. Acceptance locks the invitation row, so a link is
//! used at most once however many requests race for it.
//!
//! Creating, listing and revoking are tenant queries, kept inside the
//! workspace by row-level security. Accepting is not: the person is not a
//! member yet, and the token is what names the workspace. Every step that
//! changes something (create, accept, revoke) is in the workspace's audit
//! chain, in the same transaction as the change.
//!
//! Invitations are managed by people, not programs: the routes refuse API
//! keys, whose scopes cover links and statistics, not membership.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::api::{ApiError, StrictJson, json};
use crate::audit::{self, Action, Actor, Change};
use crate::auth::{Credential, Role, is_valid_owner, parse_duration};
use crate::quota::{MAX_PENDING_INVITATIONS, QuotaExceeded, QuotaKind};
use crate::server::App;
use crate::session::SessionAuthed;
use crate::store::{Db, DbError};
use crate::tenant::{Tenant, Workspace};
use crate::util::{hex_encode, secure_random};

/// Prefix of an invitation token.
pub const INVITE_PREFIX: &str = "rli_";

/// Where invitation links point; the token follows.
pub const INVITE_PATH: &str = "/v1/invites/";

/// Lifetime of an invitation when the inviter names none.
pub const DEFAULT_INVITE_TTL: Duration = Duration::from_secs(7 * 86_400);
/// Shortest lifetime an invitation may be given.
pub const MIN_INVITE_TTL: Duration = Duration::from_secs(5 * 60);
/// Longest lifetime an invitation may be given.
pub const MAX_INVITE_TTL: Duration = Duration::from_secs(30 * 86_400);

/// Most invitations `GET /v1/invitations` returns: every pending one (there
/// are at most [`MAX_PENDING_INVITATIONS`]), then the newest others.
pub const LIST_LIMIT: i64 = 200;

/// A new random invitation token: `rli_` and 256 bits in hex.
pub fn generate_invite_token() -> String {
    let mut b = [0u8; 32];
    secure_random(&mut b);
    format!("{INVITE_PREFIX}{}", hex_encode(&b))
}

/// Whether `token` has the shape of an invitation token.
pub fn is_well_formed_invite(token: &str) -> bool {
    token.len() == INVITE_PREFIX.len() + 64
        && token.starts_with(INVITE_PREFIX)
        && token[INVITE_PREFIX.len()..]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What the database stores of a token.
pub fn hash_invite(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// The request path as it may be logged: an invitation link's token is a
/// credential, so it is replaced by `{token}`.
pub fn loggable_path(path: &str) -> Cow<'_, str> {
    match path.strip_prefix(INVITE_PATH) {
        Some(rest) if !rest.is_empty() => {
            let tail = rest.find('/').map_or("", |i| &rest[i..]);
            Cow::Owned(format!("{INVITE_PATH}{{token}}{tail}"))
        }
        _ => Cow::Borrowed(path),
    }
}

/// Who an invitation is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invitee {
    /// Whoever signs in with this verified address (lower case).
    Email(String),
    /// The person with this member name.
    Member(String),
}

/// Checks and normalises an email address: one `@` with something on both
/// sides, a dot in the domain, no spaces or control characters, at most 320
/// bytes. Returned in lower case, which is how addresses are compared.
pub fn normalize_email(raw: &str) -> Result<String, String> {
    let e = raw.trim();
    let bad = || format!("{raw:?} is not an email address");
    if e.len() < 3 || e.len() > 320 {
        return Err(bad());
    }
    if e.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    let (local, domain) = e.split_once('@').ok_or_else(bad)?;
    if local.is_empty()
        || domain.contains('@')
        || domain.len() < 3
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(bad());
    }
    Ok(e.to_lowercase())
}

impl Invitee {
    /// Exactly one of an email address and a member name.
    pub fn parse(email: Option<&str>, member: Option<&str>) -> Result<Invitee, String> {
        match (email, member) {
            (Some(e), None) => normalize_email(e).map(Invitee::Email),
            (None, Some(m)) if is_valid_owner(m) => Ok(Invitee::Member(m.to_owned())),
            (None, Some(m)) => Err(format!(
                "{m:?} is not a member name (lower-case letters, digits, '.', '_' and '-', \
                 at most 63)"
            )),
            _ => Err("give exactly one of email and member".into()),
        }
    }

    /// Whether the signed-in person with `member` name and `email` (which
    /// their provider `verified` or not) is the one invited.
    pub fn is(&self, member: &str, email: Option<&str>, verified: bool) -> bool {
        match self {
            Invitee::Member(m) => m == member,
            Invitee::Email(want) => {
                verified && email.is_some_and(|got| got.trim().to_lowercase() == *want)
            }
        }
    }

    fn columns(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Invitee::Email(e) => (Some(e), None),
            Invitee::Member(m) => (None, Some(m)),
        }
    }
}

/// Parses an `expires_in` such as `7d` and checks it is within bounds.
pub fn parse_invite_ttl(raw: Option<&str>) -> Result<Duration, String> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_INVITE_TTL);
    };
    let ttl = parse_duration(raw)?;
    if !(MIN_INVITE_TTL..=MAX_INVITE_TTL).contains(&ttl) {
        return Err(format!(
            "expires_in must be between 5m and 30d, not {raw:?}"
        ));
    }
    Ok(ttl)
}

/// Where an invitation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Accepted => "accepted",
            Status::Revoked => "revoked",
            Status::Expired => "expired",
        }
    }
}

/// An invitation as stored, without its token hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Invitation {
    pub id: i64,
    pub workspace_id: i64,
    pub email: Option<String>,
    pub member: Option<String>,
    pub role: Role,
    pub invited_by: String,
    pub status: Status,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_member: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
}

impl Invitation {
    pub fn invitee(&self) -> Invitee {
        match (&self.email, &self.member) {
            (Some(e), _) => Invitee::Email(e.clone()),
            (None, Some(m)) => Invitee::Member(m.clone()),
            (None, None) => unreachable!("the table requires one of email and member"),
        }
    }
}

/// The columns [`row_to_invitation`] reads; `expired` is evaluated against
/// the database clock, the one acceptance uses.
macro_rules! cols {
    () => {
        "id, workspace_id, email, member, role, invited_by, created_at, expires_at, \
         accepted_at, accepted_member, revoked_at, revoked_by, (expires_at <= now()) AS expired"
    };
}

/// [`cols`] for queries that join, with the invitation aliased `i`.
macro_rules! icols {
    () => {
        "i.id, i.workspace_id, i.email, i.member, i.role, i.invited_by, i.created_at, \
         i.expires_at, i.accepted_at, i.accepted_member, i.revoked_at, i.revoked_by, \
         (i.expires_at <= now()) AS expired"
    };
}

fn row_to_invitation(r: &PgRow) -> Result<Invitation, sqlx::Error> {
    let role: String = r.try_get("role")?;
    let role = Role::parse(&role)
        .ok_or_else(|| sqlx::Error::Decode(format!("unknown role {role:?}").into()))?;
    let accepted_at: Option<DateTime<Utc>> = r.try_get("accepted_at")?;
    let revoked_at: Option<DateTime<Utc>> = r.try_get("revoked_at")?;
    let expired: bool = r.try_get("expired")?;
    let status = if accepted_at.is_some() {
        Status::Accepted
    } else if revoked_at.is_some() {
        Status::Revoked
    } else if expired {
        Status::Expired
    } else {
        Status::Pending
    };
    Ok(Invitation {
        id: r.try_get("id")?,
        workspace_id: r.try_get("workspace_id")?,
        email: r.try_get("email")?,
        member: r.try_get("member")?,
        role,
        invited_by: r.try_get("invited_by")?,
        status,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        accepted_at,
        accepted_member: r.try_get("accepted_member")?,
        revoked_at,
        revoked_by: r.try_get("revoked_by")?,
    })
}

/// An invitation as the audit log shows it; never its token.
pub fn invitation_state(i: &Invitation) -> Value {
    json!({
        "id": i.id,
        "email": i.email,
        "member": i.member,
        "role": i.role.as_str(),
        "invited_by": i.invited_by,
        "expires_at": i.expires_at,
        "status": i.status.as_str(),
        "accepted_member": i.accepted_member,
        "revoked_by": i.revoked_by,
    })
}

/// Why an invitation step was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteError {
    /// No such invitation (or token) in reach.
    NotFound,
    Expired,
    Accepted,
    Revoked,
    /// The signed-in person is not the one invited.
    NotInvitee(Invitee),
    /// The person is already a member, with this role.
    AlreadyMember(Role),
    /// Invited by a member name nobody has.
    NoSuchMember(String),
    /// The acting role does not manage the invited role.
    Denied {
        acting: Role,
        invited: Role,
    },
    Quota(QuotaExceeded),
    Db(DbError),
}

impl From<DbError> for InviteError {
    fn from(e: DbError) -> Self {
        InviteError::Db(e)
    }
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InviteError::NotFound => f.write_str("no such invitation"),
            InviteError::Expired => f.write_str("this invitation has expired; ask for a new one"),
            InviteError::Accepted => f.write_str("this invitation has already been accepted"),
            InviteError::Revoked => f.write_str("this invitation has been revoked"),
            InviteError::NotInvitee(Invitee::Email(_)) => f.write_str(
                "this invitation is for another email address, or your sign-in provider has \
                 not verified yours; sign in as the person invited",
            ),
            InviteError::NotInvitee(Invitee::Member(m)) => write!(
                f,
                "this invitation is for the member {m}; sign in as that person"
            ),
            InviteError::AlreadyMember(role) => {
                write!(f, "you are already a member of this workspace, as {role}")
            }
            InviteError::NoSuchMember(m) => {
                write!(
                    f,
                    "nobody with the member name {m:?} has signed in yet; invite them by email"
                )
            }
            InviteError::Denied { acting, invited } => match acting {
                Role::Viewer | Role::Editor => write!(
                    f,
                    "the {acting} role cannot manage invitations; ask a workspace admin"
                ),
                _ => write!(
                    f,
                    "the {acting} role cannot invite an {invited}; ask a workspace owner"
                ),
            },
            InviteError::Quota(q) => q.fmt(f),
            InviteError::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InviteError {}

/// Maps a refusal to its API error. `app` counts quota refusals.
pub fn api_error(app: &App, e: InviteError) -> ApiError {
    let msg = e.to_string();
    match e {
        InviteError::NotFound
        | InviteError::Expired
        | InviteError::Accepted
        | InviteError::Revoked => ApiError::not_found_msg(msg),
        InviteError::NotInvitee(_) | InviteError::Denied { .. } => {
            app.metrics.permission_denied.inc();
            ApiError::permission_denied(msg)
        }
        InviteError::AlreadyMember(_) => ApiError::conflict(msg),
        InviteError::NoSuchMember(_) => ApiError::invalid(msg),
        InviteError::Quota(q) => {
            app.metrics.quota_exceeded(q.kind);
            ApiError::quota_exceeded(msg)
        }
        InviteError::Db(e) => ApiError::from(e),
    }
}

/// Ok if `invitation` can still be accepted.
fn check_pending(invitation: &Invitation) -> Result<(), InviteError> {
    match invitation.status {
        Status::Pending => Ok(()),
        Status::Expired => Err(InviteError::Expired),
        Status::Accepted => Err(InviteError::Accepted),
        Status::Revoked => Err(InviteError::Revoked),
    }
}

/// Ok if someone acting as `acting` may invite to, or revoke an invitation
/// for, `invited`.
pub fn may_manage(acting: Role, invited: Role) -> Result<(), InviteError> {
    if acting.manages(invited) {
        Ok(())
    } else {
        Err(InviteError::Denied { acting, invited })
    }
}

/// A new invitation, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewInvitation {
    pub invitee: Invitee,
    pub role: Role,
    pub ttl: Duration,
}

/// What accepting gave the person.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Joined {
    pub workspace_id: i64,
    pub workspace_name: String,
    pub role: Role,
}

/// An invitation as its recipient sees it before accepting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Preview {
    pub workspace_id: i64,
    pub workspace_name: String,
    pub role: Role,
    pub invited_by: String,
    pub email: Option<String>,
    pub member: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl Tenant<'_> {
    /// Creates an invitation in this workspace on behalf of `acting`, whose
    /// role there must manage the invited role, with the token whose hash is
    /// `token_hash`.
    pub async fn create_invitation(
        &self,
        acting: Role,
        new: &NewInvitation,
        token_hash: &[u8; 32],
    ) -> Result<Invitation, InviteError> {
        may_manage(acting, new.role)?;
        let invited_by = self
            .actor()
            .member
            .clone()
            .ok_or_else(|| DbError::Other("an invitation needs a member as inviter".into()))?;
        if let Invitee::Member(m) = &new.invitee {
            // Names are never reused or changed, so checking first is as
            // good as checking in the transaction, which as the tenant role
            // cannot read users.
            let exists: bool = self
                .db()
                .timed(
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE member = $1)")
                        .bind(m)
                        .fetch_one(self.db().pool()),
                )
                .await?;
            if !exists {
                return Err(InviteError::NoSuchMember(m.clone()));
            }
        }
        let (email, member) = new.invitee.columns();
        let ttl_secs = new.ttl.as_secs() as i64;
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                // Serialise invitations in this workspace so the pending
                // count cannot be overrun by concurrent requests.
                sqlx::query("SELECT 1 FROM workspaces FOR NO KEY UPDATE")
                    .execute(&mut *tx)
                    .await?;
                if let Some(m) = member {
                    let role: Option<String> =
                        sqlx::query_scalar("SELECT role FROM workspace_members WHERE member = $1")
                            .bind(m)
                            .fetch_optional(&mut *tx)
                            .await?;
                    if let Some(role) = role.as_deref().and_then(Role::parse) {
                        return Ok(Err(InviteError::AlreadyMember(role)));
                    }
                }
                let pending: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM invitations \
                      WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
                )
                .fetch_one(&mut *tx)
                .await?;
                if pending >= MAX_PENDING_INVITATIONS {
                    return Ok(Err(InviteError::Quota(QuotaExceeded {
                        kind: QuotaKind::PendingInvitations,
                        limit: MAX_PENDING_INVITATIONS,
                        resets_on: None,
                    })));
                }
                // workspace_id defaults to the transaction's workspace.
                let row = sqlx::query(concat!(
                    "INSERT INTO invitations (token_hash, email, member, role, invited_by, \
                     expires_at) VALUES ($1, $2, $3, $4, $5, now() + $6::bigint * interval '1 second') \
                     RETURNING ",
                    cols!()
                ))
                .bind(&token_hash[..])
                .bind(email)
                .bind(member)
                .bind(new.role.as_str())
                .bind(&invited_by)
                .bind(ttl_secs)
                .fetch_one(&mut *tx)
                .await?;
                let invitation = row_to_invitation(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::InvitationCreate,
                    target: format!("invitation:{}", invitation.id),
                    before: None,
                    after: Some(invitation_state(&invitation)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(invitation))
            })
            .await?
    }

    /// This workspace's invitations: every pending one, then the others,
    /// newest first, at most [`LIST_LIMIT`].
    pub async fn invitations(&self) -> Result<Vec<Invitation>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    cols!(),
                    " FROM invitations \
                     ORDER BY (accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()) \
                     DESC, id DESC LIMIT $1"
                ))
                .bind(LIST_LIMIT)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_invitation)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// Revokes a pending invitation on behalf of `acting`, whose role must
    /// manage the invited role.
    pub async fn revoke_invitation(
        &self,
        acting: Role,
        id: i64,
    ) -> Result<Invitation, InviteError> {
        let revoked_by = self
            .actor()
            .member
            .clone()
            .ok_or_else(|| DbError::Other("revoking needs a member".into()))?;
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let Some(row) = sqlx::query(concat!(
                    "SELECT ",
                    cols!(),
                    " FROM invitations WHERE id = $1 FOR UPDATE"
                ))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                else {
                    return Ok(Err(InviteError::NotFound));
                };
                let before = row_to_invitation(&row)?;
                if let Err(e) = may_manage(acting, before.role).and(check_pending(&before)) {
                    return Ok(Err(e));
                }
                let row = sqlx::query(concat!(
                    "UPDATE invitations SET revoked_at = now(), revoked_by = $2 WHERE id = $1 \
                     RETURNING ",
                    cols!()
                ))
                .bind(id)
                .bind(&revoked_by)
                .fetch_one(&mut *tx)
                .await?;
                let after = row_to_invitation(&row)?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::InvitationRevoke,
                    target: format!("invitation:{id}"),
                    before: Some(invitation_state(&before)),
                    after: Some(invitation_state(&after)),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(after))
            })
            .await?
    }
}

impl Db {
    /// The pending invitation with this token, for its recipient to look at.
    pub async fn invitation_preview(&self, token_hash: &[u8; 32]) -> Result<Preview, InviteError> {
        let row = self
            .timed(
                sqlx::query(concat!(
                    "SELECT ",
                    icols!(),
                    ", w.name AS workspace_name \
                     FROM invitations i JOIN workspaces w ON w.id = i.workspace_id \
                     WHERE i.token_hash = $1"
                ))
                .bind(&token_hash[..])
                .fetch_optional(self.pool()),
            )
            .await?
            .ok_or(InviteError::NotFound)?;
        let invitation = row_to_invitation(&row).map_err(DbError::from)?;
        check_pending(&invitation)?;
        Ok(Preview {
            workspace_id: invitation.workspace_id,
            workspace_name: row.try_get("workspace_name").map_err(DbError::from)?,
            role: invitation.role,
            invited_by: invitation.invited_by,
            email: invitation.email,
            member: invitation.member,
            expires_at: invitation.expires_at,
        })
    }

    /// Accepts the invitation with this token for the signed-in person
    /// `user_id`, making them a member with the invited role. One
    /// transaction that locks the invitation, so it is used at most once.
    pub async fn accept_invitation(
        &self,
        token_hash: &[u8; 32],
        user_id: i64,
    ) -> Result<Joined, InviteError> {
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            let Some(row) = sqlx::query(concat!(
                "SELECT ",
                icols!(),
                ", w.name AS workspace_name \
                 FROM invitations i JOIN workspaces w ON w.id = i.workspace_id \
                 WHERE i.token_hash = $1 FOR UPDATE OF i"
            ))
            .bind(&token_hash[..])
            .fetch_optional(&mut *tx)
            .await?
            else {
                return Ok(Err(InviteError::NotFound));
            };
            let before = row_to_invitation(&row)?;
            let workspace_name: String = row.try_get("workspace_name")?;
            if let Err(e) = check_pending(&before) {
                return Ok(Err(e));
            }
            // The person as they are now, not as a cached session saw them.
            let user = sqlx::query("SELECT member, email, email_verified FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
            let member: String = user.try_get("member")?;
            let email: Option<String> = user.try_get("email")?;
            let verified: bool = user.try_get("email_verified")?;
            let invitee = before.invitee();
            if !invitee.is(&member, email.as_deref(), verified) {
                return Ok(Err(InviteError::NotInvitee(invitee)));
            }
            let added = sqlx::query(
                "INSERT INTO workspace_members (workspace_id, member, role) VALUES ($1, $2, $3) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(before.workspace_id)
            .bind(&member)
            .bind(before.role.as_str())
            .execute(&mut *tx)
            .await?;
            if added.rows_affected() == 0 {
                let role: String = sqlx::query_scalar(
                    "SELECT role FROM workspace_members WHERE workspace_id = $1 AND member = $2",
                )
                .bind(before.workspace_id)
                .bind(&member)
                .fetch_one(&mut *tx)
                .await?;
                let role = Role::parse(&role)
                    .ok_or_else(|| sqlx::Error::Decode(format!("unknown role {role:?}").into()))?;
                return Ok(Err(InviteError::AlreadyMember(role)));
            }
            let row = sqlx::query(concat!(
                "UPDATE invitations SET accepted_at = now(), accepted_by = $2, \
                 accepted_member = $3 WHERE id = $1 RETURNING ",
                cols!()
            ))
            .bind(before.id)
            .bind(user_id)
            .bind(&member)
            .fetch_one(&mut *tx)
            .await?;
            let after = row_to_invitation(&row)?;
            let change = Change {
                workspace_id: before.workspace_id,
                action: Action::InvitationAccept,
                target: format!("invitation:{}", before.id),
                before: Some(invitation_state(&before)),
                after: Some(invitation_state(&after)),
            };
            audit::record(&mut tx, &Actor::session(&member, user_id), change).await?;
            tx.commit().await?;
            Ok(Ok(Joined {
                workspace_id: before.workspace_id,
                workspace_name,
                role: before.role,
            }))
        })
        .await?
    }
}

/// A signed-in person acting in a workspace: invitations are managed with a
/// session, never with an API key.
pub struct Person(pub Workspace);

impl FromRequestParts<Arc<App>> for Person {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let ws = Workspace::from_request_parts(parts, app).await?;
        match ws.principal.credential {
            Credential::Session(_) => Ok(Person(ws)),
            Credential::ApiKey(_) => {
                app.metrics.permission_denied.inc();
                Err(ApiError::permission_denied(
                    "invitations are managed by signed-in people; API keys cannot manage members",
                ))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvitation {
    pub email: Option<String>,
    pub member: Option<String>,
    pub role: String,
    pub expires_in: Option<String>,
}

impl CreateInvitation {
    /// Checks the request.
    pub fn validate(&self) -> Result<NewInvitation, String> {
        let invitee = Invitee::parse(self.email.as_deref(), self.member.as_deref())?;
        let role = Role::parse(&self.role).ok_or_else(|| {
            format!(
                "role must be one of owner, admin, editor and viewer, not {:?}",
                self.role
            )
        })?;
        let ttl = parse_invite_ttl(self.expires_in.as_deref())?;
        Ok(NewInvitation { invitee, role, ttl })
    }
}

#[derive(Serialize)]
struct Created<'a> {
    #[serde(flatten)]
    invitation: &'a Invitation,
    token: &'a str,
    url: String,
}

#[derive(Serialize)]
struct InvitationList<'a> {
    invitations: &'a [Invitation],
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// `POST /v1/invitations`: invite someone; the answer carries the link,
/// shown only now.
pub async fn create_invitation(
    State(app): State<Arc<App>>,
    Person(ws): Person,
    StrictJson(req): StrictJson<CreateInvitation>,
) -> Result<Response, ApiError> {
    // The role is checked before the body, as scopes are elsewhere.
    if !ws.principal.role.manages(Role::Viewer) {
        return Err(api_error(
            &app,
            InviteError::Denied {
                acting: ws.principal.role,
                invited: Role::Viewer,
            },
        ));
    }
    let new = req.validate().map_err(ApiError::invalid)?;
    let token = generate_invite_token();
    let invitation = ws
        .tenant(&app.db)
        .create_invitation(ws.principal.role, &new, &hash_invite(&token))
        .await
        .map_err(|e| api_error(&app, e))?;
    tracing::info!(invitation = invitation.id, role = %invitation.role, "invitation created");
    let url = format!("{}{INVITE_PATH}{token}", app.cfg.public_base_url);
    let mut resp = json(
        StatusCode::CREATED,
        &Created {
            invitation: &invitation,
            token: &token,
            url,
        },
    );
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/invitations/{}", invitation.id)) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(no_store(resp))
}

/// `GET /v1/invitations`: the workspace's invitations, pending first.
pub async fn list_invitations(
    State(app): State<Arc<App>>,
    Person(ws): Person,
) -> Result<Response, ApiError> {
    if !ws.principal.role.manages(Role::Viewer) {
        return Err(api_error(
            &app,
            InviteError::Denied {
                acting: ws.principal.role,
                invited: Role::Viewer,
            },
        ));
    }
    let invitations = ws.tenant(&app.db).invitations().await?;
    Ok(json(
        StatusCode::OK,
        &InvitationList {
            invitations: &invitations,
        },
    ))
}

/// `DELETE /v1/invitations/{id}`: revoke a pending invitation.
pub async fn revoke_invitation(
    State(app): State<Arc<App>>,
    Person(ws): Person,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let id = id
        .parse::<i64>()
        .ok()
        .filter(|&i| i > 0 && !id.starts_with('+'))
        .ok_or_else(|| ApiError::not_found_msg("no such invitation"))?;
    let invitation = ws
        .tenant(&app.db)
        .revoke_invitation(ws.principal.role, id)
        .await
        .map_err(|e| match e {
            // A revoker learns why it cannot be revoked, not "not found".
            InviteError::Accepted | InviteError::Revoked | InviteError::Expired => {
                ApiError::conflict(format!("cannot revoke: {e}"))
            }
            e => api_error(&app, e),
        })?;
    tracing::info!(invitation = invitation.id, "invitation revoked");
    Ok(StatusCode::NO_CONTENT.into_response())
}

fn token_hash(token: &str) -> Result<[u8; 32], ApiError> {
    if is_well_formed_invite(token) {
        Ok(hash_invite(token))
    } else {
        Err(ApiError::not_found_msg("this invitation link is not valid"))
    }
}

/// `GET /v1/invites/{token}`: what accepting would do, for the signed-in
/// recipient.
pub async fn preview_invite(
    State(app): State<Arc<App>>,
    _person: SessionAuthed,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    let hash = token_hash(&token)?;
    let preview = app
        .db
        .invitation_preview(&hash)
        .await
        .map_err(|e| api_error(&app, e))?;
    Ok(no_store(json(StatusCode::OK, &preview)))
}

/// `POST /v1/invites/{token}/accept`: join the workspace.
pub async fn accept_invite(
    State(app): State<Arc<App>>,
    authed: SessionAuthed,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    let hash = token_hash(&token)?;
    let s = &authed.session;
    let joined = app
        .db
        .accept_invitation(&hash, s.user_id)
        .await
        .map_err(|e| api_error(&app, e))?;
    app.auth.forget_role(&s.member, joined.workspace_id);
    tracing::info!(workspace = joined.workspace_id, role = %joined.role, "invitation accepted");
    Ok(json(StatusCode::OK, &joined))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let t = generate_invite_token();
        assert!(is_well_formed_invite(&t), "{t}");
        assert_ne!(t, generate_invite_token());
        assert_eq!(hash_invite(&t), hash_invite(&t));
        assert_ne!(hash_invite(&t), hash_invite(&generate_invite_token()));
        assert!(!is_well_formed_invite(&t.to_uppercase()));
        assert!(!is_well_formed_invite(&t.replace("rli_", "rlk_")));
        assert!(!is_well_formed_invite(&t[..t.len() - 1]));
        assert!(!is_well_formed_invite(&format!("{t}0")));
        assert!(!is_well_formed_invite(&format!("rli_{}", "g".repeat(64))));
        assert!(!is_well_formed_invite(""));
    }

    #[test]
    fn tokens_never_reach_the_log() {
        let t = generate_invite_token();
        assert_eq!(
            loggable_path(&format!("/v1/invites/{t}")),
            "/v1/invites/{token}"
        );
        assert_eq!(
            loggable_path(&format!("/v1/invites/{t}/accept")),
            "/v1/invites/{token}/accept"
        );
        assert_eq!(loggable_path("/v1/invites/"), "/v1/invites/");
        assert_eq!(loggable_path("/v1/invitations/3"), "/v1/invitations/3");
        assert_eq!(loggable_path("/v1/links"), "/v1/links");
        assert!(matches!(loggable_path("/v1/links"), Cow::Borrowed(_)));
    }

    #[test]
    fn emails() {
        assert_eq!(
            normalize_email(" Ada@Example.COM ").unwrap(),
            "ada@example.com"
        );
        assert_eq!(normalize_email("a+b@x.io").unwrap(), "a+b@x.io");
        for bad in [
            "",
            "ada",
            "@example.com",
            "ada@",
            "ada@example",
            "ada@.com",
            "ada@example.",
            "a@b@c.com",
            "a da@example.com",
            "ada@exa\tmple.com",
            "ada@x\u{0}.com",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}@example.com", "a".repeat(320));
        assert!(normalize_email(&long).is_err());
    }

    #[test]
    fn invitees() {
        assert_eq!(
            Invitee::parse(Some("Ada@Example.com"), None),
            Ok(Invitee::Email("ada@example.com".into()))
        );
        assert_eq!(
            Invitee::parse(None, Some("ada")),
            Ok(Invitee::Member("ada".into()))
        );
        assert!(Invitee::parse(None, Some("Ada")).is_err());
        assert!(Invitee::parse(None, None).is_err());
        assert!(Invitee::parse(Some("a@b.co"), Some("ada")).is_err());

        let by_email = Invitee::Email("ada@example.com".into());
        assert!(by_email.is("anyone", Some("ADA@example.com"), true));
        // An address the provider did not verify proves nothing.
        assert!(!by_email.is("anyone", Some("ada@example.com"), false));
        assert!(!by_email.is("anyone", Some("eve@example.com"), true));
        assert!(!by_email.is("anyone", None, true));
        let by_name = Invitee::Member("ada".into());
        assert!(by_name.is("ada", None, false));
        assert!(!by_name.is("ada-2", Some("ada@example.com"), true));
    }

    #[test]
    fn lifetimes() {
        assert_eq!(parse_invite_ttl(None), Ok(DEFAULT_INVITE_TTL));
        assert_eq!(parse_invite_ttl(Some("5m")), Ok(MIN_INVITE_TTL));
        assert_eq!(parse_invite_ttl(Some("30d")), Ok(MAX_INVITE_TTL));
        assert_eq!(parse_invite_ttl(Some("2h")), Ok(Duration::from_secs(7_200)));
        for bad in ["4m", "31d", "0s", "7", "d", "1w"] {
            assert!(parse_invite_ttl(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn who_invites_whom() {
        assert_eq!(may_manage(Role::Owner, Role::Owner), Ok(()));
        assert_eq!(may_manage(Role::Admin, Role::Editor), Ok(()));
        assert_eq!(may_manage(Role::Admin, Role::Viewer), Ok(()));
        let e = may_manage(Role::Admin, Role::Admin).unwrap_err();
        assert!(e.to_string().contains("cannot invite an admin"), "{e}");
        let e = may_manage(Role::Editor, Role::Viewer).unwrap_err();
        assert!(e.to_string().contains("editor role cannot manage"), "{e}");
        assert!(may_manage(Role::Viewer, Role::Viewer).is_err());
    }

    #[test]
    fn requests() {
        let req = |email: Option<&str>, member: Option<&str>, role: &str, exp: Option<&str>| {
            CreateInvitation {
                email: email.map(Into::into),
                member: member.map(Into::into),
                role: role.into(),
                expires_in: exp.map(Into::into),
            }
            .validate()
        };
        assert_eq!(
            req(Some("a@b.co"), None, "editor", Some("1d")),
            Ok(NewInvitation {
                invitee: Invitee::Email("a@b.co".into()),
                role: Role::Editor,
                ttl: Duration::from_secs(86_400),
            })
        );
        assert!(
            req(Some("a@b.co"), None, "superuser", None)
                .unwrap_err()
                .contains("role must be")
        );
        assert!(req(None, None, "viewer", None).is_err());
        assert!(req(None, Some("bob"), "viewer", Some("60d")).is_err());
        let bad: Result<CreateInvitation, _> =
            serde_json::from_str(r#"{"member":"bob","role":"viewer","extra":1}"#);
        assert!(bad.is_err());
    }

    fn sample() -> Invitation {
        let t = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        Invitation {
            id: 7,
            workspace_id: 3,
            email: None,
            member: Some("bob".into()),
            role: Role::Editor,
            invited_by: "alice".into(),
            status: Status::Pending,
            created_at: t,
            expires_at: t,
            accepted_at: None,
            accepted_member: None,
            revoked_at: None,
            revoked_by: None,
        }
    }

    #[test]
    fn states_and_views() {
        let mut i = sample();
        assert_eq!(i.invitee(), Invitee::Member("bob".into()));
        assert_eq!(check_pending(&i), Ok(()));
        let state = invitation_state(&i);
        assert_eq!(state["role"], "editor");
        assert_eq!(state["status"], "pending");
        assert!(state.get("token").is_none() && state.get("token_hash").is_none());
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["role"], "editor");
        assert_eq!(v["status"], "pending");
        for (status, err) in [
            (Status::Expired, InviteError::Expired),
            (Status::Accepted, InviteError::Accepted),
            (Status::Revoked, InviteError::Revoked),
        ] {
            i.status = status;
            assert_eq!(check_pending(&i), Err(err));
            assert_eq!(serde_json::to_value(status).unwrap(), status.as_str());
        }
        i.email = Some("a@b.co".into());
        i.member = None;
        assert_eq!(i.invitee(), Invitee::Email("a@b.co".into()));
    }

    #[test]
    fn messages() {
        assert!(InviteError::Expired.to_string().contains("expired"));
        assert!(
            InviteError::Accepted
                .to_string()
                .contains("already been accepted")
        );
        assert!(InviteError::Revoked.to_string().contains("revoked"));
        assert_eq!(InviteError::NotFound.to_string(), "no such invitation");
        assert!(
            InviteError::NotInvitee(Invitee::Email("a@b.co".into()))
                .to_string()
                .contains("not verified")
        );
        // The invited address is not repeated to whoever holds the link.
        assert!(
            !InviteError::NotInvitee(Invitee::Email("a@b.co".into()))
                .to_string()
                .contains("a@b.co")
        );
        assert!(
            InviteError::NotInvitee(Invitee::Member("bob".into()))
                .to_string()
                .contains("member bob")
        );
        assert!(
            InviteError::AlreadyMember(Role::Viewer)
                .to_string()
                .contains("as viewer")
        );
        assert!(
            InviteError::NoSuchMember("zed".into())
                .to_string()
                .contains("\"zed\"")
        );
        assert!(
            InviteError::from(DbError::NotFound)
                .to_string()
                .contains("not found")
        );
    }

    #[test]
    fn joined_columns_are_the_same_columns() {
        let qualified: Vec<String> = cols!()
            .split(", ")
            .map(|c| match c.strip_prefix('(') {
                Some(expr) => format!("(i.{expr}"),
                None => format!("i.{c}"),
            })
            .collect();
        assert_eq!(qualified.join(", "), icols!());
    }
}
