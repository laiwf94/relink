//! The audit log: who changed what, before and after, in a hash chain per
//! workspace (migration 0007, docs/DESIGN.md "Audit log").
//!
//! [`record`] appends an entry inside the caller's transaction, so the entry
//! commits or rolls back with the change it describes. The database fills in
//! the sequence number, the time and both hashes in a trigger, so no writer
//! can break or skip the chain. [`Db::verify_audit`] reads the chains back
//! and recomputes every hash here, independently of that trigger:
//! [`entry_hash`] is the same function in Rust. An entry edited, inserted,
//! reordered or removed in the middle of a chain breaks the next entry's
//! link; one removed from the end disagrees with the chain's head. An
//! operator who keeps a copy of a head elsewhere (`relink audit-verify`
//! prints them) can also detect the head being rewritten along with the
//! table, with [`Anchor`].
//!
//! The log covers changes made by people and operators: links, API keys,
//! workspaces, sign-ins and sign-outs, and invitations. Bookkeeping the server does by itself
//! (click counts, click leases, health results, the KV outbox) is not
//! logged; it is not anyone's decision and would drown the log.

use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

use crate::auth::{Credential, Principal, Scopes};
use crate::store::{Db, DbError, KeyInfo, StoredLink};
use crate::util::hex_encode;

/// Prefix of every hashed entry; a new hash layout gets a new one.
const DOMAIN: &[u8] = b"relink-audit-v1";

/// The previous hash of the first entry in a chain.
pub const GENESIS: [u8; 32] = [0; 32];

/// Entries read per query while verifying.
const VERIFY_BATCH: i64 = 1000;

/// Who made a change and through what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// The member who acted; None for an operator at the command line or the
    /// server itself.
    pub member: Option<String>,
    pub via: Via,
}

/// How an actor reached relink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// An API key, by ID.
    Key(i64),
    /// A signed-in session, by user ID.
    Session(i64),
    /// An operator running a `relink` command.
    Cli,
    /// The server, on someone's behalf, such as creating a personal
    /// workspace on first use.
    System,
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Via::Key(id) => write!(f, "key:{id}"),
            Via::Session(id) => write!(f, "session:{id}"),
            Via::Cli => f.write_str("cli"),
            Via::System => f.write_str("system"),
        }
    }
}

impl Actor {
    /// An operator at the command line.
    pub fn cli() -> Actor {
        Actor {
            member: None,
            via: Via::Cli,
        }
    }

    /// The server itself.
    pub fn system() -> Actor {
        Actor {
            member: None,
            via: Via::System,
        }
    }

    /// A signed-in person.
    pub fn session(member: &str, user_id: i64) -> Actor {
        Actor {
            member: Some(member.to_owned()),
            via: Via::Session(user_id),
        }
    }
}

impl From<&Principal> for Actor {
    fn from(p: &Principal) -> Actor {
        Actor {
            member: Some(p.owner.clone()),
            via: match p.credential {
                Credential::ApiKey(id) => Via::Key(id),
                Credential::Session(id) => Via::Session(id),
            },
        }
    }
}

/// What was done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    LinkCreate,
    LinkUpdate,
    LinkDelete,
    KeyCreate,
    KeyRotate,
    KeyRevoke,
    WorkspaceCreate,
    WorkspacePlan,
    UserCreate,
    UserSignIn,
    SessionEnd,
    InvitationCreate,
    InvitationAccept,
    InvitationRevoke,
    DomainCreate,
    DomainVerify,
    DomainDelete,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::LinkCreate => "link.create",
            Action::LinkUpdate => "link.update",
            Action::LinkDelete => "link.delete",
            Action::KeyCreate => "key.create",
            Action::KeyRotate => "key.rotate",
            Action::KeyRevoke => "key.revoke",
            Action::WorkspaceCreate => "workspace.create",
            Action::WorkspacePlan => "workspace.plan",
            Action::UserCreate => "user.create",
            Action::UserSignIn => "user.sign_in",
            Action::SessionEnd => "session.end",
            Action::InvitationCreate => "invitation.create",
            Action::InvitationAccept => "invitation.accept",
            Action::InvitationRevoke => "invitation.revoke",
            Action::DomainCreate => "domain.create",
            Action::DomainVerify => "domain.verify",
            Action::DomainDelete => "domain.delete",
        }
    }
}

/// One change to record.
#[derive(Clone, Debug)]
pub struct Change {
    pub workspace_id: i64,
    pub action: Action,
    /// What was acted on, like `link:42`.
    pub target: String,
    pub before: Option<Value>,
    pub after: Option<Value>,
}

/// Appends `change` by `actor` to its workspace's chain, inside `tx`. In a
/// tenant transaction row-level security refuses any other workspace.
pub async fn record(
    tx: &mut Transaction<'_, Postgres>,
    actor: &Actor,
    change: Change,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (workspace_id, actor, via, action, target, before, after, \
                                seq, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $8)",
    )
    .bind(change.workspace_id)
    .bind(actor.member.as_deref())
    .bind(actor.via.to_string())
    .bind(change.action.as_str())
    .bind(&change.target)
    .bind(change.before)
    .bind(change.after)
    // Placeholders: the trigger overwrites seq and both hashes.
    .bind(&GENESIS[..])
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// A link as the audit log shows it: the redirect record and its creator.
pub fn link_state(link: &StoredLink) -> Value {
    let mut v = serde_json::to_value(&link.link).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.insert("owner".into(), Value::String(link.owner.clone()));
        // Only links on custom domains say so; the default domain has none.
        if let Some(d) = link.domain_id {
            m.insert("domain_id".into(), Value::from(d));
        }
    }
    v
}

/// A key as the audit log shows it; never its hash.
pub fn key_state(
    id: i64,
    owner: &str,
    name: &str,
    scopes: Scopes,
    expires_at: Option<DateTime<Utc>>,
) -> Value {
    json!({
        "id": id,
        "owner": owner,
        "name": name,
        "scopes": scopes.names(),
        "expires_at": expires_at,
    })
}

/// [`key_state`] of a key as created.
pub fn key_info_state(k: &KeyInfo, name: &str) -> Value {
    key_state(k.id, &k.owner, name, k.scopes, k.expires_at)
}

/// An entry as stored, with the fields that are hashed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub workspace_id: i64,
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub actor: Option<String>,
    pub via: String,
    pub action: String,
    pub target: String,
    /// `before` and `after` in jsonb's text form, which is what is hashed.
    pub before: Option<String>,
    pub after: Option<String>,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

fn field(h: &mut Sha256, v: Option<&str>) {
    match v {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            // Fields are bounded far below 4 GiB by the table's checks and
            // Postgres's 1 GB value limit.
            h.update((s.len() as u32).to_be_bytes());
            h.update(s.as_bytes());
        }
    }
}

/// The hash of `e` given the previous entry's hash; the trigger in
/// migration 0007 computes the same.
pub fn entry_hash(prev: &[u8; 32], e: &Entry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(prev);
    h.update(e.workspace_id.to_be_bytes());
    h.update(e.seq.to_be_bytes());
    h.update(e.at.timestamp_micros().to_be_bytes());
    field(&mut h, e.actor.as_deref());
    field(&mut h, Some(&e.via));
    field(&mut h, Some(&e.action));
    field(&mut h, Some(&e.target));
    field(&mut h, e.before.as_deref());
    field(&mut h, e.after.as_deref());
    h.finalize().into()
}

/// A head recorded earlier, outside the database: the entry `seq` of
/// `workspace_id` must still have this hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub workspace_id: i64,
    pub seq: i64,
    pub hash: [u8; 32],
}

impl Anchor {
    /// Parses `WORKSPACE:SEQ:HASH`, the hash in hex, as `audit-verify`
    /// prints it.
    pub fn parse(s: &str) -> Result<Anchor, String> {
        let bad = || format!("anchor {s:?} is not WORKSPACE:SEQ:HASH");
        let mut parts = s.split(':');
        let (Some(ws), Some(seq), Some(hash), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let positive = |v: &str| v.parse::<i64>().ok().filter(|&n| n > 0);
        let hash: [u8; 32] = crate::util::hex_decode(hash)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(bad)?;
        Ok(Anchor {
            workspace_id: positive(ws).ok_or_else(bad)?,
            seq: positive(seq).ok_or_else(bad)?,
            hash,
        })
    }
}

/// One workspace's verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub workspace_id: i64,
    pub seq: i64,
    pub hash: [u8; 32],
}

impl fmt::Display for ChainHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.workspace_id,
            self.seq,
            hex_encode(&self.hash)
        )
    }
}

/// Where and why a chain does not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Break {
    pub workspace_id: i64,
    /// The first entry that is wrong or missing.
    pub seq: i64,
    pub reason: BreakReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakReason {
    /// The entry with this number is missing.
    Missing,
    /// Its stored previous hash is not the previous entry's hash.
    Unlinked,
    /// Its contents do not hash to its stored hash.
    Altered,
    /// The chain's head records a later or different last entry.
    HeadMismatch { head_seq: i64 },
    /// Entries exist but the chain has no head.
    NoHead,
    /// The entry an anchor names has a different hash, or is gone.
    AnchorMismatch,
}

impl fmt::Display for Break {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (ws, seq) = (self.workspace_id, self.seq);
        match &self.reason {
            BreakReason::Missing => write!(f, "workspace {ws}: entry {seq} is missing"),
            BreakReason::Unlinked => write!(
                f,
                "workspace {ws}: entry {seq} does not follow from entry {}",
                seq - 1
            ),
            BreakReason::Altered => {
                write!(
                    f,
                    "workspace {ws}: entry {seq} was altered after it was written"
                )
            }
            BreakReason::HeadMismatch { head_seq } => write!(
                f,
                "workspace {ws}: the chain ends at entry {seq} but its head records entry {head_seq}"
            ),
            BreakReason::NoHead => {
                write!(f, "workspace {ws}: entries exist but the chain has no head")
            }
            BreakReason::AnchorMismatch => write!(
                f,
                "workspace {ws}: entry {seq} no longer has the anchored hash"
            ),
        }
    }
}

/// Why verification did not finish.
#[derive(Debug)]
pub enum VerifyError {
    Broken(Break),
    Db(DbError),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Broken(b) => write!(f, "audit chain broken: {b}"),
            VerifyError::Db(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<sqlx::Error> for VerifyError {
    fn from(e: sqlx::Error) -> Self {
        VerifyError::Db(e.into())
    }
}

impl From<DbError> for VerifyError {
    fn from(e: DbError) -> Self {
        VerifyError::Db(e)
    }
}

fn hash32(row: &sqlx::postgres::PgRow, col: &str) -> Result<[u8; 32], sqlx::Error> {
    let v: Vec<u8> = row.try_get(col)?;
    v.try_into()
        .map_err(|_| sqlx::Error::Decode(format!("{col} is not 32 bytes").into()))
}

/// Checks one chain's entries in order, from wherever the caller is.
#[derive(Clone, Debug)]
pub struct ChainCheck {
    workspace_id: i64,
    next_seq: i64,
    prev: [u8; 32],
}

impl ChainCheck {
    pub fn new(workspace_id: i64) -> ChainCheck {
        ChainCheck {
            workspace_id,
            next_seq: 1,
            prev: GENESIS,
        }
    }

    fn broken(&self, seq: i64, reason: BreakReason) -> Break {
        Break {
            workspace_id: self.workspace_id,
            seq,
            reason,
        }
    }

    /// Takes the next entry; entries must come in `seq` order.
    pub fn push(&mut self, e: &Entry) -> Result<(), Break> {
        if e.seq != self.next_seq {
            return Err(self.broken(self.next_seq, BreakReason::Missing));
        }
        if e.prev_hash != self.prev {
            return Err(self.broken(e.seq, BreakReason::Unlinked));
        }
        if entry_hash(&self.prev, e) != e.hash {
            return Err(self.broken(e.seq, BreakReason::Altered));
        }
        self.prev = e.hash;
        self.next_seq += 1;
        Ok(())
    }

    /// Ends the chain against its stored head (None when there is none).
    pub fn finish(self, head: Option<(i64, [u8; 32])>) -> Result<ChainHead, Break> {
        let last = self.next_seq - 1;
        match head {
            None if last == 0 => {}
            None => return Err(self.broken(last, BreakReason::NoHead)),
            Some((seq, hash)) if seq == last && hash == self.prev => {}
            Some((seq, _)) if seq > last => {
                return Err(self.broken(last + 1, BreakReason::Missing));
            }
            Some((seq, _)) => {
                return Err(self.broken(last, BreakReason::HeadMismatch { head_seq: seq }));
            }
        }
        Ok(ChainHead {
            workspace_id: self.workspace_id,
            seq: last,
            hash: self.prev,
        })
    }
}

impl Db {
    /// Verifies the chain of `workspace_id`, or of every workspace that has
    /// one, and each anchor. Reads in batches, so memory stays flat however
    /// long a chain is. Returns each chain's head, in workspace order.
    pub async fn verify_audit(
        &self,
        workspace_id: Option<i64>,
        anchors: &[Anchor],
    ) -> Result<Vec<ChainHead>, VerifyError> {
        let workspaces: Vec<i64> = self
            .timed(
                sqlx::query_scalar(
                    "SELECT workspace_id FROM audit_heads WHERE $1::bigint IS NULL OR workspace_id = $1
                      UNION
                     SELECT DISTINCT workspace_id FROM audit_log WHERE $1::bigint IS NULL OR workspace_id = $1
                      UNION
                     SELECT unnest($2::bigint[])
                      ORDER BY 1",
                )
                .bind(workspace_id)
                .bind(
                    anchors
                        .iter()
                        .map(|a| a.workspace_id)
                        .filter(|w| workspace_id.is_none_or(|ws| ws == *w))
                        .collect::<Vec<_>>(),
                )
                .fetch_all(self.pool()),
            )
            .await?;
        let mut heads = Vec::with_capacity(workspaces.len());
        for ws in workspaces {
            heads.push(self.verify_chain(ws, anchors).await?);
        }
        Ok(heads)
    }

    async fn verify_chain(&self, ws: i64, anchors: &[Anchor]) -> Result<ChainHead, VerifyError> {
        let mut check = ChainCheck::new(ws);
        let mut pending: Vec<&Anchor> = anchors.iter().filter(|a| a.workspace_id == ws).collect();
        // The head first: entries appended while we read are then beyond it
        // and ignored, rather than looking like a head that fell behind.
        let head = self
            .timed(
                sqlx::query("SELECT seq, hash FROM audit_heads WHERE workspace_id = $1")
                    .bind(ws)
                    .fetch_optional(self.pool()),
            )
            .await?
            .map(|r| Ok::<_, sqlx::Error>((r.try_get::<i64, _>("seq")?, hash32(&r, "hash")?)))
            .transpose()?;
        let limit = head.map_or(0, |(seq, _)| seq);
        let mut after = 0i64;
        loop {
            let rows = self
                .timed(
                    sqlx::query(
                        "SELECT seq, at, actor, via, action, target, before::text AS before, \
                                after::text AS after, prev_hash, hash \
                           FROM audit_log \
                          WHERE workspace_id = $1 AND seq > $2 AND ($3 = 0 OR seq <= $3) \
                          ORDER BY seq LIMIT $4",
                    )
                    .bind(ws)
                    .bind(after)
                    .bind(limit)
                    .bind(VERIFY_BATCH)
                    .fetch_all(self.pool()),
                )
                .await?;
            for r in &rows {
                let e = Entry {
                    workspace_id: ws,
                    seq: r.try_get("seq")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    via: r.try_get("via")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    before: r.try_get("before")?,
                    after: r.try_get("after")?,
                    prev_hash: hash32(r, "prev_hash")?,
                    hash: hash32(r, "hash")?,
                };
                check.push(&e).map_err(VerifyError::Broken)?;
                if pending.iter().any(|a| a.seq == e.seq && a.hash != e.hash) {
                    return Err(VerifyError::Broken(Break {
                        workspace_id: ws,
                        seq: e.seq,
                        reason: BreakReason::AnchorMismatch,
                    }));
                }
                pending.retain(|a| a.seq != e.seq);
                after = e.seq;
            }
            if (rows.len() as i64) < VERIFY_BATCH {
                break;
            }
        }
        let verified = check.finish(head).map_err(VerifyError::Broken)?;
        // An anchor beyond the end names an entry that is gone.
        if let Some(a) = pending.first() {
            return Err(VerifyError::Broken(Break {
                workspace_id: ws,
                seq: a.seq,
                reason: BreakReason::AnchorMismatch,
            }));
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: i64, prev: [u8; 32]) -> Entry {
        let mut e = Entry {
            workspace_id: 7,
            seq,
            at: DateTime::from_timestamp_micros(1_790_000_000_123_456).unwrap(),
            actor: Some("alice".into()),
            via: "key:3".into(),
            action: "link.update".into(),
            target: "link:9".into(),
            before: Some(r#"{"enabled": true}"#.into()),
            after: Some(r#"{"enabled": false}"#.into()),
            prev_hash: prev,
            hash: [0; 32],
        };
        e.hash = entry_hash(&prev, &e);
        e
    }

    fn chain(n: i64) -> Vec<Entry> {
        let mut prev = GENESIS;
        (1..=n)
            .map(|seq| {
                let e = entry(seq, prev);
                prev = e.hash;
                e
            })
            .collect()
    }

    fn verify(entries: &[Entry], head: Option<(i64, [u8; 32])>) -> Result<ChainHead, Break> {
        let mut c = ChainCheck::new(7);
        for e in entries {
            c.push(e)?;
        }
        c.finish(head)
    }

    #[test]
    fn a_sound_chain_verifies() {
        let c = chain(3);
        let head = verify(&c, Some((3, c[2].hash))).unwrap();
        assert_eq!((head.seq, head.hash), (3, c[2].hash));
        assert_eq!(verify(&[], None).unwrap().seq, 0);
    }

    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = entry(1, GENESIS);
        let edits: [fn(&mut Entry); 10] = [
            |e| e.workspace_id = 8,
            |e| e.seq = 2,
            |e| e.at += chrono::Duration::microseconds(1),
            |e| e.actor = None,
            |e| e.actor = Some("mallory".into()),
            |e| e.via = "cli".into(),
            |e| e.action = "link.delete".into(),
            |e| e.target = "link:10".into(),
            |e| e.before = None,
            |e| e.after = Some(r#"{"enabled": true}"#.into()),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut e = base.clone();
            edit(&mut e);
            assert_ne!(entry_hash(&GENESIS, &e), base.hash, "edit {i}");
        }
        assert_ne!(entry_hash(&[1; 32], &base), base.hash);
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Moving text from one field to the next changes the hash.
        let mut a = entry(1, GENESIS);
        a.action = "link.create".into();
        a.target = "x".into();
        let mut b = a.clone();
        b.action = "link.createx".into();
        b.target = String::new();
        assert_ne!(entry_hash(&GENESIS, &a), entry_hash(&GENESIS, &b));
        // An empty value is not a missing one.
        let mut c = a.clone();
        c.before = Some(String::new());
        let mut d = a.clone();
        d.before = None;
        assert_ne!(entry_hash(&GENESIS, &c), entry_hash(&GENESIS, &d));
    }

    #[test]
    fn breaks_are_located() {
        let c = chain(4);
        let head = Some((4, c[3].hash));

        let mut altered = c.clone();
        altered[1].target = "link:666".into();
        let b = verify(&altered, head).unwrap_err();
        assert_eq!((b.seq, &b.reason), (2, &BreakReason::Altered));

        // Re-hashing the altered entry moves the break to its successor.
        altered[1].hash = entry_hash(&altered[1].prev_hash, &altered[1]);
        let b = verify(&altered, head).unwrap_err();
        assert_eq!((b.seq, &b.reason), (3, &BreakReason::Unlinked));

        let mut gap = c.clone();
        gap.remove(1);
        let b = verify(&gap, head).unwrap_err();
        assert_eq!((b.seq, &b.reason), (2, &BreakReason::Missing));

        let b = verify(&c[..3], head).unwrap_err();
        assert_eq!((b.seq, &b.reason), (4, &BreakReason::Missing));

        let b = verify(&c, Some((4, [9; 32]))).unwrap_err();
        assert_eq!(
            (b.seq, &b.reason),
            (4, &BreakReason::HeadMismatch { head_seq: 4 })
        );
        let b = verify(&c, Some((3, c[2].hash))).unwrap_err();
        assert_eq!(
            (b.seq, &b.reason),
            (4, &BreakReason::HeadMismatch { head_seq: 3 })
        );

        let b = verify(&c, None).unwrap_err();
        assert_eq!((b.seq, &b.reason), (4, &BreakReason::NoHead));
        assert!(b.to_string().contains("no head"));
    }

    #[test]
    fn hash_layout_is_stable() {
        // Changing the layout invalidates every stored chain; this pins it.
        let e = entry(1, GENESIS);
        let mut h = Sha256::new();
        h.update(b"relink-audit-v1");
        h.update([0u8; 32]);
        h.update(7i64.to_be_bytes());
        h.update(1i64.to_be_bytes());
        h.update(1_790_000_000_123_456i64.to_be_bytes());
        for s in [
            "alice",
            "key:3",
            "link.update",
            "link:9",
            r#"{"enabled": true}"#,
            r#"{"enabled": false}"#,
        ] {
            h.update([1u8]);
            h.update((s.len() as u32).to_be_bytes());
            h.update(s.as_bytes());
        }
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(e.hash, want);
    }

    #[test]
    fn anchors_parse() {
        let hex = "ab".repeat(32);
        assert_eq!(
            Anchor::parse(&format!("3:12:{hex}")).unwrap(),
            Anchor {
                workspace_id: 3,
                seq: 12,
                hash: [0xab; 32]
            }
        );
        for bad in [
            String::new(),
            "3:12".into(),
            format!("3:12:{hex}:1"),
            format!("0:12:{hex}"),
            format!("3:-1:{hex}"),
            format!("x:1:{hex}"),
            "3:12:abcd".into(),
            format!("3:12:{}", "zz".repeat(32)),
        ] {
            assert!(Anchor::parse(&bad).is_err(), "{bad:?}");
        }
        let head = ChainHead {
            workspace_id: 3,
            seq: 12,
            hash: [0xab; 32],
        };
        assert_eq!(Anchor::parse(&head.to_string()).unwrap().hash, head.hash);
    }

    #[test]
    fn actors_and_actions_render() {
        assert_eq!(Via::Key(3).to_string(), "key:3");
        assert_eq!(Via::Session(4).to_string(), "session:4");
        assert_eq!(Actor::cli().via.to_string(), "cli");
        assert_eq!(Actor::system().via.to_string(), "system");
        assert_eq!(Actor::session("bob", 2).member.as_deref(), Some("bob"));
        let p = Principal {
            credential: Credential::ApiKey(5),
            owner: "alice".into(),
            workspace_id: 1,
            role: crate::auth::Role::Editor,
            scopes: crate::auth::Scopes::ALL,
            expires_at: None,
        };
        assert_eq!(
            Actor::from(&p),
            Actor {
                member: Some("alice".into()),
                via: Via::Key(5)
            }
        );
        for a in [
            Action::LinkCreate,
            Action::LinkUpdate,
            Action::LinkDelete,
            Action::KeyCreate,
            Action::KeyRotate,
            Action::KeyRevoke,
            Action::WorkspaceCreate,
            Action::WorkspacePlan,
            Action::UserCreate,
            Action::UserSignIn,
            Action::SessionEnd,
            Action::InvitationCreate,
            Action::InvitationAccept,
            Action::InvitationRevoke,
            Action::DomainCreate,
            Action::DomainVerify,
            Action::DomainDelete,
        ] {
            let s = a.as_str();
            let (noun, verb) = s.split_once('.').unwrap();
            assert!(noun.bytes().all(|b| b.is_ascii_lowercase()), "{s}");
            assert!(
                verb.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s}"
            );
        }
    }
}
