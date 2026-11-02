//! People and their sessions: the Postgres side of sign-in ([`crate::oidc`]),
//! the session cookie, CSRF tokens and the `/v1/auth/session` and
//! `/v1/auth/logout` endpoints.
//!
//! A session is a random cookie (`rls_` and 64 hex characters, HttpOnly,
//! SameSite=Lax, scoped to `/v1`) of which only the SHA-256 is stored, like
//! an API key. It expires at a fixed time (`RELINK_SESSION_TTL_S`). Each
//! session has its own CSRF token, returned by `GET /v1/auth/session`; a
//! request authenticated by the cookie that could change anything (any
//! method but GET, HEAD and OPTIONS) must send it in `X-CSRF-Token`, so
//! another site cannot make a signed-in browser act. Requests with an API
//! key carry no cookie authority and need no token.
//!
//! A person acts in a workspace with the rights of their role there
//! ([`crate::auth::Role`]): the workspace named in `Relink-Workspace`, or
//! their personal workspace without the header.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::api::{ApiError, json};
use crate::auth::{AuthError, Credential, Role, is_valid_owner};
use crate::oidc::IdClaims;
use crate::server::App;
use crate::store::{Db, DbError};
use crate::util::{hex_encode, secure_random};

/// The session cookie.
pub const SESSION_COOKIE: &str = "relink_session";
/// Its path: the API, not redirects, so `GET /{code}` never carries it.
pub const SESSION_COOKIE_PATH: &str = "/v1";
/// The cookie holding a sign-in's `state` between login and callback.
pub const LOGIN_COOKIE: &str = "relink_login";
pub const LOGIN_COOKIE_PATH: &str = "/v1/auth";
/// The request header carrying the session's CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

const SESSION_PREFIX: &str = "rls_";

/// A new session token from the OS CSPRNG.
pub fn generate_session_token() -> String {
    let mut b = [0u8; 32];
    secure_random(&mut b);
    format!("{SESSION_PREFIX}{}", hex_encode(&b))
}

/// Shape check before any database work.
pub fn is_well_formed_session(token: &str) -> bool {
    token.strip_prefix(SESSION_PREFIX).is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

pub fn hash_session(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// A `Set-Cookie` value. `value` must be cookie-safe (ours are base64url or
/// hex); `max_age` of `None` makes a cookie that ends with the browser.
pub fn cookie(
    name: &str,
    value: &str,
    path: &str,
    max_age: Option<Duration>,
    secure: bool,
) -> HeaderValue {
    let mut c = format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax");
    if let Some(age) = max_age {
        c.push_str(&format!("; Max-Age={}", age.as_secs()));
    }
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).expect("cookie names, values and paths are header-safe")
}

/// A `Set-Cookie` value that deletes the cookie.
pub fn clear_cookie(name: &str, path: &str, secure: bool) -> HeaderValue {
    cookie(name, "", path, Some(Duration::ZERO), secure)
}

/// The value of the first cookie called `name` across all `Cookie` headers.
pub fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim_matches('"'))
}

/// Whether a request with this method needs the CSRF token when it is
/// authenticated by the session cookie.
pub fn needs_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Turns claims into a member name: the preferred username, else the local
/// part of the email address, else the display name, lowercased, with
/// anything outside `[a-z0-9._-]` replaced, at most 40 characters, starting
/// with a letter or digit. Collisions are resolved by [`Db::sign_in_user`].
pub fn member_base(claims: &IdClaims) -> String {
    let source = claims
        .preferred_username
        .as_deref()
        .or_else(|| claims.email.as_deref().and_then(|e| e.split('@').next()))
        .or(claims.name.as_deref())
        .unwrap_or("");
    let mut out = String::new();
    for c in source.chars().flat_map(char::to_lowercase) {
        let c = match c {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            c if c.is_whitespace() => '-',
            _ => continue,
        };
        if out.is_empty() && !c.is_ascii_alphanumeric() {
            continue;
        }
        out.push(c);
        if out.len() == 40 {
            break;
        }
    }
    if out.is_empty() { "user".into() } else { out }
}

/// A sign-in waiting for the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingLogin {
    pub nonce: String,
    pub code_verifier: String,
    pub return_to: String,
}

/// Who signed in.
pub struct NewUser<'a> {
    pub issuer: &'a str,
    pub claims: &'a IdClaims,
}

/// The person behind a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedInUser {
    pub id: i64,
    pub member: String,
    /// Whether this sign-in created them.
    pub created: bool,
}

/// A live session and its person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub user_id: i64,
    pub member: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

/// One workspace a person belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Membership {
    pub id: i64,
    pub name: String,
    pub role: &'static str,
}

/// Most candidate names tried with a counter before a random suffix.
const NAME_ATTEMPTS: u32 = 20;

impl Db {
    /// Stores a sign-in in progress.
    pub async fn insert_login(
        &self,
        state_hash: &[u8; 32],
        nonce: &str,
        code_verifier: &str,
        return_to: &str,
        ttl: Duration,
    ) -> Result<(), DbError> {
        self.timed(
            sqlx::query(
                "INSERT INTO oidc_logins (state_hash, nonce, code_verifier, return_to, expires_at) \
                 VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))",
            )
            .bind(&state_hash[..])
            .bind(nonce)
            .bind(code_verifier)
            .bind(return_to)
            .bind(ttl.as_secs_f64())
            .execute(self.pool()),
        )
        .await
        .map(|_| ())
    }

    /// Takes a sign-in in progress: returns it and deletes it, so a `state`
    /// completes at most once. Expired sign-ins are not returned.
    pub async fn take_login(&self, state_hash: &[u8; 32]) -> Result<Option<PendingLogin>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "DELETE FROM oidc_logins WHERE state_hash = $1 \
                     RETURNING nonce, code_verifier, return_to, expires_at > now() AS live",
                )
                .bind(&state_hash[..])
                .fetch_optional(self.pool()),
            )
            .await?;
        let Some(r) = row else { return Ok(None) };
        if !r.try_get::<bool, _>("live").map_err(DbError::from)? {
            return Ok(None);
        }
        Ok(Some(PendingLogin {
            nonce: r.try_get("nonce").map_err(DbError::from)?,
            code_verifier: r.try_get("code_verifier").map_err(DbError::from)?,
            return_to: r.try_get("return_to").map_err(DbError::from)?,
        }))
    }

    /// Finds the person with this identity, refreshing their email address
    /// and name, or creates them with a member name of their own and a
    /// personal workspace they own.
    ///
    /// A new member name never matches an existing member, API key owner,
    /// link creator or personal workspace: otherwise whoever registers
    /// `alice` at the provider would inherit alice's memberships.
    pub async fn sign_in_user(&self, new: &NewUser<'_>) -> Result<SignedInUser, DbError> {
        let c = new.claims;
        self.timed(async {
            let mut tx = self.pool().begin().await?;
            let existing = sqlx::query(
                "UPDATE users SET email = $3, display_name = $4, last_login_at = now() \
                  WHERE issuer = $1 AND subject = $2 RETURNING id, member",
            )
            .bind(new.issuer)
            .bind(&c.subject)
            .bind(&c.email)
            .bind(&c.name)
            .fetch_optional(&mut *tx)
            .await?;
            let user = match existing {
                Some(r) => SignedInUser {
                    id: r.try_get("id")?,
                    member: r.try_get("member")?,
                    created: false,
                },
                None => {
                    let base = member_base(c);
                    let mut user = None;
                    for attempt in 0..=NAME_ATTEMPTS {
                        let member = match attempt {
                            0 => base.clone(),
                            n if n < NAME_ATTEMPTS => format!("{base}-{}", n + 1),
                            _ => {
                                let mut b = [0u8; 4];
                                secure_random(&mut b);
                                format!("{base}-{}", hex_encode(&b))
                            }
                        };
                        debug_assert!(is_valid_owner(&member));
                        // Nothing is inserted when the name is taken,
                        // including by a concurrent sign-in, or when this
                        // same person's first sign-in in another tab just
                        // committed; the latter is picked up below.
                        let id: Option<i64> = sqlx::query_scalar(
                            "INSERT INTO users (issuer, subject, member, email, display_name) \
                             SELECT $1, $2, $3, $4, $5 \
                              WHERE NOT EXISTS (SELECT 1 FROM workspace_members WHERE member = $3) \
                                AND NOT EXISTS (SELECT 1 FROM api_keys WHERE owner = $3) \
                                AND NOT EXISTS (SELECT 1 FROM links WHERE owner = $3) \
                                AND NOT EXISTS (SELECT 1 FROM workspaces WHERE personal_owner = $3) \
                             ON CONFLICT DO NOTHING RETURNING id",
                        )
                        .bind(new.issuer)
                        .bind(&c.subject)
                        .bind(&member)
                        .bind(&c.email)
                        .bind(&c.name)
                        .fetch_optional(&mut *tx)
                        .await?;
                        if let Some(id) = id {
                            user = Some(SignedInUser {
                                id,
                                member,
                                created: true,
                            });
                            break;
                        }
                        let raced = sqlx::query(
                            "SELECT id, member FROM users WHERE issuer = $1 AND subject = $2",
                        )
                        .bind(new.issuer)
                        .bind(&c.subject)
                        .fetch_optional(&mut *tx)
                        .await?;
                        if let Some(r) = raced {
                            user = Some(SignedInUser {
                                id: r.try_get("id")?,
                                member: r.try_get("member")?,
                                created: false,
                            });
                            break;
                        }
                    }
                    user.ok_or_else(|| {
                        sqlx::Error::Protocol("no free member name for this person".into())
                    })?
                }
            };
            crate::store::personal_workspace(&mut tx, &user.member).await?;
            tx.commit().await?;
            Ok(user)
        })
        .await
    }

    /// Starts a session for `user_id`. Returns the cookie value (shown only
    /// now; only its hash is kept) and the CSRF token.
    pub async fn create_session(
        &self,
        user_id: i64,
        ttl: Duration,
    ) -> Result<(String, String), DbError> {
        let token = generate_session_token();
        let mut csrf = [0u8; 32];
        secure_random(&mut csrf);
        let csrf = hex_encode(&csrf);
        self.timed(
            sqlx::query(
                "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) \
                 VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
            )
            .bind(&hash_session(&token)[..])
            .bind(user_id)
            .bind(&csrf)
            .bind(ttl.as_secs_f64())
            .execute(self.pool()),
        )
        .await?;
        Ok((token, csrf))
    }

    /// The live session with this hash, with its person.
    pub async fn session_by_hash(&self, hash: &[u8; 32]) -> Result<Option<SessionRow>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT s.user_id, u.member, u.email, u.display_name, s.csrf_token, s.expires_at \
                       FROM sessions s JOIN users u ON u.id = s.user_id \
                      WHERE s.token_hash = $1 AND s.expires_at > now()",
                )
                .bind(&hash[..])
                .fetch_optional(self.pool()),
            )
            .await?;
        row.map(|r| {
            Ok(SessionRow {
                user_id: r.try_get("user_id")?,
                member: r.try_get("member")?,
                email: r.try_get("email")?,
                display_name: r.try_get("display_name")?,
                csrf_token: r.try_get("csrf_token")?,
                expires_at: r.try_get("expires_at")?,
            })
        })
        .transpose()
        .map_err(|e: sqlx::Error| DbError::from(e))
    }

    /// Ends a session. Returns false if there was none.
    pub async fn delete_session(&self, hash: &[u8; 32]) -> Result<bool, DbError> {
        self.timed(
            sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
                .bind(&hash[..])
                .execute(self.pool()),
        )
        .await
        .map(|r| r.rows_affected() == 1)
    }

    /// `member`'s role in `workspace_id`, or in their personal workspace
    /// when `None`, with that workspace's ID; `None` if they are not a
    /// member. One primary-key probe.
    pub async fn member_role(
        &self,
        member: &str,
        workspace_id: Option<i64>,
    ) -> Result<Option<(i64, Role)>, DbError> {
        let row = self
            .timed(
                sqlx::query(
                    "SELECT m.workspace_id, m.role FROM workspace_members m \
                      WHERE m.member = $1 AND m.workspace_id = \
                            COALESCE($2, (SELECT id FROM workspaces WHERE personal_owner = $1))",
                )
                .bind(member)
                .bind(workspace_id)
                .fetch_optional(self.pool()),
            )
            .await?;
        row.map(|r| {
            let role: String = r.try_get("role")?;
            let role = Role::parse(&role)
                .ok_or_else(|| sqlx::Error::Decode(format!("unknown role {role:?}").into()))?;
            Ok((r.try_get("workspace_id")?, role))
        })
        .transpose()
        .map_err(|e: sqlx::Error| DbError::from(e))
    }

    /// The workspaces `member` belongs to, oldest first.
    pub async fn memberships(&self, member: &str) -> Result<Vec<Membership>, DbError> {
        let rows = self
            .timed(
                sqlx::query(
                    "SELECT w.id, w.name, m.role FROM workspace_members m \
                       JOIN workspaces w ON w.id = m.workspace_id \
                      WHERE m.member = $1 ORDER BY w.id LIMIT 1000",
                )
                .bind(member)
                .fetch_all(self.pool()),
            )
            .await?;
        rows.iter()
            .map(|r| {
                let role: String = r.try_get("role")?;
                let role = Role::parse(&role)
                    .ok_or_else(|| sqlx::Error::Decode(format!("unknown role {role:?}").into()))?;
                Ok(Membership {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    role: role.as_str(),
                })
            })
            .collect::<Result<_, sqlx::Error>>()
            .map_err(DbError::from)
    }

    /// Deletes expired sessions and abandoned sign-ins. Returns how many.
    pub async fn purge_expired_sessions(&self) -> Result<u64, DbError> {
        self.timed(async {
            let a = sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
                .execute(self.pool())
                .await?;
            let b = sqlx::query("DELETE FROM oidc_logins WHERE expires_at <= now()")
                .execute(self.pool())
                .await?;
            Ok(a.rows_affected() + b.rows_affected())
        })
        .await
    }
}

/// Maps an authentication failure to its API error.
pub fn auth_error(e: AuthError) -> ApiError {
    match e {
        AuthError::Unauthenticated => ApiError::unauthenticated(),
        AuthError::Unavailable => ApiError::unavailable(),
        AuthError::Busy => ApiError::rate_limited(1),
    }
}

/// Refuses a state-changing request whose `X-CSRF-Token` is not the
/// session's.
pub fn check_csrf(app: &App, parts: &Parts, session: &SessionRow) -> Result<(), ApiError> {
    if !needs_csrf(&parts.method) {
        return Ok(());
    }
    let sent = parts
        .headers
        .get(CSRF_HEADER)
        .map_or(&b""[..], HeaderValue::as_bytes);
    if bool::from(sent.ct_eq(session.csrf_token.as_bytes())) {
        Ok(())
    } else {
        app.metrics.csrf_rejected.inc();
        Err(ApiError::permission_denied(
            "a request made with a session cookie must send the session's CSRF token \
             (GET /v1/auth/session) in X-CSRF-Token",
        ))
    }
}

/// The session cookie checked against the database (through the auth
/// cache), with the per-session rate limit applied.
pub async fn authenticate_session(
    app: &App,
    parts: &Parts,
    token: &str,
) -> Result<Arc<SessionRow>, ApiError> {
    let client = crate::api::client_addr(app, parts);
    let session = app.auth.session(token, client).await.map_err(auth_error)?;
    if let Err(wait) = app
        .api_limiter
        .check(&Credential::Session(session.user_id), Instant::now())
    {
        app.metrics.rate_limited.inc();
        return Err(ApiError::rate_limited(
            wait.as_secs_f64().ceil().max(1.0) as u64
        ));
    }
    Ok(session)
}

/// A request signed in with the session cookie (API keys do not count),
/// with its CSRF token checked when the method needs one.
pub struct SessionAuthed {
    pub session: Arc<SessionRow>,
    pub token_hash: [u8; 32],
}

impl FromRequestParts<Arc<App>> for SessionAuthed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, ApiError> {
        let token = read_cookie(&parts.headers, SESSION_COOKIE)
            .ok_or_else(|| ApiError::unauthenticated_msg("sign in first: no session cookie"))?;
        let session = authenticate_session(app, parts, token).await?;
        check_csrf(app, parts, &session)?;
        Ok(SessionAuthed {
            session,
            token_hash: hash_session(token),
        })
    }
}

#[derive(Serialize)]
struct UserView<'a> {
    id: i64,
    member: &'a str,
    email: Option<&'a str>,
    name: Option<&'a str>,
}

#[derive(Serialize)]
struct SessionView<'a> {
    user: UserView<'a>,
    csrf_token: &'a str,
    expires_at: DateTime<Utc>,
    workspaces: Vec<Membership>,
}

/// `GET /v1/auth/session`: who is signed in, their CSRF token and their
/// workspaces.
pub async fn get_session(
    State(app): State<Arc<App>>,
    SessionAuthed { session: s, .. }: SessionAuthed,
) -> Result<Response, ApiError> {
    let workspaces = app.db.memberships(&s.member).await?;
    let mut resp = json(
        StatusCode::OK,
        &SessionView {
            user: UserView {
                id: s.user_id,
                member: &s.member,
                email: s.email.as_deref(),
                name: s.display_name.as_deref(),
            },
            csrf_token: &s.csrf_token,
            expires_at: s.expires_at,
            workspaces,
        },
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(resp)
}

/// `POST /v1/auth/logout`: ends the session and deletes the cookie.
pub async fn logout(
    State(app): State<Arc<App>>,
    authed: SessionAuthed,
) -> Result<Response, ApiError> {
    app.db.delete_session(&authed.token_hash).await?;
    app.auth.forget_session(&authed.token_hash);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        clear_cookie(SESSION_COOKIE, SESSION_COOKIE_PATH, app.cfg.cookie_secure),
    );
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(username: Option<&str>, email: Option<&str>, name: Option<&str>) -> IdClaims {
        IdClaims {
            subject: "1".into(),
            email: email.map(Into::into),
            email_verified: true,
            name: name.map(Into::into),
            preferred_username: username.map(Into::into),
        }
    }

    #[test]
    fn member_names() {
        let cases = [
            (claims(Some("Ada.Lovelace"), None, None), "ada.lovelace"),
            (
                claims(None, Some("ada+relink@example.com"), None),
                "adarelink",
            ),
            (claims(None, None, Some("Ada Lovelace")), "ada-lovelace"),
            (claims(None, None, Some("Ünïcode Ñame")), "ncode-ame"),
            (claims(Some("__x"), None, None), "x"),
            (claims(Some("日本"), None, None), "user"),
            (claims(None, None, None), "user"),
            (claims(Some(&"a".repeat(100)), None, None), &"a".repeat(40)),
        ];
        for (c, want) in cases {
            let got = member_base(&c);
            assert_eq!(got, want, "{c:?}");
            assert!(is_valid_owner(&got));
            assert!(is_valid_owner(&format!("{got}-{}", "f".repeat(8))));
        }
    }

    #[test]
    fn session_tokens() {
        let t = generate_session_token();
        assert!(is_well_formed_session(&t));
        assert_ne!(t, generate_session_token());
        assert!(!is_well_formed_session("rls_short"));
        assert!(!is_well_formed_session(&t.to_uppercase()));
        assert!(!is_well_formed_session(&t.replace("rls_", "rlk_")));
        assert_eq!(hash_session(&t), hash_session(&t));
    }

    #[test]
    fn cookies() {
        let c = cookie(
            "relink_session",
            "abc",
            "/v1",
            Some(Duration::from_secs(60)),
            true,
        );
        assert_eq!(
            c,
            "relink_session=abc; Path=/v1; HttpOnly; SameSite=Lax; Max-Age=60; Secure"
        );
        assert_eq!(
            clear_cookie("relink_login", "/v1/auth", false),
            "relink_login=; Path=/v1/auth; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        assert_eq!(
            cookie("a", "b", "/", None, false),
            "a=b; Path=/; HttpOnly; SameSite=Lax"
        );
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            HeaderValue::from_static("x=1; relink_login=\"st\""),
        );
        h.append(
            header::COOKIE,
            HeaderValue::from_static("relink_session=tok; relink_session=second"),
        );
        assert_eq!(read_cookie(&h, "relink_session"), Some("tok"));
        assert_eq!(read_cookie(&h, "relink_login"), Some("st"));
        assert_eq!(read_cookie(&h, "x"), Some("1"));
        assert_eq!(read_cookie(&h, "missing"), None);
        assert_eq!(read_cookie(&HeaderMap::new(), "x"), None);
    }

    #[test]
    fn csrf_methods() {
        for m in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
            assert!(needs_csrf(&m), "{m}");
        }
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!needs_csrf(&m), "{m}");
        }
    }
}
