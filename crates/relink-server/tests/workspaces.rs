//! Week 1 end to end: a team workspace used the way a team would use it,
//! through the real sign-in flow, the HTTP API and the `relink` binary.
//! People sign in with OpenID Connect, the owner invites an editor by email
//! and a viewer by member name, each acts with their role, scoped and
//! expiring API keys are made and rotated from the command line, a plan
//! limits links and monthly clicks, Postgres row-level security hides every
//! row from a query without a workspace, and every change is in the
//! workspace's audit chain, which the binary verifies.

mod common;
#[path = "common/idp.rs"]
mod idp;

use std::process::Command;
use std::time::Duration;

use common::eventually;
use idp::{Idp, me, sign_in, start, with_session};
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::{Connection, Row};

const BIN: &str = env!("CARGO_BIN_EXE_relink");

/// Runs the binary against `db_url` and returns its stdout; panics with its
/// stderr if it fails.
fn relink(db_url: &str, args: &[&str]) -> String {
    let out = run(db_url, args);
    assert!(
        out.status.success(),
        "relink {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn run(db_url: &str, args: &[&str]) -> std::process::Output {
    let mut c = Command::new(BIN);
    c.env_clear();
    if let Ok(v) = std::env::var("LLVM_PROFILE_FILE") {
        c.env("LLVM_PROFILE_FILE", v);
    }
    c.args(args)
        .env("RELINK_DATABASE_URL", db_url)
        .env("RELINK_LOG", "warn")
        .output()
        .unwrap()
}

/// The value of `name=` in a line of `name=value` words.
fn field(line: &str, name: &str) -> String {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("{name} missing from {line}"))
        .to_owned()
}

/// A signed-in person: their session cookie, CSRF token and member name.
struct Person {
    session: String,
    csrf: String,
    member: String,
}

async fn person(h: &common::Harness, idp: &Idp, claims: Value) -> Person {
    let session = sign_in(h, idp, claims).await;
    let (status, body) = me(h, &session).await;
    assert_eq!(status, 200, "{body}");
    Person {
        csrf: body["csrf_token"].as_str().unwrap().to_owned(),
        member: body["user"]["member"].as_str().unwrap().to_owned(),
        session,
    }
}

/// A request as `who` in workspace `ws`, with their CSRF token.
async fn act(
    h: &common::Harness,
    who: &Person,
    method: Method,
    path: &str,
    ws: Option<i64>,
    body: Option<Value>,
) -> (u16, Value) {
    let ws = ws.map(|w| w.to_string());
    with_session(
        h,
        method,
        path,
        &who.session,
        Some(&who.csrf),
        ws.as_deref(),
        body,
    )
    .await
}

fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_team_workspace_end_to_end() {
    let idp = Idp::start().await;
    let Some(mut h) = start(&idp, &[]).await else {
        return;
    };
    let db = h.db.url.clone();

    // 1. Three people sign in through the provider. Each gets a personal
    // workspace they own; Ada's becomes the team's.
    let ada = person(
        &h,
        &idp,
        json!({"sub": "ada-1", "email": "ada@example.com", "email_verified": true,
               "preferred_username": "ada"}),
    )
    .await;
    let grace = person(
        &h,
        &idp,
        json!({"sub": "grace-1", "email": "grace@example.com", "email_verified": true,
               "preferred_username": "grace"}),
    )
    .await;
    let linus = person(
        &h,
        &idp,
        json!({"sub": "linus-1", "email": "linus@example.com", "email_verified": true,
               "preferred_username": "linus"}),
    )
    .await;
    let (_, me_ada) = me(&h, &ada.session).await;
    assert_eq!(me_ada["workspaces"].as_array().unwrap().len(), 1);
    assert_eq!(me_ada["workspaces"][0]["role"], "owner");
    let ws = me_ada["workspaces"][0]["id"].as_i64().unwrap();

    let (status, body) = act(
        &h,
        &ada,
        Method::POST,
        "/v1/links",
        None,
        Some(json!({"url": "https://example.com/launch", "alias": "team-launch"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");

    // Strangers cannot reach the workspace.
    let (status, body) = act(&h, &grace, Method::GET, "/v1/links", Some(ws), None).await;
    assert_eq!((status, code(&body)), (403, "permission_denied"), "{body}");

    // 2. Ada invites Grace by email as an editor and Linus by member name
    // as a viewer; each accepts their own link.
    let (status, by_email) = act(
        &h,
        &ada,
        Method::POST,
        "/v1/invitations",
        Some(ws),
        Some(json!({"email": "grace@example.com", "role": "editor"})),
    )
    .await;
    assert_eq!(status, 201, "{by_email}");
    let (status, by_name) = act(
        &h,
        &ada,
        Method::POST,
        "/v1/invitations",
        Some(ws),
        Some(json!({"member": linus.member, "role": "viewer"})),
    )
    .await;
    assert_eq!(status, 201, "{by_name}");
    let grace_link = format!("/v1/invites/{}/accept", by_email["token"].as_str().unwrap());
    let linus_link = format!("/v1/invites/{}/accept", by_name["token"].as_str().unwrap());

    // Only the person invited can use a link.
    let (status, _) = act(&h, &linus, Method::POST, &grace_link, None, None).await;
    assert_eq!(status, 403);
    let (status, body) = act(&h, &grace, Method::POST, &grace_link, None, None).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = act(&h, &linus, Method::POST, &linus_link, None, None).await;
    assert_eq!(status, 200, "{body}");
    // Once.
    let (status, _) = act(&h, &grace, Method::POST, &grace_link, None, None).await;
    assert_ne!(status, 200);
    let (_, me_grace) = me(&h, &grace.session).await;
    let team = me_grace["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["id"] == ws)
        .expect("grace is in the team workspace");
    assert_eq!(team["role"], "editor");

    // 3. Each acts with their role. Grace edits; Linus reads.
    let (status, body) = act(
        &h,
        &grace,
        Method::POST,
        "/v1/links",
        Some(ws),
        Some(json!({"url": "https://example.com/docs", "alias": "team-docs"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = act(
        &h,
        &linus,
        Method::POST,
        "/v1/links",
        Some(ws),
        Some(json!({"url": "https://example.com/nope"})),
    )
    .await;
    assert_eq!((status, code(&body)), (403, "permission_denied"), "{body}");
    let (status, body) = act(&h, &linus, Method::GET, "/v1/links", Some(ws), None).await;
    assert_eq!(status, 200, "{body}");
    let mut aliases: Vec<&str> = body["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["code"].as_str().unwrap())
        .collect();
    aliases.sort();
    assert_eq!(aliases, ["team-docs", "team-launch"]);
    let (status, _) = act(
        &h,
        &linus,
        Method::GET,
        "/v1/links/team-docs/stats",
        Some(ws),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = act(
        &h,
        &linus,
        Method::POST,
        "/v1/invitations",
        Some(ws),
        Some(json!({"email": "x@example.com", "role": "viewer"})),
    )
    .await;
    assert_eq!(status, 403, "viewers cannot invite");
    // A write without the CSRF token is refused even for the owner.
    let (status, _) = with_session(
        &h,
        Method::DELETE,
        "/v1/links/team-docs",
        &ada.session,
        None,
        Some(&ws.to_string()),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // 4. API keys carry scopes and expiry, and are bounded by the role.
    let ws_arg = ws.to_string();
    let line = relink(
        &db,
        &[
            "create-key",
            &ada.member,
            "dashboard",
            "--workspace",
            &ws_arg,
            "--scopes",
            "links:read,stats:read",
        ],
    );
    let read_key = field(&line, "key");
    let read_id = field(&line, "id");
    let (status, body) = h.api(Method::GET, "/v1/links", &read_key, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["links"].as_array().unwrap().len(), 2);
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &read_key,
            Some(json!({"url": "https://example.com/k"})),
        )
        .await;
    assert_eq!((status, code(&body)), (403, "permission_denied"), "{body}");
    // A viewer's key cannot be given a scope the viewer lacks.
    let out = run(
        &db,
        &[
            "create-key",
            &linus.member,
            "--workspace",
            &ws_arg,
            "--scopes",
            "links:write",
        ],
    );
    assert!(!out.status.success());
    // Rotation: both keys work during the overlap.
    let line = relink(&db, &["rotate-key", &read_id, "--overlap", "1h"]);
    let rotated = field(&line, "key");
    for key in [&read_key, &rotated] {
        let (status, _) = h.api(Method::GET, "/v1/usage", key, None).await;
        assert_eq!(status, 200);
    }
    // Expiry is exact, even for a key the server has cached.
    let line = relink(
        &db,
        &[
            "create-key",
            &grace.member,
            "--workspace",
            &ws_arg,
            "--expires-in",
            "2s",
        ],
    );
    let short = field(&line, "key");
    let (status, _) = h.api(Method::GET, "/v1/links", &short, None).await;
    assert_eq!(status, 200);
    assert!(
        eventually(Duration::from_secs(5), || async {
            h.api(Method::GET, "/v1/links", &short, None).await.0 == 401
        })
        .await,
        "an expired key still works"
    );

    // 5. A plan limits links and monthly clicks; redirects are never refused.
    relink(
        &db,
        &["plan-set", "team", "--links", "3", "--monthly-clicks", "4"],
    );
    let line = relink(&db, &["plan-assign", &ws_arg, "team"]);
    assert_eq!(field(&line, "previous"), "unlimited");
    let third = json!({"url": "https://example.com/three", "alias": "team-three"});
    let (status, body) = act(&h, &grace, Method::POST, "/v1/links", Some(ws), Some(third)).await;
    assert_eq!(status, 201, "{body}");
    let (status, body) = act(
        &h,
        &grace,
        Method::POST,
        "/v1/links",
        Some(ws),
        Some(json!({"url": "https://example.com/four"})),
    )
    .await;
    assert_eq!((status, code(&body)), (403, "quota_exceeded"), "{body}");
    for _ in 0..5 {
        assert_eq!(h.visit("team-launch", &[]).await.status(), 302);
    }
    assert!(
        eventually(Duration::from_secs(5), || async {
            let (_, u) = h.api(Method::GET, "/v1/usage", &rotated, None).await;
            u["clicks"]["used"] == 5
        })
        .await,
        "clicks were not metered"
    );
    let (_, usage) = h.api(Method::GET, "/v1/usage", &rotated, None).await;
    assert_eq!(usage["plan"], "team");
    assert_eq!(usage["links"], json!({"used": 3, "limit": 3}));
    assert_eq!(usage["clicks"]["limit"], 4);
    // Over the click limit, a freed link slot still cannot be used.
    let (status, _) = act(
        &h,
        &ada,
        Method::DELETE,
        "/v1/links/team-three",
        Some(ws),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, body) = act(
        &h,
        &ada,
        Method::POST,
        "/v1/links",
        Some(ws),
        Some(json!({"url": "https://example.com/five"})),
    )
    .await;
    assert_eq!((status, code(&body)), (403, "quota_exceeded"), "{body}");
    assert!(body["error"]["message"].as_str().unwrap().contains("click"));
    assert_eq!(h.visit("team-launch", &[]).await.status(), 302);

    // 6. Row-level security: the tenant role sees nothing without a
    // workspace, and only the named workspace's rows with one.
    let mut conn = sqlx::PgConnection::connect(&db).await.unwrap();
    let tables = [
        "workspaces",
        "workspace_members",
        "links",
        "api_keys",
        "click_daily",
        "audit_log",
        "invitations",
        "workspace_usage",
    ];
    let mut tx = conn.begin().await.unwrap();
    sqlx::raw_sql("SET LOCAL ROLE relink_tenant")
        .execute(&mut *tx)
        .await
        .unwrap();
    for t in tables {
        let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {t}")))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(n, 0, "{t} is visible without a workspace");
    }
    tx.rollback().await.unwrap();
    let grace_ws: i64 = sqlx::query_scalar("SELECT id FROM workspaces WHERE personal_owner = $1")
        .bind(&grace.member)
        .fetch_one(&mut conn)
        .await
        .unwrap();
    let mut tx = h.store.begin_tenant(grace_ws).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM links")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 0, "Grace's own workspace does not see the team's links");
    tx.rollback().await.unwrap();
    let mut tx = h.store.begin_tenant(ws).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM links")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(n, 2);
    tx.rollback().await.unwrap();

    // 7. Every change is in the team's audit chain, attributed to whoever
    // made it, and the chain verifies.
    let rows = sqlx::query(
        "SELECT seq, actor, via, action, target FROM audit_log \
          WHERE workspace_id = $1 ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(&mut conn)
    .await
    .unwrap();
    let log: Vec<(String, String, String)> = rows
        .iter()
        .map(|r| {
            (
                r.get::<Option<String>, _>("actor").unwrap_or_default(),
                r.get::<String, _>("via")
                    .split(':')
                    .next()
                    .unwrap()
                    .to_owned(),
                r.get("action"),
            )
        })
        .collect();
    let seqs: Vec<i64> = rows.iter().map(|r| r.get("seq")).collect();
    assert_eq!(seqs, (1..=rows.len() as i64).collect::<Vec<_>>(), "no gaps");
    let expect = |actor: &str, via: &str, action: &str| {
        assert!(
            log.iter()
                .any(|(a, v, x)| a == actor && v == via && x == action),
            "{actor} {via} {action} missing from {log:?}"
        );
    };
    expect(&ada.member, "session", "link.create");
    expect(&ada.member, "session", "invitation.create");
    expect(&grace.member, "session", "invitation.accept");
    expect(&linus.member, "session", "invitation.accept");
    expect(&grace.member, "session", "link.create");
    expect(&ada.member, "session", "link.delete");
    expect("", "cli", "key.create");
    expect("", "cli", "key.rotate");
    expect("", "cli", "workspace.plan");
    // Refused creates (the viewer's, and those over the plan) leave no entry.
    let creates = log.iter().filter(|(_, _, x)| x == "link.create").count();
    assert_eq!(creates, 3, "{log:?}");
    let text = relink(&db, &["audit-verify", "--workspace", &ws_arg]);
    let head = text.lines().next().unwrap();
    assert_eq!(head.split(':').nth(1).unwrap(), rows.len().to_string());
    relink(&db, &["audit-verify", "--anchors", head]);
    // Five chains: the team's, Grace's and Linus's personal workspaces, and
    // the harness's two key owners.
    let all = relink(&db, &["audit-verify"]);
    assert!(all.contains("verified 5 audit chain(s)"), "{all}");

    // 8. Signing out ends the session at once.
    let (status, _) = act(&h, &linus, Method::POST, "/v1/auth/logout", None, None).await;
    assert_eq!(status, 204);
    let (status, _) = act(&h, &linus, Method::GET, "/v1/links", Some(ws), None).await;
    assert_eq!(status, 401);

    h.shutdown().await;
}
