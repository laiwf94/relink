//! Invitations end to end: an admin invites by email or member name, the
//! one-time link is accepted once by the person invited before it expires,
//! can be revoked, and every step is in the workspace's audit chain.

mod common;

use std::time::Duration;

use common::{Harness, admin_url};
use relink_server::oidc::IdClaims;
use relink_server::session::NewUser;
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::Row;

macro_rules! harness {
    () => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000")]).await
    }};
}

const ISSUER: &str = "https://idp.example.com";

/// A signed-in person: their member name, user ID, session cookie and CSRF
/// token.
#[derive(Clone)]
struct Person {
    member: String,
    user_id: i64,
    cookie: String,
    csrf: String,
}

/// Signs `subject` in (creating them on first use) and starts a session.
async fn sign_in(h: &Harness, subject: &str, email: Option<&str>, verified: bool) -> Person {
    let claims = IdClaims {
        subject: subject.into(),
        email: email.map(Into::into),
        email_verified: verified,
        name: None,
        preferred_username: Some(subject.into()),
    };
    let user = h
        .store
        .sign_in_user(&NewUser {
            issuer: ISSUER,
            claims: &claims,
        })
        .await
        .unwrap();
    let (cookie, csrf) = h
        .store
        .create_session(user.id, Duration::from_secs(3_600))
        .await
        .unwrap();
    Person {
        member: user.member,
        user_id: user.id,
        cookie,
        csrf,
    }
}

/// A request as `who`, with the CSRF token unless `csrf` is false, acting in
/// `workspace` if given.
async fn call(
    h: &Harness,
    who: &Person,
    method: Method,
    path: &str,
    workspace: Option<i64>,
    body: Option<Value>,
    csrf: bool,
) -> (u16, Value) {
    let mut req = h
        .http
        .request(method, format!("{}{path}", h.base))
        .header("cookie", format!("relink_session={}", who.cookie));
    if csrf {
        req = req.header("x-csrf-token", &who.csrf);
    }
    if let Some(w) = workspace {
        req = req.header("relink-workspace", w.to_string());
    }
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn invite(h: &Harness, who: &Person, ws: i64, body: Value) -> (u16, Value) {
    call(
        h,
        who,
        Method::POST,
        "/v1/invitations",
        Some(ws),
        Some(body),
        true,
    )
    .await
}

/// The path of an invitation link from its `url`.
fn link_path(created: &Value) -> String {
    let url = created["url"].as_str().unwrap();
    let path = url.strip_prefix("http://localhost:8080").unwrap_or(url);
    assert!(path.starts_with("/v1/invites/rli_"), "{url}");
    assert_eq!(
        &path["/v1/invites/".len()..],
        created["token"].as_str().unwrap()
    );
    path.to_owned()
}

async fn accept(h: &Harness, who: &Person, path: &str) -> (u16, Value) {
    call(
        h,
        who,
        Method::POST,
        &format!("{path}/accept"),
        None,
        None,
        true,
    )
    .await
}

async fn role_of(h: &Harness, ws: i64, member: &str) -> Option<String> {
    sqlx::query_scalar("SELECT role FROM workspace_members WHERE workspace_id = $1 AND member = $2")
        .bind(ws)
        .bind(member)
        .fetch_optional(h.store.pool())
        .await
        .unwrap()
}

/// The audit entries of `ws` with `action`, oldest first: (actor, target,
/// before, after).
async fn audited(
    h: &Harness,
    ws: i64,
    action: &str,
) -> Vec<(Option<String>, String, Value, Value)> {
    sqlx::query(
        "SELECT actor, target, before, after FROM audit_log \
          WHERE workspace_id = $1 AND action = $2 ORDER BY seq",
    )
    .bind(ws)
    .bind(action)
    .fetch_all(h.store.pool())
    .await
    .unwrap()
    .iter()
    .map(|r| {
        (
            r.get("actor"),
            r.get("target"),
            r.get::<Option<Value>, _>("before").unwrap_or(Value::Null),
            r.get::<Option<Value>, _>("after").unwrap_or(Value::Null),
        )
    })
    .collect()
}

fn message(body: &Value) -> &str {
    body["error"]["message"].as_str().unwrap_or("")
}

#[tokio::test]
async fn invite_by_email_accepted_once_by_the_person_invited() {
    let mut h = harness!();
    let ada = sign_in(&h, "ada", Some("ada@example.com"), true).await;
    let ws = h.store.personal_workspace(&ada.member).await.unwrap();
    h.create(json!({"url": "https://example.com/", "alias": "not-theirs"}))
        .await;

    // An API key cannot invite, whatever its owner's role.
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/invitations",
            &h.alice,
            Some(json!({"email": "carol@example.com", "role": "editor"})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert!(message(&body).contains("API keys"), "{body}");
    // Nor can a session without its CSRF token.
    let (status, _) = call(
        &h,
        &ada,
        Method::POST,
        "/v1/invitations",
        Some(ws),
        Some(json!({"email": "carol@example.com", "role": "editor"})),
        false,
    )
    .await;
    assert_eq!(status, 403);
    // Bad requests are refused before anything is stored.
    for (bad, want) in [
        (json!({"role": "editor"}), "exactly one"),
        (json!({"email": "carol", "role": "editor"}), "not an email"),
        (
            json!({"email": "c@example.com", "member": "c", "role": "editor"}),
            "exactly one",
        ),
        (
            json!({"email": "c@example.com", "role": "boss"}),
            "role must be",
        ),
        (
            json!({"email": "c@example.com", "role": "editor", "expires_in": "90d"}),
            "30d",
        ),
        (
            json!({"email": "c@example.com", "role": "editor", "extra": 1}),
            "unknown field",
        ),
    ] {
        let (status, body) = invite(&h, &ada, ws, bad.clone()).await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert!(message(&body).contains(want), "{bad}: {body}");
    }

    let (status, created) = invite(
        &h,
        &ada,
        ws,
        json!({"email": "Carol@Example.com", "role": "editor", "expires_in": "2d"}),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["email"], "carol@example.com");
    assert_eq!(created["role"], "editor");
    assert_eq!(created["status"], "pending");
    assert_eq!(created["invited_by"], ada.member.as_str());
    let path = link_path(&created);
    // Only the hash is kept.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM invitations WHERE id = $1")
        .bind(created["id"].as_i64().unwrap())
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(
        stored,
        relink_server::invite::hash_invite(created["token"].as_str().unwrap())
    );

    // Opening the link needs a sign-in.
    let r = h
        .http
        .get(format!("{}{path}", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Someone else holding the link can look but not join.
    let eve = sign_in(&h, "eve", Some("eve@example.com"), true).await;
    let (status, preview) = call(&h, &eve, Method::GET, &path, None, None, false).await;
    assert_eq!(status, 200, "{preview}");
    assert_eq!(preview["workspace_id"], ws);
    assert_eq!(preview["role"], "editor");
    let (status, body) = accept(&h, &eve, &path).await;
    assert_eq!(status, 403, "{body}");
    assert!(!message(&body).contains("carol"), "{body}");
    assert_eq!(role_of(&h, ws, &eve.member).await, None);

    // Carol with the right address, not verified by her provider: refused.
    let carol = sign_in(&h, "carol", Some("carol@example.com"), false).await;
    let (status, body) = accept(&h, &carol, &path).await;
    assert_eq!(status, 403, "{body}");
    assert!(message(&body).contains("not verified"), "{body}");
    // Without the CSRF token: refused before anything happens.
    let (status, _) = call(
        &h,
        &carol,
        Method::POST,
        &format!("{path}/accept"),
        None,
        None,
        false,
    )
    .await;
    assert_eq!(status, 403);
    // Not a member yet; this answer is now cached on the instance.
    let (status, _) = call(&h, &carol, Method::GET, "/v1/links", Some(ws), None, false).await;
    assert_eq!(status, 403);

    // Signed in again with the address verified: she joins, once.
    let carol = sign_in(&h, "carol", Some("carol@example.com"), true).await;
    let (status, joined) = accept(&h, &carol, &path).await;
    assert_eq!(status, 200, "{joined}");
    assert_eq!(
        joined,
        json!({"workspace_id": ws, "workspace_name": ada.member, "role": "editor"})
    );
    assert_eq!(
        role_of(&h, ws, &carol.member).await.as_deref(),
        Some("editor")
    );
    // Acting there works at once, despite the cached refusal.
    let (status, body) = call(&h, &carol, Method::GET, "/v1/links", Some(ws), None, false).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = accept(&h, &carol, &path).await;
    assert_eq!(status, 404, "{body}");
    assert!(message(&body).contains("already been accepted"), "{body}");
    let (status, _) = call(&h, &eve, Method::GET, &path, None, None, false).await;
    assert_eq!(status, 404);
    // A made-up token is just not valid.
    let (status, body) = accept(&h, &carol, &format!("/v1/invites/rli_{}", "0".repeat(64))).await;
    assert_eq!(status, 404, "{body}");
    let (status, _) = accept(&h, &carol, "/v1/invites/nonsense").await;
    assert_eq!(status, 404);

    // The list shows it accepted, and never the token.
    let (status, list) = call(
        &h,
        &ada,
        Method::GET,
        "/v1/invitations",
        Some(ws),
        None,
        false,
    )
    .await;
    assert_eq!(status, 200, "{list}");
    let items = list["invitations"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["status"], "accepted");
    assert_eq!(items[0]["accepted_member"], carol.member.as_str());
    assert!(items[0].get("token").is_none() && items[0].get("url").is_none());
    // An editor does not manage invitations.
    let (status, body) = call(
        &h,
        &carol,
        Method::GET,
        "/v1/invitations",
        Some(ws),
        None,
        false,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = invite(
        &h,
        &carol,
        ws,
        json!({"email": "x@example.com", "role": "viewer"}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(message(&body).contains("editor role cannot"), "{body}");

    // Both steps are in the chain, as their actors, without the token.
    let created_log = audited(&h, ws, "invitation.create").await;
    assert_eq!(created_log.len(), 1);
    assert_eq!(created_log[0].0.as_deref(), Some(ada.member.as_str()));
    assert_eq!(created_log[0].1, format!("invitation:{}", created["id"]));
    assert_eq!(created_log[0].3["status"], "pending");
    let accepted_log = audited(&h, ws, "invitation.accept").await;
    assert_eq!(accepted_log.len(), 1);
    assert_eq!(accepted_log[0].0.as_deref(), Some(carol.member.as_str()));
    assert_eq!(accepted_log[0].2["status"], "pending");
    assert_eq!(accepted_log[0].3["status"], "accepted");
    assert_eq!(accepted_log[0].3["accepted_member"], carol.member.as_str());
    let via: Vec<String> = sqlx::query_scalar(
        "SELECT via FROM audit_log WHERE workspace_id = $1 AND action LIKE 'invitation.%' \
          ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(
        via,
        [
            format!("session:{}", ada.user_id),
            format!("session:{}", carol.user_id)
        ]
    );
    let token = created["token"].as_str().unwrap();
    let dump: Vec<String> = sqlx::query_scalar(
        "SELECT concat(before::text, after::text) FROM audit_log WHERE workspace_id = $1",
    )
    .bind(ws)
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert!(dump.iter().all(|d| !d.contains(&token[4..])));
    h.store.verify_audit(Some(ws), &[]).await.unwrap();
    h.shutdown().await;
}

#[tokio::test]
async fn invite_by_member_revoke_expire_and_roles() {
    let mut h = harness!();
    let ada = sign_in(&h, "ada", Some("ada@example.com"), true).await;
    let ws = h.store.personal_workspace(&ada.member).await.unwrap();
    let dave = sign_in(&h, "dave", None, false).await;

    // A member name must belong to someone who has signed in.
    let (status, body) = invite(&h, &ada, ws, json!({"member": "nobody", "role": "viewer"})).await;
    assert_eq!(status, 400, "{body}");
    assert!(message(&body).contains("invite them by email"), "{body}");
    // An existing member cannot be invited again.
    let (status, body) = invite(
        &h,
        &ada,
        ws,
        json!({"member": ada.member, "role": "viewer"}),
    )
    .await;
    assert_eq!(status, 409, "{body}");

    // Invite dave by name, then revoke it before he accepts.
    let (status, first) = invite(
        &h,
        &ada,
        ws,
        json!({"member": dave.member, "role": "viewer"}),
    )
    .await;
    assert_eq!(status, 201, "{first}");
    let first_path = link_path(&first);
    let id = first["id"].as_i64().unwrap();
    let (status, body) = call(
        &h,
        &ada,
        Method::DELETE,
        &format!("/v1/invitations/{id}"),
        Some(ws),
        None,
        true,
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let (status, body) = accept(&h, &dave, &first_path).await;
    assert_eq!(status, 404, "{body}");
    assert!(message(&body).contains("revoked"), "{body}");
    let (status, body) = call(
        &h,
        &ada,
        Method::DELETE,
        &format!("/v1/invitations/{id}"),
        Some(ws),
        None,
        true,
    )
    .await;
    assert_eq!(status, 409, "{body}");
    for bad in ["0", "-1", "abc", "99999999"] {
        let (status, _) = call(
            &h,
            &ada,
            Method::DELETE,
            &format!("/v1/invitations/{bad}"),
            Some(ws),
            None,
            true,
        )
        .await;
        assert_eq!(status, 404, "{bad}");
    }

    // A second invitation, for a person by name: only that person accepts.
    let (_, second) = invite(
        &h,
        &ada,
        ws,
        json!({"member": dave.member, "role": "admin"}),
    )
    .await;
    let second_path = link_path(&second);
    let eve = sign_in(&h, "eve", Some("eve@example.com"), true).await;
    let (status, body) = accept(&h, &eve, &second_path).await;
    assert_eq!(status, 403, "{body}");
    assert!(
        message(&body).contains(&format!("member {}", dave.member)),
        "{body}"
    );
    let (status, joined) = accept(&h, &dave, &second_path).await;
    assert_eq!(status, 200, "{joined}");
    assert_eq!(joined["role"], "admin");

    // An admin invites editors and viewers, never admins or owners, and
    // cannot revoke what only an owner could have made.
    let (status, body) = invite(
        &h,
        &dave,
        ws,
        json!({"email": "o@example.com", "role": "owner"}),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(message(&body).contains("cannot invite an owner"), "{body}");
    let (status, by_admin) = invite(
        &h,
        &dave,
        ws,
        json!({"email": "v@example.com", "role": "viewer"}),
    )
    .await;
    assert_eq!(status, 201, "{by_admin}");
    let (_, owner_inv) = invite(
        &h,
        &ada,
        ws,
        json!({"email": "o@example.com", "role": "owner"}),
    )
    .await;
    let oid = owner_inv["id"].as_i64().unwrap();
    let (status, body) = call(
        &h,
        &dave,
        Method::DELETE,
        &format!("/v1/invitations/{oid}"),
        Some(ws),
        None,
        true,
    )
    .await;
    assert_eq!(status, 403, "{body}");

    // Invitations of one workspace are invisible from another.
    let dave_ws = h.store.personal_workspace(&dave.member).await.unwrap();
    let (status, _) = call(
        &h,
        &dave,
        Method::DELETE,
        &format!("/v1/invitations/{oid}"),
        Some(dave_ws),
        None,
        true,
    )
    .await;
    assert_eq!(status, 404);
    let (_, list) = call(
        &h,
        &dave,
        Method::GET,
        "/v1/invitations",
        Some(dave_ws),
        None,
        false,
    )
    .await;
    assert_eq!(list["invitations"], json!([]));

    // Expired: refused, and listed as expired after the pending ones.
    sqlx::query(
        "UPDATE invitations SET created_at = now() - interval '2 days', \
                                expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(by_admin["id"].as_i64().unwrap())
    .execute(h.store.pool())
    .await
    .unwrap();
    let viewer = sign_in(&h, "vic", Some("v@example.com"), true).await;
    let (status, body) = accept(&h, &viewer, &link_path(&by_admin)).await;
    assert_eq!(status, 404, "{body}");
    assert!(message(&body).contains("expired"), "{body}");
    let (status, body) = call(
        &h,
        &ada,
        Method::DELETE,
        &format!("/v1/invitations/{}", by_admin["id"]),
        Some(ws),
        None,
        true,
    )
    .await;
    assert_eq!(status, 409, "{body}");
    let (_, list) = call(
        &h,
        &ada,
        Method::GET,
        "/v1/invitations",
        Some(ws),
        None,
        false,
    )
    .await;
    let statuses: Vec<(&str, i64)> = list["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["status"].as_str().unwrap(), i["id"].as_i64().unwrap()))
        .collect();
    assert_eq!(statuses[0], ("pending", oid), "{statuses:?}");
    let mut rest: Vec<&str> = statuses[1..].iter().map(|s| s.0).collect();
    rest.sort();
    assert_eq!(rest, ["accepted", "expired", "revoked"], "{statuses:?}");

    // Every step, by whom.
    let revoked = audited(&h, ws, "invitation.revoke").await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].0.as_deref(), Some(ada.member.as_str()));
    assert_eq!(revoked[0].2["status"], "pending");
    assert_eq!(revoked[0].3["status"], "revoked");
    assert_eq!(revoked[0].3["revoked_by"], ada.member.as_str());
    assert_eq!(audited(&h, ws, "invitation.create").await.len(), 4);
    assert_eq!(audited(&h, ws, "invitation.accept").await.len(), 1);
    h.store.verify_audit(None, &[]).await.unwrap();
    h.shutdown().await;
}

#[tokio::test]
async fn a_link_is_used_once_under_races_and_pending_invitations_are_bounded() {
    let mut h = harness!();
    let ada = sign_in(&h, "ada", Some("ada@example.com"), true).await;
    let ws = h.store.personal_workspace(&ada.member).await.unwrap();
    let bea = sign_in(&h, "bea", Some("bea@example.com"), true).await;
    let (_, created) = invite(
        &h,
        &ada,
        ws,
        json!({"email": "bea@example.com", "role": "viewer"}),
    )
    .await;
    let path = link_path(&created);

    // Twenty concurrent acceptances: exactly one joins.
    let results = race(
        &h,
        &bea,
        (0..20).map(|_| (format!("{path}/accept"), None)).collect(),
    )
    .await;
    let ok = results.iter().filter(|(s, _)| *s == 200).count();
    assert_eq!(ok, 1, "{results:?}");
    assert!(
        results.iter().all(|(s, _)| matches!(s, 200 | 404)),
        "{results:?}"
    );
    assert_eq!(audited(&h, ws, "invitation.accept").await.len(), 1);

    // Someone already a member keeps the invitation for later.
    let (_, again) = invite(
        &h,
        &ada,
        ws,
        json!({"email": "bea@example.com", "role": "editor"}),
    )
    .await;
    let (status, body) = accept(&h, &bea, &link_path(&again)).await;
    assert_eq!(status, 409, "{body}");
    assert!(message(&body).contains("as viewer"), "{body}");
    let (status, _) = call(&h, &bea, Method::GET, &link_path(&again), None, None, false).await;
    assert_eq!(status, 200);

    // At most 100 pending: fill to the bound, then concurrent requests
    // cannot overrun it.
    sqlx::query(
        "INSERT INTO invitations (workspace_id, token_hash, email, role, invited_by, expires_at) \
         SELECT $1, sha256(convert_to('fill-' || g, 'UTF8')), 'p' || g || '@example.com', \
                'viewer', $2, now() + interval '1 day' \
           FROM generate_series(1, 97) g",
    )
    .bind(ws)
    .bind(&ada.member)
    .execute(h.store.pool())
    .await
    .unwrap();
    let results = race(
        &h,
        &ada,
        (0..5)
            .map(|i| {
                let body = json!({"email": format!("race{i}@example.com"), "role": "viewer"});
                ("/v1/invitations".to_owned(), Some((ws, body)))
            })
            .collect(),
    )
    .await;
    let made = results.iter().filter(|(s, _)| *s == 201).count();
    assert_eq!(made, 2, "{results:?}");
    for (status, body) in results.iter().filter(|(s, _)| *s != 201) {
        assert_eq!(*status, 403, "{body}");
        assert_eq!(body["error"]["code"], "quota_exceeded");
        assert!(message(body).contains("100 invitations waiting"), "{body}");
    }
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM invitations WHERE workspace_id = $1 \
            AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now()",
    )
    .bind(ws)
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert_eq!(pending, 100);
    let metrics = h.metrics().await;
    assert!(
        metrics.contains("relink_quota_exceeded_total{limit=\"pending_invitations\"} 3"),
        "{metrics}"
    );
    // Listing shows every pending one even with history around.
    let (_, list) = call(
        &h,
        &ada,
        Method::GET,
        "/v1/invitations",
        Some(ws),
        None,
        false,
    )
    .await;
    let items = list["invitations"].as_array().unwrap();
    assert_eq!(items.len(), 101);
    assert!(items[..100].iter().all(|i| i["status"] == "pending"));
    assert_eq!(items[100]["status"], "accepted");

    // The tenant role cannot read another workspace's invitations, nor
    // delete its own (revoking keeps the record).
    let other = h.store.personal_workspace(&bea.member).await.unwrap();
    let mut tx = h.store.begin_tenant(other).await.unwrap();
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM invitations")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, 0);
    tx.rollback().await.unwrap();
    let mut tx = h.store.begin_tenant(ws).await.unwrap();
    let err = sqlx::query("DELETE FROM invitations")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
    tx.rollback().await.unwrap();
    h.shutdown().await;
}

/// POSTs to each path at once as `who` (with a workspace and JSON body when
/// given) and collects the answers.
async fn race(
    h: &Harness,
    who: &Person,
    requests: Vec<(String, Option<(i64, Value)>)>,
) -> Vec<(u16, Value)> {
    let mut tasks = Vec::new();
    for (path, ws_body) in requests {
        let http = h.http.clone();
        let url = format!("{}{path}", h.base);
        let who = who.clone();
        tasks.push(tokio::spawn(async move {
            let mut req = http
                .post(url)
                .header("cookie", format!("relink_session={}", who.cookie))
                .header("x-csrf-token", &who.csrf);
            if let Some((ws, body)) = ws_body {
                req = req
                    .header("relink-workspace", ws.to_string())
                    .header("content-type", "application/json")
                    .body(body.to_string());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap();
            (status, serde_json::from_str(&text).unwrap_or(Value::Null))
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}
