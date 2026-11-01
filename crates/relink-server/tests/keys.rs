//! Roles and scoped API keys (migration 0005): what a key may do is its
//! scopes within its owner's role, keys expire exactly, and rotation leaves
//! the old key working for an overlap window and no longer.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::{Harness, admin_url, metric};
use relink_server::auth::{Role, Scope, Scopes, generate_key, hash_key};
use relink_server::store::{KeyError, KeyInfo, NewApiKey};
use reqwest::Method;
use serde_json::{Value, json};

/// These tests use many fresh keys from one address, which the per-address
/// limit on uncached key lookups would otherwise throttle.
macro_rules! harness {
    () => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[("RELINK_AUTH_LOOKUP_RATE_PER_IP", "1000")]).await
    }};
}

/// Creates a key and returns it with what the store says about it.
async fn make_key(
    h: &Harness,
    owner: &str,
    workspace_id: Option<i64>,
    scopes: Scopes,
    lifetime: Option<Duration>,
) -> Result<(String, KeyInfo), KeyError> {
    let key = generate_key();
    let info = h
        .store
        .create_api_key(&NewApiKey {
            owner,
            name: "test",
            hash: hash_key(&key),
            workspace_id,
            scopes,
            lifetime,
        })
        .await?;
    Ok((key, info))
}

async fn add_member(h: &Harness, workspace_id: i64, member: &str, role: Role) {
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, member, role) VALUES ($1, $2, $3)
         ON CONFLICT (workspace_id, member) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(workspace_id)
    .bind(member)
    .bind(role.as_str())
    .execute(h.store.pool())
    .await
    .unwrap();
}

fn all_but(s: Scope) -> Scopes {
    Scope::ALL
        .into_iter()
        .filter(|&o| o != s)
        .fold(Scopes::NONE, |acc, o| acc | o)
}

/// Sends one request for a documented route with a body that would succeed.
async fn call(h: &Harness, method: &str, path: &str, code: &str, key: &str) -> (u16, Value) {
    let m = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
    let body = matches!(method, "post" | "patch")
        .then(|| json!({"enabled": true, "url": "https://example.com/"}));
    h.api(m, &path.replace("{code}", code), key, body).await
}

#[tokio::test]
async fn every_route_requires_its_documented_scope() {
    let mut h = harness!();
    let doc: Value = serde_json::from_str(
        &h.http
            .get(format!("{}/openapi.json", h.base))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
    )
    .unwrap();
    let mut routes = Vec::new();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for method in ["get", "post", "patch", "delete"] {
            let Some(op) = item.get(method) else { continue };
            let scopes: Vec<&str> = op["security"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.get("apiKey"))
                .flat_map(|s| s.as_array().unwrap().iter().map(|v| v.as_str().unwrap()))
                .collect();
            if let [scope] = scopes.as_slice() {
                routes.push((method, path.clone(), Scope::parse(scope).unwrap()));
            } else {
                assert!(
                    !path.starts_with("/v1/links"),
                    "{method} {path} must name exactly one scope"
                );
            }
        }
    }
    let documented: BTreeSet<Scope> = routes.iter().map(|r| r.2).collect();
    assert_eq!(documented.len(), 3, "every scope guards some route");
    assert_eq!(routes.len(), 6);
    // Deletion last, so the other routes still find the link.
    routes.sort_by_key(|(m, _, _)| *m == "delete");

    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap();
    for (method, path, scope) in &routes {
        let (without, _) = make_key(&h, "alice", None, all_but(*scope), None)
            .await
            .unwrap();
        let (status, body) = call(&h, method, path, code, &without).await;
        assert_eq!(status, 403, "{method} {path} without {scope}: {body}");
        assert_eq!(body["error"]["code"], "permission_denied");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(scope.as_str()), "{message}");

        let (only, _) = make_key(&h, "alice", None, (*scope).into(), None)
            .await
            .unwrap();
        let (status, body) = call(&h, method, path, code, &only).await;
        assert!(
            matches!(status, 200 | 201 | 204),
            "{method} {path} with only {scope}: {status} {body}"
        );
    }

    // The scope is checked before the body is read: a read-only key gets
    // 403, not a complaint about its malformed JSON.
    let (reader, _) = make_key(&h, "alice", None, Scope::LinksRead.into(), None)
        .await
        .unwrap();
    let r = h
        .http
        .post(format!("{}/v1/links", h.base))
        .bearer_auth(&reader)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert!(metric(&h.metrics().await, "relink_api_permission_denied_total") >= 7.0);
    h.shutdown().await;
}

#[tokio::test]
async fn roles_limit_what_keys_can_do() {
    let mut h = harness!();
    let link = h.create(json!({"url": "https://example.com/"})).await;
    let code = link["code"].as_str().unwrap().to_owned();
    let ws = h.store.personal_workspace("alice").await.unwrap();
    add_member(&h, ws, "vera", Role::Viewer).await;
    add_member(&h, ws, "ed", Role::Editor).await;

    // A viewer cannot be given a key with more than the role grants.
    assert_eq!(
        make_key(&h, "vera", Some(ws), Scopes::ALL, None)
            .await
            .unwrap_err(),
        KeyError::ScopesExceedRole {
            role: Role::Viewer,
            scopes: Scopes::ALL
        }
    );
    let (vera, info) = make_key(&h, "vera", Some(ws), Role::Viewer.grants(), None)
        .await
        .unwrap();
    assert_eq!((info.role, info.workspace_id), (Role::Viewer, ws));
    let (status, list) = h.api(Method::GET, "/v1/links", &vera, None).await;
    assert_eq!(status, 200);
    assert_eq!(list["links"][0]["code"], code.as_str());
    let (status, _) = h
        .api(Method::GET, &format!("/v1/links/{code}/stats"), &vera, None)
        .await;
    assert_eq!(status, 200);

    // A key made while ed was an editor keeps links:write on paper, but their
    // role no longer grants it once he is demoted.
    let (stale, _) = make_key(&h, "ed", Some(ws), Scopes::ALL, None)
        .await
        .unwrap();
    add_member(&h, ws, "ed", Role::Viewer).await;
    let (status, body) = h
        .api(
            Method::PATCH,
            &format!("/v1/links/{code}"),
            &stale,
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    let message = body["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("viewer role does not grant links:write"),
        "{message}"
    );
    let (status, _) = h.api(Method::GET, "/v1/links", &stale, None).await;
    assert_eq!(status, 200, "reading is still within the role");

    // Editors write; and someone removed from the workspace has no working
    // keys at all.
    add_member(&h, ws, "ed", Role::Editor).await;
    let (ed2, _) = make_key(&h, "ed", Some(ws), Scopes::ALL, None)
        .await
        .unwrap();
    let (status, body) = h
        .api(
            Method::POST,
            "/v1/links",
            &ed2,
            Some(json!({"url": "https://example.org/"})),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let (gone, _) = make_key(&h, "vera", Some(ws), Scope::LinksRead.into(), None)
        .await
        .unwrap();
    sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND member = 'vera'")
        .bind(ws)
        .execute(h.store.pool())
        .await
        .unwrap();
    let (status, _) = h.api(Method::GET, "/v1/links", &gone, None).await;
    assert_eq!(status, 401);

    // Keys are only made for members, in workspaces that exist.
    let bob_ws = h.store.personal_workspace("bob").await.unwrap();
    for (owner, ws) in [("alice", bob_ws), ("vera", ws), ("alice", i64::MAX)] {
        assert_eq!(
            make_key(&h, owner, Some(ws), Scope::LinksRead.into(), None)
                .await
                .unwrap_err(),
            KeyError::NotMember {
                owner: owner.into(),
                workspace_id: ws
            }
        );
    }
    assert!(
        make_key(&h, "alice", None, Scopes::NONE, None)
            .await
            .is_err(),
        "a key with no scopes is useless"
    );
    // The database refuses unknown scopes on its own.
    let err = sqlx::query(
        "INSERT INTO api_keys (owner, key_hash, workspace_id, scopes)
         VALUES ('alice', $1, $2, '{links:read,billing:read}')",
    )
    .bind(&[7u8; 32][..])
    .bind(ws)
    .execute(h.store.pool())
    .await
    .unwrap_err();
    assert_eq!(
        err.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("23514")
    );
    h.shutdown().await;
}

#[tokio::test]
async fn keys_expire_exactly_even_when_cached() {
    let mut h = harness!();
    let (short, info) = make_key(&h, "alice", None, Scopes::ALL, Some(Duration::from_secs(2)))
        .await
        .unwrap();
    let expires = info.expires_at.unwrap();
    let left = expires - chrono::Utc::now();
    assert!(
        left > chrono::Duration::zero() && left <= chrono::Duration::seconds(2),
        "{left}"
    );
    let (status, _) = h.api(Method::GET, "/v1/links", &short, None).await;
    assert_eq!(status, 200, "valid now, and cached from here on");
    tokio::time::sleep(
        (expires - chrono::Utc::now()).to_std().unwrap() + Duration::from_millis(50),
    )
    .await;
    let (status, body) = h.api(Method::GET, "/v1/links", &short, None).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"]["code"], "unauthenticated");

    // A key that expired before it was ever seen is refused by the lookup.
    let (old, info) = make_key(
        &h,
        "alice",
        None,
        Scopes::ALL,
        Some(Duration::from_secs(3_600)),
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE api_keys SET created_at = now() - interval '2 hours',
                             expires_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(info.id)
    .execute(h.store.pool())
    .await
    .unwrap();
    let (status, _) = h.api(Method::GET, "/v1/links", &old, None).await;
    assert_eq!(status, 401);
    // And it cannot be rotated back to life.
    assert_eq!(
        h.store
            .rotate_api_key(info.id, &hash_key(&generate_key()), Duration::ZERO)
            .await
            .unwrap_err(),
        KeyError::NoSuchKey(info.id)
    );
    h.shutdown().await;
}

#[tokio::test]
async fn rotation_keeps_both_keys_for_the_overlap_only() {
    let mut h = harness!();
    let scopes = Scopes::from(Scope::LinksRead) | Scope::StatsRead;
    let lifetime = Duration::from_secs(90 * 86_400);
    let (old, old_info) = make_key(&h, "alice", None, scopes, Some(lifetime))
        .await
        .unwrap();
    let new = generate_key();
    let r = h
        .store
        .rotate_api_key(old_info.id, &hash_key(&new), Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(r.old_id, old_info.id);
    assert_ne!(r.new.id, old_info.id);
    assert_eq!(
        (
            r.new.owner.as_str(),
            r.new.workspace_id,
            r.new.role,
            r.new.scopes
        ),
        ("alice", old_info.workspace_id, Role::Owner, scopes)
    );
    // The successor gets the same lifetime, counted from now.
    let new_expiry = r.new.expires_at.unwrap();
    assert!(new_expiry >= old_info.expires_at.unwrap());
    assert!(new_expiry - chrono::Utc::now() <= chrono::Duration::from_std(lifetime).unwrap());
    let overlap_left = r.old_expires_at - chrono::Utc::now();
    assert!(
        overlap_left > chrono::Duration::zero() && overlap_left <= chrono::Duration::seconds(2),
        "{overlap_left}"
    );

    // During the overlap both keys work.
    for key in [&old, &new] {
        let (status, _) = h.api(Method::GET, "/v1/links", key, None).await;
        assert_eq!(status, 200);
    }
    // A key is rotated once; a second rotation would fork the chain.
    assert_eq!(
        h.store
            .rotate_api_key(old_info.id, &hash_key(&generate_key()), Duration::ZERO)
            .await
            .unwrap_err(),
        KeyError::AlreadyRotated {
            id: old_info.id,
            successor: r.new.id
        }
    );
    tokio::time::sleep(
        (r.old_expires_at - chrono::Utc::now()).to_std().unwrap() + Duration::from_millis(50),
    )
    .await;
    let (status, _) = h.api(Method::GET, "/v1/links", &old, None).await;
    assert_eq!(status, 401, "the old key ends with the overlap");
    let (status, _) = h.api(Method::GET, "/v1/links", &new, None).await;
    assert_eq!(status, 200);

    // No overlap ends the old key at once; a key without expiry has a
    // successor without expiry; a revoked key cannot be rotated.
    let (k, info) = make_key(&h, "alice", None, Scopes::ALL, None)
        .await
        .unwrap();
    let r = h
        .store
        .rotate_api_key(info.id, &hash_key(&generate_key()), Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(r.new.expires_at, None);
    let (status, _) = h.api(Method::GET, "/v1/links", &k, None).await;
    assert_eq!(status, 401);
    assert!(h.store.revoke_api_key(r.new.id).await.unwrap());
    assert_eq!(
        h.store
            .rotate_api_key(r.new.id, &hash_key(&generate_key()), Duration::ZERO)
            .await
            .unwrap_err(),
        KeyError::NoSuchKey(r.new.id)
    );
    h.shutdown().await;
}

#[tokio::test]
async fn rotation_follows_the_owners_current_role() {
    let mut h = harness!();
    let ws = h.store.personal_workspace("alice").await.unwrap();
    add_member(&h, ws, "ed", Role::Editor).await;
    let (_, all) = make_key(&h, "ed", Some(ws), Scopes::ALL, None)
        .await
        .unwrap();
    let (_, write_only) = make_key(&h, "ed", Some(ws), Scope::LinksWrite.into(), None)
        .await
        .unwrap();
    add_member(&h, ws, "ed", Role::Viewer).await;

    // The successor carries only what the role grants today.
    let new = generate_key();
    let r = h
        .store
        .rotate_api_key(all.id, &hash_key(&new), Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(
        (r.new.role, r.new.scopes),
        (Role::Viewer, Role::Viewer.grants())
    );
    let (status, _) = h.api(Method::GET, "/v1/links", &new, None).await;
    assert_eq!(status, 200);
    // Nothing would be left of a write-only key.
    assert_eq!(
        h.store
            .rotate_api_key(write_only.id, &hash_key(&generate_key()), Duration::ZERO)
            .await
            .unwrap_err(),
        KeyError::ScopesExceedRole {
            role: Role::Viewer,
            scopes: Scope::LinksWrite.into()
        }
    );
    // Someone who left the workspace cannot rotate their way back in.
    sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND member = 'ed'")
        .bind(ws)
        .execute(h.store.pool())
        .await
        .unwrap();
    let err = h
        .store
        .rotate_api_key(r.new.id, &hash_key(&generate_key()), Duration::ZERO)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        KeyError::NotMember {
            owner: "ed".into(),
            workspace_id: ws
        }
    );
    assert!(err.to_string().contains("ed is not a member"));
    h.shutdown().await;
}

#[test]
fn key_errors_read_well() {
    let cases = [
        (KeyError::NoSuchKey(4), "no active key with id 4"),
        (
            KeyError::AlreadyRotated {
                id: 4,
                successor: 9,
            },
            "already rotated to key 9",
        ),
        (
            KeyError::ScopesExceedRole {
                role: Role::Viewer,
                scopes: Scopes::ALL,
            },
            "viewer role grants only links:read,stats:read, not links:read,links:write,stats:read",
        ),
        (
            KeyError::Db(relink_server::store::DbError::Conflict),
            "conflict",
        ),
    ];
    for (e, want) in cases {
        assert!(e.to_string().contains(want), "{e}");
    }
}
