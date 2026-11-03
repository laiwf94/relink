//! The audit log against Postgres: every change lands in its workspace's
//! hash chain with its actor, before and after; the chain the trigger
//! writes verifies in Rust; tampering of every kind is found; and tenants
//! can neither rewrite the log nor reach another workspace's.

mod common;

use std::time::Duration;

use common::{Harness, admin_url, new_link_for};
use relink_server::audit::{Anchor, BreakReason, Entry, GENESIS, VerifyError, entry_hash};
use relink_server::auth::{Scopes, generate_key, hash_key};
use relink_server::store::{Db, LinkPatch, NewApiKey};
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::Row;

/// The entries of one workspace's chain, oldest first.
async fn entries(store: &Db, ws: i64) -> Vec<(String, Option<String>, String, String, Value)> {
    sqlx::query(
        "SELECT action, actor, via, target, \
                json_build_object('before', before, 'after', after) AS change \
           FROM audit_log WHERE workspace_id = $1 ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(store.pool())
    .await
    .unwrap()
    .iter()
    .map(|r| {
        (
            r.get("action"),
            r.get("actor"),
            r.get("via"),
            r.get("target"),
            r.get("change"),
        )
    })
    .collect()
}

async fn key_id(store: &Db, owner: &str) -> i64 {
    sqlx::query_scalar("SELECT min(id) FROM api_keys WHERE owner = $1")
        .bind(owner)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// Runs `sql` as the table owner with the log's triggers (the append-only
/// guard and the chaining) lifted, the way someone with database access
/// would tamper with it.
async fn tamper(store: &Db, sql: &str) {
    let mut tx = store.pool().begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_log ENABLE TRIGGER USER")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn broken(r: Result<Vec<relink_server::audit::ChainHead>, VerifyError>) -> (i64, BreakReason) {
    match r {
        Err(VerifyError::Broken(b)) => (b.seq, b.reason),
        other => panic!("expected a broken chain, got {other:?}"),
    }
}

#[tokio::test]
async fn api_changes_are_recorded_with_actor_before_and_after() {
    let Some(admin) = admin_url() else { return };
    let mut h = Harness::start(&admin, &[]).await;
    let ws = h.store.personal_workspace("alice").await.unwrap();
    let key = key_id(&h.store, "alice").await;

    h.create(json!({"url": "https://example.com/a", "alias": "audited"}))
        .await;
    let link_id = h.store.tenant(ws).link("audited").await.unwrap().id;
    let (status, _) = h
        .api(
            Method::PATCH,
            "/v1/links/audited",
            &h.alice,
            Some(json!({"enabled": false, "fallback_url": "https://example.com/ünïcode/☕"})),
        )
        .await;
    assert_eq!(status, 200);
    // A refused change records nothing.
    let (status, _) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.alice,
            Some(json!({"url": "https://example.com/b", "alias": "audited"})),
        )
        .await;
    assert_eq!(status, 409);
    let (status, _) = h
        .api(Method::DELETE, "/v1/links/audited", &h.alice, None)
        .await;
    assert_eq!(status, 204);
    // Reads record nothing either.
    let (status, _) = h.api(Method::GET, "/v1/links", &h.alice, None).await;
    assert_eq!(status, 200);

    let log = entries(&h.store, ws).await;
    let actions: Vec<&str> = log.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        actions,
        [
            "workspace.create",
            "key.create",
            "link.create",
            "link.update",
            "link.delete"
        ]
    );
    let target = format!("link:{link_id}");
    for (action, actor, via, t, _) in &log[2..] {
        assert_eq!(actor.as_deref(), Some("alice"), "{action}");
        assert_eq!(via, &format!("key:{key}"), "{action}");
        assert_eq!(t, &target, "{action}");
    }
    let (_, create) = (&log[2].0, &log[2].4);
    assert!(create["before"].is_null());
    assert_eq!(create["after"]["code"], "audited");
    assert_eq!(create["after"]["owner"], "alice");
    assert_eq!(create["after"]["enabled"], true);
    let update = &log[3].4;
    assert_eq!(update["before"]["enabled"], true);
    assert_eq!(update["after"]["enabled"], false);
    assert_eq!(
        update["after"]["fallback_url"],
        "https://example.com/%C3%BCn%C3%AFcode/%E2%98%95"
    );
    let delete = &log[4].4;
    assert_eq!(delete["before"]["enabled"], false);
    assert!(delete["after"].is_null());
    // The personal workspace and the harness's key were made by the
    // server and an operator.
    assert_eq!((log[0].1.as_deref(), log[0].2.as_str()), (None, "system"));
    assert_eq!((log[1].1.as_deref(), log[1].2.as_str()), (None, "cli"));
    assert!(
        !log[1].4.to_string().contains("hash"),
        "a key's hash is never logged"
    );

    // The chain the trigger wrote verifies here, entry by entry, and the
    // other workspace (bob's) has its own.
    let heads = h.store.verify_audit(None, &[]).await.unwrap();
    assert_eq!(heads.len(), 2);
    let mine = heads.iter().find(|c| c.workspace_id == ws).unwrap();
    assert_eq!(mine.seq, 5);
    assert_eq!(
        h.store.verify_audit(Some(ws), &[]).await.unwrap(),
        vec![mine.clone()]
    );
    h.shutdown().await;
}

#[tokio::test]
async fn the_rust_hash_matches_the_trigger() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    // Non-ASCII text, so the length prefix must count bytes on both sides.
    let new = relink_server::store::NewLink {
        fallback_url: Some("https://example.com/naïve/☕".into()),
        ..new_link_for("zoe", "unicode")
    };
    let link = common::insert_link(&store, &new, 7).await.unwrap();
    let rows = sqlx::query(
        "SELECT workspace_id, seq, at, actor, via, action, target, before::text AS before, \
                after::text AS after, prev_hash, hash \
           FROM audit_log ORDER BY seq",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 2, "workspace.create and link.create");
    let mut prev = GENESIS;
    for r in &rows {
        let e = Entry {
            workspace_id: r.get("workspace_id"),
            seq: r.get("seq"),
            at: r.get("at"),
            actor: r.get("actor"),
            via: r.get("via"),
            action: r.get("action"),
            target: r.get("target"),
            before: r.get("before"),
            after: r.get("after"),
            prev_hash: r.get::<Vec<u8>, _>("prev_hash").try_into().unwrap(),
            hash: r.get::<Vec<u8>, _>("hash").try_into().unwrap(),
        };
        assert_eq!(e.workspace_id, link.workspace_id);
        assert_eq!(e.prev_hash, prev);
        assert_eq!(entry_hash(&prev, &e), e.hash, "entry {}", e.seq);
        prev = e.hash;
    }
}

#[tokio::test]
async fn tampering_is_found_and_located() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    let link = common::insert_link(&store, &new_link_for("alice", "tamper1"), 7)
        .await
        .unwrap();
    let ws = link.workspace_id;
    let alice = store.tenant(ws);
    for enabled in [false, true, false] {
        let patch = LinkPatch {
            enabled: Some(enabled),
            ..LinkPatch::default()
        };
        alice.update_link("tamper1", &patch).await.unwrap();
    }
    // Entries 1 to 5: workspace.create, link.create, three updates.
    let heads = store.verify_audit(Some(ws), &[]).await.unwrap();
    assert_eq!(heads[0].seq, 5);
    let anchor = Anchor::parse(&heads[0].to_string()).unwrap();
    let early = Anchor {
        workspace_id: ws,
        seq: 2,
        hash: sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT hash FROM audit_log WHERE workspace_id = $1 AND seq = 2",
        )
        .bind(ws)
        .fetch_one(store.pool())
        .await
        .unwrap()
        .try_into()
        .unwrap(),
    };
    assert!(store.verify_audit(None, &[anchor, early]).await.is_ok());

    // Each kind of tampering, undone afterwards from a saved copy.
    sqlx::query("CREATE TABLE saved AS SELECT * FROM audit_log")
        .execute(store.pool())
        .await
        .unwrap();
    let restore = "DELETE FROM audit_log; INSERT INTO audit_log SELECT * FROM saved";
    let cases: &[(&str, i64, BreakReason)] = &[
        (
            "UPDATE audit_log SET after = jsonb_set(after, '{enabled}', 'true') WHERE seq = 3",
            3,
            BreakReason::Altered,
        ),
        (
            "UPDATE audit_log SET actor = 'mallory' WHERE seq = 4",
            4,
            BreakReason::Altered,
        ),
        (
            "UPDATE audit_log SET at = at - interval '1 day' WHERE seq = 2",
            2,
            BreakReason::Altered,
        ),
        (
            "DELETE FROM audit_log WHERE seq = 3",
            3,
            BreakReason::Missing,
        ),
        (
            "DELETE FROM audit_log WHERE seq = 5",
            5,
            BreakReason::Missing,
        ),
        (
            "UPDATE audit_log SET prev_hash = (SELECT prev_hash FROM saved WHERE seq = 3) WHERE seq = 4",
            4,
            BreakReason::Unlinked,
        ),
    ];
    for (sql, seq, reason) in cases {
        tamper(&store, sql).await;
        assert_eq!(
            broken(store.verify_audit(None, &[]).await),
            (*seq, reason.clone()),
            "{sql}"
        );
        tamper(&store, restore).await;
        assert!(store.verify_audit(None, &[]).await.is_ok(), "restored");
    }

    // Removing the last entry and moving the head back with it is only
    // caught by an anchor kept elsewhere.
    tamper(&store, "DELETE FROM audit_log WHERE seq = 5").await;
    sqlx::query(
        "UPDATE audit_heads SET seq = 4, hash = (SELECT hash FROM audit_log WHERE seq = 4) \
          WHERE workspace_id = $1",
    )
    .bind(ws)
    .execute(store.pool())
    .await
    .unwrap();
    assert!(store.verify_audit(None, &[]).await.is_ok());
    assert_eq!(
        broken(store.verify_audit(None, &[anchor]).await),
        (5, BreakReason::AnchorMismatch)
    );
    // As is rewriting a whole chain consistently: re-hash entry 2 onwards
    // after editing entry 2, as an attacker who read the code would.
    tamper(&store, restore).await;
    sqlx::query("UPDATE audit_heads SET seq = 5, hash = $2 WHERE workspace_id = $1")
        .bind(ws)
        .bind(&anchor.hash[..])
        .execute(store.pool())
        .await
        .unwrap();
    tamper(
        &store,
        "UPDATE audit_log SET actor = 'mallory' WHERE seq = 2",
    )
    .await;
    rehash(&store, ws).await;
    assert!(store.verify_audit(None, &[]).await.is_ok());
    assert_eq!(
        broken(store.verify_audit(None, &[early]).await),
        (2, BreakReason::AnchorMismatch)
    );
    assert_eq!(
        broken(store.verify_audit(Some(ws), &[anchor]).await),
        (5, BreakReason::AnchorMismatch)
    );
    // An anchor for a workspace with no chain at all.
    let missing = Anchor {
        workspace_id: ws + 1000,
        ..anchor
    };
    assert_eq!(
        broken(store.verify_audit(None, &[missing]).await),
        (5, BreakReason::AnchorMismatch)
    );

    // A head with no entries behind it, and entries with no head.
    sqlx::query("INSERT INTO audit_heads VALUES (424242, 1, $1)")
        .bind(&[7u8; 32][..])
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        broken(store.verify_audit(Some(424242), &[]).await),
        (1, BreakReason::Missing)
    );
    sqlx::query("DELETE FROM audit_heads WHERE workspace_id = $1")
        .bind(ws)
        .execute(store.pool())
        .await
        .unwrap();
    let err = store.verify_audit(Some(ws), &[]).await.unwrap_err();
    assert!(err.to_string().contains("has no head"), "{err}");
}

/// Recomputes every hash of a chain from its (edited) contents, and its
/// head, the way a careful attacker would.
async fn rehash(store: &Db, ws: i64) {
    let rows = sqlx::query(
        "SELECT seq, at, actor, via, action, target, before::text AS before, \
                after::text AS after FROM audit_log WHERE workspace_id = $1 ORDER BY seq",
    )
    .bind(ws)
    .fetch_all(store.pool())
    .await
    .unwrap();
    let mut prev = GENESIS;
    let mut sql = String::new();
    for r in &rows {
        let mut e = Entry {
            workspace_id: ws,
            seq: r.get("seq"),
            at: r.get("at"),
            actor: r.get("actor"),
            via: r.get("via"),
            action: r.get("action"),
            target: r.get("target"),
            before: r.get("before"),
            after: r.get("after"),
            prev_hash: prev,
            hash: [0; 32],
        };
        e.hash = entry_hash(&prev, &e);
        let hex = |b: &[u8; 32]| relink_server::util::hex_encode(b);
        sql.push_str(&format!(
            "UPDATE audit_log SET prev_hash = '\\x{}', hash = '\\x{}' \
              WHERE workspace_id = {ws} AND seq = {};",
            hex(&prev),
            hex(&e.hash),
            e.seq
        ));
        prev = e.hash;
    }
    sql.push_str(&format!(
        "UPDATE audit_heads SET hash = '\\x{}' WHERE workspace_id = {ws};",
        relink_server::util::hex_encode(&prev)
    ));
    tamper(store, &sql).await;
}

#[tokio::test]
async fn the_log_is_append_only_and_tenant_scoped() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    let a = common::insert_link(&store, &new_link_for("alice", "alpha1"), 7)
        .await
        .unwrap();
    let b = common::insert_link(&store, &new_link_for("bob", "bravo1"), 7)
        .await
        .unwrap();

    // Not even the owner can change or remove entries while the guard is on.
    for sql in [
        "UPDATE audit_log SET actor = 'mallory'",
        "DELETE FROM audit_log",
        "TRUNCATE audit_log",
        "TRUNCATE audit_heads",
    ] {
        let err = sqlx::query(sql).execute(store.pool()).await.unwrap_err();
        assert!(err.to_string().contains("append-only"), "{sql}: {err}");
    }

    // A tenant sees its own chain only, cannot write another workspace's
    // or touch the heads, and has no right to update or delete at all.
    let mut tx = store.begin_tenant(a.workspace_id).await.unwrap();
    let seen: Vec<i64> = sqlx::query_scalar("SELECT DISTINCT workspace_id FROM audit_log")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, vec![a.workspace_id]);
    tx.rollback().await.unwrap();
    for sql in [
        format!(
            "INSERT INTO audit_log (workspace_id, via, action, target, seq, prev_hash, hash) \
             VALUES ({}, 'system', 'link.delete', 'link:1', 1, '\\x{z}', '\\x{z}')",
            b.workspace_id,
            z = "00".repeat(32)
        ),
        "UPDATE audit_log SET actor = 'mallory'".into(),
        "DELETE FROM audit_log".into(),
        "SELECT * FROM audit_heads".into(),
        "UPDATE audit_heads SET seq = 1".into(),
    ] {
        let mut tx = store.begin_tenant(a.workspace_id).await.unwrap();
        let err = sqlx::raw_sql(sqlx::AssertSqlSafe(sql.clone()))
            .execute(&mut *tx)
            .await
            .unwrap_err();
        let code = err
            .as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.into_owned());
        assert_eq!(code.as_deref(), Some("42501"), "{sql}: {err}");
    }
    // A tenant's own entry still chains, whatever seq and hashes it claims.
    let mut tx = store.begin_tenant(a.workspace_id).await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "INSERT INTO audit_log (via, action, target, seq, prev_hash, hash) \
         VALUES ('system', 'link.delete', 'link:1', 99, '\\x{z}', '\\x{z}')",
        z = "ab".repeat(32)
    )))
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let heads = store.verify_audit(Some(a.workspace_id), &[]).await.unwrap();
    assert_eq!(heads[0].seq, 3);
}

#[tokio::test]
async fn concurrent_changes_chain_without_gaps_and_rollbacks_leave_none() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    let ws = store.personal_workspace("carol").await.unwrap();
    let mut tasks = Vec::new();
    for i in 0..24 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            common::insert_link(&store, &new_link_for("carol", &format!("carol{i}")), 7)
                .await
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    // A change that fails after writing its entry takes the entry with it,
    // and the sequence number with the entry.
    let mut tx = store.begin_tenant(ws).await.unwrap();
    relink_server::audit::record(
        &mut tx,
        &relink_server::audit::Actor::system(),
        relink_server::audit::Change {
            workspace_id: ws,
            action: relink_server::audit::Action::LinkDelete,
            target: "link:1".into(),
            before: None,
            after: None,
        },
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        common::insert_link(&store, &new_link_for("carol", "carol0"), 7)
            .await
            .is_err()
    );
    common::insert_link(&store, &new_link_for("carol", "carol-last"), 7)
        .await
        .unwrap();
    let heads = store.verify_audit(Some(ws), &[]).await.unwrap();
    assert_eq!(heads[0].seq, 26, "workspace.create, 24 links and one more");
}

#[tokio::test]
async fn key_administration_is_recorded() {
    let Some(admin) = admin_url() else { return };
    let db = common::TestDb::create(&admin).await;
    let store = common::open_store(&db.url).await;
    let created = store
        .create_api_key(&NewApiKey {
            owner: "dave",
            name: "ci ☁",
            hash: hash_key(&generate_key()),
            workspace_id: None,
            scopes: Scopes::parse_list("links:read").unwrap(),
            lifetime: Some(Duration::from_secs(86_400)),
        })
        .await
        .unwrap();
    let rotated = store
        .rotate_api_key(created.id, &hash_key(&generate_key()), Duration::ZERO)
        .await
        .unwrap();
    assert!(store.revoke_api_key(rotated.new.id).await.unwrap());
    assert!(!store.revoke_api_key(rotated.new.id).await.unwrap());

    let log = entries(&store, created.workspace_id).await;
    let actions: Vec<&str> = log.iter().map(|e| e.0.as_str()).collect();
    assert_eq!(
        actions,
        ["workspace.create", "key.create", "key.rotate", "key.revoke"]
    );
    for (action, actor, via, _, _) in &log[1..] {
        assert_eq!((actor.as_deref(), via.as_str()), (None, "cli"), "{action}");
    }
    let create = &log[1];
    assert_eq!(create.3, format!("key:{}", created.id));
    assert_eq!(create.4["after"]["name"], "ci ☁");
    assert_eq!(create.4["after"]["scopes"], json!(["links:read"]));
    let rotate = &log[2];
    assert_eq!(rotate.3, format!("key:{}", created.id));
    assert!(rotate.4["before"]["rotated_to"].is_null());
    assert_eq!(rotate.4["after"]["rotated_to"]["id"], rotated.new.id);
    assert_ne!(
        rotate.4["before"]["expires_at"],
        rotate.4["after"]["expires_at"]
    );
    let revoke = &log[3];
    assert_eq!(revoke.3, format!("key:{}", rotated.new.id));
    assert!(revoke.4["before"]["revoked_at"].is_null());
    assert!(revoke.4["after"]["revoked_at"].is_string());
    assert!(
        store
            .verify_audit(Some(created.workspace_id), &[])
            .await
            .is_ok()
    );
}
