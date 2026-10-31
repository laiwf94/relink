//! Workspaces and row-level security (migration 0003): the backfill from
//! owners, and that a tenant transaction sees and writes only its own
//! workspace's rows, and nothing at all without a workspace set.

mod common;

use std::borrow::Cow;
use std::time::Duration;

use common::{TestDb, admin_url, config};
use relink_server::model::Destination;
use relink_server::server::{migrate_with_retry, open_db};
use relink_server::store::{ClickRow, Db, MIGRATOR, NewLink, TENANT_ROLE};
use relink_server::util::utc_day;
use sqlx::migrate::Migrator;
use sqlx::{Postgres, Transaction};

async fn fresh() -> Option<(TestDb, Db)> {
    let admin = admin_url()?;
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, &[])).unwrap();
    migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    Some((db, store))
}

fn new_link(owner: &str, alias: &str) -> NewLink {
    NewLink {
        owner: owner.into(),
        alias: Some(alias.into()),
        destinations: vec![Destination {
            url: "https://example.com/".into(),
            weight: 1,
        }],
        redirect_status: 302,
        expires_at: None,
        max_clicks: None,
        geo: None,
        fallback_url: None,
        enabled: true,
        health_check: false,
    }
}

async fn codes(tx: &mut Transaction<'_, Postgres>) -> Vec<String> {
    sqlx::query_scalar("SELECT code FROM links ORDER BY code")
        .fetch_all(&mut **tx)
        .await
        .unwrap()
}

async fn count(tx: &mut Transaction<'_, Postgres>, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

#[tokio::test]
async fn migration_backfills_a_personal_workspace_per_owner() {
    let Some(admin) = admin_url() else {
        return;
    };
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, &[])).unwrap();
    // The schema as it was before workspaces, with data in it.
    let before = Migrator {
        migrations: Cow::Owned(MIGRATOR.migrations[..2].to_vec()),
        ..Migrator::DEFAULT
    };
    before.run(store.pool()).await.unwrap();
    sqlx::raw_sql(
        r#"INSERT INTO api_keys (owner, name, key_hash) VALUES
               ('alice', 'a', decode(repeat('aa', 32), 'hex')),
               ('carol', 'c', decode(repeat('cc', 32), 'hex'));
           INSERT INTO links (code, owner, destinations) VALUES
               ('alice1', 'alice', '[{"url":"https://example.com/","weight":1}]'),
               ('alice2', 'alice', '[{"url":"https://example.com/","weight":1}]'),
               ('bob1',   'bob',   '[{"url":"https://example.com/","weight":1}]');"#,
    )
    .execute(store.pool())
    .await
    .unwrap();

    store.migrate().await.unwrap();

    // One workspace per distinct owner of a key or a link, each with its
    // owner as the 'owner' member.
    let members: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT w.personal_owner, m.member, m.role FROM workspaces w
           JOIN workspace_members m ON m.workspace_id = w.id ORDER BY w.personal_owner",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    let expected: Vec<(String, String, String)> = ["alice", "bob", "carol"]
        .iter()
        .map(|o| (o.to_string(), o.to_string(), "owner".to_string()))
        .collect();
    assert_eq!(members, expected);
    // Every link and key points at its owner's workspace.
    let mismatched: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM links l JOIN workspaces w ON w.id = l.workspace_id
                  WHERE w.personal_owner <> l.owner)
              + (SELECT count(*) FROM api_keys k JOIN workspaces w ON w.id = k.workspace_id
                  WHERE w.personal_owner <> k.owner)
              + (SELECT count(*) FROM links WHERE workspace_id IS NULL)
              + (SELECT count(*) FROM api_keys WHERE workspace_id IS NULL)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(mismatched, 0);
    // New rows land in the same workspaces, and new owners get their own.
    let alice_ws = store.personal_workspace("alice").await.unwrap();
    let link = store
        .insert_link(&new_link("alice", "alice3"), 7)
        .await
        .unwrap();
    assert_eq!(link.workspace_id, alice_ws);
    let dave = store
        .insert_link(&new_link("dave", "dave1"), 7)
        .await
        .unwrap();
    assert_ne!(dave.workspace_id, alice_ws);
    assert_eq!(
        store.personal_workspace("dave").await.unwrap(),
        dave.workspace_id
    );
    // The tenant role is not a superuser and cannot bypass the policies.
    let (superuser, bypass): (bool, bool) =
        sqlx::query_as("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1")
            .bind(TENANT_ROLE)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(!superuser && !bypass);
}

#[tokio::test]
async fn tenant_transactions_see_only_their_workspace() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let a1 = store
        .insert_link(&new_link("alice", "alice1"), 7)
        .await
        .unwrap();
    store
        .insert_link(&new_link("alice", "alice2"), 7)
        .await
        .unwrap();
    let b1 = store
        .insert_link(&new_link("bob", "bob1"), 7)
        .await
        .unwrap();
    store
        .insert_api_key("alice", "a", &[0xaa; 32])
        .await
        .unwrap();
    store.insert_api_key("bob", "b", &[0xbb; 32]).await.unwrap();
    let today = utc_day(chrono::Utc::now().timestamp_millis());
    let click = |id| {
        (
            ClickRow {
                link_id: id,
                day: today,
                country: *b"NZ",
                device: "desktop",
                referrer: None,
            },
            3,
        )
    };
    store
        .flush_clicks(
            &[click(a1.id), click(b1.id)],
            &[(a1.id, today, [1; 16]), (b1.id, today, [2; 16])],
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO visitor_rollup (link_id, day, visitors) VALUES ($1, '2020-01-01', 5), ($2, '2020-01-01', 6)")
        .bind(a1.id)
        .bind(b1.id)
        .execute(store.pool())
        .await
        .unwrap();
    let alice = a1.workspace_id;
    let bob = b1.workspace_id;
    assert_ne!(alice, bob);

    // Alice's transaction: her rows only, in every tenant table.
    let mut tx = store.begin_tenant(alice).await.unwrap();
    assert_eq!(codes(&mut tx).await, ["alice1", "alice2"]);
    for (table, n) in [
        ("workspaces", 1),
        ("workspace_members", 1),
        ("api_keys", 1),
        ("click_daily", 1),
        ("visitor_daily", 1),
        ("visitor_rollup", 1),
    ] {
        assert_eq!(count(&mut tx, table).await, n, "{table}");
    }
    let clicks: i64 = sqlx::query_scalar("SELECT sum(clicks)::bigint FROM click_daily")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(clicks, 3);
    // Bob's link is invisible: reads find nothing, writes touch nothing.
    let hit = sqlx::query("UPDATE links SET enabled = false WHERE id = $1")
        .bind(b1.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(hit.rows_affected(), 0);
    let hit = sqlx::query("DELETE FROM links WHERE id = $1")
        .bind(b1.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(hit.rows_affected(), 0);
    // An insert takes the transaction's workspace by default.
    let ws: i64 = sqlx::query_scalar(
        r#"INSERT INTO links (code, owner, destinations)
           VALUES ('alice3', 'alice', '[{"url":"https://example.com/","weight":1}]')
           RETURNING workspace_id"#,
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(ws, alice);
    tx.commit().await.unwrap();

    // Writing a row into another workspace, or moving one there, is refused.
    let mut tx = store.begin_tenant(alice).await.unwrap();
    let err = sqlx::query(
        r#"INSERT INTO links (code, owner, destinations, workspace_id)
           VALUES ('sneaky', 'alice', '[{"url":"https://example.com/","weight":1}]', $1)"#,
    )
    .bind(bob)
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert_eq!(sqlstate(&err), "42501", "{err}");
    tx.rollback().await.unwrap();
    let mut tx = store.begin_tenant(alice).await.unwrap();
    let err = sqlx::query("UPDATE links SET workspace_id = $1 WHERE id = $2")
        .bind(bob)
        .bind(a1.id)
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&err), "42501", "{err}");
    tx.rollback().await.unwrap();

    // Bob's transaction sees his link and not Alice's three.
    let mut tx = store.begin_tenant(bob).await.unwrap();
    assert_eq!(codes(&mut tx).await, ["bob1"]);
    tx.commit().await.unwrap();

    // The system path (redirect lookups, workers) still sees everything.
    assert!(store.link_by_code("alice3").await.unwrap().is_some());
    assert!(store.link_by_code("bob1").await.unwrap().is_some());
}

#[tokio::test]
async fn without_a_workspace_set_a_tenant_sees_no_rows() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let a1 = store
        .insert_link(&new_link("alice", "alice1"), 7)
        .await
        .unwrap();
    store
        .insert_api_key("alice", "a", &[0xaa; 32])
        .await
        .unwrap();
    let today = utc_day(chrono::Utc::now().timestamp_millis());
    store
        .flush_clicks(
            &[(
                ClickRow {
                    link_id: a1.id,
                    day: today,
                    country: *b"NZ",
                    device: "desktop",
                    referrer: None,
                },
                1,
            )],
            &[],
        )
        .await
        .unwrap();

    // The role alone, never a workspace: nothing is visible or writable.
    let mut tx = store.pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('role', $1, true)")
        .bind(TENANT_ROLE)
        .execute(&mut *tx)
        .await
        .unwrap();
    for table in [
        "links",
        "api_keys",
        "workspaces",
        "workspace_members",
        "click_daily",
    ] {
        assert_eq!(count(&mut tx, table).await, 0, "{table}");
    }
    let err = sqlx::query(
        r#"INSERT INTO links (code, owner, destinations)
           VALUES ('orphan', 'alice', '[{"url":"https://example.com/","weight":1}]')"#,
    )
    .execute(&mut *tx)
    .await
    .unwrap_err();
    // No workspace: the policy refuses the row (its workspace_id defaults
    // to NULL, which matches no workspace) before NOT NULL is checked.
    assert_eq!(sqlstate(&err), "42501", "{err}");
    tx.rollback().await.unwrap();

    // A workspace set earlier on the same pooled connection does not leak
    // into a later transaction: the settings are transaction-local.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&_db.url)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    relink_server::store::scope_to_workspace(&mut tx, a1.workspace_id)
        .await
        .unwrap();
    assert_eq!(codes(&mut tx).await, ["alice1"]);
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('role', $1, true)")
        .bind(TENANT_ROLE)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(codes(&mut tx).await.is_empty());
    tx.rollback().await.unwrap();
    // And the connection itself is back to the connecting role.
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(role, TENANT_ROLE);
}

#[tokio::test]
async fn concurrent_first_use_creates_one_personal_workspace() {
    let Some((_db, store)) = fresh().await else {
        return;
    };
    let tasks: Vec<_> = (0..16)
        .map(|i| {
            let s = store.clone();
            tokio::spawn(async move {
                if i % 2 == 0 {
                    s.personal_workspace("erin").await.unwrap()
                } else {
                    s.insert_link(&new_link("erin", &format!("erin{i}")), 7)
                        .await
                        .unwrap()
                        .workspace_id
                }
            })
        })
        .collect();
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    ids.dedup();
    assert_eq!(ids.len(), 1, "{ids:?}");
    let (workspaces, members): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM workspaces), (SELECT count(*) FROM workspace_members)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!((workspaces, members), (1, 1));
}

fn sqlstate(e: &sqlx::Error) -> String {
    match e {
        sqlx::Error::Database(db) => db.code().unwrap_or_default().into_owned(),
        other => format!("not a database error: {other}"),
    }
}
