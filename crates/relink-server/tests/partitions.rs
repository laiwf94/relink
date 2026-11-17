//! Raw click events in monthly partitions: the partitions migration 0020
//! creates, routing at month boundaries in any session time zone, retention
//! by dropping whole months, one manager at a time across instances, and
//! tenant isolation through the parent table.

mod common;

use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, Utc};
use relink_server::partitions::{self, LOCK_KEY, Month, Outcome, Report};
use relink_server::server::{migrate_with_retry, open_db};
use relink_server::store::Db;
use relink_server::util::{now_ms, utc_day};
use sqlx::{Connection, PgConnection, Row};

use common::{TestDb, admin_url, config};

async fn fresh(extra: &[(&str, &str)]) -> Option<(TestDb, Db)> {
    let admin = admin_url()?;
    let db = TestDb::create(&admin).await;
    let store = open_db(&config(&db.url, extra)).unwrap();
    migrate_with_retry(&store, Duration::from_secs(10))
        .await
        .unwrap();
    Some((db, store))
}

fn m(year: i32, month: u32) -> Month {
    Month::new(year, month).unwrap()
}

/// Days since the epoch of a date.
fn day(y: i32, mo: u32, d: u32) -> i32 {
    let date = NaiveDate::from_ymd_opt(y, mo, d).unwrap();
    (date - NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()).num_days() as i32
}

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().to_utc()
}

/// The month partitions of click_events, oldest first, and any others.
async fn existing(store: &Db) -> (Vec<Month>, Vec<String>) {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
          WHERE i.inhparent = 'click_events'::regclass ORDER BY 1",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    let mut months = Vec::new();
    let mut other = Vec::new();
    for n in names {
        match Month::parse_table(&n) {
            Some(x) => months.push(x),
            None => other.push(n),
        }
    }
    months.sort();
    (months, other)
}

async fn insert(
    store: &Db,
    workspace: i64,
    link: i64,
    when: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO click_events (at, workspace_id, link_id, country, device, referrer_host, visitor)
         VALUES ($1, $2, $3, 'NZ', 'mobile', '(direct)', $4)",
    )
    .bind(when)
    .bind(workspace)
    .bind(link)
    .bind(vec![7u8; 16])
    .execute(store.pool())
    .await
    .map(|_| ())
}

/// The partition each event of `link` landed in, by time.
async fn placement(store: &Db, link: i64) -> Vec<(DateTime<Utc>, String)> {
    sqlx::query("SELECT at, tableoid::regclass::text AS part FROM click_events WHERE link_id = $1 ORDER BY at")
        .bind(link)
        .fetch_all(store.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get("at"), r.get("part")))
        .collect()
}

fn done(o: Outcome) -> Report {
    match o {
        Outcome::Done(r) => r,
        Outcome::Busy => panic!("unexpectedly busy"),
    }
}

#[tokio::test]
async fn migration_creates_the_current_month_and_two_ahead() {
    let Some((_db, store)) = fresh(&[]).await else {
        return;
    };
    let current = Month::of_day(utc_day(now_ms()));
    let (months, other) = existing(&store).await;
    assert_eq!(months, vec![current, current.plus(1), current.plus(2)]);
    assert!(other.is_empty(), "{other:?}");
    // The manager agrees: nothing to do today.
    let r = done(
        partitions::maintain(&store, utc_day(now_ms()), 13)
            .await
            .unwrap(),
    );
    assert_eq!(r, Report::default());
    // An insert for now lands in the current month's partition.
    let now = Utc::now();
    insert(&store, 1, 1, now).await.unwrap();
    assert_eq!(placement(&store, 1).await[0].1, current.table());
}

#[tokio::test]
async fn events_land_in_their_utc_month_whatever_the_session_time_zone() {
    let Some((db, store)) = fresh(&[]).await else {
        return;
    };
    // The server's own sessions run in UTC, but the partition function may
    // be called from any session (the migration, an operator's psql). Here
    // it runs 14 hours ahead of UTC and 11 behind: bounds written without
    // an offset would move by those amounts.
    for (tz, month) in [
        ("Pacific/Kiritimati", "2030-11-15"),
        ("Pacific/Pago_Pago", "2030-12-31"),
    ] {
        let mut conn = PgConnection::connect(&db.url).await.unwrap();
        sqlx::query(sqlx::AssertSqlSafe(format!("SET TIME ZONE '{tz}'")))
            .execute(&mut conn)
            .await
            .unwrap();
        let created: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT relink_click_events_partition('{month}')"
        )))
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert!(created, "{tz}");
    }
    let bounds: Vec<String> = sqlx::query_scalar(
        "SELECT pg_get_expr(relpartbound, oid) FROM pg_class
          WHERE relname IN ('click_events_p203011', 'click_events_p203012') ORDER BY relname",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        bounds,
        [
            "FOR VALUES FROM ('2030-11-01 00:00:00+00') TO ('2030-12-01 00:00:00+00')",
            "FOR VALUES FROM ('2030-12-01 00:00:00+00') TO ('2031-01-01 00:00:00+00')",
        ]
    );
    // The manager fills in the month after and finds the other two there.
    let r = done(
        partitions::maintain(&store, day(2030, 11, 15), 1000)
            .await
            .unwrap(),
    );
    assert_eq!(r.created, vec![m(2031, 1)]);

    for (i, (when, part)) in [
        ("2030-11-01T00:00:00Z", "click_events_p203011"),
        ("2030-11-30T23:59:59.999999Z", "click_events_p203011"),
        ("2030-12-01T00:00:00Z", "click_events_p203012"),
        // 23:30 on 30 November in Pago Pago (UTC-11) is December in UTC.
        ("2030-11-30T23:30:00-11:00", "click_events_p203012"),
        ("2031-01-31T23:59:59Z", "click_events_p203101"),
    ]
    .into_iter()
    .enumerate()
    {
        insert(&store, 1, 100 + i as i64, at(when)).await.unwrap();
        assert_eq!(placement(&store, 100 + i as i64).await[0].1, part, "{when}");
    }

    // A month with no partition is refused rather than kept somewhere else.
    let err = insert(&store, 1, 1, at("2045-06-01T00:00:00Z"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no partition"), "{err}");
}

#[tokio::test]
async fn retention_drops_whole_old_months_and_nothing_else() {
    let Some((_db, store)) = fresh(&[]).await else {
        return;
    };
    // Twelve months of history, from 2030-01 to 2030-12.
    for n in 0..12 {
        let month = m(2030, 1).plus(n);
        let r = done(
            partitions::maintain(&store, day(month.year(), month.month(), 1), 1000)
                .await
                .unwrap(),
        );
        assert!(r.dropped.is_empty());
        insert(
            &store,
            1,
            7,
            at(&format!(
                "{}-{:02}-15T12:00:00Z",
                month.year(),
                month.month()
            )),
        )
        .await
        .unwrap();
    }
    // An operator's own partition, older than everything, is left alone.
    sqlx::query(
        "CREATE TABLE click_events_archive PARTITION OF click_events
             FOR VALUES FROM ('1999-01-01 00:00:00+00') TO ('2000-01-01 00:00:00+00')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    insert(&store, 1, 7, at("1999-06-01T00:00:00Z"))
        .await
        .unwrap();

    // 2030-12 with six months' retention keeps 2030-07 to 2030-12 and drops
    // everything before, including the months the migration created for
    // today (which, in this test's calendar, are far in the past).
    let r = done(
        partitions::maintain(&store, day(2030, 12, 31), 6)
            .await
            .unwrap(),
    );
    let real_now = Month::of_day(utc_day(now_ms()));
    let mut expected: Vec<Month> = (0..3).map(|n| real_now.plus(n)).collect();
    expected.extend((0..6).map(|n| m(2030, 1).plus(n)));
    expected.sort();
    expected.dedup();
    assert_eq!(r.dropped, expected);
    assert_eq!(r.unknown, vec!["click_events_archive".to_owned()]);
    assert!(r.created.is_empty(), "2031-01 and 2031-02 exist: {r:?}");

    let (months, other) = existing(&store).await;
    let kept: Vec<Month> = (6..14).map(|n| m(2030, 1).plus(n)).collect();
    assert_eq!(months, kept);
    assert_eq!(other, vec!["click_events_archive".to_owned()]);

    // Events of dropped months are gone; the rest are untouched.
    let rows = placement(&store, 7).await;
    let parts: Vec<&str> = rows.iter().map(|(_, p)| p.as_str()).collect();
    assert_eq!(
        parts,
        [
            "click_events_archive",
            "click_events_p203007",
            "click_events_p203008",
            "click_events_p203009",
            "click_events_p203010",
            "click_events_p203011",
            "click_events_p203012",
        ]
    );

    // A second run the same day changes nothing.
    let r = done(
        partitions::maintain(&store, day(2030, 12, 31), 6)
            .await
            .unwrap(),
    );
    assert!(r.created.is_empty() && r.dropped.is_empty(), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_instance_at_a_time() {
    let Some((db, store)) = fresh(&[]).await else {
        return;
    };
    // Another instance holds the lock: this run does nothing.
    let mut other = PgConnection::connect(&db.url).await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut other)
        .await
        .unwrap();
    assert_eq!(
        partitions::maintain(&store, day(2031, 5, 1), 13)
            .await
            .unwrap(),
        Outcome::Busy
    );
    assert!(!existing(&store).await.0.contains(&m(2031, 5)));
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(&mut other)
        .await
        .unwrap();

    // Eight instances at once: no errors, and each month is created once.
    let mut runs = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        runs.spawn(async move { partitions::maintain(&store, day(2031, 5, 1), 13).await });
    }
    let mut created = Vec::new();
    while let Some(r) = runs.join_next().await {
        if let Outcome::Done(r) = r.unwrap().unwrap() {
            created.extend(r.created);
        }
    }
    created.sort();
    assert_eq!(created, vec![m(2031, 5), m(2031, 6), m(2031, 7)]);
}

#[tokio::test]
async fn a_busy_partition_makes_the_run_give_up_quickly_and_retry() {
    // A database timeout well above the lock timeout, so the error below
    // comes from lock_timeout and not from the query bound.
    let Some((db, store)) = fresh(&[("RELINK_DB_TIMEOUT_MS", "20000")]).await else {
        return;
    };
    done(
        partitions::maintain(&store, day(2030, 1, 1), 1000)
            .await
            .unwrap(),
    );
    // A long query is reading January when February's run wants to drop it.
    let mut reader = PgConnection::connect(&db.url).await.unwrap();
    sqlx::query("BEGIN").execute(&mut reader).await.unwrap();
    // Read through the partition itself, so only January is locked.
    sqlx::query("SELECT count(*) FROM click_events_p203001")
        .execute(&mut reader)
        .await
        .unwrap();
    let start = Instant::now();
    let err = partitions::maintain(&store, day(2030, 2, 1), 1)
        .await
        .unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    assert!(err.to_string().contains("lock"), "{err}");
    // Nothing of the failed run was kept: February's new month is not there.
    assert!(!existing(&store).await.0.contains(&m(2030, 4)));
    // Inserts go on.
    insert(&store, 1, 9, at("2030-02-10T00:00:00Z"))
        .await
        .unwrap();

    sqlx::query("COMMIT").execute(&mut reader).await.unwrap();
    let r = done(
        partitions::maintain(&store, day(2030, 2, 1), 1)
            .await
            .unwrap(),
    );
    assert!(r.dropped.contains(&m(2030, 1)), "{r:?}");
    assert!(r.created.contains(&m(2030, 4)), "{r:?}");
}

#[tokio::test]
async fn tenants_see_their_own_events_and_never_a_partition() {
    let Some((_db, store)) = fresh(&[]).await else {
        return;
    };
    let ids: Vec<i64> =
        sqlx::query_scalar("INSERT INTO workspaces (name) VALUES ('a'), ('b') RETURNING id")
            .fetch_all(store.pool())
            .await
            .unwrap();
    let (a, b) = (ids[0], ids[1]);
    let now = Utc::now();
    insert(&store, a, 1, now).await.unwrap();
    insert(&store, a, 1, now).await.unwrap();
    insert(&store, b, 2, now).await.unwrap();

    let mut tx = store.begin_tenant(a).await.unwrap();
    let seen: Vec<i64> = sqlx::query_scalar("SELECT workspace_id FROM click_events")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    assert_eq!(seen, vec![a, a]);
    tx.rollback().await.unwrap();

    // A partition read directly is refused, not filtered.
    let part = Month::of_day(utc_day(now_ms())).table();
    let mut tx = store.begin_tenant(a).await.unwrap();
    let err = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {part}")))
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
    drop(tx);

    // Tenants cannot write events either.
    let mut tx = store.begin_tenant(a).await.unwrap();
    let err = sqlx::query(
        "INSERT INTO click_events (at, workspace_id, link_id, country, device, referrer_host)
         VALUES (now(), relink_current_workspace(), 1, 'NZ', 'mobile', '(direct)')",
    )
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

#[tokio::test]
async fn events_hold_no_address_and_check_their_shape() {
    let Some((_db, store)) = fresh(&[]).await else {
        return;
    };
    // The columns are exactly these: nothing that could hold an address.
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
          WHERE table_name = 'click_events' ORDER BY ordinal_position",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        cols,
        [
            "at",
            "workspace_id",
            "link_id",
            "domain_id",
            "country",
            "device",
            "referrer_host",
            "visitor",
            "bot"
        ]
    );
    for bad in [
        "'NZL', 'mobile', '(direct)', NULL",
        "'NZ', '', '(direct)', NULL",
        "'NZ', 'mobile', '', NULL",
        "'NZ', 'mobile', '(direct)', '\\x00'::bytea",
    ] {
        let r = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO click_events (at, workspace_id, link_id, country, device, referrer_host, visitor)
             VALUES (now(), 1, 1, {bad})"
        )))
        .execute(store.pool())
        .await;
        assert!(
            r.unwrap_err().to_string().contains("check constraint"),
            "{bad}"
        );
    }
}
