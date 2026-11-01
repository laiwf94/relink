//! The `relink` binary itself: admin commands, configuration errors, and a
//! real server process stopped with SIGTERM.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

use common::{TestDb, admin_url, client, eventually};

const BIN: &str = env!("CARGO_BIN_EXE_relink");

/// The binary with an empty environment, except the coverage profile path so
/// `cargo llvm-cov` can measure the child process too.
fn bin() -> Command {
    let mut c = Command::new(BIN);
    c.env_clear();
    if let Ok(v) = std::env::var("LLVM_PROFILE_FILE") {
        c.env("LLVM_PROFILE_FILE", v);
    }
    c
}

fn relink(db_url: &str, args: &[&str]) -> std::process::Output {
    bin()
        .args(args)
        .env("RELINK_DATABASE_URL", db_url)
        .env("RELINK_LOG", "warn")
        .output()
        .unwrap()
}

#[test]
fn usage_and_configuration_errors() {
    let out = bin().arg("help").output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("usage: relink"));

    let out = bin().arg("bogus").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: relink"));

    let out = bin().output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("RELINK_DATABASE_URL is required"));

    let out = relink("not a url", &["migrate"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a valid postgres:// URL"));

    let out = relink("postgres://x@127.0.0.1:1/x", &["create-key", "Bad Owner"]);
    assert!(!out.status.success());
    let out = relink(
        "postgres://x@127.0.0.1:1/x",
        &["create-key", "alice", &"n".repeat(101)],
    );
    assert!(!out.status.success());
    let out = relink("postgres://x@127.0.0.1:1/x", &["revoke-key", "abc"]);
    assert!(!out.status.success());
    for bad in [
        &["create-key", "alice", "--scopes", "links:delete"][..],
        &["create-key", "alice", "--expires-in", "forever"],
        &["create-key", "alice", "--workspace"],
        &["rotate-key"],
        &["rotate-key", "1", "--overlap", "31d"],
    ] {
        let out = relink("postgres://x@127.0.0.1:1/x", bad);
        assert!(!out.status.success(), "{bad:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage: relink"),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn admin_commands_and_graceful_sigterm() {
    let Some(admin) = admin_url() else { return };
    let db = TestDb::create(&admin).await;

    let out = relink(&db.url, &["migrate"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = relink(&db.url, &["create-key", "alice", "laptop"]);
    assert!(out.status.success());
    let line = String::from_utf8(out.stdout).unwrap();
    let key = line
        .split_whitespace()
        .find_map(|w| w.strip_prefix("key="))
        .unwrap()
        .to_owned();
    let id = line
        .split_whitespace()
        .find_map(|w| w.strip_prefix("id="))
        .unwrap()
        .to_owned();
    assert!(relink_server::auth::is_well_formed(&key));
    let out = relink(&db.url, &["create-key", "alice"]);
    assert!(out.status.success());

    // Start a real server process on free ports.
    let port = free_port();
    let admin_port = free_port();
    let child = bin()
        .env("RELINK_DATABASE_URL", &db.url)
        .env("RELINK_ADDR", format!("127.0.0.1:{port}"))
        .env("RELINK_ADMIN_ADDR", format!("127.0.0.1:{admin_port}"))
        .env("RELINK_HEALTH_ENABLED", "false")
        .env("RELINK_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let http = client();
    let base = format!("http://127.0.0.1:{port}");
    let up = eventually(Duration::from_secs(20), || {
        let http = http.clone();
        let url = format!("{base}/healthz");
        async move { http.get(url).send().await.is_ok_and(|r| r.status() == 200) }
    })
    .await;
    assert!(up, "server did not start");
    let r = http
        .post(format!("{base}/v1/links"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"url":"https://example.com/","alias":"from-binary"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    assert_eq!(
        http.get(format!("{base}/from-binary"))
            .send()
            .await
            .unwrap()
            .status(),
        302
    );

    // SIGTERM: drains, flushes the click and exits cleanly.
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(out.status.success(), "exit status {:?}", out.status);
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(log.contains("click queue drained"), "{log}");
    assert!(log.contains("shutdown complete"));
    assert!(!log.contains(&key), "the API key must never be logged");
    assert!(
        !log.contains("postgres://"),
        "the database URL must never be logged"
    );

    let out = relink(&db.url, &["revoke-key", &id]);
    assert!(out.status.success());
    let out = relink(&db.url, &["revoke-key", &id]);
    assert!(!out.status.success(), "already revoked");

    // Scoped, expiring keys and rotation.
    let out = relink(
        &db.url,
        &[
            "create-key",
            "alice",
            "ci",
            "--scopes",
            "links:read,stats:read",
            "--expires-in",
            "30d",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8(out.stdout).unwrap();
    let field = |line: &str, name: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("{name} missing from {line}"))
            .to_owned()
    };
    assert_eq!(field(&line, "scopes"), "links:read,stats:read");
    assert_eq!(field(&line, "role"), "owner");
    assert_ne!(field(&line, "expires_at"), "never");
    let scoped = field(&line, "id");
    let out = relink(&db.url, &["rotate-key", &scoped, "--overlap", "1h"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = String::from_utf8(out.stdout).unwrap();
    assert_eq!(field(&line, "replaces"), scoped);
    assert_eq!(field(&line, "scopes"), "links:read,stats:read");
    assert!(relink_server::auth::is_well_formed(&field(&line, "key")));
    let out = relink(&db.url, &["rotate-key", &scoped]);
    assert!(!out.status.success(), "a key is rotated once");
    assert!(String::from_utf8_lossy(&out.stderr).contains("already rotated"));
    let out = relink(&db.url, &["create-key", "alice", "--workspace", "999999"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not a member"));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
