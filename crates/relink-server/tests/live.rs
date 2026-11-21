//! Live clicks (`GET /v1/links/{code}/live`, src/live.rs) over real HTTP
//! against a real Postgres: a click reaches an open stream within a second,
//! on the same instance and from another one; bots are left out unless
//! asked for; streams are capped per workspace; another workspace cannot
//! open one; and shutdown ends them.

mod common;

use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::{Value, json};

use common::{Harness, admin_url, eventually, metric};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[$($extra),*]).await
    }};
}

const PERSON: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148";
const CRAWLER: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

/// An open event stream and the bytes read from it not yet parsed.
struct Sse {
    resp: reqwest::Response,
    buf: String,
}

impl Sse {
    async fn open(base: &str, path: &str, key: &str) -> Result<Sse, (u16, String)> {
        let resp = common::client()
            .get(format!("{base}{path}"))
            .bearer_auth(key)
            .send()
            .await
            .unwrap();
        if resp.status() != 200 {
            let status = resp.status().as_u16();
            return Err((status, resp.text().await.unwrap()));
        }
        assert_eq!(resp.headers()["content-type"], "text/event-stream");
        assert_eq!(resp.headers()["cache-control"], "no-store");
        let mut s = Sse {
            resp,
            buf: String::new(),
        };
        let (event, data) = s.next(Duration::from_secs(5)).await.expect("open event");
        assert_eq!(event, "open");
        assert!(data["code"].is_string());
        Ok(s)
    }

    /// The next event (comments and `retry` skipped), or `None` if none
    /// arrives within `wait` or the stream ends.
    async fn next(&mut self, wait: Duration) -> Option<(String, Value)> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            while let Some(end) = self.buf.find("\n\n") {
                let frame: String = self.buf.drain(..end + 2).collect();
                let mut event = None;
                let mut data = None;
                for line in frame.lines() {
                    if let Some(e) = line.strip_prefix("event: ") {
                        event = Some(e.to_owned());
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        data = Some(serde_json::from_str(d).unwrap());
                    }
                }
                if let (Some(e), Some(d)) = (event, data) {
                    return Some((e, d));
                }
            }
            match tokio::time::timeout_at(deadline, self.resp.chunk()).await {
                Ok(Ok(Some(bytes))) => self.buf.push_str(std::str::from_utf8(&bytes).unwrap()),
                Ok(Ok(None)) | Ok(Err(_)) | Err(_) => return None,
            }
        }
    }

    /// Whether the stream ends (rather than staying open) within `wait`.
    async fn ends_within(&mut self, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, self.resp.chunk()).await {
                Ok(Ok(Some(_))) => continue,
                Ok(Ok(None)) | Ok(Err(_)) => return true,
                Err(_) => return false,
            }
        }
    }
}

async fn new_link(h: &Harness) -> String {
    let link = h.create(json!({"url": "https://example.com/"})).await;
    link["code"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn clicks_arrive_within_a_second_and_bots_only_when_asked() {
    let mut h = harness!(("RELINK_CLIENT_IP_HEADER", "x-client-ip"));
    let code = new_link(&h).await;
    let other = new_link(&h).await;
    let path = format!("/v1/links/{code}/live");
    let mut people = Sse::open(&h.base, &path, &h.alice).await.unwrap();
    let mut all = Sse::open(&h.base, &format!("{path}?include_bots=true"), &h.alice)
        .await
        .unwrap();

    let sent = Instant::now();
    let resp = h
        .visit(
            &code,
            &[
                ("user-agent", PERSON),
                ("x-client-ip", "203.0.113.9"),
                ("cf-ipcountry", "DE"),
                ("referer", "https://news.example.org/story"),
            ],
        )
        .await;
    assert_eq!(resp.status(), 302);
    let (event, click) = people.next(Duration::from_secs(1)).await.expect("a click");
    let latency = sent.elapsed();
    assert!(latency < Duration::from_secs(1), "{latency:?}");
    assert_eq!(event, "click");
    assert_eq!(click["code"], code.as_str());
    assert_eq!(click["country"], "DE");
    assert_eq!(click["device"], "mobile");
    assert_eq!(click["referrer"], "news.example.org");
    assert_eq!(click["bot"], false);
    let at = chrono::DateTime::parse_from_rfc3339(click["at"].as_str().unwrap()).unwrap();
    assert!((chrono::Utc::now() - at.to_utc()).num_seconds().abs() < 5);
    // Nothing about the visitor's address is sent.
    let text = click.to_string();
    assert!(!text.contains("203.0.113.9") && !text.contains("fingerprint"));
    assert_eq!(all.next(Duration::from_secs(1)).await.unwrap().1, click);

    // A crawler reaches only the stream that asked for bots; a click on
    // another link reaches neither.
    h.visit(&code, &[("user-agent", CRAWLER)]).await;
    h.visit(&other, &[("user-agent", PERSON)]).await;
    let (_, bot) = all.next(Duration::from_secs(1)).await.expect("the bot");
    assert_eq!(bot["device"], "bot");
    assert_eq!(bot["bot"], true);
    assert!(people.next(Duration::from_millis(300)).await.is_none());
    assert!(all.next(Duration::from_millis(300)).await.is_none());

    // A burst arrives whole, in order.
    for i in 0..50 {
        h.visit(&code, &[("x-client-ip", &format!("198.51.100.{i}"))])
            .await;
    }
    for _ in 0..50 {
        assert_eq!(
            people.next(Duration::from_secs(2)).await.expect("burst").0,
            "click"
        );
    }

    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_live_streams"), 2.0);
    // Both streams got the person and the burst, and one of them the bot.
    assert_eq!(metric(&m, "relink_live_clicks_sent_total"), 103.0);
    assert_eq!(metric(&m, "relink_live_clicks_lagged_total"), 0.0);

    // Shutdown ends open streams instead of waiting for them.
    let started = Instant::now();
    h.shutdown().await;
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(people.ends_within(Duration::from_secs(1)).await);
    assert!(all.ends_within(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn a_click_on_one_instance_reaches_a_stream_on_another() {
    let fast = [("RELINK_LIVE_ANNOUNCE_MS", "200")];
    let mut h = harness!(fast[0]);
    let other = h.second_instance(&fast).await;
    let other_base = format!("http://{}", other.addr);
    let code = new_link(&h).await;
    let mut stream = Sse::open(&other_base, &format!("/v1/links/{code}/live"), &h.alice)
        .await
        .unwrap();
    // The first instance learns of the stream from the announcement.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        h.visit(&code, &[("user-agent", PERSON)]).await;
        if stream.next(Duration::from_millis(100)).await.is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "clicks never crossed instances");
    }
    // Drain whatever else the warm-up produced, then time one click.
    while stream.next(Duration::from_millis(300)).await.is_some() {}
    let sent = Instant::now();
    h.visit(&code, &[("user-agent", PERSON), ("cf-ipcountry", "NZ")])
        .await;
    let (event, click) = stream
        .next(Duration::from_secs(1))
        .await
        .expect("a relayed click");
    assert!(
        sent.elapsed() < Duration::from_secs(1),
        "{:?}",
        sent.elapsed()
    );
    assert_eq!(event, "click");
    assert_eq!(click["country"], "NZ");
    let m = h.metrics().await;
    assert!(metric(&m, "relink_live_clicks_relayed_total") >= 2.0);
    let m = common::client()
        .get(format!("http://{}/metrics", other.admin_addr))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metric(&m, "relink_live_clicks_received_total") >= 2.0);
    drop(stream);
    other.shutdown().await;
    h.shutdown().await;
}

#[tokio::test]
async fn streams_are_per_workspace_and_capped() {
    let mut h = harness!(("RELINK_LIVE_MAX_PER_WORKSPACE", "2"));
    let code = new_link(&h).await;
    let path = format!("/v1/links/{code}/live");
    // Another workspace cannot see the link, let alone watch it.
    let (status, body) = Sse::open(&h.base, &path, &h.bob).await.err().unwrap();
    assert_eq!(status, 404, "{body}");
    let (status, _) = Sse::open(&h.base, "/v1/links/nope/live", &h.alice)
        .await
        .err()
        .unwrap();
    assert_eq!(status, 404);
    let (status, body) = Sse::open(&h.base, &format!("{path}?include_bots=maybe"), &h.alice)
        .await
        .err()
        .unwrap();
    assert_eq!(status, 400, "{body}");
    let (status, _) = Sse::open(&h.base, &format!("{path}?since=0"), &h.alice)
        .await
        .err()
        .unwrap();
    assert_eq!(status, 400);
    let (status, _) = Sse::open(&h.base, &path, "rlk_not_a_key")
        .await
        .err()
        .unwrap();
    assert_eq!(status, 401);

    let first = Sse::open(&h.base, &path, &h.alice).await.unwrap();
    let _second = Sse::open(&h.base, &path, &h.alice).await.unwrap();
    let (status, body) = Sse::open(&h.base, &path, &h.alice).await.err().unwrap();
    assert_eq!(status, 429, "{body}");
    let err: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(err["error"]["code"], "resource_exhausted");
    // Bob's workspace has its own allowance.
    let (status, bob_link) = h
        .api(
            Method::POST,
            "/v1/links",
            &h.bob,
            Some(json!({"url": "https://example.com/"})),
        )
        .await;
    assert_eq!(status, 201);
    let bob_path = format!("/v1/links/{}/live", bob_link["code"].as_str().unwrap());
    let _bobs = Sse::open(&h.base, &bob_path, &h.bob).await.unwrap();
    // Closing a stream frees its place.
    drop(first);
    let reopened = eventually(Duration::from_secs(5), || async {
        Sse::open(&h.base, &path, &h.alice).await.is_ok()
    })
    .await;
    assert!(reopened);
    assert!(metric(&h.metrics().await, "relink_live_streams_refused_total") >= 1.0);
    h.shutdown().await;
}

#[tokio::test]
async fn streams_end_at_their_age_limit() {
    let mut h = harness!(
        ("RELINK_LIVE_MAX_AGE_S", "1"),
        ("RELINK_LIVE_KEEPALIVE_MS", "200")
    );
    let code = new_link(&h).await;
    let mut s = Sse::open(&h.base, &format!("/v1/links/{code}/live"), &h.alice)
        .await
        .unwrap();
    let started = Instant::now();
    assert!(s.ends_within(Duration::from_secs(3)).await);
    assert!(started.elapsed() >= Duration::from_millis(700));
    assert!(
        eventually(Duration::from_secs(2), || async {
            metric(&h.metrics().await, "relink_live_streams") == 0.0
        })
        .await
    );
    h.shutdown().await;
}
