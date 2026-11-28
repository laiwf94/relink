//! Background jobs end to end: CSV and NDJSON imports with per-row errors,
//! uploads refused whole, exports that import again, bulk patches,
//! cancelling, limits, workspace isolation, a lost lease taken over with
//! every row done once, jobs taking turns, and the background worker.

mod common;

use std::time::Duration;

use common::{Harness, admin_url, eventually, metric};
use relink_server::jobs::{JobWorker, Step};
use reqwest::Method;
use serde_json::{Value, json};

macro_rules! harness {
    ($($extra:expr),*) => {{
        let Some(admin) = admin_url() else { return };
        Harness::start(&admin, &[
            // Tests drive the worker by hand unless they turn it on.
            ("RELINK_JOBS_ENABLED", "false"),
            $($extra),*
        ]).await
    }};
}

async fn upload(h: &Harness, key: &str, content_type: &str, body: &[u8]) -> (u16, Value) {
    let resp = h
        .http
        .post(format!("{}/v1/jobs/import", h.base))
        .bearer_auth(key)
        .header("content-type", content_type)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let location = resp
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_owned());
    let mut body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    if status == 202 {
        assert_eq!(location, Some(format!("/v1/jobs/{}", body["id"])));
    }
    if let Some(l) = location {
        body["location"] = Value::String(l);
    }
    (status, body)
}

/// Runs rounds until no job is left to run.
async fn drain(h: &Harness) {
    let worker = JobWorker::new(h.app().clone());
    for _ in 0..10_000 {
        if !worker.round().await {
            return;
        }
    }
    panic!("jobs never finished");
}

async fn job(h: &Harness, key: &str, id: &Value) -> Value {
    let (status, job) = h
        .api(Method::GET, &format!("/v1/jobs/{id}"), key, None)
        .await;
    assert_eq!(status, 200, "{job}");
    job
}

async fn output(h: &Harness, key: &str, id: &Value) -> (u16, String, String) {
    let resp = h
        .http
        .get(format!("{}/v1/jobs/{id}/output", h.base))
        .bearer_auth(key)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let ct = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    (status, ct, resp.text().await.unwrap())
}

async fn count(h: &Harness, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(h.store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_csv_import_inserts_every_good_row_and_names_the_bad_ones() {
    let mut h = harness!();
    h.create(json!({"alias": "taken", "url": "https://example.com/"}))
        .await;
    let file = "\u{feff}code,url,redirect_type,enabled,expires_at,short_url\r\n\
                spring,https://example.com/spring,301,false,,http://x/spring\r\n\
                ,https://example.com/random,,,,\r\n\
                \r\n\
                taken,https://example.com/dup,,,,\r\n\
                bad,ftp://example.com/,,,,\r\n\
                \"quoted\",\"https://example.com/a,b\",,,,\r\n\
                spring,https://example.com/again,,,,\r\n\
                odd,https://example.com/,999,,,\r\n\
                late,https://example.com/,,,2001-01-01T00:00:00Z,\r\n\
                short,https://example.com/\r\n";
    let (status, queued) = upload(&h, &h.alice, "text/csv; charset=utf-8", file.as_bytes()).await;
    assert_eq!(status, 202, "{queued}");
    assert_eq!(queued["kind"], "import");
    assert_eq!(queued["format"], "csv");
    assert_eq!(queued["state"], "queued");
    assert_eq!(queued["total"], 9);
    assert_eq!(queued["processed"], 0);
    assert_eq!(queued["progress"], 0.0);
    assert_eq!(queued["created_by"], "alice");
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(done["total"], 9);
    assert_eq!(done["processed"], 9);
    assert_eq!(done["succeeded"], 3);
    assert_eq!(done["failed"], 6);
    assert_eq!(done["progress"], 1.0);
    assert!(done["finished_at"].is_string());
    assert_eq!(done["output_url"], Value::Null);
    let errors: Vec<(i64, String)> = done["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["row"].as_i64().unwrap(),
                e["code"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        errors,
        [
            (3, "already_exists".into()),
            (4, "invalid_argument".into()),
            (6, "already_exists".into()),
            (7, "invalid_argument".into()),
            (8, "invalid_argument".into()),
            (9, "invalid_argument".into()),
        ]
    );
    let messages: Vec<&str> = done["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["message"].as_str().unwrap())
        .collect();
    assert_eq!(messages[0], "this alias is already taken");
    assert!(
        messages[1].starts_with("destinations[0].url: "),
        "{}",
        messages[1]
    );
    assert_eq!(messages[3], "redirect_type must be 301, 302, 307 or 308");
    assert_eq!(messages[4], "expires_at must be in the future");
    assert_eq!(messages[5], "the row has 2 fields; the header has 6");

    // The good rows are links like any other, made by alice.
    let (status, spring) = h.api(Method::GET, "/v1/links/spring", &h.alice, None).await;
    assert_eq!(status, 200);
    assert_eq!(spring["redirect_type"], 301);
    assert_eq!(spring["enabled"], false);
    assert_eq!(
        spring["destinations"][0]["url"],
        "https://example.com/spring"
    );
    let (_, quoted) = h.api(Method::GET, "/v1/links/quoted", &h.alice, None).await;
    assert_eq!(quoted["destinations"][0]["url"], "https://example.com/a,b");
    assert_eq!(h.visit("quoted", &[]).await.status(), 302);
    let random: i64 = count(
        &h,
        "SELECT count(*) FROM links WHERE destinations->0->>'url' = 'https://example.com/random'",
    )
    .await;
    assert_eq!(random, 1);
    assert_eq!(
        count(&h, "SELECT count(*) FROM links WHERE owner = 'alice'").await,
        4
    );
    // Audited as alice's key, with the job itself.
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM audit_log WHERE action = 'link.create' AND actor = 'alice' \
              AND via LIKE 'key:%'"
        )
        .await,
        4
    );
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM audit_log WHERE action = 'job.create'"
        )
        .await,
        1
    );
    // A finished import keeps no input.
    assert_eq!(count(&h, "SELECT count(*) FROM job_chunks").await, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn an_ndjson_import_takes_create_bodies() {
    let mut h = harness!();
    let file = concat!(
        r#"{"alias":"abtest","destinations":[{"url":"https://example.com/a","weight":3},{"url":"https://example.com/b","weight":1}]}"#,
        "\n",
        r#"{"alias":"ruled","url":"https://example.com/","rules":[{"if":{"country":["DE"]},"url":"https://example.de/"}]}"#,
        "\n\n",
        r#"{"alias":"nope","colour":"red"}"#,
        "\n",
        r#"not json"#,
    );
    let (status, queued) = upload(&h, &h.alice, "application/x-ndjson", file.as_bytes()).await;
    assert_eq!(status, 202, "{queued}");
    assert_eq!(queued["format"], "ndjson");
    assert_eq!(queued["total"], 4);
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["succeeded"], 2, "{done}");
    assert_eq!(done["errors"][0]["row"], 3);
    assert!(
        done["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("unknown field `colour`")
    );
    assert_eq!(done["errors"][1]["row"], 4);
    let (_, ab) = h.api(Method::GET, "/v1/links/abtest", &h.alice, None).await;
    assert_eq!(ab["destinations"][1]["weight"], 1);
    let de = h.visit("ruled", &[("cf-ipcountry", "DE")]).await;
    assert_eq!(de.headers()["location"], "https://example.de/");
    h.shutdown().await;
}

#[tokio::test]
async fn uploads_that_cannot_be_read_are_refused_whole() {
    let mut h = harness!(("RELINK_JOB_MAX_UPLOAD_MB", "1"));
    let cases: Vec<(&str, Vec<u8>, u16, &str)> = vec![
        (
            "application/json",
            b"url\n".to_vec(),
            415,
            "unsupported_media_type",
        ),
        ("text/csv", b"".to_vec(), 400, "the file has no header"),
        ("text/csv", b"url\n\n".to_vec(), 400, "the file has no rows"),
        (
            "application/x-ndjson",
            b"\n \n".to_vec(),
            400,
            "the file has no rows",
        ),
        (
            "text/csv",
            b"code\nx\n".to_vec(),
            400,
            "the header has no url column",
        ),
        (
            "text/csv",
            b"url\n\"https://example.com/\n".to_vec(),
            400,
            "the file ends inside a quoted field",
        ),
        (
            "text/csv",
            [b"url\nhttps://example.com/\n".as_slice(), &[b'a'; 70_000]].concat(),
            400,
            "row 2 is longer than 65536 bytes",
        ),
    ];
    for (ct, body, want, what) in cases {
        let (status, err) = upload(&h, &h.alice, ct, &body).await;
        assert_eq!(status, want, "{ct} {what}: {err}");
        let msg = err["error"]["message"].as_str().unwrap();
        assert!(
            msg == what || err["error"]["code"] == what,
            "{ct} {what}: {err}"
        );
    }
    // Over the limit: refused once the limit is passed.
    let mut big = b"url\n".to_vec();
    while big.len() <= 1 << 20 {
        big.extend_from_slice(b"https://example.com/a-long-enough-path\n");
    }
    let (status, err) = upload(&h, &h.alice, "text/csv", &big).await;
    assert_eq!(status, 413, "{err}");
    assert_eq!(err["error"]["code"], "payload_too_large");
    // Nothing was stored for any of them.
    assert_eq!(count(&h, "SELECT count(*) FROM jobs").await, 0);
    assert_eq!(count(&h, "SELECT count(*) FROM job_chunks").await, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn an_export_imports_again_into_another_workspace() {
    let mut h = harness!();
    for i in 0..1_234 {
        let body = if i % 3 == 0 {
            json!({"alias": format!("lnk{i}"), "url": format!("https://example.com/{i}?a=1,2"),
                   "redirect_type": 301, "max_clicks": 5 + i})
        } else {
            json!({"alias": format!("lnk{i}"), "url": format!("https://example.com/{i}"),
                   "enabled": i % 2 == 0, "conversion_window_days": 7})
        };
        let (status, _) = h.api(Method::POST, "/v1/links", &h.alice, Some(body)).await;
        assert_eq!(status, 201);
    }
    let (status, queued) = h
        .api(
            Method::POST,
            "/v1/jobs/export",
            &h.alice,
            Some(json!({"format": "csv"})),
        )
        .await;
    assert_eq!(status, 202, "{queued}");
    assert_eq!(queued["total"], 1_234);
    // Not ready yet.
    let (status, ..) = output(&h, &h.alice, &queued["id"]).await;
    assert_eq!(status, 409);
    // Links made after the export are not in it.
    h.create(json!({"alias": "after", "url": "https://example.com/"}))
        .await;
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(done["processed"], 1_234);
    assert_eq!(
        done["output_url"],
        format!("/v1/jobs/{}/output", queued["id"])
    );
    let (status, ct, csv) = output(&h, &h.alice, &queued["id"]).await;
    assert_eq!(status, 200);
    assert_eq!(ct, "text/csv; charset=utf-8");
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 1_235);
    assert_eq!(
        lines[0],
        "code,domain,short_url,url,redirect_type,expires_at,max_clicks,enabled,health_check,\
         fallback_url,conversion_window_days,version,created_at,updated_at"
    );
    assert!(
        lines[1].starts_with(&format!(
            "lnk0,,{}/lnk0,\"https://example.com/0?a=1,2\",301,,5,true,false,,,1,",
            h.app().cfg.public_base_url
        )),
        "{}",
        lines[1]
    );
    assert!(!csv.contains("after"));
    // Another workspace imports the file as it is: the same links on its
    // own codes would clash with alice's, so bob drops the code column.
    let (status, queued) = upload(&h, &h.bob, "text/csv", csv.as_bytes()).await;
    assert_eq!(status, 202);
    drain(&h).await;
    let clash = job(&h, &h.bob, &queued["id"]).await;
    assert_eq!(clash["failed"], 1_234, "every code is alice's");
    assert_eq!(clash["errors"].as_array().unwrap().len(), 100);
    let without_codes: String = csv
        .lines()
        .map(|l| l.split_once(',').unwrap().1.to_owned() + "\n")
        .collect();
    let (status, queued) = upload(&h, &h.bob, "text/csv", without_codes.as_bytes()).await;
    assert_eq!(status, 202);
    drain(&h).await;
    let done = job(&h, &h.bob, &queued["id"]).await;
    assert_eq!(done["succeeded"], 1_234, "{done}");
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM links a JOIN links b ON a.destinations = b.destinations \
               AND a.redirect_status = b.redirect_status AND a.max_clicks IS NOT DISTINCT FROM b.max_clicks \
               AND a.enabled = b.enabled \
               AND a.conversion_window_days IS NOT DISTINCT FROM b.conversion_window_days \
             WHERE a.owner = 'alice' AND b.owner = 'bob'"
        )
        .await,
        1_234
    );

    // NDJSON: each line is the link as the API shows it.
    let (_, queued) = h
        .api(
            Method::POST,
            "/v1/jobs/export",
            &h.bob,
            Some(json!({"format": "ndjson"})),
        )
        .await;
    drain(&h).await;
    let (status, ct, nd) = output(&h, &h.bob, &queued["id"]).await;
    assert_eq!(status, 200);
    assert_eq!(ct, "application/x-ndjson");
    let views: Vec<Value> = nd
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(views.len(), 1_234);
    let (_, first) = h
        .api(
            Method::GET,
            &format!("/v1/links/{}", views[0]["code"].as_str().unwrap()),
            &h.bob,
            None,
        )
        .await;
    assert_eq!(views[0], first);
    // Alice cannot see bob's jobs.
    let (status, _) = h
        .api(
            Method::GET,
            &format!("/v1/jobs/{}", queued["id"]),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 404);
    let (status, ..) = output(&h, &h.alice, &queued["id"]).await;
    assert_eq!(status, 404);
    // An export names a domain of the workspace.
    let (status, empty) = h
        .api(
            Method::POST,
            "/v1/jobs/export",
            &h.alice,
            Some(json!({"format": "csv", "domain": "nowhere.example"})),
        )
        .await;
    assert_eq!(status, 400, "{empty}");
    h.shutdown().await;
}

#[tokio::test]
async fn a_bulk_patch_changes_each_link_as_a_patch_would() {
    let mut h = harness!();
    for i in 0..450 {
        h.create(json!({"alias": format!("pat{i}"), "url": "https://example.com/"}))
            .await;
    }
    let (status, queued) = h
        .api(
            Method::POST,
            "/v1/jobs/patch",
            &h.alice,
            Some(json!({
                "filter": {"codes": ["pat1", "pat2", "ghost", "pat2", "pat3"]},
                "patch": {"url": "https://example.com/moved", "redirect_type": 308}
            })),
        )
        .await;
    assert_eq!(status, 202, "{queued}");
    assert_eq!(queued["kind"], "patch");
    assert_eq!(queued["format"], Value::Null);
    assert_eq!(queued["total"], 4);
    assert_eq!(queued["failed"], 1);
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(
        (done["succeeded"].as_i64(), done["failed"].as_i64()),
        (Some(3), Some(1))
    );
    assert_eq!(
        done["errors"],
        json!([{"row": 3, "code": "not_found", "message": "no link ghost"}])
    );
    for code in ["pat1", "pat2", "pat3"] {
        let resp = h.visit(code, &[]).await;
        assert_eq!(resp.status(), 308);
        assert_eq!(resp.headers()["location"], "https://example.com/moved");
        let (_, versions) = h
            .api(
                Method::GET,
                &format!("/v1/links/{code}/versions"),
                &h.alice,
                None,
            )
            .await;
        assert_eq!(versions["versions"].as_array().unwrap().len(), 2);
    }
    assert_eq!(h.visit("pat4", &[]).await.status(), 302);

    // Every link, across pages.
    let (status, queued) = h
        .api(
            Method::POST,
            "/v1/jobs/patch",
            &h.alice,
            Some(json!({"filter": {"all": true}, "patch": {"enabled": false}})),
        )
        .await;
    assert_eq!(status, 202);
    assert_eq!(queued["total"], 450);
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["succeeded"], 450, "{done}");
    assert_eq!(
        count(&h, "SELECT count(*) FROM links WHERE enabled").await,
        0
    );
    assert_ne!(h.visit("pat449", &[]).await.status(), 302);
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM audit_log WHERE action = 'link.update'"
        )
        .await,
        453
    );

    for (body, why) in [
        (
            json!({"filter": {}, "patch": {"enabled": true}}),
            "filter: give codes, or all: true",
        ),
        (
            json!({"filter": {"codes": ["a"], "all": true}, "patch": {"enabled": true}}),
            "filter: give codes or all, not both",
        ),
        (
            json!({"filter": {"codes": []}, "patch": {"enabled": true}}),
            "filter.codes must have 1 to 1000 entries",
        ),
        (
            json!({"filter": {"all": true}, "patch": {}}),
            "patch: the request changes nothing",
        ),
        (
            json!({"filter": {"all": true}, "patch": {"redirect_type": 200}}),
            "patch: redirect_type must be 301, 302, 307 or 308",
        ),
        (
            json!({"filter": {"all": true, "domain": "nope.example"}, "patch": {"enabled": true}}),
            "domain: nope.example is not a domain of this workspace",
        ),
    ] {
        let (status, err) = h
            .api(Method::POST, "/v1/jobs/patch", &h.alice, Some(body))
            .await;
        assert_eq!(status, 400, "{err}");
        assert!(
            err["error"]["message"].as_str().unwrap().starts_with(why),
            "{err}"
        );
    }
    let (status, err) = h
        .api(
            Method::POST,
            "/v1/jobs/patch",
            &h.alice,
            Some(json!({"filter": {"all": true}, "patch": {"colour": 1}})),
        )
        .await;
    assert_eq!(status, 400);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown field `colour`")
    );
    h.shutdown().await;
}

#[tokio::test]
async fn a_patch_that_goes_stale_fails_the_job() {
    let mut h = harness!();
    h.create(json!({"alias": "soon", "url": "https://example.com/"}))
        .await;
    let at = (chrono::Utc::now() + chrono::Duration::milliseconds(1_500)).to_rfc3339();
    let (status, queued) = h
        .api(
            Method::POST,
            "/v1/jobs/patch",
            &h.alice,
            Some(json!({"filter": {"all": true}, "patch": {"expires_at": at}})),
        )
        .await;
    assert_eq!(status, 202, "{queued}");
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    drain(&h).await;
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["state"], "failed", "{done}");
    assert_eq!(done["error"], "patch: expires_at must be in the future");
    assert_eq!(done["processed"], 0);
    assert!(metric(&h.metrics().await, "relink_jobs_failed_total") >= 1.0);
    h.shutdown().await;
}

#[tokio::test]
async fn jobs_are_cancelled_listed_and_limited() {
    let mut h = harness!();
    let mut ids = Vec::new();
    for _ in 0..10 {
        let (status, j) = h
            .api(
                Method::POST,
                "/v1/jobs/export",
                &h.alice,
                Some(json!({"format": "csv"})),
            )
            .await;
        assert_eq!(status, 202);
        ids.push(j["id"].clone());
    }
    let (status, err) = upload(&h, &h.alice, "text/csv", b"url\nhttps://example.com/\n").await;
    assert_eq!(status, 409, "{err}");
    assert_eq!(err["error"]["code"], "failed_precondition");
    // Another workspace has its own limit.
    let (status, _) = upload(&h, &h.bob, "text/csv", b"url\nhttps://example.com/\n").await;
    assert_eq!(status, 202);

    let (status, cancelled) = h
        .api(
            Method::POST,
            &format!("/v1/jobs/{}/cancel", ids[0]),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 200, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
    let (status, err) = h
        .api(
            Method::POST,
            &format!("/v1/jobs/{}/cancel", ids[0]),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(status, 409);
    assert_eq!(err["error"]["message"], "the job has cancelled");
    let (status, _) = h
        .api(
            Method::POST,
            &format!("/v1/jobs/{}/cancel", ids[1]),
            &h.bob,
            None,
        )
        .await;
    assert_eq!(status, 404);
    let (status, ..) = output(&h, &h.alice, &ids[0]).await;
    assert_eq!(status, 409);
    // A slot is free again.
    let (status, _) = upload(&h, &h.alice, "text/csv", b"url\nhttps://example.com/\n").await;
    assert_eq!(status, 202);
    assert_eq!(
        count(
            &h,
            "SELECT count(*) FROM audit_log WHERE action = 'job.cancel'"
        )
        .await,
        1
    );

    // Newest first, in pages.
    let (_, page) = h.api(Method::GET, "/v1/jobs?limit=4", &h.alice, None).await;
    let jobs = page["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 4);
    assert_eq!(jobs[0]["kind"], "import");
    assert!(jobs[0].get("errors").is_none());
    let cursor = page["next_cursor"].as_str().unwrap();
    let (_, rest) = h
        .api(
            Method::GET,
            &format!("/v1/jobs?cursor={cursor}&limit=100"),
            &h.alice,
            None,
        )
        .await;
    assert_eq!(rest["jobs"].as_array().unwrap().len(), 7);
    assert_eq!(rest["next_cursor"], Value::Null);
    assert_eq!(rest["jobs"][6]["state"], "cancelled");
    for bad in ["limit=0", "limit=101", "cursor=zz", "state=x"] {
        let (status, _) = h
            .api(Method::GET, &format!("/v1/jobs?{bad}"), &h.alice, None)
            .await;
        assert_eq!(status, 400, "{bad}");
    }
    let (status, _) = h.api(Method::GET, "/v1/jobs/999999", &h.alice, None).await;
    assert_eq!(status, 404);
    // A patch has no file.
    h.create(json!({"alias": "xxx", "url": "https://example.com/"}))
        .await;
    let (_, patch) = h
        .api(
            Method::POST,
            "/v1/jobs/patch",
            &h.bob,
            Some(json!({"filter": {"all": true}, "patch": {"enabled": true}})),
        )
        .await;
    drain(&h).await;
    let (status, ..) = output(&h, &h.bob, &patch["id"]).await;
    assert_eq!(status, 409);
    // The cancelled one never ran; the others did.
    let cancelled = job(&h, &h.alice, &ids[0]).await;
    assert_eq!(cancelled["started_at"], Value::Null);
    assert_eq!(job(&h, &h.alice, &ids[1]).await["state"], "succeeded");
    // Alice had no links when it was made: the file is the header alone.
    let (status, _, csv) = output(&h, &h.alice, &ids[1]).await;
    assert_eq!(status, 200);
    assert_eq!(csv.lines().count(), 1);
    assert!(csv.starts_with("code,domain,short_url,url,"));
    // Finished jobs go after their retention.
    sqlx::query(
        "UPDATE jobs SET finished_at = now() - interval '8 days' WHERE finished_at IS NOT NULL",
    )
    .execute(h.store.pool())
    .await
    .unwrap();
    let purged = h.store.purge_jobs(7, 1_000).await.unwrap();
    assert_eq!(purged, 13);
    assert_eq!(count(&h, "SELECT count(*) FROM jobs").await, 0);
    assert_eq!(count(&h, "SELECT count(*) FROM job_chunks").await, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn a_lost_lease_is_taken_over_and_every_row_is_done_once() {
    let mut h = harness!();
    let mut file = b"url\n".to_vec();
    for i in 0..1_200 {
        file.extend_from_slice(format!("https://example.com/{i}\n").as_bytes());
    }
    let (status, queued) = upload(&h, &h.alice, "text/csv", &file).await;
    assert_eq!(status, 202);
    let worker = JobWorker::new(h.app().clone());
    // A worker takes the job, does one step and stops answering.
    let first = h
        .store
        .claim_job(Duration::from_secs(60))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.id, queued["id"].as_i64().unwrap());
    assert_eq!(worker.step_once(first).await.unwrap(), Step::Progress(500));
    // Nobody else may take it while the lease holds.
    assert_eq!(
        h.store.claim_job(Duration::from_secs(1)).await.unwrap(),
        None
    );
    // Time passes: the lease runs out.
    sqlx::query("UPDATE jobs SET lease_until = now() - interval '1 second'")
        .execute(h.store.pool())
        .await
        .unwrap();
    let second = h
        .store
        .claim_job(Duration::from_secs(60))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(second.token, first.token);
    // The first worker comes back: its steps no longer count.
    assert_eq!(worker.step_once(first).await.unwrap(), Step::Lost);
    let running = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(running["state"], "running");
    assert_eq!(running["processed"], 500);
    assert_eq!(running["progress"], 0.4166);
    assert_eq!(worker.step_once(second).await.unwrap(), Step::Progress(500));
    assert_eq!(worker.step_once(second).await.unwrap(), Step::Progress(200));
    assert_eq!(
        worker.step_once(second).await.unwrap(),
        Step::Finished("succeeded")
    );
    assert_eq!(worker.step_once(second).await.unwrap(), Step::Lost);
    let done = job(&h, &h.alice, &queued["id"]).await;
    assert_eq!(done["succeeded"], 1_200, "{done}");
    assert_eq!(
        count(&h, "SELECT count(DISTINCT destinations) FROM links").await,
        1_200
    );
    assert_eq!(count(&h, "SELECT count(*) FROM links").await, 1_200);
    h.shutdown().await;
}

#[tokio::test]
async fn jobs_take_turns() {
    let mut h = harness!(("RELINK_JOB_SLICE_MS", "10"));
    let mut file = b"url\n".to_vec();
    for i in 0..1_500 {
        file.extend_from_slice(format!("https://example.com/{i}\n").as_bytes());
    }
    let (_, a) = upload(&h, &h.alice, "text/csv", &file).await;
    let (_, b) = upload(&h, &h.bob, "text/csv", &file).await;
    let worker = JobWorker::new(h.app().clone());
    let mut seen = Vec::new();
    for _ in 0..4 {
        assert!(worker.round().await);
        let pa = job(&h, &h.alice, &a["id"]).await["processed"]
            .as_i64()
            .unwrap();
        let pb = job(&h, &h.bob, &b["id"]).await["processed"]
            .as_i64()
            .unwrap();
        seen.push((pa, pb));
    }
    assert_eq!(seen, [(500, 0), (500, 500), (1_000, 500), (1_000, 1_000)]);
    drain(&h).await;
    assert_eq!(job(&h, &h.alice, &a["id"]).await["succeeded"], 1_500);
    assert_eq!(job(&h, &h.bob, &b["id"]).await["succeeded"], 1_500);
    h.shutdown().await;
}

#[tokio::test]
async fn the_background_worker_runs_jobs() {
    let mut h = harness!(
        ("RELINK_JOBS_ENABLED", "true"),
        ("RELINK_JOB_POLL_MS", "20")
    );
    let mut file = b"code,url\n".to_vec();
    for i in 0..2_000 {
        file.extend_from_slice(format!("bg{i},https://example.com/{i}\n").as_bytes());
    }
    let (status, queued) = upload(&h, &h.alice, "text/csv", &file).await;
    assert_eq!(status, 202);
    assert!(
        eventually(Duration::from_secs(30), || async {
            job(&h, &h.alice, &queued["id"]).await["state"] == "succeeded"
        })
        .await,
        "the import did not finish"
    );
    // The links redirect at once, on this instance and from the database.
    assert_eq!(h.visit("bg1999", &[]).await.status(), 302);
    let m = h.metrics().await;
    assert_eq!(metric(&m, "relink_jobs_succeeded_total"), 1.0);
    assert_eq!(metric(&m, "relink_job_rows_total"), 2_000.0);
    h.shutdown().await;
}
