//! The Cloudflare Worker entry point. Only built for wasm32; everything it
//! decides is in `logic`, which the native tests cover.

use std::cell::RefCell;
use std::time::Duration;

use relink_core::abtest::Signer;
use relink_core::classify::country;
use relink_core::hex;
use relink_core::rules::Settings;
use relink_core::wire::ClickBatch;
use worker::{
    Context, Delay, Env, Fetch, Headers, KvStore, Method, Request, RequestInit, RequestRedirect,
    Response, Result, console_warn, event, js_sys, wasm_bindgen::JsValue,
};

use crate::logic::{self, ClickBatcher, EdgeError, EdgeRequest, EdgeResponse, Kv, Origin, Push};

/// Clicks per batch, and the longest a click waits in an idle isolate.
const BATCH_MAX: usize = 50;
const BATCH_AGE: Duration = Duration::from_secs(5);

thread_local! {
    // Workers run one request at a time per isolate thread, so a RefCell is
    // enough; the batch is shared by the requests an isolate serves.
    static BATCH: RefCell<ClickBatcher> =
        RefCell::new(ClickBatcher::new(BATCH_MAX, BATCH_AGE.as_millis() as u64));
}

struct WorkerKv(KvStore);

impl Kv for WorkerKv {
    async fn get(&self, key: &str) -> std::result::Result<Option<String>, EdgeError> {
        // Hot keys stay in the colo's cache for a minute, matching KV's own
        // propagation delay, so they cost no KV round trip.
        self.0
            .get(key)
            .cache_ttl(60)
            .text()
            .await
            .map_err(|e| EdgeError(e.to_string()))
    }
}

struct WorkerOrigin {
    base: String,
}

impl Origin for WorkerOrigin {
    async fn redirect(&self, req: &EdgeRequest) -> std::result::Result<EdgeResponse, EdgeError> {
        let err = |e: worker::Error| EdgeError(e.to_string());
        let headers = Headers::new();
        let cookie = req
            .cookies
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie.is_empty() {
            headers.set("cookie", &cookie).map_err(err)?;
        }
        if let Some(ua) = &req.user_agent {
            headers
                .set("user-agent", &String::from_utf8_lossy(ua))
                .map_err(err)?;
        }
        if let Some(r) = &req.referer {
            headers
                .set("referer", &String::from_utf8_lossy(r))
                .map_err(err)?;
        }
        // The origin believes these only because the edge is in its
        // RELINK_TRUSTED_PROXIES.
        if let Some(ip) = req.client_ip {
            headers
                .set("x-forwarded-for", &ip.to_string())
                .map_err(err)?;
        }
        if let Some(c) = req.country {
            headers
                .set("cf-ipcountry", &String::from_utf8_lossy(&c))
                .map_err(err)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Get)
            .with_headers(headers)
            .with_redirect(RequestRedirect::Manual);
        let request =
            Request::new_with_init(&format!("{}/{}", self.base, req.code), &init).map_err(err)?;
        let mut resp = Fetch::Request(request).send().await.map_err(err)?;
        let mut out = Vec::new();
        for name in [
            "location",
            "set-cookie",
            "cache-control",
            "retry-after",
            "content-type",
        ] {
            if let Some(v) = resp.headers().get(name).map_err(err)? {
                out.push((name.to_owned(), v));
            }
        }
        Ok(EdgeResponse {
            status: resp.status_code(),
            headers: out,
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

fn random_u64() -> u64 {
    let hi = (js_sys::Math::random() * 4_294_967_296.0) as u64;
    let lo = (js_sys::Math::random() * 4_294_967_296.0) as u64;
    (hi << 32) | lo
}

async fn send_clicks(origin: String, token: String, batch: ClickBatch) {
    let Ok(body) = serde_json::to_string(&batch) else {
        return;
    };
    let headers = Headers::new();
    let _ = headers.set("authorization", &format!("Bearer {token}"));
    let _ = headers.set("content-type", "application/json");
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    let sent = match Request::new_with_init(&format!("{origin}/v1/edge/clicks"), &init) {
        Ok(r) => Fetch::Request(r).send().await.map(|r| r.status_code()),
        Err(e) => Err(e),
    };
    match sent {
        Ok(202) => {}
        Ok(status) => console_warn!("click batch of {} refused: {status}", batch.clicks.len()),
        Err(e) => console_warn!("click batch of {} lost: {e}", batch.clicks.len()),
    }
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    if !matches!(req.method(), Method::Get | Method::Head) {
        return Response::error("method not allowed\n", 405);
    }
    let path = req.path();
    let code = path.trim_start_matches('/');
    if code == "healthz" {
        return Response::ok("ok\n");
    }
    let key = env.secret("COOKIE_KEY")?.to_string();
    let Some(key) = hex::decode(key.trim()).and_then(|k| <[u8; 32]>::try_from(k.get(..32)?).ok())
    else {
        return Response::error("COOKIE_KEY must be 64 hex characters\n", 500);
    };
    let signer = Signer::new(key);
    let settings = Settings {
        signer: &signer,
        cookie_secure: env
            .var("COOKIE_SECURE")
            .map(|v| v.to_string() != "false")
            .unwrap_or(true),
    };
    let origin_url = env
        .var("ORIGIN_URL")?
        .to_string()
        .trim_end_matches('/')
        .to_owned();
    let headers = req.headers();
    let edge_req = EdgeRequest {
        code: code.to_owned(),
        cookies: headers
            .get("cookie")?
            .map(String::into_bytes)
            .into_iter()
            .collect(),
        country: req
            .cf()
            .and_then(|cf| cf.country())
            .and_then(|c| country(Some(c.as_bytes()))),
        client_ip: headers
            .get("cf-connecting-ip")?
            .and_then(|ip| ip.parse().ok()),
        user_agent: headers.get("user-agent")?.map(String::into_bytes),
        referer: headers.get("referer")?.map(String::into_bytes),
        now_ms: worker::Date::now().as_millis() as i64,
        random: random_u64(),
    };
    let kv = WorkerKv(env.kv("LINKS")?);
    let origin = WorkerOrigin {
        base: origin_url.clone(),
    };
    let out = logic::handle(&kv, &origin, &settings, &edge_req).await;

    if let Some(click) = out.click {
        let token = env.secret("EDGE_TOKEN")?.to_string();
        match BATCH.with(|b| b.borrow_mut().push(click)) {
            Push::Flush(batch) => ctx.wait_until(send_clicks(origin_url, token, batch)),
            Push::Schedule => ctx.wait_until(async move {
                Delay::from(BATCH_AGE).await;
                if let Some(batch) = BATCH.with(|b| b.borrow_mut().take()) {
                    send_clicks(origin_url, token, batch).await;
                }
            }),
            Push::Buffered => {}
        }
    }

    let r = out.response;
    let mut resp = Response::ok(r.body)?.with_status(r.status);
    for (name, value) in &r.headers {
        resp.headers_mut().set(name, value)?;
    }
    resp.headers_mut().set(
        "x-relink-served-by",
        match out.served {
            logic::Served::Edge => "edge",
            logic::Served::Origin => "origin",
        },
    )?;
    Ok(resp)
}
