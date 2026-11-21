//! The read-only dashboard: a web UI on `DASHBOARD_ADDR` over the overview and explain APIs.
//! Full reference: `docs/ref/dashboard.md`.
//!
//! A second TCP listener, like `METRICS_ADDR`, because a browser cannot reach the admin unix
//! socket. It serves the assets compiled into the binary ([`ASSETS`]), `GET /api/overview`
//! and `/api/explain`, and nothing else: every other path is `404`, every other method on those
//! paths `405`. The two APIs run the admin endpoints' own code on the same [`AppState`], in
//! process, so the answers cannot differ and the admin socket stays unreachable. The event
//! feed, failed requests, the snapshot and the plan are not routes here, which is what keeps a
//! private key or a recorded request out of a browser.
//!
//! Every request passes the same two gates before it is routed:
//!
//! 1. The `Host` header must name the bound address, `localhost` on a loopback or wildcard bind,
//!    or a name in `DASHBOARD_HOSTS`: a DNS rebinding page reaches a loopback dashboard under
//!    its own name and is refused with `421`.
//! 2. With `DASHBOARD_AUTH_FILE`, HTTP Basic credentials checked by the `basic_auth`
//!    machinery ([`Htpasswd`]): bounded hashing, a failed-attempt delay, `401` otherwise.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, FromRequest, Query, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, REFERRER_POLICY, RETRY_AFTER,
    WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::uri::Authority;
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::{Next, from_fn_with_state, map_response};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower_http::timeout::TimeoutLayer;

use crate::admin::{AppState, explain, overview};
use crate::error::AppError;
use crate::middleware::basic_auth::{Htpasswd, Pool};

/// The `Content-Security-Policy` of every answer: only same-origin files, no inline script or
/// style, no framing, no form posts.
pub const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// The realm of the credentials prompt.
const REALM: &str = "podgate dashboard";

/// Largest `/api/explain` request body, in bytes.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// API requests (overview and explain together) that may run at once; more get `503`. Below the
/// admin API's own cap of overview computations, so a busy browser cannot take every slot.
const API_SLOTS: usize = 4;

/// Password verifications the dashboard may run at once, at most.
const HASH_WORKERS: usize = 4;

/// Longest a password verification waits for a worker.
const HASH_WAIT: Duration = Duration::from_secs(1);

/// One file compiled into the binary.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// Name under `dashboard/`.
    pub file: &'static str,
    /// The only path it is served at.
    pub path: &'static str,
    /// The `Content-Type` it is served with.
    pub content_type: &'static str,
    /// Its bytes.
    pub bytes: &'static [u8],
}

/// Every file of `dashboard/`: the UI always matches the API of the same build and needs no
/// directory at run time.
pub const ASSETS: [Asset; 4] = [
    Asset {
        file: "index.html",
        path: "/",
        content_type: "text/html; charset=utf-8",
        bytes: include_bytes!("../dashboard/index.html"),
    },
    Asset {
        file: "app.js",
        path: "/app.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../dashboard/app.js"),
    },
    Asset {
        file: "style.css",
        path: "/style.css",
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("../dashboard/style.css"),
    },
    Asset {
        file: "favicon.svg",
        path: "/favicon.svg",
        content_type: "image/svg+xml",
        bytes: include_bytes!("../dashboard/favicon.svg"),
    },
];

fn asset(path: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|asset| asset.path == path)
}

/// Binds the dashboard address. Like `METRICS_ADDR` it is a TCP port other hosts may reach, so
/// it is the operator's to place and never read from a snapshot.
///
/// # Errors
///
/// Fails when the address cannot be bound.
pub fn bind(addr: SocketAddr) -> io::Result<StdTcpListener> {
    crate::observe::metrics::bind(addr)
}

/// Reads the htpasswd file at `path`.
///
/// # Errors
///
/// The reason the file cannot be used: unreadable, no user, a hash that is not bcrypt or
/// argon2, or one over the cost caps of `basic_auth`. Never a hash.
pub fn load_auth(path: &Path, workers: usize) -> Result<Htpasswd, String> {
    let text = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    Htpasswd::parse(
        &text,
        REALM,
        Pool::new(workers.min(HASH_WORKERS), HASH_WAIT),
    )
}

/// Reads `DASHBOARD_HOSTS`: comma separated host names or IPv4 addresses, lower-cased, without
/// port.
///
/// # Errors
///
/// The entry that is not a bare host name.
pub fn parse_hosts(raw: &str) -> Result<Vec<Box<str>>, String> {
    raw.split(',')
        .map(|entry| entry.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let valid = entry
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'))
                && !entry.starts_with('.')
                && !entry.contains("..");
            if valid {
                Ok(entry.into_boxed_str())
            } else {
                Err(format!(
                    "{entry:?} is not a host name; give bare names without port, scheme or wildcard"
                ))
            }
        })
        .collect()
}

/// Who may reach the dashboard.
#[derive(Debug)]
pub struct Access {
    /// The address it is bound to.
    pub addr: SocketAddr,
    /// Host names besides the bound address that the `Host` header may carry
    /// (`DASHBOARD_HOSTS`).
    pub hosts: Vec<Box<str>>,
    /// The credentials it asks for. `None` is only valid on a loopback address.
    pub auth: Option<Htpasswd>,
}

/// The `Host` values the dashboard answers to.
#[derive(Debug)]
struct Hosts {
    ip: IpAddr,
    names: Vec<Box<str>>,
}

impl Hosts {
    /// Whether the `Host` header `value` is one of ours: a literal of the bound IP (any literal
    /// when it is a wildcard address; DNS rebinding needs a name), `localhost` when the bind is
    /// loopback or wildcard, or a configured name. The port is not compared: a published port
    /// or a proxy may differ, and rebinding changes the name, not the port.
    fn allows(&self, value: &str) -> bool {
        if value.contains('@') {
            return false;
        }
        let Ok(authority) = value.parse::<Authority>() else {
            return false;
        };
        // `Authority` lets a port that is not a number through; a header like that is no client's.
        let host_end = if value.starts_with('[') {
            value.find(']').map_or(value.len(), |end| end + 1)
        } else {
            value.find(':').unwrap_or(value.len())
        };
        let port = value.get(host_end..).unwrap_or_default();
        let port_ok = port.is_empty()
            || port.strip_prefix(':').is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit())
            });
        if !port_ok {
            return false;
        }
        let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = literal(&host) {
            return self.ip.is_unspecified() || ip.to_canonical() == self.ip.to_canonical();
        }
        let loopback = self.ip.to_canonical().is_loopback() || self.ip.is_unspecified();
        (loopback && host == "localhost") || self.names.iter().any(|name| **name == host)
    }
}

/// An IP literal as it appears in a `Host` header: IPv4, or IPv6 in brackets.
fn literal(host: &str) -> Option<IpAddr> {
    match host.strip_prefix('[') {
        Some(inner) => inner
            .strip_suffix(']')?
            .parse::<Ipv6Addr>()
            .ok()
            .map(IpAddr::V6),
        None => host.parse().ok().filter(IpAddr::is_ipv4),
    }
}

#[derive(Debug)]
struct Inner {
    state: AppState,
    hosts: Hosts,
    auth: Option<Htpasswd>,
    slots: Semaphore,
}

/// Handler state: the admin state the shared endpoint code reads, and the gates.
#[derive(Clone, Debug)]
struct Shared(Arc<Inner>);

impl FromRef<Shared> for AppState {
    fn from_ref(shared: &Shared) -> Self {
        shared.0.state.clone()
    }
}

/// Serves the dashboard on a bound TCP listener. Run it as a Pingora background service.
#[derive(Debug)]
pub struct DashboardService {
    listener: StdTcpListener,
    shared: Shared,
    loopback: bool,
    timeout: Duration,
}

impl DashboardService {
    /// Serves `state`'s overview and explain on `listener` to whoever passes `access`, ending a
    /// request that runs longer than `timeout` with `408`.
    #[must_use]
    pub fn new(
        listener: StdTcpListener,
        access: Access,
        state: AppState,
        timeout: Duration,
    ) -> Self {
        Self {
            listener,
            loopback: access.addr.ip().to_canonical().is_loopback(),
            shared: Shared(Arc::new(Inner {
                state,
                hosts: Hosts {
                    ip: access.addr.ip(),
                    names: access.hosts,
                },
                auth: access.auth,
                slots: Semaphore::new(API_SLOTS),
            })),
            timeout,
        }
    }

    /// The routes, then, outermost first: security headers on every answer (a refusal or a
    /// timeout too), the timeout, the `Host` and credentials gate, the request body cap.
    fn router(&self) -> Router {
        let api = Router::new()
            .route("/api/overview", any(overview::entry))
            .route("/api/explain", any(explain_entry))
            .route_layer(from_fn_with_state(self.shared.clone(), api_slot));
        Router::new()
            .merge(api)
            .fallback(assets)
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .layer(from_fn_with_state(self.shared.clone(), gate))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.timeout,
            ))
            .layer(map_response(harden))
            .with_state(self.shared.clone())
    }
}

/// Adds the browser hardening headers. `no-store` unless the handler chose a cache policy:
/// the API answers and every refusal must not be kept.
async fn harden(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// The `Host` check, then the credentials check. Nothing is routed, hashed or read before both
/// pass, so an unauthenticated client learns nothing, not even which paths exist.
async fn gate(
    State(shared): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(Authority::as_str));
    if !host.is_some_and(|host| shared.0.hosts.allows(host)) {
        return AppError::Misdirected.into_response();
    }
    if let Some(auth) = &shared.0.auth {
        match auth.check(Some(peer.ip()), request.headers()).await {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(WWW_AUTHENTICATE, auth.challenge().clone())],
                    Json(json!({ "error": "unauthorized" })),
                )
                    .into_response();
            }
            Err(err) => {
                tracing::warn!("dashboard sign-in refused: {err}");
                return err.into_response();
            }
        }
    }
    next.run(request).await
}

/// The `503` that says no API slot is free.
fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, "1")],
        Json(json!({ "error": "dashboard is busy" })),
    )
        .into_response()
}

/// Caps the API calls that run at once; the ninth caller of the admin overview must not be
/// someone with a browser tab.
async fn api_slot(State(shared): State<Shared>, request: Request, next: Next) -> Response {
    let Ok(_slot) = shared.0.slots.try_acquire() else {
        return busy();
    };
    next.run(request).await
}

fn method_not_allowed(allow: &'static str) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, allow)],
        Json(json!({ "error": "method not allowed" })),
    )
        .into_response()
}

/// An embedded file for `GET`, `404` for any other path.
async fn assets(method: Method, uri: Uri) -> Response {
    let Some(asset) = asset(uri.path()) else {
        return AppError::NotFound.into_response();
    };
    if method != Method::GET {
        return method_not_allowed("GET");
    }
    (
        [
            (CONTENT_TYPE, asset.content_type),
            (CACHE_CONTROL, "no-cache"),
        ],
        asset.bytes,
    )
        .into_response()
}

/// The body of `POST /api/explain`: the admin endpoint's parameters, and nothing else.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainBody {
    url: String,
    method: Option<String>,
    entry_point: Option<String>,
    client_ip: Option<IpAddr>,
}

impl From<ExplainBody> for explain::Params {
    fn from(body: ExplainBody) -> Self {
        Self {
            url: body.url,
            method: body.method,
            entry_point: body.entry_point,
            client_ip: body.client_ip,
        }
    }
}

/// `GET /api/explain?url=...` as `GET /v1/explain`, or `POST /api/explain` with the same
/// parameters as a JSON body of at most [`MAX_BODY_BYTES`]. Both answer from the live table and
/// change nothing; the body is for URLs a query string handles badly.
async fn explain_entry(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let params = match *request.method() {
        Method::GET => Query::<explain::Params>::try_from_uri(request.uri())
            .map(|Query(params)| params)
            .map_err(|err| AppError::BadRequest(format!("invalid query: {err}").into()))?,
        Method::POST => Json::<ExplainBody>::from_request(request, &())
            .await
            .map(|Json(body)| body.into())
            .map_err(|rejection| body_error(&rejection))?,
        _ => return Ok(method_not_allowed("GET, POST")),
    };
    explain::answer(&state, &params)
}

fn body_error(rejection: &JsonRejection) -> AppError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        AppError::PayloadTooLarge
    } else {
        AppError::BadRequest(format!("invalid body: {}", rejection.body_text()).into())
    }
}

#[async_trait]
impl BackgroundService for DashboardService {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let listener = match self.listener.try_clone().and_then(TcpListener::from_std) {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "cannot serve the dashboard listener");
                return;
            }
        };
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, "dashboard listener ready");
            if !self.loopback {
                tracing::warn!(
                    %addr,
                    "the dashboard listens beyond loopback over plain HTTP, so Basic credentials travel in clear; put it behind podgate's own TLS entry point or keep it on loopback"
                );
            }
        }
        // Like the admin API it serves until the process exits: every request is short and
        // read-only.
        let service = self
            .router()
            .into_make_service_with_connect_info::<SocketAddr>();
        if let Err(err) = axum::serve(listener, service).await {
            tracing::error!(%err, "dashboard listener stopped");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn hosts(ip: &str, names: &[&str]) -> Hosts {
        Hosts {
            ip: ip.parse().expect("ip"),
            names: names.iter().map(|name| Box::from(*name)).collect(),
        }
    }

    #[test]
    fn loopback_allows_its_literal_and_localhost_only() {
        let hosts = hosts("127.0.0.1", &[]);
        for ok in [
            "127.0.0.1",
            "127.0.0.1:9200",
            "localhost",
            "LOCALHOST:80",
            "localhost.",
        ] {
            assert!(hosts.allows(ok), "{ok}");
        }
        for bad in [
            "",
            "evil.test",
            "evil.test:9200",
            "127.0.0.2",
            "[::1]",
            "127.0.0.1.evil.test",
            "u@127.0.0.1",
            "localhost.evil.test",
            "127.0.0.1:port",
        ] {
            assert!(!hosts.allows(bad), "{bad}");
        }
    }

    #[test]
    fn ipv6_loopback_is_bracketed() {
        let hosts = hosts("::1", &[]);
        assert!(hosts.allows("[::1]:9200"));
        assert!(!hosts.allows("[::2]"));
        assert!(hosts.allows("localhost"));
    }

    #[test]
    fn wildcard_bind_allows_any_literal_but_no_name() {
        let hosts = hosts("0.0.0.0", &["dash.example"]);
        assert!(hosts.allows("10.1.2.3:8080"));
        assert!(hosts.allows("[2001:db8::1]"));
        assert!(hosts.allows("dash.example"));
        assert!(hosts.allows("DASH.example:8443"));
        assert!(!hosts.allows("other.example"));
    }

    #[test]
    fn a_routable_bind_allows_only_its_address_and_the_configured_names() {
        let hosts = hosts("10.0.0.5", &["dash.example"]);
        assert!(hosts.allows("10.0.0.5:9200"));
        assert!(hosts.allows("dash.example"));
        assert!(!hosts.allows("localhost"));
        assert!(!hosts.allows("10.0.0.6"));
    }

    #[test]
    fn hosts_setting_takes_bare_names() {
        assert_eq!(
            parse_hosts("Dash.Example, ops.example.,").expect("names"),
            vec![Box::<str>::from("dash.example"), Box::from("ops.example")]
        );
        for bad in ["a:80", "https://a", "*.a", "a b", ".a", "a..b", "u@a"] {
            assert!(parse_hosts(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn assets_are_found_by_path() {
        assert_eq!(asset("/").map(|a| a.file), Some("index.html"));
        assert_eq!(asset("/app.js").map(|a| a.file), Some("app.js"));
        assert!(asset("/nope").is_none());
        assert!(asset("/../Cargo.toml").is_none());
        assert!(asset("/api/overview").is_none());
    }

    #[tokio::test]
    async fn api_slots_cap_concurrent_requests() {
        let slots = Semaphore::new(API_SLOTS);
        let held: Vec<_> = (0..API_SLOTS)
            .map(|_| slots.try_acquire().expect("a free slot"))
            .collect();
        assert!(slots.try_acquire().is_err(), "no slot is left");
        let busy = busy();
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers()[RETRY_AFTER], "1");
        let body = axum::body::to_bytes(busy.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(&body[..], br#"{"error":"dashboard is busy"}"#);
        drop(held);
        assert!(
            slots.try_acquire().is_ok(),
            "a finished request frees its slot"
        );
    }
}
