//! The mutual TLS HTTP/1 listener both roles use.
//!
//! Nothing is parsed before the handshake completes with a certificate from the configured CA, so
//! the surface before authentication is `rustls`'s handshake and nothing else. After it: `GET`
//! only (the handler decides), no request body, a 16 KiB request head, a deadline for every stage,
//! a cap on connections, and the same hardening headers on every answer.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    HeaderValue, REFERRER_POLICY, RETRY_AFTER, TRANSFER_ENCODING, X_CONTENT_TYPE_OPTIONS,
};
use http::{Method, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ServerConfig;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::wire::percent_decode;

/// Time allowed for a TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(5);
/// Time allowed for a request head, also while a kept-alive connection is idle.
const HEAD: Duration = Duration::from_secs(10);
/// Time allowed for one request from its head to its answer.
const REQUEST: Duration = Duration::from_secs(30);
/// The longest a connection lives.
const LIFETIME: Duration = Duration::from_secs(300);
/// The largest request head, in bytes.
const MAX_HEAD: usize = 16 * 1024;

/// A request as a handler sees it: the method, the path and the raw query. No headers and no body.
#[derive(Debug, Clone)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The path.
    pub path: String,
    /// The query string, without the `?`.
    pub query: Option<String>,
}

/// An answer: JSON, always.
#[derive(Debug, Clone)]
pub struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    retry_after: Option<u32>,
    allow_get: bool,
    close: bool,
}

impl Reply {
    /// A `200` with `body`, which must be JSON.
    #[must_use]
    pub fn ok(body: Vec<u8>) -> Self {
        Self::with(StatusCode::OK, body)
    }

    fn with(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            retry_after: None,
            allow_get: false,
            close: false,
        }
    }

    /// The repo's error shape, `{"error": "<message>"}`.
    #[must_use]
    pub fn error(status: StatusCode, message: &str) -> Self {
        Self::with(status, json!({ "error": message }).to_string().into_bytes())
    }

    /// `404`.
    #[must_use]
    pub fn not_found() -> Self {
        Self::error(StatusCode::NOT_FOUND, "not found")
    }

    /// `405` with `allow: GET`.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self {
            allow_get: true,
            ..Self::error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
    }

    /// `400`.
    #[must_use]
    pub fn bad_request(message: &str) -> Self {
        Self::error(StatusCode::BAD_REQUEST, message)
    }

    /// Adds `retry-after: <secs>`.
    #[must_use]
    pub fn retry_after(mut self, secs: u32) -> Self {
        self.retry_after = Some(secs);
        self
    }

    /// The status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    fn into_response(self) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::new(Bytes::from(self.body)));
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; sandbox"),
        );
        headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.allow_get {
            headers.insert(ALLOW, HeaderValue::from_static("GET"));
        }
        if let Some(secs) = self.retry_after {
            headers.insert(RETRY_AFTER, HeaderValue::from(secs));
        }
        if self.close {
            headers.insert(CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }
}

/// The query parameters of a request, each at most once, only the names a route lists.
#[derive(Debug, Default)]
pub struct Params(BTreeMap<String, String>);

impl Params {
    /// Reads `query`, refusing a name not in `allowed`, a repeated name, a broken escape and a
    /// value that is not UTF-8.
    ///
    /// # Errors
    ///
    /// The `400` to send.
    pub fn parse(query: Option<&str>, allowed: &[&str]) -> Result<Self, Reply> {
        let bad = || Reply::bad_request("malformed query");
        let mut map = BTreeMap::new();
        for pair in query
            .unwrap_or_default()
            .split('&')
            .filter(|p| !p.is_empty())
        {
            let (name, value) = pair.split_once('=').ok_or_else(bad)?;
            let name = percent_decode(name).ok_or_else(bad)?;
            let value = percent_decode(value).ok_or_else(bad)?;
            if !allowed.contains(&name.as_str()) {
                return Err(Reply::bad_request(&format!("unknown parameter {name:?}")));
            }
            if map.insert(name, value).is_some() {
                return Err(bad());
            }
        }
        Ok(Self(map))
    }

    /// The value of `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

/// What a listener serves.
pub trait Handler: Send + Sync + 'static {
    /// Answers one request. Called only for a complete, bodyless request on an authenticated
    /// connection; the future is dropped when the request deadline passes.
    fn handle(&self, request: Request) -> impl Future<Output = Reply> + Send;
}

/// Serves `handler` on `listener` until the task is dropped.
///
/// At most `max_connections` connections are held; one over is closed before the handshake.
pub async fn serve<H: Handler>(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    max_connections: usize,
    handler: Arc<H>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let slots = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!(%peer, "connection refused: at the connection cap");
            continue;
        };
        let acceptor = acceptor.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _permit = permit;
            connection(stream, peer, acceptor, handler).await;
        });
    }
}

async fn connection<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    handler: Arc<H>,
) {
    let tls = match timeout(HANDSHAKE, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            tracing::debug!(%peer, %err, "TLS handshake refused");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "TLS handshake timed out");
            return;
        }
    };
    let service = service_fn(move |request: hyper::Request<Incoming>| {
        let handler = Arc::clone(&handler);
        async move { Ok::<_, Infallible>(answer(&*handler, &request).await.into_response()) }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD)
        .max_buf_size(MAX_HEAD)
        .serve_connection(TokioIo::new(tls), service);
    match timeout(LIFETIME, connection).await {
        Ok(Ok(())) | Err(_) => {}
        Ok(Err(err)) => tracing::debug!(%peer, %err, "connection ended"),
    }
}

async fn answer<H: Handler>(handler: &H, request: &hyper::Request<Incoming>) -> Reply {
    let headers = request.headers();
    let has_body = headers.contains_key(TRANSFER_ENCODING)
        || headers
            .get(CONTENT_LENGTH)
            .is_some_and(|value| value.as_bytes() != b"0");
    if has_body {
        let mut reply = Reply::bad_request("request bodies are not accepted");
        reply.close = true;
        return reply;
    }
    let request = Request {
        method: request.method().clone(),
        path: request.uri().path().to_owned(),
        query: request.uri().query().map(str::to_owned),
    };
    match timeout(REQUEST, handler.handle(request)).await {
        Ok(reply) => reply,
        Err(_) => Reply::error(StatusCode::REQUEST_TIMEOUT, "request timed out"),
    }
}
