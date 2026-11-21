//! A client for the two read-only Consul endpoints the source needs.
//!
//! The client has one way to talk to Consul, [`Client::get`], and that sends `GET`: a source
//! that watches the catalog has no business registering or deregistering anything, and the type
//! has no method that could. A Consul ACL token with `service:read` and `node:read` is enough.
//!
//! A blocking query is `?index=<n>&wait=<s>s`: Consul holds the answer until the index of the
//! data passes `n` or the wait is over, and sends the data's index in `X-Consul-Index`. The
//! token travels in `X-Consul-Token`, marked sensitive, and is removed from any text that
//! leaves this module.

use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderValue;
use http::{HeaderName, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as Hyper;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::time::timeout;

use crate::acme::Secret;

use super::Scope;
use super::model::{Catalog, Entry};

/// The longest a request that does not block may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The most a blocking request outlasts its `wait`: Consul adds up to a sixteenth of it as
/// jitter.
const WAIT_SLACK: Duration = Duration::from_secs(5);

/// The largest answer the client reads: 256 instances with their tags and checks fit many times
/// over, a runaway server does not.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// How much of an error answer is quoted in a report.
const MAX_QUOTED: usize = 256;

static TOKEN_HEADER: HeaderName = HeaderName::from_static("x-consul-token");
static INDEX_HEADER: HeaderName = HeaderName::from_static("x-consul-index");

type Http = Hyper<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// What went wrong talking to Consul. Never holds the token.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// The request failed before an answer: refused, reset, unresolvable, TLS.
    #[error("cannot reach Consul: {0}")]
    Request(Box<str>),
    /// Consul did not answer in time.
    #[error("Consul did not answer within {} seconds", .0.as_secs())]
    Timeout(Duration),
    /// Consul answered with an error status.
    #[error("Consul answered {status} to GET {path}: {body}")]
    Status {
        status: u16,
        path: Box<str>,
        body: Box<str>,
    },
    /// The body is not the JSON that was expected.
    #[error("Consul sent JSON that does not parse: {0}")]
    Json(#[from] serde_json::Error),
    /// A body is larger than the client reads.
    #[error("Consul sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge,
    /// The answer is not what Consul sends.
    #[error("unexpected response from Consul: {0}")]
    Protocol(&'static str),
}

/// A configured blocking query: wait for the data's index to pass `index`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Blocking {
    /// `0` asks for the current data at once.
    pub(super) index: u64,
    /// Whole seconds, at least one.
    pub(super) wait: Duration,
}

/// An answer and the index of the data it carries.
#[derive(Debug)]
pub(super) struct Reply<T> {
    pub(super) body: T,
    /// `X-Consul-Index`, `0` when Consul sent none.
    pub(super) index: u64,
}

/// What every request has in common.
#[derive(Debug, Clone, Default)]
pub(super) struct Query {
    pub(super) datacenter: Option<Box<str>>,
    pub(super) stale: bool,
}

/// Consul's HTTP API.
#[derive(Clone)]
pub(super) struct Client {
    http: Http,
    base: Box<str>,
    token: Option<Secret>,
    query: Query,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client of the agent at `base` (`http://host:port` or `https://host:port`).
    ///
    /// # Errors
    ///
    /// The reason the platform's root certificates cannot be loaded.
    pub(super) fn new(base: &str, token: Option<Secret>, query: Query) -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            http: Hyper::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(connector),
            base: base.into(),
            token,
            query,
        })
    }

    /// `GET /v1/catalog/services` in `scope`.
    pub(super) async fn services(
        &self,
        scope: &Scope,
        blocking: Blocking,
    ) -> Result<Reply<Catalog>, ClientError> {
        self.get("/v1/catalog/services", scope, None, blocking)
            .await
    }

    /// `GET /v1/health/service/<name>?passing=true` in `scope`.
    pub(super) async fn instances(
        &self,
        scope: &Scope,
        name: &str,
        blocking: Blocking,
    ) -> Result<Reply<Vec<Entry>>, ClientError> {
        let path = format!("/v1/health/service/{}", encode(name));
        self.get(&path, scope, Some("passing=true"), blocking).await
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        scope: &Scope,
        filter: Option<&str>,
        blocking: Blocking,
    ) -> Result<Reply<T>, ClientError> {
        let mut params: Vec<String> = filter.map(str::to_owned).into_iter().collect();
        let mut add = |key: &str, value: &str| params.push(format!("{key}={}", encode(value)));
        if let Some(datacenter) = &self.query.datacenter {
            add("dc", datacenter);
        }
        if let Some(namespace) = &scope.namespace {
            add("ns", namespace);
        }
        if let Some(partition) = &scope.partition {
            add("partition", partition);
        }
        if blocking.index > 0 {
            add("index", &blocking.index.to_string());
            add("wait", &format!("{}s", blocking.wait.as_secs().max(1)));
        }
        if self.query.stale {
            params.push("stale".to_owned());
        }
        let target = if params.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{}", params.join("&"))
        };
        let uri: Uri = format!("{}{target}", self.base)
            .parse()
            .map_err(|_| ClientError::Protocol("the request URL is not a URL"))?;
        let mut request = Request::get(uri);
        if let Some(token) = &self.token {
            let mut value = HeaderValue::from_str(token.expose())
                .map_err(|_| ClientError::Protocol("the token is not a header value"))?;
            value.set_sensitive(true);
            request = request.header(&TOKEN_HEADER, value);
        }
        let request = request
            .body(Full::new(Bytes::new()))
            .map_err(|_| ClientError::Protocol("cannot build the request"))?;
        let limit = if blocking.index > 0 {
            blocking.wait + (blocking.wait / 8).max(WAIT_SLACK)
        } else {
            REQUEST_TIMEOUT
        };
        timeout(limit, async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|err| ClientError::Request(self.scrub(&err.to_string())))?;
            let status = response.status();
            let index = response
                .headers()
                .get(&INDEX_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|text| text.trim().parse().ok())
                .unwrap_or(0);
            let mut incoming = response.into_body();
            let mut body = Vec::new();
            while let Some(frame) = incoming.frame().await {
                let frame =
                    frame.map_err(|err| ClientError::Request(self.scrub(&err.to_string())))?;
                if let Some(data) = frame.data_ref() {
                    if body.len() + data.len() > MAX_BODY_BYTES {
                        return Err(ClientError::TooLarge);
                    }
                    body.extend_from_slice(data);
                }
            }
            if !status.is_success() {
                let quoted = String::from_utf8_lossy(&body[..body.len().min(MAX_QUOTED)]);
                return Err(ClientError::Status {
                    status: status.as_u16(),
                    path: self.scrub(&target),
                    body: self.scrub(quoted.trim()),
                });
            }
            Ok(Reply {
                body: serde_json::from_slice(&body)?,
                index,
            })
        })
        .await
        .map_err(|_| ClientError::Timeout(limit))?
    }

    /// `text` without the token: Consul echoes what it dislikes about a request in its errors.
    fn scrub(&self, text: &str) -> Box<str> {
        match &self.token {
            Some(token) if !token.expose().is_empty() => {
                text.replace(token.expose(), "[redacted]").into()
            }
            _ => text.into(),
        }
    }
}

/// Percent-encodes everything but the unreserved characters.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encodes_reserved_characters() {
        assert_eq!(encode("web-api_1.v2~"), "web-api_1.v2~");
        assert_eq!(encode("a b/c?d"), "a%20b%2Fc%3Fd");
        assert_eq!(encode("é"), "%C3%A9");
    }
}
