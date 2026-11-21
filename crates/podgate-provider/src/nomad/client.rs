//! A client for the parts of Nomad's HTTP API the source reads.
//!
//! The client has one way to talk to the server, [`Client::get`], and that sends `GET`: a source
//! that watches registrations has no business registering or deregistering anything, and the type
//! has no method that could. An ACL token with the `read` capability on the services of the
//! configured namespaces is therefore enough.
//!
//! The token goes into the `X-Nomad-Token` header, marked sensitive, and nowhere else: it is not
//! part of any error, `Debug` output or log line.

use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderValue;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as Hyper;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::model::{Instance, Listing, ServiceStub};
use crate::acme::Secret;

/// The longest an ordinary request, from connect to the last byte of its body, may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long Nomad holds a blocking query when nothing changes (the `wait` parameter).
const BLOCK_SECS: u64 = 60;

/// What a blocking query may take: the wait, Nomad's jitter of a sixteenth, and slack.
const BLOCKING_TIMEOUT: Duration = Duration::from_secs(BLOCK_SECS + BLOCK_SECS / 16 + 26);

/// The largest response body the client reads: a list of thousands of services fits, a runaway
/// server does not.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The most of an error answer that is quoted.
const MAX_QUOTED: usize = 200;

const TOKEN_HEADER: &str = "x-nomad-token";
const INDEX_HEADER: &str = "x-nomad-index";

/// What went wrong talking to Nomad.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// The request could not be made or the connection broke.
    #[error("cannot reach Nomad: {0}")]
    Transport(Box<str>),
    /// Nomad did not answer in time.
    #[error("Nomad did not answer GET {path} in time")]
    Timeout { path: Box<str> },
    /// Nomad answered with an error status.
    #[error("Nomad answered {status} to GET {path}: {body}")]
    Status {
        status: u16,
        path: Box<str>,
        body: Box<str>,
    },
    /// The body is not the JSON that was expected.
    #[error("Nomad sent JSON that does not parse: {0}")]
    Json(#[from] serde_json::Error),
    /// A body is larger than the client reads.
    #[error("Nomad sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge,
    /// A blocking query came back without `X-Nomad-Index`: without it the next query cannot
    /// block, and would spin.
    #[error("Nomad's answer to GET {path} has no X-Nomad-Index header")]
    NoIndex { path: Box<str> },
    /// The token is not a header value.
    #[error("the ACL token is not a valid header value")]
    Token,
}

type Http = Hyper<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// The Nomad server.
#[derive(Clone)]
pub(super) struct Client {
    /// `scheme://authority`, without a trailing slash.
    base: Box<str>,
    token: Option<Secret>,
    stale: bool,
    http: Http,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("token", &self.token)
            .field("stale", &self.stale)
            .finish_non_exhaustive()
    }
}

/// Percent-encodes everything but unreserved characters, for a path segment or a query value.
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

impl Client {
    /// A client of `base` (`scheme://authority`) that sends `token`, if any.
    ///
    /// # Errors
    ///
    /// The reason the platform's root certificates cannot be loaded.
    pub(super) fn new(base: &str, token: Option<Secret>, stale: bool) -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            base: base.into(),
            token,
            stale,
            // One connection per request: a blocking query holds its connection for a minute,
            // and a pooled one that the server closed in the meantime is a spurious error.
            http: Hyper::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(connector),
        })
    }

    /// One `GET`, returning the body and the `X-Nomad-Index` of the answer.
    async fn get(
        &self,
        path_and_query: &str,
        patience: Duration,
    ) -> Result<(Bytes, Option<u64>), ClientError> {
        let path = path_and_query.split('?').next().unwrap_or(path_and_query);
        let uri: Uri = format!("{}{path_and_query}", self.base)
            .parse()
            .map_err(|err: http::uri::InvalidUri| ClientError::Transport(err.to_string().into()))?;
        let mut request = Request::get(uri);
        if let Some(token) = &self.token {
            let mut value =
                HeaderValue::from_str(token.expose()).map_err(|_| ClientError::Token)?;
            value.set_sensitive(true);
            request = request.header(TOKEN_HEADER, value);
        }
        let request = request
            .body(Full::new(Bytes::new()))
            .map_err(|err| ClientError::Transport(err.to_string().into()))?;
        let exchange = async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|err| ClientError::Transport(err.to_string().into()))?;
            let status = response.status();
            let index = response
                .headers()
                .get(INDEX_HEADER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
                .collect()
                .await
                .map_err(|err| {
                    if err
                        .downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        ClientError::TooLarge
                    } else {
                        ClientError::Transport(err.to_string().into())
                    }
                })?
                .to_bytes();
            if status.is_success() {
                Ok((body, index))
            } else {
                let text = String::from_utf8_lossy(&body);
                let quoted: String = text.trim().chars().take(MAX_QUOTED).collect();
                Err(ClientError::Status {
                    status: status.as_u16(),
                    path: path.into(),
                    body: quoted.into(),
                })
            }
        };
        tokio::time::timeout(patience, exchange)
            .await
            .map_err(|_| ClientError::Timeout { path: path.into() })?
    }

    async fn json<T: DeserializeOwned>(&self, path_and_query: &str) -> Result<T, ClientError> {
        let (body, _) = self.get(path_and_query, REQUEST_TIMEOUT).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn consistency(&self) -> &'static str {
        if self.stale { "&stale" } else { "" }
    }

    /// The services registered in `namespace`, with the tags of all their instances together.
    pub(super) async fn services(&self, namespace: &str) -> Result<Vec<ServiceStub>, ClientError> {
        let path = format!(
            "/v1/services?namespace={}{}",
            encode(namespace),
            self.consistency()
        );
        let listings: Vec<Listing> = self.json(&path).await?;
        Ok(listings
            .into_iter()
            .filter(|listing| listing.namespace == namespace)
            .flat_map(|listing| listing.services.unwrap_or_default())
            .collect())
    }

    /// The instances of one service.
    pub(super) async fn instances(
        &self,
        namespace: &str,
        service: &str,
    ) -> Result<Vec<Instance>, ClientError> {
        let path = format!(
            "/v1/service/{}?namespace={}{}",
            encode(service),
            encode(namespace),
            self.consistency()
        );
        self.json(&path).await
    }

    /// Waits until the registrations of `namespace` pass `index` (a blocking query), or Nomad's
    /// wait runs out, and returns the index it answers with. Index `0` answers at once.
    pub(super) async fn block(&self, namespace: &str, index: u64) -> Result<u64, ClientError> {
        let path = format!(
            "/v1/services?namespace={}&index={index}&wait={BLOCK_SECS}s{}",
            encode(namespace),
            self.consistency()
        );
        let (_, answered) = self.get(&path, BLOCKING_TIMEOUT).await?;
        answered.ok_or_else(|| ClientError::NoIndex {
            path: path.split('?').next().unwrap_or(&path).into(),
        })
    }
}
