//! A client for the three calls of etcd's JSON gateway that the source needs.
//!
//! The only way out of this module is [`Client::send`], and it takes a [`Call`]: `Range`, `Watch`
//! or `Authenticate`. There is no variant for a put, a delete or a transaction, so a source that
//! only follows configuration cannot change what it follows, and a read-only etcd user is enough
//! (`/v3/auth/authenticate` and `/v3/kv/range` need the `read` permission on the prefixes).
//!
//! Requests are `POST` with a JSON body, as the gateway wants; `int64` fields come back as
//! strings and keys and values are base64. A refused token (`401`, or the server's "auth store
//! is old" `400`) is replaced once through [`Auth`] and the request repeated. With several
//! endpoints, a request goes to the one that answered last and moves on to the next when an
//! endpoint cannot be reached or answers with a server error.
//!
//! Tokens and passwords are never part of an error, `Debug` output or log line; the token header
//! is marked sensitive.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as Hyper;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use thiserror::Error;

use super::auth::{Auth, Credentials};
use crate::acme::Secret;
use crate::kv::MAX_KEYS_PER_PREFIX;
use crate::tls_client::{TlsPem, tls_config};

/// The longest an ordinary request, from connect to the last byte of its answer, may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest answer or buffered watch message the client reads.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The most of an error answer that is quoted.
const MAX_QUOTED: usize = 200;

/// What the source asks etcd. Nothing here writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    /// `POST /v3/kv/range`.
    Range,
    /// `POST /v3/watch`, answered by a stream.
    Watch,
    /// `POST /v3/auth/authenticate`.
    Authenticate,
}

impl Call {
    fn path(self) -> &'static str {
        match self {
            Self::Range => "/v3/kv/range",
            Self::Watch => "/v3/watch",
            Self::Authenticate => "/v3/auth/authenticate",
        }
    }
}

/// What went wrong talking to etcd.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// The request could not be made or the connection broke.
    #[error("cannot reach etcd: {0}")]
    Transport(Box<str>),
    /// etcd did not answer in time.
    #[error("etcd did not answer {path} in time")]
    Timeout { path: &'static str },
    /// etcd answered with an error status.
    #[error("etcd answered {status} to {path}: {body}")]
    Status {
        status: u16,
        path: &'static str,
        body: Box<str>,
    },
    /// The body is not the JSON that was expected.
    #[error("etcd sent JSON that does not parse: {0}")]
    Json(#[from] serde_json::Error),
    /// A key or value is not base64.
    #[error("etcd sent a key or value that is not base64")]
    Base64,
    /// An answer is larger than the client reads.
    #[error("etcd sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge,
    /// The prefix holds more keys than the provider reads.
    #[error("the prefix holds more than {MAX_KEYS_PER_PREFIX} keys; nothing is read from it")]
    TooManyKeys,
    /// The token is not a header value.
    #[error("the authentication token is not a valid header value")]
    Token,
    /// The server ended a watch with an error.
    #[error("etcd ended the watch: {0}")]
    Watch(Box<str>),
}

impl ClientError {
    /// Whether another endpoint may answer differently.
    fn is_endpoint_failure(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Timeout { .. } => true,
            Self::Status { status, .. } => *status >= 500,
            _ => false,
        }
    }
}

type Http = Hyper<HttpsConnector<HttpConnector>, Full<Bytes>>;

struct Shared {
    /// `scheme://authority` of each endpoint, without a trailing slash.
    endpoints: Box<[Box<str>]>,
    auth: Option<Auth>,
    http: Http,
    /// The endpoint that answered last.
    preferred: AtomicUsize,
}

/// The etcd cluster.
#[derive(Clone)]
pub(super) struct Client {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("endpoints", &self.shared.endpoints)
            .field("auth", &self.shared.auth)
            .finish_non_exhaustive()
    }
}

/// The key range of everything that starts with `prefix`: the end is the prefix with its last
/// byte incremented.
fn range_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xff {
            end.push(last + 1);
            return end;
        }
    }
    // A prefix of nothing but 0xff bytes: "every key from here", which etcd spells `\0`.
    vec![0]
}

/// The text of an error answer, cut short.
fn quote(body: &[u8]) -> Box<str> {
    let text = String::from_utf8_lossy(body);
    text.trim()
        .chars()
        .take(MAX_QUOTED)
        .collect::<String>()
        .into()
}

/// Whether an error answer means "ask for a new token".
fn needs_new_token(status: StatusCode, body: &str) -> bool {
    status == StatusCode::UNAUTHORIZED
        || body.contains("invalid auth token")
        || body.contains("auth store is old")
}

/// An `int64` as the gateway writes it (a string) or as plain JSON has it (a number).
fn number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Text(String),
        Plain(u64),
    }
    match Number::deserialize(deserializer)? {
        Number::Plain(value) => Ok(value),
        Number::Text(text) => text.parse().map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize, Default)]
struct Header {
    #[serde(default, deserialize_with = "number")]
    revision: u64,
}

#[derive(Deserialize, Default)]
struct Kv {
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
}

impl Kv {
    fn decode(self) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        let key = STANDARD.decode(self.key).map_err(|_| ClientError::Base64)?;
        let value = STANDARD
            .decode(self.value)
            .map_err(|_| ClientError::Base64)?;
        Ok((key, value))
    }
}

#[derive(Deserialize)]
struct RangeResponse {
    #[serde(default)]
    header: Header,
    #[serde(default)]
    kvs: Vec<Kv>,
    #[serde(default)]
    more: bool,
}

/// The keys under a prefix and the store revision they were read at.
#[derive(Debug)]
pub(super) struct Ranged {
    pub(super) revision: u64,
    pub(super) entries: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Deserialize)]
struct WatchEvent {
    #[serde(default, rename = "type")]
    kind: Option<serde_json::Value>,
    #[serde(default)]
    kv: Option<Kv>,
}

#[derive(Deserialize)]
struct WatchResult {
    #[serde(default)]
    created: bool,
    #[serde(default)]
    canceled: bool,
    #[serde(default, deserialize_with = "number")]
    compact_revision: u64,
    #[serde(default)]
    cancel_reason: String,
    #[serde(default)]
    events: Vec<WatchEvent>,
}

#[derive(Deserialize)]
struct WatchEnvelope {
    #[serde(default)]
    result: Option<WatchResult>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// One change of a watched prefix.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Change {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// One message of a watch stream.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Notice {
    /// The server registered the watch.
    Created,
    /// Nothing changed; the server says it is alive.
    Progress,
    /// Keys changed, in revision order.
    Changes(Vec<Change>),
    /// The revision the watch asked to start from is gone: read the prefix again.
    Compacted,
    /// The server ended the watch.
    Canceled(Box<str>),
}

impl WatchEvent {
    fn change(self) -> Result<Option<Change>, ClientError> {
        let Some(kv) = self.kv else {
            return Ok(None);
        };
        let (key, value) = kv.decode()?;
        let delete = match &self.kind {
            Some(serde_json::Value::String(kind)) => kind == "DELETE",
            Some(serde_json::Value::Number(kind)) => kind.as_u64() == Some(1),
            _ => false,
        };
        Ok(Some(if delete {
            Change::Delete(key)
        } else {
            Change::Put(key, value)
        }))
    }
}

/// A watch stream: the body of the gateway's answer, cut into messages.
pub(super) struct Watch {
    body: Incoming,
    buffer: Vec<u8>,
}

impl Watch {
    /// The next message, or `None` when the server closed the stream.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the connection breaks or a message does not parse.
    pub(super) async fn next(&mut self) -> Result<Option<Notice>, ClientError> {
        loop {
            if let Some(notice) = self.parse()? {
                return Ok(Some(notice));
            }
            match self.body.frame().await {
                None => return Ok(None),
                Some(Err(err)) => return Err(ClientError::Transport(err.to_string().into())),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buffer.extend_from_slice(&data);
                        if self.buffer.len() > MAX_BODY_BYTES {
                            return Err(ClientError::TooLarge);
                        }
                    }
                }
            }
        }
    }

    /// The first complete message of the buffer, removed from it. The gateway ends each message
    /// with a newline, but a message is also complete when the next one follows directly.
    fn parse(&mut self) -> Result<Option<Notice>, ClientError> {
        let mut stream =
            serde_json::Deserializer::from_slice(&self.buffer).into_iter::<WatchEnvelope>();
        let envelope = match stream.next() {
            None => {
                self.buffer.clear();
                return Ok(None);
            }
            Some(Err(err)) if err.is_eof() => return Ok(None),
            Some(Err(err)) => return Err(err.into()),
            Some(Ok(envelope)) => envelope,
        };
        let used = stream.byte_offset();
        self.buffer.drain(..used);
        if let Some(error) = envelope.error {
            let message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| error.to_string(), str::to_owned);
            return Err(ClientError::Watch(quote(message.as_bytes())));
        }
        let Some(result) = envelope.result else {
            return Ok(Some(Notice::Progress));
        };
        if result.canceled {
            return Ok(Some(if result.compact_revision > 0 {
                Notice::Compacted
            } else {
                Notice::Canceled(quote(result.cancel_reason.as_bytes()))
            }));
        }
        if result.events.is_empty() {
            return Ok(Some(if result.created {
                Notice::Created
            } else {
                Notice::Progress
            }));
        }
        let changes = result
            .events
            .into_iter()
            .map(WatchEvent::change)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(Some(Notice::Changes(changes)))
    }
}

impl Client {
    /// A client of `endpoints` (`scheme://authority`), authenticating as `credentials` when given.
    ///
    /// # Errors
    ///
    /// The reason the TLS settings or the platform's root certificates cannot be used.
    pub(super) fn new(
        endpoints: Vec<Box<str>>,
        tls: TlsPem,
        credentials: Option<Credentials>,
    ) -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config(tls)?)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            shared: Arc::new(Shared {
                endpoints: endpoints.into(),
                auth: credentials.map(Auth::new),
                // One connection per request: a watch holds its connection for good, and a
                // pooled one that the server closed in the meantime is a spurious error.
                http: Hyper::builder(TokioExecutor::new())
                    .pool_max_idle_per_host(0)
                    .build(connector),
                preferred: AtomicUsize::new(0),
            }),
        })
    }

    /// One `POST` to `base`, returning the status and the unread body.
    async fn post(
        &self,
        base: &str,
        call: Call,
        body: &[u8],
        token: Option<&Secret>,
    ) -> Result<(StatusCode, Incoming), ClientError> {
        let uri: Uri = format!("{base}{}", call.path())
            .parse()
            .map_err(|err: http::uri::InvalidUri| ClientError::Transport(err.to_string().into()))?;
        let mut request = Request::post(uri).header(CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            let mut value =
                HeaderValue::from_str(token.expose()).map_err(|_| ClientError::Token)?;
            value.set_sensitive(true);
            request = request.header(AUTHORIZATION, value);
        }
        let request = request
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|err| ClientError::Transport(err.to_string().into()))?;
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.shared.http.request(request))
            .await
            .map_err(|_| ClientError::Timeout { path: call.path() })?
            .map_err(|err| ClientError::Transport(err.to_string().into()))?;
        Ok((response.status(), response.into_body()))
    }

    /// Reads a whole body, within the limit.
    async fn collect(body: Incoming) -> Result<Bytes, ClientError> {
        Ok(Limited::new(body, MAX_BODY_BYTES)
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
            .to_bytes())
    }

    /// Asks for a token at `base`.
    async fn authenticate(
        &self,
        base: &str,
        credentials: &Credentials,
    ) -> Result<Secret, ClientError> {
        let exchange = async {
            let (status, body) = self
                .post(base, Call::Authenticate, &credentials.body(), None)
                .await?;
            let body = Self::collect(body).await?;
            if !status.is_success() {
                return Err(ClientError::Status {
                    status: status.as_u16(),
                    path: Call::Authenticate.path(),
                    body: quote(&body),
                });
            }
            #[derive(Deserialize)]
            struct Answer {
                #[serde(default)]
                token: String,
            }
            let answer: Answer = serde_json::from_slice(&body)?;
            if answer.token.is_empty() {
                return Err(ClientError::Status {
                    status: status.as_u16(),
                    path: Call::Authenticate.path(),
                    body: "etcd answered without a token".into(),
                });
            }
            Ok(Secret::new(answer.token))
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| ClientError::Timeout {
                path: Call::Authenticate.path(),
            })?
    }

    /// The call to one endpoint, with the token and one renewal when the server refuses it. The
    /// body of a success is returned unread.
    async fn send_to(&self, base: &str, call: Call, body: &[u8]) -> Result<Incoming, ClientError> {
        let auth = self.shared.auth.as_ref();
        let mut stale: Option<Secret> = None;
        for attempt in 0..2 {
            let token = match auth {
                Some(auth) => Some(
                    auth.token(stale.as_ref(), async |credentials| {
                        self.authenticate(base, credentials).await
                    })
                    .await?,
                ),
                None => None,
            };
            let (status, answer) = self.post(base, call, body, token.as_ref()).await?;
            if status.is_success() {
                return Ok(answer);
            }
            let text = tokio::time::timeout(REQUEST_TIMEOUT, Self::collect(answer))
                .await
                .map_err(|_| ClientError::Timeout { path: call.path() })??;
            let text = quote(&text);
            if attempt == 0 && token.is_some() && needs_new_token(status, &text) {
                stale = token;
                continue;
            }
            return Err(ClientError::Status {
                status: status.as_u16(),
                path: call.path(),
                body: text,
            });
        }
        Err(ClientError::Status {
            status: StatusCode::UNAUTHORIZED.as_u16(),
            path: call.path(),
            body: "etcd refused a freshly issued token".into(),
        })
    }

    /// Sends `call` to the endpoint that answered last, and to the others in turn while an
    /// endpoint cannot be reached or answers with a server error.
    async fn send(&self, call: Call, body: &[u8]) -> Result<Incoming, ClientError> {
        let endpoints = &self.shared.endpoints;
        let start = self.shared.preferred.load(Ordering::Relaxed);
        let mut last = None;
        for offset in 0..endpoints.len() {
            let at = (start + offset) % endpoints.len();
            match self.send_to(&endpoints[at], call, body).await {
                Ok(answer) => {
                    self.shared.preferred.store(at, Ordering::Relaxed);
                    return Ok(answer);
                }
                Err(err) if err.is_endpoint_failure() => last = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| ClientError::Transport("no endpoint is configured".into())))
    }

    /// Every key under `prefix` and the revision they were read at.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when etcd cannot be reached or refuses, the answer does not parse, or the
    /// prefix holds more than [`MAX_KEYS_PER_PREFIX`] keys.
    pub(super) async fn range(&self, prefix: &str) -> Result<Ranged, ClientError> {
        let body = json!({
            "key": STANDARD.encode(prefix),
            "range_end": STANDARD.encode(range_end(prefix.as_bytes())),
            "limit": MAX_KEYS_PER_PREFIX + 1,
        })
        .to_string();
        let exchange = async {
            let answer = self.send(Call::Range, body.as_bytes()).await?;
            Self::collect(answer).await
        };
        let bytes = tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| ClientError::Timeout {
                path: Call::Range.path(),
            })??;
        let response: RangeResponse = serde_json::from_slice(&bytes)?;
        if response.more || response.kvs.len() > MAX_KEYS_PER_PREFIX {
            return Err(ClientError::TooManyKeys);
        }
        Ok(Ranged {
            revision: response.header.revision,
            entries: response
                .kvs
                .into_iter()
                .map(Kv::decode)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Watches `prefix` from `start_revision` on.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when etcd cannot be reached or refuses.
    pub(super) async fn watch(
        &self,
        prefix: &str,
        start_revision: u64,
    ) -> Result<Watch, ClientError> {
        let body = json!({
            "create_request": {
                "key": STANDARD.encode(prefix),
                "range_end": STANDARD.encode(range_end(prefix.as_bytes())),
                "start_revision": start_revision,
            }
        })
        .to_string();
        let body = self.send(Call::Watch, body.as_bytes()).await?;
        Ok(Watch {
            body,
            buffer: Vec::new(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn range_end_is_the_prefix_with_its_last_byte_incremented() {
        assert_eq!(range_end(b"podgate/acme/"), b"podgate/acme0".to_vec());
        assert_eq!(range_end(b"a\xff"), b"b".to_vec());
        assert_eq!(range_end(b"\xff\xff"), vec![0]);
    }

    #[test]
    fn a_refused_token_is_recognised() {
        assert!(needs_new_token(StatusCode::UNAUTHORIZED, ""));
        assert!(needs_new_token(
            StatusCode::BAD_REQUEST,
            r#"{"error":"etcdserver: revision of auth store is old"}"#
        ));
        assert!(!needs_new_token(
            StatusCode::BAD_REQUEST,
            r#"{"error":"etcdserver: authentication failed, invalid user ID or password"}"#
        ));
        assert!(!needs_new_token(StatusCode::FORBIDDEN, "permission denied"));
    }
}
