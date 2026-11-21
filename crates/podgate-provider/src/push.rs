//! Talking to the admin socket, and the timing rules of a push.
//!
//! [`AdminClient`] speaks the three endpoints the provider needs over the admin unix socket:
//! `PUT /v1/snapshot` (as the writer [`WRITER`]), `POST /v1/snapshot/validate` and
//! `GET /v1/snapshot/version` (`docs/ref/admin-tools.md`). One connection per request,
//! `Connection: close`, every exchange under a deadline.
//!
//! [`Debounce`] and [`Backoff`] are plain state machines over millisecond counts, so their bounds
//! are tested with a fake clock. The provider reads no clock to number snapshots: the version of
//! a push is the live version plus one.

use std::hash::{BuildHasher, RandomState};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The name the provider pushes under, in the `podgate-writer` header.
pub const WRITER: &str = "podgate-provider";

/// Largest answer the client reads. The event feed answers with every event after the cursor, a
/// full ring (4096) of certificates included, and an answer the client refuses would be
/// refused again on every poll.
const MAX_ANSWER_BYTES: usize = 32 * 1024 * 1024;

/// Why a request got no answer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The socket is missing or refuses connections.
    #[error("cannot connect to {path}")]
    Connect {
        /// The socket path.
        path: Box<str>,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// The connection broke while the request or the answer travelled.
    #[error("admin socket i/o failed")]
    Io(#[source] io::Error),
    /// The exchange did not finish in time.
    #[error("admin socket request timed out")]
    Timeout,
    /// The answer is not HTTP/1.1 or is not what the endpoint documents.
    #[error("unexpected answer from the admin socket: {0}")]
    Protocol(Box<str>),
}

/// One HTTP answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The status code.
    pub status: u16,
    /// Header names (lowercase) and values.
    pub headers: Vec<(Box<str>, Box<str>)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Answer {
    /// The body as JSON, when it is.
    #[must_use]
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The value of the header `name` (lowercase), if present.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| &**key == name)
            .map(|(_, value)| &**value)
    }

    /// The body as text for an error message, shortened.
    #[must_use]
    pub fn excerpt(&self) -> String {
        let text = String::from_utf8_lossy(&self.body);
        let mut excerpt: String = text.chars().take(300).collect();
        if text.chars().count() > 300 {
            excerpt.push_str("...");
        }
        excerpt
    }
}

/// The answer of `GET /v1/snapshot/version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    /// The live version; `0` before the first snapshot.
    pub version: u64,
    /// The pinned writer, when there is one with a name.
    pub writer: Option<Box<str>>,
    /// Identifies the running process: a new one after a restart.
    pub boot_id: Box<str>,
}

/// Timing knobs of the client and the retry loop. The defaults are the documented ones; tests
/// shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// First retry delay after a transient failure.
    pub backoff_min: Duration,
    /// The retry delay stops doubling here.
    pub backoff_max: Duration,
    /// Deadline of one request.
    pub request_timeout: Duration,
    /// How long to wait when validate answers `503` busy, before asking again.
    pub busy_wait: Duration,
    /// How long one poll of the event feed waits for an event (`timeout_secs`); the request
    /// deadline is this plus `request_timeout`.
    pub event_poll: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            busy_wait: Duration::from_secs(1),
            event_poll: Duration::from_secs(20),
        }
    }
}

/// A client of the admin socket.
#[derive(Debug, Clone)]
pub struct AdminClient {
    socket: PathBuf,
    timeout: Duration,
}

impl AdminClient {
    /// A client of the socket at `socket`.
    #[must_use]
    pub fn new(socket: &Path, timeout: Duration) -> Self {
        Self {
            socket: socket.to_owned(),
            timeout,
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        writer: bool,
        body: &[u8],
    ) -> Result<Answer, ClientError> {
        self.request_within(self.timeout, method, path, writer, body)
            .await
    }

    async fn request_within(
        &self,
        timeout: Duration,
        method: &str,
        path: &str,
        writer: bool,
        body: &[u8],
    ) -> Result<Answer, ClientError> {
        let exchange = async {
            let mut stream =
                UnixStream::connect(&self.socket)
                    .await
                    .map_err(|source| ClientError::Connect {
                        path: self.socket.display().to_string().into(),
                        source,
                    })?;
            let writer_header = if writer {
                format!("podgate-writer: {WRITER}\r\n")
            } else {
                String::new()
            };
            let head = format!(
                "{method} {path} HTTP/1.1\r\nhost: podgate\r\n{writer_header}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(head.as_bytes())
                .await
                .map_err(ClientError::Io)?;
            stream.write_all(body).await.map_err(ClientError::Io)?;
            let mut raw = Vec::new();
            let mut limited = stream.take(MAX_ANSWER_BYTES as u64 + 1);
            limited
                .read_to_end(&mut raw)
                .await
                .map_err(ClientError::Io)?;
            if raw.len() > MAX_ANSWER_BYTES {
                return Err(ClientError::Protocol("the answer is too large".into()));
            }
            parse_answer(&raw)
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    /// `GET /v1/snapshot/version`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when there is no answer, or the answer is not `200` with the documented
    /// fields.
    pub async fn version(&self) -> Result<Live, ClientError> {
        let answer = self
            .request("GET", "/v1/snapshot/version", false, b"")
            .await?;
        let unexpected = |why: &str| {
            ClientError::Protocol(format!("{why}: {} {}", answer.status, answer.excerpt()).into())
        };
        if answer.status != 200 {
            return Err(unexpected("version was refused"));
        }
        let json = answer
            .json()
            .ok_or_else(|| unexpected("version is not JSON"))?;
        let version = json
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| unexpected("version has no `version`"))?;
        let boot_id = json
            .get("boot_id")
            .and_then(Value::as_str)
            .ok_or_else(|| unexpected("version has no `boot_id`"))?;
        Ok(Live {
            version,
            writer: json.get("writer").and_then(Value::as_str).map(Into::into),
            boot_id: boot_id.into(),
        })
    }

    /// `GET /v1/schema`: the JSON Schema of a snapshot, as the daemon builds it. Sends no writer
    /// header.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when there is no answer, or the answer is not `200` with a JSON document.
    pub async fn schema(&self) -> Result<Value, ClientError> {
        let answer = self.request("GET", "/v1/schema", false, b"").await?;
        if answer.status != 200 {
            return Err(ClientError::Protocol(
                format!("schema was refused: {} {}", answer.status, answer.excerpt()).into(),
            ));
        }
        answer
            .json()
            .ok_or_else(|| ClientError::Protocol("the schema is not JSON".into()))
    }

    /// `PUT /v1/snapshot` as [`WRITER`], with `body` already holding the version.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when there is no answer. Every status is an [`Answer`].
    pub async fn put(&self, body: &str) -> Result<Answer, ClientError> {
        self.request("PUT", "/v1/snapshot", true, body.as_bytes())
            .await
    }

    /// `POST /v1/snapshot/validate`: would the compiler accept `body`. Sends no writer header.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when there is no answer. Every status is an [`Answer`].
    pub async fn validate(&self, body: &str) -> Result<Answer, ClientError> {
        self.request("POST", "/v1/snapshot/validate", false, body.as_bytes())
            .await
    }

    /// `GET /v1/events?after=<after>&timeout_secs=<wait>`: a long poll that waits up to `wait`
    /// (at least one second) for an event after `after`. Sends no writer header.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when there is no answer. Every status is an [`Answer`].
    pub async fn events(&self, after: u64, wait: Duration) -> Result<Answer, ClientError> {
        let path = format!(
            "/v1/events?after={after}&timeout_secs={}",
            wait.as_secs().max(1)
        );
        self.request_within(self.timeout + wait, "GET", &path, false, b"")
            .await
    }
}

fn parse_answer(raw: &[u8]) -> Result<Answer, ClientError> {
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut slots);
    let head_len = match response.parse(raw) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => {
            return Err(ClientError::Protocol(
                "the answer ends inside its head".into(),
            ));
        }
        Err(err) => return Err(ClientError::Protocol(err.to_string().into())),
    };
    let status = response
        .code
        .ok_or_else(|| ClientError::Protocol("no status code".into()))?;
    let headers: Vec<(Box<str>, Box<str>)> = response
        .headers
        .iter()
        .map(|header| {
            (
                header.name.to_ascii_lowercase().into(),
                String::from_utf8_lossy(header.value).trim().into(),
            )
        })
        .collect();
    let rest = &raw[head_len..];
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| &**key == name)
            .map(|(_, value)| &**value)
    };
    let body = if find("transfer-encoding").is_some_and(|value| value.contains("chunked")) {
        dechunk(rest)?
    } else if let Some(length) = find("content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| ClientError::Protocol("bad content-length".into()))?;
        rest.get(..length)
            .ok_or_else(|| ClientError::Protocol("the body is shorter than content-length".into()))?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Answer {
        status,
        headers,
        body,
    })
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, ClientError> {
    let bad = || ClientError::Protocol("bad chunked body".into());
    let mut body = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .ok_or_else(bad)?;
        let size_text = std::str::from_utf8(&rest[..line_end]).map_err(|_| bad())?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| bad())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let chunk = rest.get(..size).ok_or_else(bad)?;
        body.extend_from_slice(chunk);
        rest = rest.get(size + 2..).ok_or_else(bad)?;
    }
}

/// Coalesces updates: a push becomes due `window` after the last update, but never later than
/// `max_delay` after the first update of the burst. Plain state over millisecond counts; the
/// caller supplies the clock.
///
/// ```
/// use podgate_provider::push::Debounce;
///
/// let mut debounce = Debounce::new(100, 300);
/// debounce.note(0);
/// debounce.note(80);
/// assert_eq!(debounce.deadline(), Some(180));
/// debounce.note(160);
/// debounce.note(240);
/// assert_eq!(debounce.deadline(), Some(300), "a steady stream cannot push past max_delay");
/// assert!(debounce.due(300));
/// assert_eq!(debounce.deadline(), None);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Debounce {
    window: u64,
    max_delay: u64,
    burst: Option<Burst>,
}

#[derive(Debug, Clone, Copy)]
struct Burst {
    first: u64,
    last: u64,
}

impl Debounce {
    /// A debouncer with the quiet `window` and the `max_delay`, both in milliseconds.
    #[must_use]
    pub fn new(window: u64, max_delay: u64) -> Self {
        Self {
            window,
            max_delay: max_delay.max(window),
            burst: None,
        }
    }

    /// Records an update at `now`.
    pub fn note(&mut self, now: u64) {
        match &mut self.burst {
            Some(burst) => burst.last = now,
            None => {
                self.burst = Some(Burst {
                    first: now,
                    last: now,
                });
            }
        }
    }

    /// When the pending push is due, if one is pending.
    #[must_use]
    pub fn deadline(&self) -> Option<u64> {
        self.burst
            .map(|burst| (burst.last + self.window).min(burst.first + self.max_delay))
    }

    /// Whether the pending push is due at `now`; when it is, the burst is over.
    pub fn due(&mut self, now: u64) -> bool {
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.burst = None;
            true
        } else {
            false
        }
    }
}

/// The retry delays: `min`, then doubling up to `max`, until [`Self::reset`]. A
/// [`jittered`](Self::jittered) backoff adds up to a quarter to each delay, so many watchers that
/// failed together do not retry together.
///
/// ```
/// use std::time::Duration;
/// use podgate_provider::push::Backoff;
///
/// let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
/// let delays: Vec<u64> = (0..7).map(|_| backoff.next_delay().as_secs()).collect();
/// assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30]);
/// backoff.reset();
/// assert_eq!(backoff.next_delay().as_secs(), 1);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
    jitter: bool,
}

impl Backoff {
    /// Delays from `min` to `max`.
    #[must_use]
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max: max.max(min),
            next: min,
            jitter: false,
        }
    }

    /// Adds up to a quarter to every delay; the delays are exact otherwise.
    #[must_use]
    pub fn jittered(mut self) -> Self {
        self.jitter = true;
        self
    }

    /// The delay to wait now; the one after it is twice as long, up to the maximum.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        if !self.jitter {
            return delay;
        }
        // `RandomState` is randomly keyed per instance: enough jitter without a new dependency.
        let random = RandomState::new().hash_one(delay);
        let spread = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX).max(4) / 4;
        delay + Duration::from_millis(random % spread)
    }

    /// Starts over from the minimum, after a success.
    pub fn reset(&mut self) {
        self.next = self.min;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dechunks_a_body() {
        let body = dechunk(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").expect("chunks");
        assert_eq!(body, b"hello world");
        assert!(dechunk(b"zz\r\nhello").is_err());
    }

    #[test]
    fn parses_an_answer_with_content_length() {
        let raw = b"HTTP/1.1 409 Conflict\r\nContent-Length: 11\r\nX-A: b\r\n\r\n{\"a\":\"b\"}\n\n";
        let answer = parse_answer(raw).expect("answer");
        assert_eq!(answer.status, 409);
        assert_eq!(answer.header("x-a"), Some("b"));
        assert_eq!(answer.body.len(), 11);
    }
}
