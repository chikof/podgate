//! A client for the Docker Engine API (and Podman's compatible one) over a unix socket.
//!
//! The client has one way to talk to the daemon, [`Client::get`], and that sends `GET`: a source
//! that watches containers has no business starting, stopping or creating them, and the
//! type has no method that could. A socket proxy that only lets `GET` through is therefore
//! enough in front of the daemon.
//!
//! The transport is HTTP/1.1 with `Connection: close`, one connection per request, which keeps
//! the client free of pooling and of half-read connections. Bodies are `Content-Length`,
//! chunked (the `/events` stream) or read to the end of the connection.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::model::{Container, Inspect, Listed, NetworkName};

/// The longest a request, from connect to the last byte of its body, may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response body the client reads: a list of thousands of containers fits, a runaway
/// daemon does not.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The longest status, header or chunk-size line.
const MAX_LINE_BYTES: u64 = 8 * 1024;

/// The longest single event the stream decoder buffers.
const MAX_EVENT_BYTES: usize = 1024 * 1024;

const READ_CHUNK: usize = 16 * 1024;

/// The event names the source reacts to (`docs/ref/provider-docker.md`).
const EVENTS_QUERY: &str = "/events?filters=%7B%22type%22%3A%5B%22container%22%5D%2C%22event%22%3A%5B%22start%22%2C%22stop%22%2C%22die%22%2C%22health_status%22%2C%22destroy%22%5D%7D";

/// What went wrong talking to the daemon.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// The socket cannot be connected to.
    #[error("cannot connect to {path}: {source}")]
    Connect {
        path: Box<str>,
        #[source]
        source: io::Error,
    },
    /// The connection broke mid-request.
    #[error("connection to the daemon failed: {0}")]
    Io(#[from] io::Error),
    /// The daemon did not answer in time.
    #[error("the daemon did not answer within {} seconds", REQUEST_TIMEOUT.as_secs())]
    Timeout,
    /// The daemon answered something that is not HTTP/1.1 as expected.
    #[error("unexpected response from the daemon: {0}")]
    Protocol(&'static str),
    /// The daemon answered with an error status.
    #[error("the daemon answered {status} to GET {path}: {body}")]
    Status {
        status: u16,
        path: Box<str>,
        body: Box<str>,
    },
    /// The body is not the JSON that was expected.
    #[error("the daemon sent JSON that does not parse: {0}")]
    Json(#[from] serde_json::Error),
    /// A body is larger than the client reads.
    #[error("the daemon sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge,
}

/// A daemon event, reduced to what decides whether to look at the containers again.
#[derive(Debug, Deserialize)]
pub(super) struct Event {
    #[serde(rename = "Type", default)]
    kind: Option<String>,
    #[serde(rename = "Action", default)]
    action: Option<String>,
    /// Older Docker and Podman put the action here as well.
    #[serde(default)]
    status: Option<String>,
}

impl Event {
    /// Whether the event can change which containers serve. An event of a shape this code does
    /// not know counts: looking again costs one list, missing a change costs a route.
    pub(super) fn changes_containers(&self) -> bool {
        if self.kind.as_deref().is_some_and(|kind| kind != "container") {
            return false;
        }
        match self.action.as_deref().or(self.status.as_deref()) {
            Some(action) => {
                // `health_status: healthy` carries the result after a colon.
                let name = action.split(':').next().unwrap_or(action).trim();
                matches!(name, "start" | "stop" | "die" | "health_status" | "destroy")
            }
            None => true,
        }
    }
}

/// The daemon's socket.
#[derive(Debug, Clone)]
pub(super) struct Client {
    socket: PathBuf,
}

impl Client {
    pub(super) fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    /// The ids of the running containers, oldest listing order of the daemon.
    pub(super) async fn list(&self) -> Result<Vec<Box<str>>, ClientError> {
        let listed: Vec<Listed> = self.json("/containers/json").await?;
        Ok(listed.into_iter().map(|entry| entry.id.into()).collect())
    }

    /// One container, or `None` when it is gone by now: a container that stops between the list
    /// and the inspect is a normal race, not an error.
    pub(super) async fn inspect(&self, id: &str) -> Result<Option<Container>, ClientError> {
        let path = format!("/containers/{}/json", encode(id));
        match self.json::<Inspect>(&path).await {
            Ok(inspect) => Ok(Some(inspect.into_container())),
            Err(ClientError::Status { status: 404, .. }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The names of the networks the daemon has.
    pub(super) async fn networks(&self) -> Result<BTreeSet<String>, ClientError> {
        let networks: Vec<NetworkName> = self.json("/networks").await?;
        Ok(networks.into_iter().map(|network| network.name).collect())
    }

    /// Opens the event stream, filtered to the container events the source reacts to.
    pub(super) async fn events(&self) -> Result<Events, ClientError> {
        let (reader, head) = self.open(EVENTS_QUERY).await?;
        if head.status >= 400 {
            return Err(ClientError::Status {
                status: head.status,
                path: "/events".into(),
                body: "".into(),
            });
        }
        let body = Body::new(reader, &head);
        Ok(Events {
            body,
            buffer: Vec::new(),
        })
    }

    async fn json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let bytes = self.get(path).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// `GET path`, the whole body. The only request the client sends.
    async fn get(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        let exchange = async {
            let (reader, head) = self.open(path).await?;
            let mut body = Body::new(reader, &head);
            let mut bytes = Vec::new();
            while let Some(chunk) = body.next().await? {
                if bytes.len() + chunk.len() > MAX_BODY_BYTES {
                    return Err(ClientError::TooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            if head.status >= 400 {
                return Err(ClientError::Status {
                    status: head.status,
                    path: path.into(),
                    body: snippet(&bytes),
                });
            }
            Ok(bytes)
        };
        tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    /// Connects, sends `GET path` and reads the response head. An error status is returned as
    /// a head: the caller reads its body for the message.
    async fn open(&self, path: &str) -> Result<(BufReader<UnixStream>, Head), ClientError> {
        let mut stream =
            UnixStream::connect(&self.socket)
                .await
                .map_err(|source| ClientError::Connect {
                    path: self.socket.display().to_string().into(),
                    source,
                })?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: podgate-provider\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut reader = BufReader::new(stream);
        let head = read_head(&mut reader).await?;
        Ok((reader, head))
    }
}

/// The part of a response head the client acts on.
#[derive(Debug)]
struct Head {
    status: u16,
    chunked: bool,
    length: Option<u64>,
}

async fn read_line(reader: &mut BufReader<UnixStream>) -> Result<String, ClientError> {
    let mut line = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE_BYTES)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Err(ClientError::Protocol("the connection closed too early"));
    }
    if !line.ends_with(b"\n") {
        return Err(ClientError::Protocol("a line is too long"));
    }
    let text = std::str::from_utf8(&line)
        .map_err(|_| ClientError::Protocol("a line is not text"))?
        .trim_end_matches(['\r', '\n']);
    Ok(text.to_owned())
}

async fn read_head(reader: &mut BufReader<UnixStream>) -> Result<Head, ClientError> {
    let status_line = read_line(reader).await?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(ClientError::Protocol("the answer is not HTTP/1.x"));
    }
    let status = parts
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(ClientError::Protocol("the status line has no status"))?;
    let mut head = Head {
        status,
        chunked: false,
        length: None,
    };
    loop {
        let line = read_line(reader).await?;
        if line.is_empty() {
            return Ok(head);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ClientError::Protocol("a header has no colon"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.to_ascii_lowercase().contains("chunked");
        } else if name.eq_ignore_ascii_case("content-length") {
            head.length = Some(
                value
                    .parse()
                    .map_err(|_| ClientError::Protocol("content-length is not a number"))?,
            );
        }
    }
}

/// How the body ends.
#[derive(Debug)]
enum Framing {
    Chunked { left: u64, finished: bool },
    Length(u64),
    Close,
}

/// A response body, read piece by piece.
struct Body {
    reader: BufReader<UnixStream>,
    framing: Framing,
}

impl Body {
    fn new(reader: BufReader<UnixStream>, head: &Head) -> Self {
        let framing = if head.chunked {
            Framing::Chunked {
                left: 0,
                finished: false,
            }
        } else if let Some(length) = head.length {
            Framing::Length(length)
        } else {
            Framing::Close
        };
        Self { reader, framing }
    }

    /// The next piece, or `None` at the end of the body.
    async fn next(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        let wanted = match &mut self.framing {
            Framing::Length(0) | Framing::Chunked { finished: true, .. } => return Ok(None),
            Framing::Length(left) => *left,
            Framing::Close => u64::MAX,
            Framing::Chunked { left, .. } if *left > 0 => *left,
            Framing::Chunked { .. } => {
                let size = read_line(&mut self.reader).await?;
                let digits = size.split(';').next().unwrap_or_default().trim();
                let size = u64::from_str_radix(digits, 16)
                    .map_err(|_| ClientError::Protocol("a chunk size is not hex"))?;
                if size == 0 {
                    // Trailers, if any, end with an empty line.
                    while !read_line(&mut self.reader).await?.is_empty() {}
                    self.framing = Framing::Chunked {
                        left: 0,
                        finished: true,
                    };
                    return Ok(None);
                }
                self.framing = Framing::Chunked {
                    left: size,
                    finished: false,
                };
                size
            }
        };
        let mut piece = vec![
            0;
            usize::try_from(wanted)
                .unwrap_or(READ_CHUNK)
                .min(READ_CHUNK)
        ];
        let read = self.reader.read(&mut piece).await?;
        if read == 0 {
            return match self.framing {
                Framing::Close => Ok(None),
                _ => Err(ClientError::Protocol("the body ended early")),
            };
        }
        piece.truncate(read);
        match &mut self.framing {
            Framing::Length(left) => *left -= read as u64,
            Framing::Chunked { left, .. } => {
                *left -= read as u64;
                if *left == 0 {
                    // The CRLF that closes the chunk.
                    read_line(&mut self.reader).await?;
                }
            }
            Framing::Close => {}
        }
        Ok(Some(piece))
    }
}

/// The open `/events` stream.
pub(super) struct Events {
    body: Body,
    buffer: Vec<u8>,
}

impl Events {
    /// The next event, or `None` when the daemon closed the stream.
    ///
    /// Events are JSON values, one per line on Docker and Podman; the decoder does not rely on
    /// the newline, so a value split over chunks or two values in one chunk both work.
    pub(super) async fn next(&mut self) -> Result<Option<Event>, ClientError> {
        loop {
            let mut values =
                serde_json::Deserializer::from_slice(&self.buffer).into_iter::<Event>();
            match values.next() {
                Some(Ok(event)) => {
                    let used = values.byte_offset();
                    self.buffer.drain(..used);
                    return Ok(Some(event));
                }
                Some(Err(err)) if err.is_eof() => {}
                Some(Err(err)) => return Err(err.into()),
                None => self.buffer.clear(),
            }
            match self.body.next().await? {
                Some(piece) => {
                    self.buffer.extend_from_slice(&piece);
                    if self.buffer.len() > MAX_EVENT_BYTES {
                        return Err(ClientError::TooLarge);
                    }
                }
                None => return Ok(None),
            }
        }
    }
}

/// An error body, cut to a line a log can carry.
fn snippet(bytes: &[u8]) -> Box<str> {
    let text = String::from_utf8_lossy(bytes);
    let line = text.trim().lines().next().unwrap_or_default();
    line.chars().take(200).collect::<String>().into()
}

/// Percent-encodes everything but the unreserved characters.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
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
    fn event_filter_query_is_the_documented_one() {
        let decoded = EVENTS_QUERY
            .replace("%22", "\"")
            .replace("%5B", "[")
            .replace("%5D", "]");
        let decoded = decoded
            .replace("%7B", "{")
            .replace("%7D", "}")
            .replace("%3A", ":")
            .replace("%2C", ",");
        assert_eq!(
            decoded,
            "/events?filters={\"type\":[\"container\"],\"event\":[\"start\",\"stop\",\"die\",\"health_status\",\"destroy\"]}"
        );
    }

    #[test]
    fn event_shapes() {
        let parse = |text: &str| serde_json::from_str::<Event>(text).expect("an event");
        assert!(
            parse(r#"{"Type":"container","Action":"health_status: healthy"}"#).changes_containers()
        );
        assert!(parse(r#"{"status":"die"}"#).changes_containers());
        assert!(!parse(r#"{"Type":"network","Action":"connect"}"#).changes_containers());
        assert!(!parse(r#"{"Type":"container","Action":"exec_start: sh"}"#).changes_containers());
        assert!(
            parse("{}").changes_containers(),
            "an unknown shape is a reason to look"
        );
    }

    #[test]
    fn encodes_ids() {
        assert_eq!(encode("abc/def 1"), "abc%2Fdef%201");
    }
}
