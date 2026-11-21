//! A scripted HTTP(S) endpoint on a loopback port, for the HTTP source's tests. No test talks to a
//! real server.
//!
//! Each path has one [`Reply`] (a body, a status, headers, a delay, or a dropped connection);
//! [`FakeHttp::set`] changes it while the source runs. A reply that carries a validator
//! ([`Reply::etag`], [`Reply::last_modified`]) is answered `304` to a request that sends the same
//! validator back, as a real server does. Every request is recorded with its headers, the time it
//! arrived and whether the TLS connection carried a client certificate.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use super::etcd::Pki;

/// What the endpoint answers.
#[derive(Debug, Clone)]
pub struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
    drop_connection: bool,
    /// Answer with this many bytes, chunked and without a length, as a server that never stops.
    stream: Option<usize>,
}

impl Reply {
    fn new(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: content_type
                .map(|value| ("content-type".to_owned(), value.to_owned()))
                .into_iter()
                .collect(),
            body,
            delay: Duration::ZERO,
            drop_connection: false,
            stream: None,
        }
    }

    /// `200` with a JSON body.
    pub fn json(body: impl Into<String>) -> Self {
        Self::new(200, Some("application/json"), body.into().into_bytes())
    }

    /// `200` with a YAML body.
    pub fn yaml(body: impl Into<String>) -> Self {
        Self::new(200, Some("application/yaml"), body.into().into_bytes())
    }

    /// An answer with `status`, no `Content-Type` and no body.
    pub fn status(status: u16) -> Self {
        Self::new(status, None, Vec::new())
    }

    /// A redirect to `location`.
    pub fn redirect(status: u16, location: &str) -> Self {
        Self::status(status).header("location", location)
    }

    /// Closes the connection without an answer.
    pub fn dropped() -> Self {
        Self {
            drop_connection: true,
            ..Self::status(200)
        }
    }

    /// Sets (or replaces) a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .retain(|(have, _)| !have.eq_ignore_ascii_case(name));
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn content_type(self, value: &str) -> Self {
        self.header("content-type", value)
    }

    #[must_use]
    pub fn etag(self, value: &str) -> Self {
        self.header("etag", value)
    }

    #[must_use]
    pub fn last_modified(self, value: &str) -> Self {
        self.header("last-modified", value)
    }

    /// Waits this long before answering.
    #[must_use]
    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Streams `bytes` bytes without a `Content-Length`.
    #[must_use]
    pub fn endless(mut self, bytes: usize) -> Self {
        self.stream = Some(bytes);
        self
    }

    fn header_of(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(have, _)| have == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A request the endpoint received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub path: String,
    /// Header names in lower case.
    pub headers: BTreeMap<String, String>,
    pub at: Instant,
    /// Whether the connection was TLS and the client showed a certificate.
    pub client_cert: bool,
}

#[derive(Default)]
struct Inner {
    routes: HashMap<String, Reply>,
    requests: Vec<Seen>,
}

struct Shared {
    inner: Mutex<Inner>,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Inner> {
    shared.inner.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The running endpoint.
pub struct FakeHttp {
    port: u16,
    shared: Arc<Shared>,
    https: bool,
    server: JoinHandle<()>,
}

impl FakeHttp {
    /// Plain HTTP on `127.0.0.1`.
    pub async fn start() -> Self {
        Self::start_with(None).await
    }

    /// TLS with a certificate of `pki` for `127.0.0.1`; with `require_client_cert` a client
    /// certificate of the same CA is demanded.
    pub async fn start_tls(pki: &Pki, require_client_cert: bool) -> Self {
        Self::start_with(Some(TlsAcceptor::from(
            pki.server_config(require_client_cert),
        )))
        .await
    }

    async fn start_with(acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake endpoint");
        let port = listener.local_addr().expect("local addr").port();
        let shared = Arc::new(Shared {
            inner: Mutex::new(Inner::default()),
        });
        let https = acceptor.is_some();
        let server = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                let mut connections = JoinSet::new();
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        return;
                    };
                    connections.spawn(connection(
                        stream,
                        peer,
                        Arc::clone(&shared),
                        acceptor.clone(),
                    ));
                    while connections.try_join_next().is_some() {}
                }
            }
        });
        Self {
            port,
            shared,
            https,
            server,
        }
    }

    /// `http://127.0.0.1:<port>` or `https://...`, without a path.
    pub fn origin(&self) -> String {
        format!(
            "{}://127.0.0.1:{}",
            if self.https { "https" } else { "http" },
            self.port
        )
    }

    /// The URL of `path` (which starts with `/`).
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// What `path` answers from now on.
    pub fn set(&self, path: &str, reply: Reply) {
        lock(&self.shared).routes.insert(path.to_owned(), reply);
    }

    pub fn requests(&self) -> Vec<Seen> {
        lock(&self.shared).requests.clone()
    }

    pub fn count(&self, path: &str) -> usize {
        lock(&self.shared)
            .requests
            .iter()
            .filter(|seen| seen.path == path)
            .count()
    }

    /// Waits until `condition` holds for the requests so far.
    pub async fn wait_requests(&self, what: &str, condition: impl Fn(&[Seen]) -> bool) {
        let wait = async {
            while !condition(&self.requests()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        if tokio::time::timeout(super::DEADLINE, wait).await.is_err() {
            panic!(
                "timed out waiting for: {what}; requests: {:?}",
                self.requests()
            );
        }
    }
}

impl Drop for FakeHttp {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn connection(
    stream: TcpStream,
    _peer: SocketAddr,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
) {
    match acceptor {
        Some(acceptor) => {
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            let client_cert = stream.get_ref().1.peer_certificates().is_some();
            Box::pin(serve(stream, shared, client_cert)).await;
        }
        None => Box::pin(serve(stream, shared, false)).await,
    }
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Option<String> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&raw).into_owned());
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || raw.len() > 64 * 1024 {
            return None;
        }
        raw.extend_from_slice(&chunk[..read]);
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    shared: Arc<Shared>,
    client_cert: bool,
) {
    let Some(head) = read_head(&mut stream).await else {
        return;
    };
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let (_method, path) = (request_line.next(), request_line.next().unwrap_or("/"));
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let reply = {
        let mut inner = lock(&shared);
        inner.requests.push(Seen {
            path: path.to_owned(),
            headers: headers.clone(),
            at: Instant::now(),
            client_cert,
        });
        inner.routes.get(path).cloned()
    }
    .unwrap_or_else(|| Reply::status(404));
    if reply.drop_connection {
        return;
    }
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let unchanged = [
        ("if-none-match", "etag"),
        ("if-modified-since", "last-modified"),
    ]
    .iter()
    .any(|(sent, have)| {
        headers
            .get(*sent)
            .is_some_and(|sent| reply.header_of(have) == Some(sent.as_str()))
    });
    let (status, body) = if reply.status == 200 && unchanged {
        (304, Vec::new())
    } else {
        (reply.status, reply.body.clone())
    };
    let mut answer = format!(
        "HTTP/1.1 {status} {}\r\nConnection: close\r\n",
        reason(status)
    );
    for (name, value) in &reply.headers {
        answer.push_str(&format!("{name}: {value}\r\n"));
    }
    match reply.stream.filter(|_| status == 200) {
        Some(total) => {
            answer.push_str("transfer-encoding: chunked\r\n\r\n");
            if stream.write_all(answer.as_bytes()).await.is_err() {
                return;
            }
            let block = vec![b' '; 16 * 1024];
            let mut sent = 0;
            while sent < total {
                let size = block.len().min(total - sent);
                let chunk = format!("{size:x}\r\n");
                if stream.write_all(chunk.as_bytes()).await.is_err()
                    || stream.write_all(&block[..size]).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    return;
                }
                sent += size;
            }
            let _ = stream.write_all(b"0\r\n\r\n").await;
        }
        None => {
            answer.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
            let _ = stream.write_all(answer.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    }
    let _ = stream.shutdown().await;
}
