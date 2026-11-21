//! A FastCGI application for the `fastcgi` service tests: it speaks the record protocol, hands
//! each request (parameters and body) to a closure, and writes back what the closure says, so a
//! test decides exactly what a script would have sent. It also counts connections and requests
//! in flight, which is how the pool limits are checked.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinHandle;
use tokio::time::sleep;

const BEGIN_REQUEST: u8 = 1;
const END_REQUEST: u8 = 3;
const PARAMS: u8 = 4;
const STDIN: u8 = 5;
const STDOUT: u8 = 6;
const STDERR: u8 = 7;

/// One request as the application received it.
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// Every parameter, in the order they were sent.
    pub params: Vec<(String, String)>,
    /// The body.
    pub stdin: Vec<u8>,
    /// Whether the client asked to keep the connection open.
    pub keep_conn: bool,
}

impl Request {
    /// The value of parameter `name`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every parameter whose name starts with `HTTP_`.
    pub fn http_names(&self) -> Vec<&str> {
        self.params
            .iter()
            .map(|(name, _)| name.as_str())
            .filter(|name| name.starts_with("HTTP_"))
            .collect()
    }
}

/// What the application answers with.
#[derive(Clone, Debug, Default)]
pub struct Reply {
    /// The bytes of `FCGI_STDOUT`: CGI headers, a blank line, the body.
    pub stdout: Vec<u8>,
    /// The bytes of `FCGI_STDERR`.
    pub stderr: Vec<u8>,
    /// How long to wait before answering.
    pub delay: Duration,
    /// Closes the connection after the output without saying the request ended.
    pub drop_connection: bool,
    /// Closes the connection after a complete answer.
    pub close_after: bool,
}

impl Reply {
    /// `200` with `Content-Type: text/plain` and `body`.
    pub fn text(body: &str) -> Self {
        Self::cgi("Content-Type: text/plain\r\n", body.as_bytes())
    }

    /// `head` (CGI header lines, each ending in `\r\n`), a blank line, `body`.
    pub fn cgi(head: &str, body: &[u8]) -> Self {
        let mut stdout = head.as_bytes().to_vec();
        stdout.extend_from_slice(b"\r\n");
        stdout.extend_from_slice(body);
        Self {
            stdout,
            ..Self::default()
        }
    }

    /// Exactly these bytes as the output.
    pub fn raw(stdout: &[u8]) -> Self {
        Self {
            stdout: stdout.to_vec(),
            ..Self::default()
        }
    }

    /// The same answer after `delay`.
    #[must_use]
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// The same answer with `stderr`.
    #[must_use]
    pub fn with_stderr(mut self, stderr: &str) -> Self {
        self.stderr = stderr.as_bytes().to_vec();
        self
    }

    /// The same answer, then the application closes the connection although the client asked
    /// to keep it (a PHP-FPM worker that reached `pm.max_requests`).
    #[must_use]
    pub fn then_close(mut self) -> Self {
        self.close_after = true;
        self
    }
}

#[derive(Default)]
struct Shared {
    requests: Mutex<Vec<Request>>,
    accepted: AtomicUsize,
    open: AtomicUsize,
    peak_open: AtomicUsize,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    connections: Mutex<Vec<JoinHandle<()>>>,
}

type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

/// A listening FastCGI application. Stops on drop.
pub struct Fcgi {
    /// `127.0.0.1:<port>` for a TCP application, `unix:<path>` for a unix one: what
    /// `FASTCGI_FILE` calls the address.
    pub address: String,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Fcgi {
    /// Starts an application on a loopback port; `handler` answers every request.
    pub async fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let shared = Arc::new(Shared::default());
        let handler: Handler = Arc::new(handler);
        let task = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let task = tokio::spawn(connection(
                        stream,
                        Arc::clone(&shared),
                        Arc::clone(&handler),
                    ));
                    shared.connections.lock().expect("connections").push(task);
                }
            }
        });
        Self {
            address,
            shared,
            task,
        }
    }

    /// Starts an application on the unix socket `path`.
    pub async fn start_unix(
        path: &Path,
        handler: impl Fn(&Request) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = UnixListener::bind(path).expect("bind the unix socket");
        let shared = Arc::new(Shared::default());
        let handler: Handler = Arc::new(handler);
        let task = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let task = tokio::spawn(connection(
                        stream,
                        Arc::clone(&shared),
                        Arc::clone(&handler),
                    ));
                    shared.connections.lock().expect("connections").push(task);
                }
            }
        });
        Self {
            address: format!("unix:{}", path.display()),
            shared,
            task,
        }
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Request> {
        self.shared.requests.lock().expect("requests").clone()
    }

    /// Connections accepted so far.
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Most connections open at once.
    pub fn peak_open(&self) -> usize {
        self.shared.peak_open.load(Ordering::SeqCst)
    }

    /// Most requests being answered at once.
    pub fn peak_in_flight(&self) -> usize {
        self.shared.peak_in_flight.load(Ordering::SeqCst)
    }
}

impl Drop for Fcgi {
    fn drop(&mut self) {
        self.task.abort();
        for task in self
            .shared
            .connections
            .lock()
            .expect("connections")
            .drain(..)
        {
            task.abort();
        }
    }
}

fn bump(counter: &AtomicUsize, peak: &AtomicUsize) {
    let now = counter.fetch_add(1, Ordering::SeqCst) + 1;
    peak.fetch_max(now, Ordering::SeqCst);
}

async fn connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    shared: Arc<Shared>,
    handler: Handler,
) {
    shared.accepted.fetch_add(1, Ordering::SeqCst);
    bump(&shared.open, &shared.peak_open);
    while let Some(request) = read_request(&mut stream).await {
        shared
            .requests
            .lock()
            .expect("requests")
            .push(request.clone());
        bump(&shared.in_flight, &shared.peak_in_flight);
        let reply = handler(&request);
        sleep(reply.delay).await;
        let wrote = write_reply(&mut stream, &reply).await;
        shared.in_flight.fetch_sub(1, Ordering::SeqCst);
        if wrote.is_err() || reply.drop_connection || reply.close_after || !request.keep_conn {
            break;
        }
    }
    shared.open.fetch_sub(1, Ordering::SeqCst);
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Request> {
    let mut request = Request::default();
    let mut params = Vec::new();
    loop {
        let mut head = [0_u8; 8];
        stream.read_exact(&mut head).await.ok()?;
        let len = usize::from(u16::from_be_bytes([head[4], head[5]]));
        let mut content = vec![0_u8; len];
        stream.read_exact(&mut content).await.ok()?;
        let mut padding = vec![0_u8; usize::from(head[6])];
        stream.read_exact(&mut padding).await.ok()?;
        match head[1] {
            BEGIN_REQUEST => request.keep_conn = content.get(2).is_some_and(|flags| flags & 1 == 1),
            PARAMS if content.is_empty() => request.params = decode_pairs(&params),
            PARAMS => params.extend_from_slice(&content),
            STDIN if content.is_empty() => return Some(request),
            STDIN => request.stdin.extend_from_slice(&content),
            _ => {}
        }
    }
}

fn decode_pairs(mut bytes: &[u8]) -> Vec<(String, String)> {
    fn length(bytes: &mut &[u8]) -> usize {
        let first = bytes[0];
        if first < 0x80 {
            *bytes = &bytes[1..];
            usize::from(first)
        } else {
            let value = u32::from_be_bytes([first & 0x7f, bytes[1], bytes[2], bytes[3]]);
            *bytes = &bytes[4..];
            value as usize
        }
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let name = length(&mut bytes);
        let value = length(&mut bytes);
        out.push((
            String::from_utf8_lossy(&bytes[..name]).into_owned(),
            String::from_utf8_lossy(&bytes[name..name + value]).into_owned(),
        ));
        bytes = &bytes[name + value..];
    }
    out
}

fn record(kind: u8, content: &[u8]) -> Vec<u8> {
    let len = u16::try_from(content.len()).expect("record content fits");
    let mut out = vec![1, kind, 0, 1];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(content);
    out
}

async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: &Reply) -> std::io::Result<()> {
    for chunk in reply.stdout.chunks(65535) {
        stream.write_all(&record(STDOUT, chunk)).await?;
    }
    if !reply.drop_connection {
        stream.write_all(&record(STDOUT, &[])).await?;
    }
    for chunk in reply.stderr.chunks(65535) {
        stream.write_all(&record(STDERR, chunk)).await?;
    }
    if reply.drop_connection {
        return stream.shutdown().await;
    }
    stream
        .write_all(&record(END_REQUEST, &[0, 0, 0, 0, 0, 0, 0, 0]))
        .await?;
    stream.flush().await
}
