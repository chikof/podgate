//! A UDP echo backend and two closed-loop load generators, for `scripts/bench-proxies.sh`.
//!
//! * `load_bench echo <addr>` answers every datagram with itself, and the datagram `__stats` with
//!   the number of datagrams echoed so far, so a benchmark can prove that the datagrams reached it.
//! * `load_bench stats <addr>` prints that counter.
//! * `load_bench udp <addr> <connections> <seconds>` opens one socket per connection and, on each,
//!   sends a 100 byte datagram, waits for the echo and sends the next, for the given time.
//! * `load_bench h3 <addr> <server name> <cert.pem> <connections> <seconds>` opens one QUIC
//!   connection per connection (trusting `cert.pem`) and, on each, sends `GET /` over HTTP/3,
//!   reads the 100 byte answer and sends the next. The `oha` in the benchmark's toolbox is built
//!   without HTTP/3.
//! * `load_bench h3-count|tls-count <addr> <server name> <cert.pem> <connections> <warmup> <requests>`
//!   is the fixed-count form for `scripts/bench-callgrind.sh`: every connection is made
//!   first, then `warmup` requests are sent (shared out evenly), then exactly `requests` more,
//!   then the connections close. `h3-count` is HTTP/3 as `h3` is; `tls-count` is HTTP/1.1
//!   keep-alive over TLS 1.3. With `LOAD_BENCH_SYNC=<dir>` it creates `<dir>/warm` when the warm-up
//!   is over and waits for `<dir>/go`, creates `<dir>/done` when the count is over and waits for
//!   `<dir>/release`, so the script can zero and dump callgrind's counters exactly around the
//!   counted requests. `LOAD_BENCH_REPLY_TIMEOUT_MS` (default 1000) is the time one request may
//!   take, which valgrind needs to have raised. The `h3-count` report has a `quic` object: the sum
//!   over the connections of `quinn::ConnectionStats` for the counted requests (`window`) and for
//!   the whole connection (`total`).
//!
//! The two generators print one JSON object in the shape of `oha --output-format json` (the fields
//! the script reads), so their runs go through the same bookkeeping as an HTTP one. A reply that
//! does not arrive within a second, or is not what the backend sends, counts as an error.

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAYLOAD_LEN: usize = 100;
const STATS: &[u8] = b"__stats";
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn usage() -> ! {
    eprintln!(
        "usage: load_bench echo <addr> | stats <addr> | udp <addr> <connections> <seconds> |\n       h3 <addr> <server name> <cert.pem> <connections> <seconds> |\n       h3-count|tls-count <addr> <server name> <cert.pem> <connections> <warmup> <requests>"
    );
    std::process::exit(2);
}

fn echo(addr: SocketAddr) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr)?);
    let echoed = Arc::new(AtomicU64::new(0));
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let socket = Arc::clone(&socket);
            let echoed = Arc::clone(&echoed);
            std::thread::spawn(move || {
                let mut buf = [0_u8; 2048];
                while let Ok((len, from)) = socket.recv_from(&mut buf) {
                    if &buf[..len] == STATS {
                        let reply = echoed.load(Ordering::Relaxed).to_string();
                        let _ = socket.send_to(reply.as_bytes(), from);
                    } else {
                        echoed.fetch_add(1, Ordering::Relaxed);
                        let _ = socket.send_to(&buf[..len], from);
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn stats(addr: SocketAddr) -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(REPLY_TIMEOUT))?;
    socket.send_to(STATS, addr)?;
    let mut buf = [0_u8; 64];
    let (len, _) = socket.recv_from(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf[..len]));
    Ok(())
}

/// What one connection saw: the round trips in microseconds, and the failures.
#[derive(Default)]
struct Seen {
    micros: Vec<u32>,
    errors: u64,
}

impl Seen {
    fn ok(&mut self, started: Instant) {
        self.micros
            .push(u32::try_from(started.elapsed().as_micros()).unwrap_or(u32::MAX));
    }

    fn failed(err: &Failure) -> Self {
        eprintln!("connection failed: {err}");
        Self {
            micros: Vec::new(),
            errors: 1,
        }
    }
}

async fn udp_connection(addr: SocketAddr, run: Duration, index: u64) -> Result<Seen, Failure> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(addr).await?;
    let mut payload = [b'x'; PAYLOAD_LEN];
    payload[..8].copy_from_slice(&index.to_be_bytes());
    let mut reply = [0_u8; 2048];
    let mut seen = Seen::default();
    let until = Instant::now() + run;
    while Instant::now() < until {
        let started = Instant::now();
        socket.send(&payload).await?;
        match tokio::time::timeout(REPLY_TIMEOUT, socket.recv(&mut reply)).await {
            Ok(Ok(len)) if reply[..len] == payload => seen.ok(started),
            _ => seen.errors += 1,
        }
    }
    Ok(seen)
}

/// The client side of TLS 1.3 against the benchmark's self-signed certificate, offering one ALPN
/// protocol.
fn tls_config(cert_pem: &str, alpn: &[u8]) -> Result<rustls::ClientConfig, Failure> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(cert_pem)?)?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    Ok(tls)
}

fn client_config(cert_pem: &str) -> Result<quinn::ClientConfig, Failure> {
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config(cert_pem, b"h3")?)?,
    )))
}

/// One QUIC connection, established before `begin` releases every connection together, then
/// `GET /` in a loop for `run`.
async fn h3_connection(
    addr: SocketAddr,
    name: Arc<str>,
    config: quinn::ClientConfig,
    begin: Arc<tokio::sync::Barrier>,
    run: Duration,
) -> Result<Seen, Failure> {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(config);
    let conn = endpoint.connect(addr, &name)?.await?;
    let (mut driver, mut send) = Box::pin(h3::client::new(h3_quinn::Connection::new(conn))).await?;
    let driver = tokio::spawn(async move { driver.wait_idle().await });
    let uri = format!("https://{name}/");
    begin.wait().await;
    let until = Instant::now() + run;
    let mut seen = Seen::default();
    while Instant::now() < until {
        let started = Instant::now();
        let request = http::Request::get(&uri).body(())?;
        let outcome = tokio::time::timeout(REPLY_TIMEOUT, async {
            let mut stream = send.send_request(request).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            let mut body = 0;
            while let Some(chunk) = stream.recv_data().await? {
                body += chunk.remaining();
            }
            Ok::<_, h3::error::StreamError>((response.status(), body))
        })
        .await;
        match outcome {
            Ok(Ok((status, PAYLOAD_LEN))) if status == http::StatusCode::OK => seen.ok(started),
            _ => {
                seen.errors += 1;
                break;
            }
        }
    }
    driver.abort();
    Ok(seen)
}

fn percentile(sorted: &[u32], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    f64::from(sorted[index]) / 1e6
}

/// Runs `tasks`, which each run for `seconds`, on a runtime with one worker per CPU and prints the
/// report.
fn report<F>(tasks: Vec<F>, seconds: u64) -> std::io::Result<()>
where
    F: Future<Output = Seen> + Send + 'static,
{
    let runtime = runtime()?;
    let seen = runtime.block_on(async {
        let handles: Vec<_> = tasks.into_iter().map(tokio::spawn).collect();
        let mut all = Seen::default();
        for handle in handles {
            let one = handle.await.unwrap_or_default();
            all.micros.extend(one.micros);
            all.errors += one.errors;
        }
        all
    });
    println!("{}", summarize(seen, seconds as f64));
    Ok(())
}

/// A runtime with one worker per CPU the process may use.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
}

/// The report, in the shape of `oha --output-format json` (the fields the script reads).
fn summarize(seen: Seen, seconds: f64) -> serde_json::Value {
    let mut sorted = seen.micros;
    sorted.sort_unstable();
    let ok = sorted.len();
    let rate = ok as f64 / seconds;
    json!({
        "summary": { "requestsPerSec": rate },
        "latencyPercentiles": {
            "p50": percentile(&sorted, 0.50),
            "p99": percentile(&sorted, 0.99),
            "p99.9": percentile(&sorted, 0.999),
        },
        "statusCodeDistribution": { "200": ok },
        "errorDistribution": if seen.errors == 0 { json!({}) } else { json!({ "no answer": seen.errors }) },
    })
}

fn udp(addr: SocketAddr, connections: u64, seconds: u64) -> std::io::Result<()> {
    let run = Duration::from_secs(seconds);
    let tasks = (0..connections)
        .map(|index| async move {
            udp_connection(addr, run, index)
                .await
                .unwrap_or_else(|err| Seen::failed(&err))
        })
        .collect();
    report(tasks, seconds)
}

/// The clock of an HTTP/3 run starts when every connection is up, so the handshakes are not
/// counted.
fn h3(
    addr: SocketAddr,
    name: &str,
    cert_pem: &str,
    connections: usize,
    seconds: u64,
) -> Result<(), Failure> {
    let config = client_config(cert_pem)?;
    let name: Arc<str> = Arc::from(name);
    let begin = Arc::new(tokio::sync::Barrier::new(connections));
    let run = Duration::from_secs(seconds);
    let tasks: Vec<_> = (0..connections)
        .map(|_| {
            let (name, config, begin) = (Arc::clone(&name), config.clone(), Arc::clone(&begin));
            async move {
                Box::pin(h3_connection(addr, name, config, begin, run))
                    .await
                    .unwrap_or_else(|err| Seen::failed(&err))
            }
        })
        .collect();
    Ok(report(tasks, seconds)?)
}

/// Loss recovery counters from `quinn::ConnectionStats`. quinn does not count probe
/// timeouts: one shows as a ping frame, or as stream frames sent a second time.
type Quic = BTreeMap<&'static str, u64>;

fn quic_of(stats: &quinn::ConnectionStats) -> Quic {
    BTreeMap::from([
        ("sent_packets", stats.path.sent_packets),
        ("lost_packets", stats.path.lost_packets),
        ("lost_bytes", stats.path.lost_bytes),
        ("congestion_events", stats.path.congestion_events),
        ("ping_frames_tx", stats.frame_tx.ping),
        ("ping_frames_rx", stats.frame_rx.ping),
        ("stream_frames_tx", stats.frame_tx.stream),
        ("stream_frames_rx", stats.frame_rx.stream),
        ("ack_frames_tx", stats.frame_tx.acks),
        ("udp_datagrams_tx", stats.udp_tx.datagrams),
        ("udp_datagrams_rx", stats.udp_rx.datagrams),
    ])
}

fn quic_since(now: &Quic, before: &Quic) -> Quic {
    now.iter()
        .map(|(key, value)| {
            (
                *key,
                value.saturating_sub(before.get(key).copied().unwrap_or(0)),
            )
        })
        .collect()
}

fn quic_add(sum: &mut Quic, one: &Quic) {
    for (key, value) in one {
        *sum.entry(*key).or_default() += *value;
    }
}

/// One client connection of a counted run.
#[async_trait]
trait Client: Send {
    /// `GET /` and the 100 byte answer.
    async fn get(&mut self) -> Result<(), Failure>;
    /// The connection's QUIC counters, when it is QUIC.
    fn quic(&self) -> Option<Quic>;
    async fn close(self: Box<Self>);
}

struct H3Client {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: tokio::task::JoinHandle<()>,
    uri: String,
}

impl H3Client {
    async fn connect(
        addr: SocketAddr,
        name: &str,
        config: quinn::ClientConfig,
    ) -> Result<Box<dyn Client>, Failure> {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(config);
        let connection = endpoint.connect(addr, name)?.await?;
        let (mut driver, send) = Box::pin(h3::client::new(h3_quinn::Connection::new(
            connection.clone(),
        )))
        .await?;
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Box::new(Self {
            endpoint,
            connection,
            send,
            driver,
            uri: format!("https://{name}/"),
        }))
    }
}

#[async_trait]
impl Client for H3Client {
    async fn get(&mut self) -> Result<(), Failure> {
        let request = http::Request::get(&self.uri).body(())?;
        let mut stream = self.send.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        let mut body = 0;
        while let Some(chunk) = stream.recv_data().await? {
            body += chunk.remaining();
        }
        if response.status() == http::StatusCode::OK && body == PAYLOAD_LEN {
            Ok(())
        } else {
            Err(format!("status {} with {body} body bytes", response.status()).into())
        }
    }

    fn quic(&self) -> Option<Quic> {
        Some(quic_of(&self.connection.stats()))
    }

    async fn close(self: Box<Self>) {
        self.connection.close(quinn::VarInt::from_u32(0), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(5), self.endpoint.wait_idle()).await;
        self.driver.abort();
    }
}

struct TlsClient {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    request: Vec<u8>,
    reply: Vec<u8>,
}

impl TlsClient {
    async fn connect(
        addr: SocketAddr,
        name: &str,
        config: Arc<rustls::ClientConfig>,
    ) -> Result<Box<dyn Client>, Failure> {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(ServerName::try_from(name.to_owned())?, tcp)
            .await?;
        Ok(Box::new(Self {
            stream,
            request: format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n").into_bytes(),
            reply: Vec::with_capacity(4096),
        }))
    }
}

#[async_trait]
impl Client for TlsClient {
    async fn get(&mut self) -> Result<(), Failure> {
        self.stream.write_all(&self.request).await?;
        self.reply.clear();
        let mut chunk = [0_u8; 4096];
        let head_end = loop {
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err("connection closed before the response head ended".into());
            }
            self.reply.extend_from_slice(&chunk[..read]);
            if let Some(at) = self
                .reply
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                break at + 4;
            }
        };
        let length = {
            let head = std::str::from_utf8(&self.reply[..head_end])?;
            if !head.starts_with("HTTP/1.1 200 ") {
                return Err(format!("response head {:?}", head.lines().next()).into());
            }
            head.lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or("the response has no content-length")?
        };
        while self.reply.len() < head_end + length {
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err("connection closed inside the response body".into());
            }
            self.reply.extend_from_slice(&chunk[..read]);
        }
        if length == PAYLOAD_LEN && self.reply.len() == head_end + length {
            Ok(())
        } else {
            Err(format!(
                "{length} body bytes announced, {} read",
                self.reply.len() - head_end
            )
            .into())
        }
    }

    fn quic(&self) -> Option<Quic> {
        None
    }

    async fn close(self: Box<Self>) {
        let mut client = self;
        let _ = client.stream.shutdown().await;
    }
}

/// How the connections of a counted run are made.
#[derive(Clone)]
enum Mode {
    H3(Arc<quinn::ClientConfig>),
    Tls(Arc<rustls::ClientConfig>),
}

impl Mode {
    async fn connect(&self, addr: SocketAddr, name: &str) -> Result<Box<dyn Client>, Failure> {
        match self {
            Self::H3(config) => H3Client::connect(addr, name, config.as_ref().clone()).await,
            Self::Tls(config) => TlsClient::connect(addr, name, Arc::clone(config)).await,
        }
    }
}

/// The phases of a counted run, shared by its connections and the coordinator. Every connection
/// and the coordinator pass the same five barriers, whether or not the connection is alive:
/// connected, warmed up, released to count, counted, released to close.
struct Plan {
    barrier: tokio::sync::Barrier,
    warmup_each: u64,
    requests: u64,
    taken: AtomicU64,
    reply_timeout: Duration,
    sync: Option<PathBuf>,
}

impl Plan {
    /// Whether the caller may send one of the counted requests.
    fn take(&self) -> bool {
        self.taken.fetch_add(1, Ordering::Relaxed) < self.requests
    }

    /// Creates `<sync>/<name>` and waits for `<sync>/<answer>`. Without a sync directory it does
    /// nothing.
    async fn hand_over(&self, name: &str, answer: &str) {
        let Some(dir) = &self.sync else { return };
        if let Err(err) = std::fs::write(dir.join(name), b"") {
            eprintln!("cannot write {}: {err}", dir.join(name).display());
            std::process::exit(1);
        }
        while !dir.join(answer).exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// Runs the phases between the connections, and returns how long the counted requests took.
async fn coordinate(plan: Arc<Plan>) -> Duration {
    plan.barrier.wait().await;
    plan.barrier.wait().await;
    plan.hand_over("warm", "go").await;
    let started = Instant::now();
    plan.barrier.wait().await;
    plan.barrier.wait().await;
    let elapsed = started.elapsed();
    plan.hand_over("done", "release").await;
    plan.barrier.wait().await;
    elapsed
}

/// One request. A failure ends the connection's run: it is counted and the link is dropped.
async fn attempt(
    link: &mut Option<Box<dyn Client>>,
    seen: &mut Seen,
    record: bool,
    limit: Duration,
) -> bool {
    let Some(client) = link.as_mut() else {
        return false;
    };
    let started = Instant::now();
    match tokio::time::timeout(limit, client.get()).await {
        Ok(Ok(())) => {
            if record {
                seen.ok(started);
            }
            true
        }
        Ok(Err(err)) => {
            eprintln!("request failed: {err}");
            seen.errors += 1;
            *link = None;
            false
        }
        Err(_) => {
            eprintln!("no answer within {limit:?}");
            seen.errors += 1;
            *link = None;
            false
        }
    }
}

/// What one connection of a counted run saw, and its QUIC counters when it is QUIC.
struct Counted {
    seen: Seen,
    window: Option<Quic>,
    total: Option<Quic>,
}

async fn counted_connection(link: Result<Box<dyn Client>, Failure>, plan: Arc<Plan>) -> Counted {
    let mut seen = Seen::default();
    let mut link = match link {
        Ok(link) => Some(link),
        Err(err) => {
            seen = Seen::failed(&err);
            None
        }
    };
    plan.barrier.wait().await;
    for _ in 0..plan.warmup_each {
        if !attempt(&mut link, &mut seen, false, plan.reply_timeout).await {
            break;
        }
    }
    plan.barrier.wait().await;
    plan.barrier.wait().await;
    let before = link.as_ref().and_then(|link| link.quic());
    while link.is_some() && plan.take() {
        if !attempt(&mut link, &mut seen, true, plan.reply_timeout).await {
            break;
        }
    }
    plan.barrier.wait().await;
    let after = link.as_ref().and_then(|link| link.quic());
    plan.barrier.wait().await;
    if let Some(link) = link {
        link.close().await;
    }
    let (window, total) = match (before, after) {
        (Some(before), Some(after)) => (Some(quic_since(&after, &before)), Some(after)),
        _ => (None, None),
    };
    Counted {
        seen,
        window,
        total,
    }
}

/// A fixed number of requests over `connections` connections after a warm-up, see the module
/// documentation.
fn counted(
    addr: SocketAddr,
    quic: bool,
    name: &str,
    cert_pem: &str,
    connections: u64,
    warmup: u64,
    requests: u64,
) -> Result<(), Failure> {
    if connections == 0 {
        usage();
    }
    let mode = if quic {
        Mode::H3(Arc::new(client_config(cert_pem)?))
    } else {
        Mode::Tls(Arc::new(tls_config(cert_pem, b"http/1.1")?))
    };
    let millis = |var: &str, default: u64| {
        std::env::var(var)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let reply_timeout = Duration::from_millis(millis("LOAD_BENCH_REPLY_TIMEOUT_MS", 1000));
    let plan = Arc::new(Plan {
        barrier: tokio::sync::Barrier::new(usize::try_from(connections)? + 1),
        warmup_each: warmup.div_ceil(connections),
        requests,
        taken: AtomicU64::new(0),
        reply_timeout,
        sync: std::env::var_os("LOAD_BENCH_SYNC").map(PathBuf::from),
    });
    let name: Arc<str> = Arc::from(name);
    let (outcomes, elapsed) = runtime()?.block_on(async {
        let coordinator = tokio::spawn(coordinate(Arc::clone(&plan)));
        let handles: Vec<_> = (0..connections)
            .map(|_| {
                let (mode, name, plan) = (mode.clone(), Arc::clone(&name), Arc::clone(&plan));
                tokio::spawn(async move {
                    let made =
                        tokio::time::timeout(plan.reply_timeout * 30, mode.connect(addr, &name))
                            .await
                            .unwrap_or_else(|_| Err("the connection was not made in time".into()));
                    counted_connection(made, plan).await
                })
            })
            .collect();
        let mut outcomes = Vec::new();
        for handle in handles {
            outcomes.extend(handle.await);
        }
        (outcomes, coordinator.await.unwrap_or_default())
    });
    let (mut seen, mut window, mut total) = (Seen::default(), Quic::new(), Quic::new());
    let mut quic_connections = 0_u64;
    for one in outcomes {
        seen.micros.extend(one.seen.micros);
        seen.errors += one.seen.errors;
        if let (Some(one_window), Some(one_total)) = (&one.window, &one.total) {
            quic_add(&mut window, one_window);
            quic_add(&mut total, one_total);
            quic_connections += 1;
        }
    }
    let counted_requests = seen.micros.len();
    let mut report = summarize(seen, elapsed.as_secs_f64());
    if quic {
        report["quic"] = json!({
            "connections": quic_connections,
            "warmup_requests": plan.warmup_each * connections,
            "counted_requests": counted_requests,
            "window": window,
            "total": total,
        });
    }
    println!("{report}");
    Ok(())
}

fn main() -> Result<(), Failure> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let addr = |text: &String| text.parse::<SocketAddr>().unwrap_or_else(|_| usage());
    let number = |text: &String| text.parse::<u64>().unwrap_or_else(|_| usage());
    match args.as_slice() {
        [mode, target] if mode == "echo" => Ok(echo(addr(target))?),
        [mode, target] if mode == "stats" => Ok(stats(addr(target))?),
        [mode, target, connections, seconds] if mode == "udp" => {
            Ok(udp(addr(target), number(connections), number(seconds))?)
        }
        [mode, target, name, cert, connections, seconds] if mode == "h3" => h3(
            addr(target),
            name,
            cert,
            usize::try_from(number(connections))?,
            number(seconds),
        ),
        [mode, target, name, cert, connections, warmup, requests]
            if mode == "h3-count" || mode == "tls-count" =>
        {
            counted(
                addr(target),
                mode == "h3-count",
                name,
                cert,
                number(connections),
                number(warmup),
                number(requests),
            )
        }
        _ => usage(),
    }
}
