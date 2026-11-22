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
//!
//! The two generators print one JSON object in the shape of `oha --output-format json` (the fields
//! the script reads), so their runs go through the same bookkeeping as an HTTP one. A reply that
//! does not arrive within a second, or is not what the backend sends, counts as an error.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde_json::json;

const PAYLOAD_LEN: usize = 100;
const STATS: &[u8] = b"__stats";
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);

type Failure = Box<dyn std::error::Error + Send + Sync>;

fn usage() -> ! {
    eprintln!(
        "usage: load_bench echo <addr> | stats <addr> | udp <addr> <connections> <seconds> |\n       h3 <addr> <server name> <cert.pem> <connections> <seconds>"
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

fn client_config(cert_pem: &str) -> Result<quinn::ClientConfig, Failure> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(cert_pem)?)?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
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
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
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
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    f64::from(sorted[index]) / 1e6
}

/// Runs `tasks`, which each run for `seconds`, on a runtime with one worker per CPU and prints the
/// report.
fn report<F>(tasks: Vec<F>, seconds: u64) -> std::io::Result<()>
where
    F: Future<Output = Seen> + Send + 'static,
{
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
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
    let mut sorted = seen.micros;
    sorted.sort_unstable();
    let ok = sorted.len();
    #[allow(clippy::cast_precision_loss)]
    let rate = ok as f64 / seconds as f64;
    let report = json!({
        "summary": { "requestsPerSec": rate },
        "latencyPercentiles": {
            "p50": percentile(&sorted, 0.50),
            "p99": percentile(&sorted, 0.99),
            "p99.9": percentile(&sorted, 0.999),
        },
        "statusCodeDistribution": { "200": ok },
        "errorDistribution": if seen.errors == 0 { json!({}) } else { json!({ "no answer": seen.errors }) },
    });
    println!("{report}");
    Ok(())
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
                h3_connection(addr, name, config, begin, run)
                    .await
                    .unwrap_or_else(|err| Seen::failed(&err))
            }
        })
        .collect();
    Ok(report(tasks, seconds)?)
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
        _ => usage(),
    }
}
