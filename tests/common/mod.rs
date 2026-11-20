//! Shared harness for black-box tests: spawn the real `podgate` binary, push snapshots over its
//! admin socket, and talk to the proxy over HTTP and HTTPS.
//!
//! Every helper uses raw HTTP/1.1 with `Connection: close`, so a test reads exactly what the
//! server sent. Include it from a test file with `mod common;`.
//!
//! - [`Podgate::start`]: spawn the binary on free ports with a temp admin socket; killed on drop.
//! - [`Podgate::push_snapshot`], [`Podgate::get`], [`Podgate::https_get`]: drive it.
//! - [`Upstream::start`]: a backend that answers every request with a fixed body.
//! - [`snapshot`], [`TestCert`]: build snapshot JSON and self-signed certificates.

// Each test file compiles this module on its own and uses a different subset of it.
#![allow(dead_code, unreachable_pub, clippy::needless_pass_by_value)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

/// Longest any single exchange may take.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed HTTP/1.1 response.
#[derive(Debug)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header names (lowercase) and values.
    pub headers: Vec<(String, String)>,
    /// The body as text.
    pub body: String,
}

impl Response {
    /// Value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body parsed as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
    }
}

fn parse_response(raw: &[u8]) -> Response {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end in response: {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("bad status line: {status_line:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    assert!(
        !headers
            .iter()
            .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked")),
        "chunked responses are not supported by the test client: {text:?}"
    );
    Response {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// Writes `request`, reads until the server closes, and parses the response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &str) -> Response {
    timeout(IO_TIMEOUT, async {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        parse_response(&raw)
    })
    .await
    .expect("response in time")
}

fn get_request(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

/// `count` distinct free loopback ports.
///
/// All probes stay bound until every port is chosen: probing one at a time released each port
/// before the next probe, and the kernel can hand the same port out twice in a row.
pub fn free_ports(count: usize) -> Vec<u16> {
    let probes: Vec<std::net::TcpListener> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind free port"))
        .collect();
    probes
        .iter()
        .map(|probe| probe.local_addr().expect("local addr").port())
        .collect()
}

/// A loopback address that refuses connections, for a test that needs a dead upstream or collector.
///
/// The socket is bound but never listens, so a connect is refused and the kernel will not hand the
/// port to another test's `127.0.0.1:0` bind while the value lives. A listener that is bound,
/// read for its port and dropped frees the port, and under the parallel gate another test's
/// backend can get it and answer where the test expects a refusal. Keep the value until the end
/// of the test.
pub struct Refused {
    _socket: tokio::net::TcpSocket,
    pub addr: SocketAddr,
}

pub fn refused() -> Refused {
    let socket = tokio::net::TcpSocket::new_v4().expect("refused socket");
    socket
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("bind refused socket");
    let addr = socket.local_addr().expect("refused addr");
    Refused {
        _socket: socket,
        addr,
    }
}

fn free_port() -> u16 {
    free_ports(1)[0]
}

fn free_port_pair() -> (u16, u16) {
    let ports = free_ports(2);
    (ports[0], ports[1])
}

/// Starts of `podgate` tried before the harness gives up; see [`Podgate::wait_until_ready`].
const START_ATTEMPTS: u32 = 5;
/// Longest one start attempt waits for the process to listen.
const START_WAIT: Duration = Duration::from_secs(10);

/// The upstream address policy the harness gives every `podgate`: the built-in deny list minus
/// loopback (and the other ranges tests have no use for), so local upstreams work. A test that
/// needs another policy passes its own `UPSTREAM_POLICY_FILE` through `start_with_env`.
const LOOPBACK_POLICY: &str =
    r#"{"deny": ["0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8"]}"#;

/// Whether process `pid` has a TCP socket listening on loopback `port`.
fn listens(pid: u32, port: u16) -> bool {
    let wanted = format!(":{port:04X}");
    let inodes: Vec<String> = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|table| std::fs::read_to_string(table).ok())
        .flat_map(|table| {
            table
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let columns: Vec<&str> = line.split_whitespace().collect();
                    // Columns: sl, local_address, rem_address, st, ..., inode (index 9).
                    let local = columns.get(1)?;
                    let state = columns.get(3)?;
                    (*state == "0A" && local.ends_with(&wanted))
                        .then(|| format!("socket:[{}]", columns.get(9).copied().unwrap_or("")))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return false;
    };
    fds.filter_map(Result::ok)
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .any(|target| {
            inodes
                .iter()
                .any(|inode| target.to_string_lossy() == *inode)
        })
}

/// A running `podgate` process. Killed and cleaned up on drop.
pub struct Podgate {
    child: Child,
    dir: PathBuf,
    /// Address of the plain HTTP proxy listener.
    pub proxy_addr: SocketAddr,
    /// Address of the HTTPS proxy listener.
    pub tls_addr: SocketAddr,
    /// Every listener by entry point name.
    listeners: Vec<(String, SocketAddr)>,
    /// Path of the admin unix socket.
    pub admin_socket: PathBuf,
}

impl Podgate {
    /// Spawns the binary with free ports and a temporary admin socket, and returns once
    /// `/readyz` answers 200 and the proxy port accepts connections.
    pub async fn start() -> Self {
        Self::start_with_env(&[]).await
    }

    /// [`Self::start`] with extra environment variables, for settings the default does not
    /// cover.
    pub async fn start_with_env(extra_env: &[(&str, &str)]) -> Self {
        Self::start_on(extra_env, None).await
    }

    /// [`Self::start_with_env`], the first attempt on the given proxy port instead of a
    /// free one. For testing the harness itself: a port taken by someone else must not fool it.
    pub async fn start_on(extra_env: &[(&str, &str)], first_proxy_port: Option<u16>) -> Self {
        let mut failures = Vec::new();
        for attempt in 0..START_ATTEMPTS {
            let ports = first_proxy_port
                .filter(|_| attempt == 0)
                .map(|proxy| (proxy, free_port()))
                .unwrap_or_else(free_port_pair);
            match Self::try_start(extra_env, ports, &[], false).await {
                Ok(podgate) => return podgate,
                Err(reason) => failures.push(format!("attempt {}: {reason}", attempt + 1)),
            }
        }
        panic!("podgate did not start:\n{}", failures.join("\n"));
    }

    /// Spawns the binary with `ENTRY_POINTS` instead of `PROXY_ADDR` and `PROXY_TLS_ADDR`:
    /// each of `entries` is `(name, protocol)` on a free loopback port. [`Self::proxy_addr`] is
    /// the first `http` entry point and [`Self::tls_addr`] the first `https` one (the last
    /// entry when there is none), so [`Self::get`] and [`Self::https_get`] reach those; use
    /// [`Self::entry_addr`] and [`Self::get_on`] for the others.
    pub async fn start_with_entry_points(
        entries: &[(&str, &str)],
        extra_env: &[(&str, &str)],
    ) -> Self {
        let mut failures = Vec::new();
        for attempt in 0..START_ATTEMPTS {
            match Self::try_start(extra_env, (0, 0), entries, false).await {
                Ok(podgate) => return podgate,
                Err(reason) => failures.push(format!("attempt {}: {reason}", attempt + 1)),
            }
        }
        panic!("podgate did not start:\n{}", failures.join("\n"));
    }

    /// [`Self::start_with_env`] with the process's output kept in a file, which [`Self::log`]
    /// reads; pass `RUST_LOG` in `extra_env` to log more than warnings. For tests that assert
    /// on what podgate logs.
    pub async fn start_logged(extra_env: &[(&str, &str)]) -> Self {
        let mut failures = Vec::new();
        for attempt in 0..START_ATTEMPTS {
            let ports = free_port_pair();
            match Self::try_start(extra_env, ports, &[], true).await {
                Ok(podgate) => return podgate,
                Err(reason) => failures.push(format!("attempt {}: {reason}", attempt + 1)),
            }
        }
        panic!("podgate did not start:\n{}", failures.join("\n"));
    }

    /// Everything the process has written to stdout and stderr so far; empty unless it was
    /// started with [`Self::start_logged`].
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("podgate.log")).unwrap_or_default()
    }

    /// The address of the entry point called `name`.
    pub fn entry_addr(&self, name: &str) -> SocketAddr {
        self.listeners
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, addr)| *addr)
            .unwrap_or_else(|| panic!("no entry point called {name}"))
    }

    /// `GET path` on the entry point called `name` with `Host: host`.
    pub async fn get_on(&self, name: &str, host: &str, path: &str) -> Response {
        let mut stream = TcpStream::connect(self.entry_addr(name))
            .await
            .expect("connect to the entry point");
        exchange(&mut stream, &get_request(host, path)).await
    }

    pub async fn try_start(
        extra_env: &[(&str, &str)],
        ports: (u16, u16),
        entries: &[(&str, &str)],
        capture_log: bool,
    ) -> Result<Self, String> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let admin_socket = dir.join("admin.sock");
        // The tests' upstreams listen on loopback, which the built-in policy denies.
        let policy_file = dir.join("upstream-policy.json");
        std::fs::write(&policy_file, LOOPBACK_POLICY).expect("write the upstream policy file");
        let mut command = Command::new(env!("CARGO_BIN_EXE_podgate"));
        let listeners: Vec<(String, SocketAddr)> = if entries.is_empty() {
            let proxy_addr = SocketAddr::from(([127, 0, 0, 1], ports.0));
            let tls_addr = SocketAddr::from(([127, 0, 0, 1], ports.1));
            command
                .env("PROXY_ADDR", proxy_addr.to_string())
                .env("PROXY_TLS_ADDR", tls_addr.to_string());
            vec![("web".into(), proxy_addr), ("websecure".into(), tls_addr)]
        } else {
            let listeners: Vec<(String, SocketAddr)> = entries
                .iter()
                .zip(free_ports(entries.len()))
                .map(|((name, _), port)| {
                    ((*name).to_owned(), SocketAddr::from(([127, 0, 0, 1], port)))
                })
                .collect();
            let list: Vec<String> = entries
                .iter()
                .zip(&listeners)
                .map(|((_, protocol), (name, addr))| format!("{name}={addr}/{protocol}"))
                .collect();
            command.env("ENTRY_POINTS", list.join(","));
            listeners
        };
        // Two entry points on one port: the bind of one retries while the other holds it, and the
        // ownership check in [`Self::wait_until_ready`] passes for both, so a request lands on either.
        let mut taken = std::collections::HashSet::new();
        if let Some((name, addr)) = listeners
            .iter()
            .find(|(_, addr)| !taken.insert(addr.port()))
        {
            drop(std::fs::remove_dir_all(&dir));
            return Err(format!(
                "entry point {name} shares port {} with another",
                addr.port()
            ));
        }
        let first_of = |wanted: &str| {
            entries
                .iter()
                .zip(&listeners)
                .find(|((_, protocol), _)| *protocol == wanted)
                .map(|(_, (_, addr))| *addr)
        };
        let proxy_addr = first_of("http").unwrap_or(listeners[0].1);
        let tls_addr = first_of("https").unwrap_or(listeners[listeners.len() - 1].1);
        if capture_log {
            let log = std::fs::File::create(dir.join("podgate.log")).expect("create the log file");
            command
                .stdout(Stdio::from(log.try_clone().expect("clone the log file")))
                .stderr(Stdio::from(log));
        }
        let child = command
            .env("ADMIN_SOCKET", &admin_socket)
            .env("UPSTREAM_POLICY_FILE", &policy_file)
            .env("REQUEST_TIMEOUT_SECS", "5")
            .env("RUST_LOG", "warn")
            .envs(extra_env.iter().copied())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn podgate");
        let mut podgate = Self {
            child,
            dir,
            proxy_addr,
            tls_addr,
            admin_socket,
            listeners,
        };
        // On `Err`, dropping `podgate` kills the process and removes its directory.
        podgate.wait_until_ready().await?;
        Ok(podgate)
    }

    /// Ready when `/readyz` answers 200 and this process itself listens on both proxy ports.
    ///
    /// The ports come from [`free_port`], which releases them again; between that and the bind
    /// another process (a test running in parallel) can take one. Pingora then retries the bind
    /// for as long as the port is busy, and a plain connect succeeds against the squatter, so
    /// the test would talk to somebody else's proxy. Checking who owns the listener closes that.
    async fn wait_until_ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + START_WAIT;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("podgate exited with {status}"));
            }
            if let Ok(mut stream) = UnixStream::connect(&self.admin_socket).await {
                let ready = exchange(&mut stream, &get_request("x", "/readyz")).await;
                let pid = self.child.id();
                if ready.status == 200
                    && self
                        .listeners
                        .iter()
                        .all(|(_, addr)| listens(pid, addr.port()))
                {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        Err(format!(
            "not ready after {START_WAIT:?}: ports {:?} are not all listened on by pid {}",
            self.listeners
                .iter()
                .map(|(_, addr)| addr.port())
                .collect::<Vec<_>>(),
            self.child.id()
        ))
    }

    /// `GET path` on the admin socket.
    pub async fn admin_get(&self, path: &str) -> Response {
        let mut stream = UnixStream::connect(&self.admin_socket)
            .await
            .expect("connect to the admin socket");
        exchange(&mut stream, &get_request("x", path)).await
    }

    /// `PUT /v1/snapshot` with `body` as the raw request body.
    pub async fn push_snapshot_raw(&self, body: &str) -> Response {
        let mut stream = UnixStream::connect(&self.admin_socket)
            .await
            .expect("connect to the admin socket");
        let request = format!(
            "PUT /v1/snapshot HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        exchange(&mut stream, &request).await
    }

    /// `PUT /v1/snapshot` with a JSON snapshot.
    pub async fn push_snapshot(&self, snapshot: &Value) -> Response {
        self.push_snapshot_raw(&snapshot.to_string()).await
    }

    /// `POST path` on the admin socket with a JSON body.
    pub async fn admin_post(&self, path: &str, body: &Value) -> Response {
        let body = body.to_string();
        let mut stream = UnixStream::connect(&self.admin_socket)
            .await
            .expect("connect to the admin socket");
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        exchange(&mut stream, &request).await
    }

    /// `GET path` on the HTTP proxy listener with `Host: host`.
    pub async fn get(&self, host: &str, path: &str) -> Response {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .await
            .expect("connect to the proxy");
        exchange(&mut stream, &get_request(host, path)).await
    }

    /// `GET path` on the HTTP proxy listener with `Host: host` and extra request headers.
    pub async fn get_with_headers(
        &self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .await
            .expect("connect to the proxy");
        let extra: String = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
        exchange(&mut stream, &request).await
    }

    /// `method path` on the HTTP proxy listener with `Host: host` and extra request headers
    /// (repeat a name to send it twice).
    pub async fn request(
        &self,
        method: &str,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut stream = TcpStream::connect(self.proxy_addr)
            .await
            .expect("connect to the proxy");
        let extra: String = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect();
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
        exchange(&mut stream, &request).await
    }

    /// `GET path` on the HTTPS listener: TLS handshake with `sni` as server name (like
    /// `curl --resolve`), trusting only `trusted`, then `Host: host`.
    ///
    /// # Panics
    ///
    /// Panics when the handshake fails; use [`Self::https_handshake_fails`] to expect that.
    pub async fn https_get(
        &self,
        sni: &str,
        host: &str,
        path: &str,
        trusted: &TestCert,
    ) -> Response {
        let mut stream = self
            .tls_connect(sni, trusted)
            .await
            .unwrap_or_else(|err| panic!("TLS handshake for {sni} failed: {err}"));
        exchange(&mut stream, &get_request(host, path)).await
    }

    /// Whether a TLS handshake with `sni` is refused.
    pub async fn https_handshake_fails(&self, sni: &str, trusted: &TestCert) -> bool {
        self.tls_connect(sni, trusted).await.is_err()
    }

    async fn tls_connect(
        &self,
        sni: &str,
        trusted: &TestCert,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(trusted.der.clone())
            .expect("trust the test certificate");
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("server name");
        let tcp = TcpStream::connect(self.tls_addr).await?;
        timeout(
            IO_TIMEOUT,
            TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await
        .expect("handshake in time")
    }
}

impl Drop for Podgate {
    fn drop(&mut self) {
        // The process may already be gone; there is nothing to do about a failed kill.
        drop(self.child.kill());
        drop(self.child.wait());
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// A backend that answers every request with 200 and a fixed body.
pub struct Upstream {
    /// Where it listens.
    pub addr: SocketAddr,
}

impl Upstream {
    /// Starts serving on a free loopback port until the test's runtime ends.
    pub async fn start(body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = listener.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve_connection(stream, body));
            }
        });
        Self { addr }
    }
}

/// Answers each request on `stream` (keep-alive) until the peer closes. Requests carry no body.
async fn serve_connection(mut stream: TcpStream, body: &'static str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// A self-signed certificate for `names`.
pub struct TestCert {
    /// Certificate chain, PEM.
    pub cert_pem: String,
    /// Private key, PEM.
    pub key_pem: String,
    /// The certificate, DER, for a client trust store.
    pub der: rustls::pki_types::CertificateDer<'static>,
}

impl TestCert {
    /// Generates a certificate valid for `names`.
    pub fn new(names: &[&str]) -> Self {
        let certified = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("generate certificate");
        Self {
            cert_pem: certified.cert.pem(),
            key_pem: certified.signing_key.serialize_pem(),
            der: certified.cert.der().clone(),
        }
    }

    /// The snapshot entry serving this certificate for `hosts`.
    pub fn entry(&self, hosts: &[&str]) -> Value {
        json!({ "hosts": hosts, "cert_pem": self.cert_pem, "key_pem": self.key_pem })
    }
}

/// A serving revision with weight 100 on `addr`.
pub fn serving(id: &str, addr: SocketAddr) -> Value {
    revision(id, addr, 100, "serving")
}

/// A `loadbalancer` service called `name` over the plain HTTP servers `addrs`.
pub fn service(name: &str, addrs: &[SocketAddr]) -> Value {
    let servers: Vec<Value> = addrs
        .iter()
        .map(|addr| json!({ "url": format!("http://{addr}") }))
        .collect();
    json!({ "name": name, "type": "loadbalancer", "servers": servers })
}

/// A revision in any state, whose service `web` (the one [`app`]'s router uses) has one server
/// on `addr`.
pub fn revision(id: &str, addr: SocketAddr, weight: u16, state: &str) -> Value {
    json!({ "id": id, "state": state, "weight": weight, "services": [service("web", &[addr])] })
}

/// Like [`revision`], with any number of servers (none: the revision has a backend of nobody,
/// which is how an app sleeps).
pub fn revision_on(id: &str, addrs: &[SocketAddr], weight: u16, state: &str) -> Value {
    json!({ "id": id, "state": state, "weight": weight, "services": [service("web", addrs)] })
}

/// A router called `name` with the matcher `matcher`, answered by service `service`.
pub fn router(name: &str, matcher: Value, service: &str) -> Value {
    json!({ "name": name, "match": matcher, "service": service })
}

/// A middleware of type `kind`: `config` holds its own fields next to the name and type.
pub fn middleware(name: &str, kind: &str, config: Value) -> Value {
    let mut declared = json!({ "name": name, "type": kind });
    if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
        object.extend(extra.clone());
    }
    declared
}

/// One app named `id` of tenant `t1`, answering for `hosts` through one router, `default`,
/// that sends everything to service `web`. Add `routers`, `middlewares` or `default_chain` on
/// the returned value to change that.
pub fn app(id: &str, hosts: &[&str], revisions: &[Value]) -> Value {
    json!({
        "id": id,
        "tenant": "t1",
        "declared_by": format!("tests/{id}"),
        "tls": { "mode": "acme" },
        "routers": [router("default", json!({ "host": hosts }), "web")],
        "revisions": revisions,
    })
}

/// `app` with `middlewares` declared and all of them in the app's `default_chain`, in order.
pub fn with_chain(mut app: Value, middlewares: &[Value]) -> Value {
    let names: Vec<Value> = middlewares
        .iter()
        .map(|declared| declared["name"].clone())
        .collect();
    app["middlewares"] = Value::Array(middlewares.to_vec());
    app["default_chain"] = Value::Array(names);
    app
}

/// `app` with WASM filters: each of `filters` (`{wasm_base64, fuel, max_memory_bytes}`) becomes a
/// `wasm` middleware, and all of them go in the app's `default_chain`, in order.
pub fn with_filters(mut app: Value, filters: &[Value]) -> Value {
    let named: Vec<(String, &Value)> = filters
        .iter()
        .enumerate()
        .map(|(index, filter)| (format!("filter{index}"), filter))
        .collect();
    app["middlewares"] = Value::Array(
        named
            .iter()
            .map(|(name, filter)| middleware(name, "wasm", (*filter).clone()))
            .collect(),
    );
    app["default_chain"] = json!(
        named
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
    );
    app
}

/// `app` with one more middleware `name` of type `kind` (`config`: its own fields), appended to
/// the app's `default_chain`.
pub fn with_middleware(mut app: Value, name: &str, kind: &str, config: Value) -> Value {
    if let Some(list) = app["middlewares"].as_array_mut() {
        list.push(middleware(name, kind, config));
    } else {
        app["middlewares"] = json!([middleware(name, kind, config)]);
    }
    if let Some(chain) = app["default_chain"].as_array_mut() {
        chain.push(json!(name));
    } else {
        app["default_chain"] = json!([name]);
    }
    app
}

/// `app` with one `buffering` middleware, `config` holding its fields, in the app's
/// `default_chain`.
pub fn with_buffering(mut app: Value, config: Value) -> Value {
    app["middlewares"] = json!([middleware("buffer", "buffering", config)]);
    app["default_chain"] = json!(["buffer"]);
    app
}

/// A snapshot with tenant `t1`, the given apps and no certificates.
pub fn snapshot(version: u64, apps: &[Value]) -> Value {
    json!({
        "version": version,
        "tenants": [{ "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } }],
        "apps": apps,
    })
}

/// The simplest snapshot: one app per `(host, upstream)`, each with one serving revision.
pub fn simple_snapshot(version: u64, routes: &[(&str, SocketAddr)]) -> Value {
    let apps: Vec<Value> = routes
        .iter()
        .map(|(host, addr)| app(host, &[host], &[serving("r1", *addr)]))
        .collect();
    snapshot(version, &apps)
}

/// A certificate authority that signs client certificates, for specs that need mutual TLS.
pub struct TestCa {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    /// The CA certificate, PEM: the value of `tls.client_ca_pem`.
    pub pem: String,
}

/// A client certificate chain and its key.
pub struct TestClient {
    /// Certificate chain, leaf first.
    pub chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// The leaf's private key.
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

impl TestCa {
    /// Generates a CA whose common name is `name`.
    pub fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    /// A client certificate with common name `common_name`, signed by this CA.
    pub fn client(&self, common_name: &str) -> TestClient {
        self.client_with(|params| {
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, common_name);
        })
    }

    /// A client certificate signed by this CA whose parameters (names, alternative names,
    /// serial, validity) `edit` fills in.
    pub fn client_with(&self, edit: impl FnOnce(&mut rcgen::CertificateParams)) -> TestClient {
        let key = rcgen::KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        edit(&mut params);
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("sign client certificate");
        TestClient {
            chain: vec![cert.der().clone()],
            key: rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }
}

impl Podgate {
    /// `GET path` on the HTTPS listener with a caller-built client `config`: TLS handshake with
    /// `sni` as server name, then `Host: host`. Unlike [`Self::https_get`] it returns the I/O
    /// error of a refused handshake, or of a connection the server closed without answering.
    pub async fn try_https_get(
        &self,
        config: Arc<rustls::ClientConfig>,
        sni: &str,
        host: &str,
        path: &str,
    ) -> std::io::Result<Response> {
        self.try_https_get_with_headers(config, sni, host, path, &[])
            .await
    }

    /// [`Self::try_https_get`] with extra request headers (repeat a name to send it twice).
    pub async fn try_https_get_with_headers(
        &self,
        config: Arc<rustls::ClientConfig>,
        sni: &str,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> std::io::Result<Response> {
        let name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("server name");
        let extra: String = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n");
        timeout(IO_TIMEOUT, async {
            let tcp = TcpStream::connect(self.tls_addr).await?;
            let mut stream = TlsConnector::from(config).connect(name, tcp).await?;
            stream.write_all(request.as_bytes()).await?;
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await?;
            if raw.is_empty() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            Ok(parse_response(&raw))
        })
        .await
        .expect("response in time")
    }
}
