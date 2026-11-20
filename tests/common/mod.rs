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
#![allow(dead_code, unreachable_pub)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind a free port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A running `podgate` process. Killed and cleaned up on drop.
pub struct Podgate {
    child: Child,
    dir: PathBuf,
    /// Address of the plain HTTP proxy listener.
    pub proxy_addr: SocketAddr,
    /// Address of the HTTPS proxy listener.
    pub tls_addr: SocketAddr,
    /// Path of the admin unix socket.
    pub admin_socket: PathBuf,
}

impl Podgate {
    /// Spawns the binary with free ports and a temporary admin socket, and returns once
    /// `/readyz` answers 200 and the proxy port accepts connections.
    pub async fn start() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let proxy_addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let tls_addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
        let admin_socket = dir.join("admin.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_podgate"))
            .env("PROXY_ADDR", proxy_addr.to_string())
            .env("PROXY_TLS_ADDR", tls_addr.to_string())
            .env("ADMIN_SOCKET", &admin_socket)
            .env("REQUEST_TIMEOUT_SECS", "5")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn podgate");
        let podgate = Self {
            child,
            dir,
            proxy_addr,
            tls_addr,
            admin_socket,
        };
        podgate.wait_until_ready().await;
        podgate
    }

    async fn wait_until_ready(&self) {
        for _ in 0..200 {
            if let Ok(mut stream) = UnixStream::connect(&self.admin_socket).await {
                let ready = exchange(&mut stream, &get_request("x", "/readyz")).await;
                if ready.status == 200 && TcpStream::connect(self.proxy_addr).await.is_ok() {
                    return;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("podgate did not become ready");
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

/// A revision in any state.
pub fn revision(id: &str, addr: SocketAddr, weight: u16, state: &str) -> Value {
    json!({ "id": id, "upstreams": [addr.to_string()], "weight": weight, "state": state })
}

/// One app named `id` of tenant `t1`, answering for `hosts`.
pub fn app(id: &str, hosts: &[&str], revisions: &[Value]) -> Value {
    json!({
        "id": id,
        "tenant": "t1",
        "declared_by": format!("tests/{id}"),
        "hosts": hosts,
        "tls": { "mode": "acme" },
        "revisions": revisions,
    })
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
