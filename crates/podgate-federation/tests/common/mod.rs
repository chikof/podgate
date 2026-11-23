//! Shared harness: a private CA, a mutual TLS fake peer with scripted answers, a fake read
//! socket for the exporter, and a client for the listeners under test.
//!
//! Every wait has a deadline, so a broken test fails instead of hanging.

#![allow(dead_code, unreachable_pub)]

pub mod peer;
pub mod pki;
pub mod read_socket;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use podgate_federation::tls::{Identity, roots};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[allow(unused_imports)]
pub use self::peer::{Answer, FakePeer, Script, Seen, catalog_script};
pub use self::pki::Pki;

/// The longest a test waits for anything.
pub const DEADLINE: Duration = Duration::from_secs(20);

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh directory under the temp dir, removed on drop.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "pgf-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create test dir");
        Self(path)
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One catalog entry as the daemon and the exporter write it.
pub fn item(tenant: &str, id: &str, version: &str, lifecycle: &str) -> Value {
    json!({
        "tenant": tenant, "app": "app", "declared_by": "podkit", "id": id, "version": version,
        "title": format!("{id} api"), "lifecycle": lifecycle, "routers": ["r"],
        "hosts": [format!("{id}.{tenant}.test")], "published": true
    })
}

/// Polls `check` until it holds or the deadline passes.
pub async fn eventually<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < DEADLINE {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

/// One answer of a listener under test.
#[derive(Debug)]
pub struct Got {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Got {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| {
            panic!("not JSON ({err}): {}", String::from_utf8_lossy(&self.body))
        })
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }
}

/// A client that presents the certificate in `dir/<name>.pem` and trusts `pki`'s CA.
pub fn client_config(pki: &Pki, dir: &Dir, name: &str) -> std::sync::Arc<rustls::ClientConfig> {
    let (cert, key) = pki.client_files(&dir.0, name);
    let ca = pki.ca_file(&dir.0, &format!("{name}-ca"));
    Identity::load("test", &cert, &key)
        .expect("identity")
        .client_config("test", roots("test", &ca).expect("roots"))
        .expect("client config")
}

/// Sends one request with `method` over mutual TLS to `addr` and reads the answer to the end.
pub async fn request(
    addr: SocketAddr,
    tls: std::sync::Arc<rustls::ClientConfig>,
    method: &str,
    target: &str,
    extra: &str,
) -> std::io::Result<Got> {
    let stream = TcpStream::connect(addr).await?;
    let name = rustls_pki_types::ServerName::try_from("127.0.0.1").expect("name");
    let mut tls = TlsConnector::from(tls).connect(name, stream).await?;
    let text = format!("{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}\r\n");
    tls.write_all(text.as_bytes()).await?;
    let mut raw = Vec::new();
    // A server that closes without close_notify ends the read with an error after the answer.
    let _ = tokio::time::timeout(DEADLINE, tls.read_to_end(&mut raw)).await;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no answer"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::other("no status"))?;
    Ok(Got {
        status,
        head,
        body: raw[split + 4..].to_vec(),
    })
}

pub async fn get(
    addr: SocketAddr,
    tls: &std::sync::Arc<rustls::ClientConfig>,
    target: &str,
) -> Got {
    request(addr, tls.clone(), "GET", target, "")
        .await
        .unwrap_or_else(|err| panic!("GET {target}: {err}"))
}

/// A client that presents no certificate.
pub fn anonymous_client(pki: &Pki, dir: &Dir) -> std::sync::Arc<rustls::ClientConfig> {
    let ca = pki.ca_file(&dir.0, "anon-ca");
    let roots = roots("anon", &ca).expect("roots");
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}
