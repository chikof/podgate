//! `pebble` and `pebble-challtestsrv` for the ACME tests: a copy of `tests/common/pebble.rs` of
//! the `podgate` crate, which the provider does not depend on. A private CA for pebble's own
//! HTTPS listener, the processes with their ports, and what a test needs to talk to them. A
//! missing `pebble` fails the test (it is on PATH in `devenv shell`); nothing is skipped.
//!
//! pebble resolves every name through challtestsrv, which answers 127.0.0.1, so HTTP-01 and
//! TLS-ALPN-01 are validated for real against the node the test names in [`Validation`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Times to start `pebble` before giving up: its ports come from `free_ports`.
const START_ATTEMPTS: u32 = 5;
/// Longest one start attempt waits for pebble's ports to open.
const START_WAIT: Duration = Duration::from_secs(30);

/// Where pebble validates challenges. A `None` port is a free one nobody listens on.
#[derive(Clone, Copy, Default)]
pub struct Validation {
    /// The port of the plain HTTP listener that answers HTTP-01.
    pub http: Option<u16>,
    /// The port of the TLS listener that answers TLS-ALPN-01.
    pub tls: Option<u16>,
}

/// A private CA that signs the certificate of pebble's own HTTPS listener.
#[derive(Clone)]
pub struct Pki {
    pub dir: PathBuf,
    /// The CA certificate, PEM: the value of `ACME_CA_FILE`.
    pub ca_pem: PathBuf,
    ca_der: CertificateDer<'static>,
    server_pem: PathBuf,
    server_key: PathBuf,
}

impl Pki {
    /// Writes a fresh CA and pebble server certificate into `dir`.
    pub fn new(dir: &Path) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "podgate test acme server ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca cert");
        let mut server_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().expect("dns name")),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let server_key = KeyPair::generate().expect("server key");
        let issuer = Issuer::new(ca_params, ca_key);
        let server = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let write = |name: &str, content: String| {
            let path = dir.join(name);
            std::fs::write(&path, content).expect("write pki file");
            path
        };
        Self {
            dir: dir.to_owned(),
            ca_pem: write("acme-ca.pem", ca.pem()),
            ca_der: ca.der().clone(),
            server_pem: write("pebble.pem", server.pem()),
            server_key: write("pebble.key", server_key.serialize_pem()),
        }
    }

    /// The text of `name` in the directory, empty when it does not exist.
    pub fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.join(name)).unwrap_or_default()
    }
}

/// `pebble` and `pebble-challtestsrv`, killed on drop. `pebble-challtestsrv` is pebble's DNS:
/// it answers every name with 127.0.0.1, so HTTP-01 is validated for real against podgate.
pub struct Pebble {
    children: Vec<Child>,
    /// The ACME directory URL.
    pub directory: String,
    pub management: SocketAddr,
    /// challtestsrv's management API.
    pub challtest: SocketAddr,
    pub pki: Pki,
}

impl Pebble {
    /// Starts both, with pebble's HTTP-01 validation pointed at `ports.http` and its
    /// TLS-ALPN-01 validation at `ports.tls` on 127.0.0.1 (a free port when `None`).
    ///
    /// The other ports come from [`super::free_ports`], which another process can take between
    /// the probe and the bind (and `cargo test` runs tests as threads of one process), so a
    /// process that exits at start is retried with fresh ports.
    pub async fn start(pki: Pki, ports: Validation) -> Self {
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match Self::try_start(pki.clone(), ports).await {
                Ok(started) => return started,
                Err(reason) => failures.push(format!("attempt {attempt}: {reason}")),
            }
        }
        panic!("pebble did not start:\n{}", failures.join("\n"));
    }

    async fn try_start(pki: Pki, validation: Validation) -> Result<Self, String> {
        let ports = super::free_ports(5);
        let (acme, management, spare) = (ports[0], ports[1], ports[2]);
        let (dns, challtest_management) = (ports[3], ports[4]);
        let config = json!({"pebble": {
            "listenAddress": format!("127.0.0.1:{acme}"),
            "managementListenAddress": format!("127.0.0.1:{management}"),
            "certificate": pki.server_pem,
            "privateKey": pki.server_key,
            "httpPort": validation.http.unwrap_or(spare),
            "tlsPort": validation.tls.unwrap_or(spare),
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
            "retryAfter": {"authz": 1, "order": 1},
            "profiles": {"default": {"description": "test", "validityPeriod": 7_776_000}},
        }});
        let config_path = pki.dir.join("pebble-config.json");
        std::fs::write(&config_path, config.to_string()).expect("write pebble config");
        let log = |name: &str| {
            Stdio::from(std::fs::File::create(pki.dir.join(name)).expect("create log file"))
        };
        let challtestsrv = Command::new("pebble-challtestsrv")
            .args([
                "-dnsserver",
                &format!("127.0.0.1:{dns}"),
                "-management",
                &format!("127.0.0.1:{challtest_management}"),
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
                "-defaultIPv4",
                "127.0.0.1",
                "-defaultIPv6",
                "",
            ])
            .stdout(log("challtestsrv.log"))
            .stderr(log("challtestsrv.err"))
            .spawn()
            .expect("spawn pebble-challtestsrv: it must be on PATH (devenv shell)");
        let pebble = Command::new("pebble")
            .arg("-config")
            .arg(&config_path)
            .args(["-dnsserver", &format!("127.0.0.1:{dns}")])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_AUTHZREUSE", "0")
            // pebble answers badNonce to 5% of requests by default; instant-acme retries a
            // POST only twice, so about 1 in 1000 POSTs would fail an order for nothing.
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .stdout(log("pebble.log"))
            .stderr(log("pebble.err"))
            .spawn()
            .expect("spawn pebble: it must be on PATH (devenv shell)");
        let mut this = Self {
            children: vec![challtestsrv, pebble],
            directory: format!("https://127.0.0.1:{acme}/dir"),
            management: SocketAddr::from(([127, 0, 0, 1], management)),
            challtest: SocketAddr::from(([127, 0, 0, 1], challtest_management)),
            pki,
        };
        // On `Err`, dropping `this` kills what is left.
        this.wait_until_listening(acme).await?;
        Ok(this)
    }

    async fn wait_until_listening(&mut self, acme_port: u16) -> Result<(), String> {
        let deadline = Instant::now() + START_WAIT;
        while Instant::now() < deadline {
            for (child, name) in self.children.iter_mut().zip(["challtestsrv", "pebble"]) {
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "{name} exited with {status}\n--- {name}.log\n{}\n--- {name}.err\n{}",
                        self.pki.read(&format!("{name}.log")),
                        self.pki.read(&format!("{name}.err")),
                    ));
                }
            }
            let up = TcpStream::connect(("127.0.0.1", acme_port)).await.is_ok()
                && TcpStream::connect(self.management).await.is_ok()
                && TcpStream::connect(self.challtest).await.is_ok();
            if up {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "no listener after {START_WAIT:?}\n--- pebble.log\n{}\n--- pebble.err\n{}",
            self.pki.read("pebble.log"),
            self.pki.read("pebble.err"),
        ))
    }

    /// pebble's root certificate, for a client that must trust what pebble issues.
    pub async fn root(&self) -> CertificateDer<'static> {
        let pem = self.management_get("/roots/0").await;
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .expect("pebble serves a root")
            .expect("root is PEM")
    }

    /// `GET path` over TLS to pebble's management port, trusting only the test CA.
    pub async fn management_get(&self, path: &str) -> String {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.pki.ca_der.clone())
            .expect("trust the test ca");
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = rustls::pki_types::ServerName::IpAddress(self.management.ip().into());
        let tcp = TcpStream::connect(self.management).await.expect("connect");
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .expect("handshake with pebble");
        tls.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("send");
        let mut raw = Vec::new();
        // pebble closes without a TLS close_notify; what was read is the whole answer.
        drop(tls.read_to_end(&mut raw).await);
        let text = String::from_utf8_lossy(&raw).into_owned();
        text.split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or(text)
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for child in &mut self.children {
            drop(child.kill());
            drop(child.wait());
        }
    }
}
