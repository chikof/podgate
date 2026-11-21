//! A real `valkey-server` for the cluster rate limit tests, and a store file that names it.
//! A missing `valkey-server` or `valkey-cli` fails the test (both are on PATH in `devenv shell`);
//! nothing is skipped.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::time::sleep;

/// Times to start the server before giving up: its port comes from `free_ports`.
const START_ATTEMPTS: u32 = 5;
/// Longest one start waits for the port to open and the server to answer `PING`.
const START_WAIT: Duration = Duration::from_secs(10);

/// A CA and the server certificate it signed for 127.0.0.1, as PEM files.
#[derive(Clone)]
pub struct TlsFiles {
    /// The CA certificate: what a client trusts.
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl TlsFiles {
    /// Writes a fresh CA called `name` and a server certificate into `dir`.
    pub fn new(dir: &Path, name: &str) -> Self {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, name);
        let ca_key = KeyPair::generate().expect("ca key");
        let ca = ca_params.self_signed(&ca_key).expect("ca cert");
        let mut server_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        server_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let server_key = KeyPair::generate().expect("server key");
        let issuer = Issuer::new(ca_params, ca_key);
        let server = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let write = |file: &str, content: String| {
            let path = dir.join(format!("{name}-{file}"));
            std::fs::write(&path, content).expect("write a tls file");
            path
        };
        Self {
            ca: write("ca.pem", ca.pem()),
            cert: write("server.pem", server.pem()),
            key: write("server.key", server_key.serialize_pem()),
        }
    }
}

/// A `valkey-server` on a loopback port. Killed on drop.
pub struct Valkey {
    child: Option<Child>,
    pub port: u16,
    dir: PathBuf,
    password: Option<String>,
    tls: Option<TlsFiles>,
}

impl Valkey {
    /// Starts a server with no password.
    pub async fn start() -> Self {
        Self::start_with(None, None).await
    }

    /// Starts a server that requires `password` (`requirepass`) and speaks TLS with `tls` instead
    /// of plain text, when given.
    pub async fn start_with(password: Option<&str>, tls: Option<TlsFiles>) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-valkey-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create the valkey directory");
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            let port = super::free_ports(1)[0];
            let mut this = Self {
                child: None,
                port,
                dir: dir.clone(),
                password: password.map(str::to_owned),
                tls: tls.clone(),
            };
            match this.spawn().await {
                Ok(()) => return this,
                Err(reason) => failures.push(format!("attempt {attempt}: {reason}")),
            }
        }
        panic!("valkey-server did not start:\n{}", failures.join("\n"));
    }

    async fn spawn(&mut self) -> Result<(), String> {
        // A failed earlier attempt was dropped, and its Drop removed the shared directory.
        std::fs::create_dir_all(&self.dir)
            .map_err(|err| format!("create {:?}: {err}", self.dir))?;
        let log = |name: &str| {
            Stdio::from(std::fs::File::create(self.dir.join(name)).expect("create a log file"))
        };
        let mut command = Command::new("valkey-server");
        match &self.tls {
            None => command.args(["--port", &self.port.to_string()]),
            Some(tls) => command
                .args(["--port", "0", "--tls-port", &self.port.to_string()])
                .args(["--tls-auth-clients", "no", "--tls-cert-file"])
                .arg(&tls.cert)
                .arg("--tls-key-file")
                .arg(&tls.key)
                .arg("--tls-ca-cert-file")
                .arg(&tls.ca),
        };
        command
            .args([
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
            ])
            .arg(&self.dir)
            .stdout(log("valkey.log"))
            .stderr(log("valkey.err"))
            .stdin(Stdio::null());
        if let Some(password) = &self.password {
            command.args(["--requirepass", password]);
        }
        let child = command
            .spawn()
            .expect("spawn valkey-server: it must be on PATH (devenv shell)");
        self.child = Some(child);
        let deadline = Instant::now() + START_WAIT;
        while Instant::now() < deadline {
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                self.child = None;
                return Err(format!(
                    "valkey-server exited with {status}: {}{}",
                    std::fs::read_to_string(self.dir.join("valkey.log")).unwrap_or_default(),
                    std::fs::read_to_string(self.dir.join("valkey.err")).unwrap_or_default(),
                ));
            }
            if TcpStream::connect(self.addr()).await.is_ok() && self.cli(&["PING"]) == "PONG" {
                return Ok(());
            }
            sleep(Duration::from_millis(20)).await;
        }
        self.stop();
        Err(format!("no answer after {START_WAIT:?}"))
    }

    /// The address the server listens on.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// `redis://127.0.0.1:<port>`, or `rediss://` for a TLS server.
    pub fn url(&self) -> String {
        let scheme = if self.tls.is_some() {
            "rediss"
        } else {
            "redis"
        };
        format!("{scheme}://{}", self.addr())
    }

    /// Kills the server: its port refuses connections until [`Self::restart`].
    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            drop(child.kill());
            drop(child.wait());
        }
    }

    /// Starts the server again on the same port, with an empty database.
    pub async fn restart(&mut self) {
        self.stop();
        let mut failures = Vec::new();
        for attempt in 1..=START_ATTEMPTS {
            match self.spawn().await {
                Ok(()) => return,
                Err(reason) => failures.push(format!("attempt {attempt}: {reason}")),
            }
        }
        panic!("valkey-server did not restart:\n{}", failures.join("\n"));
    }

    /// Runs one command through `valkey-cli --raw` and returns what it printed, trimmed.
    pub fn cli(&self, args: &[&str]) -> String {
        let mut command = Command::new("valkey-cli");
        command
            .args(["-h", "127.0.0.1", "-p", &self.port.to_string(), "--raw"])
            .args(["--no-auth-warning"]);
        if let Some(tls) = &self.tls {
            command.arg("--tls").arg("--cacert").arg(&tls.ca);
        }
        if let Some(password) = &self.password {
            command.args(["-a", password]);
        }
        let output = command
            .args(args)
            .output()
            .expect("run valkey-cli: it must be on PATH (devenv shell)");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// Every key that matches `pattern`.
    pub fn keys(&self, pattern: &str) -> Vec<String> {
        self.cli(&["KEYS", pattern])
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Valkey {
    fn drop(&mut self) {
        self.stop();
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// Writes `RATE_LIMIT_STORES_FILE` content into `dir` and returns its path. `stores` is the
/// JSON object of store entries.
pub fn stores_file(dir: &Path, stores: &Value) -> PathBuf {
    std::fs::create_dir_all(dir).expect("create the stores directory");
    let path = dir.join("stores.json");
    std::fs::write(&path, stores.to_string()).expect("write the stores file");
    path
}

/// A store entry for tenant `t1` (the harness's tenant) on `addr`.
pub fn entry(addr: SocketAddr) -> Value {
    json!({"url": format!("redis://{addr}"), "tenants": ["t1"], "timeout_ms": 100})
}

/// A fresh scratch directory for one test's files.
pub fn scratch(what: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "podgate-{what}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create a scratch directory");
    dir
}
