//! A real `podgate` process for the end-to-end tests: the binary the workspace build produces,
//! its ports and admin socket chosen by the test, killed on drop.
//!
//! The binary is `PODGATE_BIN`, else `target/debug/podgate` of the workspace. A missing binary
//! fails the test (an ACME test that silently skipped would prove nothing): build the workspace
//! first (`cargo nextest run --workspace` does), or `cargo build -p podgate`. This never runs
//! cargo itself, because a test must not build under the shared build lock.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};

/// An upstream policy that allows loopback, the only place the test backends live.
pub const LOOPBACK_POLICY: &str =
    r#"{"deny": ["0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8"]}"#;

/// The daemon binary, or a panic that says how to get one.
pub fn binary() -> PathBuf {
    let path = std::env::var("PODGATE_BIN").map_or_else(
        |_| {
            let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
            let target = std::env::var("CARGO_TARGET_DIR")
                .map_or_else(|_| workspace.join("target"), PathBuf::from);
            target.join("debug/podgate")
        },
        PathBuf::from,
    );
    assert!(
        path.exists(),
        "the podgate binary is missing at {}: run `cargo build -p podgate` (or `cargo nextest run --workspace`, whose build produces it) or set PODGATE_BIN",
        path.display()
    );
    path
}

/// A `podgate` process.
pub struct Daemon {
    child: Child,
    binary: PathBuf,
    env: Vec<(String, String)>,
    pub dir: PathBuf,
    pub admin: PathBuf,
    pub proxy: SocketAddr,
    pub tls: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether process `pid` has a TCP socket listening on loopback `port`.
///
/// A copy of the TCP half of `listens` in the daemon's own `tests/common/mod.rs`: Pingora reports
/// ready (and `/readyz` answers 200) before its listeners are bound, so readiness alone does not
/// mean the proxy accepts connections. Matching on the pid keeps another process that holds the
/// port from counting.
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

async fn http(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    request: &str,
) -> (u16, String) {
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("answer in time")
        .ok();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

impl Daemon {
    /// Starts the daemon with the plain HTTP listener on `ports.0`, the TLS listener on
    /// `ports.1`, `policy` as its upstream policy file and `env` on top, and waits until its
    /// admin API serves and both listeners are bound. One attempt: the caller chose the ports
    /// (an ACME test points pebble at them), so the caller owns the race for them; a test that
    /// does not need fixed ports uses [`Self::start_free`].
    pub async fn start(policy: &Path, ports: (u16, u16), env: &[(&str, &str)]) -> Self {
        let mut daemon = Self::launch(policy, ports, env);
        assert!(daemon.wait_ready().await, "the daemon did not become ready");
        daemon
    }

    /// [`Self::start`] on ports it picks itself, with fresh ports on each of up to four
    /// attempts: a port probed free can be taken by a parallel test before podgate binds it.
    pub async fn start_free(policy: &Path, env: &[(&str, &str)]) -> Self {
        let mut failures = Vec::new();
        for attempt in 1..=4 {
            let ports = super::free_ports(2);
            let mut daemon = Self::launch(policy, (ports[0], ports[1]), env);
            if daemon.wait_ready().await {
                return daemon;
            }
            let exit = daemon.child.try_wait().ok().flatten();
            failures.push(format!(
                "attempt {attempt} on ports {}/{}: {}",
                ports[0],
                ports[1],
                exit.map_or_else(
                    || "not ready in time".to_owned(),
                    |status| format!("exited with {status}")
                )
            ));
        }
        panic!("the daemon did not become ready:\n{}", failures.join("\n"));
    }

    fn launch(policy: &Path, ports: (u16, u16), env: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pgp-daemon-{}-{}",
            std::process::id(),
            super::socket_path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("x")
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let admin = dir.join("admin.sock");
        let binary = binary();
        let mut env: Vec<(String, String)> = env
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        env.push(("UPSTREAM_POLICY_FILE".into(), policy.display().to_string()));
        let child = spawn(&binary, &admin, ports, &env);
        Self {
            child,
            binary,
            env,
            dir,
            admin,
            proxy: SocketAddr::from(([127, 0, 0, 1], ports.0)),
            tls: SocketAddr::from(([127, 0, 0, 1], ports.1)),
        }
    }

    /// Kills the process and starts a new one on the same ports and admin socket: a podgate
    /// restart, which forgets its snapshot and its event feed.
    pub async fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.admin);
        let ports = (self.proxy.port(), self.tls.port());
        self.child = spawn(&self.binary, &self.admin, ports, &self.env);
        assert!(
            self.wait_ready().await,
            "the restarted daemon did not become ready"
        );
    }

    async fn wait_ready(&mut self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return false;
            }
            if let Ok(mut stream) = UnixStream::connect(&self.admin).await {
                let (status, _) = http(
                    &mut stream,
                    "GET /readyz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
                )
                .await;
                // `/readyz` alone is not enough (see `listens`): wait for the listeners too.
                if status == 200
                    && listens(self.child.id(), self.proxy.port())
                    && listens(self.child.id(), self.tls.port())
                {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// `GET path` on the admin socket.
    pub async fn admin_get(&self, path: &str) -> (u16, Value) {
        let mut stream = UnixStream::connect(&self.admin)
            .await
            .expect("admin socket");
        let (status, body) = http(
            &mut stream,
            &format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n"),
        )
        .await;
        (status, serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    /// Every event the daemon's feed holds, oldest first.
    pub async fn events(&self) -> Vec<Value> {
        let (status, body) = self.admin_get("/v1/events?after=0").await;
        assert_eq!(status, 200, "{body}");
        body["events"].as_array().cloned().unwrap_or_default()
    }

    /// `GET /` with `Host: host` on the plain listener.
    pub async fn get(&self, host: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(self.proxy).await.expect("proxy");
        http(
            &mut stream,
            &format!("GET / HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n"),
        )
        .await
    }
}

fn spawn(binary: &Path, admin: &Path, ports: (u16, u16), env: &[(String, String)]) -> Child {
    let mut command = Command::new(binary);
    command
        .env("PROXY_ADDR", format!("127.0.0.1:{}", ports.0))
        .env("PROXY_TLS_ADDR", format!("127.0.0.1:{}", ports.1))
        .env("ADMIN_SOCKET", admin)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command.spawn().expect("spawn the daemon")
}

/// A backend answering every request with `body`, on a loopback port.
pub async fn backend(body: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("backend");
    let addr = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                let answer = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    (addr, task)
}
