//! End to end: the daemon's opt-in read-only socket (`ADMIN_READ_SOCKET`). It serves the overview
//! summary and nothing else, refuses every write, and answers as the admin socket does.

mod common;

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::Podgate;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const SUMMARY: &str = "/v1/overview?section=summary";

/// One answer on a unix socket.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

async fn call(socket: &Path, method: &str, target: &str, body: &str) -> Reply {
    let mut stream = UnixStream::connect(socket).await.expect("connect");
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), async {
        stream.write_all(request.as_bytes()).await.expect("send");
        stream.read_to_end(&mut raw).await.expect("read");
    })
    .await
    .expect("an answer in time");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a response head");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// A socket path in the temp dir that is removed when the test ends.
struct TempSocket(PathBuf);

impl std::ops::Deref for TempSocket {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempSocket {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

async fn start_with_read_socket(extra: &[(&str, &str)]) -> (Podgate, TempSocket) {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let socket = TempSocket(std::env::temp_dir().join(format!(
        "podgate-read-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )));
    let mut env: Vec<(&str, &str)> = vec![("ADMIN_READ_SOCKET", socket.to_str().expect("utf8"))];
    env.extend_from_slice(extra);
    let podgate = Podgate::start_with_env(&env).await;
    (podgate, socket)
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("socket exists")
        .permissions()
        .mode()
        & 0o777
}

/// Paths are not shown for a socket renamed after binding, so the count of listening unix sockets
/// this process holds is what the test compares.
fn listening_unix_sockets(pid: u32) -> usize {
    let held: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read fds")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            target
                .to_string_lossy()
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_owned)
        })
        .collect();
    std::fs::read_to_string("/proc/net/unix")
        .expect("read unix table")
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let flags = u32::from_str_radix(fields.get(3)?, 16).ok()?;
            (flags & 0x1_0000 != 0
                && held
                    .iter()
                    .any(|inode| Some(&inode.as_str()) == fields.get(6)))
            .then_some(())
        })
        .count()
}

#[tokio::test]
async fn admin_read_socket_off_by_default() {
    let podgate = Podgate::start().await;
    let dir = podgate.admin_socket.parent().expect("directory");
    let sockets: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read the directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_socket()))
        .map(|entry| entry.path())
        .collect();
    assert_eq!(sockets, vec![podgate.admin_socket.clone()]);
    assert_eq!(listening_unix_sockets(podgate.pid()), 1);
}

#[tokio::test]
async fn admin_read_socket_serves_only_two_gets() {
    let (podgate, socket) = start_with_read_socket(&[]).await;
    assert_eq!(listening_unix_sockets(podgate.pid()), 2);
    let summary = call(&socket, "GET", SUMMARY, "").await;
    assert_eq!(summary.status, 200, "{}", summary.body);
    for target in [
        "/v1/overview",
        "/v1/overview?section=apps",
        "/v1/overview?section=summary,apps",
        "/v1/overview?section=",
        "/v1/overview?limit=5",
    ] {
        let reply = call(&socket, "GET", target, "").await;
        assert_eq!(reply.status, 400, "{target}");
        assert_eq!(
            serde_json::from_str::<Value>(&reply.body).expect("JSON")["error"],
            "this socket serves section=summary only",
            "{target}"
        );
    }
    for target in [
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/snapshot",
        "/v1/snapshot/version",
        "/v1/schema",
        "/v1/events",
        "/v1/explain",
        "/v1/apps/x/failures",
        "/v1/cache/purge",
        "/",
        "/v1/overview/",
    ] {
        let reply = call(&socket, "GET", target, "").await;
        assert_eq!(reply.status, 404, "{target}");
        assert_eq!(reply.body, r#"{"error":"not found"}"#, "{target}");
    }
}

#[tokio::test]
#[ignore = "needs 0135's /v1/catalog"]
async fn admin_read_socket_catalog_route() {
    let (podgate, socket) = start_with_read_socket(&[]).await;
    let reply = call(&socket, "GET", "/v1/catalog", "").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let admin = podgate.admin_get("/v1/catalog").await;
    assert_eq!(reply.body, admin.body);
}

#[tokio::test]
async fn admin_read_socket_refuses_writes() {
    let (podgate, socket) = start_with_read_socket(&[]).await;
    for method in ["PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        let reply = call(&socket, method, SUMMARY, "").await;
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.header("allow"), Some("GET"), "{method}");
    }
    let before = podgate.admin_get("/v1/snapshot/version").await;
    assert_eq!(before.status, 200, "{}", before.body);
    let snapshot = common::simple_snapshot(before_version(&before.body) + 1, &[]);
    let refused = call(&socket, "PUT", "/v1/snapshot", &snapshot.to_string()).await;
    assert_eq!(refused.status, 404);
    assert_eq!(refused.body, r#"{"error":"not found"}"#);
    let after = podgate.admin_get("/v1/snapshot/version").await;
    assert_eq!(after.body, before.body);
}

fn before_version(body: &str) -> u64 {
    serde_json::from_str::<Value>(body).expect("JSON")["version"]
        .as_u64()
        .unwrap_or(0)
}

#[tokio::test]
async fn admin_read_socket_same_answers() {
    let (podgate, socket) = start_with_read_socket(&[]).await;
    let read = call(&socket, "GET", SUMMARY, "").await;
    let admin = call(&podgate.admin_socket, "GET", SUMMARY, "").await;
    assert_eq!(read.status, 200);
    assert_eq!(read.status, admin.status);
    assert_eq!(read.body, admin.body);
    assert_eq!(read.header("content-type"), admin.header("content-type"));
    let refused = call(&socket, "GET", "/v1/overview?section=apps", "").await;
    let admin_error = call(
        &podgate.admin_socket,
        "GET",
        "/v1/overview?section=nope",
        "",
    )
    .await;
    assert_eq!(refused.status, admin_error.status);
    assert_eq!(
        refused.header("content-type"),
        admin_error.header("content-type")
    );
}

#[tokio::test]
async fn admin_read_socket_mode() {
    let (podgate, socket) = start_with_read_socket(&[]).await;
    assert_eq!(mode_of(&socket), 0o660);
    assert_eq!(mode_of(&podgate.admin_socket), 0o600);
    let (podgate, socket) = start_with_read_socket(&[("ADMIN_READ_SOCKET_MODE", "0600")]).await;
    assert_eq!(mode_of(&socket), 0o600);
    assert_eq!(mode_of(&podgate.admin_socket), 0o600);
}

#[test]
fn admin_read_socket_bad_settings() {
    let dir = std::env::temp_dir().join(format!("podgate-read-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let admin = dir.join("admin.sock");
    let read = dir.join("read.sock");
    let admin_text = admin.to_string_lossy().into_owned();
    let read_text = read.to_string_lossy().into_owned();
    let cases: Vec<(Vec<(&str, String)>, &str)> = vec![
        (
            vec![
                ("ADMIN_READ_SOCKET", read_text.clone()),
                ("ADMIN_READ_SOCKET_MODE", "0777".into()),
            ],
            "ADMIN_READ_SOCKET_MODE",
        ),
        (
            vec![
                ("ADMIN_READ_SOCKET", read_text.clone()),
                ("ADMIN_READ_SOCKET_MODE", "0610".into()),
            ],
            "ADMIN_READ_SOCKET_MODE",
        ),
        (
            vec![
                ("ADMIN_READ_SOCKET", read_text.clone()),
                ("ADMIN_READ_SOCKET_MODE", "rw-rw----".into()),
            ],
            "ADMIN_READ_SOCKET_MODE",
        ),
        (
            vec![
                ("ADMIN_READ_SOCKET", read_text.clone()),
                ("ADMIN_READ_SOCKET_MODE", "0400".into()),
            ],
            "ADMIN_READ_SOCKET_MODE",
        ),
        (
            vec![("ADMIN_READ_SOCKET_MODE", "0600".into())],
            "ADMIN_READ_SOCKET_MODE",
        ),
        (vec![("ADMIN_READ_SOCKET", admin_text)], "ADMIN_READ_SOCKET"),
        (
            vec![("ADMIN_READ_SOCKET", "/dev/null/read.sock".into())],
            "ADMIN_READ_SOCKET",
        ),
    ];
    for (env, var) in cases {
        let mut command = Command::new(env!("CARGO_BIN_EXE_podgate"));
        command
            .env(
                "PROXY_ADDR",
                format!("127.0.0.1:{}", common::free_ports(1)[0]),
            )
            .env("ADMIN_SOCKET", &admin)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null());
        for (name, value) in &env {
            command.env(name, value);
        }
        let output = command.output().expect("run podgate");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{env:?} started");
        assert!(stderr.contains(var), "{env:?}: {stderr}");
    }
    drop(std::fs::remove_dir_all(&dir));
}
