//! A fake of the daemon's read socket: a unix socket that answers `/healthz`, the summary and the
//! catalog the way the daemon does, logs every request, and tracks how many run at once.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use super::peer::page;
use podgate_federation::wire::percent_decode;

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
}

pub struct FakeRead {
    pub path: PathBuf,
    pub log: Arc<Mutex<Vec<Seen>>>,
    pub peak: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for FakeRead {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How the fake answers.
pub struct Daemon {
    /// The catalog entries.
    pub items: Vec<Value>,
    pub version: u64,
    /// What `GET /healthz` answers: 404 for a read socket, 200 for the full admin socket.
    pub healthz: u16,
    /// Extra fields put on the summary and on every item, to prove they do not get through.
    pub extras: bool,
    /// Answers every `/v1/` route with this status instead.
    pub fail: Option<u16>,
    /// How long each request is held.
    pub delay: Duration,
    /// Entries per daemon page at most.
    pub page_cap: usize,
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            version: 7,
            healthz: 404,
            extras: false,
            fail: None,
            delay: Duration::ZERO,
            page_cap: 500,
        }
    }
}

impl FakeRead {
    pub fn start(path: PathBuf, daemon: Daemon) -> Self {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the fake read socket");
        let log = Arc::new(Mutex::new(Vec::new()));
        let peak = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));
        let daemon = Arc::new(daemon);
        let task = tokio::spawn({
            let (log, peak) = (log.clone(), peak.clone());
            async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (log, peak, current, daemon) =
                        (log.clone(), peak.clone(), current.clone(), daemon.clone());
                    tokio::spawn(async move {
                        let mut raw = Vec::new();
                        let mut chunk = [0_u8; 2048];
                        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            let Ok(read) = stream.read(&mut chunk).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            raw.extend_from_slice(&chunk[..read]);
                        }
                        let head = String::from_utf8_lossy(&raw).into_owned();
                        let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
                        let method = parts.next().unwrap_or_default().to_owned();
                        let target = parts.next().unwrap_or_default().to_owned();
                        log.lock().expect("log").push(Seen {
                            method,
                            target: target.clone(),
                        });
                        let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(daemon.delay).await;
                        let (code, body) = answer(&daemon, &target);
                        current.fetch_sub(1, Ordering::SeqCst);
                        let text = format!(
                            "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(text.as_bytes()).await;
                        let _ = stream.write_all(&body).await;
                    });
                }
            }
        });
        Self {
            path,
            log,
            peak,
            task,
        }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log").clone()
    }
}

fn answer(daemon: &Daemon, target: &str) -> (u16, Vec<u8>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let param = |name: &str| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, _)| *k == name)
            .and_then(|(_, v)| percent_decode(v))
    };
    if let (Some(code), true) = (daemon.fail, path.starts_with("/v1/")) {
        return (code, json!({"error": "scripted"}).to_string().into_bytes());
    }
    match path {
        "/healthz" => (
            daemon.healthz,
            json!({"status": "ok"}).to_string().into_bytes(),
        ),
        "/v1/overview" if param("section").as_deref() == Some("summary") => {
            let mut summary = json!({
                "version": daemon.version, "applied_at": 100, "boot_id": "daemon-boot",
                "writer": "podgate-provider", "tenants": 1, "apps": 2, "routers": 3, "services": 4,
                "servers": {"healthy": 5, "unhealthy": 0, "ejected": 0}
            });
            if daemon.extras {
                summary["client_ca_pem"] = json!("SECRET-SUMMARY");
                summary["metrics_addr"] = json!("127.0.0.1:9");
            }
            (200, json!({ "summary": summary }).to_string().into_bytes())
        }
        "/v1/catalog" => {
            let limit = param("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(50)
                .min(daemon.page_cap);
            let items: Vec<Value> = daemon
                .items
                .iter()
                .cloned()
                .map(|mut item| {
                    if daemon.extras {
                        item["client_ca_pem"] = json!("SECRET-ITEM");
                        item["nested"] = json!({"deep": [1, 2, 3]});
                    }
                    item
                })
                .collect();
            let (taken, truncated, next) = page(&items, limit, param("after").as_deref());
            let mut doc = json!({
                "version": daemon.version, "total": items.len(), "items": taken
            });
            if truncated {
                doc["truncated"] = json!(true);
                doc["next"] = json!(next);
            }
            (200, doc.to_string().into_bytes())
        }
        _ => (404, json!({"error": "not found"}).to_string().into_bytes()),
    }
}
