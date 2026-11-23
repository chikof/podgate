//! A fake peer: a mutual TLS HTTP/1.1 server that answers from a script and logs every request.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podgate_federation::wire::{Cursor, Key, percent_decode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::Pki;

/// One request the peer saw.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: HashMap<String, String>,
}

pub enum Answer {
    /// `200` with a JSON body.
    Json(Vec<u8>),
    /// Any status with headers and a body.
    Status(u16, Vec<(String, String)>, Vec<u8>),
    /// Exactly these bytes.
    Raw(Vec<u8>),
    /// Never answers.
    Hang,
    /// Announces a long body and sends a byte every 200 ms.
    Trickle,
}

pub type Script = Arc<dyn Fn(&Seen) -> Answer + Send + Sync>;

pub struct FakePeer {
    pub addr: SocketAddr,
    pub log: Arc<Mutex<Vec<Seen>>>,
    pub connections: Arc<AtomicUsize>,
    script: Arc<Mutex<Script>>,
    task: JoinHandle<()>,
}

impl Drop for FakePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakePeer {
    /// A peer whose server certificate is `pki`'s and that requires a client certificate of
    /// `client_ca`.
    pub async fn start(pki: &Pki, client_ca: &Pki, script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let acceptor = TlsAcceptor::from(pki.server_config(client_ca));
        let log = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(Mutex::new(script));
        let task = tokio::spawn({
            let (log, script, connections) = (log.clone(), script.clone(), connections.clone());
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::Relaxed);
                    let (acceptor, log, script) = (acceptor.clone(), log.clone(), script.clone());
                    tokio::spawn(async move {
                        if let Ok(tls) = acceptor.accept(stream).await {
                            let _ = Box::pin(connection(tls, log, script)).await;
                        }
                    });
                }
            }
        });
        Self {
            addr,
            log,
            connections,
            script,
            task,
        }
    }

    pub fn set(&self, script: Script) {
        *self.script.lock().expect("script lock") = script;
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log lock").clone()
    }
}

async fn connection<S>(
    mut stream: S,
    log: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<Script>>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let split = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..read]);
        };
        let head = String::from_utf8_lossy(&buffer[..split]).into_owned();
        buffer.drain(..split + 4);
        let mut parts = head.lines().next().unwrap_or_default().split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let target = parts.next().unwrap_or_default().to_owned();
        let (path, query_text) = target.split_once('?').unwrap_or((&target, ""));
        let query = query_text
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (k.to_owned(), percent_decode(v).unwrap_or_default()))
            .collect();
        let seen = Seen {
            method,
            target: target.clone(),
            path: path.to_owned(),
            query,
        };
        log.lock().expect("log lock").push(seen.clone());
        let answer = {
            let script = script.lock().expect("script lock").clone();
            script(&seen)
        };
        match answer {
            Answer::Json(body) => {
                write(
                    &mut stream,
                    200,
                    &[("content-type", "application/json")],
                    &body,
                )
                .await?
            }
            Answer::Status(code, headers, body) => {
                let headers: Vec<(&str, &str)> = headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                write(&mut stream, code, &headers, &body).await?;
            }
            Answer::Raw(bytes) => stream.write_all(&bytes).await?,
            Answer::Hang => std::future::pending::<()>().await,
            Answer::Trickle => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 50000\r\n\r\n")
                    .await?;
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    stream.write_all(b" ").await?;
                    stream.flush().await?;
                }
            }
        }
    }
}

async fn write<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    code: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut text = format!("HTTP/1.1 {code} X\r\ncontent-length: {}\r\n", body.len());
    for (key, value) in headers {
        text.push_str(&format!("{key}: {value}\r\n"));
    }
    text.push_str("\r\n");
    stream.write_all(text.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// A page of `items` (sorted by key) the way the daemon and the exporter both page: after the
/// cursor, at most `limit`, `truncated` and `next` when more remain.
pub fn page(
    items: &[Value],
    limit: usize,
    after: Option<&str>,
) -> (Vec<Value>, bool, Option<String>) {
    let key_of = |v: &Value| Key {
        tenant: v["tenant"].as_str().unwrap_or_default().into(),
        id: v["id"].as_str().unwrap_or_default().into(),
        version: v["version"].as_str().unwrap_or_default().into(),
    };
    let mut sorted: Vec<&Value> = items.iter().collect();
    sorted.sort_by_key(|v| key_of(v));
    let after = after
        .and_then(|text| Cursor::parse(text).ok())
        .map(|c| c.key());
    let rest: Vec<&Value> = sorted
        .into_iter()
        .filter(|v| after.as_ref().is_none_or(|a| key_of(v) > *a))
        .collect();
    let truncated = rest.len() > limit;
    let taken: Vec<Value> = rest.into_iter().take(limit).cloned().collect();
    let next = truncated.then(|| {
        Cursor::after(&key_of(taken.last().expect("a page")))
            .as_str()
            .to_owned()
    });
    (taken, truncated, next)
}

/// A well-behaved exporter holding `items`, at snapshot `version`.
pub fn catalog_script(items: Vec<Value>, version: u64) -> Script {
    Arc::new(move |seen: &Seen| match seen.path.as_str() {
        "/federation/v1/status" => Answer::Json(
            json!({
                "format_version": 1, "snapshot_version": version, "applied_at": 100,
                "boot_id": "boot-1", "writer": "podgate-provider",
                "counts": {"tenants": 1, "apps": 2, "routers": 3, "services": 4,
                           "servers": {"healthy": 5, "unhealthy": 0, "ejected": 0}}
            })
            .to_string()
            .into_bytes(),
        ),
        "/federation/v1/catalog" => {
            let limit = seen
                .query
                .get("limit")
                .and_then(|l| l.parse().ok())
                .unwrap_or(100);
            let (taken, truncated, next) =
                page(&items, limit, seen.query.get("after").map(String::as_str));
            let mut doc = json!({
                "format_version": 1, "snapshot_version": version, "total": items.len(),
                "items": taken, "truncated": truncated
            });
            if let Some(next) = next {
                doc["next"] = json!(next);
            }
            Answer::Json(doc.to_string().into_bytes())
        }
        _ => Answer::Status(404, Vec::new(), b"{}".to_vec()),
    })
}
