//! The exporter: two read routes over mutual TLS, answered from the daemon's read socket.
//!
//! `GET /federation/v1/status` and `GET /federation/v1/catalog?limit=&after=`; everything else is
//! `404`, another method `405`. A hub's `after` is validated into a [`Cursor`] before the read
//! socket is touched. The daemon's answers are re-parsed with the same caps the hub applies and
//! written again in the closed shape of [`crate::wire`], so a field the daemon adds, or a string a
//! tenant wrote, leaves the cluster bounded.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{Method, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::admin_get::{AdminError, AdminGet, AdminTarget};
use crate::config::ExportFile;
use crate::serve::{Handler, Params, Reply, Request, serve};
use crate::wire::{Cursor, FORMAT_VERSION, Item, Key, Page, Status};

/// Entries asked of the daemon, and offered to a hub, when `limit` is absent.
const DEFAULT_LIMIT: u16 = 100;
/// The most entries in one page.
const MAX_LIMIT: u16 = 200;
/// The most bytes of items in one page.
const MAX_PAGE_BYTES: usize = 3 * 1024 * 1024;
/// Daemon pages read to find one entry that passes the caps.
const MAX_SKIPPED_PAGES: usize = 8;

/// Why the exporter does not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// The listen address cannot be bound.
    #[error("cannot bind the exporter address")]
    Bind(#[source] Box<io::Error>),
    /// `read_socket` serves the full admin API.
    #[error("read_socket serves the full admin API; set it to the daemon's ADMIN_READ_SOCKET")]
    FullSocket,
}

/// A running exporter. Dropping it stops it.
#[derive(Debug)]
pub struct Exporter {
    addr: SocketAddr,
    task: JoinHandle<()>,
    fatal: watch::Receiver<bool>,
}

impl Drop for Exporter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Exporter {
    /// Binds the listener. When the read socket answers, it is probed at once: a path that
    /// serves the full admin API stops the start. A daemon that is not up yet is not an error.
    ///
    /// # Errors
    ///
    /// [`StartError`].
    pub async fn start(file: ExportFile) -> Result<Self, StartError> {
        let admin = AdminGet::new(file.read_socket, file.admin_slots);
        if let Err(AdminError::FullSocket) = admin.probe().await {
            return Err(StartError::FullSocket);
        }
        let listener = TcpListener::bind(file.serve.addr)
            .await
            .map_err(|err| StartError::Bind(Box::new(err)))?;
        let addr = listener
            .local_addr()
            .map_err(|err| StartError::Bind(Box::new(err)))?;
        let (fatal_tx, fatal) = watch::channel(false);
        let handler = Arc::new(ExportHandler {
            admin,
            fatal: fatal_tx,
        });
        let task = tokio::spawn(serve(
            listener,
            file.serve.tls,
            file.serve.max_connections,
            handler,
        ));
        Ok(Self { addr, task, fatal })
    }

    /// Where the exporter listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Resolves when the exporter finds that it must stop: its read socket serves the full admin
    /// API.
    pub async fn fatal(&mut self) -> AdminError {
        while !*self.fatal.borrow_and_update() {
            if self.fatal.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
        AdminError::FullSocket
    }
}

struct ExportHandler {
    admin: AdminGet,
    fatal: watch::Sender<bool>,
}

impl ExportHandler {
    fn failed(&self, error: AdminError) -> Reply {
        match error {
            AdminError::Status(503) => {
                Reply::error(StatusCode::SERVICE_UNAVAILABLE, "busy").retry_after(1)
            }
            AdminError::FullSocket => {
                self.fatal.send_replace(true);
                Reply::error(StatusCode::BAD_GATEWAY, "read socket is not a read socket")
            }
            AdminError::Malformed | AdminError::TooLarge => Reply::error(
                StatusCode::BAD_GATEWAY,
                "the daemon's answer is not readable",
            ),
            _ => Reply::error(StatusCode::BAD_GATEWAY, "the daemon is unavailable"),
        }
    }

    async fn status(&self) -> Reply {
        let body = match self.admin.get(&AdminTarget::Summary).await {
            Ok(body) => body,
            Err(error) => return self.failed(error),
        };
        match Status::from_daemon(&body).and_then(|status| {
            status
                .to_doc()
                .map_err(|_| crate::wire::ParseError::Malformed)
        }) {
            Ok(doc) => Reply::ok(doc),
            Err(_) => self.failed(AdminError::Malformed),
        }
    }

    async fn catalog(&self, query: Option<&str>) -> Reply {
        let params = match Params::parse(query, &["limit", "after"]) {
            Ok(params) => params,
            Err(reply) => return reply,
        };
        let limit = match params.get("limit") {
            None => DEFAULT_LIMIT,
            Some(text) => match text.parse::<u16>() {
                Ok(0) | Err(_) => {
                    return Reply::bad_request("limit must be a number of at least 1");
                }
                Ok(limit) => limit.min(MAX_LIMIT),
            },
        };
        let mut after = match params.get("after").map(Cursor::parse).transpose() {
            Ok(after) => after,
            Err(_) => return Reply::bad_request("bad cursor"),
        };
        for _ in 0..MAX_SKIPPED_PAGES {
            let body = match self
                .admin
                .get(&AdminTarget::Catalog {
                    limit,
                    after: after.clone(),
                })
                .await
            {
                Ok(body) => body,
                Err(error) => return self.failed(error),
            };
            let Ok(page) = Page::from_daemon(&body) else {
                return self.failed(AdminError::Malformed);
            };
            if page.items.is_empty() && page.truncated {
                // Every entry of the page broke a cap: step past them.
                match page.last_key {
                    Some(key) => after = Some(Cursor::after(&key)),
                    None => return self.failed(AdminError::Malformed),
                }
                continue;
            }
            return match encode(&page) {
                Ok(doc) => Reply::ok(doc),
                Err(_) => self.failed(AdminError::Malformed),
            };
        }
        self.failed(AdminError::Malformed)
    }
}

/// The exporter's catalog document for `page`, ending early when the items reach the byte cap.
fn encode(page: &Page) -> Result<Vec<u8>, serde_json::Error> {
    let mut items: Vec<u8> = Vec::new();
    let mut kept: Option<Key> = None;
    let mut trimmed = false;
    for (at, item) in page.items.iter().enumerate() {
        let bytes = serde_json::to_vec::<Item>(item)?;
        if at > 0 && items.len() + bytes.len() + 1 > MAX_PAGE_BYTES {
            trimmed = true;
            break;
        }
        if at > 0 {
            items.push(b',');
        }
        items.extend_from_slice(&bytes);
        kept = Some(Key::of(item));
    }
    let truncated = page.truncated || trimmed;
    let mut out = format!(
        r#"{{"format_version":{FORMAT_VERSION},"snapshot_version":{},"total":{},"items":["#,
        page.snapshot_version, page.total
    )
    .into_bytes();
    out.extend_from_slice(&items);
    out.extend_from_slice(b"]");
    match (truncated, kept) {
        (true, Some(key)) => {
            out.extend_from_slice(br#","truncated":true,"next":"#);
            out.extend_from_slice(&serde_json::to_vec(Cursor::after(&key).as_str())?);
        }
        _ => out.extend_from_slice(br#","truncated":false"#),
    }
    out.push(b'}');
    Ok(out)
}

impl Handler for ExportHandler {
    async fn handle(&self, request: Request) -> Reply {
        let path = request.path.as_str();
        if !matches!(path, "/federation/v1/status" | "/federation/v1/catalog") {
            return Reply::not_found();
        }
        if request.method != Method::GET {
            return Reply::method_not_allowed();
        }
        if path == "/federation/v1/status" {
            match Params::parse(request.query.as_deref(), &[]) {
                Ok(_) => self.status().await,
                Err(reply) => reply,
            }
        } else {
            self.catalog(request.query.as_deref()).await
        }
    }
}
