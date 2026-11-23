//! The exporter's only reader of the daemon: `GET`s on the read socket.
//!
//! The request target is built from [`AdminTarget`] and a validated [`Cursor`], never from a
//! string a hub sent. On its first use the reader asks `GET /healthz`: the read socket answers
//! `404`, and a socket that answers `200` serves the full admin API, which the exporter refuses.

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, HOST};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::{OnceCell, Semaphore};
use tokio::time::timeout;

use crate::wire::{Cursor, percent_encode};

/// The largest answer read from the daemon.
pub const MAX_ANSWER: usize = 5 * 1024 * 1024;
/// The deadline of one request to the daemon.
const DEADLINE: Duration = Duration::from_secs(10);

/// What the exporter reads.
#[derive(Debug, Clone)]
pub enum AdminTarget {
    /// `GET /v1/overview?section=summary`.
    Summary,
    /// `GET /v1/catalog?limit=<n>[&after=<cursor>]`.
    Catalog {
        /// Entries per page.
        limit: u16,
        /// Where the page starts.
        after: Option<Cursor>,
    },
}

impl AdminTarget {
    fn path_and_query(&self) -> String {
        match self {
            Self::Summary => "/v1/overview?section=summary".to_owned(),
            Self::Catalog { limit, after: None } => format!("/v1/catalog?limit={limit}"),
            Self::Catalog {
                limit,
                after: Some(after),
            } => format!(
                "/v1/catalog?limit={limit}&after={}",
                percent_encode(after.as_str())
            ),
        }
    }
}

/// Why a read of the daemon failed.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdminError {
    /// The socket is missing or the connection broke.
    #[error("cannot reach the read socket")]
    Connect,
    /// No complete answer within the deadline.
    #[error("the read socket did not answer in time")]
    Timeout,
    /// The answer is over the cap.
    #[error("the answer is too large")]
    TooLarge,
    /// The daemon answered this status.
    #[error("the daemon answered {0}")]
    Status(u16),
    /// The answer is not what the route documents.
    #[error("the answer is not readable")]
    Malformed,
    /// The socket serves the full admin API.
    #[error("read_socket serves the full admin API; set it to the daemon's ADMIN_READ_SOCKET")]
    FullSocket,
}

/// A bounded reader of the read socket.
#[derive(Debug)]
pub struct AdminGet {
    socket: PathBuf,
    slots: Semaphore,
    probed: OnceCell<()>,
}

impl AdminGet {
    /// A reader of `socket` that makes at most `slots` requests at once.
    #[must_use]
    pub fn new(socket: PathBuf, slots: usize) -> Self {
        Self {
            socket,
            slots: Semaphore::new(slots),
            probed: OnceCell::new(),
        }
    }

    /// Reads `target`.
    ///
    /// # Errors
    ///
    /// An [`AdminError`]; [`AdminError::FullSocket`] when the first-use probe finds the full
    /// admin API.
    pub async fn get(&self, target: &AdminTarget) -> Result<Bytes, AdminError> {
        self.probed.get_or_try_init(|| self.probe()).await?;
        let (status, body) = self.request(&target.path_and_query()).await?;
        if status == StatusCode::OK {
            Ok(body)
        } else {
            Err(AdminError::Status(status.as_u16()))
        }
    }

    /// Checks that the socket is a read socket.
    ///
    /// # Errors
    ///
    /// [`AdminError::FullSocket`] when `GET /healthz` is answered `200`, and the failure of the
    /// request otherwise.
    pub async fn probe(&self) -> Result<(), AdminError> {
        let (status, _) = self.request("/healthz").await?;
        if status == StatusCode::OK {
            Err(AdminError::FullSocket)
        } else {
            Ok(())
        }
    }

    async fn request(&self, path_and_query: &str) -> Result<(StatusCode, Bytes), AdminError> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| AdminError::Connect)?;
        timeout(DEADLINE, self.exchange(path_and_query))
            .await
            .map_err(|_| AdminError::Timeout)?
    }

    async fn exchange(&self, path_and_query: &str) -> Result<(StatusCode, Bytes), AdminError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| AdminError::Connect)?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| AdminError::Connect)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::get(path_and_query)
            .header(HOST, "localhost")
            .header(ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| AdminError::Malformed)?;
        let result = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| AdminError::Connect)?;
            let status = response.status();
            let mut body = response.into_body();
            let mut buffer = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| AdminError::Connect)?;
                if let Some(data) = frame.data_ref() {
                    if buffer.len() + data.len() > MAX_ANSWER {
                        return Err(AdminError::TooLarge);
                    }
                    buffer.extend_from_slice(data);
                }
            }
            Ok((status, Bytes::from(buffer)))
        }
        .await;
        driver.abort();
        result
    }
}
