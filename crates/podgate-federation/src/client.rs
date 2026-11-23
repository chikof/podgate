//! The hub's only way to talk to a peer: one pinned mutual TLS connection that sends `GET`s.
//!
//! [`PeerConn::get`] is the one place a request is made, and it makes only `GET`. The target is
//! an enum plus a validated [`Cursor`], never a string from anywhere else, and no redirect is
//! followed: a `3xx` is a failed pull.

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::config::Peer;
use crate::failure::{ErrorClass, Failure};
use crate::wire::{Cursor, percent_encode};

/// What the hub asks a peer for.
#[derive(Debug, Clone)]
pub enum Target {
    /// `GET /federation/v1/status`.
    Status,
    /// `GET /federation/v1/catalog?limit=<n>[&after=<cursor>]`.
    Catalog {
        /// Entries per page.
        limit: u16,
        /// Where the page starts.
        after: Option<Cursor>,
    },
}

impl Target {
    fn path_and_query(&self) -> String {
        match self {
            Self::Status => "/federation/v1/status".to_owned(),
            Self::Catalog { limit, after: None } => format!("/federation/v1/catalog?limit={limit}"),
            Self::Catalog {
                limit,
                after: Some(after),
            } => format!(
                "/federation/v1/catalog?limit={limit}&after={}",
                percent_encode(after.as_str())
            ),
        }
    }
}

/// One connection to one peer.
#[derive(Debug)]
pub struct PeerConn {
    sender: SendRequest<Empty<Bytes>>,
    host: String,
    driver: JoinHandle<()>,
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Whether a `rustls` alert sits in the error's chain: with TLS 1.3 the handshake ends on the
/// client before the server has judged the client's certificate, so a refusal arrives later.
fn is_tls(err: &hyper::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(error) = source {
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && io
                .get_ref()
                .is_some_and(|inner| inner.is::<rustls::Error>())
        {
            return true;
        }
        source = error.source();
    }
    false
}

fn from_hyper(err: &hyper::Error) -> Failure {
    if is_tls(err) {
        Failure::new(ErrorClass::Tls)
    } else if err.is_parse() || err.is_parse_status() || err.is_parse_too_large() {
        Failure::new(ErrorClass::Malformed)
    } else {
        Failure::new(ErrorClass::Connect)
    }
}

impl PeerConn {
    /// Connects to `peer`: resolve, connect, handshake against the pinned CA with the hub's
    /// certificate. The caller bounds the time.
    ///
    /// # Errors
    ///
    /// [`ErrorClass::Connect`] or [`ErrorClass::Tls`].
    pub async fn open(peer: &Peer) -> Result<Self, Failure> {
        let addresses = tokio::net::lookup_host((&*peer.host, peer.port))
            .await
            .map_err(|_| Failure::new(ErrorClass::Connect))?;
        let mut connected = None;
        for address in addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                connected = Some(stream);
                break;
            }
        }
        let stream = connected.ok_or_else(|| Failure::new(ErrorClass::Connect))?;
        let tls = TlsConnector::from(peer.tls.clone())
            .connect(peer.server_name.clone(), stream)
            .await
            .map_err(|_| Failure::new(ErrorClass::Tls))?;
        let (sender, connection) = http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|err| from_hyper(&err))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let host = if peer.host.contains(':') {
            format!("[{}]:{}", peer.host, peer.port)
        } else {
            format!("{}:{}", peer.host, peer.port)
        };
        Ok(Self {
            sender,
            host,
            driver,
        })
    }

    /// Sends one `GET` and reads the body, at most `cap` bytes.
    ///
    /// # Errors
    ///
    /// [`ErrorClass::Status`] for anything but `200`, [`ErrorClass::Malformed`] for a body that
    /// is not declared JSON, [`ErrorClass::TooLarge`] past `cap`, [`ErrorClass::Connect`] when
    /// the connection breaks.
    pub async fn get(&mut self, target: &Target, cap: usize) -> Result<Bytes, Failure> {
        let request = Request::get(target.path_and_query())
            .header(HOST, &self.host)
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, "podgate-federation")
            .body(Empty::<Bytes>::new())
            .map_err(|_| Failure::new(ErrorClass::Malformed))?;
        self.sender.ready().await.map_err(|err| from_hyper(&err))?;
        let response = self
            .sender
            .send_request(request)
            .await
            .map_err(|err| from_hyper(&err))?;
        if response.status() != StatusCode::OK {
            return Err(Failure::status(response.status().as_u16()));
        }
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"));
        if !is_json {
            return Err(Failure::new(ErrorClass::Malformed));
        }
        let declared = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());
        if declared.is_some_and(|length| length > cap) {
            return Err(Failure::new(ErrorClass::TooLarge));
        }
        let mut body = response.into_body();
        let mut buffer = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|err| from_hyper(&err))?;
            if let Some(data) = frame.data_ref() {
                if buffer.len() + data.len() > cap {
                    return Err(Failure::new(ErrorClass::TooLarge));
                }
                buffer.extend_from_slice(data);
            }
        }
        Ok(Bytes::from(buffer))
    }
}
