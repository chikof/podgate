//! The SPIFFE Workload API client: gRPC over the agent's unix socket.
//!
//! The Workload API is two server-streaming calls on the `SpiffeWorkloadAPI` service,
//! `FetchX509SVID` and `FetchX509Bundles`, both with the request header `workload.spiffe.io:
//! true`. The agent sends a full response when the call opens and a new one whenever anything
//! changes, so a stream that stays open is how rotation reaches the process.
//!
//! This is a hand-written client on `h2` and `prost`, both already dependencies: the service is
//! two calls with one empty request each, and a gRPC framework would bring its own HTTP stack
//! for them. The messages are `pub` so a test can play the agent.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, Request, StatusCode};
use prost::Message;
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The path of the SVID stream.
pub const FETCH_X509_SVID: &str = "/SpiffeWorkloadAPI/FetchX509SVID";

/// The path of the bundle stream.
pub const FETCH_X509_BUNDLES: &str = "/SpiffeWorkloadAPI/FetchX509Bundles";

/// The header every Workload API call carries.
pub const SECURITY_HEADER: &str = "workload.spiffe.io";

/// The longest a connection to the agent may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest message accepted from the agent: a bundle of a federation with many domains.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// One identity of the workload (`X509SVID`).
#[derive(Clone, PartialEq, Message)]
pub struct X509Svid {
    /// The SPIFFE ID, `spiffe://<trust domain>/<path>`.
    #[prost(string, tag = "1")]
    pub spiffe_id: String,
    /// The certificate chain, leaf first, as concatenated ASN.1 DER.
    #[prost(bytes = "vec", tag = "2")]
    pub x509_svid: Vec<u8>,
    /// The private key, PKCS#8 ASN.1 DER.
    #[prost(bytes = "vec", tag = "3")]
    pub x509_svid_key: Vec<u8>,
    /// The roots of the SVID's own trust domain, concatenated ASN.1 DER.
    #[prost(bytes = "vec", tag = "4")]
    pub bundle: Vec<u8>,
    /// The agent's label for this identity.
    #[prost(string, tag = "5")]
    pub hint: String,
}

/// What `FetchX509SVID` streams: every identity of the workload and the federated bundles.
#[derive(Clone, PartialEq, Message)]
pub struct X509SvidResponse {
    /// The identities.
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<X509Svid>,
    /// Certificate revocation lists, which podgate does not use.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub crl: Vec<Vec<u8>>,
    /// The bundles of the trust domains this one is federated with, by trust domain.
    #[prost(btree_map = "string, bytes", tag = "3")]
    pub federated_bundles: BTreeMap<String, Vec<u8>>,
}

/// What `FetchX509Bundles` streams: the bundles of every trust domain the agent knows.
#[derive(Clone, PartialEq, Message)]
pub struct X509BundlesResponse {
    /// Certificate revocation lists, which podgate does not use.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub crl: Vec<Vec<u8>>,
    /// The bundles by trust domain, concatenated ASN.1 DER.
    #[prost(btree_map = "string, bytes", tag = "2")]
    pub bundles: BTreeMap<String, Vec<u8>>,
}

/// Why a stream ended.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The agent's socket cannot be reached.
    #[error("cannot connect to the agent: {0}")]
    Connect(#[source] io::Error),
    /// The connection to the agent timed out.
    #[error("connecting to the agent timed out")]
    ConnectTimeout,
    /// HTTP/2 failed.
    #[error("HTTP/2: {0}")]
    Http2(#[from] h2::Error),
    /// The request could not be built.
    #[error("request: {0}")]
    Request(#[from] http::Error),
    /// The agent answered with an HTTP status other than 200.
    #[error("the agent answered HTTP {0}")]
    Status(StatusCode),
    /// The call ended with a gRPC status other than `OK`.
    #[error("gRPC status {code}: {message}")]
    Grpc {
        /// The `grpc-status` code.
        code: i32,
        /// The `grpc-message`, when there was one.
        message: Box<str>,
    },
    /// A frame is compressed, too large, or cut short.
    #[error("bad gRPC frame: {0}")]
    Frame(&'static str),
    /// A message does not decode.
    #[error("message: {0}")]
    Decode(#[from] prost::DecodeError),
    /// The stream ended with no error: an agent that is going away.
    #[error("the agent closed the stream")]
    Closed,
}

/// Ends the connection task with the call.
struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The gRPC status in `headers`, if there is one: its code and message.
fn status_of(headers: &HeaderMap) -> Option<(i32, Box<str>)> {
    let code = headers.get("grpc-status")?.to_str().ok()?.parse().ok()?;
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    Some((code, message.into()))
}

fn check_status(headers: &HeaderMap) -> Result<(), ClientError> {
    match status_of(headers) {
        Some((0, _)) | None => Ok(()),
        Some((code, message)) => Err(ClientError::Grpc { code, message }),
    }
}

/// Takes one whole message out of `buffer`, or `None` while it is incomplete.
fn next_message(buffer: &mut BytesMut) -> Result<Option<Bytes>, ClientError> {
    let Some(head) = buffer.get(..5) else {
        return Ok(None);
    };
    if head[0] != 0 {
        return Err(ClientError::Frame("compressed message"));
    }
    let length = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(ClientError::Frame("message too large"));
    }
    if buffer.len() < 5 + length {
        return Ok(None);
    }
    buffer.advance(5);
    Ok(Some(buffer.split_to(length).freeze()))
}

/// Calls the server-streaming `method` of the agent listening on `socket` and hands every
/// message to `on` until the stream ends. A stream that ends is always an error: the agent keeps
/// it open for as long as it is serving.
///
/// # Errors
///
/// [`ClientError`] for any failure of the connection, the call, a frame or a message, and
/// [`ClientError::Closed`] when the agent ends the stream with `OK`.
pub async fn watch<M: Message + Default>(
    socket: &Path,
    method: &str,
    mut on: impl FnMut(M),
) -> Result<(), ClientError> {
    let stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| ClientError::ConnectTimeout)?
        .map_err(ClientError::Connect)?;
    let (sender, connection) = h2::client::handshake(stream).await?;
    let _driver = Driver(tokio::spawn(async move {
        drop(connection.await);
    }));
    let mut sender = sender.ready().await?;
    let request = Request::post(format!("http://localhost{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header(SECURITY_HEADER, "true")
        .body(())?;
    let (response, mut body) = sender.send_request(request, false)?;
    // One empty message: both requests have no fields.
    body.send_data(Bytes::from_static(&[0, 0, 0, 0, 0]), true)?;
    let (head, mut incoming) = response.await?.into_parts();
    if head.status != StatusCode::OK {
        return Err(ClientError::Status(head.status));
    }
    // A call the agent refuses answers with the status in the headers and no body.
    check_status(&head.headers)?;
    let mut buffer = BytesMut::new();
    while let Some(chunk) = incoming.data().await {
        let chunk = chunk?;
        incoming.flow_control().release_capacity(chunk.len())?;
        buffer.extend_from_slice(&chunk);
        while let Some(message) = next_message(&mut buffer)? {
            on(M::decode(message)?);
        }
    }
    if !buffer.is_empty() {
        return Err(ClientError::Frame("stream ended inside a message"));
    }
    if let Some(trailers) = incoming.trailers().await? {
        check_status(&trailers)?;
    }
    Err(ClientError::Closed)
}

/// Encodes `message` as one gRPC frame: what a server writes for each response.
#[must_use]
pub fn frame<M: Message>(message: &M) -> Bytes {
    let body = message.encode_to_vec();
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&body);
    out.freeze()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn frames_round_trip_and_wait_for_the_rest() {
        let message = X509BundlesResponse {
            crl: Vec::new(),
            bundles: BTreeMap::from([("td".to_owned(), vec![1, 2, 3])]),
        };
        let bytes = frame(&message);
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&bytes[..bytes.len() - 1]);
        assert!(next_message(&mut buffer).expect("partial").is_none());
        buffer.extend_from_slice(&bytes[bytes.len() - 1..]);
        let whole = next_message(&mut buffer)
            .expect("whole")
            .expect("a message");
        assert_eq!(
            X509BundlesResponse::decode(whole).expect("decodes"),
            message
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn refuses_compressed_and_oversized_frames() {
        let mut compressed = BytesMut::from(&[1, 0, 0, 0, 0][..]);
        assert!(matches!(
            next_message(&mut compressed),
            Err(ClientError::Frame(_))
        ));
        let mut huge = BytesMut::from(&[0, 0xff, 0xff, 0xff, 0xff][..]);
        assert!(matches!(
            next_message(&mut huge),
            Err(ClientError::Frame(_))
        ));
    }
}
