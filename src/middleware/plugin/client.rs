//! The client of a plugin: unary gRPC calls over a unix socket, on `h2`, so the proxy needs no
//! gRPC framework (the same approach as the OTLP exporter in `observe::tracing::grpc`).
//!
//! One HTTP/2 connection is made on demand and shared by every call, each call being one
//! stream. A call has a deadline that covers connecting, waiting for a stream, sending and
//! reading the answer; a call that passes it is dropped, which resets its stream and leaves the
//! connection and the other calls alone. A connection that breaks is forgotten and the next
//! call connects again.
//!
//! The answer is read with its size known first: the 5-byte gRPC prefix says how long the
//! message is, a message over the cap fails the call before a byte of it is kept, and the
//! tenant is charged for the message before it is read.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use h2::client::SendRequest;
use h2::{Reason, RecvStream, SendStream};
use http::{HeaderMap, Request};
use prost::Message;
use tokio::net::UnixStream;
use tokio::time::timeout;

use super::limits::{CALL_MAX, DECISION_MAX};
use super::wire::{Decision, DescribeRequest, DescribeResponse};
use crate::budget::{BufferGuard, TenantBudget};

/// The method that describes a plugin.
const DESCRIBE_PATH: &str = "/podgate.plugin.v1.Plugin/Describe";

/// The method that decides one phase of one request.
const PROCESS_PATH: &str = "/podgate.plugin.v1.Plugin/Process";

/// The size of the gRPC prefix of a message: the compressed flag and a big-endian length.
const PREFIX: usize = 5;

/// Why a call to a plugin failed.
#[derive(Debug, thiserror::Error)]
pub(super) enum CallError {
    /// The call did not finish within its deadline.
    #[error("the plugin did not answer in time")]
    Timeout,
    /// Nothing listens on the plugin's socket.
    #[error("cannot reach the plugin: {0}")]
    Unreachable(String),
    /// The connection or the stream broke.
    #[error("the connection to the plugin failed: {0}")]
    Transport(String),
    /// The plugin answered a gRPC status other than `OK`.
    #[error("the plugin answered {}", status_name(*.0))]
    Status(u32),
    /// The answer is not a single, whole, uncompressed gRPC message that decodes.
    #[error("the plugin's answer is not a valid message: {0}")]
    Malformed(&'static str),
    /// The decision decodes but cannot be applied.
    #[error("the plugin's decision cannot be applied: {0}")]
    Invalid(String),
    /// The answer is longer than a decision may be.
    #[error("the plugin's answer is over {DECISION_MAX} bytes")]
    DecisionTooLarge,
    /// The call is longer than a call may be: nothing was sent.
    #[error("the call is over {CALL_MAX} bytes")]
    CallTooLarge,
    /// The tenant's buffer budget cannot take the answer.
    #[error("the tenant's buffer budget cannot take the plugin's answer")]
    OverBudget,
}

impl CallError {
    /// Whether the plugin is the one at fault, so the call counts towards its circuit.
    pub(super) fn is_plugin_failure(&self) -> bool {
        !matches!(self, Self::CallTooLarge | Self::OverBudget)
    }
}

const fn status_name(code: u32) -> &'static str {
    match code {
        1 => "CANCELLED",
        2 => "UNKNOWN",
        3 => "INVALID_ARGUMENT",
        4 => "DEADLINE_EXCEEDED",
        5 => "NOT_FOUND",
        7 => "PERMISSION_DENIED",
        8 => "RESOURCE_EXHAUSTED",
        9 => "FAILED_PRECONDITION",
        12 => "UNIMPLEMENTED",
        13 => "INTERNAL",
        14 => "UNAVAILABLE",
        16 => "UNAUTHENTICATED",
        _ => "an error status",
    }
}

fn transport(err: &impl std::fmt::Display) -> CallError {
    CallError::Transport(err.to_string())
}

/// One gRPC message: the uncompressed flag, a big-endian length, the encoded `message`.
///
/// # Errors
///
/// [`CallError::CallTooLarge`] when the message is over [`CALL_MAX`].
pub(super) fn frame(message: &impl Message) -> Result<Bytes, CallError> {
    let len = message.encoded_len();
    if len > CALL_MAX {
        return Err(CallError::CallTooLarge);
    }
    let mut out = BytesMut::with_capacity(PREFIX + len);
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
    // Writing to a `BytesMut` that has the room cannot fail.
    let _ = message.encode(&mut out);
    Ok(out.freeze())
}

/// Sends `data`, waiting for the peer's flow-control window as it must, then ends the stream.
async fn send_message(stream: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), h2::Error> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(Reason::CANCEL))??;
        if capacity > 0 {
            stream.send_data(data.split_to(capacity.min(data.len())), false)?;
        }
    }
    stream.send_data(Bytes::new(), true)
}

/// The `grpc-status` of `headers`, when there is one.
fn grpc_status(headers: &HeaderMap) -> Option<u32> {
    headers
        .get("grpc-status")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The one message of an answer: reads its prefix, charges `tenant` for it, then reads it.
async fn read_message(
    recv: &mut RecvStream,
    tenant: Option<&Arc<TenantBudget>>,
) -> Result<(Bytes, Option<BufferGuard>), CallError> {
    let mut head = BytesMut::with_capacity(PREFIX);
    let mut body = BytesMut::new();
    let mut want: Option<usize> = None;
    let mut charge = None;
    loop {
        if let Some(len) = want
            && body.len() >= len
        {
            break;
        }
        let Some(chunk) = recv.data().await else {
            return Err(CallError::Malformed("the message ends early"));
        };
        let chunk = chunk.map_err(|err| transport(&err))?;
        drop(recv.flow_control().release_capacity(chunk.len()));
        let mut rest = chunk;
        if want.is_none() {
            let take = (PREFIX - head.len()).min(rest.len());
            head.extend_from_slice(&rest.split_to(take));
            if head.len() < PREFIX {
                continue;
            }
            if head[0] != 0 {
                return Err(CallError::Malformed("the message is compressed"));
            }
            let len = usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]]))
                .unwrap_or(usize::MAX);
            if len > DECISION_MAX {
                return Err(CallError::DecisionTooLarge);
            }
            // The message and its decoded form exist together: charge both before either does.
            if let Some(tenant) = tenant {
                let bytes = u64::try_from(len.saturating_mul(2)).unwrap_or(u64::MAX);
                charge = Some(tenant.charge(bytes).ok_or(CallError::OverBudget)?);
            }
            body.reserve(len);
            want = Some(len);
        }
        body.extend_from_slice(&rest);
        if let Some(len) = want
            && body.len() > len
        {
            return Err(CallError::Malformed("more than one message"));
        }
    }
    Ok((body.freeze(), charge))
}

/// One unary call on `sender`: `message` is a framed request. The answer is the one message of
/// at most [`DECISION_MAX`] bytes.
async fn unary(
    mut sender: SendRequest<Bytes>,
    path: &str,
    message: Bytes,
    deadline: Duration,
    tenant: Option<&Arc<TenantBudget>>,
) -> Result<(Bytes, Option<BufferGuard>), CallError> {
    let request = Request::post(format!("http://plugin{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-accept-encoding", "identity")
        .header("grpc-timeout", format!("{}m", deadline.as_millis().max(1)))
        .header("user-agent", concat!("podgate/", env!("CARGO_PKG_VERSION")))
        .body(())
        .map_err(|err| transport(&err))?;
    let (response, mut stream) = sender
        .send_request(request, false)
        .map_err(|err| transport(&err))?;
    // The answer can come before the request is all sent (an error status), so both run.
    let (_, response) = tokio::join!(send_message(&mut stream, message), response);
    let (head, mut recv) = response.map_err(|err| transport(&err))?.into_parts();
    if let Some(code) = grpc_status(&head.headers) {
        // A trailers-only answer: the status is all of it.
        return Err(if code == 0 {
            CallError::Malformed("the answer has no message")
        } else {
            CallError::Status(code)
        });
    }
    if head.status != 200 {
        return Err(CallError::Transport(format!(
            "the plugin answered HTTP {}",
            head.status
        )));
    }
    let (payload, charge) = read_message(&mut recv, tenant).await?;
    let trailers = recv
        .trailers()
        .await
        .map_err(|err| transport(&err))?
        .unwrap_or_default();
    match grpc_status(&trailers) {
        Some(0) => Ok((payload, charge)),
        Some(code) => Err(CallError::Status(code)),
        None => Err(CallError::Malformed("the answer has no grpc-status")),
    }
}

/// An HTTP/2 client handshake on `io`; the connection is driven by a task that ends with it.
async fn handshake(io: UnixStream) -> Result<SendRequest<Bytes>, CallError> {
    // The handshake future is several kilobytes; boxed, it does not inflate every caller.
    let (sender, connection) = Box::pin(
        h2::client::Builder::new()
            .initial_window_size(1 << 18)
            .initial_connection_window_size(1 << 20)
            .handshake(io),
    )
    .await
    .map_err(|err| transport(&err))?;
    tokio::spawn(async move { drop(connection.await) });
    Ok(sender)
}

/// What a plugin answered to a call, and the memory it holds until dropped.
#[derive(Debug)]
pub(super) struct Answered {
    /// The decision.
    pub(super) decision: Decision,
    /// The tenant's charge for the answer; dropping it releases the bytes.
    pub(super) charge: Option<BufferGuard>,
}

/// The connection to one plugin.
pub(super) struct Client {
    path: PathBuf,
    connection: Mutex<Option<SendRequest<Bytes>>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub(super) fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            connection: Mutex::new(None),
        }
    }

    fn stored(&self) -> Option<SendRequest<Bytes>> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store(&self, sender: Option<SendRequest<Bytes>>) {
        *self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = sender;
    }

    /// Forgets the connection: the plugin restarted, so the next call connects again.
    pub(super) fn reset(&self) {
        self.store(None);
    }

    async fn connect(&self) -> Result<SendRequest<Bytes>, CallError> {
        let stream = UnixStream::connect(&self.path)
            .await
            .map_err(|err| CallError::Unreachable(format!("{}: {err}", self.path.display())))?;
        handshake(stream).await
    }

    /// A connection that can take a stream: the kept one, or a new one.
    async fn ready(&self) -> Result<SendRequest<Bytes>, CallError> {
        if let Some(sender) = self.stored() {
            if let Ok(sender) = sender.ready().await {
                return Ok(sender);
            }
            self.store(None);
        }
        let sender = self
            .connect()
            .await?
            .ready()
            .await
            .map_err(|err| transport(&err))?;
        self.store(Some(sender.clone()));
        Ok(sender)
    }

    /// Asks the plugin what it is, on a connection of its own that is dropped after the answer:
    /// the supervisor uses it while the plugin starts, when the kept connection (if any) belongs
    /// to a process that is gone.
    ///
    /// # Errors
    ///
    /// [`CallError`]: [`CallError::Unreachable`] while nothing listens yet.
    pub(super) async fn describe(&self, deadline: Duration) -> Result<DescribeResponse, CallError> {
        let call = async {
            let sender = self
                .connect()
                .await?
                .ready()
                .await
                .map_err(|err| transport(&err))?;
            let message = frame(&DescribeRequest {})?;
            let (payload, _) = unary(sender, DESCRIBE_PATH, message, deadline, None).await?;
            DescribeResponse::decode(payload)
                .map_err(|_| CallError::Malformed("the description does not decode"))
        };
        timeout(deadline, call)
            .await
            .map_err(|_| CallError::Timeout)?
    }

    /// Sends `message` (a framed `Call`) and returns the plugin's decision, charging `tenant` for
    /// it before it is read.
    ///
    /// # Errors
    ///
    /// [`CallError`] for a failed call; [`CallError::Timeout`] when `deadline` passed.
    pub(super) async fn process(
        &self,
        message: Bytes,
        deadline: Duration,
        tenant: Option<&Arc<TenantBudget>>,
    ) -> Result<Answered, CallError> {
        let call = async {
            let sender = self.ready().await?;
            let (payload, charge) = unary(sender, PROCESS_PATH, message, deadline, tenant).await?;
            let decision = Decision::decode(payload)
                .map_err(|_| CallError::Malformed("the decision does not decode"))?;
            Ok(Answered { decision, charge })
        };
        timeout(deadline, call)
            .await
            .map_err(|_| CallError::Timeout)?
    }
}
