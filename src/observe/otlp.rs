//! The OTLP transport every signal shares (extracted from the span exporter of specs
//! 0067 and 0112). Traces, metrics and logs differ in their messages and in what they queue; the
//! collector settings, the wire, the retry loop and the message limit are the same.
//!
//! - [`collector`]: [`Collector`], the operator's `OTEL_EXPORTER_OTLP_*` settings, and [`Signal`].
//! - [`transport`]: [`Transport`], one signal's HTTP client or gRPC channel, with the timeout
//!   and the retry loop.
//! - `grpc`: the unary gRPC call on `h2`, no gRPC framework.
//! - [`batch`]: [`Feed`] and [`BatchExporter`] for a signal with a bounded queue, and the split
//!   to the 4 MiB message limit.
//! - [`common`]: the messages every signal uses (`Resource`, `KeyValue`, `AnyValue`).
//!
//! A signal brings its own variables, messages, queue and counters. None of this is ever read
//! from a snapshot: a snapshot is tenant-influenced data, and letting it name an address
//! podgate calls would be an SSRF primitive.

pub mod batch;
pub mod collector;
pub mod common;
mod grpc;
pub mod transport;

pub use batch::{BatchExporter, Feed};
pub use collector::{Collector, Protocol, Signal};
pub use transport::{Failure, Transport};
