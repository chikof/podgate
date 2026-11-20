//! A finished span, as it waits in the export queue.

use std::borrow::Cow;

use super::context::{SpanId, TraceId};

/// What a span is: the proxy serving a request, or the proxy calling an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Server,
    Client,
}

/// An attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    Str(Box<str>),
    Int(i64),
    /// A header with several values.
    Strs(Vec<Box<str>>),
}

/// A finished span. Built on the request path from copied, length-capped strings, so a queue of
/// these holds a bounded amount of text per span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Span {
    pub(super) trace_id: TraceId,
    pub(super) span_id: SpanId,
    pub(super) parent: Option<SpanId>,
    pub(super) trace_state: Option<Box<str>>,
    pub(super) name: Box<str>,
    pub(super) kind: Kind,
    pub(super) start_unix_nanos: u64,
    pub(super) end_unix_nanos: u64,
    pub(super) attributes: Vec<(Cow<'static, str>, Value)>,
    pub(super) error: bool,
}

// 112: ids (16 + 8 + 9), the two optional or boxed strings (16 each), the times (8 each), the
// attribute vector (24) and two one-byte tags, padded to 8.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Span>() == 112);
