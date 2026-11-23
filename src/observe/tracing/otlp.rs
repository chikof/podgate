//! The OTLP trace messages (`opentelemetry/proto/trace/v1/trace.proto` and the types it uses),
//! only the fields podgate sends, and the encoding of a batch of finished [`Span`]s.
//!
//! The messages are `pub` so a collector in a test can decode what the exporter sends.

use prost::Message;

use super::super::otlp::common;
use super::span::{Kind, Span, Value};

pub use super::super::otlp::common::{
    AnyValue, ArrayValue, InstrumentationScope, KeyValue, Resource, any_value,
};

/// `ExportTraceServiceRequest`: the body of a `POST /v1/traces`.
#[derive(Clone, PartialEq, Message)]
pub struct ExportTraceServiceRequest {
    /// One entry per resource; podgate sends one.
    #[prost(message, repeated, tag = "1")]
    pub resource_spans: Vec<ResourceSpans>,
}

/// `ExportTraceServiceResponse`: what a collector answers an export with.
#[derive(Clone, PartialEq, Message)]
pub struct ExportTraceServiceResponse {
    /// Present when the collector kept only some of the spans.
    #[prost(message, optional, tag = "1")]
    pub partial_success: Option<ExportTracePartialSuccess>,
}

/// The spans a collector refused out of an export it otherwise took.
#[derive(Clone, PartialEq, Message)]
pub struct ExportTracePartialSuccess {
    /// How many spans were refused.
    #[prost(int64, tag = "1")]
    pub rejected_spans: i64,
    /// Why, for a human.
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// Spans of one resource.
#[derive(Clone, PartialEq, Message)]
pub struct ResourceSpans {
    /// Who produced the spans.
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    /// The spans, grouped by instrumentation scope.
    #[prost(message, repeated, tag = "2")]
    pub scope_spans: Vec<ScopeSpans>,
}

/// Spans of one instrumentation scope.
#[derive(Clone, PartialEq, Message)]
pub struct ScopeSpans {
    /// The scope.
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    /// The spans.
    #[prost(message, repeated, tag = "2")]
    pub spans: Vec<OtlpSpan>,
}

/// One span.
#[derive(Clone, PartialEq, Message)]
pub struct OtlpSpan {
    /// 16 bytes.
    #[prost(bytes = "vec", tag = "1")]
    pub trace_id: Vec<u8>,
    /// 8 bytes.
    #[prost(bytes = "vec", tag = "2")]
    pub span_id: Vec<u8>,
    /// The W3C `tracestate` of the trace.
    #[prost(string, tag = "3")]
    pub trace_state: String,
    /// 8 bytes, empty for a root span.
    #[prost(bytes = "vec", tag = "4")]
    pub parent_span_id: Vec<u8>,
    /// The span name.
    #[prost(string, tag = "5")]
    pub name: String,
    /// `2` server, `3` client.
    #[prost(int32, tag = "6")]
    pub kind: i32,
    /// Start, nanoseconds since the Unix epoch.
    #[prost(fixed64, tag = "7")]
    pub start_time_unix_nano: u64,
    /// End, nanoseconds since the Unix epoch.
    #[prost(fixed64, tag = "8")]
    pub end_time_unix_nano: u64,
    /// Attributes.
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    /// Outcome.
    #[prost(message, optional, tag = "15")]
    pub status: Option<Status>,
}

/// A span's outcome.
#[derive(Clone, PartialEq, Message)]
pub struct Status {
    /// `0` unset, `2` error.
    #[prost(int32, tag = "3")]
    pub code: i32,
}

fn attribute(key: &str, value: &Value) -> KeyValue {
    match value {
        Value::Str(value) => KeyValue::text(key, value),
        Value::Int(value) => KeyValue::int(key, *value),
        Value::Strs(values) => KeyValue {
            key: key.to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::Array(ArrayValue {
                    values: values.iter().map(|value| AnyValue::string(value)).collect(),
                })),
            }),
        },
    }
}

fn convert(span: &Span) -> OtlpSpan {
    OtlpSpan {
        trace_id: span.trace_id.0.to_vec(),
        span_id: span.span_id.0.to_vec(),
        trace_state: span.trace_state.as_deref().unwrap_or_default().to_owned(),
        parent_span_id: span
            .parent
            .map(|parent| parent.0.to_vec())
            .unwrap_or_default(),
        name: span.name.to_string(),
        kind: match span.kind {
            Kind::Server => 2,
            Kind::Client => 3,
        },
        start_time_unix_nano: span.start_unix_nanos,
        end_time_unix_nano: span.end_unix_nanos,
        attributes: span
            .attributes
            .iter()
            .map(|(key, value)| attribute(key, value))
            .collect(),
        status: span.error.then_some(Status { code: 2 }),
    }
}

/// The request body for `spans`, all attributed to `service_name`.
#[must_use]
pub(super) fn encode(service_name: &str, spans: &[Span]) -> Vec<u8> {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(common::resource(service_name)),
            scope_spans: vec![ScopeSpans {
                scope: Some(common::scope()),
                spans: spans.iter().map(convert).collect(),
            }],
        }],
    }
    .encode_to_vec()
}

#[cfg(test)]
mod test {
    use super::super::context::{SpanId, TraceId};
    use super::*;

    #[test]
    fn otlp_encoding_round_trips() {
        let span = Span {
            trace_id: TraceId([1; 16]),
            span_id: SpanId([2; 8]),
            parent: Some(SpanId([3; 8])),
            trace_state: Some("a=1".into()),
            name: "GET web".into(),
            kind: Kind::Server,
            start_unix_nanos: 10,
            end_unix_nanos: 20,
            attributes: vec![
                ("http.request.method".into(), Value::Str("GET".into())),
                ("http.response.status_code".into(), Value::Int(502)),
                (
                    "http.request.header.accept".into(),
                    Value::Strs(vec!["a".into(), "b".into()]),
                ),
            ],
            error: true,
        };
        let bytes = encode("podgate", &[span]);
        let decoded = ExportTraceServiceRequest::decode(bytes.as_slice()).expect("decodes");
        let resource = decoded.resource_spans.first().expect("one resource");
        let spans = &resource.scope_spans.first().expect("one scope").spans;
        let got = spans.first().expect("one span");
        assert_eq!(got.trace_id, vec![1; 16]);
        assert_eq!(got.parent_span_id, vec![3; 8]);
        assert_eq!(got.kind, 2);
        assert_eq!(got.status, Some(Status { code: 2 }));
        assert_eq!(got.attributes.len(), 3);
        let service = resource
            .resource
            .as_ref()
            .expect("resource")
            .attributes
            .first()
            .expect("name");
        assert_eq!(service.key, "service.name");
    }
}
