//! The OTLP log messages (`opentelemetry/proto/logs/v1/logs.proto` and
//! `collector/logs/v1/logs_service.proto`), only the fields podgate sends, and the encoding of a
//! batch of access log [`Record`]s.
//!
//! The encoder reads nothing but the record, so it can carry only what the snapshot's policy let
//! the record copy, and it applies the policy's actions again for the fields the record keeps
//! for the line writer: a dropped field is absent, a redacted one reads `[redacted]`, and
//! `client_ip` is masked as the JSON line masks it. Attribute names follow the OpenTelemetry HTTP
//! semantic conventions where one exists and the `podgate.*` names of the spans otherwise.
//!
//! The messages are `pub` so a collector in a test can decode what the exporter sends.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;

use super::Record;
use super::policy::{Action, Field, REDACTED};
use crate::observe::otlp::common::{
    self, AnyValue, ArrayValue, InstrumentationScope, KeyValue, Resource, any_value,
};

/// `ExportLogsServiceRequest`: the body of a `POST /v1/logs`.
#[derive(Clone, PartialEq, Message)]
pub struct ExportLogsServiceRequest {
    /// One entry per resource; podgate sends one.
    #[prost(message, repeated, tag = "1")]
    pub resource_logs: Vec<ResourceLogs>,
}

/// Log records of one resource.
#[derive(Clone, PartialEq, Message)]
pub struct ResourceLogs {
    /// Who produced the records.
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    /// The records, grouped by instrumentation scope.
    #[prost(message, repeated, tag = "2")]
    pub scope_logs: Vec<ScopeLogs>,
}

/// Log records of one instrumentation scope.
#[derive(Clone, PartialEq, Message)]
pub struct ScopeLogs {
    /// The scope.
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    /// The records.
    #[prost(message, repeated, tag = "2")]
    pub log_records: Vec<LogRecord>,
}

/// One log record: an access log line.
#[derive(Clone, PartialEq, Message)]
pub struct LogRecord {
    /// When the request finished, nanoseconds since the Unix epoch; `0` when the policy drops or
    /// redacts `time`.
    #[prost(fixed64, tag = "1")]
    pub time_unix_nano: u64,
    /// `9` info, `13` warn, `17` error.
    #[prost(int32, tag = "2")]
    pub severity_number: i32,
    /// `INFO`, `WARN` or `ERROR`.
    #[prost(string, tag = "3")]
    pub severity_text: String,
    /// A short summary built from the kept `method`, `path` and `status`.
    #[prost(message, optional, tag = "5")]
    pub body: Option<AnyValue>,
    /// What the policy keeps of the line.
    #[prost(message, repeated, tag = "6")]
    pub attributes: Vec<KeyValue>,
    /// W3C trace flags: `1` when the request's trace was sampled.
    #[prost(fixed32, tag = "8")]
    pub flags: u32,
    /// 16 bytes, empty when the request was not traced.
    #[prost(bytes = "vec", tag = "9")]
    pub trace_id: Vec<u8>,
    /// 8 bytes: the proxy's server span of the request, empty when it was not traced.
    #[prost(bytes = "vec", tag = "10")]
    pub span_id: Vec<u8>,
    /// Equal to `time_unix_nano`: the record is exported as it is observed.
    #[prost(fixed64, tag = "11")]
    pub observed_time_unix_nano: u64,
    /// `podgate.access_log`, so a backend can select these records.
    #[prost(string, tag = "12")]
    pub event_name: String,
}

const INFO: (i32, &str) = (9, "INFO");
const WARN: (i32, &str) = (13, "WARN");
const ERROR: (i32, &str) = (17, "ERROR");

/// The attribute a field is written as; `time` is the record's timestamp, not an attribute.
fn key(field: Field) -> Option<&'static str> {
    Some(match field {
        Field::Time => return None,
        Field::RequestId => "podgate.request.id",
        Field::EntryPoint => "podgate.entry_point",
        Field::Tenant => "podgate.tenant",
        Field::App => "podgate.app",
        Field::Router => "podgate.router",
        Field::Service => "podgate.service",
        Field::Revision => "podgate.revision",
        Field::Server => "podgate.upstream.address",
        Field::Method => "http.request.method",
        Field::Host => "server.address",
        Field::Path => "url.path",
        Field::Query => "url.query",
        Field::Proto => "network.protocol.version",
        Field::Status => "http.response.status_code",
        Field::BytesIn => "http.request.body.size",
        Field::BytesOut => "http.response.body.size",
        Field::DurationMs => "podgate.duration_ms",
        Field::UpstreamDurationMs => "podgate.upstream.duration_ms",
        Field::ClientIp => "client.address",
        Field::TlsVersion => "tls.protocol.version",
        Field::Sni => "tls.client.server_name",
        Field::RetryAttempts => "podgate.retry_attempts",
        Field::Origin => "podgate.origin",
        Field::Reason => "podgate.reason",
        Field::UserAgent => "user_agent.original",
        Field::Referer => "http.request.header.referer",
    })
}

fn int(value: u64) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::Int(
            i64::try_from(value).unwrap_or(i64::MAX),
        )),
    }
}

/// Milliseconds with microsecond precision, cut (not rounded) as the JSON line prints them.
fn millis(duration: std::time::Duration) -> AnyValue {
    let micros = duration.as_micros();
    let whole = u32::try_from(micros / 1000).unwrap_or(u32::MAX);
    let fraction = u32::try_from(micros % 1000).unwrap_or_default();
    AnyValue {
        value: Some(any_value::Value::Double(
            f64::from(whole) + f64::from(fraction) / 1000.0,
        )),
    }
}

fn list<'a>(values: impl IntoIterator<Item = &'a str>) -> AnyValue {
    AnyValue {
        value: Some(any_value::Value::Array(ArrayValue {
            values: values.into_iter().map(AnyValue::string).collect(),
        })),
    }
}

/// `HTTP/1.1` is `1.1`, `HTTP/2.0` is `2`.
fn protocol_version(proto: &str) -> &str {
    match proto.strip_prefix("HTTP/").unwrap_or(proto) {
        "2.0" => "2",
        "3.0" => "3",
        version => version,
    }
}

/// The value of `field` in `record`, when the request has one. `action` is `Keep` or `Mask`.
fn value(record: &Record, field: Field, action: Action) -> Option<AnyValue> {
    let text = |value: Option<&str>| value.map(AnyValue::string);
    match field {
        Field::Time => None,
        Field::RequestId => text(Some(&record.request_id)),
        Field::EntryPoint => text(Some(&record.entry_point)),
        Field::Tenant => text(record.tenant.as_deref()),
        Field::App => text(record.app.as_deref()),
        Field::Router => text(record.router.as_deref()),
        Field::Service => text(record.service.as_deref()),
        Field::Revision => text(record.revision.as_deref()),
        Field::Server => text(record.server.map(|addr| addr.to_string()).as_deref()),
        Field::Method => text(Some(&record.method)),
        Field::Host => text(record.host.as_deref()),
        Field::Path => text(Some(&record.path)),
        Field::Query => text(record.query.as_deref()),
        Field::Proto => text(Some(protocol_version(record.proto))),
        Field::Status => Some(int(u64::from(record.status))),
        Field::BytesIn => Some(int(record.bytes_in)),
        Field::BytesOut => Some(int(record.bytes_out)),
        Field::DurationMs => Some(millis(record.duration)),
        Field::UpstreamDurationMs => record.upstream.map(millis),
        Field::ClientIp => text(record.client_ip_text(action).as_deref()),
        Field::TlsVersion => text(
            record
                .tls_version
                .as_deref()
                .map(|version| version.strip_prefix("TLSv").unwrap_or(version)),
        ),
        Field::Sni => text(record.sni.as_deref()),
        Field::RetryAttempts => Some(int(u64::from(record.retry_attempts))),
        Field::Origin => text(Some(record.origin)),
        Field::Reason => text(record.reason),
        Field::UserAgent => text(record.user_agent.as_deref()),
        Field::Referer => record.referer.as_deref().map(|referer| list([referer])),
    }
}

/// How serious the request was, from the status the policy lets the record show. A status the
/// policy drops or redacts is not hinted at: the record is an `INFO`.
fn severity(record: &Record) -> (i32, &'static str) {
    if record.policy.action(Field::Status) != Action::Keep {
        return INFO;
    }
    match record.status {
        0 | 500.. => ERROR,
        400..=499 => WARN,
        _ => INFO,
    }
}

/// `GET /p 200`, from the kept method, path and status; `request` when none is kept. A redacted
/// part reads `[redacted]`.
fn body(record: &Record) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(3);
    for (field, value) in [
        (Field::Method, record.method.to_string()),
        (Field::Path, record.path.to_string()),
        (Field::Status, record.status.to_string()),
    ] {
        match record.policy.action(field) {
            Action::Drop => {}
            Action::Redact => parts.push(REDACTED.to_owned()),
            Action::Keep | Action::Mask(_) => parts.push(value),
        }
    }
    if parts.is_empty() {
        "request".to_owned()
    } else {
        parts.join(" ")
    }
}

fn nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or_default()
}

fn convert(record: &Record) -> LogRecord {
    let policy = &record.policy;
    let mut attributes = Vec::with_capacity(32);
    for field in Field::ALL {
        let Some(name) = key(field) else { continue };
        match policy.action(field) {
            Action::Drop => {}
            Action::Redact => attributes.push(KeyValue::text(name, REDACTED)),
            action @ (Action::Keep | Action::Mask(_)) => {
                if let Some(value) = value(record, field, action) {
                    attributes.push(KeyValue {
                        key: name.to_owned(),
                        value: Some(value),
                    });
                }
            }
        }
    }
    for (prefix, headers) in [
        ("http.request.header.", &record.request_headers),
        ("http.response.header.", &record.response_headers),
    ] {
        for (name, value) in headers {
            let name = format!("{prefix}{name}");
            // The referer field is the one header the line also has as a field of its own.
            if attributes.iter().all(|seen| seen.key != name) {
                attributes.push(KeyValue {
                    key: name,
                    value: Some(list([&**value])),
                });
            }
        }
    }
    if !record.truncated.is_empty() {
        attributes.push(KeyValue {
            key: "podgate.truncated".to_owned(),
            value: Some(list(record.truncated.iter().copied())),
        });
    }
    let (severity_number, severity_text) = severity(record);
    let time = if policy.action(Field::Time) == Action::Keep {
        nanos(record.time)
    } else {
        0
    };
    let (trace_id, span_id, flags) = record.trace.map_or((Vec::new(), Vec::new(), 0), |ids| {
        (
            ids.trace_id.to_vec(),
            ids.span_id.to_vec(),
            u32::from(ids.sampled),
        )
    });
    LogRecord {
        time_unix_nano: time,
        severity_number,
        severity_text: severity_text.to_owned(),
        body: Some(AnyValue::string(&body(record))),
        attributes,
        flags,
        trace_id,
        span_id,
        observed_time_unix_nano: time,
        event_name: "podgate.access_log".to_owned(),
    }
}

/// The request body for `batch`, all attributed to `service_name`.
#[must_use]
pub(super) fn encode(service_name: &str, batch: &[Arc<Record>]) -> Vec<u8> {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(common::resource(service_name)),
            scope_logs: vec![ScopeLogs {
                scope: Some(common::scope()),
                log_records: batch.iter().map(|record| convert(record)).collect(),
            }],
        }],
    }
    .encode_to_vec()
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::observe::tracing::Ids;

    fn decode(batch: &[Arc<Record>]) -> LogRecord {
        let request =
            ExportLogsServiceRequest::decode(encode("edge", batch).as_slice()).expect("decodes");
        let resource = request.resource_logs.first().expect("one resource");
        let service = resource
            .resource
            .as_ref()
            .and_then(|resource| resource.attributes.first())
            .expect("service.name");
        assert_eq!(service.key, "service.name");
        resource
            .scope_logs
            .first()
            .and_then(|scope| scope.log_records.first())
            .expect("one record")
            .clone()
    }

    fn attributes(record: &LogRecord) -> BTreeMap<&str, &any_value::Value> {
        record
            .attributes
            .iter()
            .map(|pair| {
                (
                    pair.key.as_str(),
                    pair.value
                        .as_ref()
                        .and_then(|value| value.value.as_ref())
                        .expect("a value"),
                )
            })
            .collect()
    }

    fn string(value: &str) -> any_value::Value {
        any_value::Value::String(value.to_owned())
    }

    #[test]
    fn otlp_logs_encoding_round_trips() {
        let mut record = Record::sample(&json!({}));
        record.time = UNIX_EPOCH + std::time::Duration::from_secs(5);
        record.trace = Some(Ids {
            trace_id: [1; 16],
            span_id: [2; 8],
            sampled: true,
        });
        let got = decode(&[Arc::new(record)]);
        assert_eq!(got.time_unix_nano, 5_000_000_000);
        assert_eq!(got.observed_time_unix_nano, 5_000_000_000);
        assert_eq!(got.trace_id, vec![1; 16]);
        assert_eq!(got.span_id, vec![2; 8]);
        assert_eq!(got.flags, 1);
        assert_eq!(got.event_name, "podgate.access_log");
        assert_eq!(got.severity_text, "INFO");
        assert_eq!(got.body, Some(AnyValue::string("GET / 200")));
        let attributes = attributes(&got);
        assert_eq!(attributes["http.request.method"], &string("GET"));
        assert_eq!(attributes["url.path"], &string("/"));
        assert_eq!(
            attributes["http.response.status_code"],
            &any_value::Value::Int(200)
        );
        assert_eq!(attributes["podgate.tenant"], &string("t"));
        assert_eq!(
            attributes["podgate.upstream.address"],
            &string("127.0.0.1:9000")
        );
        assert_eq!(attributes["network.protocol.version"], &string("1.1"));
        assert_eq!(
            attributes["podgate.duration_ms"],
            &any_value::Value::Double(3.0)
        );
        assert_eq!(attributes["client.address"], &string("203.0.113.7"));
        assert!(
            !attributes.contains_key("url.query"),
            "optional fields are off"
        );

        let untraced = decode(&[Arc::new(Record::sample(&json!({})))]);
        assert!(untraced.trace_id.is_empty() && untraced.span_id.is_empty());
        assert_eq!(untraced.flags, 0);
    }

    #[test]
    fn otlp_logs_severity_follows_status() {
        for (status, wanted) in [
            (0, 17),
            (200, 9),
            (302, 9),
            (404, 13),
            (499, 13),
            (500, 17),
            (503, 17),
        ] {
            let mut record = Record::sample(&json!({}));
            record.status = status;
            assert_eq!(
                decode(&[Arc::new(record)]).severity_number,
                wanted,
                "{status}"
            );
        }
        let mut hidden = Record::sample(&json!({"fields": {"names": {"status": "drop"}}}));
        hidden.status = 503;
        let got = decode(&[Arc::new(hidden)]);
        assert_eq!(got.severity_number, 9, "a dropped status is not hinted at");
        assert_eq!(got.body, Some(AnyValue::string("GET /")));
    }

    #[test]
    fn otlp_logs_policy_actions_apply() {
        let mut record = Record::sample(&json!({
            "fields": {"names": {
                "tenant": "drop",
                "app": "redact",
                "time": "redact",
                "path": "redact",
                "client_ip": {"action": "mask", "ipv4_bits": 16},
                "user_agent": "keep",
            }},
            "headers": {"default": "keep"},
        }));
        record.user_agent = Some("probe/1".into());
        record.request_headers = vec![
            ("authorization".into(), "[redacted]".into()),
            ("x-a".into(), "1".into()),
        ];
        record.truncated = vec!["path"];
        let got = decode(&[Arc::new(record)]);
        let attributes = attributes(&got);
        assert!(!attributes.contains_key("podgate.tenant"), "dropped");
        assert_eq!(attributes["podgate.app"], &string("[redacted]"));
        assert_eq!(attributes["url.path"], &string("[redacted]"));
        assert_eq!(attributes["client.address"], &string("203.0.0.0"));
        assert_eq!(attributes["user_agent.original"], &string("probe/1"));
        assert_eq!(got.time_unix_nano, 0, "a redacted time is not exported");
        assert_eq!(got.observed_time_unix_nano, 0);
        assert_eq!(got.body, Some(AnyValue::string("GET [redacted] 200")));
        assert_eq!(
            attributes["http.request.header.authorization"],
            &any_value::Value::Array(ArrayValue {
                values: vec![AnyValue::string("[redacted]")]
            })
        );
        assert!(attributes.contains_key("http.request.header.x-a"));
        assert!(attributes.contains_key("podgate.truncated"));
    }
}
