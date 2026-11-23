//! The OTLP messages every signal shares (`opentelemetry/proto/common/v1/common.proto`,
//! `resource/v1/resource.proto` and the `partial_success` answer of the collector services), only
//! the fields podgate uses. A signal adds its own `ExportXServiceRequest`, its data messages and
//! its encoder.
//!
//! The messages are `pub` so a collector in a test can decode what an exporter sends.

use prost::Message;

/// The producer of telemetry.
#[derive(Clone, PartialEq, Message)]
pub struct Resource {
    /// `service.name` and friends.
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
}

/// The library that made the telemetry.
#[derive(Clone, PartialEq, Message)]
pub struct InstrumentationScope {
    /// The library's name.
    #[prost(string, tag = "1")]
    pub name: String,
    /// Its version.
    #[prost(string, tag = "2")]
    pub version: String,
}

/// An attribute.
#[derive(Clone, PartialEq, Message)]
pub struct KeyValue {
    /// Its name.
    #[prost(string, tag = "1")]
    pub key: String,
    /// Its value.
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

/// An attribute value.
#[derive(Clone, PartialEq, Message)]
pub struct AnyValue {
    /// Which kind it is.
    #[prost(oneof = "any_value::Value", tags = "1, 3, 4, 5")]
    pub value: Option<any_value::Value>,
}

/// The kinds of [`AnyValue`].
pub mod any_value {
    use prost::Oneof;

    use super::ArrayValue;

    /// A string, an integer, a floating point number or a list.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Value {
        /// A string.
        #[prost(string, tag = "1")]
        String(String),
        /// An integer.
        #[prost(int64, tag = "3")]
        Int(i64),
        /// A floating point number.
        #[prost(double, tag = "4")]
        Double(f64),
        /// A list.
        #[prost(message, tag = "5")]
        Array(ArrayValue),
    }
}

/// A list of values.
#[derive(Clone, PartialEq, Message)]
pub struct ArrayValue {
    /// The values.
    #[prost(message, repeated, tag = "1")]
    pub values: Vec<AnyValue>,
}

/// What every collector service answers an export with, for the one field podgate reads:
/// `ExportTraceServiceResponse`, `ExportMetricsServiceResponse` and `ExportLogsServiceResponse`
/// are wire-identical in it.
#[derive(Clone, PartialEq, Message)]
pub struct PartialSuccessResponse {
    /// Present when the collector kept only some of the items.
    #[prost(message, optional, tag = "1")]
    pub partial_success: Option<PartialSuccess>,
}

/// The items a collector refused out of an export it otherwise took: spans, data points or log
/// records, by signal.
#[derive(Clone, PartialEq, Message)]
pub struct PartialSuccess {
    /// How many items were refused.
    #[prost(int64, tag = "1")]
    pub rejected: i64,
    /// Why, for a human.
    #[prost(string, tag = "2")]
    pub error_message: String,
}

impl AnyValue {
    /// A string value.
    #[must_use]
    pub fn string(value: &str) -> Self {
        Self {
            value: Some(any_value::Value::String(value.to_owned())),
        }
    }
}

impl KeyValue {
    /// A string attribute.
    #[must_use]
    pub fn text(key: &str, value: &str) -> Self {
        Self {
            key: key.to_owned(),
            value: Some(AnyValue::string(value)),
        }
    }

    /// An integer attribute.
    #[must_use]
    pub fn int(key: &str, value: i64) -> Self {
        Self {
            key: key.to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::Int(value)),
            }),
        }
    }

    /// A floating point attribute.
    #[must_use]
    pub fn double(key: &str, value: f64) -> Self {
        Self {
            key: key.to_owned(),
            value: Some(AnyValue {
                value: Some(any_value::Value::Double(value)),
            }),
        }
    }
}

/// The resource of every export: the one attribute `service.name`.
#[must_use]
pub fn resource(service_name: &str) -> Resource {
    Resource {
        attributes: vec![KeyValue::text("service.name", service_name)],
    }
}

/// The instrumentation scope of every export: podgate and its version.
#[must_use]
pub fn scope() -> InstrumentationScope {
    InstrumentationScope {
        name: "podgate".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn otlp_any_value_double_round_trips() {
        let pair = KeyValue::double("http.server.request.duration", 0.125);
        let decoded = KeyValue::decode(pair.encode_to_vec().as_slice()).expect("decodes");
        assert_eq!(decoded, pair);
        assert_eq!(
            decoded.value.and_then(|value| value.value),
            Some(any_value::Value::Double(0.125))
        );
    }

    #[test]
    fn otlp_text_and_int_attributes_round_trip() {
        for pair in [KeyValue::text("a", "b"), KeyValue::int("n", -3)] {
            let decoded = KeyValue::decode(pair.encode_to_vec().as_slice()).expect("decodes");
            assert_eq!(decoded, pair);
        }
    }

    #[test]
    fn otlp_resource_names_the_service() {
        let named = resource("edge");
        assert_eq!(
            named.attributes,
            vec![KeyValue::text("service.name", "edge")]
        );
        assert_eq!(scope().name, "podgate");
    }
}
