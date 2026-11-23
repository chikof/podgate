//! The OTLP metrics messages (`opentelemetry/proto/metrics/v1/metrics.proto` and
//! `collector/metrics/v1/metrics_service.proto`), only the fields podgate sends, and the encoding
//! of scraped [`Family`]s.
//!
//! Counters are cumulative monotonic `Sum`s, gauges `Gauge`s and the latency series explicit-bounds
//! `Histogram`s with cumulative temporality. The messages are `pub` so a collector in a test can
//! decode what the exporter sends.

use prost::Message;

use super::scrape::{Family, Kind, Number, Value};
use crate::observe::otlp::common::{self, AnyValue, KeyValue, Resource};

/// `AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE`.
const CUMULATIVE: i32 = 2;

/// `ExportMetricsServiceRequest`: the body of a `POST /v1/metrics`.
#[derive(Clone, PartialEq, Message)]
pub struct ExportMetricsServiceRequest {
    /// One entry per resource; podgate sends one.
    #[prost(message, repeated, tag = "1")]
    pub resource_metrics: Vec<ResourceMetrics>,
}

/// `ExportMetricsServiceResponse`: what a collector answers an export with.
#[derive(Clone, PartialEq, Message)]
pub struct ExportMetricsServiceResponse {
    /// Present when the collector kept only some of the data points.
    #[prost(message, optional, tag = "1")]
    pub partial_success: Option<ExportMetricsPartialSuccess>,
}

/// The data points a collector refused out of an export it otherwise took.
#[derive(Clone, PartialEq, Message)]
pub struct ExportMetricsPartialSuccess {
    /// How many data points were refused.
    #[prost(int64, tag = "1")]
    pub rejected_data_points: i64,
    /// Why, for a human.
    #[prost(string, tag = "2")]
    pub error_message: String,
}

/// Metrics of one resource.
#[derive(Clone, PartialEq, Message)]
pub struct ResourceMetrics {
    /// Who produced the metrics.
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    /// The metrics, grouped by instrumentation scope.
    #[prost(message, repeated, tag = "2")]
    pub scope_metrics: Vec<ScopeMetrics>,
}

/// Metrics of one instrumentation scope.
#[derive(Clone, PartialEq, Message)]
pub struct ScopeMetrics {
    /// The scope.
    #[prost(message, optional, tag = "1")]
    pub scope: Option<common::InstrumentationScope>,
    /// The metrics.
    #[prost(message, repeated, tag = "2")]
    pub metrics: Vec<Metric>,
}

/// One metric: a name and its data points.
#[derive(Clone, PartialEq, Message)]
pub struct Metric {
    /// The name, as Prometheus names it.
    #[prost(string, tag = "1")]
    pub name: String,
    /// The `# HELP` text.
    #[prost(string, tag = "2")]
    pub description: String,
    /// Which kind of data it holds.
    #[prost(oneof = "metric::Data", tags = "5, 7, 9")]
    pub data: Option<metric::Data>,
}

/// The kinds of [`Metric`] data.
pub mod metric {
    use prost::Oneof;

    use super::{Gauge, Histogram, Sum};

    /// Gauge, sum or histogram.
    #[derive(Clone, PartialEq, Oneof)]
    pub enum Data {
        /// A value that goes up and down.
        #[prost(message, tag = "5")]
        Gauge(Gauge),
        /// A cumulative counter.
        #[prost(message, tag = "7")]
        Sum(Sum),
        /// A latency distribution.
        #[prost(message, tag = "9")]
        Histogram(Histogram),
    }
}

/// A value that goes up and down.
#[derive(Clone, PartialEq, Message)]
pub struct Gauge {
    /// One per label set.
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<NumberDataPoint>,
}

/// A cumulative counter.
#[derive(Clone, PartialEq, Message)]
pub struct Sum {
    /// One per label set.
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<NumberDataPoint>,
    /// Always cumulative (2).
    #[prost(int32, tag = "2")]
    pub aggregation_temporality: i32,
    /// Always true: a counter only goes up.
    #[prost(bool, tag = "3")]
    pub is_monotonic: bool,
}

/// A latency distribution with explicit bounds.
#[derive(Clone, PartialEq, Message)]
pub struct Histogram {
    /// One per label set.
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<HistogramDataPoint>,
    /// Always cumulative (2).
    #[prost(int32, tag = "2")]
    pub aggregation_temporality: i32,
}

/// One value of a gauge or a sum.
#[derive(Clone, PartialEq, Message)]
pub struct NumberDataPoint {
    /// The label set.
    #[prost(message, repeated, tag = "7")]
    pub attributes: Vec<KeyValue>,
    /// When the counting began: the start of the process.
    #[prost(fixed64, tag = "2")]
    pub start_time_unix_nano: u64,
    /// When the value was read.
    #[prost(fixed64, tag = "3")]
    pub time_unix_nano: u64,
    /// The value.
    #[prost(oneof = "number_data_point::Value", tags = "4, 6")]
    pub value: Option<number_data_point::Value>,
}

/// The kinds of [`NumberDataPoint`] value.
pub mod number_data_point {
    use prost::Oneof;

    /// An integer when the text was one, else a float.
    #[derive(Clone, Copy, PartialEq, Oneof)]
    pub enum Value {
        /// A float.
        #[prost(double, tag = "4")]
        AsDouble(f64),
        /// An integer.
        #[prost(sfixed64, tag = "6")]
        AsInt(i64),
    }
}

/// One distribution.
#[derive(Clone, PartialEq, Message)]
pub struct HistogramDataPoint {
    /// The label set.
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    /// When the counting began: the start of the process.
    #[prost(fixed64, tag = "2")]
    pub start_time_unix_nano: u64,
    /// When the buckets were read.
    #[prost(fixed64, tag = "3")]
    pub time_unix_nano: u64,
    /// The number of observations.
    #[prost(fixed64, tag = "4")]
    pub count: u64,
    /// The sum of the observations.
    #[prost(double, optional, tag = "5")]
    pub sum: Option<f64>,
    /// Observations per bucket: one more than there are bounds, the last is the overflow.
    #[prost(fixed64, repeated, tag = "6")]
    pub bucket_counts: Vec<u64>,
    /// The upper bounds of every bucket but the last.
    #[prost(double, repeated, tag = "7")]
    pub explicit_bounds: Vec<f64>,
}

fn attributes(labels: &[(String, String)]) -> Vec<KeyValue> {
    labels
        .iter()
        .map(|(key, value)| KeyValue {
            key: key.clone(),
            value: Some(AnyValue::string(value)),
        })
        .collect()
}

fn number_points(family: &Family, start: u64, now: u64) -> Vec<NumberDataPoint> {
    family
        .points
        .iter()
        .filter_map(|point| {
            let Value::Number(number) = &point.value else {
                return None;
            };
            Some(NumberDataPoint {
                attributes: attributes(&point.labels),
                start_time_unix_nano: start,
                time_unix_nano: now,
                value: Some(match *number {
                    Number::Int(int) => number_data_point::Value::AsInt(int),
                    Number::Double(double) => number_data_point::Value::AsDouble(double),
                }),
            })
        })
        .collect()
}

fn histogram_points(family: &Family, start: u64, now: u64) -> Vec<HistogramDataPoint> {
    family
        .points
        .iter()
        .filter_map(|point| {
            let Value::Histogram(histogram) = &point.value else {
                return None;
            };
            Some(HistogramDataPoint {
                attributes: attributes(&point.labels),
                start_time_unix_nano: start,
                time_unix_nano: now,
                count: histogram.count,
                sum: Some(histogram.sum),
                bucket_counts: histogram.counts.clone(),
                explicit_bounds: histogram.bounds.clone(),
            })
        })
        .collect()
}

/// The OTLP metric of each family: `start` is when the process began counting, `now` when the
/// scrape was read, both in unix nanoseconds.
pub(super) fn metrics(families: &[Family], start: u64, now: u64) -> Vec<Metric> {
    families
        .iter()
        .map(|family| Metric {
            name: family.name.clone(),
            description: family.help.clone(),
            data: Some(match family.kind {
                Kind::Counter => metric::Data::Sum(Sum {
                    data_points: number_points(family, start, now),
                    aggregation_temporality: CUMULATIVE,
                    is_monotonic: true,
                }),
                Kind::Gauge => metric::Data::Gauge(Gauge {
                    data_points: number_points(family, start, now),
                }),
                Kind::Histogram => metric::Data::Histogram(Histogram {
                    data_points: histogram_points(family, start, now),
                    aggregation_temporality: CUMULATIVE,
                }),
            }),
        })
        .collect()
}

/// The request body for `metrics`, all attributed to `service_name`.
#[must_use]
pub(super) fn encode(service_name: &str, metrics: &[Metric]) -> Vec<u8> {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(common::resource(service_name)),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(common::scope()),
                metrics: metrics.to_vec(),
            }],
        }],
    }
    .encode_to_vec()
}

#[cfg(test)]
mod test {
    use super::super::scrape::parse;
    use super::*;

    const TEXT: &str = "# HELP podgate_r_total Requests.\n# TYPE podgate_r_total counter\n\
        podgate_r_total{router=\"a\",code_class=\"2xx\"} 5\n\
        # HELP podgate_up Up.\n# TYPE podgate_up gauge\npodgate_up{server=\"s\"} 1\n\
        # HELP podgate_d Latency.\n# TYPE podgate_d histogram\n\
        podgate_d_bucket{router=\"a\",le=\"0.005\"} 2\n\
        podgate_d_bucket{router=\"a\",le=\"+Inf\"} 3\n\
        podgate_d_sum{router=\"a\"} 0.5\npodgate_d_count{router=\"a\"} 3\n";

    fn decoded() -> Vec<Metric> {
        let parsed = parse(TEXT);
        assert_eq!(parsed.skipped, 0);
        let sent = metrics(&parsed.families, 10, 20);
        let body = encode("edge", &sent);
        let request = ExportMetricsServiceRequest::decode(body.as_slice()).expect("decodes");
        let resource = request.resource_metrics.first().expect("one resource");
        let named = resource.resource.as_ref().expect("resource");
        assert_eq!(
            named.attributes,
            vec![KeyValue::text("service.name", "edge")]
        );
        resource
            .scope_metrics
            .first()
            .expect("one scope")
            .metrics
            .clone()
    }

    #[test]
    fn otlp_metrics_encode_counters_as_cumulative_monotonic_sums() {
        let all = decoded();
        let counter = all.first().expect("counter");
        assert_eq!(counter.name, "podgate_r_total");
        assert_eq!(counter.description, "Requests.");
        let Some(metric::Data::Sum(sum)) = &counter.data else {
            panic!("a counter is a sum: {counter:?}");
        };
        assert!(sum.is_monotonic);
        assert_eq!(sum.aggregation_temporality, 2);
        let point = sum.data_points.first().expect("one point");
        assert_eq!(point.value, Some(number_data_point::Value::AsInt(5)));
        assert_eq!((point.start_time_unix_nano, point.time_unix_nano), (10, 20));
        assert_eq!(
            point.attributes,
            vec![
                KeyValue::text("router", "a"),
                KeyValue::text("code_class", "2xx")
            ]
        );
    }

    #[test]
    fn otlp_metrics_encode_gauges_and_histograms() {
        let all = decoded();
        let Some(metric::Data::Gauge(gauge)) = &all[1].data else {
            panic!("a gauge: {:?}", all[1]);
        };
        assert_eq!(gauge.data_points.len(), 1);
        let Some(metric::Data::Histogram(histogram)) = &all[2].data else {
            panic!("a histogram: {:?}", all[2]);
        };
        assert_eq!(histogram.aggregation_temporality, 2);
        let point = histogram.data_points.first().expect("one point");
        assert_eq!(point.count, 3);
        assert_eq!(point.sum, Some(0.5));
        assert_eq!(point.bucket_counts, vec![2, 1]);
        assert_eq!(point.explicit_bounds, vec![0.005]);
        assert_eq!(point.attributes, vec![KeyValue::text("router", "a")]);
    }
}
