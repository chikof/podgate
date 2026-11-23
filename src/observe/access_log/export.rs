//! Access logs over OTLP: `OTEL_LOGS_EXPORTER` and the background service that sends
//! the access log's second queue to the collector on the shared transport
//! (`crate::observe::otlp`).
//!
//! The queue is another consumer of the records the line writer gets, bounded the same way: when
//! it is full the oldest record is dropped and counted, so a slow or dead collector costs
//! records and never a request's time. Batching, the timeout, the retries and the message limit
//! are the shared exporter's.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use super::sink::{AccessLog, Lane};
use super::{Record, otlp};
use crate::config::ConfigError;
use crate::observe::otlp::collector::{Collector, Signal, bad, present};
use crate::observe::otlp::{BatchExporter, Feed, Transport};

/// Records per request, and the queue length that wakes the exporter before its flush interval.
pub(super) const BATCH: usize = 512;

/// `OTEL_LOGS_EXPORTER`: operator-only, never from a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogsExporter {
    /// Access log records go to the line sink only.
    #[default]
    None,
    /// Every record also goes to the OTLP collector.
    Otlp,
}

impl LogsExporter {
    /// Reads `OTEL_LOGS_EXPORTER` through `lookup`. The collector comes from `collector`.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] naming the variable: a value other than `none` and `otlp`, or `otlp`
    /// with no `OTEL_EXPORTER_OTLP_ENDPOINT`.
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
        collector: &Collector,
    ) -> Result<Self, ConfigError> {
        match present(&lookup, "OTEL_LOGS_EXPORTER")?.as_deref() {
            None | Some("none") => Ok(Self::None),
            Some("otlp") if collector.endpoint.is_some() => Ok(Self::Otlp),
            Some("otlp") => Err(bad(
                "OTEL_LOGS_EXPORTER",
                "is `otlp` but OTEL_EXPORTER_OTLP_ENDPOINT is not set: podgate has no default \
                 collector address",
            )),
            Some(_) => Err(bad(
                "OTEL_LOGS_EXPORTER",
                "must be `none` or `otlp`: no other exporter is built",
            )),
        }
    }
}

/// The access log's OTLP queue as a [`Feed`].
#[derive(Debug)]
struct LogFeed {
    lane: Arc<Lane>,
    service_name: Box<str>,
}

#[async_trait]
impl Feed for LogFeed {
    type Item = Arc<Record>;
    const NOUN: &'static str = "log records";
    const BATCH: usize = BATCH;

    fn take(&self, max: usize) -> Vec<Arc<Record>> {
        self.lane.take(max)
    }

    async fn ready(&self) {
        self.lane.woken().await;
    }

    fn encode(&self, items: &[Arc<Record>]) -> Vec<u8> {
        otlp::encode(&self.service_name, items)
    }

    fn exported(&self, count: usize) {
        self.lane.delivered(count);
    }

    fn lost(&self, count: usize) {
        self.lane.lost(count);
    }
}

/// Sends the access log's OTLP queue to the collector. Register it with the server as a
/// background service.
#[derive(Debug)]
pub struct LogService(BatchExporter<LogFeed>);

impl AccessLog {
    /// The exporter draining this log's OTLP queue; `None` when the node does not export access
    /// logs (no queue was added with [`AccessLog::with_otlp`]) or has no collector.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates or the client certificate cannot be loaded.
    pub fn otlp_exporter(&self, collector: &Collector) -> Result<Option<LogService>, ConfigError> {
        let Some(lane) = &self.otlp else {
            return Ok(None);
        };
        let Some(transport) = Transport::new(collector, Signal::Logs)? else {
            return Ok(None);
        };
        let feed = LogFeed {
            lane: Arc::clone(lane),
            service_name: collector.service_name.clone(),
        };
        Ok(Some(LogService(BatchExporter::new(feed, transport))))
    }
}

#[async_trait]
impl BackgroundService for LogService {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.0.start(shutdown).await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn collector(vars: &[(&str, &str)]) -> Collector {
        Collector::from_lookup(&|name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
        .expect("collector settings")
    }

    fn parse(vars: &[(&str, &str)], exporter: Option<&str>) -> Result<LogsExporter, ConfigError> {
        let collector = collector(vars);
        LogsExporter::from_lookup(
            |name| {
                (name == "OTEL_LOGS_EXPORTER")
                    .then_some(exporter)
                    .flatten()
                    .map(str::to_owned)
            },
            &collector,
        )
    }

    #[test]
    fn otlp_logs_exporter_parse() {
        let endpoint = [("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")];
        assert_eq!(parse(&endpoint, None).expect("unset"), LogsExporter::None);
        assert_eq!(
            parse(&endpoint, Some("none")).expect("none"),
            LogsExporter::None
        );
        assert_eq!(
            parse(&endpoint, Some("otlp")).expect("otlp"),
            LogsExporter::Otlp
        );
        assert_eq!(parse(&[], None).expect("unset"), LogsExporter::None);
        for bad_value in ["console", "otlp,none", "OTLP", " "] {
            let err = parse(&endpoint, Some(bad_value)).expect_err(bad_value);
            assert_eq!(err.var, "OTEL_LOGS_EXPORTER", "{bad_value}");
        }
        let err = parse(&[], Some("otlp")).expect_err("no endpoint");
        assert_eq!(err.var, "OTEL_LOGS_EXPORTER");
    }
}
