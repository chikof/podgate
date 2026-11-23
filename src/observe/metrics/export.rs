//! Metrics over OTLP: every `OTEL_METRIC_EXPORT_INTERVAL` the service renders the
//! same text `GET /metrics` serves, reads it back into families and sends it to the collector on
//! the shared transport (`crate::observe::otlp`).
//!
//! Converting the scrape instead of keeping a second view of the registry means the exported
//! names, types, labels and values are the scrape's by construction, and the per-tenant series
//! cap and the `other` collapse already hold before the text exists.
//!
//! Metrics are cumulative, so a failed interval loses nothing the next one does not carry: each
//! interval makes one attempt and a failure only adds to `podgate_otlp_metrics_failed_total`. The
//! work runs on this service's task (the render and the parse on the blocking pool), never on the
//! request path.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::time::{MissedTickBehavior, interval_at};

use super::{Sources, otlp, scrape};
use crate::config::ConfigError;
use crate::observe::otlp::Transport;
use crate::observe::otlp::batch::{MAX_MESSAGE, split};
use crate::observe::otlp::collector::{Collector, Signal, bad, present};

/// The default `OTEL_METRIC_EXPORT_INTERVAL`.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// The shortest and the longest `OTEL_METRIC_EXPORT_INTERVAL`, in milliseconds.
const INTERVAL_RANGE_MS: std::ops::RangeInclusive<u64> = 100..=3_600_000;

/// Intervals whose export failed: a timeout, a connection error, a refusal, a status that asks
/// for a retry, a metric too large for one message.
static FAILED: AtomicU64 = AtomicU64::new(0);

/// Appends `podgate_otlp_metrics_failed_total`, with its value 0 when the exporter is off.
pub(super) fn render(out: &mut String) {
    // Writing to a `String` cannot fail.
    let _ = write!(
        out,
        "# HELP podgate_otlp_metrics_failed_total Metric exports that failed; the next interval carries what they held.\n\
         # TYPE podgate_otlp_metrics_failed_total counter\n\
         podgate_otlp_metrics_failed_total {}\n",
        FAILED.load(Ordering::Relaxed)
    );
}

/// `OTEL_METRICS_EXPORTER` and `OTEL_METRIC_EXPORT_INTERVAL`: operator-only, never from a
/// snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsExportConfig {
    /// The time between exports; `None` when `OTEL_METRICS_EXPORTER` is not `otlp`: nothing is
    /// exported and no task runs.
    pub interval: Option<Duration>,
}

impl MetricsExportConfig {
    /// Reads the variables through `lookup`. The collector comes from `collector`.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] naming the variable: an exporter other than `none` and `otlp`, an
    /// interval outside 100..=3600000 milliseconds, or `otlp` with no
    /// `OTEL_EXPORTER_OTLP_ENDPOINT`. The interval is checked even when the exporter is off.
    pub fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
        collector: &Collector,
    ) -> Result<Self, ConfigError> {
        let exporter = present(&lookup, "OTEL_METRICS_EXPORTER")?;
        let on = match exporter.as_deref() {
            None | Some("none") => false,
            Some("otlp") => true,
            Some(_) => {
                return Err(bad(
                    "OTEL_METRICS_EXPORTER",
                    "must be `none` or `otlp`: no other exporter is built",
                ));
            }
        };
        let mut interval = DEFAULT_INTERVAL;
        if let Some(raw) = present(&lookup, "OTEL_METRIC_EXPORT_INTERVAL")? {
            let millis: u64 = raw
                .parse()
                .ok()
                .filter(|millis| INTERVAL_RANGE_MS.contains(millis))
                .ok_or_else(|| {
                    bad(
                        "OTEL_METRIC_EXPORT_INTERVAL",
                        format!(
                            "must be milliseconds in {}..={}",
                            INTERVAL_RANGE_MS.start(),
                            INTERVAL_RANGE_MS.end()
                        ),
                    )
                })?;
            interval = Duration::from_millis(millis);
        }
        if on && collector.endpoint.is_none() {
            return Err(bad(
                "OTEL_METRICS_EXPORTER",
                "is `otlp` but OTEL_EXPORTER_OTLP_ENDPOINT is not set: podgate has no default \
                 collector address",
            ));
        }
        Ok(Self {
            interval: on.then_some(interval),
        })
    }
}

fn unix_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or_default()
}

/// Pushes the metrics to the collector on an interval. Register it with the server as a
/// background service.
#[derive(Debug)]
pub struct MetricsExportService {
    sources: Arc<Sources>,
    transport: Transport,
    service_name: Box<str>,
    interval: Duration,
    started: SystemTime,
}

impl MetricsExportService {
    /// The exporter for `config` reading `sources`; `None` when the exporter is off.
    ///
    /// # Errors
    ///
    /// A [`ConfigError`] when the root certificates or the client certificate cannot be loaded.
    pub fn new(
        sources: Sources,
        collector: &Collector,
        config: MetricsExportConfig,
    ) -> Result<Option<Self>, ConfigError> {
        let Some(interval) = config.interval else {
            return Ok(None);
        };
        let Some(transport) = Transport::new(collector, Signal::Metrics)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            sources: Arc::new(sources),
            transport,
            service_name: collector.service_name.clone(),
            interval,
            started: SystemTime::now(),
        }))
    }

    /// Renders and encodes the metrics as of now, split to the message limit. The number of
    /// metrics too large to send at all comes with it.
    fn requests(
        sources: &Sources,
        service_name: &str,
        started: SystemTime,
    ) -> (Vec<(usize, Bytes)>, usize) {
        let text = sources.render();
        let now = unix_nanos(SystemTime::now());
        let parsed = scrape::parse(&text);
        if parsed.skipped > 0 {
            tracing::warn!(
                lines = parsed.skipped,
                "metrics export: skipped lines of the exposition it could not read"
            );
        }
        let metrics = otlp::metrics(&parsed.families, unix_nanos(started), now);
        split(metrics, MAX_MESSAGE, |metrics| {
            otlp::encode(service_name, metrics)
        })
    }

    /// One export: one attempt per request. A failure is counted and logged, never retried.
    async fn export(&self) {
        let (sources, name, started) = (
            Arc::clone(&self.sources),
            self.service_name.clone(),
            self.started,
        );
        let Ok((requests, oversized)) =
            tokio::task::spawn_blocking(move || Self::requests(&sources, &name, started)).await
        else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("metrics export: rendering the metrics failed");
            return;
        };
        let mut failed = oversized > 0;
        if oversized > 0 {
            tracing::warn!(
                metrics = oversized,
                "metrics export: dropped metrics that alone are larger than the 4 MiB message limit"
            );
        }
        for (_, body) in requests {
            match self.transport.deliver(&body, 1).await {
                Ok(0) => {}
                Ok(rejected) => {
                    tracing::warn!(
                        data_points = rejected,
                        "the collector refused some data points"
                    );
                }
                Err(why) => {
                    failed = true;
                    tracing::warn!(reason = %why, "metrics export failed; the next interval carries everything");
                }
            }
        }
        if failed {
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[async_trait]
impl BackgroundService for MetricsExportService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut tick = interval_at(tokio::time::Instant::now() + self.interval, self.interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tick.tick() => {}
            }
            tokio::select! {
                _ = shutdown.changed() => break,
                () = self.export() => {}
            }
        }
        // The counts since the last interval go out once more on a planned stop.
        self.export().await;
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
        .expect("collector")
    }

    fn config(vars: &[(&str, &str)]) -> Result<MetricsExportConfig, ConfigError> {
        let collector = collector(vars);
        MetricsExportConfig::from_lookup(
            |name| {
                vars.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            },
            &collector,
        )
    }

    const ENDPOINT: (&str, &str) = ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318");

    #[test]
    fn otlp_metrics_settings_default_to_off() {
        assert_eq!(config(&[]).expect("defaults").interval, None);
        let none = config(&[("OTEL_METRICS_EXPORTER", "none"), ENDPOINT]).expect("none");
        assert_eq!(none.interval, None);
    }

    #[test]
    fn otlp_metrics_settings_read_the_interval() {
        let default = config(&[("OTEL_METRICS_EXPORTER", "otlp"), ENDPOINT]).expect("otlp");
        assert_eq!(default.interval, Some(Duration::from_secs(60)));
        let set = config(&[
            ("OTEL_METRICS_EXPORTER", "otlp"),
            ("OTEL_METRIC_EXPORT_INTERVAL", "250"),
            ENDPOINT,
        ])
        .expect("interval");
        assert_eq!(set.interval, Some(Duration::from_millis(250)));
    }

    #[test]
    fn otlp_metrics_settings_name_the_variable_that_is_wrong() {
        for (vars, var) in [
            (
                vec![("OTEL_METRICS_EXPORTER", "prometheus"), ENDPOINT],
                "OTEL_METRICS_EXPORTER",
            ),
            (
                vec![("OTEL_METRICS_EXPORTER", "otlp,console"), ENDPOINT],
                "OTEL_METRICS_EXPORTER",
            ),
            (
                vec![("OTEL_METRICS_EXPORTER", " ")],
                "OTEL_METRICS_EXPORTER",
            ),
            (
                vec![("OTEL_METRICS_EXPORTER", "otlp")],
                "OTEL_METRICS_EXPORTER",
            ),
            (
                vec![("OTEL_METRIC_EXPORT_INTERVAL", "0")],
                "OTEL_METRIC_EXPORT_INTERVAL",
            ),
            (
                vec![("OTEL_METRIC_EXPORT_INTERVAL", "99")],
                "OTEL_METRIC_EXPORT_INTERVAL",
            ),
            (
                vec![("OTEL_METRIC_EXPORT_INTERVAL", "3600001")],
                "OTEL_METRIC_EXPORT_INTERVAL",
            ),
            (
                vec![("OTEL_METRIC_EXPORT_INTERVAL", "60s")],
                "OTEL_METRIC_EXPORT_INTERVAL",
            ),
        ] {
            let err = config(&vars).expect_err("refused");
            assert_eq!(err.var, var, "{vars:?}: {err}");
        }
    }

    #[test]
    fn otlp_metrics_failed_counter_is_always_rendered() {
        let mut text = String::new();
        render(&mut text);
        assert!(text.contains("# TYPE podgate_otlp_metrics_failed_total counter\n"));
        assert!(text.contains("podgate_otlp_metrics_failed_total "));
    }
}
