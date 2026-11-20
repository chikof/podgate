//! Observability settings of a snapshot: access log, metrics and tracing.
//!
//! `src/observe/` owns the semantics. The access log is built; a snapshot that sets
//! `metrics` or `tracing` is refused with `observability_not_built` rather than silently
//! recording nothing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Snapshot-wide observability settings; a router may override them per router.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observability {
    /// Structured access log: `format`, `fields`, `headers`, `filters`, `sampling_percent`; a
    /// boolean switches it off or on with the defaults. Absent: nothing is logged.
    #[serde(default)]
    pub access_log: Option<Value>,
    /// Per entry point, router and service metrics.
    #[serde(default)]
    pub metrics: Option<Value>,
    /// OpenTelemetry tracing: sample rate, propagation, recorded headers.
    #[serde(default)]
    pub tracing: Option<Value>,
}

impl Observability {
    /// Whether any setting is present.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.access_log.is_some() || self.metrics.is_some() || self.tracing.is_some()
    }
}
