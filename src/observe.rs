//! Access log, metrics and tracing. The model is in [`podgate_model::Observability`]; the
//! runtime is not built. A snapshot that sets any of it is refused with `observability_not_built`
//! rather than silently logging nothing.

mod access_log;
mod metrics;
mod tracing;

use crate::compile::Invalid;
use podgate_model::Snapshot;

/// The refusal for settings nothing implements yet, `None` when the snapshot sets none.
#[must_use]
pub fn reject(snapshot: &Snapshot) -> Option<Invalid> {
    let snapshot_wide = snapshot
        .observability
        .as_ref()
        .is_some_and(podgate_model::Observability::is_set);
    let per_router = snapshot
        .apps
        .iter()
        .flat_map(|app| &app.routers)
        .any(|router| router.observability.is_some());
    (snapshot_wide || per_router).then(|| {
        Invalid::new(
            "observability_not_built",
            "access log, metrics and tracing settings are planned and not built yet",
        )
    })
}
