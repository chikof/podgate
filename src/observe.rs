//! Access log, metrics and tracing. The model is in [`podgate_model::Observability`]. The access
//! log is built ([`access_log`]); metrics and tracing are not, and a snapshot that sets them is
//! refused with `observability_not_built` rather than silently recording nothing.

pub mod access_log;
mod metrics;
mod tracing;

use crate::compile::Invalid;
use podgate_model::{Router, Snapshot};

/// The refusal for settings that are invalid or that nothing implements yet, `None` when the
/// snapshot sets none.
#[must_use]
pub fn reject(snapshot: &Snapshot) -> Option<Invalid> {
    if let Err(invalid) = access_log::compile(snapshot) {
        return Some(invalid);
    }
    let snapshot_wide = snapshot
        .observability
        .as_ref()
        .is_some_and(|set| set.metrics.is_some() || set.tracing.is_some());
    if snapshot_wide {
        return Some(not_built());
    }
    snapshot
        .apps
        .iter()
        .flat_map(|app| &app.routers)
        .find_map(reject_router)
}

fn reject_router(router: &Router) -> Option<Invalid> {
    let setting = router.observability.as_ref()?;
    let Some(object) = setting.as_object() else {
        return Some(Invalid::new(
            "invalid_observability",
            format!("router {}: observability must be an object", router.name),
        ));
    };
    for (key, value) in object {
        match key.as_str() {
            "access_log" if value.is_boolean() => {}
            "access_log" => {
                return Some(Invalid::new(
                    "invalid_access_log",
                    format!("router {}: access_log must be true or false", router.name),
                ));
            }
            "metrics" | "tracing" => return Some(not_built()),
            other => {
                return Some(Invalid::new(
                    "invalid_observability",
                    format!(
                        "router {}: unknown observability setting `{other}`",
                        router.name
                    ),
                ));
            }
        }
    }
    None
}

fn not_built() -> Invalid {
    Invalid::new(
        "observability_not_built",
        "metrics and tracing settings are planned and not built yet",
    )
}
