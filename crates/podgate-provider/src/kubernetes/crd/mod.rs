//! The podgate custom resources: `PodgateRoute` and `PodgateMiddleware`, group `podgate.io`,
//! version `v1alpha1`, both namespaced.
//!
//! They are for routing that Ingress cannot say: routers with matcher trees, per-route
//! middlewares, services other than one load balancer, transports. The source reads them when
//! its `[[source]]` entry says `crds = true` (the CRDs in `deploy/crd/` must be installed first;
//! without them the lists fail and the source reports an outage, so the default is off).
//!
//! - [`route`]: a PodgateRoute becomes one app; servers come from EndpointSlices through
//!   `serviceRef`, never from addresses.
//! - [`middleware`]: a PodgateMiddleware is read and copied into every app that names it. The
//!   daemon has no cross-app references, so the output never refers outside one app.
//! - [`schema`]: the generator of the CRD manifests from the daemon's `GET /v1/schema`, run by
//!   `podgate-provider print-crd`.
//!
//! Tenancy is the Ingress rule: the namespace decides the tenant (`namespace_tenants`,
//! `default_tenant`), `spec.tenant` is a label claim, and the hosts a route's routers claim must
//! lie where that tenant may claim hosts. The reference is `docs/ref/provider-crd.md`.

pub mod middleware;
pub mod route;
pub mod schema;

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tracing::debug;

use self::middleware::{Middlewares, PodgateMiddleware};
use self::route::PodgateRoute;
use super::client::{ApiClient, Event, Query, Store};
use super::ingress::Cluster;
use super::{Change, Tagged, track};
use crate::push::AdminClient;
use crate::source::SourceApp;

/// The API group of the custom resources.
pub const GROUP: &str = "podgate.io";

/// The API version of the custom resources.
pub const VERSION: &str = "v1alpha1";

/// A change to one of the custom resources.
pub(super) enum CrdChange {
    Route(Event<PodgateRoute>),
    Middleware(Event<PodgateMiddleware>),
}

/// What the source has read of the custom resources: one store per kind and scope. Empty, and
/// always synced, while the kinds are not enabled.
pub(super) struct Cache {
    enabled: bool,
    routes: Vec<Store<PodgateRoute>>,
    middlewares: Vec<Store<PodgateMiddleware>>,
}

impl Cache {
    pub(super) fn new(enabled: bool, scopes: usize) -> Self {
        Self {
            enabled,
            routes: super::stores(scopes),
            middlewares: super::stores(scopes),
        }
    }

    pub(super) fn apply(
        &mut self,
        outages: &mut std::collections::BTreeMap<(&'static str, usize), Box<str>>,
        scope: usize,
        change: CrdChange,
    ) {
        match change {
            CrdChange::Route(event) => track(outages, &mut self.routes[scope], scope, event),
            CrdChange::Middleware(event) => {
                track(outages, &mut self.middlewares[scope], scope, event);
            }
        }
    }

    pub(super) fn synced(&self) -> bool {
        !self.enabled
            || (self.routes.iter().all(Store::is_synced)
                && self.middlewares.iter().all(Store::is_synced))
    }
}

/// Starts the watchers of one scope, when the kinds are enabled.
pub(super) fn watch(
    enabled: bool,
    tasks: &mut JoinSet<()>,
    client: &ApiClient,
    query: &Query,
    scope: usize,
    tx: &Sender<Tagged>,
) {
    if !enabled {
        return;
    }
    super::watch::<PodgateRoute>(tasks, client, query.clone(), scope, tx, |event| {
        Change::Crd(CrdChange::Route(event))
    });
    super::watch::<PodgateMiddleware>(tasks, client, query.clone(), scope, tx, |event| {
        Change::Crd(CrdChange::Middleware(event))
    });
}

/// Maps every PodgateRoute of `cache` into `apps`; the ones that cannot be mapped are named in
/// `rejected`, and so are PodgateMiddlewares that cannot be read.
pub(super) fn build(
    cache: &Cache,
    context: &Cluster<'_>,
    apps: &mut Vec<SourceApp>,
    rejected: &mut Vec<String>,
) {
    if !cache.enabled {
        return;
    }
    let shared = Middlewares::new(cache.middlewares.iter().flat_map(Store::values));
    for (item, why) in shared.invalid() {
        rejected.push(format!(
            "PodgateMiddleware {} rejected: {why}",
            item.metadata.key()
        ));
    }
    for route in cache.routes.iter().flat_map(Store::values) {
        debug!(route = %route.metadata.key(), "mapping a PodgateRoute");
        match route::map(route, context, &shared) {
            Ok(mapped) => {
                for note in mapped.notes {
                    rejected.push(format!("PodgateRoute {}: {note}", route.metadata.key()));
                }
                apps.push(mapped.app);
            }
            Err(why) => rejected.push(format!(
                "PodgateRoute {} rejected: {why}",
                route.metadata.key()
            )),
        }
    }
}

/// `podgate-provider print-crd` failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PrintError {
    /// The schema could not be read from the daemon or the file.
    #[error("cannot read the schema: {0}")]
    Schema(Box<str>),
    /// The schema is not one the generator understands.
    #[error(transparent)]
    Generate(#[from] schema::SchemaError),
    /// A file could not be written.
    #[error("cannot write {path}: {source}")]
    Write {
        /// The file.
        path: Box<str>,
        /// Why.
        source: std::io::Error,
    },
}

/// Where `print-crd` reads the schema from.
#[derive(Debug, Clone, Copy)]
pub enum SchemaSource<'a> {
    /// A running daemon's admin socket.
    Socket(&'a Path),
    /// A saved copy of the document.
    File(&'a Path),
}

/// The schema document of `source`, read for `print-crd`.
///
/// # Errors
///
/// [`PrintError::Schema`] when the daemon or the file does not give a JSON document.
pub async fn read_schema(source: SchemaSource<'_>) -> Result<Value, PrintError> {
    let fail = |why: String| PrintError::Schema(why.into());
    match source {
        SchemaSource::File(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|err| fail(format!("{}: {err}", path.display())))?;
            serde_json::from_str(&text).map_err(|err| fail(format!("{}: {err}", path.display())))
        }
        SchemaSource::Socket(path) => {
            let client = AdminClient::new(path, Duration::from_secs(30));
            client.schema().await.map_err(|err| fail(err.to_string()))
        }
    }
}

/// Writes the manifests of `document` to `out`, or returns them as one YAML stream when `out` is
/// `None`. With `save_schema`, also saves the document (without the daemon's version, which the
/// manifests do not depend on) there, as the fixture `crd_manifests_not_stale` compares with.
///
/// # Errors
///
/// [`PrintError`] when the document cannot be turned into manifests or a file cannot be written.
pub fn print(
    document: &Value,
    out: Option<&Path>,
    save_schema: Option<&Path>,
) -> Result<String, PrintError> {
    let manifests = schema::manifests(document)?;
    let write = |path: &Path, text: &str| {
        std::fs::write(path, text).map_err(|source| PrintError::Write {
            path: path.display().to_string().into(),
            source,
        })
    };
    if let Some(path) = save_schema {
        let mut saved = document.clone();
        if let Some(object) = saved.as_object_mut() {
            object.remove("podgate_version");
        }
        // A `Value` always serializes.
        let text = serde_json::to_string_pretty(&saved).unwrap_or_default();
        write(path, &format!("{text}\n"))?;
    }
    match out {
        Some(dir) => {
            for manifest in &manifests {
                write(&dir.join(manifest.file), &manifest.yaml)?;
            }
            Ok(String::new())
        }
        None => Ok(manifests
            .iter()
            .map(|manifest| manifest.yaml.as_str())
            .collect::<Vec<_>>()
            .join("---\n")),
    }
}
