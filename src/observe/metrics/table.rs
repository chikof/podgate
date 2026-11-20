//! The metric handles a compiled routing table carries: what a request records into, found by
//! the indices it already has.

use std::sync::Arc;

use super::series::Series;
use crate::router::Matched;

/// The series one router records into: its own, and its service's.
#[derive(Debug, Clone)]
pub struct RouteSeries {
    router: Arc<Series>,
    service: Arc<Series>,
}

impl RouteSeries {
    pub(super) fn new(router: Arc<Series>, service: Arc<Series>) -> Self {
        Self { router, service }
    }

    /// The router's series, or the app's `other` series when the tenant is over its cap.
    #[must_use]
    pub fn router(&self) -> &Series {
        &self.router
    }

    /// The series of the service the router names, shared by every router that names it and by
    /// every revision that defines it.
    #[must_use]
    pub fn service(&self) -> &Series {
        &self.service
    }
}

/// What the registry settled for one app.
#[derive(Debug)]
pub(super) struct AppSeries {
    /// One entry per router of the app, in order.
    pub(super) routes: Box<[RouteSeries]>,
    /// How many of the app's servers `service_server_up` reports; the rest are over the tenant's
    /// cap.
    pub(super) servers_shown: usize,
}

/// The handles of every router and service of one table, indexed like the table's apps and
/// routers. A table that never went through a registry has none, and nothing is recorded for it.
#[derive(Debug, Default)]
pub struct TableSeries {
    apps: Box<[AppSeries]>,
}

impl TableSeries {
    pub(super) fn new(apps: Vec<AppSeries>) -> Self {
        Self {
            apps: apps.into_boxed_slice(),
        }
    }

    /// The series of the router `matched` points at.
    #[must_use]
    pub fn route(&self, matched: Matched) -> Option<&RouteSeries> {
        self.apps.get(matched.app)?.routes.get(matched.router)
    }

    /// How many servers of app `app` the table reports on `service_server_up`; all of them for
    /// a table without handles.
    pub(super) fn servers_shown(&self, app: usize) -> usize {
        self.apps
            .get(app)
            .map_or(usize::MAX, |app| app.servers_shown)
    }
}
