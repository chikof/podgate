//! `TCPRoute` (`gateway.networking.k8s.io/v1alpha2`, experimental channel): every connection of
//! a `TCP` listener goes to the route's backends.
//!
//! The route becomes the catch-all `tcp` router of the listener's entry point. A TCP entry point
//! is reserved to one tenant (`exclusive_entry_points`), or the tenant is allowed catch-all
//! routers (`catch_all`); otherwise the route is rejected with `catch_all_not_allowed`. A second
//! `TCPRoute` on one entry point is a conflict (`l4::conflicts`).

use serde::Deserialize;
use serde_json::Value;

use super::backend::Backends;
use super::l4::{self, RouterDraft, StreamRule};
use super::listener::Attachment;
use super::route::Draft;
use super::types::ParentRef;
use super::{Kind, Rejection};
use crate::kubernetes::client::{ObjectMeta, Resource};

/// A `TCPRoute`.
#[derive(Debug, Deserialize)]
pub struct TcpRoute {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The route.
    #[serde(default)]
    pub spec: TcpRouteSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The spec of a `TCPRoute`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpRouteSpec {
    /// The listeners it wants to attach to.
    #[serde(default)]
    pub parent_refs: Vec<ParentRef>,
    /// The rules: one is served.
    #[serde(default)]
    pub rules: Vec<StreamRule>,
}

impl Resource for TcpRoute {
    const GROUP: &'static str = super::types::GROUP;
    const VERSION: &'static str = "v1alpha2";
    const PLURAL: &'static str = "tcproutes";
    const KIND: &'static str = "TCPRoute";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// The routers and service of `route` attached as `attachments`: one router for all of its
/// entry points.
///
/// # Errors
///
/// A [`Rejection`] for a second rule, or a backend that cannot be used.
pub fn draft(
    route: &TcpRoute,
    namespace: &str,
    attachments: &[Attachment],
    backends: &Backends<'_>,
) -> Result<Draft, Rejection> {
    let routers = vec![RouterDraft {
        entry_points: l4::entry_points(attachments),
        hosts: None,
        passthrough: None,
    }];
    l4::draft(Kind::Tcp, namespace, &route.spec.rules, routers, backends)
}
