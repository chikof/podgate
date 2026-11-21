//! `UDPRoute` (`gateway.networking.k8s.io/v1alpha2`, experimental channel): every datagram of a
//! `UDP` listener goes to the route's backends.
//!
//! The route becomes the one `udp` router of the listener's entry point, which the daemon
//! requires to be reserved to the route's tenant (`exclusive_entry_points`). A second `UDPRoute`
//! on one entry point is a conflict (`l4::conflicts`). The backends' Service ports must be UDP,
//! and a UDP service has no weights: backends of different weights per endpoint are rejected.

use serde::Deserialize;
use serde_json::Value;

use super::backend::Backends;
use super::l4::{self, RouterDraft, StreamRule};
use super::listener::Attachment;
use super::route::Draft;
use super::types::ParentRef;
use super::{Kind, Rejection};
use crate::kubernetes::client::{ObjectMeta, Resource};

/// A `UDPRoute`.
#[derive(Debug, Deserialize)]
pub struct UdpRoute {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The route.
    #[serde(default)]
    pub spec: UdpRouteSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The spec of a `UDPRoute`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpRouteSpec {
    /// The listeners it wants to attach to.
    #[serde(default)]
    pub parent_refs: Vec<ParentRef>,
    /// The rules: one is served.
    #[serde(default)]
    pub rules: Vec<StreamRule>,
}

impl Resource for UdpRoute {
    const GROUP: &'static str = super::types::GROUP;
    const VERSION: &'static str = "v1alpha2";
    const PLURAL: &'static str = "udproutes";
    const KIND: &'static str = "UDPRoute";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// The router and service of `route` attached as `attachments`: one router for all of its
/// entry points.
///
/// # Errors
///
/// A [`Rejection`] for a second rule, a backend that cannot be used, or weights a UDP service
/// cannot express.
pub fn draft(
    route: &UdpRoute,
    namespace: &str,
    attachments: &[Attachment],
    backends: &Backends<'_>,
) -> Result<Draft, Rejection> {
    let routers = vec![RouterDraft {
        entry_points: l4::entry_points(attachments),
        hosts: None,
        passthrough: None,
    }];
    l4::draft(Kind::Udp, namespace, &route.spec.rules, routers, backends)
}
