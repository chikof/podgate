//! `TLSRoute` (`gateway.networking.k8s.io/v1`, standard channel since Gateway API 1.5): TLS
//! connections of a `TLS` listener, told apart by their server name.
//!
//! `hostnames` become the `sni` leaf of a `tcp` router, intersected with the listener's
//! `hostname` as for an HTTP route. A listener in mode `Passthrough` forwards the encrypted
//! stream (`tls {passthrough: true}`); in mode `Terminate` podgate ends TLS with the
//! certificates of the listener's `certificateRefs` (`tls {}`) and forwards plain bytes. The
//! names are claims like `host` names: the tenant must own them (`foreign_host_claim`), and a
//! route without names, which takes every server name, needs a reserved entry point or the
//! operator's allowance (`catch_all_not_allowed`).
//!
//! Routes attached through listeners that differ in host names or in mode become one router
//! each; two `TLSRoute`s that claim one name on one entry point are a conflict
//! (`l4::conflicts`).

use serde::Deserialize;
use serde_json::Value;

use super::backend::Backends;
use super::l4::{self, RouterDraft, StreamRule};
use super::listener::Attachment;
use super::route::Draft;
use super::types::ParentRef;
use super::{Kind, Rejection};
use crate::kubernetes::client::{ObjectMeta, Resource};

/// A `TLSRoute`.
#[derive(Debug, Deserialize)]
pub struct TlsRoute {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The route.
    #[serde(default)]
    pub spec: TlsRouteSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The spec of a `TLSRoute`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsRouteSpec {
    /// The listeners it wants to attach to.
    #[serde(default)]
    pub parent_refs: Vec<ParentRef>,
    /// The server names it serves; absent inherits the listener's.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// The rules: one is served.
    #[serde(default)]
    pub rules: Vec<StreamRule>,
}

impl Resource for TlsRoute {
    const GROUP: &'static str = super::types::GROUP;
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "tlsroutes";
    const KIND: &'static str = "TLSRoute";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// The routers of `attachments`: those that share their server names and their mode are one
/// router on the entry points of all of them.
fn routers(attachments: &[Attachment]) -> Vec<RouterDraft> {
    let mut routers: Vec<RouterDraft> = Vec::new();
    for attachment in attachments {
        let passthrough = Some(attachment.passthrough);
        match routers
            .iter_mut()
            .find(|router| router.hosts == attachment.hosts && router.passthrough == passthrough)
        {
            Some(router) => {
                if !router.entry_points.contains(&attachment.entry_point) {
                    router.entry_points.push(attachment.entry_point.clone());
                    router.entry_points.sort();
                }
            }
            None => routers.push(RouterDraft {
                entry_points: vec![attachment.entry_point.clone()],
                hosts: attachment.hosts.clone(),
                passthrough,
            }),
        }
    }
    routers
}

/// The routers and service of `route` attached as `attachments`.
///
/// # Errors
///
/// A [`Rejection`] for a second rule or a backend that cannot be used.
pub fn draft(
    route: &TlsRoute,
    namespace: &str,
    attachments: &[Attachment],
    backends: &Backends<'_>,
) -> Result<Draft, Rejection> {
    l4::draft(
        Kind::Tls,
        namespace,
        &route.spec.rules,
        routers(attachments),
        backends,
    )
}
