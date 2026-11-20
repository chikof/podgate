//! `uri_hash`: a path always goes to the same server (consistent hashing, see [`super::ring`]),
//! which keeps the cache of a server warm for the paths it serves. The path is the one the
//! proxy normalized before routing (`router::path`, applied to the request in place), without
//! the query unless `include_query` is `true`. A request with no path goes to a random
//! available server.

use super::PickCx;
use super::ring::{Ring, fallback};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The path hash balancer.
#[derive(Debug)]
pub struct UriHash {
    ring: Ring,
    include_query: bool,
}

impl UriHash {
    pub(super) fn compile(servers: &[Server], include_query: bool) -> Result<Self, Invalid> {
        Ring::compile("uri_hash", servers).map(|ring| Self {
            ring,
            include_query,
        })
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        let uri = &cx.request.uri;
        let path = uri.path();
        if path.is_empty() {
            return fallback(cx, servers, shared);
        }
        let digest = if self.include_query {
            shared.keyed_hash((path, uri.query()))
        } else {
            shared.keyed_hash(path)
        };
        self.ring.pick(digest, cx, servers)
    }
}
