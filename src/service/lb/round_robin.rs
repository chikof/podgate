//! `round_robin`: servers take turns, skipping the unavailable ones. This is how the proxy
//! always balanced the upstreams of a revision. Weights are not used: a server with a weight
//! other than `1` needs `weighted_round_robin` and is refused here instead of being ignored.

use std::sync::atomic::{AtomicU64, Ordering};

use super::PickCx;
use crate::compile::Invalid;
use crate::service::Server;

/// The round-robin counter.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicU64,
}

impl RoundRobin {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        if let Some(server) = servers.iter().find(|server| server.weight != 1) {
            return Err(Invalid::new(
                "invalid_service",
                format!(
                    "server {} has a weight: round_robin ignores weights, use weighted_round_robin",
                    server.url
                ),
            ));
        }
        Ok(Self::default())
    }

    pub(super) fn pick(&self, _cx: PickCx<'_>, servers: &[Server]) -> Option<usize> {
        let count = u64::try_from(servers.len())
            .ok()
            .filter(|count| *count > 0)?;
        let turn = self.next.fetch_add(1, Ordering::Relaxed);
        (0..count)
            .filter_map(|skip| usize::try_from((turn + skip) % count).ok())
            .find(|index| servers.get(*index).is_some_and(Server::available))
    }
}
