//! `round_robin`: servers take turns, skipping the unavailable ones. This is how the proxy
//! always balanced the upstreams of a revision. Weights are not used: a server with a weight
//! other than `1` needs `weighted_round_robin` and is refused here instead of being ignored.
//! The turn counter is the service's [`ServiceState`], so a push does not restart the rotation.

use super::{PickCx, unweighted};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The round-robin algorithm; its counter is in the [`ServiceState`].
#[derive(Debug, Default)]
pub struct RoundRobin;

impl RoundRobin {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        unweighted("round_robin", servers)?;
        Ok(Self)
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        let count = u64::try_from(servers.len())
            .ok()
            .filter(|count| *count > 0)?;
        let turn = shared.turn();
        (0..count)
            .filter_map(|skip| usize::try_from((turn + skip) % count).ok())
            .find(|index| servers.get(*index).is_some_and(|server| cx.allows(server)))
    }
}

#[cfg(test)]
mod test {
    use super::super::test_support::{request, servers};
    use super::*;

    #[test]
    fn servers_take_turns_and_the_counter_is_shared_state() {
        let up = servers(3);
        let request = request();
        let shared = ServiceState::default();
        let picks: Vec<usize> = (0..6)
            .filter_map(|_| RoundRobin.pick(PickCx::new(&request), &up, &shared))
            .collect();
        assert_eq!(picks, [0, 1, 2, 0, 1, 2]);
    }
}
