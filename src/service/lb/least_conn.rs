//! `least_conn`: a new request goes to the server with the fewest requests in flight. A slow
//! server holds its requests longer, so it holds more of them and gets fewer new ones.
//!
//! Up to [`SCAN_LIMIT`] servers are all compared, starting at a rotating offset so servers that
//! tie share the load. Above it the algorithm compares two random servers and takes the less
//! loaded one (power of two choices), because a full scan of a long list on every request costs
//! more than the small imbalance it removes. Weights are not used.

use std::sync::atomic::Ordering;

use super::{PickCx, below, pair, unweighted};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The most servers compared in full.
const SCAN_LIMIT: usize = 8;

/// The least-connections algorithm.
#[derive(Debug, Default)]
pub struct LeastConn;

impl LeastConn {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        unweighted("least_conn", servers)?;
        Ok(Self)
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        let count = servers.len();
        if count == 0 {
            return None;
        }
        let load = |index: usize| {
            servers.get(index).map_or(u32::MAX, |server| {
                server.state.active.load(Ordering::Relaxed)
            })
        };
        if count > SCAN_LIMIT {
            let (first, second) = pair(cx, servers, shared)?;
            return Some(if load(second) < load(first) {
                second
            } else {
                first
            });
        }
        let start = below(shared.turn(), count);
        (0..count)
            .map(|offset| (start + offset) % count)
            .filter(|index| servers.get(*index).is_some_and(|server| cx.allows(server)))
            .min_by_key(|index| load(*index))
    }
}

#[cfg(test)]
mod test {
    use super::super::test_support::{request, servers, set_active};
    use super::*;

    #[test]
    fn least_conn_prefers_idle_server() {
        let up = servers(3);
        // The first server is slow: it still holds five requests, the others one and none.
        set_active(&up[0], 5);
        set_active(&up[1], 1);
        let request = request();
        let shared = ServiceState::default();
        assert_eq!(LeastConn.pick(PickCx::new(&request), &up, &shared), Some(2));
        set_active(&up[2], 2);
        assert_eq!(LeastConn.pick(PickCx::new(&request), &up, &shared), Some(1));
    }

    #[test]
    fn least_conn_shares_ties_and_follows_the_leases() {
        let up = servers(3);
        let request = request();
        let shared = ServiceState::default();
        let leases: Vec<_> = (0..6)
            .filter_map(|_| {
                let index = LeastConn.pick(PickCx::new(&request), &up, &shared)?;
                Some(crate::service::Lease::take(&up.get(index)?.state, None))
            })
            .collect();
        let active: Vec<u32> = up
            .iter()
            .map(|server| server.state.active.load(Ordering::Relaxed))
            .collect();
        assert_eq!(active, [2, 2, 2], "six requests over three idle servers");
        drop(leases);
        assert!(
            up.iter()
                .all(|server| server.state.active.load(Ordering::Relaxed) == 0)
        );
    }

    #[test]
    fn least_conn_compares_two_when_there_are_many_servers() {
        let up = servers(20);
        for server in &up[1..] {
            set_active(server, 100);
        }
        let request = request();
        let shared = ServiceState::default();
        let idle = (0..2000)
            .filter(|_| LeastConn.pick(PickCx::new(&request), &up, &shared) == Some(0))
            .count();
        // The idle server wins whenever it is one of the two candidates: about 2 in 20 picks.
        assert!((100..=300).contains(&idle), "{idle}");
    }
}
