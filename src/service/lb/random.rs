//! `random`: every available server is equally likely. Weights are not used.

use super::{PickCx, below, unweighted};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The random algorithm; its random numbers come from the [`ServiceState`].
#[derive(Debug, Default)]
pub struct Random;

impl Random {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        unweighted("random", servers)?;
        Ok(Self)
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        // Counting first and then taking the n-th allowed server keeps the choice uniform
        // among the allowed ones, which "the next one at or after a random index" would not.
        let allowed = servers.iter().filter(|server| cx.allows(server)).count();
        if allowed == 0 {
            return None;
        }
        let nth = below(shared.random(), allowed);
        servers
            .iter()
            .enumerate()
            .filter(|(_, server)| cx.allows(server))
            .nth(nth)
            .map(|(index, _)| index)
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;

    use super::super::test_support::{request, servers};
    use super::*;

    #[test]
    fn random_is_uniform() {
        let up = servers(4);
        let request = request();
        let shared = ServiceState::with_seed(7);
        let mut counts = [0_u32; 4];
        for _ in 0..10_000 {
            let index = Random
                .pick(PickCx::new(&request), &up, &shared)
                .expect("a server is up");
            counts[index] += 1;
        }
        for count in counts {
            assert!((2300..=2700).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn random_stays_uniform_among_the_servers_that_are_up() {
        let up = servers(4);
        up[1].state.healthy.store(false, Ordering::Relaxed);
        let request = request();
        let shared = ServiceState::with_seed(11);
        let mut counts = [0_u32; 4];
        for _ in 0..9_000 {
            let index = Random
                .pick(PickCx::new(&request), &up, &shared)
                .expect("a server is up");
            counts[index] += 1;
        }
        assert_eq!(counts[1], 0);
        for count in [counts[0], counts[2], counts[3]] {
            assert!((2700..=3300).contains(&count), "{counts:?}");
        }
    }
}
