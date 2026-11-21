//! `weighted_round_robin`: servers take turns in proportion to their `weight`, interleaved
//! smoothly (the algorithm of nginx), so weights 5, 1, 1 give `a a b a c a a` and not
//! `a a a a a b c`. A server with weight `0` receives nothing.
//!
//! The interleaving is computed once at compile time as one cycle of server indices, as long as
//! the weights after dividing by their greatest common divisor add up. A pick takes the next
//! turn from the service's counter and reads the cycle, so it is lock-free and allocation-free
//! and a push that leaves the service alone does not restart the cycle. A turn that lands on an
//! unavailable server is spent and the next one is tried, so the others keep their proportions
//! while a server is down.

use super::PickCx;
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The longest cycle a service may have: weights that add up to more, after dividing by their
/// common divisor, are refused rather than expanded.
pub(super) const MAX_CYCLE: u64 = 4096;

/// The cycle of server indices.
#[derive(Debug)]
pub struct WeightedRoundRobin {
    cycle: Box<[u32]>,
}

pub(super) fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

impl WeightedRoundRobin {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        if servers.is_empty() {
            return Ok(Self {
                cycle: Box::new([]),
            });
        }
        let divisor = servers
            .iter()
            .fold(0, |divisor, server| gcd(divisor, u64::from(server.weight)));
        if divisor == 0 {
            return Err(Invalid::new(
                "invalid_service",
                "weighted_round_robin: every server has weight 0, so none could receive a request",
            ));
        }
        let weights: Vec<i64> = servers
            .iter()
            .filter_map(|server| i64::try_from(u64::from(server.weight) / divisor).ok())
            .collect();
        let total: i64 = weights.iter().sum();
        if u64::try_from(total).map_or(true, |total| total > MAX_CYCLE) {
            return Err(Invalid::new(
                "invalid_service",
                format!(
                    "weighted_round_robin: the weights add up to {total} after dividing by their \
                     common divisor, which is more than {MAX_CYCLE}; scale them down"
                ),
            ));
        }
        // Each turn every server gains its weight, the leader is chosen and pays the total.
        let mut current = vec![0_i64; weights.len()];
        let mut cycle = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        for _ in 0..total {
            for (current, weight) in current.iter_mut().zip(&weights) {
                *current += weight;
            }
            let leader = current
                .iter()
                .enumerate()
                .fold(None::<(usize, i64)>, |best, (index, value)| match best {
                    Some((_, most)) if most >= *value => best,
                    _ => Some((index, *value)),
                })
                .map_or(0, |(index, _)| index);
            if let Some(value) = current.get_mut(leader) {
                *value -= total;
            }
            cycle.push(u32::try_from(leader).unwrap_or(0));
        }
        Ok(Self {
            cycle: cycle.into_boxed_slice(),
        })
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        let length = u64::try_from(self.cycle.len()).ok().filter(|n| *n > 0)?;
        if !servers.iter().any(|server| cx.allows(server)) {
            return None;
        }
        // A full cycle visits every server of it, so one allowed server is found within it.
        (0..length).find_map(|_| {
            let slot = usize::try_from(shared.turn() % length).ok()?;
            let index = usize::try_from(*self.cycle.get(slot)?).ok()?;
            servers
                .get(index)
                .filter(|server| cx.allows(server))
                .map(|_| index)
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;

    use super::super::test_support::{request, servers, weighted};
    use super::*;

    fn run(up: &[Server], picks: usize) -> Vec<usize> {
        let wrr = WeightedRoundRobin::compile(up).expect("compiles");
        let request = request();
        let shared = ServiceState::default();
        (0..picks)
            .filter_map(|_| wrr.pick(PickCx::new(&request), up, &shared))
            .collect()
    }

    #[test]
    fn wrr_smooth_sequence() {
        let up = weighted(&[5, 1, 1]);
        assert_eq!(run(&up, 14), [0, 0, 1, 0, 2, 0, 0, 0, 0, 1, 0, 2, 0, 0]);
        // 50, 10, 10 is the same ratio and the same cycle.
        let scaled = weighted(&[50, 10, 10]);
        assert_eq!(run(&scaled, 7), [0, 0, 1, 0, 2, 0, 0]);
        // Equal weights are plain round robin.
        assert_eq!(run(&servers(3), 6), [0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn wrr_zero_weight_gets_nothing() {
        let up = weighted(&[0, 2, 1]);
        let picks = run(&up, 300);
        assert!(!picks.contains(&0));
        assert_eq!(picks.iter().filter(|index| **index == 1).count(), 200);
        assert_eq!(picks.iter().filter(|index| **index == 2).count(), 100);
        let all_zero = weighted(&[0, 0]);
        let err = WeightedRoundRobin::compile(&all_zero).expect_err("nothing could be picked");
        assert_eq!(err.code, "invalid_service");
        assert!(
            WeightedRoundRobin::compile(&[]).is_ok(),
            "an empty service is a sleeping app"
        );
    }

    #[test]
    fn wrr_keeps_proportions_while_a_server_is_down() {
        let up = weighted(&[5, 1, 1]);
        up[0].state.healthy.store(false, Ordering::Relaxed);
        let picks = run(&up, 200);
        assert!(!picks.contains(&0));
        assert_eq!(picks.iter().filter(|index| **index == 1).count(), 100);
        assert_eq!(picks.iter().filter(|index| **index == 2).count(), 100);
    }

    #[test]
    fn wrr_refuses_weights_that_cannot_be_expanded() {
        let err = WeightedRoundRobin::compile(&weighted(&[4096, 1])).expect_err("too long");
        assert_eq!(err.code, "invalid_service");
        assert!(WeightedRoundRobin::compile(&weighted(&[4095, 1])).is_ok());
    }
}
