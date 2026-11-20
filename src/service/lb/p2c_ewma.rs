//! `p2c_ewma`: power of two choices on latency. Two random servers are compared and the one
//! with the lower `ewma_latency * (active + 1)` takes the request: a server that answers slowly
//! or already holds many requests loses. This is the peak-EWMA of Finagle and Linkerd; Traefik
//! and Caddy have no latency-aware balancer. Weights are not used.
//!
//! The EWMA is written by [`done`] when a response header arrives (through the request's
//! [`crate::service::Lease`]). It rises at once to a slower sample (the peak) and falls toward
//! faster ones with a time constant of [`DECAY_MS`]. The score also decays with the time since the
//! last sample, so a server that was slow and then got no traffic is tried again after a while
//! instead of being shunned for ever. A server with no sample yet is scored as the other
//! candidate, so the choice between them is by load alone and a new server is neither flooded nor
//! starved.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{PickCx, pair, unweighted};
use crate::compile::Invalid;
use crate::service::state::now_ms;
use crate::service::{Server, ServerState, ServiceState};

/// The time constant of the decay, in milliseconds.
const DECAY_MS: f64 = 10_000.0;

/// The power-of-two-choices algorithm on EWMA latency.
#[derive(Debug, Default)]
pub struct P2cEwma;

/// Weight of the old value after `elapsed_ms`.
fn kept(elapsed_ms: u64) -> f64 {
    (-(elapsed_ms as f64) / DECAY_MS).exp()
}

/// Folds one response time into the server's EWMA. `now` is [`now_ms`], injected for tests.
pub(crate) fn done(state: &ServerState, sample: Duration, now: u64) {
    let sample_us = u64::try_from(sample.as_micros()).unwrap_or(u64::MAX).max(1);
    let cost = state.ewma_us.load(Ordering::Relaxed);
    let next = if cost == 0 || sample_us > cost {
        sample_us
    } else {
        let keep = kept(now.saturating_sub(state.ewma_at_ms.load(Ordering::Relaxed)));
        (cost as f64 * keep + sample_us as f64 * (1.0 - keep)) as u64
    };
    state.ewma_us.store(next.max(1), Ordering::Relaxed);
    state.ewma_at_ms.store(now, Ordering::Relaxed);
}

/// The EWMA of a server as of `now`, decayed by the time since its last sample; `0`: no sample.
fn latency_us(state: &ServerState, now: u64) -> f64 {
    let cost = state.ewma_us.load(Ordering::Relaxed);
    let age = now.saturating_sub(state.ewma_at_ms.load(Ordering::Relaxed));
    cost as f64 * kept(age)
}

impl P2cEwma {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        unweighted("p2c_ewma", servers)?;
        Ok(Self)
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        self.pick_at(cx, servers, shared, now_ms())
    }

    /// [`Self::pick`] at the time `now`, in [`now_ms`] terms.
    fn pick_at(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
        now: u64,
    ) -> Option<usize> {
        let (first, second) = pair(cx, servers, shared)?;
        if first == second {
            return Some(first);
        }
        let (a, b) = (servers.get(first)?, servers.get(second)?);
        let (mut latency_a, mut latency_b) = (latency_us(&a.state, now), latency_us(&b.state, now));
        if latency_a == 0.0 || latency_b == 0.0 {
            let known = latency_a.max(latency_b).max(1.0);
            (latency_a, latency_b) = (known, known);
        }
        let score = |latency: f64, server: &Server| {
            latency * (f64::from(server.state.active.load(Ordering::Relaxed)) + 1.0)
        };
        Some(if score(latency_b, b) < score(latency_a, a) {
            second
        } else {
            first
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::test_support::{request, servers};
    use super::*;
    use crate::service::Lease;

    /// A closed-loop simulation on a virtual clock: `clients` requests are always in flight,
    /// each finishing after the latency of its server, and every pick is made at the virtual
    /// time the request before it finished. Returns the picks per server.
    fn simulate(
        up: &[Server],
        latencies_ms: &dyn Fn(u64, usize) -> u64,
        clients: usize,
        until_ms: u64,
        start_ms: u64,
        shared: &ServiceState,
    ) -> Vec<u32> {
        let request = request();
        let mut counts = vec![0_u32; up.len()];
        // (finish time, server index, lease)
        let mut flying: Vec<(u64, usize, Lease)> = Vec::new();
        let mut clock = start_ms;
        let sample = |clock: u64, flying: &mut Vec<(u64, usize, Lease)>, counts: &mut [u32]| {
            while flying.len() < clients {
                let Some(index) = P2cEwma.pick_at(PickCx::new(&request), up, shared, clock) else {
                    return;
                };
                counts[index] += 1;
                let lease = Lease::take(&up[index].state, None);
                flying.push((clock + latencies_ms(clock, index), index, lease));
            }
        };
        sample(clock, &mut flying, &mut counts);
        while clock < start_ms + until_ms {
            let Some(next) = flying.iter().enumerate().min_by_key(|(_, f)| f.0) else {
                break;
            };
            let (slot, finish) = (next.0, next.1.0);
            clock = finish;
            let (_, index, lease) = flying.swap_remove(slot);
            done(
                &up[index].state,
                Duration::from_millis(latencies_ms(clock, index)),
                clock,
            );
            drop(lease);
            sample(clock, &mut flying, &mut counts);
        }
        counts
    }

    #[test]
    fn p2c_ewma_prefers_fast_server() {
        let up = servers(2);
        let shared = ServiceState::with_seed(3);
        let counts = simulate(
            &up,
            &|_, index| if index == 0 { 20 } else { 200 },
            4,
            60_000,
            1,
            &shared,
        );
        assert!(
            counts[0] >= counts[1] * 4,
            "20 ms server {} against 200 ms server {}",
            counts[0],
            counts[1]
        );
        assert!(counts[1] > 0, "the slow server is still probed");
    }

    #[test]
    fn p2c_ewma_recovers() {
        let up = servers(2);
        let shared = ServiceState::with_seed(3);
        // Server 1 is slow for a minute, then as fast as the other.
        let latency = |clock: u64, index: usize| {
            if index == 1 && clock < 60_000 {
                200
            } else {
                20
            }
        };
        let slow_phase = simulate(&up, &latency, 4, 59_000, 1, &shared);
        assert!(slow_phase[0] >= slow_phase[1] * 4, "{slow_phase:?}");
        let fast_phase = simulate(&up, &latency, 4, 120_000, 61_000, &shared);
        let (a, b) = (f64::from(fast_phase[0]), f64::from(fast_phase[1]));
        assert!(
            (0.7..=1.3).contains(&(a / b)),
            "equal servers share the load again: {fast_phase:?}"
        );
    }

    #[test]
    fn p2c_ewma_peaks_up_at_once_and_decays_down() {
        let state = ServerState::default();
        done(&state, Duration::from_millis(20), 1_000);
        assert_eq!(state.ewma_us.load(Ordering::Relaxed), 20_000);
        done(&state, Duration::from_millis(200), 1_001);
        assert_eq!(state.ewma_us.load(Ordering::Relaxed), 200_000);
        // Ten seconds later a fast sample pulls the average down by 1 - 1/e of the gap:
        // 200 ms * 0.368 + 20 ms * 0.632 = 86 ms.
        done(&state, Duration::from_millis(20), 11_001);
        let ewma = state.ewma_us.load(Ordering::Relaxed);
        assert!((85_000..=87_500).contains(&ewma), "{ewma}");
    }

    #[test]
    fn p2c_ewma_does_not_flood_a_server_without_samples() {
        let up = servers(2);
        done(&up[0].state, Duration::from_millis(20), now_ms());
        let request = request();
        let shared = ServiceState::with_seed(1);
        // Server 1 has no sample: it is scored like server 0, so load decides.
        up[0].state.active.store(3, Ordering::Relaxed);
        assert_eq!(P2cEwma.pick(PickCx::new(&request), &up, &shared), Some(1));
        up[0].state.active.store(0, Ordering::Relaxed);
        up[1].state.active.store(3, Ordering::Relaxed);
        assert_eq!(P2cEwma.pick(PickCx::new(&request), &up, &shared), Some(0));
    }
}
