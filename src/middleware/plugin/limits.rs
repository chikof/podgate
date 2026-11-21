//! What bounds a plugin call: the size caps, the calls in flight per plugin and per tenant, and
//! the circuit that stops calling a plugin that keeps failing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Largest encoded `Call`, in bytes. A call that would be bigger is not sent.
pub const CALL_MAX: usize = 256 * 1024;

/// Largest encoded `Decision`, in bytes. A plugin that answers with more has failed the call.
pub const DECISION_MAX: usize = 64 * 1024;

/// Largest `config` a middleware may pass to its plugin, as JSON text.
pub const CONFIG_MAX: usize = 16 * 1024;

/// The deadline of a call when the middleware sets no `timeout_ms`.
pub const DEFAULT_TIMEOUT_MS: u32 = 50;

/// The longest `timeout_ms`.
pub const MAX_TIMEOUT_MS: u32 = 1000;

/// Calls one plugin has in flight at once when its entry sets no `max_concurrent`.
pub(super) const DEFAULT_MAX_CONCURRENT: u32 = 256;

/// The most `max_concurrent` an entry may set.
pub(super) const MAX_CONCURRENT: u32 = 65_536;

/// Consecutive failed calls that open the circuit.
pub(super) const CIRCUIT_AFTER: u32 = 5;

/// How long an open circuit refuses calls before it lets one probe through.
pub(super) const CIRCUIT_FOR: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Calls go through; `failures` have failed in a row.
    Closed { failures: u32 },
    /// Calls are refused until `until`.
    Open { until: Instant },
    /// One probe call is out; every other is refused until it settles.
    Probing,
}

/// What settling a call did to the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Change {
    /// Nothing worth telling the operator.
    None,
    /// The circuit opened.
    Opened,
    /// A probe succeeded: the circuit closed.
    Closed,
}

/// The circuit of one plugin: after a run of failures it opens, so a dead plugin costs one
/// timeout per period instead of one per request, then lets exactly one probe through.
#[derive(Debug)]
pub(super) struct Circuit {
    state: Mutex<State>,
    threshold: u32,
    period: Duration,
}

/// The right to make one call. Settle it with [`Self::settle`]; one dropped unsettled (the
/// request was cancelled) counts as a failure when it is the probe, so the circuit never stays
/// in the probing state.
#[derive(Debug)]
#[must_use = "a call must be settled"]
pub(super) struct Permit<'a> {
    circuit: &'a Circuit,
    probe: bool,
    settled: bool,
}

impl Circuit {
    pub(super) fn new(threshold: u32, period: Duration) -> Self {
        Self {
            state: Mutex::new(State::Closed { failures: 0 }),
            threshold,
            period,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the circuit refuses calls now: open, or probing.
    pub(super) fn is_open(&self) -> bool {
        !matches!(*self.lock(), State::Closed { .. })
    }

    /// Takes the right to call the plugin, or `None` while the circuit is open.
    pub(super) fn admit(&self) -> Option<Permit<'_>> {
        let mut state = self.lock();
        let probe = match *state {
            State::Closed { .. } => false,
            State::Open { until } if Instant::now() >= until => {
                *state = State::Probing;
                true
            }
            State::Open { .. } | State::Probing => return None,
        };
        Some(Permit {
            circuit: self,
            probe,
            settled: false,
        })
    }

    /// Closes the circuit and forgets the failures: the plugin restarted and answered `Describe`.
    pub(super) fn reset(&self) {
        *self.lock() = State::Closed { failures: 0 };
    }

    fn settle(&self, probe: bool, ok: bool) -> Change {
        let mut state = self.lock();
        let reopen = State::Open {
            until: Instant::now() + self.period,
        };
        match (*state, probe, ok) {
            (State::Probing, true, true) => {
                *state = State::Closed { failures: 0 };
                Change::Closed
            }
            (State::Probing, true, false) => {
                *state = reopen;
                Change::None
            }
            (State::Closed { .. }, false, true) => {
                *state = State::Closed { failures: 0 };
                Change::None
            }
            (State::Closed { failures }, false, false) => {
                if failures + 1 >= self.threshold {
                    *state = reopen;
                    Change::Opened
                } else {
                    *state = State::Closed {
                        failures: failures + 1,
                    };
                    Change::None
                }
            }
            // A call that began before the circuit opened and ended after: it says nothing new.
            _ => Change::None,
        }
    }
}

impl Permit<'_> {
    /// Records how the call went.
    pub(super) fn settle(mut self, ok: bool) -> Change {
        self.settled = true;
        self.circuit.settle(self.probe, ok)
    }

    /// The call says nothing about the plugin (the request was refused before it was made, or
    /// the plugin is not the one at fault): a probe goes back to the open state without a
    /// verdict, so another probe can follow.
    pub(super) fn forget(mut self) {
        self.settled = true;
        if self.probe {
            let mut state = self.circuit.lock();
            if *state == State::Probing {
                *state = State::Open {
                    until: Instant::now(),
                };
            }
        }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.circuit.settle(self.probe, false);
        }
    }
}

/// Why a call found no room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Busy {
    /// The plugin has `max_concurrent` calls in flight.
    Plugin,
    /// The tenant has its share of them in flight.
    Tenant,
    /// The tenant is not one the plugin lists.
    Unlisted,
}

/// The calls one plugin has in flight: `max` in all, and per listed tenant at most its share.
#[derive(Debug)]
pub(super) struct Slots {
    total: AtomicUsize,
    max: usize,
    tenants: Box<[(Box<str>, AtomicUsize)]>,
}

/// One call's place in [`Slots`]. Dropping it frees the place.
#[derive(Debug)]
#[must_use = "dropping a slot frees it at once"]
pub(super) struct Slot<'a> {
    total: &'a AtomicUsize,
    tenant: &'a AtomicUsize,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.tenant.fetch_sub(1, Ordering::AcqRel);
        self.total.fetch_sub(1, Ordering::AcqRel);
    }
}

fn take(counter: &AtomicUsize, max: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
            (now < max).then_some(now + 1)
        })
        .is_ok()
}

impl Slots {
    pub(super) fn new(max: usize, tenants: &[Box<str>]) -> Self {
        Self {
            total: AtomicUsize::new(0),
            max,
            tenants: tenants
                .iter()
                .map(|tenant| (tenant.clone(), AtomicUsize::new(0)))
                .collect(),
        }
    }

    /// Calls in flight now.
    pub(super) fn in_flight(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    /// The calls a tenant of `weight` may have in flight when the listed tenants' weights sum to
    /// `sum`: its share of `max`, at least one. With nobody to share with, all of them.
    pub(super) fn share(max: usize, weight: u64, sum: u64) -> usize {
        if sum == 0 || weight >= sum {
            return max;
        }
        let share = u128::from(max as u64) * u128::from(weight) / u128::from(sum);
        usize::try_from(share).unwrap_or(max).clamp(1, max)
    }

    /// Takes a place for a call of `tenant`, which may hold `share` of them.
    pub(super) fn acquire(&self, tenant: &str, share: usize) -> Result<Slot<'_>, Busy> {
        let Some((_, mine)) = self.tenants.iter().find(|(listed, _)| &**listed == tenant) else {
            return Err(Busy::Unlisted);
        };
        if !take(mine, share) {
            return Err(Busy::Tenant);
        }
        if !take(&self.total, self.max) {
            mine.fetch_sub(1, Ordering::AcqRel);
            return Err(Busy::Plugin);
        }
        Ok(Slot {
            total: &self.total,
            tenant: mine,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_circuit_opens_after_the_threshold_and_probes_once() {
        let circuit = Circuit::new(3, Duration::from_millis(20));
        for _ in 0..2 {
            let permit = circuit.admit().expect("closed");
            assert_eq!(permit.settle(false), Change::None);
        }
        let permit = circuit.admit().expect("closed");
        assert_eq!(permit.settle(false), Change::Opened);
        assert!(circuit.admit().is_none(), "open refuses");
        std::thread::sleep(Duration::from_millis(30));
        let probe = circuit.admit().expect("a probe after the period");
        assert!(circuit.admit().is_none(), "one probe at a time");
        assert_eq!(probe.settle(true), Change::Closed);
        assert!(circuit.admit().is_some());
    }

    #[test]
    fn a_success_clears_the_run_of_failures() {
        let circuit = Circuit::new(2, Duration::from_secs(60));
        circuit.admit().expect("closed").settle(false);
        circuit.admit().expect("closed").settle(true);
        circuit.admit().expect("closed").settle(false);
        assert!(circuit.admit().is_some(), "one failure since the success");
    }

    #[test]
    fn a_dropped_probe_counts_as_a_failure() {
        let circuit = Circuit::new(1, Duration::from_millis(1));
        circuit.admit().expect("closed").settle(false);
        std::thread::sleep(Duration::from_millis(5));
        drop(circuit.admit().expect("probe"));
        assert!(circuit.is_open());
    }

    #[test]
    fn a_forgotten_probe_lets_the_next_call_probe() {
        let circuit = Circuit::new(1, Duration::from_millis(1));
        circuit.admit().expect("closed").settle(false);
        std::thread::sleep(Duration::from_millis(5));
        circuit.admit().expect("probe").forget();
        assert!(circuit.admit().is_some(), "no verdict, so another probe");
    }

    #[test]
    fn a_tenant_share_is_its_weight_of_the_sum_and_at_least_one() {
        assert_eq!(Slots::share(8, 1, 2), 4);
        assert_eq!(Slots::share(8, 3, 4), 6);
        assert_eq!(Slots::share(8, 1, 100), 1, "at least one");
        assert_eq!(Slots::share(8, 5, 5), 8, "alone it may use all");
        assert_eq!(Slots::share(8, 0, 0), 8);
    }

    #[test]
    fn a_tenant_cannot_take_more_than_its_share_or_the_plugin_more_than_its_total() {
        let tenants: Vec<Box<str>> = vec!["a".into(), "b".into()];
        let slots = Slots::new(4, &tenants);
        let held: Vec<_> = (0..2)
            .map(|_| slots.acquire("a", 2).expect("share"))
            .collect();
        assert_eq!(slots.acquire("a", 2).expect_err("over share"), Busy::Tenant);
        let b: Vec<_> = (0..2)
            .map(|_| slots.acquire("b", 3).expect("share"))
            .collect();
        assert_eq!(slots.acquire("b", 3).expect_err("total"), Busy::Plugin);
        assert_eq!(slots.in_flight(), 4);
        drop(held);
        drop(b);
        assert_eq!(slots.in_flight(), 0);
        assert_eq!(
            slots.acquire("c", 1).expect_err("not listed"),
            Busy::Unlisted
        );
    }
}
