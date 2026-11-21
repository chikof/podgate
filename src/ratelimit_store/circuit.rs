//! The circuit of one store: after a run of errors it opens, so a dead store costs one timeout
//! per period instead of one per request, then lets exactly one probe call through.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Consecutive errors that open the circuit.
pub const OPEN_AFTER_ERRORS: u32 = 5;

/// How long an open circuit refuses calls before it lets one probe through.
pub const OPEN_FOR: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Calls go through; `errors` have failed in a row.
    Closed { errors: u32 },
    /// Calls are refused until `until`.
    Open { until: Instant },
    /// One probe call is out; every other is refused until it settles.
    Probing,
}

/// What a settled call did to the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Change {
    /// Nothing worth telling the operator.
    None,
    /// The circuit opened.
    Opened,
    /// A probe succeeded: the circuit closed.
    Closed,
}

/// The circuit.
#[derive(Debug)]
pub(super) struct Circuit {
    state: Mutex<State>,
    threshold: u32,
    period: Duration,
}

/// The right to make one call. Settle it with [`Self::settle`]; a probe dropped unsettled (the
/// request was cancelled) counts as an error, so the circuit never stays in the probing state.
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
            state: Mutex::new(State::Closed { errors: 0 }),
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

    /// Takes the right to call the store, or `None` while the circuit is open.
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

    fn settle(&self, probe: bool, ok: bool) -> Change {
        let mut state = self.lock();
        let reopen = State::Open {
            until: Instant::now() + self.period,
        };
        match (*state, probe, ok) {
            (State::Probing, true, true) => {
                *state = State::Closed { errors: 0 };
                Change::Closed
            }
            (State::Probing, true, false) => {
                *state = reopen;
                Change::None
            }
            (State::Closed { .. }, false, true) => {
                *state = State::Closed { errors: 0 };
                Change::None
            }
            (State::Closed { errors }, false, false) => {
                if errors + 1 >= self.threshold {
                    *state = reopen;
                    Change::Opened
                } else {
                    *state = State::Closed { errors: errors + 1 };
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
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if self.probe && !self.settled {
            self.circuit.settle(true, false);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn circuit() -> Circuit {
        Circuit::new(OPEN_AFTER_ERRORS, Duration::from_millis(40))
    }

    #[test]
    fn opens_after_consecutive_errors_only() {
        let circuit = circuit();
        for _ in 0..OPEN_AFTER_ERRORS - 1 {
            assert_eq!(circuit.admit().expect("closed").settle(false), Change::None);
        }
        assert_eq!(circuit.admit().expect("closed").settle(true), Change::None);
        for _ in 0..OPEN_AFTER_ERRORS - 1 {
            circuit.admit().expect("closed").settle(false);
        }
        assert!(!circuit.is_open(), "a success reset the run");
        assert_eq!(
            circuit.admit().expect("closed").settle(false),
            Change::Opened
        );
        assert!(circuit.is_open());
        assert!(circuit.admit().is_none());
    }

    #[test]
    fn one_probe_after_the_period_and_its_result_decides() {
        let circuit = circuit();
        for _ in 0..OPEN_AFTER_ERRORS {
            circuit.admit().expect("closed").settle(false);
        }
        std::thread::sleep(Duration::from_millis(60));
        let probe = circuit.admit().expect("the period is over");
        assert!(circuit.admit().is_none(), "only one probe at a time");
        assert_eq!(probe.settle(false), Change::None);
        assert!(circuit.admit().is_none(), "a failed probe reopens it");
        std::thread::sleep(Duration::from_millis(60));
        let probe = circuit.admit().expect("the period is over again");
        assert_eq!(probe.settle(true), Change::Closed);
        assert!(!circuit.is_open());
        assert!(circuit.admit().is_some());
    }

    #[test]
    fn an_abandoned_probe_does_not_wedge_the_circuit() {
        let circuit = circuit();
        for _ in 0..OPEN_AFTER_ERRORS {
            circuit.admit().expect("closed").settle(false);
        }
        std::thread::sleep(Duration::from_millis(60));
        drop(circuit.admit().expect("probe"));
        assert!(circuit.admit().is_none());
        std::thread::sleep(Duration::from_millis(60));
        assert!(circuit.admit().is_some(), "the next period probes again");
    }

    #[test]
    fn a_late_result_from_before_the_opening_changes_nothing() {
        let circuit = circuit();
        let late = circuit.admit().expect("closed");
        for _ in 0..OPEN_AFTER_ERRORS {
            circuit.admit().expect("closed").settle(false);
        }
        assert_eq!(late.settle(true), Change::None);
        assert!(circuit.is_open());
    }
}
