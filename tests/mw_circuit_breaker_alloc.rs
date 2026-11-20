//! The circuit breaker's request path allocates nothing. Own test binary: it installs a counting
//! global allocator that other tests must not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use podgate::middleware::circuit_breaker::{Admit, Breaker, Config, Outcome, Phase, Transition};
use serde_json::json;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards unchanged to `System`, which upholds the `GlobalAlloc`
// contract; the counter is an atomic and does not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn outcome(status: u16, latency_us: u64) -> Outcome {
    Outcome {
        status: Some(status),
        network_error: false,
        latency_us,
    }
}

#[test]
fn circuit_hot_path_allocates_nothing() {
    let config: Config = serde_json::from_value(json!({
        "trip_when": {
            "network_error_ratio": 0.9,
            "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.25 },
            "latency_quantile_ms": { "quantile": 99.0, "ms": 5000 }
        },
        "check_period_ms": 10,
        "fallback_secs": 1,
        "recovery_secs": 1,
        "min_requests": 5,
    }))
    .expect("config");
    let breaker = Breaker::new(config);
    // Warm up: first use may initialise the latency table lazily.
    let _ = breaker.record(0, outcome(200, 1000));

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut now = 1;
    // Closed: the common case, a request that passes and is counted.
    for _ in 0..1000 {
        assert_eq!(breaker.admit(now), (Admit::Allow, None));
        assert_eq!(breaker.record(now, outcome(200, 12_000)), None);
        now += 1;
    }
    // A burst of failures opens it.
    let mut opened = None;
    for _ in 0..1000 {
        opened = breaker.record(now, outcome(500, 12_000)).or(opened);
        now += 1;
    }
    assert_eq!(opened, Some(Transition::Opened));
    // Open: every request is refused.
    for _ in 0..1000 {
        assert!(matches!(breaker.admit(now), (Admit::Reject { .. }, None)));
    }
    // Recovering, then closed again.
    now += 1000;
    let mut passed = 0;
    for step in 0..2000 {
        if breaker.admit(now + step).0 == Admit::Allow {
            passed += 1;
        }
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(after - before, 0, "the request path allocated");
    assert!(passed > 0);
    assert_eq!(breaker.phase(), Phase::Closed);
}
