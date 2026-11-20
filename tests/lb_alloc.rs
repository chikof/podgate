//! Picking a server allocates nothing, for every algorithm. Own test binary: it installs a
//! counting global allocator that other tests must not share.
//!
//! The count is per thread. A pick runs synchronously on the calling thread, so its allocations
//! land in the caller's counter. The libtest runner thread allocates on its own schedule (it
//! registers the running test right after spawning it) and, under load, did land inside a
//! process-wide measurement window: that was the intermittent `0.006s` failure.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use pingora::http::RequestHeader;
use podgate::RoutingTable;
use podgate::service::PickCx;
use podgate_model::Snapshot;

/// Allocations by every thread of the process; only reported, never asserted.
static ALL_THREADS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // `const` init and no destructor: touching it from the allocator never allocates.
    static THIS_THREAD: Cell<usize> = const { Cell::new(0) };
}

fn count() {
    ALL_THREADS.fetch_add(1, Ordering::Relaxed);
    // Gone during thread teardown, when there is nothing left to count.
    let _ = THIS_THREAD.try_with(|own| own.set(own.get() + 1));
}

struct Counting;

// SAFETY: every method forwards unchanged to `System`, which upholds the `GlobalAlloc`
// contract; the counters are an atomic and a `const`-initialised `Cell`, neither allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

const ALGORITHMS: [&str; 9] = [
    "round_robin",
    "weighted_round_robin",
    "least_conn",
    "p2c_ewma",
    "random",
    "ip_hash",
    "uri_hash",
    "header_hash",
    "hrw",
];

/// The `algorithm` of the service for `name`: `header_hash` needs its header.
fn declared(name: &str) -> serde_json::Value {
    if name == "header_hash" {
        serde_json::json!({ "type": "header_hash", "header": "x-key" })
    } else {
        serde_json::json!(name)
    }
}

/// One app per algorithm, host `<algorithm>.test`, with ten servers (so `least_conn` also takes
/// its two-candidates path) of which the first is unhealthy-to-be.
fn table() -> RoutingTable {
    let apps: Vec<serde_json::Value> = ALGORITHMS
        .iter()
        .map(|algorithm| {
            let servers: Vec<serde_json::Value> = (1..=10)
                .map(|port| {
                    let mut server = serde_json::json!({ "url": format!("http://127.0.0.1:{port}") });
                    if *algorithm == "weighted_round_robin" {
                        server["weight"] = serde_json::json!(port % 4);
                    }
                    server
                })
                .collect();
            serde_json::json!({
                "id": algorithm, "tenant": "t", "declared_by": "test",
                "tls": {"mode": "acme"},
                "routers": [{"name": "all", "match": {"host": format!("{algorithm}.test")}, "service": "web"}],
                "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "algorithm": declared(algorithm), "servers": servers}]}]
            })
        })
        .collect();
    let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
        "apps": apps,
    }))
    .expect("valid snapshot");
    RoutingTable::compile(&snapshot).expect("compiles")
}

/// Allocations so far by this thread and by all threads.
fn counts() -> (usize, usize) {
    (
        THIS_THREAD.with(Cell::get),
        ALL_THREADS.load(Ordering::Relaxed),
    )
}

#[test]
fn balancer_pick_allocates_nothing() {
    let table = table();
    // The hashing algorithms hash the key when there is one and fall back to a random server
    // when there is not: pick both.
    let mut keyed = RequestHeader::build("GET", b"/some/path?q=1", None).expect("request");
    keyed.insert_header("x-key", "tenant-1").expect("header");
    let bare = RequestHeader::build("GET", b"/", None).expect("request");
    let client: std::net::IpAddr = [192, 0, 2, 7].into();
    let tried = ["127.0.0.1:3".parse().expect("addr")];
    for (index, algorithm) in ALGORITHMS.iter().enumerate() {
        let app = table.app(index).expect("app");
        let servers = app
            .service(0, 0)
            .map(podgate::service::Service::servers)
            .unwrap_or_default();
        let first = servers.first();
        // Warm up: first use may initialise lazily.
        drop(app.pick(0, PickCx::new(&keyed)).expect("a server"));

        for (phase, rounds) in [("all servers up", 0..500), ("first server down", 500..1000)] {
            if phase == "first server down" {
                // The skip path: one server down.
                if let Some(server) = first {
                    server.state.healthy.store(false, Ordering::Relaxed);
                }
            }
            let (own_before, all_before) = counts();
            for round in rounds {
                let cx = PickCx {
                    request: if round % 3 == 0 { &bare } else { &keyed },
                    excluded: if round % 2 == 0 { &tried } else { &[] },
                    client: (round % 5 != 0).then_some(client),
                };
                let pick = app.pick(0, cx).expect("a server is left");
                drop(pick);
            }
            let (own_after, all_after) = counts();
            assert_eq!(
                own_after - own_before,
                0,
                "{algorithm}, phase {phase:?}: allocations by the picking thread \
                 (all threads together: {})",
                all_after - all_before
            );
        }
    }
}
