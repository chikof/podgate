//! Picking a server allocates nothing, for every algorithm. Own test binary: it installs a
//! counting global allocator that other tests must not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use pingora::http::RequestHeader;
use podgate::RoutingTable;
use podgate::service::PickCx;
use podgate_model::Snapshot;

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

const ALGORITHMS: [&str; 5] = [
    "round_robin",
    "weighted_round_robin",
    "least_conn",
    "p2c_ewma",
    "random",
];

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
                    {"name": "web", "type": "loadbalancer", "algorithm": algorithm, "servers": servers}]}]
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

#[test]
fn balancer_pick_allocates_nothing() {
    let table = table();
    let request = RequestHeader::build("GET", b"/", None).expect("request");
    let tried = ["127.0.0.1:3".parse().expect("addr")];
    for (index, algorithm) in ALGORITHMS.iter().enumerate() {
        let app = table.app(index).expect("app");
        let first = app
            .service(0, 0)
            .and_then(|service| service.servers().first());
        // Warm up: first use may initialise lazily.
        drop(app.pick(0, PickCx::new(&request)).expect("a server"));

        let before = ALLOCATIONS.load(Ordering::Relaxed);
        for round in 0..1000 {
            if round == 500 {
                // The skip path: one server down.
                if let Some(server) = first {
                    server.state.healthy.store(false, Ordering::Relaxed);
                }
            }
            let cx = PickCx {
                request: &request,
                excluded: if round % 2 == 0 { &tried } else { &[] },
            };
            let pick = app.pick(0, cx).expect("a server is left");
            drop(pick);
        }
        let after = ALLOCATIONS.load(Ordering::Relaxed);
        assert_eq!(after - before, 0, "{algorithm} allocated while picking");
    }
}
