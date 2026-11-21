//! The in-flight hot path allocates nothing. Own test binary: it installs a counting global
//! allocator that other tests must not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use podgate::route::Selected;
use podgate::{EventFeed, Inflight, RoutingTable};
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

fn table() -> RoutingTable {
    let snapshot: Snapshot = serde_json::from_str(
        r#"{
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test",
                "tls": {"mode": "acme"},
                "routers": [{"name": "all", "match": {"host": "a.test"}, "service": "web"}],
                "revisions": [{"id": "r", "weight": 1, "state": "serving", "services": [
                    {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9000"}]}]}]
            }]
        }"#,
    )
    .expect("valid snapshot");
    RoutingTable::compile(&snapshot).expect("compiles")
}

#[test]
fn inflight_no_alloc() {
    let table = table();
    let inflight = Inflight::new(EventFeed::new());
    inflight.sync(&table);
    let selected = Selected {
        app: 0,
        router: 0,
        revision: 0,
        upstream: "127.0.0.1:9000".parse().expect("addr"),
        path: podgate::service::graph::Path::default(),
        pinned: false,
    };
    // Warm up: first use may initialise lazily.
    drop(inflight.acquire("a", "r").expect("counted"));

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..1000 {
        let by_name = inflight.acquire("a", "r").expect("counted");
        let by_selection = inflight.admit(&table, &selected).expect("counted");
        drop(by_name);
        drop(by_selection);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    assert_eq!(after - before, 0, "acquire and drop allocated");
    assert_eq!(inflight.count("a", "r"), 0);
}
