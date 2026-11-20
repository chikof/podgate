//! Recording a finished request allocates nothing. Own test binary: it installs a counting
//! global allocator that other tests must not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use podgate::TableHandle;
use podgate::observe::metrics::{InFlight, Registry};
use podgate::router::Matched;
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

#[test]
fn metrics_hot_path_allocates_nothing() {
    let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenants": [{ "id": "t", "weight": 1,
            "budget": { "max_inflight": 10, "max_buffer_bytes": 1024 } }],
        "apps": [{
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [{ "name": "all", "match": { "host": "a.test" }, "service": "web" }],
            "revisions": [{ "id": "r", "weight": 1, "state": "serving", "services": [
                { "name": "web", "type": "loadbalancer",
                  "servers": [{ "url": "http://10.0.0.1:80" }] }] }]
        }]
    }))
    .expect("snapshot");
    let handle = TableHandle::new().with_metrics(Registry::default());
    handle.apply(&snapshot).expect("applies");
    let table = handle.load();
    let entry = handle.metrics().entry_point("web");
    let matched = Some(Matched { app: 0, router: 0 });

    // Prove the handles are really there, so the loop below measures a recording.
    InFlight::begin(&entry).finish(&table, matched, true, 200);
    let route = table
        .series()
        .route(Matched { app: 0, router: 0 })
        .expect("handles");
    assert_eq!(route.router().total(), 1);
    assert_eq!(route.service().total(), 1);

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for status in (0..1000_u16).map(|n| [200, 404, 503][usize::from(n % 3)]) {
        let request = InFlight::begin(&entry);
        request.finish(&table, matched, true, status);
        request.finish(&table, None, false, status);
    }
    let allocated = ALLOCATIONS.load(Ordering::Relaxed) - before;
    assert_eq!(
        allocated, 0,
        "recording 2000 requests allocated {allocated} times"
    );
    assert_eq!(route.router().total(), 1 + 1000);
    assert_eq!(entry.requests().total(), 1 + 2000);
    assert_eq!(entry.open(), 0);
}
