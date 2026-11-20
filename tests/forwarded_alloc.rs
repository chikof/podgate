//! Writing the forwarding headers allocates only what the request itself must own.
//! Own test binary: it installs a counting global allocator that other tests must not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use pingora::http::RequestHeader;
use podgate::client_ip::{ForwardedView, Proto};
use podgate::forwarded;
use podgate_model::Forwarded;

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

fn count<R>(work: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let result = work();
    (result, ALLOCATIONS.load(Ordering::Relaxed) - before)
}

fn view() -> ForwardedView {
    let chain: Vec<IpAddr> = ["203.0.113.7", "2001:db8::7"]
        .iter()
        .map(|addr| addr.parse().expect("address"))
        .collect();
    ForwardedView {
        peer: "192.0.2.1".parse().expect("address"),
        client_ip: chain[0],
        proto: Proto::Https,
        host: None,
        port: Some(8443),
        port_reported: false,
        chain,
        trusted: true,
    }
}

/// Allocations of one more `apply` on `request`, after a first one has sized its maps.
fn steady_state(mut request: RequestHeader) -> (usize, usize) {
    let view = view();
    let set = Forwarded::default();
    request
        .insert_header("Host", "a.test:8443".to_owned())
        .expect("host");
    forwarded::apply(&mut request, &view, set, None).expect("applies");

    let (result, allocations) = count(|| forwarded::apply(&mut request, &view, set, None));

    result.expect("applies");
    (allocations, forwarded::names(set).len())
}

/// Every value is one allocation. Pingora's `insert_header` adds one for the parsed header name
/// and, on a request that keeps header case (an HTTP/1 downstream), one more for the clone it
/// stores in its case map; podgate cannot avoid those without a pre-built name API. Nothing
/// else is allocated: no value is formatted on the heap.
#[test]
fn forwarded_allocates_only_values() {
    let plain = RequestHeader::build_no_case("GET", b"/", None).expect("request");
    let (allocations, headers) = steady_state(plain);
    assert!(
        allocations <= 2 * headers,
        "{allocations} allocations for {headers} headers without a case map"
    );

    let cased = RequestHeader::build("GET", b"/", None).expect("request");
    let (allocations, headers) = steady_state(cased);
    assert!(
        allocations <= 3 * headers,
        "{allocations} allocations for {headers} headers with a case map"
    );
}
