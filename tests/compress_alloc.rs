//! The heap one compressed response holds stays inside the reservation its algorithm charges
//!. Own test binary: it installs a counting global allocator that other tests must
//! not share.

// A counting `GlobalAlloc` has no safe form.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use podgate::budget::Budgets;
use podgate::compress::{self, Algorithm, Settings};
use podgate_model::Budget;

/// Heap bytes live now, and the highest the figure reached since the last reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method forwards unchanged to `System`, which upholds the `GlobalAlloc`
// contract; the counters are atomics and do not allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        // SAFETY: same layout and caller obligations as ours.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            grow(new_size - layout.size());
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const CHUNK: usize = 64 * 1024;
const BODY: usize = 8 * 1024 * 1024;

fn compressible() -> Vec<Bytes> {
    let text: Vec<u8> = (0..)
        .flat_map(|n: u32| format!("line {n}: some text that compresses well\n").into_bytes())
        .take(BODY)
        .collect();
    text.chunks(CHUNK).map(Bytes::copy_from_slice).collect()
}

/// Bytes a compressor cannot shrink: the output is as large as the input.
fn incompressible() -> Vec<Bytes> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let noise: Vec<u8> = (0..BODY)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect();
    noise.chunks(CHUNK).map(Bytes::copy_from_slice).collect()
}

/// The most heap one response of `algorithm` held beyond what existed before it started, while
/// `chunks` went through it one at a time and each output was dropped as soon as it came out.
fn peak_of(algorithm: Algorithm, level: u8, chunks: &[Bytes]) -> usize {
    let tenant = Budgets::new().tenant(
        "t",
        Budget {
            max_inflight: 1,
            max_buffer_bytes: u64::MAX,
        },
    );
    let settings = Settings {
        algorithms: vec![algorithm],
        level,
        ..Settings::platform().clone()
    };
    let mut request = RequestHeader::build("GET", b"/", None).expect("request");
    request
        .insert_header("accept-encoding", algorithm.token())
        .expect("header");
    let mut head = ResponseHeader::build(200, None).expect("response");
    head.insert_header("content-type", "text/plain")
        .expect("header");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let mut encoder = compress::start(&request, &mut head, &tenant, &settings);
    assert!(encoder.is_some(), "{algorithm:?} compresses");
    for (index, chunk) in chunks.iter().enumerate() {
        let mut body = Some(chunk.clone());
        compress::filter(&mut encoder, &mut body, index + 1 == chunks.len()).expect("encodes");
    }
    assert!(encoder.is_none(), "the stream ended");
    PEAK.load(Ordering::Relaxed) - baseline
}

#[test]
fn compress_peak_memory_per_response_bounded() {
    let inputs = [("text", compressible()), ("noise", incompressible())];
    for algorithm in [Algorithm::Gzip, Algorithm::Brotli, Algorithm::Zstd] {
        let reserved = usize::try_from(algorithm.reservation()).expect("fits");
        for level in 1..=compress::MAX_LEVEL {
            for (kind, chunks) in &inputs {
                let peak = peak_of(algorithm, level, chunks);
                println!("{algorithm:?} level {level} {kind}: peak {peak} of {reserved} reserved");
                assert!(
                    peak <= reserved,
                    "{algorithm:?} level {level} on {kind} held {peak} bytes, reservation is {reserved}"
                );
            }
        }
    }
}
