//! The `circuit_breaker` middleware: stops sending traffic to a failing downstream for a while
//! when its error ratio or latency crosses a threshold, then lets traffic back gradually.
//! Full reference: `docs/ref/mw-circuit-breaker.md`.
//!
//! ```json
//! {
//!   "name": "cb", "type": "circuit_breaker",
//!   "trip_when": {
//!     "network_error_ratio": 0.30,
//!     "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.25 },
//!     "latency_quantile_ms": { "quantile": 50.0, "ms": 100 }
//!   },
//!   "check_period_ms": 100, "fallback_secs": 10, "recovery_secs": 10, "min_requests": 20
//! }
//! ```
//!
//! Traefik writes the same triggers as an expression string (`NetworkErrorRatio() > 0.30 ||
//! ResponseCodeRatio(500, 600, 0, 600) > 0.25 || LatencyAtQuantileMS(50.0) > 100`). Here the
//! triggers are typed fields, any one of which trips the breaker; the string is never parsed
//! and nothing is evaluated per request. A translator from Traefik's string belongs to the
//! Traefik translators.
//!
//! # States
//!
//! - **Closed.** Every request passes. Finished requests fill a window of ten one-second
//!   buckets; at most every `check_period_ms` the window is judged, and a breach with at least
//!   `min_requests` requests in it opens the circuit.
//! - **Open** for `fallback_secs`. Every request is answered at once (`503` with `Retry-After`)
//!   and no upstream is contacted.
//! - **Recovering** for `recovery_secs`. The window starts empty; the share of requests that
//!   pass rises linearly from 0 to 100%, the rest are answered as when open. The first breach
//!   re-opens the circuit. When the time is over the circuit is closed again.
//!
//! The transitions out of open and out of recovering happen on the first request after their
//! time is up, so a circuit nobody calls stays in its state until somebody does.
//!
//! # Cost
//!
//! One breaker is a few kilobytes whatever the traffic: ten buckets of counters and a
//! 64-bucket latency histogram on a log scale (25% wide, from 1 ms up). The request path takes
//! no lock and allocates nothing: the state is one atomic word moved by compare-and-swap, the
//! counters are relaxed atomics, and a transition is won by exactly one caller, which is the one
//! that emits the event. A request that lands while its bucket rolls over to the next second can
//! be lost from the count, which is a rounding error for a ratio and never an overcount.
//!
//! # State that outlives a push
//!
//! A breaker belongs to (app, middleware name) and is shared by every router that names the
//! middleware. A snapshot swap hands a new table the registered breaker when the configuration
//! is equal (`Registry::settle`), so an unrelated push neither closes an open circuit nor
//! forgets the window; a changed configuration starts closed and empty.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::Instant;

use bytes::Bytes;
use pingora::http::ResponseHeader;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{CompileCx, FinishCx, Flow, Kind, Named, RequestCx, Stage};
use crate::compile::Invalid;
use crate::events::EventKind;
use crate::table::CompiledApp;
use podgate_model::Declared;

/// Seconds of history the window keeps, as Traefik's ten one-second buckets.
const WINDOW_SECS: u64 = 10;
/// Buckets of the latency histogram.
const HISTOGRAM: usize = 64;
/// Upper edge of the first latency bucket, in microseconds; each next bucket is
/// [`LATENCY_GROWTH`] times wider.
const LATENCY_FIRST_US: f64 = 1000.0;
/// How much each latency bucket's upper edge grows over the previous one.
const LATENCY_GROWTH: f64 = 1.25;
/// Longest fallback and recovery a snapshot may ask for.
const MAX_SECS: u64 = 86_400;
/// Longest check period a snapshot may ask for.
const MAX_CHECK_PERIOD_MS: u64 = 3_600_000;
/// Largest latency threshold a snapshot may ask for; the histogram cannot see beyond a few
/// minutes anyway.
const MAX_LATENCY_MS: u64 = 600_000;
/// One past the largest status code a ratio range may name.
const STATUS_END: u16 = 1000;

/// The configuration of a `circuit_breaker` middleware.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// What opens the circuit; any one of the triggers does.
    pub trip_when: TripWhen,
    /// How often the closed circuit is judged, in milliseconds. Default `100`.
    #[serde(default = "default_check_period_ms")]
    pub check_period_ms: u64,
    /// How long the circuit stays open, in seconds. Default `10`.
    #[serde(default = "default_secs")]
    pub fallback_secs: u64,
    /// How long traffic takes to return from 0 to 100%, in seconds. Default `10`; `0` closes the
    /// circuit as soon as the fallback is over.
    #[serde(default = "default_secs")]
    pub recovery_secs: u64,
    /// Fewest requests a window needs before it can trip the circuit. Default `20`.
    #[serde(default = "default_min_requests")]
    pub min_requests: u32,
    /// The status of the answer while the circuit is not letting a request through. Default
    /// `503`.
    #[serde(default = "default_response_code")]
    pub response_code: u16,
}

const fn default_check_period_ms() -> u64 {
    100
}

const fn default_secs() -> u64 {
    10
}

const fn default_min_requests() -> u32 {
    20
}

const fn default_response_code() -> u16 {
    503
}

/// The triggers, any-of. At least one is required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripWhen {
    /// Trips when more than this share of the window's requests ended in a network error: the
    /// upstream could not be reached or failed before it answered. Traefik's
    /// `NetworkErrorRatio() > r`. `0..=1`.
    #[serde(default)]
    pub network_error_ratio: Option<f64>,
    /// Trips when responses in one status range are more than a share of those in another.
    /// Traefik's `ResponseCodeRatio(from, to, over_from, over_to) > r`.
    #[serde(default)]
    pub response_code_ratio: Option<ResponseCodeRatio>,
    /// Trips when a latency quantile of the window is above a limit. Traefik's
    /// `LatencyAtQuantileMS(q) > ms`.
    #[serde(default)]
    pub latency_quantile_ms: Option<LatencyQuantile>,
}

/// Responses with a status in `from..to` per response with a status in `over_from..over_to`.
/// Both ranges are half open, as in Traefik.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCodeRatio {
    /// First status of the counted range.
    pub from: u16,
    /// One past the last status of the counted range.
    pub to: u16,
    /// First status of the range it is measured against. Default `0`.
    #[serde(default)]
    pub over_from: u16,
    /// One past the last status of the range it is measured against. Default `600`.
    #[serde(default = "default_over_to")]
    pub over_to: u16,
    /// Trips above this ratio. `0..=1`.
    pub ratio: f64,
}

const fn default_over_to() -> u16 {
    600
}

/// A latency quantile and the limit it must stay under.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyQuantile {
    /// The quantile as a percentage, `0..=100`: `50.0` is the median, `99.0` the 99th percentile.
    pub quantile: f64,
    /// Trips above this many milliseconds. The quantile is estimated from a histogram whose
    /// buckets are 25% wide and read at the middle of the bucket, so it is off by up to 12%.
    pub ms: u64,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new(
        "invalid_middleware",
        format!("circuit_breaker: {}", message.into()),
    )
}

fn in_unit_interval(name: &str, ratio: f64) -> Result<(), Invalid> {
    if ratio.is_finite() && (0.0..=1.0).contains(&ratio) {
        Ok(())
    } else {
        Err(invalid(format!("{name} must be between 0 and 1")))
    }
}

fn status_range(name: &str, from: u16, to: u16) -> Result<Range<u16>, Invalid> {
    if from < to && to <= STATUS_END {
        Ok(from..to)
    } else {
        Err(invalid(format!(
            "{name}: the range {from}..{to} must have from < to and to at most {STATUS_END}"
        )))
    }
}

impl Config {
    fn validate(&self) -> Result<(), Invalid> {
        let trip = &self.trip_when;
        if trip.network_error_ratio.is_none()
            && trip.response_code_ratio.is_none()
            && trip.latency_quantile_ms.is_none()
        {
            return Err(invalid(
                "trip_when needs at least one of network_error_ratio, response_code_ratio, latency_quantile_ms",
            ));
        }
        if let Some(ratio) = trip.network_error_ratio {
            in_unit_interval("network_error_ratio", ratio)?;
        }
        if let Some(codes) = &trip.response_code_ratio {
            in_unit_interval("response_code_ratio.ratio", codes.ratio)?;
            status_range("response_code_ratio", codes.from, codes.to)?;
            status_range("response_code_ratio.over", codes.over_from, codes.over_to)?;
        }
        if let Some(latency) = &trip.latency_quantile_ms {
            if !(latency.quantile.is_finite() && (0.0..=100.0).contains(&latency.quantile)) {
                return Err(invalid(
                    "latency_quantile_ms.quantile must be between 0 and 100",
                ));
            }
            if !(1..=MAX_LATENCY_MS).contains(&latency.ms) {
                return Err(invalid(format!(
                    "latency_quantile_ms.ms must be between 1 and {MAX_LATENCY_MS}"
                )));
            }
        }
        if !(1..=MAX_CHECK_PERIOD_MS).contains(&self.check_period_ms) {
            return Err(invalid(format!(
                "check_period_ms must be between 1 and {MAX_CHECK_PERIOD_MS}"
            )));
        }
        if !(1..=MAX_SECS).contains(&self.fallback_secs) {
            return Err(invalid(format!(
                "fallback_secs must be between 1 and {MAX_SECS}"
            )));
        }
        if self.recovery_secs > MAX_SECS {
            return Err(invalid(format!("recovery_secs must be at most {MAX_SECS}")));
        }
        if self.min_requests == 0 {
            return Err(invalid("min_requests must be at least 1"));
        }
        if !(400..=599).contains(&self.response_code) {
            return Err(invalid("response_code must be a 4xx or 5xx status"));
        }
        Ok(())
    }
}

/// What a finished request means to the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The status the client got, when a response was written.
    pub status: Option<u16>,
    /// Whether the upstream could not be reached or failed before it answered.
    pub network_error: bool,
    /// Time from the request's arrival at the breaker to its end, in microseconds.
    pub latency_us: u64,
}

/// Where the circuit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Requests pass and are counted.
    Closed,
    /// Requests are answered without an upstream.
    Open,
    /// A growing share of requests passes.
    Recovering,
}

/// A change of [`Phase`] that the control plane hears about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// The circuit opened (from closed, or again from recovering).
    Opened,
    /// Recovery finished: all traffic passes again.
    Closed,
}

/// What a request meets at the breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// The request goes on, and its outcome is to be recorded.
    Allow,
    /// The request is answered here.
    Reject {
        /// Seconds for the `Retry-After` header: when the circuit is expected to take traffic.
        retry_after_secs: u32,
    },
}

const PHASE_SHIFT: u32 = 62;
const MS_MASK: u64 = (1 << PHASE_SHIFT) - 1;

fn pack(phase: Phase, since_ms: u64) -> u64 {
    let bits = match phase {
        Phase::Closed => 0,
        Phase::Open => 1,
        Phase::Recovering => 2,
    };
    (bits << PHASE_SHIFT) | (since_ms & MS_MASK)
}

fn unpack(word: u64) -> (Phase, u64) {
    let phase = match word >> PHASE_SHIFT {
        1 => Phase::Open,
        2 => Phase::Recovering,
        _ => Phase::Closed,
    };
    (phase, word & MS_MASK)
}

/// Upper edge of each latency bucket, in microseconds.
static LATENCY_EDGES_US: LazyLock<[u64; HISTOGRAM]> = LazyLock::new(|| {
    let mut edges = [0; HISTOGRAM];
    let mut edge = LATENCY_FIRST_US;
    for slot in &mut edges {
        *slot = edge as u64;
        edge *= LATENCY_GROWTH;
    }
    edges
});

fn latency_bucket(latency_us: u64) -> usize {
    LATENCY_EDGES_US
        .partition_point(|edge| *edge < latency_us)
        .min(HISTOGRAM - 1)
}

/// The `quantile` (a percentage) of `histogram`, read at the middle of its bucket, in
/// microseconds; `None` when it is empty.
fn quantile_us(histogram: &[u64; HISTOGRAM], quantile: f64) -> Option<u64> {
    let total: u64 = histogram.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = ((quantile / 100.0 * total as f64).ceil() as u64).clamp(1, total);
    let mut seen = 0;
    for (index, count) in histogram.iter().enumerate() {
        seen += count;
        if seen >= rank {
            let upper = LATENCY_EDGES_US.get(index).copied()?;
            let lower = index
                .checked_sub(1)
                .and_then(|before| LATENCY_EDGES_US.get(before).copied())
                .unwrap_or(0);
            return Some(lower + (upper - lower) / 2);
        }
    }
    None
}

#[derive(Debug)]
struct Bucket {
    /// The second this bucket counts, plus one, so a fresh bucket (0) matches no second.
    stamp: AtomicU64,
    total: AtomicU32,
    network: AtomicU32,
    numerator: AtomicU32,
    denominator: AtomicU32,
    latency: [AtomicU32; HISTOGRAM],
}

impl Bucket {
    fn new() -> Self {
        Self {
            stamp: AtomicU64::new(0),
            total: AtomicU32::new(0),
            network: AtomicU32::new(0),
            numerator: AtomicU32::new(0),
            denominator: AtomicU32::new(0),
            latency: std::array::from_fn(|_| AtomicU32::new(0)),
        }
    }

    fn clear(&self) {
        self.total.store(0, Ordering::Relaxed);
        self.network.store(0, Ordering::Relaxed);
        self.numerator.store(0, Ordering::Relaxed);
        self.denominator.store(0, Ordering::Relaxed);
        for count in &self.latency {
            count.store(0, Ordering::Relaxed);
        }
    }
}

/// What the window holds.
#[derive(Debug)]
struct Counts {
    total: u64,
    network: u64,
    numerator: u64,
    denominator: u64,
    latency: [u64; HISTOGRAM],
}

/// The ranges the response-code trigger counts, resolved from the configuration.
#[derive(Debug, Clone)]
struct Ranges {
    counted: Range<u16>,
    over: Range<u16>,
}

#[derive(Debug)]
struct Window {
    buckets: Box<[Bucket]>,
}

impl Window {
    fn new() -> Self {
        Self {
            buckets: (0..WINDOW_SECS).map(|_| Bucket::new()).collect(),
        }
    }

    fn bucket(&self, second: u64) -> Option<&Bucket> {
        self.buckets
            .get(usize::try_from(second % WINDOW_SECS).ok()?)
    }

    fn record(&self, second: u64, ranges: Option<&Ranges>, outcome: Outcome) {
        let Some(bucket) = self.bucket(second) else {
            return;
        };
        let stamp = second + 1;
        let seen = bucket.stamp.load(Ordering::Acquire);
        if seen > stamp {
            // A straggler from a second the bucket has left: drop it.
            return;
        }
        if seen != stamp
            && bucket
                .stamp
                .compare_exchange(seen, stamp, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            bucket.clear();
        }
        bucket.total.fetch_add(1, Ordering::Relaxed);
        if outcome.network_error {
            bucket.network.fetch_add(1, Ordering::Relaxed);
        }
        if let (Some(ranges), Some(status)) = (ranges, outcome.status) {
            if ranges.counted.contains(&status) {
                bucket.numerator.fetch_add(1, Ordering::Relaxed);
            }
            if ranges.over.contains(&status) {
                bucket.denominator.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(count) = bucket.latency.get(latency_bucket(outcome.latency_us)) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counts of the [`WINDOW_SECS`] seconds ending with `second`.
    fn counts(&self, second: u64) -> Counts {
        let newest = second + 1;
        let oldest = (newest + 1).saturating_sub(WINDOW_SECS).max(1);
        let mut counts = Counts {
            total: 0,
            network: 0,
            numerator: 0,
            denominator: 0,
            latency: [0; HISTOGRAM],
        };
        for bucket in &*self.buckets {
            if !(oldest..=newest).contains(&bucket.stamp.load(Ordering::Acquire)) {
                continue;
            }
            counts.total += u64::from(bucket.total.load(Ordering::Relaxed));
            counts.network += u64::from(bucket.network.load(Ordering::Relaxed));
            counts.numerator += u64::from(bucket.numerator.load(Ordering::Relaxed));
            counts.denominator += u64::from(bucket.denominator.load(Ordering::Relaxed));
            for (sum, count) in counts.latency.iter_mut().zip(&bucket.latency) {
                *sum += u64::from(count.load(Ordering::Relaxed));
            }
        }
        counts
    }

    fn reset(&self) {
        for bucket in &*self.buckets {
            bucket.stamp.store(0, Ordering::Release);
            bucket.clear();
        }
    }
}

/// The live state of one circuit breaker: the window, the phase and the arithmetic that moves
/// it. It reads no clock: every call takes `now_ms`, milliseconds since the breaker was made, so
/// tests drive time by hand.
#[derive(Debug)]
pub struct Breaker {
    config: Config,
    ranges: Option<Ranges>,
    fallback_ms: u64,
    recovery_ms: u64,
    /// [`Phase`] in the top two bits, the millisecond it began in the rest.
    state: AtomicU64,
    last_check: AtomicU64,
    /// Counts requests during recovery, to space the ones that pass evenly.
    ticket: AtomicU64,
    window: Window,
    origin: Instant,
}

impl Breaker {
    /// A closed breaker with an empty window. `config` must have passed validation (see
    /// [`CircuitBreaker`]'s compile).
    #[must_use]
    pub fn new(config: Config) -> Self {
        let ranges = config
            .trip_when
            .response_code_ratio
            .as_ref()
            .map(|codes| Ranges {
                counted: codes.from..codes.to,
                over: codes.over_from..codes.over_to,
            });
        Self {
            fallback_ms: config.fallback_secs * 1000,
            recovery_ms: config.recovery_secs * 1000,
            config,
            ranges,
            state: AtomicU64::new(pack(Phase::Closed, 0)),
            last_check: AtomicU64::new(0),
            ticket: AtomicU64::new(0),
            window: Window::new(),
            origin: Instant::now(),
        }
    }

    /// Milliseconds since this breaker was made: the clock the request path feeds it.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX) & MS_MASK
    }

    /// The phase at `now_ms`, without moving it.
    #[must_use]
    pub fn phase(&self) -> Phase {
        unpack(self.state.load(Ordering::Acquire)).0
    }

    /// Decides whether a request at `now_ms` goes on, and moves the circuit out of open or out of
    /// recovering when their time is up. Returns the transition this call made, if any; the
    /// caller reports it.
    #[must_use]
    pub fn admit(&self, now_ms: u64) -> (Admit, Option<Transition>) {
        loop {
            let word = self.state.load(Ordering::Acquire);
            match unpack(word) {
                (Phase::Closed, _) => return (Admit::Allow, None),
                (Phase::Open, since) => {
                    let until = since + self.fallback_ms;
                    if now_ms < until {
                        let secs = (until - now_ms).div_ceil(1000).max(1);
                        let retry_after_secs = u32::try_from(secs).unwrap_or(u32::MAX);
                        return (Admit::Reject { retry_after_secs }, None);
                    }
                    if self
                        .state
                        .compare_exchange(
                            word,
                            pack(Phase::Recovering, now_ms),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        // Nothing from before the outage may count against the recovery.
                        self.window.reset();
                        self.ticket.store(0, Ordering::Relaxed);
                        self.last_check.store(now_ms, Ordering::Relaxed);
                    }
                }
                (Phase::Recovering, since) => {
                    let elapsed = now_ms.saturating_sub(since);
                    if elapsed >= self.recovery_ms {
                        if self
                            .state
                            .compare_exchange(
                                word,
                                pack(Phase::Closed, now_ms),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return (Admit::Allow, Some(Transition::Closed));
                        }
                        continue;
                    }
                    // Of every thousand requests, `permille` pass, evenly spaced.
                    let permille = elapsed * 1000 / self.recovery_ms;
                    let turn = self.ticket.fetch_add(1, Ordering::Relaxed) % 1000;
                    let passes = (turn + 1) * permille / 1000 > turn * permille / 1000;
                    let admit = if passes {
                        Admit::Allow
                    } else {
                        Admit::Reject {
                            retry_after_secs: 1,
                        }
                    };
                    return (admit, None);
                }
            }
        }
    }

    /// Counts a request that [`Self::admit`] let through and judges the window when
    /// `check_period_ms` has passed. Returns the transition this call made, if any.
    #[must_use]
    pub fn record(&self, now_ms: u64, outcome: Outcome) -> Option<Transition> {
        let word = self.state.load(Ordering::Acquire);
        if unpack(word).0 == Phase::Open {
            // Late answers of requests admitted before the circuit opened: the window restarts
            // when recovery begins, so they are not counted.
            return None;
        }
        self.window
            .record(now_ms / 1000, self.ranges.as_ref(), outcome);
        self.judge(now_ms, word)
    }

    fn judge(&self, now_ms: u64, observed: u64) -> Option<Transition> {
        let last = self.last_check.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < self.config.check_period_ms {
            return None;
        }
        if self
            .last_check
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let counts = self.window.counts(now_ms / 1000);
        if !self.breached(&counts) {
            return None;
        }
        self.state
            .compare_exchange(
                observed,
                pack(Phase::Open, now_ms),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()
            .map(|_| Transition::Opened)
    }

    fn breached(&self, counts: &Counts) -> bool {
        let floor = u64::from(self.config.min_requests);
        let trip = &self.config.trip_when;
        if let Some(ratio) = trip.network_error_ratio
            && counts.total >= floor
            && counts.network as f64 > ratio * counts.total as f64
        {
            return true;
        }
        if let Some(codes) = &trip.response_code_ratio
            && counts.denominator >= floor
            && counts.numerator as f64 > codes.ratio * counts.denominator as f64
        {
            return true;
        }
        if let Some(latency) = &trip.latency_quantile_ms
            && counts.total >= floor
            && quantile_us(&counts.latency, latency.quantile)
                .is_some_and(|estimate| estimate > latency.ms * 1000)
        {
            return true;
        }
        false
    }

    fn config(&self) -> &Config {
        &self.config
    }
}

/// A compiled `circuit_breaker` middleware: its configuration and the breaker it drives.
#[derive(Debug)]
pub struct CircuitBreaker {
    breaker: Arc<Breaker>,
    app: Box<str>,
    name: Box<str>,
}

/// Per-request state: whether the request was let through, and when.
#[derive(Debug, Default)]
pub struct State {
    started: Option<Instant>,
}

impl CircuitBreaker {
    fn announce(&self, events: &crate::events::EventFeed, transition: Transition) {
        let app = self.app.clone();
        let middleware = self.name.clone();
        events.emit(match transition {
            Transition::Opened => EventKind::CircuitOpened { app, middleware },
            Transition::Closed => EventKind::CircuitClosed { app, middleware },
        });
        tracing::info!(app = %self.app, middleware = %self.name, ?transition, "circuit breaker moved");
    }

    async fn refuse(&self, cx: &mut RequestCx<'_>, retry_after_secs: u32) -> pingora::Result<()> {
        let body = Bytes::from_static(br#"{"error":"circuit breaker open"}"#);
        let mut head = ResponseHeader::build(self.breaker.config().response_code, Some(3))?;
        head.insert_header("content-type", "application/json")?;
        head.insert_header("content-length", body.len().to_string())?;
        head.insert_header("retry-after", retry_after_secs.to_string())?;
        cx.session
            .write_response_header(Box::new(head), false)
            .await?;
        cx.session.write_response_body(Some(body), true).await
    }
}

impl Kind for CircuitBreaker {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        config.validate()?;
        Ok(Self {
            breaker: Arc::new(Breaker::new(config)),
            app: cx.app.id.clone(),
            name: declared.name.clone(),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let (admit, transition) = self.breaker.admit(self.breaker.now_ms());
        if let Some(transition) = transition {
            self.announce(cx.events, transition);
        }
        match admit {
            Admit::Allow => {
                state.started = Some(Instant::now());
                Ok(Flow::Continue)
            }
            Admit::Reject { retry_after_secs } => {
                self.refuse(cx, retry_after_secs).await?;
                Ok(Flow::Respond)
            }
        }
    }

    fn finished(&self, cx: &FinishCx<'_>, state: &mut State) {
        let Some(started) = state.started.take() else {
            return;
        };
        if cx.status.is_none() && !cx.upstream_error {
            return;
        }
        let outcome = Outcome {
            status: cx.status,
            network_error: cx.upstream_error,
            latency_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        if let Some(transition) = self.breaker.record(self.breaker.now_ms(), outcome) {
            self.announce(cx.events, transition);
        }
    }

    fn describe(&self) -> Value {
        json!({
            "config": self.breaker.config(),
            "phase": self.breaker.phase(),
        })
    }
}

/// An app id and a middleware name.
type Key = (Box<str>, Box<str>);

/// The breakers of the live table by (app id, middleware name). Owned by
/// [`crate::table::TableHandle`], outside any table, so they outlive swaps like
/// [`crate::Outcomes`] and the canary's state.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    breakers: Mutex<HashMap<Key, Arc<Breaker>>>,
}

impl Registry {
    /// Settles the breakers of a table about to go live: a middleware whose configuration equals
    /// the registered one takes over the registered breaker (phase and window); any other keeps
    /// the fresh breaker compiled for it, which replaces the old entry. Entries of middlewares
    /// the table no longer has are dropped.
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        let mut registered = self.breakers.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = HashMap::new();
        for app in apps {
            let id: Box<str> = app.id().into();
            for Named { name, stage } in app.stages_mut() {
                let Stage::CircuitBreaker(circuit) = stage else {
                    continue;
                };
                let key = (id.clone(), name.clone());
                if let Some(old) = registered.get(&key)
                    && old.config == circuit.breaker.config
                {
                    circuit.breaker = Arc::clone(old);
                }
                kept.insert(key, Arc::clone(&circuit.breaker));
            }
        }
        *registered = kept;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SECOND: u64 = 1000;

    fn config(trip_when: &Value) -> Config {
        serde_json::from_value(json!({
            "trip_when": trip_when,
            "fallback_secs": 10,
            "recovery_secs": 10,
        }))
        .expect("config")
    }

    fn breaker(trip_when: &Value) -> Breaker {
        let config = config(trip_when);
        config.validate().expect("valid");
        Breaker::new(config)
    }

    fn ok(latency_us: u64) -> Outcome {
        Outcome {
            status: Some(200),
            network_error: false,
            latency_us,
        }
    }

    fn status(code: u16) -> Outcome {
        Outcome {
            status: Some(code),
            network_error: false,
            latency_us: 1000,
        }
    }

    fn network_error() -> Outcome {
        Outcome {
            status: Some(502),
            network_error: true,
            latency_us: 1000,
        }
    }

    /// Records `count` outcomes spread over one second starting at `at`.
    fn feed(breaker: &Breaker, at: u64, count: u64, outcome: Outcome) -> Option<Transition> {
        let mut last = None;
        for step in 0..count {
            let now = at + step * (SECOND / count.max(1));
            last = breaker.record(now, outcome).or(last);
        }
        last
    }

    fn five_hundreds() -> Value {
        json!({ "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.25 } })
    }

    #[test]
    fn circuit_trips_on_network_error_ratio() {
        let breaker = breaker(&json!({ "network_error_ratio": 0.30 }));
        // 25% network errors: under the limit.
        for step in 0..100_u64 {
            let outcome = if step % 4 == 0 {
                network_error()
            } else {
                ok(1000)
            };
            assert_eq!(breaker.record(step * 10, outcome), None, "step {step}");
        }
        assert_eq!(breaker.phase(), Phase::Closed);
        // Another burst takes the window over 30%.
        let opened = feed(&breaker, 1000, 100, network_error());
        assert_eq!(opened, Some(Transition::Opened));
        assert_eq!(breaker.phase(), Phase::Open);
        assert!(matches!(breaker.admit(2100), (Admit::Reject { .. }, None)));
    }

    #[test]
    fn circuit_trips_on_latency_quantile() {
        let slow = breaker(&json!({ "latency_quantile_ms": { "quantile": 50.0, "ms": 100 } }));
        // The median is 10 ms: fine.
        for step in 0..60_u64 {
            assert_eq!(slow.record(step * 10, ok(10_000)), None);
        }
        assert_eq!(slow.phase(), Phase::Closed);
        // 300 ms requests move the median above 100 ms.
        let opened = feed(&slow, 1000, 200, ok(300_000));
        assert_eq!(opened, Some(Transition::Opened));

        // A p99 limit sees a slow tail the median does not.
        let tail = breaker(&json!({ "latency_quantile_ms": { "quantile": 99.0, "ms": 100 } }));
        for step in 0..95_u64 {
            assert_eq!(tail.record(step * 10, ok(10_000)), None);
        }
        let opened = feed(&tail, 1000, 5, ok(500_000));
        assert_eq!(opened, Some(Transition::Opened));
    }

    #[test]
    fn circuit_window_trips_on_5xx_ratio() {
        let breaker = breaker(&five_hundreds());
        feed(&breaker, 0, 70, status(200));
        assert_eq!(
            feed(&breaker, 1000, 30, status(500)),
            Some(Transition::Opened)
        );
    }

    #[test]
    fn circuit_min_requests_floor() {
        let breaker = breaker(&json!({
            "network_error_ratio": 0.0,
            "response_code_ratio": { "from": 500, "to": 600, "ratio": 0.0 },
            "latency_quantile_ms": { "quantile": 50.0, "ms": 1 }
        }));
        // 19 requests, every one a failure and a slow one: still under `min_requests` (20).
        for step in 0..19_u64 {
            let outcome = Outcome {
                status: Some(500),
                network_error: true,
                latency_us: 5_000_000,
            };
            assert_eq!(breaker.record(500 + step * 10, outcome), None, "{step}");
        }
        assert_eq!(breaker.phase(), Phase::Closed);
        // The twentieth, past the check period, trips it.
        let outcome = Outcome {
            status: Some(500),
            network_error: true,
            latency_us: 5_000_000,
        };
        assert_eq!(breaker.record(900, outcome), Some(Transition::Opened));
    }

    #[test]
    fn circuit_check_period_limits_judging() {
        let breaker = Breaker::new(
            serde_json::from_value(json!({
                "trip_when": { "network_error_ratio": 0.1 },
                "check_period_ms": 500,
                "min_requests": 1,
            }))
            .expect("config"),
        );
        // Inside the first period nothing is judged, however bad the window.
        for now in [10, 100, 400] {
            assert_eq!(breaker.record(now, network_error()), None);
        }
        assert_eq!(
            breaker.record(500, network_error()),
            Some(Transition::Opened)
        );
    }

    #[test]
    fn circuit_open_answers_with_the_time_left() {
        let (breaker, opened_at) = opened();
        let (admit, _) = breaker.admit(opened_at + 1);
        assert_eq!(
            admit,
            Admit::Reject {
                retry_after_secs: 10
            }
        );
        let (admit, _) = breaker.admit(opened_at + 9_500);
        assert_eq!(
            admit,
            Admit::Reject {
                retry_after_secs: 1
            }
        );
    }

    /// A breaker that tripped on a burst of 500s: returns it and the time it opened.
    fn opened() -> (Breaker, u64) {
        let breaker = breaker(&five_hundreds());
        feed(&breaker, 0, 100, status(500));
        let (phase, since) = unpack(breaker.state.load(Ordering::Acquire));
        assert_eq!(phase, Phase::Open);
        (breaker, since)
    }

    /// How many of `requests` asked at the same instant `at` get through.
    fn passed(breaker: &Breaker, at: u64, requests: u64) -> u64 {
        (0..requests)
            .filter(|_| breaker.admit(at).0 == Admit::Allow)
            .count() as u64
    }

    #[test]
    fn circuit_recovers_gradually() {
        let (breaker, opened_at) = opened();
        let recovery_from = opened_at + 10 * SECOND;
        // Open until the fallback is over.
        assert_eq!(passed(&breaker, opened_at + 1, 1000), 0);
        assert_eq!(breaker.phase(), Phase::Open);
        // Recovery begins at the first request after the fallback. Then the share that passes
        // follows time: about 0%, 25%, 50%, 75% of 1000 requests asked at an instant each.
        assert_eq!(breaker.admit(recovery_from).1, None);
        assert_eq!(breaker.phase(), Phase::Recovering);
        let mut shares = Vec::new();
        for quarter in 1..=3 {
            shares.push(passed(&breaker, recovery_from + quarter * 2_500, 1000));
        }
        assert_eq!(shares, [250, 500, 750]);
        // Past the recovery everything passes, once, with the transition.
        let (admit, transition) = breaker.admit(recovery_from + 10 * SECOND);
        assert_eq!(
            (admit, transition),
            (Admit::Allow, Some(Transition::Closed))
        );
        assert_eq!(breaker.phase(), Phase::Closed);
        assert_eq!(passed(&breaker, recovery_from + 11 * SECOND, 1000), 1000);
    }

    #[test]
    fn circuit_reopens_on_breach_in_recovery() {
        let (breaker, opened_at) = opened();
        let recovery_from = opened_at + 10 * SECOND;
        assert_eq!(breaker.admit(recovery_from).1, None);
        // Failures of the requests that pass in recovery re-open it at the first breach.
        let now = recovery_from + 5 * SECOND;
        let mut reopened = None;
        for step in 0..30_u64 {
            reopened = breaker.record(now + step * 10, status(500)).or(reopened);
        }
        assert_eq!(reopened, Some(Transition::Opened));
        assert_eq!(breaker.phase(), Phase::Open);
        assert!(matches!(
            breaker.admit(now + 400),
            (Admit::Reject { .. }, None)
        ));
    }

    #[test]
    fn circuit_recovery_starts_with_an_empty_window() {
        let (breaker, opened_at) = opened();
        let recovery_from = opened_at + 10 * SECOND;
        assert_eq!(breaker.admit(recovery_from).1, None);
        // A healthy request in recovery does not meet the failures from before the outage.
        assert_eq!(breaker.record(recovery_from + 200, ok(1000)), None);
        assert_eq!(breaker.phase(), Phase::Recovering);
    }

    #[test]
    fn circuit_ignores_late_answers_while_open() {
        let (breaker, opened_at) = opened();
        let before = breaker.window.counts(opened_at / 1000).total;
        assert_eq!(breaker.record(opened_at + 100, status(500)), None);
        assert_eq!(breaker.window.counts(opened_at / 1000).total, before);
    }

    #[test]
    fn circuit_zero_recovery_closes_at_once() {
        let breaker = Breaker::new(
            serde_json::from_value(json!({
                "trip_when": { "network_error_ratio": 0.1 },
                "fallback_secs": 1, "recovery_secs": 0, "min_requests": 1,
            }))
            .expect("config"),
        );
        assert_eq!(
            breaker.record(100, network_error()),
            Some(Transition::Opened)
        );
        assert_eq!(
            breaker.admit(1100),
            (Admit::Allow, Some(Transition::Closed))
        );
    }

    #[test]
    fn circuit_window_forgets_old_seconds() {
        let breaker = breaker(&five_hundreds());
        feed(&breaker, 0, 19, status(500));
        // More than ten seconds later the failures are out of the window.
        assert_eq!(feed(&breaker, 15 * SECOND, 50, status(200)), None);
        assert_eq!(breaker.window.counts(15).total, 50);
    }

    #[test]
    fn circuit_quantile_reads_the_bucket_middle() {
        let mut histogram = [0_u64; HISTOGRAM];
        histogram[latency_bucket(300_000)] = 10;
        let estimate = quantile_us(&histogram, 50.0).expect("estimate");
        assert!((260_000..=340_000).contains(&estimate), "{estimate}");
        assert_eq!(quantile_us(&[0; HISTOGRAM], 50.0), None);
    }

    fn rejected(config: &Value) -> Invalid {
        let config: Config = serde_json::from_value(config.clone()).expect("shape");
        config.validate().expect_err("invalid")
    }

    #[test]
    fn circuit_invalid_config_rejected() {
        for (config, what) in [
            (json!({ "trip_when": {} }), "no trigger"),
            (
                json!({ "trip_when": { "network_error_ratio": 1.5 } }),
                "ratio over 1",
            ),
            (
                json!({ "trip_when": { "network_error_ratio": -0.1 } }),
                "negative ratio",
            ),
            (
                json!({ "trip_when": { "response_code_ratio": { "from": 500, "to": 600, "ratio": 2.0 } } }),
                "status ratio over 1",
            ),
            (
                json!({ "trip_when": { "response_code_ratio": { "from": 600, "to": 500, "ratio": 0.5 } } }),
                "empty range",
            ),
            (
                json!({ "trip_when": { "latency_quantile_ms": { "quantile": 101.0, "ms": 100 } } }),
                "quantile over 100",
            ),
            (
                json!({ "trip_when": { "latency_quantile_ms": { "quantile": -1.0, "ms": 100 } } }),
                "negative quantile",
            ),
            (
                json!({ "trip_when": { "latency_quantile_ms": { "quantile": 50.0, "ms": 0 } } }),
                "zero latency",
            ),
            (
                json!({ "trip_when": { "network_error_ratio": 0.1 }, "min_requests": 0 }),
                "no floor",
            ),
            (
                json!({ "trip_when": { "network_error_ratio": 0.1 }, "fallback_secs": 0 }),
                "no fallback",
            ),
            (
                json!({ "trip_when": { "network_error_ratio": 0.1 }, "check_period_ms": 0 }),
                "no check period",
            ),
            (
                json!({ "trip_when": { "network_error_ratio": 0.1 }, "response_code": 200 }),
                "success as the answer",
            ),
        ] {
            let err = rejected(&config);
            assert_eq!(err.code, "invalid_middleware", "{what}");
        }
    }

    #[test]
    fn circuit_defaults_match_traefik() {
        let config: Config =
            serde_json::from_value(json!({ "trip_when": { "network_error_ratio": 0.3 } }))
                .expect("config");
        config.validate().expect("valid");
        assert_eq!(
            (
                config.check_period_ms,
                config.fallback_secs,
                config.recovery_secs,
                config.min_requests,
                config.response_code
            ),
            (100, 10, 10, 20, 503)
        );
    }
}
