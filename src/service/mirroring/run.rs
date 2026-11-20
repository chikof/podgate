//! What a request does about its mirrors: decide, admit, copy, hand over.
//!
//! The request is mirrored from the proxy's point of view *after* it was routed: `begin` runs in
//! `upstream_request_filter`, where the upstream request is final (every middleware's rewrite
//! included), `tee` in `request_body_filter` and `finish` in `logging`. Nothing here waits for a
//! mirror or reports into the response: a copy runs in its own task ([`super::send`]) and can
//! only be counted.
//!
//! # What a copy may cost
//!
//! A mirror may only consume what real traffic leaves unused, so each copy is shed, counted and
//! never queued, at the first of these that says no:
//!
//! 1. the process runs [`MAX_IN_FLIGHT`] copies already;
//! 2. the tenant has used three quarters of `max_inflight`, or runs a quarter of it in copies
//!    already ([`TenantBudget::admit_background`]; a copy is never counted as an in-flight request);
//! 3. the service has no server to take the copy;
//! 4. the server's concurrency limit is reached or someone waits for it
//!    ([`Backends::try_admit`]).
//!
//! The head and the body are copied only after the tenant's `max_buffer_bytes` was charged for
//! them: the head's [`HEAD_ALLOWANCE`] first, then the body block by block ([`BLOCK`] bytes
//! each), so a stream of tiny chunks costs what it weighs. A copy that does not fit is dropped,
//! the request is not touched. The charge stays until the last copy of the request ended.
//!
//! # Sampling
//!
//! Each mirror is sampled on its own, from `hash(request key, mirror index)`: the key is the
//! `X-Request-Id` a trusted peer sent, else a counter. The same request always gets the same
//! verdict, and `percent` is exact at both ends.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use pingora::http::RequestHeader;
use pingora::proxy::Session;

use super::send::{self, Copy, GlobalSlot, Job};
use super::{BLOCK, HEAD_ALLOWANCE, Plan, WHOLE};
use crate::budget::{BufferGuard, TenantBudget};
use crate::compile::hash_of;
use crate::fairq::Backends;
use crate::proxy::Ctx;
use crate::route::Selected;
use crate::service::PickCx;
use crate::service::upstream_policy::UpstreamPolicy;

/// The header every mirrored request carries, so the shadow can avoid side effects. A request
/// that already has it is itself a mirror and is not mirrored again.
pub(super) const MARKER: &str = "x-podgate-mirrored";

/// Why a copy was not sent, in the order of the labels of `podgate_mirror_dropped_total`.
#[derive(Debug, Clone, Copy)]
pub(super) enum Dropped {
    /// The process runs too many copies.
    Inflight,
    /// The tenant has no headroom in `max_inflight`.
    Tenant,
    /// The tenant's `max_buffer_bytes` has no room for the copy.
    Budget,
    /// The mirror's server is at its concurrency limit.
    Backend,
    /// The mirror's service has no available server.
    NoServer,
    /// The upstream address policy refuses the server.
    Policy,
    /// The body is over `max_body_size`.
    BodyTooLarge,
    /// The head is over [`HEAD_ALLOWANCE`].
    HeadTooLarge,
    /// An `Upgrade` or `Expect` request with `mirror_body`.
    Upgrade,
    /// The request already is a mirror.
    Mirror,
    /// The client's body never ended.
    Incomplete,
}

const DROPPED: [&str; 11] = [
    "inflight",
    "tenant",
    "budget",
    "backend",
    "no_server",
    "policy",
    "body_too_large",
    "head_too_large",
    "upgrade",
    "mirror",
    "incomplete",
];
const SENT: [&str; 3] = ["ok", "error", "timeout"];

static DROPPED_COUNT: [AtomicU64; DROPPED.len()] = [const { AtomicU64::new(0) }; DROPPED.len()];
static SENT_COUNT: [AtomicU64; SENT.len()] = [const { AtomicU64::new(0) }; SENT.len()];

/// Counts `copies` copies dropped for `reason`.
pub(super) fn dropped(reason: Dropped, copies: usize) {
    if let Some(count) = DROPPED_COUNT.get(reason as usize) {
        count.fetch_add(copies as u64, Ordering::Relaxed);
    }
}

/// How a copy that was sent ended.
#[derive(Debug, Clone, Copy)]
pub(super) enum Sent {
    /// The shadow answered.
    Ok,
    /// Connecting, writing or reading failed.
    Error,
    /// The copy ran past `mirror_timeout_secs`.
    Timeout,
}

pub(super) fn sent(result: Sent) {
    if let Some(count) = SENT_COUNT.get(result as usize) {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// The copies dropped so far for `reason`, for tests.
#[cfg(test)]
pub(super) fn dropped_total(reason: Dropped) -> u64 {
    DROPPED_COUNT[reason as usize].load(Ordering::Relaxed)
}

/// The copies sent so far with `result`, for tests.
#[cfg(test)]
pub(super) fn sent_total(result: Sent) -> u64 {
    SENT_COUNT[result as usize].load(Ordering::Relaxed)
}

/// The `podgate_mirror_*` series, for `GET /metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "# HELP podgate_mirror_sent_total Mirrored requests sent to a shadow service, by how they ended.\n# TYPE podgate_mirror_sent_total counter"
    );
    for (label, count) in SENT.iter().zip(&SENT_COUNT) {
        let _ = writeln!(
            out,
            "podgate_mirror_sent_total{{result=\"{label}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_mirror_dropped_total Mirrored requests that were not sent, by reason: shed under load, over a budget or limit, or skipped.\n# TYPE podgate_mirror_dropped_total counter"
    );
    for (label, count) in DROPPED.iter().zip(&DROPPED_COUNT) {
        let _ = writeln!(
            out,
            "podgate_mirror_dropped_total{{reason=\"{label}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_mirror_inflight Mirrored requests running now.\n# TYPE podgate_mirror_inflight gauge\npodgate_mirror_inflight {}",
        send::in_flight()
    );
}

/// The tenant's buffer bytes one request's copies hold. Dropping it gives them back.
#[derive(Debug)]
pub(super) struct Reservation {
    tenant: Arc<TenantBudget>,
    guards: Vec<BufferGuard>,
}

impl Reservation {
    pub(super) fn new(tenant: &Arc<TenantBudget>, bytes: u64) -> Option<Self> {
        let first = tenant.charge(bytes)?;
        Some(Self {
            tenant: Arc::clone(tenant),
            guards: vec![first],
        })
    }

    /// Charges `bytes` more, before anything is allocated for them.
    fn take(&mut self, bytes: u64) -> bool {
        match self.tenant.charge(bytes) {
            Some(guard) => {
                self.guards.push(guard);
                true
            }
            None => false,
        }
    }
}

/// The copied body: blocks of at most [`BLOCK`] bytes, each charged before it exists.
#[derive(Debug, Default)]
struct Body {
    blocks: Vec<Vec<u8>>,
    /// Bytes copied.
    len: u64,
    /// Bytes allocated: what has been charged.
    allocated: u64,
    /// Free bytes in the last block.
    room: usize,
}

impl Body {
    fn push(
        &mut self,
        mut data: &[u8],
        max: u64,
        reserved: &mut Reservation,
    ) -> Result<(), Dropped> {
        let incoming = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if self.len.saturating_add(incoming) > max {
            return Err(Dropped::BodyTooLarge);
        }
        while !data.is_empty() {
            if self.room == 0 {
                let block = BLOCK.min(max - self.allocated);
                if !reserved.take(block) {
                    return Err(Dropped::Budget);
                }
                let size = usize::try_from(block).map_err(|_| Dropped::Budget)?;
                self.blocks.push(Vec::with_capacity(size));
                self.allocated += block;
                self.room = size;
            }
            let take = self.room.min(data.len());
            let (now, later) = data.split_at(take);
            if let Some(block) = self.blocks.last_mut() {
                block.extend_from_slice(now);
            }
            self.room -= take;
            self.len += take as u64;
            data = later;
        }
        Ok(())
    }

    fn into_chunks(self) -> Vec<Bytes> {
        self.blocks.into_iter().map(Bytes::from).collect()
    }
}

/// A request whose body is still arriving.
#[derive(Debug)]
pub struct Collect {
    head: RequestHeader,
    wanted: Vec<usize>,
    body: Body,
    reserved: Reservation,
    max: u64,
}

/// What one request has done about mirroring. Lives in the request context.
#[derive(Debug, Default)]
pub enum State {
    /// Not looked at yet.
    #[default]
    Idle,
    /// Decided: sent, dropped or nothing to do. A retry of the upstream request does not decide
    /// again.
    Done,
    /// Waiting for the end of the body.
    Collecting(Box<Collect>),
}

const _: () = assert!(std::mem::size_of::<State>() == 16);

/// The sampling key of a request: the id a trusted peer sent, else a counter.
fn key_of(request: &RequestHeader, trusted: bool) -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let supplied = trusted
        .then(|| request.headers.get("x-request-id"))
        .flatten()
        .map(HeaderValue::as_bytes)
        .filter(|id| (1..=128).contains(&id.len()));
    match supplied {
        Some(id) => hash_of(&id),
        None => hash_of(&NEXT.fetch_add(1, Ordering::Relaxed)),
    }
}

/// Whether the mirror at `index` with `share` millionths of the traffic copies the request with
/// `key`. `0` never, one million always.
fn sampled(key: u64, index: usize, share: u32) -> bool {
    let value = (u128::from(hash_of(&(key, index))) * u128::from(WHOLE)) >> 64;
    value < u128::from(share)
}

/// Headers that are about one connection, never copied.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
];
/// Headers that carry the client's credentials, copied only with `forward_credentials`.
const CREDENTIALS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

/// The bytes a request head weighs, as a copy of it would.
fn head_weight(request: &RequestHeader) -> u64 {
    let headers: usize = request
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4)
        .sum();
    u64::try_from(headers + request.uri.to_string().len() + 64).unwrap_or(u64::MAX)
}

/// The copy of `request` a mirror gets: no connection-level header, no credentials unless
/// `credentials`, no length (the sender sets it), and the marker. `identity` says which headers a
/// middleware of the request's chain put in as an identity (`forward_auth`'s answer); they are
/// credentials too and go only with `credentials`.
fn copy_of(
    request: &RequestHeader,
    credentials: bool,
    identity: &dyn Fn(&HeaderName) -> bool,
) -> Option<RequestHeader> {
    let mut copy = request.clone();
    let mut remove: Vec<HeaderName> = copy
        .headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|list| list.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in HOP_BY_HOP
        .iter()
        .chain(["content-length", MARKER].iter())
        .chain(CREDENTIALS.iter().filter(|_| !credentials))
    {
        remove.push(HeaderName::from_static(name));
    }
    if !credentials {
        remove.extend(copy.headers.keys().filter(|name| identity(name)).cloned());
    }
    for name in &remove {
        copy.remove_header(name);
    }
    copy.insert_header(MARKER, "1").ok()?;
    Some(copy)
}

/// Decides what the request does about its mirrors, once its upstream request is final. A
/// request with no body (or with `mirror_body` off) is sent now; one whose body is copied waits
/// in [`State::Collecting`] for [`tee`] to see its end.
pub fn begin(
    backends: &Backends,
    policy: &UpstreamPolicy,
    session: &mut Session,
    upstream_request: &RequestHeader,
    ctx: &mut Ctx,
) {
    if !matches!(ctx.mirror, State::Idle) {
        return;
    }
    ctx.mirror = State::Done;
    let Some(route) = ctx.route else { return };
    let table = Arc::clone(&ctx.table);
    let Some(app) = table.app(route.app) else {
        return;
    };
    let Some(plan) = app.mirror_plan(route.revision, route.router) else {
        return;
    };
    let key = key_of(upstream_request, ctx.forwarded.trusted);
    let wanted: Vec<usize> = plan
        .targets()
        .iter()
        .enumerate()
        .filter(|(index, target)| sampled(key, *index, target.share))
        .map(|(index, _)| index)
        .collect();
    if wanted.is_empty() {
        return;
    }
    let settings = plan.settings();
    let refuse = |reason| dropped(reason, wanted.len());
    if upstream_request.headers.contains_key(MARKER) {
        return refuse(Dropped::Mirror);
    }
    let has_body = !session.is_body_empty();
    let upgrade = session.is_upgrade_req() || upstream_request.headers.contains_key("upgrade");
    if settings.mirror_body && (upgrade || upstream_request.headers.contains_key("expect")) {
        return refuse(Dropped::Upgrade);
    }
    if head_weight(upstream_request) > HEAD_ALLOWANCE {
        return refuse(Dropped::HeadTooLarge);
    }
    let copies_body = settings.mirror_body && has_body;
    let declared = upstream_request
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok());
    if copies_body && declared.is_some_and(|length| length > settings.max_body) {
        return refuse(Dropped::BodyTooLarge);
    }
    let Some(tenant) = ctx
        .tenant_slot
        .as_ref()
        .map(|slot| Arc::clone(slot.tenant()))
    else {
        return refuse(Dropped::Tenant);
    };
    let Some(reserved) = Reservation::new(&tenant, HEAD_ALLOWANCE) else {
        return refuse(Dropped::Budget);
    };
    let chain = ctx.matched.and_then(|matched| table.router(matched));
    let identity = |name: &HeaderName| {
        chain.is_some_and(|(app, router)| {
            router
                .chain()
                .iter()
                .filter_map(|index| app.stages().get(*index))
                .any(|named| named.stage.carries_identity(name))
        })
    };
    let Some(head) = copy_of(upstream_request, settings.forward_credentials, &identity) else {
        return refuse(Dropped::HeadTooLarge);
    };
    if copies_body {
        ctx.mirror = State::Collecting(Box::new(Collect {
            head,
            wanted,
            body: Body::default(),
            reserved,
            max: settings.max_body,
        }));
        return;
    }
    let client = ctx.forwarded.known_client();
    let hand = Handover {
        backends,
        policy,
        table: &table,
        route,
        plan,
        client,
    };
    hand.dispatch(head, &wanted, Body::default(), reserved);
}

/// Copies a chunk of the request body for the mirrors and, at the end of the body, sends them.
pub fn tee(
    backends: &Backends,
    policy: &UpstreamPolicy,
    chunk: Option<&Bytes>,
    end_of_stream: bool,
    ctx: &mut Ctx,
) {
    let State::Collecting(collect) = &mut ctx.mirror else {
        return;
    };
    if let Some(chunk) = chunk {
        let Collect {
            body,
            reserved,
            max,
            wanted,
            ..
        } = &mut **collect;
        if let Err(reason) = body.push(chunk, *max, reserved) {
            dropped(reason, wanted.len());
            ctx.mirror = State::Done;
            return;
        }
    }
    if !end_of_stream {
        return;
    }
    let State::Collecting(collect) = std::mem::replace(&mut ctx.mirror, State::Done) else {
        return;
    };
    let Some(route) = ctx.route else { return };
    let table = Arc::clone(&ctx.table);
    let Some(plan) = table
        .app(route.app)
        .and_then(|app| app.mirror_plan(route.revision, route.router))
    else {
        return;
    };
    let Collect {
        head,
        wanted,
        body,
        reserved,
        ..
    } = *collect;
    let hand = Handover {
        backends,
        policy,
        table: &table,
        route,
        plan,
        client: ctx.forwarded.known_client(),
    };
    hand.dispatch(head, &wanted, body, reserved);
}

/// Ends the request's mirroring: a body that never ended is never sent, and its charge goes
/// back.
pub fn finish(ctx: &mut Ctx) {
    if let State::Collecting(collect) = std::mem::replace(&mut ctx.mirror, State::Done) {
        dropped(Dropped::Incomplete, collect.wanted.len());
    }
}

/// Everything [`Self::dispatch`] needs to start the copies of one request.
struct Handover<'a> {
    backends: &'a Backends,
    policy: &'a UpstreamPolicy,
    table: &'a Arc<crate::table::RoutingTable>,
    route: Selected,
    plan: &'a Plan,
    client: Option<std::net::IpAddr>,
}

impl Handover<'_> {
    /// Starts one task for each wanted mirror that passes admission; counts the others.
    fn dispatch(&self, head: RequestHeader, wanted: &[usize], body: Body, reserved: Reservation) {
        let Some(app) = self.table.app(self.route.app) else {
            return;
        };
        let tenant = Arc::clone(&reserved.tenant);
        let copy = Arc::new(Copy::new(head, body.into_chunks(), reserved));
        for index in wanted {
            let Some(target) = self.plan.targets().get(*index) else {
                continue;
            };
            let Some(service) = app.mirror_service(target) else {
                continue;
            };
            let shed = |reason| {
                tracing::debug!(app = app.id(), mirror = %target.label, ?reason, "mirror shed");
                dropped(reason, 1);
            };
            let Some(global) = GlobalSlot::take() else {
                shed(Dropped::Inflight);
                continue;
            };
            let Some(slot) = tenant.admit_background() else {
                shed(Dropped::Tenant);
                continue;
            };
            let request = copy.head();
            let Some((addr, lease)) = service.pick(PickCx::new(request).with_client(self.client))
            else {
                shed(Dropped::NoServer);
                continue;
            };
            let Some(permit) = self.backends.try_admit(self.table, addr) else {
                shed(Dropped::Backend);
                continue;
            };
            // The server is one the resolver's checked addresses made (for a name), never the
            // name: the copy dials the IP, and `send` checks it again.
            let Some(peer) = service.with_upstream(addr, |upstream| upstream.peer()) else {
                continue;
            };
            let job = Job {
                peer,
                copy: Arc::clone(&copy),
                timeout: self.plan.settings().timeout,
                policy: self.policy.clone(),
                tenant: app.tenant().into(),
                _hold: (global, slot, lease, permit),
            };
            tokio::spawn(Box::pin(send::run(job)));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mirror_percent_sampling_is_exact_at_both_ends_and_close_in_between() {
        let keys = 10_000_u64;
        let count = |share: u32, index: usize| {
            (0..keys)
                .filter(|key| sampled(hash_of(key), index, share))
                .count()
        };
        assert_eq!(count(0, 0), 0);
        assert_eq!(count(1_000_000, 0), usize::try_from(keys).expect("fits"));
        for share in [10_000_u32, 300_000, 999_000] {
            let expected = f64::from(share) / 1_000_000.0 * 10_000.0;
            #[allow(clippy::cast_precision_loss, reason = "a count below 10,000")]
            let got = count(share, 1) as f64;
            let sigma = (expected * (1.0 - expected / 10_000.0)).sqrt();
            assert!(
                (got - expected).abs() < 5.0 * sigma + 1.0,
                "share {share}: {got} of {expected}"
            );
        }
        let key = hash_of(&7_u64);
        let first: Vec<bool> = (0..64).map(|index| sampled(key, index, 500_000)).collect();
        let again: Vec<bool> = (0..64).map(|index| sampled(key, index, 500_000)).collect();
        assert_eq!(first, again, "one request always gets one verdict");
        assert!(
            first.contains(&true) && first.contains(&false),
            "mirrors sample independently"
        );
    }

    #[test]
    fn mirror_head_copy_drops_connection_headers_and_credentials() {
        let mut request = RequestHeader::build("POST", b"/p?q=1", None).expect("request");
        for (name, value) in [
            ("host", "a.test"),
            ("connection", "keep-alive, x-hop"),
            ("x-hop", "1"),
            ("content-length", "5"),
            ("authorization", "Bearer t"),
            ("cookie", "sid=1"),
            ("accept", "text/plain"),
            ("x-user", "ann"),
            (MARKER, "spoofed"),
        ] {
            request.insert_header(name, value).expect("header");
        }
        let bare = copy_of(&request, false, &|name| name.as_str() == "x-user").expect("copy");
        let names: Vec<&str> = bare.headers.keys().map(HeaderName::as_str).collect();
        assert_eq!(bare.headers.get(MARKER).expect("marker"), "1");
        for gone in [
            "connection",
            "x-hop",
            "content-length",
            "authorization",
            "cookie",
        ] {
            assert!(!names.contains(&gone), "{gone} stays out: {names:?}");
        }
        assert!(names.contains(&"host") && names.contains(&"accept"));
        let with = copy_of(&request, true, &|name| name.as_str() == "x-user").expect("copy");
        assert!(with.headers.contains_key("authorization") && with.headers.contains_key("cookie"));
        assert!(
            with.headers.contains_key("x-user"),
            "identity goes with credentials"
        );
        assert!(!with.headers.contains_key("connection"));
    }

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        crate::budget::Budgets::new().tenant(
            "t",
            podgate_model::Budget {
                max_inflight: 10,
                max_buffer_bytes,
            },
        )
    }

    #[test]
    fn mirror_bounded_by_budget_charges_each_block_before_it_exists() {
        let tenant = tenant(HEAD_ALLOWANCE + 3 * BLOCK);
        let mut reserved = Reservation::new(&tenant, HEAD_ALLOWANCE).expect("head fits");
        let mut body = Body::default();
        let max = 10 * BLOCK;
        let chunk = vec![7_u8; 1000];
        // Tiny chunks fill one block: the charge is one block, not a thousand chunks.
        for _ in 0..16 {
            body.push(&chunk, max, &mut reserved).expect("fits");
        }
        assert_eq!(tenant.buffered(), HEAD_ALLOWANCE + BLOCK);
        let big = vec![1_u8; usize::try_from(BLOCK).expect("fits")];
        body.push(&big, max, &mut reserved).expect("second block");
        body.push(&big, max, &mut reserved).expect("third block");
        assert_eq!(tenant.buffered(), HEAD_ALLOWANCE + 3 * BLOCK);
        assert!(matches!(
            body.push(&big, max, &mut reserved),
            Err(Dropped::Budget)
        ));
        assert_eq!(
            tenant.buffered(),
            HEAD_ALLOWANCE + 3 * BLOCK,
            "a refusal charges nothing"
        );
        let copied: usize = body.blocks.iter().map(Vec::len).sum();
        assert_eq!(copied as u64, body.len);
        drop((body, reserved));
        assert_eq!(tenant.buffered(), 0, "the charge goes back");
    }

    #[test]
    fn mirror_body_over_limit_skipped_stops_at_max_body_size() {
        let tenant = tenant(1 << 20);
        let mut reserved = Reservation::new(&tenant, HEAD_ALLOWANCE).expect("head");
        let mut body = Body::default();
        body.push(&[0; 10], 12, &mut reserved).expect("under");
        assert!(matches!(
            body.push(&[0; 3], 12, &mut reserved),
            Err(Dropped::BodyTooLarge)
        ));
        body.push(&[0; 2], 12, &mut reserved)
            .expect("exactly at the cap");
        assert_eq!(body.len, 12);
        assert_eq!(
            tenant.buffered(),
            HEAD_ALLOWANCE + 12,
            "the last block is as small as the cap"
        );
    }

    #[test]
    fn mirror_background_admission_keeps_a_quarter_for_real_requests() {
        let tenant = tenant(1 << 20);
        let mut held = Vec::new();
        while let Some(slot) = tenant.admit_background() {
            held.push(slot);
        }
        // max_inflight is 10: at most 10 / 4 = 2 copies, and none once 8 requests run.
        assert_eq!(held.len(), 2);
        let real: Vec<_> = std::iter::from_fn(|| tenant.admit()).collect();
        assert_eq!(real.len(), 10, "copies never take a real request's place");
        drop(held);
        assert!(
            tenant.admit_background().is_none(),
            "busy: no copy above three quarters"
        );
    }
}
