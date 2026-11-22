//! The `quota` middleware through the real binary and a real `valkey-server`, and the
//! counter behind it through the library with a chosen clock: one quota across nodes, `429` with
//! `retry-after` at the window end, UTC day and month boundaries, keys that isolate tenants and
//! configurations and never hold a client's identity, the store failing and returning, `charge`
//! after a response, a JWT claim as the source, and the rules that are refused at apply time.

// The builders take the JSON they are given, as the ones in `common` do.
#![allow(clippy::needless_pass_by_value)]

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::valkey::{self, Valkey};
use common::{
    Podgate, Response, Upstream, app, middleware, serving, snapshot, with_chain, with_jwt_auth,
    with_middleware,
};
use podgate::ratelimit_store::quota::{Admission, Counter, Period, SourceId, Usage, now_secs};
use podgate::ratelimit_store::{OPEN_FOR, Store, Stores};
use serde_json::{Value, json};
use signer::{Signer, now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

/// App `a` on `a.test` with one quota called `plan` in its chain.
fn planned(upstream: SocketAddr, config: Value) -> Value {
    with_chain(
        app("a", &["a.test"], &[serving("r1", upstream)]),
        &[middleware("plan", "quota", config)],
    )
}

/// A quota on store `main`, counted per `x-client`, with `limit` requests a day.
fn quota(limit: u64, failure: Value) -> Value {
    let mut config = json!({
        "limit": limit, "period": "day",
        "source": {"header": "x-client"}, "store": "main",
    });
    let object = config.as_object_mut().expect("object");
    object.extend(failure.as_object().expect("object").clone());
    config
}

fn deny() -> Value {
    json!({"on_store_error": "deny"})
}

fn allow() -> Value {
    json!({"on_store_error": "allow"})
}

/// A node whose `RATE_LIMIT_STORES_FILE` is `stores`.
async fn node(stores: &Path) -> Podgate {
    Podgate::start_with_env(&[(
        "RATE_LIMIT_STORES_FILE",
        stores.to_str().expect("utf-8 path"),
    )])
    .await
}

async fn push(podgate: &Podgate, pushed: &Value) {
    let response = podgate.push_snapshot(pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn hit(podgate: &Podgate, host: &str, who: &str) -> Response {
    podgate
        .get_with_headers(host, "/", &[("x-client", who)])
        .await
}

/// The stores file naming `store` as `main` for tenant `t1`.
fn one_store(dir: &Path, store: Value) -> std::path::PathBuf {
    valkey::stores_file(dir, &json!({ "main": store }))
}

/// The code of the first rejection of a refused push.
fn rejection_code(response: &Response) -> String {
    assert_eq!(response.status, 422, "{}", response.body);
    response.json()["conflicts"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The message of the first rejection of a refused push.
fn rejection_message(response: &Response) -> String {
    response.json()["conflicts"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// The value of the metric line that starts with `series`.
fn metric(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

/// A header's value as a number.
fn number(response: &Response, name: &str) -> u64 {
    response
        .header(name)
        .unwrap_or_else(|| panic!("no {name} in {response:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not a number in {response:?}"))
}

/// Unix seconds of a UTC civil time, from the `time` crate rather than from podgate.
fn at(year: i32, month: time::Month, day: u8, hour: u8, minute: u8, second: u8) -> u64 {
    let stamp = time::Date::from_calendar_date(year, month, day)
        .expect("a date")
        .with_hms(hour, minute, second)
        .expect("a time")
        .assume_utc()
        .unix_timestamp();
    u64::try_from(stamp).expect("after 1970")
}

/// Seconds left of the UTC day at `now`.
fn day_left(now: u64) -> u64 {
    86_400 - now % 86_400
}

/// Waits out the last seconds of a UTC day, so a test that counts in the day window is not
/// split by midnight.
async fn clear_of_midnight() {
    let left = day_left(now_secs());
    if left < 8 {
        sleep(Duration::from_secs(left + 1)).await;
    }
}

/// A real store, the way a node loads it, for the counter tests.
async fn library_store(dir: &Path, valkey: &Valkey) -> Arc<Store> {
    let stores = Stores::load(&one_store(dir, valkey::entry(valkey.addr()))).expect("stores");
    Arc::clone(stores.get("main").expect("main"))
}

fn counter(limit: u64, period: Period) -> Arc<Counter> {
    Counter::new("t1", "a", "plan", 7, period, limit, None)
}

fn usage(limit: u64, used: u64, reset_secs: u32) -> Usage {
    Usage {
        limit,
        used,
        reset_secs,
    }
}

/// A server that answers 200 with a `RateLimit-Remaining` of its own.
async fn opinionated_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let reply = "HTTP/1.1 200 OK\r\nRateLimit-Remaining: 999\r\nRateLimit-Limit: 5000\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                drop(stream.write_all(reply.as_bytes()).await);
            });
        }
    });
    addr
}

#[tokio::test]
async fn quota_shared_across_nodes() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-shared");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let (first, second) = (node(&stores).await, node(&stores).await);
    let pushed = snapshot(1, &[planned(upstream.addr, quota(10, deny()))]);
    push(&first, &pushed).await;
    push(&second, &pushed).await;

    let (mut admitted, mut refused) = (0, 0);
    for round in 0..30 {
        let node = if round % 2 == 0 { &first } else { &second };
        let response = hit(node, "a.test", "client-1").await;
        match response.status {
            200 => admitted += 1,
            429 => refused += 1,
            other => panic!("unexpected status {other}: {response:?}"),
        }
    }
    // Each node alone would admit its own 10, 20 in all.
    assert_eq!(admitted, 10, "the sum across both nodes stays at the limit");
    assert_eq!(refused, 20);
    let other = hit(&first, "a.test", "client-2").await;
    assert_eq!(other.status, 200, "another source has its own count");
}

#[tokio::test]
async fn quota_429_retry_after_is_window_end() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-retry");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(1, deny()))]),
    )
    .await;

    assert_eq!(hit(&podgate, "a.test", "client").await.status, 200);
    let before = now_secs();
    let refused = hit(&podgate, "a.test", "client").await;
    let after = now_secs();
    assert_eq!(refused.status, 429, "{refused:?}");
    assert_eq!(refused.json(), json!({"error": "quota exceeded"}));
    let retry = number(&refused, "retry-after");
    assert!(
        (day_left(after)..=day_left(before)).contains(&retry),
        "retry-after {retry} is the time to UTC midnight, between {} and {}",
        day_left(after),
        day_left(before)
    );
    assert_eq!(number(&refused, "ratelimit-reset"), retry);
    assert_eq!(number(&refused, "ratelimit-remaining"), 0);
    assert_eq!(number(&refused, "ratelimit-limit"), 1);
}

#[tokio::test]
async fn quota_headers_on_every_answer() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = opinionated_upstream().await;
    let dir = valkey::scratch("quota-headers");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[planned(upstream, quota(2, deny()))]),
    )
    .await;

    for (status, remaining) in [(200, 1), (200, 0), (429, 0)] {
        let response = hit(&podgate, "a.test", "client").await;
        assert_eq!(response.status, status, "{response:?}");
        assert_eq!(
            number(&response, "ratelimit-limit"),
            2,
            "the upstream's own value is replaced: {response:?}"
        );
        assert_eq!(number(&response, "ratelimit-remaining"), remaining);
        let reset = number(&response, "ratelimit-reset");
        assert!((1..=86_400).contains(&reset), "{response:?}");
    }
}

#[tokio::test]
async fn quota_resets_at_utc_window() {
    let valkey = Valkey::start().await;
    let dir = valkey::scratch("quota-reset");
    let store = library_store(&dir, &valkey).await;
    let bound = counter(2, Period::Day).bind(&store, SourceId::of(b"client"));
    let last = at(2026, time::Month::November, 22, 23, 59, 59);

    assert_eq!(
        bound.admit(1, last).await.expect("admit"),
        Admission::Admitted(usage(2, 1, 1))
    );
    assert_eq!(
        bound.admit(1, last).await.expect("admit"),
        Admission::Admitted(usage(2, 2, 1))
    );
    assert_eq!(
        bound.admit(1, last).await.expect("admit"),
        Admission::Exhausted(usage(2, 2, 1)),
        "spent, one second to midnight"
    );
    // One second later it is the next UTC day, and the count starts at zero.
    assert_eq!(
        bound.admit(1, last + 1).await.expect("admit"),
        Admission::Admitted(usage(2, 1, 86_400))
    );
    // A window of another period is a window of its own: the minute that holds `last`.
    let minute = counter(1, Period::Minute).bind(&store, SourceId::of(b"client"));
    assert!(matches!(
        minute.admit(1, last).await.expect("admit"),
        Admission::Admitted(_)
    ));
    assert!(matches!(
        minute.admit(1, last).await.expect("admit"),
        Admission::Exhausted(_)
    ));
    assert!(matches!(
        minute.admit(1, last + 1).await.expect("admit"),
        Admission::Admitted(_)
    ));
}

#[tokio::test]
async fn quota_month_boundary() {
    let valkey = Valkey::start().await;
    let dir = valkey::scratch("quota-month");
    let store = library_store(&dir, &valkey).await;
    let bound = counter(1, Period::Month).bind(&store, SourceId::of(b"client"));
    let admitted = |answer: Admission| matches!(answer, Admission::Admitted(_));

    // 31 January into 1 February, 28 February into 1 March in a common year, and in a leap year
    // 28 February is still February and 29 February is its last day.
    let last_second = |year, month, day| at(year, month, day, 23, 59, 59);
    for (year, month, day, next) in [
        (
            2026,
            time::Month::January,
            31,
            (2026, time::Month::February, 1),
        ),
        (
            2027,
            time::Month::February,
            28,
            (2027, time::Month::March, 1),
        ),
        (
            2028,
            time::Month::February,
            29,
            (2028, time::Month::March, 1),
        ),
        (
            2026,
            time::Month::December,
            31,
            (2027, time::Month::January, 1),
        ),
    ] {
        let last = last_second(year, month, day);
        let first = at(next.0, next.1, next.2, 0, 0, 0);
        assert_eq!(first, last + 1);
        assert!(
            admitted(bound.admit(1, last).await.expect("admit")),
            "{year}-{month}"
        );
        assert!(
            !admitted(bound.admit(1, last).await.expect("admit")),
            "{year}-{month} is spent"
        );
        assert!(
            admitted(bound.admit(1, first).await.expect("admit")),
            "{year}-{month}: the first second of the next month starts at zero"
        );
    }
    let leap_day = at(2028, time::Month::February, 28, 23, 59, 59);
    assert!(
        !admitted(bound.admit(1, leap_day + 1).await.expect("admit")),
        "29 February 2028 is still the month that 28 February is in"
    );
    let Admission::Exhausted(shown) = bound.admit(1, leap_day).await.expect("admit") else {
        panic!("spent");
    };
    assert_eq!(
        u64::from(shown.reset_secs),
        at(2028, time::Month::March, 1, 0, 0, 0) - leap_day
    );
}

#[tokio::test]
async fn quota_limit_change_keeps_count() {
    let valkey = Valkey::start().await;
    let dir = valkey::scratch("quota-limit-change");
    let store = library_store(&dir, &valkey).await;
    let now = at(2026, time::Month::November, 22, 12, 0, 0);
    // The same middleware at another limit: the fingerprint of the key does not hold the limit.
    let at_limit = |limit| {
        Counter::new("t1", "a", "plan", 7, Period::Month, limit, None)
            .bind(&store, SourceId::of(b"client"))
    };
    let charged = at_limit(10_000).charge(3, now).await.expect("charge");
    assert_eq!(charged.used, 3);

    // Lowered below what was used: refused at once, nothing handed out again.
    assert!(matches!(
        at_limit(2).admit(1, now).await.expect("admit"),
        Admission::Exhausted(shown) if shown.used == 3 && shown.limit == 2
    ));
    // Lowered to just above: one more passes.
    assert!(matches!(
        at_limit(4).admit(1, now).await.expect("admit"),
        Admission::Admitted(shown) if shown.used == 4 && shown.limit == 4
    ));
    assert!(matches!(
        at_limit(4).admit(1, now).await.expect("admit"),
        Admission::Exhausted(shown) if shown.used == 4
    ));
    // Raised: exactly the difference is free.
    assert!(matches!(
        at_limit(6).admit(1, now).await.expect("admit"),
        Admission::Admitted(shown) if shown.used == 5 && shown.remaining() == 1
    ));
    assert_eq!(
        valkey.keys("podgate:q:t1:a:plan:*").len(),
        1,
        "one count throughout"
    );
}

#[tokio::test]
async fn quota_overspend_then_refused() {
    let valkey = Valkey::start().await;
    let dir = valkey::scratch("quota-overspend");
    let store = library_store(&dir, &valkey).await;
    let bound = counter(10, Period::Day).bind(&store, SourceId::of(b"client"));
    let now = at(2026, time::Month::November, 22, 12, 0, 0);

    let charged = bound.charge(9, now).await.expect("charge");
    assert_eq!((charged.used, charged.remaining()), (9, 1));
    // One unit is left, so the check passes: the amount of the response is not known yet.
    assert!(matches!(
        bound.admit(0, now).await.expect("admit"),
        Admission::Admitted(_)
    ));
    // The response turns out to have cost 5: an over-spend, allowed once.
    let over = bound.charge(5, now).await.expect("charge");
    assert_eq!((over.used, over.remaining()), (14, 0));
    // Then the source is refused, whether the next call takes a unit or not.
    for cost in [0, 1] {
        let Admission::Exhausted(shown) = bound.admit(cost, now).await.expect("admit") else {
            panic!(
                "a source that spent {} of {} is refused",
                over.used, over.limit
            );
        };
        assert_eq!(shown.remaining(), 0);
    }
    // A check that takes nothing creates nothing: another source has no key yet.
    let other = counter(10, Period::Day).bind(&store, SourceId::of(b"other"));
    assert!(matches!(
        other.admit(0, now).await.expect("admit"),
        Admission::Admitted(usage) if usage.used == 0
    ));
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 1);
}

#[tokio::test]
async fn quota_charge_after_response() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-charge");
    let stores = one_store(&dir, valkey::entry(valkey.addr()));
    let podgate = node(&stores).await;
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(10, deny()))]),
    )
    .await;
    let first = hit(&podgate, "a.test", "client-1").await;
    assert_eq!(number(&first, "ratelimit-remaining"), 9, "{first:?}");

    // What the AI token limit does after a response: charge the key the node made for this
    // source, with the amount the response cost.
    let keys = valkey.keys("podgate:q:t1:a:plan:*");
    assert_eq!(keys.len(), 1, "{keys:?}");
    let fingerprint = u64::from_str_radix(keys[0].split(':').nth(5).expect("fingerprint"), 16)
        .expect("a hex fingerprint");
    let store = library_store(&dir, &valkey).await;
    let bound = Counter::new("t1", "a", "plan", fingerprint, Period::Day, 10, None)
        .bind(&store, SourceId::of(b"client-1"));
    let charged = bound.charge(5, now_secs()).await.expect("charge");
    assert_eq!(charged.used, 6);

    let next = hit(&podgate, "a.test", "client-1").await;
    assert_eq!(next.status, 200, "{next:?}");
    assert_eq!(
        number(&next, "ratelimit-remaining"),
        3,
        "10 - 6 - this request"
    );
    let other = hit(&podgate, "a.test", "client-2").await;
    assert_eq!(number(&other, "ratelimit-remaining"), 9, "nobody else paid");
}

#[tokio::test]
async fn quota_keys_isolated() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-isolated");
    let mut entry = valkey::entry(valkey.addr());
    entry["tenants"] = json!(["t1", "t2"]);
    let podgate = node(&one_store(&dir, entry)).await;
    let build = |version: u64, limit: u64, failure: Value| {
        let first = planned(upstream.addr, quota(limit, failure));
        let mut second = with_chain(
            app("b", &["b.test"], &[serving("r1", upstream.addr)]),
            &[middleware("plan", "quota", quota(1, deny()))],
        );
        second["tenant"] = json!("t2");
        // One app with two quotas of its own: the middleware name is part of the key.
        let third = with_chain(
            app("c", &["c.test"], &[serving("r1", upstream.addr)]),
            &[
                middleware("m1", "quota", quota(5, deny())),
                middleware("m2", "quota", quota(5, deny())),
            ],
        );
        let mut pushed = snapshot(version, &[first, second, third]);
        pushed["tenants"] = json!([
            {"id": "t1", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 1_048_576}},
            {"id": "t2", "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 1_048_576}},
        ]);
        pushed
    };
    push(&podgate, &build(1, 1, deny())).await;

    assert_eq!(hit(&podgate, "a.test", "same").await.status, 200);
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 429);
    assert_eq!(
        hit(&podgate, "b.test", "same").await.status,
        200,
        "the same source in another tenant has its own count"
    );
    assert_eq!(hit(&podgate, "c.test", "same").await.status, 200);
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 1);
    assert_eq!(valkey.keys("podgate:q:t2:b:plan:*").len(), 1);
    assert_eq!(valkey.keys("podgate:q:t1:c:m1:*").len(), 1);
    assert_eq!(valkey.keys("podgate:q:t1:c:m2:*").len(), 1);
    assert_eq!(valkey.keys("podgate:q:*").len(), 4);

    // A changed limit keeps the count (see `quota_limit_change_keeps_count`): the one used is
    // judged against the new limit of 2, so one more passes and then it is spent.
    push(&podgate, &build(2, 2, deny())).await;
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 200);
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 1);
    // Nor does the failure choice name a count.
    push(&podgate, &build(3, 2, allow())).await;
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 429);
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 1);

    // Another period is another count: its first request passes though this one is spent.
    let mut hourly = quota(2, deny());
    hourly["period"] = json!("hour");
    let mut pushed = build(4, 2, deny());
    pushed["apps"][0] = planned(upstream.addr, hourly);
    push(&podgate, &pushed).await;
    assert_eq!(hit(&podgate, "a.test", "same").await.status, 200);
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 2);

    // Another source in the same app is another count.
    assert_eq!(hit(&podgate, "a.test", "different").await.status, 200);
}

#[tokio::test]
async fn quota_source_hashed_in_key() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-hashed");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let by_ip = with_chain(
        app("b", &["b.test"], &[serving("r1", upstream.addr)]),
        &[middleware("plan", "quota", {
            let mut config = quota(5, deny());
            config["source"] = json!({"ip": {}});
            config
        })],
    );
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(5, deny())), by_ip]),
    )
    .await;
    let api_key = "sk-live-planted-api-key-81c4";
    assert_eq!(hit(&podgate, "a.test", api_key).await.status, 200);
    assert_eq!(hit(&podgate, "b.test", "anything").await.status, 200);

    let keys = valkey.keys("podgate:q:*");
    assert_eq!(keys.len(), 2, "{keys:?}");
    for key in &keys {
        assert!(!key.contains(api_key), "{key}");
        assert!(!key.contains("127.0.0.1"), "{key}");
        let source = key.rsplit(':').next().expect("source part");
        assert_eq!(source.len(), 32, "16 bytes of SHA-256 as hex: {key}");
        assert!(source.bytes().all(|byte| byte.is_ascii_hexdigit()), "{key}");
    }
    let window = keys[0].rsplit(':').nth(1).expect("window id");
    assert_eq!(window.len(), 8, "a day window id: {}", keys[0]);
    assert!(
        valkey
            .cli(&["PTTL", &keys[0]])
            .parse::<u64>()
            .expect("a time to live")
            > 0,
        "a key expires with its window"
    );
}

#[tokio::test]
async fn quota_store_down_deny() {
    clear_of_midnight().await;
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-deny");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(100, deny()))]),
    )
    .await;
    assert_eq!(hit(&podgate, "a.test", "client").await.status, 200);

    valkey.stop();
    for _ in 0..8 {
        let response = hit(&podgate, "a.test", "client").await;
        assert_eq!(response.status, 503, "{response:?}");
        assert_eq!(response.header("retry-after"), Some("1"));
        assert_eq!(response.json(), json!({"error": "quota unavailable"}));
    }
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_quota_store_errors_total{store="main",mode="deny"}"#
        ),
        Some(8)
    );
    assert_eq!(
        metric(&metrics, r#"podgate_quota_store_up{store="main"}"#),
        Some(0)
    );
}

#[tokio::test]
async fn quota_store_down_allow() {
    clear_of_midnight().await;
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-allow");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(1, allow()))]),
    )
    .await;
    let counted = hit(&podgate, "a.test", "client").await;
    assert_eq!(number(&counted, "ratelimit-remaining"), 0, "{counted:?}");
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_quota_unmetered_total{store="main"}"#),
        Some(0),
        "nothing is unmetered while the store answers"
    );

    valkey.stop();
    for _ in 0..6 {
        // Over the quota in the store, and admitted: with the store down nobody counts it.
        let response = hit(&podgate, "a.test", "client").await;
        assert_eq!(response.status, 200, "{response:?}");
        assert!(
            response.header("ratelimit-remaining").is_none(),
            "what is left is unknown: {response:?}"
        );
    }
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_quota_unmetered_total{store="main"}"#),
        Some(6)
    );
    assert_eq!(
        metric(
            &metrics,
            r#"podgate_quota_store_errors_total{store="main",mode="allow"}"#
        ),
        Some(6)
    );
}

#[tokio::test]
async fn quota_store_recovers() {
    clear_of_midnight().await;
    let mut valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-recovers");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let open = with_chain(
        app("b", &["b.test"], &[serving("r1", upstream.addr)]),
        &[middleware("plan", "quota", quota(10, allow()))],
    );
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(10, deny())), open]),
    )
    .await;
    assert_eq!(hit(&podgate, "a.test", "client").await.status, 200);

    // Five errors open the circuit.
    valkey.stop();
    for _ in 0..5 {
        assert_eq!(hit(&podgate, "a.test", "client").await.status, 503);
    }
    assert_eq!(
        hit(&podgate, "b.test", "client").await.status,
        200,
        "allow admits while the store is down"
    );
    valkey.restart().await;

    // Open for OPEN_FOR, then one request probes the returned store.
    let deadline = Instant::now() + OPEN_FOR + Duration::from_secs(10);
    loop {
        let response = hit(&podgate, "a.test", "client").await;
        if response.status == 200 {
            // The restarted store is empty, so this is the first request it has seen.
            assert_eq!(number(&response, "ratelimit-remaining"), 9, "{response:?}");
            break;
        }
        assert_eq!(response.status, 503, "{response:?}");
        assert!(Instant::now() < deadline, "deny never recovered");
        sleep(Duration::from_millis(250)).await;
    }
    let metered = hit(&podgate, "b.test", "client").await;
    assert_eq!(metered.status, 200, "{metered:?}");
    assert_eq!(
        number(&metered, "ratelimit-remaining"),
        9,
        "allow counts again: {metered:?}"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        metric(&metrics, r#"podgate_quota_store_up{store="main"}"#),
        Some(1)
    );
}

/// Two jwt_auth-protected apps' worth of setup: a `jwt_auth` copying `sub` into `X-User`, then
/// a quota counting by that claim.
fn claim_app(upstream: SocketAddr, signer: &Signer, limit: u64) -> Value {
    let jwt = json!({
        "keys": {"keys": [signer.jwk()]}, "algorithms": ["ES256"],
        "forward_claims": {"sub": "X-User"},
    });
    with_middleware(
        with_jwt_auth(app("a", &["a.test"], &[serving("r1", upstream)]), jwt),
        "plan",
        "quota",
        json!({
            "limit": limit, "period": "day", "source": {"jwt_claim": "sub"},
            "store": "main", "on_store_error": "deny",
        }),
    )
}

async fn as_subject(
    podgate: &Podgate,
    signer: &Signer,
    claims: &Value,
    extra: &[(&str, &str)],
) -> Response {
    let token = signer.sign("ES256", &json!({}), claims);
    let bearer = format!("Bearer {token}");
    let mut headers = vec![("Authorization", bearer.as_str())];
    headers.extend_from_slice(extra);
    podgate.get_with_headers("a.test", "/", &headers).await
}

#[tokio::test]
async fn quota_jwt_claim_source() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-claim");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let signer = Signer::es256("k1");
    push(
        &podgate,
        &snapshot(1, &[claim_app(upstream.addr, &signer, 1)]),
    )
    .await;
    let claims = |sub: &str| json!({"sub": sub, "exp": now() + 600});

    assert_eq!(
        as_subject(&podgate, &signer, &claims("ann"), &[])
            .await
            .status,
        200
    );
    assert_eq!(
        as_subject(&podgate, &signer, &claims("ann"), &[])
            .await
            .status,
        429
    );
    assert_eq!(
        as_subject(&podgate, &signer, &claims("bob"), &[])
            .await
            .status,
        200,
        "another subject counts apart"
    );
    // A client's own X-User never decides whose quota it spends.
    assert_eq!(
        as_subject(&podgate, &signer, &claims("ann"), &[("X-User", "carol")])
            .await
            .status,
        429
    );
    assert_eq!(
        podgate.get("a.test", "/").await.status,
        401,
        "no token: jwt_auth refuses before the quota counts"
    );
    assert_eq!(valkey.keys("podgate:q:t1:a:plan:*").len(), 2);
}

#[tokio::test]
async fn quota_jwt_claim_cannot_be_forged() {
    clear_of_midnight().await;
    let valkey = Valkey::start().await;
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-forged");
    let podgate = node(&one_store(&dir, valkey::entry(valkey.addr()))).await;
    let signer = Signer::es256("k1");
    push(
        &podgate,
        &snapshot(1, &[claim_app(upstream.addr, &signer, 2)]),
    )
    .await;

    // A valid token with no `sub`, and a forged, rotating X-User. `jwt_auth` removes the client's
    // copy of every forward_claims header before it verifies (jwt_auth.rs, `request`), so the
    // quota sees no claim and every request counts against the one shared `-` source.
    let claims = json!({"exp": now() + 600});
    let mut statuses = Vec::new();
    for round in 0..5 {
        let forged = format!("forged-{round}");
        statuses.push(
            as_subject(&podgate, &signer, &claims, &[("X-User", &forged)])
                .await
                .status,
        );
    }
    assert_eq!(statuses, [200, 200, 429, 429, 429]);
    assert_eq!(
        valkey.keys("podgate:q:t1:a:plan:*").len(),
        1,
        "one count, not one per forged value"
    );
}

#[tokio::test]
async fn quota_posture_kinds() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-posture");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    let kinds = |response: &Response| -> Vec<String> {
        assert_eq!(response.status, 200, "{}", response.body);
        let mut kinds: Vec<String> = response.json()["posture_changes"]
            .as_array()
            .expect("posture_changes")
            .iter()
            .map(|change| change["kind"].as_str().expect("kind").to_owned())
            .collect();
        kinds.sort();
        kinds
    };
    let plan = |pushed: Value| {
        let podgate = &podgate;
        async move { podgate.admin_post("/v1/snapshot/plan", &pushed).await }
    };
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut config = quota(10, deny());
        edit(&mut config);
        snapshot(2, &[planned(upstream.addr, config)])
    };
    push(
        &podgate,
        &snapshot(1, &[planned(upstream.addr, quota(10, deny()))]),
    )
    .await;

    assert!(kinds(&plan(with(&|config| config["limit"] = json!(5))).await).is_empty());
    assert_eq!(
        kinds(&plan(with(&|config| config["limit"] = json!(11))).await),
        ["quota_loosened"]
    );
    assert_eq!(
        kinds(&plan(with(&|config| config["period"] = json!("hour"))).await),
        ["quota_loosened"],
        "10 an hour lets more through than 10 a day"
    );
    let monthly = with(&|config| config["period"] = json!("month"));
    assert!(
        kinds(&plan(monthly).await).is_empty(),
        "10 a month is stricter than 10 a day"
    );
    assert_eq!(
        kinds(&plan(with(&|config| config["source"] = json!({"host": true}))).await),
        ["quota_source_changed"]
    );
    assert_eq!(
        kinds(&plan(with(&|config| config["on_store_error"] = json!("allow"))).await),
        ["quota_fail_open"]
    );
    let removed = snapshot(
        2,
        &[with_chain(
            app("a", &["a.test"], &[serving("r1", upstream.addr)]),
            &[],
        )],
    );
    assert_eq!(kinds(&plan(removed).await), ["quota_removed"]);
}

#[tokio::test]
async fn quota_requires_store_and_failure_mode() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-config");
    let podgate = node(&one_store(&dir, valkey::entry(refused.addr))).await;
    let with = |edit: &dyn Fn(&mut Value)| {
        let mut config = quota(5, deny());
        edit(&mut config);
        snapshot(1, &[planned(upstream.addr, config)])
    };
    let wrong: Vec<(&str, Value)> = vec![
        (
            "no on_store_error",
            with(&|config| {
                config
                    .as_object_mut()
                    .expect("object")
                    .remove("on_store_error");
            }),
        ),
        (
            "no store",
            with(&|config| {
                config.as_object_mut().expect("object").remove("store");
            }),
        ),
        (
            "unknown store",
            with(&|config| config["store"] = json!("nope")),
        ),
        (
            "an empty store name",
            with(&|config| config["store"] = json!("")),
        ),
        (
            "unknown mode",
            with(&|config| config["on_store_error"] = json!("shrug")),
        ),
        (
            "a node scope",
            with(&|config| config["scope"] = json!("node")),
        ),
        (
            "a local fallback",
            with(&|config| config["local_fallback"] = json!({"average": 1, "burst": 1})),
        ),
        (
            "a limit of zero",
            with(&|config| config["limit"] = json!(0)),
        ),
        (
            "a limit over 2^40",
            with(&|config| config["limit"] = json!((1_u64 << 40) + 1)),
        ),
        (
            "an unknown period",
            with(&|config| config["period"] = json!("week")),
        ),
        (
            "no period",
            with(&|config| {
                config.as_object_mut().expect("object").remove("period");
            }),
        ),
        (
            "no source",
            with(&|config| {
                config.as_object_mut().expect("object").remove("source");
            }),
        ),
        (
            "an address in the snapshot",
            with(&|config| config["url"] = json!("redis://127.0.0.1:6379")),
        ),
        (
            "timeout over the cap",
            with(&|config| config["store_timeout_ms"] = json!(201)),
        ),
        (
            "timeout of zero",
            with(&|config| config["store_timeout_ms"] = json!(0)),
        ),
        (
            "a claim with no jwt_auth",
            with(&|config| config["source"] = json!({"jwt_claim": "sub"})),
        ),
        (
            "an empty claim",
            with(&|config| config["source"] = json!({"jwt_claim": ""})),
        ),
    ];
    for (what, pushed) in &wrong {
        let response = podgate.push_snapshot(pushed).await;
        assert_eq!(
            rejection_code(&response),
            "invalid_middleware",
            "{what}: {}",
            response.body
        );
    }
    let message = rejection_message(&podgate.push_snapshot(&wrong[0].1).await);
    assert!(message.contains("on_store_error"), "{message}");
    let message = rejection_message(&podgate.push_snapshot(&wrong[1].1).await);
    assert!(message.contains("no node scope"), "{message}");

    // A claim only counts when a jwt_auth earlier in the chain puts it into a header.
    let signer = Signer::es256("k1");
    let jwt = |forward: Value| json!({"keys": {"keys": [signer.jwk()]}, "algorithms": ["ES256"], "forward_claims": forward});
    let claim = json!({"limit": 5, "period": "day", "source": {"jwt_claim": "sub"},
                       "store": "main", "on_store_error": "deny"});
    let site = |first: (&str, &str, Value), second: (&str, &str, Value)| {
        let a = app("a", &["a.test"], &[serving("r1", upstream.addr)]);
        let a = with_middleware(a, first.0, first.1, first.2);
        snapshot(1, &[with_middleware(a, second.0, second.1, second.2)])
    };
    let before = site(
        ("plan", "quota", claim.clone()),
        ("jwt", "jwt_auth", jwt(json!({"sub": "X-User"}))),
    );
    let response = podgate.push_snapshot(&before).await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "{}",
        response.body
    );
    let other_claim = site(
        ("jwt", "jwt_auth", jwt(json!({"email": "X-Email"}))),
        ("plan", "quota", claim.clone()),
    );
    let response = podgate.push_snapshot(&other_claim).await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "{}",
        response.body
    );
    let good = site(
        ("jwt", "jwt_auth", jwt(json!({"sub": "X-User"}))),
        ("plan", "quota", claim),
    );
    push(&podgate, &good).await;
}

#[tokio::test]
async fn quota_store_forbidden_for_tenant() {
    let refused = common::refused();
    let upstream = Upstream::start("ok").await;
    let dir = valkey::scratch("quota-forbidden");
    let mut entry = valkey::entry(refused.addr);
    entry["tenants"] = json!(["someone-else"]);
    let podgate = node(&one_store(&dir, entry)).await;

    let try_store = |name: &str| {
        let mut config = quota(5, deny());
        config["store"] = json!(name);
        snapshot(1, &[planned(upstream.addr, config)])
    };
    let forbidden = podgate.push_snapshot(&try_store("main")).await;
    assert_eq!(
        rejection_code(&forbidden),
        "invalid_middleware",
        "{}",
        forbidden.body
    );
    let unknown = podgate.push_snapshot(&try_store("other")).await;
    assert_eq!(
        rejection_code(&unknown),
        "invalid_middleware",
        "{}",
        unknown.body
    );
    assert_eq!(
        rejection_message(&forbidden).replace("main", "NAME"),
        rejection_message(&unknown).replace("other", "NAME"),
        "a store that exists and one the tenant may not use read the same"
    );

    // No store file at all: no store exists, and a quota has no node scope to fall back on.
    let bare = Podgate::start().await;
    let response = bare.push_snapshot(&try_store("main")).await;
    assert_eq!(
        rejection_code(&response),
        "invalid_middleware",
        "{}",
        response.body
    );
}
