//! The counter of quotas: how many units a source has used in the current calendar window,
//! kept in the shared store so every node counts one quota. Reference: `docs/ref/mw-quota.md`.
//!
//! # Windows
//!
//! A [`Period`] (minute, hour, day, month) cuts time into fixed UTC calendar [`Window`]s, not
//! rolling ones: one counter per window is one key and one `INCRBY`, and "resets at 00:00 UTC on
//! the 1st" is what a plan page promises. The window is named by the node's clock, which every
//! call takes as `now_secs` (tests pass a chosen time, the middleware passes [`now_secs`]).
//! Nodes whose clocks disagree by a second near a boundary count that second in the
//! neighbouring window.
//!
//! # One call
//!
//! [`Counter::bind`] ties a counter to a store and a source; the [`Bound`] it returns is
//! `Clone + Send + 'static`, so a task can own it. [`Bound::admit`] checks and adds in one script
//! call; [`Bound::charge`] adds an amount known only after the response, with no check: an
//! over-spend is allowed and shows on the next [`Bound::admit`]. Both go through
//! [`Store::run`], so they share its tenant share, circuit, connection pool and deadline.
//!
//! # The key
//!
//! `podgate:q:<tenant>:<app>:<middleware>:<fingerprint>:<window id>:<source>`. Tenant, app and
//! middleware are percent-escaped (`:` and `%`) so two tenants can never build the same key; the
//! fingerprint is the declaration's digest, so a changed limit starts fresh counters; the source
//! is the first 16 bytes of the SHA-256 of what identifies it, so no address, header value or
//! claim reaches the store. The key expires at the window end plus a grace.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Script, Store, StoreError};

/// The most a limit or one charge may be: the scripts do their arithmetic in doubles, which
/// count integers exactly up to 2^53.
pub const MAX_LIMIT: u64 = 1 << 40;

/// The last second the window arithmetic handles, 9999-12-31T23:59:59Z.
const MAX_SECS: u64 = 253_402_300_799;

/// Checks a source and adds `ARGV[2]` to it. `ARGV[1]` is the limit and `ARGV[3]` the time to
/// live in milliseconds. Returns `{0, used}` when the source has used its limit up (nothing is
/// added) and `{1, used}` otherwise, `used` counting what was just added. A cost of zero adds
/// nothing and creates no key.
static ADMIT: Script = Script::new(
    "\
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
if used >= tonumber(ARGV[1]) then return {0, used} end
local cost = tonumber(ARGV[2])
if cost > 0 then
  used = redis.call('INCRBY', KEYS[1], cost)
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return {1, used}
",
);

/// Adds `ARGV[1]` with no check. `ARGV[2]` is the time to live in milliseconds. Returns
/// `{used}`. A counter at 2^52 is left as it is, so `INCRBY` can never overflow.
static CHARGE: Script = Script::new(
    "\
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
if used >= 4503599627370496 then return {used} end
used = redis.call('INCRBY', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return {used}
",
);

/// How a quota cuts time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Period {
    /// A calendar minute, UTC.
    Minute,
    /// A calendar hour, UTC.
    Hour,
    /// A calendar day, UTC.
    Day,
    /// A calendar month, UTC.
    Month,
}

/// One window of a [`Period`]: `[start, end)` in unix seconds, and the id its keys carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    start: u64,
    end: u64,
    id: String,
}

impl Window {
    /// The first second of the window.
    #[must_use]
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The first second of the next window.
    #[must_use]
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The window's name in a key: `202611221430` for a minute, `2026112214` for an hour,
    /// `20261122` for a day, `202611` for a month.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Days since 1970-01-01 of the civil date `year-month-day` (month 1 to 12).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date `(year, month, day)` of `days` since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Unix seconds of midnight UTC on the first of `month` of `year`.
fn month_start(year: i64, month: i64) -> u64 {
    u64::try_from(days_from_civil(year, month, 1) * 86_400).unwrap_or(0)
}

impl Period {
    /// The window of this period that holds `now_secs` (unix seconds, UTC).
    #[must_use]
    pub fn window(self, now_secs: u64) -> Window {
        let now = now_secs.min(MAX_SECS);
        let days = i64::try_from(now / 86_400).unwrap_or(0);
        let (year, month, day) = civil_from_days(days);
        let secs = now % 86_400;
        let (hour, minute) = (secs / 3600, secs % 3600 / 60);
        let (start, end, id) = match self {
            Self::Minute => {
                let start = now - now % 60;
                (
                    start,
                    start + 60,
                    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}"),
                )
            }
            Self::Hour => {
                let start = now - now % 3600;
                (
                    start,
                    start + 3600,
                    format!("{year:04}{month:02}{day:02}{hour:02}"),
                )
            }
            Self::Day => {
                let start = now - now % 86_400;
                (
                    start,
                    start + 86_400,
                    format!("{year:04}{month:02}{day:02}"),
                )
            }
            Self::Month => {
                let (next_year, next_month) = if month == 12 {
                    (year + 1, 1)
                } else {
                    (year, month + 1)
                };
                (
                    month_start(year, month),
                    month_start(next_year, next_month),
                    format!("{year:04}{month:02}"),
                )
            }
        };
        Window { start, end, id }
    }

    /// How long a key outlives its window: long enough for a charge that lands late and a node
    /// whose clock runs behind.
    fn grace_secs(self) -> u64 {
        match self {
            Self::Minute => 60,
            Self::Hour => 600,
            Self::Day | Self::Month => 3600,
        }
    }

    /// The seconds a window of this period nominally lasts (a month counts 31 days), to compare
    /// two limits of different periods.
    pub(crate) fn nominal_secs(self) -> u64 {
        match self {
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86_400,
            Self::Month => 2_678_400,
        }
    }

    /// The period as a snapshot writes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// The node's UTC clock in unix seconds: the `now_secs` of production calls.
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What identifies the source a quota counts: the first 16 bytes of the SHA-256 of its material,
/// so the store never sees an address, a header value or a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId([u8; 16]);

impl SourceId {
    /// The id of the source described by `material`: the same bytes give the same id on every
    /// node and every run.
    #[must_use]
    pub fn of(material: &[u8]) -> Self {
        let digest = Sha256::digest(material);
        let mut id = [0_u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }
}

/// What a source has used of its quota, as of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage {
    /// The quota.
    pub limit: u64,
    /// What the source has used in the window, what the call added included.
    pub used: u64,
    /// Seconds until the window ends, at least 1.
    pub reset_secs: u32,
}

impl Usage {
    /// What is left: zero once the source has used the quota up, however far it went over.
    #[must_use]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}

/// What [`Bound::admit`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The source had something left; the cost was added.
    Admitted(Usage),
    /// The source has used its quota up; nothing was added.
    Exhausted(Usage),
}

/// `text` with `%` and `:` escaped, so a key's parts cannot run into each other.
fn escaped(text: &str) -> String {
    text.replace('%', "%25").replace(':', "%3A")
}

/// One quota: where its keys live, its period and its limit. Built when the middleware compiles,
/// shared by every request.
#[derive(Debug)]
pub struct Counter {
    tenant: Box<str>,
    prefix: Box<str>,
    period: Period,
    limit: u64,
    limit_arg: Box<str>,
    timeout: Option<Duration>,
}

impl Counter {
    /// The quota of middleware `middleware` of app `app` of `tenant`, whose declaration digests
    /// to `fingerprint`: `limit` units (at most [`MAX_LIMIT`]) per `period`. Each store call ends
    /// within `timeout` (the store's own when `None`).
    #[must_use]
    pub fn new(
        tenant: &str,
        app: &str,
        middleware: &str,
        fingerprint: u64,
        period: Period,
        limit: u64,
        timeout: Option<Duration>,
    ) -> Arc<Self> {
        let limit = limit.min(MAX_LIMIT);
        Arc::new(Self {
            tenant: tenant.into(),
            prefix: format!(
                "podgate:q:{}:{}:{}:{fingerprint:016x}:",
                escaped(tenant),
                escaped(app),
                escaped(middleware)
            )
            .into(),
            period,
            limit,
            limit_arg: limit.to_string().into(),
            timeout,
        })
    }

    /// Ties the quota to `store` and `source`.
    #[must_use]
    pub fn bind(self: &Arc<Self>, store: &Arc<Store>, source: SourceId) -> Bound {
        store.note_quota_use();
        Bound {
            counter: Arc::clone(self),
            store: Arc::clone(store),
            source,
        }
    }

    /// The store key of `source` in `window`.
    fn key(&self, window: &Window, source: SourceId) -> String {
        let mut key = String::with_capacity(self.prefix.len() + window.id.len() + 33);
        key.push_str(&self.prefix);
        key.push_str(&window.id);
        key.push(':');
        for byte in source.0 {
            // Writing to a `String` cannot fail.
            let _ = write!(key, "{byte:02x}");
        }
        key
    }

    /// The key's time to live, in milliseconds, for a call at `now_secs`.
    fn ttl_ms(&self, window: &Window, now_secs: u64) -> u64 {
        (window.end.saturating_sub(now_secs).max(1) + self.period.grace_secs()) * 1000
    }

    fn usage(&self, window: &Window, now_secs: u64, used: i64) -> Usage {
        Usage {
            limit: self.limit,
            used: u64::try_from(used).unwrap_or(0),
            reset_secs: u32::try_from(window.end.saturating_sub(now_secs).max(1))
                .unwrap_or(u32::MAX),
        }
    }
}

/// A [`Counter`] tied to a store and a source. Cheap to clone and `'static`: a request can hand
/// it to a task that charges after the response.
#[derive(Debug, Clone)]
pub struct Bound {
    counter: Arc<Counter>,
    store: Arc<Store>,
    source: SourceId,
}

impl Bound {
    /// Refuses when the source has used its limit up. Otherwise adds `cost` (at most
    /// [`MAX_LIMIT`]; zero adds nothing, for a check that takes no unit) and admits. `now_secs`
    /// names the window.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] when no verdict could be had; the caller decides what that means for
    /// the request.
    pub async fn admit(&self, cost: u64, now_secs: u64) -> Result<Admission, StoreError> {
        let counter = &*self.counter;
        let window = counter.period.window(now_secs);
        let key = counter.key(&window, self.source);
        let cost = cost.min(MAX_LIMIT).to_string();
        let ttl = counter.ttl_ms(&window, now_secs).to_string();
        let answer = self
            .store
            .run(
                &counter.tenant,
                &ADMIT,
                &key,
                &[&counter.limit_arg, &cost, &ttl],
                counter.timeout,
            )
            .await?;
        match answer.as_slice() {
            [1, used] => Ok(Admission::Admitted(counter.usage(&window, now_secs, *used))),
            [0, used] => Ok(Admission::Exhausted(
                counter.usage(&window, now_secs, *used),
            )),
            _ => Err(StoreError::Unexpected),
        }
    }

    /// Adds `amount` (at most [`MAX_LIMIT`]) to what the source has used, with no check: the
    /// amount was spent already, and an over-spend shows on the next [`Self::admit`]. It lands in
    /// the window that holds `now_secs`, not the one of an earlier check: the units are spent
    /// when the response ends.
    ///
    /// # Errors
    ///
    /// A [`StoreError`] when the store gave no answer; the amount is then not counted.
    pub async fn charge(&self, amount: u64, now_secs: u64) -> Result<Usage, StoreError> {
        let counter = &*self.counter;
        let window = counter.period.window(now_secs);
        let key = counter.key(&window, self.source);
        let amount = amount.min(MAX_LIMIT).to_string();
        let ttl = counter.ttl_ms(&window, now_secs).to_string();
        let answer = self
            .store
            .run(
                &counter.tenant,
                &CHARGE,
                &key,
                &[&amount, &ttl],
                counter.timeout,
            )
            .await?;
        match answer.as_slice() {
            [used] => Ok(counter.usage(&window, now_secs, *used)),
            _ => Err(StoreError::Unexpected),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Unix seconds of a civil time.
    fn at(year: i64, month: i64, day: i64, hour: u64, minute: u64, second: u64) -> u64 {
        u64::try_from(days_from_civil(year, month, day)).expect("after 1970") * 86_400
            + hour * 3600
            + minute * 60
            + second
    }

    fn bounds(period: Period, now: u64) -> (u64, u64, String) {
        let window = period.window(now);
        (window.start(), window.end(), window.id().to_owned())
    }

    #[test]
    fn quota_window_math() {
        // Anchors that are known: the epoch, 2023-11-14T22:13:20Z, 2000-02-29.
        assert_eq!(at(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(at(2023, 11, 14, 22, 13, 20), 1_700_000_000);
        assert_eq!(at(2000, 2, 29, 0, 0, 0), 951_782_400);
        assert_eq!(civil_from_days(19_675), (2023, 11, 14));

        let now = at(2026, 11, 22, 14, 30, 45);
        assert_eq!(
            bounds(Period::Minute, now),
            (
                at(2026, 11, 22, 14, 30, 0),
                at(2026, 11, 22, 14, 31, 0),
                "202611221430".to_owned()
            )
        );
        assert_eq!(
            bounds(Period::Hour, now),
            (
                at(2026, 11, 22, 14, 0, 0),
                at(2026, 11, 22, 15, 0, 0),
                "2026112214".to_owned()
            )
        );
        assert_eq!(
            bounds(Period::Day, now),
            (
                at(2026, 11, 22, 0, 0, 0),
                at(2026, 11, 23, 0, 0, 0),
                "20261122".to_owned()
            )
        );
        assert_eq!(
            bounds(Period::Month, now),
            (
                at(2026, 11, 1, 0, 0, 0),
                at(2026, 12, 1, 0, 0, 0),
                "202611".to_owned()
            )
        );

        // December rolls the year; February knows leap years.
        assert_eq!(
            bounds(Period::Month, at(2026, 12, 31, 23, 59, 59)),
            (
                at(2026, 12, 1, 0, 0, 0),
                at(2027, 1, 1, 0, 0, 0),
                "202612".to_owned()
            )
        );
        assert_eq!(
            Period::Month.window(at(2027, 2, 10, 0, 0, 0)).end(),
            at(2027, 3, 1, 0, 0, 0)
        );
        assert_eq!(
            Period::Month.window(at(2028, 2, 10, 0, 0, 0)).end(),
            at(2028, 3, 1, 0, 0, 0)
        );
        assert_eq!(
            Period::Month.window(at(2100, 2, 10, 0, 0, 0)).end(),
            at(2100, 3, 1, 0, 0, 0)
        );
        assert_eq!(
            Period::Month.window(at(2000, 2, 10, 0, 0, 0)).end(),
            at(2000, 3, 1, 0, 0, 0)
        );

        // The last second belongs to the window it ends; the next second to the next window.
        let last = at(2026, 11, 22, 23, 59, 59);
        assert_eq!(Period::Day.window(last).id(), "20261122");
        assert_eq!(Period::Day.window(last + 1).id(), "20261123");
        assert_eq!(Period::Day.window(last).end(), last + 1);

        // A call on the first second of a window has the whole window left.
        let counter = Counter::new("t", "a", "m", 1, Period::Day, 10, None);
        let window = Period::Day.window(last + 1);
        assert_eq!(counter.usage(&window, last + 1, 1).reset_secs, 86_400);
        // A call on the last second has one second left, never zero.
        let window = Period::Day.window(last);
        assert_eq!(counter.usage(&window, last, 1).reset_secs, 1);
        assert_eq!(counter.usage(&window, last + 5, 1).reset_secs, 1);
    }

    #[test]
    fn quota_key_has_no_source_material() {
        let counter = Counter::new("t:1", "a%b", "m", 0xabc, Period::Day, 10, None);
        let window = Period::Day.window(at(2026, 11, 22, 1, 2, 3));
        let key = counter.key(&window, SourceId::of(b"sk-live-planted-api-key"));
        assert!(
            key.starts_with("podgate:q:t%3A1:a%25b:m:0000000000000abc:20261122:"),
            "{key}"
        );
        assert!(!key.contains("planted"), "{key}");
        let source = key.rsplit(':').next().expect("a source part");
        assert_eq!(source.len(), 32);
        assert!(source.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(
            SourceId::of(b"a"),
            SourceId::of(b"b"),
            "two sources have two ids"
        );
    }
}
