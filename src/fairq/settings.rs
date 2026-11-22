//! The operator's settings for the backend limiter: a JSON file named by `BACKEND_LIMITER_FILE`,
//! read once at startup. Never part of a snapshot: the limiter of an upstream address is shared by
//! every tenant behind it and carries the fairness between them, so no tenant may tune it.
//! Reference: `docs/ref/backend-limiter.md`.
//!
//! ```json
//! { "default": { "max_limit": 512 },
//!   "backends": {
//!     "10.0.0.0/8": { "queue_wait_ms": 1000 },
//!     "10.1.2.3:8080": { "enabled": false } } }
//! ```
//!
//! # Resolution
//!
//! A limiter is created the first time a request names its upstream address, and
//! [`Settings::resolve`] picks its [`Tunables`] then: the built-in values, overlaid with the
//! `default` block, overlaid with every `backends` entry that matches the address from the least
//! to the most specific. An entry is a patch: a field it does not set comes from the entries less
//! specific than it. An exact `ip:port` is the most specific, then the longest CIDR prefix (a bare
//! address is a one-address range). Every combination is resolved and checked at load, so a bad
//! file stops startup and resolving at run time cannot fail.
//!
//! The settings are read once and have no hot reload; restart to change them. A limiter that
//! exists keeps the values it was created with.

use std::fmt;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::{
    BASELINE_DRIFT, INITIAL_LIMIT, MAX_LIMIT, MAX_WAIT, MIN_GRADIENT, MIN_LIMIT, QUEUE_CAP,
    SMOOTHING, TOLERANCE, WINDOW,
};
use crate::service::upstream_policy::{Cidr, Pairs};

/// Range of `initial_limit`, `min_limit` and `max_limit`.
const LIMITS: RangeInclusive<u32> = 1..=1_000_000;
/// Range of `window_samples`.
const WINDOWS: RangeInclusive<u32> = 1..=65_536;
/// Range of `queue_size`.
const QUEUE_SIZES: RangeInclusive<u32> = 0..=65_536;
/// Range of `queue_wait_ms`.
const QUEUE_WAITS_MS: RangeInclusive<u32> = 1..=600_000;
/// Range of `tolerance`.
const TOLERANCES: RangeInclusive<f64> = 1.0..=10.0;
/// Range of `min_gradient`.
const MIN_GRADIENTS: RangeInclusive<f64> = 0.1..=1.0;
/// Range of `smoothing`.
const SMOOTHINGS: RangeInclusive<f64> = 0.01..=1.0;
/// Range of `baseline_drift`.
const BASELINE_DRIFTS: RangeInclusive<f64> = 1.0..=2.0;

/// The settings file has a problem. Names the field that is wrong.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{entry}: {reason}")]
pub struct SettingsError {
    /// The field that is wrong, like `default.max_limit` or `backends["10.0.0.0/8"].queue_size`;
    /// the file path for a file that cannot be read.
    pub entry: Box<str>,
    /// What is wrong with it.
    pub reason: Box<str>,
}

impl SettingsError {
    fn new(entry: impl Into<Box<str>>, reason: impl fmt::Display) -> Self {
        Self {
            entry: entry.into(),
            reason: reason.to_string().into(),
        }
    }
}

/// The gradient limit's own parameters (see the module docs of [`crate::fairq`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Gradient {
    /// The limit a new backend starts with.
    pub(crate) initial_limit: u32,
    /// The limit never falls below this.
    pub(crate) min_limit: u32,
    /// The limit never grows past this.
    pub(crate) max_limit: u32,
    /// How far latency may rise over the baseline before the limit shrinks.
    pub(crate) tolerance: f64,
    /// The strongest shrink of one update.
    pub(crate) min_gradient: f64,
    /// Share of the new target taken by each update.
    pub(crate) smoothing: f64,
    /// Per-window upward creep of the baseline above the floor.
    pub(crate) baseline_drift: f64,
}

impl Default for Gradient {
    fn default() -> Self {
        Self {
            initial_limit: INITIAL_LIMIT,
            min_limit: MIN_LIMIT,
            max_limit: MAX_LIMIT,
            tolerance: TOLERANCE,
            min_gradient: MIN_GRADIENT,
            smoothing: SMOOTHING,
            baseline_drift: BASELINE_DRIFT,
        }
    }
}

/// What one limiter runs with: the values of its address after the file is applied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Tunables {
    /// `false`: no adaptive limit and no queue.
    pub(crate) enabled: bool,
    /// Latency samples per estimate update.
    pub(crate) window_samples: u32,
    /// Most requests one tenant may have waiting for the backend.
    pub(crate) queue_size: usize,
    /// Longest a request waits for a slot.
    pub(crate) queue_wait: Duration,
    /// The gradient limit.
    pub(crate) gradient: Gradient,
}

impl Default for Tunables {
    fn default() -> Self {
        Self {
            enabled: true,
            window_samples: WINDOW,
            queue_size: QUEUE_CAP,
            queue_wait: MAX_WAIT,
            gradient: Gradient::default(),
        }
    }
}

/// One block of the file as written: every field is the raw JSON value, so a wrong one is
/// reported under its own name instead of as a position in the text.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPatch {
    enabled: Option<Value>,
    initial_limit: Option<Value>,
    min_limit: Option<Value>,
    max_limit: Option<Value>,
    window_samples: Option<Value>,
    tolerance: Option<Value>,
    min_gradient: Option<Value>,
    smoothing: Option<Value>,
    baseline_drift: Option<Value>,
    queue_size: Option<Value>,
    queue_wait_ms: Option<Value>,
}

/// A block, checked field by field. A `None` field leaves the value of the block below it.
#[derive(Debug, Default, Clone, Copy)]
struct Patch {
    enabled: Option<bool>,
    initial_limit: Option<u32>,
    min_limit: Option<u32>,
    max_limit: Option<u32>,
    window_samples: Option<u32>,
    tolerance: Option<f64>,
    min_gradient: Option<f64>,
    smoothing: Option<f64>,
    baseline_drift: Option<f64>,
    queue_size: Option<u32>,
    queue_wait_ms: Option<u32>,
}

fn whole(
    entry: &str,
    field: &str,
    value: Option<&Value>,
    range: &RangeInclusive<u32>,
) -> Result<Option<u32>, SettingsError> {
    let Some(value) = value else { return Ok(None) };
    let wrong = |what: &dyn fmt::Display| {
        SettingsError::new(
            format!("{entry}.{field}"),
            format!(
                "{what} is not a whole number from {} to {}",
                range.start(),
                range.end()
            ),
        )
    };
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .filter(|number| range.contains(number))
        .map(Some)
        .ok_or_else(|| wrong(value))
}

fn real(
    entry: &str,
    field: &str,
    value: Option<&Value>,
    range: &RangeInclusive<f64>,
) -> Result<Option<f64>, SettingsError> {
    let Some(value) = value else { return Ok(None) };
    value
        .as_f64()
        .filter(|number| range.contains(number))
        .map(Some)
        .ok_or_else(|| {
            SettingsError::new(
                format!("{entry}.{field}"),
                format!(
                    "{value} is not a number from {} to {}",
                    range.start(),
                    range.end()
                ),
            )
        })
}

impl Patch {
    fn check(entry: &str, raw: &RawPatch) -> Result<Self, SettingsError> {
        let enabled = match &raw.enabled {
            None => None,
            Some(Value::Bool(flag)) => Some(*flag),
            Some(other) => {
                return Err(SettingsError::new(
                    format!("{entry}.enabled"),
                    format!("{other} is not true or false"),
                ));
            }
        };
        Ok(Self {
            enabled,
            initial_limit: whole(entry, "initial_limit", raw.initial_limit.as_ref(), &LIMITS)?,
            min_limit: whole(entry, "min_limit", raw.min_limit.as_ref(), &LIMITS)?,
            max_limit: whole(entry, "max_limit", raw.max_limit.as_ref(), &LIMITS)?,
            window_samples: whole(
                entry,
                "window_samples",
                raw.window_samples.as_ref(),
                &WINDOWS,
            )?,
            tolerance: real(entry, "tolerance", raw.tolerance.as_ref(), &TOLERANCES)?,
            min_gradient: real(
                entry,
                "min_gradient",
                raw.min_gradient.as_ref(),
                &MIN_GRADIENTS,
            )?,
            smoothing: real(entry, "smoothing", raw.smoothing.as_ref(), &SMOOTHINGS)?,
            baseline_drift: real(
                entry,
                "baseline_drift",
                raw.baseline_drift.as_ref(),
                &BASELINE_DRIFTS,
            )?,
            queue_size: whole(entry, "queue_size", raw.queue_size.as_ref(), &QUEUE_SIZES)?,
            queue_wait_ms: whole(
                entry,
                "queue_wait_ms",
                raw.queue_wait_ms.as_ref(),
                &QUEUE_WAITS_MS,
            )?,
        })
    }

    /// This block on top of `base`: a field set here wins.
    fn over(self, base: Self) -> Self {
        Self {
            enabled: self.enabled.or(base.enabled),
            initial_limit: self.initial_limit.or(base.initial_limit),
            min_limit: self.min_limit.or(base.min_limit),
            max_limit: self.max_limit.or(base.max_limit),
            window_samples: self.window_samples.or(base.window_samples),
            tolerance: self.tolerance.or(base.tolerance),
            min_gradient: self.min_gradient.or(base.min_gradient),
            smoothing: self.smoothing.or(base.smoothing),
            baseline_drift: self.baseline_drift.or(base.baseline_drift),
            queue_size: self.queue_size.or(base.queue_size),
            queue_wait_ms: self.queue_wait_ms.or(base.queue_wait_ms),
        }
    }

    /// The values this stack of blocks gives, the built-in ones where no block says. `entry` is
    /// the block on top, which a conflict between the limits is reported under.
    fn finish(self, entry: &str) -> Result<Tunables, SettingsError> {
        let min = self.min_limit.unwrap_or(MIN_LIMIT);
        let max = self.max_limit.unwrap_or(MAX_LIMIT);
        if min > max {
            return Err(SettingsError::new(
                format!("{entry}.min_limit"),
                format!("{min} is above max_limit {max}"),
            ));
        }
        let initial = match self.initial_limit {
            Some(initial) if initial < min => {
                return Err(SettingsError::new(
                    format!("{entry}.initial_limit"),
                    format!("{initial} is below min_limit {min}"),
                ));
            }
            Some(initial) if initial > max => {
                return Err(SettingsError::new(
                    format!("{entry}.initial_limit"),
                    format!("{initial} is above max_limit {max}"),
                ));
            }
            Some(initial) => initial,
            // Nobody chose a start: the built-in one, moved into the range somebody did choose.
            None => INITIAL_LIMIT.clamp(min, max),
        };
        let built_in = Tunables::default();
        let built_in_gradient = built_in.gradient;
        Ok(Tunables {
            enabled: self.enabled.unwrap_or(built_in.enabled),
            window_samples: self.window_samples.unwrap_or(built_in.window_samples),
            queue_size: self.queue_size.map_or(built_in.queue_size, |size| {
                usize::try_from(size).unwrap_or(usize::MAX)
            }),
            queue_wait: self.queue_wait_ms.map_or(built_in.queue_wait, |ms| {
                Duration::from_millis(u64::from(ms))
            }),
            gradient: Gradient {
                initial_limit: initial,
                min_limit: min,
                max_limit: max,
                tolerance: self.tolerance.unwrap_or(built_in_gradient.tolerance),
                min_gradient: self.min_gradient.unwrap_or(built_in_gradient.min_gradient),
                smoothing: self.smoothing.unwrap_or(built_in_gradient.smoothing),
                baseline_drift: self
                    .baseline_drift
                    .unwrap_or(built_in_gradient.baseline_drift),
            },
        })
    }
}

/// Which upstream addresses an entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Matcher {
    /// A range of addresses on any port; a bare address is a range of one.
    Range(Cidr),
    /// One address and port.
    Exact(SocketAddr),
}

impl Matcher {
    fn parse(key: &str) -> Result<Self, String> {
        if let Ok(addr) = key.parse::<SocketAddr>() {
            return Ok(Self::Exact(addr));
        }
        key.parse::<Cidr>()
            .map(Self::Range)
            .map_err(|err| format!("{key:?} is neither an ip:port nor an address or CIDR ({err})"))
    }

    fn matches(&self, addr: SocketAddr) -> bool {
        match self {
            Self::Range(range) => range.contains(addr.ip()),
            Self::Exact(exact) => *exact == addr,
        }
    }

    /// Sort key: the more specific, the larger.
    fn specificity(&self) -> (u8, u8) {
        match self {
            Self::Range(range) => (0, range.prefix()),
            Self::Exact(_) => (1, 0),
        }
    }

    /// Whether every address `inner` matches is matched by `self` too.
    fn covers(&self, inner: &Self) -> bool {
        match (self, inner) {
            (Self::Range(outer), Self::Range(inner)) => {
                outer.prefix() <= inner.prefix() && outer.contains(inner.network())
            }
            (Self::Range(outer), Self::Exact(inner)) => outer.contains(inner.ip()),
            (Self::Exact(outer), Self::Exact(inner)) => outer == inner,
            (Self::Exact(_), Self::Range(_)) => false,
        }
    }
}

/// An entry as written, checked.
struct Entry {
    /// Its key in error messages, `backends["10.0.0.0/8"]`.
    name: String,
    matcher: Matcher,
    patch: Patch,
}

/// An entry with the values its addresses get.
#[derive(Debug, Clone)]
struct Rule {
    matcher: Matcher,
    tunables: Tunables,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    default: Option<RawPatch>,
    backends: Option<Pairs<RawPatch>>,
}

/// The limiter settings of every backend address, from `BACKEND_LIMITER_FILE`. Reference:
/// `docs/ref/backend-limiter.md`.
///
/// ```
/// use podgate::fairq::Settings;
///
/// Settings::parse(
///     r#"{"default": {"max_limit": 512}, "backends": {"10.1.2.3:8080": {"enabled": false}}}"#,
/// )?;
///
/// let wrong = Settings::parse(r#"{"default": {"min_limit": 9, "max_limit": 3}}"#)
///     .expect_err("min_limit is above max_limit");
/// assert_eq!(&*wrong.entry, "default.min_limit");
/// # Ok::<(), podgate::fairq::SettingsError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct Settings {
    default: Tunables,
    /// Least specific first, so the last rule that matches an address is the most specific.
    rules: Box<[Rule]>,
}

impl Settings {
    /// Parses the file contents.
    ///
    /// # Errors
    ///
    /// [`SettingsError`] naming the field that is wrong: an unknown field, a value that is not a
    /// number of the field's range, `min_limit` above `max_limit` or `initial_limit` outside
    /// them, a key that is neither `ip:port` nor an address or CIDR, or two keys for one
    /// address or range.
    pub fn parse(json: &str) -> Result<Self, SettingsError> {
        // A JSON array would otherwise be read positionally as the struct's fields.
        if !json.trim_start().starts_with('{') {
            return Err(SettingsError::new("file", "expected a JSON object"));
        }
        let file: File =
            serde_json::from_str(json).map_err(|err| SettingsError::new("file", err))?;
        let default = match &file.default {
            Some(raw) => Patch::check("default", raw)?,
            None => Patch::default(),
        };
        let default_tunables = default.finish("default")?;
        let mut entries: Vec<Entry> = Vec::new();
        for (key, raw) in file.backends.map_or_else(Vec::new, |pairs| pairs.0) {
            let name = format!("backends[{key:?}]");
            let matcher =
                Matcher::parse(&key).map_err(|reason| SettingsError::new(&*name, reason))?;
            if let Some(known) = entries.iter().find(|known| known.matcher == matcher) {
                return Err(SettingsError::new(
                    name,
                    format!("is the same address or range as {}", known.name),
                ));
            }
            let patch = Patch::check(&name, &raw)?;
            entries.push(Entry {
                name,
                matcher,
                patch,
            });
        }
        entries.sort_by_key(|entry| entry.matcher.specificity());
        let mut rules = Vec::with_capacity(entries.len());
        for (at, entry) in entries.iter().enumerate() {
            // Everything that matches an address this entry matches sits below it in the order,
            // so the stack of an address is the entries that cover this one, then this one.
            let stack = entries
                .iter()
                .take(at)
                .filter(|outer| outer.matcher.covers(&entry.matcher))
                .fold(default, |below, outer| outer.patch.over(below));
            rules.push(Rule {
                matcher: entry.matcher,
                tunables: entry.patch.over(stack).finish(&entry.name)?,
            });
        }
        Ok(Self {
            default: default_tunables,
            rules: rules.into(),
        })
    }

    /// Reads and parses the settings file at `path`.
    ///
    /// # Errors
    ///
    /// [`SettingsError`] when the file cannot be read or [`Self::parse`] refuses it.
    pub fn load(path: &Path) -> Result<Self, SettingsError> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| SettingsError::new(path.display().to_string(), err))?;
        Self::parse(&text)
    }

    /// The values the limiter of `addr` runs with: those of the most specific entry that matches
    /// it, else the default.
    #[must_use]
    pub(crate) fn resolve(&self, addr: SocketAddr) -> Tunables {
        self.rules
            .iter()
            .rev()
            .find(|rule| rule.matcher.matches(addr))
            .map_or(self.default, |rule| rule.tunables)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("socket address")
    }

    fn refused(json: &str) -> SettingsError {
        Settings::parse(json).expect_err(json)
    }

    #[test]
    fn no_file_is_the_built_in_values() {
        let settings = Settings::default();
        assert_eq!(settings.resolve(addr("10.0.0.1:80")), Tunables::default());
        let parsed = Settings::parse("{}").expect("an empty file");
        assert_eq!(parsed.resolve(addr("10.0.0.1:80")), Tunables::default());
    }

    #[test]
    fn built_in_values_are_the_documented_defaults() {
        let built_in = Tunables::default();
        assert!(built_in.enabled);
        assert_eq!(built_in.window_samples, 16);
        assert_eq!(built_in.queue_size, 512);
        assert_eq!(built_in.queue_wait, Duration::from_secs(5));
        assert_eq!(
            built_in.gradient,
            Gradient {
                initial_limit: 32,
                min_limit: 4,
                max_limit: 2048,
                tolerance: 1.25,
                min_gradient: 0.5,
                smoothing: 0.2,
                baseline_drift: 1.0001,
            }
        );
    }

    #[test]
    fn the_most_specific_entry_wins_field_by_field() {
        let json = r#"{
            "default": {"queue_size": 100, "max_limit": 900},
            "backends": {
                "10.1.2.3:80": {"initial_limit": 30},
                "10.1.0.0/16": {"initial_limit": 20, "queue_wait_ms": 700},
                "10.0.0.0/8": {"initial_limit": 10, "queue_wait_ms": 100, "queue_size": 7},
                "10.1.2.4": {"initial_limit": 40}
            }
        }"#;
        let settings = Settings::parse(json).expect("parses");
        let of = |text: &str| settings.resolve(addr(text));

        let outside = of("192.168.0.1:80");
        assert_eq!(outside.gradient.initial_limit, 32);
        assert_eq!(outside.queue_size, 100);
        assert_eq!(outside.gradient.max_limit, 900);

        let wide = of("10.9.9.9:80");
        assert_eq!(wide.gradient.initial_limit, 10);
        assert_eq!(wide.queue_wait, Duration::from_millis(100));
        assert_eq!(wide.queue_size, 7);

        let narrow = of("10.1.9.9:80");
        assert_eq!(narrow.gradient.initial_limit, 20, "the /16 beats the /8");
        assert_eq!(narrow.queue_wait, Duration::from_millis(700));
        assert_eq!(narrow.queue_size, 7, "unset in the /16: the /8's value");

        let exact = of("10.1.2.3:80");
        assert_eq!(exact.gradient.initial_limit, 30, "the exact address wins");
        assert_eq!(exact.queue_wait, Duration::from_millis(700));
        let other_port = of("10.1.2.3:81");
        assert_eq!(
            other_port.gradient.initial_limit, 20,
            "another port: the /16"
        );

        assert_eq!(
            of("10.1.2.4:1").gradient.initial_limit,
            40,
            "a bare address"
        );
        assert_eq!(of("10.1.2.4:2").gradient.initial_limit, 40, "on every port");
        assert_eq!(of("10.1.2.5:1").gradient.initial_limit, 20);
    }

    #[test]
    fn the_order_of_the_entries_does_not_matter() {
        let forward = Settings::parse(
            r#"{"backends": {"10.0.0.0/8": {"queue_size": 1}, "10.1.0.0/16": {"queue_size": 2}}}"#,
        )
        .expect("parses");
        let backward = Settings::parse(
            r#"{"backends": {"10.1.0.0/16": {"queue_size": 2}, "10.0.0.0/8": {"queue_size": 1}}}"#,
        )
        .expect("parses");
        for text in ["10.1.0.1:80", "10.2.0.1:80", "11.0.0.1:80"] {
            assert_eq!(
                forward.resolve(addr(text)),
                backward.resolve(addr(text)),
                "{text}"
            );
        }
        assert_eq!(forward.resolve(addr("10.1.0.1:80")).queue_size, 2);
    }

    #[test]
    fn a_start_nobody_chose_moves_into_the_range_somebody_did() {
        let high = Settings::parse(r#"{"default": {"min_limit": 100}}"#).expect("parses");
        assert_eq!(high.resolve(addr("10.0.0.1:1")).gradient.initial_limit, 100);
        let low = Settings::parse(r#"{"default": {"max_limit": 8}}"#).expect("parses");
        assert_eq!(low.resolve(addr("10.0.0.1:1")).gradient.initial_limit, 8);
    }

    #[test]
    fn ipv6_addresses_and_ranges_match() {
        let settings = Settings::parse(
            r#"{"backends": {"fd00::/8": {"queue_size": 3}, "[fd00::1]:80": {"queue_size": 4}}}"#,
        )
        .expect("parses");
        assert_eq!(settings.resolve(addr("[fd00::9]:80")).queue_size, 3);
        assert_eq!(settings.resolve(addr("[fd00::1]:80")).queue_size, 4);
        assert_eq!(settings.resolve(addr("10.0.0.1:80")).queue_size, 512);
    }

    #[test]
    fn a_value_out_of_range_names_its_field() {
        for (json, entry) in [
            (r#"{"default": {"max_limit": -1}}"#, "default.max_limit"),
            (r#"{"default": {"max_limit": 0}}"#, "default.max_limit"),
            (
                r#"{"default": {"max_limit": 1000001}}"#,
                "default.max_limit",
            ),
            (r#"{"default": {"min_limit": 0}}"#, "default.min_limit"),
            (
                r#"{"default": {"initial_limit": 0}}"#,
                "default.initial_limit",
            ),
            (
                r#"{"default": {"window_samples": 0}}"#,
                "default.window_samples",
            ),
            (r#"{"default": {"queue_size": -1}}"#, "default.queue_size"),
            (
                r#"{"default": {"queue_size": 65537}}"#,
                "default.queue_size",
            ),
            (
                r#"{"default": {"queue_wait_ms": 0}}"#,
                "default.queue_wait_ms",
            ),
            (
                r#"{"default": {"queue_wait_ms": 600001}}"#,
                "default.queue_wait_ms",
            ),
            (r#"{"default": {"tolerance": 0.9}}"#, "default.tolerance"),
            (r#"{"default": {"tolerance": 11}}"#, "default.tolerance"),
            (
                r#"{"default": {"min_gradient": 0}}"#,
                "default.min_gradient",
            ),
            (
                r#"{"default": {"min_gradient": 1.5}}"#,
                "default.min_gradient",
            ),
            (r#"{"default": {"smoothing": 0}}"#, "default.smoothing"),
            (r#"{"default": {"smoothing": 2}}"#, "default.smoothing"),
            (
                r#"{"default": {"baseline_drift": 0.99}}"#,
                "default.baseline_drift",
            ),
            (
                r#"{"default": {"baseline_drift": 3}}"#,
                "default.baseline_drift",
            ),
            (
                r#"{"backends": {"10.0.0.0/8": {"queue_size": -5}}}"#,
                r#"backends["10.0.0.0/8"].queue_size"#,
            ),
        ] {
            assert_eq!(&*refused(json).entry, entry, "{json}");
        }
    }

    #[test]
    fn a_value_of_the_wrong_kind_names_its_field() {
        for (json, entry) in [
            (r#"{"default": {"max_limit": "big"}}"#, "default.max_limit"),
            (r#"{"default": {"max_limit": 1.5}}"#, "default.max_limit"),
            (r#"{"default": {"enabled": 1}}"#, "default.enabled"),
            (r#"{"default": {"enabled": "false"}}"#, "default.enabled"),
            (r#"{"default": {"tolerance": "high"}}"#, "default.tolerance"),
            (
                r#"{"default": {"queue_wait_ms": [5]}}"#,
                "default.queue_wait_ms",
            ),
        ] {
            assert_eq!(&*refused(json).entry, entry, "{json}");
        }
    }

    #[test]
    fn min_above_max_and_a_start_outside_them_are_refused() {
        for (json, entry, reason) in [
            (
                r#"{"default": {"min_limit": 9, "max_limit": 3}}"#,
                "default.min_limit",
                "above max_limit",
            ),
            (
                r#"{"default": {"initial_limit": 2}}"#,
                "default.initial_limit",
                "below min_limit",
            ),
            (
                r#"{"default": {"initial_limit": 5000}}"#,
                "default.initial_limit",
                "above max_limit",
            ),
            (
                r#"{"default": {"max_limit": 50}, "backends": {"10.0.0.0/8": {"min_limit": 100}}}"#,
                r#"backends["10.0.0.0/8"].min_limit"#,
                "above max_limit 50",
            ),
        ] {
            let err = refused(json);
            assert_eq!(&*err.entry, entry, "{json}");
            assert!(err.reason.contains(reason), "{json}: {err}");
        }
    }

    #[test]
    fn an_unknown_key_is_named() {
        for (json, key) in [
            (r#"{"default": {"max_limits": 5}}"#, "max_limits"),
            (
                r#"{"backends": {"10.0.0.1:80": {"enable": false}}}"#,
                "enable",
            ),
            (r#"{"defaults": {}}"#, "defaults"),
        ] {
            let err = refused(json);
            assert!(err.to_string().contains(key), "{json}: {err}");
        }
    }

    #[test]
    fn a_malformed_address_or_range_is_refused_under_its_key() {
        for key in [
            "nope",
            "10.0.0.0.1:80",
            "10.0.0.0/33",
            "10.0.0.1/8",
            "10.0.0.1:99999",
            "[::1]",
            "",
        ] {
            let json = format!(r#"{{"backends": {{"{key}": {{"enabled": false}}}}}}"#);
            let err = refused(&json);
            assert_eq!(&*err.entry, format!("backends[{key:?}]"), "{json}");
        }
    }

    #[test]
    fn two_keys_for_one_address_or_range_are_refused() {
        for (first, second) in [
            ("10.0.0.1", "10.0.0.1/32"),
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("[::1]:80", "[0:0:0:0:0:0:0:1]:80"),
        ] {
            let json = format!(
                r#"{{"backends": {{"{first}": {{"queue_size": 1}}, "{second}": {{"queue_size": 2}}}}}}"#
            );
            let err = Settings::parse(&json).expect_err(&json);
            assert!(
                err.reason.contains("same address or range")
                    || err.to_string().contains("appears twice"),
                "{json}: {err}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_an_object_or_not_there_is_refused() {
        assert_eq!(&*refused("[]").entry, "file");
        assert_eq!(&*refused("not json").entry, "file");
        let err = Settings::load(Path::new("/nonexistent/podgate-limiter.json"))
            .expect_err("no such file");
        assert!(
            err.entry.contains("/nonexistent/podgate-limiter.json"),
            "{err}"
        );
    }
}
