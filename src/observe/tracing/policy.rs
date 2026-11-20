//! The snapshot's `observability.tracing` setting, parsed at compile time.

use std::sync::{Arc, LazyLock};

use http::HeaderName;
use podgate_model::Snapshot;
use serde::Deserialize;
use serde_json::Value;

use crate::compile::Invalid;

/// Most request headers a policy may record as attributes.
const HEADERS_MAX: usize = 16;

/// Headers that carry credentials. A tenant cannot ask for them to be copied into the operator's
/// trace backend.
const CREDENTIALS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// The setting as written. Unknown fields are refused, so `endpoint` or `headers` in a snapshot
/// is an error rather than silently ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    sample_percent: Option<f64>,
    parent_based: Option<bool>,
    propagate: Option<bool>,
    attribute_headers: Option<Vec<String>>,
}

/// How requests are traced: the root sampling rate, whether a caller's sampled flag counts, whether
/// the upstream gets a `traceparent`, and which request headers become attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    hundredths: u32,
    parent_based: bool,
    propagate: bool,
    headers: Box<[HeaderName]>,
}

impl Default for Policy {
    /// Every request is sampled, a caller's flag is honoured, the upstream gets a `traceparent`
    /// and no header is recorded.
    fn default() -> Self {
        Self {
            hundredths: 10_000,
            parent_based: true,
            propagate: true,
            headers: Box::default(),
        }
    }
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_tracing", message)
}

impl Policy {
    /// Parses `{sample_percent?, parent_based?, propagate?, attribute_headers?}`.
    ///
    /// # Errors
    ///
    /// `invalid_tracing` for an unknown field (the collector endpoint is process configuration,
    /// so it is one), a percentage outside `0..=100`, or a header list that is too long, holds
    /// an invalid name or names a credential header.
    pub fn parse(setting: &Value) -> Result<Self, Invalid> {
        let raw = Raw::deserialize(setting).map_err(|err| {
            let message = err.to_string();
            if message.contains("unknown field") {
                invalid(format!(
                    "tracing: {message}; the collector is set by OTEL_EXPORTER_OTLP_ENDPOINT on the node, never in a snapshot"
                ))
            } else {
                invalid(format!("tracing: {message}"))
            }
        })?;
        let mut policy = Self::default();
        if let Some(percent) = raw.sample_percent {
            if !(0.0..=100.0).contains(&percent) {
                return Err(invalid(
                    "tracing: sample_percent must be a number in 0..=100",
                ));
            }
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "percent is in 0..=100, so hundredths fit a u32"
            )]
            let hundredths = (percent * 100.0).round() as u32;
            policy.hundredths = hundredths;
        }
        policy.parent_based = raw.parent_based.unwrap_or(true);
        policy.propagate = raw.propagate.unwrap_or(true);
        if let Some(names) = raw.attribute_headers {
            policy.headers = parse_headers(&names)?;
        }
        Ok(policy)
    }

    /// Whether a root draw `roll` (any `u32`) falls inside the sampling rate.
    #[must_use]
    pub fn samples(&self, roll: u32) -> bool {
        roll % 10_000 < self.hundredths
    }

    /// Whether a caller's sampled flag decides, instead of the sampling rate.
    #[must_use]
    pub fn parent_based(&self) -> bool {
        self.parent_based
    }

    /// Whether the upstream request gets a `traceparent`.
    #[must_use]
    pub fn propagates(&self) -> bool {
        self.propagate
    }

    /// The request headers recorded as attributes, lowercase.
    #[must_use]
    pub fn headers(&self) -> &[HeaderName] {
        &self.headers
    }
}

fn parse_headers(names: &[String]) -> Result<Box<[HeaderName]>, Invalid> {
    if names.len() > HEADERS_MAX {
        return Err(invalid(format!(
            "tracing: attribute_headers lists {} names, at most {HEADERS_MAX} are allowed",
            names.len()
        )));
    }
    let mut parsed: Vec<HeaderName> = Vec::with_capacity(names.len());
    for name in names {
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            invalid(format!(
                "tracing: attribute_headers entry {name:?} is not a header name"
            ))
        })?;
        if CREDENTIALS.contains(&header.as_str()) {
            return Err(invalid(format!(
                "tracing: attribute_headers may not name {header}: it carries credentials"
            )));
        }
        if !parsed.contains(&header) {
            parsed.push(header);
        }
    }
    Ok(parsed.into())
}

/// The snapshot-wide policy: `tracing` absent or `false` traces nothing, `true` or `{}` traces
/// every request with the defaults.
///
/// # Errors
///
/// `invalid_tracing` for a setting [`Policy::parse`] refuses.
pub fn compile(snapshot: &Snapshot) -> Result<Option<Arc<Policy>>, Invalid> {
    match snapshot
        .observability
        .as_ref()
        .and_then(|set| set.tracing.as_ref())
    {
        None | Some(Value::Bool(false)) => Ok(None),
        Some(Value::Bool(true)) => Ok(Some(Arc::new(Policy::default()))),
        Some(setting) => Policy::parse(setting).map(|policy| Some(Arc::new(policy))),
    }
}

/// A router's own `observability.tracing` switch, when it sets one.
#[must_use]
pub fn router_override(observability: &Value) -> Option<bool> {
    observability.get("tracing")?.as_bool()
}

/// The policy that applies to a request: the router's switch over the snapshot's policy. A
/// router that turns tracing on in a snapshot with no policy uses the defaults.
#[must_use]
pub fn effective(snapshot: Option<&Arc<Policy>>, router: Option<bool>) -> Option<&Arc<Policy>> {
    static ENABLED: LazyLock<Arc<Policy>> = LazyLock::new(|| Arc::new(Policy::default()));
    match router {
        Some(false) => None,
        Some(true) => Some(snapshot.unwrap_or(&ENABLED)),
        None => snapshot,
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    #[test]
    fn tracing_policy_defaults() {
        let policy = Policy::parse(&json!({})).expect("parses");
        assert_eq!(policy, Policy::default());
        assert!(policy.samples(9_999));
        assert!(policy.parent_based() && policy.propagates());
    }

    #[test]
    fn tracing_policy_sample_rate_is_a_share_of_rolls() {
        let policy = Policy::parse(&json!({"sample_percent": 25.5})).expect("parses");
        let hits = (0..10_000_u32).filter(|roll| policy.samples(*roll)).count();
        assert_eq!(hits, 2_550);
        let never = Policy::parse(&json!({"sample_percent": 0})).expect("parses");
        assert!((0..10_000_u32).all(|roll| !never.samples(roll)));
    }

    #[test]
    fn tracing_policy_refuses_what_is_unsafe_or_unknown() {
        for bad in [
            json!({"sample_percent": 101}),
            json!({"sample_percent": -1}),
            json!({"sample_percent": "all"}),
            json!({"endpoint": "http://127.0.0.1:4318"}),
            json!({"headers": {"x": "y"}}),
            json!({"propagate": "yes"}),
            json!({"attribute_headers": ["Authorization"]}),
            json!({"attribute_headers": ["cookie"]}),
            json!({"attribute_headers": ["bad header"]}),
            json!({"attribute_headers": (0..17).map(|n| format!("x-h{n}")).collect::<Vec<_>>()}),
            json!([1]),
        ] {
            let err = Policy::parse(&bad).expect_err(&format!("{bad} must be refused"));
            assert_eq!(err.code, "invalid_tracing", "{bad}");
        }
        let unknown = Policy::parse(&json!({"endpoint": "x"})).expect_err("refused");
        assert!(
            unknown.message.contains("OTEL_EXPORTER_OTLP_ENDPOINT"),
            "{}",
            unknown.message
        );
    }

    #[test]
    fn tracing_policy_headers_are_lowercase_and_unique() {
        let policy = Policy::parse(
            &json!({"attribute_headers": ["X-Request-Id", "x-request-id", "Accept"]}),
        )
        .expect("parses");
        let names: Vec<&str> = policy.headers().iter().map(HeaderName::as_str).collect();
        assert_eq!(names, ["x-request-id", "accept"]);
    }

    #[test]
    fn tracing_router_switch_beats_the_snapshot() {
        let snapshot = Arc::new(Policy::default());
        assert!(effective(Some(&snapshot), None).is_some());
        assert!(effective(Some(&snapshot), Some(false)).is_none());
        assert!(effective(None, None).is_none());
        assert!(effective(None, Some(true)).is_some());
    }
}
