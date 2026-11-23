//! The access log settings of a snapshot, parsed once at compile time: which fields and headers
//! a line carries and how each is treated, which requests are logged (filters, sampling) and in
//! which format.

use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::compile::Invalid;

const CODE: &str = "invalid_access_log";

/// Request headers whose values are redacted unless the operator sets them to `keep` by name.
const SENSITIVE: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// The text a redacted value is replaced by.
pub(crate) const REDACTED: &str = "[redacted]";

/// How a line is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Format {
    /// One JSON object per line.
    #[default]
    Json,
    /// The Common Log Format.
    Common,
}

/// One value of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// When the request finished.
    Time,
    /// The request id.
    RequestId,
    /// The entry point the request arrived on.
    EntryPoint,
    /// The tenant of the matched app.
    Tenant,
    /// The matched app.
    App,
    /// The matched router.
    Router,
    /// The service the router names.
    Service,
    /// The revision that served the request.
    Revision,
    /// The upstream server address.
    Server,
    /// The request method.
    Method,
    /// The request host.
    Host,
    /// The request path, without the query.
    Path,
    /// The HTTP version of the client's request.
    Proto,
    /// The status the client got.
    Status,
    /// Request body bytes read from the client.
    BytesIn,
    /// Response body bytes written to the client.
    BytesOut,
    /// Request duration in milliseconds.
    DurationMs,
    /// Time spent on the upstream in milliseconds.
    UpstreamDurationMs,
    /// The client address, as resolved behind trusted proxies.
    ClientIp,
    /// The negotiated TLS version.
    TlsVersion,
    /// The server name the client asked for in the handshake.
    Sni,
    /// Times the request was retried.
    RetryAttempts,
    /// `upstream` or `podgate`: who produced the response.
    Origin,
    /// Why podgate itself refused or failed the request.
    Reason,
    /// The query string. Optional: logged only when named.
    Query,
    /// The `User-Agent` header. Optional.
    UserAgent,
    /// The `Referer` header. Optional.
    Referer,
}

impl Field {
    /// Every field, in the order a JSON line lists them.
    pub const ALL: [Self; 27] = [
        Self::Time,
        Self::RequestId,
        Self::EntryPoint,
        Self::Tenant,
        Self::App,
        Self::Router,
        Self::Service,
        Self::Revision,
        Self::Server,
        Self::Method,
        Self::Host,
        Self::Path,
        Self::Proto,
        Self::Status,
        Self::BytesIn,
        Self::BytesOut,
        Self::DurationMs,
        Self::UpstreamDurationMs,
        Self::ClientIp,
        Self::TlsVersion,
        Self::Sni,
        Self::RetryAttempts,
        Self::Origin,
        Self::Reason,
        Self::Query,
        Self::UserAgent,
        Self::Referer,
    ];

    /// The field's name in a line and in the configuration.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::RequestId => "request_id",
            Self::EntryPoint => "entry_point",
            Self::Tenant => "tenant",
            Self::App => "app",
            Self::Router => "router",
            Self::Service => "service",
            Self::Revision => "revision",
            Self::Server => "server",
            Self::Method => "method",
            Self::Host => "host",
            Self::Path => "path",
            Self::Proto => "proto",
            Self::Status => "status",
            Self::BytesIn => "bytes_in",
            Self::BytesOut => "bytes_out",
            Self::DurationMs => "duration_ms",
            Self::UpstreamDurationMs => "upstream_duration_ms",
            Self::ClientIp => "client_ip",
            Self::TlsVersion => "tls_version",
            Self::Sni => "sni",
            Self::RetryAttempts => "retry_attempts",
            Self::Origin => "origin",
            Self::Reason => "reason",
            Self::Query => "query",
            Self::UserAgent => "user_agent",
            Self::Referer => "referer",
        }
    }

    /// Whether the field is in the default set; the others are logged only when named.
    #[must_use]
    pub fn is_default(self) -> bool {
        !matches!(self, Self::Query | Self::UserAgent | Self::Referer)
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == name)
    }

    /// The position in [`Self::ALL`]: the enum is fieldless and declared in that order.
    fn index(self) -> usize {
        self as usize
    }
}

/// How many leading bits of a client address a `mask` keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mask {
    /// Bits kept of an IPv4 address, 0..=32.
    pub ipv4_bits: u8,
    /// Bits kept of an IPv6 address, 0..=128.
    pub ipv6_bits: u8,
}

impl Mask {
    /// Caddy's `ip_mask` default is none; a /24 and a /48 hide the host and keep the network.
    const DEFAULT: Self = Self {
        ipv4_bits: 24,
        ipv6_bits: 48,
    };

    /// `addr` with every bit past the mask zeroed.
    #[must_use]
    pub fn apply(self, addr: IpAddr) -> IpAddr {
        match addr {
            IpAddr::V4(v4) => {
                let keep = u32::from(self.ipv4_bits.min(32));
                let mask = u32::MAX.checked_shl(32 - keep).unwrap_or(0);
                IpAddr::from((u32::from(v4) & mask).to_be_bytes())
            }
            IpAddr::V6(v6) => {
                let keep = u32::from(self.ipv6_bits.min(128));
                let mask = u128::MAX.checked_shl(128 - keep).unwrap_or(0);
                IpAddr::from((u128::from(v6) & mask).to_be_bytes())
            }
        }
    }
}

/// What a line does with one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Write the value.
    Keep,
    /// Leave the field out.
    Drop,
    /// Write `[redacted]` instead of the value.
    Redact,
    /// Write the client address with its host bits cleared; only for `client_ip`.
    Mask(Mask),
}

/// What a line does with one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAction {
    /// Write the value.
    Keep,
    /// Leave the header out.
    Drop,
    /// Write the name with `[redacted]` as its value.
    Redact,
}

/// The lines that are written: any matching filter selects a line; none set selects all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Filters {
    status: Vec<RangeInclusive<u16>>,
    min_duration: Option<Duration>,
    retry_attempts: Option<u32>,
}

impl Filters {
    fn is_empty(&self) -> bool {
        self.status.is_empty() && self.min_duration.is_none() && self.retry_attempts.is_none()
    }
}

/// The compiled `observability.access_log` of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    format: Format,
    fields: [Action; Field::ALL.len()],
    header_default: HeaderAction,
    header_names: Vec<(Box<str>, HeaderAction)>,
    query_redact: Vec<Box<str>>,
    filters: Filters,
    /// Hundredths of a percent of requests that are logged; `None` logs every selected one.
    sampling: Option<u32>,
}

impl Default for Policy {
    /// What `access_log: {}` means: the default fields, no headers, every request.
    fn default() -> Self {
        Self {
            format: Format::Json,
            fields: Field::ALL.map(|field| {
                if field.is_default() {
                    Action::Keep
                } else {
                    Action::Drop
                }
            }),
            header_default: HeaderAction::Drop,
            header_names: Vec::new(),
            query_redact: Vec::new(),
            filters: Filters::default(),
            sampling: None,
        }
    }
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new(CODE, message)
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, Invalid> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} must be an object")))
}

fn only_keys(map: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), Invalid> {
    match map.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(invalid(format!(
            "{what} has an unknown setting `{key}` (allowed: {})",
            allowed.join(", ")
        ))),
        None => Ok(()),
    }
}

fn word<'a>(value: &'a Value, what: &str, allowed: &[&str]) -> Result<&'a str, Invalid> {
    value
        .as_str()
        .filter(|text| allowed.contains(text))
        .ok_or_else(|| invalid(format!("{what} must be one of {}", allowed.join(", "))))
}

fn bits(map: &Map<String, Value>, key: &str, max: u8, default: u8) -> Result<u8, Invalid> {
    match map.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|bits| u8::try_from(bits).ok())
            .filter(|bits| *bits <= max)
            .ok_or_else(|| invalid(format!("{key} must be a whole number in 0..={max}"))),
    }
}

fn field_action(field: Field, value: &Value) -> Result<Action, Invalid> {
    let (name, detail) = match value {
        Value::String(name) => (name.as_str(), None),
        Value::Object(map) => {
            only_keys(
                map,
                &["action", "ipv4_bits", "ipv6_bits"],
                &format!("fields.names.{}", field.name()),
            )?;
            let name = map.get("action").and_then(Value::as_str).ok_or_else(|| {
                invalid(format!("fields.names.{} needs an `action`", field.name()))
            })?;
            (name, Some(map))
        }
        _ => {
            return Err(invalid(format!(
                "fields.names.{} must be keep, drop, redact or mask, or an object with an `action`",
                field.name()
            )));
        }
    };
    let action = match name {
        "keep" => Action::Keep,
        "drop" => Action::Drop,
        "redact" => Action::Redact,
        "mask" if field == Field::ClientIp => {
            let empty = Map::new();
            let detail = detail.unwrap_or(&empty);
            Action::Mask(Mask {
                ipv4_bits: bits(detail, "ipv4_bits", 32, Mask::DEFAULT.ipv4_bits)?,
                ipv6_bits: bits(detail, "ipv6_bits", 128, Mask::DEFAULT.ipv6_bits)?,
            })
        }
        "mask" => return Err(invalid("`mask` applies to client_ip only")),
        other => {
            return Err(invalid(format!(
                "fields.names.{}: `{other}` is not keep, drop, redact or mask",
                field.name()
            )));
        }
    };
    if detail.is_some_and(|map| map.len() > 1) && !matches!(action, Action::Mask(_)) {
        return Err(invalid(format!(
            "fields.names.{}: ipv4_bits and ipv6_bits belong to `mask`",
            field.name()
        )));
    }
    Ok(action)
}

fn parse_range(text: &str) -> Option<RangeInclusive<u16>> {
    let (low, high) = text.split_once('-').unwrap_or((text, text));
    let (low, high) = (low.trim().parse().ok()?, high.trim().parse().ok()?);
    (100..=599).contains(&low).then_some(())?;
    (low <= high && high <= 599).then_some(low..=high)
}

impl Policy {
    /// Parses the `access_log` object of a snapshot (or of nothing: `{}`).
    ///
    /// # Errors
    ///
    /// `invalid_access_log` for an unknown setting, a bad action, range or percentage.
    pub fn parse(value: &Value) -> Result<Self, Invalid> {
        let root = object(value, "access_log")?;
        only_keys(
            root,
            &["format", "fields", "headers", "filters", "sampling_percent"],
            "access_log",
        )?;
        let mut policy = Self::default();
        if let Some(format) = root.get("format") {
            policy.format = match word(format, "format", &["json", "common"])? {
                "common" => Format::Common,
                _ => Format::Json,
            };
        }
        if let Some(fields) = root.get("fields") {
            policy.parse_fields(object(fields, "fields")?)?;
        }
        if let Some(headers) = root.get("headers") {
            policy.parse_headers(object(headers, "headers")?)?;
        }
        if let Some(filters) = root.get("filters") {
            policy.filters = parse_filters(object(filters, "filters")?)?;
        }
        if let Some(percent) = root.get("sampling_percent") {
            let percent = percent
                .as_f64()
                .filter(|percent| (0.0..=100.0).contains(percent))
                .ok_or_else(|| invalid("sampling_percent must be a number in 0..=100"))?;
            if percent < 100.0 {
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "percent is in 0..=100, so hundredths fit a u32"
                )]
                let hundredths = (percent * 100.0).round() as u32;
                policy.sampling = Some(hundredths);
            }
        }
        Ok(policy)
    }

    fn parse_fields(&mut self, fields: &Map<String, Value>) -> Result<(), Invalid> {
        only_keys(fields, &["default", "names", "query_redact"], "fields")?;
        if let Some(default) = fields.get("default")
            && word(default, "fields.default", &["keep", "drop"])? == "drop"
        {
            self.fields = Field::ALL.map(|_| Action::Drop);
        }
        if let Some(names) = fields.get("names") {
            for (name, value) in object(names, "fields.names")? {
                let field = Field::parse(name)
                    .ok_or_else(|| invalid(format!("fields.names: `{name}` is not a log field")))?;
                self.fields[field.index()] = field_action(field, value)?;
            }
        }
        if let Some(list) = fields.get("query_redact") {
            self.query_redact = list
                .as_array()
                .and_then(|list| list.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
                .ok_or_else(|| invalid("fields.query_redact must be a list of parameter names"))?
                .into_iter()
                .map(Box::from)
                .collect();
        }
        Ok(())
    }

    fn parse_headers(&mut self, headers: &Map<String, Value>) -> Result<(), Invalid> {
        only_keys(headers, &["default", "names"], "headers")?;
        let action = |value: &Value, what: &str| -> Result<HeaderAction, Invalid> {
            Ok(match word(value, what, &["keep", "drop", "redact"])? {
                "keep" => HeaderAction::Keep,
                "redact" => HeaderAction::Redact,
                _ => HeaderAction::Drop,
            })
        };
        if let Some(default) = headers.get("default") {
            self.header_default = action(default, "headers.default")?;
        }
        if let Some(names) = headers.get("names") {
            for (name, value) in object(names, "headers.names")? {
                let rule = action(value, &format!("headers.names.{name}"))?;
                self.header_names
                    .push((name.to_ascii_lowercase().into(), rule));
            }
        }
        Ok(())
    }

    /// How a line is written.
    #[must_use]
    pub fn format(&self) -> Format {
        self.format
    }

    /// What a line does with `field`.
    #[must_use]
    pub fn action(&self, field: Field) -> Action {
        self.fields[field.index()]
    }

    /// What a line does with the header called `name` (lowercase). A rule by name wins. Without
    /// one, a credential header is redacted whenever it would otherwise be written.
    #[must_use]
    pub fn header_action(&self, name: &str) -> HeaderAction {
        if let Some((_, rule)) = self.header_names.iter().find(|(known, _)| &**known == name) {
            return *rule;
        }
        match self.header_default {
            HeaderAction::Drop => HeaderAction::Drop,
            _ if SENSITIVE.contains(&name) => HeaderAction::Redact,
            other => other,
        }
    }

    /// Whether any header can appear in a line.
    #[must_use]
    pub fn logs_headers(&self) -> bool {
        self.header_default != HeaderAction::Drop
            || self
                .header_names
                .iter()
                .any(|(_, rule)| *rule != HeaderAction::Drop)
    }

    /// Whether the query parameter `name` carries a value that must not be logged.
    #[must_use]
    pub fn redacts_query_param(&self, name: &str) -> bool {
        self.query_redact.iter().any(|known| &**known == name)
    }

    /// Whether the filters select a request that got `status` after `duration` and `retries`
    /// retries. No filters select every request.
    #[must_use]
    pub fn selects(&self, status: u16, duration: Duration, retries: u32) -> bool {
        let filters = &self.filters;
        filters.is_empty()
            || filters.status.iter().any(|range| range.contains(&status))
            || filters.min_duration.is_some_and(|min| duration >= min)
            || filters.retry_attempts.is_some_and(|min| retries >= min)
    }

    /// Whether sampling keeps the request with this id. Pure in the id, so a request and its
    /// retries agree.
    #[must_use]
    pub fn sampled(&self, request_id: &str) -> bool {
        self.sampling
            .is_none_or(|hundredths| bucket(request_id) < hundredths)
    }
}

fn parse_filters(filters: &Map<String, Value>) -> Result<Filters, Invalid> {
    only_keys(
        filters,
        &["status_codes", "min_duration_ms", "retry_attempts"],
        "filters",
    )?;
    let mut parsed = Filters::default();
    if let Some(codes) = filters.get("status_codes") {
        let list = codes
            .as_array()
            .ok_or_else(|| invalid("filters.status_codes must be a list like [\"400-599\"]"))?;
        for entry in list {
            let range = entry.as_str().and_then(parse_range).ok_or_else(|| {
                invalid(format!(
                    "filters.status_codes entry {entry} is not a status (404) or range (400-599) in 100..=599"
                ))
            })?;
            parsed.status.push(range);
        }
    }
    if let Some(millis) = filters.get("min_duration_ms") {
        let millis = millis
            .as_u64()
            .ok_or_else(|| invalid("filters.min_duration_ms must be a whole number"))?;
        parsed.min_duration = Some(Duration::from_millis(millis));
    }
    if let Some(retries) = filters.get("retry_attempts") {
        parsed.retry_attempts = Some(
            retries
                .as_u64()
                .and_then(|retries| u32::try_from(retries).ok())
                .ok_or_else(|| invalid("filters.retry_attempts must be a whole number"))?,
        );
    }
    Ok(parsed)
}

/// A request id's place in `0..10_000`: FNV-1a, then a finalizer so that ids differing in their
/// last characters (a counter) still spread over the whole range.
fn bucket(request_id: &str) -> u32 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in request_id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^= hash >> 33;
    u32::try_from(hash % 10_000).unwrap_or(0)
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn parse(value: &Value) -> Result<Policy, Invalid> {
        Policy::parse(value)
    }

    #[test]
    fn the_default_policy_keeps_the_default_fields_and_no_headers() {
        let policy = parse(&json!({})).expect("parses");
        assert_eq!(policy, Policy::default());
        assert_eq!(policy.action(Field::Path), Action::Keep);
        assert_eq!(policy.action(Field::Query), Action::Drop);
        assert_eq!(policy.action(Field::UserAgent), Action::Drop);
        assert!(!policy.logs_headers());
    }

    #[test]
    fn field_defaults_and_names_combine() {
        let policy = parse(&json!({"fields": {"default": "drop", "names": {
            "status": "keep", "path": "redact",
            "client_ip": {"action": "mask", "ipv4_bits": 16}
        }}}))
        .expect("parses");
        assert_eq!(policy.action(Field::Status), Action::Keep);
        assert_eq!(policy.action(Field::Path), Action::Redact);
        assert_eq!(policy.action(Field::Method), Action::Drop);
        assert_eq!(
            policy.action(Field::ClientIp),
            Action::Mask(Mask {
                ipv4_bits: 16,
                ipv6_bits: 48
            })
        );
    }

    #[test]
    fn bad_settings_are_refused() {
        for bad in [
            json!(true),
            json!({"format": "xml"}),
            json!({"unknown": 1}),
            json!({"fields": {"names": {"nope": "keep"}}}),
            json!({"fields": {"names": {"status": "mask"}}}),
            json!({"fields": {"names": {"client_ip": {"action": "mask", "ipv4_bits": 33}}}}),
            json!({"fields": {"names": {"client_ip": {"action": "keep", "ipv4_bits": 8}}}}),
            json!({"headers": {"default": "all"}}),
            json!({"filters": {"status_codes": ["99"]}}),
            json!({"filters": {"status_codes": ["500-400"]}}),
            json!({"filters": {"min_duration_ms": -1}}),
            json!({"sampling_percent": 101}),
            json!({"sampling_percent": "half"}),
        ] {
            let err = parse(&bad).expect_err(&format!("{bad} must be refused"));
            assert_eq!(err.code, "invalid_access_log", "{bad}");
        }
    }

    #[test]
    fn access_log_header_defaults() {
        let drop_all = parse(&json!({})).expect("parses");
        assert_eq!(drop_all.header_action("authorization"), HeaderAction::Drop);
        assert_eq!(drop_all.header_action("accept"), HeaderAction::Drop);

        let keep_all = parse(&json!({"headers": {"default": "keep"}})).expect("parses");
        for name in SENSITIVE {
            assert_eq!(keep_all.header_action(name), HeaderAction::Redact, "{name}");
        }
        assert_eq!(keep_all.header_action("accept"), HeaderAction::Keep);

        let explicit = parse(&json!({"headers": {"default": "keep", "names": {
            "Cookie": "keep", "accept": "drop"}}}))
        .expect("parses");
        assert_eq!(explicit.header_action("cookie"), HeaderAction::Keep);
        assert_eq!(explicit.header_action("accept"), HeaderAction::Drop);
        assert_eq!(
            explicit.header_action("authorization"),
            HeaderAction::Redact
        );

        let by_name = parse(&json!({"headers": {"names": {"x-user": "keep"}}})).expect("parses");
        assert_eq!(by_name.header_action("x-user"), HeaderAction::Keep);
        assert_eq!(by_name.header_action("authorization"), HeaderAction::Drop);
        assert!(by_name.logs_headers());
    }

    #[test]
    fn access_log_ip_mask() {
        let v4 = Mask {
            ipv4_bits: 24,
            ipv6_bits: 48,
        };
        assert_eq!(
            v4.apply("203.0.113.77".parse().expect("ip")),
            "203.0.113.0".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(
            v4.apply("2001:db8:1:2:3:4:5:6".parse().expect("ip")),
            "2001:db8:1::".parse::<IpAddr>().expect("ip")
        );
        let none = Mask {
            ipv4_bits: 0,
            ipv6_bits: 0,
        };
        assert_eq!(
            none.apply("203.0.113.77".parse().expect("ip")),
            "0.0.0.0".parse::<IpAddr>().expect("ip")
        );
        let all = Mask {
            ipv4_bits: 32,
            ipv6_bits: 128,
        };
        assert_eq!(
            all.apply("203.0.113.77".parse().expect("ip")),
            "203.0.113.77".parse::<IpAddr>().expect("ip")
        );
    }

    #[test]
    fn access_log_filters_select_when_any_matches() {
        let none = parse(&json!({})).expect("parses");
        assert!(none.selects(200, Duration::ZERO, 0));

        let policy = parse(&json!({"filters": {
            "status_codes": ["400-599", "301"], "min_duration_ms": 500, "retry_attempts": 2}}))
        .expect("parses");
        let fast = Duration::from_millis(5);
        assert!(!policy.selects(200, fast, 0));
        assert!(policy.selects(404, fast, 0));
        assert!(policy.selects(599, fast, 0));
        assert!(policy.selects(301, fast, 0));
        assert!(!policy.selects(399, fast, 1));
        assert!(policy.selects(200, Duration::from_millis(500), 0));
        assert!(policy.selects(200, fast, 2));
    }

    #[test]
    fn access_log_sampling_deterministic() {
        let policy = parse(&json!({"sampling_percent": 30})).expect("parses");
        let ids: Vec<String> = (0..20_000).map(|n| format!("0a1b2c3d{n:08x}")).collect();
        let first: Vec<bool> = ids.iter().map(|id| policy.sampled(id)).collect();
        let again: Vec<bool> = ids.iter().map(|id| policy.sampled(id)).collect();
        assert_eq!(first, again, "the same id always gets the same verdict");
        let kept = first.iter().filter(|kept| **kept).count();
        assert!(
            (5_400..=6_600).contains(&kept),
            "30% of 20000 is about 6000, got {kept}"
        );
        let all = parse(&json!({"sampling_percent": 100})).expect("parses");
        let none = parse(&json!({"sampling_percent": 0})).expect("parses");
        assert!(ids.iter().all(|id| all.sampled(id)));
        assert!(ids.iter().all(|id| !none.sampled(id)));
    }
}
