//! SPIFFE IDs, ID patterns, and the operator's policy file (`SPIFFE_POLICY_FILE`).
//!
//! The policy maps each tenant to the one identity it may use and to the identities it may talk
//! to, so a snapshot can name neither an SVID nor a trust relation the operator did not grant:
//!
//! ```json
//! { "tenants": {
//!     "acme": {
//!       "svid_hint": "acme",
//!       "allowed_server_ids": ["spiffe://prod.example/ns/acme/*"],
//!       "allowed_client_trust_domains": ["prod.example"],
//!       "allow": { "upstream_mtls": true, "client_identity": true }
//!     }
//! } }
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

/// The longest SPIFFE ID, pattern or trust domain accepted: the limit of the SPIFFE ID standard.
const MAX_ID_BYTES: usize = 2048;

/// Most tenants a policy file may list.
const MAX_TENANTS: usize = 10_000;

/// Why a string is no SPIFFE ID, pattern or trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct IdError(Box<str>);

impl IdError {
    fn new(reason: impl Into<Box<str>>) -> Self {
        Self(reason.into())
    }
}

/// A trust domain name: lowercase letters, digits, `.`, `-` and `_`.
fn trust_domain(name: &str) -> Result<Box<str>, IdError> {
    if name.is_empty() {
        return Err(IdError::new("the trust domain is empty"));
    }
    if !name
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
    {
        return Err(IdError::new(
            "a trust domain holds only lowercase letters, digits, `.`, `-` and `_`",
        ));
    }
    Ok(name.into())
}

/// A trust domain given as a bare name or as `spiffe://name`, as the Workload API and the policy
/// file write it.
///
/// # Errors
///
/// [`IdError`] when the name is empty or holds a character a trust domain cannot.
pub fn parse_trust_domain(text: &str) -> Result<Box<str>, IdError> {
    trust_domain(text.strip_prefix("spiffe://").unwrap_or(text))
}

/// The segments of a SPIFFE ID path, each checked with `allowed` for its characters.
fn segments(
    path: &str,
    mut segment: impl FnMut(&str) -> Result<(), IdError>,
) -> Result<Vec<Box<str>>, IdError> {
    let mut out = Vec::new();
    for part in path.split('/') {
        if part.is_empty() {
            return Err(IdError::new("the path has an empty segment"));
        }
        if part == "." || part == ".." {
            return Err(IdError::new("the path has a `.` or `..` segment"));
        }
        segment(part)?;
        out.push(part.into());
    }
    Ok(out)
}

fn path_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn literal_segment(part: &str) -> Result<(), IdError> {
    if part.bytes().all(path_char) {
        Ok(())
    } else {
        Err(IdError::new(
            "a path segment holds only letters, digits, `.`, `-` and `_`",
        ))
    }
}

/// Splits `spiffe://<trust domain>[/<path>]`.
fn split(text: &str) -> Result<(Box<str>, Option<&str>), IdError> {
    if text.len() > MAX_ID_BYTES {
        return Err(IdError::new(format!("longer than {MAX_ID_BYTES} bytes")));
    }
    let rest = text
        .strip_prefix("spiffe://")
        .ok_or_else(|| IdError::new("does not start with `spiffe://`"))?;
    let (domain, path) = match rest.split_once('/') {
        Some((domain, path)) => (domain, Some(path)),
        None => (rest, None),
    };
    Ok((trust_domain(domain)?, path))
}

/// A workload's SPIFFE ID: a trust domain and a path of at least one segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpiffeId {
    trust_domain: Box<str>,
    segments: Vec<Box<str>>,
}

impl SpiffeId {
    /// Parses `spiffe://<trust domain>/<segment>[/<segment>...]`.
    ///
    /// # Errors
    ///
    /// [`IdError`] when the text is not that: another scheme, a query, a port, a user, an empty
    /// or dot segment, a character outside the SPIFFE alphabet, or no path at all.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let (trust_domain, path) = split(text)?;
        let path = path.ok_or_else(|| IdError::new("a workload ID needs a path"))?;
        Ok(Self {
            trust_domain,
            segments: segments(path, literal_segment)?,
        })
    }

    /// The trust domain.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spiffe://{}", self.trust_domain)?;
        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(Box<str>),
    /// `*`: exactly one segment.
    One,
    /// `**`, the last segment only: one or more segments.
    Rest,
}

/// A SPIFFE ID with wildcards: `*` stands for one path segment, a final `**` for one or more.
/// The trust domain is always literal.
///
/// `spiffe://td/ns/acme/*` matches `spiffe://td/ns/acme/web` and not `spiffe://td/ns/acme` or
/// `spiffe://td/ns/acme/a/b`; `spiffe://td/ns/acme/**` matches all three below `acme` but not
/// `acme` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdPattern {
    trust_domain: Box<str>,
    segments: Vec<Segment>,
}

impl IdPattern {
    /// Parses an exact ID or a pattern.
    ///
    /// # Errors
    ///
    /// [`IdError`] as for [`SpiffeId::parse`]; a `*` or `**` that is part of a segment instead
    /// of the whole segment, and a `**` that is not last.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let (trust_domain, path) = split(text)?;
        let path = path.ok_or_else(|| IdError::new("a pattern needs a path"))?;
        let parts = segments(path, |part| {
            if matches!(part, "*" | "**") {
                Ok(())
            } else {
                literal_segment(part)
            }
        })?;
        let last = parts.len() - 1;
        let segments = parts
            .into_iter()
            .enumerate()
            .map(|(index, part)| match &*part {
                "*" => Ok(Segment::One),
                "**" if index == last => Ok(Segment::Rest),
                "**" => Err(IdError::new("`**` is only allowed as the last segment")),
                _ => Ok(Segment::Literal(part)),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            trust_domain,
            segments,
        })
    }

    /// The trust domain every match is in.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Whether `id` is one of the IDs the pattern stands for.
    #[must_use]
    pub fn matches(&self, id: &SpiffeId) -> bool {
        if self.trust_domain != id.trust_domain {
            return false;
        }
        for (index, segment) in self.segments.iter().enumerate() {
            match (segment, id.segments.get(index)) {
                (Segment::Rest, Some(_)) => return true,
                (Segment::One, Some(_)) => {}
                (Segment::Literal(want), Some(got)) if want == got => {}
                _ => return false,
            }
        }
        self.segments.len() == id.segments.len()
    }

    /// Whether every ID `other` stands for is one `self` stands for.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        if self.trust_domain != other.trust_domain {
            return false;
        }
        for (index, segment) in self.segments.iter().enumerate() {
            let theirs = other.segments.get(index);
            match (segment, theirs) {
                (Segment::Rest, Some(_)) => return true,
                (Segment::One, Some(Segment::Literal(_) | Segment::One)) => {}
                (Segment::Literal(want), Some(Segment::Literal(got))) if want == got => {}
                _ => return false,
            }
        }
        self.segments.len() == other.segments.len()
    }
}

impl fmt::Display for IdPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spiffe://{}", self.trust_domain)?;
        for segment in &self.segments {
            match segment {
                Segment::Literal(text) => write!(f, "/{text}")?,
                Segment::One => f.write_str("/*")?,
                Segment::Rest => f.write_str("/**")?,
            }
        }
        Ok(())
    }
}

/// Whether some pattern of `patterns` matches `id`.
#[must_use]
pub fn any_matches(patterns: &[IdPattern], id: &SpiffeId) -> bool {
    patterns.iter().any(|pattern| pattern.matches(id))
}

/// A policy file that cannot be used.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The file cannot be read.
    #[error("cannot read: {0}")]
    Read(#[source] std::io::Error),
    /// The text is not the expected JSON.
    #[error("file: {0}")]
    Syntax(#[source] serde_json::Error),
    /// One entry is wrong.
    #[error("{entry}: {reason}")]
    Entry {
        /// Where, such as `tenants.acme.allowed_server_ids[1]`.
        entry: String,
        /// What is wrong.
        reason: Box<str>,
    },
}

fn entry(at: String, reason: impl Into<Box<str>>) -> PolicyError {
    PolicyError::Entry {
        entry: at,
        reason: reason.into(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTenant {
    #[serde(default)]
    svid_hint: Option<String>,
    #[serde(default)]
    allowed_server_ids: Vec<String>,
    #[serde(default)]
    allowed_client_trust_domains: Vec<String>,
    #[serde(default)]
    allow: FileAllow,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileAllow {
    #[serde(default)]
    upstream_mtls: bool,
    #[serde(default)]
    client_identity: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    tenants: BTreeMap<String, FileTenant>,
}

/// What one tenant may do with SPIFFE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicy {
    svid_hint: Option<Box<str>>,
    allowed_server_ids: Vec<IdPattern>,
    allowed_client_trust_domains: Vec<Box<str>>,
    upstream_mtls: bool,
    client_identity: bool,
}

impl TenantPolicy {
    /// The hint of the SVID the tenant's upstream connections present. Present whenever
    /// [`Self::upstream_mtls`] is.
    #[must_use]
    pub fn svid_hint(&self) -> Option<&str> {
        self.svid_hint.as_deref()
    }

    /// The patterns the IDs of the tenant's servers must fall under.
    #[must_use]
    pub fn allowed_server_ids(&self) -> &[IdPattern] {
        &self.allowed_server_ids
    }

    /// Whether the tenant's transports may use `spiffe`.
    #[must_use]
    pub fn upstream_mtls(&self) -> bool {
        self.upstream_mtls
    }

    /// Whether the tenant's apps may use `tls.spiffe_client`.
    #[must_use]
    pub fn client_identity(&self) -> bool {
        self.client_identity
    }

    /// Whether the tenant's apps may verify clients of `trust_domain`.
    #[must_use]
    pub fn allows_client_trust_domain(&self, trust_domain: &str) -> bool {
        self.allowed_client_trust_domains
            .iter()
            .any(|allowed| &**allowed == trust_domain)
    }
}

/// The operator's SPIFFE policy: per tenant, what it may do. A tenant that is not listed may do
/// nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    tenants: BTreeMap<Box<str>, TenantPolicy>,
}

impl Policy {
    /// Reads the policy file at `path`.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] when the file cannot be read or [`Self::parse`] refuses it.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path).map_err(PolicyError::Read)?;
        Self::parse(&text)
    }

    /// Parses policy JSON.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] for JSON that is not the policy shape, an ID, pattern or trust domain that
    /// does not parse, an `upstream_mtls` tenant without `svid_hint` or `allowed_server_ids`, a
    /// `client_identity` tenant without `allowed_client_trust_domains`, and a pattern list for a
    /// flag that is off (it would never be used).
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let file: File = serde_json::from_str(text).map_err(PolicyError::Syntax)?;
        if file.tenants.len() > MAX_TENANTS {
            return Err(entry(
                "tenants".into(),
                format!("at most {MAX_TENANTS} tenants"),
            ));
        }
        let mut tenants = BTreeMap::new();
        for (name, tenant) in file.tenants {
            let at = |field: &str| format!("tenants.{name}.{field}");
            let allowed_server_ids = tenant
                .allowed_server_ids
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    IdPattern::parse(text).map_err(|err| {
                        entry(
                            format!("tenants.{name}.allowed_server_ids[{index}]"),
                            err.to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let allowed_client_trust_domains = tenant
                .allowed_client_trust_domains
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    parse_trust_domain(text).map_err(|err| {
                        entry(
                            format!("tenants.{name}.allowed_client_trust_domains[{index}]"),
                            err.to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let svid_hint = match tenant.svid_hint.as_deref() {
                Some("") => return Err(entry(at("svid_hint"), "is empty")),
                other => other.map(Box::from),
            };
            let allow = tenant.allow;
            if allow.upstream_mtls && svid_hint.is_none() {
                return Err(entry(
                    at("svid_hint"),
                    "is required when allow.upstream_mtls is true: a tenant needs its own identity",
                ));
            }
            if allow.upstream_mtls && allowed_server_ids.is_empty() {
                return Err(entry(
                    at("allowed_server_ids"),
                    "is required when allow.upstream_mtls is true",
                ));
            }
            if !allow.upstream_mtls && (svid_hint.is_some() || !allowed_server_ids.is_empty()) {
                return Err(entry(
                    at("allow.upstream_mtls"),
                    "is false but svid_hint or allowed_server_ids is set",
                ));
            }
            if allow.client_identity && allowed_client_trust_domains.is_empty() {
                return Err(entry(
                    at("allowed_client_trust_domains"),
                    "is required when allow.client_identity is true",
                ));
            }
            if !allow.client_identity && !allowed_client_trust_domains.is_empty() {
                return Err(entry(
                    at("allow.client_identity"),
                    "is false but allowed_client_trust_domains is set",
                ));
            }
            tenants.insert(
                name.into(),
                TenantPolicy {
                    svid_hint,
                    allowed_server_ids,
                    allowed_client_trust_domains,
                    upstream_mtls: allow.upstream_mtls,
                    client_identity: allow.client_identity,
                },
            );
        }
        Ok(Self { tenants })
    }

    /// What `tenant` may do; `None` when the policy does not list it.
    #[must_use]
    pub fn tenant(&self, tenant: &str) -> Option<&TenantPolicy> {
        self.tenants.get(tenant)
    }

    /// The hint of every SVID some tenant uses.
    pub fn hints(&self) -> impl Iterator<Item = &str> {
        self.tenants
            .values()
            .filter_map(|tenant| tenant.svid_hint.as_deref())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn id(text: &str) -> SpiffeId {
        SpiffeId::parse(text).expect("id")
    }

    fn pattern(text: &str) -> IdPattern {
        IdPattern::parse(text).expect("pattern")
    }

    #[test]
    fn ids_follow_the_standard() {
        assert_eq!(
            id("spiffe://td/ns/a/sa/web").to_string(),
            "spiffe://td/ns/a/sa/web"
        );
        for bad in [
            "http://td/a",
            "spiffe://td",
            "spiffe://td/",
            "spiffe://td/a//b",
            "spiffe://td/a/../b",
            "spiffe://TD/a",
            "spiffe://td:80/a",
            "spiffe://u@td/a",
            "spiffe://td/a?x=1",
            "spiffe://td/a#f",
            "spiffe://td/a/*",
        ] {
            assert!(SpiffeId::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn patterns_match_by_segment() {
        let star = pattern("spiffe://td/ns/acme/*");
        assert!(star.matches(&id("spiffe://td/ns/acme/web")));
        assert!(!star.matches(&id("spiffe://td/ns/acme")));
        assert!(!star.matches(&id("spiffe://td/ns/acme/a/b")));
        assert!(!star.matches(&id("spiffe://other/ns/acme/web")));
        let rest = pattern("spiffe://td/ns/acme/**");
        assert!(rest.matches(&id("spiffe://td/ns/acme/web")));
        assert!(rest.matches(&id("spiffe://td/ns/acme/a/b")));
        assert!(!rest.matches(&id("spiffe://td/ns/acme")));
        assert!(!rest.matches(&id("spiffe://td/ns/other/web")));
        assert!(pattern("spiffe://td/a/b").matches(&id("spiffe://td/a/b")));
        assert!(!pattern("spiffe://td/a/b").matches(&id("spiffe://td/a/bc")));
        for bad in ["spiffe://td/a*", "spiffe://td/**/a", "spiffe://td/a/*x"] {
            assert!(IdPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn covering_is_containment() {
        let wide = pattern("spiffe://td/ns/acme/**");
        assert!(wide.covers(&pattern("spiffe://td/ns/acme/*")));
        assert!(wide.covers(&pattern("spiffe://td/ns/acme/sa/web")));
        assert!(wide.covers(&pattern("spiffe://td/ns/acme/**")));
        assert!(!wide.covers(&pattern("spiffe://td/ns/*/sa")));
        let one = pattern("spiffe://td/ns/acme/*");
        assert!(one.covers(&pattern("spiffe://td/ns/acme/web")));
        assert!(one.covers(&pattern("spiffe://td/ns/acme/*")));
        assert!(!one.covers(&pattern("spiffe://td/ns/acme/**")));
        assert!(!one.covers(&pattern("spiffe://td/ns/acme/a/b")));
        assert!(!pattern("spiffe://td/a/b").covers(&pattern("spiffe://td/a/*")));
        assert!(!one.covers(&pattern("spiffe://other/ns/acme/web")));
    }

    #[test]
    fn policy_requires_what_a_flag_needs() {
        let policy = Policy::parse(
            r#"{"tenants": {"acme": {"svid_hint": "acme",
                "allowed_server_ids": ["spiffe://td/ns/acme/*"],
                "allowed_client_trust_domains": ["td", "spiffe://fed.example"],
                "allow": {"upstream_mtls": true, "client_identity": true}}}}"#,
        )
        .expect("policy");
        let acme = policy.tenant("acme").expect("acme");
        assert_eq!(acme.svid_hint(), Some("acme"));
        assert!(acme.allows_client_trust_domain("fed.example"));
        assert!(!acme.allows_client_trust_domain("evil"));
        assert!(policy.tenant("other").is_none());
        for (bad, field) in [
            (
                r#"{"tenants": {"t": {"allow": {"upstream_mtls": true}}}}"#,
                "svid_hint",
            ),
            (
                r#"{"tenants": {"t": {"svid_hint": "h", "allow": {"upstream_mtls": true}}}}"#,
                "allowed_server_ids",
            ),
            (
                r#"{"tenants": {"t": {"allow": {"client_identity": true}}}}"#,
                "allowed_client_trust_domains",
            ),
            (
                r#"{"tenants": {"t": {"svid_hint": "h"}}}"#,
                "allow.upstream_mtls",
            ),
            (
                r#"{"tenants": {"t": {"svid_hint": "h", "allowed_server_ids": ["nope"], "allow": {"upstream_mtls": true}}}}"#,
                "allowed_server_ids[0]",
            ),
        ] {
            let err = Policy::parse(bad).expect_err(bad).to_string();
            assert!(err.contains(field), "{bad}: {err}");
        }
        assert!(Policy::parse(r#"{"tenant": {}}"#).is_err());
    }
}
