//! Who may claim which host.
//!
//! The provider is the one place that knows which tenant an object belongs to and which hosts
//! that tenant is allowed to serve, so the rule that keeps one tenant from capturing another's
//! traffic is enforced here, before a snapshot exists. The daemon enforces its own conflict rules
//! on top (`docs/architecture.md`, `### Priority, ambiguity and conflicts`) and stays the
//! authority; nothing in this module relaxes it.
//!
//! - A tenant named in the configuration may claim a host only inside its `hosts` patterns.
//! - The default tenant may claim a host only when no configured tenant's patterns reach it.
//! - A tenant label (or annotation) on an object is the deployer's claim, not the operator's.
//!   It is honoured only for a tenant whose `label_sources` list the object's source; otherwise
//!   it is ignored and the object takes the tenant its source maps, or the default tenant. A
//!   label naming a tenant that does not exist rejects the object: a typo must not change a
//!   tenant.
//! - A router with no literal host (a `host_regexp`, or no host constraint) matches every host
//!   nobody claims. It is allowed only for a tenant with `catch_all = true`, or when every entry
//!   point it listens on is exclusive to the tenant. This mirrors `catch_all_not_allowed` in the
//!   daemon.

use std::fmt;

use podgate_model::Router;
use serde_json::Value;
use thiserror::Error;

use crate::config::{Config, TenantConfig};
use crate::source::TenantClaim;

/// Deepest nesting of combinators a matcher may have, as in the daemon.
const MAX_DEPTH: usize = 8;

/// A declared host that is neither a valid exact name nor a valid `*.` wildcard.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0:?} is not a host name or a `*.` wildcard")]
pub struct InvalidHost(pub Box<str>);

/// A host a tenant may serve or an object claims: an exact name or one leading `*.` wildcard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostPattern {
    /// `app.example.com`, stored lowercase.
    Exact(Box<str>),
    /// `*.example.com`, stored as the suffix `example.com`. Matches exactly one extra label.
    Wildcard(Box<str>),
}

impl HostPattern {
    /// Parses a declared host the way the daemon does. Names are lowercased.
    ///
    /// # Errors
    ///
    /// [`InvalidHost`] for an empty name, an empty label, a character outside `a-z 0-9 - _`, or a
    /// `*` anywhere but the whole first label.
    pub fn parse(raw: &str) -> Result<Self, InvalidHost> {
        let lower = raw.to_ascii_lowercase();
        let (wildcard, name) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                    })
            });
        if !valid {
            return Err(InvalidHost(raw.into()));
        }
        Ok(if wildcard {
            Self::Wildcard(name.into())
        } else {
            Self::Exact(name.into())
        })
    }

    /// Whether every host `claim` can match lies inside `self`: the same pattern, or a claim
    /// whose name is one label below the base of a wildcard (`x.a.test` and `*.x.a.test` are
    /// under `*.a.test`, as in the daemon's `cross_tenant_wildcard`).
    #[must_use]
    pub fn covers(&self, claim: &Self) -> bool {
        match (self, claim) {
            (Self::Exact(own), Self::Exact(other)) => own == other,
            (Self::Exact(_), Self::Wildcard(_)) => false,
            (Self::Wildcard(base), Self::Exact(name)) => one_label_under(name, base),
            (Self::Wildcard(base), Self::Wildcard(other)) => {
                base == other || one_label_under(other, base)
            }
        }
    }

    /// Whether either pattern lies inside the other, so a tenant holding one must not hand the
    /// other to a different tenant.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.covers(other) || other.covers(self)
    }
}

fn one_label_under(name: &str, base: &str) -> bool {
    name.strip_suffix(base)
        .and_then(|head| head.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Wildcard(base) => write!(f, "*.{base}"),
        }
    }
}

/// What a router's matcher claims, as the daemon sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// A literal host or wildcard.
    Pattern(HostPattern),
    /// A regular expression: claims no literal host.
    Regexp,
}

/// A matcher the provider cannot read.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MatcherError {
    /// The matcher is not a tree of one-key objects the daemon knows.
    #[error("{0}")]
    Invalid(Box<str>),
    /// A `host` leaf names something that is not a host.
    #[error(transparent)]
    Host(#[from] InvalidHost),
}

impl MatcherError {
    fn invalid(message: impl Into<Box<str>>) -> Self {
        Self::Invalid(message.into())
    }

    /// The stable code of the finding: `invalid_matcher` or `invalid_host`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_matcher",
            Self::Host(_) => "invalid_host",
        }
    }
}

/// The leaves that claim no host. A key outside this list and the combinators is refused: a
/// leaf the provider does not know could claim hosts, so it must not pass unexamined.
const OTHER_LEAVES: [&str; 9] = [
    "path",
    "path_prefix",
    "path_regexp",
    "method",
    "client_ip",
    "header",
    "header_regexp",
    "query",
    "query_regexp",
];

/// The hosts a matcher can match, or `None` when it does not limit the host. Mirrors the
/// daemon's `Matcher::claims`: `all` is limited by its limited children, and a child that names
/// only literal hosts bounds it (a `host_regexp` beside a literal host narrows it and never
/// widens it); `any` is limited only when every branch is; `not` never is.
///
/// # Errors
///
/// [`MatcherError`] for a matcher the daemon would refuse by shape: not an object with exactly
/// one key, an unknown key, an empty `all` or `any`, a bad `host`, more than 8 levels.
pub fn claims(matcher: &Value) -> Result<Option<Vec<Claim>>, MatcherError> {
    claims_at(matcher, 0)
}

fn claims_at(matcher: &Value, depth: usize) -> Result<Option<Vec<Claim>>, MatcherError> {
    if depth > MAX_DEPTH {
        return Err(MatcherError::invalid(format!(
            "matchers nest at most {MAX_DEPTH} deep"
        )));
    }
    let one_key = || MatcherError::invalid("a matcher is an object with exactly one key");
    let object = matcher.as_object().ok_or_else(one_key)?;
    let mut entries = object.iter();
    let (Some((key, argument)), None) = (entries.next(), entries.next()) else {
        return Err(one_key());
    };
    match key.as_str() {
        "host" => Ok(Some(host_claims(argument)?)),
        "host_regexp" => Ok(Some(vec![Claim::Regexp])),
        leaf if OTHER_LEAVES.contains(&leaf) => Ok(None),
        "not" => {
            claims_at(argument, depth + 1)?;
            Ok(None)
        }
        key @ ("all" | "any") => {
            let list = argument
                .as_array()
                .filter(|list| !list.is_empty())
                .ok_or_else(|| {
                    MatcherError::invalid(format!("{key}: a non-empty list of matchers"))
                })?;
            let children = list
                .iter()
                .map(|child| claims_at(child, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if key == "all" {
                all_claims(children)
            } else {
                any_claims(children)
            })
        }
        other => Err(MatcherError::invalid(format!("unknown matcher {other}"))),
    }
}

fn host_claims(argument: &Value) -> Result<Vec<Claim>, MatcherError> {
    let names: Vec<&str> = match argument {
        Value::String(name) => vec![name],
        Value::Array(list) => list
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .ok_or_else(|| MatcherError::invalid("host: every entry is a string"))
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(MatcherError::invalid(
                "host: a string or a list of strings, like \"a.test\" or \"*.a.test\"",
            ));
        }
    };
    if names.is_empty() {
        return Err(MatcherError::invalid("host: the list is empty"));
    }
    names
        .into_iter()
        .map(|name| Ok(Claim::Pattern(HostPattern::parse(name)?)))
        .collect()
}

fn all_claims(children: Vec<Option<Vec<Claim>>>) -> Option<Vec<Claim>> {
    let limited: Vec<Vec<Claim>> = children.into_iter().flatten().collect();
    if limited.is_empty() {
        return None;
    }
    let literal: Vec<Claim> = limited
        .iter()
        .filter(|claims| {
            claims
                .iter()
                .all(|claim| matches!(claim, Claim::Pattern(_)))
        })
        .flatten()
        .cloned()
        .collect();
    Some(if literal.is_empty() {
        limited.into_iter().flatten().collect()
    } else {
        literal
    })
}

fn any_claims(children: Vec<Option<Vec<Claim>>>) -> Option<Vec<Claim>> {
    let mut all = Vec::new();
    for child in children {
        all.extend(child?);
    }
    Some(all)
}

/// The literal hosts of a router and whether it is a fallback (it has no literal host of its
/// own: a `host_regexp` without a literal host beside it, or no host constraint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterHosts {
    /// Every literal host or wildcard the router claims.
    pub hosts: Vec<HostPattern>,
    /// Whether it matches hosts nobody claims.
    pub fallback: bool,
}

impl RouterHosts {
    /// Reads the claims of `router`.
    ///
    /// # Errors
    ///
    /// [`MatcherError`] as [`claims`].
    pub fn of(router: &Router) -> Result<Self, MatcherError> {
        let claims = claims(&router.matcher)?;
        let fallback = claims
            .as_ref()
            .is_none_or(|claims| claims.contains(&Claim::Regexp));
        let hosts = claims
            .into_iter()
            .flatten()
            .filter_map(|claim| match claim {
                Claim::Pattern(pattern) => Some(pattern),
                Claim::Regexp => None,
            })
            .collect();
        Ok(Self { hosts, fallback })
    }
}

/// A reason an object cannot go into the snapshot: a stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// `unknown_tenant`, `foreign_host_claim` or `catch_all_not_allowed`.
    pub code: &'static str,
    /// What is wrong, naming the tenant and the host or router.
    pub message: Box<str>,
}

impl Problem {
    pub(crate) fn new(code: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The tenant an object ended up with.
#[derive(Debug, Clone, Copy)]
pub struct Resolved<'a> {
    /// The tenant's configuration.
    pub tenant: &'a TenantConfig,
    /// Whether it is the default tenant.
    pub is_default: bool,
    /// A tenant label that was ignored because the source may not set it, when there was one.
    pub ignored_label: Option<&'a str>,
}

/// The rules of one configuration.
#[derive(Debug, Clone)]
pub struct Trust {
    tenants: Vec<TenantConfig>,
    default: TenantConfig,
}

impl Trust {
    /// The trust rules of `config`.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self {
            tenants: config.tenants.clone(),
            default: config.default_tenant.clone(),
        }
    }

    /// The tenant called `id`.
    ///
    /// # Errors
    ///
    /// `unknown_tenant` when it is not in the configuration.
    pub fn lookup(&self, id: &str) -> Result<Resolved<'_>, Problem> {
        if id == &*self.default.id {
            return Ok(Resolved {
                tenant: &self.default,
                is_default: true,
                ignored_label: None,
            });
        }
        self.tenants
            .iter()
            .find(|tenant| &*tenant.id == id)
            .map(|tenant| Resolved {
                tenant,
                is_default: false,
                ignored_label: None,
            })
            .ok_or_else(|| {
                Problem::new(
                    "unknown_tenant",
                    format!("tenant {id:?} is not in the configuration"),
                )
            })
    }

    /// The tenant of an object of `source` that carries `claim`.
    ///
    /// # Errors
    ///
    /// `unknown_tenant` when the label or the mapping names a tenant that is not configured.
    /// The object is never defaulted: a typo must not change a tenant.
    pub fn resolve<'a>(
        &'a self,
        source: &str,
        claim: &'a TenantClaim,
    ) -> Result<Resolved<'a>, Problem> {
        let mut ignored_label = None;
        if let Some(label) = claim.label.as_deref() {
            let named = self.lookup(label)?;
            // The default tenant is the least privileged one: naming it can only lower what an
            // object may claim, so any source may.
            if named.is_default
                || named
                    .tenant
                    .label_sources
                    .iter()
                    .any(|allowed| &**allowed == source)
            {
                return Ok(named);
            }
            ignored_label = Some(label);
        }
        let mut resolved = match claim.mapped.as_deref() {
            Some(mapped) => self.lookup(mapped)?,
            None => self.lookup(&self.default.id)?,
        };
        resolved.ignored_label = ignored_label;
        Ok(resolved)
    }

    /// Whether `tenant` may claim `host`.
    ///
    /// # Errors
    ///
    /// `foreign_host_claim` when the host lies outside the tenant's patterns, or, for the
    /// default tenant, inside any configured tenant's.
    pub fn check_host(&self, tenant: Resolved<'_>, host: &HostPattern) -> Result<(), Problem> {
        let allowed = if tenant.is_default {
            !self
                .tenants
                .iter()
                .any(|other| other.hosts.iter().any(|pattern| pattern.overlaps(host)))
        } else {
            tenant
                .tenant
                .hosts
                .iter()
                .any(|pattern| pattern.covers(host))
        };
        if allowed {
            return Ok(());
        }
        let why = if tenant.is_default {
            "a configured tenant owns hosts that overlap it"
        } else {
            "it is outside the tenant's hosts"
        };
        Err(Problem::new(
            "foreign_host_claim",
            format!("tenant {} may not claim {host}: {why}", tenant.tenant.id),
        ))
    }

    /// Whether `tenant` may have `router`, given what it matches.
    ///
    /// # Errors
    ///
    /// `catch_all_not_allowed` for a fallback router of a tenant that has neither `catch_all`
    /// nor an exclusive entry point for every entry point the router listens on.
    pub fn check_catch_all(
        tenant: Resolved<'_>,
        router: &Router,
        hosts: &RouterHosts,
    ) -> Result<(), Problem> {
        if !hosts.fallback || tenant.tenant.catch_all {
            return Ok(());
        }
        let exclusive = router.entry_points.as_deref().is_some_and(|list| {
            !list.is_empty()
                && list.iter().all(|entry| {
                    tenant
                        .tenant
                        .exclusive_entry_points
                        .iter()
                        .any(|own| own == entry)
                })
        });
        if exclusive {
            return Ok(());
        }
        Err(Problem::new(
            "catch_all_not_allowed",
            format!(
                "router {} would match every host nobody claims; add a literal host in an `all`, attach it only to entry points exclusive to tenant {}, or set catch_all = true for it",
                router.name, tenant.tenant.id
            ),
        ))
    }
}
