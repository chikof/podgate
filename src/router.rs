//! Routers: which app and router answer a request.
//!
//! Every router of every app is compiled into a [`CompiledRouter`] (a parsed matcher, a priority,
//! a middleware chain and a service name) and indexed by host in an [`Index`]. A request takes
//! the best matching router by [`Key`]: explicit `priority`, then host specificity (exact,
//! wildcard, regexp, none), then path and other constraints, then `(app id, router name)`, so
//! the order is total and equal on every node.
//!
//! Two rules keep a tenant from capturing another tenant's traffic, whatever its priority:
//!
//! - A literal host (`host`) is claimed by one tenant only (`host_conflict`), so priority only
//!   ever orders the routers of one tenant for a host.
//! - A router with no literal host (a `host_regexp`, or no host constraint) is a *fallback*: it
//!   matches only hosts no other tenant claims, at most one tenant may have fallbacks on an
//!   entry point (`cross_tenant_catch_all`), and an entry point whose `tenants` policy names that
//!   tenant alone lifts the first restriction there.
//!
//! The matcher leaves are in [`matcher`], the path normalization in [`path`].

pub mod matcher;
pub mod path;
mod priority;
pub(crate) mod rule;
mod tree;

use std::hash::{DefaultHasher, Hash, Hasher};

use crate::host::HostPattern;
use crate::observe::{access_log, tracing};
use podgate_model::{App, EntryPointPolicy, Router};
use serde_json::Value;

pub use matcher::{Claim, Failure, Matcher, Spec, View};
pub use priority::Key;
pub use tree::{Candidate, Index, NearMiss, Via};

/// The router a request matched: indices into the table the request was matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matched {
    /// Index of the app, for [`crate::RoutingTable::app`].
    pub app: usize,
    /// Index of the router in [`crate::table::CompiledApp::routers`].
    pub router: usize,
}

/// Which hosts a router can match, which decides how it is indexed and restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Only literal hosts (`host` leaves).
    Literal,
    /// A `host_regexp`: matches hosts by pattern, no literal claim. A fallback.
    Regexp,
    /// No host constraint at all. A fallback.
    Hostless,
}

/// One router, ready for matching.
#[derive(Debug)]
pub struct CompiledRouter {
    name: Box<str>,
    declared_by: Box<str>,
    priority: i32,
    matcher: Matcher,
    entry_points: Option<Box<[Box<str>]>>,
    claims: Option<Vec<Claim>>,
    spec: Spec,
    service: Box<str>,
    unrestricted: bool,
    chain: Box<[usize]>,
    chain_digest: u64,
    access_log: Option<bool>,
    matcher_json: Value,
    rule: Option<Box<str>>,
    tracing: Option<bool>,
}

impl CompiledRouter {
    /// Parses the matcher of `router` and keeps what matching needs. `app` names the tenant and
    /// the default source; `policies` are the snapshot's entry point policies.
    ///
    /// # Errors
    ///
    /// The matcher [`matcher::Error`] when its matcher is refused.
    pub fn compile(
        router: &Router,
        app: &App,
        policies: &[EntryPointPolicy],
    ) -> Result<Self, matcher::Error> {
        let mut matcher = matcher::parse(&router.matcher)?;
        matcher.bind_app(&app.id);
        let tenant: &str = &app.tenant;
        let owned_alone = |entry: &str| {
            policies.iter().any(|policy| {
                &*policy.name == entry
                    && policy
                        .tenants
                        .as_deref()
                        .is_some_and(|tenants| tenants.iter().all(|t| &**t == tenant))
                    && policy.tenants.as_deref().is_some_and(|t| !t.is_empty())
            })
        };
        let unrestricted = router
            .entry_points
            .as_deref()
            .is_some_and(|list| !list.is_empty() && list.iter().all(|entry| owned_alone(entry)));
        Ok(Self {
            name: router.name.clone(),
            declared_by: router
                .declared_by
                .clone()
                .unwrap_or_else(|| app.declared_by.clone()),
            priority: router.priority.unwrap_or(0),
            claims: matcher.claims(),
            spec: matcher.spec(),
            matcher,
            entry_points: router.entry_points.as_deref().map(Into::into),
            service: router.service.clone(),
            unrestricted,
            chain: Box::default(),
            chain_digest: 0,
            access_log: router
                .observability
                .as_ref()
                .and_then(access_log::router_override),
            matcher_json: router.matcher.clone(),
            rule: router.rule.clone(),
            tracing: router
                .observability
                .as_ref()
                .and_then(tracing::router_override),
        })
    }

    /// Sets the effective middleware chain: indices into the app's stages, and a digest of what
    /// they are, so a request can tell later whether a table still has the same chain.
    pub(crate) fn set_chain(&mut self, chain: Box<[usize]>, digest: u64) {
        self.chain = chain;
        self.chain_digest = digest;
    }

    /// Limits an unrestricted router to `list`, the entry points whose policy admits its tenant.
    pub(crate) fn narrow_entry_points(&mut self, list: Box<[Box<str>]>) {
        self.entry_points = Some(list);
    }

    /// The router's name, unique in its app.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The source of the router: its own `declared_by`, else its app's.
    #[must_use]
    pub fn declared_by(&self) -> &str {
        &self.declared_by
    }

    /// The explicit priority, `0` when absent.
    #[must_use]
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// The matcher as the snapshot wrote it, for the read-only overview; for a router with a
    /// `rule`, the tree the rule compiled to.
    #[must_use]
    pub fn matcher_json(&self) -> &Value {
        &self.matcher_json
    }

    /// The Traefik rule string the router was declared with, if it has one.
    #[must_use]
    pub fn rule(&self) -> Option<&str> {
        self.rule.as_deref()
    }

    /// The matcher.
    #[must_use]
    pub fn matcher(&self) -> &Matcher {
        &self.matcher
    }

    /// The matcher's specificity beyond the host.
    #[must_use]
    pub fn spec(&self) -> Spec {
        self.spec
    }

    /// The name of the service that answers.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The entry points the router is limited to; `None` means every HTTP and HTTPS one.
    #[must_use]
    pub fn entry_points(&self) -> Option<&[Box<str>]> {
        self.entry_points.as_deref()
    }

    /// Whether the router listens on `entry_point`.
    #[must_use]
    pub fn listens_on(&self, entry_point: &str) -> bool {
        self.entry_points
            .as_deref()
            .is_none_or(|list| list.iter().any(|name| &**name == entry_point))
    }

    /// Which hosts the router can match.
    #[must_use]
    pub fn tier(&self) -> Tier {
        match &self.claims {
            None => Tier::Hostless,
            Some(claims) if claims.contains(&Claim::Regexp) => Tier::Regexp,
            Some(_) => Tier::Literal,
        }
    }

    /// Whether the router is a fallback: it has no literal host of its own.
    #[must_use]
    pub fn is_fallback(&self) -> bool {
        self.tier() != Tier::Literal
    }

    /// Whether every entry point of the router belongs to its tenant alone, which lifts the
    /// restriction on fallbacks.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.unrestricted
    }

    /// The literal host patterns the router claims, in declaration order.
    pub fn patterns(&self) -> impl Iterator<Item = &HostPattern> {
        self.claims
            .iter()
            .flatten()
            .filter_map(|claim| match claim {
                Claim::Pattern(pattern) => Some(pattern),
                Claim::Regexp => None,
            })
    }

    /// The router's own access log switch: `Some(false)` silences it, `Some(true)` turns it on.
    #[must_use]
    pub fn access_log(&self) -> Option<bool> {
        self.access_log
    }

    /// The router's own tracing switch: `Some(false)` turns it off, `Some(true)` turns it on.
    #[must_use]
    pub fn tracing(&self) -> Option<bool> {
        self.tracing
    }

    /// The effective middleware chain: indices into the app's stages.
    #[must_use]
    pub fn chain(&self) -> &[usize] {
        &self.chain
    }

    /// A digest of the effective chain's stage declarations, equal across two tables exactly
    /// when the chains do the same.
    #[must_use]
    pub fn chain_digest(&self) -> u64 {
        self.chain_digest
    }

    /// Whether `other` and this router can never both match one request: they listen on no
    /// common entry point, or their matchers are provably disjoint.
    #[must_use]
    pub fn disjoint(&self, other: &Self) -> bool {
        let entries = match (&self.entry_points, &other.entry_points) {
            (Some(a), Some(b)) => !a.iter().any(|name| b.contains(name)),
            _ => false,
        };
        entries || matcher::disjoint(&self.matcher, &other.matcher)
    }

    /// The part of the order that does not depend on the host: priority and specificity.
    #[must_use]
    pub fn same_order_as(&self, other: &Self) -> bool {
        self.priority == other.priority && self.spec == other.spec
    }

    /// The ordering key of a match found through `via`.
    #[must_use]
    pub fn key(&self, via: &Via<'_>) -> Key {
        Key::new(self.priority, via.rank(), self.spec)
    }
}

/// A digest of any hashable description, for [`CompiledRouter::set_chain`].
pub(crate) fn digest(parts: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    parts.hash(&mut hasher);
    hasher.finish()
}
