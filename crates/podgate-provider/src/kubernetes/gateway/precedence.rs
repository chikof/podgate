//! The Gateway API's match precedence, turned into explicit podgate `priority` values.
//!
//! The Gateway API orders the matches that can answer one request:
//!
//! 1. The most specific host name (an exact name beats a wildcard, a longer wildcard suffix beats
//!    a shorter one). The API settles this when it picks the listener and hostname; podgate has
//!    no such step, so it is the first key here.
//! 2. Exact path, then the regular-expression path, then the longest prefix (the API leaves
//!    regular expressions to the implementation; this one ranks them between the two).
//! 3. A method match.
//! 4. The larger number of header matches.
//! 5. The larger number of query parameter matches.
//! 6. Across routes: the oldest creation timestamp, then the alphabetically first
//!    `namespace/name`. Within a route: the rule written first, then its first match.
//!
//! A `GRPCRoute` ranks by the characters of the service, then of the method, then by headers;
//! [`PathRank::grpc`] maps that onto the same keys.
//!
//! podgate orders routers by `priority` first, then by its own specificity tuple, so the
//! translator does not rely on the tuple: it sorts the routers of each tenant by the order above
//! and gives each one a distinct priority. Priority orders only inside one tenant (a tenant never
//! outranks another through it), so the numbers of one tenant are `1..=n` and do not depend on
//! what any other tenant has.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::trust::HostPattern;

/// How specific the host names of a router are; more is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct HostRank(u8, usize);

impl HostRank {
    /// The rank of a router that claims `hosts`: the best of them. No host name is the lowest.
    #[must_use]
    pub fn of<'a>(hosts: impl IntoIterator<Item = &'a HostPattern>) -> Self {
        hosts
            .into_iter()
            .map(|host| match host {
                HostPattern::Exact(_) => Self(2, 0),
                HostPattern::Wildcard(suffix) => Self(1, suffix.split('.').count()),
            })
            .max()
            .unwrap_or_default()
    }
}

/// How specific a path match is; more is better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PathRank(u8, usize, usize);

impl PathRank {
    /// An exact path.
    #[must_use]
    pub const fn exact() -> Self {
        Self(3, 0, 0)
    }

    /// A regular expression.
    #[must_use]
    pub const fn regex() -> Self {
        Self(2, 0, 0)
    }

    /// A prefix of `len` characters; the longer one wins.
    #[must_use]
    pub const fn prefix(len: usize) -> Self {
        Self(1, len, 0)
    }

    /// A gRPC method match with `service_len` characters of service and `method_len` of method,
    /// written as exact names (`exact`) or as expressions. The API compares the characters of
    /// the service first, then of the method: both named exactly is the most specific, then a
    /// service, then a method alone; expressions follow, and a match of every call ranks last
    /// among gRPC matches (but level with a plain `/` prefix, which it beats on its header).
    #[must_use]
    pub const fn grpc(service_len: usize, method_len: usize, exact: bool) -> Self {
        if service_len == 0 && method_len == 0 {
            return Self(1, 0, 0);
        }
        match (exact, service_len > 0 && method_len > 0) {
            (true, true) => Self(3, service_len, method_len),
            (true, false) => Self(2, service_len, method_len),
            (false, _) => Self(1, service_len, method_len),
        }
    }
}

/// How specific one match is, field by field in the order the Gateway API compares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Rank {
    /// The host names.
    pub host: HostRank,
    /// The path.
    pub path: PathRank,
    /// Whether the match names a method.
    pub method: bool,
    /// The number of header matches.
    pub headers: usize,
    /// The number of query parameter matches.
    pub queries: usize,
}

/// One router waiting for its priority.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The tenant the router belongs to; priorities are never compared across tenants.
    pub tenant: Option<Box<str>>,
    /// The specificity of its match.
    pub rank: Rank,
    /// The route's creation time in unix seconds; the older wins a tie.
    pub created: u64,
    /// The route's namespace.
    pub namespace: Box<str>,
    /// The route's name.
    pub name: Box<str>,
    /// The index of the rule in the route.
    pub rule: usize,
    /// The index of the match in the rule.
    pub matched: usize,
    /// The router's own name; the last tie-break, so the order is total.
    pub router: Box<str>,
}

impl Candidate {
    /// `Less` when `self` goes first.
    fn compare(&self, other: &Self) -> Ordering {
        other
            .rank
            .cmp(&self.rank)
            .then(self.created.cmp(&other.created))
            .then(self.namespace.cmp(&other.namespace))
            .then(self.name.cmp(&other.name))
            .then(self.rule.cmp(&other.rule))
            .then(self.matched.cmp(&other.matched))
            .then(self.router.cmp(&other.router))
    }
}

/// The priority of each candidate, in the order given: within one tenant the first in Gateway
/// API order gets `n` and the last gets `1`.
#[must_use]
pub fn priorities(candidates: &[Candidate]) -> Vec<i32> {
    let mut by_tenant: BTreeMap<Option<&str>, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_tenant
            .entry(candidate.tenant.as_deref())
            .or_default()
            .push(index);
    }
    let mut priorities = vec![0; candidates.len()];
    for mut indexes in by_tenant.into_values() {
        indexes.sort_by(|a, b| candidates[*a].compare(&candidates[*b]));
        let count = indexes.len();
        for (position, index) in indexes.into_iter().enumerate() {
            priorities[index] = i32::try_from(count - position).unwrap_or(i32::MAX);
        }
    }
    priorities
}

#[cfg(test)]
mod test {
    use super::*;

    fn candidate(tenant: &str, name: &str, rank: Rank) -> Candidate {
        Candidate {
            tenant: Some(tenant.into()),
            rank,
            created: 100,
            namespace: "ns".into(),
            name: name.into(),
            rule: 0,
            matched: 0,
            router: "r0m0".into(),
        }
    }

    fn host(text: &str) -> HostRank {
        HostRank::of([&HostPattern::parse(text).expect("a host")])
    }

    fn order(candidates: &[Candidate]) -> Vec<&str> {
        let priorities = priorities(candidates);
        let mut named: Vec<(i32, &str)> = priorities
            .into_iter()
            .zip(candidates)
            .map(|(priority, candidate)| (priority, &*candidate.name))
            .collect();
        named.sort_by_key(|(priority, _)| std::cmp::Reverse(*priority));
        named.into_iter().map(|(_, name)| name).collect()
    }

    fn path(path: PathRank) -> Rank {
        Rank {
            path,
            ..Rank::default()
        }
    }

    #[test]
    fn gateway_precedence_matches_spec() {
        let mut method = path(PathRank::prefix(4));
        method.method = true;
        let mut two_headers = path(PathRank::prefix(4));
        two_headers.headers = 2;
        let mut one_header = path(PathRank::prefix(4));
        one_header.headers = 1;
        let mut queries = path(PathRank::prefix(4));
        queries.queries = 1;
        let candidates = [
            candidate("t", "queries", queries),
            candidate("t", "short-prefix", path(PathRank::prefix(2))),
            candidate("t", "one-header", one_header),
            candidate("t", "regex", path(PathRank::regex())),
            candidate("t", "exact", path(PathRank::exact())),
            candidate("t", "two-headers", two_headers),
            candidate("t", "long-prefix", path(PathRank::prefix(9))),
            candidate("t", "method", method),
            candidate("t", "plain-prefix", path(PathRank::prefix(4))),
        ];
        assert_eq!(
            order(&candidates),
            [
                "exact",
                "regex",
                "long-prefix",
                // Same prefix length: the method, then more headers, then more queries.
                "method",
                "two-headers",
                "one-header",
                "queries",
                "plain-prefix",
                "short-prefix",
            ]
        );
    }

    #[test]
    fn gateway_precedence_host_first_then_age_then_name() {
        let mut exact_host = path(PathRank::prefix(1));
        exact_host.host = host("a.test");
        let mut wild_host = path(PathRank::exact());
        wild_host.host = host("*.test");
        let mut deeper_wild = path(PathRank::prefix(1));
        deeper_wild.host = host("*.a.test");
        let mut old = candidate("t", "old", path(PathRank::exact()));
        old.created = 1;
        let mut young_b = candidate("t", "young-b", path(PathRank::exact()));
        young_b.created = 2;
        let mut young_a = candidate("t", "young-a", path(PathRank::exact()));
        young_a.created = 2;
        assert_eq!(
            order(&[
                candidate("t", "wild", wild_host),
                young_b,
                candidate("t", "exact-host", exact_host),
                young_a,
                candidate("t", "deeper-wild", deeper_wild),
                old,
            ]),
            [
                "exact-host",
                "deeper-wild",
                "wild",
                "old",
                "young-a",
                "young-b"
            ]
        );
    }

    #[test]
    fn grpc_rank_prefers_service_then_method() {
        let both = path(PathRank::grpc(10, 3, true));
        let service = path(PathRank::grpc(12, 0, true));
        let method_only = path(PathRank::grpc(0, 5, true));
        let all = path(PathRank::grpc(0, 0, true));
        assert_eq!(
            order(&[
                candidate("t", "all", all),
                candidate("t", "service", service),
                candidate("t", "method", method_only),
                candidate("t", "both", both),
            ]),
            ["both", "service", "method", "all"]
        );
    }

    #[test]
    fn precedence_never_crosses_tenants() {
        let exact = path(PathRank::exact());
        let prefix = path(PathRank::prefix(1));
        // Tenant `a` has three routers, tenant `b` one: `b`'s only router is priority 1, the
        // same it would have alone, and `a`'s exact router does not outrank it by number.
        let candidates = [
            candidate("a", "a-exact", exact),
            candidate("a", "a-prefix", prefix),
            candidate("a", "a-third", path(PathRank::prefix(0))),
            candidate("b", "b-exact", exact),
        ];
        let alone = priorities(&candidates[3..]);
        assert_eq!(alone, [1]);
        assert_eq!(priorities(&candidates), [3, 2, 1, 1]);
        // Adding routers to `a` never changes `b`'s number.
        assert_eq!(priorities(&candidates[1..])[2], 1);
    }
}
