//! Cache keys. The tenant and the app are part of every key, so one tenant's entry can never
//! match another tenant's request, even when the host, the path and everything else are equal.

use crate::cache::policy::Query;

/// What names one cached resource: everything about a request except the headers the response
/// varies on, which [`crate::cache::store`] adds as the variant.
///
/// Unkeyed request headers (`X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`) are not part of
/// it: a response that depends on one must say so in `Vary`, and one that says `Vary: *` is
/// never stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct ResourceKey {
    /// The tenant that owns the app.
    pub(crate) tenant: Box<str>,
    /// The app whose middleware stores and serves the entry.
    pub(crate) app: Box<str>,
    /// The router that matched: two routers of one app may answer one path differently.
    pub(crate) router: Box<str>,
    /// The revision that produced the response; `None` when entries are shared across
    /// revisions.
    pub(crate) revision: Option<Box<str>>,
    /// Whether the request came in over TLS: the same URL over `http` and `https` may differ.
    pub(crate) tls: bool,
    /// The host the request is for: normalized, no port.
    pub(crate) host: Box<str>,
    /// The normalized path and the query. Only `GET` responses are stored (`HEAD` reads them),
    /// so the method class is implied.
    pub(crate) target: Box<str>,
}

/// The pieces of a request that make a [`ResourceKey`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parts<'a> {
    pub(crate) tenant: &'a str,
    pub(crate) app: &'a str,
    pub(crate) router: &'a str,
    pub(crate) revision: Option<&'a str>,
    pub(crate) tls: bool,
    pub(crate) host: &'a str,
    /// `uri.path()`, already normalized by the proxy before routing.
    pub(crate) path: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) query_order: Query,
}

impl ResourceKey {
    /// The key for `parts`.
    #[must_use]
    pub(crate) fn new(parts: &Parts<'_>) -> Self {
        let mut target = String::with_capacity(parts.path.len() + 1);
        target.push_str(parts.path);
        if let Some(query) = parts.query {
            target.push('?');
            match parts.query_order {
                Query::AsSent => target.push_str(query),
                Query::Sorted => {
                    let mut pairs: Vec<&str> = query.split('&').collect();
                    pairs.sort_unstable();
                    let mut first = true;
                    for pair in pairs {
                        if !first {
                            target.push('&');
                        }
                        first = false;
                        target.push_str(pair);
                    }
                }
            }
        }
        Self {
            tenant: parts.tenant.into(),
            app: parts.app.into(),
            router: parts.router.into(),
            revision: parts.revision.map(Box::from),
            tls: parts.tls,
            host: parts.host.into(),
            target: target.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parts<'a>(tenant: &'a str, app: &'a str) -> Parts<'a> {
        Parts {
            tenant,
            app,
            router: "r",
            revision: Some("v1"),
            tls: false,
            host: "a.test",
            path: "/p",
            query: Some("b=2&a=1"),
            query_order: Query::AsSent,
        }
    }

    #[test]
    fn tenant_app_and_revision_are_part_of_the_key() {
        let base = ResourceKey::new(&parts("t1", "a"));
        assert_ne!(base, ResourceKey::new(&parts("t2", "a")));
        assert_ne!(base, ResourceKey::new(&parts("t1", "b")));
        let mut other_revision = parts("t1", "a");
        other_revision.revision = Some("v2");
        assert_ne!(base, ResourceKey::new(&other_revision));
        let mut shared = parts("t1", "a");
        shared.revision = None;
        assert_ne!(base, ResourceKey::new(&shared));
    }

    #[test]
    fn the_query_is_sorted_only_when_asked() {
        let as_sent = ResourceKey::new(&parts("t", "a"));
        assert_eq!(&*as_sent.target, "/p?b=2&a=1");
        let mut sorted = parts("t", "a");
        sorted.query_order = Query::Sorted;
        assert_eq!(&*ResourceKey::new(&sorted).target, "/p?a=1&b=2");
    }
}
