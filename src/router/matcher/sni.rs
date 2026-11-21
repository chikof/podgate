//! `{"sni": "a.test"}` and `{"sni": ["a.test", "*.b.test"]}` (TCP routers): the server
//! name the client sent in its TLS ClientHello is an exact name or one label under a `*.`
//! wildcard; a list matches any of its entries. It is `host` for a connection that has no HTTP
//! request yet.
//!
//! A connection that sent no server name matches no `sni` leaf. The leaf claims its patterns
//! like `host` does, so two tenants cannot hold one SNI (`host_conflict`,
//! `cross_tenant_wildcard`): in passthrough the name is whatever the client chose, and the claim
//! is what keeps tenant A's router from receiving tenant B's connections.

use serde_json::Value;

use super::host::{covers, parse_patterns};
use super::{Claim, Error, Spec, View};
use crate::host::{HostPattern, overlaps};

/// The server names of an `sni` leaf.
#[derive(Debug)]
pub struct Sni {
    patterns: Vec<HostPattern>,
}

impl Sni {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        Ok(Self {
            patterns: parse_patterns("sni", argument)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.hello
            .server_name
            .is_some_and(|name| self.patterns.iter().any(|pattern| covers(pattern, name)))
    }

    pub(super) fn claims(&self) -> Vec<Claim> {
        self.patterns.iter().cloned().map(Claim::Pattern).collect()
    }

    /// Exact names rank above wildcards, and both above `sni_regexp`: the class goes in
    /// [`Spec::path`], which a TCP router has no other use for.
    pub(super) fn spec(&self) -> Spec {
        let exact = self
            .patterns
            .iter()
            .all(|pattern| matches!(pattern, HostPattern::Exact(_)));
        Spec {
            path: if exact { 3 } else { 2 },
            others: 0,
        }
    }
}

/// Two `sni` leaves are disjoint when no name of one is a name of the other.
pub(super) fn disjoint(a: &Sni, b: &Sni) -> bool {
    !a.patterns
        .iter()
        .any(|left| b.patterns.iter().any(|right| overlaps(left, right)))
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::{Value, json};

    use crate::router::matcher::{Dialect, Hello, Matcher, View, disjoint, parse_in};

    fn leaf(argument: &Value) -> Matcher {
        parse_in(Dialect::Tcp, &json!({ "sni": argument })).expect("parses")
    }

    fn matches(matcher: &Matcher, name: Option<&str>) -> bool {
        let request = RequestHeader::build("GET", b"/", None).expect("request");
        matcher.matches(&View {
            host: "",
            path: "/",
            entry_point: "pg",
            tls: true,
            request: &request,
            client_ip: None,
            hello: Hello {
                server_name: name,
                alpn: &[],
            },
        })
    }

    #[test]
    fn matches_exact_and_wildcard_names() {
        let matcher = leaf(&json!(["a.test", "*.b.test"]));
        assert!(matches(&matcher, Some("a.test")));
        assert!(matches(&matcher, Some("x.b.test")));
        assert!(!matches(&matcher, Some("b.test")));
        assert!(!matches(&matcher, Some("x.y.b.test")));
        assert!(!matches(&matcher, Some("other.test")));
    }

    #[test]
    fn no_server_name_matches_no_sni_leaf() {
        assert!(!matches(&leaf(&json!("a.test")), None));
        assert!(!matches(&leaf(&json!("*.a.test")), None));
    }

    #[test]
    fn disjoint_when_no_name_is_shared() {
        assert!(disjoint(&leaf(&json!("a.test")), &leaf(&json!("b.test"))));
        assert!(disjoint(&leaf(&json!("a.test")), &leaf(&json!("*.a.test"))));
        assert!(!disjoint(
            &leaf(&json!("x.a.test")),
            &leaf(&json!("*.a.test"))
        ));
    }
}
