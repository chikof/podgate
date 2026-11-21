//! `{"client_ip": ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]}`: the resolved client address
//! (see [`crate::client_ip`]) is in any of the blocks. The argument is one string or a list;
//! blocks mix IPv4 and IPv6, a bare address is a block of one, and IPv4-mapped IPv6 addresses
//! count as the IPv4 address they carry. With an entry point that trusts no proxy the client is
//! the connection's peer.

use serde_json::Value;

use super::{Error, Spec, View};
use crate::client_ip::Cidr;

/// The blocks of a `client_ip` leaf.
#[derive(Debug)]
pub struct ClientIp {
    blocks: Vec<Cidr>,
}

impl ClientIp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let list = match argument {
            Value::String(one) => vec![one.as_str()],
            Value::Array(list) => list
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .ok_or_else(|| Error::invalid("client_ip: every entry is a string"))
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(Error::invalid("client_ip: a string or a list of strings"));
            }
        };
        if list.is_empty() {
            return Err(Error::invalid("client_ip: the list is empty"));
        }
        let blocks = list
            .into_iter()
            .map(|text| {
                text.parse()
                    .map_err(|err| Error::invalid(format!("client_ip: {err}")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { blocks })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.client_ip
            .is_some_and(|client| self.blocks.iter().any(|block| block.contains(client)))
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }
}

/// Two client IP leaves are disjoint when no block of one overlaps a block of the other.
pub(super) fn disjoint(a: &ClientIp, b: &ClientIp) -> bool {
    !a.blocks
        .iter()
        .any(|left| b.blocks.iter().any(|right| left.overlaps(right)))
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use pingora::http::RequestHeader;
    use serde_json::{Value, json};

    use crate::router::matcher::{Matcher, View, disjoint, parse};

    fn leaf(argument: &Value) -> Matcher {
        parse(&json!({ "client_ip": argument })).expect("parses")
    }

    fn matches(matcher: &Matcher, client: Option<&str>) -> bool {
        let request = RequestHeader::build("GET", b"/", None).expect("request");
        matcher.matches(&View {
            host: "a.test",
            path: "/",
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: client.map(|text| text.parse::<IpAddr>().expect("address")),
            hello: crate::router::matcher::Hello::NONE,
        })
    }

    #[test]
    fn client_ip_leaf_cidr() {
        let blocks = leaf(&json!(["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]));
        for (client, want) in [
            ("10.200.1.1", true),
            ("11.0.0.1", false),
            ("2001:db8:ffff::1", true),
            ("2001:db9::1", false),
            ("192.0.2.7", true),
            ("192.0.2.8", false),
            ("::1", false),
        ] {
            assert_eq!(matches(&blocks, Some(client)), want, "{client}");
        }
        assert!(!matches(&blocks, None), "an unknown client matches nothing");
        assert!(
            matches(&leaf(&json!("10.0.0.0/8")), Some("10.0.0.1")),
            "one string is a list of one"
        );
        assert!(matches(
            &parse(&json!({"not": {"client_ip": "10.0.0.0/8"}})).expect("parses"),
            Some("11.0.0.1")
        ));
        for bad in [
            json!([]),
            json!(7),
            json!([7]),
            json!(["10.0.0.0/33"]),
            json!(["a.b"]),
        ] {
            let err = parse(&json!({ "client_ip": bad })).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}");
        }
    }

    #[test]
    fn client_ip_v4_mapped_normalized() {
        let ipv4 = leaf(&json!(["10.0.0.0/8"]));
        assert!(matches(&ipv4, Some("::ffff:10.1.2.3")));
        assert!(!matches(&ipv4, Some("::ffff:11.1.2.3")));
        let mapped = leaf(&json!(["::ffff:10.0.0.0/104"]));
        assert!(matches(&mapped, Some("10.1.2.3")));
        assert!(matches(&mapped, Some("::ffff:10.1.2.3")));
        assert!(!matches(&mapped, Some("11.1.2.3")));
    }

    #[test]
    fn client_ip_disjoint() {
        let pair = |a: &Value, b: &Value| disjoint(&leaf(a), &leaf(b));
        assert!(pair(&json!(["10.0.0.0/8"]), &json!(["192.168.0.0/16"])));
        assert!(pair(&json!(["10.0.0.0/8"]), &json!(["2001:db8::/32"])));
        assert!(pair(
            &json!(["10.0.0.0/8", "172.16.0.0/12"]),
            &json!(["192.168.0.0/16", "::1"])
        ));
        assert!(!pair(&json!(["10.0.0.0/8"]), &json!(["10.1.0.0/16"])));
        assert!(!pair(
            &json!(["10.0.0.0/8", "172.16.0.0/12"]),
            &json!(["172.17.0.1"])
        ));
        assert!(pair(
            &json!(["10.0.0.0/8"]),
            &json!(["::ffff:11.0.0.0/104"])
        ));
        assert!(!pair(
            &json!(["10.0.0.0/8"]),
            &json!(["::ffff:10.1.0.0/112"])
        ));
        let with_host = parse(&json!({"all": [{"host": "a.test"}, {"client_ip": ["10.0.0.0/8"]}]}))
            .expect("parses");
        assert!(disjoint(&with_host, &leaf(&json!(["192.168.0.0/16"]))));
    }

    #[test]
    fn client_ip_specificity() {
        let spec = |value: Value| parse(&value).expect("parses").spec();
        assert_eq!(spec(json!({"client_ip": ["10.0.0.0/8"]})).others, 1);
        let both = spec(json!({"all": [{"client_ip": "10.0.0.0/8"}, {"method": ["GET"]}]}));
        assert_eq!(
            both.others, 1,
            "`all` takes the largest of each field, not the sum"
        );
        assert!(spec(json!({"client_ip": "10.0.0.0/8"})) > spec(json!({"host": "a.test"})));
        let either = spec(json!({"any": [{"client_ip": "10.0.0.0/8"}, {"path": "/x"}]}));
        assert_eq!(either.others, 0);
    }
}
