//! The `ip_allow_list` middleware: admits only clients whose resolved address is in a set of
//! ranges and refuses everyone else with `403` before any upstream is contacted.
//!
//! ```json
//! { "name": "office", "type": "ip_allow_list", "source_range": ["203.0.113.0/24", "2001:db8::/32"],
//!   "ip_strategy": { "depth": 2, "excluded": ["10.0.0.0/8"], "ipv6_subnet_bits": 64 } }
//! ```
//!
//! - The address checked is [`ClientIp::resolve`] over the request's [`ForwardedView`]: the
//!   connection's peer, unless the entry point trusts that peer (`forwarded_headers`), in which
//!   case the forwarding chain it sent is read from the right. A peer the entry point does not
//!   trust cannot name its own address, and `ip_strategy` has no chain to pick from for it.
//!   This middleware never reads `X-Forwarded-For` itself.
//! - IPv4-mapped IPv6 addresses are normalized first, on both sides of the comparison.
//! - `ipv6_subnet_bits` (1 to 128) replaces an IPv6 client by the first address of its subnet
//!   before the comparison, as Traefik's `ipv6Subnet`.
//! - A connection with no IP peer (a unix socket) has no address and is refused.
//! - The refusal is `403` with `{"error":"forbidden"}`: it never names a range.

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;

use bytes::Bytes;
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Flow, Kind, RequestCx};
use crate::client_ip::set::CidrSet;
use crate::client_ip::{Cidr, ClientIp, ForwardedView, IpStrategy, UNKNOWN, normalize};
use crate::compile::Invalid;
use podgate_model::Declared;

/// Most blocks in `source_range`.
const MAX_RANGES: usize = 4096;

/// Most blocks in `ip_strategy.excluded`: each is tested against every address of the chain.
const MAX_EXCLUDED: usize = 64;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: everyone is admitted.
    pub const REMOVED: &str = "ip_allow_list_removed";
    /// `source_range` covers addresses it did not: more clients are admitted.
    pub const WIDENED: &str = "ip_allow_list_widened";
    /// `ip_strategy` changed, so another address of the request is checked.
    pub const STRATEGY_CHANGED: &str = "ip_allow_list_strategy_changed";
}

/// The configuration of an `ip_allow_list` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    source_range: Vec<Cidr>,
    #[serde(default)]
    ip_strategy: StrategyConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrategyConfig {
    #[serde(default)]
    depth: Option<NonZeroU16>,
    #[serde(default)]
    excluded: Vec<Cidr>,
    #[serde(default)]
    ipv6_subnet_bits: Option<u8>,
}

/// A compiled `ip_allow_list` middleware.
#[derive(Debug)]
pub struct IpAllowList {
    allowed: CidrSet,
    strategy: IpStrategy,
    ipv6_subnet_bits: Option<u8>,
}

fn invalid(message: impl fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("ip_allow_list: {message}"))
}

/// `addr` as the first address of the `/bits` subnet it belongs to, when it is IPv6.
fn subnet_of(addr: IpAddr, bits: Option<u8>) -> IpAddr {
    match (addr, bits) {
        (IpAddr::V6(v6), Some(bits)) if bits < 128 => {
            let mask = u128::MAX << (128 - u32::from(bits));
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        _ => addr,
    }
}

impl IpAllowList {
    /// Whether the client the request's peer is trusted to describe may pass.
    fn admits(&self, view: &ForwardedView) -> bool {
        let client = normalize(ClientIp::resolve(view, &self.strategy));
        client != UNKNOWN
            && self
                .allowed
                .contains(subnet_of(client, self.ipv6_subnet_bits))
    }
}

async fn refuse(cx: &mut RequestCx<'_>) -> pingora::Result<()> {
    let body = Bytes::from_static(br#"{"error":"forbidden"}"#);
    let mut header = ResponseHeader::build(403, Some(3))?;
    header.insert_header("content-type", "application/json")?;
    header.insert_header("content-length", body.len().to_string())?;
    cx.session
        .write_response_header(Box::new(header), false)
        .await?;
    cx.session.write_response_body(Some(body), true).await
}

impl Kind for IpAllowList {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if config.source_range.is_empty() {
            return Err(invalid(
                "`source_range` is empty; a list that admits nobody is a mistake (use `respond` to close a route)",
            ));
        }
        if config.source_range.len() > MAX_RANGES {
            return Err(invalid(format!("more than {MAX_RANGES} ranges")));
        }
        let strategy = config.ip_strategy;
        if strategy.excluded.len() > MAX_EXCLUDED {
            return Err(invalid(format!(
                "`ip_strategy.excluded` has more than {MAX_EXCLUDED} entries"
            )));
        }
        if strategy
            .ipv6_subnet_bits
            .is_some_and(|bits| !(1..=128).contains(&bits))
        {
            return Err(invalid("`ip_strategy.ipv6_subnet_bits` must be 1 to 128"));
        }
        Ok(Self {
            allowed: CidrSet::new(config.source_range),
            strategy: IpStrategy {
                depth: strategy.depth,
                excluded: strategy.excluded,
            },
            ipv6_subnet_bits: strategy.ipv6_subnet_bits,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        if self.admits(cx.forwarded) {
            return Ok(Flow::Continue);
        }
        refuse(cx).await?;
        Ok(Flow::Respond)
    }

    /// Dropping the middleware admits everyone; more ranges admit more clients; another
    /// strategy checks another address, which can admit clients the old one refused.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        if !self.allowed.covers_all(&new.allowed) {
            kinds.push(kind::WIDENED);
        }
        if self.strategy != new.strategy || self.ipv6_subnet_bits != new.ipv6_subnet_bits {
            kinds.push(kind::STRATEGY_CHANGED);
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "source_range": self.allowed.blocks().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "ip_strategy": {
                "depth": self.strategy.depth,
                "excluded": self.strategy.excluded.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ipv6_subnet_bits": self.ipv6_subnet_bits,
            },
        })
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;
    use crate::client_ip::Trust;

    fn compiled(config: &Value) -> Result<IpAllowList, Invalid> {
        let mut object = config.as_object().cloned().unwrap_or_default();
        object.insert("name".into(), json!("allow"));
        object.insert("type".into(), json!("ip_allow_list"));
        let declared: Declared = serde_json::from_value(Value::Object(object)).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        IpAllowList::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn kind_of(config: &Value) -> IpAllowList {
        compiled(config).expect("valid config")
    }

    fn view(peer: &str, trusted: bool, xff: Option<&str>) -> ForwardedView {
        let trust = Trust::parse(&json!({"trusted_ips": ["10.0.0.0/8"]})).expect("policy");
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        if let Some(xff) = xff {
            request
                .append_header("X-Forwarded-For", xff)
                .expect("header");
        }
        ForwardedView::from_request(
            &mut request,
            Some(peer.parse().expect("peer")),
            None,
            false,
            trusted.then_some(&trust),
        )
    }

    #[test]
    fn listed_addresses_pass_and_the_rest_do_not() {
        let list = kind_of(&json!({"source_range": ["203.0.113.0/24", "2001:db8::/32"]}));
        assert!(list.admits(&view("203.0.113.9", false, None)));
        assert!(list.admits(&view("2001:db8::5", false, None)));
        assert!(!list.admits(&view("198.51.100.1", false, None)));
        assert!(!list.admits(&view("2001:db9::1", false, None)));
    }

    #[test]
    fn an_untrusted_peer_cannot_name_its_own_address() {
        let list = kind_of(&json!({"source_range": ["203.0.113.0/24"]}));
        let spoofed = view("198.51.100.1", false, Some("203.0.113.9"));
        assert!(!list.admits(&spoofed));
        let deep = kind_of(&json!({
            "source_range": ["203.0.113.0/24"], "ip_strategy": {"depth": 1}
        }));
        assert!(!deep.admits(&spoofed));
    }

    #[test]
    fn a_trusted_chain_is_read_through_the_strategy() {
        let plain = kind_of(&json!({"source_range": ["203.0.113.0/24"]}));
        let chain = view(
            "10.0.0.1",
            true,
            Some("203.0.113.9, 198.51.100.7, 10.0.0.2"),
        );
        assert!(
            !plain.admits(&chain),
            "the right-most untrusted hop is 198.51.100.7"
        );
        let second = kind_of(&json!({
            "source_range": ["203.0.113.0/24"], "ip_strategy": {"depth": 3}
        }));
        assert!(second.admits(&chain));
        let skipped = kind_of(&json!({
            "source_range": ["203.0.113.0/24"], "ip_strategy": {"excluded": ["198.51.100.0/24", "10.0.0.0/8"]}
        }));
        assert!(skipped.admits(&chain));
    }

    #[test]
    fn no_peer_address_is_refused_even_by_an_everyone_list() {
        let list = kind_of(&json!({"source_range": ["::/0", "0.0.0.0/0"]}));
        assert!(!list.admits(&ForwardedView::default()));
        assert!(list.admits(&view("203.0.113.9", false, None)));
    }

    #[test]
    fn ipv6_subnet_bits_mask_the_client() {
        let list = kind_of(&json!({
            "source_range": ["2001:db8:1::/64"], "ip_strategy": {"ipv6_subnet_bits": 64}
        }));
        assert!(list.admits(&view("2001:db8:1::dead:beef", false, None)));
        assert!(!list.admits(&view("2001:db8:2::1", false, None)));
        let single = kind_of(&json!({
            "source_range": ["2001:db8::1"], "ip_strategy": {"ipv6_subnet_bits": 128}
        }));
        assert!(single.admits(&view("2001:db8::1", false, None)));
        assert!(!single.admits(&view("2001:db8::2", false, None)));
        let v4 = kind_of(&json!({
            "source_range": ["203.0.113.9"], "ip_strategy": {"ipv6_subnet_bits": 64}
        }));
        assert!(
            v4.admits(&view("203.0.113.9", false, None)),
            "IPv4 is not masked"
        );
    }

    #[test]
    fn bad_declarations_are_invalid_middleware() {
        for config in [
            json!({}),
            json!({"source_range": []}),
            json!({"source_range": ["10.0.0.0/33"]}),
            json!({"source_range": ["nope"]}),
            json!({"source_range": "10.0.0.0/8"}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"depth": 0}}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"excluded": ["x"]}}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"ipv6_subnet_bits": 0}}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"ipv6_subnet_bits": 129}}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"excludedIPs": []}}),
            json!({"source_range": ["10.0.0.0/8"], "ipStrategy": {}}),
            json!({"source_range": vec!["10.0.0.0/8"; MAX_RANGES + 1]}),
            json!({"source_range": ["10.0.0.0/8"], "ip_strategy": {"excluded": vec!["10.0.0.0/8"; MAX_EXCLUDED + 1]}}),
        ] {
            let err = compiled(&config).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}");
        }
    }

    #[test]
    fn posture_lists_removal_widening_and_another_strategy() {
        let narrow = kind_of(&json!({"source_range": ["10.1.0.0/16"]}));
        let same = kind_of(&json!({"source_range": ["10.1.0.0/17", "10.1.128.0/17"]}));
        let wide = kind_of(&json!({"source_range": ["10.0.0.0/8"]}));
        let extra = kind_of(&json!({"source_range": ["10.1.0.0/16", "192.0.2.1"]}));
        let deeper = kind_of(&json!({
            "source_range": ["10.1.0.0/16"], "ip_strategy": {"depth": 2}
        }));
        assert_eq!(narrow.posture(None), [kind::REMOVED]);
        assert!(narrow.posture(Some(&same)).is_empty());
        assert!(
            wide.posture(Some(&narrow)).is_empty(),
            "narrowing is not a relaxation"
        );
        assert_eq!(narrow.posture(Some(&wide)), [kind::WIDENED]);
        assert_eq!(narrow.posture(Some(&extra)), [kind::WIDENED]);
        assert_eq!(narrow.posture(Some(&deeper)), [kind::STRATEGY_CHANGED]);
    }
}
