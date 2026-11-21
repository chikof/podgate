//! The middleware chain of a TCP router: `in_flight_conn` and `ip_allow_list`.
//!
//! ```json
//! { "tcp": {
//!   "middlewares": [
//!     { "name": "office", "type": "ip_allow_list", "source_range": ["203.0.113.0/24"] },
//!     { "name": "cap", "type": "in_flight_conn", "amount": 20,
//!       "source": { "ip": { "ipv6_subnet_bits": 64 } }, "max_sources": 10000 } ],
//!   "routers": [ { "name": "db", "entry_points": ["pg"], "service": "primary",
//!                  "chain": ["office", "cap"] } ] } }
//! ```
//!
//! A TCP connection carries no HTTP, so a middleware here sees one thing: the address of the
//! peer, which is the source of the PROXY protocol header when the entry point reads one
//! (`docs/ref/proxy-protocol.md`) and the TCP peer otherwise. Nothing is read from the stream.
//!
//! The chain of the router that took the connection runs in order, before the tenant takes its
//! slot and before any server is dialled. A refusal closes the connection without a byte and
//! is counted in `podgate_l4_refused_total`; the permits the earlier middlewares took go back.
//! The permits of the whole chain are held until the connection ends, whatever ends it.
//!
//! - `ip_allow_list {source_range}` admits the peers inside the blocks ([`CidrSet`], the type of
//!   the HTTP middleware) and refuses the others. There is no `ip_strategy`: with no headers
//!   there is no chain of addresses to pick from.
//! - `in_flight_conn {amount, source?, max_sources?}` lets each source hold `amount`
//!   connections open at once. The table of sources is the one of `in_flight_req` (see
//!   `src/middleware/limits.rs`): `max_sources` entries, charged to the tenant's
//!   `max_buffer_bytes` before it is allocated, never evicting a source with a connection open,
//!   and one shared overflow count for the sources that find their set full.

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::budget::TenantBudget;
use crate::client_ip::Cidr;
use crate::client_ip::set::CidrSet;
use crate::compile::Invalid;
use crate::middleware::limits::{
    DEFAULT_IPV6_SUBNET_BITS, DEFAULT_MAX_SOURCES, Limiter, MAX_SOURCES, Permit, SourceTable,
    Stats, ip_material,
};
use crate::middleware::{ip_allow_list, state};
use crate::table::CompiledApp;
use podgate_model::Declared;

/// The kinds a TCP middleware can be.
pub const KINDS: [&str; 2] = ["in_flight_conn", "ip_allow_list"];

/// Posture change kinds of `in_flight_conn`; `ip_allow_list` reports the HTTP kinds
/// ([`ip_allow_list::kind`]).
pub mod kind {
    /// The middleware is gone from every chain: nothing caps the connections.
    pub const IN_FLIGHT_CONN_REMOVED: &str = "in_flight_conn_removed";
    /// A higher `amount`.
    pub const IN_FLIGHT_CONN_LOOSENED: &str = "in_flight_conn_loosened";
    /// Connections are counted per another source, which can let a client leave its count.
    pub const IN_FLIGHT_CONN_SOURCE_CHANGED: &str = "in_flight_conn_source_changed";
}

/// Why a connection did not pass the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// `ip_allow_list`: the peer is outside the blocks.
    NotAllowed,
    /// `in_flight_conn`: the source already has `amount` connections open.
    OverSource,
    /// `in_flight_conn`: the tenant's buffer budget cannot take the table of sources now.
    OverBudget,
}

/// The configuration of an `ip_allow_list` middleware on a TCP router.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpAllowListConfig {
    /// The blocks, CIDR or single addresses, IPv4 and IPv6, 1 to 4096 of them.
    source_range: Vec<Cidr>,
}

/// The configuration of an `in_flight_conn` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InFlightConnConfig {
    /// Connections one source may hold open at once, at least 1.
    amount: u32,
    /// What counts as a source. Absent: `{"ip": {}}`, the peer address.
    #[serde(default)]
    source: Option<SourceConfig>,
    /// Sources the table holds, 1 to 1,000,000; default 10,000.
    #[serde(default)]
    max_sources: Option<u32>,
}

/// A `source` of `in_flight_conn`: only the address exists at layer 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceConfig {
    /// The peer address, an IPv6 one counted by its first `ipv6_subnet_bits` bits.
    Ip(IpSource),
}

/// The `ip` source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpSource {
    /// Prefix length an IPv6 peer is counted by, 1 to 128; default 64.
    #[serde(default)]
    ipv6_subnet_bits: Option<u8>,
}

fn invalid(kind: &str, message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("{kind}: {message}"))
}

/// A compiled `ip_allow_list`.
#[derive(Debug)]
pub struct IpAllowList {
    allowed: CidrSet,
}

impl IpAllowList {
    fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: IpAllowListConfig =
            serde_json::from_value(Value::Object(declared.config.clone()))
                .map_err(|err| invalid("ip_allow_list", err))?;
        if config.source_range.is_empty() {
            return Err(invalid(
                "ip_allow_list",
                "`source_range` is empty; a list that admits nobody is a mistake (remove the router instead)",
            ));
        }
        if config.source_range.len() > ip_allow_list::MAX_RANGES {
            return Err(invalid(
                "ip_allow_list",
                format!("more than {} ranges", ip_allow_list::MAX_RANGES),
            ));
        }
        Ok(Self {
            allowed: CidrSet::new(config.source_range),
        })
    }
}

/// A compiled `in_flight_conn`.
#[derive(Debug)]
pub struct InFlightConn {
    amount: u32,
    max_sources: u32,
    subnet_bits: u8,
    fingerprint: u64,
    runtime: Arc<Limiter>,
}

impl InFlightConn {
    fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: InFlightConnConfig =
            serde_json::from_value(Value::Object(declared.config.clone()))
                .map_err(|err| invalid("in_flight_conn", err))?;
        if config.amount == 0 {
            return Err(invalid(
                "in_flight_conn",
                "`amount` must be at least 1; a cap of zero refuses every connection (remove the router instead)",
            ));
        }
        let max_sources = config.max_sources.unwrap_or(DEFAULT_MAX_SOURCES);
        if !(1..=MAX_SOURCES).contains(&max_sources) {
            return Err(invalid(
                "in_flight_conn",
                format!("`max_sources` must be 1 to {MAX_SOURCES}"),
            ));
        }
        let SourceConfig::Ip(source) = config
            .source
            .unwrap_or(SourceConfig::Ip(IpSource::default()));
        let subnet_bits = source.ipv6_subnet_bits.unwrap_or(DEFAULT_IPV6_SUBNET_BITS);
        if !(1..=128).contains(&subnet_bits) {
            return Err(invalid(
                "in_flight_conn",
                "`source.ip.ipv6_subnet_bits` must be 1 to 128",
            ));
        }
        Ok(Self {
            amount: config.amount,
            max_sources,
            subnet_bits,
            fingerprint: state::fingerprint(declared),
            runtime: Arc::new(Limiter::new(max_sources)),
        })
    }

    /// Takes one of the peer's connection slots. The table is allocated, after charging the
    /// tenant for it, by the first connection that reaches the middleware.
    fn admit(&self, peer: IpAddr, tenant: &Arc<TenantBudget>) -> Result<Permit, Refusal> {
        let Some(table) = self.runtime.table(Some(tenant)) else {
            return Err(Refusal::OverBudget);
        };
        let key = ip_material(peer, self.subnet_bits, |material| {
            self.runtime.hasher().hash_one(material)
        })
        .max(1);
        self.runtime
            .acquire(table, key, self.amount)
            .ok_or_else(|| {
                self.runtime.count_rejected();
                Refusal::OverSource
            })
    }
}

/// A compiled TCP middleware.
#[derive(Debug)]
pub enum Stage {
    /// `in_flight_conn`.
    InFlightConn(InFlightConn),
    /// `ip_allow_list`.
    IpAllowList(IpAllowList),
}

impl Stage {
    /// Compiles one declared TCP middleware.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` for a configuration that does not parse or is out of range, or for
    /// an HTTP middleware kind; `unknown_middleware` for a type that is none of [`KINDS`].
    pub fn compile(declared: &Declared) -> Result<Self, Invalid> {
        match &*declared.kind {
            "in_flight_conn" => InFlightConn::compile(declared).map(Self::InFlightConn),
            "ip_allow_list" => IpAllowList::compile(declared).map(Self::IpAllowList),
            other if crate::middleware::Stage::BUILT.contains(&other) => Err(Invalid::new(
                "invalid_middleware",
                format!(
                    "middleware type {other} is an HTTP middleware; a TCP router takes {}",
                    KINDS.join(" and ")
                ),
            )),
            other => Err(Invalid::new(
                "unknown_middleware",
                format!(
                    "unknown TCP middleware type {other}; a TCP router takes {}",
                    KINDS.join(" and ")
                ),
            )),
        }
    }

    /// The `type` as written in a snapshot.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InFlightConn(_) => "in_flight_conn",
            Self::IpAllowList(_) => "ip_allow_list",
        }
    }

    /// Entries of the table of sources, for the kind that has one.
    pub(crate) fn max_sources(&self) -> Option<u32> {
        match self {
            Self::InFlightConn(cap) => Some(cap.max_sources),
            Self::IpAllowList(_) => None,
        }
    }

    /// What the limiter reports, for the kind that has one.
    pub(crate) fn stats(&self) -> Option<Stats> {
        match self {
            Self::InFlightConn(cap) => Some(cap.runtime.stats()),
            Self::IpAllowList(_) => None,
        }
    }

    /// Whether the connection from `peer` of `tenant` may pass, and the permit it then holds.
    fn admit(&self, peer: IpAddr, tenant: &Arc<TenantBudget>) -> Result<Option<Permit>, Refusal> {
        match self {
            Self::IpAllowList(list) => list
                .allowed
                .contains(peer)
                .then_some(None)
                .ok_or(Refusal::NotAllowed),
            Self::InFlightConn(cap) => cap.admit(peer, tenant).map(Some),
        }
    }

    /// The relaxations a plan lists when `new` (`None`: nothing) replaces this stage.
    #[must_use]
    pub fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match (self, new) {
            (Self::IpAllowList(_), None) => vec![ip_allow_list::kind::REMOVED],
            (Self::IpAllowList(old), Some(Self::IpAllowList(new))) => {
                if old.allowed.covers_all(&new.allowed) {
                    Vec::new()
                } else {
                    vec![ip_allow_list::kind::WIDENED]
                }
            }
            (Self::InFlightConn(_), None) => vec![kind::IN_FLIGHT_CONN_REMOVED],
            (Self::InFlightConn(old), Some(Self::InFlightConn(new))) => {
                let mut kinds = Vec::new();
                if new.amount > old.amount {
                    kinds.push(kind::IN_FLIGHT_CONN_LOOSENED);
                }
                if old.subnet_bits != new.subnet_bits {
                    kinds.push(kind::IN_FLIGHT_CONN_SOURCE_CHANGED);
                }
                kinds
            }
            // A middleware replaced by one of another kind no longer does what it did.
            (Self::IpAllowList(_), Some(_)) => vec![ip_allow_list::kind::REMOVED],
            (Self::InFlightConn(_), Some(_)) => vec![kind::IN_FLIGHT_CONN_REMOVED],
        }
    }

    /// What explain and the overview show for this stage besides its name and type.
    #[must_use]
    pub fn describe(&self) -> Value {
        match self {
            Self::IpAllowList(list) => json!({
                "source_range": list.allowed.blocks().iter().map(ToString::to_string).collect::<Vec<_>>(),
            }),
            Self::InFlightConn(cap) => json!({
                "amount": cap.amount,
                "source": { "ip": { "ipv6_subnet_bits": cap.subnet_bits } },
                "max_sources": cap.max_sources,
                "table_bytes": SourceTable::bytes(cap.max_sources),
            }),
        }
    }
}

/// A middleware and the name it was declared under.
#[derive(Debug)]
pub struct Named {
    /// The declared name, unique among the app's TCP middlewares.
    pub name: Box<str>,
    /// The compiled middleware.
    pub stage: Stage,
}

/// The JSON Schema of every TCP middleware kind, by type name.
#[must_use]
pub fn schemas() -> Vec<(&'static str, Value)> {
    vec![
        (
            "in_flight_conn",
            crate::admin::schema::of::<InFlightConnConfig>(),
        ),
        (
            "ip_allow_list",
            crate::admin::schema::of::<IpAllowListConfig>(),
        ),
    ]
}

/// The permits a connection holds while the chain's `in_flight_conn` middlewares count it.
/// Dropping them returns every slot.
#[derive(Debug, Default)]
pub(crate) struct Held(Vec<Permit>);

impl Held {
    /// How many slots are held.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Runs the middlewares of `chain` (indices into `stages`) in order for a connection from `peer`
/// of `tenant`. The first refusal ends it; the permits taken before it go back.
pub(crate) fn admit(
    stages: &[Named],
    chain: &[usize],
    peer: IpAddr,
    tenant: &Arc<TenantBudget>,
) -> Result<Held, Refusal> {
    let mut held = Held::default();
    for named in chain.iter().filter_map(|at| stages.get(*at)) {
        if let Some(permit) = named.stage.admit(peer, tenant)? {
            held.0.push(permit);
        }
    }
    Ok(held)
}

/// The posture changes of an app's TCP middlewares between the live table and a candidate, as a
/// plan lists them: for each middleware some router of `live` runs, what the candidate's
/// middleware of the same name, run by some router of it, does less (`None`: it runs none).
#[must_use]
pub fn relaxations(
    live: &super::tcp::Compiled,
    candidate: &super::tcp::Compiled,
) -> Vec<&'static str> {
    let used = |tcp: &super::tcp::Compiled| -> HashSet<usize> {
        tcp.routers()
            .iter()
            .flat_map(|router| router.chain().iter().copied())
            .collect()
    };
    let used_now = used(candidate);
    let mut kinds = Vec::new();
    for index in used(live) {
        let Some(old) = live.middlewares().get(index) else {
            continue;
        };
        let new = candidate
            .middlewares()
            .iter()
            .enumerate()
            .find(|(at, named)| named.name == old.name && used_now.contains(at))
            .map(|(_, named)| &named.stage);
        for posture in old.stage.posture(new) {
            if !kinds.contains(&posture) {
                kinds.push(posture);
            }
        }
    }
    kinds
}

/// Compiles the TCP middlewares of an app, each of `declared` once; every problem goes to
/// `problem` by name. Returns the compiled ones and the names of those that did not compile (or
/// were declared twice), so a router naming one adds no second problem.
pub(crate) fn compile_all(
    declared: &[Declared],
    mut problem: impl FnMut(String, Invalid),
) -> (Vec<Named>, HashSet<&str>) {
    let mut named = Vec::with_capacity(declared.len());
    let mut broken = HashSet::new();
    let mut seen = HashSet::new();
    for declared in declared {
        let at = format!("tcp middleware {}", declared.name);
        if !seen.insert(&*declared.name) {
            problem(
                at,
                Invalid::new(
                    "duplicate_name",
                    format!("tcp middleware {} is declared twice", declared.name),
                ),
            );
            continue;
        }
        match Stage::compile(declared) {
            Ok(stage) => named.push(Named {
                name: declared.name.clone(),
                stage,
            }),
            Err(invalid) => {
                broken.insert(&*declared.name);
                problem(at, invalid);
            }
        }
    }
    (named, broken)
}

/// The counts of every `in_flight_conn` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]), like the
/// ones of `in_flight_req`: a push that leaves a middleware's declaration as it was keeps its
/// counts, so a connection that started under the old table still returns its slot to the
/// counts the new one uses; one whose declaration changed starts with empty ones.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Limiter>);

impl Registry {
    /// See [`state::Registry::settle_entries`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle_entries(apps.iter_mut().flat_map(|app| {
            let app_id: Box<str> = app.id().into();
            app.l4_mut()
                .tcp_mut()
                .middlewares_mut()
                .iter_mut()
                .filter_map(move |named| match &mut named.stage {
                    Stage::InFlightConn(cap) => Some((
                        app_id.clone(),
                        named.name.clone(),
                        cap.fingerprint,
                        &mut cap.runtime,
                    )),
                    Stage::IpAllowList(_) => None,
                })
        }));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use podgate_model::Budget;

    fn declared(kind: &str, config: &Value) -> Declared {
        let mut object = config.as_object().cloned().unwrap_or_default();
        object.insert("name".into(), json!("m"));
        object.insert("type".into(), json!(kind));
        serde_json::from_value(Value::Object(object)).expect("declared")
    }

    fn stage(kind: &str, config: &Value) -> Result<Stage, Invalid> {
        Stage::compile(&declared(kind, config))
    }

    fn tenant(max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t",
            Budget {
                max_inflight: 100,
                max_buffer_bytes,
            },
        )
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn named(stages: Vec<Stage>) -> Vec<Named> {
        stages
            .into_iter()
            .enumerate()
            .map(|(at, stage)| Named {
                name: format!("m{at}").into(),
                stage,
            })
            .collect()
    }

    #[test]
    fn an_allow_list_admits_its_blocks_only() {
        let list = stage(
            "ip_allow_list",
            &json!({ "source_range": ["10.0.0.0/8", "2001:db8::/32"] }),
        )
        .expect("compiles");
        let stages = named(vec![list]);
        let tenant = tenant(1 << 20);
        for inside in ["10.1.2.3", "::ffff:10.1.2.3", "2001:db8::1"] {
            assert!(
                admit(&stages, &[0], ip(inside), &tenant).is_ok(),
                "{inside}"
            );
        }
        for outside in ["11.0.0.1", "::ffff:11.0.0.1", "2001:db9::1", "::1"] {
            assert_eq!(
                admit(&stages, &[0], ip(outside), &tenant).err(),
                Some(Refusal::NotAllowed),
                "{outside}"
            );
        }
    }

    #[test]
    fn in_flight_conn_caps_each_source_and_returns_slots_on_drop() {
        let cap = stage("in_flight_conn", &json!({ "amount": 2 })).expect("compiles");
        let stages = named(vec![cap]);
        let tenant = tenant(1 << 20);
        let first = admit(&stages, &[0], ip("192.0.2.1"), &tenant).expect("first");
        let _second = admit(&stages, &[0], ip("192.0.2.1"), &tenant).expect("second");
        assert_eq!(first.len(), 1);
        assert_eq!(
            admit(&stages, &[0], ip("192.0.2.1"), &tenant).err(),
            Some(Refusal::OverSource)
        );
        assert!(
            admit(&stages, &[0], ip("192.0.2.2"), &tenant).is_ok(),
            "another source has its own count"
        );
        drop(first);
        assert!(admit(&stages, &[0], ip("192.0.2.1"), &tenant).is_ok());
    }

    #[test]
    fn a_refusal_returns_the_slots_the_chain_took_before_it() {
        let stages = named(vec![
            stage("in_flight_conn", &json!({ "amount": 1 })).expect("cap"),
            stage("ip_allow_list", &json!({ "source_range": ["10.0.0.0/8"] })).expect("list"),
        ]);
        let tenant = tenant(1 << 20);
        assert_eq!(
            admit(&stages, &[0, 1], ip("192.0.2.1"), &tenant).err(),
            Some(Refusal::NotAllowed)
        );
        assert!(
            admit(&stages, &[0], ip("192.0.2.1"), &tenant).is_ok(),
            "the refused connection gave its slot back"
        );
    }

    #[test]
    fn an_ipv6_peer_is_counted_by_its_prefix() {
        let cap = stage(
            "in_flight_conn",
            &json!({ "amount": 1, "source": { "ip": { "ipv6_subnet_bits": 64 } } }),
        )
        .expect("compiles");
        let stages = named(vec![cap]);
        let tenant = tenant(1 << 20);
        let _held = admit(&stages, &[0], ip("2001:db8:1:2::1"), &tenant).expect("first");
        assert_eq!(
            admit(&stages, &[0], ip("2001:db8:1:2::ffff"), &tenant).err(),
            Some(Refusal::OverSource),
            "the same /64"
        );
        assert!(admit(&stages, &[0], ip("2001:db8:1:3::1"), &tenant).is_ok());
    }

    #[test]
    fn the_table_is_bounded_and_charged_to_the_tenant() {
        let cap =
            stage("in_flight_conn", &json!({ "amount": 1, "max_sources": 8 })).expect("compiles");
        let stages = named(vec![cap]);
        let tenant = tenant(SourceTable::bytes(8));
        assert_eq!(tenant.buffered(), 0, "nothing before the first connection");
        let mut held = Vec::new();
        let mut refused = 0;
        for last in 1..=40_u8 {
            match admit(&stages, &[0], ip(&format!("192.0.2.{last}")), &tenant) {
                Ok(permit) => held.push(permit),
                Err(Refusal::OverSource) => refused += 1,
                Err(other) => panic!("{other:?}"),
            }
        }
        assert_eq!(
            tenant.buffered(),
            SourceTable::bytes(8),
            "one table, however many sources"
        );
        assert!(
            held.len() <= 9,
            "eight entries and one overflow slot, got {}",
            held.len()
        );
        assert!(refused >= 31, "{refused}");
    }

    #[test]
    fn a_budget_that_cannot_take_the_table_refuses_the_connection() {
        let cap = stage("in_flight_conn", &json!({ "amount": 1 })).expect("compiles");
        let stages = named(vec![cap]);
        assert_eq!(
            admit(&stages, &[0], ip("192.0.2.1"), &tenant(10)).err(),
            Some(Refusal::OverBudget)
        );
    }

    #[test]
    fn invalid_configurations_are_refused_with_their_codes() {
        let code = |kind: &str, config: Value| stage(kind, &config).expect_err(kind).code;
        for (kind, config) in [
            ("ip_allow_list", json!({})),
            ("ip_allow_list", json!({ "source_range": [] })),
            ("ip_allow_list", json!({ "source_range": ["nonsense"] })),
            (
                "ip_allow_list",
                json!({ "source_range": ["10.0.0.0/8"], "ip_strategy": { "depth": 1 } }),
            ),
            ("in_flight_conn", json!({})),
            ("in_flight_conn", json!({ "amount": 0 })),
            ("in_flight_conn", json!({ "amount": 1, "max_sources": 0 })),
            (
                "in_flight_conn",
                json!({ "amount": 1, "max_sources": MAX_SOURCES + 1 }),
            ),
            (
                "in_flight_conn",
                json!({ "amount": 1, "source": { "header": "x" } }),
            ),
            (
                "in_flight_conn",
                json!({ "amount": 1, "source": { "ip": { "depth": 2 } } }),
            ),
            (
                "in_flight_conn",
                json!({ "amount": 1, "source": { "ip": { "ipv6_subnet_bits": 0 } } }),
            ),
            ("headers", json!({})),
        ] {
            assert_eq!(
                code(kind, config.clone()),
                "invalid_middleware",
                "{kind} {config}"
            );
        }
        assert_eq!(code("nonsense", json!({})), "unknown_middleware");
    }

    #[test]
    fn posture_lists_removal_and_loosening() {
        let list = |ranges: Value| {
            stage("ip_allow_list", &json!({ "source_range": ranges })).expect("compiles")
        };
        let base = list(json!(["10.0.0.0/8"]));
        assert_eq!(base.posture(None), [ip_allow_list::kind::REMOVED]);
        assert!(base.posture(Some(&list(json!(["10.1.0.0/16"])))).is_empty());
        assert_eq!(
            base.posture(Some(&list(json!(["10.0.0.0/8", "192.0.2.0/24"])))),
            [ip_allow_list::kind::WIDENED]
        );
        let cap = |amount: u32, bits: u8| {
            stage(
                "in_flight_conn",
                &json!({ "amount": amount, "source": { "ip": { "ipv6_subnet_bits": bits } } }),
            )
            .expect("compiles")
        };
        let base = cap(5, 64);
        assert_eq!(base.posture(None), [kind::IN_FLIGHT_CONN_REMOVED]);
        assert!(base.posture(Some(&cap(4, 64))).is_empty());
        assert_eq!(
            base.posture(Some(&cap(6, 64))),
            [kind::IN_FLIGHT_CONN_LOOSENED]
        );
        assert_eq!(
            base.posture(Some(&cap(5, 128))),
            [kind::IN_FLIGHT_CONN_SOURCE_CHANGED]
        );
    }
}
