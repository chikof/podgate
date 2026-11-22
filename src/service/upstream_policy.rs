//! The upstream address policy: which addresses podgate may connect to on behalf of a tenant.
//!
//! A tenant's snapshot decides *where* its servers are, so without a rule a tenant could aim
//! podgate at loopback, the cloud metadata service, the admin plane or another tenant's
//! network. The operator owns that rule: a JSON file named by `UPSTREAM_POLICY_FILE`, read once
//! at startup and never part of a snapshot, so no snapshot field can add an allowed range.
//!
//! ```json
//! { "deny": ["10.9.0.0/16"],
//!   "default": { "allow": ["10.0.0.0/8"] },
//!   "tenants": { "acme": { "allow": ["10.4.0.0/16", "192.168.7.0/24"] } } }
//! ```
//!
//! An address is permitted when it is in no `deny` range and, when the tenant's entry (else
//! `default`) has an `allow` list, inside it. Without `deny` the [built-in default](
//! UpstreamPolicy::builtin) applies; `deny_extra` adds to the default instead of replacing it.
//! A deny range always beats an allow range. IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible
//! (`::a.b.c.d`) IPv6 addresses are checked as the IPv4 address they carry (and, for deny, as
//! written too), so `[::ffff:127.0.0.1]` is loopback.
//!
//! # Who calls what
//!
//! Every code path that opens a connection a tenant can influence calls the policy with the
//! tenant's id and the address it is about to dial:
//!
//! - [`UpstreamPolicy::check`]: at connect time. Counts a refusal in
//!   `podgate_upstream_refused_total{tenant}` and logs it. Proxying, health probes, mirrors, forward
//!   auth, error pages and every address a resolver returns call this, immediately before
//!   `connect`, on every address, every time.
//! - [`UpstreamPolicy::evaluate`]: the same verdict with no side effect, for the compiler
//!   (`upstream_forbidden`) and for dry runs.
//!
//! The policy is read once and has no hot reload; restart to change it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use thiserror::Error;

use super::Server;
use crate::budget::Escaped;
use crate::compile::Invalid;

/// A CIDR range of IPv4 or IPv6 addresses, such as `10.0.0.0/8`. A bare address is a single
/// host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

const fn v4(octets: [u8; 4], prefix: u8) -> Cidr {
    let [a, b, c, d] = octets;
    Cidr {
        network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        prefix,
    }
}

const fn v6(segments: [u16; 8], prefix: u8) -> Cidr {
    let [a, b, c, d, e, f, g, h] = segments;
    Cidr {
        network: IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
        prefix,
    }
}

fn mask4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// Why a string is not a CIDR.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CidrError {
    /// The address part does not parse.
    #[error("{0:?} is not an IP address")]
    Address(Box<str>),
    /// The prefix is not a number up to the address length.
    #[error("prefix {0:?} is not a whole number up to {1}")]
    Prefix(Box<str>, u8),
    /// Bits beyond the prefix are set, which is almost always a typo.
    #[error("host bits are set, write it as {0}")]
    HostBits(Box<str>),
}

impl FromStr for Cidr {
    type Err = CidrError;

    /// Parses `address/prefix`, or a bare address as a single host. Host bits beyond the prefix
    /// are an error. An IPv4-mapped IPv6 range (`::ffff:a.b.c.d/N`, `N >= 96`) is the IPv4 range
    /// it carries.
    fn from_str(text: &str) -> Result<Self, CidrError> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let ip: IpAddr = address
            .parse()
            .map_err(|_| CidrError::Address(address.into()))?;
        let width: u8 = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= width)
                .ok_or_else(|| CidrError::Prefix(prefix.into(), width))?,
        };
        let cidr = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(mapped) if prefix >= 96 => Cidr {
                    network: IpAddr::V4(mapped),
                    prefix: prefix - 96,
                },
                _ => Cidr {
                    network: ip,
                    prefix,
                },
            },
            IpAddr::V4(_) => Cidr {
                network: ip,
                prefix,
            },
        };
        let masked = cidr.masked();
        if masked == cidr {
            Ok(cidr)
        } else {
            Err(CidrError::HostBits(masked.to_string().into()))
        }
    }
}

impl Cidr {
    fn masked(self) -> Self {
        let network = match self.network {
            IpAddr::V4(net) => IpAddr::V4(Ipv4Addr::from(u32::from(net) & mask4(self.prefix))),
            IpAddr::V6(net) => IpAddr::V6(Ipv6Addr::from(u128::from(net) & mask6(self.prefix))),
        };
        Self {
            network,
            prefix: self.prefix,
        }
    }

    /// The first address of the range.
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The number of leading bits the range fixes.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside the range. An address of the other family never is.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & mask4(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask6(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// What is denied when the policy file has no `deny` list: loopback, unspecified, link-local
/// (which holds the metadata address `169.254.169.254`) and multicast, for both families, plus
/// the other well-known metadata addresses: Alibaba `100.100.100.200`, Oracle `192.0.0.192` and
/// AWS over IPv6 `fd00:ec2::254`. Private ranges are not here: they are the normal upstreams.
const BUILTIN_DENY: [Cidr; 11] = [
    v4([127, 0, 0, 0], 8),
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128),
    v4([0, 0, 0, 0], 8),
    v6([0; 8], 128),
    v4([169, 254, 0, 0], 16),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    v4([224, 0, 0, 0], 4),
    v6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
    v4([100, 100, 100, 200], 32),
    v4([192, 0, 0, 192], 32),
    v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128),
];

/// Why the policy refuses an address.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Refused {
    /// The address is in a denied range.
    #[error("{ip} is in the denied range {range}")]
    Denied {
        /// The address that was checked, as given.
        ip: IpAddr,
        /// The `deny` entry that matched.
        range: Cidr,
    },
    /// The tenant (or the default) has an allow list and the address is not in it.
    #[error("{ip} is outside the allowed ranges of {scope}")]
    NotAllowed {
        /// The address that was checked, as given.
        ip: IpAddr,
        /// `tenant <id>` or `the default entry`.
        scope: Box<str>,
    },
}

impl Refused {
    /// The rule that refused, for logs and `422` entries: the denied range, or `not in the
    /// allow list`.
    #[must_use]
    pub fn rule(&self) -> String {
        match self {
            Self::Denied { range, .. } => format!("deny {range}"),
            Self::NotAllowed { scope, .. } => format!("not in the allow list of {scope}"),
        }
    }
}

/// A policy file that cannot be used. Names the entry that is wrong.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{entry}: {reason}")]
pub struct PolicyError {
    /// The entry that is wrong, like `deny[1]` or `tenants.acme.allow[0]`; the file path for a
    /// file that cannot be read.
    pub entry: Box<str>,
    /// What is wrong with it.
    pub reason: Box<str>,
}

impl PolicyError {
    fn new(entry: impl Into<Box<str>>, reason: impl fmt::Display) -> Self {
        Self {
            entry: entry.into(),
            reason: reason.to_string().into(),
        }
    }
}

/// `{"allow": [cidr...], "srv_allow_ports": [port...]}`. `allow` is required: an entry that
/// restricts nothing would be a typo that silently loosens the policy.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    allow: Vec<String>,
    #[serde(default)]
    srv_allow_ports: Option<Vec<u16>>,
}

/// A JSON object read as a list of pairs, so a repeated key is an error instead of the last
/// one winning.
pub(crate) struct Pairs<T>(pub(crate) Vec<(String, T)>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Pairs<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairsVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for PairsVisitor<T> {
            type Value = Pairs<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs<T>, A::Error> {
                let mut seen = HashSet::new();
                let mut pairs = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, T>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!("{key:?} appears twice")));
                    }
                    pairs.push((key, value));
                }
                Ok(Pairs(pairs))
            }
        }

        deserializer.deserialize_map(PairsVisitor(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    deny: Option<Vec<String>>,
    #[serde(default)]
    deny_extra: Option<Vec<String>>,
    #[serde(default)]
    srv_deny_ports: Option<Vec<u16>>,
    #[serde(default)]
    default: Option<EntryFile>,
    #[serde(default)]
    tenants: Option<Pairs<EntryFile>>,
}

/// Ports no SRV record may point a tenant's server at unless the operator's `srv_deny_ports`
/// replaces the list: remote shells and mail (22, 23, 25, 110, 143, 465, 587, 993, 995), the
/// Docker daemon (2375, 2376) and the usual databases and caches (3306, 5432, 5984, 6379,
/// 9200, 9300, 11211, 27017).
const DEFAULT_SRV_DENY_PORTS: [u16; 19] = [
    22, 23, 25, 110, 143, 465, 587, 993, 995, 2375, 2376, 3306, 5432, 5984, 6379, 9200, 9300,
    11211, 27017,
];

/// Why the policy refuses the port of an SRV target.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PortRefused {
    /// The port is in the operator's deny list.
    #[error("port {port} is in {list}")]
    Denied {
        /// The port that was checked.
        port: u16,
        /// The list that denied it: `srv_deny_ports`.
        list: &'static str,
    },
    /// The tenant (or the default) has `srv_allow_ports` and the port is not in it.
    #[error("port {port} is outside the srv_allow_ports of {scope}")]
    NotAllowed {
        /// The port that was checked.
        port: u16,
        /// `tenant <id>` or `the default entry`.
        scope: Box<str>,
    },
}

fn ports(entry: &str, list: &[u16]) -> Result<Box<[u16]>, PolicyError> {
    match list.iter().position(|port| *port == 0) {
        Some(at) => Err(PolicyError::new(
            format!("{entry}[{at}]"),
            "0 is not a port",
        )),
        None => Ok(list.into()),
    }
}

/// The rules on the port of an SRV target, which DNS (and not the snapshot) chooses.
#[derive(Debug, Default)]
struct PortRules {
    deny: Box<[u16]>,
    default_allow: Option<Box<[u16]>>,
    tenants: HashMap<Box<str>, Box<[u16]>>,
}

fn ranges(entry: &str, list: &[String]) -> Result<Vec<Cidr>, PolicyError> {
    list.iter()
        .enumerate()
        .map(|(at, text)| {
            text.trim()
                .parse::<Cidr>()
                .map_err(|err| PolicyError::new(format!("{entry}[{at}]"), err))
        })
        .collect()
}

#[derive(Debug)]
struct Inner {
    deny: Box<[Cidr]>,
    default_allow: Option<Box<[Cidr]>>,
    tenants: HashMap<Box<str>, Box<[Cidr]>>,
    ports: PortRules,
    refused: Mutex<BTreeMap<Box<str>, u64>>,
    refused_ports: Mutex<BTreeMap<Box<str>, u64>>,
}

/// The operator's rule for which addresses podgate may connect to, per tenant. Cheap to clone;
/// every clone shares the same refusal counters. See the [module docs](self).
///
/// ```
/// use podgate::service::upstream_policy::UpstreamPolicy;
///
/// let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)?;
/// assert!(policy.evaluate("acme", "10.4.1.2".parse()?).is_ok());
/// assert!(policy.evaluate("acme", "10.5.1.2".parse()?).is_err());
/// assert!(policy.evaluate("other", "10.5.1.2".parse()?).is_ok());
/// assert!(policy.evaluate("other", "169.254.169.254".parse()?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct UpstreamPolicy {
    inner: Arc<Inner>,
}

impl UpstreamPolicy {
    fn from_parts(
        deny: Vec<Cidr>,
        default_allow: Option<Vec<Cidr>>,
        tenants: HashMap<Box<str>, Box<[Cidr]>>,
        ports: PortRules,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                deny: deny.into(),
                default_allow: default_allow.map(Vec::into),
                tenants,
                ports,
                refused: Mutex::new(BTreeMap::new()),
                refused_ports: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// The policy with no file: the built-in deny list (loopback, unspecified, link-local,
    /// metadata and multicast), the default `srv_deny_ports` and no allow lists. What a process
    /// without `UPSTREAM_POLICY_FILE` runs.
    #[must_use]
    pub fn builtin() -> Self {
        Self::from_parts(
            BUILTIN_DENY.to_vec(),
            None,
            HashMap::new(),
            PortRules {
                deny: DEFAULT_SRV_DENY_PORTS.into(),
                ..PortRules::default()
            },
        )
    }

    /// A policy that refuses nothing. Only for tests and tools that build a routing table
    /// without a running process; `run` always installs the operator's policy.
    #[must_use]
    pub fn allow_all() -> Self {
        Self::from_parts(Vec::new(), None, HashMap::new(), PortRules::default())
    }

    /// Parses the JSON of a policy file.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] naming the entry that is wrong: a CIDR that does not parse (`deny[1]`),
    /// an unknown field, a tenant that appears twice, or both `deny` and `deny_extra`.
    pub fn parse(json: &str) -> Result<Self, PolicyError> {
        // A JSON array would otherwise be read positionally as the struct's fields. The text is
        // parsed once, straight into the struct: going through `Value` would let the last of
        // two equal keys win silently.
        if !json.trim_start().starts_with('{') {
            return Err(PolicyError::new("file", "expected a JSON object"));
        }
        let file: PolicyFile =
            serde_json::from_str(json).map_err(|err| PolicyError::new("file", err))?;
        let deny = match (&file.deny, &file.deny_extra) {
            (Some(_), Some(_)) => {
                return Err(PolicyError::new(
                    "deny_extra",
                    "cannot be combined with deny: deny replaces the built-in list and deny_extra adds to it",
                ));
            }
            (Some(list), None) => ranges("deny", list)?,
            (None, extra) => {
                let mut list = BUILTIN_DENY.to_vec();
                if let Some(extra) = extra {
                    list.extend(ranges("deny_extra", extra)?);
                }
                list
            }
        };
        let default_ports = match file
            .default
            .as_ref()
            .and_then(|entry| entry.srv_allow_ports.as_deref())
        {
            Some(list) => Some(ports("default.srv_allow_ports", list)?),
            None => None,
        };
        let default_allow = file
            .default
            .map(|entry| ranges("default.allow", &entry.allow))
            .transpose()?;
        let mut tenants = HashMap::new();
        let mut port_tenants = HashMap::new();
        for (id, entry) in file.tenants.map_or_else(Vec::new, |pairs| pairs.0) {
            let allow = ranges(&format!("tenants.{id}.allow"), &entry.allow)?;
            if let Some(list) = &entry.srv_allow_ports {
                let list = ports(&format!("tenants.{id}.srv_allow_ports"), list)?;
                port_tenants.insert(Box::from(id.as_str()), list);
            }
            tenants.insert(Box::from(id), allow.into());
        }
        let deny_ports = match &file.srv_deny_ports {
            Some(list) => ports("srv_deny_ports", list)?,
            None => DEFAULT_SRV_DENY_PORTS.into(),
        };
        Ok(Self::from_parts(
            deny,
            default_allow,
            tenants,
            PortRules {
                deny: deny_ports,
                default_allow: default_ports,
                tenants: port_tenants,
            },
        ))
    }

    /// Reads and parses the policy file at `path`.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] when the file cannot be read or [`Self::parse`] refuses it.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| PolicyError::new(path.display().to_string(), err))?;
        Self::parse(&text)
    }

    fn allow_list(&self, tenant: &str) -> Option<(&[Cidr], Box<str>)> {
        match self.inner.tenants.get(tenant) {
            Some(list) => Some((list, format!("tenant {tenant}").into())),
            None => self
                .inner
                .default_allow
                .as_deref()
                .map(|list| (list, "the default entry".into())),
        }
    }

    /// The verdict for `tenant` dialling `ip`, with no side effect. Use it where nothing is
    /// dialled, such as the compiler's check of literal server addresses; use [`Self::check`]
    /// right before a connection.
    ///
    /// # Errors
    ///
    /// [`Refused`] naming the deny range that matched, or the allow list `ip` is outside of.
    pub fn evaluate(&self, tenant: &str, ip: IpAddr) -> Result<(), Refused> {
        let seen = canonical(ip);
        let compat = compat_v4(ip);
        let hit = self.inner.deny.iter().find(|range| {
            range.contains(seen)
                || (seen != ip && range.contains(ip))
                || compat.is_some_and(|v4| range.contains(v4))
        });
        if let Some(range) = hit {
            return Err(Refused::Denied { ip, range: *range });
        }
        match self.allow_list(tenant) {
            Some((allow, scope)) if !allow.iter().any(|range| range.contains(seen)) => {
                Err(Refused::NotAllowed { ip, scope })
            }
            _ => Ok(()),
        }
    }

    fn allow_ports(&self, tenant: &str) -> Option<(&[u16], Box<str>)> {
        match self.inner.ports.tenants.get(tenant) {
            Some(list) => Some((list, format!("tenant {tenant}").into())),
            None => self
                .inner
                .ports
                .default_allow
                .as_deref()
                .map(|list| (list, "the default entry".into())),
        }
    }

    /// The verdict for `tenant` using `port` of an SRV target, with no side effect: the port is
    /// refused when it is in `srv_deny_ports` or, when the tenant (else `default`) has
    /// `srv_allow_ports`, outside it. A deny entry always beats an allow entry. DNS chooses the
    /// port of an SRV target, so this is checked besides [`Self::evaluate`] on the address.
    ///
    /// # Errors
    ///
    /// [`PortRefused`] naming the list that refused.
    pub fn evaluate_port(&self, tenant: &str, port: u16) -> Result<(), PortRefused> {
        if self.inner.ports.deny.contains(&port) {
            return Err(PortRefused::Denied {
                port,
                list: "srv_deny_ports",
            });
        }
        match self.allow_ports(tenant) {
            Some((allow, scope)) if !allow.contains(&port) => {
                Err(PortRefused::NotAllowed { port, scope })
            }
            _ => Ok(()),
        }
    }

    /// [`Self::evaluate_port`] for a target that is about to be used: a refusal is also counted
    /// in `podgate_upstream_refused_total{tenant,reason="port"}` and logged.
    ///
    /// # Errors
    ///
    /// The same as [`Self::evaluate_port`]; the caller must not use the target.
    pub fn check_port(&self, tenant: &str, port: u16) -> Result<(), PortRefused> {
        let verdict = self.evaluate_port(tenant, port);
        if let Err(refused) = &verdict {
            let mut counts = self
                .inner
                .refused_ports
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            *counts.entry(tenant.into()).or_insert(0) += 1;
            tracing::warn!(tenant, port, why = %refused, "upstream port refused");
        }
        verdict
    }

    /// [`Self::evaluate`] for a connection that is about to be made: a refusal is also counted
    /// in `podgate_upstream_refused_total{tenant}` and logged. Call it with every address
    /// actually dialled, on every dial, so DNS answers and any future source of addresses are
    /// covered.
    ///
    /// # Errors
    ///
    /// The same as [`Self::evaluate`]; the caller must not connect.
    pub fn check(&self, tenant: &str, ip: IpAddr) -> Result<(), Refused> {
        let verdict = self.evaluate(tenant, ip);
        if let Err(refused) = &verdict {
            let mut counts = self
                .inner
                .refused
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match counts.get_mut(tenant) {
                Some(count) => *count += 1,
                None => {
                    counts.insert(tenant.into(), 1);
                }
            }
            tracing::warn!(tenant, %ip, rule = %refused.rule(), "upstream address refused");
        }
        verdict
    }

    /// One `upstream_forbidden` problem per server of service `service` whose literal address
    /// `tenant` may not use, naming the server and the rule. What the compiler calls for every
    /// service of every revision; empty when all servers pass.
    pub(crate) fn forbidden_servers(
        &self,
        tenant: &str,
        service: &str,
        servers: &[Server],
    ) -> Vec<Invalid> {
        servers
            .iter()
            .filter_map(|server| {
                let refused = self.evaluate(tenant, server.addr.ip()).err()?;
                Some(
                    Invalid::new(
                        "upstream_forbidden",
                        format!(
                            "service {service} server {}: {refused} (rule: {})",
                            server.url,
                            refused.rule()
                        ),
                    )
                    .with("service", service)
                    .with("server", &*server.url)
                    .with("rule", refused.rule()),
                )
            })
            .collect()
    }

    /// Prometheus text exposition of `podgate_upstream_refused_total{tenant}`, which the admin
    /// API appends to `GET /metrics`.
    #[must_use]
    pub fn render(&self) -> String {
        let name = "podgate_upstream_refused_total";
        let mut out = format!(
            "# HELP {name} Connections refused by the upstream address policy.\n# TYPE {name} counter\n"
        );
        let counts = self
            .inner
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (tenant, count) in counts.iter() {
            // Writing to a `String` cannot fail.
            let _ = writeln!(out, "{name}{{tenant=\"{}\"}} {count}", Escaped(tenant));
        }
        drop(counts);
        let counts = self
            .inner
            .refused_ports
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (tenant, count) in counts.iter() {
            let _ = writeln!(
                out,
                "{name}{{tenant=\"{}\",reason=\"port\"}} {count}",
                Escaped(tenant)
            );
        }
        out
    }
}

/// The IPv4 address an IPv4-mapped IPv6 address carries; any other address as it is.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The IPv4 address an IPv4-compatible IPv6 address (`::a.b.c.d`) carries. `::` and `::1` are
/// IPv6 addresses in their own right, so they carry none.
fn compat_v4(ip: IpAddr) -> Option<IpAddr> {
    let IpAddr::V6(v6) = ip else { return None };
    if v6.is_unspecified() || v6.is_loopback() || v6.to_ipv4_mapped().is_some() {
        return None;
    }
    v6.to_ipv4().map(IpAddr::V4)
}

#[cfg(test)]
mod test {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn policy(json: &str) -> UpstreamPolicy {
        UpstreamPolicy::parse(json).expect("policy parses")
    }

    #[test]
    fn loopback_denied_by_default() {
        let builtin = UpstreamPolicy::builtin();
        for denied in [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            "224.0.0.1",
            "239.255.255.250",
            "ff02::1",
            "ff05::2",
        ] {
            assert!(
                builtin.evaluate("t", ip(denied)).is_err(),
                "{denied} must be denied"
            );
        }
        for allowed in [
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "fd12::1",
            "fc00::5",
            "8.8.8.8",
            "2001:db8::1",
            "126.255.255.255",
            "128.0.0.1",
        ] {
            assert!(
                builtin.evaluate("t", ip(allowed)).is_ok(),
                "{allowed} must be allowed"
            );
        }
    }

    #[test]
    fn link_local_metadata_denied() {
        let builtin = UpstreamPolicy::builtin();
        for denied in [
            "169.254.169.254",
            "169.254.0.1",
            "169.254.255.255",
            "fe80::1",
            "febf::1",
            "fd00:ec2::254",
            "100.100.100.200",
            "192.0.0.192",
        ] {
            let refused = builtin
                .evaluate("t", ip(denied))
                .expect_err("must be denied");
            assert!(matches!(refused, Refused::Denied { .. }), "{denied}");
        }
        assert!(builtin.evaluate("t", ip("169.253.255.255")).is_ok());
        assert!(builtin.evaluate("t", ip("fec0::1")).is_ok());
    }

    #[test]
    fn v4_mapped_v6_denied() {
        let builtin = UpstreamPolicy::builtin();
        for denied in [
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
            "::127.0.0.1",
            "::169.254.169.254",
            "0:0:0:0:0:ffff:7f00:1",
        ] {
            assert!(
                builtin.evaluate("t", ip(denied)).is_err(),
                "{denied} must be denied"
            );
        }
        assert!(builtin.evaluate("t", ip("::ffff:10.1.2.3")).is_ok());
        let allow = policy(r#"{"default": {"allow": ["10.0.0.0/8"]}}"#);
        assert!(allow.evaluate("t", ip("::ffff:10.1.2.3")).is_ok());
        assert!(allow.evaluate("t", ip("::ffff:11.1.2.3")).is_err());
        let custom = policy(r#"{"deny": ["::1/128"]}"#);
        assert!(custom.evaluate("t", ip("::1")).is_err());
        assert!(custom.evaluate("t", ip("::ffff:127.0.0.1")).is_ok());
    }

    #[test]
    fn deny_beats_allow() {
        let both = policy(
            r#"{"deny": ["10.9.0.0/16"],
                "default": {"allow": ["10.0.0.0/8"]},
                "tenants": {"t": {"allow": ["10.9.0.0/16", "10.1.0.0/16"]}}}"#,
        );
        assert!(both.evaluate("t", ip("10.1.2.3")).is_ok());
        let refused = both.evaluate("t", ip("10.9.0.1")).expect_err("denied");
        assert_eq!(
            refused,
            Refused::Denied {
                ip: ip("10.9.0.1"),
                range: "10.9.0.0/16".parse().expect("cidr")
            }
        );
        assert!(both.evaluate("other", ip("10.9.0.1")).is_err());
        let allow_loopback = policy(r#"{"default": {"allow": ["127.0.0.0/8"]}}"#);
        assert!(
            allow_loopback.evaluate("t", ip("127.0.0.1")).is_err(),
            "the built-in deny list still applies when only allow is given"
        );
    }

    #[test]
    fn tenant_without_entry_uses_default() {
        let file = policy(
            r#"{"default": {"allow": ["10.0.0.0/8"]},
                "tenants": {"acme": {"allow": ["192.168.0.0/16"]}}}"#,
        );
        assert!(file.evaluate("acme", ip("192.168.1.1")).is_ok());
        assert!(file.evaluate("acme", ip("10.1.1.1")).is_err());
        assert!(file.evaluate("other", ip("10.1.1.1")).is_ok());
        let refused = file
            .evaluate("other", ip("192.168.1.1"))
            .expect_err("outside the default");
        assert_eq!(
            refused,
            Refused::NotAllowed {
                ip: ip("192.168.1.1"),
                scope: "the default entry".into()
            }
        );
        let open = policy(r#"{"tenants": {"acme": {"allow": []}}}"#);
        assert!(open.evaluate("acme", ip("10.1.1.1")).is_err());
        assert!(open.evaluate("other", ip("10.1.1.1")).is_ok());
    }

    #[test]
    fn deny_extra_adds_to_the_default_and_deny_replaces_it() {
        let extra = policy(r#"{"deny_extra": ["10.9.0.0/16"]}"#);
        assert!(extra.evaluate("t", ip("10.9.0.1")).is_err());
        assert!(extra.evaluate("t", ip("127.0.0.1")).is_err());
        let replaced = policy(r#"{"deny": ["10.9.0.0/16"]}"#);
        assert!(replaced.evaluate("t", ip("10.9.0.1")).is_err());
        assert!(replaced.evaluate("t", ip("127.0.0.1")).is_ok());
        assert!(
            UpstreamPolicy::parse(r#"{"deny": [], "deny_extra": []}"#).is_err(),
            "deny and deny_extra are exclusive"
        );
    }

    #[test]
    fn an_empty_file_is_the_builtin_policy_and_allow_all_refuses_nothing() {
        let empty = policy("{}");
        assert!(empty.evaluate("t", ip("127.0.0.1")).is_err());
        assert!(empty.evaluate("t", ip("10.0.0.1")).is_ok());
        assert!(
            UpstreamPolicy::allow_all()
                .evaluate("t", ip("127.0.0.1"))
                .is_ok()
        );
    }

    #[test]
    fn bad_files_name_the_entry() {
        for (json, entry) in [
            (r#"{"deny": ["10.0.0.0/8", "nope"]}"#, "deny[1]"),
            (r#"{"deny": ["10.0.0.0/33"]}"#, "deny[0]"),
            (r#"{"deny": ["10.0.0.1/8"]}"#, "deny[0]"),
            (r#"{"deny_extra": ["x"]}"#, "deny_extra[0]"),
            (
                r#"{"default": {"allow": ["1.2.3.4/x"]}}"#,
                "default.allow[0]",
            ),
            (
                r#"{"tenants": {"acme": {"allow": ["10.0.0.0/8", "::/129"]}}}"#,
                "tenants.acme.allow[1]",
            ),
            (
                r#"{"tenants": {"a": {"allow": []}, "a": {"allow": []}}}"#,
                "file",
            ),
            (r#"{"allow": []}"#, "file"),
            (r#"{"default": {}}"#, "file"),
            (r#"{"default": {"allow": [], "deny": []}}"#, "file"),
            (r#"[]"#, "file"),
            (r#"{"deny": "10.0.0.0/8"}"#, "file"),
            ("", "file"),
        ] {
            let err = UpstreamPolicy::parse(json).expect_err(json);
            assert_eq!(&*err.entry, entry, "{json}: {err}");
        }
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let err = UpstreamPolicy::load(Path::new("/nonexistent/podgate-policy.json"))
            .expect_err("missing");
        assert_eq!(&*err.entry, "/nonexistent/podgate-policy.json");
    }

    #[test]
    fn cidrs_parse_normalize_and_match() {
        let net: Cidr = "10.0.0.0/8".parse().expect("cidr");
        assert!(net.contains(ip("10.255.0.1")) && !net.contains(ip("11.0.0.0")));
        assert!(!net.contains(ip("::1")));
        let host: Cidr = "192.168.1.7".parse().expect("bare address");
        assert_eq!(host.to_string(), "192.168.1.7/32");
        assert!(host.contains(ip("192.168.1.7")) && !host.contains(ip("192.168.1.8")));
        let all: Cidr = "0.0.0.0/0".parse().expect("everything");
        assert!(all.contains(ip("8.8.8.8")));
        let mapped: Cidr = "::ffff:10.0.0.0/104".parse().expect("mapped range");
        assert_eq!(mapped.to_string(), "10.0.0.0/8");
        let six: Cidr = "fe80::/10".parse().expect("v6");
        assert!(six.contains(ip("fe80::1")) && six.contains(ip("febf::1")));
        assert!(!six.contains(ip("fec0::1")));
        assert_eq!(
            "10.0.0.1/8".parse::<Cidr>(),
            Err(CidrError::HostBits("10.0.0.0/8".into()))
        );
    }

    #[test]
    fn refusals_are_counted_per_tenant_only_by_check() {
        let builtin = UpstreamPolicy::builtin();
        assert!(builtin.evaluate("a", ip("127.0.0.1")).is_err());
        assert!(!builtin.render().contains("{tenant="));
        assert!(builtin.check("a", ip("127.0.0.1")).is_err());
        assert!(builtin.check("a", ip("::1")).is_err());
        assert!(builtin.check("b\"x", ip("169.254.169.254")).is_err());
        assert!(builtin.check("a", ip("10.0.0.1")).is_ok());
        let shared = builtin.clone();
        let text = shared.render();
        assert!(text.contains("# TYPE podgate_upstream_refused_total counter\n"));
        assert!(text.contains("podgate_upstream_refused_total{tenant=\"a\"} 2\n"));
        assert!(text.contains("podgate_upstream_refused_total{tenant=\"b\\\"x\"} 1\n"));
    }

    #[test]
    fn srv_ports_denied_by_default_and_the_list_replaces_it() {
        let builtin = UpstreamPolicy::builtin();
        for port in DEFAULT_SRV_DENY_PORTS {
            assert!(
                matches!(
                    builtin.evaluate_port("t", port),
                    Err(PortRefused::Denied { port: denied, .. }) if denied == port
                ),
                "{port}"
            );
        }
        for port in [80, 443, 8080, 3000, 8500, 32768, 65535] {
            assert_eq!(builtin.evaluate_port("t", port), Ok(()), "{port}");
        }
        let file = policy(r#"{"srv_deny_ports": [8080]}"#);
        assert!(file.evaluate_port("t", 8080).is_err());
        assert!(
            file.evaluate_port("t", 5432).is_ok(),
            "srv_deny_ports replaces the default list"
        );
        assert!(
            policy(r#"{"srv_deny_ports": []}"#)
                .evaluate_port("t", 22)
                .is_ok()
        );
        assert!(policy("{}").evaluate_port("t", 22).is_err());
        assert!(UpstreamPolicy::allow_all().evaluate_port("t", 22).is_ok());
    }

    #[test]
    fn srv_allow_ports_narrow_a_tenant_and_deny_beats_them() {
        let file = policy(
            r#"{"srv_deny_ports": [22],
                "default": {"allow": ["10.0.0.0/8"], "srv_allow_ports": [8000, 22]},
                "tenants": {"acme": {"allow": ["10.0.0.0/8"], "srv_allow_ports": [9000]},
                            "plain": {"allow": ["10.0.0.0/8"]}}}"#,
        );
        assert!(file.evaluate_port("acme", 9000).is_ok());
        assert_eq!(
            file.evaluate_port("acme", 8000),
            Err(PortRefused::NotAllowed {
                port: 8000,
                scope: "tenant acme".into()
            })
        );
        assert!(file.evaluate_port("other", 8000).is_ok());
        assert_eq!(
            file.evaluate_port("other", 9000),
            Err(PortRefused::NotAllowed {
                port: 9000,
                scope: "the default entry".into()
            })
        );
        assert!(
            matches!(
                file.evaluate_port("other", 22),
                Err(PortRefused::Denied { port: 22, .. })
            ),
            "a deny entry beats an allow entry"
        );
        assert!(
            file.evaluate_port("plain", 8000).is_ok(),
            "an entry without srv_allow_ports uses the default's"
        );
    }

    #[test]
    fn bad_srv_port_entries_name_the_entry() {
        for (json, entry) in [
            (r#"{"srv_deny_ports": [22, 0]}"#, "srv_deny_ports[1]"),
            (
                r#"{"tenants": {"a": {"allow": [], "srv_allow_ports": [0]}}}"#,
                "tenants.a.srv_allow_ports[0]",
            ),
            (
                r#"{"default": {"allow": [], "srv_allow_ports": [1, 2, 0]}}"#,
                "default.srv_allow_ports[2]",
            ),
            (r#"{"srv_deny_ports": [70000]}"#, "file"),
            (r#"{"srv_deny_ports": "22"}"#, "file"),
            (r#"{"srv_allow_ports": [1]}"#, "file"),
        ] {
            let err = UpstreamPolicy::parse(json).expect_err(json);
            assert_eq!(&*err.entry, entry, "{json}: {err}");
        }
    }

    #[test]
    fn port_refusals_are_counted_with_a_reason_only_by_check_port() {
        let builtin = UpstreamPolicy::builtin();
        assert!(builtin.evaluate_port("a", 22).is_err());
        assert!(!builtin.render().contains("reason="));
        assert!(builtin.check_port("a", 22).is_err());
        assert!(builtin.check_port("a", 5432).is_err());
        assert!(builtin.check_port("a", 8080).is_ok());
        let text = builtin.render();
        assert!(text.contains("podgate_upstream_refused_total{tenant=\"a\",reason=\"port\"} 2\n"));
        assert!(
            !text.contains("podgate_upstream_refused_total{tenant=\"a\"}"),
            "a port refusal is not an address refusal"
        );
    }
}
