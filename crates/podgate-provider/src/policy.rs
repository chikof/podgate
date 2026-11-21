//! The upstream address policy, checked before a push.
//!
//! The daemon refuses a snapshot whose literal server addresses a tenant may not use (`422`,
//! `upstream_forbidden`) and checks every address again at connect time. The provider
//! reads the same operator file and applies the same rule to the apps it is about to push, so the
//! mistake shows up in the provider's report first, next to the object that caused it, instead of
//! as an unattributed rejection. This is a copy of the rule, not a second authority: the daemon
//! decides, and `tests/fixtures/upstream_policy_cases.json` holds the vectors both sides must
//! agree on.
//!
//! The file is JSON, read once:
//!
//! ```json
//! { "deny": ["10.9.0.0/16"],
//!   "default": { "allow": ["10.0.0.0/8"] },
//!   "tenants": { "acme": { "allow": ["10.4.0.0/16"] } } }
//! ```
//!
//! An address is permitted when it is in no `deny` range and, when the tenant's entry (else
//! `default`) has an `allow` list, inside it. Without `deny` the built-in list applies
//! (loopback, unspecified, link-local, multicast and the well-known metadata addresses);
//! `deny_extra` adds to it. IPv4-mapped and IPv4-compatible IPv6 addresses are checked as the
//! IPv4 address they carry. Only literal addresses can be checked here: a server named by a DNS
//! name is checked by the daemon on every answer it resolves.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;

use podgate_model::{App, Declared};
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::{Map, Value};
use thiserror::Error;

/// A CIDR range, such as `10.0.0.0/8`. A bare address is a single host.
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
                Some(mapped) if prefix >= 96 => Self {
                    network: IpAddr::V4(mapped),
                    prefix: prefix - 96,
                },
                _ => Self {
                    network: ip,
                    prefix,
                },
            },
            IpAddr::V4(_) => Self {
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

/// What is denied when the file has no `deny` list.
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
        /// The address that was checked.
        ip: IpAddr,
        /// The `deny` entry that matched.
        range: Cidr,
    },
    /// The tenant (or the default) has an allow list and the address is not in it.
    #[error("{ip} is outside the allowed ranges of {scope}")]
    NotAllowed {
        /// The address that was checked.
        ip: IpAddr,
        /// `tenant <id>` or `the default entry`.
        scope: Box<str>,
    },
}

impl Refused {
    /// The rule that refused: the denied range, or `not in the allow list of ...`.
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
    /// file that cannot be read; `file` for a syntax or structure error.
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    allow: Vec<String>,
}

/// A JSON object read as a list of pairs, so a repeated key is an error instead of the last
/// one winning.
struct Pairs<T>(Vec<(String, T)>);

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
                        return Err(serde::de::Error::custom(format!(
                            "tenant {key:?} appears twice"
                        )));
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
    default: Option<EntryFile>,
    #[serde(default)]
    tenants: Option<Pairs<EntryFile>>,
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

/// The operator's rule for which addresses podgate may connect to, per tenant.
///
/// ```
/// use podgate_provider::policy::UpstreamPolicy;
///
/// let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)?;
/// assert!(policy.evaluate("acme", "10.4.1.2".parse()?).is_ok());
/// assert!(policy.evaluate("acme", "10.5.1.2".parse()?).is_err());
/// assert!(policy.evaluate("other", "169.254.169.254".parse()?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct UpstreamPolicy {
    deny: Box<[Cidr]>,
    default_allow: Option<Box<[Cidr]>>,
    tenants: BTreeMap<Box<str>, Box<[Cidr]>>,
}

/// One server a tenant may not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forbidden {
    /// The service that lists it.
    pub service: Box<str>,
    /// The server's URL as declared.
    pub server: Box<str>,
    /// The rule that refused it.
    pub rule: String,
    /// The reason in words.
    pub message: String,
}

impl UpstreamPolicy {
    /// The policy with no file: the built-in deny list and no allow lists.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            deny: BUILTIN_DENY.to_vec().into(),
            default_allow: None,
            tenants: BTreeMap::new(),
        }
    }

    /// Parses the JSON of a policy file.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] naming the entry that is wrong: a CIDR that does not parse (`deny[1]`),
    /// an unknown field, a tenant that appears twice, or both `deny` and `deny_extra`.
    pub fn parse(json: &str) -> Result<Self, PolicyError> {
        // A JSON array would otherwise be read positionally as the struct's fields.
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
        let default_allow = file
            .default
            .map(|entry| ranges("default.allow", &entry.allow))
            .transpose()?;
        let mut tenants = BTreeMap::new();
        for (id, entry) in file.tenants.map_or_else(Vec::new, |pairs| pairs.0) {
            let allow = ranges(&format!("tenants.{id}.allow"), &entry.allow)?;
            tenants.insert(Box::from(id), allow.into());
        }
        Ok(Self {
            deny: deny.into(),
            default_allow: default_allow.map(Vec::into),
            tenants,
        })
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

    /// Whether the file gives `tenant` an `allow` list of its own. The `default` entry does not
    /// count: every tenant without an entry of its own shares it.
    #[must_use]
    pub fn has_tenant_allow_list(&self, tenant: &str) -> bool {
        self.tenants.contains_key(tenant)
    }

    /// The verdict for `tenant` dialling `ip`.
    ///
    /// # Errors
    ///
    /// [`Refused`] naming the deny range that matched, or the allow list `ip` is outside of.
    pub fn evaluate(&self, tenant: &str, ip: IpAddr) -> Result<(), Refused> {
        let seen = canonical(ip);
        let compat = compat_v4(ip);
        let hit = self.deny.iter().find(|range| {
            range.contains(seen)
                || (seen != ip && range.contains(ip))
                || compat.is_some_and(|v4| range.contains(v4))
        });
        if let Some(range) = hit {
            return Err(Refused::Denied { ip, range: *range });
        }
        let allow = match self.tenants.get(tenant) {
            Some(list) => Some((list, format!("tenant {tenant}"))),
            None => self
                .default_allow
                .as_ref()
                .map(|list| (list, "the default entry".to_owned())),
        };
        match allow {
            Some((allow, scope)) if !allow.iter().any(|range| range.contains(seen)) => {
                Err(Refused::NotAllowed {
                    ip,
                    scope: scope.into(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Every server of `app`'s services, in the app's and in each revision's, whose literal
    /// address `tenant` may not use.
    #[must_use]
    pub fn forbidden_servers(&self, tenant: &str, app: &App) -> Vec<Forbidden> {
        let mut found = Vec::new();
        let revisions = app.revisions.iter().flat_map(|revision| &revision.services);
        for service in app.services.iter().chain(revisions) {
            self.visit(tenant, service, &mut found);
        }
        found
    }

    fn visit(&self, tenant: &str, service: &Declared, found: &mut Vec<Forbidden>) {
        let mut urls = Vec::new();
        collect_in_map(&service.config, &mut urls);
        for url in urls {
            let Some(addr) = literal_address(url) else {
                continue;
            };
            if let Err(refused) = self.evaluate(tenant, addr.ip()) {
                found.push(Forbidden {
                    service: service.name.clone(),
                    server: url.into(),
                    rule: refused.rule(),
                    message: format!(
                        "service {} server {url}: {refused} (rule: {})",
                        service.name,
                        refused.rule()
                    ),
                });
            }
        }
    }
}

/// The `url` of every element of every `servers` list at any depth, so a kind that nests its
/// servers (a failover pool, say) is covered too.
fn collect_in_map<'a>(map: &'a Map<String, Value>, urls: &mut Vec<&'a str>) {
    if let Some(Value::Array(servers)) = map.get("servers") {
        urls.extend(
            servers
                .iter()
                .filter_map(|server| server.get("url").and_then(Value::as_str)),
        );
    }
    for (key, inner) in map {
        if key != "servers" {
            collect_in_value(inner, urls);
        }
    }
}

fn collect_in_value<'a>(value: &'a Value, urls: &mut Vec<&'a str>) {
    match value {
        Value::Object(map) => collect_in_map(map, urls),
        Value::Array(items) => {
            for item in items {
                collect_in_value(item, urls);
            }
        }
        _ => {}
    }
}

/// The socket address of `http://ip:port`, `https://` or `h2c://`; `None` for a DNS name or
/// anything else, which the daemon judges.
fn literal_address(url: &str) -> Option<SocketAddr> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme, "http" | "https" | "h2c") {
        return None;
    }
    rest.strip_suffix('/').unwrap_or(rest).parse().ok()
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
