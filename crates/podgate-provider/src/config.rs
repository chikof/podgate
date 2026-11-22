//! The provider's configuration file (TOML).
//!
//! ```toml
//! admin_socket = "/run/podgate/admin.sock"
//! upstream_policy_file = "/etc/podgate/upstream-policy.json"
//! debounce_ms = 500
//! max_delay_ms = 5000
//! resync_secs = 30
//!
//! [default_tenant]
//! weight = 1
//! budget = { max_inflight = 256, max_buffer_bytes = 67108864 }
//!
//! [[tenant]]
//! id = "acme"
//! hosts = ["acme.example", "*.acme.example"]
//! label_sources = ["docker-prod"]
//!
//! [[source]]
//! kind = "docker"
//! name = "docker-prod"
//! ```
//!
//! Every error names the field it is about. Unknown keys are errors: a misspelt option must not
//! turn a rule off. `[[source]]` entries keep their own keys for the source's module to read.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use podgate_model::{Budget, Observability, SkewSecret};
use serde::Deserialize;
use thiserror::Error;

use crate::acme::settings::{AcmeSettings, RawAcme};
use crate::trust::HostPattern;

/// The id of the default tenant.
pub const DEFAULT_TENANT: &str = "default";

const DEFAULT_WEIGHT: u32 = 1;
const DEFAULT_MAX_INFLIGHT: u32 = 256;
const DEFAULT_MAX_BUFFER_BYTES: u64 = 64 * 1024 * 1024;

/// A configuration that cannot be used.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file cannot be read.
    #[error("cannot read {path}")]
    Read {
        /// The path.
        path: Box<str>,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
    /// The text is not valid TOML, or a key has the wrong type or is unknown. The message holds
    /// the line and column.
    #[error("{0}")]
    Syntax(#[from] toml::de::Error),
    /// A value is not acceptable.
    #[error("{field}: {reason}")]
    Invalid {
        /// The field, like `tenant[1].hosts[0]` or `max_delay_ms`.
        field: Box<str>,
        /// What is wrong with it.
        reason: Box<str>,
    },
}

impl ConfigError {
    pub(crate) fn invalid(field: impl Into<Box<str>>, reason: impl std::fmt::Display) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.to_string().into(),
        }
    }
}

/// One tenant: who owns which hosts, and what it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantConfig {
    /// The id; `default` for the default tenant.
    pub id: Box<str>,
    /// Fair-share weight against other tenants.
    pub weight: u32,
    /// Resource limits.
    pub budget: Budget,
    /// The hosts the tenant may claim. Empty for the default tenant, which may claim every host
    /// no other tenant's patterns reach.
    pub hosts: Vec<HostPattern>,
    /// The sources whose objects may name this tenant in a label or annotation.
    pub label_sources: Vec<Box<str>>,
    /// The operator's decision to let the tenant have routers that match hosts nobody claims
    /// (the same as listing it in the daemon's `CATCH_ALL_TENANTS`).
    pub catch_all: bool,
    /// Entry points only this tenant may attach routers to; the snapshot says so to the daemon.
    pub exclusive_entry_points: Vec<Box<str>>,
}

/// One `[[source]]` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceConfig {
    /// What kind of backend: `consul`, `docker`, `ecs`, `etcd`, `file`, `http`, `kubernetes`,
    /// `nomad`, `redis` or `swarm`.
    pub kind: Box<str>,
    /// The unique name; the one in `declared_by`, app ids and `label_sources`.
    pub name: Box<str>,
    /// The other keys of the entry, for the source's module.
    pub settings: toml::Table,
}

/// The validated configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// The admin socket of the node's podgate.
    pub admin_socket: PathBuf,
    /// The operator's upstream address policy, the file the daemon reads. Absent: the built-in
    /// deny list.
    pub upstream_policy_file: Option<PathBuf>,
    /// How long updates are coalesced before a push.
    pub debounce: Duration,
    /// The longest a pending push waits under a steady stream of updates.
    pub max_delay: Duration,
    /// How often the live version is checked, and how long a quarantined object waits for a new
    /// try.
    pub resync: Duration,
    /// The tenant of every object that names none.
    pub default_tenant: TenantConfig,
    /// The configured tenants.
    pub tenants: Vec<TenantConfig>,
    /// The sources.
    pub sources: Vec<SourceConfig>,
    /// The parts of the snapshot the operator owns, copied into every snapshot.
    pub operator: Operator,
    /// The ACME broker or follower, when `[acme]` is enabled.
    pub acme: Option<AcmeSettings>,
    /// The internal CA, when `[ca]` is enabled.
    pub ca: Option<crate::ca::settings::CaSettings>,
}
/// The snapshot fields no source declares: the operator's `[snapshot]` section. A provider-only
/// node has no other writer for them, so the provider copies them into every snapshot verbatim.
/// Unset means the field is absent from the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Operator {
    /// Seconds an auto-revert watches a new snapshot.
    pub revert_window_secs: Option<u64>,
    /// Access log, metrics and tracing settings.
    pub observability: Option<Observability>,
    /// The key of the session cookie that pins a browser to a revision, read from
    /// `skew_secret_file`. Never in the TOML, never printed.
    pub skew_secret: Option<SkewSecret>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    max_inflight: Option<u32>,
    max_buffer_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaultTenant {
    weight: Option<u32>,
    budget: Option<RawBudget>,
    #[serde(default)]
    catch_all: bool,
    #[serde(default)]
    exclusive_entry_points: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTenant {
    id: String,
    weight: Option<u32>,
    budget: Option<RawBudget>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    label_sources: Vec<String>,
    #[serde(default)]
    catch_all: bool,
    #[serde(default)]
    exclusive_entry_points: Vec<String>,
}

#[derive(Deserialize)]
struct RawSource {
    kind: String,
    name: String,
    #[serde(flatten)]
    settings: toml::Table,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSnapshot {
    revert_window_secs: Option<u64>,
    observability: Option<Observability>,
    skew_secret_file: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    admin_socket: PathBuf,
    upstream_policy_file: Option<PathBuf>,
    debounce_ms: Option<u64>,
    max_delay_ms: Option<u64>,
    resync_secs: Option<u64>,
    default_tenant: Option<RawDefaultTenant>,
    #[serde(default)]
    tenant: Vec<RawTenant>,
    #[serde(default)]
    source: Vec<RawSource>,
    snapshot: Option<RawSnapshot>,
    acme: Option<RawAcme>,
    ca: Option<crate::ca::settings::RawCa>,
}

/// A tenant or source name: lowercase letters, digits, `.`, `_` and `-`, starting with a letter
/// or digit, at most 64 characters. App ids are built from source names, so the alphabet is the
/// one an id may safely hold.
fn is_slug(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn budget(field: &str, raw: Option<RawBudget>) -> Result<Budget, ConfigError> {
    let (inflight, buffer) = raw.map_or((None, None), |b| (b.max_inflight, b.max_buffer_bytes));
    let max_inflight = inflight.unwrap_or(DEFAULT_MAX_INFLIGHT);
    let max_buffer_bytes = buffer.unwrap_or(DEFAULT_MAX_BUFFER_BYTES);
    if max_inflight == 0 {
        return Err(ConfigError::invalid(
            format!("{field}.budget.max_inflight"),
            "must be at least 1: 0 would refuse every request",
        ));
    }
    if max_buffer_bytes == 0 {
        return Err(ConfigError::invalid(
            format!("{field}.budget.max_buffer_bytes"),
            "must be at least 1",
        ));
    }
    Ok(Budget {
        max_inflight,
        max_buffer_bytes,
    })
}

fn weight(field: &str, raw: Option<u32>) -> Result<u32, ConfigError> {
    match raw.unwrap_or(DEFAULT_WEIGHT) {
        0 => Err(ConfigError::invalid(
            format!("{field}.weight"),
            "must be at least 1",
        )),
        weight => Ok(weight),
    }
}

fn entry_points(field: &str, raw: Vec<String>) -> Result<Vec<Box<str>>, ConfigError> {
    raw.into_iter()
        .enumerate()
        .map(|(at, name)| {
            if name.is_empty() {
                Err(ConfigError::invalid(
                    format!("{field}.exclusive_entry_points[{at}]"),
                    "is empty",
                ))
            } else {
                Ok(name.into())
            }
        })
        .collect()
}

impl Config {
    /// Reads and validates the file at `path`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the file cannot be read or [`Self::parse`] refuses it.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string().into(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parses and validates configuration text.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the field: a syntax error with its line, an unknown key, a name
    /// that is not a slug, a duplicate tenant or source, a host pattern that does not parse or
    /// that two tenants both reach, a `label_sources` entry that names no source, an
    /// entry point two tenants both claim, a `max_delay_ms` below `debounce_ms`, or a zero
    /// weight, budget or interval.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text)?;
        if raw.admin_socket.as_os_str().is_empty() {
            return Err(ConfigError::invalid("admin_socket", "is empty"));
        }
        let debounce_ms = raw.debounce_ms.unwrap_or(500);
        let max_delay_ms = raw.max_delay_ms.unwrap_or(5000);
        let resync_secs = raw.resync_secs.unwrap_or(30);
        if max_delay_ms < debounce_ms {
            return Err(ConfigError::invalid(
                "max_delay_ms",
                format!("must not be below debounce_ms ({debounce_ms})"),
            ));
        }
        if resync_secs == 0 {
            return Err(ConfigError::invalid("resync_secs", "must be at least 1"));
        }

        let sources = sources(raw.source)?;
        let default_tenant = default_tenant(raw.default_tenant)?;
        let tenants = tenants(raw.tenant, &sources, &default_tenant)?;
        let operator = operator(raw.snapshot)?;
        let acme = crate::acme::settings::parse(raw.acme)?;
        let ca = crate::ca::settings::parse(raw.ca)?;
        Ok(Self {
            admin_socket: raw.admin_socket,
            upstream_policy_file: raw.upstream_policy_file,
            debounce: Duration::from_millis(debounce_ms),
            max_delay: Duration::from_millis(max_delay_ms),
            resync: Duration::from_secs(resync_secs),
            default_tenant,
            tenants,
            sources,
            operator,
            acme,
            ca,
        })
    }

    /// The names of the configured sources.
    pub fn source_names(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(|source| &*source.name)
    }
}

fn operator(raw: Option<RawSnapshot>) -> Result<Operator, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Operator::default());
    };
    let skew_secret = match raw.skew_secret_file {
        None => None,
        Some(path) => {
            let field = "snapshot.skew_secret_file";
            let text = std::fs::read_to_string(&path).map_err(|err| {
                ConfigError::invalid(field, format!("cannot read {}: {err}", path.display()))
            })?;
            // A trailing newline is how files end, not part of the key.
            let secret = text.strip_suffix('\n').unwrap_or(&text);
            let secret = secret.strip_suffix('\r').unwrap_or(secret);
            let secret = SkewSecret::new(secret);
            if !secret.is_long_enough() {
                return Err(ConfigError::invalid(
                    field,
                    format!(
                        "{} holds a key shorter than {} bytes",
                        path.display(),
                        SkewSecret::MIN_LEN
                    ),
                ));
            }
            Some(secret)
        }
    };
    Ok(Operator {
        revert_window_secs: raw.revert_window_secs,
        observability: raw.observability,
        skew_secret,
    })
}

fn sources(raw: Vec<RawSource>) -> Result<Vec<SourceConfig>, ConfigError> {
    let mut seen = BTreeSet::new();
    raw.into_iter()
        .enumerate()
        .map(|(at, source)| {
            let field = format!("source[{at}]");
            if source.kind.is_empty() {
                return Err(ConfigError::invalid(format!("{field}.kind"), "is empty"));
            }
            if !is_slug(&source.name) {
                return Err(ConfigError::invalid(
                    format!("{field}.name"),
                    format!(
                        "{:?} must be lowercase letters, digits, `.`, `_` or `-`, at most 64",
                        source.name
                    ),
                ));
            }
            if !seen.insert(source.name.clone()) {
                return Err(ConfigError::invalid(
                    format!("{field}.name"),
                    format!("source {:?} appears twice", source.name),
                ));
            }
            Ok(SourceConfig {
                kind: source.kind.into(),
                name: source.name.into(),
                settings: source.settings,
            })
        })
        .collect()
}

fn default_tenant(raw: Option<RawDefaultTenant>) -> Result<TenantConfig, ConfigError> {
    let field = "default_tenant";
    let (raw_weight, raw_budget, catch_all, entries) = match raw {
        Some(raw) => (
            raw.weight,
            raw.budget,
            raw.catch_all,
            raw.exclusive_entry_points,
        ),
        None => (None, None, false, Vec::new()),
    };
    Ok(TenantConfig {
        id: DEFAULT_TENANT.into(),
        weight: weight(field, raw_weight)?,
        budget: budget(field, raw_budget)?,
        hosts: Vec::new(),
        label_sources: Vec::new(),
        catch_all,
        exclusive_entry_points: entry_points(field, entries)?,
    })
}

fn tenants(
    raw: Vec<RawTenant>,
    sources: &[SourceConfig],
    default: &TenantConfig,
) -> Result<Vec<TenantConfig>, ConfigError> {
    let mut out: Vec<TenantConfig> = Vec::new();
    for (at, tenant) in raw.into_iter().enumerate() {
        let field = format!("tenant[{at}]");
        if !is_slug(&tenant.id) {
            return Err(ConfigError::invalid(
                format!("{field}.id"),
                format!(
                    "{:?} must be lowercase letters, digits, `.`, `_` or `-`, at most 64",
                    tenant.id
                ),
            ));
        }
        if tenant.id == DEFAULT_TENANT {
            return Err(ConfigError::invalid(
                format!("{field}.id"),
                "`default` is the default tenant; configure it under [default_tenant]",
            ));
        }
        if out.iter().any(|other| *other.id == *tenant.id) {
            return Err(ConfigError::invalid(
                format!("{field}.id"),
                format!("tenant {:?} appears twice", tenant.id),
            ));
        }
        if tenant.hosts.is_empty() {
            return Err(ConfigError::invalid(
                format!("{field}.hosts"),
                "a tenant with no hosts could claim nothing",
            ));
        }
        let mut hosts = Vec::with_capacity(tenant.hosts.len());
        for (host_at, text) in tenant.hosts.iter().enumerate() {
            let pattern = HostPattern::parse(text)
                .map_err(|err| ConfigError::invalid(format!("{field}.hosts[{host_at}]"), err))?;
            if let Some(owner) = out
                .iter()
                .find(|other| other.hosts.iter().any(|own| own.overlaps(&pattern)))
            {
                return Err(ConfigError::invalid(
                    format!("{field}.hosts[{host_at}]"),
                    format!("{pattern} overlaps hosts of tenant {}", owner.id),
                ));
            }
            hosts.push(pattern);
        }
        let mut label_sources = Vec::with_capacity(tenant.label_sources.len());
        for (source_at, name) in tenant.label_sources.iter().enumerate() {
            if !sources.iter().any(|source| *source.name == **name) {
                return Err(ConfigError::invalid(
                    format!("{field}.label_sources[{source_at}]"),
                    format!("there is no source named {name:?}"),
                ));
            }
            label_sources.push(name.as_str().into());
        }
        let exclusive = entry_points(&field, tenant.exclusive_entry_points)?;
        for entry in &exclusive {
            let taken = out
                .iter()
                .chain(std::iter::once(default))
                .find(|other| other.exclusive_entry_points.contains(entry));
            if let Some(other) = taken {
                return Err(ConfigError::invalid(
                    format!("{field}.exclusive_entry_points"),
                    format!(
                        "entry point {entry:?} is already exclusive to tenant {}",
                        other.id
                    ),
                ));
            }
        }
        out.push(TenantConfig {
            weight: weight(&field, tenant.weight)?,
            budget: budget(&field, tenant.budget)?,
            id: tenant.id.into(),
            hosts,
            label_sources,
            catch_all: tenant.catch_all,
            exclusive_entry_points: exclusive,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;

    const MINIMAL: &str = "admin_socket = \"/run/podgate/admin.sock\"\n";

    fn invalid(text: &str) -> (String, String) {
        match Config::parse(text) {
            Err(ConfigError::Invalid { field, reason }) => (field.into(), reason.into()),
            other => panic!("expected an invalid field, got {other:?}"),
        }
    }

    #[test]
    fn config_defaults() {
        let config = Config::parse(MINIMAL).expect("minimal config");
        assert_eq!(config.debounce, Duration::from_millis(500));
        assert_eq!(config.max_delay, Duration::from_millis(5000));
        assert_eq!(config.resync, Duration::from_secs(30));
        assert_eq!(&*config.default_tenant.id, "default");
        assert_eq!(config.default_tenant.weight, 1);
        assert!(config.tenants.is_empty() && config.sources.is_empty());
    }

    #[test]
    fn config_names_the_bad_field() {
        let tenant =
            |extra: &str| format!("{MINIMAL}[[tenant]]\nid = \"a\"\nhosts = [\"a.test\"]\n{extra}");
        assert_eq!(
            invalid(&format!(
                "{MINIMAL}[[tenant]]\nid = \"a\"\nhosts = [\"A b\"]\n"
            ))
            .0,
            "tenant[0].hosts[0]"
        );
        assert_eq!(
            invalid(&tenant("label_sources = [\"x\"]\n")).0,
            "tenant[0].label_sources[0]"
        );
        assert_eq!(invalid(&tenant("weight = 0\n")).0, "tenant[0].weight");
        assert_eq!(
            invalid(&tenant("budget = { max_inflight = 0 }\n")).0,
            "tenant[0].budget.max_inflight"
        );
        assert_eq!(
            invalid(&format!(
                "{MINIMAL}[[tenant]]\nid = \"default\"\nhosts = [\"a.test\"]\n"
            ))
            .0,
            "tenant[0].id"
        );
        assert_eq!(
            invalid(&format!("{MINIMAL}debounce_ms = 10\nmax_delay_ms = 5\n")).0,
            "max_delay_ms"
        );
        assert_eq!(
            invalid(&format!("{MINIMAL}resync_secs = 0\n")).0,
            "resync_secs"
        );
    }

    #[test]
    fn config_rejects_overlapping_tenants_and_duplicates() {
        let text = format!(
            "{MINIMAL}[[tenant]]\nid = \"a\"\nhosts = [\"*.x.test\"]\n[[tenant]]\nid = \"b\"\nhosts = [\"y.x.test\"]\n"
        );
        let (field, reason) = invalid(&text);
        assert_eq!(field, "tenant[1].hosts[0]");
        assert!(reason.contains("overlaps hosts of tenant a"), "{reason}");
        let twice = format!(
            "{MINIMAL}[[source]]\nkind = \"file\"\nname = \"f\"\n[[source]]\nkind = \"file\"\nname = \"f\"\n"
        );
        assert_eq!(invalid(&twice).0, "source[1].name");
    }

    #[test]
    fn config_syntax_and_unknown_keys_are_errors() {
        assert!(matches!(
            Config::parse("admin_socket = "),
            Err(ConfigError::Syntax(_))
        ));
        let text = format!("{MINIMAL}debounce = 5\n");
        let err = Config::parse(&text).expect_err("unknown key");
        assert!(err.to_string().contains("debounce"), "{err}");
    }

    #[test]
    fn config_keeps_source_settings() {
        let text = format!(
            "{MINIMAL}[[source]]\nkind = \"docker\"\nname = \"local\"\nsocket = \"/var/run/docker.sock\"\n"
        );
        let config = Config::parse(&text).expect("config");
        assert_eq!(&*config.sources[0].kind, "docker");
        assert_eq!(
            config.sources[0]
                .settings
                .get("socket")
                .and_then(toml::Value::as_str),
            Some("/var/run/docker.sock")
        );
    }
}
