//! The `[acme]` section of the provider's configuration.
//!
//! ```toml
//! [acme]
//! enabled = true
//! mode = "broker"                     # or "follower"
//! state_dir = "/var/lib/podgate-provider/acme"
//! directory_url = "https://acme-v02.api.letsencrypt.org/directory"
//! contact = ["mailto:ops@example.com"]
//! issuer_node = "node-1"
//! # account_key_file = "/etc/podgate/acme-account.pem"
//! # challenge_lead_ms = 0
//!
//! [acme.on_demand]
//! max_per_tenant_per_hour = 10
//! max_pending = 100
//! ```
//!
//! Secrets (`account_key_file`, the EAB HMAC key) are paths, never values: an inline key is an
//! unknown key.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::config::ConfigError;

/// What this provider does for ACME.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Reads its own podgate's event feed, keeps the state directory and answers the feed.
    Broker,
    /// Reads the directory a broker keeps, and pushes the same certificates and challenges.
    Follower,
}

/// Limits of on-demand approvals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnDemandLimits {
    /// Most approvals one tenant gets in any hour.
    pub max_per_tenant_per_hour: u32,
    /// Most approved hosts that wait for their certificate at once, over all tenants.
    pub max_pending: u32,
}

impl Default for OnDemandLimits {
    fn default() -> Self {
        Self {
            max_per_tenant_per_hour: 10,
            max_pending: 100,
        }
    }
}

/// External account binding: the CA's key id, and the file that holds its base64url HMAC key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EabSettings {
    /// The key identifier.
    pub key_id: Box<str>,
    /// The file with the HMAC key, base64url, one trailing newline allowed.
    pub hmac_key_file: PathBuf,
}

/// The validated `[acme]` section. Present only when `enabled = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeSettings {
    /// Broker or follower.
    pub mode: Mode,
    /// Where the broker keeps its state (mode `0700`), and where a follower reads it.
    pub state_dir: PathBuf,
    /// The ACME directory, `https://...`.
    pub directory_url: Box<str>,
    /// Contact URIs of the account.
    pub contact: Vec<String>,
    /// `NODE_NAME` of the one podgate that orders.
    pub issuer_node: Box<str>,
    /// External account binding. Excludes an account key.
    pub eab: Option<EabSettings>,
    /// A PKCS#8 PEM account key kept by the operator. Absent (and no `eab`): the broker makes
    /// one and keeps it in the state directory.
    pub account_key_file: Option<PathBuf>,
    /// On-demand approval limits.
    pub on_demand: OnDemandLimits,
    /// How long a new HTTP-01 or TLS-ALPN-01 answer stays in the shared directory before the
    /// broker pushes it to its own podgate, so that followers hold it first (the issuer last).
    pub challenge_lead: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEab {
    key_id: String,
    hmac_key_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawOnDemand {
    max_per_tenant_per_hour: Option<u32>,
    max_pending: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAcme {
    #[serde(default)]
    enabled: bool,
    mode: Option<Mode>,
    state_dir: Option<PathBuf>,
    directory_url: Option<String>,
    #[serde(default)]
    contact: Vec<String>,
    issuer_node: Option<String>,
    eab: Option<RawEab>,
    account_key_file: Option<PathBuf>,
    on_demand: Option<RawOnDemand>,
    challenge_lead_ms: Option<u64>,
}

fn required<T>(field: &str, value: Option<T>) -> Result<T, ConfigError> {
    value.ok_or_else(|| ConfigError::invalid(format!("acme.{field}"), "is required"))
}

/// Validates the section. `Ok(None)` when it is absent or `enabled = false`.
pub(crate) fn parse(raw: Option<RawAcme>) -> Result<Option<AcmeSettings>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !raw.enabled {
        return Ok(None);
    }
    let mode = raw.mode.unwrap_or(Mode::Broker);
    let state_dir = required("state_dir", raw.state_dir)?;
    if state_dir.as_os_str().is_empty() {
        return Err(ConfigError::invalid("acme.state_dir", "is empty"));
    }
    let directory_url = required("directory_url", raw.directory_url)?;
    if !directory_url.starts_with("https://") {
        return Err(ConfigError::invalid(
            "acme.directory_url",
            "must start with https://",
        ));
    }
    let issuer_node = required("issuer_node", raw.issuer_node)?;
    if issuer_node.trim().is_empty() {
        return Err(ConfigError::invalid("acme.issuer_node", "is empty"));
    }
    if raw.eab.is_some() && raw.account_key_file.is_some() {
        return Err(ConfigError::invalid(
            "acme.eab",
            "cannot be combined with account_key_file: a CA binds an external account only when it creates the account",
        ));
    }
    let eab = match raw.eab {
        None => None,
        Some(eab) if eab.key_id.is_empty() => {
            return Err(ConfigError::invalid("acme.eab.key_id", "is empty"));
        }
        Some(eab) => Some(EabSettings {
            key_id: eab.key_id.into(),
            hmac_key_file: eab.hmac_key_file,
        }),
    };
    let defaults = OnDemandLimits::default();
    let on_demand = raw.on_demand.map_or(defaults, |limits| OnDemandLimits {
        max_per_tenant_per_hour: limits
            .max_per_tenant_per_hour
            .unwrap_or(defaults.max_per_tenant_per_hour),
        max_pending: limits.max_pending.unwrap_or(defaults.max_pending),
    });
    if on_demand.max_per_tenant_per_hour == 0 {
        return Err(ConfigError::invalid(
            "acme.on_demand.max_per_tenant_per_hour",
            "must be at least 1",
        ));
    }
    if on_demand.max_pending == 0 {
        return Err(ConfigError::invalid(
            "acme.on_demand.max_pending",
            "must be at least 1",
        ));
    }
    Ok(Some(AcmeSettings {
        mode,
        state_dir,
        directory_url: directory_url.into(),
        contact: raw.contact,
        issuer_node: issuer_node.into(),
        eab,
        account_key_file: raw.account_key_file,
        on_demand,
        challenge_lead: Duration::from_millis(raw.challenge_lead_ms.unwrap_or(0)),
    }))
}
