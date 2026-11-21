//! The `[ca]` section of the provider's configuration.
//!
//! ```toml
//! [ca]
//! enabled = true
//! dir = "/var/lib/podgate-provider/ca"
//! allowed_suffixes = ["internal", "svc.cluster.local"]
//! # leaf_days = 14
//! # allow_wildcards = false
//! ```

use std::path::PathBuf;

use serde::Deserialize;

use super::names::{Policy, Suffix, parse_suffixes};
use crate::config::ConfigError;

/// The leaf lifetime when `leaf_days` is not set.
pub const DEFAULT_LEAF_DAYS: u32 = 14;
/// The longest leaf lifetime: short-lived leaves are the revocation story.
pub const MAX_LEAF_DAYS: u32 = 90;

/// The validated `[ca]` section. Present only when `enabled = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaSettings {
    /// The CA directory, made by `ca init` (mode `0700`): the intermediate, the root certificate
    /// and the leaves. Never the root key.
    pub dir: PathBuf,
    /// The suffixes the CA certifies names under.
    pub allowed_suffixes: Vec<Suffix>,
    /// Whether apps may claim `*.name` hosts and get a wildcard leaf.
    pub allow_wildcards: bool,
    /// How long a leaf lives, 1 to 90 days.
    pub leaf_days: u32,
}

impl CaSettings {
    /// The names this CA certifies.
    #[must_use]
    pub fn policy(&self) -> Policy {
        Policy::new(self.allowed_suffixes.clone(), self.allow_wildcards)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCa {
    #[serde(default)]
    enabled: bool,
    dir: Option<PathBuf>,
    #[serde(default)]
    allowed_suffixes: Vec<String>,
    #[serde(default)]
    allow_wildcards: bool,
    leaf_days: Option<u32>,
}

/// Validates the section. `Ok(None)` when it is absent or `enabled = false`.
///
/// Public suffixes are checked by `ca init`, which is where the constraint is made; the provider
/// holds the intermediate to whatever that certificate permits ([`super::Ca::open`]).
pub(crate) fn parse(raw: Option<RawCa>) -> Result<Option<CaSettings>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if !raw.enabled {
        return Ok(None);
    }
    let dir = raw
        .dir
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| ConfigError::invalid("ca.dir", "is required"))?;
    let allowed_suffixes = parse_suffixes(&raw.allowed_suffixes, true)
        .map_err(|err| ConfigError::invalid("ca.allowed_suffixes", err))?;
    let leaf_days = raw.leaf_days.unwrap_or(DEFAULT_LEAF_DAYS);
    if !(1..=MAX_LEAF_DAYS).contains(&leaf_days) {
        return Err(ConfigError::invalid(
            "ca.leaf_days",
            format!("must be between 1 and {MAX_LEAF_DAYS}"),
        ));
    }
    Ok(Some(CaSettings {
        dir,
        allowed_suffixes,
        allow_wildcards: raw.allow_wildcards,
        leaf_days,
    }))
}
