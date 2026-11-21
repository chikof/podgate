//! Approving on-demand certificate requests.
//!
//! podgate emits `certificate_requested {host}` when a TLS handshake names a host of an
//! `on_demand` app that has no certificate, and orders it only when the control plane lists the
//! host in `acme.requested_hosts`. The SNI is chosen by whoever connects, so approving is a
//! security decision, taken here:
//!
//! 1. The host must be a plain name (no wildcard, no IP, no odd characters).
//! 2. An app that declares `tls.mode = on_demand` must claim it: a router host that is the name
//!    itself or a wildcard one label above it.
//! 3. The tenant of that app must be one whose configured `hosts` patterns cover the name (the
//!    trust rule of `docs/ref/provider.md`, the same check the merge ran on the app).
//! 4. That tenant must have fewer than `max_per_tenant_per_hour` approvals in the last hour.
//! 5. Fewer than `max_pending` approvals may be waiting for their certificate.
//!
//! Anything else is not listed: the handshake fails after 30 seconds as it does without a
//! control plane, and the host is asked about again after podgate's pending period (10 minutes).
//! The approvals, with their times, are kept in the state directory, so a restart neither forgets
//! what is pending nor resets the rate window.
//!
//! The type has no clock: callers pass `now_ms`.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::Claims;
use super::settings::OnDemandLimits;
use crate::trust::{HostPattern, Trust};

const HOUR_MS: u64 = 3_600_000;

/// One approval: its host, tenant and time, and whether its certificate is still awaited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The approved host.
    pub host: Box<str>,
    /// The tenant it was counted against.
    pub tenant: Box<str>,
    /// When it was approved (unix milliseconds).
    pub at_ms: u64,
    /// Whether the host is still listed in `requested_hosts`. It stays in the rate window for
    /// an hour either way.
    pub open: bool,
}

/// Why a request was not approved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The name is not a plain host name.
    InvalidHost,
    /// No app declares `on_demand` for this host.
    NotOnDemand,
    /// The apps that declare it belong to a tenant whose `hosts` do not cover it.
    ForeignHost {
        /// The tenant that declared it.
        tenant: Box<str>,
    },
    /// The tenant used up its hourly approvals.
    TenantRateLimited {
        /// The tenant.
        tenant: Box<str>,
    },
    /// Too many approvals wait for their certificate.
    TooManyPending,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHost => f.write_str("the name is not a plain host name"),
            Self::NotOnDemand => f.write_str("no app declares on_demand TLS for this host"),
            Self::ForeignHost { tenant } => {
                write!(f, "the host is outside the hosts of tenant {tenant}")
            }
            Self::TenantRateLimited { tenant } => {
                write!(f, "tenant {tenant} has used its approvals for this hour")
            }
            Self::TooManyPending => f.write_str("too many approved hosts wait for a certificate"),
        }
    }
}

/// The answer to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// List the host in `requested_hosts`.
    Approved {
        /// The tenant it counts against.
        tenant: Box<str>,
    },
    /// Do not list it.
    Refused(Refusal),
}

/// Decides requests and remembers what it approved.
#[derive(Debug)]
pub struct Approver {
    limits: OnDemandLimits,
    trust: Trust,
    records: Vec<Approval>,
}

impl Approver {
    /// An approver with `limits`, `trust` for the tenant rule, and the `records` kept from an
    /// earlier run.
    #[must_use]
    pub fn new(limits: OnDemandLimits, trust: Trust, records: Vec<Approval>) -> Self {
        Self {
            limits,
            trust,
            records,
        }
    }

    /// Decides whether `host` may be ordered, and counts the approval.
    pub fn decide(&mut self, host: &str, claims: &Claims, now_ms: u64) -> Decision {
        self.expire(now_ms);
        let name = match HostPattern::parse(host) {
            Ok(pattern @ HostPattern::Exact(_)) if host.parse::<std::net::IpAddr>().is_err() => {
                pattern
            }
            _ => return Decision::Refused(Refusal::InvalidHost),
        };
        let host: Box<str> = host.to_ascii_lowercase().into();
        if self
            .records
            .iter()
            .any(|record| record.open && record.host == host)
        {
            let tenant = self
                .records
                .iter()
                .find(|record| record.host == host)
                .map(|record| record.tenant.clone())
                .unwrap_or_default();
            return Decision::Approved { tenant };
        }
        let mut owner: Option<Box<str>> = None;
        let mut foreign: Option<Box<str>> = None;
        for app in claims.apps.iter().filter(|app| app.on_demand) {
            if !app.hosts.iter().any(|pattern| pattern.covers(&name)) {
                continue;
            }
            let allowed = self
                .trust
                .lookup(&app.tenant)
                .and_then(|tenant| self.trust.check_host(tenant, &name));
            if allowed.is_ok() {
                owner = Some(app.tenant.clone());
                break;
            }
            foreign.get_or_insert_with(|| app.tenant.clone());
        }
        let Some(tenant) = owner else {
            return Decision::Refused(foreign.map_or(Refusal::NotOnDemand, |tenant| {
                Refusal::ForeignHost { tenant }
            }));
        };
        let used = self
            .records
            .iter()
            .filter(|record| record.tenant == tenant)
            .count();
        if u32::try_from(used).is_ok_and(|used| used >= self.limits.max_per_tenant_per_hour) {
            return Decision::Refused(Refusal::TenantRateLimited { tenant });
        }
        let open = self.records.iter().filter(|record| record.open).count();
        if u32::try_from(open).is_ok_and(|open| open >= self.limits.max_pending) {
            return Decision::Refused(Refusal::TooManyPending);
        }
        self.records.push(Approval {
            host,
            tenant: tenant.clone(),
            at_ms: now_ms,
            open: true,
        });
        Decision::Approved { tenant }
    }

    /// The certificate for `host` exists: stop listing it. The approval still counts in the
    /// tenant's hour.
    pub fn release(&mut self, host: &str) -> bool {
        let mut changed = false;
        for record in self
            .records
            .iter_mut()
            .filter(|r| r.open && *r.host == *host)
        {
            record.open = false;
            changed = true;
        }
        changed
    }

    /// Forgets approvals older than an hour: they no longer count, and an unanswered one stops
    /// being listed. Returns whether anything changed.
    pub fn expire(&mut self, now_ms: u64) -> bool {
        let before = self.records.len();
        self.records
            .retain(|record| now_ms.saturating_sub(record.at_ms) < HOUR_MS);
        self.records.len() != before
    }

    /// The hosts to list in `requested_hosts`, sorted.
    #[must_use]
    pub fn open_hosts(&self) -> Vec<Box<str>> {
        let mut hosts: Vec<Box<str>> = self
            .records
            .iter()
            .filter(|record| record.open)
            .map(|record| record.host.clone())
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }

    /// Every record, for the state directory.
    #[must_use]
    pub fn records(&self) -> &[Approval] {
        &self.records
    }
}
