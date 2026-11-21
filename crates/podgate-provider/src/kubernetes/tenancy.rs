//! Which tenant an Ingress belongs to, and what that tenant may have.
//!
//! The tenant is the operator's decision, by namespace: `namespace_tenants` maps a namespace to a
//! tenant and `default_tenant` covers the rest (with neither, the provider's default tenant). An
//! Ingress may also name a tenant in the annotation `podgate.io/tenant`; that is the deployer's
//! claim, and the core honours it only for tenants that list this source in `label_sources`
//! (`docs/ref/provider.md`). Namespaces are what Kubernetes RBAC isolates, so a tenant boundary
//! drawn on them is one the cluster already enforces.
//!
//! The merge enforces the same rules on whatever the source sends, and drops a whole app when one
//! of them fails. The source applies them first, per Ingress and per router, so that one bad
//! Ingress (or one catch-all router) is refused with a report that names it instead of being
//! found later by object name only.

use std::collections::BTreeMap;

use podgate_model::Router;

use crate::config::Config;
use crate::source::TenantClaim;
use crate::trust::{HostPattern, Problem, RouterHosts, Trust};

/// The tenant rules of one Kubernetes source.
#[derive(Debug, Clone)]
pub struct Tenancy {
    source: Box<str>,
    trust: Trust,
    namespaces: BTreeMap<Box<str>, Box<str>>,
    default_tenant: Option<Box<str>>,
    /// Entry point to the one tenant that may attach routers to it.
    exclusive: BTreeMap<Box<str>, Box<str>>,
}

/// What the tenant rules decided about the routers of one Ingress.
#[derive(Debug)]
pub struct Vetted {
    /// The hosts the routers claim, once each.
    pub hosts: Vec<HostPattern>,
    /// For each router, in order: why it may not exist, if it may not (a catch-all router of a
    /// tenant that is not allowed one).
    pub refused: Vec<Option<Problem>>,
}

impl Tenancy {
    /// The rules for the source called `source`.
    ///
    /// # Errors
    ///
    /// A message naming the key when a mapped or default tenant is not in the configuration: a
    /// typo must not quietly move a namespace to another tenant.
    pub fn new(
        source: &str,
        config: &Config,
        namespaces: BTreeMap<Box<str>, Box<str>>,
        default_tenant: Option<Box<str>>,
    ) -> Result<Self, String> {
        let trust = Trust::new(config);
        for (namespace, tenant) in &namespaces {
            trust
                .lookup(tenant)
                .map_err(|_| format!("namespace_tenants[{namespace:?}]: tenant {tenant:?} is not in the configuration"))?;
        }
        if let Some(tenant) = &default_tenant {
            trust.lookup(tenant).map_err(|_| {
                format!("default_tenant: tenant {tenant:?} is not in the configuration")
            })?;
        }
        let exclusive = config
            .tenants
            .iter()
            .chain([&config.default_tenant])
            .flat_map(|tenant| {
                tenant
                    .exclusive_entry_points
                    .iter()
                    .map(|entry| (entry.clone(), tenant.id.clone()))
            })
            .collect();
        Ok(Self {
            source: source.into(),
            trust,
            namespaces,
            default_tenant,
            exclusive,
        })
    }

    /// Whether objects of namespaces `a` and `b` belong to one tenant. A reference across
    /// namespaces is only ever allowed inside one tenant, whatever a `ReferenceGrant` says.
    #[must_use]
    pub fn same_tenant(&self, a: &str, b: &str) -> bool {
        self.claim(a, None).mapped == self.claim(b, None).mapped
    }

    /// Whether the tenant of `claim` may attach routers to `entry_points`: an entry point that
    /// the operator made exclusive to another tenant is refused.
    ///
    /// # Errors
    ///
    /// `entry_point_forbidden`, naming the entry point and its tenant, or the [`Problem`] of an
    /// unknown tenant.
    pub fn check_entry_points(
        &self,
        claim: &TenantClaim,
        entry_points: &[Box<str>],
    ) -> Result<(), Problem> {
        let tenant = self.trust.resolve(&self.source, claim)?;
        for entry in entry_points {
            if let Some(owner) = self.exclusive.get(entry)
                && *owner != tenant.tenant.id
            {
                return Err(Problem::new(
                    "entry_point_forbidden",
                    format!(
                        "entry point {entry} is exclusive to tenant {owner}, not to {}",
                        tenant.tenant.id
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Whether the tenant of `claim` may claim every one of `hosts`.
    ///
    /// # Errors
    ///
    /// `foreign_host_claim` for the first host outside what the tenant may claim, or the
    /// [`Problem`] of an unknown tenant.
    pub fn check_hosts(&self, claim: &TenantClaim, hosts: &[HostPattern]) -> Result<(), Problem> {
        let tenant = self.trust.resolve(&self.source, claim)?;
        hosts
            .iter()
            .try_for_each(|host| self.trust.check_host(tenant, host))
    }

    /// Whose an Ingress in `namespace` is, given its `podgate.io/tenant` annotation.
    #[must_use]
    pub fn claim(&self, namespace: &str, annotation: Option<&str>) -> TenantClaim {
        let mapped = self
            .namespaces
            .get(namespace)
            .or(self.default_tenant.as_ref());
        let mut claim = mapped.map_or_else(TenantClaim::none, |tenant| TenantClaim::mapped(tenant));
        if let Some(label) = annotation {
            claim = claim.with_label(label);
        }
        claim
    }

    /// Applies the tenant rules to the routers an Ingress would get.
    ///
    /// # Errors
    ///
    /// The [`Problem`] that refuses the whole Ingress: an unknown tenant, a router the provider
    /// cannot read, or a host outside what the tenant may claim.
    pub fn vet(&self, claim: &TenantClaim, routers: &[Router]) -> Result<Vetted, Problem> {
        let tenant = self.trust.resolve(&self.source, claim)?;
        let mut hosts: Vec<HostPattern> = Vec::new();
        let mut refused = Vec::with_capacity(routers.len());
        for router in routers {
            let claimed = RouterHosts::of(router).map_err(|err| {
                Problem::new(err.code(), format!("router {}: {err}", router.name))
            })?;
            for host in &claimed.hosts {
                if !hosts.contains(host) {
                    self.trust.check_host(tenant, host)?;
                    hosts.push(host.clone());
                }
            }
            refused.push(Trust::check_catch_all(tenant, router, &claimed).err());
        }
        Ok(Vetted { hosts, refused })
    }
}
