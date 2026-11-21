//! The Amazon ECS source: running tasks whose task definition carries `podgate.*` labels become
//! apps.
//!
//! ```toml
//! [[source]]
//! kind = "ecs"
//! name = "ecs-prod"
//! region = "eu-west-1"                 # else AWS_REGION
//! clusters = ["prod-acme", "prod-globex"]   # or auto_discover = true
//! refresh_secs = 15                    # at least 5
//! tenant_from = "cluster"              # "fixed", "cluster" or "tag"
//! cluster_tenants = { prod-acme = "acme", prod-globex = "globex" }
//! exposed_by_default = false
//! ```
//!
//! The server of an app is the task's own network interface address (`awsvpc` mode, for Fargate
//! and EC2) plus the container port, never an address a label spells out ([`crate::docker::labels`]).
//! Only `RUNNING` tasks, and when the container defines a health check only `HEALTHY` ones, are
//! servers. The labels are the Docker labels of the task definition (`dockerLabels`), read by the
//! same parser the Docker source uses.
//!
//! ECS has no event stream, so the source polls: every `refresh_secs` it lists the running tasks
//! of each cluster, describes them in batches, and describes each task definition revision once.
//! It only ever calls `List*` and `Describe*` operations (see `client`), signs them with AWS
//! Signature Version 4, and takes credentials from the standard chain (`auth`), never from this
//! configuration. A poll that fails keeps the last state in force and reports the error as an
//! outage.
//!
//! A container that carries labels but cannot be used (an unknown or address-bearing label, no
//! address, a task in bridge mode without `ec2 = true`) is left out and reported next to the
//! state, as an outage text naming it, like the Docker source does.
//!
//! The reference is `docs/ref/provider-ecs.md`.

mod apps;
mod auth;
mod client;
mod model;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::config::SourceConfig;
use crate::push::Backoff;
use crate::source::{Source, State, Update, UpdateBody};

use apps::{ClusterTasks, Observed};
use auth::{Chain, dns_suffix};
use client::{Client, ClientError, Endpoint, Http};
use model::{TaskDefinition, arn_name, unix_secs};

const DEFAULT_REFRESH_SECS: u64 = 15;
const MIN_REFRESH_SECS: u64 = 5;
const OWN_TENANT: &str = "default";

/// The longest wait between polls while the API fails.
const MAX_RETRY: Duration = Duration::from_secs(60);

/// A `[[source]]` entry of kind `ecs` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct EcsConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TenantFrom {
    #[default]
    Fixed,
    Cluster,
    Tag,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    region: Option<String>,
    endpoint: Option<String>,
    ec2_endpoint: Option<String>,
    clusters: Option<Vec<String>>,
    #[serde(default)]
    auto_discover: bool,
    refresh_secs: Option<u64>,
    #[serde(default)]
    tenant_from: TenantFrom,
    tenant: Option<String>,
    cluster_tenants: Option<BTreeMap<String, String>>,
    #[serde(default)]
    exposed_by_default: bool,
    network: Option<String>,
    #[serde(default)]
    ec2: bool,
}

/// Where the tenant of a task comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TenantSource {
    /// The operator names one tenant for the whole source.
    Fixed(Box<str>),
    /// The tenant of the cluster, else `fallback`.
    Cluster {
        map: BTreeMap<Box<str>, Box<str>>,
        fallback: Box<str>,
    },
    /// The task names it in its `podgate.tenant` tag (or its container in a `podgate.tenant`
    /// label); the core honours that only for tenants that trust the source.
    Tag { mapped: Option<Box<str>> },
}

/// Which clusters are read.
#[derive(Debug)]
enum Clusters {
    Listed(Vec<Box<str>>),
    /// Every cluster of the account and region, listed again on every poll.
    Discover,
}

/// The validated `[[source]]` entry.
#[derive(Debug)]
struct Settings {
    client: Client,
    clusters: Clusters,
    tenants: TenantSource,
    exposed_by_default: bool,
    ec2: bool,
    refresh: Duration,
}

/// The Amazon ECS source.
#[derive(Debug)]
pub struct EcsSource {
    name: Box<str>,
    settings: Settings,
}

/// A region name is lowercase letters, digits and `-`: it becomes part of a host name and of a
/// signature's scope.
fn valid_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 32
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl EcsSource {
    /// An ECS source from its `[[source]]` entry, reading the credential chain from the
    /// process's environment.
    ///
    /// `clusters` defaults to `["default"]` unless `auto_discover` is set. With
    /// `tenant_from = "cluster"`, `cluster_tenants` maps the clusters, and `tenant` (default
    /// `default`) is the tenant of any other cluster.
    ///
    /// # Errors
    ///
    /// [`EcsConfigError`] when a key is unknown or has the wrong type (so a misspelt `tenant`
    /// cannot move the source's apps to the default tenant, and `access_key_id` is not a key at
    /// all: credentials come from the AWS chain), the region is missing or malformed, an
    /// endpoint is not an `http://` or `https://` origin, `refresh_secs` is below 5, `network`
    /// is not `awsvpc`, the tenant keys do not fit `tenant_from`, or the platform's root
    /// certificates cannot be loaded.
    pub fn from_config(config: &SourceConfig) -> Result<Self, EcsConfigError> {
        Self::from_config_with_env(config, std::env::vars())
    }

    /// Like [`Self::from_config`], with `env` as the environment the credential chain and the
    /// region fallback read. Tests give each source its own; the program passes the process's.
    ///
    /// # Errors
    ///
    /// As [`Self::from_config`].
    pub fn from_config_with_env(
        config: &SourceConfig,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, EcsConfigError> {
        let invalid = |reason: String| EcsConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let raw = Raw::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let env: BTreeMap<String, String> = env.into_iter().collect();

        let region = raw
            .region
            .clone()
            .or_else(|| env.get("AWS_REGION").cloned())
            .or_else(|| env.get("AWS_DEFAULT_REGION").cloned())
            .ok_or_else(|| invalid("region: is required (or set AWS_REGION)".to_owned()))?;
        if !valid_region(&region) {
            return Err(invalid(format!(
                "region: {region:?} must be lowercase letters, digits and `-`"
            )));
        }
        let suffix = dns_suffix(&region);
        let endpoint = |key: &str, given: Option<&String>, service: &str| {
            let address = given.map_or_else(
                || format!("https://{service}.{region}.{suffix}"),
                Clone::clone,
            );
            Endpoint::parse(&address).map_err(|why| invalid(format!("{key}: {why}")))
        };
        let ecs = endpoint("endpoint", raw.endpoint.as_ref(), "ecs")?;
        if raw.ec2_endpoint.is_some() && !raw.ec2 {
            return Err(invalid(
                "ec2_endpoint: only used with ec2 = true".to_owned(),
            ));
        }
        let ec2 = endpoint("ec2_endpoint", raw.ec2_endpoint.as_ref(), "ec2")?;

        if let Some(network) = &raw.network
            && network != "awsvpc"
        {
            return Err(invalid(format!(
                "network: {network:?} is not supported; tasks reach the proxy over their own awsvpc interface (bridge and host tasks need ec2 = true)"
            )));
        }
        let refresh_secs = raw.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS);
        if refresh_secs < MIN_REFRESH_SECS {
            return Err(invalid(format!(
                "refresh_secs: must be at least {MIN_REFRESH_SECS}, to stay inside the ECS API limits"
            )));
        }

        let clusters = match (raw.clusters, raw.auto_discover) {
            (Some(_), true) => {
                return Err(invalid(
                    "clusters and auto_discover = true exclude each other".to_owned(),
                ));
            }
            (None, true) => Clusters::Discover,
            (listed, false) => {
                let listed = listed.unwrap_or_else(|| vec!["default".to_owned()]);
                if listed.is_empty()
                    || listed
                        .iter()
                        .any(|cluster| cluster.is_empty() || cluster.contains(char::is_whitespace))
                {
                    return Err(invalid(
                        "clusters: must name at least one cluster, by name or ARN".to_owned(),
                    ));
                }
                Clusters::Listed(
                    listed
                        .iter()
                        .map(|cluster| cluster.as_str().into())
                        .collect(),
                )
            }
        };

        if raw.tenant.as_deref().is_some_and(str::is_empty) {
            return Err(invalid("tenant: is empty".to_owned()));
        }
        let tenants = match (raw.tenant_from, raw.cluster_tenants) {
            (TenantFrom::Fixed, None) => {
                TenantSource::Fixed(raw.tenant.unwrap_or_else(|| OWN_TENANT.to_owned()).into())
            }
            (TenantFrom::Tag, None) => TenantSource::Tag {
                mapped: raw.tenant.map(Into::into),
            },
            (TenantFrom::Cluster, Some(mapping)) => {
                if mapping
                    .iter()
                    .any(|(cluster, tenant)| cluster.is_empty() || tenant.is_empty())
                {
                    return Err(invalid(
                        "cluster_tenants: a cluster or a tenant is empty".to_owned(),
                    ));
                }
                let map: BTreeMap<Box<str>, Box<str>> = mapping
                    .iter()
                    .map(|(cluster, tenant)| (arn_name(cluster).into(), tenant.as_str().into()))
                    .collect();
                if let Clusters::Listed(listed) = &clusters {
                    let names: BTreeSet<&str> =
                        listed.iter().map(|cluster| arn_name(cluster)).collect();
                    if let Some(extra) = map.keys().find(|key| !names.contains(&***key)) {
                        return Err(invalid(format!(
                            "cluster_tenants: {extra:?} is not one of the source's clusters"
                        )));
                    }
                    if raw.tenant.is_none()
                        && let Some(unmapped) = names.iter().find(|name| !map.contains_key(**name))
                    {
                        return Err(invalid(format!(
                            "cluster_tenants: has no tenant for cluster {unmapped:?}, and no `tenant` names one for the others"
                        )));
                    }
                }
                TenantSource::Cluster {
                    map,
                    fallback: raw.tenant.unwrap_or_else(|| OWN_TENANT.to_owned()).into(),
                }
            }
            (TenantFrom::Cluster, None) => {
                return Err(invalid(
                    "tenant_from = \"cluster\" needs cluster_tenants".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "cluster_tenants: only with tenant_from = \"cluster\"".to_owned(),
                ));
            }
        };

        let http = Http::new().map_err(invalid)?;
        let chain = Chain::new(env, http.clone(), &region);
        Ok(Self {
            name: config.name.clone(),
            settings: Settings {
                client: Client::new(ecs, ec2, &region, http, chain),
                clusters,
                tenants,
                exposed_by_default: raw.exposed_by_default,
                ec2: raw.ec2,
                refresh: Duration::from_secs(refresh_secs),
            },
        })
    }
}

/// What one source keeps between polls.
#[derive(Default)]
struct Cache {
    /// Task definition revisions never change: each is described once, while a task uses it.
    definitions: BTreeMap<Box<str>, Arc<TaskDefinition>>,
    first_seen: BTreeMap<Box<str>, u64>,
}

/// What was last told to the core.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Unavailable(Box<str>),
    Available {
        state: State,
        report: Option<Box<str>>,
    },
}

impl EcsSource {
    /// Lists the tasks and builds the state; the error is AWS's.
    async fn sync(&self, cache: &mut Cache) -> Result<(State, Option<Box<str>>), ClientError> {
        let client = &self.settings.client;
        let mut reports: Vec<Box<str>> = Vec::new();

        let cluster_ids: Vec<Box<str>> = match &self.settings.clusters {
            Clusters::Listed(listed) => listed.clone(),
            Clusters::Discover => client
                .clusters()
                .await?
                .into_iter()
                .map(String::into_boxed_str)
                .collect(),
        };
        let mut observed = Observed::default();
        let mut queried: Vec<Box<str>> = Vec::new();
        for cluster in &cluster_ids {
            let name: Box<str> = arn_name(cluster).into();
            let arns = client.running_tasks(cluster).await?;
            let described = if arns.is_empty() {
                Vec::new()
            } else {
                let described = client.describe_tasks(cluster, &arns).await?;
                reports.extend(failures(&name, "task", &described.failures));
                described.tasks
            };
            observed.clusters.push(ClusterTasks {
                name,
                tasks: described,
            });
            queried.push(cluster.clone());
        }

        let arns: BTreeSet<&str> = observed
            .clusters
            .iter()
            .flat_map(|cluster| &cluster.tasks)
            .map(|task| task.task_definition_arn.as_str())
            .collect();
        let mut current = BTreeMap::new();
        for arn in arns {
            let definition = match cache.definitions.get(arn) {
                Some(known) => Arc::clone(known),
                None => Arc::new(client.task_definition(arn).await?),
            };
            current.insert(Box::<str>::from(arn), definition);
        }
        cache.definitions = current;

        for (cluster, tasks) in queried.iter().zip(&observed.clusters) {
            let services: BTreeSet<String> = tasks
                .tasks
                .iter()
                .filter_map(|task| task.group.as_deref()?.strip_prefix("service:"))
                .map(str::to_owned)
                .collect();
            if services.is_empty() {
                continue;
            }
            let names: Vec<String> = services.into_iter().collect();
            let described = client.services(cluster, &names).await?;
            reports.extend(failures(&tasks.name, "service", &described.failures));
            for service in described.services {
                observed.services.insert(
                    (tasks.name.clone(), service.service_name.as_str().into()),
                    unix_secs(service.created_at),
                );
            }
        }

        if self.settings.ec2 {
            self.instances(&queried, &mut observed, &cache.definitions, &mut reports)
                .await?;
        }

        let built = apps::build(
            &self.name,
            &self.settings,
            &observed,
            &cache.definitions,
            &mut cache.first_seen,
        );
        reports.extend(built.reports);
        for line in &reports {
            debug!(source = %self.name, "{line}");
        }
        let report = (!reports.is_empty()).then(|| reports.join("; ").into());
        Ok((
            State {
                apps: built.apps,
                certificates: Vec::new(),
            },
            report,
        ))
    }

    /// The private addresses of the EC2 instances that run the host and bridge tasks.
    async fn instances(
        &self,
        queried: &[Box<str>],
        observed: &mut Observed,
        definitions: &BTreeMap<Box<str>, Arc<TaskDefinition>>,
        reports: &mut Vec<Box<str>>,
    ) -> Result<(), ClientError> {
        let client = &self.settings.client;
        let mut by_instance: BTreeMap<String, String> = BTreeMap::new();
        for (cluster, tasks) in queried.iter().zip(&observed.clusters) {
            let wanted: BTreeSet<String> = tasks
                .tasks
                .iter()
                .filter(|task| {
                    definitions
                        .get(task.task_definition_arn.as_str())
                        .is_some_and(|definition| apps::needs_instance(task, definition))
                })
                .filter_map(|task| task.container_instance_arn.clone())
                .collect();
            if wanted.is_empty() {
                continue;
            }
            let wanted: Vec<String> = wanted.into_iter().collect();
            let described = client.container_instances(cluster, &wanted).await?;
            reports.extend(failures(
                &tasks.name,
                "container instance",
                &described.failures,
            ));
            for instance in described.instances {
                // Only EC2 instances (`i-...`) have a private address to look up.
                if let Some(id) = instance.ec2_instance_id.filter(|id| id.starts_with("i-")) {
                    by_instance.insert(instance.container_instance_arn, id);
                }
            }
        }
        let ids: Vec<String> = by_instance
            .values()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let addresses: BTreeMap<String, IpAddr> = client.instance_addresses(&ids).await?;
        for (arn, id) in by_instance {
            if let Some(address) = addresses.get(&id) {
                observed.instances.insert(arn, *address);
            }
        }
        Ok(())
    }
}

/// The reports of the entries an ECS `Describe*` call could not describe. A task that stopped
/// between the list and the description (`MISSING`) is not worth one.
fn failures(cluster: &str, what: &str, failures: &[model::Failure]) -> Vec<Box<str>> {
    failures
        .iter()
        .filter(|failure| failure.reason.as_deref() != Some("MISSING"))
        .map(|failure| {
            format!(
                "cluster {cluster}: cannot describe {what} {}: {}",
                failure.arn.as_deref().map_or("?", arn_name),
                failure.reason.as_deref().unwrap_or("no reason given")
            )
            .into()
        })
        .collect()
}

impl Source for EcsSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let mut cache = Cache::default();
        let mut sent: Option<Sent> = None;
        let refresh = self.settings.refresh;
        let mut retry = Backoff::new(refresh, MAX_RETRY.max(refresh)).jittered();
        let mut wait = Duration::ZERO;
        loop {
            tokio::time::sleep(wait).await;
            let observed = match self.sync(&mut cache).await {
                Ok((state, report)) => {
                    retry.reset();
                    wait = refresh;
                    Sent::Available { state, report }
                }
                Err(err) => {
                    wait = retry.next_delay();
                    Sent::Unavailable(format!("{err}").into())
                }
            };
            if sent.as_ref() == Some(&observed) {
                continue;
            }
            let outgoing = match &observed {
                Sent::Unavailable(why) => {
                    warn!(source = %self.name, error = %why, "the ECS poll failed; the last state stays");
                    vec![Update::outage(&self.name, why)]
                }
                Sent::Available { state, report } => {
                    let mut outgoing = vec![Update {
                        source: self.name.clone(),
                        body: UpdateBody::State(state.clone()),
                    }];
                    if let Some(report) = report {
                        warn!(source = %self.name, "{report}");
                        outgoing.push(Update::outage(&self.name, report));
                    }
                    outgoing
                }
            };
            sent = Some(observed);
            for update in outgoing {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn regions_become_host_names() {
        assert!(valid_region("eu-west-1"));
        assert!(valid_region("cn-north-1"));
        assert!(!valid_region(""));
        assert!(!valid_region("EU-West-1"));
        assert!(!valid_region("evil.example.com/"));
    }
}
