//! From the tasks ECS lists to the apps the source declares.
//!
//! Which tasks and containers count, which address gives the server, which tenant they belong
//! to: the decisions that are ECS's. The labels themselves (`dockerLabels` of the task
//! definition) are read by [`crate::docker::labels`], the same parser the Docker source uses.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::docker::labels::{self, Labels, Member};
use crate::source::{Origin, SourceApp, TenantClaim};

use super::model::{Container, ContainerDefinition, Task, TaskDefinition, arn_name, unix_secs};
use super::{Settings, TenantSource};

/// The task tag that names a tenant under `tenant_from = "tag"`.
const TENANT_TAG: &str = "podgate.tenant";

/// The tasks of one cluster.
#[derive(Debug)]
pub(super) struct ClusterTasks {
    /// The cluster's name (its ARN's last segment).
    pub(super) name: Box<str>,
    pub(super) tasks: Vec<Task>,
}

/// What one poll found.
#[derive(Debug, Default)]
pub(super) struct Observed {
    pub(super) clusters: Vec<ClusterTasks>,
    /// The private address of each container instance (by ARN), for bridge and host tasks.
    pub(super) instances: BTreeMap<String, IpAddr>,
    /// When each service of each cluster was created, in unix seconds.
    pub(super) services: BTreeMap<(Box<str>, Box<str>), u64>,
}

/// The apps of one pass over the tasks, and what was left out and why.
#[derive(Debug, Default)]
pub(super) struct Built {
    pub(super) apps: Vec<SourceApp>,
    /// One line per container that is exposed but not used.
    pub(super) reports: Vec<Box<str>>,
}

struct Candidate {
    name: String,
    /// The task's creation time.
    created: u64,
    /// The creation time of the task's service, when it has one: the app's age.
    service_created: Option<u64>,
    labels: Labels,
    server: SocketAddr,
    claim: TenantClaim,
}

/// How a task reaches the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Awsvpc,
    Host,
    Bridge,
    Other,
}

/// Whether the address of a task's container instance is needed: it has no interface of its own.
pub(super) fn needs_instance(task: &Task, definition: &TaskDefinition) -> bool {
    mode(definition, task) != Mode::Awsvpc
}

fn mode(definition: &TaskDefinition, task: &Task) -> Mode {
    match definition.network_mode.as_deref() {
        Some("awsvpc") => Mode::Awsvpc,
        Some("host") => Mode::Host,
        Some("bridge") => Mode::Bridge,
        Some(_) => Mode::Other,
        // Fargate tasks always have their own interface; on EC2 the default is bridge.
        None if task.launch_type.as_deref() == Some("FARGATE") => Mode::Awsvpc,
        None => Mode::Bridge,
    }
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Awsvpc => "awsvpc",
            Self::Host => "host",
            Self::Bridge => "bridge",
            Self::Other => "this network mode",
        }
    }
}

/// The tag keys that turn exposure on or off: podgate's own, and Traefik's, which the label
/// parser reads too.
const ENABLE_KEYS: [&str; 2] = ["podgate.enable", "traefik.enable"];

fn exposed(labels: &BTreeMap<String, String>, exposed_by_default: bool) -> bool {
    let enable = ENABLE_KEYS.iter().find_map(|key| labels.get(*key));
    match enable.map(String::as_str) {
        Some(value) if value.trim().eq_ignore_ascii_case("false") => false,
        // Any other value is for the label parser to reject, with a report.
        Some(_) => true,
        None => exposed_by_default,
    }
}

/// A task that may serve: running and wanted running, and not reported unhealthy.
fn serving(task: &Task) -> bool {
    task.last_status.as_deref() == Some("RUNNING")
        && task
            .desired_status
            .as_deref()
            .is_none_or(|status| status == "RUNNING")
        && task.health_status.as_deref() != Some("UNHEALTHY")
}

/// A container that may serve: running, and healthy when its definition has a health check.
fn container_serves(definition: &ContainerDefinition, container: &Container) -> bool {
    container.last_status.as_deref() == Some("RUNNING")
        && (definition.health_check.is_none()
            || container.health_status.as_deref() == Some("HEALTHY"))
}

/// The service a task belongs to, or its task definition family.
fn default_name<'a>(task: &'a Task, definition: &'a TaskDefinition) -> Option<&'a str> {
    service_of(task).or_else(|| {
        definition
            .family
            .as_deref()
            .or_else(|| task.group.as_deref()?.strip_prefix("family:"))
    })
}

fn service_of(task: &Task) -> Option<&str> {
    task.group.as_deref()?.strip_prefix("service:")
}

/// The private IPv4 address of a task's network interface.
fn interface_address(task: &Task, container: &Container) -> Option<String> {
    task.attachments
        .iter()
        .filter(|attachment| attachment.kind.as_deref() == Some("ElasticNetworkInterface"))
        .flat_map(|attachment| &attachment.details)
        .find(|detail| detail.name == "privateIPv4Address")
        .and_then(|detail| detail.value.clone())
        .or_else(|| {
            container
                .network_interfaces
                .iter()
                .find_map(|interface| interface.private_ipv4_address.clone())
        })
}

fn report(cluster: &str, task: &Task, container: &str, why: &str) -> Box<str> {
    format!(
        "task {} (cluster {cluster}, container {container}): {why}",
        arn_name(&task.task_arn)
    )
    .into()
}

/// Builds the apps of the observed tasks.
///
/// `first_seen` remembers when each app was first seen, so an older app keeps its place in a
/// conflict across passes; it keeps only the apps of this pass.
pub(super) fn build(
    source: &str,
    settings: &Settings,
    observed: &Observed,
    definitions: &BTreeMap<Box<str>, Arc<TaskDefinition>>,
    first_seen: &mut BTreeMap<Box<str>, u64>,
) -> Built {
    let mut built = Built::default();
    let mut groups: BTreeMap<Box<str>, Vec<Candidate>> = BTreeMap::new();
    for cluster in &observed.clusters {
        let mut tasks: Vec<&Task> = cluster.tasks.iter().filter(|task| serving(task)).collect();
        tasks.sort_by(|a, b| {
            (unix_secs(a.created_at), &a.task_arn).cmp(&(unix_secs(b.created_at), &b.task_arn))
        });
        for task in tasks {
            let Some(definition) = definitions.get(&*task.task_definition_arn) else {
                built.reports.push(report(
                    &cluster.name,
                    task,
                    "*",
                    &format!(
                        "its task definition {} was not described",
                        task.task_definition_arn
                    ),
                ));
                continue;
            };
            for container_definition in &definition.container_definitions {
                if !exposed(
                    &container_definition.docker_labels,
                    settings.exposed_by_default,
                ) {
                    continue;
                }
                match candidate(
                    settings,
                    observed,
                    &cluster.name,
                    task,
                    definition,
                    container_definition,
                ) {
                    Ok(Some((id, candidate))) => {
                        for problem in &candidate.labels.problems {
                            built.reports.push(report(
                                &cluster.name,
                                task,
                                &container_definition.name,
                                &problem.to_string(),
                            ));
                        }
                        groups.entry(id).or_default().push(candidate);
                    }
                    Ok(None) => {}
                    Err(why) => built.reports.push(report(
                        &cluster.name,
                        task,
                        &container_definition.name,
                        &why,
                    )),
                }
            }
        }
    }

    let mut seen = BTreeMap::new();
    for (id, candidates) in groups {
        let members: Vec<Member<'_>> = candidates
            .iter()
            .map(|candidate| Member {
                name: &candidate.name,
                labels: &candidate.labels,
                server: candidate.server,
                claim: &candidate.claim,
                created: candidate.created,
            })
            .collect();
        let assembled = match labels::assemble(&id, &members) {
            Ok(assembled) => assembled,
            Err(why) => {
                for candidate in &candidates {
                    built
                        .reports
                        .push(format!("{}: {why}", candidate.name).into());
                }
                continue;
            }
        };
        for (index, why) in &assembled.rejected {
            built
                .reports
                .push(format!("{}: {why}", candidates[*index].name).into());
        }
        let rejected: BTreeSet<usize> =
            assembled.rejected.iter().map(|(index, _)| *index).collect();
        let oldest = candidates
            .iter()
            .enumerate()
            .filter(|(index, _)| !rejected.contains(index))
            .map(|(_, candidate)| candidate.service_created.unwrap_or(candidate.created))
            .min()
            .unwrap_or(0);
        let first = *first_seen.get(&id).unwrap_or(&oldest);
        seen.insert(id.clone(), first);
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                object: id,
                first_seen: first,
            },
            tenant: assembled.claim,
            app: assembled.app,
        });
    }
    *first_seen = seen;
    built
}

/// The app id, labels, server and tenant claim of one exposed container, `None` when it is
/// not serving, or why it is not used.
fn candidate(
    settings: &Settings,
    observed: &Observed,
    cluster: &str,
    task: &Task,
    definition: &TaskDefinition,
    container_definition: &ContainerDefinition,
) -> Result<Option<(Box<str>, Candidate)>, String> {
    let Some(container) = task
        .containers
        .iter()
        .find(|container| container.name == container_definition.name)
    else {
        return Ok(None);
    };
    if !container_serves(container_definition, container) {
        return Ok(None);
    }
    let labels = labels::parse(
        container_definition
            .docker_labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
    .map_err(|why| why.to_string())?;

    let name = match &labels.app {
        Some(app) => app.to_string(),
        None => default_name(task, definition)
            .ok_or("the task has no service or task definition family to name the app")?
            .to_owned(),
    };
    let id =
        labels::identifier("app", &format!("{cluster}.{name}")).map_err(|why| why.to_string())?;

    let port = match labels.port {
        Some(port) => port,
        None => {
            let mut declared = container_definition.port_mappings.iter().filter(|mapping| {
                mapping
                    .protocol
                    .as_deref()
                    .is_none_or(|protocol| protocol.eq_ignore_ascii_case("tcp"))
            });
            match (declared.next(), declared.next()) {
                (Some(only), None) => only
                    .container_port
                    .ok_or("podgate.port: is required, the port the container listens on")?,
                _ => {
                    return Err(
                        "podgate.port: is required, the port the container listens on (the task definition declares none or several)"
                            .to_owned(),
                    );
                }
            }
        }
    };

    let server = server(settings, observed, task, definition, container, port)?;

    let claim = match &settings.tenants {
        TenantSource::Fixed(tenant) => TenantClaim::mapped(tenant),
        TenantSource::Cluster { map, fallback } => {
            TenantClaim::mapped(map.get(cluster).unwrap_or(fallback))
        }
        TenantSource::Tag { mapped } => {
            let claim = mapped
                .as_deref()
                .map_or_else(TenantClaim::none, TenantClaim::mapped);
            let named = task
                .tags
                .iter()
                .find(|tag| tag.key == TENANT_TAG)
                .map(|tag| tag.value.as_str())
                .filter(|value| !value.is_empty())
                .or(labels.tenant.as_deref());
            match named {
                Some(tenant) => claim.with_label(tenant),
                None => claim,
            }
        }
    };
    let service_created = service_of(task).and_then(|service| {
        observed
            .services
            .get(&(cluster.into(), service.into()))
            .copied()
    });
    Ok(Some((
        id,
        Candidate {
            name: format!("{} {}", arn_name(&task.task_arn), container_definition.name),
            created: unix_secs(task.created_at),
            service_created,
            labels,
            server,
            claim,
        },
    )))
}

/// The server of a container: the task's own address and the container port, never a value from
/// a label.
fn server(
    settings: &Settings,
    observed: &Observed,
    task: &Task,
    definition: &TaskDefinition,
    container: &Container,
    port: u16,
) -> Result<SocketAddr, String> {
    let how = mode(definition, task);
    match how {
        Mode::Awsvpc => {
            let text = interface_address(task, container).ok_or(
                "no address: the task has no network interface with a private IPv4 address",
            )?;
            let address: Ipv4Addr = text.trim().parse().map_err(|_| {
                format!("its network interface address {text:?} is not an IPv4 address")
            })?;
            Ok(SocketAddr::new(address.into(), port))
        }
        Mode::Other => Err(format!(
            "skipped: a task in {} has no routable address of its own",
            how.name()
        )),
        Mode::Host | Mode::Bridge if !settings.ec2 => Err(format!(
            "skipped: a task in {} mode has no routable address of its own; set ec2 = true to reach it on its container instance",
            how.name()
        )),
        Mode::Host | Mode::Bridge => {
            let address = task
                .container_instance_arn
                .as_ref()
                .and_then(|arn| observed.instances.get(arn))
                .ok_or(
                    "no address: its container instance has no EC2 private address (ECS Anywhere instances have none)",
                )?;
            let published = if how == Mode::Host {
                port
            } else {
                container
                    .network_bindings
                    .iter()
                    .filter(|binding| {
                        binding.container_port == Some(port)
                            && binding
                                .protocol
                                .as_deref()
                                .is_none_or(|protocol| protocol.eq_ignore_ascii_case("tcp"))
                    })
                    .find_map(|binding| binding.host_port.filter(|host| *host != 0))
                    .ok_or_else(|| format!("no host port is published for container port {port}"))?
            };
            Ok(SocketAddr::new(*address, published))
        }
    }
}
