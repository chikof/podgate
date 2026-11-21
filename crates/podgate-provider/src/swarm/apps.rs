//! From the services, tasks and nodes the engine lists to the apps the source declares.
//!
//! Which services count, which tasks serve, which network gives the address, which tenant they
//! belong to: the decisions that are Swarm's. The labels are read by [`crate::docker::labels`],
//! from the service only.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use crate::docker::labels::{self, Labels, Member};
use crate::source::{Origin, SourceApp, TenantClaim};

use super::model::{Network, Node, Service, Task};
use super::{Backend, EndpointMode, Settings, tasks, vip};

/// What one pass read from the engine.
#[derive(Debug, Default)]
pub(super) struct Observed {
    pub(super) services: Vec<Service>,
    pub(super) tasks: Vec<Task>,
    /// `None` when the engine (or a socket proxy in front of it) does not offer the list.
    pub(super) nodes: Option<Vec<Node>>,
    /// `None` when the engine (or a socket proxy in front of it) does not offer the list.
    pub(super) networks: Option<Vec<Network>>,
}

/// The apps of one pass, and what was left out and why.
#[derive(Debug, Default)]
pub(super) struct Built {
    pub(super) apps: Vec<SourceApp>,
    /// One line per service (or task) that carries labels but is not used.
    pub(super) reports: Vec<Box<str>>,
}

/// A service whose labels, app and tasks are usable.
struct Prepared<'a> {
    service: &'a Service,
    labels: Labels,
    members: Vec<Server>,
}

/// One server of a service and who it says it belongs to.
struct Server {
    name: String,
    address: SocketAddr,
    claim: TenantClaim,
}

/// The keys that turn exposure on or off: podgate's own, and Traefik's, which the label parser
/// reads too.
const ENABLE_KEYS: [&str; 2] = ["podgate.enable", "traefik.enable"];

/// Builds the apps of `observed`.
pub(super) fn build(source: &str, settings: &Settings, observed: &Observed) -> Built {
    let mut built = Built::default();
    let down: BTreeSet<&str> = observed
        .nodes
        .iter()
        .flatten()
        .filter(|node| !node.ready)
        .map(|node| &*node.id)
        .collect();
    let mut tasks_of: BTreeMap<&str, Vec<&Task>> = BTreeMap::new();
    for task in &observed.tasks {
        tasks_of.entry(&task.service_id).or_default().push(task);
    }
    let ids = vip::network_ids(
        settings,
        observed.networks.as_deref().unwrap_or_default(),
        &observed.tasks,
    );
    let mut services: Vec<&Service> = observed.services.iter().collect();
    services.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));

    let mut groups: BTreeMap<Box<str>, Vec<Prepared<'_>>> = BTreeMap::new();
    // The oldest service of each app, whether or not it has a task that serves right now: an
    // app must not turn younger while its tasks restart.
    let mut born: BTreeMap<Box<str>, u64> = BTreeMap::new();
    for service in services {
        if !exposed(service, settings) {
            continue;
        }
        let tasks = tasks_of.get(&*service.id).map_or(&[][..], Vec::as_slice);
        let mut lines = Vec::new();
        let prepared = prepare(settings, service, tasks, &down, &ids, &mut lines);
        built
            .reports
            .extend(lines.iter().map(|line| report(service, line)));
        match prepared {
            Ok((app, prepared)) => {
                for problem in &prepared.labels.problems {
                    built.reports.push(report(service, &problem.to_string()));
                }
                let oldest = born.entry(app.clone()).or_insert(service.created);
                *oldest = (*oldest).min(service.created);
                if !prepared.members.is_empty() {
                    groups.entry(app).or_default().push(prepared);
                }
            }
            Err(why) => built.reports.push(report(service, &why)),
        }
    }

    for (app, prepared) in groups {
        let members: Vec<(usize, Member<'_>)> = prepared
            .iter()
            .enumerate()
            .flat_map(|(index, prepared)| {
                prepared.members.iter().map(move |server| {
                    (
                        index,
                        Member {
                            name: &server.name,
                            labels: &prepared.labels,
                            server: server.address,
                            claim: &server.claim,
                            created: prepared.service.created,
                        },
                    )
                })
            })
            .collect();
        let flat: Vec<Member<'_>> = members.iter().map(|(_, member)| member.clone()).collect();
        let assembled = match labels::assemble(&app, &flat) {
            Ok(assembled) => assembled,
            Err(why) => {
                for prepared in &prepared {
                    built
                        .reports
                        .push(report(prepared.service, &why.to_string()));
                }
                continue;
            }
        };
        for (index, why) in &assembled.rejected {
            let (owner, member) = &members[*index];
            built.reports.push(report(
                prepared[*owner].service,
                &format!("task {}: {why}", member.name),
            ));
        }
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                first_seen: born.get(&app).copied().unwrap_or(0),
                object: app,
            },
            tenant: assembled.claim,
            app: assembled.app,
        });
    }
    built
}

/// Whether the service is exposed: `false` in either enable label hides it, any other value
/// exposes it (the label parser rejects a value that is no boolean, with a report), and
/// without one `exposed_by_default` decides.
fn exposed(service: &Service, settings: &Settings) -> bool {
    let mut values = ENABLE_KEYS
        .iter()
        .filter_map(|key| service.labels.get(*key))
        .peekable();
    if values.peek().is_none() {
        return settings.exposed_by_default;
    }
    !values.any(|value| value.trim().eq_ignore_ascii_case("false"))
}

fn report(service: &Service, why: &str) -> Box<str> {
    let short: String = service.id.chars().take(12).collect();
    format!("service {} ({short}): {why}", service.name).into()
}

/// The app id and the labels and servers of one service, or why it is not used. Lines for tasks
/// that are skipped go to `lines`.
fn prepare<'a>(
    settings: &Settings,
    service: &'a Service,
    service_tasks: &[&Task],
    down: &BTreeSet<&str>,
    ids: &BTreeMap<&str, BTreeSet<&str>>,
    lines: &mut Vec<String>,
) -> Result<(Box<str>, Prepared<'a>), String> {
    // The service's own labels and nothing else: a container label is what an image author can
    // set, the service spec is what the deployer wrote.
    let labels = labels::parse(
        service
            .labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
    .map_err(|why| why.to_string())?;
    let app = match &labels.app {
        Some(app) => app.clone(),
        None => labels::identifier("app", &service.name).map_err(|why| why.to_string())?,
    };
    let port = labels
        .port
        .ok_or("podgate.port: is required, the port the service's tasks listen on")?;

    let (serving, skipped) = tasks::serving(service, service_tasks, down);
    lines.extend(skipped);
    let backends: Vec<Backend> = match settings.endpoint {
        EndpointMode::Tasks => {
            let (backends, skipped) = tasks::backends(settings, service, &serving);
            lines.extend(skipped);
            backends
        }
        EndpointMode::Vip => vip::backend(settings, service, &serving, ids)?
            .into_iter()
            .collect(),
    };

    let mut members = Vec::new();
    for backend in backends {
        let networks: Vec<&str> = backend.networks.iter().map(String::as_str).collect();
        match settings.tenants.claim(&networks, labels.tenant.as_deref()) {
            Ok(claim) => members.push(Server {
                name: backend.name,
                address: SocketAddr::new(backend.address, port),
                claim,
            }),
            Err(why) => lines.push(format!("{}: {why}", backend.name)),
        }
    }
    Ok((
        app,
        Prepared {
            service,
            labels,
            members,
        },
    ))
}
