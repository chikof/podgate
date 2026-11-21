//! From the containers the daemon lists to the apps the source declares.
//!
//! Which containers count, which network gives the address, which tenant they belong to: the
//! decisions that are Docker's. The labels themselves are read by [`super::labels`].

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use crate::source::{Origin, SourceApp, TenantClaim};

use super::Settings;
use super::labels::{self, Labels, Member};
use super::model::{Container, Readiness};

const COMPOSE_SERVICE: &str = "com.docker.compose.service";

/// The apps of one pass over the containers, and what was left out and why.
#[derive(Debug, Default)]
pub(super) struct Built {
    pub(super) apps: Vec<SourceApp>,
    /// One line per container that carries labels but is not used.
    pub(super) reports: Vec<Box<str>>,
}

struct Candidate<'a> {
    container: &'a Container,
    labels: Labels,
    app: Box<str>,
    server: SocketAddr,
    claim: TenantClaim,
}

/// Builds the apps of `containers`.
///
/// `first_seen` remembers when each app was first seen, so an older app keeps its place in a
/// conflict across passes; it keeps only the apps of this pass.
pub(super) fn build(
    source: &str,
    settings: &Settings,
    containers: &[Container],
    first_seen: &mut BTreeMap<Box<str>, u64>,
) -> Built {
    let mut built = Built::default();
    let mut serving: Vec<&Container> = containers
        .iter()
        .filter(|container| container.readiness == Readiness::Serving)
        .collect();
    serving.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));

    let mut groups: BTreeMap<Box<str>, Vec<Candidate<'_>>> = BTreeMap::new();
    for container in serving {
        let enable = container
            .labels
            .get("podgate.enable")
            .or_else(|| container.labels.get("traefik.enable"));
        let exposed = match enable.map(String::as_str) {
            Some(value) if value.eq_ignore_ascii_case("false") => false,
            // Any other value is for the label parser to reject, with a report.
            Some(_) => true,
            None => settings.exposed_by_default,
        };
        if !exposed {
            continue;
        }
        match candidate(settings, container) {
            Ok(candidate) => {
                for problem in &candidate.labels.problems {
                    built.reports.push(report(container, &problem.to_string()));
                }
                groups
                    .entry(candidate.app.clone())
                    .or_default()
                    .push(candidate);
            }
            Err(why) => built.reports.push(report(container, &why)),
        }
    }

    let mut seen = BTreeMap::new();
    for (app, candidates) in groups {
        let members: Vec<Member<'_>> = candidates
            .iter()
            .map(|candidate| Member {
                name: &candidate.container.name,
                labels: &candidate.labels,
                server: candidate.server,
                claim: &candidate.claim,
                created: candidate.container.created,
            })
            .collect();
        let assembled = match labels::assemble(&app, &members) {
            Ok(assembled) => assembled,
            Err(why) => {
                for candidate in &candidates {
                    built
                        .reports
                        .push(report(candidate.container, &why.to_string()));
                }
                continue;
            }
        };
        for (index, why) in &assembled.rejected {
            built
                .reports
                .push(report(candidates[*index].container, &why.to_string()));
        }
        let rejected: BTreeSet<usize> =
            assembled.rejected.iter().map(|(index, _)| *index).collect();
        let oldest = candidates
            .iter()
            .enumerate()
            .filter(|(index, _)| !rejected.contains(index))
            .map(|(_, candidate)| candidate.container.created)
            .min()
            .unwrap_or(0);
        let first = *first_seen.get(&app).unwrap_or(&oldest);
        seen.insert(app.clone(), first);
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                object: app,
                first_seen: first,
            },
            tenant: assembled.claim,
            app: assembled.app,
        });
    }
    *first_seen = seen;
    built
}

fn report(container: &Container, why: &str) -> Box<str> {
    let short: String = container.id.chars().take(12).collect();
    format!("container {} ({short}): {why}", container.name).into()
}

/// The labels, address and tenant claim of one container, or why it is not used.
fn candidate<'a>(settings: &Settings, container: &'a Container) -> Result<Candidate<'a>, String> {
    let labels = labels::parse(
        container
            .labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
    .map_err(|why| why.to_string())?;
    let app = match &labels.app {
        Some(app) => app.clone(),
        None => {
            let default = container
                .labels
                .get(COMPOSE_SERVICE)
                .map_or(&*container.name, String::as_str);
            labels::identifier("app", default).map_err(|why| why.to_string())?
        }
    };
    let port = labels
        .port
        .ok_or("podgate.port: is required, the port the container listens on")?;

    let reachable: Vec<(&str, std::net::IpAddr)> = settings
        .networks
        .iter()
        .filter_map(|network| {
            let address = container.networks.get(network).copied().flatten()?;
            Some((network.as_str(), address))
        })
        .collect();
    let Some(&(_, address)) = reachable.first() else {
        let attached: Vec<&str> = container.networks.keys().map(String::as_str).collect();
        return Err(format!(
            "skipped: no address on {} (attached to {attached:?}); a server is only ever the container's address on a configured network",
            settings.networks.join(" or ")
        ));
    };

    let names: Vec<&str> = reachable.iter().map(|(network, _)| *network).collect();
    let claim = settings.tenants.claim(&names, labels.tenant.as_deref())?;
    Ok(Candidate {
        container,
        labels,
        app,
        server: SocketAddr::new(address, port),
        claim,
    })
}
