//! Which tasks of a service serve, and in `tasks` mode their addresses on the configured
//! network.
//!
//! A task serves when it is running (and healthy when the engine reports a health status) on a
//! node that is not known to be down. A task is a server only through the address the engine gave
//! it on a configured network; an address anywhere else is never used.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::model::{Readiness, Service, Task};
use super::{Backend, Settings};

/// The tasks of `service` that serve, oldest slot first, and a line for each one that is skipped
/// for a reason the operator can fix.
///
/// `down` holds the ids of the nodes the engine reports as anything but `ready`. A task on such a
/// node keeps the state it had when the node was lost until the orchestrator replaces it, so the
/// state alone would send traffic to an address nobody answers on.
pub(super) fn serving<'t>(
    service: &Service,
    tasks: &[&'t Task],
    down: &BTreeSet<&str>,
) -> (Vec<&'t Task>, Vec<String>) {
    let mut serving: Vec<&Task> = Vec::new();
    let mut reports = Vec::new();
    for &task in tasks {
        if task.readiness != Readiness::Serving {
            continue;
        }
        if down.contains(&*task.node_id) {
            reports.push(format!(
                "task {}: skipped: its node {} is not ready",
                name(service, task),
                short(&task.node_id)
            ));
            continue;
        }
        serving.push(task);
    }
    serving.sort_by(|a, b| (a.slot, &a.id).cmp(&(b.slot, &b.id)));
    (serving, reports)
}

/// One backend per serving task: its address on the first configured network it has one on.
pub(super) fn backends(
    settings: &Settings,
    service: &Service,
    serving: &[&Task],
) -> (Vec<Backend>, Vec<String>) {
    let mut found = Vec::new();
    let mut reports = Vec::new();
    for task in serving {
        let reachable: Vec<(&str, IpAddr)> = settings
            .networks
            .iter()
            .filter_map(|network| {
                let attached = task.attachments.iter().find(|attached| {
                    attached.address.is_some()
                        && (*attached.network_name == **network
                            || *attached.network_id == **network)
                })?;
                Some((network.as_str(), attached.address?))
            })
            .collect();
        let Some(&(_, address)) = reachable.first() else {
            let attached: Vec<&str> = task
                .attachments
                .iter()
                .map(|attached| &*attached.network_name)
                .collect();
            reports.push(format!(
                "task {}: skipped: no address on {} (attached to {attached:?}); a server is only ever the task's address on a configured network, so podgate must share an overlay network with the service",
                name(service, task),
                settings.networks.join(" or ")
            ));
            continue;
        };
        found.push(Backend {
            name: name(service, task),
            address,
            networks: reachable
                .iter()
                .map(|(network, _)| (*network).to_owned())
                .collect(),
        });
    }
    (found, reports)
}

/// `<service>.<slot>`, the name `docker service ps` shows, or the task id of a global service.
fn name(service: &Service, task: &Task) -> String {
    match task.slot {
        Some(slot) => format!("{}.{slot}", service.name),
        None => format!("{}.{}", service.name, short(&task.id)),
    }
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}
