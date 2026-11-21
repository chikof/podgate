//! `vip` mode: the service's virtual IP on the configured network is the one server, and the
//! Swarm routing mesh balances between the tasks behind it.
//!
//! podgate cannot see which task answers, so it has no per-task health check and no outlier
//! detection in this mode. It still asks that at least one task serves, so a service scaled to
//! zero or without a healthy task has no server instead of a dead address.

use std::collections::{BTreeMap, BTreeSet};

use super::model::{Network, Service, Task};
use super::{Backend, Settings};

/// For each configured network, the ids the engine knows it by: a service's virtual IP names
/// its network by id only.
///
/// The ids come from the engine's network list and from the attachments of every task, so a
/// socket proxy that hides `/networks` still works for services that have tasks. A name or id can
/// belong to more than one network (a local and a swarm one): a virtual IP only carries the id of
/// a swarm network, so every id of the name is a candidate and none can be another network's.
pub(super) fn network_ids<'a>(
    settings: &'a Settings,
    networks: &'a [Network],
    tasks: &'a [Task],
) -> BTreeMap<&'a str, BTreeSet<&'a str>> {
    let mut ids: BTreeMap<&str, BTreeSet<&str>> = settings
        .networks
        .iter()
        .map(|network| (network.as_str(), BTreeSet::new()))
        .collect();
    for (configured, found) in &mut ids {
        for network in networks {
            if *network.name == **configured || *network.id == **configured {
                found.insert(&network.id);
            }
        }
        for attached in tasks.iter().flat_map(|task| &task.attachments) {
            if *attached.network_name == **configured || *attached.network_id == **configured {
                found.insert(&attached.network_id);
            }
        }
    }
    ids
}

/// The backend of `service`, `Ok(None)` when no task serves.
///
/// # Errors
///
/// Why the service has no virtual IP on a configured network.
pub(super) fn backend(
    settings: &Settings,
    service: &Service,
    serving: &[&Task],
    ids: &BTreeMap<&str, BTreeSet<&str>>,
) -> Result<Option<Backend>, String> {
    if serving.is_empty() {
        return Ok(None);
    }
    let reachable: Vec<(&str, std::net::IpAddr)> = settings
        .networks
        .iter()
        .filter_map(|network| {
            let known = ids.get(network.as_str())?;
            let address = service
                .virtual_ips
                .iter()
                .find(|(id, _)| known.contains(&***id))
                .and_then(|(_, address)| *address)?;
            Some((network.as_str(), address))
        })
        .collect();
    let Some(&(_, address)) = reachable.first() else {
        return Err(format!(
            "skipped: no virtual IP on {}; a service in endpoint_mode dnsrr has none, and a server is only ever the service's own virtual IP on a configured network (endpoint = \"tasks\" uses the tasks' addresses instead)",
            settings.networks.join(" or ")
        ));
    };
    Ok(Some(Backend {
        name: service.name.to_string(),
        address,
        networks: reachable
            .iter()
            .map(|(network, _)| (*network).to_owned())
            .collect(),
    }))
}
