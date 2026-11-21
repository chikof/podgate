//! From the registrations Nomad lists to the apps the source declares.
//!
//! Which registrations count, which address and port give the server, which tenant they belong
//! to: the decisions that are Nomad's. The tags themselves are read by
//! [`crate::docker::labels`], the same parser the Docker source uses.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use crate::docker::labels::{self, Labels, Member};
use crate::source::{Origin, SourceApp, TenantClaim};

use super::Settings;
use super::model::Instance;

/// The most characters of an app id (`<namespace>.<app>`).
const MAX_ID: usize = 63;

/// The apps of one pass over the registrations, and what was left out and why.
#[derive(Debug, Default)]
pub(super) struct Built {
    pub(super) apps: Vec<SourceApp>,
    /// One line per registration that carries tags but is not used.
    pub(super) reports: Vec<Box<str>>,
}

struct Candidate<'a> {
    instance: &'a Instance,
    /// `service alloc <short id>`: what reports and the member order call it.
    name: String,
    labels: Labels,
    server: SocketAddr,
    claim: TenantClaim,
}

/// Whether a service is worth listing its instances: some instance may carry `podgate.enable`
/// other than `false`, or every service counts. `tags` are the tags of all its instances.
pub(super) fn worth_fetching(tags: &[String], exposed_by_default: bool) -> bool {
    exposed_by_default
        || tags
            .iter()
            .filter_map(|tag| tag.strip_prefix(ENABLE))
            .any(|value| value.trim() != "false")
}

const ENABLE: &str = "podgate.enable=";

/// The `key=value` tags of one registration. A tag is split at the first `=`, so a value may
/// hold more. Every `podgate.*` tag must be a pair, and none may repeat: with a repeated key one
/// value would silently win.
fn pairs(tags: &[String]) -> Result<Vec<(&str, &str)>, String> {
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::with_capacity(tags.len());
    for tag in tags {
        let governed = tag.starts_with("podgate.");
        match tag.split_once('=') {
            Some((key, value)) => {
                if governed && !seen.insert(key) {
                    return Err(format!("{key}: the tag is given more than once"));
                }
                pairs.push((key, value));
            }
            None if governed => {
                return Err(format!("{tag}: a podgate tag must be written key=value"));
            }
            None => {}
        }
    }
    Ok(pairs)
}

fn exposed(pairs: &[(&str, &str)], exposed_by_default: bool) -> bool {
    match pairs.iter().find(|(key, _)| *key == "podgate.enable") {
        Some((_, value)) => value.trim() != "false",
        None => exposed_by_default,
    }
}

/// A name valid as the app part of an id. The label parser's own check is private to it; this one
/// is the same rule.
fn app_name(name: &str) -> Result<Box<str>, String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > MAX_ID
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "app name {name:?}: must be 1 to {MAX_ID} letters, digits, `-`, `_` or `.`"
        ));
    }
    Ok(name.into())
}

/// Builds the apps of `instances`, which belong to the services Nomad lists.
///
pub(super) fn build(source: &str, settings: &Settings, instances: &[Instance]) -> Built {
    let mut built = Built::default();
    let mut ordered: Vec<&Instance> = instances.iter().collect();
    ordered.sort_by(|a, b| (a.created, &a.alloc).cmp(&(b.created, &b.alloc)));

    let mut groups: BTreeMap<Box<str>, Vec<Candidate<'_>>> = BTreeMap::new();
    for instance in ordered {
        let tags = instance.tags.as_deref().unwrap_or_default();
        let candidate = pairs(tags).and_then(|pairs| {
            if exposed(&pairs, settings.exposed_by_default) {
                candidate(settings, instance, &pairs).map(Some)
            } else {
                Ok(None)
            }
        });
        match candidate {
            Ok(Some((id, candidate))) => groups.entry(id).or_default().push(candidate),
            Ok(None) => {}
            Err(why) => built.reports.push(report(instance, &why)),
        }
    }

    for (id, candidates) in groups {
        let members: Vec<Member<'_>> = candidates
            .iter()
            .map(|candidate| Member {
                name: &candidate.name,
                labels: &candidate.labels,
                server: candidate.server,
                claim: &candidate.claim,
                created: candidate.instance.created,
            })
            .collect();
        let assembled = match labels::assemble(&id, &members) {
            Ok(assembled) => assembled,
            Err(why) => {
                for candidate in &candidates {
                    built
                        .reports
                        .push(report(candidate.instance, &why.to_string()));
                }
                continue;
            }
        };
        for (index, why) in &assembled.rejected {
            built
                .reports
                .push(report(candidates[*index].instance, &why.to_string()));
        }
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                object: id,
                first_seen: 0,
            },
            tenant: assembled.claim,
            app: assembled.app,
        });
    }
    built
}

fn report(instance: &Instance, why: &str) -> Box<str> {
    let short: String = instance.alloc.chars().take(8).collect();
    format!(
        "service {}/{} (job {}, alloc {short}): {why}",
        instance.namespace, instance.service, instance.job
    )
    .into()
}

/// The app id, labels, server and tenant claim of one registration, or why it is not used.
fn candidate<'a>(
    settings: &Settings,
    instance: &'a Instance,
    pairs: &[(&str, &str)],
) -> Result<(Box<str>, Candidate<'a>), String> {
    let labels = labels::parse(pairs.iter().copied()).map_err(|why| why.to_string())?;
    if labels.port.is_some() {
        return Err(
            "podgate.port: not used with Nomad; the server is the registration's own address and port"
                .to_owned(),
        );
    }
    let namespace = &*instance.namespace;
    let Some(tenant) = settings.tenants.get(namespace) else {
        return Err(format!(
            "namespace {namespace:?} is not one of the source's namespaces"
        ));
    };
    let name = match &labels.app {
        Some(app) => app.clone(),
        None => app_name(&instance.service)?,
    };
    let id: Box<str> = format!("{namespace}.{name}").into();
    if id.len() > MAX_ID {
        return Err(format!("app id {id:?}: longer than {MAX_ID} characters"));
    }
    let address: IpAddr = instance.address.trim().parse().map_err(|_| {
        format!(
            "registered address {:?} is not an IP address; a server is the registration's own IP address and port",
            instance.address
        )
    })?;
    if instance.port == 0 {
        return Err("the registration has no port".to_owned());
    }
    let claim = {
        let claim = TenantClaim::mapped(tenant);
        match &labels.tenant {
            Some(label) => claim.with_label(label),
            None => claim,
        }
    };
    let short: String = instance.alloc.chars().take(8).collect();
    Ok((
        id,
        Candidate {
            instance,
            name: format!("{} alloc {short}", instance.service),
            labels,
            server: SocketAddr::new(address, instance.port),
            claim,
        },
    ))
}
