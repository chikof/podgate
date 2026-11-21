//! One route to routers, middlewares and services.
//!
//! Each rule of a route has one service (its backends, a `weighted` split of them, or a
//! `mirroring` wrapper) and one chain (its filters, in order). Each match of the rule becomes one
//! router per attachment group, so that every match carries its own precedence; the matches of a
//! rule stay alternatives because they share the service and the chain.
//!
//! Names inside the route's app:
//!
//! | Object | Name |
//! |---|---|
//! | router | `r<rule>m<match>`, plus `g<group>` when the route attaches with different host names |
//! | middleware | `r<rule>f<filter>`, or `r<rule>m<match>f<filter>` when it depends on the match's prefix |
//! | backend service | `<namespace>.<service>.<port>` |
//! | split, mirror | `r<rule>-split`, `r<rule>-mirror` |
//! | no backend | `none`, a `loadbalancer` without servers |

use std::collections::{BTreeMap, BTreeSet};

use podgate_model::{Declared, Router};
use serde_json::{Value, json};

use super::backend::{Backends, Resolved};
use super::filters::{self, Stage};
use super::httproute::{Rule, prefixed};
use super::listener::Attachment;
use super::precedence::{HostRank, Rank};
use super::types::Mirror;
use super::{Kind, Rejection, reject};
use crate::trust::HostPattern;

/// The attachments of a route that share their host names: they become one set of routers, on
/// the entry points of all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// The host names; `None` is every host.
    pub hosts: Option<Vec<HostPattern>>,
    /// The entry points, sorted.
    pub entry_points: Vec<Box<str>>,
}

/// Groups `attachments` by the host names they serve.
#[must_use]
pub fn groups(attachments: &[Attachment]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    for attachment in attachments {
        match groups
            .iter_mut()
            .find(|group| group.hosts == attachment.hosts)
        {
            Some(group) => {
                if !group.entry_points.contains(&attachment.entry_point) {
                    group.entry_points.push(attachment.entry_point.clone());
                    group.entry_points.sort();
                }
            }
            None => groups.push(Group {
                hosts: attachment.hosts.clone(),
                entry_points: vec![attachment.entry_point.clone()],
            }),
        }
    }
    groups
}

/// A router and what ranks it.
#[derive(Debug)]
pub struct Built {
    /// The router, without a priority.
    pub router: Router,
    /// How specific its match is.
    pub rank: Rank,
    /// The rule it came from.
    pub rule: usize,
    /// The match of the rule it came from.
    pub matched: usize,
}

/// A service and the services it names.
#[derive(Debug)]
pub struct Service {
    /// The declaration.
    pub declared: Declared,
    /// The services it routes to.
    pub children: Vec<Box<str>>,
}

/// What translating one route produced.
#[derive(Debug, Default)]
pub struct Draft {
    /// The routers.
    pub routers: Vec<Built>,
    /// The middlewares the routers' chains name.
    pub middlewares: Vec<Declared>,
    /// The services, by name.
    pub services: BTreeMap<Box<str>, Service>,
}

fn declared(value: Value) -> Result<Declared, Rejection> {
    serde_json::from_value(value).map_err(|err| reject("UnsupportedValue", err.to_string()))
}

impl Draft {
    fn add(&mut self, name: &str, value: Value, children: Vec<Box<str>>) -> Result<(), Rejection> {
        let declared = declared(value)?;
        self.services
            .entry(name.into())
            .or_insert(Service { declared, children });
        Ok(())
    }

    fn backend(&mut self, backend: &Resolved) -> Result<(), Rejection> {
        self.add(
            &backend.key,
            json!({
                "name": &*backend.key,
                "type": "loadbalancer",
                "servers": backend.servers.iter().map(|url| json!({ "url": &**url })).collect::<Vec<_>>(),
            }),
            Vec::new(),
        )
    }

    /// A service with no server, for a rule that answers by itself.
    fn nothing(&mut self) -> Result<Box<str>, Rejection> {
        self.add(
            "none",
            json!({ "name": "none", "type": "loadbalancer", "servers": [] }),
            Vec::new(),
        )?;
        Ok("none".into())
    }
}

/// The percent of a mirror filter, `0` to `100` with up to four decimals.
fn percent(mirror: &Mirror) -> Result<Value, Rejection> {
    let bad = |why: &str| reject("UnsupportedValue", format!("RequestMirror: {why}"));
    match (mirror.percent, &mirror.fraction) {
        (Some(_), Some(_)) => Err(bad("percent and fraction are both set")),
        (Some(percent), None) if percent <= 100 => Ok(json!(percent)),
        (Some(_), None) => Err(bad("percent is over 100")),
        (None, Some(fraction)) => {
            let denominator = fraction.denominator.unwrap_or(100);
            if denominator == 0 || fraction.numerator > denominator {
                return Err(bad("fraction is not between 0 and 1"));
            }
            let share = f64::from(fraction.numerator) * 100.0 / f64::from(denominator);
            Ok(json!((share * 10_000.0).round() / 10_000.0))
        }
        (None, None) => Ok(json!(100)),
    }
}

/// The matcher of a router: the host names of the group, then the leaves of the match.
fn matcher(hosts: Option<&[HostPattern]>, leaves: &[Value]) -> Value {
    let mut all: Vec<Value> = Vec::new();
    if let Some(hosts) = hosts {
        let names: Vec<String> = hosts.iter().map(ToString::to_string).collect();
        all.push(match names.as_slice() {
            [one] => json!({ "host": one }),
            _ => json!({ "host": names }),
        });
    }
    all.extend(leaves.iter().cloned());
    match all.len() {
        1 => all.remove(0),
        _ => json!({ "all": all }),
    }
}

/// Translates `rules` of a route of `kind` in `namespace`, attached as `groups`.
///
/// # Errors
///
/// A [`Rejection`] naming the rule that cannot be honoured.
pub fn translate(
    kind: Kind,
    namespace: &str,
    rules: &[Rule],
    groups: &[Group],
    backends: &Backends<'_>,
) -> Result<Draft, Rejection> {
    let grpc = kind == Kind::Grpc;
    let mut draft = Draft::default();
    let mut seen: BTreeSet<(usize, String)> = BTreeSet::new();
    for (r, rule) in rules.iter().enumerate() {
        let place = format!("rules[{r}]");
        let plan = filters::plan(&rule.filters, kind).map_err(|why| prefixed(&place, why))?;
        let resolved: Vec<Resolved> = rule
            .backends
            .iter()
            .map(|backend| backends.resolve(kind, namespace, backend, grpc))
            .collect::<Result<_, _>>()
            .map_err(|why| prefixed(&place, why))?;
        for backend in &resolved {
            draft.backend(backend)?;
        }

        let mut mirrors: Vec<(Box<str>, Value)> = Vec::new();
        for mirror in &plan.mirrors {
            if grpc {
                return Err(prefixed(
                    &place,
                    reject(
                        "UnsupportedValue",
                        "RequestMirror cannot copy gRPC calls: a copy is sent as HTTP/1.1",
                    ),
                ));
            }
            let target = mirror.backend_ref.as_ref().ok_or_else(|| {
                prefixed(
                    &place,
                    reject("UnsupportedValue", "RequestMirror has no backendRef"),
                )
            })?;
            let target = backends
                .resolve(kind, namespace, target, false)
                .map_err(|why| prefixed(&place, why))?;
            if target.servers.iter().any(|url| url.starts_with("h2c://")) {
                return Err(prefixed(
                    &place,
                    reject(
                        "UnsupportedValue",
                        format!(
                            "RequestMirror target {} speaks h2c, and a copy is HTTP/1.1",
                            target.key
                        ),
                    ),
                ));
            }
            draft.backend(&target)?;
            mirrors.push((
                target.key,
                percent(mirror).map_err(|why| prefixed(&place, why))?,
            ));
        }

        // A weight of 0 sends nothing; a rule with nothing to send to answers 500, as the API
        // says, unless a filter (a redirect) answers.
        let live: Vec<&Resolved> = resolved
            .iter()
            .filter(|backend| backend.weight > 0)
            .collect();
        let mut stages: Vec<Stage> = plan.stages.clone();
        let main: Box<str> = match live.as_slice() {
            [] => {
                if !plan.redirects() {
                    stages.push(filters::no_backend());
                }
                draft.nothing()?
            }
            [only] => only.key.clone(),
            many => {
                let name = format!("r{r}-split");
                let mut children = Vec::new();
                let mut entries = Vec::new();
                for backend in many {
                    let weight = u16::try_from(backend.weight).map_err(|_| {
                        prefixed(
                            &place,
                            reject(
                                "UnsupportedValue",
                                format!(
                                    "the weight {} of {} is over 65535",
                                    backend.weight, backend.key
                                ),
                            ),
                        )
                    })?;
                    entries.push(json!({ "service": &*backend.key, "weight": weight }));
                    children.push(backend.key.clone());
                }
                draft.add(
                    &name,
                    json!({ "name": name, "type": "weighted", "services": entries }),
                    children,
                )?;
                name.into()
            }
        };
        let service: Box<str> = if mirrors.is_empty() {
            main
        } else {
            let name = format!("r{r}-mirror");
            let entries: Vec<Value> = mirrors
                .iter()
                .map(|(service, percent)| json!({ "service": &**service, "percent": percent }))
                .collect();
            let mut children: Vec<Box<str>> = mirrors.iter().map(|(key, _)| key.clone()).collect();
            children.push(main.clone());
            draft.add(
                &name,
                json!({ "name": name, "type": "mirroring", "service": &*main,
                        "mirrors": entries, "mirror_body": true }),
                children,
            )?;
            name.into()
        };

        for (m, matched) in rule.matches.iter().enumerate() {
            let mut chain: Vec<Box<str>> = Vec::new();
            for (f, stage) in stages.iter().enumerate() {
                let name: Box<str> = if stage.needs_prefix() {
                    format!("r{r}m{m}f{f}").into()
                } else {
                    format!("r{r}f{f}").into()
                };
                if !draft.middlewares.iter().any(|known| known.name == name) {
                    let middleware = stage
                        .declare(&name, matched.prefix.as_deref())
                        .map_err(|why| prefixed(&format!("{place}.matches[{m}]"), why))?;
                    draft.middlewares.push(middleware);
                }
                chain.push(name);
            }
            for (g, group) in groups.iter().enumerate() {
                let value = matcher(group.hosts.as_deref(), &matched.leaves);
                if !seen.insert((g, value.to_string())) {
                    // The same match twice in one route: the first one serves.
                    continue;
                }
                let name = if groups.len() > 1 {
                    format!("r{r}m{m}g{g}")
                } else {
                    format!("r{r}m{m}")
                };
                let router: Router = serde_json::from_value(json!({
                    "name": name,
                    "match": value,
                    "service": &*service,
                    "chain": chain,
                    "entry_points": group.entry_points,
                }))
                .map_err(|err| reject("UnsupportedValue", err.to_string()))?;
                draft.routers.push(Built {
                    router,
                    rank: Rank {
                        host: HostRank::of(group.hosts.iter().flatten()),
                        path: matched.path,
                        method: matched.method,
                        headers: matched.headers,
                        queries: matched.queries,
                    },
                    rule: r,
                    matched: m,
                });
            }
        }
    }
    Ok(draft)
}
