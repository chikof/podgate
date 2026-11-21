//! The `mirroring` service: every request goes to one service, and a copy of a percentage of them
//! goes to others, whose answers are thrown away. Full reference: `docs/ref/svc-mirroring.md`.
//!
//! ```json
//! { "name": "m", "type": "mirroring", "service": "web",
//!   "mirrors": [ { "service": "web@r2", "percent": 10 } ],
//!   "mirror_body": true, "max_body_size": 65536, "mirror_timeout_secs": 10 }
//! ```
//!
//! The mirroring service has no server of its own. A router that names it is answered by
//! `service` (a `loadbalancer`, `weighted` or `failover` service of the revision the request picked, else of the app), exactly as
//! if the router had named that service; the copies are an addition that can never change the
//! answer. A mirror target is a `loadbalancer` of the same app, `name` (in the revision the
//! request picked) or `name@revision`; a `static` service or another `mirroring` service is
//! `invalid_service`, because a copy of a request needs a server to dial and a graph of mirrors
//! has no use. The names are resolved when the snapshot compiles (`unknown_service`), per
//! revision, into a [`Plan`] the table keeps next to the route.
//!
//! What a mirror may cost is bounded: see `run` (admission, sampling, the body copy) and
//! `send` (the one HTTP/1.1 exchange). `percent` takes decimals down to `0.0001`; `0` mirrors
//! nothing and `100` mirrors everything.

mod run;
mod send;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

pub use run::{State, begin, finish, render, tee};

use super::{Named, Service};
use crate::compile::Invalid;
use crate::table::ServiceRef;
use podgate_model::Declared;

/// What a copy of the request head may weigh, charged to the tenant before the head is copied: a
/// request whose head is larger is not mirrored.
pub(crate) const HEAD_ALLOWANCE: u64 = 16 * 1024;
/// The default `max_body_size`.
const DEFAULT_MAX_BODY: u64 = 1024 * 1024;
/// The largest `max_body_size`.
const MAX_BODY: u64 = 16 * 1024 * 1024;
/// The default `mirror_timeout_secs`.
const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// The largest `mirror_timeout_secs`.
const MAX_TIMEOUT_SECS: u64 = 60;
/// The most mirrors one service declares.
const MAX_MIRRORS: usize = 8;
/// What 100 percent is, in the units sampling uses: `percent` is kept to `0.0001`.
pub(crate) const WHOLE: u32 = 1_000_000;
/// The unit the body copy is charged in: a block is charged before it is allocated.
pub(crate) const BLOCK: u64 = 16 * 1024;

/// The configuration of a `mirroring` service.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The service every request goes to: a `loadbalancer` of the revision, else of the app.
    service: String,
    /// Where copies go.
    mirrors: Vec<MirrorConfig>,
    /// Send the request body to the mirrors too (default `false`).
    #[serde(default)]
    mirror_body: Option<bool>,
    /// The most body bytes that are mirrored, default 1 MiB, at most 16 MiB. Larger bodies are
    /// not mirrored. Needs `mirror_body`.
    #[serde(default)]
    max_body_size: Option<u64>,
    /// How long one copy may take in all, default 10, at most 60.
    #[serde(default)]
    mirror_timeout_secs: Option<u64>,
    /// Send `Authorization`, `Proxy-Authorization` and `Cookie` to the mirrors (default
    /// `false`).
    #[serde(default)]
    forward_credentials: Option<bool>,
}

/// One mirror as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct MirrorConfig {
    /// A `loadbalancer` of the same app: `name`, or `name@revision`.
    service: String,
    /// The share of requests copied, `0` to `100`, down to four decimals.
    percent: f64,
}

/// How copies are made, shared by the plans of one service.
#[derive(Debug)]
pub struct Settings {
    /// Whether the body is copied.
    pub(crate) mirror_body: bool,
    /// The most body bytes copied.
    pub(crate) max_body: u64,
    /// The time one copy may take.
    pub(crate) timeout: Duration,
    /// Whether credential headers are copied.
    pub(crate) forward_credentials: bool,
}

/// A mirror as declared: a name, the revision it names when it names one, and its share.
#[derive(Debug)]
struct MirrorTo {
    name: Box<str>,
    revision: Option<Box<str>>,
    /// The share in millionths of the traffic.
    share: u32,
}

/// A compiled `mirroring` service. It names services; `resolve` turns the names into a
/// [`Plan`] for each revision.
#[derive(Debug)]
pub struct Mirroring {
    name: Box<str>,
    main: Box<str>,
    mirrors: Box<[MirrorTo]>,
    settings: Arc<Settings>,
}

/// The services of one app a mirroring service is resolved in.
pub(crate) struct Scopes<'a> {
    /// The app's own services.
    pub(crate) shared: &'a [Named],
    /// Each revision, in the app's order.
    pub(crate) revisions: &'a [Scope<'a>],
}

/// One revision's part of [`Scopes`].
pub(crate) struct Scope<'a> {
    /// The revision id.
    pub(crate) id: &'a str,
    /// Whether the revision is `draining`: it takes no new request, so a name it lacks is not an
    /// error.
    pub(crate) draining: bool,
    /// The revision's own services.
    pub(crate) own: &'a [Named],
}

impl Scopes<'_> {
    /// `name` as revision `revision` sees it: its own service, else the app's.
    pub(crate) fn find(&self, revision: usize, name: &str) -> Option<ServiceRef> {
        let own = self.revisions.get(revision)?.own;
        own.iter()
            .position(|named| &*named.name == name)
            .map(ServiceRef::Own)
            .or_else(|| {
                self.shared
                    .iter()
                    .position(|named| &*named.name == name)
                    .map(ServiceRef::App)
            })
    }

    pub(crate) fn get(&self, revision: usize, found: ServiceRef) -> Option<&Named> {
        match found {
            ServiceRef::Own(index) => self.revisions.get(revision)?.own.get(index),
            ServiceRef::App(index) => self.shared.get(index),
        }
    }
}

/// Where the copies of one mirroring service go, resolved for one revision.
#[derive(Debug)]
pub struct Plan {
    main: ServiceRef,
    targets: Box<[Target]>,
    settings: Arc<Settings>,
}

/// One resolved mirror.
#[derive(Debug)]
pub struct Target {
    /// The name as declared, `name` or `name@revision`, for logs.
    pub(crate) label: Box<str>,
    /// Index of the revision whose scope holds the service.
    pub(crate) revision: usize,
    /// The service, in that revision's scope.
    pub(crate) service: ServiceRef,
    /// The share in millionths of the traffic.
    pub(crate) share: u32,
}

impl Plan {
    /// The service that answers: the router's requests are served as if it had named this.
    pub(crate) fn main(&self) -> ServiceRef {
        self.main
    }

    /// The mirrors, in declaration order.
    pub(crate) fn targets(&self) -> &[Target] {
        &self.targets
    }

    /// How copies are made.
    pub(crate) fn settings(&self) -> &Settings {
        &self.settings
    }
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_service", format!("mirroring: {}", message.into()))
}

fn unknown(message: impl Into<String>) -> Invalid {
    Invalid::new("unknown_service", format!("mirroring: {}", message.into()))
}

/// `name` or `name@revision`.
fn parse_name(text: &str) -> Result<(&str, Option<&str>), Invalid> {
    let (name, revision) = match text.split_once('@') {
        Some((name, revision)) => (name, Some(revision)),
        None => (text, None),
    };
    if name.is_empty() || revision.is_some_and(|rev| rev.is_empty() || rev.contains('@')) {
        return Err(invalid(format!(
            "service {text:?} is a service name or name@revision"
        )));
    }
    Ok((name, revision))
}

/// `percent` in millionths of the traffic.
fn share_of(percent: f64) -> Result<u32, Invalid> {
    let scaled = percent * 10_000.0;
    let share = scaled.round();
    if !percent.is_finite() || !(0.0..=100.0).contains(&percent) || (scaled - share).abs() > 1e-6 {
        return Err(invalid(format!(
            "percent {percent} is a number from 0 to 100 with at most four decimals"
        )));
    }
    // In range: `0.0..=1_000_000.0` after the check above.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "share is a whole number in 0..=1_000_000"
    )]
    Ok(share as u32)
}

impl Mirroring {
    /// Compiles one declared `mirroring` service: its fields and limits. Names are resolved
    /// later, by [`Self::resolve`], once the app's services exist.
    pub(super) fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let (main, revision) = parse_name(&config.service)?;
        if revision.is_some() {
            return Err(invalid(
                "service names a service of the revision, not name@revision",
            ));
        }
        if config.mirrors.is_empty() || config.mirrors.len() > MAX_MIRRORS {
            return Err(invalid(format!("mirrors lists 1 to {MAX_MIRRORS} entries")));
        }
        let mirror_body = config.mirror_body.unwrap_or(false);
        if config.max_body_size.is_some() && !mirror_body {
            return Err(invalid("max_body_size needs mirror_body: true"));
        }
        let max_body = config.max_body_size.unwrap_or(DEFAULT_MAX_BODY);
        if !(1..=MAX_BODY).contains(&max_body) {
            return Err(invalid(format!("max_body_size is in 1..={MAX_BODY}")));
        }
        let timeout = config.mirror_timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout) {
            return Err(invalid(format!(
                "mirror_timeout_secs is in 1..={MAX_TIMEOUT_SECS}"
            )));
        }
        let mirrors = config
            .mirrors
            .iter()
            .map(|mirror| {
                let (name, revision) = parse_name(&mirror.service)?;
                Ok(MirrorTo {
                    name: name.into(),
                    revision: revision.map(Into::into),
                    share: share_of(mirror.percent)?,
                })
            })
            .collect::<Result<Box<[_]>, Invalid>>()?;
        Ok(Self {
            name: declared.name.clone(),
            main: main.into(),
            mirrors,
            settings: Arc::new(Settings {
                mirror_body,
                max_body,
                timeout: Duration::from_secs(timeout),
                forward_credentials: config.forward_credentials.unwrap_or(false),
            }),
        })
    }

    /// Refuses a copy that could never be charged: its head allowance, and its body cap with
    /// `mirror_body`, are more than the tenant's whole `max_buffer_bytes`. A budget that is only
    /// full right now is not judged here; the copy is shed when its charge is refused.
    ///
    /// # Errors
    ///
    /// `invalid_service` naming the tenant, the bytes a copy needs and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        let body = if self.settings.mirror_body {
            self.settings.max_body
        } else {
            0
        };
        let needed = HEAD_ALLOWANCE + body;
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one mirrored request reserves (max_body_size {body} plus {HEAD_ALLOWANCE}); lower max_body_size or raise the budget"
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// Resolves the names for revision `at` of `scopes`.
    ///
    /// # Errors
    ///
    /// `unknown_service` for a name nothing defines (a revision that is `draining` may lack one),
    /// `invalid_service` for a service that is not a `loadbalancer`, `service_cycle` for a
    /// service that mirrors to itself.
    pub(crate) fn resolve(&self, scopes: &Scopes<'_>, at: usize) -> Result<Option<Plan>, Invalid> {
        let draining = scopes.revisions.get(at).is_none_or(|scope| scope.draining);
        let Some(main) = scopes.find(at, &self.main) else {
            return if draining {
                Ok(None)
            } else {
                Err(unknown(format!(
                    "service {} is defined by neither the revision nor the app",
                    self.main
                )))
            };
        };
        self.check_kind(scopes, at, main, &self.main, true)?;
        let mut targets = Vec::with_capacity(self.mirrors.len());
        for mirror in &self.mirrors {
            let (revision, label) = match &mirror.revision {
                Some(id) => {
                    let Some(revision) =
                        scopes.revisions.iter().position(|scope| scope.id == &**id)
                    else {
                        return Err(unknown(format!("the app has no revision {id}")));
                    };
                    (revision, format!("{}@{id}", mirror.name))
                }
                None => (at, mirror.name.to_string()),
            };
            let Some(service) = scopes.find(revision, &mirror.name) else {
                if mirror.revision.is_none() && draining {
                    continue;
                }
                return Err(unknown(format!(
                    "revision {} has no service {}",
                    scopes.revisions.get(revision).map_or("", |scope| scope.id),
                    mirror.name
                )));
            };
            self.check_kind(scopes, revision, service, &mirror.name, false)?;
            if scopes
                .get(revision, service)
                .is_some_and(|named| named.service.servers().iter().any(|server| server.h2c))
            {
                return Err(invalid(format!(
                    "service {} has an h2c:// server: a copy is HTTP/1.1, so it cannot be a mirror",
                    mirror.name
                )));
            }
            targets.push(Target {
                label: label.into(),
                revision,
                service,
                share: mirror.share,
            });
        }
        Ok(Some(Plan {
            main,
            targets: targets.into_boxed_slice(),
            settings: Arc::clone(&self.settings),
        }))
    }

    /// The service `found` (named `name`) must be a `loadbalancer`; the main service may also be
    /// a `weighted` or `failover` one (`graph_ok`), because the router that names the mirroring
    /// service is still the one the posture checks see.
    fn check_kind(
        &self,
        scopes: &Scopes<'_>,
        revision: usize,
        found: ServiceRef,
        name: &str,
        graph_ok: bool,
    ) -> Result<(), Invalid> {
        let Some(named) = scopes.get(revision, found) else {
            return Err(unknown(format!("service {name} is gone")));
        };
        match &named.service {
            Service::LoadBalancer(_) => Ok(()),
            Service::Weighted(_) | Service::Failover(_) if graph_ok => Ok(()),
            Service::Weighted(_) | Service::Failover(_) => Err(invalid(format!(
                "service {name} is a {} service: a mirror is one loadbalancer, so a weighted or failover service is not a mirror",
                named.service.kind()
            ))),
            Service::Static(_) => Err(invalid(format!(
                "service {name} is a static service: a copy of a request needs a server to dial, so a static service is neither mirrored nor a mirror"
            ))),
            Service::Mirroring(_) if *named.name == *self.name => Err(Invalid::new(
                "service_cycle",
                format!("mirroring: service {name} mirrors to itself"),
            )),
            Service::Mirroring(_) => Err(invalid(format!(
                "service {name} is a mirroring service: only a loadbalancer is mirrored or a mirror"
            ))),
        }
    }
}

/// A mirror was added to a service a router uses, or an existing one now copies to a service it
/// did not copy to before.
pub const ADDED: &str = "mirror_added";
/// A mirror of a service a router uses now copies a larger share of the requests.
pub const PERCENT_RAISED: &str = "mirror_percent_raised";
/// Users' `Authorization`, `Cookie` and identity headers now go to the mirrors of a service a
/// router uses (`forward_credentials: true`).
pub const CREDENTIALS_FORWARDED: &str = "mirror_credentials_forwarded";

/// What an app's routed `mirroring` services copy: `(service, mirror as declared) -> share`, and
/// the services that copy credentials to at least one mirror.
fn exposure(app: &crate::table::CompiledApp) -> (BTreeMap<(&str, String), u32>, BTreeSet<&str>) {
    let routed: BTreeSet<&str> = app
        .routers()
        .iter()
        .map(|router| router.service())
        .collect();
    let mut shares = BTreeMap::new();
    let mut credentials = BTreeSet::new();
    let services = app.services().iter().chain(
        app.revisions()
            .iter()
            .flat_map(|revision| revision.services().iter()),
    );
    for named in services.filter(|named| routed.contains(&*named.name)) {
        let Some(mirroring) = named.service.as_mirroring() else {
            continue;
        };
        for mirror in &mirroring.mirrors {
            let label = match &mirror.revision {
                Some(revision) => format!("{}@{revision}", mirror.name),
                None => mirror.name.to_string(),
            };
            let share = shares.entry((&*named.name, label)).or_insert(0);
            *share = (*share).max(mirror.share);
            if mirror.share > 0 && mirroring.settings.forward_credentials {
                credentials.insert(&*named.name);
            }
        }
    }
    (shares, credentials)
}

/// What a plan lists when `candidate` replaces `live` for the same host: mirroring that sends more
/// of what users send to more places. Removing or lowering a mirror is never listed.
pub(crate) fn relaxations(
    live: &crate::table::CompiledApp,
    candidate: &crate::table::CompiledApp,
) -> Vec<&'static str> {
    let (old, old_credentials) = exposure(live);
    let (new, new_credentials) = exposure(candidate);
    let mut kinds = Vec::new();
    if new_credentials
        .iter()
        .any(|name| !old_credentials.contains(name))
    {
        kinds.push(CREDENTIALS_FORWARDED);
    }
    for (key, share) in &new {
        match old.get(key) {
            _ if *share == 0 => {}
            None if !kinds.contains(&ADDED) => kinds.push(ADDED),
            Some(before) if share > before && !kinds.contains(&PERCENT_RAISED) => {
                kinds.push(PERCENT_RAISED);
            }
            _ => {}
        }
    }
    kinds
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::service::resolve::Resolver;

    fn declared(value: Value) -> Declared {
        serde_json::from_value(value).expect("declared")
    }

    fn mirroring(extra: Value) -> Value {
        let mut value = json!({
            "name": "m", "type": "mirroring", "service": "web",
            "mirrors": [{"service": "shadow", "percent": 10}],
        });
        if let (Some(object), Value::Object(extra)) = (value.as_object_mut(), extra) {
            object.extend(extra);
        }
        value
    }

    fn code(value: Value) -> &'static str {
        Mirroring::compile(&declared(value))
            .expect_err("refused")
            .code
    }

    fn lb(name: &str) -> Named {
        Named {
            name: name.into(),
            service: Service::compile(
                &declared(json!({
                    "name": name, "type": "loadbalancer",
                    "servers": [{"url": "http://10.0.0.1:80"}],
                })),
                &[],
                None,
                "t",
                &Resolver::default(),
            )
            .expect("loadbalancer"),
        }
    }

    fn static_site() -> Named {
        let dir = std::env::temp_dir().join(format!("podgate-mirroring-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the root");
        let root = crate::service::StaticRoot::open(&dir).expect("open the root");
        let roots = crate::service::TenantRoots::from([(Box::from("site"), Arc::new(root))]);
        let service = Service::compile(
            &declared(json!({"name": "site", "type": "static", "root": "site"})),
            &[],
            Some(&roots),
            "t",
            &Resolver::default(),
        )
        .expect("static");
        drop(std::fs::remove_dir_all(dir));
        Named {
            name: "site".into(),
            service,
        }
    }

    fn compiled(name: &str, extra: Value) -> Named {
        let mut value = mirroring(extra);
        value["name"] = json!(name);
        Named {
            name: name.into(),
            service: Service::compile(&declared(value), &[], None, "t", &Resolver::default())
                .expect("mirroring"),
        }
    }

    fn mirror(extra: Value) -> Mirroring {
        Mirroring::compile(&declared(mirroring(extra))).expect("compiles")
    }

    #[test]
    fn mirror_config_defaults_and_limits() {
        let compiled = mirror(json!({}));
        let settings = &compiled.settings;
        assert!(!settings.mirror_body && !settings.forward_credentials);
        assert_eq!(settings.max_body, 1024 * 1024);
        assert_eq!(settings.timeout, Duration::from_secs(10));
        assert_eq!(compiled.mirrors[0].share, 100_000);
        assert_eq!(
            code(mirroring(json!({"max_body_size": 10}))),
            "invalid_service"
        );
        assert_eq!(
            code(mirroring(json!({"mirror_body": true, "max_body_size": 0}))),
            "invalid_service"
        );
        assert_eq!(
            code(mirroring(
                json!({"mirror_body": true, "max_body_size": 17 * 1024 * 1024})
            )),
            "invalid_service"
        );
        assert_eq!(
            code(mirroring(json!({"mirror_timeout_secs": 0}))),
            "invalid_service"
        );
        assert_eq!(
            code(mirroring(json!({"mirror_timeout_secs": 61}))),
            "invalid_service"
        );
        assert_eq!(code(mirroring(json!({"mirrors": []}))), "invalid_service");
        assert_eq!(code(mirroring(json!({"nope": 1}))), "invalid_service");
        assert_eq!(
            code(mirroring(json!({"service": "web@r1"}))),
            "invalid_service"
        );
        assert_eq!(code(mirroring(json!({"service": ""}))), "invalid_service");
        let mut many = Vec::new();
        for _ in 0..=MAX_MIRRORS {
            many.push(json!({"service": "s", "percent": 1}));
        }
        assert_eq!(code(mirroring(json!({"mirrors": many}))), "invalid_service");
    }

    #[test]
    fn mirror_config_percent_takes_decimals_and_nothing_else() {
        for (percent, share) in [
            (0.0, 0),
            (0.1, 1_000),
            (30.0, 300_000),
            (100.0, WHOLE),
            (0.0001, 1),
        ] {
            let value = mirroring(json!({"mirrors": [{"service": "s", "percent": percent}]}));
            let compiled = Mirroring::compile(&declared(value)).expect("compiles");
            assert_eq!(compiled.mirrors[0].share, share, "{percent}");
        }
        for percent in [json!(-1), json!(100.1), json!(0.00001), json!("10")] {
            let value = mirroring(json!({"mirrors": [{"service": "s", "percent": percent}]}));
            assert_eq!(code(value), "invalid_service", "{percent}");
        }
        let value = mirroring(json!({"mirrors": [{"service": "s"}]}));
        assert_eq!(code(value), "invalid_service");
        let value = mirroring(json!({"mirrors": [{"service": "s", "percent": 1, "x": 1}]}));
        assert_eq!(code(value), "invalid_service");
        let value = mirroring(json!({"mirrors": [{"service": "a@b@c", "percent": 1}]}));
        assert_eq!(code(value), "invalid_service");
    }

    #[test]
    fn mirror_config_budget_covers_the_head_and_with_mirror_body_the_cap() {
        let bodyless = mirror(json!({}));
        assert!(bodyless.check_budget("t", HEAD_ALLOWANCE).is_ok());
        let err = bodyless
            .check_budget("t", HEAD_ALLOWANCE - 1)
            .expect_err("too small");
        assert_eq!(err.code, "invalid_service");
        assert_eq!(err.details["tenant"], "t");
        assert_eq!(err.details["needed_bytes"], HEAD_ALLOWANCE);
        let with_body = mirror(json!({"mirror_body": true, "max_body_size": 4096}));
        assert!(with_body.check_budget("t", HEAD_ALLOWANCE + 4096).is_ok());
        let err = with_body
            .check_budget("t", HEAD_ALLOWANCE + 4095)
            .expect_err("too small");
        assert_eq!(err.details["needed_bytes"], HEAD_ALLOWANCE + 4096);
    }

    fn scopes<'a>(shared: &'a [Named], revisions: &'a [Scope<'a>]) -> Scopes<'a> {
        Scopes { shared, revisions }
    }

    #[test]
    fn mirror_config_resolves_in_the_revision_then_the_app_and_across_revisions() {
        let shared = [lb("web")];
        let own1 = [lb("shadow")];
        let own2 = [lb("shadow"), lb("only2")];
        let revisions = [
            Scope {
                id: "r1",
                draining: false,
                own: &own1,
            },
            Scope {
                id: "r2",
                draining: false,
                own: &own2,
            },
        ];
        let scopes = scopes(&shared, &revisions);
        let plan = mirror(json!({"mirrors": [
            {"service": "shadow", "percent": 5},
            {"service": "only2@r2", "percent": 7},
        ]}))
        .resolve(&scopes, 0)
        .expect("resolves")
        .expect("a plan");
        assert_eq!(plan.main(), ServiceRef::App(0));
        let targets = plan.targets();
        assert_eq!(
            (targets[0].revision, targets[0].service, &*targets[0].label),
            (0, ServiceRef::Own(0), "shadow")
        );
        assert_eq!(
            (targets[1].revision, targets[1].service, &*targets[1].label),
            (1, ServiceRef::Own(1), "only2@r2")
        );
        let err = |extra: Value, at: usize| {
            mirror(extra)
                .resolve(&scopes, at)
                .expect_err("refused")
                .code
        };
        let nowhere = json!({"mirrors": [{"service": "nowhere", "percent": 5}]});
        assert_eq!(err(nowhere, 0), "unknown_service");
        let missing_here = json!({"mirrors": [{"service": "only2", "percent": 5}]});
        assert_eq!(err(missing_here.clone(), 0), "unknown_service");
        assert!(mirror(missing_here).resolve(&scopes, 1).is_ok());
        let no_revision = json!({"mirrors": [{"service": "shadow@r9", "percent": 5}]});
        assert_eq!(err(no_revision, 0), "unknown_service");
        let no_service = json!({"mirrors": [{"service": "only2@r1", "percent": 5}]});
        assert_eq!(err(no_service, 0), "unknown_service");
        assert_eq!(err(json!({"service": "gone"}), 0), "unknown_service");
    }

    #[test]
    fn mirror_config_refuses_an_h2c_mirror() {
        let h2c = Named {
            name: "shadow".into(),
            service: Service::compile(
                &declared(json!({
                    "name": "shadow", "type": "loadbalancer",
                    "servers": [{"url": "h2c://10.0.0.1:80"}],
                })),
                &[],
                None,
                "t",
                &Resolver::default(),
            )
            .expect("h2c"),
        };
        let shared = [lb("web"), h2c];
        let revisions = [Scope {
            id: "r1",
            draining: false,
            own: &[],
        }];
        let scopes = scopes(&shared, &revisions);
        let err = mirror(json!({})).resolve(&scopes, 0).expect_err("refused");
        assert_eq!(err.code, "invalid_service");
        assert!(err.message.contains("h2c"), "{}", err.message);
    }

    #[test]
    fn mirror_config_a_draining_revision_may_lack_a_name() {
        let shared: [Named; 0] = [];
        let own = [lb("shadow")];
        let revisions = [Scope {
            id: "r1",
            draining: true,
            own: &own,
        }];
        let scopes = scopes(&shared, &revisions);
        assert!(
            mirror(json!({}))
                .resolve(&scopes, 0)
                .expect("no error")
                .is_none()
        );
        let own = [lb("web")];
        let revisions = [Scope {
            id: "r1",
            draining: true,
            own: &own,
        }];
        let scopes = self::scopes(&shared, &revisions);
        let plan = mirror(json!({}))
            .resolve(&scopes, 0)
            .expect("ok")
            .expect("plan");
        assert!(
            plan.targets().is_empty(),
            "the target the revision lacks is dropped"
        );
    }

    #[test]
    fn mirror_config_refuses_static_and_mirroring_as_main_or_target() {
        let site = static_site();
        let shared = [lb("web"), lb("shadow"), site, compiled("other", json!({}))];
        let revisions = [Scope {
            id: "r1",
            draining: false,
            own: &[],
        }];
        let scopes = scopes(&shared, &revisions);
        let code_of = |extra: Value| mirror(extra).resolve(&scopes, 0).expect_err("refused").code;
        assert_eq!(code_of(json!({"service": "site"})), "invalid_service");
        let target = |name: &str| json!({"mirrors": [{"service": name, "percent": 1}]});
        assert_eq!(code_of(target("site")), "invalid_service");
        assert_eq!(code_of(json!({"service": "other"})), "invalid_service");
        assert_eq!(code_of(target("other")), "invalid_service");
        assert_eq!(code_of(target("m@r1")), "unknown_service");
        let itself = [lb("web"), compiled("m", json!({}))];
        let scopes = self::scopes(&itself, &revisions);
        let err = mirror(target("m")).resolve(&scopes, 0).expect_err("cycle");
        assert_eq!(err.code, "service_cycle");
    }
}
