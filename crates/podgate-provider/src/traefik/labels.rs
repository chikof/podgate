//! The label tree: `traefik.*` pairs to the routers, services and middlewares of one app.

use std::collections::{BTreeMap, BTreeSet};

use podgate_model::{Declared, Router, TlsMode};
use podgate_rule::{Dialect, parse};
use serde_json::Value;

use super::problem::Problem;
use super::reader::Reader;
use super::{middlewares, services};
use crate::docker::labels::{DEFAULT_SERVICE, looks_like_address};

/// The only provider whose objects a label may name: this container's own.
const OWN_PROVIDER: &str = "docker";

/// Traefik's usual name of the TLS entry point, which podgate's built-in one shares.
const HTTPS_ENTRY_POINT: &str = "websecure";

const MAX_NAME: usize = 63;

/// `(path below the object, label key, value)`.
type Entries<'a> = Vec<(String, &'a str, &'a str)>;

/// What the `traefik.*` labels of one container say, in podgate's terms.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Translation {
    /// `traefik.enable`, when given.
    pub enabled: Option<bool>,
    /// `acme` when a router names a `tls.certresolver`: podgate has one issuer, so the name is
    /// not kept. `None` leaves the choice to the other labels and the default.
    pub tls: Option<TlsMode>,
    /// The port of the services (`loadbalancer.server.port`). A container has one.
    pub port: Option<u16>,
    /// The routers, by name. Priorities are explicit: the label's, else the rule's length.
    pub routers: Vec<Router>,
    /// The middlewares, by name.
    pub middlewares: Vec<Declared>,
    /// The load balancers, by name, without servers.
    pub services: Vec<Declared>,
    /// The scheme (`https` or `h2c`) of the servers of a service, for the services that do not
    /// use plain `http`.
    pub schemes: BTreeMap<Box<str>, Box<str>>,
    /// What was left out, and why. Each router, service or middleware named by a problem is not
    /// in the lists above, and neither is a router that uses it.
    pub problems: Vec<Problem>,
}

/// Translates the `traefik.*` pairs of one object. Pairs whose key does not start with
/// `traefik.` are not this function's and are skipped.
///
/// The pairs are plain key and value strings, so any source whose objects carry them calls this
/// the same way: Docker labels, Nomad service tags (`traefik.http.routers.web.rule=Host(...)`
/// split at the first `=`), Kubernetes annotations.
///
/// Nothing is guessed. A rule or label that podgate cannot express exactly becomes a
/// [`Problem`] naming the label, and the router, service or middleware it belongs to is left
/// out together with every router that names it.
#[must_use]
pub fn translate<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Translation {
    let mut out = Translation::default();
    let mut tree = Tree::default();
    for (key, value) in pairs {
        let Some(prefix) = key.get(..8) else {
            continue;
        };
        if prefix.eq_ignore_ascii_case("traefik.") {
            tree.accept(&mut out, key, &key[8..], value);
        }
    }
    tree.translate(out)
}

#[derive(Default)]
struct Tree<'a> {
    routers: BTreeMap<String, Entries<'a>>,
    services: BTreeMap<String, Entries<'a>>,
    middlewares: BTreeMap<String, Entries<'a>>,
}

impl<'a> Tree<'a> {
    fn accept(&mut self, out: &mut Translation, key: &'a str, rest: &str, value: &'a str) {
        let parts: Vec<&str> = rest.split('.').collect();
        let head = parts[0].to_ascii_lowercase();
        if head == "enable" && parts.len() == 1 {
            match value.trim().to_ascii_lowercase().as_str() {
                "true" => out.enabled = Some(true),
                "false" => out.enabled = Some(false),
                _ => out
                    .problems
                    .push(Problem::invalid(key, "must be true or false").fatal()),
            }
            return;
        }
        if head == "http" && parts.len() >= 4 {
            let group = match parts[1].to_ascii_lowercase().as_str() {
                "routers" => Some(&mut self.routers),
                "services" => Some(&mut self.services),
                "middlewares" => Some(&mut self.middlewares),
                _ => None,
            };
            if let Some(group) = group {
                let name = parts[2];
                if let Some(problem) = bad_name(key, name) {
                    out.problems.push(problem);
                } else {
                    group.entry(name.to_owned()).or_default().push((
                        parts[3..].join(".").to_ascii_lowercase(),
                        key,
                        value,
                    ));
                }
                return;
            }
        }
        let why = match head.as_str() {
            "tcp" | "udp" => {
                "TCP and UDP labels are not translated; declare L4 routers in the file source"
            }
            "http"
                if parts
                    .get(1)
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("serverstransports")) =>
            {
                "serversTransport objects are not translated; declare the transport with podgate.transport.<name>.config"
            }
            "tls" => "TLS stores and options are not translated; podgate has TLS settings per app",
            _ => "podgate has no equivalent of this label",
        };
        out.problems.push(Problem::unsupported_label(key, why));
    }

    fn translate(self, mut out: Translation) -> Translation {
        let mut refs = Refs::default();

        for (name, entries) in self.middlewares {
            let base = format!("traefik.http.middlewares.{name}");
            match middlewares::build(&name, &base, entries) {
                Ok(declared) => {
                    refs.middlewares.insert(name);
                    out.middlewares.push(declared);
                }
                Err(problems) => {
                    refs.bad_middlewares.insert(name);
                    out.problems.extend(problems);
                }
            }
        }

        for (name, entries) in self.services {
            let reader = Reader::new(format!("traefik.http.services.{name}"), entries);
            let service = match services::build(&name, reader) {
                Ok(service) => service,
                Err(problems) => {
                    refs.bad_services.insert(name);
                    out.problems.extend(problems);
                    continue;
                }
            };
            if let Some(port) = service.port {
                if out.port.is_some_and(|known| known != port) {
                    out.problems.push(Problem::invalid(
                        &format!("traefik.http.services.{name}.loadbalancer.server.port"),
                        format!(
                            "a container serves one port and an earlier service uses {}; give each port its own container",
                            out.port.unwrap_or_default()
                        ),
                    ));
                    refs.bad_services.insert(name);
                    continue;
                }
                out.port = Some(port);
            }
            if let Some(scheme) = service.scheme {
                out.schemes.insert(name.as_str().into(), scheme.into());
            }
            refs.services.insert(name);
            out.services.push(service.declared);
        }

        for (name, entries) in self.routers {
            match router(&name, entries, &refs) {
                Ok(built) => {
                    if built.acme {
                        out.tls = Some(TlsMode::Acme);
                    }
                    out.routers.push(built.router);
                }
                Err(problems) => out.problems.extend(problems),
            }
        }
        out
    }
}

/// The names the labels of the container define, and the ones that did not translate.
#[derive(Default)]
struct Refs {
    services: BTreeSet<String>,
    bad_services: BTreeSet<String>,
    middlewares: BTreeSet<String>,
    bad_middlewares: BTreeSet<String>,
}

struct Built {
    router: Router,
    acme: bool,
}

/// What is wrong with the name of a router, service or middleware.
fn bad_name(key: &str, name: &str) -> Option<Problem> {
    if looks_like_address(name) {
        return Some(Problem::address(key, name));
    }
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    (!valid).then(|| {
        Problem::invalid(
            key,
            format!("{name:?} must be 1 to {MAX_NAME} letters, digits, `-` or `_`"),
        )
    })
}

/// A name in a label of this container, without the `@docker` of Traefik's own spelling.
fn own_name<'t>(reader: &mut Reader<'_>, path: &str, text: &'t str) -> Option<&'t str> {
    let key = reader.key_of(path);
    let (name, provider) = match text.split_once('@') {
        Some((name, provider)) => (name, Some(provider)),
        None => (text, None),
    };
    if looks_like_address(text) {
        reader.fail(Problem::address(&key, text));
        return None;
    }
    if provider.is_some_and(|provider| !provider.eq_ignore_ascii_case(OWN_PROVIDER)) {
        reader.fail(Problem::foreign(&key, text));
        return None;
    }
    if let Some(problem) = bad_name(&key, name) {
        reader.fail(problem);
        return None;
    }
    Some(name)
}

fn router(name: &str, entries: Entries<'_>, refs: &Refs) -> Result<Built, Vec<Problem>> {
    let mut reader = Reader::new(format!("traefik.http.routers.{name}"), entries);
    let rule = reader.text("rule");
    if rule.is_none() {
        reader.missing("rule", "is required");
    }
    match reader
        .text("rulesyntax")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("v3" | "default") => {}
        Some("v2") => {
            let key = reader.key_of("rulesyntax");
            reader.fail(Problem::unsupported_rule(
                &key,
                "ruleSyntax v2 is Traefik v2 syntax; podgate translates v3 rules only",
            ));
        }
        Some(_) => {
            let key = reader.key_of("rulesyntax");
            reader.fail(Problem::invalid(&key, "must be v2 or v3"));
        }
    }
    let priority = reader.number::<i64>("priority").and_then(|priority| {
        let fitted = i32::try_from(priority).ok();
        if fitted.is_none() {
            let key = reader.key_of("priority");
            reader.fail(Problem::invalid(&key, "does not fit in 32 bits"));
        }
        fitted
    });
    let entry_points = reader.list("entrypoints").map(|list| {
        list.into_iter()
            .filter_map(|entry| {
                let key = reader.key_of("entrypoints");
                match bad_name(&key, entry) {
                    Some(problem) => {
                        reader.fail(problem);
                        None
                    }
                    None => Some(Box::<str>::from(entry)),
                }
            })
            .collect::<Vec<_>>()
    });
    let service = reader.text("service");
    let chain = reader.list("middlewares");
    let tls = reader.boolean("tls");
    let resolver = reader.text("tls.certresolver");
    reader.refuse(
        "tls.options",
        "TLS options are per host in podgate, which the handshake decides before any router; use a separate host",
    );
    reader.refuse_under(
        "tls.domains",
        "podgate issues certificates for the hosts the router matches",
    );
    reader.refuse_under(
        "observability",
        "podgate sets observability per router with podgate.router.<name>.*",
    );

    let mut matcher = None;
    let mut len = 0;
    if let Some(rule) = rule {
        let key = reader.key_of("rule");
        match parse(rule, Dialect::Http) {
            Ok(parsed) => {
                len = parsed.len;
                matcher = parsed.matcher;
                for host in hosts(matcher.as_ref()) {
                    if looks_like_address(&host) {
                        reader.fail(Problem::address(&key, &host));
                    }
                }
            }
            Err(why) => reader.fail(Problem::unsupported_rule(&key, why.to_string())),
        }
    }

    let service = match service {
        Some(text) => own_name(&mut reader, "service", text).and_then(|name| {
            if refs.services.contains(name) {
                Some(name.to_owned())
            } else if refs.bad_services.contains(name) {
                let key = reader.key_of("service");
                reader.fail(Problem::unsupported_label(
                    &key,
                    format!("the service {name:?} was not translated, see its own labels"),
                ));
                None
            } else {
                let key = reader.key_of("service");
                reader.fail(Problem::foreign(&key, name));
                None
            }
        }),
        None => match (refs.services.len(), refs.bad_services.is_empty()) {
            (1, true) => refs.services.first().cloned(),
            (0, true) => Some(DEFAULT_SERVICE.to_owned()),
            _ => {
                reader.missing(
                    "service",
                    "is required: the labels define several services, or one that did not translate",
                );
                None
            }
        },
    };

    let mut chosen = Vec::new();
    for text in chain.unwrap_or_default() {
        let Some(name) = own_name(&mut reader, "middlewares", text) else {
            continue;
        };
        if refs.middlewares.contains(name) {
            chosen.push(Box::<str>::from(name));
        } else {
            let key = reader.key_of("middlewares");
            if refs.bad_middlewares.contains(name) {
                reader.fail(Problem::unsupported_label(
                    &key,
                    format!(
                        "the middleware {name:?} was not translated, so this router is left out rather than served without it"
                    ),
                ));
            } else {
                reader.fail(Problem::foreign(&key, name));
            }
        }
    }

    reader.finish()?;
    let (Some(matcher), Some(service)) = (matcher, service) else {
        return Err(vec![Problem::invalid(
            &format!("traefik.http.routers.{name}.rule"),
            "has no matcher",
        )]);
    };
    let secure = tls.unwrap_or(false) || resolver.is_some();
    let entry_points = match entry_points {
        None if secure => Some(vec![Box::<str>::from(HTTPS_ENTRY_POINT)]),
        other => other,
    };
    Ok(Built {
        router: Router {
            name: name.into(),
            entry_points,
            matcher,
            priority: Some(priority.unwrap_or_else(|| i32::try_from(len).unwrap_or(i32::MAX))),
            chain: chosen,
            service: service.as_str().into(),
            observability: None,
            declared_by: None,
        },
        acme: resolver.is_some(),
    })
}

/// The literal host names of the `host` leaves of a matcher.
fn hosts(matcher: Option<&Value>) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending: Vec<&Value> = matcher.into_iter().collect();
    while let Some(node) = pending.pop() {
        let Value::Object(map) = node else {
            continue;
        };
        for (key, value) in map {
            match (key.as_str(), value) {
                ("host", Value::String(name)) => found.push(name.clone()),
                ("host", Value::Array(names)) => {
                    found.extend(
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_owned)),
                    );
                }
                ("all" | "any", Value::Array(items)) => pending.extend(items),
                ("not", inner) => pending.push(inner),
                _ => {}
            }
        }
    }
    found
}
