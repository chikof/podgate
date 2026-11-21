//! `http.services`: `loadBalancer`, `weighted`, `mirroring` and `failover` as podgate services
//! (`docs/architecture.md ### Services`).

use std::collections::BTreeMap;

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::flat;
use super::names::{Names, Resolved, valid_name};
use super::obj::{Cx, Obj};

/// The most a mirrored body can be in podgate: 16 MiB.
const MAX_MIRROR_BODY: i64 = 16 * 1024 * 1024;

/// Builds every service of `http.services`. `transports` says which `serversTransport` exist.
pub(super) fn build(
    cx: &Cx,
    group: Vec<(&str, &Value)>,
    transports: &Names,
    out: &mut Vec<Declared>,
) -> Names {
    let mut names = Names::default();
    let mut composites: BTreeMap<&str, (&Value, Kind)> = BTreeMap::new();
    for (name, value) in group {
        if !valid_name(cx, &format!("http.services.{name}"), name) {
            continue;
        }
        names.expect(name);
        let Some(mut obj) = Obj::new(cx, format!("http.services.{name}"), value) else {
            names.settle(name, false);
            continue;
        };
        let present: Vec<Kind> = Kind::ALL
            .into_iter()
            .filter(|kind| obj.has(kind.key()))
            .collect();
        let [kind] = present[..] else {
            obj.invalid(
                "",
                "a service has exactly one of loadBalancer, weighted, mirroring and failover",
            );
            names.settle(name, false);
            continue;
        };
        if kind == Kind::LoadBalancer {
            let built = obj
                .child("loadBalancer")
                .and_then(|lb| load_balancer(cx, name, lb, transports));
            obj.finish();
            names.settle(name, built.is_some());
            out.extend(built);
        } else {
            composites.insert(name, (value, kind));
        }
    }
    // A composite names other services, so it waits until the composites it names are built.
    while !composites.is_empty() {
        let ready: Vec<&str> = composites
            .iter()
            .filter(|(_, (value, kind))| {
                !references(value, *kind)
                    .iter()
                    .any(|reference| composites.contains_key(strip_provider(reference)))
            })
            .map(|(name, _)| *name)
            .collect();
        if ready.is_empty() {
            for (name, _) in std::mem::take(&mut composites) {
                cx.invalid(
                    &format!("http.services.{name}"),
                    "is part of a cycle of services",
                );
                names.settle(name, false);
            }
            break;
        }
        for name in ready {
            let Some((value, kind)) = composites.remove(name) else {
                continue;
            };
            let built = composite(cx, name, value, kind, &names);
            names.settle(name, built.is_some());
            out.extend(built);
        }
    }
    names
}

fn strip_provider(reference: &str) -> &str {
    reference
        .split_once('@')
        .map_or(reference, |(name, _)| name)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    LoadBalancer,
    Weighted,
    Mirroring,
    Failover,
}

impl Kind {
    const ALL: [Self; 4] = [
        Self::LoadBalancer,
        Self::Weighted,
        Self::Mirroring,
        Self::Failover,
    ];

    fn key(self) -> &'static str {
        match self {
            Self::LoadBalancer => "loadBalancer",
            Self::Weighted => "weighted",
            Self::Mirroring => "mirroring",
            Self::Failover => "failover",
        }
    }
}

/// The names a composite service refers to, read loosely: a malformed one is the build's problem.
fn references(value: &Value, kind: Kind) -> Vec<String> {
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    let Some((_, body)) = map
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(kind.key()))
    else {
        return Vec::new();
    };
    let get = |name: &str| -> Option<&Value> {
        body.as_object()?
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    };
    let text = |name: &str| get(name).and_then(Value::as_str).map(str::to_owned);
    let listed = |name: &str, field: &str| -> Vec<String> {
        get(name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| {
                item.as_object()?
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(field))
                    .and_then(|(_, value)| value.as_str())
                    .map(str::to_owned)
            })
            .collect()
    };
    match kind {
        Kind::LoadBalancer => Vec::new(),
        Kind::Weighted => listed("services", "name"),
        Kind::Mirroring => text("service")
            .into_iter()
            .chain(listed("mirrors", "name"))
            .collect(),
        Kind::Failover => text("service")
            .into_iter()
            .chain(text("fallback"))
            .collect(),
    }
}

fn declared(name: &str, kind: &str, config: Map<String, Value>) -> Declared {
    Declared {
        name: name.into(),
        kind: kind.into(),
        config,
    }
}

fn load_balancer(cx: &Cx, name: &str, mut lb: Obj<'_>, transports: &Names) -> Option<Declared> {
    let mark = cx.mark();
    let real = lb.path().to_owned();
    let mut servers = Vec::new();
    let mut weighted = false;
    if let Some(list) = lb.children("servers") {
        for mut server in list {
            let url = server.text("url").and_then(|url| server_url(&server, url));
            let weight = server.number::<u32>("weight");
            server.refuse_if_set(
                "preservePath",
                "podgate sends the request path as it is and has no server path to preserve",
            );
            if weight == Some(0) {
                server.unsupported(
                    "weight",
                    "a weight of 0 means 1 in Traefik and nothing in podgate; write 1, or remove the server",
                );
            }
            server.finish();
            weighted |= weight.is_some_and(|weight| weight != 1);
            servers.push((url, weight.unwrap_or(1)));
        }
    }
    match lb.text("strategy") {
        None | Some("wrr") => {}
        Some(_) => lb.unsupported(
            "strategy",
            "only the weighted round robin (`wrr`) is translated",
        ),
    }
    lb.refuse_if_set(
        "responseForwarding",
        "podgate streams responses as they arrive and has no flush interval",
    );
    let pass_host_header = lb.boolean("passHostHeader");
    let health = lb
        .value("healthCheck")
        .map(|value| (lb.path_of("healthCheck"), value));
    let sticky = lb
        .value("sticky")
        .map(|value| (lb.path_of("sticky"), value));
    let transport = lb.text("serversTransport").and_then(|raw| {
        let at = lb.path_of("serversTransport");
        match transports.resolve(cx, &at, raw, "serversTransport") {
            Resolved::Found(found) => Some(found),
            _ => None,
        }
    });
    lb.finish();
    if !cx.clean_since(mark) {
        return None;
    }
    let mut config = flat::service_options(
        cx,
        name,
        &real,
        pass_host_header,
        health.as_ref().map(|(path, value)| (path.as_str(), *value)),
        sticky.as_ref().map(|(path, value)| (path.as_str(), *value)),
    )?;
    let list: Vec<Value> = servers
        .into_iter()
        .filter_map(|(url, weight)| {
            let url = url?;
            Some(if weighted {
                json!({ "url": url, "weight": weight })
            } else {
                json!({ "url": url })
            })
        })
        .collect();
    config.insert("servers".into(), Value::Array(list));
    if weighted {
        config.insert("algorithm".into(), json!("weighted_round_robin"));
    }
    if let Some(transport) = transport {
        config.insert("transport".into(), json!(transport));
    }
    Some(declared(name, "loadbalancer", config))
}

/// A server URL in podgate's form: `scheme://host[:port]`, nothing else.
fn server_url(server: &Obj<'_>, url: &str) -> Option<String> {
    let parsed = url.parse::<http::Uri>().ok();
    let usable = parsed.as_ref().and_then(|uri| {
        let scheme = uri.scheme_str()?;
        let authority = uri.authority()?;
        let bare_path = matches!(uri.path(), "" | "/") && uri.query().is_none();
        let plain = !authority.as_str().contains('@') && !url.contains('#');
        (matches!(scheme, "http" | "https" | "h2c") && bare_path && plain)
            .then(|| format!("{scheme}://{authority}"))
    });
    if usable.is_none() {
        server.invalid(
            "url",
            format!("{url:?} must be http://, https:// or h2c:// with a host and an optional port, and no path, query or credentials"),
        );
    }
    usable
}

fn composite(cx: &Cx, name: &str, value: &Value, kind: Kind, known: &Names) -> Option<Declared> {
    let mark = cx.mark();
    let mut obj = Obj::new(cx, format!("http.services.{name}"), value)?;
    let mut body = obj.child(kind.key())?;
    let built = match kind {
        Kind::Weighted => weighted(cx, name, &mut body, known),
        Kind::Mirroring => mirroring(cx, name, &mut body, known),
        Kind::Failover => failover(cx, name, &mut body, known),
        Kind::LoadBalancer => None,
    };
    body.finish();
    obj.finish();
    cx.clean_since(mark).then_some(built).flatten()
}

/// A service named by `key` of `obj`, which must be one of the file's.
pub(super) fn service_ref(obj: &mut Obj<'_>, key: &str, known: &Names) -> Option<String> {
    let at = obj.path_of(key);
    let raw = obj.text(key);
    let Some(raw) = raw else {
        if !obj.has(key) {
            obj.invalid(key, "is required");
        }
        return None;
    };
    match known.resolve(obj.cx(), &at, raw, "service") {
        Resolved::Found(found) => Some(found),
        _ => None,
    }
}

/// The `name` of an entry of a list of services.
fn entry_ref(entry: &mut Obj<'_>, known: &Names) -> Option<String> {
    service_ref(entry, "name", known)
}

fn weighted(cx: &Cx, name: &str, body: &mut Obj<'_>, known: &Names) -> Option<Declared> {
    let mut children = Vec::new();
    if let Some(entries) = body.children("services") {
        for mut entry in entries {
            let child = entry_ref(&mut entry, known);
            let weight = entry.number::<u16>("weight").unwrap_or(1);
            entry.finish();
            children.push(json!({ "service": child?, "weight": weight }));
        }
    }
    if children.is_empty() {
        body.invalid("services", "needs at least one service");
        return None;
    }
    let mut config = Map::new();
    config.insert("services".into(), Value::Array(children));
    let sticky = body
        .value("sticky")
        .map(|value| (body.path_of("sticky"), value));
    health_check_is_empty(body);
    if let Some((path, value)) = sticky {
        let real = format!("http.services.{name}.weighted");
        let options = flat::service_options(cx, name, &real, None, None, Some((&path, value)))?;
        if let Some(sticky) = options.get("sticky") {
            config.insert("sticky".into(), sticky.clone());
        }
    }
    Some(declared(name, "weighted", config))
}

fn mirroring(cx: &Cx, name: &str, body: &mut Obj<'_>, known: &Names) -> Option<Declared> {
    let service = service_ref(body, "service", known);
    let mirror_body = body.boolean("mirrorBody").unwrap_or(true);
    let max_body = body.number::<i64>("maxBodySize");
    let mut mirrors = Vec::new();
    if let Some(entries) = body.children("mirrors") {
        for mut entry in entries {
            let target = entry_ref(&mut entry, known);
            let percent = entry.number::<u8>("percent");
            match percent {
                Some(percent) if percent <= 100 => {}
                Some(_) => entry.invalid("percent", "must be 0 to 100"),
                None if !entry.has("percent") => entry.invalid("", "needs a percent"),
                None => {}
            }
            entry.finish();
            mirrors.push(json!({ "service": target?, "percent": percent? }));
        }
    }
    health_check_is_empty(body);
    if mirrors.is_empty() {
        body.invalid("mirrors", "needs at least one mirror");
        return None;
    }
    let mut config = Map::new();
    config.insert("service".into(), json!(service?));
    config.insert("mirrors".into(), Value::Array(mirrors));
    config.insert("mirror_body".into(), json!(mirror_body));
    if mirror_body {
        match max_body {
            Some(limit) if (1..=MAX_MIRROR_BODY).contains(&limit) => {
                config.insert("max_body_size".into(), json!(limit));
            }
            _ => {
                body.unsupported(
                    "maxBodySize",
                    "is required with mirrorBody, from 1 to 16777216: Traefik's default has no limit, podgate caps a mirrored body",
                );
                return None;
            }
        }
    }
    // Traefik copies the request as it is, credentials included; podgate's default does not.
    config.insert("forward_credentials".into(), json!(true));
    let _ = cx;
    Some(declared(name, "mirroring", config))
}

fn failover(cx: &Cx, name: &str, body: &mut Obj<'_>, known: &Names) -> Option<Declared> {
    let service = service_ref(body, "service", known);
    let fallback = service_ref(body, "fallback", known);
    health_check_is_empty(body);
    let _ = cx;
    let mut config = Map::new();
    config.insert("service".into(), json!(service?));
    config.insert("fallback".into(), json!(fallback?));
    // Traefik goes back to the main service as soon as it is healthy; podgate's default holds the
    // fallback for ten seconds.
    config.insert("fallback_hold_secs".into(), json!(0));
    Some(declared(name, "failover", config))
}

/// `healthCheck: {}` switches Traefik's health propagation on, which podgate always does. It has
/// no options, so anything inside is unsupported.
fn health_check_is_empty(body: &mut Obj<'_>) {
    if let Some(check) = body.child("healthCheck") {
        check.finish();
    }
}
