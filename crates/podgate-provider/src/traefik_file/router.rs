//! Routers: `http.routers`, `tcp.routers` and `udp.routers`.
//!
//! The rule is `podgate_rule::parse`, the grammar of the label translator, so a rule means the
//! same in a file and in a label.

use podgate_rule::{Dialect, parse};
use serde_json::{Map, Value, json};

use super::names::{Names, Resolved, valid_name};
use super::obj::{Cx, Obj};
use super::service::service_ref;
use crate::traefik::Code;

/// Traefik's usual name of the TLS entry point, which podgate's built-in one shares.
const HTTPS_ENTRY_POINT: &str = "websecure";

/// A router that translated, and what the app's TLS has to know about it.
pub(super) struct Built {
    pub(super) name: String,
    pub(super) json: Value,
    /// Set when the router takes TLS.
    pub(super) tls: Option<TlsUse>,
}

/// What a router's `tls` section asks of the app.
pub(super) struct TlsUse {
    /// The named `tls.options`, as written.
    pub(super) options: Option<String>,
    pub(super) passthrough: bool,
}

/// `rule`, `ruleSyntax` and `priority`: the matcher and the rule's length.
fn rule(obj: &mut Obj<'_>, dialect: Dialect) -> Option<(Option<Value>, usize)> {
    let rule = obj.text("rule");
    match obj
        .text("ruleSyntax")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("v3" | "default") => {}
        Some("v2") => obj.cx().report(
            Code::UnsupportedRule,
            &obj.path_of("ruleSyntax"),
            "ruleSyntax v2 is Traefik v2 syntax; podgate translates v3 rules only",
        ),
        Some(_) => obj.invalid("ruleSyntax", "must be v2 or v3"),
    }
    let Some(rule) = rule else {
        if !obj.has("rule") {
            obj.invalid("rule", "is required");
        }
        return None;
    };
    match parse(rule, dialect) {
        Ok(parsed) => Some((parsed.matcher, parsed.len)),
        Err(why) => {
            obj.cx()
                .report(Code::UnsupportedRule, &obj.path_of("rule"), why.to_string());
            None
        }
    }
}

fn priority(obj: &mut Obj<'_>, len: usize) -> i32 {
    match obj.number::<i64>("priority") {
        Some(given) => i32::try_from(given).unwrap_or_else(|_| {
            obj.invalid("priority", "does not fit in 32 bits");
            0
        }),
        None => i32::try_from(len).unwrap_or(i32::MAX),
    }
}

/// The `tls` section of a router: `None` when the router has none.
fn tls(obj: &mut Obj<'_>) -> Option<TlsUse> {
    let present = obj.has("tls");
    let mut section = obj.child("tls");
    if !present {
        return None;
    }
    let mut used = TlsUse {
        options: None,
        passthrough: false,
    };
    if let Some(tls) = section.as_mut() {
        used.options = tls.text("options").map(str::to_owned);
        // podgate has one issuer, so the resolver's name is not kept.
        tls.text("certResolver");
        used.passthrough = tls.boolean("passthrough") == Some(true);
        tls.refuse_if_set(
            "domains",
            "podgate issues certificates for the hosts the router matches",
        );
    }
    if let Some(tls) = section {
        tls.finish();
    }
    Some(used)
}

/// `http.routers.<name>`.
pub(super) fn http(
    cx: &Cx,
    name: &str,
    value: &Value,
    services: &Names,
    middlewares: &Names,
) -> Option<Built> {
    let mark = cx.mark();
    let path = format!("http.routers.{name}");
    if !valid_name(cx, &path, name) {
        return None;
    }
    let mut obj = Obj::new(cx, path, value)?;
    let matched = rule(&mut obj, Dialect::Http);
    let priority = priority(&mut obj, matched.as_ref().map_or(0, |(_, len)| *len));
    let entries = obj.texts("entryPoints");
    let service = service_ref(&mut obj, "service", services);
    let chain = chain_of(&mut obj, middlewares);
    let tls = tls(&mut obj);
    let observability = observability(&mut obj);
    obj.refuse_if_set("parentRefs", "internal to Traefik's own routers");
    obj.finish();
    if !cx.clean_since(mark) {
        return None;
    }
    let (Some((Some(matcher), _)), Some(service)) = (matched, service) else {
        return None;
    };
    // A router that asked for TLS is never served in clear text.
    let entries = match (entries, &tls) {
        (None, Some(_)) => Some(vec![HTTPS_ENTRY_POINT]),
        (given, _) => given,
    };
    let mut router = Map::new();
    router.insert("name".into(), json!(name));
    if let Some(entries) = entries {
        router.insert("entry_points".into(), json!(entries));
    }
    router.insert("match".into(), matcher);
    router.insert("priority".into(), json!(priority));
    router.insert("chain".into(), json!(chain));
    router.insert("service".into(), json!(service));
    if let Some(observability) = observability {
        router.insert("observability".into(), observability);
    }
    Some(Built {
        name: name.to_owned(),
        json: Value::Object(router),
        tls,
    })
}

fn observability(obj: &mut Obj<'_>) -> Option<Value> {
    let mut section = obj.child("observability")?;
    let mut out = Map::new();
    for (key, snake) in [
        ("accessLogs", "access_log"),
        ("metrics", "metrics"),
        ("tracing", "tracing"),
    ] {
        if let Some(on) = section.boolean(key) {
            out.insert(snake.into(), json!(on));
        }
    }
    section.refuse_if_set(
        "traceVerbosity",
        "podgate has one trace verbosity, set for the process",
    );
    section.finish();
    (!out.is_empty()).then_some(Value::Object(out))
}

/// The `middlewares` of a router, in order.
fn chain_of(obj: &mut Obj<'_>, known: &Names) -> Vec<String> {
    let at = obj.path_of("middlewares");
    let mut chain = Vec::new();
    for (index, raw) in obj
        .texts("middlewares")
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        if let Resolved::Found(found) =
            known.resolve(obj.cx(), &format!("{at}[{index}]"), raw, "middleware")
        {
            chain.push(found);
        }
    }
    chain
}

/// The entry points a TCP or UDP router must name: Traefik's default of every entry point is
/// not one podgate can reserve to a tenant.
fn required_entry_points<'a>(obj: &mut Obj<'a>) -> Option<Vec<&'a str>> {
    match obj.texts("entryPoints") {
        Some(list) if !list.is_empty() => Some(list),
        _ => {
            if !obj.has("entryPoints") {
                obj.invalid(
                    "entryPoints",
                    "is required: a TCP or UDP router names the entry points it listens on",
                );
            }
            None
        }
    }
}

/// `tcp.routers.<name>`.
pub(super) fn tcp(
    cx: &Cx,
    name: &str,
    value: &Value,
    services: &Names,
    middlewares: &Names,
) -> Option<Built> {
    let mark = cx.mark();
    let path = format!("tcp.routers.{name}");
    if !valid_name(cx, &path, name) {
        return None;
    }
    let mut obj = Obj::new(cx, path, value)?;
    let matched = rule(&mut obj, Dialect::Tcp);
    obj.refuse(
        "priority",
        "podgate ranks TCP routers by their constraints, not by priority",
    );
    let entries = required_entry_points(&mut obj);
    let service = service_ref(&mut obj, "service", services);
    let chain = chain_of(&mut obj, middlewares);
    let tls = tls(&mut obj);
    obj.finish();
    if !cx.clean_since(mark) {
        return None;
    }
    let (Some((matcher, _)), Some(service), Some(entries)) = (matched, service, entries) else {
        return None;
    };
    let mut router = Map::new();
    router.insert("name".into(), json!(name));
    router.insert("entry_points".into(), json!(entries));
    if let Some(matcher) = matcher {
        router.insert("match".into(), matcher);
    }
    if let Some(tls) = &tls {
        router.insert("tls".into(), json!({ "passthrough": tls.passthrough }));
    }
    if !chain.is_empty() {
        router.insert("chain".into(), json!(chain));
    }
    router.insert("service".into(), json!(service));
    Some(Built {
        name: name.to_owned(),
        json: Value::Object(router),
        tls,
    })
}

/// `udp.routers.<name>`.
pub(super) fn udp(cx: &Cx, name: &str, value: &Value, services: &Names) -> Option<Value> {
    let mark = cx.mark();
    let path = format!("udp.routers.{name}");
    if !valid_name(cx, &path, name) {
        return None;
    }
    let mut obj = Obj::new(cx, path, value)?;
    let entries = required_entry_points(&mut obj);
    let service = service_ref(&mut obj, "service", services);
    obj.finish();
    if !cx.clean_since(mark) {
        return None;
    }
    Some(json!({ "name": name, "entry_points": entries?, "service": service? }))
}
