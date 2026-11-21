//! The bridge to the label translator.
//!
//! Traefik's file is a tree and its labels are flat `key=value` pairs, with the same option
//! names. The translator of `podgate_provider::traefik` is reachable through [`translate`] only,
//! so an option tree is flattened to `traefik.http.<group>.<name>.<path>=<value>` pairs and
//! translated one object at a time. Its problems name the key, which is the file's path with a
//! `traefik.` in front, so they are the file's problems once that is taken off.

use podgate_model::Declared;
use serde_json::{Map, Value};

use super::obj::Cx;
use crate::traefik::translate;

/// Flattens `value` into label pairs below `prefix`. `path` is where `value` is in the file, for
/// the problems. A list becomes the comma separated list a label holds, so an item that has a
/// comma in it cannot be carried and is a problem.
pub(super) fn flatten(
    cx: &Cx,
    prefix: &str,
    path: &str,
    value: &Value,
    out: &mut Vec<(String, String)>,
) {
    match value {
        Value::Null => {}
        Value::Object(map) => {
            for (key, value) in map {
                flatten(
                    cx,
                    &format!("{prefix}.{key}"),
                    &format!("{path}.{key}"),
                    value,
                    out,
                );
            }
        }
        Value::Array(items) => {
            let mut texts = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(text) if text.contains(',') => {
                        cx.unsupported(
                            path,
                            "an entry with a comma cannot be carried by the translator, which splits lists at commas; write the middleware in the podgate file format",
                        );
                        return;
                    }
                    Value::String(text) => texts.push(text.clone()),
                    Value::Number(n) => texts.push(n.to_string()),
                    Value::Bool(flag) => texts.push(flag.to_string()),
                    _ => {
                        cx.unsupported(path, "a list of maps is not translated");
                        return;
                    }
                }
            }
            if !texts.is_empty() {
                out.push((prefix.to_owned(), texts.join(",")));
            }
        }
        Value::String(text) => out.push((prefix.to_owned(), text.clone())),
        Value::Bool(flag) => out.push((prefix.to_owned(), flag.to_string())),
        Value::Number(n) => out.push((prefix.to_owned(), n.to_string())),
    }
}

/// Translates one middleware of the label translator's kinds. `options` is the middleware's
/// option tree below its type (`stripPrefix: {...}`), `kind` the type as the file spells it, and
/// `extra` options the caller built itself, as label pairs below the type.
pub(super) fn middleware(
    cx: &Cx,
    name: &str,
    kind: &str,
    options: &Value,
    extra: Vec<(&str, String)>,
) -> Option<Declared> {
    let base = format!("traefik.http.middlewares.{name}.{kind}");
    let path = format!("http.middlewares.{name}.{kind}");
    let mark = cx.mark();
    let mut pairs = Vec::new();
    flatten(cx, &base, &path, options, &mut pairs);
    for (key, value) in extra {
        pairs.push((format!("{base}.{key}"), value));
    }
    if !cx.clean_since(mark) {
        return None;
    }
    if pairs.is_empty() {
        cx.invalid(&path, "has no options, so there is nothing to translate");
        return None;
    }
    let translated = translate(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    let failed = !translated.problems.is_empty();
    cx.adopt(translated.problems, "", "");
    if failed {
        return None;
    }
    translated.middlewares.into_iter().next()
}

/// The `loadbalancer` options the translator knows (`passHostHeader`, `healthCheck`, `sticky`),
/// from the options of the service `name`. `real` is where they are in the file, for the
/// problems: `http.services.<name>.loadBalancer`, or `.weighted` for the sticky cookie of a
/// weighted service.
pub(super) fn service_options(
    cx: &Cx,
    name: &str,
    real: &str,
    pass_host_header: Option<bool>,
    health_check: Option<(&str, &Value)>,
    sticky: Option<(&str, &Value)>,
) -> Option<Map<String, Value>> {
    let label = format!("http.services.{name}.loadBalancer");
    let base = format!("traefik.{label}");
    let mark = cx.mark();
    let mut pairs = Vec::new();
    if let Some(on) = pass_host_header {
        pairs.push((format!("{base}.passHostHeader"), on.to_string()));
    }
    if let Some((path, value)) = health_check {
        flatten(cx, &format!("{base}.healthCheck"), path, value, &mut pairs);
    }
    if let Some((path, value)) = sticky {
        flatten(cx, &format!("{base}.sticky"), path, value, &mut pairs);
        // `cookie: {}` switches the cookie on with its defaults, which a label spells `cookie=true`.
        let empty_cookie = value
            .as_object()
            .and_then(|map| {
                map.iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("cookie"))
            })
            .is_some_and(|(_, cookie)| {
                cookie.is_null() || cookie.as_object().is_some_and(Map::is_empty)
            });
        if empty_cookie {
            pairs.push((format!("{base}.sticky.cookie"), "true".to_owned()));
        }
    }
    if !cx.clean_since(mark) {
        return None;
    }
    let translated = translate(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    let failed = !translated.problems.is_empty();
    cx.adopt(translated.problems, &label, real);
    if failed {
        return None;
    }
    Some(
        translated
            .services
            .into_iter()
            .next()
            .map(|declared| declared.config)
            .unwrap_or_default(),
    )
}

/// The `source` of an `in_flight_req`, from its `sourceCriterion`. The translator reads the
/// criterion of a `rateLimit`, which is the same object, so a rate limit with the smallest
/// bucket is translated and its `source` is what comes back. `at` is where the criterion is.
pub(super) fn source(cx: &Cx, name: &str, at: &str, criterion: Option<&Value>) -> Option<Value> {
    let label = format!("http.middlewares.{name}.rateLimit.sourceCriterion");
    let base = format!("traefik.http.middlewares.{name}.rateLimit");
    let mark = cx.mark();
    let mut pairs = vec![
        (format!("{base}.average"), "1".to_owned()),
        (format!("{base}.burst"), "1".to_owned()),
    ];
    if let Some(criterion) = criterion {
        flatten(
            cx,
            &format!("{base}.sourceCriterion"),
            at,
            criterion,
            &mut pairs,
        );
    }
    if !cx.clean_since(mark) {
        return None;
    }
    let translated = translate(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    let failed = !translated.problems.is_empty();
    cx.adopt(translated.problems, &label, at);
    if failed {
        return None;
    }
    translated
        .middlewares
        .into_iter()
        .next()
        .and_then(|declared| declared.config.get("source").cloned())
}
