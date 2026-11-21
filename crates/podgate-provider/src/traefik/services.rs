//! `traefik.http.services.<name>.loadbalancer.*`: a service of the container's revision.
//!
//! The servers of the service are never here. The runtime's address for the container and the
//! port are the only server there is, and `loadbalancer.server.url` is refused as an address.

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::problem::Problem;
use super::reader::Reader;

/// A service as translated.
pub(super) struct Service {
    /// The `loadbalancer` service, without servers.
    pub(super) declared: Declared,
    /// `server.scheme`, when it is not `http`.
    pub(super) scheme: Option<&'static str>,
    /// `server.port`.
    pub(super) port: Option<u16>,
}

/// Translates the options of the service `name`.
///
/// # Errors
///
/// Every problem with its labels.
pub(super) fn build(name: &str, mut reader: Reader<'_>) -> Result<Service, Vec<Problem>> {
    let mut config = Map::new();
    let mut scheme = None;

    let port = reader
        .number::<u16>("loadbalancer.server.port")
        .filter(|port| {
            let valid = *port != 0;
            if !valid {
                let key = reader.key_of("loadbalancer.server.port");
                reader.fail(Problem::invalid(&key, "must be a port number, 1 to 65535"));
            }
            valid
        });
    if let Some(text) = reader.text("loadbalancer.server.scheme") {
        scheme = match text.trim().to_ascii_lowercase().as_str() {
            "http" => None,
            "https" => Some("https"),
            "h2c" => Some("h2c"),
            _ => {
                let key = reader.key_of("loadbalancer.server.scheme");
                reader.fail(Problem::invalid(&key, "must be http, https or h2c"));
                None
            }
        };
    }
    for destination in ["loadbalancer.server.url", "loadbalancer.servers"] {
        if let Some(key) = reader.first_under(destination) {
            reader.fail(Problem::address(key, "a server url"));
        }
    }
    if let Some(on) = reader.boolean("loadbalancer.passhostheader") {
        config.insert("pass_host_header".into(), Value::Bool(on));
    }
    reader.refuse(
        "loadbalancer.serverstransport",
        "a serversTransport reference is not translated; declare the transport with podgate.transport.<name>.config and name it in podgate.service.<name>.config",
    );
    if let Some(health) = health_check(&mut reader) {
        config.insert("health_check".into(), health);
    }
    if let Some(sticky) = sticky(&mut reader) {
        config.insert("sticky".into(), sticky);
    }
    reader.finish()?;
    Ok(Service {
        declared: Declared {
            name: name.into(),
            kind: "loadbalancer".into(),
            config,
        },
        scheme,
        port,
    })
}

/// `loadbalancer.healthcheck.*`. Traefik's defaults (30 seconds, 5 seconds, healthy on 200 to
/// 399) are the daemon's too, except that the daemon asks for both durations.
fn health_check(reader: &mut Reader<'_>) -> Option<Value> {
    const PREFIX: &str = "loadbalancer.healthcheck";
    let path = reader.text("loadbalancer.healthcheck.path");
    let interval = reader.seconds("loadbalancer.healthcheck.interval");
    let timeout = reader.seconds("loadbalancer.healthcheck.timeout");
    let method = reader.text("loadbalancer.healthcheck.method");
    let scheme = reader.text("loadbalancer.healthcheck.scheme");
    let hostname = reader.text("loadbalancer.healthcheck.hostname");
    let port = reader.number::<u16>("loadbalancer.healthcheck.port");
    let status = reader.number::<u16>("loadbalancer.healthcheck.status");
    let headers = reader.map("loadbalancer.healthcheck.headers");
    let follow = reader.boolean("loadbalancer.healthcheck.followredirects");
    reader.refuse(
        "loadbalancer.healthcheck.mode",
        "only the HTTP health check is translated",
    );
    if follow == Some(true) {
        let key = reader.key_of("loadbalancer.healthcheck.followredirects");
        reader.fail(Problem::unsupported_label(
            &key,
            "podgate's health check never follows redirects, and Traefik's default is to follow them; set it to false",
        ));
    }
    let present = path.is_some()
        || interval.is_some()
        || timeout.is_some()
        || method.is_some()
        || scheme.is_some()
        || hostname.is_some()
        || port.is_some()
        || status.is_some()
        || !headers.is_empty()
        || follow.is_some();
    if !present {
        return None;
    }
    let Some(path) = path else {
        reader.missing(&format!("{PREFIX}.path"), "is required for a health check");
        return None;
    };
    let mut check = Map::new();
    check.insert("path".into(), json!(path));
    check.insert("interval_secs".into(), json!(interval.unwrap_or(30)));
    check.insert("timeout_secs".into(), json!(timeout.unwrap_or(5)));
    if let Some(method) = method {
        check.insert("method".into(), json!(method));
    }
    if let Some(scheme) = scheme {
        check.insert("scheme".into(), json!(scheme.to_ascii_lowercase()));
    }
    if let Some(hostname) = hostname {
        check.insert("hostname".into(), json!(hostname));
    }
    if let Some(port) = port {
        check.insert("port".into(), json!(port));
    }
    if let Some(status) = status {
        check.insert("expect_status".into(), json!([status]));
    }
    if !headers.is_empty() {
        let headers: Map<String, Value> = headers
            .into_iter()
            .map(|(name, value)| (name, json!(value)))
            .collect();
        check.insert("headers".into(), Value::Object(headers));
    }
    Some(Value::Object(check))
}

/// `loadbalancer.sticky.cookie` and its options.
fn sticky(reader: &mut Reader<'_>) -> Option<Value> {
    let on = reader.boolean("loadbalancer.sticky.cookie");
    let name = reader.text("loadbalancer.sticky.cookie.name");
    let secure = reader.boolean("loadbalancer.sticky.cookie.secure");
    let http_only = reader.boolean("loadbalancer.sticky.cookie.httponly");
    let same_site = reader.text("loadbalancer.sticky.cookie.samesite");
    let max_age = reader.number::<u64>("loadbalancer.sticky.cookie.maxage");
    let path = reader.text("loadbalancer.sticky.cookie.path");
    reader.refuse(
        "loadbalancer.sticky.cookie.domain",
        "podgate's sticky cookie has no Domain attribute",
    );
    if on == Some(false)
        && (name.is_some() || secure.is_some() || http_only.is_some() || same_site.is_some())
    {
        let key = reader.key_of("loadbalancer.sticky.cookie");
        reader.fail(Problem::invalid(&key, "is false but cookie options follow"));
        return None;
    }
    let present = on == Some(true)
        || name.is_some()
        || secure.is_some()
        || http_only.is_some()
        || same_site.is_some()
        || max_age.is_some()
        || path.is_some();
    if !present {
        return None;
    }
    let mut cookie = Map::new();
    if let Some(name) = name {
        cookie.insert("name".into(), json!(name));
    }
    if let Some(secure) = secure {
        cookie.insert("secure".into(), json!(secure));
    }
    if let Some(http_only) = http_only {
        cookie.insert("http_only".into(), json!(http_only));
    }
    if let Some(same_site) = same_site.filter(|text| !text.is_empty()) {
        cookie.insert("same_site".into(), json!(same_site.to_ascii_lowercase()));
    }
    if let Some(max_age) = max_age {
        cookie.insert("max_age_secs".into(), json!(max_age));
    }
    if let Some(path) = path {
        cookie.insert("path".into(), json!(path));
    }
    Some(json!({ "cookie": cookie }))
}
