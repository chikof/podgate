//! `http.middlewares` and `tcp.middlewares`.
//!
//! The kinds the label translator has (`stripPrefix` to `circuitBreaker`) go through it, so a
//! file and a label say the same thing in the same words. The kinds it has not, because they
//! name an address, a file or a nested object that a label cannot carry (`forwardAuth`,
//! `digestAuth`, `buffering`, `errors`, `passTLSClientCert`, `grpcWeb`, `contentType`,
//! `inFlightReq`, `chain`), are read here, option by option, so an option nobody reads is
//! reported with its path.

use std::collections::{BTreeMap, BTreeSet};

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::files;
use super::flat;
use super::names::{Names, Resolved, valid_name};
use super::obj::{Cx, Obj};
use super::service::service_ref;
use super::transport::pem_of;

/// The kinds of the label translator.
const TRANSLATED: [&str; 14] = [
    "stripprefix",
    "stripprefixregex",
    "addprefix",
    "replacepath",
    "replacepathregex",
    "redirectscheme",
    "redirectregex",
    "headers",
    "compress",
    "ratelimit",
    "ipallowlist",
    "basicauth",
    "retry",
    "circuitbreaker",
];

/// Where the middlewares go.
pub(super) struct Sinks<'s> {
    pub(super) middlewares: &'s mut Vec<Declared>,
    /// The transports of the app, which a `forwardAuth` with a `tls` section adds one to.
    pub(super) transports: &'s mut Vec<Declared>,
    /// Every transport name in use, whatever its protocol.
    pub(super) taken: &'s mut BTreeSet<String>,
}

fn declared(name: &str, kind: &str, config: Map<String, Value>) -> Declared {
    Declared {
        name: name.into(),
        kind: kind.into(),
        config,
    }
}

/// Builds `http.middlewares`. `services` are the services of the file, for `errors`.
pub(super) fn build_http(
    cx: &Cx,
    group: Vec<(&str, &Value)>,
    services: &Names,
    sinks: &mut Sinks<'_>,
) -> Names {
    let mut names = Names::default();
    let mut chains: BTreeMap<&str, &Value> = BTreeMap::new();
    for (name, value) in group {
        if !valid_name(cx, &format!("http.middlewares.{name}"), name) {
            continue;
        }
        names.expect(name);
        let Some(mut obj) = Obj::new(cx, format!("http.middlewares.{name}"), value) else {
            names.settle(name, false);
            continue;
        };
        let Some((kind, options)) = obj.sole("types") else {
            names.settle(name, false);
            continue;
        };
        if kind.eq_ignore_ascii_case("chain") {
            chains.insert(name, options);
            continue;
        }
        let built = single(cx, name, kind, options, services, sinks);
        names.settle(name, built.is_some());
        sinks.middlewares.extend(built);
    }
    // A chain names other middlewares, so it waits for the chains it names.
    while !chains.is_empty() {
        let ready: Vec<&str> = chains
            .iter()
            .filter(|(_, options)| {
                !chain_refs(options)
                    .iter()
                    .any(|reference| chains.contains_key(strip_provider(reference)))
            })
            .map(|(name, _)| *name)
            .collect();
        if ready.is_empty() {
            for (name, _) in std::mem::take(&mut chains) {
                cx.invalid(
                    &format!("http.middlewares.{name}.chain"),
                    "is part of a cycle of chains",
                );
                names.settle(name, false);
            }
            break;
        }
        for name in ready {
            let Some(options) = chains.remove(name) else {
                continue;
            };
            let built = chain(cx, name, options, &names);
            names.settle(name, built.is_some());
            sinks.middlewares.extend(built);
        }
    }
    names
}

fn strip_provider(reference: &str) -> &str {
    reference
        .split_once('@')
        .map_or(reference, |(name, _)| name)
}

fn chain_refs(options: &Value) -> Vec<String> {
    options
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.eq_ignore_ascii_case("middlewares"))
        .filter_map(|(_, list)| list.as_array())
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn chain(cx: &Cx, name: &str, options: &Value, known: &Names) -> Option<Declared> {
    let mark = cx.mark();
    let mut obj = Obj::new(cx, format!("http.middlewares.{name}.chain"), options)?;
    let at = obj.path_of("middlewares");
    let mut members = Vec::new();
    match obj.texts("middlewares") {
        Some(list) if !list.is_empty() => {
            for (index, raw) in list.into_iter().enumerate() {
                if let Resolved::Found(found) =
                    known.resolve(cx, &format!("{at}[{index}]"), raw, "middleware")
                {
                    members.push(json!(found));
                }
            }
        }
        _ => {
            if !obj.has("middlewares") || !cx.clean_since(mark) {
                obj.invalid("middlewares", "is required");
            } else {
                obj.invalid("middlewares", "is empty");
            }
        }
    }
    obj.finish();
    cx.clean_since(mark).then(|| {
        let mut config = Map::new();
        config.insert("middlewares".into(), Value::Array(members));
        declared(name, "chain", config)
    })
}

fn single(
    cx: &Cx,
    name: &str,
    kind: &str,
    options: &Value,
    services: &Names,
    sinks: &mut Sinks<'_>,
) -> Option<Declared> {
    let lower = kind.to_ascii_lowercase();
    let path = format!("http.middlewares.{name}.{kind}");
    if TRANSLATED.contains(&lower.as_str()) {
        return translated(cx, name, kind, &lower, &path, options);
    }
    let mark = cx.mark();
    let mut obj = Obj::new(cx, path, options)?;
    let (podgate_kind, config) = match lower.as_str() {
        "forwardauth" => ("forward_auth", forward_auth(&mut obj, name, sinks)),
        "digestauth" => ("digest_auth", digest_auth(&mut obj)),
        "buffering" => ("buffering", buffering(&mut obj)),
        "errors" => ("errors", errors(&mut obj, services)),
        "passtlsclientcert" => ("pass_tls_client_cert", pass_tls_client_cert(&mut obj)),
        "grpcweb" => ("grpc_web", grpc_web(&mut obj)),
        "contenttype" => ("content_type", content_type(&mut obj)),
        "inflightreq" => ("in_flight_req", in_flight_req(&mut obj, name)),
        other => {
            let why = match other {
                "ipwhitelist" => "ipWhiteList is deprecated in Traefik; use ipAllowList".to_owned(),
                "plugin" => {
                    "plugins run Go code inside Traefik, which podgate does not host".to_owned()
                }
                _ => format!("podgate has no translation of the middleware type {kind}"),
            };
            obj.cx().unsupported(obj.path(), why);
            return None;
        }
    };
    obj.finish();
    if cx.clean_since(mark) {
        Some(declared(name, podgate_kind, config?))
    } else {
        None
    }
}

/// A kind of the label translator.
fn translated(
    cx: &Cx,
    name: &str,
    kind: &str,
    lower: &str,
    path: &str,
    options: &Value,
) -> Option<Declared> {
    let mut extra = Vec::new();
    let mut inlined = None;
    match lower {
        // `compress: {}` is Traefik's default set; a label cannot be empty, so it says so.
        "compress" if options.is_null() || options.as_object().is_some_and(Map::is_empty) => {
            extra.push(("encodings", "gzip,br,zstd".to_owned()));
        }
        "basicauth" => inlined = Some(inline_users_file(cx, path, options)?),
        _ => {}
    }
    flat::middleware(cx, name, kind, inlined.as_ref().unwrap_or(options), extra)
}

/// `basicAuth` with the entries of its `usersFile` added to `users`, which is how a file says
/// what the label form cannot: the proxy reads the file, and the snapshot carries the entries.
fn inline_users_file(cx: &Cx, path: &str, options: &Value) -> Option<Value> {
    let Value::Object(map) = options else {
        return Some(options.clone());
    };
    let mut map = map.clone();
    let Some(key) = map
        .keys()
        .find(|key| key.eq_ignore_ascii_case("usersfile"))
        .cloned()
    else {
        return Some(Value::Object(map));
    };
    let file = map.remove(&key);
    let file_path = format!("{path}.{key}");
    let spec = match file {
        Some(Value::String(spec)) => spec,
        Some(Value::Null) | None => return Some(Value::Object(map)),
        Some(_) => {
            cx.invalid(&file_path, "must be text");
            return None;
        }
    };
    let entries = users_of(cx, &file_path, &spec)?;
    let users_key = map
        .keys()
        .find(|key| key.eq_ignore_ascii_case("users"))
        .cloned()
        .unwrap_or_else(|| "users".to_owned());
    let mut users = match map.remove(&users_key) {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    users.extend(entries.into_iter().map(Value::String));
    map.insert(users_key, Value::Array(users));
    Some(Value::Object(map))
}

/// The entries of a users file: one per line, blank lines and `#` comments skipped.
fn users_of(cx: &Cx, at: &str, spec: &str) -> Option<Vec<String>> {
    let text = files::read(cx, at, spec)?;
    Some(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect(),
    )
}

fn forward_auth(
    obj: &mut Obj<'_>,
    name: &str,
    sinks: &mut Sinks<'_>,
) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    match obj.text("address") {
        Some(address) => {
            config.insert("address".into(), json!(address));
        }
        None if !obj.has("address") => obj.invalid("address", "is required"),
        None => {}
    }
    if let Some(trust) = obj.boolean("trustForwardHeader") {
        config.insert("trust_forward_header".into(), json!(trust));
    }
    if let Some(headers) = obj.texts("authResponseHeaders") {
        config.insert("response_headers".into(), json!(headers));
    }
    if let Some(regex) = obj.text("authResponseHeadersRegex") {
        let at = obj.path_of("authResponseHeadersRegex");
        if let Err(why) = podgate_rule::check_pattern(regex) {
            obj.cx().report(
                crate::traefik::Code::UnsupportedRule,
                &at,
                format!("regular expression {regex:?}: {why}"),
            );
        }
        config.insert("response_headers_regex".into(), json!(regex));
    }
    if let Some(headers) = obj.texts("authRequestHeaders") {
        config.insert("request_headers".into(), json!(headers));
    }
    obj.refuse_if_set(
        "addAuthCookiesToResponse",
        "podgate never forwards the cookies of the auth answer to the client",
    );
    obj.refuse_if_set(
        "forwardBody",
        "podgate sends no request body to the auth service",
    );
    obj.refuse_if_set(
        "maxBodySize",
        "podgate sends no request body to the auth service",
    );
    obj.refuse_if_set(
        "headerField",
        "podgate has no header for the authenticated user",
    );
    obj.refuse_if_set(
        "preserveLocationHeader",
        "podgate relays the auth answer's headers unchanged",
    );
    obj.refuse_if_set(
        "preserveRequestMethod",
        "podgate always asks the auth service with the method of the request",
    );
    if let Some(mut tls) = obj.child("tls") {
        // The TLS settings of the call are a transport of the app, which the middleware names.
        let transport = format!("{name}-forward-auth");
        let mut settings = Map::new();
        if let Some(ca) = optional_pem(&mut tls, "ca") {
            settings.insert("ca_pem".into(), json!(ca));
        }
        let cert = optional_pem(&mut tls, "cert");
        let key = optional_pem(&mut tls, "key");
        match (cert, key) {
            (Some(cert_pem), Some(key_pem)) => {
                settings.insert(
                    "client_cert".into(),
                    json!({ "cert_pem": cert_pem, "key_pem": key_pem }),
                );
            }
            (None, None) => {}
            _ => tls.invalid("cert", "needs the key as well, and the key the certificate"),
        }
        if let Some(skip) = tls.boolean("insecureSkipVerify") {
            settings.insert("insecure_skip_verify".into(), json!(skip));
        }
        tls.refuse_if_set(
            "caOptional",
            "podgate always verifies the certificate of the auth service",
        );
        tls.finish();
        if sinks.taken.contains(&transport) {
            obj.invalid(
                "tls",
                format!("needs a transport named {transport:?}, which the file already defines"),
            );
        } else if !settings.is_empty() {
            sinks.taken.insert(transport.clone());
            sinks
                .transports
                .push(declared(&transport, "servers_transport", settings));
            config.insert("transport".into(), json!(transport));
        }
    }
    Some(config)
}

/// An optional certificate, key or CA of a `tls` section: a path or the PEM itself.
fn optional_pem(obj: &mut Obj<'_>, key: &str) -> Option<String> {
    obj.has(key).then(|| pem_of(obj, key)).flatten()
}

fn digest_auth(obj: &mut Obj<'_>) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    let mut users: Vec<String> = obj
        .texts("users")
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect();
    let file_at = obj.path_of("usersFile");
    if let Some(spec) = obj.text("usersFile") {
        users.extend(users_of(obj.cx(), &file_at, spec)?);
    }
    if users.is_empty() {
        obj.invalid(
            "users",
            "is required: list the entries, or name a usersFile",
        );
    }
    config.insert("users".into(), json!(users));
    // Traefik's realm is `traefik` unless given, and the entries are written for it.
    config.insert(
        "realm".into(),
        json!(obj.text("realm").unwrap_or("traefik")),
    );
    if let Some(field) = obj.text("headerField") {
        config.insert("header_field".into(), json!(field));
    }
    // Traefik keeps the Authorization header unless told to remove it; podgate's default removes it.
    config.insert(
        "remove_header".into(),
        json!(obj.boolean("removeHeader").unwrap_or(false)),
    );
    Some(config)
}

fn buffering(obj: &mut Obj<'_>) -> Option<Map<String, Value>> {
    /// The largest request body podgate holds before the upstream request.
    const HELD_REQUEST: u64 = 64 * 1024;
    let mut config = Map::new();
    for key in ["memRequestBodyBytes", "memResponseBodyBytes"] {
        obj.refuse_if_set(
            key,
            "podgate buffers in memory only, within the tenant's budget; remove it",
        );
    }
    obj.refuse_if_set(
        "retryExpression",
        "retries are the `retry` middleware, which retries before the upstream has answered",
    );
    let request = obj
        .number::<u64>("maxRequestBodyBytes")
        .filter(|max| *max > 0);
    let response = obj
        .number::<u64>("maxResponseBodyBytes")
        .filter(|max| *max > 0);
    if let Some(max) = request {
        config.insert("max_request_body_bytes".into(), json!(max));
        // Past 64 KiB podgate enforces the limit while the body streams, and does not hold it.
        if max <= HELD_REQUEST {
            config.insert("buffer_request".into(), json!(true));
        }
    }
    if let Some(max) = response {
        config.insert("max_response_body_bytes".into(), json!(max));
        config.insert("buffer_response".into(), json!(true));
    }
    if request.is_none() && response.is_none() {
        obj.invalid(
            "",
            "needs maxRequestBodyBytes or maxResponseBodyBytes: podgate's buffering enforces a limit",
        );
    }
    Some(config)
}

fn errors(obj: &mut Obj<'_>, services: &Names) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    match obj.value("status") {
        Some(Value::Array(items))
            if !items.is_empty() && items.iter().all(|item| item.is_string() || item.is_u64()) =>
        {
            config.insert("status".into(), Value::Array(items.clone()));
        }
        Some(_) => obj.invalid(
            "status",
            "must be a list of codes or ranges such as \"500-599\"",
        ),
        None => obj.invalid("status", "is required"),
    }
    if let Some(service) = service_ref(obj, "service", services) {
        config.insert("service".into(), json!(service));
    }
    match obj.text("query") {
        Some(query) if query.contains("{status_code}") => {
            obj.unsupported("query", "podgate interpolates {status} only");
        }
        Some(query) => {
            config.insert("query".into(), json!(query));
        }
        None if !obj.has("query") => obj.invalid(
            "query",
            "is required: podgate's default page path differs from Traefik's",
        ),
        None => {}
    }
    obj.refuse_if_set(
        "statusRewrites",
        "podgate writes the page with the status it replaces",
    );
    Some(config)
}

/// The Traefik names of `info` fields and the names podgate has for them.
const SUBJECT: [(&str, &str); 8] = [
    ("country", "country"),
    ("province", "province"),
    ("locality", "locality"),
    ("organization", "organization"),
    ("organizationalUnit", "organizational_unit"),
    ("commonName", "common_name"),
    ("serialNumber", "serial_number"),
    ("domainComponent", "domain_component"),
];

fn flags(obj: &mut Obj<'_>, table: &[(&str, &str)]) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, snake) in table {
        if let Some(on) = obj.boolean(key) {
            out.insert((*snake).into(), json!(on));
        }
    }
    out
}

fn pass_tls_client_cert(obj: &mut Obj<'_>) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    if let Some(pem) = obj.boolean("pem") {
        config.insert("pem".into(), json!(pem));
    }
    if let Some(mut info) = obj.child("info") {
        let mut fields = flags(
            &mut info,
            &[
                ("notAfter", "not_after"),
                ("notBefore", "not_before"),
                ("sans", "sans"),
                ("serialNumber", "serial_number"),
            ],
        );
        if let Some(mut subject) = info.child("subject") {
            fields.insert(
                "subject".into(),
                Value::Object(flags(&mut subject, &SUBJECT)),
            );
            subject.finish();
        }
        if let Some(mut issuer) = info.child("issuer") {
            let table: Vec<(&str, &str)> = SUBJECT
                .iter()
                .copied()
                .filter(|(key, _)| *key != "organizationalUnit")
                .collect();
            fields.insert("issuer".into(), Value::Object(flags(&mut issuer, &table)));
            issuer.finish();
        }
        info.finish();
        config.insert("info".into(), Value::Object(fields));
    }
    Some(config)
}

fn grpc_web(obj: &mut Obj<'_>) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    if let Some(origins) = obj.texts("allowOrigins") {
        config.insert("allow_origins".into(), json!(origins));
    }
    Some(config)
}

fn content_type(obj: &mut Obj<'_>) -> Option<Map<String, Value>> {
    if obj.boolean("autoDetect") == Some(true) {
        obj.unsupported(
            "autoDetect",
            "podgate never guesses a content type from the body",
        );
    }
    let mut config = Map::new();
    config.insert("auto_detect".into(), json!(false));
    Some(config)
}

fn in_flight_req(obj: &mut Obj<'_>, name: &str) -> Option<Map<String, Value>> {
    let mut config = Map::new();
    match obj.number::<u32>("amount") {
        Some(amount) if amount > 0 => {
            config.insert("amount".into(), json!(amount));
        }
        Some(_) => obj.invalid("amount", "must be at least 1: Traefik reads 0 as no limit"),
        None if !obj.has("amount") => obj.invalid("amount", "is required"),
        None => {}
    }
    let criterion = obj.value("sourceCriterion");
    let at = obj.path_of("sourceCriterion");
    if let Some(source) = flat::source(obj.cx(), name, &at, criterion) {
        config.insert("source".into(), source);
    }
    Some(config)
}

/// Builds `tcp.middlewares`.
pub(super) fn build_tcp(cx: &Cx, group: Vec<(&str, &Value)>, out: &mut Vec<Declared>) -> Names {
    let mut names = Names::default();
    for (name, value) in group {
        if !valid_name(cx, &format!("tcp.middlewares.{name}"), name) {
            continue;
        }
        names.expect(name);
        let Some(mut obj) = Obj::new(cx, format!("tcp.middlewares.{name}"), value) else {
            names.settle(name, false);
            continue;
        };
        let Some((kind, options)) = obj.sole("types") else {
            names.settle(name, false);
            continue;
        };
        let built = tcp_single(cx, name, kind, options);
        names.settle(name, built.is_some());
        out.extend(built);
    }
    names
}

fn tcp_single(cx: &Cx, name: &str, kind: &str, options: &Value) -> Option<Declared> {
    let path = format!("tcp.middlewares.{name}.{kind}");
    let mark = cx.mark();
    let mut obj = Obj::new(cx, path, options)?;
    let mut config = Map::new();
    let podgate_kind = match kind.to_ascii_lowercase().as_str() {
        "ipallowlist" => {
            match obj.texts("sourceRange") {
                Some(ranges) if !ranges.is_empty() => {
                    config.insert("source_range".into(), json!(ranges));
                }
                _ => obj.invalid("sourceRange", "is required"),
            }
            "ip_allow_list"
        }
        "inflightconn" => {
            match obj.number::<u32>("amount") {
                Some(amount) if amount > 0 => {
                    config.insert("amount".into(), json!(amount));
                }
                Some(_) => obj.invalid("amount", "must be at least 1"),
                None if !obj.has("amount") => obj.invalid("amount", "is required"),
                None => {}
            }
            "in_flight_conn"
        }
        "ipwhitelist" => {
            cx.unsupported(
                obj.path(),
                "ipWhiteList is deprecated in Traefik; use ipAllowList",
            );
            return None;
        }
        _ => {
            cx.unsupported(
                obj.path(),
                format!("podgate has no translation of the TCP middleware type {kind}"),
            );
            return None;
        }
    };
    obj.finish();
    cx.clean_since(mark)
        .then(|| declared(name, podgate_kind, config))
}
