//! `traefik.http.middlewares.<name>.<type>.*`: Traefik's middleware options as podgate's
//! `Declared` middlewares.
//!
//! Every option is read by name. An option nobody reads is an `unsupported_label` that names its
//! key (see [`Reader`]), so a middleware is either translated whole or not at all, and a router
//! that names a middleware that was not translated is not emitted either.

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::problem::Problem;
use super::reader::Reader;

/// Translates the middleware `name`. `entries` are `(path, key, value)` with the type as the
/// first segment of the path.
///
/// # Errors
///
/// Every problem with its labels.
pub(super) fn build<'a>(
    name: &str,
    base: &str,
    entries: Vec<(String, &'a str, &'a str)>,
) -> Result<Declared, Vec<Problem>> {
    let first_key = entries.first().map_or(base, |(_, key, _)| *key);
    let mut kinds: Vec<&str> = entries
        .iter()
        .filter_map(|(path, _, _)| path.split('.').next())
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    let kind = match kinds.as_slice() {
        [kind] => (*kind).to_owned(),
        _ => {
            let key = first_key;
            return Err(vec![Problem::invalid(
                key,
                format!("a middleware has exactly one type, this one has {kinds:?}"),
            )]);
        }
    };
    let rest: Vec<(String, &str, &str)> = entries
        .into_iter()
        .map(|(path, key, value)| {
            let rest = path
                .strip_prefix(&kind)
                .map(|rest| rest.strip_prefix('.').unwrap_or(rest).to_owned())
                .unwrap_or_default();
            (rest, key, value)
        })
        .collect();
    let mut reader = Reader::new(format!("{base}.{kind}"), rest);
    let (podgate_kind, config) = match kind.as_str() {
        "stripprefix" => ("strip_prefix", strip_prefix(&mut reader)),
        "stripprefixregex" => ("strip_prefix_regex", strip_prefix_regex(&mut reader)),
        "addprefix" => ("add_prefix", add_prefix(&mut reader)),
        "replacepath" => ("replace_path", replace_path(&mut reader)),
        "replacepathregex" => ("replace_path_regex", replace_path_regex(&mut reader)),
        "redirectscheme" => ("redirect_scheme", redirect_scheme(&mut reader)),
        "redirectregex" => ("redirect_regex", redirect_regex(&mut reader)),
        "headers" => ("headers", headers(&mut reader)),
        "compress" => ("compress", compress(&mut reader)),
        "ratelimit" => ("rate_limit", rate_limit(&mut reader)),
        "ipallowlist" => ("ip_allow_list", ip_allow_list(&mut reader)),
        "basicauth" => ("basic_auth", basic_auth(&mut reader)),
        "retry" => ("retry", retry(&mut reader)),
        "circuitbreaker" => ("circuit_breaker", circuit_breaker(&mut reader)),
        other => {
            let reason = match other {
                "forwardauth" => {
                    "forwardauth names an address, which no label may; declare it in the file source"
                        .to_owned()
                }
                "chain" => {
                    "name the middlewares in the router's `middlewares` label, in order".to_owned()
                }
                "ipwhitelist" => "ipwhitelist is deprecated in Traefik; use ipallowlist".to_owned(),
                other => format!("podgate has no translation of the middleware type {other}"),
            };
            return Err(vec![Problem::unsupported_label(first_key, reason)]);
        }
    };
    reader.finish()?;
    Ok(Declared {
        name: name.into(),
        kind: podgate_kind.into(),
        config,
    })
}

type Config = Map<String, Value>;

/// The value of a required option.
fn required<T>(reader: &mut Reader<'_>, path: &str, found: Option<T>) -> Option<T> {
    if found.is_none() && !reader.has(path) {
        reader.missing(path, "is required");
    }
    found
}

fn put(config: &mut Config, key: &str, value: impl Into<Value>) {
    config.insert(key.to_owned(), value.into());
}

/// A regular expression that the daemon's `regex` crate compiles.
fn regex(reader: &mut Reader<'_>, path: &str, pattern: &str) {
    if let Err(why) = podgate_rule::check_pattern(pattern) {
        let key = reader.key_of(path);
        reader.fail(Problem::unsupported_rule(
            &key,
            format!("regular expression {pattern:?}: {why}"),
        ));
    }
}

fn strip_prefix(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let prefixes = reader.list("prefixes");
    if let Some(prefixes) = required(reader, "prefixes", prefixes) {
        put(&mut config, "prefixes", json!(prefixes));
    }
    reader.refuse(
        "forceslash",
        "deprecated in Traefik; podgate's strip_prefix always leaves a path starting with /",
    );
    config
}

fn strip_prefix_regex(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let regexes = reader.list("regex");
    if let Some(regexes) = required(reader, "regex", regexes) {
        for pattern in &regexes {
            regex(reader, "regex", pattern);
        }
        put(&mut config, "regexes", json!(regexes));
    }
    config
}

fn add_prefix(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let prefix = reader.text("prefix");
    if let Some(prefix) = required(reader, "prefix", prefix) {
        put(&mut config, "prefix", prefix);
    }
    config
}

fn replace_path(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let path = reader.text("path");
    if let Some(path) = required(reader, "path", path) {
        put(&mut config, "path", path);
    }
    config
}

fn replace_path_regex(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let pattern = reader.text("regex");
    if let Some(pattern) = required(reader, "regex", pattern) {
        regex(reader, "regex", pattern);
        put(&mut config, "regex", pattern);
    }
    let replacement = reader.text("replacement");
    if let Some(replacement) = required(reader, "replacement", replacement) {
        put(&mut config, "replacement", replacement);
    }
    config
}

fn redirect_scheme(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let scheme = reader.text("scheme");
    if let Some(scheme) = required(reader, "scheme", scheme) {
        put(&mut config, "scheme", scheme);
    }
    if let Some(port) = reader.number::<u16>("port") {
        put(&mut config, "port", port);
    }
    if let Some(permanent) = reader.boolean("permanent") {
        put(&mut config, "permanent", permanent);
    }
    reader.refuse(
        "forcepermanentredirect",
        "podgate's redirect_scheme answers 302, or 301 when permanent",
    );
    config
}

fn redirect_regex(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let pattern = reader.text("regex");
    if let Some(pattern) = required(reader, "regex", pattern) {
        regex(reader, "regex", pattern);
        put(&mut config, "regex", pattern);
    }
    let replacement = reader.text("replacement");
    if let Some(replacement) = required(reader, "replacement", replacement) {
        put(&mut config, "replacement", replacement);
    }
    if let Some(permanent) = reader.boolean("permanent") {
        put(&mut config, "permanent", permanent);
    }
    config
}

/// Header edits: a value that is empty removes the header, as in Traefik.
fn header_edits(reader: &mut Reader<'_>, prefix: &str) -> Option<(Config, Vec<String>)> {
    let headers = reader.map(prefix);
    if headers.is_empty() {
        return None;
    }
    let mut set = Config::new();
    let mut remove = Vec::new();
    for (name, value) in headers {
        if value.is_empty() {
            remove.push(name);
        } else {
            put(&mut set, &name, value);
        }
    }
    Some((set, remove))
}

fn headers(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    if let Some((set, remove)) = header_edits(reader, "customrequestheaders") {
        put(
            &mut config,
            "request",
            json!({ "set": set, "remove": remove }),
        );
    }
    let mut response = Config::new();
    if let Some((set, remove)) = header_edits(reader, "customresponseheaders") {
        put(&mut response, "set", Value::Object(set));
        put(&mut response, "remove", json!(remove));
    }
    let security = security(reader);
    if !security.is_empty() {
        put(&mut response, "security", Value::Object(security));
    }
    if !response.is_empty() {
        put(&mut config, "response", Value::Object(response));
    }
    if let Some(cors) = cors(reader) {
        put(&mut config, "cors", Value::Object(cors));
    }
    reader.refuse(
        "forcestsheader",
        "podgate sends Strict-Transport-Security on TLS connections only",
    );
    config
}

fn security(reader: &mut Reader<'_>) -> Config {
    let mut security = Config::new();
    let seconds = reader.number::<u64>("stsseconds");
    let subdomains = reader.boolean("stsincludesubdomains");
    let preload = reader.boolean("stspreload");
    if let Some(max_age) = seconds.filter(|seconds| *seconds > 0) {
        put(
            &mut security,
            "hsts",
            json!({
                "max_age_secs": max_age,
                "include_subdomains": subdomains.unwrap_or(false),
                "preload": preload.unwrap_or(false),
            }),
        );
    }
    if let Some(on) = reader.boolean("contenttypenosniff") {
        put(&mut security, "content_type_nosniff", on);
    }
    let deny = reader.boolean("framedeny");
    match reader
        .text("customframeoptionsvalue")
        .filter(|text| !text.is_empty())
    {
        Some(value) => put(&mut security, "frame_options", value),
        None if deny == Some(true) => put(&mut security, "frame_options", "DENY"),
        None => {}
    }
    for (path, field) in [
        ("referrerpolicy", "referrer_policy"),
        ("permissionspolicy", "permissions_policy"),
        ("contentsecuritypolicy", "csp"),
        ("contentsecuritypolicyreportonly", "csp_report_only"),
    ] {
        if let Some(value) = reader.text(path).filter(|text| !text.is_empty()) {
            put(&mut security, field, value);
        }
    }
    security
}

fn cors(reader: &mut Reader<'_>) -> Option<Config> {
    let origins = reader.list("accesscontrolalloworiginlist");
    let regexes = reader.list("accesscontrolalloworiginlistregex");
    let methods = reader.list("accesscontrolallowmethods");
    let allow_headers = reader.list("accesscontrolallowheaders");
    let expose = reader.list("accesscontrolexposeheaders");
    let credentials = reader.boolean("accesscontrolallowcredentials");
    let max_age = reader.number::<u64>("accesscontrolmaxage");
    let vary = reader.boolean("addvaryheader");
    if origins.is_none()
        && regexes.is_none()
        && methods.is_none()
        && allow_headers.is_none()
        && expose.is_none()
        && credentials.is_none()
        && max_age.is_none()
        && vary.is_none()
    {
        return None;
    }
    let mut cors = Config::new();
    for (field, list) in [
        ("allow_origins", &origins),
        ("allow_origin_regexes", &regexes),
        ("allow_methods", &methods),
        ("allow_headers", &allow_headers),
        ("expose_headers", &expose),
    ] {
        if let Some(list) = list {
            put(&mut cors, field, json!(list));
        }
    }
    for pattern in regexes.iter().flatten() {
        regex(reader, "accesscontrolalloworiginlistregex", pattern);
    }
    if let Some(credentials) = credentials {
        put(&mut cors, "allow_credentials", credentials);
    }
    if let Some(max_age) = max_age {
        put(&mut cors, "max_age_secs", max_age);
    }
    // Traefik adds `Vary: Origin` only when asked; podgate's default is to add it.
    put(&mut cors, "add_vary", vary.unwrap_or(false));
    Some(cors)
}

fn compress(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let encodings = reader.list("encodings");
    let algorithms: Vec<&str> = match encodings {
        Some(list) => {
            for name in &list {
                if !matches!(*name, "gzip" | "br" | "zstd") {
                    let key = reader.key_of("encodings");
                    reader.fail(Problem::unsupported_label(
                        &key,
                        format!("{name:?} is not gzip, br or zstd"),
                    ));
                }
            }
            list
        }
        // Traefik's default set, in the order it prefers them for an equal quality.
        None => vec!["gzip", "br", "zstd"],
    };
    put(&mut config, "algorithms", json!(algorithms));
    if let Some(min) = reader.number::<u64>("minresponsebodybytes") {
        put(&mut config, "min_bytes", min);
    }
    if let Some(list) = reader.list("includedcontenttypes") {
        put(&mut config, "include_content_types", json!(list));
    }
    if let Some(list) = reader.list("excludedcontenttypes") {
        put(&mut config, "exclude_content_types", json!(list));
    }
    reader.refuse(
        "defaultencoding",
        "podgate answers a request that names no coding it knows without compression",
    );
    config
}

/// `ipstrategy.*` as podgate's `ip_strategy` object, or `None`.
fn ip_strategy(reader: &mut Reader<'_>, prefix: &str) -> Option<Config> {
    let depth = reader.number::<u16>(&format!("{prefix}.depth"));
    let excluded = reader.list(&format!("{prefix}.excludedips"));
    let subnet = reader.number::<u8>(&format!("{prefix}.ipv6subnet"));
    let mut strategy = Config::new();
    // Depth 0 is Traefik's "the connection's peer", which is also podgate's without a depth.
    if let Some(depth) = depth.filter(|depth| *depth > 0) {
        put(&mut strategy, "depth", depth);
    }
    if let Some(excluded) = excluded {
        put(&mut strategy, "excluded", json!(excluded));
    }
    if let Some(subnet) = subnet {
        put(&mut strategy, "ipv6_subnet_bits", subnet);
    }
    Some(strategy).filter(|strategy| !strategy.is_empty())
}

fn rate_limit(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let average = reader.number::<u32>("average");
    let unlimited = "must be at least 1: Traefik reads 0 or nothing as unlimited, and podgate has no limiter that limits nothing";
    match average {
        Some(average) if average > 0 => put(&mut config, "average", average),
        Some(_) => {
            let key = reader.key_of("average");
            reader.fail(Problem::invalid(&key, unlimited));
        }
        None if !reader.has("average") => reader.missing("average", unlimited),
        None => {}
    }
    if let Some(period) = reader.seconds("period") {
        put(&mut config, "period_secs", period);
    }
    put(
        &mut config,
        "burst",
        reader.number::<u32>("burst").unwrap_or(1),
    );

    let strategy = ip_strategy(reader, "sourcecriterion.ipstrategy");
    let header = reader.text("sourcecriterion.requestheadername");
    let host = reader.boolean("sourcecriterion.requesthost");
    let chosen = usize::from(strategy.is_some())
        + usize::from(header.is_some())
        + usize::from(host == Some(true));
    if chosen > 1 {
        let key = reader.key_of("sourcecriterion");
        reader.fail(Problem::invalid(
            &key,
            "name one source criterion: an IP strategy, a request header or the request host",
        ));
    }
    let source = if let Some(name) = header {
        json!({ "header": name })
    } else if host == Some(true) {
        json!({ "host": true })
    } else {
        json!({ "ip": strategy.unwrap_or_default() })
    };
    put(&mut config, "source", source);
    config
}

fn ip_allow_list(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let ranges = reader.list("sourcerange");
    if let Some(ranges) = required(reader, "sourcerange", ranges) {
        put(&mut config, "source_range", json!(ranges));
    }
    if let Some(strategy) = ip_strategy(reader, "ipstrategy") {
        put(&mut config, "ip_strategy", Value::Object(strategy));
    }
    config
}

fn basic_auth(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    reader.refuse(
        "usersfile",
        "a users file is a path inside the proxy, which a label cannot name; put the entries in `users`",
    );
    let users = reader.list("users");
    if let Some(users) = required(reader, "users", users) {
        put(&mut config, "users", json!(users));
    }
    if let Some(realm) = reader.text("realm") {
        put(&mut config, "realm", realm);
    }
    if let Some(field) = reader.text("headerfield") {
        put(&mut config, "header_field", field);
    }
    if let Some(remove) = reader.boolean("removeheader") {
        put(&mut config, "remove_header", remove);
    }
    config
}

fn retry(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let attempts = reader.number::<u32>("attempts");
    if let Some(attempts) = required(reader, "attempts", attempts) {
        put(&mut config, "attempts", attempts);
    }
    if let Some(interval) = reader.millis("initialinterval") {
        put(&mut config, "initial_interval_ms", interval);
    }
    config
}

fn circuit_breaker(reader: &mut Reader<'_>) -> Config {
    let mut config = Config::new();
    let expression = reader.text("expression");
    if let Some(expression) = required(reader, "expression", expression) {
        match trip_when(expression) {
            Ok(trip) => put(&mut config, "trip_when", trip),
            Err(why) => {
                let key = reader.key_of("expression");
                reader.fail(Problem::unsupported_rule(&key, why));
            }
        }
    }
    if let Some(period) = reader.millis("checkperiod") {
        put(&mut config, "check_period_ms", period);
    }
    if let Some(fallback) = reader.seconds("fallbackduration") {
        put(&mut config, "fallback_secs", fallback);
    }
    if let Some(recovery) = reader.seconds("recoveryduration") {
        put(&mut config, "recovery_secs", recovery);
    }
    if let Some(code) = reader.number::<u16>("responsecode") {
        put(&mut config, "response_code", code);
    }
    config
}

/// The three shapes of Traefik's circuit breaker expression:
/// `NetworkErrorRatio() > r`, `ResponseCodeRatio(from, to, over_from, over_to) > r` and
/// `LatencyAtQuantileMS(q) > ms`. Compound expressions and the other comparisons have no
/// structured equivalent.
fn trip_when(expression: &str) -> Result<Value, String> {
    let text = expression.trim();
    if text.contains("&&") || text.contains("||") {
        return Err(
            "an expression that combines comparisons is not translated; podgate trips on any one of the structured conditions"
                .to_owned(),
        );
    }
    let open = text
        .find('(')
        .ok_or_else(|| format!("{text:?} is not NetworkErrorRatio(), ResponseCodeRatio(...) or LatencyAtQuantileMS(...)"))?;
    let close = text
        .find(')')
        .filter(|close| *close > open)
        .ok_or_else(|| format!("{text:?} has no closing parenthesis"))?;
    let name = text[..open].trim();
    let args: Vec<&str> = if text[open + 1..close].trim().is_empty() {
        Vec::new()
    } else {
        text[open + 1..close].split(',').map(str::trim).collect()
    };
    let Some(limit) = text[close + 1..].trim().strip_prefix('>') else {
        return Err(format!(
            "{text:?} must compare with `>`, the only comparison podgate has"
        ));
    };
    if limit.starts_with('=') {
        return Err("`>=` is not translated, only `>`".to_owned());
    }
    let limit = limit.trim();
    let ratio = || {
        limit
            .parse::<f64>()
            .map_err(|_| format!("{limit:?} is not a number"))
    };
    let int = |text: &str| {
        text.parse::<u16>()
            .map_err(|_| format!("{text:?} is not a status code"))
    };
    match (name, args.as_slice()) {
        ("NetworkErrorRatio", []) => Ok(json!({ "network_error_ratio": ratio()? })),
        ("ResponseCodeRatio", [from, to, over_from, over_to]) => Ok(json!({
            "response_code_ratio": {
                "from": int(from)?,
                "to": int(to)?,
                "over_from": int(over_from)?,
                "over_to": int(over_to)?,
                "ratio": ratio()?,
            }
        })),
        ("LatencyAtQuantileMS", [quantile]) => {
            let quantile: f64 = quantile
                .parse()
                .map_err(|_| format!("{quantile:?} is not a quantile"))?;
            let ms: u64 = limit
                .parse()
                .map_err(|_| format!("{limit:?} is not a whole number of milliseconds"))?;
            Ok(json!({ "latency_quantile_ms": { "quantile": quantile, "ms": ms } }))
        }
        _ => Err(format!(
            "{name}({}) is none of NetworkErrorRatio(), ResponseCodeRatio(from, to, over_from, over_to) and LatencyAtQuantileMS(q)",
            args.join(", ")
        )),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_three_expression_shapes() {
        assert_eq!(
            trip_when("NetworkErrorRatio() > 0.30").expect("shape"),
            json!({ "network_error_ratio": 0.3 })
        );
        assert_eq!(
            trip_when("ResponseCodeRatio(500, 600, 0, 600) > 0.25").expect("shape"),
            json!({ "response_code_ratio": {
                "from": 500, "to": 600, "over_from": 0, "over_to": 600, "ratio": 0.25
            } })
        );
        assert_eq!(
            trip_when("LatencyAtQuantileMS(50.0) > 100").expect("shape"),
            json!({ "latency_quantile_ms": { "quantile": 50.0, "ms": 100 } })
        );
    }

    #[test]
    fn other_expressions_are_refused() {
        for expression in [
            "NetworkErrorRatio() > 0.3 || LatencyAtQuantileMS(50.0) > 100",
            "NetworkErrorRatio() < 0.3",
            "NetworkErrorRatio() >= 0.3",
            "Foo() > 1",
            "LatencyAtQuantileMS(50.0) > 1.5",
            "NetworkErrorRatio > 1",
        ] {
            assert!(trip_when(expression).is_err(), "{expression}");
        }
    }
}
