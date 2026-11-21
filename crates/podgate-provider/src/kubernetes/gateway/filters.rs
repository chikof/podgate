//! Route filters: what a rule's `filters` become as podgate middlewares and mirrors.
//!
//! | Filter | podgate |
//! |---|---|
//! | `RequestHeaderModifier`, `ResponseHeaderModifier` | a `headers` middleware (`set`, `remove`; `add` has no equivalent and refuses the route) |
//! | `RequestRedirect` | `redirect_scheme` when only the scheme (and port) change, else `redirect_regex` over the request URL |
//! | `URLRewrite` path | `ReplaceFullPath` to `replace_path`, `ReplacePrefixMatch` to `replace_path_regex` (the hostname rewrite refuses the route) |
//! | `RequestMirror` | a `mirroring` service around the rule's backends |
//! | `ExtensionRef` | refused until the podgate `Middleware` object exists |
//!
//! A filter podgate cannot express refuses the route with a reason; none is ever ignored.

use std::collections::BTreeSet;

use podgate_model::Declared;
use regex::escape;
use serde_json::{Map, Value, json};

use super::types::{Filter, HeaderModifier, Mirror, PathModifier, Redirect};
use super::{Kind, Rejection, reject};
use crate::trust::HostPattern;

/// One middleware a rule puts on its routers' chains, before it knows which match it serves.
#[derive(Debug, Clone)]
pub enum Stage {
    /// A middleware that does not depend on the match: its settings, with `type`.
    Fixed(Map<String, Value>),
    /// A redirect; `ReplacePrefixMatch` depends on the prefix of the match.
    Redirect(Redirect),
    /// A path rewrite; `ReplacePrefixMatch` depends on the prefix of the match.
    Rewrite(PathModifier),
}

/// What a rule's filters ask for.
#[derive(Debug, Default)]
pub struct Plan {
    /// The middlewares, in the order the filters are written.
    pub stages: Vec<Stage>,
    /// The `RequestMirror` filters.
    pub mirrors: Vec<Mirror>,
}

impl Plan {
    /// Whether a redirect answers requests of this rule.
    #[must_use]
    pub fn redirects(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| matches!(stage, Stage::Redirect(_)))
    }
}

/// The middleware of a `respond` that answers `500`: a rule with no backend that can take a
/// request, as the Gateway API says.
#[must_use]
pub fn no_backend() -> Stage {
    Stage::Fixed(object(json!({ "type": "respond", "status": 500 })))
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// Reads the filters of one rule.
///
/// # Errors
///
/// A [`Rejection`] for a filter or a setting that podgate cannot apply.
pub fn plan(filters: &[Filter], kind: Kind) -> Result<Plan, Rejection> {
    let mut plan = Plan::default();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for filter in filters {
        let name = filter.kind.as_str();
        // Only the mirror may repeat: the API does not allow the others twice.
        if name != "RequestMirror" && !seen.insert(name) {
            return Err(unsupported(format!(
                "the filter {name} appears twice in one rule"
            )));
        }
        match name {
            "RequestHeaderModifier" | "ResponseHeaderModifier" => {
                let modifier = if name == "RequestHeaderModifier" {
                    filter.request_header_modifier.as_ref()
                } else {
                    filter.response_header_modifier.as_ref()
                };
                let modifier = modifier
                    .ok_or_else(|| unsupported(format!("the filter {name} has no settings")))?;
                let direction = if name == "RequestHeaderModifier" {
                    "request"
                } else {
                    "response"
                };
                if let Some(stage) = header_stage(name, direction, modifier)? {
                    plan.stages.push(stage);
                }
            }
            "RequestRedirect" | "URLRewrite" if kind == Kind::Grpc => {
                return Err(unsupported(format!(
                    "the filter {name} is not a GRPCRoute filter"
                )));
            }
            "RequestRedirect" => {
                let redirect = filter
                    .request_redirect
                    .clone()
                    .ok_or_else(|| unsupported("the filter RequestRedirect has no settings"))?;
                check_redirect(&redirect)?;
                plan.stages.push(Stage::Redirect(redirect));
            }
            "URLRewrite" => {
                let rewrite = filter
                    .url_rewrite
                    .clone()
                    .ok_or_else(|| unsupported("the filter URLRewrite has no settings"))?;
                if rewrite
                    .hostname
                    .as_deref()
                    .is_some_and(|host| !host.is_empty())
                {
                    return Err(unsupported(
                        "URLRewrite hostname is not supported: podgate sends the client's Host to the upstream",
                    ));
                }
                if let Some(path) = rewrite.path {
                    check_path(&path)?;
                    plan.stages.push(Stage::Rewrite(path));
                }
            }
            "RequestMirror" => {
                let mirror = filter
                    .request_mirror
                    .clone()
                    .ok_or_else(|| unsupported("the filter RequestMirror has no settings"))?;
                plan.mirrors.push(mirror);
            }
            "ExtensionRef" => {
                return Err(unsupported(
                    "the filter ExtensionRef needs the podgate Middleware object, which this source does not read yet",
                ));
            }
            other => {
                return Err(unsupported(format!(
                    "the filter type {other:?} is not supported"
                )));
            }
        }
    }
    if plan.redirects()
        && plan
            .stages
            .iter()
            .any(|stage| matches!(stage, Stage::Rewrite(_)))
    {
        return Err(unsupported(
            "RequestRedirect and URLRewrite cannot be used in one rule",
        ));
    }
    Ok(plan)
}

fn unsupported(message: impl Into<String>) -> Rejection {
    reject("UnsupportedValue", message)
}

/// Names `headers` refuses: they decide framing or the connection, as in the middleware.
const FORBIDDEN: [&str; 9] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "http2-settings",
];

fn header_stage(
    filter: &str,
    direction: &str,
    modifier: &HeaderModifier,
) -> Result<Option<Stage>, Rejection> {
    if !modifier.add.is_empty() {
        return Err(unsupported(format!(
            "{filter} add is not supported: podgate overwrites a header (use set) but cannot append to one"
        )));
    }
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut set = Map::new();
    for header in &modifier.set {
        check_name(filter, &header.name, &mut names)?;
        let value = &header.value;
        if value.is_empty() || value.bytes().any(|b| b.is_ascii_control() || !b.is_ascii()) {
            return Err(unsupported(format!(
                "{filter}: the value of {} is empty or holds a control or non-ASCII character",
                header.name
            )));
        }
        set.insert(
            header.name.to_ascii_lowercase(),
            Value::from(value.as_str()),
        );
    }
    let mut remove = Vec::new();
    for name in &modifier.remove {
        check_name(filter, name, &mut names)?;
        remove.push(Value::from(name.to_ascii_lowercase()));
    }
    if set.is_empty() && remove.is_empty() {
        return Ok(None);
    }
    let mut edits = Map::new();
    if !set.is_empty() {
        edits.insert("set".to_owned(), Value::Object(set));
    }
    if !remove.is_empty() {
        edits.insert("remove".to_owned(), Value::Array(remove));
    }
    Ok(Some(Stage::Fixed(object(
        json!({ "type": "headers", direction: edits }),
    ))))
}

fn check_name(filter: &str, name: &str, seen: &mut BTreeSet<String>) -> Result<(), Rejection> {
    let lower = name.to_ascii_lowercase();
    let token = !lower.is_empty()
        && lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if !token {
        return Err(unsupported(format!(
            "{filter}: {name:?} is not a header name"
        )));
    }
    if FORBIDDEN.contains(&lower.as_str()) || lower.starts_with("proxy-") {
        return Err(unsupported(format!(
            "{filter}: podgate does not change {name}: it decides how the message is framed or which connection carries it"
        )));
    }
    if !seen.insert(lower) {
        return Err(unsupported(format!(
            "{filter}: the header {name} is named twice"
        )));
    }
    Ok(())
}

fn check_redirect(redirect: &Redirect) -> Result<(), Rejection> {
    if redirect
        .scheme
        .as_deref()
        .is_some_and(|scheme| !matches!(scheme, "http" | "https"))
    {
        return Err(unsupported("RequestRedirect scheme is not http or https"));
    }
    if !matches!(redirect.status_code, None | Some(301 | 302)) {
        return Err(unsupported(format!(
            "RequestRedirect statusCode {} is not supported (301 and 302 are)",
            redirect.status_code.unwrap_or_default()
        )));
    }
    if let Some(host) = redirect.hostname.as_deref() {
        match HostPattern::parse(host) {
            Ok(HostPattern::Exact(_)) => {}
            _ => {
                return Err(unsupported(format!(
                    "RequestRedirect hostname {host:?} is not a host name"
                )));
            }
        }
    }
    if let Some(path) = &redirect.path {
        check_path(path)?;
    }
    if redirect.port == Some(0) {
        return Err(unsupported("RequestRedirect port is 0"));
    }
    Ok(())
}

fn check_path(path: &PathModifier) -> Result<(), Rejection> {
    let value = match path.kind.as_str() {
        "ReplaceFullPath" => path.replace_full_path.as_deref(),
        "ReplacePrefixMatch" => path.replace_prefix_match.as_deref(),
        other => {
            return Err(unsupported(format!(
                "the path modifier type {other:?} is not supported"
            )));
        }
    };
    let Some(value) = value else {
        return Err(unsupported(format!(
            "the path modifier {} has no value",
            path.kind
        )));
    };
    let safe = value.starts_with('/')
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\'));
    if !safe {
        return Err(unsupported(format!(
            "the path {value:?} must start with / and hold no ?, #, backslash, space or control character"
        )));
    }
    Ok(())
}

impl Stage {
    /// Whether the middleware needs the prefix of the match it serves.
    #[must_use]
    pub fn needs_prefix(&self) -> bool {
        let modifier = match self {
            Self::Fixed(_) => return false,
            Self::Redirect(redirect) => redirect.path.as_ref(),
            Self::Rewrite(path) => Some(path),
        };
        modifier.is_some_and(|path| path.kind == "ReplacePrefixMatch")
    }

    /// The middleware `name`, for a match whose path prefix is `prefix` (`None` for a match
    /// that is not a prefix).
    ///
    /// # Errors
    ///
    /// A [`Rejection`] when `ReplacePrefixMatch` meets a match that is not a path prefix.
    pub fn declare(&self, name: &str, prefix: Option<&str>) -> Result<Declared, Rejection> {
        let mut config = match self {
            Self::Fixed(config) => config.clone(),
            Self::Redirect(redirect) => redirect_config(redirect, prefix)?,
            Self::Rewrite(path) => rewrite_config(path, prefix)?,
        };
        config.insert("name".to_owned(), Value::from(name));
        serde_json::from_value(Value::Object(config))
            .map_err(|err| unsupported(format!("middleware {name}: {err}")))
    }
}

/// A path prefix without its trailing `/`; the root is the empty string.
#[must_use]
pub fn trim_slash(prefix: &str) -> &str {
    prefix.trim_end_matches('/')
}

fn prefix_of<'a>(what: &str, prefix: Option<&'a str>) -> Result<&'a str, Rejection> {
    prefix.ok_or_else(|| {
        unsupported(format!(
            "{what} ReplacePrefixMatch needs every match of the rule to be a PathPrefix"
        ))
    })
}

/// A literal in a replacement: `$` is the only character the replacement syntax reads.
fn literal(text: &str) -> String {
    text.replace('$', "$$")
}

fn rewrite_config(
    path: &PathModifier,
    prefix: Option<&str>,
) -> Result<Map<String, Value>, Rejection> {
    if path.kind == "ReplaceFullPath" {
        let full = path.replace_full_path.as_deref().unwrap_or("/");
        return Ok(object(json!({ "type": "replace_path", "path": full })));
    }
    let matched = trim_slash(prefix_of("URLRewrite", prefix)?);
    let replacement = trim_slash(path.replace_prefix_match.as_deref().unwrap_or("/"));
    // The rest keeps its own leading `/`, so `/foo` becomes `/bar` and `/foo/x` `/bar/x`.
    Ok(object(json!({
        "type": "replace_path_regex",
        "regex": format!("^{}(?P<rest>/.*)?$", escape(matched)),
        "replacement": format!("{}${{rest}}", literal(replacement)),
    })))
}

/// The request URL as `redirect_regex` sees it: `scheme://host[:port]/path?query`.
const URL: &str =
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<host>[^/?#:\[]+|\[[^\]/?#]*\])(?P<port>:[0-9]+)?";

fn redirect_config(
    redirect: &Redirect,
    prefix: Option<&str>,
) -> Result<Map<String, Value>, Rejection> {
    let permanent = redirect.status_code == Some(301);
    if redirect.hostname.is_none()
        && redirect.path.is_none()
        && let Some(scheme) = &redirect.scheme
    {
        let mut config = object(json!({
            "type": "redirect_scheme",
            "scheme": scheme,
            "permanent": permanent,
        }));
        if let Some(port) = redirect.port {
            config.insert("port".to_owned(), Value::from(port));
        }
        return Ok(config);
    }
    let scheme = redirect
        .scheme
        .as_deref()
        .map_or_else(|| "${scheme}".to_owned(), str::to_owned);
    let host = redirect
        .hostname
        .as_deref()
        .map_or_else(|| "${host}".to_owned(), |host| host.to_ascii_lowercase());
    // Without a port and with a scheme the target has the scheme's well-known port; with
    // neither, it keeps the port the request named.
    let port = match (redirect.port, redirect.scheme.is_some()) {
        (Some(port), _) => format!(":{port}"),
        (None, true) => String::new(),
        (None, false) => "${port}".to_owned(),
    };
    let (path_pattern, path) = match &redirect.path {
        None => ("(?P<path>[^?#]*)".to_owned(), "${path}".to_owned()),
        Some(path) if path.kind == "ReplaceFullPath" => (
            "[^?#]*".to_owned(),
            literal(path.replace_full_path.as_deref().unwrap_or("/")),
        ),
        Some(path) => {
            let matched = trim_slash(prefix_of("RequestRedirect", prefix)?);
            let replacement = trim_slash(path.replace_prefix_match.as_deref().unwrap_or("/"));
            (
                format!("{}(?P<rest>(?:/[^?#]*)?)", escape(matched)),
                format!("{}${{rest}}", literal(replacement)),
            )
        }
    };
    Ok(object(json!({
        "type": "redirect_regex",
        "regex": format!("{URL}{path_pattern}(?P<query>\\?.*)?$"),
        "replacement": format!("{scheme}://{host}{port}{path}${{query}}"),
        "permanent": permanent,
    })))
}

#[cfg(test)]
mod test {
    use super::*;

    fn filters(value: Value) -> Vec<Filter> {
        serde_json::from_value(value).expect("filters")
    }

    #[test]
    fn filters_translate() {
        let plan = plan(
            &filters(json!([
                { "type": "RequestHeaderModifier",
                  "requestHeaderModifier": { "set": [{ "name": "X-Env", "value": "prod" }], "remove": ["X-Debug"] } },
                { "type": "ResponseHeaderModifier",
                  "responseHeaderModifier": { "set": [{ "name": "X-Served", "value": "podgate" }] } },
                { "type": "RequestRedirect", "requestRedirect": { "scheme": "https", "statusCode": 301 } },
            ])),
            Kind::Http,
        )
        .expect("a plan");
        let declared: Vec<Value> = plan
            .stages
            .iter()
            .enumerate()
            .map(|(index, stage)| {
                serde_json::to_value(stage.declare(&format!("s{index}"), None).expect("declared"))
                    .expect("serializes")
            })
            .collect();
        assert_eq!(
            declared,
            [
                json!({ "name": "s0", "type": "headers",
                        "request": { "set": { "x-env": "prod" }, "remove": ["x-debug"] } }),
                json!({ "name": "s1", "type": "headers",
                        "response": { "set": { "x-served": "podgate" } } }),
                json!({ "name": "s2", "type": "redirect_scheme", "scheme": "https", "permanent": true }),
            ]
        );
    }

    #[test]
    fn filters_translate_path_rewrites_and_redirects() {
        let rewrite = plan(
            &filters(json!([{ "type": "URLRewrite", "urlRewrite": {
                "path": { "type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2" } } }])),
            Kind::Http,
        )
        .expect("a plan");
        let declared = rewrite.stages[0]
            .declare("w", Some("/api"))
            .expect("declared");
        assert_eq!(&*declared.kind, "replace_path_regex");
        assert_eq!(declared.config["regex"], json!("^/api(?P<rest>/.*)?$"));
        assert_eq!(declared.config["replacement"], json!("/v2${rest}"));
        // Without a prefix match the rewrite cannot be written.
        assert!(rewrite.stages[0].declare("w", None).is_err());

        let full = plan(
            &filters(json!([{ "type": "URLRewrite", "urlRewrite": {
                "path": { "type": "ReplaceFullPath", "replaceFullPath": "/index.html" } } }])),
            Kind::Http,
        )
        .expect("a plan");
        let declared = full.stages[0].declare("w", None).expect("declared");
        assert_eq!(
            serde_json::to_value(declared).expect("json"),
            json!({ "name": "w", "type": "replace_path", "path": "/index.html" })
        );

        let redirect = plan(
            &filters(json!([{ "type": "RequestRedirect", "requestRedirect": {
                "hostname": "new.test", "port": 8443, "scheme": "https" } }])),
            Kind::Http,
        )
        .expect("a plan");
        let declared = redirect.stages[0].declare("r", None).expect("declared");
        assert_eq!(&*declared.kind, "redirect_regex");
        assert_eq!(
            declared.config["replacement"],
            json!("https://new.test:8443${path}${query}")
        );
        assert_eq!(declared.config["permanent"], json!(false));
    }

    #[test]
    fn unsupported_filter_rejects_route() {
        let refuse = |value: Value, kind: Kind| -> String {
            plan(&filters(value), kind).expect_err("a refusal").message
        };
        assert!(
            refuse(
                json!([{ "type": "RequestHeaderModifier", "requestHeaderModifier": {
                    "add": [{ "name": "x", "value": "1" }] } }]),
                Kind::Http
            )
            .contains("add is not supported")
        );
        assert!(
            refuse(
                json!([{ "type": "URLRewrite", "urlRewrite": { "hostname": "x.test" } }]),
                Kind::Http
            )
            .contains("hostname")
        );
        assert!(
            refuse(
                json!([{ "type": "ExtensionRef", "extensionRef": { "name": "x" } }]),
                Kind::Http
            )
            .contains("0076")
        );
        assert!(refuse(json!([{ "type": "Mystery" }]), Kind::Http).contains("not supported"));
        assert!(
            refuse(
                json!([{ "type": "RequestHeaderModifier", "requestHeaderModifier": {
                    "set": [{ "name": "Host", "value": "x" }] } }]),
                Kind::Http
            )
            .contains("framed")
        );
        assert!(
            refuse(
                json!([{ "type": "RequestRedirect", "requestRedirect": { "scheme": "https" } }]),
                Kind::Grpc
            )
            .contains("not a GRPCRoute filter")
        );
    }
}
