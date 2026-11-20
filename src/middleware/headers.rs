//! The `headers` middleware: custom request and response headers, the standard security
//! headers, and CORS. Full reference: `docs/ref/mw-headers.md`.
//!
//! ```json
//! {
//!   "name": "h", "type": "headers",
//!   "request": { "set": { "x-tenant": "acme" }, "remove": ["x-debug"] },
//!   "response": {
//!     "set": { "x-served-by": "podgate" }, "remove": ["server"],
//!     "security": { "hsts": { "max_age_secs": 31536000, "include_subdomains": true },
//!                   "content_type_nosniff": true, "frame_options": "DENY" }
//!   },
//!   "cors": { "allow_origins": ["https://app.example.com"], "allow_methods": ["GET", "POST"] }
//! }
//! ```
//!
//! Header names and values are checked when the snapshot compiles, and the headers that decide
//! message framing or the connection (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Proxy-*`, any `:` pseudo header) can be
//! neither set nor removed: the list is closed, not an allow list, so a header added to HTTP
//! later is not forgotten. A header the middleware sets is overwritten, never appended to, so a
//! value the client sent for it never reaches the upstream.

use std::collections::{BTreeMap, BTreeSet};

use http::{HeaderName, HeaderValue, Method};
use pingora::http::{RequestHeader, ResponseHeader};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use podgate_model::Declared;

/// Headers a tenant can neither set nor remove: they frame the message or belong to the
/// connection, and an upstream that disagrees with the proxy about them is a request smuggling
/// or response splitting primitive. `Proxy-*` and `:` pseudo headers are refused as well.
const FORBIDDEN: &[&str] = &[
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

/// Largest compiled size of an origin regular expression.
const REGEX_SIZE_LIMIT: usize = 1 << 16;

/// The configuration of a `headers` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Edits to the request on its way to the upstream.
    pub request: Edits,
    /// Edits to the upstream's response, and the security headers.
    pub response: ResponseEdits,
    /// CORS; absent means the middleware does nothing about `Origin`.
    pub cors: Option<Cors>,
}

/// Headers to set (overwrite) and remove.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Edits {
    /// Header name to value. An empty value is refused: removal is `remove`.
    pub set: BTreeMap<String, String>,
    /// Header names to remove.
    pub remove: Vec<String>,
}

/// Response edits: [`Edits`] and the security headers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResponseEdits {
    /// Header name to value.
    pub set: BTreeMap<String, String>,
    /// Header names to remove.
    pub remove: Vec<String>,
    /// The standard security headers.
    pub security: Security,
}

/// The standard security headers. A field that is absent adds nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Security {
    /// `Strict-Transport-Security`, added to responses of TLS connections only.
    pub hsts: Option<Hsts>,
    /// `Content-Security-Policy`.
    pub csp: Option<String>,
    /// `Content-Security-Policy-Report-Only`.
    pub csp_report_only: Option<String>,
    /// `X-Frame-Options`.
    pub frame_options: Option<String>,
    /// `X-Content-Type-Options: nosniff`.
    pub content_type_nosniff: bool,
    /// `Referrer-Policy`.
    pub referrer_policy: Option<String>,
    /// `Permissions-Policy`.
    pub permissions_policy: Option<String>,
    /// `Cross-Origin-Opener-Policy`.
    pub cross_origin_opener_policy: Option<String>,
    /// `Cross-Origin-Resource-Policy`.
    pub cross_origin_resource_policy: Option<String>,
}

/// `Strict-Transport-Security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hsts {
    /// `max-age`, in seconds; `0` tells browsers to forget the policy.
    pub max_age_secs: u64,
    /// `includeSubDomains`.
    #[serde(default)]
    pub include_subdomains: bool,
    /// `preload`.
    #[serde(default)]
    pub preload: bool,
}

/// Cross-origin resource sharing.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cors {
    /// Allowed origins, exact (`scheme://host[:port]`), or `*` for any.
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// Regular expressions an origin must match entirely.
    #[serde(default)]
    pub allow_origin_regexes: Vec<String>,
    /// `Access-Control-Allow-Methods`; absent means the header is not sent.
    #[serde(default)]
    pub allow_methods: Vec<String>,
    /// `Access-Control-Allow-Headers`; never copied from the request.
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// `Access-Control-Expose-Headers`.
    #[serde(default)]
    pub expose_headers: Vec<String>,
    /// `Access-Control-Allow-Credentials: true`; refused together with the `*` origin.
    #[serde(default)]
    pub allow_credentials: bool,
    /// `Access-Control-Max-Age`.
    #[serde(default)]
    pub max_age_secs: Option<u64>,
    /// Add `Vary: Origin` to responses that depend on the origin. Default `true`.
    #[serde(default = "default_true")]
    pub add_vary: bool,
}

const fn default_true() -> bool {
    true
}

/// Header edits, validated.
#[derive(Debug, Default)]
struct Compiled {
    set: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

/// CORS, validated: what the response and the preflight carry, and which origins get them.
#[derive(Debug)]
struct CompiledCors {
    any: bool,
    exact: BTreeSet<String>,
    regexes: Vec<Regex>,
    methods: Option<HeaderValue>,
    headers: Option<HeaderValue>,
    expose: Option<HeaderValue>,
    credentials: bool,
    max_age: Option<HeaderValue>,
    vary: bool,
}

/// A compiled `headers` middleware.
#[derive(Debug)]
pub struct Headers {
    request: Compiled,
    response: Compiled,
    rest: Box<Rest>,
}

/// What the response hook and the plan read less often than the edits: kept behind one pointer so
/// a stage stays small.
#[derive(Debug)]
struct Rest {
    hsts: Option<HeaderValue>,
    security: Vec<(HeaderName, HeaderValue)>,
    cors: Option<CompiledCors>,
    config: Config,
}

/// Per-request state: what the request hook learned for the response hook.
#[derive(Debug, Default)]
pub struct State {
    tls: bool,
    allow_origin: Option<HeaderValue>,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_middleware", format!("headers: {}", message.into()))
}

fn name(raw: &str) -> Result<HeaderName, Invalid> {
    if raw.starts_with(':') {
        return Err(invalid(format!(
            "{raw}: pseudo headers cannot be set or removed"
        )));
    }
    let parsed = HeaderName::from_bytes(raw.as_bytes())
        .map_err(|_| invalid(format!("{raw:?} is not a valid header name")))?;
    if FORBIDDEN.contains(&parsed.as_str()) || parsed.as_str().starts_with("proxy-") {
        return Err(invalid(format!(
            "{parsed}: a header that frames the message or belongs to the connection cannot be set or removed"
        )));
    }
    Ok(parsed)
}

fn value(header: &str, raw: &str) -> Result<HeaderValue, Invalid> {
    if raw.is_empty() {
        return Err(invalid(format!(
            "{header}: an empty value; use `remove` to remove a header"
        )));
    }
    if !raw.is_ascii() {
        return Err(invalid(format!("{header}: the value is not ASCII")));
    }
    HeaderValue::from_str(raw).map_err(|_| {
        invalid(format!(
            "{header}: the value has a character a header value cannot hold (line breaks, NUL or other control characters)"
        ))
    })
}

/// Validates `set` and `remove`; `owned` are the headers another part of this middleware writes.
fn edits(
    set: &BTreeMap<String, String>,
    remove: &[String],
    owned: &[&str],
) -> Result<Compiled, Invalid> {
    let mut compiled = Compiled::default();
    for (raw, text) in set {
        let header = name(raw)?;
        if owned.contains(&header.as_str()) {
            return Err(invalid(format!(
                "{header} is already written by the security or cors settings"
            )));
        }
        if compiled.set.iter().any(|(seen, _)| *seen == header) {
            return Err(invalid(format!("{header} is set twice")));
        }
        compiled.set.push((header, value(raw, text)?));
    }
    for raw in remove {
        let header = name(raw)?;
        if owned.contains(&header.as_str()) || compiled.set.iter().any(|(seen, _)| *seen == header)
        {
            return Err(invalid(format!(
                "{header} is both removed and written by this middleware"
            )));
        }
        compiled.remove.push(header);
    }
    Ok(compiled)
}

fn hsts_value(hsts: Hsts) -> Result<HeaderValue, Invalid> {
    let mut text = format!("max-age={}", hsts.max_age_secs);
    if hsts.include_subdomains {
        text.push_str("; includeSubDomains");
    }
    if hsts.preload {
        text.push_str("; preload");
    }
    value("strict-transport-security", &text)
}

fn security_headers(security: &Security) -> Result<Vec<(HeaderName, HeaderValue)>, Invalid> {
    let texts = [
        ("content-security-policy", security.csp.as_deref()),
        (
            "content-security-policy-report-only",
            security.csp_report_only.as_deref(),
        ),
        ("x-frame-options", security.frame_options.as_deref()),
        ("referrer-policy", security.referrer_policy.as_deref()),
        ("permissions-policy", security.permissions_policy.as_deref()),
        (
            "cross-origin-opener-policy",
            security.cross_origin_opener_policy.as_deref(),
        ),
        (
            "cross-origin-resource-policy",
            security.cross_origin_resource_policy.as_deref(),
        ),
        (
            "x-content-type-options",
            security.content_type_nosniff.then_some("nosniff"),
        ),
    ];
    let mut out = Vec::new();
    for (header, text) in texts {
        if let Some(text) = text {
            out.push((HeaderName::from_static(header), value(header, text)?));
        }
    }
    Ok(out)
}

/// The names a non-empty `security` block or CORS block writes.
fn owned_names(config: &Config) -> Vec<&'static str> {
    let mut owned: Vec<&'static str> = Vec::new();
    let security = &config.response.security;
    let pairs = [
        (security.hsts.is_some(), "strict-transport-security"),
        (security.csp.is_some(), "content-security-policy"),
        (
            security.csp_report_only.is_some(),
            "content-security-policy-report-only",
        ),
        (security.frame_options.is_some(), "x-frame-options"),
        (security.content_type_nosniff, "x-content-type-options"),
        (security.referrer_policy.is_some(), "referrer-policy"),
        (security.permissions_policy.is_some(), "permissions-policy"),
        (
            security.cross_origin_opener_policy.is_some(),
            "cross-origin-opener-policy",
        ),
        (
            security.cross_origin_resource_policy.is_some(),
            "cross-origin-resource-policy",
        ),
        (config.cors.is_some(), "access-control-allow-origin"),
        (config.cors.is_some(), "access-control-allow-credentials"),
        (config.cors.is_some(), "access-control-allow-methods"),
        (config.cors.is_some(), "access-control-allow-headers"),
        (config.cors.is_some(), "access-control-expose-headers"),
        (config.cors.is_some(), "access-control-max-age"),
    ];
    owned.extend(pairs.iter().filter(|(on, _)| *on).map(|(_, name)| *name));
    owned
}

/// Whether `raw` is `scheme://host[:port]`: what a browser sends in `Origin`.
fn is_origin(raw: &str) -> bool {
    let Some((scheme, authority)) = raw.split_once("://") else {
        return false;
    };
    let host = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => authority,
    };
    matches!(scheme, "http" | "https")
        && !host.is_empty()
        && !host
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@' | b' ') || byte.is_ascii_control())
}

fn token_list(
    what: &str,
    items: &[String],
    check: impl Fn(&str) -> bool,
) -> Result<Option<HeaderValue>, Invalid> {
    if items.is_empty() {
        return Ok(None);
    }
    if let Some(bad) = items
        .iter()
        .find(|item| !(item.as_str() == "*" || check(item)))
    {
        return Err(invalid(format!(
            "cors.{what}: {bad:?} is not a valid token"
        )));
    }
    value(what, &items.join(", ")).map(Some)
}

fn cors(config: &Cors) -> Result<CompiledCors, Invalid> {
    if config.allow_origins.is_empty() && config.allow_origin_regexes.is_empty() {
        return Err(invalid(
            "cors needs `allow_origins` or `allow_origin_regexes`",
        ));
    }
    let any = config.allow_origins.iter().any(|origin| origin == "*");
    if any && config.allow_credentials {
        return Err(invalid(
            "cors: `allow_credentials` cannot be combined with the `*` origin; list the origins",
        ));
    }
    let mut exact = BTreeSet::new();
    for origin in &config.allow_origins {
        if origin != "*" && !is_origin(origin) {
            return Err(invalid(format!(
                "cors.allow_origins: {origin:?} is not `scheme://host[:port]` with scheme http or https"
            )));
        }
        exact.insert(origin.to_ascii_lowercase());
    }
    let mut regexes = Vec::new();
    for pattern in &config.allow_origin_regexes {
        let anchored = format!("^(?:{pattern})$");
        regexes.push(
            RegexBuilder::new(&anchored)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|err| invalid(format!("cors.allow_origin_regexes: {err}")))?,
        );
    }
    let is_token = |text: &str| HeaderName::from_bytes(text.as_bytes()).is_ok();
    Ok(CompiledCors {
        any,
        exact,
        regexes,
        methods: token_list("allow_methods", &config.allow_methods, |text| {
            Method::from_bytes(text.as_bytes()).is_ok()
        })?,
        headers: token_list("allow_headers", &config.allow_headers, is_token)?,
        expose: token_list("expose_headers", &config.expose_headers, is_token)?,
        credentials: config.allow_credentials,
        max_age: config
            .max_age_secs
            .map(|secs| value("access-control-max-age", &secs.to_string()))
            .transpose()?,
        vary: config.add_vary && !any,
    })
}

impl CompiledCors {
    /// The `Access-Control-Allow-Origin` value for `origin`: `*` when any origin is allowed,
    /// otherwise the origin itself, and only when the configuration names it.
    fn allow(&self, origin: &str) -> Option<HeaderValue> {
        if self.any {
            return Some(HeaderValue::from_static("*"));
        }
        let listed = self.exact.contains(&origin.to_ascii_lowercase())
            || self.regexes.iter().any(|regex| regex.is_match(origin));
        listed.then(|| HeaderValue::from_str(origin).ok()).flatten()
    }

    fn preflight(&self, allow_origin: HeaderValue) -> pingora::Result<Box<ResponseHeader>> {
        let mut head = ResponseHeader::build(204, Some(8))?;
        head.insert_header("access-control-allow-origin", allow_origin)?;
        self.credentials_header(&mut head)?;
        for (header, value) in [
            ("access-control-allow-methods", &self.methods),
            ("access-control-allow-headers", &self.headers),
            ("access-control-max-age", &self.max_age),
        ] {
            if let Some(value) = value {
                head.insert_header(header, value.clone())?;
            }
        }
        if self.vary {
            head.insert_header("vary", "Origin")?;
        }
        head.insert_header("content-length", "0")?;
        Ok(Box::new(head))
    }

    fn credentials_header(&self, head: &mut ResponseHeader) -> pingora::Result<()> {
        if self.credentials {
            head.insert_header("access-control-allow-credentials", "true")?;
        }
        Ok(())
    }
}

/// The request's only `Origin` header, when it has exactly one and it is plain ASCII.
fn single_origin(request: &RequestHeader) -> Option<&str> {
    let mut all = request.headers.get_all("origin").iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

fn is_preflight(request: &RequestHeader) -> bool {
    request.method == Method::OPTIONS
        && request
            .headers
            .contains_key("access-control-request-method")
}

/// Adds `token` to `Vary` unless the response already varies on it (or on everything).
fn vary(response: &mut ResponseHeader, token: &'static str) -> pingora::Result<()> {
    let covered = response
        .headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|seen| seen == "*" || seen.eq_ignore_ascii_case(token));
    if !covered {
        response.append_header("vary", token)?;
    }
    Ok(())
}

impl Kind for Headers {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let owned = owned_names(&config);
        Ok(Self {
            request: edits(&config.request.set, &config.request.remove, &[])?,
            response: edits(&config.response.set, &config.response.remove, &owned)?,
            rest: Box::new(Rest {
                hsts: config.response.security.hsts.map(hsts_value).transpose()?,
                security: security_headers(&config.response.security)?,
                cors: config.cors.as_ref().map(cors).transpose()?,
                config,
            }),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        state.tls = cx
            .session
            .digest()
            .is_some_and(|digest| digest.ssl_digest.is_some());
        if let Some(cors) = &self.rest.cors {
            let request = cx.session.req_header();
            let allowed = single_origin(request).and_then(|origin| cors.allow(origin));
            if let Some(allow_origin) = allowed {
                if is_preflight(request) {
                    let head = cors.preflight(allow_origin)?;
                    cx.session.write_response_header(head, true).await?;
                    return Ok(Flow::Respond);
                }
                state.allow_origin = Some(allow_origin);
            }
        }
        let request = cx.session.req_header_mut();
        for header in &self.request.remove {
            request.remove_header(header);
        }
        for (header, value) in &self.request.set {
            request.insert_header(header, value.clone())?;
        }
        Ok(Flow::Continue)
    }

    fn response(&self, response: &mut ResponseHeader, state: &mut State) -> pingora::Result<()> {
        for header in &self.response.remove {
            response.remove_header(header);
        }
        for (header, value) in self.response.set.iter().chain(&self.rest.security) {
            response.insert_header(header, value.clone())?;
        }
        if let (true, Some(hsts)) = (state.tls, &self.rest.hsts) {
            response.insert_header("strict-transport-security", hsts.clone())?;
        }
        if let Some(cors) = &self.rest.cors {
            if let Some(allow_origin) = state.allow_origin.take() {
                response.insert_header("access-control-allow-origin", allow_origin)?;
                cors.credentials_header(response)?;
                if let Some(expose) = &cors.expose {
                    response.insert_header("access-control-expose-headers", expose.clone())?;
                }
            }
            if cors.vary {
                vary(response, "Origin")?;
            }
        }
        Ok(())
    }

    /// Less protection than before: HSTS gone or weaker, a CSP, frame option or `nosniff` gone
    /// or changed, CORS open to more origins.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let old = &self.rest.config.response.security;
        let next = new.map(|stage| &stage.rest.config.response.security);
        let mut kinds = Vec::new();
        match (old.hsts, next.map(|next| next.hsts)) {
            (Some(_), Some(None) | None) => kinds.push("hsts_removed"),
            (Some(old), Some(Some(new)))
                if new.max_age_secs < old.max_age_secs
                    || (old.include_subdomains && !new.include_subdomains)
                    || (old.preload && !new.preload) =>
            {
                kinds.push("hsts_weakened");
            }
            _ => {}
        }
        for (field, kept, removed, changed) in [
            (
                &old.csp,
                next.map(|next| &next.csp),
                "csp_removed",
                "csp_changed",
            ),
            (
                &old.frame_options,
                next.map(|next| &next.frame_options),
                "frame_options_removed",
                "frame_options_changed",
            ),
        ] {
            if field.is_some() {
                match kept {
                    None | Some(None) => kinds.push(removed),
                    Some(now) if now != field => kinds.push(changed),
                    Some(_) => {}
                }
            }
        }
        if old.content_type_nosniff && !next.is_some_and(|next| next.content_type_nosniff) {
            kinds.push("nosniff_removed");
        }
        if let Some(new) = new
            && widened(
                self.rest.config.cors.as_ref(),
                new.rest.config.cors.as_ref(),
            )
        {
            kinds.push("cors_widened");
        }
        kinds
    }

    fn describe(&self) -> Value {
        let names = |compiled: &Compiled| {
            json!({
                "set": compiled.set.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(),
                "remove": compiled.remove.iter().map(HeaderName::as_str).collect::<Vec<_>>(),
            })
        };
        let mut response = names(&self.response);
        response["security"] = json!(
            self.rest
                .security
                .iter()
                .map(|(name, _)| name.as_str())
                .chain(self.rest.hsts.iter().map(|_| "strict-transport-security"))
                .collect::<Vec<_>>()
        );
        json!({
            "request": names(&self.request),
            "response": response,
            "cors": self.rest.config.cors.as_ref().map(|cors| json!({
                "allow_origins": cors.allow_origins,
                "allow_origin_regexes": cors.allow_origin_regexes,
                "allow_credentials": cors.allow_credentials,
            })),
        })
    }
}

/// Whether `new` lets in an origin, or credentials, that `old` did not (a regular expression
/// that is not byte for byte in `old` counts: two patterns cannot be compared).
fn widened(old: Option<&Cors>, new: Option<&Cors>) -> bool {
    let Some(new) = new else { return false };
    let Some(old) = old else { return true };
    let more = |old: &[String], new: &[String]| new.iter().any(|item| !old.contains(item));
    more(&old.allow_origins, &new.allow_origins)
        || more(&old.allow_origin_regexes, &new.allow_origin_regexes)
        || (new.allow_credentials && !old.allow_credentials)
}

#[cfg(test)]
mod test {
    use super::*;

    fn compile(config: &Value) -> Result<Headers, Invalid> {
        let mut declared = json!({ "name": "h", "type": "headers" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        Headers::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    fn rejected(config: &Value) -> String {
        let err = compile(config).expect_err("rejected");
        assert_eq!(err.code, "invalid_middleware", "{err:?}");
        err.message
    }

    #[test]
    fn forbidden_and_malformed_names_and_values_are_refused() {
        for name in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "connection",
            "upgrade",
            "TE",
            "trailer",
            "proxy-authorization",
            ":authority",
            "bad name",
        ] {
            rejected(&json!({ "request": { "set": { name: "x" } } }));
            rejected(&json!({ "response": { "remove": [name] } }));
        }
        for text in ["a\r\nset-cookie: x", "a\nb", "a\0b", "", "na\u{ef}ve"] {
            rejected(&json!({ "response": { "set": { "x-a": text } } }));
        }
    }

    #[test]
    fn contradictions_are_refused() {
        rejected(&json!({ "response": { "set": { "X-A": "1", "x-a": "2" } } }));
        rejected(&json!({ "response": { "set": { "x-a": "1" }, "remove": ["X-A"] } }));
        rejected(&json!({ "response": {
            "set": { "x-frame-options": "ALLOWALL" }, "security": { "frame_options": "DENY" } } }));
        rejected(&json!({ "unknown": true }));
    }

    #[test]
    fn cors_rules() {
        rejected(&json!({ "cors": { "allow_origins": ["*"], "allow_credentials": true } }));
        rejected(&json!({ "cors": {} }));
        rejected(&json!({ "cors": { "allow_origins": ["https://a.test/"] } }));
        rejected(&json!({ "cors": { "allow_origins": ["a.test"] } }));
        rejected(&json!({ "cors": { "allow_origin_regexes": ["("] } }));
        assert!(compile(&json!({ "cors": { "allow_origins": ["https://a.test:8443"] } })).is_ok());
    }

    #[test]
    fn origins_match_exactly_or_by_anchored_regex_and_are_never_reflected_otherwise() {
        let stage = compile(&json!({ "cors": {
            "allow_origins": ["https://a.test"], "allow_origin_regexes": ["https://[a-z]+\\.b\\.test"] } }))
        .expect("compiles");
        let cors = stage.rest.cors.expect("cors");
        assert_eq!(
            cors.allow("https://a.test")
                .as_ref()
                .map(HeaderValue::as_bytes),
            Some(&b"https://a.test"[..])
        );
        assert_eq!(
            cors.allow("https://x.b.test")
                .as_ref()
                .map(HeaderValue::as_bytes),
            Some(&b"https://x.b.test"[..])
        );
        for other in [
            "https://a.test.evil.test",
            "http://a.test",
            "https://a.test:8443",
            "https://x.b.test.evil",
            "null",
        ] {
            assert!(cors.allow(other).is_none(), "{other}");
        }
    }

    #[test]
    fn posture_lists_weaker_security_and_wider_cors() {
        let strong = compile(&json!({
            "response": { "security": {
                "hsts": { "max_age_secs": 100, "include_subdomains": true },
                "csp": "default-src 'self'", "frame_options": "DENY", "content_type_nosniff": true } },
            "cors": { "allow_origins": ["https://a.test"] } }))
        .expect("strong");
        let weak = compile(&json!({
            "response": { "security": { "hsts": { "max_age_secs": 10 }, "csp": "default-src *" } },
            "cors": { "allow_origins": ["https://a.test", "https://b.test"] } }))
        .expect("weak");
        assert_eq!(
            strong.posture(Some(&weak)),
            [
                "hsts_weakened",
                "csp_changed",
                "frame_options_removed",
                "nosniff_removed",
                "cors_widened"
            ]
        );
        assert_eq!(
            strong.posture(None),
            [
                "hsts_removed",
                "csp_removed",
                "frame_options_removed",
                "nosniff_removed"
            ]
        );
        assert_eq!(
            weak.posture(Some(&strong)),
            ["csp_changed"],
            "a CSP cannot be ranked, only compared"
        );
        assert!(strong.posture(Some(&strong)).is_empty());
    }
}
