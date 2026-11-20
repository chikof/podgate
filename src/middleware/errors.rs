//! The `errors` middleware: replaces an error response with a page served by another service of
//! the same app. Full reference: `docs/ref/mw-errors.md`.
//!
//! ```json
//! { "name": "pages", "type": "errors",
//!   "status": ["500-599", "404"], "service": "pages", "query": "/{status}.html" }
//! ```
//!
//! The chain is the declaration of what a response may become, and everything the page request
//! carries is fixed here, not taken from the client:
//!
//! - **Where.** `service` names a service of the revision the request was sent to (its own, else
//!   the app's), or `name@revision` for a service of one particular revision. The name is
//!   resolved when the snapshot compiles (`unknown_service`) and again, by name, for every page,
//!   so the address that is dialled is always one the snapshot declared, checked against the
//!   upstream address policy at the moment of the dial.
//! - **What.** `GET`, the path `query` with `{status}` replaced by the three digits of the
//!   status (no other placeholder exists), and two headers: `Host`, the host the client asked
//!   for, and `Accept`, the client's when it is plain printable text. Nothing else of the
//!   client's request reaches the page server, so a tenant's page server never sees credentials.
//! - **How much.** The body is read up to `max_body_bytes` (256 KiB by default, 1 MiB at most)
//!   within `timeout_secs` (3 by default). The cap and a small allowance for the head are charged
//!   to the tenant's buffer budget before the connection is made and stay charged until the page
//!   has been written.
//! - **Failure.** Any failure (refused by the policy, no server, over the budget, slow, a status
//!   other than `2xx`, an over-cap, encoded or malformed answer) leaves the original response as
//!   it was. One request tries one page, at most once: [`Attempt`] in the request context is the
//!   loop guard, and the page request is a direct connection that never runs the chain again.
//!
//! The page is written with the status of the response it replaces and only the headers of the
//! page's `Content-Type`; the original response's headers (its `Set-Cookie` included) are dropped.

pub mod fetch;

use std::ops::RangeInclusive;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderValue;
use pingora::http::RequestHeader;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use fetch::ALLOWANCE;

use super::{CompileCx, Kind, PageCx};
use crate::budget::BufferGuard;
use crate::compile::Invalid;
use crate::service::{PickCx, Service};
use podgate_model::{App, Declared, RevisionState};

/// The default cap of a page body.
const DEFAULT_MAX_BODY: usize = 256 * 1024;
/// The largest cap `max_body_bytes` may ask for.
const MAX_BODY: usize = 1024 * 1024;
/// The default time for fetching a page.
const DEFAULT_TIMEOUT_SECS: u64 = 3;
/// The longest `timeout_secs`.
const MAX_TIMEOUT_SECS: u64 = 30;
/// The default `query`.
const DEFAULT_QUERY: &str = "/{status}.html";
/// The longest `query`.
const MAX_QUERY: usize = 256;
/// The most `status` entries.
const MAX_STATUSES: usize = 32;
/// The only placeholder `query` knows.
const STATUS: &str = "{status}";
/// The longest `Accept` that is passed on.
const MAX_ACCEPT: usize = 256;
/// The longest host that is passed on.
const MAX_HOST: usize = 255;

/// Whether an error page was tried for a request. Lives in the request context.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Attempt {
    /// No page was tried yet.
    #[default]
    Untried,
    /// A page was tried, and the original response stands.
    Tried,
    /// A page was fetched and written in place of the response.
    Replaced,
}

/// A fetched error page, charged to its tenant until dropped.
#[derive(Debug)]
pub struct Page {
    content_type: Option<HeaderValue>,
    body: Bytes,
    _charge: BufferGuard,
}

impl Page {
    /// The `Content-Type` the page server sent, if it sent a usable one.
    #[must_use]
    pub fn content_type(&self) -> Option<&HeaderValue> {
        self.content_type.as_ref()
    }

    /// The page: at least one byte.
    #[must_use]
    pub fn body(&self) -> &Bytes {
        &self.body
    }
}

/// The service an `errors` stage fetches from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    name: Box<str>,
    /// The revision named by `name@revision`; `None` follows the request's revision.
    revision: Option<Box<str>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum StatusSpec {
    Code(u16),
    Range(String),
}

impl StatusSpec {
    fn parse(&self) -> Result<RangeInclusive<u16>, Invalid> {
        let bad = || {
            invalid(format!(
                "status {self:?} is not a code or low-high in 400..=599"
            ))
        };
        let (low, high) = match self {
            Self::Code(code) => (*code, *code),
            Self::Range(text) => {
                let number = |part: &str| part.trim().parse::<u16>().map_err(|_| bad());
                match text.split_once('-') {
                    Some((low, high)) => (number(low)?, number(high)?),
                    None => {
                        let code = number(text)?;
                        (code, code)
                    }
                }
            }
        };
        if (400..=599).contains(&low) && (400..=599).contains(&high) && low <= high {
            Ok(low..=high)
        } else {
            Err(bad())
        }
    }
}

/// The configuration of an `errors` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    status: Vec<StatusSpec>,
    service: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    max_body_bytes: Option<usize>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// A compiled `errors` middleware.
#[derive(Debug)]
pub struct Errors {
    statuses: Box<[RangeInclusive<u16>]>,
    shown_statuses: Box<[Box<str>]>,
    target: Target,
    query: Box<str>,
    max_body: usize,
    timeout: Duration,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_middleware", format!("errors: {}", message.into()))
}

fn unknown_service(message: impl Into<String>) -> Invalid {
    Invalid::new("unknown_service", format!("errors: {}", message.into()))
}

/// Checks the `query` template: an origin-form path that starts with `/` (not `//`), made of
/// printable ASCII, whose only placeholder is `{status}`, and that is a valid request target once
/// the status is in it.
fn check_query(query: &str) -> Result<(), Invalid> {
    if !query.starts_with('/') || query.starts_with("//") || query.len() > MAX_QUERY {
        return Err(invalid(format!(
            "query must be a path starting with a single /, at most {MAX_QUERY} bytes"
        )));
    }
    if !query
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
        return Err(invalid(
            "query may hold only printable ASCII and no #: nothing in it can be a line break or a fragment",
        ));
    }
    let bare = query.replace(STATUS, "404");
    if bare.contains(['{', '}']) {
        return Err(invalid(format!(
            "query knows one placeholder, {STATUS}; no other request data is interpolated"
        )));
    }
    if http::uri::PathAndQuery::try_from(bare.as_str()).is_err() {
        return Err(invalid("query is not a valid request target"));
    }
    Ok(())
}

/// Parses `service` into the name and the optional revision.
fn parse_target(service: &str) -> Result<Target, Invalid> {
    let (name, revision) = match service.split_once('@') {
        Some((name, revision)) => (name, Some(revision)),
        None => (service, None),
    };
    if name.is_empty() || revision.is_some_and(|rev| rev.is_empty() || rev.contains('@')) {
        return Err(invalid(format!(
            "service {service:?} is a service name or name@revision"
        )));
    }
    Ok(Target {
        name: name.into(),
        revision: revision.map(Into::into),
    })
}

fn defines(services: &[Declared], name: &str) -> bool {
    services.iter().any(|declared| &*declared.name == name)
}

/// Whether the service `declared` has an `h2c://` server. A page is fetched by writing HTTP/1.1
/// over the connection, which such a server cannot answer.
fn has_h2c_server(declared: &Declared) -> bool {
    declared
        .config
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers.iter().any(|server| {
                server
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| url.starts_with("h2c://"))
            })
        })
}

/// Checks that `target` names a service the app declares, the way a router's service is checked:
/// every revision that takes or may still take requests defines it itself or inherits it from the
/// app, and a `name@revision` names a revision that has it.
fn check_target(app: &App, target: &Target) -> Result<(), Invalid> {
    let named = |services: &[Declared]| {
        services
            .iter()
            .any(|declared| *declared.name == *target.name && has_h2c_server(declared))
    };
    let h2c = named(&app.services)
        || app
            .revisions
            .iter()
            .filter(|revision| {
                target
                    .revision
                    .as_deref()
                    .is_none_or(|wanted| wanted == &*revision.id)
            })
            .any(|revision| named(&revision.services));
    if h2c {
        return Err(invalid(format!(
            "service {} has an h2c:// server: pages are fetched over HTTP/1.1, which it cannot answer",
            target.name
        )));
    }
    let shared = defines(&app.services, &target.name);
    if let Some(wanted) = &target.revision {
        let found = app
            .revisions
            .iter()
            .find(|revision| *revision.id == **wanted);
        return match found {
            Some(revision) if shared || defines(&revision.services, &target.name) => Ok(()),
            Some(_) => Err(unknown_service(format!(
                "revision {wanted} has no service {}",
                target.name
            ))),
            None => Err(unknown_service(format!("the app has no revision {wanted}"))),
        };
    }
    let anywhere = shared
        || app
            .revisions
            .iter()
            .any(|revision| defines(&revision.services, &target.name));
    if !anywhere {
        return Err(unknown_service(format!(
            "service {} is defined by neither a revision nor the app",
            target.name
        )));
    }
    if let Some(revision) = app.revisions.iter().find(|revision| {
        revision.state != RevisionState::Draining
            && !shared
            && !defines(&revision.services, &target.name)
    }) {
        return Err(unknown_service(format!(
            "revision {} has no service {}",
            revision.id, target.name
        )));
    }
    Ok(())
}

impl Errors {
    /// Refuses a page that could never be charged: the cap plus [`ALLOWANCE`] is more than the
    /// tenant's whole `max_buffer_bytes`. A budget that is only full right now is not judged
    /// here; the page is skipped when its charge is refused.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` naming the tenant, the bytes a page needs and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        let needed = ALLOWANCE.saturating_add(u64::try_from(self.max_body).unwrap_or(u64::MAX));
        if max_buffer_bytes >= needed {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {needed} bytes one error page reserves (max_body_bytes {} plus {ALLOWANCE}); lower max_body_bytes or raise the budget",
            self.max_body
        ))
        .with("tenant", tenant)
        .with("needed_bytes", needed)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    fn matches(&self, status: u16) -> bool {
        self.statuses.iter().any(|range| range.contains(&status))
    }

    /// The statuses this stage replaces with a page.
    pub(crate) fn statuses(&self) -> &[RangeInclusive<u16>] {
        &self.statuses
    }

    /// The request target of the page for `status`: the template and three digits, nothing else.
    fn path(&self, status: u16) -> String {
        self.query.replace(STATUS, &format!("{status:03}"))
    }

    /// The service the page comes from, for a request sent to revision `revision`.
    fn service<'a>(&self, cx: &'a PageCx<'_>) -> Option<&'a Service> {
        let app = cx.app;
        let revision = match &self.target.revision {
            Some(id) => app
                .revisions()
                .iter()
                .find(|revision| revision.id() == &**id)?,
            None => app.revisions().get(cx.revision?)?,
        };
        revision
            .services()
            .iter()
            .chain(app.services())
            .find(|named| *named.name == *self.target.name)
            .map(|named| &named.service)
    }
}

/// The host the client asked for: the authority of the request target, else the `Host` header,
/// only when it is made of host characters.
fn host_of(request: &RequestHeader) -> Option<&str> {
    let host = match request.uri.authority() {
        Some(authority) => authority.as_str(),
        None => request.headers.get("host")?.to_str().ok()?,
    };
    let plain = !host.is_empty()
        && host.len() <= MAX_HOST
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        });
    plain.then_some(host)
}

/// The client's `Accept` when it is short printable ASCII (spaces allowed), else `*/*`.
fn accept_of(request: &RequestHeader) -> &str {
    request
        .headers
        .get("accept")
        .and_then(|value| value.to_str().ok())
        .filter(|text| {
            !text.is_empty()
                && text.len() <= MAX_ACCEPT
                && text.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
        })
        .unwrap_or("*/*")
}

impl Kind for Errors {
    type State = ();

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        if config.status.is_empty() || config.status.len() > MAX_STATUSES {
            return Err(invalid(format!("status lists 1 to {MAX_STATUSES} entries")));
        }
        let mut statuses = Vec::with_capacity(config.status.len());
        let mut shown = Vec::with_capacity(config.status.len());
        for spec in &config.status {
            let range = spec.parse()?;
            shown.push(if range.start() == range.end() {
                range.start().to_string().into()
            } else {
                format!("{}-{}", range.start(), range.end()).into()
            });
            statuses.push(range);
        }
        let query = config.query.as_deref().unwrap_or(DEFAULT_QUERY);
        check_query(query)?;
        let max_body = config.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY);
        if !(1..=MAX_BODY).contains(&max_body) {
            return Err(invalid(format!("max_body_bytes is in 1..={MAX_BODY}")));
        }
        let timeout_secs = config.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=MAX_TIMEOUT_SECS).contains(&timeout_secs) {
            return Err(invalid(format!(
                "timeout_secs is in 1..={MAX_TIMEOUT_SECS}"
            )));
        }
        let target = parse_target(&config.service)?;
        check_target(cx.app, &target)?;
        Ok(Self {
            statuses: statuses.into_boxed_slice(),
            shown_statuses: shown.into_boxed_slice(),
            target,
            query: query.into(),
            max_body,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    async fn response_page(&self, cx: &PageCx<'_>) -> Option<Page> {
        if !self.matches(cx.status) {
            return None;
        }
        let service = self.service(cx)?;
        let path = self.path(cx.status);
        let target = RequestHeader::build("GET", path.as_bytes(), None).ok()?;
        // The lease counts the fetch on its server while it runs; the pick is the balancer's own.
        let (addr, _lease) = service.pick(PickCx::new(&target))?;
        let peer = service.upstream(addr)?.peer();
        let query = fetch::Query {
            host: host_of(cx.request)?,
            accept: accept_of(cx.request),
            path: &path,
        };
        let limits = fetch::Limits {
            max_body: self.max_body,
            timeout: self.timeout,
        };
        let charge = cx
            .tenant
            .charge(ALLOWANCE + u64::try_from(self.max_body).ok()?)?;
        let fetched = Box::pin(
            cx.fetcher
                .fetch(peer, cx.policy, cx.app.tenant(), &query, limits),
        )
        .await
        .inspect_err(|why| {
            debug!(app = cx.app.id(), status = cx.status, %why, "error page not used");
        })
        .ok()?;
        Some(Page {
            content_type: fetched.content_type,
            body: Bytes::from(fetched.body),
            _charge: charge,
        })
    }

    /// The template's path without its query string, which may carry a key for the page server.
    fn describe(&self) -> Value {
        let service = match &self.target.revision {
            Some(revision) => format!("{}@{revision}", self.target.name),
            None => self.target.name.to_string(),
        };
        json!({
            "status": self.shown_statuses,
            "service": service,
            "query": self.query.split('?').next().unwrap_or_default(),
            "max_body_bytes": self.max_body,
            "timeout_secs": self.timeout.as_secs(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wasm as engine;

    fn app(services: &Value, revisions: &Value) -> App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "services": services, "revisions": revisions,
        }))
        .expect("app")
    }

    fn compile(app: &App, config: &Value) -> Result<Errors, Invalid> {
        let mut declared = json!({"name": "e", "type": "errors"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let mut compiler = engine::Compiler::default();
        Errors::compile(
            &declared,
            &mut CompileCx {
                app,
                engine: &mut compiler,
            },
        )
    }

    fn lb(name: &str) -> Value {
        json!({"name": name, "type": "loadbalancer", "servers": [{"url": "http://10.0.0.1:80"}]})
    }

    fn revision(id: &str, state: &str, services: &[Value]) -> Value {
        json!({"id": id, "state": state, "weight": 1, "services": services})
    }

    fn code(result: Result<Errors, Invalid>) -> &'static str {
        result.expect_err("refused").code
    }

    #[test]
    fn compiles_ranges_codes_and_defaults() {
        let app = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        let errors = compile(
            &app,
            &json!({"status": ["500-599", 404, "418"], "service": "pages"}),
        )
        .expect("compiled");
        assert!(errors.matches(503) && errors.matches(404) && errors.matches(418));
        assert!(!errors.matches(403) && !errors.matches(499));
        assert_eq!(errors.path(404), "/404.html");
        assert_eq!(
            errors.describe()["status"],
            json!(["500-599", "404", "418"])
        );
        assert_eq!(errors.describe()["max_body_bytes"], 256 * 1024);
        assert_eq!(errors.describe()["timeout_secs"], 3);
    }

    #[test]
    fn statuses_outside_400_to_599_are_invalid() {
        let app = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        for status in [
            json!(["200"]),
            json!([399]),
            json!(["400-600"]),
            json!(["500-400"]),
            json!(["x"]),
            json!([]),
            json!(["99-199"]),
        ] {
            let result = compile(&app, &json!({"status": status, "service": "pages"}));
            assert_eq!(code(result), "invalid_middleware", "{status}");
        }
    }

    #[test]
    fn the_query_has_one_placeholder_and_no_request_data() {
        let app = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        let with = |query: &str| {
            compile(
                &app,
                &json!({"status": ["500"], "service": "pages", "query": query}),
            )
        };
        assert_eq!(
            with("/err/{status}?lang=en").expect("ok").path(502),
            "/err/502?lang=en"
        );
        assert_eq!(
            with("/{status}/{status}").expect("ok").path(500),
            "/500/500"
        );
        for bad in [
            "err",
            "//evil/{status}",
            "/{path}",
            "/{status}{host}",
            "/a b",
            "/a\r\nb",
            "/{status}#x",
            "/{",
            "/}",
            "/é",
        ] {
            assert_eq!(code(with(bad)), "invalid_middleware", "{bad:?}");
        }
        assert_eq!(
            code(with(&format!("/{}", "a".repeat(MAX_QUERY)))),
            "invalid_middleware"
        );
    }

    #[test]
    fn limits_are_bounded() {
        let app = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        let with = |extra: Value| {
            let mut config = json!({"status": ["500"], "service": "pages"});
            config
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            compile(&app, &config)
        };
        assert!(with(json!({"max_body_bytes": MAX_BODY, "timeout_secs": 30})).is_ok());
        for bad in [
            json!({"max_body_bytes": 0}),
            json!({"max_body_bytes": MAX_BODY + 1}),
            json!({"timeout_secs": 0}),
            json!({"timeout_secs": 31}),
            json!({"nope": 1}),
        ] {
            assert_eq!(code(with(bad.clone())), "invalid_middleware", "{bad}");
        }
    }

    #[test]
    fn removing_errors_is_not_a_posture_change() {
        let app = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        let errors = compile(&app, &json!({"status": ["500"], "service": "pages"})).expect("ok");
        assert!(errors.posture(None).is_empty());
        assert!(errors.posture(Some(&errors)).is_empty());
    }

    #[test]
    fn the_service_must_exist_where_a_request_can_land() {
        // Defined by the app: fine. Defined by every live revision: fine.
        let shared = app(
            &json!([lb("pages")]),
            &json!([revision("r1", "serving", &[])]),
        );
        assert!(compile(&shared, &json!({"status": ["500"], "service": "pages"})).is_ok());
        let own = app(
            &json!([]),
            &json!([
                revision("r1", "serving", &[lb("pages")]),
                revision("r2", "retiring", &[lb("pages")]),
                revision("r3", "draining", &[]),
            ]),
        );
        assert!(compile(&own, &json!({"status": ["500"], "service": "pages"})).is_ok());
        // A live revision without it, or no definition at all: unknown_service.
        let gap = app(
            &json!([]),
            &json!([
                revision("r1", "serving", &[lb("pages")]),
                revision("r2", "serving", &[]),
            ]),
        );
        assert_eq!(
            code(compile(
                &gap,
                &json!({"status": ["500"], "service": "pages"})
            )),
            "unknown_service"
        );
        assert_eq!(
            code(compile(
                &shared,
                &json!({"status": ["500"], "service": "nope"})
            )),
            "unknown_service"
        );
    }

    #[test]
    fn a_name_at_revision_names_one_revision() {
        let app = app(
            &json!([]),
            &json!([
                revision("r1", "serving", &[lb("pages")]),
                revision("r2", "serving", &[]),
            ]),
        );
        let at = |service: &str| compile(&app, &json!({"status": ["500"], "service": service}));
        assert!(at("pages@r1").is_ok());
        assert_eq!(code(at("pages@r2")), "unknown_service");
        assert_eq!(code(at("pages@r9")), "unknown_service");
        for bad in ["@r1", "pages@", "a@b@c", ""] {
            assert_eq!(code(at(bad)), "invalid_middleware", "{bad:?}");
        }
    }

    #[test]
    fn only_host_and_a_plain_accept_are_taken_from_the_request() {
        let mut request = RequestHeader::build("GET", b"/secret?token=1", None).expect("request");
        request.insert_header("Host", "a.test:8080").expect("host");
        request
            .insert_header("Accept", "text/html, */*;q=0.1")
            .expect("accept");
        assert_eq!(host_of(&request), Some("a.test:8080"));
        assert_eq!(accept_of(&request), "text/html, */*;q=0.1");
        request
            .insert_header("Accept", "x".repeat(MAX_ACCEPT + 1))
            .expect("accept");
        assert_eq!(accept_of(&request), "*/*");
        request.remove_header("accept");
        assert_eq!(accept_of(&request), "*/*");
        request.insert_header("Host", "a.test:80/x").expect("host");
        assert_eq!(host_of(&request), None);
        request.insert_header("Host", "a.test/x").expect("host");
        assert_eq!(host_of(&request), None);
    }
}
