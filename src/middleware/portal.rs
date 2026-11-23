//! The `portal` middleware: a read-only developer portal that answers in the route's
//! chain. API consumers browse the catalog of the APIs their own tenant published and read each
//! API's OpenAPI description. Full reference: `docs/ref/portal.md`.
//!
//! ```json
//! { "name": "portal", "type": "portal", "tenant_claim": "tenant" }
//! ```
//!
//! The stage has no login, session or user store, and no secret. It stands behind a `jwt_auth` or
//! `oidc` stage of the same chain and reads the viewer's tenant from the string claim
//! `tenant_claim` (default `tenant`) of the claims that stage verified ([`RequestCx::claims`]),
//! never from a header, the query or the path. Who may declare it is the operator's: only an app
//! listed in `PORTAL_APPS`, whose login stage verifies with exactly the issuer and key source the
//! operator pinned ([`pin`]), compiles it; anything else refuses the whole snapshot.
//!
//! What a viewer sees is decided in `access.rs`, the only file that reads the catalog: the entries
//! of the viewer's own tenant that are published and `preview`, `stable` or `deprecated`.
//!
//! | Request | Answer |
//! |---|---|
//! | `GET /`, `/app.js`, `/style.css` | the files of `portal/`, compiled in |
//! | `GET /api/catalog?limit=&after=&q=` | the viewer's entries (`list.rs`) |
//! | `GET /api/catalog/{tenant}/{id}/{version}/openapi` | the portal's view of the document (`document.rs`) |
//! | any other path | `404 {"error":"not found"}` |
//! | another method on those paths | `405` with `allow: GET, HEAD` |
//!
//! An API route answers `401` to a viewer with no tenant, and `404`, the same bytes, for an entry
//! that is another tenant's, unpublished, a draft, retired or missing.

pub(super) mod access;
pub(super) mod document;
pub(super) mod list;
pub mod pin;

use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::Method;
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use self::access::{Viewer, find};
use self::pin::{Grant, Grants, Login};
use super::{CompileCx, Flow, Kind, RequestCx};
use super::{Named, Stage};
use crate::compile::{Invalid, Rejected};
use crate::dashboard::{Asset, CONTENT_SECURITY_POLICY_VALUE};
use crate::table::RoutingTable;
use podgate_model::{App, Declared};

/// Answers computed at once per stage; more get `503`.
const SLOTS: usize = 4;

/// The claim a viewer's tenant is read from when the stage names none.
const DEFAULT_CLAIM: &str = "tenant";

/// Longest `tenant_claim`.
const MAX_CLAIM: usize = 64;

/// The files of `portal/`, compiled in: the page always matches the API of the same build.
const ASSETS: [Asset; 3] = [
    Asset {
        file: "index.html",
        path: "/",
        content_type: "text/html; charset=utf-8",
        bytes: include_bytes!("../../portal/index.html"),
    },
    Asset {
        file: "app.js",
        path: "/app.js",
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../portal/app.js"),
    },
    Asset {
        file: "style.css",
        path: "/style.css",
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("../../portal/style.css"),
    },
];

/// The configuration of a `portal` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The string claim of the login stage's verified claims that names the viewer's tenant.
    /// Default `tenant`.
    #[serde(default)]
    tenant_claim: Option<String>,
}

/// A compiled `portal` middleware.
#[derive(Debug)]
pub struct Portal {
    claim: Box<str>,
    /// The live table, weakly: the table holds this stage, so a strong handle would keep it.
    live: Weak<ArcSwap<RoutingTable>>,
    slots: Arc<Semaphore>,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("portal: {message}"))
}

/// What a request is asking the portal for.
enum Route<'a> {
    Asset(&'static Asset),
    List,
    /// The path between `/api/catalog/` and `/openapi`, still percent-encoded.
    Document(&'a str),
    Unknown,
}

fn route(path: &str) -> Route<'_> {
    if let Some(asset) = ASSETS.iter().find(|asset| asset.path == path) {
        return Route::Asset(asset);
    }
    if path == "/api/catalog" {
        return Route::List;
    }
    match path
        .strip_prefix("/api/catalog/")
        .and_then(|rest| rest.strip_suffix("/openapi"))
    {
        Some(rest) => Route::Document(rest),
        None => Route::Unknown,
    }
}

/// `tenant/id/version` from the percent-encoded middle of a document path. An id and a version
/// never hold `/`, so the text is split from the right and the tenant keeps any it has.
fn document_key(encoded: &str) -> Option<(String, String, String)> {
    let decoded = percent_decode(encoded)?;
    let mut parts = decoded.rsplitn(3, '/');
    let (version, id, tenant) = (parts.next()?, parts.next()?, parts.next()?);
    (!version.is_empty() && !id.is_empty() && !tenant.is_empty())
        .then(|| (tenant.to_owned(), id.to_owned(), version.to_owned()))
}

/// Decodes `%XX` once. `None` for a bad escape, bytes that are not UTF-8 or a control character.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            let digits = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            at += 3;
        } else {
            out.push(byte);
            at += 1;
        }
    }
    let decoded = String::from_utf8(out).ok()?;
    (!decoded.chars().any(char::is_control)).then_some(decoded)
}

/// What the stage answers with.
struct Reply {
    status: u16,
    content_type: &'static str,
    cache: &'static str,
    body: Bytes,
    allow: bool,
}

impl Reply {
    fn json(status: u16, body: &'static str) -> Self {
        Self {
            status,
            content_type: "application/json",
            cache: "no-store",
            body: Bytes::from_static(body.as_bytes()),
            allow: false,
        }
    }

    fn not_found() -> Self {
        Self::json(404, r#"{"error":"not found"}"#)
    }

    fn unauthorized() -> Self {
        Self::json(401, r#"{"error":"unauthorized"}"#)
    }

    fn bad_query() -> Self {
        Self::json(400, r#"{"error":"invalid query"}"#)
    }

    fn busy() -> Self {
        Self::json(503, r#"{"error":"portal is busy"}"#)
    }

    fn unavailable() -> Self {
        Self::json(503, r#"{"error":"portal is unavailable"}"#)
    }

    fn data(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            cache: "no-store",
            body: Bytes::from(body),
            allow: false,
        }
    }

    fn method_not_allowed() -> Self {
        Self {
            allow: true,
            ..Self::json(405, r#"{"error":"method not allowed"}"#)
        }
    }

    fn asset(asset: &Asset) -> Self {
        Self {
            status: 200,
            content_type: asset.content_type,
            cache: "no-cache",
            body: Bytes::from_static(asset.bytes),
            allow: false,
        }
    }

    /// What the access log says about a refusal.
    fn reason(&self) -> Option<&'static str> {
        match self.status {
            400 => Some("portal_bad_query"),
            401 => Some("portal_unauthorized"),
            404 => Some("portal_not_found"),
            405 => Some("portal_method"),
            503 => Some("portal_busy"),
            _ => None,
        }
    }
}

impl Portal {
    /// The reply to one request, computed from the live table for this viewer.
    async fn reply(
        &self,
        method: &Method,
        path: &str,
        query: Option<&str>,
        viewer: &Viewer,
    ) -> Reply {
        let route = route(path);
        if matches!(route, Route::Unknown) {
            return Reply::not_found();
        }
        if method != Method::GET && method != Method::HEAD {
            return Reply::method_not_allowed();
        }
        if let Route::Asset(asset) = route {
            return Reply::asset(asset);
        }
        if !viewer.is_known() {
            return Reply::unauthorized();
        }
        let Ok(_slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Reply::busy();
        };
        let Some(live) = self.live.upgrade() else {
            return Reply::unavailable();
        };
        let table = live.load_full();
        let viewer = viewer.clone();
        let work = match route {
            Route::List => {
                let Some(query) = list::Query::parse(query) else {
                    return Reply::bad_query();
                };
                tokio::task::spawn_blocking(move || {
                    Reply::data(list::render(&table, &viewer, &query))
                })
            }
            Route::Document(encoded) => {
                if query.is_some_and(|query| !query.is_empty()) {
                    return Reply::bad_query();
                }
                let Some(key) = document_key(encoded) else {
                    return Reply::not_found();
                };
                tokio::task::spawn_blocking(move || document_reply(&table, &viewer, &key))
            }
            Route::Asset(_) | Route::Unknown => return Reply::not_found(),
        };
        // The slot is held until the work ends; a panic in it is an error, not a hang.
        work.await.unwrap_or_else(|_| Reply::unavailable())
    }
}

/// The document of `key` for `viewer`, or the one `404`.
fn document_reply(table: &RoutingTable, viewer: &Viewer, key: &(String, String, String)) -> Reply {
    let (tenant, id, version) = key;
    if viewer.tenant() != Some(tenant.as_str()) {
        return Reply::not_found();
    }
    let Some(entry) = find(table, viewer, id, version) else {
        return Reply::not_found();
    };
    let Some(description) = entry.openapi() else {
        return Reply::not_found();
    };
    match document::project(description.document().source())
        .and_then(|view| serde_json::to_vec(&view).ok())
    {
        Some(body) => Reply::data(body),
        None => Reply::not_found(),
    }
}

impl Kind for Portal {
    type State = ();

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let Some(grant) = cx.portal.as_ref() else {
            // Nothing of the operator's list or pins is said.
            return Err(Invalid::new(
                "portal_not_allowed",
                "portal: this app may not declare a portal middleware; it is operator-only",
            ));
        };
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let claim = config
            .tenant_claim
            .unwrap_or_else(|| DEFAULT_CLAIM.to_owned());
        if claim.is_empty()
            || claim.len() > MAX_CLAIM
            || !claim
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(invalid(format!(
                "`tenant_claim` is 1 to {MAX_CLAIM} letters, digits and `-_.:`"
            )));
        }
        let live = Grant::live(grant);
        if live.strong_count() == 0 {
            return Err(invalid("there is no live table to read the catalog from"));
        }
        Ok(Self {
            claim: claim.into(),
            live,
            slots: Arc::new(Semaphore::new(SLOTS)),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let request = cx.session.req_header();
        let method = request.method.clone();
        let path = request.uri.path().to_owned();
        let query = request.uri.query().map(str::to_owned);
        let viewer = Viewer::from_claims(cx.claims.as_ref(), &self.claim);
        let reply = self.reply(&method, &path, query.as_deref(), &viewer).await;
        if reply.status == 503 {
            *cx.capacity_refusal = true;
        }
        *cx.reason = reply.reason();
        let mut head = ResponseHeader::build(reply.status, Some(9))?;
        head.insert_header("content-type", reply.content_type)?;
        head.insert_header("content-length", reply.body.len().to_string())?;
        head.insert_header("content-security-policy", CONTENT_SECURITY_POLICY_VALUE)?;
        head.insert_header("x-content-type-options", "nosniff")?;
        head.insert_header("referrer-policy", "no-referrer")?;
        head.insert_header("cache-control", reply.cache)?;
        if reply.allow {
            head.insert_header("allow", "GET, HEAD")?;
        }
        let send_body = method != Method::HEAD;
        cx.session
            .write_response_header(Box::new(head), !send_body)
            .await?;
        if send_body {
            cx.session
                .write_response_body(Some(reply.body), true)
                .await?;
        }
        Ok(Flow::Respond)
    }

    /// The portal verifies nothing and fills no claims.
    fn login(&self) -> Option<Login> {
        None
    }

    fn describe(&self) -> Value {
        json!({ "tenant_claim": &*self.claim })
    }
}

/// The fixed refusal of a login the operator did not pin. It names neither the pin nor the
/// stage's settings: the app's owner learns that it is wrong, not what would be right.
const NOT_PINNED: &str =
    "the login in front of the portal is not the one the operator pinned for this app";

/// Refuses what the operator's rules refuse about the `portal` stages of `app`, per router chain
/// (`chains`: the routers with their effective chains, as indices into `stages`): a portal with
/// no stage before it that fills claims is `portal_needs_login`, and every such stage before it
/// must verify with exactly the issuer and key source the operator pinned for the app, or
/// `portal_login_not_pinned`. It reads the compiled stages, not the declared names, so a `chain`
/// middleware or a renamed declaration cannot hide a stage.
pub(crate) fn check_chains(
    app: &App,
    stages: &[Named],
    chains: &[(&str, Vec<usize>)],
    grants: &Grants,
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    // An app that is not listed has no portal stage: each one was refused as it compiled.
    let Some(grant) = grants.of(&app.tenant, &app.id) else {
        return rejected;
    };
    for (router, chain) in chains {
        for (position, index) in chain.iter().enumerate() {
            if !matches!(
                stages.get(*index),
                Some(Named {
                    stage: Stage::Portal(_),
                    ..
                })
            ) {
                continue;
            }
            let logins: Vec<Login> = super::logins_before(stages, chain, position).collect();
            let at = format!("router {router}");
            if logins.is_empty() {
                rejected.push(Rejected::new(
                    app,
                    at,
                    Invalid::new(
                        "portal_needs_login",
                        "the portal needs a jwt_auth or oidc stage before it in the chain",
                    ),
                ));
            } else if logins.iter().any(|login| !grant.pin().admits(login)) {
                rejected.push(Rejected::new(
                    app,
                    at,
                    Invalid::new("portal_login_not_pinned", NOT_PINNED),
                ));
            }
        }
    }
    rejected
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::wasm as engine;

    #[test]
    fn a_stage_holding_no_grant_cannot_compile_portal() {
        let declared: Declared =
            serde_json::from_value(json!({"name": "p", "type": "portal"})).expect("declared");
        let app = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app");
        let mut compiler = engine::Compiler::default();
        let refused = Portal::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
                portal: None,
            },
        )
        .expect_err("no grant");
        assert_eq!(refused.code, "portal_not_allowed");
        assert!(
            !refused.message.contains("PORTAL_APPS"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn routes_and_decoding() {
        assert!(matches!(route("/"), Route::Asset(_)));
        assert!(matches!(route("/app.js"), Route::Asset(_)));
        assert!(matches!(route("/api/catalog"), Route::List));
        assert!(matches!(route("/api/catalog/"), Route::Unknown));
        assert!(matches!(route("/api/overview"), Route::Unknown));
        assert!(matches!(route("/v1/snapshot"), Route::Unknown));
        assert!(matches!(route("/../Cargo.toml"), Route::Unknown));
        assert!(matches!(
            route("/api/catalog/a/b/1/openapi"),
            Route::Document("a/b/1")
        ));
        assert_eq!(
            document_key("acme/pets/1"),
            Some(("acme".into(), "pets".into(), "1".into()))
        );
        assert_eq!(
            document_key("a%2Fb/pets/1"),
            Some(("a/b".into(), "pets".into(), "1".into()))
        );
        for bad in [
            "pets/1",
            "a//1",
            "/pets/1",
            "a/pets/",
            "a/%zz/1",
            "a/%00/1",
            "a/%ff/1",
            "a/%2e%2e%2f/1",
        ] {
            let key = document_key(bad);
            assert!(
                key.as_ref()
                    .is_none_or(|(_, id, _)| !id.contains("..") || id.contains('/')),
                "{bad}: {key:?}"
            );
        }
        assert_eq!(document_key("a/%00/1"), None);
        assert_eq!(document_key("a/%ff/1"), None);
    }

    #[test]
    fn portal_slots_cap_concurrent_answers() {
        let slots = Arc::new(Semaphore::new(SLOTS));
        let held: Vec<_> = (0..SLOTS)
            .map(|_| Arc::clone(&slots).try_acquire_owned().expect("a free slot"))
            .collect();
        assert!(Arc::clone(&slots).try_acquire_owned().is_err());
        drop(held);
        assert!(Arc::clone(&slots).try_acquire_owned().is_ok());
    }
}
