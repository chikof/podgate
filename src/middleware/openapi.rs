//! The `openapi` middleware: refuses a request that does not fit an OpenAPI description before it
//! reaches the upstream. Full reference: `docs/ref/mw-openapi.md`.
//!
//! ```json
//! { "name": "api", "type": "openapi", "max_body_bytes": 65536,
//!   "document": { "openapi": "3.1.0", "info": {"title": "Pets", "version": "1"},
//!                 "paths": { "/pets/{id}": { "get": { "parameters": [ ... ] } } } } }
//! ```
//!
//! The document is JSON, inline in the snapshot, at most 1 MiB, and is compiled once per
//! snapshot into a [`Document`] (the type the API catalog of change 0135 reads). Checked, in this
//! order: the path template (`404`), the method (`405` with `allow`), the media type of a body
//! (`415`, or `400` for a body the operation does not declare), the declared body size (`413`),
//! the parameters (`400`), a required body (`400`), and the JSON body against its schema (`400`).
//! The answer is `{"error": "request does not match the API description", "violations": [...]}`,
//! at most 10 violations, none of them repeating a value from the request.
//!
//! Tenant-supplied input, so everything is bounded: the caps are constants in `openapi/document.rs`, only
//! a local `$ref` is followed, a `$ref` cycle and a schema keyword the validator cannot enforce
//! are refused when the snapshot compiles, a JSON body is held in memory (at most
//! `max_body_bytes`, charged to the tenant's `max_buffer_bytes` before it is read), and a request
//! that is too much to check (a step budget) is refused. A body that cannot be checked is never
//! forwarded. Responses, `security`, `servers` and `callbacks` are not read.

mod build;
mod document;
mod request;
mod schema;
mod strict_json;

use std::sync::Arc;

use bytes::Bytes;
use http::Method;
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Map, Value, json};

pub use document::Document;
pub use schema::Dialect;

use self::document::{MAX_APP_BYTES, MAX_DOCUMENT_BYTES, MAX_PER_APP, serialized_len};
use self::request::{Head, Refusal, Violation, parse_cost};
use super::buffering::{self, declared_length, expects_continue};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::budget::BufferGuard;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::respond;
use podgate_model::Declared;

/// The default and the largest `max_body_bytes`: what Pingora's replay buffer can hand over
/// (`buffering::MAX_BUFFERED_REQUEST_BYTES`, checked by a test).
const DEFAULT_BODY: u32 = 64 * 1024;

/// The configuration of an `openapi` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The OpenAPI 3.0 or 3.1 document, as a JSON object, at most 1 MiB. Only local `$ref`s
    /// (`#/...`) are followed, and a `$ref` cycle is refused.
    document: Map<String, Value>,
    /// Largest JSON body that is checked; a larger one is answered `413`. Default and at most
    /// 65536.
    #[serde(default)]
    max_body_bytes: Option<u32>,
}

/// A compiled `openapi` middleware.
#[derive(Debug)]
pub struct Openapi {
    document: Arc<Document>,
    max_body: u32,
}

impl Openapi {
    /// The parsed document, for the catalog.
    #[must_use]
    pub fn document(&self) -> &Arc<Document> {
        &self.document
    }
}

/// What one request keeps for this stage.
#[derive(Debug, Default)]
pub struct State {
    /// The charge for the held body, until the request ends.
    held: Option<BufferGuard>,
}

/// Why a body could not be held.
enum Stop {
    Refuse(Refusal),
    Answer(AppError),
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("openapi: {message}"))
}

/// The refusal for an error that [`read_body`] reports.
fn read_failed(err: &AppError) -> Stop {
    match err {
        AppError::PayloadTooLarge => Stop::Refuse(Refusal::one(
            413,
            "openapi_body_too_large",
            Violation::plain("body", "the body is larger than the API description allows"),
        )),
        other => Stop::Answer(match other {
            AppError::RequestTimeout => AppError::RequestTimeout,
            _ => AppError::BadRequest("the body could not be read".into()),
        }),
    }
}

impl Openapi {
    /// Holds the whole JSON body in Pingora's replay buffer, charged to the tenant first.
    async fn hold(
        &self,
        cx: &mut RequestCx<'_>,
        state: &mut State,
        declared: Option<u64>,
    ) -> pingora::Result<Result<Bytes, Stop>> {
        let max = u64::from(self.max_body);
        // An earlier stage that read the body already charged for it.
        if !*cx.body_held
            && let Some(tenant) = cx.tenant
        {
            let Some(guard) = tenant.reserve_buffering(declared.unwrap_or(max)) else {
                *cx.capacity_refusal = true;
                return Ok(Err(Stop::Answer(AppError::BufferingOverBudget)));
            };
            state.held = Some(guard);
        }
        let held = buffering::hold_body(cx.session, cx.body_held, max).await?;
        Ok(held.map_err(|err| read_failed(&err)))
    }
}

/// Writes the refusal as the answer.
async fn refuse(
    cx: &mut RequestCx<'_>,
    mut refusal: Refusal,
    expects: bool,
) -> pingora::Result<Flow> {
    if refusal.status == 413 && expects {
        refusal.status = 417;
    }
    *cx.reason = Some(refusal.reason);
    let mut body = json!({
        "error": "request does not match the API description",
        "violations": refusal.violations.iter().map(Violation::to_json).collect::<Vec<_>>(),
    });
    if refusal.truncated {
        body["truncated"] = Value::Bool(true);
    }
    let payload = Bytes::from(body.to_string());
    let mut head = ResponseHeader::build(refusal.status, Some(4))?;
    head.insert_header("content-type", "application/json")?;
    head.insert_header("content-length", payload.len().to_string())?;
    if let Some(allow) = &refusal.allow {
        head.insert_header("allow", &**allow)?;
    }
    let head_only = cx.session.req_header().method == Method::HEAD;
    cx.session
        .write_response_header(Box::new(head), head_only)
        .await?;
    if !head_only {
        cx.session.write_response_body(Some(payload), true).await?;
    }
    Ok(Flow::Respond)
}

impl Kind for Openapi {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let max_body = match config.max_body_bytes {
            None => DEFAULT_BODY,
            Some(max) if (1..=DEFAULT_BODY).contains(&max) => max,
            Some(_) => {
                return Err(invalid(format!(
                    "max_body_bytes is 1 to {DEFAULT_BODY}: a held body goes upstream through Pingora's 64 KiB replay buffer"
                )));
            }
        };
        if serialized_len(&config.document) > MAX_DOCUMENT_BYTES {
            return Err(invalid(format!(
                "the document is over {MAX_DOCUMENT_BYTES} bytes"
            )));
        }
        let mut siblings = cx
            .app
            .middlewares
            .iter()
            .filter(|other| &*other.kind == "openapi")
            .peekable();
        if siblings
            .peek()
            .is_some_and(|first| first.name == declared.name)
        {
            // One middleware of the app checks the app's total, so the sum is computed once.
            let (count, total) = siblings.fold((0_usize, 0_usize), |(count, total), other| {
                let size = other
                    .config
                    .get("document")
                    .and_then(Value::as_object)
                    .map_or(0, serialized_len);
                (count + 1, total.saturating_add(size))
            });
            if count > MAX_PER_APP {
                return Err(invalid(format!(
                    "an app has at most {MAX_PER_APP} openapi middlewares"
                )));
            }
            if total > MAX_APP_BYTES {
                return Err(invalid(format!(
                    "the documents of an app total over {MAX_APP_BYTES} bytes"
                )));
            }
        }
        let document = Document::compile(&config.document)?;
        Ok(Self {
            document: Arc::new(document),
            max_body,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let body_present = !cx.session.is_body_empty();
        let expects = expects_continue(cx.session.req_header());
        let declared = declared_length(&cx.session.req_header().headers);
        let checked = {
            let request = cx.session.req_header();
            self.document.check_head(&Head {
                method: &request.method,
                path: request.uri.path(),
                query: request.uri.query(),
                headers: &request.headers,
                body_present,
                declared,
                max_body: self.max_body,
            })
        };
        let mut admitted = match checked {
            Ok(admitted) => admitted,
            Err(refusal) => return refuse(cx, refusal, expects).await,
        };
        if admitted.body_schema().is_none() {
            return Ok(Flow::Continue);
        }
        let body = match self.hold(cx, state, declared).await? {
            Ok(body) => body,
            Err(Stop::Refuse(refusal)) => return refuse(cx, refusal, expects).await,
            Err(Stop::Answer(err)) => {
                respond::write_error(cx.session, &err).await?;
                return Ok(Flow::Respond);
            }
        };
        // The parsed value is far larger than the text, so it is charged too, before it exists.
        let _parsed = match cx.tenant {
            Some(tenant) => {
                let Some(guard) = tenant.reserve_buffering(parse_cost(&body)) else {
                    *cx.capacity_refusal = true;
                    respond::write_error(cx.session, &AppError::BufferingOverBudget).await?;
                    return Ok(Flow::Respond);
                };
                Some(guard)
            }
            None => None,
        };
        match admitted.check_body(&body) {
            Ok(()) => Ok(Flow::Continue),
            Err(refusal) => refuse(cx, refusal, expects).await,
        }
    }

    /// Removing the stage, or raising the body limit, is less protection than before. A changed
    /// document is not listed: schemas cannot be ordered by strength.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            None => vec!["openapi_validation_removed"],
            Some(new) if new.max_body > self.max_body => vec!["openapi_body_limit_loosened"],
            Some(_) => Vec::new(),
        }
    }

    fn describe(&self) -> Value {
        json!({
            "title": self.document.title(),
            "version": self.document.version(),
            "dialect": match self.document.dialect() {
                Dialect::V30 => "3.0",
                Dialect::V31 => "3.1",
            },
            "operations": self.document.operation_count(),
            "max_body_bytes": self.max_body,
        })
    }
}

#[cfg(test)]
mod test {
    use http::{HeaderMap, HeaderName, HeaderValue};

    use super::request::Admitted;
    use super::*;
    use crate::middleware::buffering::MAX_BUFFERED_REQUEST_BYTES;

    fn api(dialect: &str, paths: &Value, components: &Value) -> Map<String, Value> {
        let document = json!({
            "openapi": dialect,
            "info": { "title": "Pets", "version": "1.2" },
            "paths": paths,
            "components": components,
        });
        document.as_object().expect("object").clone()
    }

    fn v31(paths: &Value) -> Document {
        Document::compile(&api("3.1.0", paths, &json!({}))).expect("compiles")
    }

    fn body_op(schema: &Value) -> Value {
        json!({ "/x": { "post": { "requestBody": { "required": true, "content": {
            "application/json": { "schema": schema } } } } } })
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        map
    }

    /// Runs the whole check on a request; `Ok` when the request would be forwarded.
    fn check(
        doc: &Document,
        method: &Method,
        target: &str,
        pairs: &[(&str, &str)],
        body: Option<&str>,
    ) -> Result<(), Refusal> {
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target, None),
        };
        let map = headers(pairs);
        let mut admitted: Admitted<'_> = doc.check_head(&Head {
            method,
            path,
            query,
            headers: &map,
            body_present: body.is_some(),
            declared: body.map(|body| u64::try_from(body.len()).expect("len")),
            max_body: DEFAULT_BODY,
        })?;
        match (admitted.body_schema(), body) {
            (Some(_), Some(body)) => admitted.check_body(body.as_bytes()),
            _ => Ok(()),
        }
    }

    fn post(doc: &Document, body: &str) -> Result<(), Refusal> {
        check(
            doc,
            &Method::POST,
            "/x",
            &[("content-type", "application/json")],
            Some(body),
        )
    }

    fn status(result: Result<(), Refusal>) -> u16 {
        result.map_or_else(|refusal| refusal.status, |()| 0)
    }

    fn pets() -> Document {
        Document::compile(&api(
            "3.0.3",
            &json!({
                "/pets": {
                    "get": { "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 100 } },
                        { "name": "tag", "in": "query", "schema": { "type": "array", "items": { "type": "string" }, "maxItems": 3 } },
                        { "name": "x-trace", "in": "header", "required": true, "schema": { "type": "string", "minLength": 3 } }
                    ] },
                    "post": { "requestBody": { "required": true, "content": {
                        "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } },
                        "text/plain": {} } } }
                },
                "/pets/mine": { "get": {} },
                "/pets/{id}": { "get": { "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } } ] } },
                "/files/{name}.json": { "get": { "parameters": [
                    { "name": "name", "in": "path", "required": true, "schema": { "type": "string", "pattern": "^[a-z]+$" } } ] } }
            }),
            &json!({ "schemas": { "Pet": {
                "type": "object", "required": ["name"], "additionalProperties": false,
                "properties": {
                    "name": { "type": "string", "minLength": 1 },
                    "tag": { "type": "string", "nullable": true },
                    "age": { "type": "integer", "minimum": 0, "exclusiveMinimum": false }
                } } } }),
        ))
        .expect("pets compiles")
    }

    #[test]
    fn openapi_literal_path_beats_template() {
        let doc = pets();
        // `/pets/mine` has no parameters; `/pets/{id}` would refuse `mine` as a non-integer.
        assert_eq!(
            status(check(&doc, &Method::GET, "/pets/mine", &[], None)),
            0
        );
        assert_eq!(status(check(&doc, &Method::GET, "/pets/7", &[], None)), 0);
        assert_eq!(
            status(check(&doc, &Method::GET, "/pets/seven", &[], None)),
            400
        );
        assert_eq!(
            status(check(&doc, &Method::GET, "/files/abc.json", &[], None)),
            0
        );
        assert_eq!(
            status(check(&doc, &Method::GET, "/files/ABC.json", &[], None)),
            400
        );
        assert_eq!(
            status(check(&doc, &Method::GET, "/files/abc.txt", &[], None)),
            404
        );
        assert_eq!(status(check(&doc, &Method::GET, "/pets/", &[], None)), 404);
        assert_eq!(status(check(&doc, &Method::GET, "/nope", &[], None)), 404);
    }

    #[test]
    fn openapi_unknown_path_and_method() {
        let doc = pets();
        let refusal = check(&doc, &Method::DELETE, "/pets", &[], None).expect_err("405");
        assert_eq!(refusal.status, 405);
        assert_eq!(refusal.allow.as_deref(), Some("GET, POST"));
        assert_eq!(status(check(&doc, &Method::GET, "/other", &[], None)), 404);
    }

    #[test]
    fn openapi_required_header_and_parameters() {
        let doc = pets();
        assert_eq!(status(check(&doc, &Method::GET, "/pets", &[], None)), 400);
        let ok = [("x-trace", "abc")];
        assert_eq!(
            status(check(
                &doc,
                &Method::GET,
                "/pets?limit=5&tag=a&tag=b",
                &ok,
                None
            )),
            0
        );
        assert_eq!(
            status(check(&doc, &Method::GET, "/pets?limit=abc", &ok, None)),
            400
        );
        assert_eq!(
            status(check(&doc, &Method::GET, "/pets?limit=0", &ok, None)),
            400
        );
        assert_eq!(
            status(check(
                &doc,
                &Method::GET,
                "/pets?limit=1&limit=2",
                &ok,
                None
            )),
            400
        );
        assert_eq!(
            status(check(
                &doc,
                &Method::GET,
                "/pets?tag=a&tag=b&tag=c&tag=d",
                &ok,
                None
            )),
            400
        );
        assert_eq!(
            status(check(
                &doc,
                &Method::GET,
                "/pets",
                &[("x-trace", "ab")],
                None
            )),
            400
        );
    }

    #[test]
    fn openapi_30_nullable() {
        let doc = pets();
        let json = |body: &str| {
            check(
                &doc,
                &Method::POST,
                "/pets",
                &[("content-type", "application/json; charset=utf-8")],
                Some(body),
            )
        };
        assert_eq!(status(json(r#"{"name":"rex","tag":null}"#)), 0);
        assert_eq!(status(json(r#"{"name":"rex","tag":"good"}"#)), 0);
        assert_eq!(status(json(r#"{"name":"rex","tag":3}"#)), 400);
        assert_eq!(status(json(r#"{"name":null}"#)), 400);
        assert_eq!(status(json(r#"{"name":"rex","extra":1}"#)), 400);
        assert_eq!(status(json(r#"{"tag":"x"}"#)), 400);
        assert_eq!(status(json(r#"{"name":"rex","age":-1}"#)), 400);
    }

    #[test]
    fn openapi_31_type_array() {
        let doc = v31(&body_op(
            &json!({ "type": ["string", "null"], "minLength": 2 }),
        ));
        assert_eq!(status(post(&doc, r#""ab""#)), 0);
        assert_eq!(status(post(&doc, "null")), 0);
        assert_eq!(status(post(&doc, r#""a""#)), 400);
        assert_eq!(status(post(&doc, "5")), 400);
    }

    #[test]
    fn openapi_30_rules_are_not_31_rules() {
        let compile = |dialect: &str, schema: Value| {
            Document::compile(&api(dialect, &body_op(&schema), &json!({})))
        };
        assert_eq!(
            compile("3.0.3", json!({ "const": 1 }))
                .expect_err("const")
                .code,
            "unsupported_setting"
        );
        assert_eq!(
            compile("3.0.3", json!({ "type": ["string"] }))
                .expect_err("array")
                .code,
            "invalid_middleware"
        );
        assert_eq!(
            compile("3.1.0", json!({ "nullable": true }))
                .expect_err("nullable")
                .code,
            "unsupported_setting"
        );
        assert_eq!(
            compile(
                "3.1.0",
                json!({ "type": "integer", "exclusiveMinimum": true })
            )
            .expect_err("bool")
            .code,
            "invalid_middleware"
        );
        assert!(compile("3.1.0", json!({ "type": "integer", "exclusiveMinimum": 3 })).is_ok());
        assert!(
            compile(
                "3.0.3",
                json!({ "type": "integer", "minimum": 3, "exclusiveMinimum": true })
            )
            .is_ok()
        );
        assert_eq!(
            compile("3.2.0", json!({})).expect_err("version").code,
            "invalid_middleware"
        );
    }

    #[test]
    fn openapi_unsupported_keyword_rejected() {
        let compile =
            |schema: Value| Document::compile(&api("3.1.0", &body_op(&schema), &json!({})));
        for keyword in [
            "if",
            "contains",
            "patternProperties",
            "propertyNames",
            "dependentSchemas",
            "unevaluatedProperties",
            "$dynamicRef",
        ] {
            let error = compile(json!({ keyword: {} })).expect_err(keyword);
            assert_eq!(error.code, "unsupported_setting", "{keyword}");
        }
        let unknown =
            compile(json!({ "type": "object", "frobnicate": ["a"] })).expect_err("unknown");
        assert_eq!(unknown.code, "invalid_middleware");
        assert!(compile(json!({ "type": "object", "x-vendor": 1, "description": "d", "example": {}, "discriminator": {} })).is_ok());
    }

    #[test]
    fn openapi_remote_ref_rejected() {
        let compile = |reference: &str| {
            Document::compile(&api(
                "3.1.0",
                &body_op(&json!({ "$ref": reference })),
                &json!({ "schemas": { "A": {} } }),
            ))
        };
        assert!(compile("#/components/schemas/A").is_ok());
        for remote in [
            "https://example.test/a.json",
            "other.json#/A",
            "file:///etc/passwd",
            "http://169.254.169.254/",
        ] {
            let error = compile(remote).expect_err(remote);
            assert_eq!(error.code, "invalid_middleware", "{remote}");
            assert!(error.message.contains("not local"), "{}", error.message);
        }
        assert!(compile("#/components/schemas/Missing").is_err());
    }

    #[test]
    fn openapi_ref_cycle_rejected() {
        let cyclic = json!({ "schemas": {
            "Node": { "type": "object", "properties": { "next": { "$ref": "#/components/schemas/Node" } } },
            "A": { "$ref": "#/components/schemas/B" },
            "B": { "$ref": "#/components/schemas/A" } } });
        for name in ["Node", "A"] {
            let error = Document::compile(&api(
                "3.1.0",
                &body_op(&json!({ "$ref": format!("#/components/schemas/{name}") })),
                &cyclic,
            ))
            .expect_err(name);
            assert_eq!(error.code, "invalid_middleware");
            assert!(error.message.contains("cycle"), "{}", error.message);
        }
    }

    #[test]
    fn openapi_document_caps() {
        let compile = |document: Map<String, Value>| Document::compile(&document);
        // Nesting: a schema chain deeper than the cap.
        let mut deep = json!({ "type": "string" });
        for _ in 0..70 {
            deep = json!({ "type": "array", "items": deep });
        }
        assert!(compile(api("3.1.0", &body_op(&deep), &json!({}))).is_err());
        // $ref fan-out: each level refers to the previous one twice.
        let mut schemas = Map::new();
        schemas.insert("L0".into(), json!({ "type": "string" }));
        for level in 1..=30 {
            schemas.insert(
                format!("L{level}"),
                json!({ "allOf": [
                    { "$ref": format!("#/components/schemas/L{}", level - 1) },
                    { "$ref": format!("#/components/schemas/L{}", level - 1) } ] }),
            );
        }
        let fanout = compile(api(
            "3.1.0",
            &body_op(&json!({ "$ref": "#/components/schemas/L30" })),
            &json!({ "schemas": schemas }),
        ));
        assert!(fanout.expect_err("fan-out").message.contains("expands"));
        // Paths.
        let mut paths = Map::new();
        for index in 0..1_001 {
            paths.insert(format!("/p{index}"), json!({ "get": {} }));
        }
        assert!(compile(api("3.1.0", &Value::Object(paths), &json!({}))).is_err());
        // Sizes and shape.
        assert!(compile(Map::new()).is_err());
        let nested = (0..70).fold(json!(1), |inner, _| json!({ "n": inner }));
        assert!(
            compile(api("3.1.0", &json!({}), &nested))
                .expect_err("nesting")
                .message
                .contains("nests")
        );
        // A pattern that is too big to compile.
        let pattern = json!({ "type": "string", "pattern": "(a{1000}){1000}" });
        assert!(compile(api("3.1.0", &body_op(&pattern), &json!({}))).is_err());
    }

    #[test]
    fn openapi_violations_bounded() {
        let doc = v31(&body_op(
            &json!({ "type": "array", "items": { "type": "integer" } }),
        ));
        let body = serde_json::to_string(
            &(0..50)
                .map(|index| format!("secret-{index}"))
                .collect::<Vec<_>>(),
        )
        .expect("json");
        let refusal = post(&doc, &body).expect_err("refused");
        assert_eq!(refusal.violations.len(), 10);
        assert!(refusal.truncated);
        let text = format!("{:?}", refusal.violations);
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(refusal.violations[0].pointer.as_deref(), Some("/0"));
    }

    #[test]
    fn openapi_step_budget_refuses() {
        // Each of the 30,000 items costs the item and its eight branches: over the 200,000 steps.
        let branch = json!({ "type": "integer" });
        let doc = v31(&body_op(
            &json!({ "type": "array", "items": { "allOf": vec![branch; 8] } }),
        ));
        let body = format!("[{}]", vec!["1"; 30_000].join(","));
        let refusal = check(
            &doc,
            &Method::POST,
            "/x",
            &[("content-type", "application/json")],
            Some(&body),
        )
        .expect_err("refused");
        assert_eq!(refusal.reason, "openapi_too_complex");
    }

    #[test]
    fn openapi_media_and_body_rules() {
        let doc = pets();
        let send = |content_type: &[(&str, &str)], body: Option<&str>| {
            status(check(&doc, &Method::POST, "/pets", content_type, body))
        };
        assert_eq!(send(&[("content-type", "text/plain")], Some("hello")), 0);
        assert_eq!(
            send(&[("content-type", "application/xml")], Some("<a/>")),
            415
        );
        assert_eq!(send(&[], Some("{}")), 415);
        assert_eq!(send(&[], None), 400);
        assert_eq!(
            send(
                &[("content-type", "application/json")],
                Some(r#"{"name":"a"}"#)
            ),
            0
        );
        assert_eq!(
            send(&[("content-type", "application/json")], Some("{bad")),
            400
        );
        let get = check(
            &doc,
            &Method::GET,
            "/pets/mine",
            &[("content-type", "application/json")],
            Some("{}"),
        );
        assert_eq!(status(get), 400);
    }

    #[test]
    fn openapi_matches_reference_validator() {
        let cases: Vec<(Value, Vec<Value>)> = vec![
            (
                json!({ "type": "integer" }),
                vec![
                    json!(1),
                    json!(1.0),
                    json!(1.5),
                    json!("1"),
                    json!(null),
                    json!(true),
                ],
            ),
            (
                json!({ "type": "number", "minimum": 1, "maximum": 3 }),
                vec![json!(0), json!(1), json!(3), json!(3.1), json!("2")],
            ),
            (
                json!({ "type": "number", "exclusiveMinimum": 1, "exclusiveMaximum": 3 }),
                vec![json!(1), json!(1.5), json!(3), json!(2)],
            ),
            (
                json!({ "type": "number", "multipleOf": 0.5 }),
                vec![json!(1), json!(1.5), json!(1.2), json!(-2)],
            ),
            (
                json!({ "type": "integer", "multipleOf": 3 }),
                vec![json!(9), json!(10), json!(0)],
            ),
            (
                json!({ "type": "string", "minLength": 2, "maxLength": 3 }),
                vec![
                    json!("a"),
                    json!("ab"),
                    json!("abcd"),
                    json!("日本"),
                    json!(5),
                ],
            ),
            (
                json!({ "type": "string", "pattern": "^a+b$" }),
                vec![json!("aab"), json!("ab "), json!("b"), json!(3)],
            ),
            (
                json!({ "enum": [1, "a", null, [1, 2], { "k": 1.0 }] }),
                vec![
                    json!(1),
                    json!(1.0),
                    json!("a"),
                    json!(null),
                    json!([1, 2.0]),
                    json!({ "k": 1 }),
                    json!(2),
                    json!("b"),
                ],
            ),
            (
                json!({ "const": { "a": [1] } }),
                vec![json!({ "a": [1] }), json!({ "a": [2] }), json!(null)],
            ),
            (
                json!({ "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 2 }),
                vec![
                    json!([]),
                    json!(["a"]),
                    json!(["a", "b", "c"]),
                    json!([1]),
                    json!("a"),
                ],
            ),
            (
                json!({ "type": "array", "uniqueItems": true }),
                vec![
                    json!([1, 2]),
                    json!([1, 1]),
                    json!([1, 1.0]),
                    json!([{ "a": 1, "b": 2 }, { "b": 2, "a": 1 }]),
                    json!([[1], [2]]),
                    json!(["1", 1]),
                ],
            ),
            (
                json!({ "type": "array", "prefixItems": [{ "type": "integer" }, { "type": "string" }], "items": false }),
                vec![json!([1, "a"]), json!([1, "a", 3]), json!(["a"]), json!([])],
            ),
            (
                json!({ "type": "object", "required": ["a"], "properties": { "a": { "type": "integer" } }, "additionalProperties": false }),
                vec![
                    json!({ "a": 1 }),
                    json!({}),
                    json!({ "a": "x" }),
                    json!({ "a": 1, "b": 2 }),
                ],
            ),
            (
                json!({ "type": "object", "additionalProperties": { "type": "integer" } }),
                vec![json!({ "a": 1, "b": 2 }), json!({ "a": "x" }), json!({})],
            ),
            (
                json!({ "type": "object", "minProperties": 1, "maxProperties": 2 }),
                vec![
                    json!({}),
                    json!({ "a": 1 }),
                    json!({ "a": 1, "b": 2, "c": 3 }),
                ],
            ),
            (
                json!({ "allOf": [{ "type": "integer" }, { "minimum": 2 }] }),
                vec![json!(1), json!(2), json!("a")],
            ),
            (
                json!({ "anyOf": [{ "type": "integer" }, { "type": "string" }] }),
                vec![json!(1), json!("a"), json!(null), json!([1])],
            ),
            (
                json!({ "oneOf": [{ "type": "integer" }, { "minimum": 2 }] }),
                vec![json!(1), json!(2), json!(2.5), json!("a")],
            ),
            (
                json!({ "not": { "type": "string" } }),
                vec![json!("a"), json!(1), json!(null)],
            ),
            (
                json!({ "type": ["integer", "null"] }),
                vec![json!(1), json!(null), json!("a")],
            ),
            (
                json!({ "properties": { "a": { "type": "integer" } } }),
                vec![
                    json!({ "a": "x" }),
                    json!({ "b": "x" }),
                    json!("a"),
                    json!([1]),
                ],
            ),
            (
                json!({ "required": ["a"] }),
                vec![json!({}), json!({ "a": null }), json!(1)],
            ),
            (json!(true), vec![json!(1), json!(null)]),
            (json!(false), vec![json!(1), json!(null)]),
        ];
        for (schema, instances) in cases {
            let ours = v31(&body_op(&schema));
            let reference = jsonschema::draft202012::new(&schema).expect("reference compiles");
            for instance in instances {
                let expected = reference.is_valid(&instance);
                let got = post(&ours, &instance.to_string()).is_ok();
                assert_eq!(got, expected, "schema {schema} instance {instance}");
            }
        }
    }

    #[test]
    fn openapi_formats() {
        let format = |name: &str| v31(&body_op(&json!({ "type": "string", "format": name })));
        let int = |name: &str| v31(&body_op(&json!({ "type": "integer", "format": name })));
        assert!(post(&format("uuid"), r#""123e4567-e89b-12d3-a456-426614174000""#).is_ok());
        assert!(post(&format("uuid"), r#""123e4567e89b12d3a456426614174000""#).is_err());
        assert!(post(&format("date"), r#""2024-02-29""#).is_ok());
        assert!(post(&format("date"), r#""2023-02-29""#).is_err());
        assert!(post(&format("date-time"), r#""2024-05-01T10:20:30.5+02:00""#).is_ok());
        assert!(post(&format("date-time"), r#""2024-05-01T25:20:30Z""#).is_err());
        assert!(post(&format("ipv4"), r#""10.0.0.1""#).is_ok());
        assert!(post(&format("ipv4"), r#""10.0.0""#).is_err());
        assert!(post(&format("ipv6"), r#""::1""#).is_ok());
        assert!(post(&format("email"), r#""not checked""#).is_ok());
        assert!(post(&int("int32"), "2147483647").is_ok());
        assert!(post(&int("int32"), "2147483648").is_err());
        assert!(post(&int("int64"), "9223372036854775807").is_ok());
        assert!(post(&int("int64"), "9223372036854775808").is_err());
    }

    #[test]
    fn openapi_document_caps_by_size() {
        let sized = |bytes: usize| api("3.1.0", &json!({}), &json!({ "pad": "x".repeat(bytes) }));
        let in_app = |documents: &[Map<String, Value>]| {
            let declared: Vec<Declared> = documents
                .iter()
                .enumerate()
                .map(|(index, document)| {
                    serde_json::from_value(json!({
                        "name": format!("api{index}"), "type": "openapi", "document": document
                    }))
                    .expect("declared")
                })
                .collect();
            let app: podgate_model::App = serde_json::from_value(json!({
                "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
                "routers": [], "revisions": [], "middlewares": declared
            }))
            .expect("app");
            let mut engine = crate::wasm::Compiler::default();
            Openapi::compile(
                &declared[0],
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
        };
        assert!(in_app(&[sized(10)]).is_ok());
        let over = in_app(&[sized(MAX_DOCUMENT_BYTES)]).expect_err("one document over 1 MiB");
        assert!(over.message.contains("over"), "{}", over.message);
        let big = sized(900 * 1024);
        let five = in_app(&vec![big; 5]).expect_err("five 900 KiB documents are over 4 MiB");
        assert!(five.message.contains("total"), "{}", five.message);
        let many = in_app(&vec![sized(10); MAX_PER_APP + 1]).expect_err("too many");
        assert!(many.message.contains("at most"), "{}", many.message);
        assert!(in_app(&vec![sized(10); MAX_PER_APP]).is_ok());
    }

    #[test]
    fn openapi_body_limit_is_the_replay_buffer() {
        assert_eq!(u64::from(DEFAULT_BODY), MAX_BUFFERED_REQUEST_BYTES);
    }

    #[test]
    fn openapi_posture() {
        let compile = |max: Option<u32>| {
            let mut config = Map::new();
            config.insert("name".into(), json!("api"));
            config.insert("type".into(), json!("openapi"));
            config.insert(
                "document".into(),
                Value::Object(api("3.1.0", &json!({}), &json!({}))),
            );
            if let Some(max) = max {
                config.insert("max_body_bytes".into(), json!(max));
            }
            let declared: Declared =
                serde_json::from_value(Value::Object(config)).expect("declared");
            let app: podgate_model::App = serde_json::from_value(json!({
                "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
                "routers": [], "revisions": [], "middlewares": [declared.clone()]
            }))
            .expect("app");
            let mut engine = crate::wasm::Compiler::default();
            Openapi::compile(
                &declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
        };
        let small = compile(Some(1000)).expect("small");
        let big = compile(None).expect("big");
        assert_eq!(small.posture(None), ["openapi_validation_removed"]);
        assert_eq!(small.posture(Some(&big)), ["openapi_body_limit_loosened"]);
        assert!(big.posture(Some(&small)).is_empty());
        assert_eq!(
            compile(Some(0)).expect_err("zero").code,
            "invalid_middleware"
        );
        assert_eq!(
            compile(Some(70_000)).expect_err("over").code,
            "invalid_middleware"
        );
    }
}
