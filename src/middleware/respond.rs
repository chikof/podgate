//! The `respond` middleware: answers the request with a fixed response and ends it. It is the
//! building block of closed routes (a `not` matcher plus `respond`). Full reference:
//! `docs/ref/mw-errors.md`.
//!
//! ```json
//! { "name": "closed", "type": "respond", "status": 403,
//!   "headers": { "content-type": "text/plain; charset=utf-8" }, "body": "closed" }
//! ```
//!
//! Everything is checked when the snapshot compiles (`invalid_middleware`): the status is `200`
//! to `599`, a status that carries no body (`204`, `205`, `304`) has none, the header names and
//! values are valid and free of line breaks, no header frames the message or belongs to the
//! connection (the list of the `headers` middleware, which also covers `Content-Length`: it is
//! always the length of `body`), and the sizes are capped. The middleware never contacts an
//! upstream and takes no tenant slot: it runs in the chain, before either.
//!
//! A body without a `content-type` header is served as `text/plain; charset=utf-8`; a response
//! to `HEAD` has the headers and the length of the body, and no body.

use std::collections::BTreeMap;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Value, json};

use super::headers::FORBIDDEN;
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use podgate_model::Declared;

/// The largest `body`.
pub const MAX_BODY: usize = 64 * 1024;
/// The most headers.
const MAX_HEADERS: usize = 64;
/// The longest header value.
const MAX_VALUE: usize = 8 * 1024;
/// The `content-type` of a body that sets none.
const DEFAULT_TYPE: &str = "text/plain; charset=utf-8";

/// The configuration of a `respond` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    status: u16,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

/// A compiled `respond` middleware.
#[derive(Debug)]
pub struct Respond {
    status: StatusCode,
    headers: Box<[(HeaderName, HeaderValue)]>,
    body: Bytes,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_middleware", format!("respond: {}", message.into()))
}

fn header_name(raw: &str) -> Result<HeaderName, Invalid> {
    if raw.starts_with(':') {
        return Err(invalid(format!("{raw}: pseudo headers cannot be set")));
    }
    let parsed = HeaderName::from_bytes(raw.as_bytes())
        .map_err(|_| invalid(format!("{raw:?} is not a valid header name")))?;
    if FORBIDDEN.contains(&parsed.as_str()) || parsed.as_str().starts_with("proxy-") {
        return Err(invalid(format!(
            "{parsed}: a header that frames the message or belongs to the connection cannot be set"
        )));
    }
    Ok(parsed)
}

fn header_value(name: &HeaderName, raw: &str) -> Result<HeaderValue, Invalid> {
    if raw.is_empty() || raw.len() > MAX_VALUE || !raw.is_ascii() {
        return Err(invalid(format!(
            "{name}: the value is 1 to {MAX_VALUE} ASCII bytes"
        )));
    }
    HeaderValue::from_str(raw).map_err(|_| {
        invalid(format!(
            "{name}: the value has a character a header value cannot hold (line breaks, NUL or other control characters)"
        ))
    })
}

impl Kind for Respond {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let status = StatusCode::from_u16(config.status)
            .ok()
            .filter(|status| (200..=599).contains(&status.as_u16()))
            .ok_or_else(|| {
                invalid(format!(
                    "status {} is not in 200..=599: a 1xx response is interim and cannot end a request",
                    config.status
                ))
            })?;
        let body = config.body.unwrap_or_default();
        if body.len() > MAX_BODY {
            return Err(invalid(format!("body is over {MAX_BODY} bytes")));
        }
        if !body.is_empty() && matches!(status.as_u16(), 204 | 205 | 304) {
            return Err(invalid(format!("status {status} has no body")));
        }
        if config.headers.len() > MAX_HEADERS {
            return Err(invalid(format!("at most {MAX_HEADERS} headers")));
        }
        let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::with_capacity(config.headers.len());
        for (raw, text) in &config.headers {
            let name = header_name(raw)?;
            if headers.iter().any(|(seen, _)| *seen == name) {
                return Err(invalid(format!("{name} is set twice")));
            }
            let value = header_value(&name, text)?;
            headers.push((name, value));
        }
        Ok(Self {
            status,
            headers: headers.into_boxed_slice(),
            body: Bytes::from(body.into_bytes()),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let mut head = ResponseHeader::build(self.status, Some(self.headers.len() + 2))?;
        for (name, value) in &self.headers {
            head.insert_header(name.clone(), value.clone())?;
        }
        if !self.body.is_empty() && !head.headers.contains_key("content-type") {
            head.insert_header("content-type", DEFAULT_TYPE)?;
        }
        if !matches!(self.status.as_u16(), 204 | 304) {
            head.insert_header("content-length", self.body.len().to_string())?;
        }
        let send_body = !self.body.is_empty() && cx.session.req_header().method != Method::HEAD;
        cx.session
            .write_response_header(Box::new(head), !send_body)
            .await?;
        if send_body {
            cx.session
                .write_response_body(Some(self.body.clone()), true)
                .await?;
        }
        Ok(Flow::Respond)
    }

    fn describe(&self) -> Value {
        let mut names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        json!({
            "status": self.status.as_u16(),
            "headers": names,
            "body_bytes": self.body.len(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wasm as engine;

    fn compile(config: &Value) -> Result<Respond, Invalid> {
        let mut declared = json!({"name": "r", "type": "respond"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app");
        let mut compiler = engine::Compiler::default();
        Respond::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
            },
        )
    }

    #[test]
    fn compiles_a_status_with_headers_and_a_body() {
        let respond = compile(&json!({
            "status": 418, "headers": {"X-Why": "tea", "content-type": "text/html"}, "body": "<p>no</p>\r\n",
        }))
        .expect("compiled");
        assert_eq!(respond.status.as_u16(), 418);
        assert_eq!(
            respond.describe()["headers"],
            json!(["content-type", "x-why"])
        );
        assert_eq!(respond.describe()["body_bytes"], 11);
        assert!(compile(&json!({"status": 200})).is_ok());
        assert!(compile(&json!({"status": 204})).is_ok());
        assert!(compile(&json!({"status": 599})).is_ok());
    }

    #[test]
    fn refuses_what_cannot_be_sent() {
        let too_many: BTreeMap<String, String> = (0..=MAX_HEADERS)
            .map(|n| (format!("x-{n}"), "v".into()))
            .collect();
        for bad in [
            json!({}),
            json!({"status": "200"}),
            json!({"status": 99}),
            json!({"status": 100}),
            json!({"status": 101}),
            json!({"status": 199}),
            json!({"status": 600}),
            json!({"status": 204, "body": "x"}),
            json!({"status": 304, "body": "x"}),
            json!({"status": 200, "body": "x".repeat(MAX_BODY + 1)}),
            json!({"status": 200, "headers": {"x-a": "line\r\nbreak: 1"}}),
            json!({"status": 200, "headers": {"x-a": "a\nb"}}),
            json!({"status": 200, "headers": {"x-a": "nul\u{0}"}}),
            json!({"status": 200, "headers": {"x-a": "é"}}),
            json!({"status": 200, "headers": {"x-a": ""}}),
            json!({"status": 200, "headers": {"x-a": "v".repeat(MAX_VALUE + 1)}}),
            json!({"status": 200, "headers": {"bad name": "v"}}),
            json!({"status": 200, "headers": {"x\r\ny": "v"}}),
            json!({"status": 200, "headers": {":status": "200"}}),
            json!({"status": 200, "headers": {"Content-Length": "4"}}),
            json!({"status": 200, "headers": {"transfer-encoding": "chunked"}}),
            json!({"status": 200, "headers": {"connection": "close"}}),
            json!({"status": 200, "headers": {"proxy-authenticate": "x"}}),
            json!({"status": 200, "headers": {"x-a": "1", "X-A": "2"}}),
            json!({"status": 200, "headers": too_many}),
            json!({"status": 200, "unknown": 1}),
        ] {
            assert_eq!(
                compile(&bad).expect_err(&bad.to_string()).code,
                "invalid_middleware",
                "{bad}"
            );
        }
    }

    #[test]
    fn the_description_shows_no_values() {
        let respond = compile(&json!({
            "status": 200, "headers": {"x-token": "SECRET-VALUE"}, "body": "SECRET-BODY",
        }))
        .expect("compiled");
        let shown = respond.describe().to_string();
        assert!(!shown.contains("SECRET"), "{shown}");
    }
}
