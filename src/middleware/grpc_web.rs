//! The `grpc_web` middleware: Traefik's `grpcWeb`. A browser cannot speak gRPC (it cannot read
//! HTTP/2 trailers or stream a request body), so it speaks gRPC-Web; this stage converts the
//! request to gRPC for an HTTP/2 upstream and the response back, trailers included. Full
//! reference: `docs/ref/mw-grpc-web.md`.
//!
//! ```json
//! { "name": "web", "type": "grpc_web", "allow_origins": ["https://app.example.com"] }
//! ```
//!
//! - A request whose `Content-Type` is `application/grpc-web`, `application/grpc-web+proto`
//!   (binary) or `application/grpc-web-text` (base64) goes upstream as `application/grpc` with
//!   `te: trailers`; the text body is decoded as it streams. Every other request passes untouched.
//! - A gRPC response's trailers become a trailer frame at the end of the body, and the content
//!   type becomes `application/grpc-web+proto` or `application/grpc-web-text` (encoded as it
//!   streams). A trailers-only response (`grpc-status` in the headers) becomes a body that is
//!   that frame alone.
//! - No message is buffered. The state of a request is [`State`]: at most 3 characters of base64
//!   on the way in, 2 bytes on the way out, and a trailer frame of at most
//!   [`codec::MAX_TRAILER_BYTES`] built once at the end of the response. Trailers over the cap
//!   become `grpc-status: 13`.
//! - gRPC cannot be spoken over HTTP/1.1, so a route with this stage whose service has a server
//!   that cannot speak HTTP/2 is `invalid_middleware` when the snapshot compiles.
//! - `allow_origins` answers the CORS preflight and sets the CORS headers for the listed
//!   origins; an origin that is not listed gets nothing, and no origin is ever echoed back.

pub mod codec;

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use serde::Deserialize;
use serde_json::{Value, json};

use super::headers::{self, CompiledCors, Cors};
use super::{CompileCx, Flow, Kind, RequestCx, ResponseCx};
use crate::compile::Invalid;
use crate::error::AppError;
use podgate_model::Declared;

/// The configuration of a `grpc_web` middleware.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Origins allowed to call from a browser: exact `scheme://host[:port]`, or `*` for any.
    /// Absent or empty: no CORS headers and no preflight answer.
    #[serde(default)]
    pub allow_origins: Vec<String>,
}

/// The request headers a browser may send, and the one it must: `*` covers the metadata a
/// client adds, and `Authorization`, which `*` never covers, is named.
const ALLOW_HEADERS: [&str; 2] = ["*", "authorization"];

/// The response headers a browser script may read.
const EXPOSE_HEADERS: [&str; 2] = ["grpc-status", "grpc-message"];

/// How long a browser may keep a preflight answer.
const PREFLIGHT_MAX_AGE_SECS: u64 = 600;

/// A compiled `grpc_web` middleware.
#[derive(Debug)]
pub struct GrpcWeb {
    origins: Vec<String>,
    cors: Option<CompiledCors>,
}

/// What a request's `Content-Type` says about its body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    /// Not gRPC-Web: the request and its response pass untouched.
    #[default]
    Off,
    /// `application/grpc-web` and `application/grpc-web+proto`: gRPC framing as it is.
    Binary,
    /// `application/grpc-web-text`: the same, base64 encoded.
    Text,
}

impl Mode {
    fn of(content_type: Option<&HeaderValue>) -> Self {
        let Some(text) = content_type.and_then(|value| value.to_str().ok()) else {
            return Self::Off;
        };
        let media = text.split(';').next().unwrap_or_default().trim();
        let is = |name: &str| media.eq_ignore_ascii_case(name);
        if is("application/grpc-web") || is("application/grpc-web+proto") {
            Self::Binary
        } else if is("application/grpc-web-text") || is("application/grpc-web-text+proto") {
            Self::Text
        } else {
            Self::Off
        }
    }

    /// The content type the browser gets back.
    fn response_type(self) -> &'static str {
        match self {
            Self::Text => "application/grpc-web-text",
            Self::Off | Self::Binary => "application/grpc-web+proto",
        }
    }
}

/// Whether `content_type` is a gRPC response (`application/grpc`, `application/grpc+proto`),
/// not a gRPC-Web one and not another type that starts with the same letters.
fn is_grpc(content_type: Option<&HeaderValue>) -> bool {
    let Some(text) = content_type.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let media = text
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media == "application/grpc" || media.starts_with("application/grpc+")
}

/// The headers of a trailers-only response that are not trailers.
fn is_head_only(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "content-type"
            | "content-length"
            | "content-encoding"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
            | "date"
            | "server"
            | "vary"
            | "via"
    ) || name.as_str().starts_with("access-control-")
}

/// Per-request state.
#[derive(Debug, Default)]
pub struct State {
    mode: Mode,
    /// The upstream answered with gRPC and the response is being converted.
    converted: bool,
    /// The trailer frame has been written: nothing more follows.
    done: bool,
    /// The origin a CORS header answers, for the response hook.
    allow_origin: Option<HeaderValue>,
    decoder: codec::Decoder,
    encoder: codec::Encoder,
    /// The whole converted body of a trailers-only response.
    only: Option<Bytes>,
}

fn invalid(message: impl AsRef<str>) -> Invalid {
    Invalid::new(
        "invalid_middleware",
        format!("grpc_web: {}", message.as_ref()),
    )
}

impl Kind for GrpcWeb {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let cors = if config.allow_origins.is_empty() {
            None
        } else {
            let policy = Cors {
                allow_origins: config.allow_origins.clone(),
                allow_origin_regexes: Vec::new(),
                allow_methods: vec!["POST".to_owned()],
                allow_headers: ALLOW_HEADERS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                expose_headers: EXPOSE_HEADERS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                allow_credentials: false,
                max_age_secs: Some(PREFLIGHT_MAX_AGE_SECS),
                add_vary: true,
            };
            Some(
                headers::cors(&policy)
                    .map_err(|err| invalid(err.message.trim_start_matches("headers: ")))?,
            )
        };
        Ok(Self {
            origins: config.allow_origins,
            cors,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let request = cx.session.req_header();
        state.mode = Mode::of(request.headers.get(CONTENT_TYPE));
        let Some(cors) = &self.cors else {
            return Ok(Flow::Continue);
        };
        let Some(allow) = headers::single_origin(request).and_then(|origin| cors.allow(origin))
        else {
            return Ok(Flow::Continue);
        };
        if headers::is_preflight(request) {
            let head = cors.preflight(allow)?;
            cx.session.write_response_header(head, true).await?;
            return Ok(Flow::Respond);
        }
        if state.mode != Mode::Off {
            state.allow_origin = Some(allow);
        }
        Ok(Flow::Continue)
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        state: &mut State,
    ) -> pingora::Result<()> {
        // Read again from the head that goes upstream, which is the one rewritten below.
        state.mode = Mode::of(request.headers.get(CONTENT_TYPE));
        if state.mode == Mode::Off {
            return Ok(());
        }
        request.insert_header(CONTENT_TYPE, "application/grpc")?;
        request.insert_header("te", "trailers")?;
        // A gRPC request ends with a DATA frame, never with its headers.
        request.set_send_end_stream(false);
        if state.mode == Mode::Text {
            // The decoded body is shorter than the declared one.
            request.remove_header(&CONTENT_LENGTH);
        }
        Ok(())
    }

    fn request_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> Result<(), AppError> {
        if state.mode != Mode::Text {
            return Ok(());
        }
        let bad = |err: codec::DecodeError| AppError::BadRequest(err.to_string().into());
        let mut decoded = match body.take() {
            Some(chunk) => state.decoder.push(&chunk).map_err(bad)?,
            None => Bytes::new(),
        };
        if end_of_stream {
            let tail = state.decoder.finish().map_err(bad)?;
            if !tail.is_empty() {
                decoded = [decoded, tail].concat().into();
            }
        }
        // `None` would end the upstream request: an empty chunk stays empty bytes.
        *body = Some(decoded);
        Ok(())
    }

    fn response_head(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<(), AppError> {
        if state.mode == Mode::Off || !is_grpc(cx.response.headers.get(CONTENT_TYPE)) {
            return Ok(());
        }
        state.converted = true;
        // `grpc-status` in the head: a trailers-only response, which has no body to carry the
        // frame. Built from the head as the upstream sent it, before any hook edited it.
        if cx.response.headers.contains_key("grpc-status") {
            let frame = codec::frame(&cx.response.headers, is_head_only);
            state.only = Some(match state.mode {
                Mode::Text => codec::Encoder::default().finish(&frame),
                Mode::Off | Mode::Binary => frame,
            });
            state.done = true;
        }
        Ok(())
    }

    fn response(&self, response: &mut ResponseHeader, state: &mut State) -> pingora::Result<()> {
        if let Some(cors) = &self.cors {
            if let Some(allow) = state.allow_origin.take() {
                cors.apply(response, allow)?;
            }
            if state.mode != Mode::Off {
                cors.add_vary(response)?;
            }
        }
        if state.converted {
            response.insert_header(CONTENT_TYPE, state.mode.response_type())?;
            response.remove_header(&CONTENT_LENGTH);
            if let Some(only) = &state.only {
                response.insert_header(CONTENT_LENGTH, only.len().to_string())?;
            }
        }
        Ok(())
    }

    fn response_body(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> pingora::Result<()> {
        if !state.converted || state.done {
            return Ok(());
        }
        let chunk = body.take().unwrap_or_default();
        // A response that ends without trailers is not a success the browser may assume: it
        // gets the status `unknown` in the frame a server should have sent.
        let out = match (end_of_stream, state.mode) {
            (false, Mode::Text) => state.encoder.push(&chunk),
            (false, Mode::Off | Mode::Binary) => chunk,
            (true, mode) => {
                state.done = true;
                let end = codec::missing_trailers();
                match mode {
                    Mode::Text => state.encoder.finish(&[&chunk[..], &end[..]].concat()),
                    Mode::Off | Mode::Binary => [&chunk[..], &end[..]].concat().into(),
                }
            }
        };
        *body = (!out.is_empty()).then_some(out);
        Ok(())
    }

    fn response_trailers(&self, trailers: &mut HeaderMap, state: &mut State) -> Option<Bytes> {
        if !state.converted || state.done {
            return None;
        }
        state.done = true;
        let frame = codec::frame(trailers, |_| false);
        Some(match state.mode {
            Mode::Text => state.encoder.finish(&frame),
            Mode::Off | Mode::Binary => frame,
        })
    }

    fn response_complete(&self, state: &mut State) -> Option<Bytes> {
        state.only.take()
    }

    /// CORS opened to more origins than before.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            Some(new)
                if new
                    .origins
                    .iter()
                    .any(|origin| !self.origins.contains(origin)) =>
            {
                vec!["cors_widened"]
            }
            _ => Vec::new(),
        }
    }

    fn describe(&self) -> Value {
        json!({ "allow_origins": self.origins })
    }
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::*;

    fn compile(config: &Value) -> Result<GrpcWeb, Invalid> {
        let mut declared = json!({ "name": "g", "type": "grpc_web" });
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
        GrpcWeb::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
                portal: None,
            },
        )
    }

    fn mode(content_type: &str) -> Mode {
        Mode::of(Some(&HeaderValue::from_str(content_type).expect("value")))
    }

    #[test]
    fn grpc_web_content_types_pick_the_mode() {
        assert_eq!(mode("application/grpc-web"), Mode::Binary);
        assert_eq!(mode("application/grpc-web+proto"), Mode::Binary);
        assert_eq!(
            mode("Application/GRPC-Web+Proto; charset=utf-8"),
            Mode::Binary
        );
        assert_eq!(mode("application/grpc-web-text"), Mode::Text);
        assert_eq!(mode("application/grpc-web-text+proto"), Mode::Text);
        for other in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc-web+json",
            "application/grpc-webx",
            "application/json",
            "",
        ] {
            assert_eq!(mode(other), Mode::Off, "{other}");
        }
        assert_eq!(Mode::of(None), Mode::Off);
    }

    #[test]
    fn grpc_responses_are_told_from_grpc_web_and_lookalikes() {
        let is = |text: &str| is_grpc(Some(&HeaderValue::from_str(text).expect("value")));
        assert!(is("application/grpc"));
        assert!(is("application/grpc+proto"));
        assert!(is("Application/Grpc; charset=utf-8"));
        assert!(!is("application/grpc-web"));
        assert!(!is("application/grpcx"));
        assert!(!is("text/html"));
        assert!(!is_grpc(None));
    }

    #[test]
    fn grpc_web_config_is_strict_and_origins_are_checked() {
        assert!(compile(&json!({})).is_ok());
        assert!(compile(&json!({ "allow_origins": ["https://a.example"] })).is_ok());
        assert!(compile(&json!({ "allow_origins": ["*"] })).is_ok());
        for bad in [
            json!({ "allow_origin": ["https://a.example"] }),
            json!({ "allow_origins": ["a.example"] }),
            json!({ "allow_origins": ["ftp://a.example"] }),
            json!({ "allow_origins": "https://a.example" }),
        ] {
            let err = compile(&bad).expect_err("refused");
            assert_eq!(err.code, "invalid_middleware", "{bad}");
        }
    }

    #[test]
    fn grpc_web_posture_lists_only_wider_origins() {
        let one = compile(&json!({ "allow_origins": ["https://a.example"] })).expect("one");
        let two = compile(&json!({ "allow_origins": ["https://a.example", "https://b.example"] }))
            .expect("two");
        assert_eq!(one.posture(Some(&two)), ["cors_widened"]);
        assert!(two.posture(Some(&one)).is_empty());
        assert!(one.posture(None).is_empty());
    }

    #[test]
    fn grpc_web_state_stays_small() {
        assert!(size_of::<State>() <= 112, "{}", size_of::<State>());
    }
}
