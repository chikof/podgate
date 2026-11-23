//! The JSON-RPC 2.0 envelope of the MCP gateway: what a client message is, and the bodies the
//! gateway answers with. Pure: no I/O, no state.
//!
//! Ids, `params`, `result` and `error` travel as raw JSON text ([`RawValue`]), so what a client
//! or a server wrote is forwarded byte for byte.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};

/// The body is not JSON.
pub(super) const PARSE_ERROR: i32 = -32700;
/// The JSON is not a single JSON-RPC request, notification or response.
pub(super) const INVALID_REQUEST: i32 = -32600;
/// The method is not one the gateway offers.
pub(super) const METHOD_NOT_FOUND: i32 = -32601;
/// The parameters of a method are missing or wrong, or the tool is unknown.
pub(super) const INVALID_PARAMS: i32 = -32602;
/// A registered server failed.
pub(super) const INTERNAL_ERROR: i32 = -32603;
/// No room: a permit or the tenant's buffer budget.
pub(super) const BUSY: i32 = -32000;

/// The id of every request the gateway sends to a server: each exchange has its own connection,
/// so one value cannot collide, and the answer is matched against it.
pub(super) const UPSTREAM_ID: u32 = 1;

/// The protocol revisions the gateway speaks, newest first. `2026-07-28` drops `initialize` and
/// sessions; it is not among them.
pub(super) const SUPPORTED: [&str; 2] = ["2025-11-25", "2025-06-18"];

/// The newest revision: what `initialize` answers a client that asks for one the gateway does
/// not speak, and what the gateway asks of a server.
pub(super) const LATEST: &str = SUPPORTED[0];

/// Why a client body is refused before any method is looked at. Both are `400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// Not JSON.
    Parse,
    /// JSON, but not one JSON-RPC message (a batch, a scalar, an object without `jsonrpc: "2.0"`,
    /// an id that is neither a string nor a number).
    Invalid(&'static str),
}

/// A message of the client.
#[derive(Debug)]
pub(super) enum Message<'a> {
    /// A request: it gets exactly one answer.
    Request {
        /// The id exactly as written.
        id: &'a RawValue,
        /// The method.
        method: &'a str,
        /// The `params`, when present.
        params: Option<&'a RawValue>,
    },
    /// A notification: it gets `202` and nothing else.
    Notification,
    /// A response to a request of a server: the gateway sends none, so it only acknowledges.
    Response,
}

/// Keeps `null` as a value: a field that is present is `Some`, even when it is `null`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(default)]
    jsonrpc: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    id: Option<&'a RawValue>,
    #[serde(default)]
    method: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    params: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    result: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    error: Option<&'a RawValue>,
}

/// Whether `raw` is a JSON string or number: the only kinds of id MCP allows.
fn is_id(raw: &RawValue) -> bool {
    matches!(raw.get().bytes().next(), Some(b'"' | b'-' | b'0'..=b'9'))
}

/// Reads one client message from a request body.
///
/// # Errors
///
/// [`Refused`] when the body is not exactly one JSON-RPC message.
pub(super) fn parse(body: &[u8]) -> Result<Message<'_>, Refused> {
    let text = std::str::from_utf8(body).map_err(|_| Refused::Parse)?;
    let root: &RawValue = serde_json::from_str(text).map_err(|_| Refused::Parse)?;
    match root.get().bytes().next() {
        Some(b'{') => {}
        Some(b'[') => return Err(Refused::Invalid("batches are not supported")),
        _ => return Err(Refused::Invalid("a message is a JSON object")),
    }
    let envelope: Envelope<'_> = serde_json::from_str(root.get())
        .map_err(|_| Refused::Invalid("a field has the wrong type"))?;
    if envelope.jsonrpc != Some("2.0") {
        return Err(Refused::Invalid("jsonrpc must be \"2.0\""));
    }
    if let Some(id) = envelope.id
        && !is_id(id)
    {
        return Err(Refused::Invalid("an id is a string or a number"));
    }
    match (envelope.method, envelope.id) {
        (Some(method), Some(id)) => Ok(Message::Request {
            id,
            method,
            params: envelope.params,
        }),
        (Some(_), None) => Ok(Message::Notification),
        (None, Some(_)) if envelope.result.is_some() != envelope.error.is_some() => {
            Ok(Message::Response)
        }
        _ => Err(Refused::Invalid(
            "not a request, a notification or a response",
        )),
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    jsonrpc: &'static str,
    id: Option<&'a RawValue>,
    error: ErrorObject<'a>,
}

#[derive(Serialize)]
struct ErrorObject<'a> {
    code: i32,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// A JSON-RPC error answer. `id` is `None` (`null`) when the request had none that could be
/// read.
#[must_use]
pub(super) fn error(
    id: Option<&RawValue>,
    code: i32,
    message: &str,
    data: Option<Value>,
) -> Vec<u8> {
    let body = ErrorBody {
        jsonrpc: "2.0",
        id,
        error: ErrorObject {
            code,
            message,
            data,
        },
    };
    // A struct of strings, numbers and a `Value` always serializes.
    serde_json::to_vec(&body).unwrap_or_default()
}

/// A JSON-RPC answer whose `result` is `result`, a value the gateway built.
#[must_use]
pub(super) fn result<T: Serialize>(id: &RawValue, result: &T) -> Vec<u8> {
    #[derive(Serialize)]
    struct Body<'a, T> {
        jsonrpc: &'static str,
        id: &'a RawValue,
        result: &'a T,
    }
    serde_json::to_vec(&Body {
        jsonrpc: "2.0",
        id,
        result,
    })
    .unwrap_or_default()
}

/// A JSON-RPC answer carrying text a server wrote: its `result` (`key` `"result"`) or its `error`
/// (`key` `"error"`) untouched.
#[must_use]
pub(super) fn passthrough(id: &RawValue, key: &str, raw: &RawValue) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.get().len() + id.get().len() + 40);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","id":"#);
    out.extend_from_slice(id.get().as_bytes());
    out.extend_from_slice(b",\"");
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"\":");
    out.extend_from_slice(raw.get().as_bytes());
    out.push(b'}');
    out
}

/// A request the gateway sends to a server, with the id every exchange uses.
#[must_use]
pub(super) fn request(method: &str, params: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": UPSTREAM_ID, "method": method, "params": params}).to_string()
}

/// A notification the gateway sends to a server.
#[must_use]
pub(super) fn notification(method: &str) -> String {
    json!({"jsonrpc": "2.0", "method": method}).to_string()
}

/// What a server answered to a request of the gateway.
#[derive(Debug)]
pub(super) enum Answer {
    /// The `result`.
    Result(Box<RawValue>),
    /// The `error` object, as the server wrote it.
    Error(Box<RawValue>),
}

#[derive(Deserialize)]
struct Reply {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    result: Option<Box<RawValue>>,
    #[serde(default, deserialize_with = "present")]
    error: Option<Box<RawValue>>,
}

/// Reads `text` as the answer to the request the gateway sent with [`UPSTREAM_ID`]. `None` when
/// it is anything else: another message, another id, both or neither of `result` and `error`.
#[must_use]
pub(super) fn answer(text: &str) -> Option<Answer> {
    let reply: Reply = serde_json::from_str(text).ok()?;
    if reply.jsonrpc.as_deref() != Some("2.0") {
        return None;
    }
    let id = reply.id?;
    if id.as_f64() != Some(f64::from(UPSTREAM_ID)) {
        return None;
    }
    match (reply.result, reply.error) {
        (Some(result), None) => Some(Answer::Result(result)),
        (None, Some(error)) => Some(Answer::Error(error)),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn body(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn mcp_rpc_classifies_messages() {
        let request = body(r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#);
        let Ok(Message::Request { id, method, params }) = parse(&request) else {
            panic!("a request");
        };
        assert_eq!((id.get(), method, params.is_none()), ("7", "ping", true));

        let string_id = body(r#"{"jsonrpc":"2.0","id":"a-1","method":"tools/list","params":{}}"#);
        assert!(matches!(
            parse(&string_id),
            Ok(Message::Request { id, params: Some(_), .. }) if id.get() == "\"a-1\""
        ));

        let note = body(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(matches!(parse(&note), Ok(Message::Notification)));

        let response = body(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#);
        assert!(matches!(parse(&response), Ok(Message::Response)));
        let failure = body(r#"{"jsonrpc":"2.0","id":3,"error":{"code":1,"message":"x"}}"#);
        assert!(matches!(parse(&failure), Ok(Message::Response)));
    }

    #[test]
    fn mcp_rpc_refuses_what_is_not_one_message() {
        for (text, expected) in [
            ("not json", Refused::Parse),
            ("", Refused::Parse),
            ("{\"jsonrpc\":", Refused::Parse),
        ] {
            assert_eq!(parse(&body(text)).err(), Some(expected), "{text}");
        }
        for text in [
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
            "[]",
            "7",
            r#""ping""#,
            "null",
            r#"{"id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":[1],"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0"}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
        ] {
            assert!(
                matches!(parse(&body(text)), Err(Refused::Invalid(_))),
                "{text}"
            );
        }
        assert_eq!(parse(&[0xff, 0xfe]).err(), Some(Refused::Parse));
    }

    #[test]
    fn mcp_rpc_ids_come_back_as_written() {
        let id = serde_json::from_str::<Box<RawValue>>("12345678901234567890").expect("raw");
        let reply = error(Some(&id), INVALID_PARAMS, "unknown tool", None);
        assert_eq!(
            String::from_utf8(reply).expect("utf8"),
            r#"{"jsonrpc":"2.0","id":12345678901234567890,"error":{"code":-32602,"message":"unknown tool"}}"#
        );
        let none = error(None, PARSE_ERROR, "parse error", Some(json!({"at": 3})));
        assert_eq!(
            String::from_utf8(none).expect("utf8"),
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error","data":{"at":3}}}"#
        );
    }

    #[test]
    fn mcp_rpc_passes_a_result_through_untouched() {
        let id = serde_json::from_str::<Box<RawValue>>("\"abc\"").expect("raw");
        let raw = serde_json::from_str::<Box<RawValue>>(
            r#"{ "big": 18446744073709551616, "f": 1.0, "s": "\u00e9" }"#,
        )
        .expect("raw");
        let out = passthrough(&id, "result", &raw);
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            r#"{"jsonrpc":"2.0","id":"abc","result":{ "big": 18446744073709551616, "f": 1.0, "s": "\u00e9" }}"#
        );
    }

    #[test]
    fn mcp_rpc_reads_a_server_answer_by_its_id() {
        let ok = answer(r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#);
        assert!(matches!(ok, Some(Answer::Result(raw)) if raw.get() == r#"{"tools":[]}"#));
        let null_result = answer(r#"{"jsonrpc":"2.0","id":1,"result":null}"#);
        assert!(matches!(null_result, Some(Answer::Result(raw)) if raw.get() == "null"));
        let err = answer(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"x"}}"#);
        assert!(matches!(err, Some(Answer::Error(_))));
        for bad in [
            r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#,
            r#"{"id":1,"result":{}}"#,
            "nope",
        ] {
            assert!(answer(bad).is_none(), "{bad}");
        }
    }
}
