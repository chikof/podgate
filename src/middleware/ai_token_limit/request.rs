//! What to do to a JSON request body so the model reports its token usage while it streams.
//!
//! A streamed chat completion carries `usage` only when the request has
//! `stream_options.include_usage: true`. When the client did not set it, podgate adds it to the
//! bytes that go to the model and takes the usage-only chunk out of the answer
//! ([`super::sse`]). The edit is surgical: the document is never parsed into a value and
//! written back, so key order, number text and every other byte reach the model as the client
//! wrote them.
//!
//! The body is left alone (and the answer is counted by the estimate when the model reports
//! nothing) when it is not one JSON object, when it repeats a key podgate reads (a duplicate
//! could make podgate's view differ from the model's), when it does not stream, or when it is
//! not a chat or legacy completion (the Responses API reports usage in `response.completed` and
//! may refuse an unknown `stream_options`).

use std::ops::Range;

use bytes::Bytes;
use serde::de::IgnoredAny;
use serde_json::Value;

/// What to do with a request body.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// Send the body as it is; podgate adds nothing and removes nothing.
    Untouched,
    /// A streaming chat that already asks for usage: send as it is, and nothing is removed from
    /// the answer.
    ClientAsked,
    /// Send this body instead, and remove the usage-only chunk from the answer.
    Rewrite(Bytes),
}

/// A top-level key of the object and where its value lies in the body.
struct Entry {
    key: String,
    value: Range<usize>,
}

fn skip_ws(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    at
}

/// Just past the string that starts with the quote at `at`.
fn string_end(bytes: &[u8], at: usize) -> Option<usize> {
    let mut next = at + 1;
    loop {
        match bytes.get(next)? {
            b'\\' => next += 2,
            b'"' => return Some(next + 1),
            _ => next += 1,
        }
    }
}

/// Just past the value that starts at `at`.
fn value_end(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes.get(at)? {
        b'"' => string_end(bytes, at),
        b'{' | b'[' => {
            let mut depth = 0_u32;
            let mut next = at;
            loop {
                match bytes.get(next)? {
                    b'"' => {
                        next = string_end(bytes, next)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(next + 1);
                        }
                    }
                    _ => {}
                }
                next += 1;
            }
        }
        _ => {
            let mut next = at;
            while bytes.get(next).is_some_and(|byte| {
                !matches!(byte, b',' | b'}' | b']') && !byte.is_ascii_whitespace()
            }) {
                next += 1;
            }
            Some(next)
        }
    }
}

/// The top-level entries of a body that is one valid JSON object, `None` for anything else.
fn entries(bytes: &[u8]) -> Option<Vec<Entry>> {
    serde_json::from_slice::<IgnoredAny>(bytes).ok()?;
    let mut at = skip_ws(bytes, 0);
    if bytes.get(at) != Some(&b'{') {
        return None;
    }
    at += 1;
    let mut out = Vec::new();
    loop {
        at = skip_ws(bytes, at);
        match bytes.get(at)? {
            b'}' => return Some(out),
            b'"' => {}
            _ => return None,
        }
        let key_end = string_end(bytes, at)?;
        let key: String = serde_json::from_slice(bytes.get(at..key_end)?).ok()?;
        at = skip_ws(bytes, key_end);
        if bytes.get(at) != Some(&b':') {
            return None;
        }
        at = skip_ws(bytes, at + 1);
        let end = value_end(bytes, at)?;
        out.push(Entry {
            key,
            value: at..end,
        });
        at = skip_ws(bytes, end);
        match bytes.get(at)? {
            b',' => at += 1,
            b'}' => {}
            _ => return None,
        }
    }
}

/// `body` with `range` replaced by `with`.
fn splice(body: &[u8], range: Range<usize>, with: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(body.len() + with.len());
    out.extend_from_slice(body.get(..range.start).unwrap_or_default());
    out.extend_from_slice(with);
    out.extend_from_slice(body.get(range.end..).unwrap_or_default());
    Bytes::from(out)
}

/// What to do with the request body `body`.
pub(super) fn plan(body: &[u8]) -> Plan {
    let Some(entries) = entries(body) else {
        return Plan::Untouched;
    };
    let found = |name: &str| -> Result<Option<&Entry>, ()> {
        let mut same = entries.iter().filter(|entry| entry.key == name);
        let first = same.next();
        if same.next().is_some() {
            return Err(());
        }
        Ok(first)
    };
    let (Ok(stream), Ok(options), Ok(messages), Ok(prompt), Ok(input)) = (
        found("stream"),
        found("stream_options"),
        found("messages"),
        found("prompt"),
        found("input"),
    ) else {
        return Plan::Untouched;
    };
    let text = |entry: &Entry| body.get(entry.value.clone()).unwrap_or_default();
    let present = |entry: Option<&Entry>| entry.is_some_and(|entry| text(entry) != b"null");
    let streams = stream.is_some_and(|entry| text(entry) == b"true");
    if !streams || !(present(messages) || present(prompt)) || present(input) {
        return Plan::Untouched;
    }
    let Some(last) = entries.last() else {
        return Plan::Untouched;
    };
    match options {
        Some(options) if text(options) != b"null" => {
            let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(text(options))
            else {
                return Plan::Untouched;
            };
            if object.get("include_usage") == Some(&Value::Bool(true)) {
                return Plan::ClientAsked;
            }
            object.insert("include_usage".to_owned(), Value::Bool(true));
            let Ok(object) = serde_json::to_vec(&Value::Object(object)) else {
                return Plan::Untouched;
            };
            Plan::Rewrite(splice(body, options.value.clone(), &object))
        }
        Some(options) => Plan::Rewrite(splice(
            body,
            options.value.clone(),
            br#"{"include_usage":true}"#,
        )),
        None => Plan::Rewrite(splice(
            body,
            last.value.end..last.value.end,
            br#","stream_options":{"include_usage":true}"#,
        )),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn rewritten(body: &str) -> String {
        match plan(body.as_bytes()) {
            Plan::Rewrite(bytes) => String::from_utf8(bytes.to_vec()).expect("utf-8"),
            other => panic!("expected a rewrite of {body}, got {other:?}"),
        }
    }

    #[test]
    fn ai_rewrite_adds_stream_options_and_keeps_every_other_byte() {
        let body = "{ \"model\" : \"m\",  \"messages\":[{\"role\":\"user\",\"content\":\"hi } , \\\"stream_options\\\"\"}],\n \"temperature\": 1.0e0, \"stream\": true }";
        let out = rewritten(body);
        assert_eq!(
            out,
            "{ \"model\" : \"m\",  \"messages\":[{\"role\":\"user\",\"content\":\"hi } , \\\"stream_options\\\"\"}],\n \"temperature\": 1.0e0, \"stream\": true,\"stream_options\":{\"include_usage\":true} }"
        );
        let parsed: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(parsed["stream_options"]["include_usage"], true);
        assert_eq!(parsed["temperature"], 1.0);
    }

    #[test]
    fn ai_rewrite_forces_include_usage_over_false() {
        let out = rewritten(
            r#"{"stream":true,"messages":[],"stream_options":{"include_usage":false,"continuous_usage_stats":true},"n":2}"#,
        );
        let parsed: Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(
            parsed["stream_options"],
            serde_json::json!({"include_usage": true, "continuous_usage_stats": true})
        );
        assert_eq!(parsed["n"], 2);
        let null = rewritten(r#"{"stream":true,"prompt":"p","stream_options":null}"#);
        assert_eq!(
            null,
            r#"{"stream":true,"prompt":"p","stream_options":{"include_usage":true}}"#
        );
        let empty = rewritten(r#"{"stream":true,"messages":[],"stream_options":{}}"#);
        assert_eq!(
            empty,
            r#"{"stream":true,"messages":[],"stream_options":{"include_usage":true}}"#
        );
    }

    #[test]
    fn ai_rewrite_leaves_a_client_that_asked() {
        let body = br#"{"stream":true,"messages":[],"stream_options":{"include_usage":true}}"#;
        assert_eq!(plan(body), Plan::ClientAsked);
    }

    #[test]
    fn ai_rewrite_skips_the_responses_shape() {
        let body = br#"{"stream":true,"input":"hi","model":"m"}"#;
        assert_eq!(plan(body), Plan::Untouched);
        let both = br#"{"stream":true,"input":"hi","messages":[]}"#;
        assert_eq!(plan(both), Plan::Untouched);
    }

    #[test]
    fn ai_rewrite_skips_a_body_that_does_not_stream() {
        for body in [
            r#"{"messages":[]}"#,
            r#"{"stream":false,"messages":[]}"#,
            r#"{"stream":"true","messages":[]}"#,
            r#"{"stream":null,"messages":[]}"#,
            r#"{"stream":true}"#,
            r#"{"stream":true,"stream_options":5,"messages":[]}"#,
        ] {
            assert_eq!(plan(body.as_bytes()), Plan::Untouched, "{body}");
        }
    }

    #[test]
    fn ai_rewrite_skips_duplicate_keys_and_non_objects() {
        for body in [
            r#"{"stream":true,"stream":false,"messages":[]}"#,
            r#"{"stream":true,"messages":[],"stream_options":{},"stream_options":{}}"#,
            r#"[{"stream":true,"messages":[]}]"#,
            r#"{"stream":true,"messages":[]"#,
            r#""stream""#,
            "",
        ] {
            assert_eq!(plan(body.as_bytes()), Plan::Untouched, "{body}");
        }
    }

    #[test]
    fn ai_rewrite_sees_only_top_level_keys() {
        // A nested `stream_options` or `input` is not the request's own.
        let nested =
            r#"{"messages":[{"input":"x","stream_options":{"include_usage":true}}],"stream":true}"#;
        let out = rewritten(nested);
        assert!(out.ends_with(r#""stream":true,"stream_options":{"include_usage":true}}"#));
        let escaped_key = r#"{"str\u0065am":true,"messages":[]}"#;
        assert!(matches!(plan(escaped_key.as_bytes()), Plan::Rewrite(_)));
    }
}
