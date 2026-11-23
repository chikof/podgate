//! Reads the answer of an MCP server that replies with `text/event-stream`: the events are
//! split as the Server-Sent Events format says, and the one that holds the JSON-RPC answer to
//! the gateway's request is the answer. Pure: bytes in, an answer out.
//!
//! A server may send notifications and requests before its answer; they are not for the gateway
//! (it advertises no capability that asks for them) and are skipped. Only an event that is
//! complete (ended by a blank line) is looked at, so a read that stops mid-event simply waits for
//! more bytes.

use super::rpc::{self, Answer};
use crate::middleware::forward_auth::Stop;

/// The next complete event of `buf` at or after `at`: the offset after it and its `data` (the
/// `data` lines joined with a line feed; `None` for an event with no `data` line). `None` when
/// the event is not complete yet. `eof`: the buffer is all there will be, so a `\r` at its end is
/// a line end by itself.
fn next_event(buf: &[u8], mut at: usize, eof: bool) -> Option<(usize, Option<String>)> {
    let mut data: Option<String> = None;
    loop {
        let rest = buf.get(at..)?;
        let eol = rest.iter().position(|byte| matches!(byte, b'\n' | b'\r'))?;
        let line = &rest[..eol];
        let mut after = at + eol + 1;
        if rest[eol] == b'\r' {
            match rest.get(eol + 1) {
                Some(b'\n') => after += 1,
                // A `\r` that ends the buffer may be the first half of `\r\n`.
                None if !eof => return None,
                None | Some(_) => {}
            }
        }
        at = after;
        if line.is_empty() {
            return Some((at, data));
        }
        let (name, value) = match line.iter().position(|byte| *byte == b':') {
            // A comment.
            Some(0) => continue,
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &line[line.len()..]),
        };
        if name == b"data" {
            let text = String::from_utf8_lossy(value);
            match &mut data {
                Some(joined) => {
                    joined.push('\n');
                    joined.push_str(&text);
                }
                None => data = Some(text.into_owned()),
            }
        }
    }
}

/// The first answer to the gateway's request among the complete events of `buf` after
/// `*consumed`; `*consumed` moves past every event that was not it, so the next call looks only
/// at what arrived since. `eof` as for `next_event`.
pub(super) fn scan(buf: &[u8], consumed: &mut usize, eof: bool) -> Option<Answer> {
    if *consumed == 0
        && let Some(rest) = buf.strip_prefix(b"\xef\xbb\xbf")
    {
        *consumed = buf.len() - rest.len();
    }
    while let Some((end, data)) = next_event(buf, *consumed, eof) {
        if let Some(answer) = data.as_deref().and_then(rpc::answer) {
            return Some(answer);
        }
        *consumed = end;
    }
    None
}

/// The answer in a whole body.
#[must_use]
pub(super) fn find(body: &[u8]) -> Option<Answer> {
    scan(body, &mut 0, true)
}

/// The predicate that ends a read as soon as the answer is in the body.
pub(super) fn stop() -> Stop {
    let mut consumed = 0;
    Box::new(move |body| scan(body, &mut consumed, false).is_some())
}

#[cfg(test)]
mod test {
    use super::*;

    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;

    fn is_ok(answer: Option<Answer>) -> bool {
        matches!(answer, Some(Answer::Result(raw)) if raw.get() == r#"{"ok":true}"#)
    }

    #[test]
    fn mcp_sse_reads_the_answer_after_a_notification() {
        let body = format!(
            "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\nevent: message\ndata: {ANSWER}\n\n"
        );
        assert!(is_ok(find(body.as_bytes())));
    }

    #[test]
    fn mcp_sse_accepts_every_line_end() {
        for end in ["\n", "\r\n", "\r"] {
            let body = format!("id: 9{end}data: {ANSWER}{end}{end}");
            assert!(is_ok(find(body.as_bytes())), "{end:?}");
        }
    }

    #[test]
    fn mcp_sse_joins_data_lines_and_ignores_other_fields() {
        let body = "retry: 100\n: a comment\nevent: message\nid: 3\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\ndata: \"result\":{\"ok\":true}}\n\n";
        assert!(is_ok(find(body.as_bytes())));
        let no_space = format!("data:{ANSWER}\n\n");
        assert!(is_ok(find(no_space.as_bytes())));
    }

    #[test]
    fn mcp_sse_waits_for_a_complete_event() {
        let whole = format!("data: {ANSWER}\n\n");
        for cut in [0, 5, whole.len() - 2, whole.len() - 1] {
            assert!(find(&whole.as_bytes()[..cut]).is_none(), "cut at {cut}");
        }
        assert!(find(format!("data: {ANSWER}\r").as_bytes()).is_none());
        assert!(is_ok(find(whole.as_bytes())));
    }

    #[test]
    fn mcp_sse_ignores_events_that_are_not_the_answer() {
        let other_id = r#"{"jsonrpc":"2.0","id":2,"result":{}}"#;
        let body = format!(
            "data: not json\n\ndata: {other_id}\n\nid: 1\n\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"id\":1}}\n\n"
        );
        assert!(find(body.as_bytes()).is_none());
    }

    #[test]
    fn mcp_sse_stop_looks_only_at_what_arrived() {
        let mut stop = stop();
        let first = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
        let mut body = first.as_bytes().to_vec();
        assert!(!stop(&body));
        body.extend_from_slice(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,");
        assert!(!stop(&body));
        body.extend_from_slice(b"\"result\":{\"ok\":true}}\n");
        assert!(!stop(&body));
        body.extend_from_slice(b"\n");
        assert!(stop(&body));
    }

    #[test]
    fn mcp_sse_skips_a_byte_order_mark() {
        let body = format!("\u{feff}data: {ANSWER}\n\n");
        assert!(is_ok(find(body.as_bytes())));
    }
}
