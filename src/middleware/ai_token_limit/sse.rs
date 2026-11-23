//! An incremental reader of a Server-Sent Events answer: it finds what the model reported in the
//! `usage` of the stream and, when asked, takes out the usage-only chunk the model sends because
//! podgate asked for it.
//!
//! A chunk that ends on an event boundary is forwarded as the same bytes, with no copy and no
//! wait. Only a trailing partial event is held back, and only when the usage-only chunk is to be
//! removed: when nothing is removed every chunk goes on as it came and the scanner reads a copy
//! of the tail it needs.
//!
//! An event is read only when it holds `"usage"` followed by `{`. The quotes make a model's text
//! unable to forge one: a quote inside a JSON string is escaped, so the bytes `"usage"` cannot
//! appear in a string value.

use bytes::Bytes;
use serde::Deserialize;
use serde_json::Value;

use super::usage::{Reported, reported};

/// The most bytes of one event the scanner keeps. A usage chunk is small, so an event over this
/// is never the one to remove: it is forwarded as it is and skipped to its end.
pub(super) const EVENT_MAX: usize = 16 * 1024;

/// What a stream event says about usage.
#[derive(Debug, Deserialize)]
struct Frame {
    #[serde(default)]
    choices: Option<Vec<serde::de::IgnoredAny>>,
    #[serde(default)]
    usage: Option<Value>,
    /// `response.completed` of the Responses API carries the usage inside `response`.
    #[serde(default)]
    response: Option<Inner>,
}

#[derive(Debug, Deserialize)]
struct Inner {
    #[serde(default)]
    usage: Option<Value>,
}

/// What one complete event was.
struct Event {
    /// The event is the chunk that carries `usage` and nothing else (`choices` absent or empty).
    only: bool,
    reported: Option<Reported>,
}

/// The scanner of one answer.
#[derive(Debug)]
pub(super) struct Sse {
    drop_usage: bool,
    /// Bytes of an event that has not ended yet.
    carry: Vec<u8>,
    /// An event too long to keep is being skipped to its end.
    skipping: bool,
    best: Option<Reported>,
}

/// Where the first blank line (the end of an event) ends in `bytes`: just past `\n\n`,
/// `\n\r\n` or the `\n` of `\r\n\r\n`'s last pair.
fn boundary(bytes: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = bytes
        .get(from..)
        .and_then(|rest| rest.iter().position(|byte| *byte == b'\n'))
    {
        let newline = from + at;
        match (bytes.get(newline + 1), bytes.get(newline + 2)) {
            (Some(b'\n'), _) => return Some(newline + 2),
            (Some(b'\r'), Some(b'\n')) => return Some(newline + 3),
            _ => from = newline + 1,
        }
    }
    None
}

/// Whether `event` holds the bytes `"usage"` followed (after spaces) by `:` and `{`.
fn mentions_usage(event: &[u8]) -> bool {
    const KEY: &[u8] = b"\"usage\"";
    event.windows(KEY.len()).enumerate().any(|(at, window)| {
        window == KEY && {
            let mut rest = event[at + KEY.len()..]
                .iter()
                .skip_while(|byte| byte.is_ascii_whitespace());
            rest.next() == Some(&b':')
                && rest.skip_while(|b| b.is_ascii_whitespace()).next() == Some(&b'{')
        }
    })
}

/// The `data` of an event: its `data:` lines joined by a newline.
fn data(event: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in event.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(value) = line.strip_prefix(b"data:") {
            if !out.is_empty() {
                out.push(b'\n');
            }
            out.extend_from_slice(value.strip_prefix(b" ").unwrap_or(value));
        }
    }
    out
}

fn read(event: &[u8]) -> Option<Event> {
    if !mentions_usage(event) {
        return None;
    }
    let frame: Frame = serde_json::from_slice(&data(event)).ok()?;
    let usage = frame
        .usage
        .as_ref()
        .filter(|usage| usage.is_object())
        .or_else(|| frame.response.as_ref()?.usage.as_ref())?;
    let only = frame.usage.as_ref().is_some_and(Value::is_object)
        && frame.choices.as_ref().is_none_or(Vec::is_empty);
    Some(Event {
        only,
        reported: reported(usage),
    })
}

impl Sse {
    /// A scanner that removes the usage-only chunk when `drop_usage`.
    pub(super) fn new(drop_usage: bool) -> Self {
        Self {
            drop_usage,
            carry: Vec::new(),
            skipping: false,
            best: None,
        }
    }

    /// What the stream reported, the largest total of any event that carried a usable `usage`:
    /// a model cannot lower its own count by repeating a smaller one.
    pub(super) fn best(&self) -> Option<Reported> {
        self.best
    }

    fn note(&mut self, reported: Option<Reported>) {
        if let Some(found) = reported
            && self.best.is_none_or(|best| found.total() > best.total())
        {
            self.best = Some(found);
        }
    }

    /// Reads one chunk and returns the bytes to forward: the chunk itself unless an event is
    /// taken out or a partial one is held back. An empty result is nothing to send yet.
    /// `end_of_stream` releases what is held, as a last event.
    pub(super) fn push(&mut self, chunk: Bytes, end_of_stream: bool) -> Bytes {
        let pristine = self.carry.is_empty() && !self.skipping;
        let joined;
        let input: &[u8] = if self.carry.is_empty() {
            &chunk
        } else {
            joined = [self.carry.as_slice(), &chunk].concat();
            &joined
        };
        let mut skipping = self.skipping;
        let mut cut: Vec<(usize, usize)> = Vec::new();
        let mut found: Vec<Option<Reported>> = Vec::new();
        let mut at = 0;
        while let Some(end) = input.get(at..).and_then(boundary) {
            let event = input.get(at..at + end).unwrap_or_default();
            if !std::mem::take(&mut skipping)
                && let Some(verdict) = read(event)
            {
                found.push(verdict.reported);
                if self.drop_usage && verdict.only {
                    cut.push((at, at + end));
                }
            }
            at += end;
        }
        let rest = input.get(at..).unwrap_or_default();
        let mut hold = false;
        self.carry.clear();
        if end_of_stream {
            // What is left is a last event, with no blank line after it.
            if !rest.is_empty()
                && !skipping
                && let Some(verdict) = read(rest)
            {
                found.push(verdict.reported);
                if self.drop_usage && verdict.only {
                    cut.push((at, input.len()));
                }
            }
            skipping = false;
        } else if rest.len() > EVENT_MAX {
            // Too long to be the usage chunk: it goes on as it is, and is skipped to its end.
            skipping = true;
        } else if !rest.is_empty() {
            self.carry.extend_from_slice(rest);
            hold = self.drop_usage;
        }
        self.skipping = skipping;
        for reported in found {
            self.note(reported);
        }
        if !self.drop_usage || (pristine && cut.is_empty() && !hold) {
            return chunk;
        }
        let end = if hold {
            input.len() - rest.len()
        } else {
            input.len()
        };
        let mut out = Vec::with_capacity(end);
        let mut from = 0;
        for (start, stop) in cut {
            out.extend_from_slice(input.get(from..start).unwrap_or_default());
            from = stop;
        }
        out.extend_from_slice(input.get(from..end).unwrap_or_default());
        Bytes::from(out)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn content(text: &str) -> String {
        format!(
            "data: {{\"id\":\"c1\",\"choices\":[{{\"delta\":{{\"content\":\"{text}\"}}}}],\"usage\":null}}\n\n"
        )
    }

    const USAGE: &str = "data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4,\"total_tokens\":7}}\n\n";
    const DONE: &str = "data: [DONE]\n\n";

    fn run(sse: &mut Sse, parts: &[&str]) -> Vec<String> {
        let last = parts.len().saturating_sub(1);
        parts
            .iter()
            .enumerate()
            .map(|(at, part)| {
                let out = sse.push(Bytes::from((*part).to_owned()), at == last);
                String::from_utf8(out.to_vec()).expect("utf-8")
            })
            .collect()
    }

    fn total(sse: &Sse) -> Option<u64> {
        sse.best().map(Reported::total)
    }

    #[test]
    fn ai_sse_drops_only_the_usage_only_event_when_asked() {
        let mut sse = Sse::new(true);
        let (a, b) = (content("he"), content("llo"));
        let out = run(&mut sse, &[&a, &b, USAGE, DONE]);
        assert_eq!(out, [a.as_str(), b.as_str(), "", DONE]);
        assert_eq!(total(&sse), Some(7));

        let mut kept = Sse::new(false);
        let out = run(&mut kept, &[&a, USAGE, DONE]);
        assert_eq!(out, [a.as_str(), USAGE, DONE]);
        assert_eq!(total(&kept), Some(7));
    }

    #[test]
    fn ai_sse_removes_the_usage_event_from_a_chunk_that_also_holds_others() {
        let mut sse = Sse::new(true);
        let a = content("x");
        let joined = format!("{a}{USAGE}{DONE}");
        let out = run(&mut sse, &[&joined]);
        assert_eq!(out, [format!("{a}{DONE}")]);
    }

    #[test]
    fn ai_sse_event_split_across_chunks_is_held_until_whole() {
        let mut sse = Sse::new(true);
        let a = content("he");
        let (head, tail) = USAGE.split_at(40);
        let out = run(&mut sse, &[&format!("{a}{head}"), tail, DONE]);
        assert_eq!(out, [a.as_str(), "", DONE]);

        let mut split = Sse::new(true);
        let other = content("abc");
        let (first, second) = other.split_at(25);
        let out = run(&mut split, &[first, second, DONE]);
        assert_eq!(out, ["", other.as_str(), DONE]);
    }

    #[test]
    fn ai_sse_complete_chunks_are_forwarded_as_the_same_bytes() {
        let mut sse = Sse::new(false);
        let chunk = Bytes::from(content("same"));
        let out = sse.push(chunk.clone(), false);
        assert_eq!(out.as_ptr(), chunk.as_ptr());
        let mut dropping = Sse::new(true);
        let out = dropping.push(chunk.clone(), false);
        assert_eq!(out.as_ptr(), chunk.as_ptr());
    }

    #[test]
    fn ai_sse_crlf_events() {
        let crlf = USAGE.replace('\n', "\r\n");
        let mut sse = Sse::new(true);
        let a = content("x").replace('\n', "\r\n");
        let out = run(&mut sse, &[&a, &crlf]);
        assert_eq!(out, [a.as_str(), ""]);
        assert_eq!(total(&sse), Some(7));
    }

    #[test]
    fn ai_sse_oversized_event_is_forwarded_and_skipped() {
        let mut sse = Sse::new(true);
        let big = format!("data: {}", "x".repeat(EVENT_MAX + 10));
        let out = sse.push(Bytes::from(big.clone()), false);
        assert_eq!(out, big.as_bytes());
        // The rest of that event, then a usage chunk that is still removed.
        let out = run(&mut sse, &["yy\n\n", USAGE]);
        assert_eq!(out, ["yy\n\n", ""]);
        assert_eq!(total(&sse), Some(7));
    }

    #[test]
    fn ai_sse_partial_event_is_released_at_the_end() {
        let mut sse = Sse::new(true);
        let out = run(&mut sse, &["data: {\"partial\":", "1}"]);
        assert_eq!(out, ["", "data: {\"partial\":1}"]);
        // A usage event with no closing blank line is read, and removed, at the end.
        let mut last = Sse::new(true);
        let bare = USAGE.trim_end_matches('\n');
        let out = run(&mut last, &[bare]);
        assert_eq!(out, [""]);
        assert_eq!(total(&last), Some(7));
    }

    #[test]
    fn ai_sse_responses_completed_usage() {
        let event = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":5,\"output_tokens\":6,\"total_tokens\":11}}}\n\n";
        let mut sse = Sse::new(true);
        let out = run(&mut sse, &[event]);
        assert_eq!(out, [event]);
        assert_eq!(total(&sse), Some(11));
    }

    #[test]
    fn ai_sse_cumulative_usage_keeps_the_largest() {
        let with = |total: u64| {
            format!(
                "data: {{\"choices\":[{{\"delta\":{{}}}}],\"usage\":{{\"total_tokens\":{total}}}}}\n\n"
            )
        };
        let mut sse = Sse::new(true);
        let (ten, four) = (with(10), with(4));
        let out = run(&mut sse, &[&ten, &four]);
        // Not usage-only: it has choices, so it stays.
        assert_eq!(out, [ten.as_str(), four.as_str()]);
        assert_eq!(total(&sse), Some(10));
    }

    #[test]
    fn ai_sse_text_cannot_forge_a_usage_event() {
        let forged = content("\\\"usage\\\":{\\\"total_tokens\\\":999999}");
        let mut sse = Sse::new(true);
        let out = run(&mut sse, &[&forged]);
        assert_eq!(out, [forged.as_str()]);
        assert_eq!(sse.best(), None);
    }
}
