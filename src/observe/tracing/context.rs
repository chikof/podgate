//! W3C Trace Context: reading `traceparent` and `tracestate`, and writing a `traceparent`.
//! Pure code: nothing here touches a request or a clock.

use std::fmt;

use http::HeaderMap;

/// The longest `tracestate` kept for an exported span; a longer one is passed on but not recorded.
const TRACESTATE_MAX: usize = 512;

/// A 16-byte trace id. Never all zero once parsed or generated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TraceId(pub(super) [u8; 16]);

/// An 8-byte span id. Never all zero once parsed or generated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SpanId(pub(super) [u8; 8]);

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Display for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for SpanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// The parent a request names in its `traceparent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Parent {
    /// The trace the request continues.
    pub(super) trace_id: TraceId,
    /// The caller's span, the parent of this proxy's server span.
    pub(super) span_id: SpanId,
    /// The caller's sampled flag.
    pub(super) sampled: bool,
}

/// Lowercase hex to bytes; anything else (uppercase, signs, short or long) is `None`.
fn hex<const N: usize>(text: &[u8]) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut out = [0_u8; N];
    let (pairs, _) = text.as_chunks::<2>();
    for (byte, [high, low]) in out.iter_mut().zip(pairs) {
        *byte = nibble(*high)? << 4 | nibble(*low)?;
    }
    Some(out)
}

/// Parses one `traceparent` value: `version-trace_id-parent_id-flags`, lowercase hex, neither id
/// all zero, version `ff` refused. A version above `00` may carry more fields after a dash, which
/// are ignored; version `00` carries exactly four.
#[must_use]
pub(super) fn parse_traceparent(value: &str) -> Option<Parent> {
    let bytes = value.as_bytes();
    let version: [u8; 1] = hex(bytes.get(0..2)?)?;
    if version[0] == 0xff || bytes.get(2) != Some(&b'-') {
        return None;
    }
    let trace_id: [u8; 16] = hex(bytes.get(3..35)?)?;
    let span_id: [u8; 8] = hex(bytes.get(36..52)?)?;
    let flags: [u8; 1] = hex(bytes.get(53..55)?)?;
    if bytes.get(35) != Some(&b'-') || bytes.get(52) != Some(&b'-') {
        return None;
    }
    match bytes.get(55) {
        None => {}
        Some(b'-') if version[0] != 0 => {}
        Some(_) => return None,
    }
    if trace_id == [0; 16] || span_id == [0; 8] {
        return None;
    }
    Some(Parent {
        trace_id: TraceId(trace_id),
        span_id: SpanId(span_id),
        sampled: flags[0] & 1 == 1,
    })
}

/// The parent a request names. Exactly one `traceparent` header that parses counts: two of them,
/// or one that does not parse, start a new trace.
#[must_use]
pub(super) fn incoming(headers: &HeaderMap) -> Option<Parent> {
    let mut values = headers.get_all("traceparent").iter();
    let only = values.next()?;
    if values.next().is_some() {
        return None;
    }
    parse_traceparent(only.to_str().ok()?)
}

/// The request's `tracestate`, all its header lines joined, when it is plain visible ASCII and
/// short enough to record.
#[must_use]
pub(super) fn tracestate(headers: &HeaderMap) -> Option<Box<str>> {
    let mut joined = String::new();
    for value in headers.get_all("tracestate") {
        let text = value.to_str().ok()?;
        if !joined.is_empty() {
            joined.push(',');
        }
        joined.push_str(text);
        if joined.len() > TRACESTATE_MAX {
            return None;
        }
    }
    (!joined.is_empty()).then(|| joined.into())
}

/// A version `00` `traceparent` value.
#[must_use]
pub(super) fn format(trace_id: TraceId, span_id: SpanId, sampled: bool) -> String {
    format!(
        "00-{trace_id}-{span_id}-{}",
        if sampled { "01" } else { "00" }
    )
}

#[cfg(test)]
mod test {
    use super::*;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn traceparent_parses_the_w3c_example() {
        let parent = parse_traceparent(VALID).expect("valid");
        assert_eq!(
            parent.trace_id.to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(parent.span_id.to_string(), "00f067aa0ba902b7");
        assert!(parent.sampled);
        let unsampled = parse_traceparent(&VALID.replace("-01", "-00")).expect("valid");
        assert!(!unsampled.sampled);
        let other_flags = parse_traceparent(&VALID.replace("-01", "-fe")).expect("valid");
        assert!(
            !other_flags.sampled,
            "only the lowest bit is the sampled flag"
        );
    }

    #[test]
    fn traceparent_refuses_malformed_values() {
        for bad in [
            "",
            "garbage",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-4bf92f3577b34da6a3ce929d0e0e47-00f067aa0ba902b7-01",
            "0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ] {
            assert_eq!(parse_traceparent(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_traceparent(&VALID.replace('-', "_")),
            None,
            "wrong separators"
        );
    }

    #[test]
    fn traceparent_future_versions_may_add_fields() {
        let future = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-what-ever";
        assert!(parse_traceparent(future).is_some());
        let glued = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x";
        assert_eq!(parse_traceparent(glued), None);
    }

    #[test]
    fn traceparent_two_headers_start_a_new_trace() {
        let mut headers = HeaderMap::new();
        headers.append("traceparent", VALID.parse().expect("value"));
        assert!(incoming(&headers).is_some());
        headers.append("traceparent", VALID.parse().expect("value"));
        assert_eq!(incoming(&headers), None);
    }

    #[test]
    fn traceparent_round_trips() {
        let parent = parse_traceparent(VALID).expect("valid");
        assert_eq!(format(parent.trace_id, parent.span_id, true), VALID);
    }

    #[test]
    fn tracestate_lines_are_joined_and_long_ones_are_not_recorded() {
        let mut headers = HeaderMap::new();
        assert_eq!(tracestate(&headers), None);
        headers.append("tracestate", "a=1".parse().expect("value"));
        headers.append("tracestate", "b=2".parse().expect("value"));
        assert_eq!(tracestate(&headers).as_deref(), Some("a=1,b=2"));
        headers.append("tracestate", "c=".repeat(300).parse().expect("value"));
        assert_eq!(tracestate(&headers), None);
    }
}
