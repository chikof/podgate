//! Writes a [`Record`] as one line: a JSON object or a Common Log Format line.
//!
//! Nothing a request controls can add a field or a line: JSON strings escape the quote, the
//! backslash and every control character (as `\u00XX`, so a newline is never a newline), and the
//! Common Log Format escapes the same set as `\xHH` and the quote and backslash with a
//! backslash. A value over [`FIELD_MAX`] bytes was cut when the record was built and its field
//! is listed under `truncated`.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Record;
use super::policy::{Action, Field, Format, REDACTED};

/// The longest a single logged value may be, in bytes.
pub(super) const FIELD_MAX: usize = 2048;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl Record {
    /// Appends this record as one line, with its newline.
    pub(super) fn render(&self, out: &mut String) {
        match self.policy.format() {
            Format::Json => self.json(out),
            Format::Common => self.common(out),
        }
        out.push('\n');
    }

    fn json(&self, out: &mut String) {
        out.push('{');
        let mut first = true;
        for field in Field::ALL {
            let action = self.policy.action(field);
            if action == Action::Drop {
                continue;
            }
            key(out, &mut first, field.name());
            if action == Action::Redact {
                json_string(out, REDACTED);
            } else {
                self.json_value(out, field, action);
            }
        }
        for (name, headers) in [
            ("request_headers", &self.request_headers),
            ("response_headers", &self.response_headers),
        ] {
            if headers.is_empty() {
                continue;
            }
            key(out, &mut first, name);
            out.push('{');
            for (index, (header, value)) in headers.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                json_string(out, header);
                out.push(':');
                json_string(out, value);
            }
            out.push('}');
        }
        if !self.truncated.is_empty() {
            key(out, &mut first, "truncated");
            out.push('[');
            for (index, name) in self.truncated.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                json_string(out, name);
            }
            out.push(']');
        }
        out.push('}');
    }

    fn json_value(&self, out: &mut String, field: Field, action: Action) {
        let text = |out: &mut String, value: Option<&str>| match value {
            Some(value) => json_string(out, value),
            None => out.push_str("null"),
        };
        match field {
            Field::Time => {
                let mut stamp = String::with_capacity(24);
                rfc3339(self.time, &mut stamp);
                json_string(out, &stamp);
            }
            Field::RequestId => json_string(out, &self.request_id),
            Field::EntryPoint => json_string(out, &self.entry_point),
            Field::Tenant => text(out, self.tenant.as_deref()),
            Field::App => text(out, self.app.as_deref()),
            Field::Router => text(out, self.router.as_deref()),
            Field::Service => text(out, self.service.as_deref()),
            Field::Revision => text(out, self.revision.as_deref()),
            Field::Server => text(out, self.server.map(|addr| addr.to_string()).as_deref()),
            Field::Method => json_string(out, &self.method),
            Field::Host => text(out, self.host.as_deref()),
            Field::Path => json_string(out, &self.path),
            Field::Query => text(out, self.query.as_deref()),
            Field::Proto => json_string(out, self.proto),
            Field::Status => push_number(out, self.status),
            Field::BytesIn => push_number(out, self.bytes_in),
            Field::BytesOut => push_number(out, self.bytes_out),
            Field::DurationMs => millis(out, self.duration),
            Field::UpstreamDurationMs => match self.upstream {
                Some(duration) => millis(out, duration),
                None => out.push_str("null"),
            },
            Field::ClientIp => text(out, self.client_ip_text(action).as_deref()),
            Field::TlsVersion => text(out, self.tls_version.as_deref()),
            Field::Sni => text(out, self.sni.as_deref()),
            Field::RetryAttempts => push_number(out, self.retry_attempts),
            Field::Origin => json_string(out, self.origin),
            Field::Reason => text(out, self.reason),
            Field::UserAgent => text(out, self.user_agent.as_deref()),
            Field::Referer => text(out, self.referer.as_deref()),
        }
    }

    fn client_ip_text(&self, action: Action) -> Option<String> {
        let addr: IpAddr = self.client_ip?;
        Some(match action {
            Action::Mask(mask) => mask.apply(addr).to_string(),
            _ => addr.to_string(),
        })
    }

    /// `host ident authuser [time] "request" status bytes`, with `-` for what is absent.
    fn common(&self, out: &mut String) {
        let part = |out: &mut String, field: Field, value: Option<String>, quoted: bool| match self
            .policy
            .action(field)
        {
            Action::Drop => out.push('-'),
            Action::Redact => out.push_str(REDACTED),
            Action::Keep | Action::Mask(_) => match value {
                Some(value) if quoted => clf_escaped(out, &value),
                Some(value) => out.push_str(&value),
                None => out.push('-'),
            },
        };
        let client = self.client_ip_text(self.policy.action(Field::ClientIp));
        part(out, Field::ClientIp, client, false);
        out.push_str(" - - [");
        let mut stamp = String::with_capacity(26);
        clf_time(self.time, &mut stamp);
        part(out, Field::Time, Some(stamp), false);
        out.push_str("] \"");
        part(out, Field::Method, Some(self.method.to_string()), true);
        out.push(' ');
        part(out, Field::Path, Some(self.path.to_string()), true);
        if self.truncated.contains(&"path") && self.policy.action(Field::Path) == Action::Keep {
            out.push_str("...");
        }
        out.push(' ');
        part(out, Field::Proto, Some(self.proto.to_owned()), true);
        out.push_str("\" ");
        part(out, Field::Status, Some(self.status.to_string()), false);
        out.push(' ');
        let bytes = (self.bytes_out > 0).then(|| self.bytes_out.to_string());
        part(out, Field::BytesOut, bytes, false);
    }
}

fn key(out: &mut String, first: &mut bool, name: &str) {
    if !std::mem::take(first) {
        out.push(',');
    }
    json_string(out, name);
    out.push(':');
}

fn push_number(out: &mut String, value: impl std::fmt::Display) {
    // Writing to a String cannot fail.
    let _ = write!(out, "{value}");
}

fn millis(out: &mut String, duration: Duration) {
    let micros = duration.as_micros();
    let _ = write!(out, "{}.{:03}", micros / 1000, micros % 1000);
}

/// A JSON string literal: quote, backslash and every control character escaped, so the value
/// cannot end the string, start a field or end the line. U+2028 and U+2029 are escaped too, for
/// consumers that split lines on them.
pub(super) fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0}'..='\u{1f}' | '\u{7f}' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// `value` for inside the quotes of a Common Log Format line.
fn clf_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(out, "\\x{:02x}", u32::from(ch));
            }
            other => out.push(other),
        }
    }
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, usize, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, usize::try_from(month).unwrap_or(1), day)
}

/// The parts of `time`: civil date, then hour, minute, second and millisecond.
fn parts(time: SystemTime) -> (i64, usize, i64, i64, i64, i64, u32) {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = i64::try_from(since.as_secs()).unwrap_or(0);
    let (year, month, day) = civil(secs.div_euclid(86_400));
    let in_day = secs.rem_euclid(86_400);
    (
        year,
        month,
        day,
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60,
        since.subsec_millis(),
    )
}

/// `2026-11-20T12:00:00.123Z`.
fn rfc3339(time: SystemTime, out: &mut String) {
    let (year, month, day, hour, minute, second, milli) = parts(time);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z"
    );
}

/// `20/Nov/2026:12:00:00 +0000`.
fn clf_time(time: SystemTime, out: &mut String) {
    let (year, month, day, hour, minute, second, _) = parts(time);
    let name = MONTHS
        .get(month.saturating_sub(1))
        .copied()
        .unwrap_or("Jan");
    let _ = write!(
        out,
        "{day:02}/{name}/{year:04}:{hour:02}:{minute:02}:{second:02} +0000"
    );
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::observe::access_log::Record;

    fn at(secs: u64, milli: u32) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(u64::from(milli))
    }

    #[test]
    fn times_are_rendered_in_utc() {
        let mut out = String::new();
        rfc3339(at(0, 0), &mut out);
        assert_eq!(out, "1970-01-01T00:00:00.000Z");
        out.clear();
        // 2026-11-20 12:34:56 UTC.
        rfc3339(at(1_795_178_096, 7), &mut out);
        assert_eq!(out, "2026-11-20T12:34:56.007Z");
        out.clear();
        clf_time(at(1_795_178_096, 0), &mut out);
        assert_eq!(out, "20/Nov/2026:12:34:56 +0000");
        out.clear();
        // The leap day.
        rfc3339(at(1_709_209_200, 0), &mut out);
        assert_eq!(out, "2024-02-29T12:20:00.000Z");
    }

    fn line(record: &Record) -> String {
        let mut out = String::new();
        record.render(&mut out);
        out
    }

    #[test]
    fn access_log_escapes_control_chars() {
        let hostile = "a\r\nb\"c\\d\u{0}e\u{1b}[31m\u{7f}\u{2028},\"status\":200";
        let mut record = Record::sample(&json!({}));
        record.path = hostile.into();
        record.host = Some(hostile.into());
        let text = line(&record);
        assert_eq!(text.matches('\n').count(), 1, "one line only: {text:?}");
        assert!(!text.contains('\r'));
        assert!(!text.chars().any(|ch| ch.is_control() && ch != '\n'));
        let parsed: Value = serde_json::from_str(text.trim_end()).expect("still one JSON object");
        assert_eq!(parsed["path"], hostile);
        assert_eq!(parsed["host"], hostile);
        assert_eq!(parsed["status"], 200);
        let plain: Value =
            serde_json::from_str(line(&Record::sample(&json!({}))).trim_end()).expect("json");
        assert_eq!(
            parsed.as_object().map(serde_json::Map::len),
            plain.as_object().map(serde_json::Map::len),
            "a hostile value added no field"
        );
        assert!(text.contains("\\u000d\\u000a"), "{text}");
    }

    #[test]
    fn access_log_common_format() {
        let mut record = Record::sample(&json!({"format": "common"}));
        record.time = at(1_795_178_096, 0);
        record.client_ip = Some("203.0.113.7".parse().expect("ip"));
        record.method = "GET".into();
        record.path = "/a b/\"x\"\r\n".into();
        record.proto = "HTTP/1.1";
        record.status = 404;
        record.bytes_out = 1234;
        assert_eq!(
            line(&record),
            "203.0.113.7 - - [20/Nov/2026:12:34:56 +0000] \"GET /a b/\\\"x\\\"\\x0d\\x0a HTTP/1.1\" 404 1234\n"
        );
        record.bytes_out = 0;
        assert!(line(&record).ends_with(" 404 -\n"));
    }

    #[test]
    fn common_format_follows_field_actions() {
        let mut record = Record::sample(&json!({"format": "common", "fields": {"names": {
            "client_ip": {"action": "mask", "ipv4_bits": 24}, "path": "redact", "proto": "drop"}}}));
        record.time = at(1_795_178_096, 0);
        record.client_ip = Some("203.0.113.77".parse().expect("ip"));
        record.method = "POST".into();
        record.status = 201;
        record.bytes_out = 5;
        assert_eq!(
            line(&record),
            "203.0.113.0 - - [20/Nov/2026:12:34:56 +0000] \"POST [redacted] -\" 201 5\n"
        );
    }

    #[test]
    fn json_numbers_and_durations() {
        let mut record = Record::sample(&json!({}));
        record.duration = Duration::from_micros(12_345);
        record.upstream = Some(Duration::from_millis(7));
        let parsed: Value = serde_json::from_str(line(&record).trim_end()).expect("json");
        assert_eq!(parsed["duration_ms"], 12.345);
        assert_eq!(parsed["upstream_duration_ms"], 7.0);
        record.upstream = None;
        let parsed: Value = serde_json::from_str(line(&record).trim_end()).expect("json");
        assert_eq!(parsed["upstream_duration_ms"], Value::Null);
    }
}
