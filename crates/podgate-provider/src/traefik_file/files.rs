//! What the file points at: certificates and keys on disk, and Go durations.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde_json::Value;
use x509_parser::pem::Pem;

use super::obj::{Cx, Obj};

/// The largest file the converter reads, in bytes.
const MAX_BYTES: u64 = 1024 * 1024;

/// The text of the file `spec` names, relative paths from the directory of the Traefik file. The
/// file is remembered, so a source can read the conversion again when it changes.
pub(super) fn read(cx: &Cx, at: &str, spec: &str) -> Option<String> {
    let given = Path::new(spec);
    let full = if given.is_absolute() {
        given.to_owned()
    } else {
        cx.dir.join(given)
    };
    cx.read_file(full.clone());
    let mut text = String::new();
    let outcome =
        File::open(&full).and_then(|file| file.take(MAX_BYTES + 1).read_to_string(&mut text));
    match outcome {
        Ok(read) if read as u64 > MAX_BYTES => {
            cx.invalid(
                at,
                format!("{} is larger than {MAX_BYTES} bytes", full.display()),
            );
            None
        }
        Ok(_) => Some(text),
        Err(err) => {
            cx.invalid(at, format!("cannot read {}: {err}", full.display()));
            None
        }
    }
}

/// A PEM read from a file. The content must be PEM, so a path that names some other file never
/// ends up in a snapshot.
pub(super) fn read_pem(cx: &Cx, at: &str, spec: &str) -> Option<String> {
    let text = read(cx, at, spec)?;
    if text.contains("-----BEGIN ") {
        Some(text)
    } else {
        cx.invalid(at, format!("{spec} holds no PEM block"));
        None
    }
}

/// Traefik's `FileOrContent`: a PEM given inline, or the path of one.
pub(super) fn pem_or_path(cx: &Cx, at: &str, spec: &str) -> Option<String> {
    if spec.trim_start().starts_with("-----BEGIN ") {
        Some(spec.to_owned())
    } else {
        read_pem(cx, at, spec)
    }
}

/// The names a certificate is good for: its DNS subject alternative names, else its common name.
pub(super) fn hosts_of(cx: &Cx, at: &str, pem: &str) -> Option<Vec<Box<str>>> {
    let leaf = Pem::iter_from_buffer(pem.as_bytes())
        .filter_map(Result::ok)
        .find(|block| block.label == "CERTIFICATE");
    let Some(leaf) = leaf else {
        cx.invalid(at, "holds no CERTIFICATE block");
        return None;
    };
    let certificate = match leaf.parse_x509() {
        Ok(certificate) => certificate,
        Err(err) => {
            cx.invalid(at, format!("is not a certificate: {err}"));
            return None;
        }
    };
    let mut hosts: Vec<Box<str>> = Vec::new();
    if let Ok(Some(alternative)) = certificate.subject_alternative_name() {
        for name in &alternative.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                hosts.push(dns.to_ascii_lowercase().into());
            }
        }
    }
    if hosts.is_empty() {
        hosts.extend(
            certificate
                .subject()
                .iter_common_name()
                .filter_map(|name| name.as_str().ok())
                .map(|name| Box::<str>::from(name.to_ascii_lowercase())),
        );
    }
    if hosts.is_empty() {
        cx.invalid(
            at,
            "names no host: it has no DNS subject alternative name and no common name",
        );
        return None;
    }
    Some(hosts)
}

/// The unit a duration option is kept in.
#[derive(Clone, Copy)]
pub(super) enum Unit {
    Seconds,
    Millis,
}

impl Unit {
    fn nanos(self) -> u128 {
        match self {
            Self::Seconds => 1_000_000_000,
            Self::Millis => 1_000_000,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Seconds => "second",
            Self::Millis => "millisecond",
        }
    }
}

/// A duration option: a Go duration (`10s`, `1m30s`, `250ms`) or a plain number of seconds, as a
/// whole number of `unit`. Zero is returned as zero: whether it means "none" is the caller's.
pub(super) fn duration(obj: &mut Obj<'_>, key: &str, unit: Unit) -> Option<u64> {
    let value = obj.value(key)?;
    let parsed = match value {
        Value::Number(n) => n
            .as_u64()
            .map(|seconds| u128::from(seconds) * 1_000_000_000)
            .ok_or_else(|| "must be a whole number of seconds".to_owned()),
        Value::String(text) => nanoseconds(text),
        _ => Err("must be a duration such as 10s or 250ms".to_owned()),
    };
    match parsed {
        Ok(total) if total % unit.nanos() == 0 => match u64::try_from(total / unit.nanos()) {
            Ok(whole) => Some(whole),
            Err(_) => {
                obj.invalid(key, "is too long a duration");
                None
            }
        },
        Ok(_) => {
            obj.invalid(
                key,
                format!("podgate keeps this duration in whole {}s", unit.name()),
            );
            None
        }
        Err(why) => {
            obj.invalid(key, why);
            None
        }
    }
}

/// A Go duration, in nanoseconds.
fn nanoseconds(text: &str) -> Result<u128, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("is empty".to_owned());
    }
    let mut total: u128 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(format!(
                "{text:?} is not a duration such as 10s, 250ms or 1m30s"
            ));
        }
        let amount: u128 = rest[..digits]
            .parse()
            .map_err(|_| format!("{text:?} is not a duration"))?;
        rest = &rest[digits..];
        let (unit, len): (u128, usize) = if rest.starts_with("ms") {
            (1_000_000, 2)
        } else if rest.starts_with("us") {
            (1_000, 2)
        } else if rest.starts_with("ns") {
            (1, 2)
        } else if rest.starts_with('s') {
            (1_000_000_000, 1)
        } else if rest.starts_with('m') {
            (60_000_000_000, 1)
        } else if rest.starts_with('h') {
            (3_600_000_000_000, 1)
        } else {
            return Err(format!(
                "{text:?} is not a duration; use whole numbers with ns, us, ms, s, m or h"
            ));
        };
        total = total.saturating_add(amount.saturating_mul(unit));
        rest = &rest[len..];
    }
    Ok(total)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(nanoseconds("10s"), Ok(10_000_000_000));
        assert_eq!(nanoseconds("1m30s"), Ok(90_000_000_000));
        assert_eq!(nanoseconds("250ms"), Ok(250_000_000));
        assert!(nanoseconds("1.5s").is_err());
        assert!(nanoseconds("5x").is_err());
        assert!(nanoseconds("").is_err());
    }
}
