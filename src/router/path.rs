//! Path normalization: the path that is matched is the path that is served.
//!
//! Percent-encoded unreserved characters are decoded (`%61` is `a`), other escapes get uppercase
//! hex, dot segments are removed and empty segments collapse. The proxy rewrites the request
//! with the result before routing, so a path that was authorised cannot reach the upstream as a
//! different one. A path that cannot be normalized safely is refused: an encoded `/` or `\`, an
//! encoded NUL, an encoded dot segment (`%2e%2e`) or a broken escape.

use std::borrow::Cow;

use thiserror::Error;

/// Why a path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refused {
    /// An escape that decodes to `/`, `\` or NUL.
    #[error("the path contains an encoded slash, backslash or NUL")]
    EncodedSeparator,
    /// A segment that is `.` or `..` only after decoding.
    #[error("the path contains an encoded dot segment")]
    EncodedDotSegment,
    /// A `%` not followed by two hex digits.
    #[error("the path contains a malformed percent escape")]
    Malformed,
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Decodes the unreserved escapes of one segment; `Ok(None)` when it needs no change.
fn clean_segment(segment: &str, allow_encoded_slash: bool) -> Result<Option<String>, Refused> {
    if !segment.contains('%') {
        return Ok(None);
    }
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'%' {
            out.push(char::from(byte));
            index += 1;
            continue;
        }
        let high = bytes.get(index + 1).copied().and_then(hex);
        let low = bytes.get(index + 2).copied().and_then(hex);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(Refused::Malformed);
        };
        let decoded = high << 4 | low;
        if decoded == b'/' && allow_encoded_slash {
            // Kept as an escape: it is data inside this segment, never a separator.
            out.push_str("%2F");
            index += 3;
            continue;
        }
        if matches!(decoded, b'/' | b'\\' | 0) {
            return Err(Refused::EncodedSeparator);
        }
        if is_unreserved(decoded) {
            out.push(char::from(decoded));
        } else {
            out.push_str(&format!("%{decoded:02X}"));
        }
        index += 3;
    }
    Ok(Some(out))
}

/// Normalizes the path of a request target. A target that is not an absolute path (`*`) is
/// returned as it is.
///
/// # Errors
///
/// [`Refused`] for a path that cannot be normalized without changing what it names.
pub fn normalize(raw: &str) -> Result<Cow<'_, str>, Refused> {
    normalize_with(raw, false)
}

/// [`normalize`], for an entry point that may allow an encoded slash (`allow_encoded_slash`). It
/// changes one thing: `%2F` is kept as an escape inside its segment instead of refusing the
/// path. It is never decoded into a separator, so matching and the upstream see one segment. An
/// encoded backslash and NUL stay refused.
///
/// # Errors
///
/// [`Refused`] for a path that cannot be normalized without changing what it names.
pub fn normalize_with(raw: &str, allow_encoded_slash: bool) -> Result<Cow<'_, str>, Refused> {
    if !raw.starts_with('/') || is_normal(raw) {
        return Ok(Cow::Borrowed(raw));
    }
    rebuild(raw, allow_encoded_slash)
}

/// Whether `raw`, which starts with `/`, is its own normalization: no escape, no empty segment
/// but a last one, no dot segment. Nearly every request is, and this checks it without
/// allocating, which [`rebuild`] cannot.
fn is_normal(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    // Start of the segment being read: just after the `/` before it.
    let mut start = 1;
    for (index, &byte) in bytes.iter().enumerate().skip(1) {
        match byte {
            b'%' => return false,
            b'/' => {
                let segment = &bytes[start..index];
                if matches!(segment, b"" | b"." | b"..") {
                    return false;
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    !matches!(&bytes[start..], b"." | b"..")
}

fn rebuild(raw: &str, allow_encoded_slash: bool) -> Result<Cow<'_, str>, Refused> {
    let mut kept: Vec<Cow<'_, str>> = Vec::new();
    let mut trailing = raw.ends_with('/');
    for segment in raw.split('/') {
        let cleaned = clean_segment(segment, allow_encoded_slash)?;
        let value = cleaned.as_deref().unwrap_or(segment);
        let is_dot = matches!(value, "." | "..");
        if is_dot && cleaned.is_some() {
            return Err(Refused::EncodedDotSegment);
        }
        match value {
            "" => {}
            "." => trailing = true,
            ".." => {
                kept.pop();
                trailing = true;
            }
            _ => {
                kept.push(match cleaned {
                    Some(decoded) => Cow::Owned(decoded),
                    None => Cow::Borrowed(segment),
                });
                // A segment after a dot segment restores the real ending.
                trailing = raw.ends_with('/');
            }
        }
    }
    let mut path = String::with_capacity(raw.len());
    for segment in &kept {
        path.push('/');
        path.push_str(segment);
    }
    if kept.is_empty() || trailing {
        path.push('/');
    }
    Ok(if path == raw {
        Cow::Borrowed(raw)
    } else {
        Cow::Owned(path)
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn clean(raw: &str) -> String {
        normalize(raw).expect("normalizes").into_owned()
    }

    #[test]
    fn clean_paths_are_untouched() {
        for raw in ["/", "/a", "/a/b/", "/a%20b", "/a%3Ab", "*"] {
            assert!(matches!(normalize(raw), Ok(Cow::Borrowed(_))), "{raw}");
        }
    }

    #[test]
    fn the_check_without_allocation_agrees_with_the_rebuild() {
        for raw in [
            "/", "/a", "/a/", "/a/b", "/a/b/", "/a b", "/a\\b", "/a:b", "/.a", "/a./b", "/..a",
            "/a/..b/", "//", "/a//", "//a", "/a//b", "/.", "/..", "/a/.", "/a/..", "/./a", "/../a",
            "/a/./b", "/a%20b", "/%61", "/a%2fb", "/é", "/a/é/",
        ] {
            // The check gives up at any escape, even one the rebuild keeps as it is: it may
            // say no too often, never yes for a path the rebuild changes.
            assert_eq!(
                is_normal(raw),
                !raw.contains('%') && matches!(rebuild(raw, false), Ok(Cow::Borrowed(_))),
                "{raw}"
            );
        }
    }

    #[test]
    fn unreserved_escapes_are_decoded_and_others_uppercased() {
        assert_eq!(clean("/%61pi/%7Euser"), "/api/~user");
        assert_eq!(clean("/a%3ab"), "/a%3Ab");
    }

    #[test]
    fn dot_and_empty_segments_collapse() {
        assert_eq!(clean("/a//b"), "/a/b");
        assert_eq!(clean("/a/./b"), "/a/b");
        assert_eq!(clean("/a/b/../c"), "/a/c");
        assert_eq!(clean("/../a"), "/a");
        assert_eq!(clean("//"), "/");
        assert_eq!(clean("/a/b/."), "/a/b/");
        assert_eq!(clean("/a/b/.."), "/a/");
        assert_eq!(clean("/a/b//"), "/a/b/");
    }

    #[test]
    fn a_dot_segment_cannot_hide_behind_an_escape() {
        for raw in ["/%2e%2e/x", "/a/.%2e", "/%2E/x"] {
            assert_eq!(normalize(raw), Err(Refused::EncodedDotSegment), "{raw}");
        }
    }

    #[test]
    fn encoded_separators_and_broken_escapes_are_refused() {
        for raw in ["/a%2fb", "/a%2Fb", "/a%5cb", "/a%00b"] {
            assert_eq!(normalize(raw), Err(Refused::EncodedSeparator), "{raw}");
        }
        for raw in ["/a%", "/a%2", "/a%zz"] {
            assert_eq!(normalize(raw), Err(Refused::Malformed), "{raw}");
        }
    }

    #[test]
    fn an_allowed_encoded_slash_stays_inside_its_segment() {
        let allowed = |raw| normalize_with(raw, true).map(Cow::into_owned);
        assert_eq!(allowed("/a%2fb/c"), Ok("/a%2Fb/c".to_owned()));
        assert_eq!(allowed("/a%2Fb/./c"), Ok("/a%2Fb/c".to_owned()));
        assert_eq!(allowed("/%2f/x"), Ok("/%2F/x".to_owned()));
        assert_eq!(allowed("/a%2F..%2Fb"), Ok("/a%2F..%2Fb".to_owned()));
        for raw in ["/a%5cb", "/a%00b", "/%2e%2e/x", "/a%2fb%"] {
            assert!(allowed(raw).is_err(), "{raw}");
        }
        assert_eq!(
            normalize_with("/a%2fb", false),
            Err(Refused::EncodedSeparator)
        );
    }
}
