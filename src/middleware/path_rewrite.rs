//! What the five path rewrite kinds share (`add_prefix`, `strip_prefix`, `strip_prefix_regex`,
//! `replace_path`, `replace_path_regex`): the re-normalization of a result, the write into the
//! request, the two forwarded headers and the refusal. Reference: `docs/ref/mw-rewrite.md`.
//!
//! A rewrite runs on the request head that goes to the upstream, after routing, so routing and
//! every matcher saw the original path. Whatever a kind computes goes through [`commit`], which
//! applies the same normalization the entry point applied before routing ([`crate::router::path`]),
//! so the path that was authorised is the path that is served: dot segments are resolved, empty
//! segments collapse (a result that starts with `//` cannot become an authority) and an empty
//! result is `/`. A result that cannot be a safe path is a [`Refusal`], and the request is
//! answered with `500` instead of being forwarded.

use std::borrow::Cow;

use http::HeaderValue;
use pingora::http::RequestHeader;
use pingora::{Error, ErrorType};
use thiserror::Error;

use super::RequestCx;
use crate::compile::Invalid;
use crate::router::path::{self, Refused};

/// What the stripping kinds tell the upstream: the prefix they removed.
pub(super) const FORWARDED_PREFIX: &str = "X-Forwarded-Prefix";

/// What the replacing kinds tell the upstream: the path before the first replacement.
pub(super) const REPLACED_PATH: &str = "X-Replaced-Path";

/// Longest literal a snapshot may give a rewrite (a prefix, a path, a regular expression or a
/// replacement template), in bytes.
pub(super) const MAX_LITERAL: usize = 1024;

/// Most prefixes or regular expressions one stripping middleware lists.
pub(super) const MAX_ENTRIES: usize = 32;

/// How much longer than the path it replaces a rewritten path may be, in bytes. A replacement
/// template can repeat a capture, so this keeps one request from turning into a large allocation.
const MAX_GROWTH: usize = 16 * 1024;

/// Largest compiled size of a rewrite's regular expression.
pub(super) const REGEX_SIZE_LIMIT: usize = 1 << 16;

/// Why a rewrite result is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum Refusal {
    /// The normalization refused the path (an encoded slash or NUL, an encoded dot segment, a
    /// broken escape).
    #[error("{0}")]
    Path(#[from] Refused),
    /// A character a request path cannot hold: a control character, a space, `?`, `#`, `\` or a
    /// byte outside ASCII.
    #[error("the result has a character a path cannot hold")]
    Character,
    /// The result is much longer than the path it replaces.
    #[error("the result is more than 16 KiB longer than the path it replaces")]
    TooLong,
    /// The result is not a valid request target, or a header cannot carry it.
    #[error("the result is not a valid request target")]
    Target,
}

/// The configuration error of kind `kind`: `invalid_middleware`.
pub(super) fn invalid(kind: &str, message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("{kind}: {message}"))
}

/// Checks that `text` can sit in a path: no byte a request target cannot hold.
fn check_characters(text: &str) -> Result<(), Refusal> {
    let bad = text
        .bytes()
        .any(|byte| byte <= b' ' || byte >= 0x7f || matches!(byte, b'?' | b'#' | b'\\'));
    if bad { Err(Refusal::Character) } else { Ok(()) }
}

/// Normalizes a rewrite result: rooted at `/`, characters checked, then the entry point's
/// normalization.
fn finish(candidate: &str) -> Result<String, Refusal> {
    let rooted: Cow<'_, str> = if candidate.starts_with('/') {
        Cow::Borrowed(candidate)
    } else {
        Cow::Owned(format!("/{candidate}"))
    };
    check_characters(&rooted)?;
    Ok(path::normalize(&rooted)?.into_owned())
}

/// A literal a snapshot gives (an `add_prefix` prefix, a `replace_path` path, a prefix to
/// strip): rooted at `/`, bounded, and normalizable. Returns it normalized.
pub(super) fn literal(kind: &str, field: &str, raw: &str) -> Result<String, Invalid> {
    if !raw.starts_with('/') {
        return Err(invalid(
            kind,
            format!("{field} {raw:?} must start with `/`"),
        ));
    }
    if raw.len() > MAX_LITERAL {
        return Err(invalid(
            kind,
            format!("{field} is longer than {MAX_LITERAL} bytes"),
        ));
    }
    finish(raw).map_err(|why| invalid(kind, format!("{field} {raw:?}: {why}")))
}

/// Checks that a pattern or a template is no longer than [`MAX_LITERAL`].
pub(super) fn bounded(kind: &str, field: &str, raw: &str) -> Result<(), Invalid> {
    if raw.len() > MAX_LITERAL {
        return Err(invalid(
            kind,
            format!("{field} is longer than {MAX_LITERAL} bytes"),
        ));
    }
    Ok(())
}

/// Checks that a replacement template cannot put a character a path cannot hold into the path.
pub(super) fn template_characters(kind: &str, template: &str) -> Result<(), Invalid> {
    check_characters(template).map_err(|why| invalid(kind, format!("replacement: {why}")))
}

/// The path of the request, when it is an absolute path. Other targets (`*`) are left alone by
/// every rewrite.
pub(super) fn current(request: &RequestHeader) -> Option<&str> {
    let path = request.uri.path();
    path.starts_with('/').then_some(path)
}

/// How long a rewritten path may be when it replaces one of `current` bytes.
pub(super) fn limit(current: usize) -> usize {
    current.saturating_add(MAX_GROWTH)
}

/// Makes `candidate` the path of the upstream request, keeping the query string as it is.
pub(super) fn commit(request: &mut RequestHeader, candidate: &str) -> Result<(), Refusal> {
    let before = request.uri.path().len();
    if candidate.len() > limit(before) {
        return Err(Refusal::TooLong);
    }
    let finished = finish(candidate)?;
    if finished == request.uri.path() {
        return Ok(());
    }
    let target = match request.uri.query() {
        Some(query) => format!("{finished}?{query}"),
        None => finished,
    };
    let mut parts = request.uri.clone().into_parts();
    parts.path_and_query = Some(target.parse().map_err(|_| Refusal::Target)?);
    let uri = http::Uri::from_parts(parts).map_err(|_| Refusal::Target)?;
    request.set_uri(uri);
    Ok(())
}

/// Removes the copies of `headers` the client sent, before any rewrite sets its own: a header
/// the upstream trusts to say what the proxy did must never be one the client wrote.
pub(super) fn drop_client_copies(cx: &mut RequestCx<'_>, headers: &[&str]) {
    let request = cx.session.req_header_mut();
    for header in headers {
        request.remove_header(*header);
    }
}

/// Records `prefix` as stripped. A second stripping middleware adds its prefix after the first
/// one's, so the header always holds everything that was removed.
pub(super) fn add_forwarded_prefix(
    request: &mut RequestHeader,
    prefix: &str,
) -> Result<(), Refusal> {
    let joined = match request.headers.get(FORWARDED_PREFIX) {
        Some(earlier) => format!("{}{prefix}", earlier.to_str().map_err(|_| Refusal::Target)?),
        None => prefix.to_owned(),
    };
    let value = HeaderValue::from_str(&joined).map_err(|_| Refusal::Target)?;
    request
        .insert_header(FORWARDED_PREFIX, value)
        .map_err(|_| Refusal::Target)?;
    Ok(())
}

/// Records `original` as the path before the first replacement; a later replacement keeps it.
pub(super) fn keep_replaced_path(
    request: &mut RequestHeader,
    original: &str,
) -> Result<(), Refusal> {
    if request.headers.contains_key(REPLACED_PATH) {
        return Ok(());
    }
    let value = HeaderValue::from_str(original).map_err(|_| Refusal::Target)?;
    request
        .insert_header(REPLACED_PATH, value)
        .map_err(|_| Refusal::Target)?;
    Ok(())
}

/// Turns a refused rewrite into the error that ends the request with `500`, after naming the
/// middleware in the log. The client never sees the cause.
pub(super) fn settle(
    kind: &'static str,
    middleware: &str,
    outcome: Result<(), Refusal>,
) -> pingora::Result<()> {
    outcome.map_err(|why| {
        tracing::warn!(
            kind,
            middleware,
            error = %why,
            "path rewrite refused, answering 500"
        );
        Error::explain(
            ErrorType::InternalError,
            format!("{kind} middleware {middleware}: {why}"),
        )
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn a_result_is_rooted_and_renormalized() {
        for (candidate, expected) in [
            ("/a/b", "/a/b"),
            ("a/b", "/a/b"),
            ("", "/"),
            ("//", "/"),
            ("//evil.test/x", "/evil.test/x"),
            ("///x", "/x"),
            ("/a/../b", "/b"),
            ("/a/./b/", "/a/b/"),
            ("/../..", "/"),
            ("/%61pi", "/api"),
        ] {
            assert_eq!(finish(candidate).as_deref(), Ok(expected), "{candidate:?}");
        }
    }

    #[test]
    fn a_result_a_path_cannot_hold_is_refused() {
        for candidate in [
            "/a?x=1", "/a#f", "/a b", "/a\tb", "/a\nb", "/a\\b", "/é", "/a\x7f",
        ] {
            assert_eq!(finish(candidate), Err(Refusal::Character), "{candidate:?}");
        }
        for candidate in ["/a%2fb", "/a%2Fb", "/a%00", "/a%5c", "/%2e%2e/x", "/a%zz"] {
            assert!(
                matches!(finish(candidate), Err(Refusal::Path(_))),
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn commit_keeps_the_query_and_skips_a_no_op() {
        let mut request = RequestHeader::build("GET", b"/a/b?x=1&y=%2F", None).expect("request");
        commit(&mut request, "/c//d/../e").expect("commits");
        assert_eq!(
            request
                .uri
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str),
            Some("/c/e?x=1&y=%2F")
        );
        commit(&mut request, "/c/e").expect("no-op");
        assert_eq!(request.uri.path(), "/c/e");
    }

    #[test]
    fn a_result_far_longer_than_the_path_is_refused() {
        let mut request = RequestHeader::build("GET", b"/a", None).expect("request");
        let huge = format!("/{}", "x".repeat(MAX_GROWTH + 2));
        assert_eq!(commit(&mut request, &huge), Err(Refusal::TooLong));
        assert_eq!(request.uri.path(), "/a");
    }

    #[test]
    fn forwarded_headers_accumulate_and_keep_the_first_original() {
        let mut request = RequestHeader::build("GET", b"/a", None).expect("request");
        add_forwarded_prefix(&mut request, "/a").expect("first");
        add_forwarded_prefix(&mut request, "/b").expect("second");
        assert_eq!(request.headers.get(FORWARDED_PREFIX).expect("set"), "/a/b");
        keep_replaced_path(&mut request, "/one").expect("first");
        keep_replaced_path(&mut request, "/two").expect("second");
        assert_eq!(request.headers.get(REPLACED_PATH).expect("set"), "/one");
    }
}
