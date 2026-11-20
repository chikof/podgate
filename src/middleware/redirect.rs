//! What `redirect_scheme` and `redirect_regex` share: the URL a redirect is computed from, the
//! status pair and the one place where a request-derived string becomes a `Location` header.
//!
//! The URL is `scheme://host[:port]/path?query`. The scheme is the connection's real one (a TLS
//! digest on the session), never `X-Forwarded-Proto`; the host is the URI authority or `Host`
//! header, lowercase, no trailing dot, and only host characters; the path is the one the path
//! normalization already rewrote the request to.
//!
//! [`finish`] is the header-injection guard: a control byte, a DEL, or a percent escape of one
//! anywhere in the target refuses the request (`400`), and nothing else about the target is
//! trusted either: only `http` and `https` targets, no userinfo, a bounded length, and bytes a
//! browser could read as a different URL are percent-encoded.

use http::StatusCode;
use http::uri::Authority;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use thiserror::Error;

use super::Flow;
use crate::entry;
use crate::error::AppError;
use crate::respond;

/// Longest `Location` a redirect may send. The URL a regex rewrites is bounded by the request
/// head, but a replacement can repeat a capture for every match.
pub const MAX_LOCATION: usize = 8 * 1024;

/// The status of a redirect: `301` when `permanent`, else `302`. These are the codes Traefik
/// v3.7.16 sends for `redirectScheme` and `redirectRegex` (checked against the binary pinned in
/// `devenv.nix`). Both let a client turn a `POST` into a `GET`; so does Traefik.
#[must_use]
pub fn status(permanent: bool) -> StatusCode {
    if permanent {
        StatusCode::MOVED_PERMANENTLY
    } else {
        StatusCode::FOUND
    }
}

/// Why a redirect cannot be sent. Every variant answers `400`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refused {
    /// The request names no usable host.
    #[error("request has no valid host")]
    Host,
    /// A control byte, a DEL, or an escape of one.
    #[error("redirect target has a control character")]
    Control,
    /// The target is not `http`, `https`, protocol-relative or a path.
    #[error("redirect target has an unsupported scheme")]
    Scheme,
    /// The target's authority carries `user@`.
    #[error("redirect target has userinfo")]
    Userinfo,
    /// The target is empty.
    #[error("redirect target is empty")]
    Empty,
    /// The target is longer than [`MAX_LOCATION`].
    #[error("redirect target is too long")]
    TooLong,
}

/// What a request looks like to a redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    tls: bool,
    host: String,
    port: Option<u16>,
    target: String,
}

impl Origin {
    /// The origin of the session's request.
    ///
    /// # Errors
    ///
    /// [`Refused::Host`] when the request names no host or one with characters a host cannot
    /// have.
    pub fn of(session: &Session) -> Result<Self, Refused> {
        Self::from_request(session.req_header(), entry::is_tls(session))
    }

    pub(super) fn from_request(request: &RequestHeader, tls: bool) -> Result<Self, Refused> {
        let authority = match request.uri.authority() {
            Some(authority) => authority.clone(),
            None => {
                let raw = request.headers.get("host").ok_or(Refused::Host)?;
                Authority::try_from(raw.as_bytes()).map_err(|_| Refused::Host)?
            }
        };
        if authority.as_str().contains('@') {
            return Err(Refused::Host);
        }
        let mut host = authority.host().to_ascii_lowercase();
        if let Some(trimmed) = host.strip_suffix('.') {
            host.truncate(trimmed.len());
        }
        let valid = !host.is_empty()
            && host.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'[' | b']' | b':')
            });
        if !valid {
            return Err(Refused::Host);
        }
        let target = request
            .uri
            .path_and_query()
            .map_or("/", |target| target.as_str())
            .to_owned();
        Ok(Self {
            tls,
            host,
            port: authority.port_u16(),
            target,
        })
    }

    /// The scheme of the connection: `https` over TLS, `http` otherwise.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        if self.tls { "https" } else { "http" }
    }

    /// The port the request names, or its scheme's default.
    #[must_use]
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(if self.tls { 443 } else { 80 })
    }

    /// `scheme://host[:port]/path?query`, the string `redirect_regex` matches.
    #[must_use]
    pub fn url(&self) -> String {
        let mut url = format!("{}://{}", self.scheme(), self.host);
        if let Some(port) = self.port {
            url.push(':');
            url.push_str(&port.to_string());
        }
        url.push_str(&self.target);
        url
    }

    /// `scheme://host[:port]/path?query` for another scheme and port: the port the request
    /// named is dropped, the way Traefik's `redirectScheme` does.
    #[must_use]
    pub fn with(&self, scheme: &str, port: Option<u16>) -> String {
        let mut url = format!("{scheme}://{}", self.host);
        if let Some(port) = port {
            url.push(':');
            url.push_str(&port.to_string());
        }
        url.push_str(&self.target);
        url
    }
}

/// Whether `raw` holds a control byte, a DEL, or a percent escape of one.
#[must_use]
pub fn has_control(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.iter().enumerate().any(|(index, &byte)| {
        if byte < 0x20 || byte == 0x7f {
            return true;
        }
        if byte != b'%' {
            return false;
        }
        let hex = |at: usize| {
            bytes
                .get(at)
                .and_then(|digit| char::from(*digit).to_digit(16))
        };
        match (hex(index + 1), hex(index + 2)) {
            (Some(high), Some(low)) => {
                let decoded = high << 4 | low;
                decoded < 0x20 || decoded == 0x7f
            }
            _ => false,
        }
    })
}

/// Turns a computed target into the value of a `Location` header.
///
/// # Errors
///
/// [`Refused`] for a target that must not be sent, see the module documentation.
pub fn finish(target: &str) -> Result<String, Refused> {
    if target.is_empty() {
        return Err(Refused::Empty);
    }
    if target.len() > MAX_LOCATION {
        return Err(Refused::TooLong);
    }
    if has_control(target) {
        return Err(Refused::Control);
    }
    let encoded = encode(target);
    let end = encoded.find(['/', '?', '#']).unwrap_or(encoded.len());
    let (head, rest) = encoded.split_at(end);
    if let Some((scheme, _)) = head.split_once(':') {
        if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
            return Err(Refused::Scheme);
        }
        let authority_start = rest.strip_prefix("//").ok_or(Refused::Scheme)?;
        authority_of(authority_start)?;
    } else if let Some(authority_start) = encoded.strip_prefix("//") {
        authority_of(authority_start)?;
    }
    if encoded.len() > MAX_LOCATION {
        return Err(Refused::TooLong);
    }
    Ok(encoded)
}

fn authority_of(after_slashes: &str) -> Result<(), Refused> {
    let end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    if after_slashes[..end].contains('@') {
        return Err(Refused::Userinfo);
    }
    Ok(())
}

/// Percent-encodes what is not valid in a URL and what a browser could read as something else
/// (a backslash is a slash to a browser). Existing escapes are kept.
fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte > 0x20
            && byte < 0x7f
            && !matches!(
                byte,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// What a redirect kind decided for a request.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// The request is not for this redirect: run the rest of the chain.
    Pass,
    /// Answer with this target.
    Redirect(String),
    /// Answer `400`: the target cannot be sent.
    Refuse(Refused),
}

impl Decision {
    /// Computes a [`Decision`] from a built target.
    #[must_use]
    pub fn target(target: &str) -> Self {
        match finish(target) {
            Ok(location) => Self::Redirect(location),
            Err(refused) => Self::Refuse(refused),
        }
    }
}

/// Writes the response a [`Decision`] asks for. No upstream is involved: the request ends here.
///
/// # Errors
///
/// Fails when the response cannot be written.
pub async fn answer(
    session: &mut Session,
    permanent: bool,
    decision: Decision,
) -> pingora::Result<Flow> {
    match decision {
        Decision::Pass => Ok(Flow::Continue),
        Decision::Refuse(refused) => {
            let err = AppError::BadRequest(refused.to_string().into());
            respond::write_error(session, &err).await?;
            Ok(Flow::Respond)
        }
        Decision::Redirect(location) => {
            let mut header = ResponseHeader::build(status(permanent), Some(2))?;
            header.insert_header("location", location)?;
            header.insert_header("content-length", "0")?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            Ok(Flow::Respond)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn request(host: Option<&str>, target: &str) -> RequestHeader {
        let mut request = RequestHeader::build("GET", target.as_bytes(), None).expect("request");
        if let Some(host) = host {
            request.insert_header("Host", host).expect("host");
        }
        request
    }

    #[test]
    fn the_origin_is_the_connection_scheme_with_a_normalized_host() {
        let origin =
            Origin::from_request(&request(Some("Ex.Test.:8080"), "/a?b=1"), false).expect("origin");
        assert_eq!(origin.url(), "http://ex.test:8080/a?b=1");
        assert_eq!(origin.effective_port(), 8080);
        let secure = Origin::from_request(&request(Some("ex.test"), "/"), true).expect("origin");
        assert_eq!(
            (secure.url().as_str(), secure.effective_port()),
            ("https://ex.test/", 443)
        );
        assert_eq!(secure.with("http", Some(81)), "http://ex.test:81/");
    }

    #[test]
    fn a_host_that_is_not_a_host_is_refused() {
        for host in [
            None,
            Some("a b"),
            Some("a.test/x"),
            Some("a.test@evil.test"),
        ] {
            assert_eq!(
                Origin::from_request(&request(host, "/"), false),
                Err(Refused::Host),
                "{host:?}"
            );
        }
    }

    #[test]
    fn the_status_pair_is_traefiks() {
        assert_eq!(status(true), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(status(false), StatusCode::FOUND);
    }

    #[test]
    fn control_bytes_and_their_escapes_are_refused() {
        for target in [
            "/a\r\nSet-Cookie: x",
            "/a%0d%0aSet-Cookie:x",
            "/a%0A",
            "/a\u{7f}",
            "/a%7F",
            "https://x/\t",
            "/a%00",
        ] {
            assert_eq!(finish(target), Err(Refused::Control), "{target:?}");
        }
        assert_eq!(finish("/a%2Fb%20c%zz"), Ok("/a%2Fb%20c%zz".to_owned()));
    }

    #[test]
    fn only_web_targets_without_userinfo_are_sent() {
        assert_eq!(finish("javascript:alert(1)"), Err(Refused::Scheme));
        assert_eq!(finish("data:text/html,x"), Err(Refused::Scheme));
        assert_eq!(finish("https:evil.test"), Err(Refused::Scheme));
        assert_eq!(
            finish("https://good.test@evil.test/"),
            Err(Refused::Userinfo)
        );
        assert_eq!(finish("//good.test@evil.test/"), Err(Refused::Userinfo));
        assert_eq!(finish(""), Err(Refused::Empty));
        assert_eq!(finish(&"a".repeat(MAX_LOCATION + 1)), Err(Refused::TooLong));
        assert_eq!(
            finish("https://a.test/x?y=z@w"),
            Ok("https://a.test/x?y=z@w".to_owned())
        );
        assert_eq!(finish("/p:q"), Ok("/p:q".to_owned()));
        assert_eq!(finish("//a.test/x"), Ok("//a.test/x".to_owned()));
    }

    #[test]
    fn bytes_a_browser_could_misread_are_encoded() {
        assert_eq!(
            finish("https://a.test/\\evil|x y\u{e9}\"").as_deref(),
            Ok("https://a.test/%5Cevil%7Cx%20y%C3%A9%22")
        );
    }
}
