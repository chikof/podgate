//! The responder URL a certificate names, which is attacker-chosen text when the certificate was
//! supplied by a tenant: it is parsed strictly here, checked against `OCSP_ALLOWED_HOSTS`, and
//! only ever reached through the upstream address policy (see [`super::job`]).

use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::Uri;

use super::reason::Reason;

/// A parsed `http` or `https` responder URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Responder {
    tls: bool,
    host: Box<str>,
    address: Option<IpAddr>,
    port: u16,
    /// The URL's path without a trailing slash; the request is appended to it.
    base: Box<str>,
}

impl Responder {
    /// Parses `url`.
    ///
    /// # Errors
    ///
    /// [`Reason::Scheme`] for anything but a plain `http://` or `https://` URL with a host: no
    /// user information, no query.
    pub fn parse(url: &str) -> Result<Self, Reason> {
        let uri: Uri = url.parse().map_err(|_| Reason::Scheme)?;
        let tls = match uri.scheme_str() {
            Some("http") => false,
            Some("https") => true,
            _ => return Err(Reason::Scheme),
        };
        let authority = uri.authority().ok_or(Reason::Scheme)?;
        if authority.as_str().contains('@') || uri.query().is_some() {
            return Err(Reason::Scheme);
        }
        let host = authority.host();
        let bare = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(host);
        let address = bare.parse::<IpAddr>().ok();
        let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
        Ok(Self {
            tls,
            host: bare.to_ascii_lowercase().into(),
            address,
            port,
            base: uri.path().trim_end_matches('/').into(),
        })
    }

    /// The host name or address text, without brackets, lowercase.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The IP address when the URL names one literally; `None` for a host name.
    #[must_use]
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    /// The port, defaulted by the scheme.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the exchange is TLS.
    #[must_use]
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// The `Host` header value: the host, bracketed for IPv6, with the port when it is not the
    /// scheme's default.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = match self.address {
            Some(IpAddr::V6(_)) => format!("[{}]", self.host),
            _ => self.host.to_string(),
        };
        if self.port == if self.tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The request target of the `GET` form of RFC 6960 appendix A.1: the URL's path, a slash
    /// and the percent-encoded base64 of the DER request.
    #[must_use]
    pub fn target(&self, request: &[u8]) -> String {
        let mut target = self.base.to_string();
        target.push('/');
        for byte in STANDARD.encode(request).bytes() {
            match byte {
                b'+' => target.push_str("%2B"),
                b'/' => target.push_str("%2F"),
                b'=' => target.push_str("%3D"),
                other => target.push(char::from(other)),
            }
        }
        target
    }
}

/// `OCSP_ALLOWED_HOSTS`: the responder host must be one of these names or under one. Empty means
/// any host the address policy allows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedHosts(Box<[Box<str>]>);

impl AllowedHosts {
    /// A list from suffixes such as `ocsp.example.com` or `.example.com`.
    #[must_use]
    pub fn new<'a>(suffixes: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            suffixes
                .into_iter()
                .map(|suffix| suffix.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|suffix| !suffix.is_empty())
                .map(Into::into)
                .collect(),
        )
    }

    /// Whether `host` (lowercase) is allowed: equal to an entry or a subdomain of one.
    #[must_use]
    pub fn permits(&self, host: &str) -> bool {
        self.0.is_empty()
            || self.0.iter().any(|suffix| {
                host == &**suffix
                    || host
                        .strip_suffix(&**suffix)
                        .is_some_and(|front| front.ends_with('.'))
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_literal_and_named_responders() {
        let ip = Responder::parse("http://192.0.2.7:8080/ocsp/").expect("ip");
        assert_eq!(ip.address(), Some("192.0.2.7".parse().expect("ip")));
        assert_eq!(ip.port(), 8080);
        assert_eq!(ip.authority(), "192.0.2.7:8080");
        assert_eq!(ip.target(&[0xfb, 0xff]), "/ocsp/%2B%2F8%3D");
        let v6 = Responder::parse("http://[2001:db8::1]/").expect("v6");
        assert_eq!(v6.authority(), "[2001:db8::1]");
        let named = Responder::parse("https://OCSP.Example.com").expect("name");
        assert_eq!(
            (named.host(), named.address(), named.port()),
            ("ocsp.example.com", None, 443)
        );
        assert!(named.tls());
    }

    #[test]
    fn refuses_other_shapes() {
        for bad in [
            "ldap://example.com/",
            "ftp://example.com/",
            "http://user@example.com/",
            "http://example.com/?x=1",
            "/relative",
            "http://",
            "http://exa mple.com/",
        ] {
            assert_eq!(Responder::parse(bad), Err(Reason::Scheme), "{bad}");
        }
    }

    #[test]
    fn allowed_hosts_match_whole_labels() {
        let list = AllowedHosts::new(["ocsp.example.com", " .Digicert.com "]);
        assert!(list.permits("ocsp.example.com"));
        assert!(list.permits("a.digicert.com"));
        assert!(!list.permits("evilocsp.example.com"));
        assert!(!list.permits("example.com"));
        assert!(AllowedHosts::default().permits("anything"));
    }
}
