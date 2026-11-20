//! The `redirect_scheme` middleware: answers a request on another scheme (typically `http`) with
//! a redirect to the same host, path and query on the target scheme (typically `https`).
//!
//! ```json
//! { "name": "to-https", "type": "redirect_scheme", "scheme": "https", "port": 8443, "permanent": true }
//! ```
//!
//! - The scheme a request has is the client's: the connection's own, or `X-Forwarded-Proto` from a peer the entry point trusts (`forwarded_headers.trusted_ips`), so a request that a TLS-terminating load balancer forwards as `https` is passed on. Every other peer's `X-Forwarded-*` was removed before routing.
//! - A request that already has the target scheme (and, when `port` is set, the target port) is
//!   passed on, so the redirect cannot loop. Without `port` the scheme alone decides: behind a
//!   port mapping (`Host: a.test:8443` on TLS) a redirect to the default port would break the
//!   client, where Traefik sends it there.
//! - The port the request named is dropped from the target; `port` adds one, except the
//!   scheme's default (`443` for `https`, `80` for `http`), which is left out of the URL.
//! - `permanent` answers `301`, otherwise `302` ([`super::redirect::status`]).

use serde::Deserialize;
use serde_json::{Value, json};

use super::redirect::{Decision, Origin, answer};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use podgate_model::Declared;

/// The configuration of a `redirect_scheme` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The scheme to redirect to: `http` or `https`.
    pub scheme: String,
    /// The port to redirect to; a port that is the scheme's default is not written in the URL.
    #[serde(default)]
    pub port: Option<u16>,
    /// `301` instead of `302`.
    #[serde(default)]
    pub permanent: bool,
}

/// A compiled `redirect_scheme` middleware.
#[derive(Debug)]
pub struct RedirectScheme {
    https: bool,
    port: Option<u16>,
    permanent: bool,
}

impl RedirectScheme {
    fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    fn default_port(&self) -> u16 {
        if self.https { 443 } else { 80 }
    }

    /// What to do with a request that arrived as `origin`.
    fn decide(&self, origin: &Origin) -> Decision {
        let same_scheme = origin.scheme() == self.scheme();
        let same_port = self.port.is_none_or(|port| port == origin.effective_port());
        if same_scheme && same_port {
            return Decision::Pass;
        }
        let shown = self.port.filter(|port| *port != self.default_port());
        Decision::target(&origin.with(self.scheme(), shown))
    }
}

impl Kind for RedirectScheme {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_middleware", format!("redirect_scheme: {err}")))?;
        let https = match config.scheme.as_str() {
            "https" => true,
            "http" => false,
            other => {
                return Err(Invalid::new(
                    "invalid_middleware",
                    format!("redirect_scheme: scheme is http or https, not {other:?}"),
                ));
            }
        };
        if config.port == Some(0) {
            return Err(Invalid::new(
                "invalid_middleware",
                "redirect_scheme: port 0 is not a port",
            ));
        }
        Ok(Self {
            https,
            port: config.port,
            permanent: config.permanent,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let decision = match Origin::of(cx.session, cx.forwarded) {
            Ok(origin) => self.decide(&origin),
            Err(refused) => Decision::Refuse(refused),
        };
        answer(cx.session, self.permanent, decision).await
    }

    /// An `https` redirect is how a plain HTTP client gets moved off the wire; without it (or
    /// with the target moved to `http`) the app serves cleartext.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            _ if !self.https => Vec::new(),
            Some(new) if new.https => Vec::new(),
            _ => vec!["https_redirect_removed"],
        }
    }

    fn describe(&self) -> Value {
        json!({ "scheme": self.scheme(), "port": self.port, "permanent": self.permanent })
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;
    use crate::client_ip::{ForwardedView, Proto};

    fn kind(scheme: &str, port: Option<u16>) -> RedirectScheme {
        RedirectScheme {
            https: scheme == "https",
            port,
            permanent: false,
        }
    }

    fn origin(host: &str, target: &str, tls: bool) -> Origin {
        let mut request = RequestHeader::build("GET", target.as_bytes(), None).expect("request");
        request.insert_header("Host", host).expect("host");
        let forwarded = ForwardedView {
            proto: if tls { Proto::Https } else { Proto::Http },
            ..ForwardedView::default()
        };
        Origin::from_request(&request, &forwarded).expect("origin")
    }

    fn location(decision: Decision) -> String {
        match decision {
            Decision::Redirect(location) => location,
            other => panic!("not a redirect: {other:?}"),
        }
    }

    #[test]
    fn http_goes_to_https_keeping_host_path_and_query() {
        let to = location(kind("https", None).decide(&origin("A.test:8080", "/x/y?q=1", false)));
        assert_eq!(to, "https://a.test/x/y?q=1");
    }

    #[test]
    fn the_port_is_written_unless_it_is_the_default() {
        let at = |port| location(kind("https", Some(port)).decide(&origin("a.test", "/", false)));
        assert_eq!(at(8443), "https://a.test:8443/");
        assert_eq!(at(443), "https://a.test/");
        let to_http = kind("http", Some(80)).decide(&origin("a.test", "/", true));
        assert_eq!(location(to_http), "http://a.test/");
    }

    #[test]
    fn a_request_with_the_target_scheme_and_port_passes() {
        let pass = |kind: RedirectScheme, host: &str, tls: bool| {
            kind.decide(&origin(host, "/", tls)) == Decision::Pass
        };
        assert!(pass(kind("https", None), "a.test", true));
        assert!(pass(kind("https", None), "a.test:8443", true));
        assert!(pass(kind("https", Some(443)), "a.test", true));
        assert!(pass(kind("https", Some(8443)), "a.test:8443", true));
        assert!(!pass(kind("https", Some(8443)), "a.test", true));
        assert!(!pass(kind("https", None), "a.test", false));
    }

    #[test]
    fn a_target_that_cannot_be_sent_is_refused() {
        let decision = kind("https", None).decide(&origin("a.test", "/a%0D%0Ab", false));
        assert!(matches!(decision, Decision::Refuse(_)), "{decision:?}");
    }

    #[test]
    fn posture_reports_a_lost_https_redirect() {
        let https = kind("https", None);
        assert!(https.posture(Some(&kind("https", Some(8443)))).is_empty());
        assert_eq!(https.posture(None), vec!["https_redirect_removed"]);
        assert_eq!(
            https.posture(Some(&kind("http", None))),
            vec!["https_redirect_removed"]
        );
        assert!(kind("http", None).posture(None).is_empty());
    }
}
