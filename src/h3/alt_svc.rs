//! `Alt-Svc`: how an HTTPS entry point with `;http3` tells clients it also speaks HTTP/3, and
//! which apps may be offered over it.
//!
//! The header is `Alt-Svc: h3=":<port>"; ma=86400`. It goes on responses of the apps that allow
//! HTTP/3 ([`allowed`]) and nowhere else: not on responses over HTTP/3 itself (the gateway of the
//! front's internal connection has none), not on plain HTTP entry points, and not on an HTTPS
//! entry point without the option. The gateway adds it after everything else a response goes
//! through, and the response cache neither stores it nor skips it on a hit
//! ([`crate::middleware::cache`]), so a copy stored through one entry point never advertises
//! another's port.
//!
//! An app allows HTTP/3 when `tls.http3` says so, and by default unless it has something HTTP/3
//! cannot honour ([`conflict`]): client certificates, a cipher suite list, or an `alpn` list
//! without `h2`. `tls.http3: true` next to one of those is `422` `unsupported_setting`, so mutual
//! TLS and suite policies are never silently weakened.

use std::num::NonZeroU16;

use http::HeaderValue;
use pingora::http::ResponseHeader;
use podgate_model::TlsPolicy;

use crate::table::CompiledApp;

/// How long a client may remember the alternative service: a day.
const MAX_AGE_SECS: u32 = 86_400;

/// The `Alt-Svc` value an entry point advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc(HeaderValue);

impl AltSvc {
    /// `h3=":<port>"; ma=86400`.
    ///
    /// # Panics
    ///
    /// Never: the value is digits and punctuation, valid header bytes.
    #[must_use]
    pub fn new(port: NonZeroU16) -> Self {
        Self(
            HeaderValue::from_str(&format!("h3=\":{port}\"; ma={MAX_AGE_SECS}"))
                .expect("digits and punctuation are valid header bytes"),
        )
    }

    /// Sets `Alt-Svc` on `response` when `app` allows HTTP/3, replacing one the upstream sent.
    pub fn apply(&self, response: &mut ResponseHeader, app: &CompiledApp) {
        if allowed(app.tls()) {
            // A valid value and a fixed name cannot fail to insert.
            let _ = response.insert_header("alt-svc", self.0.clone());
        }
    }

    /// The header value.
    #[must_use]
    pub fn value(&self) -> &HeaderValue {
        &self.0
    }
}

/// Why `tls` cannot be served over HTTP/3, when it cannot.
pub(crate) fn conflict(tls: &TlsPolicy) -> Option<&'static str> {
    if tls.client_ca_pem.is_some() || tls.client_auth.is_some() || tls.spiffe_client.is_some() {
        return Some(
            "client certificates are not available over HTTP/3, so the app would be served with mutual TLS silently dropped",
        );
    }
    if tls.cipher_suites.is_some() {
        return Some(
            "HTTP/3 negotiates its own cipher suites, so a cipher_suites list could not be enforced",
        );
    }
    if tls
        .alpn
        .as_ref()
        .is_some_and(|names| !names.iter().any(|name| name == "h2"))
    {
        return Some("HTTP/3 is served as `h2`, which the alpn list does not allow");
    }
    None
}

/// Whether HTTP/3 may serve an app with this TLS policy: what `http3` says, else whatever has no
/// [`conflict`].
pub(crate) fn allowed(tls: &TlsPolicy) -> bool {
    tls.http3.unwrap_or_else(|| conflict(tls).is_none())
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn policy(extra: &serde_json::Value) -> TlsPolicy {
        let mut base = json!({"mode": "acme"});
        if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
            base.extend(extra.clone());
        }
        serde_json::from_value(base).expect("valid policy")
    }

    #[test]
    fn the_header_names_the_port_and_a_day() {
        let value = AltSvc::new(NonZeroU16::new(8443).expect("port"));
        assert_eq!(value.value(), "h3=\":8443\"; ma=86400");
    }

    #[test]
    fn a_plain_app_is_offered_http3() {
        assert!(allowed(&policy(&json!({}))));
        assert!(allowed(&policy(&json!({"alpn": ["h2", "http/1.1"]}))));
    }

    #[test]
    fn what_http3_cannot_honour_is_not_offered() {
        for extra in [
            json!({"client_ca_pem": "pem"}),
            json!({"client_auth": "request"}),
            json!({"cipher_suites": ["TLS13_AES_128_GCM_SHA256"]}),
            json!({"alpn": ["http/1.1"]}),
        ] {
            let tls = policy(&extra);
            assert!(!allowed(&tls), "{extra}");
            assert!(conflict(&tls).is_some(), "{extra}");
        }
    }

    #[test]
    fn false_opts_out_and_true_does_not_override_a_conflict_check() {
        assert!(!allowed(&policy(&json!({"http3": false}))));
        assert!(allowed(&policy(&json!({"http3": true}))));
        assert!(conflict(&policy(&json!({"http3": true, "client_ca_pem": "pem"}))).is_some());
    }
}
