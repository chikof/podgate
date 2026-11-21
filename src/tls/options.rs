//! Per-app TLS options: `min_version`, `cipher_suites`, `alpn` and `sni_strict`.
//!
//! Pingora builds one rustls `ServerConfig` for a whole listener and has no hook to choose
//! another per connection, so protocol versions, suites and ALPN cannot be set per app at
//! handshake time. The listener's config is the operator's baseline (`TLS_MIN_VERSION`, the
//! provider's suites, `h2` and `http/1.1`), and an app's options narrow it in two places:
//!
//! 1. **ClientHello** ([`super::PreHandshake`]). A hello that offers no version, suite or ALPN
//!    protocol the app of its SNI allows is answered with a fatal alert and closed, so a client
//!    that can never satisfy the policy fails the handshake. The hook only closes what it can
//!    prove: the app that may serve the name must all refuse it ([`Options::hello_violation`]).
//! 2. **Request** ([`enforce`]). The version, suite and protocol the connection really
//!    negotiated, read from its TLS digest and the request's HTTP version, are compared with
//!    the policy of the app the request matched. A violating request gets `421` before
//!    anything else answers. This is the check that enforces the policy; the first layer is an
//!    early exit.
//!
//! Options that rustls cannot honour per app (`max_version`, `curves`, `session_tickets`, a
//! suite or ALPN protocol the provider lacks, an app `min_version` below the process floor) are
//! refused at compile time with `unsupported_setting`: nothing is silently ignored.
//!
//! Plain HTTP connections have no TLS to judge and pass; the entry point's redirect decides what
//! happens to them.

use std::sync::Arc;

use pingora::proxy::Session;
use rustls::CipherSuite;
use rustls::crypto::ring::ALL_CIPHER_SUITES;

use super::hello::Hello;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::plan::kind;
use crate::router::Matched;
use crate::table::RoutingTable;
use podgate_model::{App, TlsVersion};

const H2: &[u8] = b"h2";
const HTTP1: &[u8] = b"http/1.1";

/// Which part of a TLS policy a connection breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// The protocol version is below the policy's.
    Version,
    /// The cipher suite is not one the policy allows.
    Suite,
    /// The application protocol is not one the policy allows.
    Alpn,
}

impl Violation {
    /// The TLS alert record that tells a client why its hello was refused: fatal
    /// `protocol_version`, `handshake_failure` or `no_application_protocol`.
    pub(crate) fn alert(self) -> [u8; 7] {
        let description = match self {
            Self::Version => 70,
            Self::Suite => 40,
            Self::Alpn => 120,
        };
        [21, 3, 3, 0, 2, 2, description]
    }
}

/// The compiled TLS options of one app, with the process floor folded in.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    min_version: TlsVersion,
    suites: Option<Box<[CipherSuite]>>,
    h2: bool,
    http1: bool,
    sni_strict: bool,
}

fn unsupported(setting: &str, reason: impl std::fmt::Display) -> Invalid {
    Invalid::new("unsupported_setting", format!("tls.{setting} {reason}"))
}

fn invalid(setting: &str, reason: &str) -> Invalid {
    Invalid::new("invalid_tls_option", format!("tls.{setting} {reason}"))
}

fn show(version: TlsVersion) -> &'static str {
    match version {
        TlsVersion::V1_2 => "1.2",
        TlsVersion::V1_3 => "1.3",
    }
}

fn is_tls13(suite: CipherSuite) -> bool {
    ALL_CIPHER_SUITES
        .iter()
        .any(|known| known.suite() == suite && known.tls13().is_some())
}

fn supported_suites() -> String {
    ALL_CIPHER_SUITES
        .iter()
        .filter_map(|suite| suite.suite().as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

impl Options {
    /// Compiles the TLS options of `app` for a process whose lowest version is `floor`.
    /// `None` when the app asks for nothing beyond the listener's baseline.
    ///
    /// # Errors
    ///
    /// Every [`Invalid`] of the app: `unsupported_setting` for what rustls or the listener
    /// cannot honour per app, `invalid_tls_option` for a combination nothing could satisfy.
    pub fn compile(app: &App, floor: TlsVersion) -> Result<Option<Arc<Self>>, Vec<Invalid>> {
        let tls = &app.tls;
        let mut problems = Vec::new();
        if tls.pass_client_cert == Some(true) {
            problems.push(unsupported(
                "pass_client_cert",
                "was replaced by the `pass_tls_client_cert` middleware: declare one with `info.subject` (it writes `X-Forwarded-Tls-Client-Cert-Info`; the old `x-forwarded-tls-client-cert-subject` header is no longer sent)",
            ));
        }
        if tls.max_version.is_some() {
            problems.push(unsupported(
                "max_version",
                "cannot be enforced per app: the listener negotiates up to TLS 1.3 for every host, and a cap only helps downgrades",
            ));
        }
        if tls.curves.is_some() {
            problems.push(unsupported(
                "curves",
                "cannot be enforced per app: key exchange groups belong to the listener's rustls provider",
            ));
        }
        if tls.session_tickets.is_some() {
            problems.push(unsupported(
                "session_tickets",
                "cannot be enforced per app: tickets are listener wide and stay on",
            ));
        }
        if tls.http3 == Some(true)
            && let Some(reason) = crate::h3::alt_svc::conflict(tls)
        {
            problems.push(unsupported("http3", format!("cannot be true: {reason}")));
        }
        let min_version = tls.min_version.unwrap_or(floor);
        if min_version < floor {
            problems.push(unsupported(
                "min_version",
                format!(
                    "is below the process floor {} (TLS_MIN_VERSION): an app can only raise it",
                    show(floor)
                ),
            ));
        }
        let suites = tls
            .cipher_suites
            .as_deref()
            .map(|names| Self::suites(names, min_version, &mut problems));
        let (h2, http1) = tls
            .alpn
            .as_deref()
            .map_or((true, true), |names| Self::alpn(names, &mut problems));
        if !problems.is_empty() {
            return Err(problems);
        }
        let options = Self {
            min_version,
            suites: suites.flatten(),
            h2,
            http1,
            sni_strict: tls.sni_strict,
        };
        Ok((!options.is_baseline()).then(|| Arc::new(options)))
    }

    fn suites(
        names: &[String],
        min_version: TlsVersion,
        problems: &mut Vec<Invalid>,
    ) -> Option<Box<[CipherSuite]>> {
        if names.is_empty() {
            problems.push(invalid(
                "cipher_suites",
                "is empty: no connection could be served",
            ));
            return None;
        }
        let mut chosen = Vec::with_capacity(names.len());
        for name in names {
            match ALL_CIPHER_SUITES
                .iter()
                .find(|known| known.suite().as_str() == Some(name))
            {
                Some(known) => chosen.push(known.suite()),
                None => problems.push(unsupported(
                    "cipher_suites",
                    format!(
                        "{name:?} is not a suite of the rustls provider; supported: {}",
                        supported_suites()
                    ),
                )),
            }
        }
        if chosen.len() != names.len() {
            return None;
        }
        if min_version == TlsVersion::V1_3 && !chosen.iter().copied().any(is_tls13) {
            problems.push(invalid(
                "cipher_suites",
                "names no TLS 1.3 suite, so no connection could satisfy min_version 1.3",
            ));
            return None;
        }
        Some(chosen.into_boxed_slice())
    }

    /// `(h2, http/1.1)` of the protocols `names`.
    fn alpn(names: &[String], problems: &mut Vec<Invalid>) -> (bool, bool) {
        if names.is_empty() {
            problems.push(invalid("alpn", "is empty: no connection could be served"));
        }
        let (mut h2, mut http1) = (false, false);
        for name in names {
            match name.as_bytes() {
                H2 => h2 = true,
                HTTP1 => http1 = true,
                _ => problems.push(unsupported(
                    "alpn",
                    format!("{name:?} is not served: the listener offers `h2` and `http/1.1`"),
                )),
            }
        }
        (h2, http1)
    }

    /// Whether these options ask for nothing beyond the listener's baseline.
    fn is_baseline(&self) -> bool {
        self.min_version == TlsVersion::V1_2
            && self.suites.is_none()
            && self.h2
            && self.http1
            && !self.sni_strict
    }

    /// Whether a ClientHello can tell a connection that breaks these options: the pre-TLS hook
    /// only reads hellos when some app returns `true`.
    #[must_use]
    pub fn needs_hello(&self) -> bool {
        self.min_version == TlsVersion::V1_3 || self.suites.is_some() || !(self.h2 && self.http1)
    }

    /// Whether a handshake for a name of this app that no certificate covers is refused instead
    /// of served the default certificate.
    #[must_use]
    pub fn sni_strict(&self) -> bool {
        self.sni_strict
    }

    /// The posture kinds (see [`crate::plan::kind`]) by which a host served with `candidate`
    /// is less strict than one served with `live`; `None` is the listener's baseline. Wider ALPN
    /// is not listed: it changes the protocol, not who may connect.
    pub(crate) fn relaxations(live: Option<&Self>, candidate: Option<&Self>) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        let min = |options: Option<&Self>| options.map_or(TlsVersion::V1_2, |o| o.min_version);
        if min(candidate) < min(live) {
            kinds.push(kind::TLS_MIN_VERSION_LOWERED);
        }
        let widened = match (live.and_then(|o| o.suites.as_deref()), candidate) {
            (Some(old), Some(new)) => new
                .suites
                .as_deref()
                .is_none_or(|new| new.iter().any(|suite| !old.contains(suite))),
            (Some(_), None) => true,
            (None, _) => false,
        };
        if widened {
            kinds.push(kind::TLS_CIPHER_SUITES_WIDENED);
        }
        let strict = |options: Option<&Self>| options.is_some_and(|o| o.sni_strict);
        if strict(live) && !strict(candidate) {
            kinds.push(kind::SNI_STRICT_DISABLED);
        }
        kinds
    }

    fn allows_alpn(&self, protocol: &[u8]) -> bool {
        (protocol == H2 && self.h2) || (protocol == HTTP1 && self.http1)
    }

    /// What in `hello` no connection could satisfy, if anything. Never wrong in the refusing
    /// direction: a hello that passes may still negotiate something [`Self::connection_violation`]
    /// refuses.
    pub(crate) fn hello_violation(&self, hello: &Hello) -> Option<Violation> {
        self.transport_hello_violation(hello).or_else(|| {
            let offers_alpn = !hello.alpn.is_empty();
            (offers_alpn && !hello.alpn.iter().any(|protocol| self.allows_alpn(protocol)))
                .then_some(Violation::Alpn)
        })
    }

    /// The version and suite part of [`Self::hello_violation`]. A TCP router carries
    /// any protocol, so the `h2` and `http/1.1` allowance of `alpn` says nothing about it.
    pub(crate) fn transport_hello_violation(&self, hello: &Hello) -> Option<Violation> {
        let at_least_13 = self.min_version == TlsVersion::V1_3;
        let offers_tls13 =
            hello.offers_tls13 != Some(false) && hello.suites.iter().copied().any(is_tls13);
        if at_least_13 && !offers_tls13 {
            return Some(Violation::Version);
        }
        if let Some(allowed) = &self.suites {
            let usable = hello
                .suites
                .iter()
                .any(|suite| allowed.contains(suite) && (!at_least_13 || is_tls13(*suite)));
            if !usable {
                return Some(Violation::Suite);
            }
        }
        None
    }

    pub(crate) fn connection_violation(
        &self,
        version: &str,
        cipher: &str,
        h2: bool,
    ) -> Option<Violation> {
        self.transport_violation(version, cipher).or_else(|| {
            let served = if h2 { self.h2 } else { self.http1 };
            (!served).then_some(Violation::Alpn)
        })
    }

    /// The version and suite part of [`Self::connection_violation`], for a TCP router.
    pub(crate) fn transport_violation(&self, version: &str, cipher: &str) -> Option<Violation> {
        let version = match version {
            "TLSv1_3" => TlsVersion::V1_3,
            "TLSv1_2" => TlsVersion::V1_2,
            _ => return Some(Violation::Version),
        };
        if version < self.min_version {
            return Some(Violation::Version);
        }
        if let Some(allowed) = &self.suites
            && !allowed.iter().any(|suite| suite.as_str() == Some(cipher))
        {
            return Some(Violation::Suite);
        }
        None
    }
}

/// Checks the TLS connection of a request against the options of the app of the router it
/// matched. Runs right after the SNI check, before the client certificate check and anything
/// else that answers.
///
/// A request no router matched, an app without options and a plain HTTP connection pass.
///
/// # Errors
///
/// [`AppError::TlsPolicy`] when the connection negotiated a version, suite or protocol the
/// matched app does not allow.
pub fn enforce(
    session: &Session,
    table: &RoutingTable,
    matched: Option<Matched>,
) -> Result<(), AppError> {
    let Some(options) = matched
        .and_then(|matched| table.app(matched.app))
        .and_then(|app| app.tls_options())
    else {
        return Ok(());
    };
    let Some(tls) = session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
    else {
        return Ok(());
    };
    match options.connection_violation(&tls.version, &tls.cipher, session.is_http2()) {
        None => Ok(()),
        Some(_) => Err(AppError::TlsPolicy),
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;

    fn app(tls: &Value) -> App {
        let mut base = json!({
            "id": "a", "tenant": "t", "declared_by": "test", "routers": [], "revisions": [],
            "tls": {"mode": "acme"},
        });
        base["tls"]
            .as_object_mut()
            .expect("tls object")
            .extend(tls.as_object().expect("options object").clone());
        serde_json::from_value(base).expect("valid app")
    }

    fn compile(tls: &Value) -> Result<Option<Arc<Options>>, Vec<Invalid>> {
        Options::compile(&app(tls), TlsVersion::V1_2)
    }

    fn codes(tls: &Value) -> Vec<&'static str> {
        compile(tls)
            .expect_err("rejected")
            .iter()
            .map(|invalid| invalid.code)
            .collect()
    }

    #[test]
    fn tls_unsupported_cipher_rejected() {
        let problems = compile(&json!({"cipher_suites": ["TLS_RSA_WITH_RC4_128_SHA"]}))
            .expect_err("RC4 is not offered");
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].code, "unsupported_setting");
        assert!(
            problems[0].message.contains("TLS13_AES_256_GCM_SHA384"),
            "lists the supported suites: {}",
            problems[0].message
        );
        let known = compile(&json!({"cipher_suites": ["TLS13_AES_256_GCM_SHA384"]}));
        assert!(known.expect("supported suite").is_some());
    }

    #[test]
    fn tls_unenforceable_options_reject() {
        for setting in [
            json!({"max_version": "1.3"}),
            json!({"curves": ["X25519"]}),
            json!({"session_tickets": false}),
        ] {
            assert_eq!(codes(&setting), ["unsupported_setting"], "{setting}");
        }
        assert_eq!(codes(&json!({"alpn": ["h3"]})), ["unsupported_setting"]);
    }

    #[test]
    fn a_floor_can_only_be_raised() {
        let low = app(&json!({"min_version": "1.2"}));
        let problems = Options::compile(&low, TlsVersion::V1_3).expect_err("below the floor");
        assert_eq!(problems[0].code, "unsupported_setting");
        let plain = Options::compile(&app(&json!({})), TlsVersion::V1_3)
            .expect("compiles")
            .expect("the floor is a policy");
        assert!(plain.needs_hello());
    }

    #[test]
    fn nothing_asked_means_no_options() {
        assert!(compile(&json!({})).expect("compiles").is_none());
        assert!(
            compile(&json!({"min_version": "1.2", "alpn": ["http/1.1", "h2"]}))
                .expect("compiles")
                .is_none()
        );
    }

    #[test]
    fn unsatisfiable_combinations_are_invalid() {
        assert_eq!(codes(&json!({"cipher_suites": []})), ["invalid_tls_option"]);
        assert_eq!(codes(&json!({"alpn": []})), ["invalid_tls_option"]);
        assert_eq!(
            codes(&json!({
                "min_version": "1.3",
                "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            })),
            ["invalid_tls_option"]
        );
    }

    #[test]
    fn tls_min_version_13_refuses_tls12_connection() {
        let options = compile(&json!({"min_version": "1.3"}))
            .expect("compiles")
            .expect("has options");
        assert_eq!(
            options.connection_violation("TLSv1_2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false),
            Some(Violation::Version)
        );
        assert_eq!(
            options.connection_violation("TLSv1_3", "TLS13_AES_128_GCM_SHA256", true),
            None
        );
        let tls12_only = Hello {
            suites: vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            ..Hello::default()
        };
        assert_eq!(
            options.hello_violation(&tls12_only),
            Some(Violation::Version)
        );
        let declared_tls12 = Hello {
            offers_tls13: Some(false),
            suites: vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            ..Hello::default()
        };
        assert_eq!(
            options.hello_violation(&declared_tls12),
            Some(Violation::Version)
        );
        let both = Hello {
            suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS13_AES_128_GCM_SHA256,
            ],
            ..Hello::default()
        };
        assert_eq!(options.hello_violation(&both), None);
    }

    #[test]
    fn tls_cipher_suites_restrict_connection() {
        let options = compile(&json!({"cipher_suites": ["TLS13_AES_256_GCM_SHA384"]}))
            .expect("compiles")
            .expect("has options");
        assert_eq!(
            options.connection_violation("TLSv1_3", "TLS13_AES_128_GCM_SHA256", false),
            Some(Violation::Suite)
        );
        assert_eq!(
            options.connection_violation("TLSv1_3", "TLS13_AES_256_GCM_SHA384", false),
            None
        );
    }

    #[test]
    fn tls_alpn_h1_only_refuses_h2() {
        let options = compile(&json!({"alpn": ["http/1.1"]}))
            .expect("compiles")
            .expect("has options");
        assert_eq!(
            options.connection_violation("TLSv1_3", "TLS13_AES_128_GCM_SHA256", true),
            Some(Violation::Alpn)
        );
        assert_eq!(
            options.connection_violation("TLSv1_3", "TLS13_AES_128_GCM_SHA256", false),
            None
        );
        let only_h2 = Hello {
            alpn: vec![b"h2".to_vec()],
            ..Hello::default()
        };
        assert_eq!(options.hello_violation(&only_h2), Some(Violation::Alpn));
        assert_eq!(options.hello_violation(&Hello::default()), None);
    }

    #[test]
    fn an_unknown_protocol_version_is_refused() {
        let options = compile(&json!({"alpn": ["h2"]}))
            .expect("compiles")
            .expect("has options");
        assert_eq!(
            options.connection_violation("SSLv3", "", true),
            Some(Violation::Version)
        );
    }
}
