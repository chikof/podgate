//! The ACME view of a compiled snapshot: which hosts need which certificates, when the ones
//! served are due for renewal, and the HTTP-01 answers to serve.
//!
//! Compiled with the routing table, so the issuer, the HTTP-01 responder and the TLS hook all
//! read one immutable answer. Without `Snapshot.acme` the plan is empty and every query says
//! "nothing to do".

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use instant_acme::CertificateIdentifier;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use thiserror::Error;

use crate::host::{HostMap, HostPattern};
use podgate_model::{Acme, Snapshot, TlsMode};

/// A snapshot's ACME settings or certificates that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    /// An `acme` field has an unusable value.
    #[error("acme.{field}: {reason}")]
    Invalid {
        /// The offending field.
        field: &'static str,
        /// What is wrong with it.
        reason: Box<str>,
    },
    /// A certificate's validity cannot be read.
    #[error("certificate for {hosts}: {reason}")]
    Certificate {
        /// The certificate's declared hosts, comma separated.
        hosts: Box<str>,
        /// What is wrong with it.
        reason: Box<str>,
    },
}

fn invalid(field: &'static str, reason: impl Into<Box<str>>) -> PlanError {
    PlanError::Invalid {
        field,
        reason: reason.into(),
    }
}

/// What the issuer needs to know about one certificate of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// The hosts the snapshot declares for it.
    pub hosts: Box<[Box<str>]>,
    /// Start of validity.
    pub not_before: SystemTime,
    /// End of validity.
    pub not_after: SystemTime,
    /// The ACME renewal-information identifier; absent when the certificate has no authority
    /// key identifier, which makes it ineligible for ARI.
    pub id: Option<CertificateIdentifier<'static>>,
}

impl CertInfo {
    fn parse(hosts: &[Box<str>], cert_pem: &str) -> Result<Self, String> {
        let leaf = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .ok_or("cert_pem holds no certificate")?
            .map_err(|err| err.to_string())?;
        let (_, parsed) =
            x509_parser::parse_x509_certificate(&leaf).map_err(|err| err.to_string())?;
        let validity = parsed.validity();
        let at = |seconds: i64| {
            u64::try_from(seconds)
                .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))
                .map_err(|_| format!("validity before 1970: {seconds}"))
        };
        Ok(Self {
            hosts: hosts.into(),
            not_before: at(validity.not_before.timestamp())?,
            not_after: at(validity.not_after.timestamp())?,
            id: CertificateIdentifier::try_from(&leaf)
                .ok()
                .map(CertificateIdentifier::into_owned),
        })
    }

    /// The span the certificate is valid for.
    #[must_use]
    pub fn lifetime(&self) -> Duration {
        self.not_after
            .duration_since(self.not_before)
            .unwrap_or_default()
    }

    /// The renewal time without ARI: two thirds of the lifetime after it starts.
    #[must_use]
    pub fn fallback_renewal(&self) -> SystemTime {
        self.not_before + self.lifetime() * 2 / 3
    }

    /// A renewal time inside the server's suggested window, `unit` (in `0.0..=1.0`) of the way
    /// from its start to its end, and never later than a tenth of the lifetime before expiry:
    /// a window that outlives the certificate must not strand it.
    #[must_use]
    pub fn pick_renewal(&self, start: SystemTime, end: SystemTime, unit: f64) -> SystemTime {
        let span = end.duration_since(start).unwrap_or_default();
        let at = start + span.mul_f64(unit.clamp(0.0, 1.0));
        let latest = self
            .not_after
            .checked_sub(self.lifetime() / 10)
            .unwrap_or(self.not_after);
        at.min(latest)
    }
}

/// An app whose certificates the issuer orders for its exact hosts.
#[derive(Debug)]
struct AcmeApp {
    hosts: Vec<Box<str>>,
}

/// The ACME part of a [`crate::RoutingTable`].
#[derive(Debug, Default)]
pub struct Plan {
    settings: Option<Acme>,
    challenges: HashMap<Box<str>, Box<str>>,
    claimed: HostMap<TlsMode>,
    on_demand: bool,
    acme_apps: Vec<AcmeApp>,
    certs: Vec<CertInfo>,
    cert_by_host: HostMap<usize>,
}

impl Plan {
    /// Compiles the ACME view of `snapshot`. `claims[i]` are the literal host patterns the
    /// routers of `snapshot.apps[i]` claim. `Snapshot.acme` absent gives the empty plan.
    ///
    /// # Errors
    ///
    /// [`PlanError`] for an unusable `acme` field or a certificate whose validity cannot be
    /// read. Hosts are checked by the table compiler before this runs.
    pub fn compile(snapshot: &Snapshot, claims: &[Vec<HostPattern>]) -> Result<Self, PlanError> {
        let Some(acme) = &snapshot.acme else {
            return Ok(Self::default());
        };
        validate(acme)?;
        let mut plan = Self {
            challenges: acme
                .challenges
                .iter()
                .map(|challenge| (challenge.token.clone(), challenge.key_authorization.clone()))
                .collect(),
            settings: Some(acme.clone()),
            ..Self::default()
        };
        for (app, patterns) in snapshot.apps.iter().zip(claims) {
            let mut exact = Vec::new();
            for pattern in patterns {
                if let HostPattern::Exact(name) = pattern {
                    exact.push(name.clone());
                }
                plan.claimed.insert(pattern.clone(), app.tls.mode);
            }
            plan.on_demand |= app.tls.mode == TlsMode::OnDemand;
            if app.tls.mode == TlsMode::Acme && !exact.is_empty() {
                plan.acme_apps.push(AcmeApp { hosts: exact });
            }
        }
        for certificate in &snapshot.certificates {
            let info =
                CertInfo::parse(&certificate.hosts, &certificate.cert_pem).map_err(|reason| {
                    PlanError::Certificate {
                        hosts: certificate.hosts.join(",").into(),
                        reason: reason.into(),
                    }
                })?;
            for raw in &certificate.hosts {
                if let Ok(pattern) = HostPattern::parse(raw) {
                    plan.cert_by_host.insert(pattern, plan.certs.len());
                }
            }
            plan.certs.push(info);
        }
        Ok(plan)
    }

    /// The snapshot's ACME settings, when it has any.
    #[must_use]
    pub fn settings(&self) -> Option<&Acme> {
        self.settings.as_ref()
    }

    /// The key authorization the snapshot pushed for HTTP-01 `token`.
    #[must_use]
    pub fn challenge(&self, token: &str) -> Option<&str> {
        self.challenges.get(token).map(AsRef::as_ref)
    }

    /// Whether any app can get certificates on demand: there are ACME settings and an
    /// `on_demand` app. The TLS hook does nothing otherwise.
    #[must_use]
    pub fn on_demand_enabled(&self) -> bool {
        self.settings.is_some() && self.on_demand
    }

    /// Whether `host` (normalized) is routed to an `on_demand` app, so a handshake for it may
    /// wait for a certificate. A host that routes to an `acme` app or to no app is not.
    #[must_use]
    pub fn is_on_demand(&self, host: &str) -> bool {
        self.settings.is_some() && self.claimed.lookup(host) == Some(&TlsMode::OnDemand)
    }

    /// The certificate of the snapshot that answers for `host` (normalized).
    #[must_use]
    pub fn cert_for(&self, host: &str) -> Option<&CertInfo> {
        self.cert_by_host
            .lookup(host)
            .and_then(|index| self.certs.get(*index))
    }

    /// The certificates of the snapshot.
    #[must_use]
    pub fn certs(&self) -> &[CertInfo] {
        &self.certs
    }

    /// The host sets to order for `acme` apps: per app, its exact hosts that no certificate of
    /// the snapshot answers for. Wildcard hosts are skipped; HTTP-01 cannot prove them.
    #[must_use]
    pub fn missing(&self) -> Vec<Vec<Box<str>>> {
        self.acme_apps
            .iter()
            .map(|app| {
                app.hosts
                    .iter()
                    .filter(|host| self.cert_for(host).is_none())
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|hosts| !hosts.is_empty())
            .collect()
    }

    /// Whether the issuer may renew `cert`: every host is exact (HTTP-01 cannot prove a
    /// wildcard) and still claimed by an app, so a certificate of a removed app lapses.
    #[must_use]
    pub fn renewable(&self, cert: &CertInfo) -> bool {
        cert.hosts.iter().all(|host| {
            matches!(HostPattern::parse(host), Ok(HostPattern::Exact(_)))
                && self.claimed.lookup(host).is_some()
        })
    }
}

/// Decodes an external-account HMAC key. CAs hand it out as base64url; plain base64 and
/// trailing padding are accepted too.
pub(super) fn decode_hmac_key(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let normalized: String = encoded
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(normalized)
}

fn validate(acme: &Acme) -> Result<(), PlanError> {
    if acme.issuer_node.is_empty() {
        return Err(invalid("issuer_node", "is empty"));
    }
    if !acme.directory_url.starts_with("https://") {
        return Err(invalid("directory_url", "is not an https:// URL"));
    }
    if acme.eab.is_some() && acme.account_key_pem.is_some() {
        return Err(invalid(
            "eab",
            "cannot be combined with account_key_pem: a CA binds an external account only when it creates the account",
        ));
    }
    if let Some(eab) = &acme.eab {
        if eab.key_id.is_empty() {
            return Err(invalid("eab.key_id", "is empty"));
        }
        if decode_hmac_key(&eab.hmac_key).is_err() {
            return Err(invalid("eab.hmac_key", "is not base64url"));
        }
    }
    for challenge in &acme.challenges {
        let token_ok = !challenge.token.is_empty()
            && challenge
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !token_ok {
            return Err(invalid(
                "challenges",
                format!("token {:?} is not base64url", challenge.token),
            ));
        }
        if challenge.key_authorization.is_empty() {
            return Err(invalid(
                "challenges",
                format!("token {} has an empty key_authorization", challenge.token),
            ));
        }
    }
    for raw in &acme.requested_hosts {
        if !matches!(HostPattern::parse(raw), Ok(HostPattern::Exact(_))) {
            return Err(invalid(
                "requested_hosts",
                format!("{raw:?} is not an exact host name"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use podgate_model::Snapshot;

    fn snapshot(acme: &str, apps: &str, certificates: &str) -> Snapshot {
        serde_json::from_str(&format!(
            r#"{{"version": 1,
            "tenants": [{{"id": "t", "weight": 1, "budget": {{"max_inflight": 1, "max_buffer_bytes": 1}}}}],
            "apps": [{apps}], "certificates": [{certificates}], "acme": {acme}}}"#
        ))
        .expect("valid snapshot json")
    }

    fn app(id: &str, mode: &str, hosts: &str) -> String {
        format!(
            r#"{{"id": "{id}", "tenant": "t", "declared_by": "test",
            "tls": {{"mode": "{mode}"}},
            "routers": [{{"name": "r", "match": {{"host": [{hosts}]}}, "service": "web"}}],
            "revisions": [{{"id": "r", "weight": 1, "state": "serving", "services": [
                {{"name": "web", "type": "loadbalancer", "servers": [{{"url": "http://127.0.0.1:9000"}}]}}]}}]}}"#
        )
    }

    /// The plan of `snapshot`, with the hosts its apps' `host` matchers claim.
    fn compiled(snapshot: &Snapshot) -> Result<Plan, PlanError> {
        let claims: Vec<Vec<HostPattern>> = snapshot
            .apps
            .iter()
            .map(|app| {
                app.routers
                    .iter()
                    .filter_map(|router| router.matcher["host"].as_array())
                    .flatten()
                    .filter_map(|host| host.as_str())
                    .filter_map(|host| HostPattern::parse(host).ok())
                    .collect()
            })
            .collect();
        Plan::compile(snapshot, &claims)
    }

    const ACME: &str = r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir"}"#;

    fn cert_pem(names: &[&str]) -> String {
        rcgen::generate_simple_self_signed(
            names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>(),
        )
        .expect("generates")
        .cert
        .pem()
    }

    #[test]
    fn acme_plan_is_empty_without_settings() {
        let snapshot: Snapshot =
            serde_json::from_str(r#"{"version": 1, "tenants": [], "apps": []}"#).expect("valid");
        let plan = Plan::compile(&snapshot, &[]).expect("compiles");
        assert!(plan.settings().is_none());
        assert!(!plan.on_demand_enabled());
        assert!(plan.missing().is_empty());
    }

    #[test]
    fn acme_plan_orders_the_uncovered_exact_hosts_of_acme_apps() {
        let apps = [
            app("a", "acme", r#""a.test", "b.test", "*.w.test""#),
            app("p", "on_demand", r#""*.p.test""#),
        ]
        .join(",");
        let plan = compiled(&snapshot(ACME, &apps, "")).expect("compiles");
        assert_eq!(
            plan.missing(),
            vec![vec![Box::<str>::from("a.test"), "b.test".into()]]
        );
        assert!(plan.on_demand_enabled());
        assert!(plan.is_on_demand("x.p.test"));
        assert!(!plan.is_on_demand("a.test"));
        assert!(!plan.is_on_demand("x.q.test"));
    }

    #[test]
    fn acme_plan_skips_hosts_that_have_a_certificate() {
        let pem = cert_pem(&["a.test"]);
        let certificate = serde_json::json!({
            "hosts": ["a.test"], "cert_pem": pem, "key_pem": "unused"
        });
        let apps = app("a", "acme", r#""a.test", "b.test""#);
        let plan = compiled(&snapshot(ACME, &apps, &certificate.to_string())).expect("compiles");
        assert_eq!(plan.missing(), vec![vec![Box::<str>::from("b.test")]]);
        assert!(plan.cert_for("a.test").is_some());
        assert!(plan.renewable(plan.cert_for("a.test").expect("covered")));
    }

    #[test]
    fn acme_plan_does_not_renew_wildcard_or_unclaimed_certificates() {
        let pem = cert_pem(&["x.test"]);
        let wildcard = serde_json::json!({"hosts": ["*.x.test"], "cert_pem": pem, "key_pem": "k"});
        let gone = serde_json::json!({"hosts": ["gone.test"], "cert_pem": pem, "key_pem": "k"});
        let apps = app("x", "on_demand", r#""*.x.test""#);
        let certs = format!("{wildcard},{gone}");
        let plan = compiled(&snapshot(ACME, &apps, &certs)).expect("compiles");
        assert!(plan.certs().iter().all(|cert| !plan.renewable(cert)));
    }

    #[test]
    fn acme_plan_rejects_unusable_settings() {
        for acme in [
            r#"{"issuer_node": "", "directory_url": "https://ca.test/dir"}"#,
            r#"{"issuer_node": "n1", "directory_url": "http://ca.test/dir"}"#,
            r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
                "eab": {"key_id": "k", "hmac_key": "AAAA"}, "account_key_pem": "pem"}"#,
            r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
                "eab": {"key_id": "k", "hmac_key": "not base64!"}}"#,
            r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
                "challenges": [{"token": "a/b", "key_authorization": "x"}]}"#,
            r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
                "requested_hosts": ["*.a.test"]}"#,
        ] {
            let err = Plan::compile(&snapshot(acme, "", ""), &[]).expect_err("rejected");
            assert!(matches!(err, PlanError::Invalid { .. }), "{acme}: {err}");
        }
    }

    #[test]
    fn acme_plan_serves_challenges_by_token() {
        let acme = r#"{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
            "challenges": [{"token": "tok-1_A", "key_authorization": "tok-1_A.thumb"}]}"#;
        let plan = Plan::compile(&snapshot(acme, "", ""), &[]).expect("compiles");
        assert_eq!(plan.challenge("tok-1_A"), Some("tok-1_A.thumb"));
        assert_eq!(plan.challenge("other"), None);
    }

    fn info(valid_secs: u64) -> CertInfo {
        CertInfo {
            hosts: Box::new([]),
            not_before: UNIX_EPOCH + Duration::from_secs(1000),
            not_after: UNIX_EPOCH + Duration::from_secs(1000 + valid_secs),
            id: None,
        }
    }

    #[test]
    fn acme_renewal_falls_back_to_two_thirds_of_the_lifetime() {
        assert_eq!(
            info(900).fallback_renewal(),
            UNIX_EPOCH + Duration::from_secs(1600)
        );
    }

    #[test]
    fn acme_renewal_picks_inside_the_window() {
        let cert = info(1000);
        let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(cert.pick_renewal(at(1200), at(1400), 0.0), at(1200));
        assert_eq!(cert.pick_renewal(at(1200), at(1400), 0.5), at(1300));
        assert_eq!(cert.pick_renewal(at(1200), at(1400), 1.0), at(1400));
    }

    #[test]
    fn acme_renewal_never_waits_past_a_tenth_of_the_lifetime_before_expiry() {
        let cert = info(1000);
        let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
        assert_eq!(cert.pick_renewal(at(1900), at(5000), 1.0), at(1900));
    }
}
