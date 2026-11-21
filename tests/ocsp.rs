//! OCSP stapling: the verification rules against responses signed in-process, the
//! registry's schedule against a fake clock, and the real binary fetching from a responder the
//! test runs. Every certificate and response is generated here: a CA, leaf certificates with and
//! without must-staple, delegated responders with and without `id-kp-OCSPSigning`.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, Upstream, app, serving, snapshot};
use podgate::RoutingTable;
use podgate::tls::ocsp::{Fingerprint, Identity, Outcome, Reason, Staples, Verified, verify};
use podgate_model::{OcspMode, Snapshot};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SigningKey,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use sha1::{Digest as _, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;
use x509_cert::Certificate as X509;
use x509_cert::der::asn1::{BitString, Null, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse,
    ResponderId, ResponseData, RevokedInfo, SingleResponse, Version,
};

// ---------------------------------------------------------------------------------------------
// Certificates and responses
// ---------------------------------------------------------------------------------------------

const SHA1_OID: &str = "1.3.14.3.2.26";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// A certificate authority that issues leaves and signs OCSP responses.
struct Pki {
    issuer: CertifiedIssuer<'static, KeyPair>,
    der: CertificateDer<'static>,
    pem: String,
}

/// A leaf certificate and its key.
struct Leaf {
    der: CertificateDer<'static>,
    /// Leaf then CA, PEM: what a snapshot's `cert_pem` holds.
    chain_pem: String,
    key_pem: String,
    host: String,
}

/// What the leaf asks for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Extras {
    /// A TLS Feature extension with `status_request`, and an OCSP responder in the AIA.
    MustStaple,
    /// An OCSP responder in the AIA and nothing else.
    AiaOnly,
    /// Neither.
    Plain,
}

/// A delegated responder: its key and the certificate the CA issued for it.
struct Delegated {
    key: KeyPair,
    cert: X509,
}

fn name(label: &str) -> rcgen::DistinguishedName {
    let mut name = rcgen::DistinguishedName::new();
    name.push(DnType::CommonName, label);
    name
}

/// DER length bytes for `len`.
fn der_len(len: usize) -> Vec<u8> {
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => vec![short],
        Ok(byte) => vec![0x81, byte],
        Err(_) => vec![0x82, (len >> 8) as u8, (len & 0xff) as u8],
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// The Authority Information Access value naming `url` as the OCSP responder.
fn aia(url: &str) -> Vec<u8> {
    let method = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    let mut description = method.to_vec();
    description.extend(tlv(0x86, url.as_bytes()));
    tlv(0x30, &tlv(0x30, &description))
}

impl Pki {
    fn new(label: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = name(label);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer = CertifiedIssuer::self_signed(params, KeyPair::generate().expect("CA key"))
            .expect("self-signed CA");
        Self {
            der: issuer.der().clone(),
            pem: issuer.pem(),
            issuer,
        }
    }

    fn key(&self) -> &KeyPair {
        self.issuer.key()
    }

    /// A leaf for `host` that names `responder` as its OCSP responder when `extras` says so.
    fn leaf(&self, host: &str, extras: Extras, responder: &str) -> Leaf {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec![host.to_owned()]).expect("leaf params");
        params.distinguished_name = name(host);
        if extras == Extras::MustStaple {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 24],
                    vec![0x30, 0x03, 0x02, 0x01, 0x05],
                ));
        }
        if extras != Extras::Plain {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    aia(responder),
                ));
        }
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        Leaf {
            der: cert.der().clone(),
            chain_pem: format!("{}{}", cert.pem(), self.pem),
            key_pem: key.serialize_pem(),
            host: host.to_owned(),
        }
    }

    /// A responder certificate issued by this CA, with `id-kp-OCSPSigning` when `signing`.
    fn delegated(&self, signing: bool) -> Delegated {
        let key = KeyPair::generate().expect("responder key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("responder params");
        params.distinguished_name = name("delegated responder");
        if signing {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::OcspSigning];
        }
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("sign responder");
        Delegated {
            cert: X509::from_der(cert.der()).expect("parse responder"),
            key,
        }
    }

    fn ca(&self) -> X509 {
        X509::from_der(&self.der).expect("parse CA")
    }
}

impl Leaf {
    /// The `certificates` entry for the snapshot; `mode` is the `ocsp` field when given.
    fn entry(&self, mode: Option<&str>) -> Value {
        let mut entry = json!({
            "hosts": [self.host],
            "cert_pem": self.chain_pem,
            "key_pem": self.key_pem,
        });
        if let Some(mode) = mode {
            entry["ocsp"] = json!(mode);
        }
        entry
    }

    fn chain(&self, pki: &Pki) -> Vec<CertificateDer<'static>> {
        vec![self.der.clone(), pki.der.clone()]
    }

    fn x509(&self) -> X509 {
        X509::from_der(&self.der).expect("parse leaf")
    }
}

/// The `CertId` of `leaf` as `ca` issued it, hashed with SHA-1.
fn cert_id(leaf: &X509, ca: &X509) -> CertId {
    CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: SHA1_OID.parse().expect("sha1 oid"),
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(
            Sha1::digest(ca.tbs_certificate.subject.to_der().expect("name")).to_vec(),
        )
        .expect("hash"),
        issuer_key_hash: OctetString::new(
            Sha1::digest(
                ca.tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )
            .to_vec(),
        )
        .expect("hash"),
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    }
}

fn at(time: SystemTime) -> OcspGeneralizedTime {
    OcspGeneralizedTime::try_from(time).expect("time")
}

/// What a response says and who signs it. [`Answer::good`] is a response that verifies.
struct Answer {
    id: CertId,
    status: CertStatus,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    responder: ResponderId,
    certs: Option<Vec<X509>>,
}

impl Answer {
    fn good(leaf: &Leaf, pki: &Pki, now: SystemTime) -> Self {
        let ca = pki.ca();
        Self {
            id: cert_id(&leaf.x509(), &ca),
            status: CertStatus::good(),
            this_update: now - Duration::from_secs(3600),
            next_update: Some(now + Duration::from_secs(4 * 3600)),
            responder: ResponderId::ByName(ca.tbs_certificate.subject.clone()),
            certs: None,
        }
    }

    fn tbs(&self) -> ResponseData {
        ResponseData {
            version: Version::V1,
            responder_id: self.responder.clone(),
            produced_at: at(self.this_update),
            responses: vec![SingleResponse {
                cert_id: self.id.clone(),
                cert_status: self.status,
                this_update: at(self.this_update),
                next_update: self.next_update.map(at),
                single_extensions: None,
            }],
            response_extensions: None,
        }
    }

    /// Signs with `key` and encodes the whole `OCSPResponse`.
    fn sign(self, key: &KeyPair) -> Vec<u8> {
        let tbs = self.tbs();
        let signature = key.sign(&tbs.to_der().expect("tbs")).expect("sign");
        self.finish(tbs, &signature)
    }

    fn finish(self, tbs: ResponseData, signature: &[u8]) -> Vec<u8> {
        let basic = BasicOcspResponse {
            tbs_response_data: tbs,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_SHA256.parse().expect("ecdsa oid"),
                parameters: None,
            },
            signature: BitString::from_bytes(signature).expect("signature"),
            certs: self.certs,
        };
        OcspResponse::successful(basic)
            .expect("successful")
            .to_der()
            .expect("response der")
    }

    /// Encodes with `signature` instead of a real one.
    fn with_signature(self, signature: &[u8]) -> Vec<u8> {
        let tbs = self.tbs();
        self.finish(tbs, signature)
    }
}

/// A verifiable response for `leaf` signed by the CA.
fn good_response(leaf: &Leaf, pki: &Pki, now: SystemTime) -> Vec<u8> {
    Answer::good(leaf, pki, now).sign(pki.key())
}

fn identity(leaf: &Leaf, pki: &Pki, mode: OcspMode) -> Identity {
    Identity::of(&leaf.chain(pki), mode)
        .expect("the certificate wants a staple")
        .expect("an identity")
}

fn check(leaf: &Leaf, pki: &Pki, response: &[u8], now: SystemTime) -> Result<Verified, Reason> {
    verify(response, &identity(leaf, pki, OcspMode::On), &pki.der, now)
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

#[test]
fn ocsp_verifies_a_good_response() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();
    let response = good_response(&leaf, &pki, now);
    let verified = check(&leaf, &pki, &response, now).expect("verifies");
    assert_eq!(verified.der, response);
    assert!(verified.this_update < now && now < verified.next_update);
}

#[test]
fn ocsp_rejects_expired() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();

    let mut answer = Answer::good(&leaf, &pki, now);
    answer.next_update = Some(now - Duration::from_secs(10));
    let expired = answer.sign(pki.key());
    assert_eq!(check(&leaf, &pki, &expired, now), Err(Reason::Expired));

    let mut answer = Answer::good(&leaf, &pki, now);
    answer.this_update = now + Duration::from_secs(600);
    answer.next_update = Some(now + Duration::from_secs(7200));
    let early = answer.sign(pki.key());
    assert_eq!(check(&leaf, &pki, &early, now), Err(Reason::NotYetValid));

    let mut answer = Answer::good(&leaf, &pki, now);
    answer.next_update = None;
    let open_ended = answer.sign(pki.key());
    assert_eq!(
        check(&leaf, &pki, &open_ended, now),
        Err(Reason::NoNextUpdate)
    );

    let fresh = good_response(&leaf, &pki, now);
    let later = now + Duration::from_secs(5 * 3600);
    assert_eq!(check(&leaf, &pki, &fresh, later), Err(Reason::Expired));
}

#[test]
fn ocsp_rejects_wrong_serial() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let other = pki.leaf("b.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();

    let for_other = good_response(&other, &pki, now);
    assert_eq!(
        check(&leaf, &pki, &for_other, now),
        Err(Reason::WrongSerial)
    );

    let stranger = Pki::new("another ca");
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.id = cert_id(&leaf.x509(), &stranger.ca());
    let wrong_issuer = answer.sign(pki.key());
    assert_eq!(
        check(&leaf, &pki, &wrong_issuer, now),
        Err(Reason::WrongIssuer)
    );
}

#[test]
fn ocsp_rejects_bad_signature() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();

    let garbage = Answer::good(&leaf, &pki, now).with_signature(&[7; 71]);
    assert_eq!(check(&leaf, &pki, &garbage, now), Err(Reason::BadSignature));

    let unsigned = Answer::good(&leaf, &pki, now).with_signature(&[]);
    assert!(check(&leaf, &pki, &unsigned, now).is_err());

    // Signed by a key that is not the issuer's while naming the issuer as the signer.
    let intruder = KeyPair::generate().expect("key");
    let forged = Answer::good(&leaf, &pki, now).sign(&intruder);
    assert_eq!(check(&leaf, &pki, &forged, now), Err(Reason::BadSignature));

    // A response that was changed after it was signed.
    let mut tampered = good_response(&leaf, &pki, now);
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;
    assert!(check(&leaf, &pki, &tampered, now).is_err());
}

#[test]
fn ocsp_rejects_revoked_and_counts() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.status = CertStatus::revoked(RevokedInfo {
        revocation_time: at(now - Duration::from_secs(60)),
        revocation_reason: None,
    });
    let revoked = answer.sign(pki.key());
    assert_eq!(check(&leaf, &pki, &revoked, now), Err(Reason::Revoked));

    let mut answer = Answer::good(&leaf, &pki, now);
    answer.status = CertStatus::unknown();
    let unknown = answer.sign(pki.key());
    assert_eq!(
        check(&leaf, &pki, &unknown, now),
        Err(Reason::UnknownStatus)
    );
}

#[test]
fn ocsp_rejects_oversized_and_malformed() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();
    assert_eq!(
        check(&leaf, &pki, &vec![0x30; 64 * 1024 + 1], now),
        Err(Reason::Oversized)
    );
    for bad in [&b""[..], b"not asn.1", &[0x30, 0x03, 0x0a, 0x01, 0x00]] {
        assert_eq!(
            check(&leaf, &pki, bad, now),
            Err(Reason::Malformed),
            "{bad:?}"
        );
    }
    let good = good_response(&leaf, &pki, now);
    assert_eq!(
        check(&leaf, &pki, &good[..good.len() - 3], now),
        Err(Reason::Malformed)
    );
    let try_later = OcspResponse::try_later().to_der().expect("der");
    assert_eq!(
        check(&leaf, &pki, &try_later, now),
        Err(Reason::NotSuccessful)
    );
    let mut trailing = good;
    trailing.push(0);
    assert_eq!(check(&leaf, &pki, &trailing, now), Err(Reason::Malformed));
}

#[test]
fn ocsp_delegated_responder_accepted() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();
    let delegated = pki.delegated(true);
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.responder = ResponderId::ByName(delegated.cert.tbs_certificate.subject.clone());
    answer.certs = Some(vec![delegated.cert.clone()]);
    let response = answer.sign(&delegated.key);
    assert!(check(&leaf, &pki, &response, now).is_ok());

    // Identified by key hash instead of name.
    let mut answer = Answer::good(&leaf, &pki, now);
    let key_hash = Sha1::digest(
        delegated
            .cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    answer.responder = ResponderId::ByKey(OctetString::new(key_hash.to_vec()).expect("hash"));
    answer.certs = Some(vec![delegated.cert.clone()]);
    let response = answer.sign(&delegated.key);
    assert!(check(&leaf, &pki, &response, now).is_ok());
}

#[test]
fn ocsp_delegated_responder_without_eku_refused() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let now = SystemTime::now();

    let plain = pki.delegated(false);
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.responder = ResponderId::ByName(plain.cert.tbs_certificate.subject.clone());
    answer.certs = Some(vec![plain.cert.clone()]);
    let response = answer.sign(&plain.key);
    assert_eq!(
        check(&leaf, &pki, &response, now),
        Err(Reason::ResponderNotAuthorized)
    );

    // A responder certificate another CA issued, even with the usage, is not the issuer's.
    let stranger = Pki::new("another ca");
    let foreign = stranger.delegated(true);
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.responder = ResponderId::ByName(foreign.cert.tbs_certificate.subject.clone());
    answer.certs = Some(vec![foreign.cert.clone()]);
    let response = answer.sign(&foreign.key);
    assert_eq!(
        check(&leaf, &pki, &response, now),
        Err(Reason::ResponderNotAuthorized)
    );

    // A responder that names a certificate it did not include.
    let mut answer = Answer::good(&leaf, &pki, now);
    answer.responder = ResponderId::ByName(plain.cert.tbs_certificate.subject.clone());
    let response = answer.sign(&plain.key);
    assert_eq!(
        check(&leaf, &pki, &response, now),
        Err(Reason::ResponderNotAuthorized)
    );
}

#[test]
fn ocsp_policy_modes_choose_certificates() {
    let pki = Pki::new("ca");
    let url = "http://127.0.0.1:1/";
    let must = pki.leaf("a.test", Extras::MustStaple, url);
    let aia_only = pki.leaf("b.test", Extras::AiaOnly, url);
    let plain = pki.leaf("c.test", Extras::Plain, url);
    let wants = |leaf: &Leaf, mode| Identity::of(&leaf.chain(&pki), mode).is_some();
    assert!(wants(&must, OcspMode::Auto));
    assert!(!wants(&aia_only, OcspMode::Auto));
    assert!(!wants(&plain, OcspMode::Auto));
    assert!(wants(&must, OcspMode::On) && wants(&aia_only, OcspMode::On));
    assert!(!wants(&plain, OcspMode::On));
    for leaf in [&must, &aia_only, &plain] {
        assert!(!wants(leaf, OcspMode::Off));
    }
    // A chain without the issuer cannot be stapled.
    assert_eq!(
        Identity::of(&must.chain(&pki)[..1], OcspMode::Auto)
            .expect("wanted")
            .err(),
        Some(Reason::NoIssuer)
    );
}

// ---------------------------------------------------------------------------------------------
// The registry against a fake clock
// ---------------------------------------------------------------------------------------------

fn snapshot_with(certificates: &[Value]) -> Snapshot {
    let mut value = snapshot(
        1,
        &[app(
            "a",
            &["a.test"],
            &[serving("r1", "127.0.0.1:9".parse().expect("addr"))],
        )],
    );
    value["certificates"] = Value::Array(certificates.to_vec());
    serde_json::from_value(value).expect("snapshot")
}

fn table_with(leaf: &Leaf) -> RoutingTable {
    RoutingTable::compile(&snapshot_with(&[leaf.entry(None)])).expect("compiles")
}

fn verified(now: SystemTime, window: Duration) -> Verified {
    Verified {
        der: vec![1, 2, 3],
        this_update: now,
        next_update: now + window,
    }
}

fn staple_of(staples: &Staples, table: &RoutingTable) -> Option<Vec<u8>> {
    let key = table.certificates().lookup("a.test").expect("certificate");
    staples.attach(key).ocsp.clone()
}

#[test]
fn ocsp_refresh_midpoint() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let table = table_with(&leaf);
    let staples = Staples::default();
    let now = SystemTime::now();

    let jobs = staples.tick(&table, now, 8);
    assert_eq!(jobs.len(), 1, "a new certificate is due at once");
    assert!(
        staples.tick(&table, now, 8).is_empty(),
        "one fetch per certificate at a time"
    );

    staples.finish(
        jobs[0].fingerprint(),
        Outcome::Verified(verified(now, Duration::from_secs(4 * 3600))),
        now,
        0.5,
    );
    assert_eq!(staple_of(&staples, &table), Some(vec![1, 2, 3]));
    let before = now + Duration::from_secs(2 * 3600 - 1);
    assert!(
        staples.tick(&table, before, 8).is_empty(),
        "not before the midpoint"
    );
    let at_midpoint = now + Duration::from_secs(2 * 3600);
    assert_eq!(
        staples.tick(&table, at_midpoint, 8).len(),
        1,
        "at the midpoint"
    );
}

#[test]
fn ocsp_backoff_on_failure() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let table = table_with(&leaf);
    let staples = Staples::default();
    let secs = Duration::from_secs;
    let now = SystemTime::now();
    let first = staples.tick(&table, now, 8).remove(0);
    staples.finish(
        first.fingerprint(),
        Outcome::Failed(Reason::Connect),
        now,
        0.0,
    );
    assert!(
        staples.tick(&table, now + secs(59), 8).is_empty(),
        "no retry before a minute"
    );
    let second = staples.tick(&table, now + secs(60), 8);
    assert_eq!(second.len(), 1, "one minute after the first failure");

    let later = now + secs(60);
    staples.finish(
        second[0].fingerprint(),
        Outcome::Failed(Reason::Timeout),
        later,
        0.0,
    );
    assert!(
        staples.tick(&table, later + secs(119), 8).is_empty(),
        "then two minutes"
    );
    assert_eq!(staples.tick(&table, later + secs(120), 8).len(), 1);
}

#[test]
fn ocsp_backoff_doubles_to_an_hour() {
    use podgate::tls::ocsp::schedule::backoff;
    let waits: Vec<u64> = (1..=9).map(|n| backoff(n, 0.0).as_secs()).collect();
    assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
}

#[test]
fn ocsp_old_staple_kept_while_refresh_fails() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let table = table_with(&leaf);
    let staples = Staples::default();
    let now = SystemTime::now();
    let job = staples.tick(&table, now, 8).remove(0);
    staples.finish(
        job.fingerprint(),
        Outcome::Verified(verified(now, Duration::from_secs(3600))),
        now,
        0.5,
    );
    let refresh = staples
        .tick(&table, now + Duration::from_secs(1800), 8)
        .remove(0);
    staples.finish(
        refresh.fingerprint(),
        Outcome::Failed(Reason::Connect),
        now + Duration::from_secs(1800),
        0.0,
    );
    assert_eq!(staple_of(&staples, &table), Some(vec![1, 2, 3]));
}

#[test]
fn ocsp_expired_staple_dropped() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let table = table_with(&leaf);
    let staples = Staples::default();
    let now = SystemTime::now();
    let job = staples.tick(&table, now, 8).remove(0);
    staples.finish(
        job.fingerprint(),
        Outcome::Verified(verified(now, Duration::from_secs(3600))),
        now,
        0.5,
    );
    assert_eq!(staple_of(&staples, &table), Some(vec![1, 2, 3]));

    // The refresh keeps failing; the old staple is kept until `nextUpdate` and not a second more.
    let late = now + Duration::from_secs(3601);
    staples.tick(&table, late, 8);
    assert_eq!(staple_of(&staples, &table), None);
    assert!(staples.is_empty());

    // A response that is already past `nextUpdate` by the real clock is never attached.
    let stale = Staples::default();
    let job = stale.tick(&table, now, 8).remove(0);
    let past = now - Duration::from_secs(7200);
    stale.finish(
        job.fingerprint(),
        Outcome::Verified(Verified {
            der: vec![9],
            this_update: past,
            next_update: now - Duration::from_secs(1),
        }),
        now,
        0.5,
    );
    assert_eq!(staple_of(&stale, &table), None);
}

#[test]
fn ocsp_survives_unrelated_push_in_registry() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let first = table_with(&leaf);
    let staples = Staples::default();
    let now = SystemTime::now();
    let job = staples.tick(&first, now, 8).remove(0);
    staples.finish(
        job.fingerprint(),
        Outcome::Verified(verified(now, Duration::from_secs(4 * 3600))),
        now,
        0.5,
    );

    // A new table, compiled from a snapshot with one more app, holds the same certificate.
    let mut value = serde_json::to_value(snapshot_with(&[leaf.entry(None)])).expect("json");
    value["version"] = json!(2);
    let upstream: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    value["apps"].as_array_mut().expect("apps").push(app(
        "b",
        &["b.test"],
        &[serving("r1", upstream)],
    ));
    let second =
        RoutingTable::compile(&serde_json::from_value(value).expect("snapshot")).expect("compiles");
    let jobs = staples.tick(&second, now + Duration::from_secs(1), 8);
    assert!(jobs.is_empty(), "the staple is not refetched");
    assert_eq!(staple_of(&staples, &second), Some(vec![1, 2, 3]));
}

#[test]
fn ocsp_dropped_with_certificate() {
    let pki = Pki::new("ca");
    let leaf = pki.leaf("a.test", Extras::MustStaple, "http://127.0.0.1:1/");
    let table = table_with(&leaf);
    let staples = Staples::default();
    let now = SystemTime::now();
    let job = staples.tick(&table, now, 8).remove(0);
    let print: Fingerprint = job.fingerprint();
    staples.finish(
        print,
        Outcome::Verified(verified(now, Duration::from_secs(4 * 3600))),
        now,
        0.5,
    );
    assert_eq!(staples.len(), 1);

    let without = RoutingTable::compile(&snapshot_with(&[])).expect("compiles");
    assert!(staples.tick(&without, now, 8).is_empty());
    assert!(staples.is_empty(), "the staple left with its certificate");

    // A result that arrives for a certificate that left is ignored.
    staples.finish(
        print,
        Outcome::Verified(verified(now, Duration::from_secs(3600))),
        now,
        0.5,
    );
    assert!(staples.is_empty());
}

// ---------------------------------------------------------------------------------------------
// A responder the binary can fetch from
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Mode {
    Good,
    Revoked,
    Delay(Duration),
    Redirect(String),
    Garbage,
    Oversized,
}

struct Responder {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    serials: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct Shared {
    pki: Arc<Pki>,
    mode: Mode,
    hits: Arc<AtomicUsize>,
    active: AtomicUsize,
    max_active: Arc<AtomicUsize>,
    serials: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Responder {
    async fn start(pki: &Arc<Pki>, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let addr = listener.local_addr().expect("responder address");
        let shared = Arc::new(Shared {
            pki: Arc::clone(pki),
            mode,
            hits: Arc::default(),
            active: AtomicUsize::new(0),
            max_active: Arc::default(),
            serials: Arc::default(),
        });
        let out = Self {
            addr,
            hits: Arc::clone(&shared.hits),
            max_active: Arc::clone(&shared.max_active),
            serials: Arc::clone(&shared.serials),
        };
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(stream, Arc::clone(&shared)));
            }
        });
        out
    }

    fn url(&self) -> String {
        format!("http://{}/ocsp", self.addr)
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn asked_for(&self, leaf: &Leaf) -> bool {
        let serial = leaf.x509().tbs_certificate.serial_number;
        self.serials
            .lock()
            .expect("serials")
            .iter()
            .any(|seen| seen == serial.as_bytes())
    }
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap_or("00");
            out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}

async fn serve(mut stream: TcpStream, shared: Arc<Shared>) {
    let active = shared.active.fetch_add(1, Ordering::SeqCst) + 1;
    shared.max_active.fetch_max(active, Ordering::SeqCst);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                shared.active.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
    shared.hits.fetch_add(1, Ordering::SeqCst);
    let head = String::from_utf8_lossy(&seen).into_owned();
    let target = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let encoded = target.rsplit('/').next().unwrap_or_default();
    let request = STANDARD
        .decode(percent_decode(encoded))
        .ok()
        .and_then(|der| OcspRequest::from_der(&der).ok());
    let reply = match (&shared.mode, request) {
        (Mode::Redirect(to), _) => format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
        (_, None) => http(400, "text/plain", b"bad request"),
        (Mode::Garbage, _) => http(200, "application/ocsp-response", b"this is not asn.1"),
        (Mode::Oversized, _) => http(200, "application/ocsp-response", &vec![0x30; 70_000]),
        (mode, Some(request)) => {
            if let Mode::Delay(wait) = mode {
                sleep(*wait).await;
            }
            let id = request.tbs_request.request_list[0].req_cert.clone();
            shared
                .serials
                .lock()
                .expect("serials")
                .push(id.serial_number.as_bytes().to_vec());
            let now = SystemTime::now();
            let ca = shared.pki.ca();
            let answer = Answer {
                id,
                status: if matches!(mode, Mode::Revoked) {
                    CertStatus::revoked(RevokedInfo {
                        revocation_time: at(now - Duration::from_secs(60)),
                        revocation_reason: None,
                    })
                } else {
                    CertStatus::good()
                },
                this_update: now - Duration::from_secs(60),
                next_update: Some(now + Duration::from_secs(4 * 3600)),
                responder: ResponderId::ByName(ca.tbs_certificate.subject),
                certs: None,
            };
            http(
                200,
                "application/ocsp-response",
                &answer.sign(shared.pki.key()),
            )
        }
    };
    // The peer may already be gone; the test judges what it saw, not this write.
    drop(stream.write_all(&reply).await);
    shared.active.fetch_sub(1, Ordering::SeqCst);
}

fn http(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut reply = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(body);
    reply
}

// ---------------------------------------------------------------------------------------------
// The binary
// ---------------------------------------------------------------------------------------------

/// A client that accepts any certificate and remembers the OCSP response it was sent.
#[derive(Debug, Default)]
struct Capture {
    staple: Mutex<Vec<u8>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.staple.lock().expect("staple") = ocsp_response.to_vec();
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The staple (empty when none) a handshake for `sni` brings, or why it failed.
async fn staple(podgate: &Podgate, sni: &str) -> io::Result<Vec<u8>> {
    let capture = Arc::new(Capture::default());
    let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&capture) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    let name = ServerName::try_from(sni.to_owned()).expect("server name");
    let tcp = TcpStream::connect(podgate.tls_addr).await?;
    let _stream = timeout(
        Duration::from_secs(10),
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| io::Error::other("handshake timed out"))??;
    let staple = capture.staple.lock().expect("staple").clone();
    Ok(staple)
}

/// Polls until a handshake for `sni` carries a staple.
async fn wait_for_staple(podgate: &Podgate, sni: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let staple = staple(podgate, sni).await.expect("handshake");
        if !staple.is_empty() {
            return staple;
        }
        assert!(Instant::now() < deadline, "no staple for {sni} in time");
        sleep(Duration::from_millis(200)).await;
    }
}

/// The value of the `podgate_ocsp_rejected_total` series for `reason`.
async fn rejected(podgate: &Podgate, reason: &str) -> u64 {
    let metrics = podgate.admin_get("/metrics").await;
    let line = format!("podgate_ocsp_rejected_total{{reason=\"{reason}\"}} ");
    metrics
        .body
        .lines()
        .find_map(|row| row.strip_prefix(&line))
        .and_then(|count| count.trim().parse().ok())
        .unwrap_or(0)
}

async fn wait_for_rejection(podgate: &Podgate, reason: &str) {
    let deadline = Instant::now() + Duration::from_secs(25);
    while rejected(podgate, reason).await == 0 {
        assert!(Instant::now() < deadline, "no {reason} rejection in time");
        sleep(Duration::from_millis(200)).await;
    }
}

/// A policy file for one test, removed when it drops.
struct PolicyFile(std::path::PathBuf);

impl PolicyFile {
    fn new(contents: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-ocsp-policy-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&path, contents).expect("write policy");
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("utf-8 path")
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        drop(std::fs::remove_file(&self.0));
    }
}

/// A snapshot with one app per host (so every certificate has an owner) and `certificates`.
fn live_snapshot(
    version: u64,
    upstream: SocketAddr,
    hosts: &[&str],
    certificates: &[Value],
) -> Value {
    let apps: Vec<Value> = hosts
        .iter()
        .map(|host| app(host, &[host], &[serving("r1", upstream)]))
        .collect();
    let mut value = snapshot(version, &apps);
    value["certificates"] = Value::Array(certificates.to_vec());
    value
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

#[tokio::test]
async fn ocsp_staple_served_for_must_staple() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    let staple = wait_for_staple(&podgate, "a.test").await;
    let now = SystemTime::now();
    let verified = verify(
        &staple,
        &identity(&leaf, &pki, OcspMode::Auto),
        &pki.der,
        now,
    )
    .expect("the staple verifies");
    assert!(verified.next_update > now);
    assert!(responder.hits() >= 1);
}

#[tokio::test]
async fn ocsp_auto_only_for_must_staple() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let must = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let aia_only = pki.leaf("b.test", Extras::AiaOnly, &responder.url());
    let plain = pki.leaf("c.test", Extras::Plain, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let certificates = [
        must.entry(None),
        aia_only.entry(None),
        plain.entry(Some("auto")),
    ];
    push(
        &podgate,
        &live_snapshot(
            1,
            upstream.addr,
            &["a.test", "b.test", "c.test"],
            &certificates,
        ),
    )
    .await;

    wait_for_staple(&podgate, "a.test").await;
    sleep(Duration::from_secs(2)).await;
    assert!(responder.asked_for(&must));
    assert!(
        !responder.asked_for(&aia_only),
        "auto asks only for must-staple"
    );
    assert!(!responder.asked_for(&plain));
    assert!(
        staple(&podgate, "b.test")
            .await
            .expect("handshake")
            .is_empty()
    );
    assert!(
        staple(&podgate, "c.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_on_staples_with_aia() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let aia_only = pki.leaf("b.test", Extras::AiaOnly, &responder.url());
    let plain = pki.leaf("c.test", Extras::Plain, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let certificates = [aia_only.entry(Some("on")), plain.entry(Some("on"))];
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["b.test", "c.test"], &certificates),
    )
    .await;

    let staple_bytes = wait_for_staple(&podgate, "b.test").await;
    let identity = identity(&aia_only, &pki, OcspMode::On);
    verify(&staple_bytes, &identity, &pki.der, SystemTime::now()).expect("verifies");
    sleep(Duration::from_secs(1)).await;
    assert!(
        !responder.asked_for(&plain),
        "no responder in the certificate: nothing to ask"
    );
    assert!(
        staple(&podgate, "c.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_off_never() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let off = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let control = pki.leaf("b.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    let certificates = [off.entry(Some("off")), control.entry(None)];
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test", "b.test"], &certificates),
    )
    .await;

    wait_for_staple(&podgate, "b.test").await;
    sleep(Duration::from_secs(2)).await;
    assert!(!responder.asked_for(&off), "off never fetches");
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_responder_loopback_refused() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    // The built-in deny list refuses loopback; the app's upstream is elsewhere, so the snapshot
    // itself compiles.
    let policy = PolicyFile::new(r#"{"deny": ["127.0.0.0/8", "::1/128"]}"#);
    let podgate = Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.path())]).await;
    let elsewhere = "10.0.0.1:80".parse().expect("address");
    push(
        &podgate,
        &live_snapshot(1, elsewhere, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    wait_for_rejection(&podgate, "policy").await;
    sleep(Duration::from_secs(1)).await;
    assert_eq!(responder.hits(), 0, "the responder was never dialled");
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
    let metrics = podgate.admin_get("/metrics").await;
    assert!(
        metrics
            .body
            .contains("podgate_upstream_refused_total{tenant=\"t1\"}"),
        "the refusal is the address policy's, counted for the tenant:\n{}",
        metrics.body
    );
}

#[tokio::test]
async fn ocsp_responder_metadata_address_refused() {
    let pki = Arc::new(Pki::new("ca"));
    let leaf = pki.leaf(
        "a.test",
        Extras::MustStaple,
        "http://169.254.169.254/latest/meta-data/",
    );
    let upstream = Upstream::start("ok").await;
    // The harness policy allows loopback and keeps link-local denied.
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    wait_for_rejection(&podgate, "policy").await;
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_redirect_not_followed() {
    let pki = Arc::new(Pki::new("ca"));
    let target = Responder::start(&pki, Mode::Good).await;
    let redirecting = Responder::start(&pki, Mode::Redirect(target.url())).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &redirecting.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    wait_for_rejection(&podgate, "http_status").await;
    assert!(redirecting.hits() >= 1);
    assert_eq!(target.hits(), 0, "the redirect was not followed");
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_allowed_hosts_enforced() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start_with_env(&[("OCSP_ALLOWED_HOSTS", "ocsp.example.org")]).await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    wait_for_rejection(&podgate, "host_not_allowed").await;
    assert_eq!(responder.hits(), 0);

    let listed = Podgate::start_with_env(&[("OCSP_ALLOWED_HOSTS", "127.0.0.1")]).await;
    push(
        &listed,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;
    wait_for_staple(&listed, "a.test").await;
}

#[tokio::test]
async fn ocsp_rejects_revoked_and_counts_end_to_end() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Revoked).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start_logged(&[("RUST_LOG", "warn")]).await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    wait_for_rejection(&podgate, "revoked").await;
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !podgate.log().contains("revoked") {
        assert!(
            Instant::now() < deadline,
            "the revocation was not logged:\n{}",
            podgate.log()
        );
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn ocsp_rejects_oversized_and_malformed_end_to_end() {
    let pki = Arc::new(Pki::new("ca"));
    let big = Responder::start(&pki, Mode::Oversized).await;
    let garbage = Responder::start(&pki, Mode::Garbage).await;
    let a = pki.leaf("a.test", Extras::MustStaple, &big.url());
    let b = pki.leaf("b.test", Extras::MustStaple, &garbage.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(
            1,
            upstream.addr,
            &["a.test", "b.test"],
            &[a.entry(None), b.entry(None)],
        ),
    )
    .await;

    wait_for_rejection(&podgate, "oversized").await;
    wait_for_rejection(&podgate, "malformed").await;
    assert!(
        staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
    assert!(
        staple(&podgate, "b.test")
            .await
            .expect("handshake")
            .is_empty()
    );
}

#[tokio::test]
async fn ocsp_handshake_does_not_wait() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Delay(Duration::from_secs(30))).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;

    let began = Instant::now();
    let staple = staple(&podgate, "a.test").await.expect("handshake");
    assert!(staple.is_empty(), "no staple while the responder is silent");
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "the handshake waited {:?}",
        began.elapsed()
    );
    // The fetch is in flight, so the handshake above really did overlap it.
    sleep(Duration::from_secs(1)).await;
    assert!(responder.hits() >= 1);
    let again = Instant::now();
    assert!(
        self::staple(&podgate, "a.test")
            .await
            .expect("handshake")
            .is_empty()
    );
    assert!(again.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn ocsp_survives_unrelated_push() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Good).await;
    let leaf = pki.leaf("a.test", Extras::MustStaple, &responder.url());
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &live_snapshot(1, upstream.addr, &["a.test"], &[leaf.entry(None)]),
    )
    .await;
    let first = wait_for_staple(&podgate, "a.test").await;
    let hits = responder.hits();

    push(
        &podgate,
        &live_snapshot(
            2,
            upstream.addr,
            &["a.test", "other.test"],
            &[leaf.entry(None)],
        ),
    )
    .await;
    let again = staple(&podgate, "a.test").await.expect("handshake");
    assert_eq!(
        again, first,
        "the staple is there at once after an unrelated push"
    );
    sleep(Duration::from_secs(2)).await;
    assert_eq!(responder.hits(), hits, "nothing was fetched again");

    // The certificate leaves: its staple goes with it.
    push(
        &podgate,
        &live_snapshot(3, upstream.addr, &["other.test"], &[]),
    )
    .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let metrics = podgate.admin_get("/metrics").await;
        if metrics.body.contains("podgate_ocsp_staples 0\n") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the staple outlived its certificate"
        );
        sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn ocsp_fetch_concurrency_capped() {
    let pki = Arc::new(Pki::new("ca"));
    let responder = Responder::start(&pki, Mode::Delay(Duration::from_secs(1))).await;
    let hosts: Vec<String> = (0..12).map(|n| format!("h{n}.test")).collect();
    let leaves: Vec<Leaf> = hosts
        .iter()
        .map(|host| pki.leaf(host, Extras::MustStaple, &responder.url()))
        .collect();
    let entries: Vec<Value> = leaves.iter().map(|leaf| leaf.entry(None)).collect();
    let names: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let upstream = Upstream::start("ok").await;
    let podgate = Podgate::start().await;
    push(&podgate, &live_snapshot(1, upstream.addr, &names, &entries)).await;

    for host in &hosts {
        wait_for_staple(&podgate, host).await;
    }
    assert_eq!(
        responder.max_active.load(Ordering::SeqCst),
        8,
        "at most eight fetches at once, and the eight were really parallel"
    );
}
