//! The `pass_tls_client_cert` middleware: Traefik's `passTLSClientCert`. The verified client
//! certificate, or some of its fields, goes to the upstream in two request headers. Full
//! reference: `docs/ref/mw-client-cert.md`.
//!
//! ```json
//! {
//!   "name": "cert", "type": "pass_tls_client_cert", "pem": true,
//!   "info": {
//!     "not_after": true, "not_before": true, "sans": true, "serial_number": true,
//!     "subject": { "common_name": true, "organization": true },
//!     "issuer": { "common_name": true }
//!   }
//! }
//! ```
//!
//! - `X-Forwarded-Tls-Client-Cert` (`pem`): the base64 DER of every certificate the client sent,
//!   leaf first, separated by `,`. No PEM armor, no line breaks, nothing else escaped: this is
//!   what the pinned Traefik sends.
//! - `X-Forwarded-Tls-Client-Cert-Info` (`info`): per certificate the selected fields
//!   `Subject="..."`, `Issuer="..."`, `SerialNumber="..."`, `NB="..."`, `NA="..."`, `SAN="..."`
//!   (in that order, `;` between fields, `,` between certificates), the whole value
//!   URL-escaped like Go's `url.QueryEscape`.
//!
//! # Who may write the headers
//!
//! Only this middleware, and only from the certificate `clientauth` verified for the app the
//! request is routed to (`clientauth::verified_chain`). [`strip`] removes every header
//! in the reserved `x-forwarded-tls-client-cert` family from every request in the entry stage,
//! before routing, so a request that reaches an upstream without this middleware, over plain
//! HTTP, or without a certificate carries none of them. The family includes `_` spellings
//! (CGI-style upstreams map `_` and `-` to the same variable) and the
//! `x-forwarded-tls-client-cert-subject` header that change 0021 used to write.
//!
//! # Bounds
//!
//! A header value over [`MAX_HEADER_BYTES`] is not sent and counted in
//! `podgate_client_cert_header_omitted_total{header}`; the other header still is. A value is
//! never truncated: half a certificate chain is worse than none. Field values are quoted, with
//! `"` and `\` backslash-escaped and control characters replaced by `?`, so a certificate's
//! subject cannot end its own field and start another.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::HeaderName;
use pingora::http::RequestHeader;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_parser::asn1_rs::{Oid, oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::x509::X509Name;

use super::{CompileCx, Flow, Kind, RequestCx};
use crate::clientauth;
use crate::compile::Invalid;
use podgate_model::Declared;

/// The header that carries the certificate chain.
pub const PEM_HEADER: &str = "x-forwarded-tls-client-cert";

/// The header that carries the selected fields.
pub const INFO_HEADER: &str = "x-forwarded-tls-client-cert-info";

/// The longest value either header gets. A longer one is omitted, never cut.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

static OID_COUNTRY: Oid<'static> = oid!(2.5.4.6);
static OID_PROVINCE: Oid<'static> = oid!(2.5.4.8);
static OID_LOCALITY: Oid<'static> = oid!(2.5.4.7);
static OID_ORGANIZATION: Oid<'static> = oid!(2.5.4.10);
static OID_ORGANIZATIONAL_UNIT: Oid<'static> = oid!(2.5.4.11);
static OID_SERIAL_NUMBER: Oid<'static> = oid!(2.5.4.5);
static OID_COMMON_NAME: Oid<'static> = oid!(2.5.4.3);
static OID_DOMAIN_COMPONENT: Oid<'static> = oid!(0.9.2342.19200300.100.1.25);

static OMITTED_PEM: AtomicU64 = AtomicU64::new(0);
static OMITTED_INFO: AtomicU64 = AtomicU64::new(0);

/// Whether `name` belongs to the reserved family: `x-forwarded-tls-client-cert` followed by
/// anything, where `_` counts as `-`.
fn reserved(name: &str) -> bool {
    name.len() >= PEM_HEADER.len()
        && name
            .bytes()
            .zip(PEM_HEADER.bytes())
            .all(|(got, want)| got.eq_ignore_ascii_case(&want) || (got == b'_' && want == b'-'))
}

/// Removes every reserved header from `request`. Runs on every request in the entry stage,
/// whether or not the route has the middleware and whether or not the connection has a
/// certificate: the headers are never client-controlled.
pub fn strip(request: &mut RequestHeader) {
    let forged: Vec<HeaderName> = request
        .headers
        .keys()
        .filter(|name| reserved(name.as_str()))
        .cloned()
        .collect();
    for name in forged {
        request.remove_header(&name);
    }
}

/// The `podgate_client_cert_header_omitted_total` series, for `GET /metrics`.
pub(crate) fn render(out: &mut String) {
    let name = "podgate_client_cert_header_omitted_total";
    let _ = writeln!(
        out,
        "# HELP {name} Client certificate headers not sent because the value was over {MAX_HEADER_BYTES} bytes.\n# TYPE {name} counter"
    );
    for (header, count) in [("pem", &OMITTED_PEM), ("info", &OMITTED_INFO)] {
        let _ = writeln!(
            out,
            "{name}{{header=\"{header}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
}

/// The configuration of a `pass_tls_client_cert` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Send the certificate chain in `X-Forwarded-Tls-Client-Cert`.
    pub pem: bool,
    /// Send these fields in `X-Forwarded-Tls-Client-Cert-Info`. Absent: no info header.
    pub info: Option<Info>,
}

/// The fields of `X-Forwarded-Tls-Client-Cert-Info`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Traefik's `info` is a list of independent switches; this is its field list"
)]
pub struct Info {
    /// `NA`: the end of the validity, in Unix seconds.
    pub not_after: bool,
    /// `NB`: the start of the validity, in Unix seconds.
    pub not_before: bool,
    /// `SAN`: DNS names, e-mail addresses, IP addresses and URIs, `,` separated.
    pub sans: bool,
    /// `SerialNumber`: the certificate serial in decimal.
    pub serial_number: bool,
    /// `Subject`: the selected parts of the subject name.
    pub subject: Option<Subject>,
    /// `Issuer`: the selected parts of the issuer name.
    pub issuer: Option<Issuer>,
}

impl Info {
    /// Whether any field is selected.
    fn any(&self) -> bool {
        self.not_after
            || self.not_before
            || self.sans
            || self.serial_number
            || self
                .subject
                .is_some_and(|subject| any(subject.attributes()))
            || self.issuer.is_some_and(|issuer| any(issuer.attributes()))
    }
}

/// A name attribute to render: whether it is selected, its OID and the key it is written under.
type Attribute = (bool, &'static Oid<'static>, &'static str);

fn any(attributes: [Attribute; 8]) -> bool {
    attributes.iter().any(|(selected, ..)| *selected)
}

/// The parts of the subject name to send.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Traefik's `subject` is a list of independent switches; this is its field list"
)]
pub struct Subject {
    /// `C`.
    pub country: bool,
    /// `ST`.
    pub province: bool,
    /// `L`.
    pub locality: bool,
    /// `O`.
    pub organization: bool,
    /// `OU`.
    pub organizational_unit: bool,
    /// `CN`.
    pub common_name: bool,
    /// `SN`: the subject's own serial number attribute.
    pub serial_number: bool,
    /// `DC`.
    pub domain_component: bool,
}

impl Subject {
    /// The attributes in the order Traefik renders them.
    fn attributes(self) -> [Attribute; 8] {
        [
            (self.domain_component, &OID_DOMAIN_COMPONENT, "DC"),
            (self.country, &OID_COUNTRY, "C"),
            (self.province, &OID_PROVINCE, "ST"),
            (self.locality, &OID_LOCALITY, "L"),
            (self.organization, &OID_ORGANIZATION, "O"),
            (self.organizational_unit, &OID_ORGANIZATIONAL_UNIT, "OU"),
            (self.serial_number, &OID_SERIAL_NUMBER, "SN"),
            (self.common_name, &OID_COMMON_NAME, "CN"),
        ]
    }
}

/// The parts of the issuer name to send. Like [`Subject`] without the organizational unit, as in
/// Traefik.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields, default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Traefik's `issuer` is a list of independent switches; this is its field list"
)]
pub struct Issuer {
    /// `C`.
    pub country: bool,
    /// `ST`.
    pub province: bool,
    /// `L`.
    pub locality: bool,
    /// `O`.
    pub organization: bool,
    /// `CN`.
    pub common_name: bool,
    /// `SN`: the issuer's own serial number attribute.
    pub serial_number: bool,
    /// `DC`.
    pub domain_component: bool,
}

impl Issuer {
    /// The attributes in the order Traefik renders them.
    fn attributes(self) -> [Attribute; 8] {
        Subject {
            country: self.country,
            province: self.province,
            locality: self.locality,
            organization: self.organization,
            organizational_unit: false,
            common_name: self.common_name,
            serial_number: self.serial_number,
            domain_component: self.domain_component,
        }
        .attributes()
    }
}

/// A compiled `pass_tls_client_cert` middleware.
#[derive(Debug)]
pub struct PassTlsClientCert {
    config: Config,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new(
        "invalid_middleware",
        format!("pass_tls_client_cert: {}", message.into()),
    )
}

impl Kind for PassTlsClientCert {
    type State = ();

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        if !config.pem && !config.info.as_ref().is_some_and(Info::any) {
            return Err(invalid(
                "selects nothing: set pem or at least one field of info",
            ));
        }
        if cx.app.tls.client_ca_pem.is_none() {
            return Err(invalid(
                "the app verifies no client certificate: set tls.client_ca_pem and a tls.client_auth that verifies (verify_if_given or require_and_verify)",
            ));
        }
        Ok(Self { config })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let Some(chain) = clientauth::verified_chain(cx.session, cx.app) else {
            return Ok(Flow::Continue);
        };
        // shortcut: both values are rebuilt for every request; cache them on the connection
        // when a profile shows the x509 parse.
        let pem = self.config.pem.then(|| pem_value(chain));
        let info = self
            .config
            .info
            .as_ref()
            .filter(|info| info.any())
            .map(|info| info_value(info, chain));
        let request = cx.session.req_header_mut();
        for (name, omitted, value) in [
            (PEM_HEADER, &OMITTED_PEM, pem),
            (INFO_HEADER, &OMITTED_INFO, info),
        ] {
            let Some(value) = value.filter(|value| !value.is_empty()) else {
                continue;
            };
            if value.len() > MAX_HEADER_BYTES {
                omitted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            request.insert_header(name, value)?;
        }
        Ok(Flow::Continue)
    }

    fn describe(&self) -> Value {
        serde_json::to_value(&self.config).unwrap_or(Value::Null)
    }
}

/// The base64 DER of every certificate, `,` separated.
fn pem_value(chain: &[CertificateDer<'_>]) -> String {
    let mut out = String::new();
    for (index, cert) in chain.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        STANDARD.encode_string(cert, &mut out);
    }
    out
}

/// The info header value: the selected fields of every certificate, URL-escaped. Empty when
/// nothing selected exists in any certificate.
fn info_value(info: &Info, chain: &[CertificateDer<'_>]) -> String {
    let mut plain = String::new();
    let mut any = false;
    for (index, der) in chain.iter().enumerate() {
        if index > 0 {
            plain.push(',');
        }
        let before = plain.len();
        if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
            cert_fields(info, &cert, &mut plain);
        }
        any |= plain.len() > before;
    }
    if any {
        query_escape(&plain)
    } else {
        String::new()
    }
}

/// Appends `Name="value"` to `out`, `;` after a field already there.
struct Fields<'a> {
    out: &'a mut String,
    started: bool,
}

impl Fields<'_> {
    fn add(&mut self, name: &str, value: &str) {
        if self.started {
            self.out.push(';');
        }
        self.started = true;
        self.out.push_str(name);
        self.out.push_str("=\"");
        for c in value.chars() {
            match c {
                '"' | '\\' => {
                    self.out.push('\\');
                    self.out.push(c);
                }
                c if c.is_control() => self.out.push('?'),
                c => self.out.push(c),
            }
        }
        self.out.push('"');
    }
}

fn cert_fields(info: &Info, cert: &X509Certificate<'_>, out: &mut String) {
    let mut fields = Fields {
        out,
        started: false,
    };
    if let Some(subject) = info.subject {
        let subject = dn(subject.attributes(), cert.subject());
        if !subject.is_empty() {
            fields.add("Subject", &subject);
        }
    }
    if let Some(issuer) = info.issuer {
        let issuer = dn(issuer.attributes(), cert.issuer());
        if !issuer.is_empty() {
            fields.add("Issuer", &issuer);
        }
    }
    if info.serial_number {
        fields.add("SerialNumber", &cert.serial.to_string());
    }
    let validity = cert.validity();
    if info.not_before {
        fields.add("NB", &validity.not_before.timestamp().to_string());
    }
    if info.not_after {
        fields.add("NA", &validity.not_after.timestamp().to_string());
    }
    if info.sans {
        let sans = sans(cert);
        if !sans.is_empty() {
            fields.add("SAN", &sans);
        }
    }
}

/// The selected attributes of `name` as `KEY=value`, `,` separated, in the order of
/// `attributes`. An attribute that is not a string is left out.
fn dn(attributes: [Attribute; 8], name: &X509Name<'_>) -> String {
    let mut out = String::new();
    for (selected, oid, key) in attributes {
        if !selected {
            continue;
        }
        for attribute in name.iter_by_oid(oid) {
            let Ok(value) = attribute.as_str() else {
                continue;
            };
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(key);
            out.push('=');
            out.push_str(value);
        }
    }
    out
}

/// DNS names, e-mail addresses, IP addresses, then URIs, `,` separated.
fn sans(cert: &X509Certificate<'_>) -> String {
    let Ok(Some(extension)) = cert.subject_alternative_name() else {
        return String::new();
    };
    let names = &extension.value.general_names;
    let mut out = String::new();
    let mut push = |text: &str| {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(text);
    };
    for name in names {
        if let GeneralName::DNSName(dns) = name {
            push(dns);
        }
    }
    for name in names {
        if let GeneralName::RFC822Name(mail) = name {
            push(mail);
        }
    }
    for name in names {
        if let GeneralName::IPAddress(bytes) = name {
            if let Ok(octets) = <[u8; 4]>::try_from(*bytes) {
                push(&Ipv4Addr::from(octets).to_string());
            } else if let Ok(octets) = <[u8; 16]>::try_from(*bytes) {
                push(&Ipv6Addr::from(octets).to_string());
            }
        }
    }
    for name in names {
        if let GeneralName::URI(uri) = name {
            push(uri);
        }
    }
    out
}

/// Go's `url.QueryEscape`: letters, digits and `-_.~` stay, a space is `+`, every other byte is
/// `%XX`.
fn query_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 2);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use super::*;

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in headers {
            request
                .append_header(name.to_string(), *value)
                .expect("header");
        }
        request
    }

    fn compile(config: &Value, tls: &Value) -> Result<PassTlsClientCert, Invalid> {
        let mut declared = json!({ "name": "c", "type": "pass_tls_client_cert" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": tls,
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        PassTlsClientCert::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    #[test]
    fn strip_removes_the_whole_family_in_any_case_and_spelling() {
        let mut head = request(&[
            ("X-Forwarded-Tls-Client-Cert", "a"),
            ("x-forwarded-tls-client-cert-info", "b"),
            ("X-Forwarded-Tls-Client-Cert-Subject", "c"),
            ("x_forwarded_tls_client_cert", "d"),
            ("X_FORWARDED_TLS_CLIENT_CERT_INFO", "e"),
            ("x-forwarded-tls-client-cert", "second copy"),
            ("x-forwarded-tls-client", "kept"),
            ("x-forwarded-for", "kept"),
        ]);
        strip(&mut head);
        let mut left: Vec<_> = head.headers.keys().map(|name| name.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-forwarded-for", "x-forwarded-tls-client"]);
    }

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(
            query_escape("Subject=\"CN=a b\";x@y,/é~"),
            "Subject%3D%22CN%3Da+b%22%3Bx%40y%2C%2F%C3%A9~"
        );
    }

    #[test]
    fn a_field_value_cannot_end_its_own_field() {
        let mut out = String::new();
        let mut fields = Fields {
            out: &mut out,
            started: false,
        };
        fields.add("Subject", "CN=x\";SAN=\"admin\\\r\n");
        assert_eq!(out, "Subject=\"CN=x\\\";SAN=\\\"admin\\\\??\"");
    }

    #[test]
    fn compile_needs_a_selection_and_a_verifying_app() {
        let verifying = json!({ "mode": "acme", "client_ca_pem": "x" });
        assert!(compile(&json!({ "pem": true }), &verifying).is_ok());
        assert!(compile(&json!({ "info": { "sans": true } }), &verifying).is_ok());
        for (config, tls) in [
            (json!({}), &verifying),
            (json!({ "pem": false, "info": {} }), &verifying),
            (json!({ "info": { "subject": {} } }), &verifying),
            (json!({ "pem": true }), &json!({ "mode": "acme" })),
            (json!({ "pem": true, "oops": 1 }), &verifying),
            (
                json!({ "info": { "issuer": { "organizational_unit": true } } }),
                &verifying,
            ),
        ] {
            let err = compile(&config, tls).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}: {err:?}");
        }
    }
}
