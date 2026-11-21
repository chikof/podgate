//! The `tls` section: certificates, the default certificate and the options.
//!
//! Certificates are read from disk and inlined: the daemon keeps no disk state. Their hosts are
//! the names in the certificate, which is how Traefik picks one. Options are per app in podgate
//! (`docs/ref/tls-options.md`), so the caller chooses which of them the app gets.

use std::collections::BTreeMap;

use podgate_model::Certificate;
use serde_json::{Map, Value, json};

use super::files;
use super::obj::{Cx, Obj};
use super::transport::pem_of;

/// What the `tls` section says.
#[derive(Default)]
pub(super) struct Tls {
    pub(super) certificates: Vec<Certificate>,
    /// The options by name, `None` for one that did not translate. Each is a patch of the app's
    /// `tls` object.
    pub(super) options: BTreeMap<String, Option<Map<String, Value>>>,
}

pub(super) fn build(cx: &Cx, section: Option<&Value>) -> Tls {
    let mut out = Tls::default();
    let Some(section) = section else {
        return out;
    };
    let Some(mut tls) = Obj::new(cx, "tls".to_owned(), section) else {
        return out;
    };
    if let Some(entries) = tls.children("certificates") {
        for mut entry in entries {
            let mark = cx.mark();
            let cert = file_of(&mut entry, "certFile");
            let key = file_of(&mut entry, "keyFile");
            if let Some(stores) = entry.texts("stores")
                && stores.iter().any(|store| *store != "default")
            {
                entry.unsupported("stores", "podgate has one certificate store, `default`");
            }
            let at = entry.path().to_owned();
            entry.finish();
            if cx.clean_since(mark)
                && let (Some(cert), Some(key)) = (cert, key)
                && let Some(certificate) = certificate(cx, &at, &cert, &key, false)
            {
                out.certificates.push(certificate);
            }
        }
    }
    for (name, value) in tls.named("stores") {
        let at = format!("tls.stores.{name}");
        let Some(mut store) = Obj::new(cx, at.clone(), value) else {
            continue;
        };
        if name != "default" {
            cx.unsupported(&at, "podgate has one certificate store, `default`");
            continue;
        }
        let mark = cx.mark();
        let pair = store.child("defaultCertificate").map(|mut default| {
            let cert = file_of(&mut default, "certFile");
            let key = file_of(&mut default, "keyFile");
            let path = default.path().to_owned();
            default.finish();
            (path, cert, key)
        });
        store.refuse_if_set(
            "defaultGeneratedCert",
            "podgate does not generate a default certificate",
        );
        store.finish();
        if cx.clean_since(mark)
            && let Some((path, Some(cert), Some(key))) = pair
            && let Some(certificate) = certificate(cx, &path, &cert, &key, true)
        {
            out.certificates.push(certificate);
        }
    }
    for (name, value) in tls.named("options") {
        out.options.insert(
            name.to_owned(),
            option(cx, &format!("tls.options.{name}"), value),
        );
    }
    tls.finish();
    out
}

/// The PEM of a `certFile` or `keyFile`.
fn file_of(obj: &mut Obj<'_>, key: &str) -> Option<String> {
    pem_of(obj, key)
}

fn certificate(cx: &Cx, at: &str, cert: &str, key: &str, default: bool) -> Option<Certificate> {
    let hosts = files::hosts_of(cx, at, cert)?;
    let mut object = json!({ "hosts": hosts, "cert_pem": cert, "key_pem": key });
    if default {
        object["default"] = json!(true);
    }
    match serde_json::from_value(object) {
        Ok(certificate) => Some(certificate),
        Err(err) => {
            cx.invalid(at, err.to_string());
            None
        }
    }
}

/// One of `tls.options`, as a patch of the app's `tls` object.
fn option(cx: &Cx, at: &str, value: &Value) -> Option<Map<String, Value>> {
    let mark = cx.mark();
    let mut obj = Obj::new(cx, at.to_owned(), value)?;
    let mut patch = Map::new();
    match obj.text("minVersion") {
        None => {}
        Some("VersionTLS12") => {
            patch.insert("min_version".into(), json!("1.2"));
        }
        Some("VersionTLS13") => {
            patch.insert("min_version".into(), json!("1.3"));
        }
        Some(_) => obj.unsupported("minVersion", "podgate serves TLS 1.2 and 1.3 only"),
    }
    // TLS 1.3 is the highest version there is, so capping at it caps nothing.
    match obj.text("maxVersion") {
        None | Some("VersionTLS13") => {}
        Some(_) => obj.unsupported(
            "maxVersion",
            "a version cap only helps downgrade attacks, and podgate has none",
        ),
    }
    if let Some(suites) = obj.texts("cipherSuites") {
        patch.insert("cipher_suites".into(), json!(suites));
    }
    obj.refuse_if_set(
        "curvePreferences",
        "key exchange groups are set for the listener, not per app",
    );
    if let Some(strict) = obj.boolean("sniStrict") {
        patch.insert("sni_strict".into(), json!(strict));
    }
    if let Some(protocols) = obj.texts("alpnProtocols") {
        patch.insert("alpn".into(), json!(protocols));
    }
    obj.refuse_if_set(
        "disableSessionTickets",
        "session tickets are set for the listener, not per app",
    );
    // Deprecated in Traefik, and without effect there.
    obj.value("preferServerCipherSuites");
    if let Some(mut auth) = obj.child("clientAuth") {
        client_auth(&mut auth, &mut patch);
        auth.finish();
    }
    obj.finish();
    cx.clean_since(mark).then_some(patch)
}

fn client_auth(auth: &mut Obj<'_>, patch: &mut Map<String, Value>) {
    let at = auth.path_of("caFiles");
    let mut bundle = String::new();
    for (index, spec) in auth
        .texts("caFiles")
        .unwrap_or_default()
        .into_iter()
        .enumerate()
    {
        if let Some(pem) = files::pem_or_path(auth.cx(), &format!("{at}[{index}]"), spec) {
            bundle.push_str(&pem);
            if !pem.ends_with('\n') {
                bundle.push('\n');
            }
        }
    }
    let mode = match auth.text("clientAuthType") {
        None | Some("NoClientCert") => None,
        Some("RequestClientCert") => Some("request"),
        Some("RequireAnyClientCert") => Some("require"),
        Some("VerifyClientCertIfGiven") => Some("verify_if_given"),
        Some("RequireAndVerifyClientCert") => Some("require_and_verify"),
        Some(_) => {
            auth.invalid(
                "clientAuthType",
                "is not a Traefik client authentication type",
            );
            return;
        }
    };
    let Some(mode) = mode else {
        return;
    };
    patch.insert("client_auth".into(), json!(mode));
    // `request` and `require` do not judge the chain, so a CA means nothing there.
    if matches!(mode, "verify_if_given" | "require_and_verify") {
        if bundle.is_empty() {
            auth.invalid("caFiles", "is required to verify client certificates");
        } else {
            patch.insert("client_ca_pem".into(), json!(bundle));
        }
    }
}
