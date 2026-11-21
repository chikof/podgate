//! `serversTransports`: how podgate reaches the servers of a service, as `servers_transport`
//! objects (`docs/ref/transports.md`).

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::files::{self, Unit};
use super::obj::{Cx, Obj};

fn declared(name: &str, config: Map<String, Value>) -> Declared {
    Declared {
        name: name.into(),
        kind: "servers_transport".into(),
        config,
    }
}

/// `http.serversTransports.<name>`.
pub(super) fn http(cx: &Cx, name: &str, value: &Value) -> Option<Declared> {
    let mark = cx.mark();
    let mut obj = Obj::new(cx, format!("http.serversTransports.{name}"), value)?;
    let mut config = Map::new();
    tls_fields(&mut obj, &mut config);
    obj.refuse(
        "maxIdleConnsPerHost",
        "podgate's pool is per upstream and has no per-host cap",
    );
    if obj.boolean("disableHTTP2") == Some(true) {
        config.insert("http2".into(), Value::Bool(false));
    }
    if let Some(mut timeouts) = obj.child("forwardingTimeouts") {
        if let Some(dial) = positive(&mut timeouts, "dialTimeout") {
            config.insert("dial_timeout_secs".into(), json!(dial));
        }
        if let Some(idle) = positive(&mut timeouts, "idleConnTimeout") {
            config.insert("idle_timeout_secs".into(), json!(idle));
        }
        if files::duration(&mut timeouts, "responseHeaderTimeout", Unit::Seconds)
            .is_some_and(|seconds| seconds != 0)
        {
            timeouts.unsupported(
                "responseHeaderTimeout",
                "podgate's read timeout also bounds every read of the body, which Traefik's does not; set `read_timeout_secs` in a podgate transport if that is what you want",
            );
        }
        timeouts.finish();
    }
    obj.finish();
    cx.clean_since(mark).then(|| declared(name, config))
}

/// `tcp.serversTransports.<name>`.
pub(super) fn tcp(cx: &Cx, name: &str, value: &Value) -> Option<Declared> {
    let mark = cx.mark();
    let mut obj = Obj::new(cx, format!("tcp.serversTransports.{name}"), value)?;
    let mut config = Map::new();
    if let Some(dial) = positive(&mut obj, "dialTimeout") {
        config.insert("dial_timeout_secs".into(), json!(dial));
    }
    obj.refuse_if_set(
        "dialKeepAlive",
        "podgate does not set TCP keep-alive per transport",
    );
    obj.refuse_if_set(
        "terminationDelay",
        "set `termination_delay_ms` on the TCP service instead",
    );
    if let Some(mut tls) = obj.child("tls") {
        tls_fields(&mut tls, &mut config);
        tls.finish();
    }
    obj.finish();
    cx.clean_since(mark).then(|| declared(name, config))
}

/// A duration that is at least one second: Traefik reads zero as "no timeout", which podgate
/// does not have for a dial or an idle connection.
fn positive(obj: &mut Obj<'_>, key: &str) -> Option<u64> {
    match files::duration(obj, key, Unit::Seconds)? {
        0 => {
            obj.unsupported(
                key,
                "zero means no timeout in Traefik, and podgate always bounds it",
            );
            None
        }
        seconds => Some(seconds),
    }
}

/// `serverName`, `insecureSkipVerify`, `rootCAs`, `certificates` and what podgate cannot do.
fn tls_fields(obj: &mut Obj<'_>, config: &mut Map<String, Value>) {
    if let Some(name) = obj.text("serverName") {
        config.insert("server_name".into(), json!(name));
    }
    if let Some(skip) = obj.boolean("insecureSkipVerify") {
        config.insert("insecure_skip_verify".into(), json!(skip));
    }
    if let Some(roots) = obj.texts("rootCAs") {
        let at = obj.path_of("rootCAs");
        let mut bundle = String::new();
        for (index, root) in roots.iter().enumerate() {
            if let Some(pem) = files::pem_or_path(obj.cx(), &format!("{at}[{index}]"), root) {
                bundle.push_str(&pem);
                if !pem.ends_with('\n') {
                    bundle.push('\n');
                }
            }
        }
        if !bundle.is_empty() {
            config.insert("ca_pem".into(), json!(bundle));
        }
    }
    if let Some(certificates) = obj.children("certificates") {
        match certificates.len() {
            0 => {}
            1 => {
                if let Some(pair) = pair_of(certificates) {
                    config.insert("client_cert".into(), pair);
                }
            }
            _ => obj.unsupported(
                "certificates",
                "podgate presents one client certificate per transport; Traefik picks the one the server accepts",
            ),
        }
    }
    obj.refuse(
        "peerCertURI",
        "podgate verifies the server certificate by name, not by URI",
    );
    obj.refuse_if_set("spiffe", "SPIFFE identities are not translated");
}

/// The `{cert_pem, key_pem}` of the one `{certFile, keyFile}` in `certificates`.
fn pair_of(mut certificates: Vec<Obj<'_>>) -> Option<Value> {
    let mut entry = certificates.pop()?;
    let cert = pem_of(&mut entry, "certFile");
    let key = pem_of(&mut entry, "keyFile");
    entry.finish();
    Some(json!({ "cert_pem": cert?, "key_pem": key? }))
}

/// The PEM of `{key}`, a path or the content, required.
pub(super) fn pem_of(obj: &mut Obj<'_>, key: &str) -> Option<String> {
    let at = obj.path_of(key);
    let Some(spec) = obj.text(key) else {
        if !obj.has(key) {
            obj.invalid(key, "is required");
        }
        return None;
    };
    files::pem_or_path(obj.cx(), &at, spec)
}
