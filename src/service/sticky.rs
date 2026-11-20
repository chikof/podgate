//! Sticky sessions: a cookie that keeps a client on one server of a `loadbalancer`.
//!
//! ```json
//! "sticky": { "cookie": { "name": "__podgate_srv", "same_site": "lax", "max_age_secs": 3600 } }
//! ```
//!
//! # The cookie
//!
//! The value is `base64url(HMAC-SHA256(skew_secret, "podgate/sticky/v1" || len(app) || app ||
//! len(service) || service || server_url)[..16])`, `len` being two bytes, big-endian: 22
//! characters that name no address and that a client cannot compute for a server it was not
//! given. The label separates it from the revision cookie (`skew.rs`), which the same secret
//! signs, so neither cookie can stand in for the other. The tag covers the app and the service,
//! so a cookie of another app or service pins nothing.
//!
//! # Pinning
//!
//! `Sticky::pinned` runs inside the load balancer's `pick`, before the algorithm: it
//! recomputes the tag of each of the service's servers (at most 256) and takes the server whose
//! tag the cookie carries, if that server [`PickCx::allows`] the request (healthy, not ejected,
//! not already tried, not weight `0`). Otherwise the algorithm picks, and [`set_cookie`] answers
//! with a cookie for the server that was chosen. A request that already carries the cookie of
//! the chosen server gets no new `Set-Cookie`.
//!
//! Without a `skew_secret` there is no key: the snapshot is refused (`invalid_service`) when it
//! binds the secret (`Sticky::bind`, called by the compiler for every service). A response
//! that is `Cache-Control: public` never carries the cookie, because a shared cache would hand
//! one client's pin to everyone.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use podgate_model::SkewSecret;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;

use super::{PickCx, Server};
use crate::compile::Invalid;
use crate::route::Selected;
use crate::table::RoutingTable;

type HmacSha256 = Hmac<Sha256>;

/// Name of the cookie when the configuration gives none.
pub const DEFAULT_NAME: &str = "__podgate_srv";

/// The name of the revision cookie of skew protection, which a sticky cookie must not take.
const REVISION_COOKIE: &str = "__podgate_rev";

const LABEL: &[u8] = b"podgate/sticky/v1";
/// Bytes of the HMAC kept in the cookie.
const TAG_LEN: usize = 16;
/// Characters of `TAG_LEN` bytes in unpadded base64.
const ENCODED_LEN: usize = 22;

/// `sticky` as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    cookie: CookieConfig,
}

/// `sticky.cookie` as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CookieConfig {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    secure: Option<bool>,
    #[serde(default)]
    http_only: Option<bool>,
    #[serde(default)]
    same_site: Option<String>,
    #[serde(default)]
    max_age_secs: Option<u64>,
    #[serde(default)]
    path: Option<String>,
}

/// A compiled `sticky` setting: the cookie's name and attributes, and once bound the keyed HMAC
/// state that derives its values.
pub struct Sticky {
    name: Box<str>,
    /// Everything after the value except `Secure`: `; Path=/; HttpOnly; SameSite=Lax`.
    attributes: Box<str>,
    /// Whether `Secure` is always set; otherwise it is set on TLS connections.
    secure: bool,
    /// The HMAC with the key, the label, the app and the service absorbed; `None` until bound.
    key: Option<HmacSha256>,
}

impl fmt::Debug for Sticky {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sticky")
            .field("name", &self.name)
            .field("attributes", &self.attributes)
            .field("secure", &self.secure)
            .field("bound", &self.key.is_some())
            .finish()
    }
}

fn invalid(why: impl fmt::Display) -> Invalid {
    Invalid::new("invalid_service", format!("sticky: {why}"))
}

/// Whether `name` is a cookie name: a non-empty HTTP token.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

impl Sticky {
    /// Compiles the declared `sticky` value.
    ///
    /// # Errors
    ///
    /// `invalid_service` for an unknown field, a cookie name that is not a token or that is the
    /// revision cookie's, a `same_site` other than `lax`, `strict` or `none`, `none` without
    /// `secure: true`, a `max_age_secs` of `0`, or a `path` that is not an absolute path free of
    /// spaces, `;` and control characters.
    pub(super) fn compile(declared: &Value) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(declared.clone()).map_err(invalid)?;
        let cookie = config.cookie;
        let name = cookie.name.unwrap_or_else(|| DEFAULT_NAME.to_owned());
        if !is_token(&name) {
            return Err(invalid(format!(
                "cookie name {name:?} is not a cookie name"
            )));
        }
        if name == REVISION_COOKIE {
            return Err(invalid(format!(
                "cookie name {name} is the skew protection cookie"
            )));
        }
        let secure = cookie.secure == Some(true);
        let same_site = match cookie
            .same_site
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("lax") => "Lax",
            Some("strict") => "Strict",
            Some("none") if secure => "None",
            Some("none") => {
                return Err(invalid(
                    "same_site none needs secure: true, browsers drop it otherwise",
                ));
            }
            Some(other) => {
                return Err(invalid(format!(
                    "same_site {other:?} is none of lax, strict, none"
                )));
            }
        };
        let path = cookie.path.unwrap_or_else(|| "/".to_owned());
        if !path.starts_with('/')
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b';')
        {
            return Err(invalid(format!("path {path:?} is not an absolute path")));
        }
        let mut attributes = format!("; Path={path}");
        if cookie.http_only != Some(false) {
            attributes.push_str("; HttpOnly");
        }
        attributes.push_str("; SameSite=");
        attributes.push_str(same_site);
        match cookie.max_age_secs {
            Some(0) => return Err(invalid("max_age_secs must be above 0")),
            Some(seconds) => attributes.push_str(&format!("; Max-Age={seconds}")),
            None => {}
        }
        Ok(Self {
            name: name.into(),
            attributes: attributes.into(),
            secure,
            key: None,
        })
    }

    /// Keys the cookie for `service` of `app` with the snapshot's `secret`.
    ///
    /// # Errors
    ///
    /// `invalid_service` when the snapshot has no `skew_secret`.
    pub(super) fn bind(
        &mut self,
        secret: Option<&SkewSecret>,
        app: &str,
        service: &str,
    ) -> Result<(), Invalid> {
        let secret = secret.ok_or_else(|| invalid("needs the snapshot's skew_secret"))?;
        let (Ok(app_len), Ok(service_len)) =
            (u16::try_from(app.len()), u16::try_from(service.len()))
        else {
            return Err(invalid("app or service name is too long"));
        };
        let mut key = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| invalid("skew_secret cannot key the cookie"))?;
        key.update(LABEL);
        key.update(&app_len.to_be_bytes());
        key.update(app.as_bytes());
        key.update(&service_len.to_be_bytes());
        key.update(service.as_bytes());
        self.key = Some(key);
        Ok(())
    }

    /// The cookie's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The index in `servers` of the server the request's cookie pins it to, when that server
    /// may take the request. `None` (the algorithm picks) when the service is not bound, there
    /// is no cookie, no server has its tag, or the pinned one is unavailable, tried or without
    /// weight.
    #[must_use]
    pub(super) fn pinned(&self, cx: PickCx<'_>, servers: &[Server]) -> Option<usize> {
        let key = self.key.as_ref()?;
        for value in cookie_values(cx.request, &self.name) {
            let Some(tag) = decode(value) else { continue };
            let found = servers.iter().position(|server| {
                let mac = keyed_for(key, server);
                mac.verify_truncated_left(&tag).is_ok() && cx.allows(server) && server.weight > 0
            });
            if found.is_some() {
                return found;
            }
        }
        None
    }

    /// The `Set-Cookie` value that pins to `server`, or `None` when the service is not bound or
    /// `request` already carries that cookie. `tls` adds `Secure`.
    fn header(&self, request: &RequestHeader, server: &Server, tls: bool) -> Option<String> {
        let mac = keyed_for(self.key.as_ref()?, server);
        let tag = mac.finalize().into_bytes();
        let value = URL_SAFE_NO_PAD.encode(tag.get(..TAG_LEN)?);
        if cookie_values(request, &self.name).any(|presented| presented == value) {
            return None;
        }
        let secure = if self.secure || tls { "; Secure" } else { "" };
        Some(format!("{}={value}{}{secure}", self.name, self.attributes))
    }
}

/// The MAC keyed for `server`: its URL, and for a server named by DNS its address too, since
/// every address of a name has the same URL.
fn keyed_for(key: &HmacSha256, server: &Server) -> HmacSha256 {
    let mut mac = key.clone();
    mac.update(server.url.as_bytes());
    if server.host().is_some() {
        match server.addr.ip() {
            std::net::IpAddr::V4(ip) => mac.update(&ip.octets()),
            std::net::IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(&server.addr.port().to_be_bytes());
    }
    mac
}

/// The values of every cookie called `name` the request carries.
fn cookie_values<'a>(request: &'a RequestHeader, name: &'a str) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .get_all("cookie")
        .into_iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(move |pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

/// The tag a cookie value carries; `None` unless it is exactly the 16 bytes in canonical
/// unpadded base64url.
fn decode(value: &str) -> Option<[u8; TAG_LEN]> {
    if value.len() != ENCODED_LEN {
        return None;
    }
    let mut room = [0_u8; TAG_LEN + 2];
    let written = URL_SAFE_NO_PAD.decode_slice(value, &mut room).ok()?;
    let mut tag = [0_u8; TAG_LEN];
    tag.copy_from_slice(room.get(..written).filter(|bytes| bytes.len() == TAG_LEN)?);
    Some(tag)
}

/// Whether the response lets shared caches store it (`Cache-Control: public`).
fn publicly_cacheable(response: &ResponseHeader) -> bool {
    response
        .headers
        .get_all("cache-control")
        .into_iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("public"))
}

/// Pins the client to the server that answered, when the routed service is sticky and the
/// request did not already carry that pin. A no-op without a route, on a service that is not
/// sticky and on a `Cache-Control: public` response. The cookie is `Secure` on TLS connections.
///
/// # Errors
///
/// Fails when the response header cannot take another `Set-Cookie`.
pub fn set_cookie(
    session: &Session,
    table: &RoutingTable,
    selected: Option<&Selected>,
    response: &mut ResponseHeader,
) -> pingora::Result<()> {
    let Some(selected) = selected else {
        return Ok(());
    };
    let Some(service) = table
        .app(selected.app)
        .and_then(|app| app.service(selected.revision, selected.router))
    else {
        return Ok(());
    };
    let Some(sticky) = service.sticky() else {
        return Ok(());
    };
    if publicly_cacheable(response) {
        return Ok(());
    }
    let servers = service.servers();
    let Some(server) = servers
        .iter()
        .find(|server| server.addr == selected.upstream)
    else {
        return Ok(());
    };
    let tls = session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some());
    if let Some(value) = sticky.header(session.req_header(), server, tls) {
        response.append_header("set-cookie", value)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::service::ServerState;

    fn secret() -> SkewSecret {
        SkewSecret::new("0123456789abcdef")
    }

    fn bound(declared: &Value) -> Sticky {
        let mut sticky = Sticky::compile(declared).expect("compiles");
        sticky.bind(Some(&secret()), "app", "web").expect("binds");
        sticky
    }

    fn server(url: &str) -> Server {
        Server {
            url: url.into(),
            addr: url
                .trim_start_matches("http://")
                .parse()
                .expect("socket address"),
            tls: false,
            h2c: false,
            weight: 1,
            state: Arc::new(ServerState::default()),
        }
    }

    fn request(cookie: Option<&str>) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        if let Some(cookie) = cookie {
            request.insert_header("cookie", cookie).expect("header");
        }
        request
    }

    /// The cookie value `sticky` issues for `server`.
    fn issued(sticky: &Sticky, server: &Server) -> String {
        let header = sticky
            .header(&request(None), server, false)
            .expect("a header");
        let (pair, _) = header.split_once(';').expect("attributes");
        pair.strip_prefix(&format!("{}=", sticky.name()))
            .expect("named")
            .to_owned()
    }

    #[test]
    fn sticky_cookie_value_is_short_opaque_and_stable() {
        let sticky = bound(&json!({ "cookie": {} }));
        let one = server("http://10.1.2.3:8080");
        let value = issued(&sticky, &one);
        assert_eq!(value.len(), ENCODED_LEN);
        assert!(!value.contains("10.1.2.3") && !value.contains("8080"));
        assert_eq!(issued(&sticky, &one), value);
        assert_ne!(issued(&sticky, &server("http://10.1.2.3:8081")), value);
    }

    #[test]
    fn sticky_cookie_pins_to_the_server_it_names() {
        let sticky = bound(&json!({ "cookie": {} }));
        let servers = [server("http://127.0.0.1:1"), server("http://127.0.0.1:2")];
        let value = issued(&sticky, &servers[1]);
        let pinned = request(Some(&format!("a=b; __podgate_srv={value}")));
        assert_eq!(sticky.pinned(PickCx::new(&pinned), &servers), Some(1));
        assert_eq!(sticky.pinned(PickCx::new(&request(None)), &servers), None);
    }

    #[test]
    fn sticky_cookie_of_another_app_or_service_or_key_pins_nothing() {
        let servers = [server("http://127.0.0.1:1")];
        let value = issued(&bound(&json!({ "cookie": {} })), &servers[0]);
        let presented = request(Some(&format!("__podgate_srv={value}")));
        for (app, service, secret) in [
            ("other", "web", secret()),
            ("app", "api", secret()),
            ("app", "web", SkewSecret::new("fedcba9876543210")),
        ] {
            let mut sticky = Sticky::compile(&json!({ "cookie": {} })).expect("compiles");
            sticky.bind(Some(&secret), app, service).expect("binds");
            assert_eq!(sticky.pinned(PickCx::new(&presented), &servers), None);
        }
    }

    #[test]
    fn sticky_tampered_values_are_ignored() {
        let sticky = bound(&json!({ "cookie": {} }));
        let servers = [server("http://127.0.0.1:1")];
        let value = issued(&sticky, &servers[0]);
        let mut flipped = value.clone().into_bytes();
        flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
        let flipped = String::from_utf8(flipped).expect("ascii");
        for bad in [
            flipped.as_str(),
            "",
            "!!",
            &value[1..],
            &format!("{value}A"),
        ] {
            let presented = request(Some(&format!("__podgate_srv={bad}")));
            assert_eq!(
                sticky.pinned(PickCx::new(&presented), &servers),
                None,
                "{bad}"
            );
        }
    }

    #[test]
    fn sticky_falls_back_and_repins_when_unavailable() {
        let sticky = bound(&json!({ "cookie": {} }));
        let servers = [server("http://127.0.0.1:1"), server("http://127.0.0.1:2")];
        let value = issued(&sticky, &servers[0]);
        let presented = request(Some(&format!("__podgate_srv={value}")));
        assert_eq!(sticky.pinned(PickCx::new(&presented), &servers), Some(0));

        servers[0]
            .state
            .healthy
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(sticky.pinned(PickCx::new(&presented), &servers), None);
        // The server the balancer chose instead gets a cookie, the old one is not repeated.
        assert!(sticky.header(&presented, &servers[1], false).is_some());
        servers[0]
            .state
            .healthy
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(sticky.header(&presented, &servers[0], false).is_none());

        let tried = [servers[0].addr];
        let cx = PickCx {
            request: &presented,
            excluded: &tried,
            client: None,
        };
        assert_eq!(sticky.pinned(cx, &servers), None, "a retry moves on");
        assert_eq!(sticky.pinned(cx, &servers[1..]), None);
        assert_eq!(sticky.pinned(PickCx::new(&presented), &servers[1..]), None);
    }

    #[test]
    fn sticky_skips_a_server_without_weight() {
        let sticky = bound(&json!({ "cookie": {} }));
        let mut servers = [server("http://127.0.0.1:1")];
        let presented = request(Some(&format!(
            "__podgate_srv={}",
            issued(&sticky, &servers[0])
        )));
        servers[0].weight = 0;
        assert_eq!(sticky.pinned(PickCx::new(&presented), &servers), None);
    }

    #[test]
    fn sticky_cookie_attributes() {
        let sticky = bound(&json!({ "cookie": {} }));
        let one = server("http://127.0.0.1:1");
        let plain = sticky.header(&request(None), &one, false).expect("header");
        assert!(
            plain.ends_with("; Path=/; HttpOnly; SameSite=Lax"),
            "{plain}"
        );
        let tls = sticky.header(&request(None), &one, true).expect("header");
        assert!(tls.ends_with("; SameSite=Lax; Secure"), "{tls}");

        let custom = bound(&json!({ "cookie": {
            "name": "pin", "secure": true, "http_only": false, "same_site": "None",
            "max_age_secs": 60, "path": "/app"
        } }));
        let header = custom.header(&request(None), &one, false).expect("header");
        assert!(header.starts_with("pin="), "{header}");
        assert!(
            header.ends_with("; Path=/app; SameSite=None; Max-Age=60; Secure"),
            "{header}"
        );
    }

    #[test]
    fn sticky_refuses_settings_that_would_be_ignored_or_unsafe() {
        for declared in [
            json!({}),
            json!({ "cookie": { "nome": "x" } }),
            json!({ "cookie": { "name": "a b" } }),
            json!({ "cookie": { "name": "" } }),
            json!({ "cookie": { "name": "__podgate_rev" } }),
            json!({ "cookie": { "same_site": "sideways" } }),
            json!({ "cookie": { "same_site": "none" } }),
            json!({ "cookie": { "max_age_secs": 0 } }),
            json!({ "cookie": { "path": "app" } }),
            json!({ "cookie": { "path": "/a; Domain=evil" } }),
        ] {
            let err = Sticky::compile(&declared).expect_err("refused");
            assert_eq!(err.code, "invalid_service", "{declared}");
        }
        let mut unbound = Sticky::compile(&json!({ "cookie": {} })).expect("compiles");
        let err = unbound.bind(None, "app", "web").expect_err("refused");
        assert_eq!(err.code, "invalid_service");
    }

    #[test]
    fn sticky_cache_rule_reads_every_cache_control_header() {
        let mut response = ResponseHeader::build(200, None).expect("response");
        assert!(!publicly_cacheable(&response));
        response
            .append_header("cache-control", "private, max-age=5")
            .expect("header");
        assert!(!publicly_cacheable(&response));
        response
            .append_header("cache-control", "max-age=60, Public")
            .expect("header");
        assert!(publicly_cacheable(&response));
    }
}
