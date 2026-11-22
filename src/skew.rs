//! Skew protection: a browser session stays on the revision that served its first request.
//!
//! During a rollout two revisions of an app serve at once. A page loaded from one must fetch its
//! assets and API from that same revision, or the old page calls endpoints the new code changed.
//! The first response carries the cookie `__podgate_rev`; later requests that present it go to the
//! revision it names while that revision is `serving` or `retiring`. A `draining` or removed
//! revision, a cookie of another app and a tampered cookie are all ignored: the request is routed
//! by weight and gets a fresh cookie.
//!
//! The cookie value is `base64url(len(app) || app || revision || mac)` with
//! `mac = HMAC-SHA256(skew_secret, len(app) || app || revision)`. The key is the snapshot's
//! `skew_secret`, so every node accepts every node's cookie. The app id is signed, so a cookie
//! never pins a request of another app. Verification is constant-time. Without a `skew_secret`
//! the feature is off: no cookie is read or set.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use podgate_model::SkewSecret;
use sha2::Sha256;

use crate::cache::policy::shared_cacheable;
use crate::route::Selected;
use crate::service::PickCx;
use crate::table::{CompiledApp, Pick, RoutingTable};

/// Name of the session cookie.
pub const COOKIE_NAME: &str = "__podgate_rev";

/// Longest cookie value read; anything longer is not ours.
const MAX_TOKEN_LEN: usize = 1024;
const MAC_LEN: usize = 32;
const LEN_PREFIX: usize = 2;

type HmacSha256 = Hmac<Sha256>;

/// An HMAC over `payload` keyed with `secret`. `None` only if the HMAC rejects the key, which it
/// does for no length.
fn mac(secret: &SkewSecret, payload: &[u8]) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload);
    Some(mac)
}

/// `len(app) || app || revision`: what the MAC covers and the cookie carries.
fn payload(app: &str, revision: &str) -> Option<Vec<u8>> {
    let len = u16::try_from(app.len()).ok()?;
    let mut payload = Vec::with_capacity(LEN_PREFIX + app.len() + revision.len() + MAC_LEN);
    payload.extend_from_slice(&len.to_be_bytes());
    payload.extend_from_slice(app.as_bytes());
    payload.extend_from_slice(revision.as_bytes());
    Some(payload)
}

/// The signed cookie value pinning a session to `app`/`revision`.
fn sign(secret: &SkewSecret, app: &str, revision: &str) -> Option<String> {
    let mut bytes = payload(app, revision)?;
    let tag = mac(secret, &bytes)?.finalize().into_bytes();
    bytes.extend_from_slice(&tag);
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

/// The revision a cookie `value` pins to for `app`, when the MAC verifies and the cookie is for
/// that app.
fn verify(secret: &SkewSecret, value: &str, app: &str) -> Option<String> {
    if value.len() > MAX_TOKEN_LEN {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    let (payload, tag) = bytes.split_at_checked(bytes.len().checked_sub(MAC_LEN)?)?;
    mac(secret, payload)?.verify_slice(tag).ok()?;
    let (len, rest) = payload.split_at_checked(LEN_PREFIX)?;
    let app_len = usize::from(u16::from_be_bytes([*len.first()?, *len.get(1)?]));
    let (signed_app, revision) = rest.split_at_checked(app_len)?;
    if signed_app != app.as_bytes() {
        return None;
    }
    String::from_utf8(revision.to_vec()).ok()
}

/// The values of every `__podgate_rev` cookie the request carries.
fn cookie_values(request: &RequestHeader) -> impl Iterator<Item = &str> {
    request
        .headers
        .get_all("cookie")
        .into_iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|pair| pair.trim().strip_prefix(COOKIE_NAME)?.strip_prefix('='))
}

/// The pick a valid session cookie dictates for `app` and its router `router`, or `None` for
/// normal routing: the feature is off, there is no cookie, it does not verify or names another
/// app, or its revision is `draining`, gone or without a backend.
#[must_use]
pub fn pinned(
    table: &RoutingTable,
    app: &CompiledApp,
    router: usize,
    cx: PickCx<'_>,
) -> Option<Pick> {
    let secret = table.skew_secret()?;
    cookie_values(cx.request)
        .filter_map(|value| verify(secret, value, app.id()))
        .find_map(|revision| app.pick_pinned(router, &revision, cx))
}

/// Pins the session to the revision that served this request, unless the request already was
/// pinned to it. A no-op without a `skew_secret` or a route, and for a response that shared
/// caches may store (`cache::policy::shared_cacheable`): a cache in front of podgate would replay the
/// cookie to every visitor. The request stays unpinned and the next uncacheable response pins
/// it. The cookie is `Secure` on TLS connections.
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
    let Some(selected) = selected.filter(|selected| !selected.pinned) else {
        return Ok(());
    };
    // The cheap test first: nearly every snapshot has no secret, and `shared_cacheable` parses
    // the response's `Cache-Control`.
    let Some(secret) = table.skew_secret() else {
        return Ok(());
    };
    if shared_cacheable(&response.headers) {
        return Ok(());
    }
    let Some(app) = table.app(selected.app) else {
        return Ok(());
    };
    let Some(revision) = app.revisions().get(selected.revision) else {
        return Ok(());
    };
    let Some(value) = sign(secret, app.id(), revision.id()) else {
        return Ok(());
    };
    let secure = if session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some())
    {
        "; Secure"
    } else {
        ""
    };
    response.append_header(
        "set-cookie",
        format!("{COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax{secure}"),
    )?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn secret() -> SkewSecret {
        SkewSecret::new("0123456789abcdef")
    }

    #[test]
    fn signed_value_verifies_for_its_app_only() {
        let value = sign(&secret(), "app", "r1").expect("signs");
        assert_eq!(verify(&secret(), &value, "app").as_deref(), Some("r1"));
        assert_eq!(verify(&secret(), &value, "other"), None);
    }

    #[test]
    fn a_flipped_bit_or_another_key_is_refused() {
        let value = sign(&secret(), "app", "r1").expect("signs");
        let mut bytes = URL_SAFE_NO_PAD.decode(&value).expect("base64url");
        bytes[LEN_PREFIX + 3] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(bytes);
        assert_eq!(verify(&secret(), &tampered, "app"), None);
        let other = SkewSecret::new("fedcba9876543210");
        assert_eq!(verify(&other, &value, "app"), None);
        assert_eq!(verify(&secret(), "", "app"), None);
        assert_eq!(verify(&secret(), "!!!", "app"), None);
    }

    #[test]
    fn short_secrets_are_flagged_and_debug_hides_the_secret() {
        assert!(!SkewSecret::new("short").is_long_enough());
        assert!(secret().is_long_enough());
        assert!(!format!("{:?}", secret()).contains("0123456789abcdef"));
    }

    #[test]
    fn cookie_values_reads_every_cookie_header() {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .append_header("cookie", "a=1; __podgate_rev=one")
            .expect("header");
        request
            .append_header("cookie", "__podgate_rev=two; __podgate_rev_x=3")
            .expect("header");
        assert_eq!(cookie_values(&request).collect::<Vec<_>>(), ["one", "two"]);
    }
}
