//! The login flow of `oidc`: the one cookie that carries a login from the redirect to the
//! callback, the authorization URL, and the rule for where the browser goes afterwards.
//!
//! The flow cookie holds the `state` (128 random bits), the PKCE verifier (256 bits), the `nonce`
//! and the page the visitor asked for, sealed by [`super::session::Sealer`]. The identity
//! provider sees the `state`, the `nonce` and the S256 challenge of the verifier, never the
//! verifier: a code that is stolen on its way back cannot be redeemed without the cookie.
//! A second login started in another tab replaces the cookie, so the first of the two fails its
//! `state` check and the visitor starts again.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::session::{Sealer, random_token};
use crate::middleware::redirect::has_control;

/// How long the flow cookie lives: the time a visitor has to sign in at the provider.
pub(super) const FLOW_TTL_SECS: u64 = 300;

/// The longest path and query a login returns to; a longer one returns to `/`.
const MAX_NEXT: usize = 2000;

/// What a login keeps between the redirect and the callback.
#[derive(Serialize, Deserialize)]
pub(super) struct Flow {
    /// The `state`.
    s: String,
    /// The PKCE verifier.
    v: String,
    /// The `nonce`.
    n: String,
    /// The page the visitor asked for.
    next: String,
    /// When the cookie stops being valid, seconds since the epoch.
    exp: u64,
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Flow([redacted])")
    }
}

impl Flow {
    /// The PKCE verifier, sent to the token endpoint.
    pub(super) fn verifier(&self) -> &str {
        &self.v
    }

    /// The `nonce` the ID token must carry.
    pub(super) fn nonce(&self) -> &str {
        &self.n
    }

    /// Where to send the visitor now: the stored path and query when it is a relative path,
    /// `/` otherwise.
    pub(super) fn next(&self) -> &str {
        safe_target(&self.next)
    }
}

/// `target` when it is a path a redirect may name, `/` otherwise: it starts with exactly one
/// `/` (not `//`, which is a host, and not `/\`, which a browser reads as one), holds no control
/// character and is at most [`MAX_NEXT`] bytes. Nothing a client wrote becomes an absolute URL.
pub(super) fn safe_target(target: &str) -> &str {
    let relative = target.len() <= MAX_NEXT
        && target
            .strip_prefix('/')
            .is_some_and(|rest| !rest.starts_with(['/', '\\']))
        && !has_control(target);
    if relative { target } else { "/" }
}

/// The S256 challenge of a PKCE verifier.
pub(super) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

/// A login that has started.
#[derive(Debug)]
pub(super) struct Login {
    /// The value of the flow cookie.
    pub(super) cookie: String,
    /// The `state` to send.
    pub(super) state: String,
    /// The `nonce` to send.
    pub(super) nonce: String,
    /// The `code_challenge` to send.
    pub(super) challenge: String,
}

/// Starts a login at `now` for a visitor of `host` who asked for `next`. `None` without entropy.
pub(super) fn start(sealer: &Sealer, host: &str, next: &str, now: u64) -> Option<Login> {
    let (state, nonce, verifier) = (random_token(16)?, random_token(16)?, random_token(32)?);
    let challenge = challenge(&verifier);
    let flow = Flow {
        s: state.clone(),
        v: verifier,
        n: nonce.clone(),
        next: safe_target(next).to_owned(),
        exp: now.saturating_add(FLOW_TTL_SECS),
    };
    let cookie = sealer.seal(host, &serde_json::to_vec(&flow).ok()?)?;
    Some(Login {
        cookie,
        state,
        nonce,
        challenge,
    })
}

/// Why a callback does not belong to a login this middleware started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// The request has no flow cookie.
    NoCookie,
    /// No flow cookie opens: another app's, another host's, altered, or past its five minutes.
    Invalid,
    /// The `state` of the callback is not the cookie's.
    StateMismatch,
}

/// The login the callback with `state` completes: the first of the `cookies` that opens for
/// `host`, has not expired at `now` and holds that `state`.
///
/// # Errors
///
/// [`Refused`] says what was missing or different.
pub(super) fn resume<'a>(
    sealer: &Sealer,
    host: &str,
    cookies: impl Iterator<Item = &'a str>,
    state: &str,
    now: u64,
) -> Result<Flow, Refused> {
    let mut seen = false;
    let mut opened = None;
    for value in cookies {
        seen = true;
        if let Some(flow) = sealer
            .open(host, value)
            .and_then(|plain| serde_json::from_slice::<Flow>(&plain).ok())
            .filter(|flow| now < flow.exp)
        {
            opened = Some(flow);
            break;
        }
    }
    let flow = opened.ok_or(if seen {
        Refused::Invalid
    } else {
        Refused::NoCookie
    })?;
    if !bool::from(flow.s.as_bytes().ct_eq(state.as_bytes())) {
        return Err(Refused::StateMismatch);
    }
    Ok(flow)
}

/// What the authorization request asks for.
#[derive(Debug, Clone, Copy)]
pub(super) struct Authorization<'a> {
    /// The provider's `authorization_endpoint`.
    pub(super) endpoint: &'a str,
    /// The client.
    pub(super) client_id: &'a str,
    /// Where the provider sends the browser back to.
    pub(super) redirect_uri: &'a str,
    /// The scopes, space separated on the wire.
    pub(super) scope: &'a str,
    /// The values of [`Login`].
    pub(super) login: &'a Login,
}

/// The URL of the authorization request: the endpoint with `response_type=code`, the client, the
/// redirect URI, the scope, the `state`, the `nonce` and the S256 `code_challenge`, added to a
/// query the endpoint may already have.
pub(super) fn authorization_url(request: &Authorization<'_>) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", request.client_id)
        .append_pair("redirect_uri", request.redirect_uri)
        .append_pair("scope", request.scope)
        .append_pair("state", &request.login.state)
        .append_pair("nonce", &request.login.nonce)
        .append_pair("code_challenge", &request.login.challenge)
        .append_pair("code_challenge_method", "S256");
    let separator = if request.endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{separator}{}", request.endpoint, query.finish())
}

#[cfg(test)]
mod test {
    use super::super::session::{FLOW_LABEL, SESSION_LABEL};
    use super::*;

    fn sealer(label: &str) -> Sealer {
        Sealer::derive(b"0123456789abcdef0123", label, "a", "login").expect("key")
    }

    #[test]
    fn pkce_challenge_is_the_s256_of_the_verifier() {
        // The example of RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn only_a_relative_path_is_a_target() {
        for good in [
            "/",
            "/a",
            "/a/b?c=d&e=f",
            "/a:b",
            "/a//b",
            "/%2F%2Fevil.test",
        ] {
            assert_eq!(safe_target(good), good);
        }
        for bad in [
            "",
            "a",
            "//evil.test",
            "///evil.test",
            "/\\evil.test",
            "https://evil.test/",
            "http:evil.test",
            "javascript:alert(1)",
            "/a\nb",
            "/a\rb",
            "/a\tb",
            "/%0d%0aSet-Cookie: x=y",
            &format!("/{}", "a".repeat(MAX_NEXT)),
        ] {
            assert_eq!(safe_target(bad), "/", "{bad:?}");
        }
    }

    #[test]
    fn a_login_resumes_with_its_state_and_only_then() {
        let key = sealer(FLOW_LABEL);
        let login = start(&key, "a.test", "/page?x=1", 1000).expect("started");
        let resumed = resume(
            &key,
            "a.test",
            [login.cookie.as_str()].into_iter(),
            &login.state,
            1100,
        )
        .expect("resumed");
        assert_eq!(resumed.next(), "/page?x=1");
        assert_eq!(resumed.nonce(), login.nonce);
        assert_eq!(challenge(resumed.verifier()), login.challenge);

        let attempt = |key: &Sealer, host: &str, cookies: &[&str], state: &str, now: u64| {
            resume(key, host, cookies.iter().copied(), state, now).map(|_| ())
        };
        let cookie = [login.cookie.as_str()];
        assert_eq!(
            attempt(&key, "a.test", &cookie, "another", 1100),
            Err(Refused::StateMismatch)
        );
        assert_eq!(
            attempt(&key, "a.test", &[], &login.state, 1100),
            Err(Refused::NoCookie)
        );
        assert_eq!(
            attempt(&key, "a.test", &["junk"], &login.state, 1100),
            Err(Refused::Invalid)
        );
        assert_eq!(
            attempt(&key, "b.test", &cookie, &login.state, 1100),
            Err(Refused::Invalid),
            "another host"
        );
        assert_eq!(
            attempt(
                &sealer(SESSION_LABEL),
                "a.test",
                &cookie,
                &login.state,
                1100
            ),
            Err(Refused::Invalid),
            "a session key does not open a flow cookie"
        );
        assert_eq!(
            attempt(&key, "a.test", &cookie, &login.state, 1000 + FLOW_TTL_SECS),
            Err(Refused::Invalid),
            "five minutes are over"
        );
        assert!(attempt(&key, "a.test", &cookie, &login.state, 999 + FLOW_TTL_SECS).is_ok());
    }

    #[test]
    fn a_target_that_is_not_relative_is_stored_as_the_root() {
        let key = sealer(FLOW_LABEL);
        let login = start(&key, "a.test", "//evil.test/", 1000).expect("started");
        let flow = resume(
            &key,
            "a.test",
            [login.cookie.as_str()].into_iter(),
            &login.state,
            1001,
        )
        .expect("resumed");
        assert_eq!(flow.next(), "/");
    }

    #[test]
    fn the_authorization_url_carries_the_pkce_request() {
        let login = Login {
            cookie: String::new(),
            state: "st".into(),
            nonce: "no".into(),
            challenge: "ch".into(),
        };
        let url = authorization_url(&Authorization {
            endpoint: "https://idp.test/authorize?tenant=x",
            client_id: "my client",
            redirect_uri: "https://a.test/_podgate/oidc/callback",
            scope: "openid email",
            login: &login,
        });
        let (endpoint, query) = url.split_once("&response_type").expect("appended");
        assert_eq!(endpoint, "https://idp.test/authorize?tenant=x");
        assert_eq!(
            query,
            "=code&client_id=my+client&redirect_uri=https%3A%2F%2Fa.test%2F_podgate%2Foidc%2Fcallback&scope=openid+email&state=st&nonce=no&code_challenge=ch&code_challenge_method=S256"
        );
    }
}
