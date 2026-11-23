//! The encrypted cookies of `oidc`: how a key is derived from the snapshot's `skew_secret`, how a
//! value is sealed and opened, and what the session cookie holds.
//!
//! There is no state on the server. Everything a login needs between two requests (the flow
//! cookie of [`super::flow`]) and everything a signed-in browser proves (the session cookie)
//! travels in a cookie that only podgate can read or make:
//!
//! - **Key.** `HKDF-SHA256(skew_secret)` with an info string of the purpose
//!   (`podgate/oidc/flow/v1`, `podgate/oidc/session/v1`), the app id and the middleware name, each
//!   length-prefixed. A cookie of another app, another `oidc` middleware or the other purpose is
//!   sealed under another key and never opens. Every node of the platform derives the same keys,
//!   so a session survives a restart and a move to another node.
//! - **Seal.** ChaCha20-Poly1305 with a random 96-bit nonce, `base64url(nonce || ciphertext ||
//!   tag)`. The host the cookie was issued for is the associated data, so a cookie replayed at
//!   another host of a wildcard route fails to open.
//! - **Session.** `{p, iat, exp, c}`: a digest of the middleware's declaration, the time it was
//!   issued, the time it ends and the claims the declaration names. A session whose digest is not
//!   the live declaration's is refused, so tightening `required_claims` or `allow_subjects` ends
//!   every older session at once instead of at its expiry.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The info label of the flow cookie key.
pub(super) const FLOW_LABEL: &str = "podgate/oidc/flow/v1";

/// The info label of the session cookie key.
pub(super) const SESSION_LABEL: &str = "podgate/oidc/session/v1";

/// The most bytes of a cookie value: with the name and the attributes the whole `Set-Cookie`
/// stays under what browsers store (4096 bytes).
pub(super) const MAX_VALUE: usize = 3584;

/// The bytes of the nonce in front of a sealed value.
const NONCE_LEN: usize = 12;

/// The bytes of the authentication tag.
const TAG_LEN: usize = 16;

/// A session that claims to start further ahead than this is refused.
const FUTURE_SLACK_SECS: u64 = 60;

/// The length of the key `HKDF` derives.
struct KeyLen;

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// A key that seals and opens the cookies of one purpose of one middleware.
pub(super) struct Sealer(LessSafeKey);

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sealer([redacted])")
    }
}

impl Sealer {
    /// The key for `label` of the middleware `name` of `app`, derived from `secret`. `None` only
    /// when a name is longer than 65535 bytes.
    pub(super) fn derive(secret: &[u8], label: &str, app: &str, name: &str) -> Option<Self> {
        let app_len = u16::try_from(app.len()).ok()?.to_be_bytes();
        let name_len = u16::try_from(name.len()).ok()?.to_be_bytes();
        let info: [&[u8]; 5] = [
            label.as_bytes(),
            &app_len,
            app.as_bytes(),
            &name_len,
            name.as_bytes(),
        ];
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"podgate/oidc").extract(secret);
        let mut key = [0_u8; 32];
        prk.expand(&info, KeyLen).ok()?.fill(&mut key).ok()?;
        let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, &key).ok()?;
        Some(Self(LessSafeKey::new(unbound)))
    }

    /// `plain` sealed for `host`, as the text of a cookie value. `None` when there is no
    /// entropy, or the result is over [`MAX_VALUE`].
    pub(super) fn seal(&self, host: &str, plain: &[u8]) -> Option<String> {
        let mut nonce = [0_u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).ok()?;
        let mut body = plain.to_vec();
        self.0
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(host.as_bytes()),
                &mut body,
            )
            .ok()?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + body.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&body);
        let text = URL_SAFE_NO_PAD.encode(sealed);
        (text.len() <= MAX_VALUE).then_some(text)
    }

    /// What `value` holds, when it was sealed under this key for `host`. `None` for anything
    /// else: another key, another host, a change of a single bit, garbage.
    pub(super) fn open(&self, host: &str, value: &str) -> Option<Vec<u8>> {
        if value.len() > MAX_VALUE {
            return None;
        }
        let mut bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        if bytes.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(bytes.get(..NONCE_LEN)?);
        let mut body = bytes.split_off(NONCE_LEN);
        let plain = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(host.as_bytes()),
                &mut body,
            )
            .ok()?;
        Some(plain.to_vec())
    }
}

/// A random token of `bytes` bytes as unpadded base64url. `None` without entropy.
pub(super) fn random_token(bytes: usize) -> Option<String> {
    let mut raw = vec![0_u8; bytes];
    SystemRandom::new().fill(&mut raw).ok()?;
    Some(URL_SAFE_NO_PAD.encode(raw))
}

/// What a signed-in browser's cookie holds.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Session {
    /// A digest of the declaration the session was issued under.
    p: u64,
    /// When it was issued, seconds since the epoch.
    iat: u64,
    /// When it ends, seconds since the epoch.
    exp: u64,
    /// The claims the declaration names, `sub` always.
    c: Map<String, Value>,
}

impl Session {
    /// A session issued at `iat` that ends at `exp` under the declaration digested as `policy`.
    pub(super) fn new(policy: u64, iat: u64, exp: u64, claims: Map<String, Value>) -> Self {
        Self {
            p: policy,
            iat,
            exp,
            c: claims,
        }
    }

    /// When the session ends.
    #[cfg(test)]
    pub(super) fn ends(&self) -> u64 {
        self.exp
    }

    /// The claims the session carries.
    pub(super) fn claims(&self) -> &Map<String, Value> {
        &self.c
    }

    /// The cookie value for this session sealed for `host`; when it does not fit, the value of a
    /// session that carries `sub` only, and `true` in the second place. `None` without a `sub`
    /// or without entropy.
    pub(super) fn seal(&self, sealer: &Sealer, host: &str) -> Option<(String, bool)> {
        if let Some(value) = serde_json::to_vec(self)
            .ok()
            .and_then(|plain| sealer.seal(host, &plain))
        {
            return Some((value, false));
        }
        let sub = self.c.get("sub")?.clone();
        let slim = Self {
            p: self.p,
            iat: self.iat,
            exp: self.exp,
            c: Map::from_iter([("sub".to_owned(), sub)]),
        };
        let value = sealer.seal(host, &serde_json::to_vec(&slim).ok()?)?;
        Some((value, true))
    }

    /// The session in `value`, when it opens under `sealer` for `host`, was issued under the
    /// declaration digested as `policy`, has not ended at `now` and is not older than
    /// `max_age_secs`.
    pub(super) fn open(
        sealer: &Sealer,
        host: &str,
        value: &str,
        policy: u64,
        now: u64,
        max_age_secs: u64,
    ) -> Option<Self> {
        let plain = sealer.open(host, value)?;
        let session: Self = serde_json::from_slice(&plain).ok()?;
        let live = session.p == policy
            && now < session.exp
            && session.iat <= now.saturating_add(FUTURE_SLACK_SECS)
            && now < session.iat.saturating_add(max_age_secs)
            && session.c.get("sub").is_some_and(Value::is_string);
        live.then_some(session)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123";

    fn sealer(label: &str, app: &str, name: &str) -> Sealer {
        Sealer::derive(SECRET, label, app, name).expect("key")
    }

    fn claims(extra: &Value) -> Map<String, Value> {
        let mut all = json!({"sub": "ann"}).as_object().expect("object").clone();
        all.extend(extra.as_object().expect("object").clone());
        all
    }

    #[test]
    fn a_sealed_value_opens_only_under_its_key_and_host() {
        let key = sealer(SESSION_LABEL, "a", "login");
        let value = key.seal("a.test", b"hello").expect("sealed");
        assert_eq!(key.open("a.test", &value).as_deref(), Some(&b"hello"[..]));
        assert_eq!(key.open("b.test", &value), None, "another host");
        for other in [
            sealer(FLOW_LABEL, "a", "login"),
            sealer(SESSION_LABEL, "b", "login"),
            sealer(SESSION_LABEL, "a", "other"),
        ] {
            assert_eq!(other.open("a.test", &value), None);
        }
        // The length prefixes keep ("ab", "c") apart from ("a", "bc").
        let one = sealer(SESSION_LABEL, "ab", "c")
            .seal("h", b"x")
            .expect("sealed");
        assert_eq!(sealer(SESSION_LABEL, "a", "bc").open("h", &one), None);
        let mut bytes = URL_SAFE_NO_PAD.decode(&value).expect("base64");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(key.open("a.test", &URL_SAFE_NO_PAD.encode(bytes)), None);
        assert_eq!(key.open("a.test", "not base64!"), None);
        assert_eq!(key.open("a.test", ""), None);
    }

    #[test]
    fn two_seals_of_one_text_differ() {
        let key = sealer(SESSION_LABEL, "a", "login");
        assert_ne!(key.seal("h", b"x"), key.seal("h", b"x"));
    }

    #[test]
    fn a_session_is_open_until_it_ends_or_grows_too_old() {
        let key = sealer(SESSION_LABEL, "a", "login");
        let session = Session::new(7, 1000, 2000, claims(&json!({"email": "a@x"})));
        let (value, dropped) = session.seal(&key, "h").expect("sealed");
        assert!(!dropped);
        let open = |now, policy, max_age| Session::open(&key, "h", &value, policy, now, max_age);
        let live = open(1500, 7, 10_000).expect("live");
        assert_eq!(live.claims()["email"], "a@x");
        assert_eq!(live.ends(), 2000);
        assert!(open(1999, 7, 10_000).is_some());
        assert!(open(2000, 7, 10_000).is_none(), "ended");
        assert!(open(1500, 8, 10_000).is_none(), "another declaration");
        assert!(open(1500, 7, 400).is_none(), "older than the max age now");
        assert!(open(900, 7, 10_000).is_none(), "issued in the future");
    }

    /// The claims the `oidc` stage hands to later stages (`opa`, the portal) are the ones of a
    /// session that opened, so a cookie the client changed or made up yields none.
    #[test]
    fn oidc_claims_from_verified_session_only() {
        let key = sealer(SESSION_LABEL, "a", "login");
        let session = Session::new(7, 1000, 2000, claims(&json!({"tenant": "acme"})));
        let (value, _) = session.seal(&key, "h").expect("sealed");
        let open = |value: &str, key: &Sealer, host: &str, now: u64, policy: u64| {
            Session::open(key, host, value, policy, now, 10_000)
        };
        let claims = open(&value, &key, "h", 1500, 7).expect("opens");
        assert_eq!(claims.claims()["tenant"], "acme");

        // A byte changed anywhere in the cookie.
        let bytes = URL_SAFE_NO_PAD.decode(&value).expect("base64");
        for at in [0, NONCE_LEN, bytes.len() / 2, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[at] ^= 0x20;
            assert!(
                open(&URL_SAFE_NO_PAD.encode(&changed), &key, "h", 1500, 7).is_none(),
                "{at}"
            );
        }
        // A session sealed under another key, another middleware, another app or for another host.
        for other in [
            sealer(SESSION_LABEL, "b", "login"),
            sealer(SESSION_LABEL, "a", "other"),
            sealer(FLOW_LABEL, "a", "login"),
        ] {
            assert!(open(&value, &other, "h", 1500, 7).is_none());
        }
        assert!(open(&value, &key, "other-host", 1500, 7).is_none());
        // One made up by the client from a plain claims object, whatever it looks like.
        let plain =
            serde_json::to_vec(&Session::new(7, 1000, 2000, claims_of_victim())).expect("json");
        for forged in [
            URL_SAFE_NO_PAD.encode(&plain),
            String::from_utf8_lossy(&plain).into_owned(),
            "x".repeat(NONCE_LEN + TAG_LEN + 8),
        ] {
            assert!(open(&forged, &key, "h", 1500, 7).is_none(), "{forged}");
        }
        // Another declaration of the middleware, and an expired session.
        assert!(open(&value, &key, "h", 1500, 8).is_none());
        assert!(open(&value, &key, "h", 2000, 7).is_none());
    }

    fn claims_of_victim() -> Map<String, Value> {
        claims(&json!({"tenant": "globex"}))
    }

    #[test]
    fn a_session_without_a_string_sub_is_refused() {
        let key = sealer(SESSION_LABEL, "a", "login");
        for claims in [
            Map::new(),
            json!({"sub": 5}).as_object().expect("object").clone(),
        ] {
            let plain = serde_json::to_vec(&Session::new(7, 1000, 2000, claims)).expect("json");
            let value = key.seal("h", &plain).expect("sealed");
            assert!(Session::open(&key, "h", &value, 7, 1500, 10_000).is_none());
        }
    }

    #[test]
    fn claims_that_do_not_fit_are_dropped_and_sub_stays() {
        let key = sealer(SESSION_LABEL, "a", "login");
        let big = "x".repeat(MAX_VALUE);
        let session = Session::new(7, 1000, 2000, claims(&json!({"groups": big})));
        let (value, dropped) = session.seal(&key, "h").expect("sealed");
        assert!(dropped);
        assert!(value.len() <= MAX_VALUE);
        let open = Session::open(&key, "h", &value, 7, 1500, 10_000).expect("live");
        assert_eq!(open.claims().len(), 1);
        assert_eq!(open.claims()["sub"], "ann");
    }

    #[test]
    fn debug_hides_the_key() {
        assert_eq!(
            format!("{:?}", sealer(SESSION_LABEL, "a", "login")),
            "Sealer([redacted])"
        );
    }
}
