//! The operator's pin of the login in front of the developer portal.
//!
//! `PORTAL_APPS` lists the apps that may declare a `portal` middleware and, for each, the issuer
//! and the key source of the login stage the portal may stand behind. The compiler refuses a
//! snapshot whose login stage verifies with anything else, so an app's owner cannot keep the
//! issuer string and point the keys at keys of their own to mint any viewer.
//!
//! The pin lives only in the process environment. Nothing here prints one: the `Debug` of a pin,
//! a grant and the grants shows no value, and the errors name the entry's number, not its text.

use std::fmt;
use std::sync::{Mutex, PoisonError, Weak};

use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use serde_json::Value;
use thiserror::Error;

use crate::table::RoutingTable;

/// Where a login stage gets the keys it verifies with.
#[derive(Clone, PartialEq, Eq)]
pub enum Source {
    /// A `jwt_auth` stage that fetches its keys from this `jwks_uri` and has no inline keys.
    Jwks(Box<str>),
    /// A `jwt_auth` stage with inline keys and no `jwks_uri`: the fingerprint of the key set, 64
    /// lowercase hex digits ([`fingerprint`]).
    Keys(Box<str>),
    /// An `oidc` stage: the keys come from the discovery document of its issuer.
    Discovery,
}

/// What a stage that fills `RequestCx::claims` says about how it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Login {
    /// The issuer it requires and where its keys come from.
    Pinnable {
        /// The `iss` the stage requires.
        issuer: Box<str>,
        /// Where its keys come from.
        source: Source,
    },
    /// A stage whose trust cannot be written down as a pin: no issuer, a shared secret, keys from
    /// two places, or a private transport. It never matches a pin.
    Unpinnable,
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Jwks(_) => "Jwks(..)",
            Self::Keys(_) => "Keys(..)",
            Self::Discovery => "Discovery",
        })
    }
}

/// One app's pin.
#[derive(Clone, PartialEq, Eq)]
pub struct Pin {
    issuer: Box<str>,
    source: Source,
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin([redacted])")
    }
}

impl Pin {
    /// Whether `login` verifies with exactly the pinned issuer and key source.
    #[must_use]
    pub fn admits(&self, login: &Login) -> bool {
        match login {
            Login::Pinnable { issuer, source } => *issuer == self.issuer && *source == self.source,
            Login::Unpinnable => false,
        }
    }
}

/// Why `PORTAL_APPS` cannot be used. Never holds the text of an entry.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PinError {
    /// An entry is not `tenant/app=<issuer>|<source>`.
    #[error("entry {entry} is not tenant/app=<issuer>|<source>")]
    Shape {
        /// The entry's position, from 1.
        entry: usize,
    },
    /// The source of an entry is not `jwks:<url>`, `keys:<64 hex digits>` or `oidc`.
    #[error("entry {entry} has a source that is not jwks:<url>, keys:<64 hex digits> or oidc")]
    Source {
        /// The entry's position, from 1.
        entry: usize,
    },
    /// Two entries name the same app.
    #[error("entry {entry} repeats an app")]
    Repeated {
        /// The entry's position, from 1.
        entry: usize,
    },
}

/// One listed app: its tenant, its id and the pin of its login.
type Listed = (Box<str>, Box<str>, Pin);

/// The apps that may declare a `portal` middleware, with their pins: what `PORTAL_APPS` says.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Apps {
    entries: Box<[Listed]>,
}

impl fmt::Debug for Apps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Apps")
            .field("apps", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Apps {
    /// Reads `PORTAL_APPS`: comma separated `tenant/app=<issuer>|<source>`.
    ///
    /// # Errors
    ///
    /// [`PinError`] for the first entry that is malformed or repeats an app.
    pub fn parse(raw: &str) -> Result<Self, PinError> {
        let mut entries: Vec<Listed> = Vec::new();
        for (at, text) in raw
            .split(',')
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .enumerate()
        {
            let entry = at + 1;
            let shape = PinError::Shape { entry };
            let (app, rest) = text.split_once('=').ok_or(PinError::Shape { entry })?;
            let (issuer, source) = rest.split_once('|').ok_or(PinError::Shape { entry })?;
            let (tenant, app) = app.split_once('/').ok_or(PinError::Shape { entry })?;
            if tenant.is_empty() || app.is_empty() || app.contains('/') || issuer.is_empty() {
                return Err(shape);
            }
            let source = match source {
                "oidc" => Source::Discovery,
                other => match other.split_once(':') {
                    Some(("jwks", url)) if !url.is_empty() => Source::Jwks(url.into()),
                    Some(("keys", hex))
                        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        Source::Keys(hex.to_ascii_lowercase().into())
                    }
                    _ => return Err(PinError::Source { entry }),
                },
            };
            if entries.iter().any(|(known_tenant, known_app, _)| {
                **known_tenant == *tenant && **known_app == *app
            }) {
                return Err(PinError::Repeated { entry });
            }
            entries.push((
                tenant.into(),
                app.into(),
                Pin {
                    issuer: issuer.into(),
                    source,
                },
            ));
        }
        Ok(Self {
            entries: entries.into_boxed_slice(),
        })
    }

    /// Whether no app may declare a `portal` middleware.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The listed apps and the live table the `portal` stages read. One per compile context.
#[derive(Default)]
pub struct Grants {
    apps: Apps,
    live: Mutex<Weak<ArcSwap<RoutingTable>>>,
}

impl fmt::Debug for Grants {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grants")
            .field("apps", &self.apps.entries.len())
            .finish_non_exhaustive()
    }
}

impl Grants {
    /// Grants for `apps`, bound to no table yet.
    #[must_use]
    pub fn new(apps: Apps) -> Self {
        Self {
            apps,
            live: Mutex::new(Weak::new()),
        }
    }

    /// Points the grants at the live table of the handle that compiles with them. A stage holds
    /// only a weak reference, so the table that holds the stage and the handle that holds the
    /// table never keep each other alive.
    pub fn bind(&self, live: &std::sync::Arc<ArcSwap<RoutingTable>>) {
        *self.live.lock().unwrap_or_else(PoisonError::into_inner) = std::sync::Arc::downgrade(live);
    }

    /// The grant of app `app` of tenant `tenant`, when the operator listed it. Both halves are
    /// compared whole, so an id that holds `/`, `=` or `|` never matches an entry.
    #[must_use]
    pub fn of(&self, tenant: &str, app: &str) -> Option<Grant<'_>> {
        self.apps
            .entries
            .iter()
            .find(|(known_tenant, known_app, _)| **known_tenant == *tenant && **known_app == *app)
            .map(|(_, _, pin)| Grant {
                pin,
                live: self
                    .live
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            })
    }
}

/// What the compiler hands to the `portal` kind of a listed app, and to no other.
pub struct Grant<'a> {
    pin: &'a Pin,
    live: Weak<ArcSwap<RoutingTable>>,
}

impl fmt::Debug for Grant<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Grant([redacted])")
    }
}

impl<'a> Grant<'a> {
    /// The pin the app's login must match.
    #[must_use]
    pub fn pin(&self) -> &'a Pin {
        self.pin
    }

    /// A weak handle on the live table, for the stage to load per request.
    pub(super) fn live(&self) -> Weak<ArcSwap<RoutingTable>> {
        self.live.clone()
    }
}

/// The fingerprint of an inline JWK set: the SHA-256, as 64 lowercase hex digits, of the RFC 7638
/// thumbprints of its keys, sorted and joined by a newline. It covers public members only, so it
/// is no secret. `None` when a key is not an RSA, EC or OKP key with its required members (a
/// shared secret has no thumbprint worth pinning).
#[must_use]
pub fn fingerprint(set: &Value) -> Option<String> {
    let keys = set.get("keys")?.as_array()?;
    let mut thumbs: Vec<String> = keys.iter().map(thumbprint).collect::<Option<_>>()?;
    thumbs.sort_unstable();
    Some(hex(digest(&SHA256, thumbs.join("\n").as_bytes()).as_ref()))
}

/// The RFC 7638 thumbprint of one key: base64url of the SHA-256 of its required members, sorted
/// by name, with no whitespace.
fn thumbprint(key: &Value) -> Option<String> {
    let members: &[&str] = match key.get("kty")?.as_str()? {
        "RSA" => &["e", "kty", "n"],
        "EC" => &["crv", "kty", "x", "y"],
        "OKP" => &["crv", "kty", "x"],
        _ => return None,
    };
    let mut text = String::from("{");
    for (at, name) in members.iter().enumerate() {
        if at > 0 {
            text.push(',');
        }
        text.push_str(&serde_json::to_string(name).ok()?);
        text.push(':');
        text.push_str(&serde_json::to_string(key.get(*name)?.as_str()?).ok()?);
    }
    text.push('}');
    Some(URL_SAFE_NO_PAD.encode(digest(&SHA256, text.as_bytes())))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn portal_apps_setting_parses_pins() {
        let grants = Grants::new(
            Apps::parse(&format!(
                "ops/portal=https://idp.example|oidc, t2/p=https://i|jwks:https://i/keys,t3/p=i|keys:{HEX}"
            ))
            .expect("parses"),
        );
        let pin = grants.of("ops", "portal").expect("listed").pin().clone();
        assert!(pin.admits(&Login::Pinnable {
            issuer: "https://idp.example".into(),
            source: Source::Discovery
        }));
        assert!(!pin.admits(&Login::Pinnable {
            issuer: "https://idp.example/".into(),
            source: Source::Discovery
        }));
        assert!(!pin.admits(&Login::Unpinnable));
        assert!(grants.of("ops", "other").is_none());
        assert!(grants.of("t2", "portal").is_none());
        assert!(Apps::parse("").expect("empty").is_empty());
        for bad in [
            "ops/portal",
            "ops/portal=issuer",
            "ops=issuer|oidc",
            "a/b/c=issuer|oidc",
            "/p=issuer|oidc",
            "t/=issuer|oidc",
            "t/p=|oidc",
            "t/p=i|",
            "t/p=i|jwks:",
            "t/p=i|keys:abc",
            "t/p=i|keys:zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "t/p=i|saml",
            "t/p=i|oidc,t/p=j|oidc",
        ] {
            let error = Apps::parse(bad).expect_err(bad);
            let shown = error.to_string();
            assert!(
                !shown.contains(bad) || bad.len() < 3,
                "the error never repeats the entry: {shown}"
            );
        }
    }

    #[test]
    fn pins_never_print() {
        let grants = Grants::new(
            Apps::parse("t/p=https://secret-issuer|jwks:https://secret-keys").expect("parses"),
        );
        let shown = format!("{grants:?} {:?}", grants.of("t", "p"));
        assert!(!shown.contains("secret"), "{shown}");
        let pin = Pin {
            issuer: "secret-issuer".into(),
            source: Source::Jwks("secret-keys".into()),
        };
        assert!(!format!("{pin:?}").contains("secret"));
        assert!(!format!("{:?}", pin.source).contains("secret"));
    }

    #[test]
    fn grants_match_whole_halves() {
        let grants = Grants::new(Apps::parse("ops/portal=i|oidc").expect("parses"));
        for (tenant, app) in [
            ("ops/portal", ""),
            ("ops", "portal/x"),
            ("ops/", "portal"),
            ("o", "ops/portal"),
            ("ops=i|oidc,x", "portal"),
        ] {
            assert!(grants.of(tenant, app).is_none(), "{tenant} {app}");
        }
    }

    /// The RFC 7638 section 3.1 example key and its published thumbprint.
    #[test]
    fn thumbprint_matches_rfc_7638() {
        let key = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        assert_eq!(
            thumbprint(&key).as_deref(),
            Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        );
    }

    #[test]
    fn fingerprint_is_over_public_members_in_a_fixed_order() {
        let a = json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "kid": "one"});
        let b = json!({"kty": "EC", "crv": "P-256", "x": "BBBB", "y": "CCCC", "use": "sig"});
        let one = fingerprint(&json!({"keys": [a, b]})).expect("fingerprint");
        let other = fingerprint(&json!({"keys": [
            {"kty": "EC", "crv": "P-256", "x": "BBBB", "y": "CCCC"},
            {"kty": "OKP", "crv": "Ed25519", "x": "AAAA", "alg": "EdDSA"}
        ]}))
        .expect("fingerprint");
        assert_eq!(one, other, "order, kid, use and alg do not change it");
        assert_eq!(one.len(), 64);
        assert!(one.bytes().all(|b| b.is_ascii_hexdigit()));
        let changed = fingerprint(
            &json!({"keys": [a, {"kty": "EC", "crv": "P-256", "x": "BBBB", "y": "DDDD"}]}),
        );
        assert_ne!(Some(one), changed);
        assert!(fingerprint(&json!({"keys": [{"kty": "oct", "k": "AAAA"}]})).is_none());
        assert!(fingerprint(&json!({"keys": [{"kty": "RSA", "n": "AAAA"}]})).is_none());
    }

    /// What `login()` says for each way a `jwt_auth` or `oidc` stage can be set up.
    #[test]
    fn portal_login_anchor_of_jwt_and_oidc() {
        use crate::middleware::{CompileCx, Stage};
        use crate::wasm as engine;

        let key = json!({"kty": "OKP", "crv": "Ed25519",
                         "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "kid": "k1"});
        let keys = json!({"keys": [key]});
        let oct = json!({"keys": [{"kty": "oct", "k": "A".repeat(43), "kid": "s"}]});
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
            "transports": [{"name": "t", "type": "servers_transport", "server_name": "idp.internal"}],
        }))
        .expect("app");
        let login = |kind: &str, config: Value| -> Login {
            let mut declared = json!({"name": "login", "type": kind});
            declared
                .as_object_mut()
                .expect("object")
                .extend(config.as_object().expect("object").clone());
            let declared: podgate_model::Declared =
                serde_json::from_value(declared).expect("declared");
            let mut compiler = engine::Compiler::default();
            Stage::compile(
                &declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut compiler,
                    portal: None,
                },
            )
            .expect("compiles")
            .login()
            .expect("a stage that fills claims")
        };
        let jwt = |extra: Value| {
            let mut config = json!({"algorithms": ["EdDSA"], "issuer": "https://idp.test"});
            config
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            login("jwt_auth", config)
        };
        let print = fingerprint(&keys).expect("fingerprint");
        let pinned = |issuer: &str, source: Source| Login::Pinnable {
            issuer: issuer.into(),
            source,
        };

        assert_eq!(
            jwt(json!({"jwks_uri": "http://10.0.0.7/jwks"})),
            pinned(
                "https://idp.test",
                Source::Jwks("http://10.0.0.7/jwks".into())
            )
        );
        assert_eq!(
            jwt(json!({"keys": keys})),
            pinned("https://idp.test", Source::Keys(print.into()))
        );
        // Keys from two places, a private transport, a shared secret and no issuer have no pin.
        for unpinnable in [
            jwt(json!({"keys": keys, "jwks_uri": "http://10.0.0.7/jwks"})),
            jwt(json!({"jwks_uri": "https://10.0.0.7/jwks", "transport": "t"})),
            jwt(json!({"keys": oct, "algorithms": ["HS256"]})),
            login("jwt_auth", json!({"keys": keys, "algorithms": ["EdDSA"]})),
        ] {
            assert_eq!(unpinnable, Login::Unpinnable);
        }
        // `oidc`: its issuer and the discovery document; a private transport has no pin.
        let oidc = |extra: Value| {
            let mut config = json!({"issuer": "https://idp.test", "client_id": "app"});
            config
                .as_object_mut()
                .expect("object")
                .extend(extra.as_object().expect("object").clone());
            login("oidc", config)
        };
        assert_eq!(
            oidc(json!({})),
            pinned("https://idp.test", Source::Discovery)
        );
        assert_eq!(oidc(json!({"transport": "t"})), Login::Unpinnable);
        // A pin of one kind admits that kind only.
        let pin = Apps::parse("t/a=https://idp.test|oidc").expect("parses");
        let grants = Grants::new(pin);
        let grant = grants.of("t", "a").expect("listed");
        assert!(grant.pin().admits(&oidc(json!({}))));
        assert!(!grant.pin().admits(&jwt(json!({"keys": keys}))));
    }
}
