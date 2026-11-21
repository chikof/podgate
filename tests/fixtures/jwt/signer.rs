//! Signs test tokens for `jwt_auth`. Shared by the unit tests of `src/middleware/jwt_auth` and
//! `tests/mw_jwt.rs`, which both include this file with `#[path]`, so it depends on nothing but
//! `ring`, `base64` and `serde_json`. The two RSA keys are 2048-bit test keys that sign nothing
//! but these tokens.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "each includer uses some of the helpers, and `pub` is what `tests/mw_jwt.rs` needs"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, RsaPublicKeyComponents,
};
use serde_json::{Value, json};

const RSA_A: &[u8] = include_bytes!("rsa2048-a.pk8");
const RSA_B: &[u8] = include_bytes!("rsa2048-b.pk8");

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Seconds since the epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

enum Key {
    Rsa(RsaKeyPair),
    Es256(EcdsaKeyPair),
    Es384(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Hmac(Vec<u8>),
}

/// A key pair (or a secret) with the `kid` its public JWK carries.
pub struct Signer {
    kid: String,
    key: Key,
}

impl Signer {
    fn new(kid: &str, key: Key) -> Self {
        Self {
            kid: kid.to_owned(),
            key,
        }
    }

    pub fn rsa_a(kid: &str) -> Self {
        Self::new(kid, Key::Rsa(RsaKeyPair::from_pkcs8(RSA_A).expect("rsa a")))
    }

    pub fn rsa_b(kid: &str) -> Self {
        Self::new(kid, Key::Rsa(RsaKeyPair::from_pkcs8(RSA_B).expect("rsa b")))
    }

    pub fn es256(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("generate");
        let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("p256");
        Self::new(kid, Key::Es256(pair))
    }

    pub fn es384(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let alg = &signature::ECDSA_P384_SHA384_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("generate");
        let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("p384");
        Self::new(kid, Key::Es384(pair))
    }

    pub fn ed25519(kid: &str) -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("ed25519");
        Self::new(kid, Key::Ed25519(pair))
    }

    pub fn hmac(kid: &str, secret: &[u8]) -> Self {
        Self::new(kid, Key::Hmac(secret.to_vec()))
    }

    /// The public JWK (for a symmetric key, the secret itself).
    pub fn jwk(&self) -> Value {
        let mut jwk = match &self.key {
            Key::Rsa(pair) => {
                let parts = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
                json!({"kty": "RSA", "n": b64(&parts.n), "e": b64(&parts.e)})
            }
            Key::Es256(pair) | Key::Es384(pair) => {
                let point = pair.public_key().as_ref();
                let half = (point.len() - 1) / 2;
                let curve = if half == 32 { "P-256" } else { "P-384" };
                json!({"kty": "EC", "crv": curve,
                       "x": b64(&point[1..=half]), "y": b64(&point[1 + half..])})
            }
            Key::Ed25519(pair) => {
                json!({"kty": "OKP", "crv": "Ed25519", "x": b64(pair.public_key().as_ref())})
            }
            Key::Hmac(secret) => json!({"kty": "oct", "k": b64(secret)}),
        };
        jwk["kid"] = json!(self.kid);
        jwk
    }

    /// The DER of an RSA public key (what an attacker would use as an HMAC secret).
    pub fn public_der(&self) -> Vec<u8> {
        match &self.key {
            Key::Rsa(pair) => pair.public().as_ref().to_vec(),
            _ => Vec::new(),
        }
    }

    /// A signed token. `header` is merged over `{alg, kid, typ}`; `alg` also picks the primitive.
    pub fn sign(&self, alg: &str, header: &Value, claims: &Value) -> String {
        self.sign_with_kid(alg, Some(&self.kid), header, claims)
    }

    /// Like [`Self::sign`] with another `kid` (or none).
    pub fn sign_with_kid(
        &self,
        alg: &str,
        kid: Option<&str>,
        header: &Value,
        claims: &Value,
    ) -> String {
        let mut head = json!({"alg": alg, "typ": "JWT"});
        if let Some(kid) = kid {
            head["kid"] = json!(kid);
        }
        if let (Some(head), Some(extra)) = (head.as_object_mut(), header.as_object()) {
            head.extend(extra.clone());
        }
        let input = format!("{}.{}", b64(head.to_string()), b64(claims.to_string()));
        let rng = SystemRandom::new();
        let sig = match (&self.key, alg) {
            (Key::Rsa(pair), "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512") => {
                let padding: &'static dyn signature::RsaEncoding = match alg {
                    "RS256" => &signature::RSA_PKCS1_SHA256,
                    "RS384" => &signature::RSA_PKCS1_SHA384,
                    "RS512" => &signature::RSA_PKCS1_SHA512,
                    "PS256" => &signature::RSA_PSS_SHA256,
                    "PS384" => &signature::RSA_PSS_SHA384,
                    _ => &signature::RSA_PSS_SHA512,
                };
                let mut out = vec![0_u8; pair.public().modulus_len()];
                pair.sign(padding, &rng, input.as_bytes(), &mut out)
                    .expect("rsa sign");
                out
            }
            (Key::Es256(pair), _) | (Key::Es384(pair), _) => pair
                .sign(&rng, input.as_bytes())
                .expect("ecdsa sign")
                .as_ref()
                .to_vec(),
            (Key::Ed25519(pair), _) => pair.sign(input.as_bytes()).as_ref().to_vec(),
            (Key::Hmac(secret), _) => return forge_hmac(alg, secret, kid, claims),
            (Key::Rsa(_), _) => panic!("an RSA key cannot sign {alg}"),
        };
        format!("{input}.{}", b64(sig))
    }
}

/// A token with `alg` and an empty signature, which is what `alg: none` looks like.
pub fn unsigned(alg: &str, claims: &Value) -> String {
    format!(
        "{}.{}.",
        b64(json!({"alg": alg, "typ": "JWT"}).to_string()),
        b64(claims.to_string())
    )
}

/// An HMAC token signed with `secret`, whatever the secret is.
pub fn forge_hmac(alg: &str, secret: &[u8], kid: Option<&str>, claims: &Value) -> String {
    let mut head = json!({"alg": alg, "typ": "JWT"});
    if let Some(kid) = kid {
        head["kid"] = json!(kid);
    }
    let input = format!("{}.{}", b64(head.to_string()), b64(claims.to_string()));
    let digest = match alg {
        "HS256" => ring::hmac::HMAC_SHA256,
        "HS384" => ring::hmac::HMAC_SHA384,
        _ => ring::hmac::HMAC_SHA512,
    };
    let tag = ring::hmac::sign(&ring::hmac::Key::new(digest, secret), input.as_bytes());
    format!("{input}.{}", b64(tag.as_ref()))
}
