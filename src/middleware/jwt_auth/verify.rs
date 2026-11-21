//! Tokens, keys and signatures of `jwt_auth`.
//!
//! There is no signature code here: `ring` checks the signatures and the HMAC. This file decides
//! which key may check which token, and it is built so that the token never chooses.
//!
//! - The algorithm list of the configuration is the only source of algorithms. The `alg` header
//!   is looked up in it, and a header that is `none`, unknown or unlisted fails before any key is
//!   touched.
//! - A key has a type (RSA, EC P-256, EC P-384, Ed25519, symmetric) and an algorithm has the
//!   type it needs. [`Key::serves`] pairs them and [`Key::verify`] repeats the pairing, so a key
//!   of one type is never handed to the primitive of another (an RSA public key is never an HMAC
//!   secret, an `oct` key never checks an RS256 token).
//! - RSA moduli outside 2048 to 8192 bits and exponents under 65537 are refused when a key is
//!   read, and `ring` checks the same range again when it verifies.
//! - A token is read only up to [`MAX_TOKEN`] bytes. Base64url is strict: no padding, no
//!   stray trailing bits. A header with `crit` is refused whole, as are `alg` and `kid` that are
//!   not strings.
//! - A symmetric key is accepted only from the configuration, never from a JWKS endpoint, and
//!   only when it is at least as long as the hash of the HMAC it serves.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::{hmac, signature};
use serde_json::{Map, Value};
use thiserror::Error;

/// The most bytes of a token that are read.
pub(super) const MAX_TOKEN: usize = 8 * 1024;

/// The most keys that are tried against one token.
pub(super) const MAX_CANDIDATES: usize = 4;

/// The most keys of one JWK set that are used.
pub(super) const MAX_KEYS: usize = 100;

/// The longest `kid` of a token that is looked at.
const MAX_KID: usize = 256;

/// The RSA modulus sizes, in bits, that are accepted.
const RSA_BITS: std::ops::RangeInclusive<usize> = 2048..=8192;

/// The shortest symmetric key.
const MIN_SECRET: usize = 32;

/// Why a request is refused. The body of the answer never says which; the access log and the
/// metrics do ([`Self::code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// No token in any configured place.
    Missing,
    /// The token is over [`MAX_TOKEN`] bytes.
    Oversized,
    /// The token, or the place it came from, is not well formed.
    Malformed,
    /// The `alg` header is `none`, unknown or not in the configured list.
    AlgNotAllowed,
    /// The header has `crit`.
    Crit,
    /// The `kid` names no key we have, and a refresh may find it.
    UnknownKid,
    /// No key fits the algorithm (and `kid`) of the token.
    NoKey,
    /// The signature does not match.
    BadSignature,
    /// No usable `exp`.
    MissingExp,
    /// `exp` is in the past.
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
    /// `iat` is in the future.
    IssuedInFuture,
    /// `iat` is missing or older than `max_token_age_secs`.
    TooOld,
    /// `iss` is not the configured issuer.
    BadIssuer,
    /// `aud` holds none of the configured audiences.
    BadAudience,
    /// The signature is valid and a required claim is missing or different: `403`.
    ClaimsForbidden,
    /// There are no keys: the JWKS cannot be had and nothing is cached: `503`.
    Unavailable,
}

impl Failure {
    /// Every failure, in the order of [`Self::index`].
    pub(super) const ALL: [Self; 17] = [
        Self::Missing,
        Self::Oversized,
        Self::Malformed,
        Self::AlgNotAllowed,
        Self::Crit,
        Self::UnknownKid,
        Self::NoKey,
        Self::BadSignature,
        Self::MissingExp,
        Self::Expired,
        Self::NotYetValid,
        Self::IssuedInFuture,
        Self::TooOld,
        Self::BadIssuer,
        Self::BadAudience,
        Self::ClaimsForbidden,
        Self::Unavailable,
    ];

    /// The place of this failure in a table of counters.
    pub(super) fn index(self) -> usize {
        self as usize
    }

    /// The reason the access log and the metrics give.
    pub(super) fn code(self) -> &'static str {
        match self {
            Self::Missing => "jwt_missing",
            Self::Oversized => "jwt_oversized",
            Self::Malformed => "jwt_malformed",
            Self::AlgNotAllowed => "jwt_alg_not_allowed",
            Self::Crit => "jwt_crit",
            Self::UnknownKid => "jwt_unknown_kid",
            Self::NoKey => "jwt_no_key",
            Self::BadSignature => "jwt_bad_signature",
            Self::MissingExp => "jwt_missing_exp",
            Self::Expired => "jwt_expired",
            Self::NotYetValid => "jwt_not_yet_valid",
            Self::IssuedInFuture => "jwt_issued_in_future",
            Self::TooOld => "jwt_too_old",
            Self::BadIssuer => "jwt_bad_issuer",
            Self::BadAudience => "jwt_bad_audience",
            Self::ClaimsForbidden => "jwt_claims_forbidden",
            Self::Unavailable => "jwks_unavailable",
        }
    }
}

/// A signature algorithm of a JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Algorithm {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
    Hs256,
    Hs384,
    Hs512,
}

/// What a key is made of, and so what it can check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Rsa,
    EcP256,
    EcP384,
    Ed25519,
    Symmetric,
}

impl Algorithm {
    /// The algorithm named `name`, exactly as written in a token (`none` is none of them).
    pub(super) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "RS256" => Self::Rs256,
            "RS384" => Self::Rs384,
            "RS512" => Self::Rs512,
            "PS256" => Self::Ps256,
            "PS384" => Self::Ps384,
            "PS512" => Self::Ps512,
            "ES256" => Self::Es256,
            "ES384" => Self::Es384,
            "EdDSA" => Self::EdDsa,
            "HS256" => Self::Hs256,
            "HS384" => Self::Hs384,
            "HS512" => Self::Hs512,
            _ => return None,
        })
    }

    /// The name as written in a token.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }

    /// Whether this is an RSA algorithm (`RS*` or `PS*`), the costly ones.
    pub(super) fn is_rsa(self) -> bool {
        self.family() == Family::Rsa
    }

    /// Whether this is an HMAC.
    pub(super) fn is_hmac(self) -> bool {
        self.family() == Family::Symmetric
    }

    fn family(self) -> Family {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                Family::Rsa
            }
            Self::Es256 => Family::EcP256,
            Self::Es384 => Family::EcP384,
            Self::EdDsa => Family::Ed25519,
            Self::Hs256 | Self::Hs384 | Self::Hs512 => Family::Symmetric,
        }
    }

    /// The bytes of the digest of an HMAC algorithm.
    fn secret_floor(self) -> usize {
        match self {
            Self::Hs384 => 48,
            Self::Hs512 => 64,
            _ => MIN_SECRET,
        }
    }
}

/// The algorithms a configuration lists: the only ones a token may name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Algorithms(Box<[Algorithm]>);

impl Algorithms {
    /// Reads the configured names.
    ///
    /// # Errors
    ///
    /// A message when the list is empty, names an algorithm that is not supported (`none`
    /// included), repeats one, or lists more than four of `RS*` and `PS*` together.
    pub(super) fn compile(names: &[String]) -> Result<Self, String> {
        if names.is_empty() {
            return Err("`algorithms` is empty; list the algorithms a token may use".to_owned());
        }
        let mut list: Vec<Algorithm> = Vec::with_capacity(names.len());
        for name in names {
            let algorithm = Algorithm::parse(name).ok_or_else(|| {
                format!(
                    "`algorithms`: {name:?} is not one of RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, EdDSA, HS256, HS384, HS512 (\"none\" is never accepted)"
                )
            })?;
            if list.contains(&algorithm) {
                return Err(format!("`algorithms` lists {name} twice"));
            }
            list.push(algorithm);
        }
        let costly = list.iter().filter(|algorithm| algorithm.is_rsa()).count();
        if costly > 4 {
            return Err(format!(
                "`algorithms` lists {costly} of RS* and PS* algorithms; at most 4, each costs a modular exponentiation per request"
            ));
        }
        Ok(Self(list.into_boxed_slice()))
    }

    pub(super) fn contains(&self, algorithm: Algorithm) -> bool {
        self.0.contains(&algorithm)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = Algorithm> + '_ {
        self.0.iter().copied()
    }
}

/// Why a key is refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum KeyError {
    #[error("a key is not a JSON object")]
    NotObject,
    #[error("`kty` {0:?} is not RSA, EC, OKP or oct")]
    Kty(Box<str>),
    #[error("`{0}` is missing or not a string")]
    Field(&'static str),
    #[error("`{0}` is not unpadded base64url")]
    Encoding(&'static str),
    #[error("the key carries private key material (`{0}`)")]
    Private(&'static str),
    #[error("the RSA modulus is {0} bits, outside 2048 to 8192")]
    RsaSize(usize),
    #[error("the RSA public exponent is not an odd number from 65537 up")]
    RsaExponent,
    #[error("curve {0:?} is not P-256, P-384 or Ed25519")]
    Curve(Box<str>),
    #[error("an EC coordinate or an Ed25519 key has the wrong length")]
    Point,
    #[error("the symmetric key is shorter than {MIN_SECRET} bytes")]
    ShortSecret,
    #[error("`use` is not \"sig\"")]
    Use,
    #[error("`key_ops` does not allow verify")]
    Ops,
    #[error("`alg` is not an algorithm this key type can serve")]
    Alg,
    #[error("a symmetric key is accepted only in `keys`, never from a JWKS endpoint")]
    RemoteSymmetric,
}

#[derive(Clone, PartialEq, Eq)]
enum Material {
    Rsa { n: Box<[u8]>, e: Box<[u8]> },
    EcP256(Box<[u8]>),
    EcP384(Box<[u8]>),
    Ed25519(Box<[u8]>),
    Symmetric(Box<[u8]>),
}

impl Material {
    fn family(&self) -> Family {
        match self {
            Self::Rsa { .. } => Family::Rsa,
            Self::EcP256(_) => Family::EcP256,
            Self::EcP384(_) => Family::EcP384,
            Self::Ed25519(_) => Family::Ed25519,
            Self::Symmetric(_) => Family::Symmetric,
        }
    }
}

/// A key a token may be checked with.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    kid: Option<Box<str>>,
    /// The one algorithm the key is bound to, when the JWK says so.
    bound: Option<Algorithm>,
    material: Material,
}

/// Never shows key material: an `oct` key is a secret and the others add nothing to a log.
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("family", &self.material.family())
            .finish_non_exhaustive()
    }
}

fn text<'a>(object: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, KeyError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(KeyError::Field(field))
}

fn decoded(object: &Map<String, Value>, field: &'static str) -> Result<Vec<u8>, KeyError> {
    URL_SAFE_NO_PAD
        .decode(text(object, field)?)
        .map_err(|_| KeyError::Encoding(field))
}

fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// The size of a big-endian number in bits, leading zeros not counted.
fn bit_length(bytes: &[u8]) -> usize {
    match bytes.first() {
        None => 0,
        Some(first) => (bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    }
}

impl Key {
    /// Reads one JWK. `remote` is a key from a JWKS endpoint, which may not be symmetric.
    ///
    /// # Errors
    ///
    /// [`KeyError`] naming what is wrong: a key that cannot verify, that is too weak or too
    /// strong, or that carries a private part.
    pub(super) fn from_jwk(value: &Value, remote: bool) -> Result<Self, KeyError> {
        let object = value.as_object().ok_or(KeyError::NotObject)?;
        for private in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
            if object.contains_key(private) {
                return Err(KeyError::Private(private));
            }
        }
        if let Some(usage) = object.get("use")
            && usage.as_str() != Some("sig")
        {
            return Err(KeyError::Use);
        }
        if let Some(ops) = object.get("key_ops")
            && !ops
                .as_array()
                .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
        {
            return Err(KeyError::Ops);
        }
        let kid = match object.get("kid") {
            None => None,
            Some(Value::String(kid)) => Some(Box::<str>::from(kid.as_str())),
            Some(_) => return Err(KeyError::Field("kid")),
        };
        let bound = match object.get("alg") {
            None => None,
            Some(alg) => Some(
                alg.as_str()
                    .and_then(Algorithm::parse)
                    .ok_or(KeyError::Alg)?,
            ),
        };
        let material = match text(object, "kty")? {
            "RSA" => {
                let n = decoded(object, "n")?;
                let e = decoded(object, "e")?;
                let (n, e) = (strip_zeros(&n), strip_zeros(&e));
                let bits = bit_length(n);
                if !RSA_BITS.contains(&bits) {
                    return Err(KeyError::RsaSize(bits));
                }
                // ring takes up to 33 bits; 5 bytes cover them.
                let exponent = e
                    .iter()
                    .try_fold(0_u64, |acc, byte| {
                        (e.len() <= 5).then(|| (acc << 8) | u64::from(*byte))
                    })
                    .filter(|value| *value >= 65537 && value % 2 == 1)
                    .ok_or(KeyError::RsaExponent)?;
                debug_assert!(exponent >= 65537);
                Material::Rsa {
                    n: n.into(),
                    e: e.into(),
                }
            }
            "EC" => {
                let (curve, size) = match text(object, "crv")? {
                    "P-256" => (Family::EcP256, 32),
                    "P-384" => (Family::EcP384, 48),
                    other => return Err(KeyError::Curve(other.into())),
                };
                let (x, y) = (decoded(object, "x")?, decoded(object, "y")?);
                if x.len() != size || y.len() != size {
                    return Err(KeyError::Point);
                }
                let mut point = Vec::with_capacity(1 + 2 * size);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                if curve == Family::EcP256 {
                    Material::EcP256(point.into())
                } else {
                    Material::EcP384(point.into())
                }
            }
            "OKP" => {
                let curve = text(object, "crv")?;
                if curve != "Ed25519" {
                    return Err(KeyError::Curve(curve.into()));
                }
                let x = decoded(object, "x")?;
                if x.len() != 32 {
                    return Err(KeyError::Point);
                }
                Material::Ed25519(x.into())
            }
            "oct" => {
                if remote {
                    return Err(KeyError::RemoteSymmetric);
                }
                let secret = decoded(object, "k")?;
                if secret.len() < MIN_SECRET {
                    return Err(KeyError::ShortSecret);
                }
                Material::Symmetric(secret.into())
            }
            other => return Err(KeyError::Kty(other.into())),
        };
        if let Some(bound) = bound
            && bound.family() != material.family()
        {
            return Err(KeyError::Alg);
        }
        Ok(Self {
            kid,
            bound,
            material,
        })
    }

    /// Whether the key is symmetric.
    pub(super) fn is_symmetric(&self) -> bool {
        self.material.family() == Family::Symmetric
    }

    /// Whether the key may check a token signed with `algorithm`: the type fits, the JWK's own
    /// `alg` (when it has one) is this algorithm, and a symmetric key is long enough.
    fn serves(&self, algorithm: Algorithm) -> bool {
        self.material.family() == algorithm.family()
            && self.bound.is_none_or(|bound| bound == algorithm)
            && match &self.material {
                Material::Symmetric(secret) => secret.len() >= algorithm.secret_floor(),
                _ => true,
            }
    }

    /// Checks `signature` over `input`. A key of another type than `algorithm` needs checks
    /// false, whoever asks.
    fn verify(&self, algorithm: Algorithm, input: &[u8], sig: &[u8]) -> bool {
        use Algorithm as A;
        match (&self.material, algorithm) {
            (
                Material::Rsa { n, e },
                A::Rs256 | A::Rs384 | A::Rs512 | A::Ps256 | A::Ps384 | A::Ps512,
            ) => {
                let params = match algorithm {
                    A::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    A::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
                    A::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    A::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
                    A::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
                    _ => &signature::RSA_PSS_2048_8192_SHA512,
                };
                signature::RsaPublicKeyComponents {
                    n: n.as_ref(),
                    e: e.as_ref(),
                }
                .verify(params, input, sig)
                .is_ok()
            }
            (Material::EcP256(point), A::Es256) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(input, sig)
                    .is_ok()
            }
            (Material::EcP384(point), A::Es384) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, point)
                    .verify(input, sig)
                    .is_ok()
            }
            (Material::Ed25519(point), A::EdDsa) => {
                signature::UnparsedPublicKey::new(&signature::ED25519, point)
                    .verify(input, sig)
                    .is_ok()
            }
            (Material::Symmetric(secret), A::Hs256 | A::Hs384 | A::Hs512) => {
                let digest = match algorithm {
                    A::Hs256 => hmac::HMAC_SHA256,
                    A::Hs384 => hmac::HMAC_SHA384,
                    _ => hmac::HMAC_SHA512,
                };
                hmac::verify(&hmac::Key::new(digest, secret), input, sig).is_ok()
            }
            _ => false,
        }
    }
}

/// A set of keys: the `keys` of a configuration, or what a JWKS endpoint answered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct KeySet {
    keys: Vec<Key>,
}

/// Why a JWKS answer is not used.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum SetError {
    #[error("the body is not a JWK set")]
    NotASet,
    #[error("no key of the set can be used")]
    NoUsableKey,
    #[error("{0}")]
    Key(KeyError),
    #[error("the set has more than {MAX_KEYS} keys")]
    TooMany,
    #[error("two keys have the kid {0:?}")]
    DuplicateKid(Box<str>),
}

impl KeySet {
    /// Reads the `keys` of a configuration: every key must be good, none may repeat a `kid`.
    ///
    /// # Errors
    ///
    /// [`SetError`] for the first key that is refused, a set that is not `{"keys": [...]}`,
    /// more than [`MAX_KEYS`] keys or a repeated `kid`.
    pub(super) fn inline(value: &Value) -> Result<Self, SetError> {
        let list = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(SetError::NotASet)?;
        if list.len() > MAX_KEYS {
            return Err(SetError::TooMany);
        }
        let mut keys: Vec<Key> = Vec::with_capacity(list.len());
        for entry in list {
            let key = Key::from_jwk(entry, false).map_err(SetError::Key)?;
            if let Some(kid) = &key.kid
                && keys.iter().any(|other| other.kid.as_ref() == Some(kid))
            {
                return Err(SetError::DuplicateKid(kid.clone()));
            }
            keys.push(key);
        }
        Ok(Self { keys })
    }

    /// Reads a JWKS answer: the first [`MAX_KEYS`] keys, of which the unusable ones (weak,
    /// private, symmetric, of a type this verifier does not support) are left out. Returns the
    /// set and how many keys were left out.
    ///
    /// # Errors
    ///
    /// [`SetError`] when the body is not a JWK set or none of its keys can be used; the caller
    /// keeps what it had.
    pub(super) fn remote(body: &[u8]) -> Result<(Self, usize), SetError> {
        let value: Value = serde_json::from_slice(body).map_err(|_| SetError::NotASet)?;
        let list = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(SetError::NotASet)?;
        let mut keys = Vec::with_capacity(list.len().min(MAX_KEYS));
        let mut skipped = 0;
        for entry in list.iter().take(MAX_KEYS) {
            match Key::from_jwk(entry, true) {
                Ok(key) => keys.push(key),
                Err(_) => skipped += 1,
            }
        }
        if keys.is_empty() {
            return Err(SetError::NoUsableKey);
        }
        Ok((Self { keys }, skipped))
    }

    /// The number of keys.
    pub(super) fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set has a symmetric key.
    pub(super) fn has_symmetric(&self) -> bool {
        self.keys.iter().any(Key::is_symmetric)
    }

    /// The keys, for comparing two configurations.
    pub(super) fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// Descriptions of the keys, `kid` and type, for explain.
    pub(super) fn describe(&self) -> Vec<Value> {
        self.keys
            .iter()
            .map(|key| {
                serde_json::json!({
                    "kid": key.kid.as_deref(),
                    "type": format!("{:?}", key.material.family()),
                })
            })
            .collect()
    }
}

/// A token, split and decoded up to its header. The claims are decoded after the signature.
#[derive(Debug)]
pub(super) struct Token<'a> {
    algorithm: Algorithm,
    kid: Option<String>,
    signing_input: &'a [u8],
    signature: Vec<u8>,
    payload: &'a str,
}

impl<'a> Token<'a> {
    /// Splits `raw` and reads its header against the `allowed` algorithms.
    ///
    /// # Errors
    ///
    /// [`Failure::Oversized`], [`Failure::Malformed`], [`Failure::Crit`] or
    /// [`Failure::AlgNotAllowed`].
    pub(super) fn parse(raw: &'a str, allowed: &Algorithms) -> Result<Self, Failure> {
        if raw.len() > MAX_TOKEN {
            return Err(Failure::Oversized);
        }
        let (header, rest) = raw.split_once('.').ok_or(Failure::Malformed)?;
        let (payload, sig) = rest.split_once('.').ok_or(Failure::Malformed)?;
        if sig.contains('.') {
            return Err(Failure::Malformed);
        }
        let header: Value = URL_SAFE_NO_PAD
            .decode(header)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or(Failure::Malformed)?;
        let header = header.as_object().ok_or(Failure::Malformed)?;
        if header.contains_key("crit") {
            return Err(Failure::Crit);
        }
        let name = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(Failure::Malformed)?;
        let algorithm = Algorithm::parse(name)
            .filter(|algorithm| allowed.contains(*algorithm))
            .ok_or(Failure::AlgNotAllowed)?;
        let kid = match header.get("kid") {
            None => None,
            Some(Value::String(kid)) if kid.len() <= MAX_KID => Some(kid.clone()),
            Some(_) => return Err(Failure::Malformed),
        };
        let signature = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| Failure::Malformed)?;
        if signature.is_empty() || payload.is_empty() {
            return Err(Failure::Malformed);
        }
        let signed = raw.len() - sig.len() - 1;
        Ok(Self {
            algorithm,
            kid,
            signing_input: &raw.as_bytes()[..signed],
            signature,
            payload,
        })
    }

    /// The `kid` of the header.
    pub(super) fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The claims. Call it after [`verify`]: the payload of an unchecked token is not to be
    /// believed.
    ///
    /// # Errors
    ///
    /// [`Failure::Malformed`] when the payload is not a JSON object.
    pub(super) fn claims(&self) -> Result<Map<String, Value>, Failure> {
        let bytes = URL_SAFE_NO_PAD
            .decode(self.payload)
            .map_err(|_| Failure::Malformed)?;
        match serde_json::from_slice(&bytes) {
            Ok(Value::Object(claims)) => Ok(claims),
            _ => Err(Failure::Malformed),
        }
    }
}

/// The keys that may check a token with `algorithm` and `kid`, at most [`MAX_CANDIDATES`], and
/// whether any key of `sets` carries that `kid` at all.
fn select<'a>(
    sets: &[&'a KeySet],
    algorithm: Algorithm,
    kid: Option<&str>,
) -> (Vec<&'a Key>, bool) {
    let mut chosen = Vec::new();
    let mut kid_seen = false;
    for key in sets.iter().flat_map(|set| set.keys.iter()) {
        if let Some(kid) = kid {
            if key.kid.as_deref() != Some(kid) {
                continue;
            }
            kid_seen = true;
        }
        if key.serves(algorithm) && chosen.len() < MAX_CANDIDATES {
            chosen.push(key);
        }
    }
    (chosen, kid_seen)
}

/// Checks the signature of `token` against the keys of `sets` (the configuration's, then the
/// JWKS').
///
/// # Errors
///
/// [`Failure::UnknownKid`] when the token names a `kid` no key has, [`Failure::NoKey`] when keys
/// exist but none of the token's algorithm and `kid`, [`Failure::BadSignature`] otherwise.
pub(super) fn verify(token: &Token<'_>, sets: &[&KeySet]) -> Result<(), Failure> {
    let (candidates, kid_seen) = select(sets, token.algorithm, token.kid());
    if candidates.is_empty() {
        return Err(if token.kid().is_some() && !kid_seen {
            Failure::UnknownKid
        } else {
            Failure::NoKey
        });
    }
    if candidates
        .iter()
        .any(|key| key.verify(token.algorithm, token.signing_input, &token.signature))
    {
        Ok(())
    } else {
        Err(Failure::BadSignature)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;
    use crate::middleware::jwt_auth::fixture::{Signer, forge_hmac, now, unsigned};

    fn allowed(names: &[&str]) -> Algorithms {
        Algorithms::compile(&names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
            .expect("algorithms")
    }

    fn set(signers: &[&Signer]) -> KeySet {
        KeySet::inline(&json!({"keys": signers.iter().map(|s| s.jwk()).collect::<Vec<_>>()}))
            .expect("key set")
    }

    fn claims() -> Value {
        json!({"sub": "ann", "exp": now() + 600})
    }

    fn check(token: &str, algorithms: &[&str], keys: &KeySet) -> Result<(), Failure> {
        let parsed = Token::parse(token, &allowed(algorithms))?;
        verify(&parsed, &[keys])
    }

    #[test]
    fn jwt_rs256_accepted() {
        let key = Signer::rsa_a("k1");
        let token = key.sign("RS256", &json!({}), &claims());
        assert_eq!(check(&token, &["RS256"], &set(&[&key])), Ok(()));
    }

    #[test]
    fn jwt_ps256_accepted() {
        let key = Signer::rsa_a("k1");
        let token = key.sign("PS256", &json!({}), &claims());
        assert_eq!(check(&token, &["PS256"], &set(&[&key])), Ok(()));
        // The same key does not check an RS256 token that names the other padding.
        let token = key.sign("RS256", &json!({}), &claims());
        assert_eq!(check(&token, &["RS256", "PS256"], &set(&[&key])), Ok(()));
    }

    #[test]
    fn jwt_es256_accepted() {
        let key = Signer::es256("k1");
        let token = key.sign("ES256", &json!({}), &claims());
        assert_eq!(check(&token, &["ES256"], &set(&[&key])), Ok(()));
        let other = Signer::es384("k2");
        let token = other.sign("ES384", &json!({}), &claims());
        assert_eq!(check(&token, &["ES384"], &set(&[&other])), Ok(()));
    }

    #[test]
    fn jwt_eddsa_accepted() {
        let key = Signer::ed25519("k1");
        let token = key.sign("EdDSA", &json!({}), &claims());
        assert_eq!(check(&token, &["EdDSA"], &set(&[&key])), Ok(()));
    }

    #[test]
    fn jwt_bad_signature_401() {
        let key = Signer::rsa_a("k1");
        let impostor = Signer::rsa_b("k1");
        let token = impostor.sign("RS256", &json!({}), &claims());
        assert_eq!(
            check(&token, &["RS256"], &set(&[&key])),
            Err(Failure::BadSignature)
        );
        // One flipped bit in the payload.
        let good = key.sign("RS256", &json!({}), &claims());
        let mut parts: Vec<String> = good.split('.').map(str::to_owned).collect();
        parts[1] = URL_SAFE_NO_PAD.encode(json!({"sub": "root", "exp": now() + 600}).to_string());
        assert_eq!(
            check(&parts.join("."), &["RS256"], &set(&[&key])),
            Err(Failure::BadSignature)
        );
    }

    #[test]
    fn jwt_wrong_kid_and_wrong_key_type() {
        let key = Signer::rsa_a("k1");
        let token = key.sign("RS256", &json!({}), &claims());
        let other = Signer::es256("k9");
        // No key has kid k1: the verifier says so, so a refresh may be tried.
        assert_eq!(
            check(&token, &["RS256"], &set(&[&other])),
            Err(Failure::UnknownKid)
        );
        // The kid exists on a key of another type.
        let clash = Signer::es256("k1");
        assert_eq!(
            check(&token, &["RS256"], &set(&[&clash])),
            Err(Failure::NoKey)
        );
    }

    #[test]
    fn jwt_wrong_key_type_401() {
        let rsa = Signer::rsa_a("k1");
        let token = rsa.sign("RS256", &json!({}), &claims());
        for wrong in [Signer::es256("k1"), Signer::ed25519("k1")] {
            assert!(check(&token, &["RS256"], &set(&[&wrong])).is_err());
        }
        let ec = Signer::es256("k1");
        let token = ec.sign("ES256", &json!({}), &claims());
        assert!(check(&token, &["ES256"], &set(&[&Signer::es384("k1")])).is_err());
    }

    #[test]
    fn jwt_alg_none_rejected() {
        let key = Signer::rsa_a("k1");
        for name in ["none", "None", "NONE", "nOnE"] {
            let token = unsigned(name, &claims());
            let parsed = Token::parse(&token, &allowed(&["RS256"]));
            assert_eq!(parsed.err(), Some(Failure::AlgNotAllowed), "{name}");
        }
        // Not even a list that someone filled with it.
        assert!(Algorithms::compile(&["none".to_owned()]).is_err());
        assert!(Algorithms::compile(&["RS256".to_owned(), "none".to_owned()]).is_err());
        drop(key);
    }

    #[test]
    fn jwt_alg_not_listed_rejected() {
        let key = Signer::rsa_a("k1");
        let token = key.sign("RS384", &json!({}), &claims());
        assert_eq!(
            check(&token, &["RS256"], &set(&[&key])),
            Err(Failure::AlgNotAllowed)
        );
        let ps = key.sign("PS256", &json!({}), &claims());
        assert_eq!(
            check(&ps, &["RS256"], &set(&[&key])),
            Err(Failure::AlgNotAllowed)
        );
    }

    #[test]
    fn jwt_alg_confusion_hs_with_rsa_key_rejected() {
        let rsa = Signer::rsa_a("k1");
        let secret = Signer::hmac("k2", &[7; 48]);
        // The attacker signs an HS256 token with the RSA public key bytes (DER and the modulus)
        // as the secret, and names the RSA key's kid or none.
        let jwk = rsa.jwk();
        let n = URL_SAFE_NO_PAD
            .decode(jwk["n"].as_str().expect("n"))
            .expect("n bytes");
        for secret_bytes in [rsa.public_der(), n, jwk.to_string().into_bytes()] {
            for kid in [Some("k1"), None] {
                let token = forge_hmac("HS256", &secret_bytes, kid, &claims());
                let keys = set(&[&rsa, &secret]);
                let result = check(&token, &["RS256", "HS256"], &keys);
                assert!(
                    matches!(result, Err(Failure::NoKey | Failure::BadSignature)),
                    "{kid:?}: {result:?}"
                );
            }
        }
        // With only the RSA key, HS256 has no key to use at all.
        let token = forge_hmac("HS256", &rsa.public_der(), Some("k1"), &claims());
        assert_eq!(
            check(&token, &["RS256", "HS256"], &set(&[&rsa])),
            Err(Failure::NoKey)
        );
    }

    #[test]
    fn jwt_hmac_with_its_own_key_accepted() {
        let secret = Signer::hmac("k2", &[7; 64]);
        for alg in ["HS256", "HS384", "HS512"] {
            let token = secret.sign(alg, &json!({}), &claims());
            assert_eq!(check(&token, &[alg], &set(&[&secret])), Ok(()), "{alg}");
        }
        // HS512 wants a key of at least 64 bytes.
        let short = Signer::hmac("k3", &[7; 40]);
        let token = short.sign("HS512", &json!({}), &claims());
        assert_eq!(
            check(&token, &["HS512"], &set(&[&short])),
            Err(Failure::NoKey)
        );
    }

    #[test]
    fn jwt_crit_header_rejected() {
        let key = Signer::rsa_a("k1");
        for crit in [json!(["exp"]), json!(["b64"]), json!([]), json!(null)] {
            let token = key.sign("RS256", &json!({"crit": crit}), &claims());
            let parsed = Token::parse(&token, &allowed(&["RS256"]));
            assert_eq!(parsed.err(), Some(Failure::Crit));
        }
    }

    #[test]
    fn jwt_oversized_token_rejected() {
        let key = Signer::rsa_a("k1");
        let big = json!({"sub": "ann", "exp": now() + 600, "pad": "a".repeat(MAX_TOKEN)});
        let token = key.sign("RS256", &json!({}), &big);
        assert!(token.len() > MAX_TOKEN);
        let parsed = Token::parse(&token, &allowed(&["RS256"]));
        assert_eq!(parsed.err(), Some(Failure::Oversized));
    }

    #[test]
    fn a_token_is_read_strictly() {
        let key = Signer::rsa_a("k1");
        let token = key.sign("RS256", &json!({}), &claims());
        let alg = allowed(&["RS256"]);
        let mut cases = vec![
            String::new(),
            "a.b".to_owned(),
            format!("{token}.x"),
            format!("{token}="),
            format!("{token}@"),
        ];
        let (head, rest) = token.split_once('.').expect("dots");
        cases.push(format!("{head}=.{rest}"));
        for bad in &cases {
            assert!(Token::parse(bad, &alg).is_err(), "{bad:.40}");
        }
        // alg and kid must be strings.
        for header in [json!({"alg": ["RS256"]}), json!({"alg": "RS256", "kid": 1})] {
            let raw = format!(
                "{}.{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode("{}"),
                URL_SAFE_NO_PAD.encode("sig")
            );
            assert_eq!(Token::parse(&raw, &alg).err(), Some(Failure::Malformed));
        }
    }

    fn rsa_jwk(bits_of_n: usize, e: &[u8]) -> Value {
        let mut n = vec![0xff_u8; bits_of_n.div_ceil(8)];
        let spare = n.len() * 8 - bits_of_n;
        n[0] >>= spare;
        json!({"kty": "RSA", "n": URL_SAFE_NO_PAD.encode(n), "e": URL_SAFE_NO_PAD.encode(e)})
    }

    #[test]
    fn jwt_weak_rsa_key_rejected() {
        let rsa = |bits| Key::from_jwk(&rsa_jwk(bits, &[1, 0, 1]), false);
        assert_eq!(rsa(1024).err(), Some(KeyError::RsaSize(1024)));
        assert_eq!(rsa(2047).err(), Some(KeyError::RsaSize(2047)));
        assert!(rsa(2048).is_ok());
        assert!(rsa(8192).is_ok());
        assert_eq!(rsa(8193).err(), Some(KeyError::RsaSize(8193)));
        assert_eq!(rsa(16384).err(), Some(KeyError::RsaSize(16384)));
        for exponent in [&[3_u8][..], &[1, 0, 0], &[1, 0, 2], &[1, 0, 0, 0, 0, 1]] {
            assert_eq!(
                Key::from_jwk(&rsa_jwk(2048, exponent), false).err(),
                Some(KeyError::RsaExponent),
                "{exponent:?}"
            );
        }
        // Remote keys that are too weak are left out, and when none is left the set is refused.
        let body = json!({"keys": [rsa_jwk(1024, &[1, 0, 1])]}).to_string();
        assert_eq!(
            KeySet::remote(body.as_bytes()).err(),
            Some(SetError::NoUsableKey)
        );
    }

    #[test]
    fn jwt_algorithm_list_bounded() {
        let names = |list: &[&str]| list.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert!(Algorithms::compile(&names(&["RS256", "RS384", "RS512", "PS256"])).is_ok());
        assert!(
            Algorithms::compile(&names(&["RS256", "RS384", "RS512", "PS256", "PS384"])).is_err()
        );
        assert!(
            Algorithms::compile(&names(&[
                "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"
            ]))
            .is_err()
        );
        // Cheap algorithms do not count.
        assert!(
            Algorithms::compile(&names(&[
                "RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA"
            ]))
            .is_ok()
        );
        assert!(Algorithms::compile(&names(&[])).is_err());
        assert!(Algorithms::compile(&names(&["RS256", "RS256"])).is_err());
        assert!(Algorithms::compile(&names(&["rs256"])).is_err());
        assert!(Algorithms::compile(&names(&["ES512"])).is_err());
    }

    #[test]
    fn keys_are_read_strictly() {
        let rsa = Signer::rsa_a("k1").jwk();
        let mut private = rsa.clone();
        private["d"] = json!("AQAB");
        assert_eq!(
            Key::from_jwk(&private, false).err(),
            Some(KeyError::Private("d"))
        );
        let mut enc = rsa.clone();
        enc["use"] = json!("enc");
        assert_eq!(Key::from_jwk(&enc, false).err(), Some(KeyError::Use));
        let mut ops = rsa.clone();
        ops["key_ops"] = json!(["sign"]);
        assert_eq!(Key::from_jwk(&ops, false).err(), Some(KeyError::Ops));
        let mut bound = rsa.clone();
        bound["alg"] = json!("ES256");
        assert_eq!(Key::from_jwk(&bound, false).err(), Some(KeyError::Alg));
        // A key bound to RS256 does not serve PS256.
        let mut bound = rsa.clone();
        bound["alg"] = json!("RS256");
        let key = Key::from_jwk(&bound, false).expect("key");
        assert!(key.serves(Algorithm::Rs256) && !key.serves(Algorithm::Ps256));
        // A symmetric key is for the configuration only, and must be long enough.
        let oct = Signer::hmac("k", &[1; 32]).jwk();
        assert_eq!(
            Key::from_jwk(&oct, true).err(),
            Some(KeyError::RemoteSymmetric)
        );
        assert!(Key::from_jwk(&oct, false).is_ok());
        let short = Signer::hmac("k", &[1; 31]).jwk();
        assert_eq!(
            Key::from_jwk(&short, false).err(),
            Some(KeyError::ShortSecret)
        );
        let ec = Signer::es256("k").jwk();
        let mut p521 = ec.clone();
        p521["crv"] = json!("P-521");
        assert!(matches!(
            Key::from_jwk(&p521, false).err(),
            Some(KeyError::Curve(_))
        ));
        let mut short_x = ec.clone();
        short_x["x"] = json!(URL_SAFE_NO_PAD.encode([1_u8; 31]));
        assert_eq!(Key::from_jwk(&short_x, false).err(), Some(KeyError::Point));
        assert_eq!(
            Key::from_jwk(&json!({"kty": "dsa"}), false).err(),
            Some(KeyError::Kty("dsa".into()))
        );
        let debug = format!("{:?}", Key::from_jwk(&oct, false).expect("key"));
        assert!(!debug.contains("AQEB"), "{debug}");
    }

    #[test]
    fn at_most_four_keys_are_tried_without_a_kid() {
        let signers: Vec<Signer> = (0..6).map(|n| Signer::es256(&format!("k{n}"))).collect();
        let keys = set(&signers.iter().collect::<Vec<_>>());
        // The fifth and sixth key are never tried.
        let token = signers[3].sign("ES256", &json!({"kid": null}), &claims());
        let without_kid = token
            .split('.')
            .enumerate()
            .map(|(index, part)| {
                if index == 0 {
                    URL_SAFE_NO_PAD.encode(json!({"alg": "ES256"}).to_string())
                } else {
                    part.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(".");
        // The header changed after signing, so only the kid-less path is exercised: a bad
        // signature, from keys that were all tried.
        assert_eq!(
            check(&without_kid, &["ES256"], &keys),
            Err(Failure::BadSignature)
        );
        let (chosen, _) = select(&[&keys], Algorithm::Es256, None);
        assert_eq!(chosen.len(), MAX_CANDIDATES);
    }

    #[test]
    fn a_jwk_set_is_bounded_and_may_not_repeat_a_kid() {
        let key = Signer::es256("k").jwk();
        let many = json!({"keys": vec![key.clone(); MAX_KEYS + 1]});
        assert_eq!(KeySet::inline(&many).err(), Some(SetError::TooMany));
        let (set, skipped) = KeySet::remote(many.to_string().as_bytes()).expect("set");
        assert_eq!((set.len(), skipped), (MAX_KEYS, 0));
        let twice = json!({"keys": [key.clone(), key]});
        assert!(matches!(
            KeySet::inline(&twice).err(),
            Some(SetError::DuplicateKid(_))
        ));
        assert_eq!(KeySet::inline(&json!([])).err(), Some(SetError::NotASet));
        assert_eq!(KeySet::remote(b"nope").err(), Some(SetError::NotASet));
    }
}
