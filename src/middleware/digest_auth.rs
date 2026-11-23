//! The `digest_auth` middleware: HTTP Digest credentials (RFC 7616) with stateless nonces and a
//! bounded replay table. Full reference: `docs/ref/mw-digest-auth.md`.
//!
//! ```json
//! {
//!   "name": "auth", "type": "digest_auth",
//!   "users": ["alice:podgate:b1a2...64 hex digits..."], "realm": "podgate",
//!   "header_field": "x-user", "remove_header": true
//! }
//! ```
//!
//! - `qop=auth` only. Algorithms `SHA-256` and `MD5`, told apart by the length of the stored
//!   `HA1`. MD5 is accepted because existing htdigest files are MD5; the challenge offers
//!   `SHA-256` first and `MD5` only when some user has an MD5 `HA1`.
//! - A nonce is `base64url(timestamp || serial || HMAC(secret, timestamp || serial || client_ip))`: nothing is kept
//!   per nonce until a client authenticates with it. A nonce older than five minutes is
//!   answered with `stale=true`.
//! - The `nc` counter is tracked per nonce in a table of at most `REPLAY_ENTRIES` (4096) entries,
//!   each charged to the tenant's buffer budget. A request that would need a new entry when the
//!   table or the budget is full is answered `503` (`AuthBusy`; `AuthOverBudget` when the budget
//!   could never hold an entry), never by growing the table.
//! - The nonce secret, the `nc` table and the failure counter are one state per (app, name,
//!   declaration) in the shared `state::Registry`, so an unrelated push keeps them.
//! - Digests are compared in constant time and an unknown user runs the same computation as a
//!   known one. A source with five failed attempts in a minute waits a second before each
//!   further attempt is verified.
//!
//! Neither an `HA1` nor a credential is ever logged or printed.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use md5::Md5;
use pingora::http::{RequestHeader, ResponseHeader};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{CompileCx, Flow, Kind, RequestCx, Stage, headers, state};
use crate::budget::{BufferGuard, TenantBudget};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::table::CompiledApp;
use podgate_model::Declared;

const DEFAULT_REALM: &str = "podgate";
/// Most users one middleware may declare.
const MAX_USERS: usize = 4096;
/// Longest user name, in bytes, that is looked up.
const MAX_USER_BYTES: usize = 255;
/// Longest `Authorization` value, and longest single parameter value, that is parsed at all.
const MAX_HEADER_BYTES: usize = 4096;
const MAX_VALUE_BYTES: usize = 2048;
const MAX_PARAMS: usize = 24;

/// How long a nonce is accepted, in seconds. Later it is `stale`.
const NONCE_LIFETIME: u64 = 300;
/// How far into the future a nonce's timestamp may be, in seconds, before it is forged.
const NONCE_SKEW: u64 = 30;
/// Nonces the replay table tracks at once, and what each is charged to the tenant: the 32-byte
/// key, the counter, the expiry, the guard and the hash map's own overhead, rounded up.
const REPLAY_ENTRIES: usize = 4096;
const REPLAY_ENTRY_BYTES: u64 = 128;

/// Failed attempts a source gets per [`FAILURE_WINDOW`] before each further one is delayed by
/// [`FAILURE_DELAY`], and how many sources are tracked.
const FAILURES_FREE: u32 = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const FAILURE_DELAY: Duration = Duration::from_secs(1);
const FAILURE_SOURCES: usize = 4096;

/// The configuration of a `digest_auth` middleware.
#[derive(Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// htdigest entries, `user:realm:HA1`, where `HA1` is `hex(H(user:realm:password))`: 32 hex
    /// digits for MD5, 64 for SHA-256. The realm of every entry is the middleware's `realm`.
    pub users: Vec<String>,
    /// The realm of the challenge; default `podgate`.
    #[serde(default)]
    pub realm: Option<String>,
    /// Only `auth` is accepted; `auth-int` needs the body and is refused.
    #[serde(default)]
    pub qop: Option<String>,
    /// A request header that receives the user name; a value the client sent for it is replaced.
    #[serde(default)]
    pub header_field: Option<String>,
    /// Remove `Authorization` before the request goes to the upstream; default `true`. The
    /// upstream has no use for a digest response, and one it could replay is not worth handing
    /// out.
    #[serde(default = "strip_by_default")]
    pub remove_header: bool,
}

fn strip_by_default() -> bool {
    true
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("users", &format_args!("[redacted; {}]", self.users.len()))
            .field("realm", &self.realm)
            .field("qop", &self.qop)
            .field("header_field", &self.header_field)
            .field("remove_header", &self.remove_header)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha256,
    Md5,
}

impl Algorithm {
    const fn token(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Md5 => "MD5",
        }
    }

    fn parse(token: &str) -> Option<Self> {
        if token.eq_ignore_ascii_case("SHA-256") {
            Some(Self::Sha256)
        } else if token.eq_ignore_ascii_case("MD5") {
            Some(Self::Md5)
        } else {
            None
        }
    }

    /// Digits of a hex digest of this algorithm.
    const fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Md5 => 32,
        }
    }

    /// Lowercase hex of the digest of `parts` joined.
    fn hash(self, parts: &[&[u8]]) -> String {
        match self {
            Self::Sha256 => hex(&hash_with::<Sha256>(parts)),
            Self::Md5 => hex(&hash_with::<Md5>(parts)),
        }
    }
}

fn hash_with<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = D::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `response` of RFC 7616 section 3.4.1 for `qop=auth` and a stored `HA1`:
/// `H(HA1:nonce:nc:cnonce:auth:H(method:uri))`, as lowercase hex.
fn response(algorithm: Algorithm, ha1: &str, method: &str, uri: &str, claim: &Claim<'_>) -> String {
    let ha2 = algorithm.hash(&[method.as_bytes(), b":", uri.as_bytes()]);
    algorithm.hash(&[
        ha1.as_bytes(),
        b":",
        claim.nonce.as_bytes(),
        b":",
        claim.nc.as_bytes(),
        b":",
        claim.cnonce.as_bytes(),
        b":auth:",
        ha2.as_bytes(),
    ])
}

/// One user's stored `HA1`. Its `Debug` never shows it.
struct User {
    algorithm: Algorithm,
    ha1: Box<str>,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("algorithm", &self.algorithm)
            .field("ha1", &"[redacted]")
            .finish()
    }
}

/// The parameters of an `Authorization: Digest` header the middleware uses, borrowed from the
/// parsed header.
struct Claim<'a> {
    username: &'a str,
    realm: &'a str,
    nonce: &'a str,
    uri: &'a str,
    response: String,
    algorithm: Algorithm,
    cnonce: &'a str,
    /// The `nc` as sent (eight hex digits), which is what the digest covers.
    nc: &'a str,
    count: u32,
}

/// The `name=value` pairs of a `Digest` credential, names lowercased. `None` for anything that
/// is not a well-formed list: a repeated name, an unterminated quote, too many or too long
/// parameters.
fn params(value: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut rest = value;
    loop {
        rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
        if rest.is_empty() {
            return Some(out);
        }
        let (name, after) = rest.split_once('=')?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-*_.".contains(&b))
        {
            return None;
        }
        let after = after.trim_start();
        let (text, remainder) = if let Some(quoted) = after.strip_prefix('"') {
            let mut text = String::new();
            let mut chars = quoted.char_indices();
            let end = loop {
                match chars.next()? {
                    (_, '\\') => text.push(chars.next()?.1),
                    (at, '"') => break at + 1,
                    (_, c) => text.push(c),
                }
                if text.len() > MAX_VALUE_BYTES {
                    return None;
                }
            };
            (text, quoted.get(end..)?)
        } else {
            let end = after
                .find(|c: char| c == ',' || c.is_ascii_whitespace())
                .unwrap_or(after.len());
            (after.get(..end)?.to_owned(), after.get(end..)?)
        };
        if text.len() > MAX_VALUE_BYTES
            || out.len() >= MAX_PARAMS
            || out.iter().any(|(seen, _)| *seen == name)
        {
            return None;
        }
        out.push((name, text));
        rest = remainder;
    }
}

/// What the credentials of one request claim, when they are a well-formed `qop=auth` Digest
/// answer. Anything else (another scheme, `auth-int`, no `qop`, a hashed or encoded user name,
/// an unknown algorithm, a malformed `nc`) is `None`, which the caller answers with a challenge.
fn parse_claim(pairs: &[(String, String)]) -> Option<Claim<'_>> {
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if get("username*").is_some()
        || get("userhash").is_some_and(|v| !v.eq_ignore_ascii_case("false"))
    {
        return None;
    }
    if !get("qop")?.eq_ignore_ascii_case("auth") {
        return None;
    }
    let algorithm = match get("algorithm") {
        Some(token) => Algorithm::parse(token)?,
        None => Algorithm::Md5,
    };
    let nc = get("nc")?;
    let count = (nc.len() == 8 && nc.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(nc, 16).ok())
        .flatten()?;
    let cnonce = get("cnonce").filter(|value| !value.is_empty())?;
    let username = get("username").filter(|name| name.len() <= MAX_USER_BYTES)?;
    Some(Claim {
        username,
        realm: get("realm")?,
        nonce: get("nonce")?,
        uri: get("uri")?,
        response: get("response")?.to_ascii_lowercase(),
        algorithm,
        cnonce,
        nc,
        count,
    })
}

/// Whether the `uri` the client signed names the request podgate got: its request target, its
/// absolute form, or the path as the client sent it before podgate normalized it.
fn uri_matches(request: &RequestHeader, claimed: &str) -> bool {
    let target = request
        .uri
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str);
    if target == Some(claimed) || request.uri == claimed {
        return true;
    }
    RequestHeader::build("GET", claimed.as_bytes(), None)
        .ok()
        .and_then(|mut original| {
            // The client signed the path as it sent it; an encoded slash that got this far was
            // allowed by the entry point and is data here too.
            crate::entry::normalize_request(&mut original, true).ok()?;
            Some(original)
        })
        .is_some_and(|original| original.uri.path_and_query() == request.uri.path_and_query())
}

/// What a nonce says when it is checked.
#[derive(Debug, PartialEq, Eq)]
enum Nonce {
    /// Not one this middleware issued to this client.
    Invalid,
    /// Issued here, still good, with its table key and the second it expires.
    Fresh { key: [u8; 32], expires: u64 },
    /// Issued here, too old.
    Stale,
}

/// Issues and checks nonces with a secret that is random per state (see [`Runtime`]). Every
/// nonce carries a serial next to its timestamp, so two clients that ask in the same second
/// never share a nonce, and with it an `nc` counter.
struct Nonces {
    secret: [u8; 32],
    serial: AtomicU64,
}

impl fmt::Debug for Nonces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nonces")
            .field("secret", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl Nonces {
    fn tag(&self, stamp: &[u8], client: Option<IpAddr>) -> Option<Hmac<Sha256>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).ok()?;
        mac.update(stamp);
        match client.map(|addr| addr.to_canonical()) {
            Some(IpAddr::V4(v4)) => {
                mac.update(&[4]);
                mac.update(&v4.octets());
            }
            Some(IpAddr::V6(v6)) => {
                mac.update(&[6]);
                mac.update(&v6.octets());
            }
            None => mac.update(&[0]),
        }
        Some(mac)
    }

    fn issue(&self, now: u64, client: Option<IpAddr>) -> Option<String> {
        let mut raw = Vec::with_capacity(48);
        raw.extend_from_slice(&now.to_be_bytes());
        raw.extend_from_slice(&self.serial.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        let tag = self.tag(&raw, client)?.finalize().into_bytes();
        raw.extend_from_slice(&tag);
        Some(URL_SAFE_NO_PAD.encode(raw))
    }

    fn check(&self, nonce: &str, now: u64, client: Option<IpAddr>) -> Nonce {
        let Ok(raw) = URL_SAFE_NO_PAD.decode(nonce) else {
            return Nonce::Invalid;
        };
        let (Some(stamp), Some(tag)) = (raw.get(..16), raw.get(16..)) else {
            return Nonce::Invalid;
        };
        let (Some(issued), Ok(key)) = (
            stamp
                .get(..8)
                .and_then(|time| <[u8; 8]>::try_from(time).ok()),
            <[u8; 32]>::try_from(tag),
        ) else {
            return Nonce::Invalid;
        };
        let genuine = self
            .tag(stamp, client)
            .is_some_and(|mac| mac.verify_slice(&key).is_ok());
        let issued = u64::from_be_bytes(issued);
        if !genuine || issued > now.saturating_add(NONCE_SKEW) {
            Nonce::Invalid
        } else if now.saturating_sub(issued) > NONCE_LIFETIME {
            Nonce::Stale
        } else {
            Nonce::Fresh {
                key,
                expires: issued.saturating_add(NONCE_LIFETIME),
            }
        }
    }
}

/// What the replay table said about one `nc`.
#[derive(Debug, PartialEq, Eq)]
enum Use {
    Accepted,
    Replayed,
    /// The table is at its 4096 nonces and none has expired.
    TableFull,
    /// The tenant's budget is full right now but could hold an entry.
    BudgetBusy,
    /// The tenant's budget could never hold an entry.
    OverBudget,
}

struct Seen {
    last: u32,
    expires: u64,
    _charge: Option<BufferGuard>,
}

/// The highest `nc` seen per nonce, bounded and charged. Only a client that has already
/// authenticated adds an entry, and an entry lives until its nonce expires.
#[derive(Default)]
struct Replay {
    seen: HashMap<[u8; 32], Seen>,
    swept: u64,
}

impl fmt::Debug for Replay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replay")
            .field("nonces", &self.seen.len())
            .finish()
    }
}

impl Replay {
    fn accept(
        &mut self,
        key: [u8; 32],
        count: u32,
        expires: u64,
        now: u64,
        budget: Option<&Arc<TenantBudget>>,
    ) -> Use {
        if let Some(seen) = self.seen.get_mut(&key) {
            if count <= seen.last {
                return Use::Replayed;
            }
            seen.last = count;
            return Use::Accepted;
        }
        if self.seen.len() >= REPLAY_ENTRIES && self.swept < now {
            self.swept = now;
            self.seen.retain(|_, seen| seen.expires > now);
        }
        if self.seen.len() >= REPLAY_ENTRIES {
            return Use::TableFull;
        }
        let charge = match budget {
            Some(budget) => match budget.charge(REPLAY_ENTRY_BYTES) {
                Some(guard) => Some(guard),
                None if budget.fits_at_all(REPLAY_ENTRY_BYTES) => return Use::BudgetBusy,
                None => return Use::OverBudget,
            },
            None => None,
        };
        self.seen.insert(
            key,
            Seen {
                last: count,
                expires,
                _charge: charge,
            },
        );
        Use::Accepted
    }
}

/// Failed attempts per source in the current window.
#[derive(Debug, Default)]
struct Failures {
    sources: HashMap<IpAddr, (Instant, u32)>,
}

impl Failures {
    fn delayed(&self, source: IpAddr, now: Instant) -> bool {
        self.sources.get(&source).is_some_and(|(start, count)| {
            now.duration_since(*start) < FAILURE_WINDOW && *count >= FAILURES_FREE
        })
    }

    fn record(&mut self, source: IpAddr, now: Instant) {
        if !self.sources.contains_key(&source) && self.sources.len() >= FAILURE_SOURCES {
            self.sources
                .retain(|_, (start, _)| now.duration_since(*start) < FAILURE_WINDOW);
            if self.sources.len() >= FAILURE_SOURCES {
                let oldest = self
                    .sources
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(source, _)| *source);
                if let Some(oldest) = oldest {
                    self.sources.remove(&oldest);
                }
            }
        }
        let slot = self.sources.entry(source).or_insert((now, 0));
        if now.duration_since(slot.0) >= FAILURE_WINDOW {
            *slot = (now, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }
}

/// The source a failure counts against: an IPv4 address, or the /64 of an IPv6 one, so a client
/// that owns a whole /64 cannot rotate addresses.
fn source_key(addr: Option<IpAddr>) -> IpAddr {
    match addr.map(|addr| addr.to_canonical()) {
        Some(IpAddr::V6(v6)) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0_u128 << 64))),
        Some(v4) => v4,
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

/// What the middleware decided about the credentials of a request.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Known user, right digest, fresh nonce, `nc` not seen: let the request through.
    Allow(Box<str>),
    /// No credentials, or a replayed `nc`: `401` with a fresh challenge, and nobody is blamed.
    Challenge,
    /// Right digest on a nonce that expired: `401` with `stale=true`.
    Stale,
    /// Credentials that do not verify: `401` with a fresh challenge, counted against the source.
    Failed,
    /// The right digest, but the replay table or the tenant's budget has no room for the nonce
    /// right now: `503` ([`AppError::AuthBusy`], a capacity refusal).
    Busy,
    /// The tenant's budget could never hold a replay entry: `503`
    /// ([`AppError::AuthOverBudget`], which auto-revert counts).
    OverBudget,
}

/// What [`DigestAuth::decide`] reads about one request.
struct Input<'a> {
    /// The single `Authorization` value, `None` when absent or repeated.
    header: Option<&'a str>,
    request: &'a RequestHeader,
    client: Option<IpAddr>,
    budget: Option<&'a Arc<TenantBudget>>,
}

/// A compiled `digest_auth` middleware.
pub struct DigestAuth(Box<Parts>);

/// The state of a [`DigestAuth`], boxed so the stage enum stays small.
pub struct Parts {
    realm: Box<str>,
    /// The algorithms to offer, `SHA-256` first, only those some user can answer.
    offered: Vec<Algorithm>,
    header_field: Option<HeaderName>,
    remove_header: bool,
    users: HashMap<Box<str>, User>,
    runtime: Arc<Runtime>,
    /// A digest of the whole declaration: the registry hands state to an equal one only.
    fingerprint: u64,
}

impl Deref for DigestAuth {
    type Target = Parts;

    fn deref(&self) -> &Parts {
        &self.0
    }
}

/// What a middleware learns while it runs, shared by every compiled table that declares the
/// same middleware (see [`Registry`]): the nonce secret, the `nc` table and the failed
/// attempts per source. The secret and the table move together, so a nonce is never valid
/// against a table that has forgotten it.
#[derive(Debug)]
pub(crate) struct Runtime {
    nonces: Nonces,
    replay: Mutex<Replay>,
    failures: Mutex<Failures>,
}

/// The [`Runtime`] of every `digest_auth` middleware of the live table, kept by the shared
/// [`state::Registry`] and settled at the swap site ([`crate::table::TableHandle`]). A push
/// that leaves a middleware's declaration as it was keeps its nonces, spent `nc` values and
/// failure counters; a middleware whose declaration changed starts fresh.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::DigestAuth(auth) => Some((auth.0.fingerprint, &mut auth.0.runtime)),
            _ => None,
        });
    }
}

impl fmt::Debug for DigestAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestAuth")
            .field("realm", &self.realm)
            .field("header_field", &self.header_field)
            .field("remove_header", &self.remove_header)
            .field("users", &format_args!("[redacted; {}]", self.users.len()))
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("digest_auth: {message}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl DigestAuth {
    /// Decides one request. `now` is seconds since the epoch.
    fn decide(&self, now: u64, input: &Input<'_>) -> Verdict {
        let Some(header) = input.header else {
            return Verdict::Challenge;
        };
        let Some(pairs) = header
            .get(..6)
            .filter(|scheme| scheme.eq_ignore_ascii_case("digest"))
            .and_then(|_| header.get(6..))
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_whitespace()))
            .filter(|_| header.len() <= MAX_HEADER_BYTES)
            .and_then(params)
        else {
            return Verdict::Failed;
        };
        let Some(claim) = parse_claim(&pairs) else {
            return Verdict::Failed;
        };
        if claim.realm != &*self.realm || !uri_matches(input.request, claim.uri) {
            return Verdict::Failed;
        }
        let nonce = self.runtime.nonces.check(claim.nonce, now, input.client);
        if nonce == Nonce::Invalid {
            return Verdict::Failed;
        }
        let user = self.users.get(claim.username);
        let (ha1, right_algorithm) = match user {
            Some(user) => (&*user.ha1, user.algorithm == claim.algorithm),
            None => (dummy_ha1(claim.algorithm), false),
        };
        let expected = response(
            claim.algorithm,
            ha1,
            input.request.method.as_str(),
            claim.uri,
            &claim,
        );
        let digest_matches: bool = expected.as_bytes().ct_eq(claim.response.as_bytes()).into();
        if !(digest_matches && right_algorithm && user.is_some()) {
            return Verdict::Failed;
        }
        let Nonce::Fresh { key, expires } = nonce else {
            return Verdict::Stale;
        };
        let used = self
            .runtime
            .replay
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .accept(key, claim.count, expires, now, input.budget);
        match used {
            Use::Accepted => Verdict::Allow(claim.username.into()),
            Use::Replayed => Verdict::Challenge,
            Use::TableFull | Use::BudgetBusy => Verdict::Busy,
            Use::OverBudget => Verdict::OverBudget,
        }
    }

    /// The `WWW-Authenticate` headers of a fresh challenge, one per offered algorithm.
    fn challenges(&self, now: u64, client: Option<IpAddr>, stale: bool) -> Vec<HeaderValue> {
        let Some(nonce) = self.runtime.nonces.issue(now, client) else {
            return Vec::new();
        };
        self.offered
            .iter()
            .filter_map(|algorithm| {
                let stale = if stale { ", stale=true" } else { "" };
                HeaderValue::from_str(&format!(
                    "Digest realm=\"{}\", qop=\"auth\", algorithm={}, nonce=\"{nonce}\"{stale}",
                    self.realm,
                    algorithm.token()
                ))
                .ok()
            })
            .collect()
    }

    async fn challenge(
        &self,
        cx: &mut RequestCx<'_>,
        now: u64,
        client: Option<IpAddr>,
        stale: bool,
    ) -> pingora::Result<()> {
        let body = Bytes::from_static(br#"{"error":"unauthorized"}"#);
        let mut header = ResponseHeader::build(401, Some(5))?;
        for challenge in self.challenges(now, client, stale) {
            header.append_header("www-authenticate", challenge)?;
        }
        header.insert_header("content-type", "application/json")?;
        header.insert_header("content-length", body.len().to_string())?;
        header.insert_header("cache-control", "no-store")?;
        cx.session
            .write_response_header(Box::new(header), false)
            .await?;
        cx.session.write_response_body(Some(body), true).await
    }
}

/// An `HA1` for an unknown user, as long as a real one, so the same hashing runs.
fn dummy_ha1(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Sha256 => "0000000000000000000000000000000000000000000000000000000000000000",
        Algorithm::Md5 => "00000000000000000000000000000000",
    }
}

/// Parses one htdigest entry for the middleware's `realm`.
fn user_entry(line: &str, realm: &str) -> Result<(Box<str>, User), Invalid> {
    let mut parts = line.splitn(3, ':');
    let (Some(name), Some(line_realm), Some(ha1)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid("a user entry is not `user:realm:HA1`"));
    };
    if name.is_empty()
        || name.len() > MAX_USER_BYTES
        || name.chars().any(char::is_control)
        || name.starts_with(' ')
        || name.ends_with(' ')
    {
        return Err(invalid(format!("{name:?} is not a usable user name")));
    }
    if line_realm != realm {
        return Err(invalid(format!(
            "user {name:?} is for realm {line_realm:?}, not the middleware's realm {realm:?}"
        )));
    }
    let algorithm = [Algorithm::Sha256, Algorithm::Md5]
        .into_iter()
        .find(|algorithm| ha1.len() == algorithm.hex_len())
        .filter(|_| ha1.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            invalid(format!(
                "user {name:?}: the HA1 is not 32 (MD5) or 64 (SHA-256) hex digits"
            ))
        })?;
    Ok((
        name.into(),
        User {
            algorithm,
            ha1: ha1.to_ascii_lowercase().into(),
        },
    ))
}

impl Kind for DigestAuth {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        match config.qop.as_deref() {
            None | Some("auth") => {}
            Some("auth-int") => {
                return Err(invalid(
                    "`qop: auth-int` is not supported: it digests the request body, which podgate does not buffer for authentication",
                ));
            }
            Some(other) => return Err(invalid(format!("`qop` {other:?} is not `auth`"))),
        }
        if config.users.is_empty() {
            return Err(invalid(
                "`users` is empty; a chain that admits nobody is a mistake",
            ));
        }
        if config.users.len() > MAX_USERS {
            return Err(invalid(format!("more than {MAX_USERS} users")));
        }
        let realm = config.realm.unwrap_or_else(|| DEFAULT_REALM.to_owned());
        if realm.is_empty()
            || realm
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(invalid(
                "`realm` must be non-empty and free of control characters, `\"` and `\\`",
            ));
        }
        let mut users = HashMap::with_capacity(config.users.len());
        for line in &config.users {
            let (name, user) = user_entry(line, &realm)?;
            if users.insert(name.clone(), user).is_some() {
                return Err(invalid(format!("user {name:?} is declared twice")));
            }
        }
        let offered = [Algorithm::Sha256, Algorithm::Md5]
            .into_iter()
            .filter(|algorithm| users.values().any(|user| user.algorithm == *algorithm))
            .collect();
        let header_field = config
            .header_field
            .as_deref()
            .map(|raw| {
                let name = HeaderName::from_bytes(raw.as_bytes())
                    .map_err(|_| invalid(format!("`header_field` {raw:?} is not a header name")))?;
                if headers::FORBIDDEN.contains(&name.as_str())
                    || name.as_str().starts_with("proxy-")
                    || name == AUTHORIZATION
                {
                    return Err(invalid(format!(
                        "`header_field` {name} cannot carry the user name: it belongs to the connection or to authorization"
                    )));
                }
                Ok(name)
            })
            .transpose()?;
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| invalid("the system has no randomness"))?;
        Ok(Self(Box::new(Parts {
            realm: realm.into(),
            offered,
            header_field,
            remove_header: config.remove_header,
            users,
            runtime: Arc::new(Runtime {
                nonces: Nonces {
                    secret,
                    serial: AtomicU64::new(0),
                },
                replay: Mutex::default(),
                failures: Mutex::default(),
            }),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let now = unix_now();
        let client = cx.forwarded.known_client();
        let source = source_key(client);
        let verdict = {
            let mut values = cx
                .session
                .req_header()
                .headers
                .get_all(AUTHORIZATION)
                .iter();
            let first = values.next();
            let header = if values.next().is_some() { None } else { first };
            let text = header.and_then(|value| value.to_str().ok());
            let delayed = first.is_some()
                && self
                    .runtime
                    .failures
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .delayed(source, Instant::now());
            if delayed {
                tokio::time::sleep(FAILURE_DELAY).await;
            }
            self.decide(
                now,
                &Input {
                    header: text,
                    request: cx.session.req_header(),
                    client,
                    budget: cx.tenant,
                },
            )
        };
        match verdict {
            Verdict::Allow(user) => {
                let request = cx.session.req_header_mut();
                if let Some(field) = &self.header_field {
                    request.insert_header(field.clone(), user.as_bytes())?;
                }
                if self.remove_header {
                    request.remove_header(&AUTHORIZATION);
                }
                Ok(Flow::Continue)
            }
            Verdict::Busy | Verdict::OverBudget => {
                let err = if verdict == Verdict::Busy {
                    AppError::AuthBusy
                } else {
                    AppError::AuthOverBudget
                };
                tracing::warn!(app = cx.app.id(), "digest_auth refused: {err}");
                *cx.capacity_refusal = err.is_capacity_refusal();
                crate::respond::write_error(cx.session, &err).await?;
                Ok(Flow::Respond)
            }
            Verdict::Challenge | Verdict::Stale | Verdict::Failed => {
                if verdict == Verdict::Failed {
                    self.runtime
                        .failures
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .record(source, Instant::now());
                }
                self.challenge(cx, now, client, verdict == Verdict::Stale)
                    .await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// Dropping the middleware lets everyone in; losing users locks some out, which a plan
    /// shows too.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            None => vec!["digest_auth_removed"],
            Some(new) => {
                if self.users.keys().any(|user| !new.users.contains_key(user)) {
                    vec!["digest_auth_users_removed"]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn describe(&self) -> Value {
        json!({
            "realm": &*self.realm,
            "users": self.users.len(),
            "algorithms": self.offered.iter().map(|algorithm| algorithm.token()).collect::<Vec<_>>(),
            "header_field": self.header_field.as_ref().map(HeaderName::as_str),
            "remove_header": self.remove_header,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::budget::Budgets;
    use podgate_model::Budget;

    const NOW: u64 = 1_800_000_000;

    fn ha1(algorithm: Algorithm, user: &str, realm: &str, password: &str) -> String {
        algorithm.hash(&[
            user.as_bytes(),
            b":",
            realm.as_bytes(),
            b":",
            password.as_bytes(),
        ])
    }

    fn compile(config: &Value) -> Result<DigestAuth, Invalid> {
        let mut declared = json!({ "name": "d", "type": "digest_auth" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        DigestAuth::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
                portal: None,
            },
        )
    }

    fn middleware() -> DigestAuth {
        compile(&json!({ "users": [
            format!("alice:podgate:{}", ha1(Algorithm::Sha256, "alice", "podgate", "wonderland")),
            format!("bob:podgate:{}", ha1(Algorithm::Md5, "bob", "podgate", "builder")),
        ] }))
        .expect("compiles")
    }

    fn get(uri: &str) -> RequestHeader {
        RequestHeader::build("GET", uri.as_bytes(), None).expect("request")
    }

    /// The `Authorization` value of a client answering `nonce`.
    fn answer(
        algorithm: Algorithm,
        (user, realm, password): (&str, &str, &str),
        nonce: &str,
        count: u32,
        uri: &str,
    ) -> String {
        let nc = format!("{count:08x}");
        let claim = Claim {
            username: user,
            realm,
            nonce,
            uri,
            response: String::new(),
            algorithm,
            cnonce: "0a4f113b",
            nc: &nc,
            count,
        };
        let digest = response(
            algorithm,
            &ha1(algorithm, user, realm, password),
            "GET",
            uri,
            &claim,
        );
        format!(
            "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
             algorithm={}, qop=auth, nc={nc}, cnonce=\"0a4f113b\", response=\"{digest}\"",
            algorithm.token()
        )
    }

    fn decide(auth: &DigestAuth, now: u64, header: &str, uri: &str) -> Verdict {
        auth.decide(
            now,
            &Input {
                header: Some(header),
                request: &get(uri),
                client: Some("192.0.2.1".parse().expect("ip")),
                budget: None,
            },
        )
    }

    fn nonce(auth: &DigestAuth, at: u64) -> String {
        auth.runtime
            .nonces
            .issue(at, Some("192.0.2.1".parse().expect("ip")))
            .expect("nonce")
    }

    /// `nonce` with one character of its tag changed.
    fn tampered(nonce: &str) -> String {
        let mut chars: Vec<char> = nonce.chars().collect();
        chars[30] = if chars[30] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }

    const ALICE: (&str, &str, &str) = ("alice", "podgate", "wonderland");
    const BOB: (&str, &str, &str) = ("bob", "podgate", "builder");

    /// The example of RFC 7616 section 3.9.1.
    fn rfc_response(algorithm: Algorithm) -> String {
        let claim = Claim {
            username: "Mufasa",
            realm: "http-auth@example.org",
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
            uri: "/dir/index.html",
            response: String::new(),
            algorithm,
            cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
            nc: "00000001",
            count: 1,
        };
        let ha1 = ha1(
            algorithm,
            "Mufasa",
            "http-auth@example.org",
            "Circle of Life",
        );
        response(algorithm, &ha1, "GET", "/dir/index.html", &claim)
    }

    #[test]
    fn digest_auth_rfc7616_vector_sha256() {
        assert_eq!(
            rfc_response(Algorithm::Sha256),
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
    }

    #[test]
    fn digest_auth_md5_vector() {
        assert_eq!(
            rfc_response(Algorithm::Md5),
            "8ca523f5e9506fed4657c9700eebdbec"
        );
    }

    #[test]
    fn a_correct_answer_is_allowed_for_either_algorithm() {
        let auth = middleware();
        let n = nonce(&auth, NOW);
        let header = answer(Algorithm::Sha256, ALICE, &n, 1, "/x?y=1");
        assert_eq!(
            decide(&auth, NOW, &header, "/x?y=1"),
            Verdict::Allow("alice".into())
        );
        let n = nonce(&auth, NOW + 1);
        let header = answer(Algorithm::Md5, BOB, &n, 1, "/x");
        assert_eq!(
            decide(&auth, NOW, &header, "/x"),
            Verdict::Allow("bob".into())
        );
    }

    #[test]
    fn the_algorithm_must_be_the_one_of_the_stored_ha1() {
        let auth = middleware();
        let n = nonce(&auth, NOW);
        // Bob only has an MD5 HA1: a SHA-256 digest over it is not his password's digest.
        let header = answer(Algorithm::Sha256, BOB, &n, 1, "/x");
        assert_eq!(decide(&auth, NOW, &header, "/x"), Verdict::Failed);
    }

    #[test]
    fn wrong_user_realm_password_uri_and_nonce_fail() {
        let auth = middleware();
        let n = nonce(&auth, NOW);
        let alg = Algorithm::Sha256;
        for header in [
            answer(alg, ("mallory", "podgate", "wonderland"), &n, 1, "/x"),
            answer(alg, ("alice", "podgate", "wrong"), &n, 1, "/x"),
            answer(alg, ("alice", "other", "wonderland"), &n, 1, "/x"),
            answer(alg, ALICE, "AAAA", 1, "/x"),
            answer(alg, ALICE, &tampered(&nonce(&auth, NOW)), 1, "/x"),
            "Basic YWxpY2U6d29uZGVybGFuZA==".to_owned(),
            "Digest".to_owned(),
            "Digest username=\"alice\", username=\"alice\"".to_owned(),
        ] {
            assert_eq!(
                decide(&auth, NOW, &header, "/x"),
                Verdict::Failed,
                "{header}"
            );
        }
        let signed_for_another_uri = answer(alg, ALICE, &n, 1, "/other");
        assert_eq!(
            decide(&auth, NOW, &signed_for_another_uri, "/x"),
            Verdict::Failed
        );
    }

    #[test]
    fn a_nonce_is_bound_to_the_client_address() {
        let auth = middleware();
        let n = auth
            .runtime
            .nonces
            .issue(NOW, Some("198.51.100.9".parse().expect("ip")))
            .expect("nonce");
        let header = answer(Algorithm::Sha256, ALICE, &n, 1, "/x");
        assert_eq!(decide(&auth, NOW, &header, "/x"), Verdict::Failed);
    }

    #[test]
    fn digest_auth_stale_nonce() {
        let auth = middleware();
        let old = nonce(&auth, NOW - NONCE_LIFETIME - 1);
        let header = answer(Algorithm::Sha256, ALICE, &old, 1, "/x");
        assert_eq!(decide(&auth, NOW, &header, "/x"), Verdict::Stale);
        let wrong = answer(
            Algorithm::Sha256,
            ("alice", "podgate", "wrong"),
            &old,
            1,
            "/x",
        );
        assert_eq!(decide(&auth, NOW, &wrong, "/x"), Verdict::Failed);
        let edge = nonce(&auth, NOW - NONCE_LIFETIME);
        let header = answer(Algorithm::Sha256, ALICE, &edge, 1, "/x");
        assert_eq!(
            decide(&auth, NOW, &header, "/x"),
            Verdict::Allow("alice".into())
        );
        let future = nonce(&auth, NOW + NONCE_SKEW + 1);
        let header = answer(Algorithm::Sha256, ALICE, &future, 1, "/x");
        assert_eq!(decide(&auth, NOW, &header, "/x"), Verdict::Failed);
        let stale = auth.challenges(NOW, None, true);
        assert!(
            stale
                .iter()
                .all(|value| value.to_str().expect("text").ends_with(", stale=true"))
        );
    }

    #[test]
    fn digest_auth_replayed_nc_refused() {
        let auth = middleware();
        let n = nonce(&auth, NOW);
        let one = answer(Algorithm::Sha256, ALICE, &n, 1, "/x");
        let two = answer(Algorithm::Sha256, ALICE, &n, 2, "/x");
        assert_eq!(
            decide(&auth, NOW, &one, "/x"),
            Verdict::Allow("alice".into())
        );
        assert_eq!(decide(&auth, NOW, &one, "/x"), Verdict::Challenge);
        assert_eq!(
            decide(&auth, NOW, &two, "/x"),
            Verdict::Allow("alice".into())
        );
        assert_eq!(decide(&auth, NOW, &one, "/x"), Verdict::Challenge);
        assert_eq!(decide(&auth, NOW, &two, "/x"), Verdict::Challenge);
    }

    #[test]
    fn digest_auth_replay_table_bounded() {
        let mut replay = Replay::default();
        let key = |index: usize| {
            let mut key = [0_u8; 32];
            key[..8].copy_from_slice(&u64::try_from(index).expect("small").to_be_bytes());
            key
        };
        for index in 0..REPLAY_ENTRIES {
            assert_eq!(
                replay.accept(key(index), 1, NOW + 10, NOW, None),
                Use::Accepted
            );
        }
        assert_eq!(
            replay.accept(key(REPLAY_ENTRIES), 1, NOW + 10, NOW, None),
            Use::TableFull
        );
        assert_eq!(replay.seen.len(), REPLAY_ENTRIES);
        // A known nonce still counts up when the table is full.
        assert_eq!(replay.accept(key(0), 2, NOW + 10, NOW, None), Use::Accepted);
        // Entries of expired nonces make room.
        assert_eq!(
            replay.accept(key(REPLAY_ENTRIES), 1, NOW + 20, NOW + 11, None),
            Use::Accepted
        );
        assert!(replay.seen.len() <= REPLAY_ENTRIES);

        let budgets = Budgets::new();
        let tenant = budgets.tenant(
            "t",
            Budget {
                max_inflight: 10,
                max_buffer_bytes: REPLAY_ENTRY_BYTES * 3,
            },
        );
        let mut charged = Replay::default();
        for index in 0..3 {
            assert_eq!(
                charged.accept(key(index), 1, NOW + 10, NOW, Some(&tenant)),
                Use::Accepted
            );
        }
        assert_eq!(tenant.buffered(), REPLAY_ENTRY_BYTES * 3);
        assert_eq!(
            charged.accept(key(3), 1, NOW + 10, NOW, Some(&tenant)),
            Use::BudgetBusy
        );
        assert_eq!(tenant.buffered(), REPLAY_ENTRY_BYTES * 3);
        drop(charged);
        assert_eq!(tenant.buffered(), 0);
    }

    #[test]
    fn digest_auth_budget_refusals_are_503_not_challenges() {
        let auth = middleware();
        let budgets = Budgets::new();
        let tenant = budgets.tenant(
            "t",
            Budget {
                max_inflight: 10,
                max_buffer_bytes: REPLAY_ENTRY_BYTES,
            },
        );
        let (first, second) = (nonce(&auth, NOW), nonce(&auth, NOW + 1));
        let verdict = |header: &str| {
            auth.decide(
                NOW + 1,
                &Input {
                    header: Some(header),
                    request: &get("/x"),
                    client: Some("192.0.2.1".parse().expect("ip")),
                    budget: Some(&tenant),
                },
            )
        };
        assert_eq!(
            verdict(&answer(Algorithm::Sha256, ALICE, &first, 1, "/x")),
            Verdict::Allow("alice".into())
        );
        assert_eq!(
            verdict(&answer(Algorithm::Sha256, ALICE, &second, 1, "/x")),
            Verdict::Busy,
            "a budget that is full right now is a capacity refusal, not a failure"
        );
        let small = budgets.tenant(
            "small",
            Budget {
                max_inflight: 10,
                max_buffer_bytes: REPLAY_ENTRY_BYTES - 1,
            },
        );
        let fresh = middleware();
        let third = nonce(&fresh, NOW);
        assert_eq!(
            fresh.decide(
                NOW,
                &Input {
                    header: Some(&answer(Algorithm::Sha256, ALICE, &third, 1, "/x")),
                    request: &get("/x"),
                    client: Some("192.0.2.1".parse().expect("ip")),
                    budget: Some(&small),
                },
            ),
            Verdict::OverBudget,
            "an entry the tenant can never hold is a deploy problem"
        );
    }

    #[test]
    fn digest_auth_invalid_users_rejected() {
        let good = ha1(Algorithm::Sha256, "a", "podgate", "pw");
        for config in [
            json!({ "users": [] }),
            json!({ "users": ["a"] }),
            json!({ "users": ["a:podgate"] }),
            json!({ "users": [format!("a:podgate:{}", &good[..40])] }),
            json!({ "users": [format!("a:podgate:{}z", &good[..63])] }),
            json!({ "users": [format!("a:other:{good}")] }),
            json!({ "users": [format!(":podgate:{good}")] }),
            json!({ "users": [format!("a:podgate:{good}"), format!("a:podgate:{good}")] }),
            json!({ "users": [format!("a:podgate:{good}")], "qop": "auth-int" }),
            json!({ "users": [format!("a:podgate:{good}")], "qop": "none" }),
            json!({ "users": [format!("a:podgate:{good}")], "realm": "a\"b" }),
            json!({ "users": [format!("a:podgate:{good}")], "header_field": "host" }),
            json!({ "users": [format!("a:podgate:{good}")], "header_field": "authorization" }),
            json!({ "users": [format!("a:podgate:{good}")], "algorithm": "md5" }),
        ] {
            let err = compile(&config).expect_err(&config.to_string());
            assert_eq!(err.code, "invalid_middleware", "{config}");
            assert!(!err.message.contains(&good), "{}", err.message);
        }
        assert!(compile(&json!({ "users": [format!("a:podgate:{good}")], "qop": "auth" })).is_ok());
    }

    #[test]
    fn the_challenge_offers_only_algorithms_some_user_can_answer() {
        let sha = ha1(Algorithm::Sha256, "a", "r", "pw");
        let md5 = ha1(Algorithm::Md5, "b", "r", "pw");
        let offered = |users: &[String]| {
            compile(&json!({ "users": users, "realm": "r" }))
                .expect("compiles")
                .challenges(NOW, None, false)
                .iter()
                .map(|value| {
                    let text = value.to_str().expect("text");
                    text.split("algorithm=")
                        .nth(1)
                        .and_then(|rest| rest.split(',').next())
                        .expect("algorithm")
                        .to_owned()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            offered(&[format!("a:r:{sha}"), format!("b:r:{md5}")]),
            ["SHA-256", "MD5"]
        );
        assert_eq!(offered(&[format!("a:r:{sha}")]), ["SHA-256"]);
        assert_eq!(offered(&[format!("b:r:{md5}")]), ["MD5"]);
    }

    #[test]
    fn digest_auth_secrets_redacted() {
        let hash = ha1(Algorithm::Sha256, "alice", "podgate", "wonderland");
        let config = json!({ "users": [format!("alice:podgate:{hash}")] });
        let parsed: Config = serde_json::from_value(config.clone()).expect("config");
        let auth = compile(&config).expect("compiles");
        for shown in [
            format!("{parsed:?}"),
            format!("{auth:?}"),
            format!("{:?}", auth.users),
            auth.describe().to_string(),
        ] {
            assert!(!shown.contains(&hash), "{shown}");
            assert!(!shown.contains("wonderland"), "{shown}");
        }
    }

    #[test]
    fn the_parameter_parser_handles_quotes_and_refuses_junk() {
        let pairs = params(" a=1, B=\"x, \\\"y\\\"\" ,c=z").expect("parses");
        assert_eq!(
            pairs,
            [
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "x, \"y\"".to_owned()),
                ("c".to_owned(), "z".to_owned()),
            ]
        );
        assert!(params("a=\"open").is_none());
        assert!(params("a=1, a=2").is_none());
        assert!(params("=1").is_none());
        assert!(params("novalue").is_none());
    }

    #[test]
    fn failures_delay_a_source_after_five_in_a_minute() {
        let mut failures = Failures::default();
        let source: IpAddr = "192.0.2.7".parse().expect("ip");
        let now = Instant::now();
        for _ in 0..FAILURES_FREE {
            assert!(!failures.delayed(source, now));
            failures.record(source, now);
        }
        assert!(failures.delayed(source, now));
        assert!(!failures.delayed(source, now + FAILURE_WINDOW));
    }
}
