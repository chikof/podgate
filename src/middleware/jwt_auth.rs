//! The `jwt_auth` middleware: a chain stage that lets a request through only when it carries a
//! valid JSON Web Token. Full reference: `docs/ref/mw-jwt.md`.
//!
//! ```json
//! { "name": "api-auth", "type": "jwt_auth",
//!   "jwks_uri": "https://10.0.0.7:8443/.well-known/jwks.json", "transport": "internal",
//!   "algorithms": ["RS256", "ES256"], "issuer": "https://idp.example", "audiences": ["api"],
//!   "required_claims": {"role": ["admin", "ops"]},
//!   "forward_claims": {"sub": "X-User", "email": "X-Email"}, "remove_token": true }
//! ```
//!
//! This is a resource-server verifier: it checks a token somebody else issued, it never issues
//! one (login flows are another middleware).
//!
//! - **What is checked.** The token comes from the first of `token_sources` that holds one (the
//!   `Authorization: Bearer` header by default). Its `alg` must be in `algorithms`, a key of the
//!   type that algorithm needs and the token's `kid` must verify the signature, `exp` must be
//!   present and in the future, `nbf` and `iat` are checked, `iss` and `aud` when configured. The
//!   rules and why they are shaped so are in `jwt_auth/verify.rs` and `jwt_auth/claims.rs`.
//! - **Where the keys come from.** `keys` (an inline JWK set) and/or `jwks_uri`, fetched by a
//!   background task through the bounded client of `forward_auth` under the upstream address
//!   policy (`jwt_auth/jwks.rs`).
//! - **What the client sees.** `401` with `WWW-Authenticate: Bearer realm="podgate",
//!   error="invalid_token"` for a missing or invalid token, `403` when the signature is valid
//!   and `required_claims` do not match, `503 {"error":"authentication unavailable"}` when there
//!   are no keys. No body says which check failed: the reason is in the access log (`reason`)
//!   and the metrics. The token is never logged.
//! - **What the upstream sees.** The claims named in `forward_claims` as headers. Every header
//!   named there is removed from the client's request first, and written only from a verified
//!   token. With `remove_token` the credential is removed from every configured source.
//! - **Where it runs.** In the chain, before a revision is chosen and before any tenant slot is
//!   taken: unauthenticated traffic costs a signature check and nothing else, and wakes nobody.
//! - **Caches.** A request whose token was accepted carries an identity the cache key does not
//!   hold, so the `cache` stage neither serves nor stores it, as for `forward_auth`. This holds
//!   whatever the token source and with `remove_token`.

mod claims;
pub(crate) mod jwks;
mod verify;

#[cfg(test)]
#[path = "../../tests/fixtures/jwt/signer.rs"]
mod fixture;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use http::HeaderValue;
use http::header::{AUTHORIZATION, COOKIE, HOST, HeaderName};
use pingora::http::{RequestHeader, ResponseHeader};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use self::claims::{Rules, header_text};
use self::jwks::{Cache, Demand, Fetch, FetchError, Flight, Plan, Target};
use self::verify::{Algorithm, Algorithms, Failure, KeySet, MAX_TOKEN, Token, verify};
use super::{CompileCx, Flow, Kind, RequestCx, Stage, forward_auth, state};
use crate::budget::{Escaped, TenantBudget};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::middleware::forward_auth::Client;
use crate::plan;
use crate::service::Transport;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{CompiledApp, RoutingTable};
use podgate_model::{Declared, Snapshot};

/// The default `leeway_secs`.
const DEFAULT_LEEWAY_SECS: u64 = 30;
/// The largest `leeway_secs`.
const MAX_LEEWAY_SECS: u64 = 300;
/// The most `jwks_uri` a tenant may use.
const MAX_URIS_PER_TENANT: usize = 8;
/// The most entries of each list of the configuration.
const MAX_ENTRIES: usize = 32;
/// The most `token_sources`.
const MAX_SOURCES: usize = 8;
/// The longest name of a cookie or a query parameter.
const MAX_NAME: usize = 128;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: requests are no longer checked.
    pub const REMOVED: &str = "jwt_auth_removed";
    /// A token may name an algorithm it could not before.
    pub const ALGORITHM_ADDED: &str = "jwt_auth_algorithm_added";
    /// A required claim is gone, or accepts more values.
    pub const REQUIRED_CLAIMS_LOOSENED: &str = "jwt_auth_required_claims_loosened";
    /// An expired or not-yet-valid token is forgiven for longer.
    pub const LEEWAY_INCREASED: &str = "jwt_auth_leeway_increased";
    /// The issuer is no longer checked, or is another one.
    pub const ISSUER_LOOSENED: &str = "jwt_auth_issuer_loosened";
    /// The audience is no longer checked, or accepts one more.
    pub const AUDIENCE_LOOSENED: &str = "jwt_auth_audience_loosened";
    /// A key, or another JWKS endpoint, is trusted that was not.
    pub const KEY_ADDED: &str = "jwt_auth_key_added";
    /// Old tokens are accepted that were not.
    pub const MAX_TOKEN_AGE_LOOSENED: &str = "jwt_auth_max_token_age_loosened";
    /// A token is read from a place it was not.
    pub const TOKEN_SOURCE_ADDED: &str = "jwt_auth_token_source_added";
}

/// A string or a number or a boolean: what a required claim is compared with.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum Scalar {
    Text(String),
    Number(serde_json::Number),
    Flag(bool),
}

impl Scalar {
    fn value(self) -> Value {
        match self {
            Self::Text(text) => Value::String(text),
            Self::Number(number) => Value::Number(number),
            Self::Flag(flag) => Value::Bool(flag),
        }
    }
}

/// One value, or a list of which one must match.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum Want {
    Any(Vec<Scalar>),
    One(Scalar),
}

/// A place a token may be in: one of `header`, `cookie`, `query`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SourceConfig {
    /// A request header; with `scheme`, the value is `<scheme> <token>`.
    #[serde(default)]
    header: Option<String>,
    /// The authentication scheme of a `header`; `Bearer` for `authorization`.
    #[serde(default)]
    scheme: Option<String>,
    /// A cookie.
    #[serde(default)]
    cookie: Option<String>,
    /// A query parameter. A token in a URL is logged by every proxy on the way: avoid it.
    #[serde(default)]
    query: Option<String>,
}

/// The configuration of a `jwt_auth` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// An inline JWK set, `{"keys": [...]}`; the only place a symmetric (`oct`) key may be.
    #[serde(default)]
    keys: Option<Value>,
    #[serde(default)]
    jwks_uri: Option<String>,
    algorithms: Vec<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    required_claims: BTreeMap<String, Want>,
    #[serde(default)]
    leeway_secs: Option<u64>,
    #[serde(default)]
    max_token_age_secs: Option<u64>,
    #[serde(default)]
    token_sources: Option<Vec<SourceConfig>>,
    #[serde(default)]
    forward_claims: BTreeMap<String, String>,
    #[serde(default)]
    remove_token: bool,
    #[serde(default)]
    jwks_refresh_secs: Option<u64>,
    #[serde(default)]
    transport: Option<String>,
}

/// A place a token is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Header {
        name: HeaderName,
        scheme: Option<Box<str>>,
    },
    Cookie(Box<str>),
    Query(Box<str>),
}

/// What looking in one place found.
enum Found {
    Absent,
    Token(String),
    Bad(Failure),
}

fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl Source {
    fn compile(config: &SourceConfig) -> Result<Self, Invalid> {
        match (&config.header, &config.cookie, &config.query) {
            (Some(header), None, None) => {
                let name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                    invalid(format!("token_sources: {header:?} is not a header name"))
                })?;
                if name == COOKIE {
                    return Err(invalid(
                        "token_sources: read a cookie with {\"cookie\": name}, not the cookie header",
                    ));
                }
                if forward_auth::reserved(&name) {
                    return Err(invalid(format!(
                        "token_sources: {name} frames the message or belongs to the connection"
                    )));
                }
                let scheme = match config.scheme.as_deref() {
                    Some(scheme) => Some(scheme),
                    None if name == AUTHORIZATION => Some("Bearer"),
                    None => None,
                };
                if let Some(scheme) = scheme
                    && !plain_name(scheme)
                {
                    return Err(invalid(format!(
                        "token_sources: scheme {scheme:?} is not a plain word"
                    )));
                }
                Ok(Self::Header {
                    name,
                    scheme: scheme.map(Into::into),
                })
            }
            (None, Some(cookie), None) if config.scheme.is_none() => plain_name(cookie)
                .then(|| Self::Cookie(cookie.as_str().into()))
                .ok_or_else(|| invalid(format!("token_sources: {cookie:?} is not a cookie name"))),
            (None, None, Some(query)) if config.scheme.is_none() => plain_name(query)
                .then(|| Self::Query(query.as_str().into()))
                .ok_or_else(|| {
                    invalid(format!(
                        "token_sources: {query:?} is not a query parameter name"
                    ))
                }),
            _ => Err(invalid(
                "token_sources: each entry has exactly one of `header`, `cookie` and `query`, and `scheme` only with `header`",
            )),
        }
    }

    /// Looks for a token. A place that is ambiguous (the same header, cookie or parameter twice)
    /// or whose token is too long is a failure, never a reason to look elsewhere.
    fn find(&self, request: &RequestHeader) -> Found {
        let raw: Option<String> = match self {
            Self::Header { name, scheme } => {
                let mut values = request.headers.get_all(name).iter();
                let Some(first) = values.next() else {
                    return Found::Absent;
                };
                if values.next().is_some() {
                    return Found::Bad(Failure::Malformed);
                }
                let Ok(text) = first.to_str() else {
                    return Found::Bad(Failure::Malformed);
                };
                match scheme {
                    None => Some(text.to_owned()),
                    Some(scheme) => match text.split_once(' ') {
                        Some((word, rest)) if word.eq_ignore_ascii_case(scheme) => {
                            Some(rest.to_owned())
                        }
                        _ => return Found::Absent,
                    },
                }
            }
            Self::Cookie(wanted) => {
                let mut found: Option<String> = None;
                for value in &request.headers.get_all(COOKIE) {
                    let text = String::from_utf8_lossy(value.as_bytes());
                    for pair in text.split(';') {
                        if let Some((name, value)) = pair.split_once('=')
                            && name.trim() == &**wanted
                        {
                            if found.is_some() {
                                return Found::Bad(Failure::Malformed);
                            }
                            found = Some(value.trim().trim_matches('"').to_owned());
                        }
                    }
                }
                found
            }
            Self::Query(wanted) => {
                let mut found: Option<String> = None;
                if let Some(query) = request.uri.query() {
                    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
                        if name == **wanted {
                            if found.is_some() {
                                return Found::Bad(Failure::Malformed);
                            }
                            found = Some(value.into_owned());
                        }
                    }
                }
                found
            }
        };
        match raw {
            None => Found::Absent,
            Some(token) if token.len() > MAX_TOKEN => Found::Bad(Failure::Oversized),
            Some(token) if token.is_empty() || token.contains(' ') => {
                Found::Bad(Failure::Malformed)
            }
            Some(token) => Found::Token(token),
        }
    }

    /// Removes the credential of this place from `request`, when it holds one.
    fn strip(&self, request: &mut RequestHeader) {
        if matches!(self.find(request), Found::Absent) {
            return;
        }
        match self {
            Self::Header { name, .. } => {
                request.remove_header(name);
            }
            Self::Cookie(wanted) => {
                let rebuilt: Vec<HeaderValue> = request
                    .headers
                    .get_all(COOKIE)
                    .iter()
                    .filter_map(|value| without_cookie(value, wanted))
                    .collect();
                request.remove_header(&COOKIE);
                for value in rebuilt {
                    request.append_header(COOKIE, value).ok();
                }
            }
            Self::Query(wanted) => strip_query_params(request, |name| name == &**wanted),
        }
    }

    fn describe(&self) -> Value {
        match self {
            Self::Header { name, scheme } => json!({"header": name.as_str(), "scheme": scheme}),
            Self::Cookie(name) => json!({"cookie": name}),
            Self::Query(name) => json!({"query": name}),
        }
    }
}

/// `value` without the cookie `wanted`; `None` when nothing is left. A header that does not hold
/// it is returned as it is.
fn without_cookie(value: &HeaderValue, wanted: &str) -> Option<HeaderValue> {
    let text = String::from_utf8_lossy(value.as_bytes());
    let holds = |pair: &str| {
        pair.split_once('=')
            .is_some_and(|(name, _)| name.trim() == wanted)
    };
    if !text.split(';').any(holds) {
        return Some(value.clone());
    }
    let kept: Vec<&str> = text
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty() && !holds(pair))
        .collect();
    (!kept.is_empty())
        .then(|| HeaderValue::from_str(&kept.join("; ")).ok())
        .flatten()
}

/// Removes the query parameters of `request` whose (decoded) name `is_credential` says is one,
/// keeping every other piece of the query as it was written.
fn strip_query_params(request: &mut RequestHeader, is_credential: impl Fn(&str) -> bool) {
    let Some(query) = request.uri.query() else {
        return;
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|piece| {
            form_urlencoded::parse(piece.as_bytes())
                .next()
                .is_none_or(|(name, _)| !is_credential(&name))
        })
        .collect();
    let path = request.uri.path();
    let target = if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    let mut parts = request.uri.clone().into_parts();
    parts.path_and_query = target.parse().ok();
    if let Ok(uri) = http::Uri::from_parts(parts) {
        request.set_uri(uri);
    }
}

/// The places the `jwt_auth` stages of one chain read a token from, for the sinks that copy or
/// record a request and must not show it: the access log, the failed-request ring and the copy
/// a mirror gets.
#[derive(Debug, Default)]
pub(crate) struct Credentials {
    query: Vec<Box<str>>,
    headers: Vec<HeaderName>,
}

impl Credentials {
    /// The token places of the `jwt_auth` stages of `chain` (indices into the stages of `app`).
    #[must_use]
    pub(crate) fn of(app: &CompiledApp, chain: &[usize]) -> Self {
        let mut found = Self::default();
        for index in chain {
            let Some(Stage::JwtAuth(auth)) = app.stages().get(*index).map(|named| &named.stage)
            else {
                continue;
            };
            for source in &auth.0.sources {
                match source {
                    Source::Query(name) => found.query.push(name.clone()),
                    Source::Header { name, .. } => found.headers.push(name.clone()),
                    Source::Cookie(_) => {}
                }
            }
        }
        found
    }

    /// Whether the header `name` (lower case) is where a token is read from.
    #[must_use]
    pub(crate) fn header(&self, name: &str) -> bool {
        self.headers.iter().any(|header| header.as_str() == name)
    }

    /// `query` with the value of every token parameter replaced by `[redacted]`.
    #[must_use]
    pub(crate) fn redact_query(&self, query: &str) -> String {
        if self.query.is_empty() {
            return query.to_owned();
        }
        query
            .split('&')
            .map(|piece| match piece.split_once('=') {
                Some((written, _))
                    if form_urlencoded::parse(written.as_bytes())
                        .next()
                        .is_some_and(|(name, _)| {
                            self.query.iter().any(|known| **known == *name)
                        }) =>
                {
                    format!("{written}=[redacted]")
                }
                _ => piece.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    /// `target` (a path and query) with the value of every token parameter redacted.
    #[must_use]
    pub(crate) fn redact_target(&self, target: &str) -> String {
        match target.split_once('?') {
            Some((path, query)) if !self.query.is_empty() => {
                format!("{path}?{}", self.redact_query(query))
            }
            _ => target.to_owned(),
        }
    }

    /// Removes every token parameter from `request`.
    pub(crate) fn strip_query(&self, request: &mut RequestHeader) {
        if !self.query.is_empty() {
            strip_query_params(request, |name| {
                self.query.iter().any(|known| **known == *name)
            });
        }
    }
}

/// The counters of one middleware, shown by [`render`].
#[derive(Debug, Default)]
struct Stats {
    verified: AtomicU64,
    rejected: [AtomicU64; Failure::ALL.len()],
    fetched: AtomicU64,
    fetch_failed: AtomicU64,
}

/// What outlives a snapshot push: the cached keys and the counters.
#[derive(Debug)]
struct Runtime {
    cache: Cache,
    stats: Stats,
}

#[derive(Debug)]
struct Parts {
    algorithms: Algorithms,
    inline: KeySet,
    rules: Rules,
    sources: Box<[Source]>,
    /// Claim and the header it is copied into.
    forward: Box<[(Box<str>, HeaderName)]>,
    remove_token: bool,
    jwks: Option<Arc<Target>>,
    refresh_secs: u64,
    transport_name: Option<Box<str>>,
    runtime: Arc<Runtime>,
    fingerprint: u64,
}

/// A compiled `jwt_auth` middleware.
#[derive(Debug)]
pub struct JwtAuth(Box<Parts>);

/// What a request keeps of its `jwt_auth` stage.
#[derive(Debug, Default)]
pub struct State {
    /// A token was accepted: the request carries an identity the cache key does not know.
    verified: bool,
}

impl State {
    /// Whether the request carries a verified identity.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.verified
    }
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("jwt_auth: {message}"))
}

/// The transport named `name` of `app`.
fn transport_of(app: &podgate_model::App, name: Option<&str>) -> Result<Arc<Transport>, Invalid> {
    let Some(name) = name else {
        return Ok(Arc::new(Transport::default()));
    };
    let declared = app
        .transports
        .iter()
        .find(|declared| &*declared.name == name)
        .ok_or_else(|| {
            Invalid::new(
                "unknown_transport",
                format!("jwt_auth: transport {name} is not declared by the app"),
            )
        })?;
    Ok(Arc::new(Transport::compile(declared)?))
}

fn unix_now() -> f64 {
    // A clock before 1970 makes every token expired: closed.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(f64::MAX, |elapsed| elapsed.as_secs_f64())
}

/// The error a failed check is answered and logged with.
fn error_of(failure: Failure) -> AppError {
    match failure {
        Failure::ClaimsForbidden => AppError::JwtForbidden {
            reason: failure.code(),
        },
        Failure::Unavailable => AppError::JwtUnavailable,
        other => AppError::JwtUnauthorized {
            reason: other.code(),
        },
    }
}

/// What a fetch needs from the request, borrowed from its context.
struct Who<'a> {
    client: &'a Client,
    policy: &'a UpstreamPolicy,
    tenant: &'a str,
    budget: Option<&'a Arc<TenantBudget>>,
}

impl JwtAuth {
    /// The `jwks_uri` this middleware fetches, if any.
    fn target(&self) -> Option<&Arc<Target>> {
        self.0.jwks.as_ref()
    }

    /// The first place that holds a token.
    fn find_token(&self, request: &RequestHeader) -> Result<String, Failure> {
        for source in &self.0.sources {
            match source.find(request) {
                Found::Absent => {}
                Found::Token(token) => return Ok(token),
                Found::Bad(failure) => return Err(failure),
            }
        }
        Err(Failure::Missing)
    }

    /// Starts the fetch of `flight` in the background.
    fn spawn(&self, who: &Who<'_>, flight: Flight) {
        let (Some(target), Some(budget)) = (self.target(), who.budget) else {
            self.0
                .runtime
                .cache
                .finish(flight, Instant::now(), Err(FetchError::Budget));
            return;
        };
        let fetch = Fetch {
            target: Arc::clone(target),
            client: who.client.clone(),
            policy: who.policy.clone(),
            tenant: who.tenant.into(),
            budget: Arc::clone(budget),
        };
        let runtime = Arc::clone(&self.0.runtime);
        tokio::spawn(async move {
            let result = fetch.run().await;
            match &result {
                Ok((keys, skipped)) => {
                    runtime.stats.fetched.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        uri = %fetch.target.display(),
                        keys = keys.len(),
                        skipped,
                        "jwks fetched"
                    );
                }
                Err(why) => {
                    runtime.stats.fetch_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        tenant = &*fetch.tenant,
                        uri = %fetch.target.display(),
                        %why,
                        "jwks fetch failed"
                    );
                }
            }
            runtime
                .cache
                .finish(flight, Instant::now(), result.map(|(keys, _)| keys));
        });
    }

    /// The JWKS keys to check a token with, fetching when the plan says so.
    ///
    /// # Errors
    ///
    /// [`Failure::Unavailable`] when there are no keys at all.
    async fn remote_keys(
        &self,
        who: &Who<'_>,
        demand: Demand,
    ) -> Result<Option<Arc<KeySet>>, Failure> {
        if self.0.jwks.is_none() {
            return Ok(None);
        }
        let cache = &self.0.runtime.cache;
        let mut wait = match cache.plan(Instant::now(), demand) {
            Plan::Ready(keys) => return Ok(Some(keys)),
            Plan::Background(keys, flight) => {
                self.spawn(who, flight);
                return Ok(Some(keys));
            }
            Plan::Foreground(flight) => {
                let wait = flight.subscribe();
                self.spawn(who, flight);
                wait
            }
            Plan::Wait(wait) => wait,
            Plan::Unavailable => return Err(Failure::Unavailable),
        };
        // The sender is dropped, never used, when the fetch ends.
        let _ended = wait.changed().await;
        cache
            .current(Instant::now())
            .map(Some)
            .ok_or(Failure::Unavailable)
    }

    /// Finds, parses and checks the token of the request.
    async fn authenticate(
        &self,
        request: &RequestHeader,
        who: &Who<'_>,
    ) -> Result<Map<String, Value>, Failure> {
        let raw = self.find_token(request)?;
        let token = Token::parse(&raw, &self.0.algorithms)?;
        let none = KeySet::default();
        let mut remote = self.remote_keys(who, Demand::Keys).await?;
        let sets = |remote: &Option<Arc<KeySet>>| -> Result<(), Failure> {
            verify(
                &token,
                &[&self.0.inline, remote.as_deref().unwrap_or(&none)],
            )
        };
        match sets(&remote) {
            Ok(()) => {}
            Err(Failure::UnknownKid) if self.0.jwks.is_some() => {
                remote = self.remote_keys(who, Demand::KidMiss).await?;
                sets(&remote)?;
            }
            Err(failure) => return Err(failure),
        }
        let claims = token.claims()?;
        self.0.rules.check(&claims, unix_now())?;
        Ok(claims)
    }

    /// Writes the refusal of `err`: `401` carries the challenge, the rest are plain.
    async fn refuse(cx: &mut RequestCx<'_>, err: &AppError) -> pingora::Result<()> {
        if !matches!(err, AppError::JwtUnauthorized { .. }) {
            return crate::respond::write_error(cx.session, err).await;
        }
        let body = bytes::Bytes::from(err.body().to_string());
        let mut header = ResponseHeader::build(401, Some(5))?;
        header.insert_header(
            "www-authenticate",
            "Bearer realm=\"podgate\", error=\"invalid_token\"",
        )?;
        header.insert_header("content-type", "application/json")?;
        header.insert_header("content-length", body.len().to_string())?;
        header.insert_header("cache-control", "no-store")?;
        cx.session
            .write_response_header(Box::new(header), false)
            .await?;
        cx.session.write_response_body(Some(body), true).await
    }
}

impl Kind for JwtAuth {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let algorithms = Algorithms::compile(&config.algorithms).map_err(invalid)?;
        let inline = match &config.keys {
            None => KeySet::default(),
            Some(set) => KeySet::inline(set).map_err(|why| invalid(format!("`keys`: {why}")))?,
        };
        if config.keys.is_none() && config.jwks_uri.is_none() {
            return Err(invalid("needs `keys`, `jwks_uri` or both"));
        }
        if algorithms.iter().any(Algorithm::is_hmac) && !inline.has_symmetric() {
            return Err(invalid(
                "HS256, HS384 and HS512 need an `oct` key in `keys`; a key fetched from an endpoint is never a shared secret",
            ));
        }
        let jwks = match &config.jwks_uri {
            Some(uri) => {
                let transport = transport_of(cx.app, config.transport.as_deref())?;
                Some(Arc::new(jwks::parse_uri(uri, transport)?))
            }
            None if config.transport.is_some() => {
                return Err(invalid("`transport` needs `jwks_uri`"));
            }
            None => None,
        };
        let leeway_secs = config.leeway_secs.unwrap_or(DEFAULT_LEEWAY_SECS);
        if leeway_secs > MAX_LEEWAY_SECS {
            return Err(invalid(format!(
                "`leeway_secs` is at most {MAX_LEEWAY_SECS}"
            )));
        }
        if config.max_token_age_secs == Some(0) {
            return Err(invalid("`max_token_age_secs` is at least 1"));
        }
        if config.issuer.as_deref().is_some_and(str::is_empty)
            || config.audiences.len() > MAX_ENTRIES
            || config.audiences.iter().any(String::is_empty)
        {
            return Err(invalid(format!(
                "`issuer` and `audiences` are not empty, with at most {MAX_ENTRIES} audiences"
            )));
        }
        if config.required_claims.len() > MAX_ENTRIES {
            return Err(invalid(format!(
                "`required_claims` has more than {MAX_ENTRIES} entries"
            )));
        }
        let mut required = Vec::with_capacity(config.required_claims.len());
        for (name, want) in config.required_claims {
            let values: Vec<Value> = match want {
                Want::One(one) => vec![one.value()],
                Want::Any(list) => list.into_iter().map(Scalar::value).collect(),
            };
            if name.is_empty() || values.is_empty() || values.len() > MAX_ENTRIES {
                return Err(invalid(format!(
                    "`required_claims`: {name:?} needs a name and 1 to {MAX_ENTRIES} values"
                )));
            }
            required.push((name.into_boxed_str(), values.into_boxed_slice()));
        }
        let configured = config.token_sources.unwrap_or_else(|| {
            vec![SourceConfig {
                header: Some("authorization".to_owned()),
                scheme: Some("Bearer".to_owned()),
                cookie: None,
                query: None,
            }]
        });
        if configured.is_empty() || configured.len() > MAX_SOURCES {
            return Err(invalid(format!(
                "`token_sources` lists 1 to {MAX_SOURCES} places"
            )));
        }
        let mut sources: Vec<Source> = Vec::with_capacity(configured.len());
        for entry in &configured {
            let source = Source::compile(entry)?;
            if sources.contains(&source) {
                return Err(invalid("`token_sources` names a place twice"));
            }
            sources.push(source);
        }
        if config.forward_claims.len() > MAX_ENTRIES {
            return Err(invalid(format!(
                "`forward_claims` has more than {MAX_ENTRIES} entries"
            )));
        }
        let mut forward: Vec<(Box<str>, HeaderName)> =
            Vec::with_capacity(config.forward_claims.len());
        for (claim, header) in config.forward_claims {
            let name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
                invalid(format!("`forward_claims`: {header:?} is not a header name"))
            })?;
            if claim.is_empty()
                || forward_auth::reserved(&name)
                || name == AUTHORIZATION
                || name == COOKIE
                || name == HOST
                || sources.iter().any(
                    |source| matches!(source, Source::Header { name: used, .. } if *used == name),
                )
            {
                return Err(invalid(format!(
                    "`forward_claims`: {header:?} cannot carry a claim: it frames the message, belongs to the connection, is written by podgate or holds the token"
                )));
            }
            if forward.iter().any(|(_, taken)| *taken == name) {
                return Err(invalid(format!(
                    "`forward_claims` writes header {name} from two claims"
                )));
            }
            forward.push((claim.into_boxed_str(), name));
        }
        let refresh_secs = config
            .jwks_refresh_secs
            .unwrap_or(jwks::REFRESH_DEFAULT)
            .clamp(jwks::REFRESH_MIN, jwks::REFRESH_MAX);
        Ok(Self(Box::new(Parts {
            algorithms,
            inline,
            rules: Rules {
                issuer: config.issuer.map(Into::into),
                audiences: config.audiences.into_iter().map(Into::into).collect(),
                required: required.into_boxed_slice(),
                leeway_secs,
                max_token_age_secs: config.max_token_age_secs,
            },
            sources: sources.into_boxed_slice(),
            forward: forward.into_boxed_slice(),
            remove_token: config.remove_token,
            jwks,
            refresh_secs,
            transport_name: config.transport.map(Into::into),
            runtime: Arc::new(Runtime {
                cache: Cache::new(refresh_secs),
                stats: Stats::default(),
            }),
            fingerprint: state::fingerprint(declared),
        })))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        // Whatever follows, nothing the client wrote under a name a claim is copied into may
        // reach the upstream.
        let request = cx.session.req_header_mut();
        for (_, header) in &self.0.forward {
            request.remove_header(header);
        }
        let who = Who {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.app.tenant(),
            budget: cx.tenant,
        };
        match self.authenticate(cx.session.req_header(), &who).await {
            Ok(claims) => {
                state.verified = true;
                self.0
                    .runtime
                    .stats
                    .verified
                    .fetch_add(1, Ordering::Relaxed);
                let request = cx.session.req_header_mut();
                for (claim, header) in &self.0.forward {
                    if let Some(text) = claims.get(&**claim).and_then(header_text)
                        && let Ok(value) = HeaderValue::from_str(&text)
                    {
                        request.insert_header(header.clone(), value)?;
                    }
                }
                if self.0.remove_token {
                    for source in &self.0.sources {
                        source.strip(request);
                    }
                }
                Ok(Flow::Continue)
            }
            Err(failure) => {
                self.0.runtime.stats.rejected[failure.index()].fetch_add(1, Ordering::Relaxed);
                let err = error_of(failure);
                tracing::debug!(
                    app = cx.app.id(),
                    reason = failure.code(),
                    "jwt_auth refused"
                );
                *cx.reason = Some(err.log_reason());
                Self::refuse(cx, &err).await?;
                Ok(Flow::Respond)
            }
        }
    }

    /// Dropping the middleware lets everyone in; every other relaxation trusts more tokens than
    /// before.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let (old, now) = (&*self.0, &*new.0);
        let mut kinds = Vec::new();
        if now.algorithms.iter().any(|a| !old.algorithms.contains(a)) {
            kinds.push(kind::ALGORITHM_ADDED);
        }
        let required_loosened = old.rules.required.iter().any(|(name, want)| {
            !now.rules
                .required
                .iter()
                .any(|(n, w)| n == name && w.iter().all(|value| want.contains(value)))
        });
        if required_loosened {
            kinds.push(kind::REQUIRED_CLAIMS_LOOSENED);
        }
        if now.rules.leeway_secs > old.rules.leeway_secs {
            kinds.push(kind::LEEWAY_INCREASED);
        }
        if old.rules.issuer.is_some() && now.rules.issuer != old.rules.issuer {
            kinds.push(kind::ISSUER_LOOSENED);
        }
        let audience_loosened = !old.rules.audiences.is_empty()
            && (now.rules.audiences.is_empty()
                || now
                    .rules
                    .audiences
                    .iter()
                    .any(|audience| !old.rules.audiences.contains(audience)));
        if audience_loosened {
            kinds.push(kind::AUDIENCE_LOOSENED);
        }
        let key_added = now
            .inline
            .keys()
            .iter()
            .any(|key| !old.inline.keys().contains(key))
            || match (&now.jwks, &old.jwks) {
                (Some(now), Some(old)) => now.uri != old.uri,
                (Some(_), None) => true,
                _ => false,
            };
        if key_added {
            kinds.push(kind::KEY_ADDED);
        }
        let age_loosened = match (old.rules.max_token_age_secs, now.rules.max_token_age_secs) {
            (Some(_), None) => true,
            (Some(old), Some(now)) => now > old,
            _ => false,
        };
        if age_loosened {
            kinds.push(kind::MAX_TOKEN_AGE_LOOSENED);
        }
        if now
            .sources
            .iter()
            .any(|source| !old.sources.contains(source))
        {
            kinds.push(kind::TOKEN_SOURCE_ADDED);
        }
        if let Some(target) = &now.jwks
            && target.server.tls
            && target.transport.insecure_skip_verify()
            && !old
                .jwks
                .as_ref()
                .is_some_and(|t| t.server.tls && t.transport.insecure_skip_verify())
        {
            kinds.push(plan::kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
        }
        kinds
    }

    /// The headers a claim is copied into, and the header the token came in when it is not
    /// removed: a mirror does not get them unless it is meant to carry credentials.
    fn carries_identity(&self, name: &HeaderName) -> bool {
        self.0.forward.iter().any(|(_, header)| header == name)
            || (!self.0.remove_token
                && self.0.sources.iter().any(
                    |source| matches!(source, Source::Header { name: used, .. } if used == name),
                ))
    }

    /// What the stage checks; never a key, a secret or the query of `jwks_uri`.
    fn describe(&self) -> Value {
        let parts = &*self.0;
        json!({
            "algorithms": parts.algorithms.iter().map(Algorithm::name).collect::<Vec<_>>(),
            "keys": parts.inline.describe(),
            "jwks_uri": parts.jwks.as_ref().map(|target| target.display()),
            "jwks_refresh_secs": parts.jwks.as_ref().map(|_| parts.refresh_secs),
            "transport": parts.transport_name,
            "issuer": parts.rules.issuer,
            "audiences": parts.rules.audiences,
            "required_claims": parts.rules.required.iter()
                .map(|(name, want)| (name.to_string(), json!(want)))
                .collect::<Map<String, Value>>(),
            "leeway_secs": parts.rules.leeway_secs,
            "max_token_age_secs": parts.rules.max_token_age_secs,
            "token_sources": parts.sources.iter().map(Source::describe).collect::<Vec<_>>(),
            "forward_claims": parts.forward.iter()
                .map(|(claim, header)| (claim.to_string(), json!(header.as_str())))
                .collect::<Map<String, Value>>(),
            "remove_token": parts.remove_token,
        })
    }
}

/// Checks the `jwt_auth` stages of every app of `snapshot` against what only the snapshot, the
/// tenant's budget and the operator's policy know. `stages` holds the compiled middlewares of
/// each app, in order.
///
/// - A fetch that can never fit the tenant's `max_buffer_bytes` is refused (`invalid_middleware`),
///   as a `forward_auth` call is.
/// - A `jwks_uri` whose address the upstream address policy refuses for the tenant is
///   `upstream_forbidden`, as a server is; the policy is checked again on every fetch.
/// - A tenant uses at most [`MAX_URIS_PER_TENANT`] distinct `jwks_uri`.
pub(crate) fn check_snapshot(
    snapshot: &Snapshot,
    stages: &[&[super::Named]],
    policy: &UpstreamPolicy,
) -> Vec<Rejected> {
    let budgets: HashMap<&str, u64> = snapshot
        .tenants
        .iter()
        .map(|tenant| (&*tenant.id, tenant.budget.max_buffer_bytes))
        .collect();
    let mut uris: HashMap<&str, HashSet<&str>> = HashMap::new();
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        for named in *stages {
            let Stage::JwtAuth(auth) = &named.stage else {
                continue;
            };
            let Some(target) = auth.target() else {
                continue;
            };
            let at = format!("middleware {}", named.name);
            if let Some(&budget) = budgets.get(&*app.tenant)
                && budget < jwks::CHARGE
            {
                rejected.push(Rejected::new(
                    app,
                    at.clone(),
                    invalid(format!(
                        "tenant {} has max_buffer_bytes {budget}, below the {} bytes one JWKS fetch reserves; raise the budget",
                        app.tenant,
                        jwks::CHARGE
                    ))
                    .with("tenant", &*app.tenant)
                    .with("needed_bytes", jwks::CHARGE)
                    .with("max_buffer_bytes", budget),
                ));
            }
            if let Err(refused) = policy.evaluate(&app.tenant, target.ip()) {
                rejected.push(Rejected::new(
                    app,
                    at.clone(),
                    Invalid::new(
                        "upstream_forbidden",
                        format!(
                            "jwt_auth jwks_uri {}: {refused} (rule: {})",
                            target.display(),
                            refused.rule()
                        ),
                    )
                    .with("rule", refused.rule()),
                ));
            }
            let used = uris.entry(&app.tenant).or_default();
            if used.insert(&target.uri) && used.len() > MAX_URIS_PER_TENANT {
                rejected.push(Rejected::new(
                    app,
                    at,
                    invalid(format!(
                        "tenant {} uses more than {MAX_URIS_PER_TENANT} distinct jwks_uri",
                        app.tenant
                    ))
                    .with("tenant", &*app.tenant),
                ));
            }
        }
    }
    rejected
}

/// The permits of every `jwt_auth` middleware of the live table: the cached keys and counters,
/// kept by the shared [`state::Registry`] and settled at the swap site
/// ([`crate::table::TableHandle`]). A push that leaves a middleware's declaration as it was
/// keeps what it fetched.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::JwtAuth(auth) => Some((auth.0.fingerprint, &mut auth.0.runtime)),
            _ => None,
        });
    }
}

/// The Prometheus exposition of every `jwt_auth` stage of `live`:
/// `podgate_jwt_auth_verified_total`, `podgate_jwt_auth_rejected_total` (by `reason`, only the
/// reasons seen), `podgate_jwt_auth_jwks_fetches_total` (by `result`) and
/// `podgate_jwt_auth_jwks_keys`.
pub(crate) fn render(live: &RoutingTable) -> String {
    let mut out = String::new();
    let stages: Vec<(&str, &str, &Runtime)> = live
        .apps()
        .iter()
        .flat_map(|app| {
            app.stages()
                .iter()
                .filter_map(move |named| match &named.stage {
                    Stage::JwtAuth(auth) => Some((app.id(), &*named.name, &*auth.0.runtime)),
                    _ => None,
                })
        })
        .collect();
    if stages.is_empty() {
        return out;
    }
    let mut family = |name: &str, kind: &str, help: &str| {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    };
    family(
        "podgate_jwt_auth_verified_total",
        "counter",
        "Requests whose token a jwt_auth middleware accepted.",
    );
    for (app, name, runtime) in &stages {
        let _ = writeln!(
            out,
            "podgate_jwt_auth_verified_total{{app=\"{}\",middleware=\"{}\"}} {}",
            Escaped(app),
            Escaped(name),
            runtime.stats.verified.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_jwt_auth_rejected_total Requests a jwt_auth middleware refused, by reason.\n# TYPE podgate_jwt_auth_rejected_total counter"
    );
    for (app, name, runtime) in &stages {
        for failure in Failure::ALL {
            let count = runtime.stats.rejected[failure.index()].load(Ordering::Relaxed);
            if count > 0 {
                let _ = writeln!(
                    out,
                    "podgate_jwt_auth_rejected_total{{app=\"{}\",middleware=\"{}\",reason=\"{}\"}} {count}",
                    Escaped(app),
                    Escaped(name),
                    failure.code()
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "# HELP podgate_jwt_auth_jwks_fetches_total JWKS fetches of a jwt_auth middleware, by result.\n# TYPE podgate_jwt_auth_jwks_fetches_total counter"
    );
    for (app, name, runtime) in &stages {
        for (result, count) in [
            ("ok", runtime.stats.fetched.load(Ordering::Relaxed)),
            ("error", runtime.stats.fetch_failed.load(Ordering::Relaxed)),
        ] {
            if count > 0 {
                let _ = writeln!(
                    out,
                    "podgate_jwt_auth_jwks_fetches_total{{app=\"{}\",middleware=\"{}\",result=\"{result}\"}} {count}",
                    Escaped(app),
                    Escaped(name)
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "# HELP podgate_jwt_auth_jwks_keys Keys of the cached JWKS of a jwt_auth middleware.\n# TYPE podgate_jwt_auth_jwks_keys gauge"
    );
    for (app, name, runtime) in &stages {
        let _ = writeln!(
            out,
            "podgate_jwt_auth_jwks_keys{{app=\"{}\",middleware=\"{}\"}} {}",
            Escaped(app),
            Escaped(name),
            runtime.cache.held()
        );
    }
    out
}

#[cfg(test)]
mod test {
    use super::fixture::Signer;
    use super::*;
    use crate::wasm as engine;

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t1", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
            "transports": [{"name": "t", "type": "servers_transport", "server_name": "idp.internal"}],
        }))
        .expect("app")
    }

    fn compile(config: &Value) -> Result<JwtAuth, Invalid> {
        let mut declared = json!({"name": "jwt", "type": "jwt_auth"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app = app();
        let mut compiler = engine::Compiler::default();
        JwtAuth::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
            },
        )
    }

    fn good() -> Value {
        json!({"algorithms": ["ES256"], "keys": {"keys": [Signer::es256("k").jwk()]}})
    }

    fn with(extra: &Value) -> Value {
        let mut config = good();
        if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            config.extend(extra.clone());
        }
        config
    }

    #[test]
    fn jwt_invalid_config_rejected() {
        assert!(compile(&good()).is_ok());
        let oct = Signer::hmac("s", &[1; 32]).jwk();
        assert!(
            compile(&json!({"algorithms": ["HS256"], "keys": {"keys": [oct]}})).is_ok(),
            "an oct key makes HS256 fine"
        );
        let cases = [
            json!({"keys": good()["keys"]}),
            with(&json!({"algorithms": []})),
            with(&json!({"algorithms": ["none"]})),
            with(&json!({"algorithms": ["ES256", "ES256"]})),
            with(&json!({"algorithms": ["ES256", "HS256"]})),
            json!({"algorithms": ["ES256"]}),
            json!({"algorithms": ["ES256"], "keys": {"keys": []}, "jwks_uri": "no"}),
            with(&json!({"jwks_uri": "ftp://10.0.0.1/jwks"})),
            with(&json!({"jwks_uri": "https://idp.example/jwks"})),
            with(&json!({"jwks_uri": "https://user@10.0.0.1/jwks"})),
            with(&json!({"jwks_uri": "http://10.0.0.1/jwks", "transport": "t"})),
            with(&json!({"transport": "t"})),
            with(&json!({"leeway_secs": 301})),
            with(&json!({"max_token_age_secs": 0})),
            with(&json!({"issuer": ""})),
            with(&json!({"audiences": [""]})),
            with(&json!({"required_claims": {"role": []}})),
            with(&json!({"required_claims": {"role": [{"a": 1}]}})),
            with(&json!({"token_sources": []})),
            with(&json!({"token_sources": [{}]})),
            with(&json!({"token_sources": [{"cookie": "a b"}]})),
            with(&json!({"token_sources": [{"cookie": "a", "scheme": "Bearer"}]})),
            with(&json!({"token_sources": [{"header": "cookie"}]})),
            with(&json!({"token_sources": [{"header": "host"}]})),
            with(&json!({"token_sources": [{"query": "t"}, {"query": "t"}]})),
            with(&json!({"forward_claims": {"sub": "x-forwarded-for"}})),
            with(&json!({"forward_claims": {"sub": "Authorization"}})),
            with(&json!({"forward_claims": {"sub": "bad name"}})),
            with(&json!({"forward_claims": {"a": "x-user", "b": "X-User"}})),
            with(&json!({"unknown": true})),
        ];
        for (n, case) in cases.iter().enumerate() {
            let err = compile(case).expect_err(&format!("case {n}: {case}"));
            assert_eq!(err.code, "invalid_middleware", "case {n}: {}", err.message);
        }
        let err = compile(&with(
            &json!({"jwks_uri": "http://10.0.0.1/j", "transport": "nope"}),
        ))
        .expect_err("unknown transport");
        assert_eq!(err.code, "unknown_transport");
        let ok = compile(&with(&json!({
            "jwks_uri": "https://10.0.0.1/j", "transport": "t", "jwks_refresh_secs": 5,
        })))
        .expect("compiles");
        assert_eq!(ok.0.refresh_secs, 60, "the refresh interval is clamped");
    }

    fn request(path: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        for (name, value) in headers {
            request
                .append_header(name.to_string(), *value)
                .expect("header");
        }
        request
    }

    fn all_sources() -> JwtAuth {
        compile(&with(&json!({"token_sources": [
            {"header": "authorization", "scheme": "bearer"},
            {"cookie": "session"},
            {"query": "t"},
        ]})))
        .expect("compiles")
    }

    fn found(auth: &JwtAuth, request: &RequestHeader) -> Result<String, Failure> {
        auth.find_token(request)
    }

    #[test]
    fn the_first_place_with_a_token_wins_and_ambiguity_is_refused() {
        let auth = all_sources();
        let token = "a.b.c";
        let by_header = request(
            "/?t=q",
            &[("Authorization", "Bearer a.b.c"), ("Cookie", "session=x")],
        );
        assert_eq!(found(&auth, &by_header), Ok(token.to_owned()));
        // A scheme other than ours is not a token: the next place is looked at (and the scheme
        // is matched without regard to case).
        let basic = request("/?t=q.r.s", &[("Authorization", "Basic abc")]);
        assert_eq!(found(&auth, &basic), Ok("q.r.s".to_owned()));
        let lower = request("/", &[("Authorization", "BEARER a.b.c")]);
        assert_eq!(found(&auth, &lower), Ok(token.to_owned()));
        let cookie = request("/", &[("Cookie", "theme=dark; session=\"a.b.c\"")]);
        assert_eq!(found(&auth, &cookie), Ok(token.to_owned()));
        assert_eq!(found(&auth, &request("/", &[])), Err(Failure::Missing));
        for ambiguous in [
            request(
                "/",
                &[
                    ("Authorization", "Bearer a.b.c"),
                    ("Authorization", "Bearer d.e.f"),
                ],
            ),
            request("/", &[("Cookie", "session=a; session=b")]),
            request("/", &[("Cookie", "session=a"), ("Cookie", "session=b")]),
            request("/?t=a&t=b", &[]),
            request("/", &[("Authorization", "Bearer a b")]),
            request("/", &[("Authorization", "Bearer ")]),
        ] {
            assert_eq!(
                found(&auth, &ambiguous),
                Err(Failure::Malformed),
                "{ambiguous:?}"
            );
        }
        let big = format!("Bearer {}", "a".repeat(MAX_TOKEN + 1));
        assert_eq!(
            found(&auth, &request("/", &[("Authorization", &big)])),
            Err(Failure::Oversized)
        );
    }

    #[test]
    fn remove_token_takes_the_credential_out_of_every_place() {
        let auth = all_sources();
        let mut request = request(
            "/p?x=1&t=a.b.c&y=%20z&t2=k",
            &[
                ("Authorization", "Bearer a.b.c"),
                ("Cookie", "theme=dark; session=a.b.c; lang=en"),
                ("Cookie", "session=a.b.c"),
                ("Cookie", "other=1"),
            ],
        );
        for source in &auth.0.sources {
            source.strip(&mut request);
        }
        assert!(request.headers.get("authorization").is_none());
        let cookies: Vec<&str> = request
            .headers
            .get_all("cookie")
            .iter()
            .map(|value| value.to_str().expect("text"))
            .collect();
        assert_eq!(cookies, ["theme=dark; lang=en", "other=1"]);
        assert_eq!(
            request.uri.path_and_query().map(|p| p.as_str()),
            Some("/p?x=1&y=%20z&t2=k")
        );
        // A scheme that is not ours is not our credential: it stays.
        let mut basic = request_with_basic();
        for source in &auth.0.sources {
            source.strip(&mut basic);
        }
        assert!(basic.headers.get("authorization").is_some());
    }

    fn request_with_basic() -> RequestHeader {
        request("/", &[("Authorization", "Basic abc")])
    }

    #[test]
    fn explain_shows_no_key_material_and_no_query() {
        let oct = Signer::hmac("s", &[0x41; 40]);
        let auth = compile(&json!({
            "algorithms": ["HS256", "ES256"],
            "keys": {"keys": [oct.jwk(), Signer::es256("e").jwk()]},
            "jwks_uri": "https://10.0.0.1/jwks?apikey=SECRETQUERY",
        }))
        .expect("compiles");
        let shown = auth.describe().to_string();
        let secret = oct.jwk()["k"].as_str().expect("k").to_owned();
        assert!(
            !shown.contains(&secret) && !shown.contains("SECRETQUERY"),
            "{shown}"
        );
        assert!(shown.contains("\"https://10.0.0.1/jwks\""), "{shown}");
        assert!(
            !format!("{auth:?}").contains(&secret),
            "Debug leaks the key"
        );
    }

    #[test]
    fn posture_names_what_a_change_trusts_more() {
        let base = good();
        let make = |leeway: u64| {
            let mut config = base.clone();
            config["leeway_secs"] = json!(leeway);
            compile(&config).expect("compiles")
        };
        let (old, longer) = (make(10), make(11));
        assert_eq!(old.posture(Some(&longer)), [kind::LEEWAY_INCREASED]);
        assert_eq!(longer.posture(Some(&old)), Vec::<&str>::new());
        assert_eq!(old.posture(None), [kind::REMOVED]);
    }
}
