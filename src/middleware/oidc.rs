//! The `oidc` middleware: a chain stage that protects a web app with an OpenID Connect login
//! (authorization code flow with PKCE). Full reference: `docs/ref/mw-oidc.md`.
//!
//! ```json
//! { "name": "login", "type": "oidc", "issuer": "https://idp.example/realms/main",
//!   "client_id": "podgate-app", "client_secret": "…", "scopes": ["openid", "email"],
//!   "allowed_algorithms": ["RS256"], "forward_claims": {"email": "X-Email"},
//!   "required_claims": {"email_verified": true}, "session": {"max_age_secs": 28800} }
//! ```
//!
//! A browser without a valid session cookie is sent to the provider; it comes back to the
//! reserved `redirect_path` of the route, where the middleware redeems the code, verifies the ID
//! token with the machinery of `jwt_auth` and issues a session cookie. **The session is the
//! cookie**: encrypted under a key derived from the snapshot's `skew_secret`, nothing is kept on
//! the server. The price is that logout is local and a person whose access is revoked at the
//! provider stays signed in until their cookie ends.
//!
//! - **Files.** `session.rs` derives the keys and seals the cookies, `flow.rs` is the login (the
//!   flow cookie, the authorization URL, the rule for where the browser goes afterwards),
//!   `discovery.rs` is everything asked of the provider.
//! - **Where it runs.** In the chain, before a revision is chosen and before any tenant slot is
//!   taken: an unauthenticated visitor costs a redirect and nothing else, and wakes nobody.
//! - **What the upstream sees.** The claims named in `forward_claims` as headers; every header
//!   named there is removed from the client's request first. The session cookie is removed from
//!   the request, the upstream never receives it.
//! - **Caches.** A request with a session carries an identity the cache key does not hold, so the
//!   `cache` stage neither serves nor stores it, as for `forward_auth` and `jwt_auth`.
//! - **What is never shown.** The session cookie and the client secret reach no access log line,
//!   no failed-request record and no mirror copy (the `Cookie` header is redacted or dropped
//!   there, `jwt_auth::Credentials` redacts the code of a callback), and the secret is redacted
//!   in `Debug`, explain and the overview.

mod discovery;
mod flow;
mod session;

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use http::Method;
use http::header::{ACCEPT, AUTHORIZATION, COOKIE, HOST, HeaderName, HeaderValue};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session as Downstream;
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;

use self::discovery::{
    Discover, DiscoverError, Exchange, ExchangeError, Provider, REFRESH_SECS, document_url, redeem,
};
use self::flow::{Authorization, FLOW_TTL_SECS, Refused, authorization_url, resume, start};
use self::session::{FLOW_LABEL, SESSION_LABEL, Sealer, Session};
use super::forward_auth::{Client, Parsed};
use super::jwt_auth::claims::{Rules, header_text};
use super::jwt_auth::jwks::{CHARGE, Cache, Demand, Fetch, FetchError, Flight, REFRESH_DEFAULT};
use super::jwt_auth::verify::{Algorithm, Algorithms, Failure, KeySet, Token, verify};
use super::jwt_auth::{Want, requirements, strip_cookie};
use super::portal::pin::{Login, Source};
use super::redirect::{self, Origin};
use super::{CompileCx, Flow, Kind, RequestCx, Stage, forward_auth, state};
use crate::budget::{Escaped, TenantBudget};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::plan;
use crate::service::Transport;
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{CompiledApp, RoutingTable};
use podgate_model::{Declared, SkewSecret, Snapshot};

/// The query parameters of a callback that hold a credential: the code, and the state that
/// belongs to the flow cookie. Sinks that record a URL redact them.
pub(crate) const CALLBACK_SECRETS: [&str; 3] = ["code", "state", "session_state"];

/// The default `redirect_path`.
const DEFAULT_REDIRECT_PATH: &str = "/_podgate/oidc/callback";
/// The default `session.cookie_name`.
const DEFAULT_COOKIE: &str = "__Host-podgate_oidc";
/// The name of the flow cookie. `__Secure-` and not `__Host-`: its `Path` is the callback.
const FLOW_COOKIE: &str = "__Secure-podgate_oidc_flow";
/// The default and the largest `session.max_age_secs`.
const DEFAULT_MAX_AGE_SECS: u64 = 8 * 3600;
const MAX_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
/// The most distinct issuers a tenant may use.
const MAX_ISSUERS_PER_TENANT: usize = 4;
/// Clock skew allowed on `exp`, `nbf` and `iat` of the ID token.
const LEEWAY_SECS: u64 = 30;
/// The most entries of each list of the configuration.
const MAX_ENTRIES: usize = 32;
/// The most `allow_subjects`.
const MAX_SUBJECTS: usize = 256;
/// The longest name, path, identifier or subject of the configuration.
const MAX_NAME: usize = 256;
/// The longest code a callback may carry.
const MAX_CODE: usize = 2048;

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: requests are no longer asked to sign in.
    pub const REMOVED: &str = "oidc_removed";
    /// A session lasts longer than it did.
    pub const SESSION_LONGER: &str = "oidc_session_longer";
    /// A required claim is gone, or accepts more values.
    pub const REQUIRED_CLAIMS_LOOSENED: &str = "oidc_required_claims_loosened";
    /// `allow_subjects` was set and is gone or admits one more person.
    pub const SUBJECTS_LOOSENED: &str = "oidc_subjects_loosened";
    /// An ID token signed with an algorithm it could not be before is accepted.
    pub const ALGORITHM_ADDED: &str = "oidc_algorithm_added";
    /// Another issuer or another client is trusted.
    pub const PROVIDER_CHANGED: &str = "oidc_provider_changed";
}

/// A secret. `Debug` shows nothing of it.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The `SameSite` attribute of the session cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
enum SameSite {
    #[serde(alias = "lax")]
    Lax,
    #[serde(alias = "strict")]
    Strict,
    #[serde(alias = "none")]
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

/// The `session` setting.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SessionConfig {
    #[serde(default)]
    max_age_secs: Option<u64>,
    #[serde(default)]
    cookie_name: Option<String>,
    #[serde(default)]
    same_site: Option<SameSite>,
}

/// The configuration of an `oidc` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    issuer: String,
    client_id: String,
    #[serde(default)]
    client_secret: Option<Secret>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    redirect_path: Option<String>,
    #[serde(default)]
    logout_path: Option<String>,
    #[serde(default)]
    allowed_algorithms: Option<Vec<String>>,
    #[serde(default)]
    session: Option<SessionConfig>,
    #[serde(default)]
    forward_claims: BTreeMap<String, String>,
    #[serde(default)]
    required_claims: BTreeMap<String, Want>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    allow_subjects: Option<Vec<String>>,
}

/// Why a request got no session, and no login either. The counters are by reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    /// A request that cannot follow a redirect and has no session.
    LoginRequired,
    /// A callback that is malformed.
    BadCallback,
    /// A callback with no flow cookie, or one that does not open.
    NoFlow,
    /// A callback whose `state` is not the flow cookie's.
    StateMismatch,
    /// The provider answered the authorization request with an error.
    IdpError,
    /// The token endpoint refused the code, or its answer is not usable.
    CodeRejected,
    /// The ID token is not valid.
    IdToken,
    /// The ID token's `nonce` is not the flow's.
    Nonce,
    /// The person is not admitted: `required_claims` or `allow_subjects`.
    Forbidden,
    /// The provider, its document or its keys cannot be had.
    ProviderUnavailable,
    /// No room for a token endpoint call.
    Busy,
    /// The middleware cannot work: no key.
    Internal,
}

impl Reason {
    const ALL: [Self; 12] = [
        Self::LoginRequired,
        Self::BadCallback,
        Self::NoFlow,
        Self::StateMismatch,
        Self::IdpError,
        Self::CodeRejected,
        Self::IdToken,
        Self::Nonce,
        Self::Forbidden,
        Self::ProviderUnavailable,
        Self::Busy,
        Self::Internal,
    ];

    fn index(self) -> usize {
        self as usize
    }

    fn label(self) -> &'static str {
        match self {
            Self::LoginRequired => "login_required",
            Self::BadCallback => "bad_callback",
            Self::NoFlow => "no_flow",
            Self::StateMismatch => "state_mismatch",
            Self::IdpError => "idp_error",
            Self::CodeRejected => "code_rejected",
            Self::IdToken => "id_token",
            Self::Nonce => "nonce",
            Self::Forbidden => "forbidden",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Busy => "busy",
            Self::Internal => "internal",
        }
    }
}

/// A request the middleware refuses: the counter it moves and the answer it gets.
#[derive(Debug)]
struct Refusal {
    reason: Reason,
    error: AppError,
}

impl Refusal {
    /// A refusal of `reason` whose access log reason is `code`.
    fn new(reason: Reason, code: &'static str) -> Self {
        let error = match reason {
            Reason::BadCallback | Reason::NoFlow | Reason::StateMismatch => {
                AppError::OidcBadCallback { reason: code }
            }
            Reason::LoginRequired | Reason::CodeRejected | Reason::IdToken | Reason::Nonce => {
                AppError::OidcRejected { reason: code }
            }
            Reason::IdpError | Reason::Forbidden => AppError::OidcForbidden { reason: code },
            Reason::ProviderUnavailable => AppError::OidcUnavailable { reason: code },
            Reason::Busy => AppError::OidcBusy,
            Reason::Internal => AppError::Internal(anyhow::anyhow!("oidc: {code}")),
        };
        Self { reason, error }
    }
}

/// The counters of one middleware, shown by [`render`].
#[derive(Debug, Default)]
struct Stats {
    started: AtomicU64,
    completed: AtomicU64,
    sessions: AtomicU64,
    claims_dropped: AtomicU64,
    refused: [AtomicU64; Reason::ALL.len()],
    discovered: AtomicU64,
    discovery_failed: AtomicU64,
    jwks_fetched: AtomicU64,
    jwks_failed: AtomicU64,
}

/// The `jwks_uri` the discovery document named, and the keys fetched from it.
type KeyCache = Option<(Box<str>, Arc<Cache<KeySet>>)>;

/// What outlives a snapshot push: the cached discovery document and keys, and the counters.
#[derive(Debug)]
struct Runtime {
    discovery: Cache<Provider>,
    keys: Mutex<KeyCache>,
    stats: Stats,
}

/// The two keys of a middleware, from the snapshot's `skew_secret`.
#[derive(Debug)]
struct Keys {
    flow: Sealer,
    session: Sealer,
}

#[derive(Debug)]
struct Parts {
    issuer: Box<str>,
    discovery: Arc<Parsed>,
    client_id: Box<str>,
    client_secret: Option<Secret>,
    /// The scopes, space separated.
    scope: Box<str>,
    redirect_path: Box<str>,
    logout_path: Option<Box<str>>,
    algorithms: Algorithms,
    /// The checks of the ID token: issuer, audience (the client), `exp`, `required_claims`.
    rules: Rules,
    allow_subjects: Option<Box<[Box<str>]>>,
    max_age_secs: u64,
    cookie_name: Box<str>,
    same_site: SameSite,
    /// Claim and the header it is copied into.
    forward: Box<[(Box<str>, HeaderName)]>,
    /// The claims besides `sub` the session cookie carries.
    carried: Box<[Box<str>]>,
    transport: Arc<Transport>,
    transport_name: Option<Box<str>>,
    app: Box<str>,
    name: Box<str>,
    resolver: Resolver,
    keys: Option<Keys>,
    /// A digest of the declaration: a session issued under another one is refused.
    policy: u64,
    runtime: Arc<Runtime>,
    fingerprint: u64,
}

/// A compiled `oidc` middleware.
#[derive(Debug)]
pub struct Oidc(Box<Parts>);

/// What a request keeps of its `oidc` stage.
#[derive(Debug, Default)]
pub struct State {
    /// A valid session put an identity into the request that the cache key does not hold.
    authenticated: bool,
}

impl State {
    /// Whether the request carries the identity of a session.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}

fn invalid(message: impl fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("oidc: {message}"))
}

/// The transport named `name` of `app`, compiled for the calls to the provider.
fn transport_of(
    app: &podgate_model::App,
    name: Option<&str>,
    tls: bool,
) -> Result<Arc<Transport>, Invalid> {
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
                format!("oidc: transport {name} is not declared by the app"),
            )
        })?;
    let transport = Transport::compile(declared)?;
    if !tls && transport.has_tls_settings() {
        return Err(invalid(
            "the transport sets TLS options and the issuer is plain http://",
        ));
    }
    Ok(Arc::new(transport))
}

/// Whether `text` is a name of unreserved characters only, as cookie and scope names are here.
fn plain(text: &str, allowed: impl Fn(u8) -> bool) -> bool {
    !text.is_empty() && text.len() <= MAX_NAME && text.bytes().all(allowed)
}

/// A path the middleware answers: absolute, of unreserved characters, no query.
fn own_path(path: &str, field: &str) -> Result<Box<str>, Invalid> {
    let fine = path.starts_with('/')
        && !path.starts_with("//")
        && plain(path, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~')
        });
    if !fine {
        return Err(invalid(format!(
            "`{field}` {path:?} must be an absolute path of letters, digits and `/-_.~`"
        )));
    }
    Ok(path.into())
}

fn unix_secs() -> u64 {
    // A clock before 1970 makes every session expired: closed.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |elapsed| elapsed.as_secs())
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(f64::MAX, |elapsed| elapsed.as_secs_f64())
}

/// The values of the cookies called `name` of `request`.
fn cookie_values<'a>(request: &'a RequestHeader, name: &'a str) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .get_all(COOKIE)
        .into_iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(move |pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

/// Whether a request can follow a redirect to a login page: a `GET` that asks for HTML and is not
/// a script's `XMLHttpRequest`. Anything else (an `fetch`, an API call, a form post) gets a
/// `401`, which a script can read, instead of an HTML page it cannot.
fn can_redirect(request: &RequestHeader) -> bool {
    request.method == Method::GET
        && !request.headers.contains_key("x-requested-with")
        && request.headers.get_all(ACCEPT).iter().any(|accept| {
            accept.to_str().is_ok_and(|accept| {
                accept.split(',').any(|item| {
                    item.split(';')
                        .next()
                        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/html"))
                })
            })
        })
}

/// A `Set-Cookie` value. Always `Secure` and `HttpOnly`, with no `Domain`: the cookie belongs to
/// the host that set it.
fn set_cookie(name: &str, value: &str, path: &str, max_age: u64, same_site: SameSite) -> String {
    format!(
        "{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; Secure; SameSite={}",
        same_site.as_str()
    )
}

/// What a request needs to call the provider, borrowed from its context.
struct Who<'a> {
    client: &'a Client,
    policy: &'a UpstreamPolicy,
    tenant: &'a str,
    budget: Option<&'a Arc<TenantBudget>>,
}

/// Where in the middleware's own paths a request is.
enum Place {
    Callback,
    Logout,
    Elsewhere,
}

impl Oidc {
    /// The path the provider sends the browser back to; the middleware answers it itself.
    pub(crate) fn callback_path(&self) -> &str {
        &self.0.redirect_path
    }

    /// Gives the stage the keys of its cookies, derived from the snapshot's `skew_secret`, and the
    /// resolver the provider's host name is resolved with.
    ///
    /// # Errors
    ///
    /// `invalid_middleware` when the snapshot has no `skew_secret`.
    pub(crate) fn bind(
        &mut self,
        secret: Option<&SkewSecret>,
        resolver: &Resolver,
    ) -> Result<(), Invalid> {
        let secret = secret.ok_or_else(|| invalid("needs the snapshot's skew_secret"))?;
        let derive = |label| {
            Sealer::derive(secret.as_bytes(), label, &self.0.app, &self.0.name)
                .ok_or_else(|| invalid("the app or middleware name is too long"))
        };
        let keys = Keys {
            flow: derive(FLOW_LABEL)?,
            session: derive(SESSION_LABEL)?,
        };
        self.0.keys = Some(keys);
        self.0.resolver = resolver.clone();
        Ok(())
    }

    fn place(&self, path: &str) -> Place {
        if path == &*self.0.redirect_path {
            Place::Callback
        } else if self.0.logout_path.as_deref() == Some(path) {
            Place::Logout
        } else {
            Place::Elsewhere
        }
    }

    /// The session the request's cookies hold, if any of them is valid for `host` now.
    fn session_of(&self, request: &RequestHeader, host: &str, now: u64) -> Option<Session> {
        let keys = self.0.keys.as_ref()?;
        cookie_values(request, &self.0.cookie_name).find_map(|value| {
            Session::open(
                &keys.session,
                host,
                value,
                self.0.policy,
                now,
                self.0.max_age_secs,
            )
        })
    }

    /// Starts the fetch of the discovery document in the background.
    fn spawn_discovery(&self, who: &Who<'_>, flight: Flight) {
        let runtime = Arc::clone(&self.0.runtime);
        let Some(budget) = who.budget else {
            runtime
                .discovery
                .finish(flight, Instant::now(), Err(DiscoverError::Budget));
            return;
        };
        let discover = Discover {
            issuer: self.0.issuer.clone(),
            url: Arc::clone(&self.0.discovery),
            transport: Arc::clone(&self.0.transport),
            public_client: self.0.client_secret.is_none(),
            client: who.client.clone(),
            policy: who.policy.clone(),
            resolver: self.0.resolver.clone(),
            tenant: who.tenant.into(),
            budget: Arc::clone(budget),
        };
        tokio::spawn(async move {
            let result = discover.run().await;
            match &result {
                Ok(_) => {
                    runtime.stats.discovered.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(issuer = &*discover.issuer, "oidc discovery fetched");
                }
                Err(why) => {
                    runtime
                        .stats
                        .discovery_failed
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        tenant = &*discover.tenant,
                        issuer = &*discover.issuer,
                        %why,
                        "oidc discovery failed"
                    );
                }
            }
            runtime.discovery.finish(flight, Instant::now(), result);
        });
    }

    /// The provider's document, fetching it when the plan says so. `None` when there is none.
    async fn provider(&self, who: &Who<'_>) -> Option<Arc<Provider>> {
        self.0
            .runtime
            .discovery
            .obtain(Demand::Keys, |flight| self.spawn_discovery(who, flight))
            .await
    }

    /// The key cache of the `jwks_uri` of `provider`: the one the middleware already holds when
    /// the document still names the same URI, a new one when it does not.
    fn key_cache(&self, provider: &Provider) -> Arc<Cache<KeySet>> {
        let mut slot = self
            .0
            .runtime
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((uri, cache)) = &*slot
            && **uri == *provider.jwks.uri
        {
            return Arc::clone(cache);
        }
        let cache = Arc::new(Cache::new(REFRESH_DEFAULT));
        *slot = Some((provider.jwks.uri.clone(), Arc::clone(&cache)));
        cache
    }

    /// The provider's signing keys, fetching when the plan says so.
    async fn id_keys(
        &self,
        who: &Who<'_>,
        provider: &Provider,
        demand: Demand,
    ) -> Option<Arc<KeySet>> {
        let cache = self.key_cache(provider);
        let held = Arc::clone(&cache);
        let start = |flight: Flight| {
            let runtime = Arc::clone(&self.0.runtime);
            let Some(budget) = who.budget else {
                held.finish(flight, Instant::now(), Err(FetchError::Budget));
                return;
            };
            let fetch = Fetch {
                target: Arc::clone(&provider.jwks),
                client: who.client.clone(),
                policy: who.policy.clone(),
                resolver: self.0.resolver.clone(),
                tenant: who.tenant.into(),
                budget: Arc::clone(budget),
            };
            let cache = Arc::clone(&held);
            tokio::spawn(async move {
                let result = fetch.run().await;
                match &result {
                    Ok(_) => {
                        runtime.stats.jwks_fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(why) => {
                        runtime.stats.jwks_failed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            tenant = &*fetch.tenant,
                            uri = %fetch.target.display(),
                            %why,
                            "oidc jwks fetch failed"
                        );
                    }
                }
                cache.finish(flight, Instant::now(), result.map(|(keys, _)| keys));
            });
        };
        cache.obtain(demand, start).await
    }

    /// Verifies the ID token the token endpoint returned: the signature against the provider's
    /// keys, the issuer, the audience, the time, `required_claims`, the `nonce` of the login and
    /// the subject.
    async fn verify_id_token(
        &self,
        who: &Who<'_>,
        provider: &Provider,
        raw: &str,
        nonce: &str,
    ) -> Result<Map<String, Value>, Refusal> {
        let failure = |failure: Failure| match failure {
            Failure::ClaimsForbidden => Refusal::new(Reason::Forbidden, failure.code()),
            Failure::Unavailable => Refusal::new(Reason::ProviderUnavailable, failure.code()),
            other => Refusal::new(Reason::IdToken, other.code()),
        };
        let token = Token::parse(raw, &self.0.algorithms).map_err(failure)?;
        let unavailable = || Refusal::new(Reason::ProviderUnavailable, "jwks_unavailable");
        let mut keys = self
            .id_keys(who, provider, Demand::Keys)
            .await
            .ok_or_else(unavailable)?;
        match verify(&token, &[&keys]) {
            Ok(()) => {}
            Err(Failure::UnknownKid) => {
                keys = self
                    .id_keys(who, provider, Demand::KidMiss)
                    .await
                    .ok_or_else(unavailable)?;
                verify(&token, &[&keys]).map_err(failure)?;
            }
            Err(other) => return Err(failure(other)),
        }
        let claims = token.claims().map_err(failure)?;
        self.0.rules.check(&claims, unix_now()).map_err(failure)?;
        let sent = claims
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !bool::from(sent.as_bytes().ct_eq(nonce.as_bytes())) {
            return Err(Refusal::new(Reason::Nonce, "oidc_nonce_mismatch"));
        }
        // A token for several audiences names the one it was issued to (OIDC Core 3.1.3.7).
        if claims
            .get("aud")
            .and_then(Value::as_array)
            .is_some_and(|list| list.len() > 1)
            && claims.get("azp").and_then(Value::as_str) != Some(&*self.0.client_id)
        {
            return Err(Refusal::new(Reason::IdToken, "oidc_bad_azp"));
        }
        match claims.get("sub").and_then(Value::as_str) {
            Some(sub) if !sub.is_empty() => {
                if self
                    .0
                    .allow_subjects
                    .as_ref()
                    .is_some_and(|allowed| !allowed.iter().any(|known| **known == *sub))
                {
                    return Err(Refusal::new(Reason::Forbidden, "oidc_subject_forbidden"));
                }
            }
            _ => return Err(Refusal::new(Reason::IdToken, "oidc_no_subject")),
        }
        Ok(claims)
    }

    /// Answers `refusal` and ends the request.
    async fn fail(&self, cx: &mut RequestCx<'_>, refusal: Refusal) -> pingora::Result<Flow> {
        let Refusal { reason, error } = refusal;
        self.0.runtime.stats.refused[reason.index()].fetch_add(1, Ordering::Relaxed);
        tracing::debug!(app = cx.app.id(), reason = reason.label(), "oidc refused");
        *cx.reason = Some(error.log_reason());
        *cx.capacity_refusal = error.is_capacity_refusal();
        if reason == Reason::LoginRequired {
            // The challenge of a script that has no session: not a page to follow.
            let body = bytes::Bytes::from(error.body().to_string());
            let mut head = ResponseHeader::build(401, Some(5))?;
            head.insert_header("www-authenticate", "Bearer")?;
            head.insert_header("content-type", "application/json")?;
            head.insert_header("content-length", body.len().to_string())?;
            head.insert_header("cache-control", "no-store")?;
            cx.session
                .write_response_header(Box::new(head), false)
                .await?;
            cx.session.write_response_body(Some(body), true).await?;
        } else {
            crate::respond::write_error(cx.session, &error).await?;
        }
        Ok(Flow::Respond)
    }

    /// A request that is not for the middleware's own paths: it passes with a session, goes to
    /// the provider without one, and gets a `401` when it cannot follow a redirect.
    async fn protect(
        &self,
        cx: &mut RequestCx<'_>,
        origin: &Origin,
        state: &mut State,
        now: u64,
    ) -> pingora::Result<Flow> {
        if let Some(session) = self.session_of(cx.session.req_header(), origin.host(), now) {
            let request = cx.session.req_header_mut();
            for (claim, header) in &self.0.forward {
                if let Some(text) = session.claims().get(&**claim).and_then(header_text)
                    && let Ok(value) = HeaderValue::from_str(&text)
                {
                    request.insert_header(header.clone(), value)?;
                }
            }
            // The claims of a session that opened: verified at login and sealed in the cookie, so
            // nothing here came from a header or a field the client could change. Later stages
            // (`opa`, `portal`) decide on them.
            cx.claims = Some(session.claims().clone());
            // The upstream has no use for it, and it must not reach a log or a mirror there.
            strip_cookie(request, &self.0.cookie_name);
            state.authenticated = true;
            self.0
                .runtime
                .stats
                .sessions
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Flow::Continue);
        }
        if !can_redirect(cx.session.req_header()) {
            return self
                .fail(
                    cx,
                    Refusal::new(Reason::LoginRequired, "oidc_login_required"),
                )
                .await;
        }
        let who = Who {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.app.tenant(),
            budget: cx.tenant,
        };
        let Some(keys) = &self.0.keys else {
            return self
                .fail(cx, Refusal::new(Reason::Internal, "no skew_secret key"))
                .await;
        };
        let Some(provider) = self.provider(&who).await else {
            return self
                .fail(
                    cx,
                    Refusal::new(Reason::ProviderUnavailable, "oidc_provider_unavailable"),
                )
                .await;
        };
        let next = cx
            .session
            .req_header()
            .uri
            .path_and_query()
            .map_or("/", |target| target.as_str());
        let Some(login) = start(&keys.flow, origin.host(), next, now) else {
            return self
                .fail(cx, Refusal::new(Reason::Internal, "no entropy"))
                .await;
        };
        let redirect_uri = origin.at(&self.0.redirect_path);
        let url = authorization_url(&Authorization {
            endpoint: &provider.authorization_endpoint,
            client_id: &self.0.client_id,
            redirect_uri: &redirect_uri,
            scope: &self.0.scope,
            login: &login,
        });
        let cookie = set_cookie(
            FLOW_COOKIE,
            &login.cookie,
            &self.0.redirect_path,
            FLOW_TTL_SECS,
            SameSite::Lax,
        );
        self.0.runtime.stats.started.fetch_add(1, Ordering::Relaxed);
        Self::send(cx, 302, &url, &[cookie]).await
    }

    /// Writes a redirect to `location` with `cookies`, or `400` when the location cannot be sent.
    async fn send(
        cx: &mut RequestCx<'_>,
        status: u16,
        location: &str,
        cookies: &[String],
    ) -> pingora::Result<Flow> {
        match redirect::finish(location) {
            Ok(location) => {
                write_redirect(cx.session, status, &location, cookies).await?;
            }
            Err(refused) => {
                let error = AppError::BadRequest(refused.to_string().into());
                *cx.reason = Some(error.log_reason());
                crate::respond::write_error(cx.session, &error).await?;
            }
        }
        Ok(Flow::Respond)
    }

    /// The callback: redeems the code and issues the session.
    async fn callback(
        &self,
        cx: &mut RequestCx<'_>,
        origin: &Origin,
        now: u64,
    ) -> pingora::Result<Flow> {
        match self.complete(cx, origin, now).await {
            Ok((cookies, next)) => {
                self.0
                    .runtime
                    .stats
                    .completed
                    .fetch_add(1, Ordering::Relaxed);
                Self::send(cx, 302, &next, &cookies).await
            }
            Err(refusal) => self.fail(cx, refusal).await,
        }
    }

    /// Everything the callback does short of answering: the session cookie and the clearing of
    /// the flow cookie, and where to send the browser.
    async fn complete(
        &self,
        cx: &mut RequestCx<'_>,
        origin: &Origin,
        now: u64,
    ) -> Result<(Vec<String>, String), Refusal> {
        let request = cx.session.req_header();
        if request.method != Method::GET {
            return Err(Refusal::new(Reason::BadCallback, "oidc_callback_method"));
        }
        let keys = self
            .0
            .keys
            .as_ref()
            .ok_or_else(|| Refusal::new(Reason::Internal, "no skew_secret key"))?;
        let (mut code, mut state, mut denied) = (None, None, false);
        for (name, value) in form_urlencoded::parse(request.uri.query().unwrap_or("").as_bytes()) {
            let slot = match &*name {
                "code" => &mut code,
                "state" => &mut state,
                "error" => {
                    denied = true;
                    continue;
                }
                _ => continue,
            };
            if slot.replace(value.into_owned()).is_some() {
                return Err(Refusal::new(Reason::BadCallback, "oidc_callback_repeats"));
            }
        }
        let state =
            state.ok_or_else(|| Refusal::new(Reason::BadCallback, "oidc_callback_no_state"))?;
        let flow = resume(
            &keys.flow,
            origin.host(),
            cookie_values(request, FLOW_COOKIE),
            &state,
            now,
        )
        .map_err(|refused| match refused {
            Refused::NoCookie => Refusal::new(Reason::NoFlow, "oidc_no_flow_cookie"),
            Refused::Invalid => Refusal::new(Reason::NoFlow, "oidc_flow_cookie_invalid"),
            Refused::StateMismatch => Refusal::new(Reason::StateMismatch, "oidc_state_mismatch"),
        })?;
        if denied {
            return Err(Refusal::new(Reason::IdpError, "oidc_idp_error"));
        }
        let code = code
            .filter(|code| !code.is_empty() && code.len() <= MAX_CODE)
            .ok_or_else(|| Refusal::new(Reason::BadCallback, "oidc_callback_no_code"))?;
        let who = Who {
            client: cx.auth,
            policy: cx.policy,
            tenant: cx.app.tenant(),
            budget: cx.tenant,
        };
        let budget = who
            .budget
            .ok_or_else(|| Refusal::new(Reason::Busy, "oidc_busy"))?;
        let provider = self.provider(&who).await.ok_or_else(|| {
            Refusal::new(Reason::ProviderUnavailable, "oidc_provider_unavailable")
        })?;
        let redirect_uri = origin.at(&self.0.redirect_path);
        let exchange = Exchange {
            client: who.client,
            policy: who.policy,
            resolver: &self.0.resolver,
            transport: &self.0.transport,
            tenant: who.tenant,
            budget,
            token: &provider.token,
            client_id: &self.0.client_id,
            client_secret: self
                .0
                .client_secret
                .as_ref()
                .map(|secret| secret.0.as_str()),
            code: &code,
            verifier: flow.verifier(),
            redirect_uri: &redirect_uri,
        };
        let raw = redeem(&exchange).await.map_err(|why| {
            tracing::warn!(app = cx.app.id(), %why, "oidc token exchange failed");
            match why {
                ExchangeError::Busy | ExchangeError::Budget => {
                    Refusal::new(Reason::Busy, "oidc_busy")
                }
                ExchangeError::Rejected(status) if status < 500 => {
                    Refusal::new(Reason::CodeRejected, "oidc_code_rejected")
                }
                ExchangeError::Malformed => Refusal::new(Reason::CodeRejected, "oidc_no_id_token"),
                ExchangeError::Rejected(_) | ExchangeError::Call(_) => Refusal::new(
                    Reason::ProviderUnavailable,
                    "oidc_token_endpoint_unavailable",
                ),
            }
        })?;
        let claims = self
            .verify_id_token(&who, &provider, &raw, flow.nonce())
            .await?;
        let cookie = self.issue(&claims, origin.host(), keys, now)?;
        let clear = set_cookie(FLOW_COOKIE, "", &self.0.redirect_path, 0, SameSite::Lax);
        Ok((vec![cookie, clear], flow.next().to_owned()))
    }

    /// The `Set-Cookie` of the session for the person `claims` of a verified ID token describe.
    fn issue(
        &self,
        claims: &Map<String, Value>,
        host: &str,
        keys: &Keys,
        now: u64,
    ) -> Result<String, Refusal> {
        // Verified: `exp` is a finite number in the future and `sub` a string.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "exp is a finite number in the future, checked by the claim rules"
        )]
        let token_ends = claims
            .get("exp")
            .and_then(Value::as_f64)
            .map_or(0, |exp| exp as u64);
        let ends = token_ends.min(now.saturating_add(self.0.max_age_secs));
        let mut carried = Map::new();
        if let Some(sub) = claims.get("sub") {
            carried.insert("sub".to_owned(), sub.clone());
        }
        for name in &self.0.carried {
            if let Some(value) = claims.get(&**name) {
                carried.insert(name.to_string(), value.clone());
            }
        }
        let internal = || Refusal::new(Reason::Internal, "cannot seal the session");
        let (value, dropped) = Session::new(self.0.policy, now, ends, carried)
            .seal(&keys.session, host)
            .ok_or_else(internal)?;
        if dropped {
            self.0
                .runtime
                .stats
                .claims_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(set_cookie(
            &self.0.cookie_name,
            &value,
            "/",
            ends.saturating_sub(now).max(1),
            self.0.same_site,
        ))
    }

    /// The logout path: clears the session cookie and goes to `/`. The provider is not told.
    async fn logout(&self, cx: &mut RequestCx<'_>) -> pingora::Result<Flow> {
        let status = if cx.session.req_header().method == Method::GET {
            302
        } else {
            303
        };
        let clear = set_cookie(&self.0.cookie_name, "", "/", 0, self.0.same_site);
        Self::send(cx, status, "/", &[clear]).await
    }
}

/// Writes a redirect with no body.
async fn write_redirect(
    session: &mut Downstream,
    status: u16,
    location: &str,
    cookies: &[String],
) -> pingora::Result<()> {
    let mut head = ResponseHeader::build(status, Some(4 + cookies.len()))?;
    head.insert_header("location", location)?;
    for cookie in cookies {
        head.append_header("set-cookie", cookie.as_str())?;
    }
    head.insert_header("cache-control", "no-store")?;
    head.insert_header("content-length", "0")?;
    session.write_response_header(Box::new(head), true).await
}

impl Kind for Oidc {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let ok_text = |text: &str| {
            plain(text, |b| b.is_ascii_graphic() || b == b' ') && !redirect::has_control(text)
        };
        if config.issuer.is_empty() || config.client_id.is_empty() || !ok_text(&config.client_id) {
            return Err(invalid(
                "`issuer` and `client_id` are required and printable",
            ));
        }
        let discovery = document_url(&config.issuer).map_err(invalid)?;
        let transport = transport_of(cx.app, config.transport.as_deref(), discovery.server.tls)?;
        if config.client_secret.as_ref().is_some_and(|secret| {
            secret.0.is_empty() || secret.0.len() > 4 * MAX_NAME || redirect::has_control(&secret.0)
        }) {
            return Err(invalid(
                "`client_secret` is not empty and has no control character",
            ));
        }
        let scopes = config.scopes.unwrap_or_else(|| vec!["openid".to_owned()]);
        let scope_ok =
            |scope: &str| plain(scope, |b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
        if scopes.len() > MAX_ENTRIES
            || !scopes.iter().all(|scope| scope_ok(scope))
            || !scopes.iter().any(|scope| scope == "openid")
        {
            return Err(invalid(format!(
                "`scopes` lists at most {MAX_ENTRIES} scopes without spaces and includes `openid`"
            )));
        }
        let redirect_path = own_path(
            config
                .redirect_path
                .as_deref()
                .unwrap_or(DEFAULT_REDIRECT_PATH),
            "redirect_path",
        )?;
        let logout_path = config
            .logout_path
            .as_deref()
            .map(|path| own_path(path, "logout_path"))
            .transpose()?;
        if logout_path.as_deref() == Some(&*redirect_path) {
            return Err(invalid("`logout_path` and `redirect_path` are one path"));
        }
        let algorithms = Algorithms::compile(
            &config
                .allowed_algorithms
                .unwrap_or_else(|| vec!["RS256".to_owned()]),
        )
        .map_err(|why| invalid(format!("`allowed_algorithms`: {why}")))?;
        if algorithms.iter().any(Algorithm::is_hmac) {
            return Err(invalid(
                "`allowed_algorithms`: HS256, HS384 and HS512 are keyed with a shared secret, which a provider's JWKS never holds",
            ));
        }
        let session = config.session.unwrap_or_default();
        let max_age_secs = session.max_age_secs.unwrap_or(DEFAULT_MAX_AGE_SECS);
        if !(1..=MAX_MAX_AGE_SECS).contains(&max_age_secs) {
            return Err(invalid(format!(
                "`session.max_age_secs` is in 1..={MAX_MAX_AGE_SECS} (7 days)"
            )));
        }
        let cookie_name = session
            .cookie_name
            .unwrap_or_else(|| DEFAULT_COOKIE.to_owned());
        if !plain(&cookie_name, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
        }) || cookie_name == FLOW_COOKIE
        {
            return Err(invalid(
                "`session.cookie_name` is a plain name of letters, digits and `-_.`",
            ));
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
            {
                return Err(invalid(format!(
                    "`forward_claims`: {header:?} cannot carry a claim: it frames the message, belongs to the connection, holds credentials or is written by podgate"
                )));
            }
            if forward.iter().any(|(_, taken)| *taken == name) {
                return Err(invalid(format!(
                    "`forward_claims` writes header {name} from two claims"
                )));
            }
            forward.push((claim.into_boxed_str(), name));
        }
        let required = requirements(config.required_claims).map_err(invalid)?;
        let allow_subjects = match config.allow_subjects {
            None => None,
            Some(list)
                if list.is_empty()
                    || list.len() > MAX_SUBJECTS
                    || list
                        .iter()
                        .any(|sub| sub.is_empty() || sub.len() > MAX_NAME) =>
            {
                return Err(invalid(format!(
                    "`allow_subjects` lists 1 to {MAX_SUBJECTS} subjects of at most {MAX_NAME} bytes; leave it out to admit everyone the provider signs in"
                )));
            }
            Some(list) => Some(
                list.into_iter()
                    .map(String::into_boxed_str)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
        };
        let mut carried: Vec<Box<str>> = Vec::new();
        for name in forward
            .iter()
            .map(|(claim, _)| claim)
            .chain(required.iter().map(|(claim, _)| claim))
        {
            if &**name != "sub" && !carried.contains(name) {
                carried.push(name.clone());
            }
        }
        let policy = digest(
            &SHA256,
            Value::Object(declared.config.clone())
                .to_string()
                .as_bytes(),
        );
        let policy = policy
            .as_ref()
            .get(..8)
            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
            .map_or(0, u64::from_be_bytes);
        let issuer: Box<str> = config.issuer.into();
        Ok(Self(Box::new(Parts {
            rules: Rules {
                issuer: Some(issuer.clone()),
                audiences: Box::new([config.client_id.as_str().into()]),
                required: required.into_boxed_slice(),
                leeway_secs: LEEWAY_SECS,
                max_token_age_secs: None,
            },
            issuer,
            discovery: Arc::new(discovery),
            client_id: config.client_id.into(),
            client_secret: config.client_secret,
            scope: scopes.join(" ").into(),
            redirect_path,
            logout_path,
            algorithms,
            allow_subjects,
            max_age_secs,
            cookie_name: cookie_name.into(),
            same_site: session.same_site.unwrap_or(SameSite::Lax),
            forward: forward.into_boxed_slice(),
            carried: carried.into_boxed_slice(),
            transport,
            transport_name: config.transport.map(Into::into),
            app: cx.app.id.as_ref().into(),
            name: declared.name.clone(),
            resolver: Resolver::default(),
            keys: None,
            policy,
            runtime: Arc::new(Runtime {
                discovery: Cache::new(REFRESH_SECS),
                keys: Mutex::new(None),
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
        let origin = match Origin::of(cx.session, cx.forwarded) {
            Ok(origin) => origin,
            Err(refused) => {
                let error = AppError::BadRequest(refused.to_string().into());
                *cx.reason = Some(error.log_reason());
                crate::respond::write_error(cx.session, &error).await?;
                return Ok(Flow::Respond);
            }
        };
        // The cookies are always Secure: over plain http a browser drops them and the login
        // loops. Only a TLS connection, or a trusted proxy that says it terminated TLS, serves it.
        if origin.scheme() != "https" {
            let error = AppError::BadRequest("oidc requires https".into());
            *cx.reason = Some("oidc_requires_https");
            crate::respond::write_error(cx.session, &error).await?;
            return Ok(Flow::Respond);
        }
        let now = unix_secs();
        match self.place(cx.session.req_header().uri.path()) {
            Place::Callback => self.callback(cx, &origin, now).await,
            Place::Logout => self.logout(cx).await,
            Place::Elsewhere => self.protect(cx, &origin, state, now).await,
        }
    }

    /// Dropping the middleware lets everyone in; a longer session, fewer required claims, a
    /// removed subject list, another algorithm or another provider trusts more than before.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let (old, now) = (&*self.0, &*new.0);
        let mut kinds = Vec::new();
        if now.max_age_secs > old.max_age_secs {
            kinds.push(kind::SESSION_LONGER);
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
        let subjects_loosened = old.allow_subjects.as_ref().is_some_and(|old| {
            now.allow_subjects
                .as_ref()
                .is_none_or(|now| now.iter().any(|sub| !old.contains(sub)))
        });
        if subjects_loosened {
            kinds.push(kind::SUBJECTS_LOOSENED);
        }
        if now.algorithms.iter().any(|a| !old.algorithms.contains(a)) {
            kinds.push(kind::ALGORITHM_ADDED);
        }
        if now.issuer != old.issuer || now.client_id != old.client_id {
            kinds.push(kind::PROVIDER_CHANGED);
        }
        if now.discovery.server.tls
            && now.transport.insecure_skip_verify()
            && !(old.discovery.server.tls && old.transport.insecure_skip_verify())
        {
            kinds.push(plan::kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
        }
        kinds
    }

    /// The issuer this stage requires; its keys come from that issuer's discovery document. A
    /// private `transport` (its CA and server name are part of where the keys come from) cannot
    /// be pinned.
    fn login(&self) -> Option<Login> {
        Some(if self.0.transport_name.is_some() {
            Login::Unpinnable
        } else {
            Login::Pinnable {
                issuer: self.0.issuer.clone(),
                source: Source::Discovery,
                audience: self.0.client_id.clone(),
            }
        })
    }

    /// The headers a claim is copied into: a mirror does not get them unless it is meant to carry
    /// credentials.
    fn carries_identity(&self, name: &HeaderName) -> bool {
        self.0.forward.iter().any(|(_, header)| header == name)
    }

    /// What the stage checks; never the client secret, which only shows as how the client
    /// authenticates.
    fn describe(&self) -> Value {
        let parts = &*self.0;
        json!({
            "issuer": parts.issuer,
            "client_id": parts.client_id,
            "client_authentication": if parts.client_secret.is_some() { "client_secret_basic" } else { "none" },
            "scopes": parts.scope.split(' ').collect::<Vec<_>>(),
            "redirect_path": parts.redirect_path,
            "logout_path": parts.logout_path,
            "allowed_algorithms": parts.algorithms.iter().map(Algorithm::name).collect::<Vec<_>>(),
            "session": {
                "max_age_secs": parts.max_age_secs,
                "cookie_name": parts.cookie_name,
                "same_site": parts.same_site.as_str(),
            },
            "forward_claims": parts.forward.iter()
                .map(|(claim, header)| (claim.to_string(), json!(header.as_str())))
                .collect::<Map<String, Value>>(),
            "required_claims": parts.rules.required.iter()
                .map(|(name, want)| (name.to_string(), json!(want)))
                .collect::<Map<String, Value>>(),
            "transport": parts.transport_name,
            "allow_subjects": parts.allow_subjects,
        })
    }
}

/// Checks the `oidc` stages of every app of `snapshot` against what only the snapshot, the
/// tenant's budget and the operator's policy know. `stages` holds the compiled middlewares of
/// each app, in order.
///
/// - A call to the provider that can never fit the tenant's `max_buffer_bytes` is refused
///   (`invalid_middleware`), as a JWKS fetch is.
/// - An issuer whose address is an IP literal the upstream address policy refuses for the tenant
///   is `upstream_forbidden`; the policy is checked again on every call, and for a host name on
///   every answer.
/// - A tenant uses at most [`MAX_ISSUERS_PER_TENANT`] distinct issuers.
pub(crate) fn check_snapshot(
    snapshot: &Snapshot,
    stages: &[&[super::Named]],
    policy: &UpstreamPolicy,
) -> Vec<Rejected> {
    let budgets: std::collections::HashMap<&str, u64> = snapshot
        .tenants
        .iter()
        .map(|tenant| (&*tenant.id, tenant.budget.max_buffer_bytes))
        .collect();
    let mut issuers: std::collections::HashMap<&str, std::collections::HashSet<&str>> =
        std::collections::HashMap::new();
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        for named in *stages {
            let Stage::Oidc(auth) = &named.stage else {
                continue;
            };
            let at = format!("middleware {}", named.name);
            if let Some(&budget) = budgets.get(&*app.tenant)
                && budget < CHARGE
            {
                rejected.push(Rejected::new(
                    app,
                    at.clone(),
                    invalid(format!(
                        "tenant {} has max_buffer_bytes {budget}, below the {CHARGE} bytes one call to the provider reserves; raise the budget",
                        app.tenant
                    ))
                    .with("tenant", &*app.tenant)
                    .with("needed_bytes", CHARGE)
                    .with("max_buffer_bytes", budget),
                ));
            }
            let server = &auth.0.discovery.server;
            if server.host().is_none()
                && let Err(refused) = policy.evaluate(&app.tenant, server.addr.ip())
            {
                rejected.push(Rejected::new(
                    app,
                    at.clone(),
                    Invalid::new(
                        "upstream_forbidden",
                        format!(
                            "oidc issuer {}: {refused} (rule: {})",
                            auth.0.issuer,
                            refused.rule()
                        ),
                    )
                    .with("rule", refused.rule()),
                ));
            }
            let used = issuers.entry(&app.tenant).or_default();
            if used.insert(&auth.0.issuer) && used.len() > MAX_ISSUERS_PER_TENANT {
                rejected.push(Rejected::new(
                    app,
                    at,
                    invalid(format!(
                        "tenant {} uses more than {MAX_ISSUERS_PER_TENANT} distinct issuers",
                        app.tenant
                    ))
                    .with("tenant", &*app.tenant),
                ));
            }
        }
    }
    rejected
}

/// The cached provider documents, keys and counters of every `oidc` middleware of the live
/// table, kept by the shared [`state::Registry`] and settled at the swap site
/// ([`crate::table::TableHandle`]). A push that leaves a middleware's declaration as it was
/// keeps what it fetched.
#[derive(Debug, Default)]
pub(crate) struct Registry(state::Registry<Runtime>);

impl Registry {
    /// See [`state::Registry::settle`].
    pub(crate) fn settle(&self, apps: &mut [CompiledApp]) {
        self.0.settle(apps, |stage| match stage {
            Stage::Oidc(auth) => Some((auth.0.fingerprint, &mut auth.0.runtime)),
            _ => None,
        });
    }
}

/// The Prometheus exposition of every `oidc` stage of `live`: `podgate_oidc_logins_total` (by
/// `result`: `started`, `completed`), `podgate_oidc_sessions_total`,
/// `podgate_oidc_refused_total` (by `reason`, only the reasons seen),
/// `podgate_oidc_claims_dropped_total` and `podgate_oidc_fetches_total` (by `what`, `result`).
pub(crate) fn render(live: &RoutingTable) -> String {
    let stages: Vec<(&str, &str, &Runtime)> = live
        .apps()
        .iter()
        .flat_map(|app| {
            app.stages()
                .iter()
                .filter_map(move |named| match &named.stage {
                    Stage::Oidc(auth) => Some((app.id(), &*named.name, &*auth.0.runtime)),
                    _ => None,
                })
        })
        .collect();
    let mut out = String::new();
    if stages.is_empty() {
        return out;
    }
    let family = |out: &mut String, name: &str, help: &str| {
        // Writing to a `String` cannot fail.
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
    };
    let line =
        |out: &mut String, name: &str, app: &str, middleware: &str, extra: &str, count: u64| {
            let _ = writeln!(
                out,
                "{name}{{app=\"{}\",middleware=\"{}\"{extra}}} {count}",
                Escaped(app),
                Escaped(middleware)
            );
        };
    family(
        &mut out,
        "podgate_oidc_logins_total",
        "Logins of an oidc middleware, by result: started (sent to the provider), completed (session issued).",
    );
    for (app, name, runtime) in &stages {
        for (result, count) in [
            ("started", runtime.stats.started.load(Ordering::Relaxed)),
            ("completed", runtime.stats.completed.load(Ordering::Relaxed)),
        ] {
            line(
                &mut out,
                "podgate_oidc_logins_total",
                app,
                name,
                &format!(",result=\"{result}\""),
                count,
            );
        }
    }
    family(
        &mut out,
        "podgate_oidc_sessions_total",
        "Requests an oidc middleware let through on a valid session cookie.",
    );
    for (app, name, runtime) in &stages {
        line(
            &mut out,
            "podgate_oidc_sessions_total",
            app,
            name,
            "",
            runtime.stats.sessions.load(Ordering::Relaxed),
        );
    }
    family(
        &mut out,
        "podgate_oidc_refused_total",
        "Requests an oidc middleware refused, by reason.",
    );
    for (app, name, runtime) in &stages {
        for reason in Reason::ALL {
            let count = runtime.stats.refused[reason.index()].load(Ordering::Relaxed);
            if count > 0 {
                line(
                    &mut out,
                    "podgate_oidc_refused_total",
                    app,
                    name,
                    &format!(",reason=\"{}\"", reason.label()),
                    count,
                );
            }
        }
    }
    family(
        &mut out,
        "podgate_oidc_claims_dropped_total",
        "Sessions issued with only their subject because the claims did not fit the cookie.",
    );
    for (app, name, runtime) in &stages {
        line(
            &mut out,
            "podgate_oidc_claims_dropped_total",
            app,
            name,
            "",
            runtime.stats.claims_dropped.load(Ordering::Relaxed),
        );
    }
    family(
        &mut out,
        "podgate_oidc_fetches_total",
        "Fetches of the provider's discovery document and keys, by what and result.",
    );
    for (app, name, runtime) in &stages {
        for (what, result, count) in [
            (
                "discovery",
                "ok",
                runtime.stats.discovered.load(Ordering::Relaxed),
            ),
            (
                "discovery",
                "error",
                runtime.stats.discovery_failed.load(Ordering::Relaxed),
            ),
            (
                "jwks",
                "ok",
                runtime.stats.jwks_fetched.load(Ordering::Relaxed),
            ),
            (
                "jwks",
                "error",
                runtime.stats.jwks_failed.load(Ordering::Relaxed),
            ),
        ] {
            if count > 0 {
                line(
                    &mut out,
                    "podgate_oidc_fetches_total",
                    app,
                    name,
                    &format!(",what=\"{what}\",result=\"{result}\""),
                    count,
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod test {
    use serde_json::json;

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

    fn declared(config: &Value) -> Declared {
        let mut declared = json!({"name": "login", "type": "oidc"});
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        serde_json::from_value(declared).expect("declared")
    }

    fn compile(config: &Value) -> Result<Oidc, Invalid> {
        let app = app();
        let mut compiler = engine::Compiler::default();
        Oidc::compile(
            &declared(config),
            &mut CompileCx {
                app: &app,
                engine: &mut compiler,
                portal: None,
            },
        )
    }

    fn base() -> Value {
        json!({"issuer": "https://idp.test", "client_id": "app"})
    }

    fn with(extra: &Value) -> Value {
        let mut config = base();
        config
            .as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        config
    }

    fn code(config: &Value) -> &'static str {
        compile(config).expect_err("refused").code
    }

    #[test]
    fn defaults_follow_the_documentation() {
        let auth = compile(&base()).expect("compiled");
        assert_eq!(&*auth.0.scope, "openid");
        assert_eq!(&*auth.0.redirect_path, DEFAULT_REDIRECT_PATH);
        assert_eq!(&*auth.0.cookie_name, "__Host-podgate_oidc");
        assert_eq!(auth.0.max_age_secs, 8 * 3600);
        assert_eq!(auth.0.same_site, SameSite::Lax);
        assert!(auth.0.client_secret.is_none());
        assert_eq!(auth.describe()["allowed_algorithms"], json!(["RS256"]));
        assert_eq!(auth.describe()["client_authentication"], "none");
    }

    #[test]
    fn invalid_settings_are_refused() {
        for bad in [
            json!({"issuer": "", "client_id": "app"}),
            json!({"issuer": "idp.test", "client_id": "app"}),
            json!({"issuer": "https://idp.test/?x=1", "client_id": "app"}),
            json!({"issuer": "https://u:p@idp.test", "client_id": "app"}),
            json!({"issuer": "https://idp.test", "client_id": ""}),
            with(&json!({"unknown": 1})),
            with(&json!({"client_secret": ""})),
            with(&json!({"scopes": ["email"]})),
            with(&json!({"scopes": ["openid", "a b"]})),
            with(&json!({"redirect_path": "cb"})),
            with(&json!({"redirect_path": "//evil.test/cb"})),
            with(&json!({"redirect_path": "/cb?x=1"})),
            with(&json!({"logout_path": "/_podgate/oidc/callback"})),
            with(&json!({"allowed_algorithms": ["none"]})),
            with(&json!({"allowed_algorithms": ["HS256"]})),
            with(&json!({"allowed_algorithms": []})),
            with(&json!({"session": {"max_age_secs": 0}})),
            with(&json!({"session": {"max_age_secs": 7 * 24 * 3600 + 1}})),
            with(&json!({"session": {"cookie_name": "a b"}})),
            with(&json!({"session": {"cookie_name": FLOW_COOKIE}})),
            with(&json!({"session": {"same_site": "Sideways"}})),
            with(&json!({"forward_claims": {"sub": "Authorization"}})),
            with(&json!({"forward_claims": {"sub": "Cookie"}})),
            with(&json!({"forward_claims": {"sub": "X-A", "email": "x-a"}})),
            with(&json!({"required_claims": {"role": []}})),
            with(&json!({"allow_subjects": []})),
            with(&json!({"transport": "nope"})),
        ] {
            assert!(compile(&bad).is_err(), "{bad}");
        }
        assert_eq!(
            code(&with(&json!({"transport": "nope"}))),
            "unknown_transport"
        );
        assert_eq!(code(&with(&json!({"unknown": 1}))), "invalid_middleware");
        // The transport sets TLS options and the issuer is plain http.
        assert_eq!(
            code(&json!({"issuer": "http://10.0.0.5", "client_id": "app", "transport": "t"})),
            "invalid_middleware"
        );
    }

    #[test]
    fn a_host_name_is_a_valid_issuer() {
        assert!(
            compile(&json!({"issuer": "https://idp.example/realms/a", "client_id": "app"})).is_ok()
        );
        assert!(compile(&json!({"issuer": "http://10.0.0.5:8080", "client_id": "app"})).is_ok());
        assert!(compile(&json!({"issuer": "https://[2001:db8::5]", "client_id": "app"})).is_ok());
    }

    #[test]
    fn the_session_carries_the_claims_the_configuration_names() {
        let auth = compile(&with(&json!({
            "forward_claims": {"email": "X-Email", "sub": "X-User"},
            "required_claims": {"role": ["admin"], "email": "a@x"},
        })))
        .expect("compiled");
        let mut carried: Vec<&str> = auth.0.carried.iter().map(|name| &**name).collect();
        carried.sort_unstable();
        assert_eq!(
            carried,
            ["email", "role"],
            "sub is always carried and never listed"
        );
        assert!(auth.carries_identity(&HeaderName::from_static("x-email")));
        assert!(auth.carries_identity(&HeaderName::from_static("x-user")));
        assert!(!auth.carries_identity(&HeaderName::from_static("x-other")));
    }

    #[test]
    fn oidc_client_secret_redacted() {
        let secret = "PLANT-client-secret-7f3a9c";
        let auth = compile(&with(&json!({"client_secret": secret}))).expect("compiled");
        assert!(!format!("{auth:?}").contains(secret), "{auth:?}");
        assert!(!auth.describe().to_string().contains(secret));
        assert_eq!(
            auth.describe()["client_authentication"],
            "client_secret_basic"
        );
        let config: Config =
            serde_json::from_value(with(&json!({"client_secret": secret}))).expect("config");
        assert!(!format!("{config:?}").contains(secret), "{config:?}");
    }

    #[test]
    fn oidc_requires_skew_secret() {
        let mut auth = compile(&base()).expect("compiled");
        let refused = auth
            .bind(None, &Resolver::default())
            .expect_err("no secret");
        assert_eq!(refused.code, "invalid_middleware");
        assert!(auth.0.keys.is_none());
        auth.bind(
            Some(&SkewSecret::new("0123456789abcdef")),
            &Resolver::default(),
        )
        .expect("bound");
        assert!(auth.0.keys.is_some());
    }

    #[test]
    fn a_request_that_cannot_follow_a_redirect_is_not_sent_to_the_provider() {
        let request = |method: Method, headers: &[(&str, &str)]| {
            let mut request = RequestHeader::build(method, b"/", None).expect("request");
            for (name, value) in headers {
                request
                    .append_header(name.to_string(), *value)
                    .expect("header");
            }
            request
        };
        let html = [("accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")];
        assert!(can_redirect(&request(Method::GET, &html)));
        assert!(can_redirect(&request(
            Method::GET,
            &[("accept", "Text/HTML; q=1")]
        )));
        assert!(!can_redirect(&request(Method::POST, &html)));
        assert!(!can_redirect(&request(Method::GET, &[])));
        assert!(!can_redirect(&request(
            Method::GET,
            &[("accept", "application/json")]
        )));
        assert!(!can_redirect(&request(Method::GET, &[("accept", "*/*")])));
        assert!(!can_redirect(&request(
            Method::GET,
            &[
                ("accept", "text/html"),
                ("x-requested-with", "XMLHttpRequest")
            ]
        )));
    }

    #[test]
    fn cookies_are_found_by_exact_name() {
        let mut request = RequestHeader::build(Method::GET, b"/", None).expect("request");
        request
            .append_header("cookie", "a=1; __Host-podgate_oidc=v1; xa=2")
            .expect("header");
        request
            .append_header("cookie", "__Host-podgate_oidc=v2")
            .expect("header");
        assert_eq!(
            cookie_values(&request, "__Host-podgate_oidc").collect::<Vec<_>>(),
            ["v1", "v2"]
        );
        assert_eq!(cookie_values(&request, "a").collect::<Vec<_>>(), ["1"]);
        assert_eq!(cookie_values(&request, "podgate_oidc").count(), 0);
    }

    #[test]
    fn cookies_are_secure_and_http_only() {
        assert_eq!(
            set_cookie("n", "v", "/cb", 300, SameSite::Lax),
            "n=v; Path=/cb; Max-Age=300; HttpOnly; Secure; SameSite=Lax"
        );
        assert_eq!(
            set_cookie("n", "", "/", 0, SameSite::None),
            "n=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None"
        );
    }

    #[test]
    fn posture_lists_what_trusts_more() {
        let posture = |old: &Value, new: &Value| {
            let (old, new) = (compile(old).expect("old"), compile(new).expect("new"));
            old.posture(Some(&new))
        };
        assert_eq!(
            compile(&base()).expect("compiled").posture(None),
            [kind::REMOVED]
        );
        let strict = with(&json!({
            "session": {"max_age_secs": 600}, "required_claims": {"role": ["admin"]},
            "allow_subjects": ["ann"],
        }));
        assert_eq!(posture(&strict, &strict), Vec::<&str>::new());
        assert_eq!(
            posture(
                &strict,
                &with(
                    &json!({"required_claims": {"role": ["admin"]}, "allow_subjects": ["ann"], "session": {"max_age_secs": 601}})
                )
            ),
            [kind::SESSION_LONGER]
        );
        assert_eq!(
            posture(
                &strict,
                &with(&json!({"session": {"max_age_secs": 600}, "allow_subjects": ["ann"]}))
            ),
            [kind::REQUIRED_CLAIMS_LOOSENED]
        );
        assert_eq!(
            posture(
                &strict,
                &with(
                    &json!({"session": {"max_age_secs": 600}, "required_claims": {"role": ["admin", "ops"]}, "allow_subjects": ["ann"]})
                )
            ),
            [kind::REQUIRED_CLAIMS_LOOSENED]
        );
        let no_subjects = with(
            &json!({"session": {"max_age_secs": 600}, "required_claims": {"role": ["admin"]}}),
        );
        assert_eq!(posture(&strict, &no_subjects), [kind::SUBJECTS_LOOSENED]);
        let more = with(
            &json!({"session": {"max_age_secs": 600}, "required_claims": {"role": ["admin"]}, "allow_subjects": ["ann", "bob"]}),
        );
        assert_eq!(posture(&strict, &more), [kind::SUBJECTS_LOOSENED]);
        // Tighter is not a relaxation.
        assert!(posture(&no_subjects, &strict).is_empty());
        assert_eq!(
            posture(
                &base(),
                &with(&json!({"allowed_algorithms": ["RS256", "ES256"]}))
            ),
            [kind::ALGORITHM_ADDED]
        );
        assert_eq!(
            posture(
                &base(),
                &json!({"issuer": "https://other.test", "client_id": "app"})
            ),
            [kind::PROVIDER_CHANGED]
        );
    }

    #[test]
    fn explain_shows_the_setting_and_never_the_secret() {
        let auth = compile(&with(&json!({
            "client_secret": "s3cret-value", "scopes": ["openid", "email"],
            "logout_path": "/logout", "forward_claims": {"email": "X-Email"},
            "allow_subjects": ["ann"],
        })))
        .expect("compiled");
        let shown = auth.describe();
        assert_eq!(shown["scopes"], json!(["openid", "email"]));
        assert_eq!(shown["logout_path"], "/logout");
        assert_eq!(shown["forward_claims"], json!({"email": "x-email"}));
        assert_eq!(shown["allow_subjects"], json!(["ann"]));
        assert!(!shown.to_string().contains("s3cret"));
    }
}
