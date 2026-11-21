//! The `cache` middleware: an in-memory response cache. Full reference: `docs/ref/mw-cache.md`.
//!
//! ```json
//! { "name": "c", "type": "cache",
//!   "max_bytes": 1048576, "max_object_bytes": 262144,
//!   "default_ttl_secs": 60, "tag_header": "Cache-Tag" }
//! ```
//!
//! Place it after authentication in the chain: a hit is answered from the chain's `routed` hook,
//! after every request hook before it has run and before any backend admission, so a hit costs
//! the tenant no in-flight slot and the backend no connection.
//!
//! # What is stored, and as what
//!
//! The entry is the response as the client received it on the miss that stored it. Compression
//! runs before the cache sees the body, so the entry holds the encoded bytes the client got,
//! together with the `Vary: Accept-Encoding` that compression adds: a later client that accepts
//! the same codings is served the stored bytes with no recompression, and one that accepts
//! others gets its own variant. The response hooks of the stages that follow the cache in the
//! chain have run on the entry; those of the stages before it do not run on a hit.
//!
//! # Isolation
//!
//! The tenant and the app are in every key, every entry lives in its tenant's own store, and
//! every byte is charged to the tenant's `max_buffer_bytes`; see [`crate::cache`]. A request
//! with `Authorization` or `Cookie`, or with headers a `forward_auth` stage copied in, bypasses
//! the cache, and a response with `Set-Cookie`,
//! `private` or `no-store` is never stored, unless the declaration opts in for cookies.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, COOKIE, DATE, ETAG, EXPIRES, HeaderMap,
    HeaderName, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED, PRAGMA, PROXY_AUTHORIZATION, RANGE, SET_COOKIE, TRANSFER_ENCODING, UPGRADE,
    VARY,
};
use pingora::http::{Method, RequestHeader, ResponseHeader};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Earlier, FinishCx, Flow, Kind, ResponseCx, RoutedCx};
use crate::budget::TenantBudget;
use crate::cache::fill::{Fill, Finished};
use crate::cache::key::{Parts, ResourceKey};
use crate::cache::policy::{
    self, ClientControl, Directives, Query, RequestCookies, Revisions, SetCookie, Settings, Skip,
};
use crate::cache::refresh::{self, Inherited, Refresh};
use crate::cache::store::{Entry, Lookup, Standing, TenantCache};
use crate::cache::{Claim, Lead, Limits, Outcome};
use crate::client_ip::Proto;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::route;
use crate::skew;
use podgate_model::Declared;

/// Largest object a middleware stores when it sets no `max_object_bytes`.
const DEFAULT_MAX_OBJECT_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_TTL_SECS: u64 = 86_400;
const DEFAULT_MAX_STALE_WHILE_REVALIDATE_SECS: u64 = 60;
const DEFAULT_MAX_STALE_IF_ERROR_SECS: u64 = 300;
const DEFAULT_COLLAPSE_TIMEOUT_MS: u64 = 3000;
const MAX_COLLAPSE_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_STATUSES: [u16; 7] = [200, 203, 204, 301, 308, 404, 410];

/// Headers that belong to one hop, or that this stage writes itself on every hit. `alt-svc` names
/// where this entry point speaks HTTP/3, so a copy stored through one entry point
/// must not reach clients of another; a hit gets the live entry point's own.
const NOT_STORED: [&str; 12] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "age",
    "cache-status",
    "alt-svc",
];

/// What a `304` carries over from the entry: the validators and the freshness headers.
const NOT_MODIFIED_HEADERS: [&HeaderName; 6] = [
    &ETAG,
    &LAST_MODIFIED,
    &CACHE_CONTROL,
    &EXPIRES,
    &DATE,
    &VARY,
];

/// The declaration of a `cache` middleware. Every field is optional; see `docs/ref/mw-cache.md`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Most bytes the tenant's cache may hold when this middleware stores; default a quarter of
    /// the tenant's `max_buffer_bytes`, at most the operator's `CACHE_TENANT_MAX_PERCENT`.
    #[serde(default)]
    max_bytes: Option<u64>,
    /// Largest response kept, in bytes; default 1 MiB or `max_bytes`, whichever is lower.
    #[serde(default)]
    max_object_bytes: Option<u64>,
    /// Statuses that may be stored; default `200 203 204 301 308 404 410`.
    #[serde(default)]
    statuses: Option<Vec<u16>>,
    /// Freshness for a response that names none; absent: only explicit freshness is stored.
    #[serde(default)]
    default_ttl_secs: Option<u64>,
    /// Longest an entry stays fresh, in seconds; default 86400.
    #[serde(default)]
    max_ttl_secs: Option<u64>,
    /// Longest the response's own `stale-while-revalidate` and `stale-if-error` are honoured.
    #[serde(default)]
    max_stale_secs: Option<StaleConfig>,
    /// Store a `Set-Cookie` response with the cookie removed from the stored copy; default
    /// `false`: such responses are never stored.
    #[serde(default)]
    #[schemars(with = "bool")]
    cache_set_cookie: SetCookie,
    /// Serve and store for requests that carry `Cookie`; default `false`: they bypass the cache.
    #[serde(default)]
    #[schemars(with = "bool")]
    ignore_request_cookies: RequestCookies,
    /// Obey a client's `no-cache`, `max-age=0` and `no-store`; default `false`.
    #[serde(default)]
    #[schemars(with = "bool")]
    respect_request_cache_control: ClientControl,
    /// Share entries between the revisions of the app; default `false`.
    #[serde(default)]
    #[schemars(with = "bool")]
    share_across_revisions: Revisions,
    /// Sort the query parameters before they are part of the key; default `false`.
    #[serde(default)]
    #[schemars(with = "bool")]
    normalize_query: Query,
    /// How long a request waits for the fetch another request leads, in milliseconds;
    /// default 3000, at most 10000.
    #[serde(default)]
    collapse_timeout_ms: Option<u64>,
    /// The response header that lists purge tags (for example `Cache-Tag`).
    #[serde(default)]
    tag_header: Option<String>,
}

/// `max_stale_secs`: how long a response's own `stale-while-revalidate` and `stale-if-error` are
/// honoured.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct StaleConfig {
    /// Seconds of `stale-while-revalidate`; default 60.
    #[serde(default)]
    while_revalidate: Option<u64>,
    /// Seconds of `stale-if-error`; default 300.
    #[serde(default)]
    if_error: Option<u64>,
}

/// A compiled `cache` middleware.
#[derive(Debug)]
pub struct Cache {
    settings: Settings,
    declared_max_bytes: Option<u64>,
    declared_max_object_bytes: Option<u64>,
    /// The most bytes the tenant's cache may hold when this middleware inserts; set by
    /// [`Self::bind`], which the snapshot compiler calls with the tenant's limits.
    max_bytes: u64,
    /// The largest object this middleware stores; set by [`Self::bind`].
    max_object_bytes: u64,
    ignore_request_cookies: RequestCookies,
    respect_request_cache_control: ClientControl,
    revisions: Revisions,
    query: Query,
    collapse_timeout: Duration,
    tag_header: Option<HeaderName>,
}

/// A fetch this request leads, and the entry it may store.
#[derive(Debug)]
struct Leading {
    lead: Lead,
    key: ResourceKey,
    tenant: Arc<TenantBudget>,
    store: Arc<TenantCache>,
    /// The request's headers, kept when the response head arrives: the variant is keyed on them.
    request: Option<HeaderMap>,
    /// The entry a refresh subrequest asks the origin to confirm.
    confirming: Option<Arc<Entry>>,
}

/// A response being copied into the cache.
#[derive(Debug)]
struct Copying {
    lead: Lead,
    fill: Fill,
    head: ResponseHeader,
    tags: Box<[Box<str>]>,
    done: Finished,
    declared: Option<u64>,
}

#[derive(Debug, Default)]
enum Fetch {
    /// This request neither stores nor collapses.
    #[default]
    None,
    Leading(Box<Leading>),
    Copying(Box<Copying>),
}

/// What one request keeps for this stage.
#[derive(Debug, Default)]
pub struct State {
    /// What `Cache-Status` says on the response this request gets from the upstream.
    result: Option<&'static str>,
    fetch: Fetch,
    /// The entry whose validators go to the origin: set in a refresh subrequest.
    confirming: Option<Arc<Entry>>,
    /// The statuses an `errors` stage of the chain replaces with a page: such a response is
    /// neither stored nor served from the store, so the page is never skipped.
    pages: Vec<std::ops::RangeInclusive<u16>>,
}

/// How a request that may use the cache relates to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Look up, and serve what is there.
    Normal,
    /// The client asked for a fresh copy (and the declaration obeys that): go to the upstream
    /// and replace the entry.
    Forced,
}

/// What [`Cache::revalidate`] decided for a request that found a stale entry.
enum Revalidated {
    /// Serve the entry, with this `Cache-Status` token.
    Serve(&'static str),
    /// A new entry was stored: look again.
    Again,
    /// Go to the upstream and do not store.
    Forward,
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if let Some(statuses) = &self.statuses {
            if statuses.is_empty() {
                return Err("statuses is empty".into());
            }
            if let Some(bad) = statuses
                .iter()
                .find(|status| !(200..500).contains(*status) || matches!(**status, 206 | 304))
            {
                return Err(format!(
                    "status {bad} cannot be cached: only 2xx, 3xx and 4xx responses that carry a whole body, so not 206 or 304"
                ));
            }
        }
        if self.max_ttl_secs == Some(0) {
            return Err("max_ttl_secs must be at least 1".into());
        }
        if let Some(ms) = self.collapse_timeout_ms
            && !(1..=MAX_COLLAPSE_TIMEOUT_MS).contains(&ms)
        {
            return Err(format!(
                "collapse_timeout_ms must be 1..={MAX_COLLAPSE_TIMEOUT_MS}"
            ));
        }
        Ok(())
    }
}

impl Kind for Cache {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let invalid = |why: String| Invalid::new("invalid_middleware", format!("cache: {why}"));
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        config.validate().map_err(invalid)?;
        let (max_bytes, max_object_bytes) = (config.max_bytes, config.max_object_bytes);
        if max_bytes == Some(0) || max_object_bytes == Some(0) {
            return Err(invalid(
                "max_bytes and max_object_bytes must be at least 1".into(),
            ));
        }
        let max_ttl = config.max_ttl_secs.unwrap_or(DEFAULT_MAX_TTL_SECS);
        let stale = config.max_stale_secs.unwrap_or_default();
        let tag_header = config
            .tag_header
            .as_deref()
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| invalid(format!("tag_header {name:?} is not a header name")))
            })
            .transpose()?;
        Ok(Self {
            settings: Settings {
                statuses: config
                    .statuses
                    .map_or_else(|| DEFAULT_STATUSES.into(), Vec::into_boxed_slice),
                default_ttl: config.default_ttl_secs.map(|ttl| ttl.min(max_ttl)),
                max_ttl,
                max_stale_while_revalidate: stale
                    .while_revalidate
                    .unwrap_or(DEFAULT_MAX_STALE_WHILE_REVALIDATE_SECS),
                max_stale_if_error: stale.if_error.unwrap_or(DEFAULT_MAX_STALE_IF_ERROR_SECS),
                set_cookie: config.cache_set_cookie,
            },
            declared_max_bytes: max_bytes,
            declared_max_object_bytes: max_object_bytes,
            max_bytes: 0,
            max_object_bytes: 0,
            ignore_request_cookies: config.ignore_request_cookies,
            respect_request_cache_control: config.respect_request_cache_control,
            revisions: config.share_across_revisions,
            query: config.normalize_query,
            collapse_timeout: Duration::from_millis(
                config
                    .collapse_timeout_ms
                    .unwrap_or(DEFAULT_COLLAPSE_TIMEOUT_MS),
            ),
            tag_header,
        })
    }

    async fn routed(
        &self,
        cx: &mut RoutedCx<'_>,
        earlier: &mut Earlier<'_>,
        state: &mut State,
    ) -> pingora::Result<Flow> {
        *state = State::default();
        state.pages = std::mem::take(&mut cx.pages);
        if refresh::of(cx.session).is_some() {
            self.begin_refresh(cx, state);
            return Ok(Flow::Continue);
        }
        let Some(tenant) = cx.tenant.map(Arc::clone) else {
            return Ok(Flow::Continue);
        };
        let app = cx.app.id();
        let key = self
            .mode(cx.session.req_header())
            .and_then(|mode| self.key(cx).map(|key| (mode, key)));
        let Some((mode, key)) = key.filter(|_| !cx.credentialed) else {
            cx.cache.count(app, "bypass");
            state.result = Some("bypass");
            return Ok(Flow::Continue);
        };
        let store = cx.cache.tenant(cx.app.tenant());
        // What a request that was answered from an entry another request fetched is called.
        let mut token = "hit";
        let mut waited = false;
        loop {
            let found = match mode {
                Mode::Forced => Lookup::Miss,
                Mode::Normal => store.lookup(&key, &cx.session.req_header().headers),
            };
            let entry = match found {
                Lookup::Hit(entry) if !paged(&state.pages, entry.head.status.as_u16()) => entry,
                Lookup::Unkeyable => {
                    cx.cache.count(app, "miss");
                    state.result = Some("miss");
                    return Ok(Flow::Continue);
                }
                // A stored status an `errors` stage pages (stored before it was configured, or
                // while its page server was down) is not served: the request goes the normal way
                // and the page replaces the response.
                Lookup::Hit(_) | Lookup::Miss => {
                    return self
                        .miss(cx, earlier, state, &key, store, tenant, mode, waited)
                        .await;
                }
            };
            let standing = entry.standing();
            if standing.fresh {
                cx.cache.count(app, token);
                self.serve(cx, earlier, &entry, standing, token).await?;
                return Ok(Flow::Respond);
            }
            if standing.revalidate_in_background && mode == Mode::Normal {
                cx.cache.count(app, "stale");
                self.serve(cx, earlier, &entry, standing, "stale").await?;
                Self::refresh_in_background(cx, &key, &entry);
                return Ok(Flow::Respond);
            }
            if waited || !(entry.has_validator() || standing.usable_on_error) {
                return self
                    .miss(cx, earlier, state, &key, store, tenant, mode, waited)
                    .await;
            }
            match self.revalidate(cx, &key, &entry).await {
                Revalidated::Serve(result) => {
                    cx.cache.count(app, result);
                    self.serve(cx, earlier, &entry, entry.standing(), result)
                        .await?;
                    return Ok(Flow::Respond);
                }
                Revalidated::Again => {
                    waited = true;
                    token = "miss";
                }
                Revalidated::Forward => {
                    return self
                        .miss(cx, earlier, state, &key, store, tenant, mode, true)
                        .await;
                }
            }
        }
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        state: &mut State,
    ) -> pingora::Result<()> {
        let Some(entry) = &state.confirming else {
            return Ok(());
        };
        for name in [
            &IF_NONE_MATCH,
            &IF_MODIFIED_SINCE,
            &IF_MATCH,
            &IF_UNMODIFIED_SINCE,
            &IF_RANGE,
            &RANGE,
        ] {
            request.remove_header(name);
        }
        let headers = &entry.head.headers;
        if let Some(etag) = headers.get(ETAG) {
            request.insert_header(IF_NONE_MATCH, etag)?;
        }
        if let Some(modified) = headers.get(LAST_MODIFIED) {
            request.insert_header(IF_MODIFIED_SINCE, modified)?;
        }
        Ok(())
    }

    fn response_head(&self, cx: &ResponseCx<'_>, state: &mut State) -> Result<(), AppError> {
        let status = cx.response.status.as_u16();
        let Fetch::Leading(leading) = &mut state.fetch else {
            return Ok(());
        };
        if status >= 500 {
            leading.lead.set(Outcome::Failed);
            return Ok(());
        }
        if status != 304 {
            leading.request = Some(cx.request.headers.clone());
            return Ok(());
        }
        // The origin confirmed the entry: restart its clock and tell whoever waits.
        if let Some(entry) = leading.confirming.take() {
            let headers = &cx.response.headers;
            let granted = (headers.contains_key(CACHE_CONTROL) || headers.contains_key(EXPIRES))
                .then(|| {
                    policy::lifetimes(
                        &self.settings,
                        &Directives::parse(headers),
                        headers,
                        SystemTime::now(),
                    )
                })
                .flatten();
            entry.revalidated(granted, policy::initial_age(headers));
            leading.lead.set(Outcome::Revalidated);
        }
        state.fetch = Fetch::None;
        Ok(())
    }

    fn response(&self, response: &mut ResponseHeader, state: &mut State) -> pingora::Result<()> {
        if matches!(state.fetch, Fetch::Leading(_)) {
            self.decide(response, state);
        }
        if let Some(name) = &self.tag_header {
            // The client never sees the tags: they are the operator's handle on the entry.
            response.remove_header(name);
        }
        if let Some(result) = state.result {
            response.append_header("cache-status", format!("podgate; {result}"))?;
        }
        Ok(())
    }

    fn response_body(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        state: &mut State,
    ) -> pingora::Result<()> {
        let Fetch::Copying(copying) = &mut state.fetch else {
            return Ok(());
        };
        if let Some(chunk) = body.as_ref()
            && !copying.fill.push(chunk)
        {
            state.fetch = Fetch::None;
            return Ok(());
        }
        if !end_of_stream {
            return Ok(());
        }
        let Fetch::Copying(copying) = std::mem::take(&mut state.fetch) else {
            return Ok(());
        };
        let Copying {
            mut lead,
            fill,
            head,
            tags,
            done,
            declared,
        } = *copying;
        // A response that ended short of its declared length is not a whole response.
        if declared.is_none_or(|declared| declared == fill.len()) && fill.finish(head, tags, done) {
            lead.set(Outcome::Stored);
        }
        Ok(())
    }

    fn finished(&self, cx: &FinishCx<'_>, state: &mut State) {
        let failed = cx.upstream_error || cx.status.is_some_and(|status| status >= 500);
        if !failed {
            return;
        }
        match &mut state.fetch {
            Fetch::Leading(leading) => leading.lead.set(Outcome::Failed),
            Fetch::Copying(copying) => copying.lead.set(Outcome::Failed),
            Fetch::None => {}
        }
    }

    fn describe(&self) -> Value {
        json!({
            "max_bytes": self.max_bytes,
            "max_object_bytes": self.max_object_bytes,
            "statuses": self.settings.statuses,
            "default_ttl_secs": self.settings.default_ttl,
            "max_ttl_secs": self.settings.max_ttl,
            "tag_header": self.tag_header.as_ref().map(HeaderName::as_str),
            "share_across_revisions": self.revisions == Revisions::Shared,
        })
    }
}

impl Cache {
    /// Resolves the byte limits against the tenant's budget and the operator's share of it: the
    /// snapshot compiler calls this once the stage compiled. `max_bytes` defaults to a quarter of
    /// the budget and may be at most `CACHE_TENANT_MAX_PERCENT` of it, so the cache can never
    /// starve compression buffers or WASM runs.
    ///
    /// # Errors
    ///
    /// `cache_max_bytes_over_cap` when the declared `max_bytes` is over the share,
    /// `invalid_middleware` when no bytes are left or an object cap is over `max_bytes`.
    pub fn bind(&mut self, limits: Limits) -> Result<(), Invalid> {
        let invalid = |why: String| Invalid::new("invalid_middleware", format!("cache: {why}"));
        let ceiling = limits.ceiling();
        let max_bytes = self
            .declared_max_bytes
            .unwrap_or_else(|| limits.default_bytes());
        if max_bytes == 0 {
            return Err(invalid(
                "max_bytes is 0: the tenant's max_buffer_bytes leaves the cache no room".into(),
            ));
        }
        if max_bytes > ceiling {
            return Err(Invalid::new(
                "cache_max_bytes_over_cap",
                format!(
                    "cache: max_bytes {max_bytes} is over {ceiling}, the {} percent of the tenant's max_buffer_bytes ({}) the operator lets a cache hold (CACHE_TENANT_MAX_PERCENT)",
                    limits.max_percent, limits.tenant_budget
                ),
            ));
        }
        let max_object_bytes = self
            .declared_max_object_bytes
            .unwrap_or_else(|| DEFAULT_MAX_OBJECT_BYTES.min(max_bytes));
        if max_object_bytes > max_bytes {
            return Err(invalid(format!(
                "max_object_bytes {max_object_bytes} is over max_bytes ({max_bytes})"
            )));
        }
        self.max_bytes = max_bytes;
        self.max_object_bytes = max_object_bytes;
        Ok(())
    }

    /// Whether and how a request may use the cache; `None` bypasses it.
    fn mode(&self, request: &RequestHeader) -> Option<Mode> {
        if !matches!(request.method, Method::GET | Method::HEAD) {
            return None;
        }
        let headers = &request.headers;
        let refused = [
            &AUTHORIZATION,
            &PROXY_AUTHORIZATION,
            &RANGE,
            &UPGRADE,
            &TRANSFER_ENCODING,
            &IF_MATCH,
            &IF_UNMODIFIED_SINCE,
            &IF_RANGE,
        ];
        if refused.iter().any(|name| headers.contains_key(*name)) {
            return None;
        }
        if headers
            .get(CONTENT_LENGTH)
            .is_some_and(|length| length != "0")
        {
            return None;
        }
        if headers.contains_key(COOKIE) && self.ignore_request_cookies == RequestCookies::Bypass {
            return None;
        }
        if self.respect_request_cache_control == ClientControl::Respect {
            let wants = Directives::parse(headers);
            if wants.no_store() {
                return None;
            }
            let pragma = headers
                .get(PRAGMA)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("no-cache"));
            if wants.no_cache() || wants.max_age == Some(0) || pragma {
                return Some(Mode::Forced);
            }
        }
        Some(Mode::Normal)
    }

    fn key(&self, cx: &RoutedCx<'_>) -> Option<ResourceKey> {
        let request = cx.session.req_header();
        let host = route::request_host(request)?;
        let router = cx.app.routers().get(cx.selected.router)?.name();
        let revision = match self.revisions {
            Revisions::Separate => Some(cx.app.revisions().get(cx.selected.revision)?.id()),
            Revisions::Shared => None,
        };
        Some(ResourceKey::new(&Parts {
            tenant: cx.app.tenant(),
            app: cx.app.id(),
            router,
            revision,
            tls: cx.forwarded.proto == Proto::Https,
            host: &host,
            path: request.uri.path(),
            query: request.uri.query(),
            query_order: self.query,
        }))
    }

    /// The request found nothing it can serve: it goes to the upstream, leading the fetch (and
    /// storing the response) when nobody else is, and waiting for the leader when somebody is.
    /// `waited` means a fetch for this key already ended without an entry for this request, so
    /// it goes alone.
    #[allow(
        clippy::too_many_arguments,
        reason = "the one call site passes the request's context as it has it"
    )]
    async fn miss(
        &self,
        cx: &mut RoutedCx<'_>,
        earlier: &mut Earlier<'_>,
        state: &mut State,
        key: &ResourceKey,
        store: Arc<TenantCache>,
        tenant: Arc<TenantBudget>,
        mode: Mode,
        waited: bool,
    ) -> pingora::Result<Flow> {
        let app = cx.app.id();
        let request = cx.session.req_header();
        let lone = request.method == Method::HEAD
            || request.headers.contains_key(IF_NONE_MATCH)
            || request.headers.contains_key(IF_MODIFIED_SINCE)
            || waited;
        state.result = Some("miss");
        // A `HEAD` has no body to keep, and a conditional request would be answered `304`, which
        // is not an entry: neither leads a fetch.
        if lone {
            cx.cache.count(app, "miss");
            return Ok(Flow::Continue);
        }
        match cx.cache.claim(key) {
            Claim::Lead(lead) => {
                cx.cache.count(app, "miss");
                state.fetch = Fetch::Leading(Box::new(Leading {
                    lead,
                    key: key.clone(),
                    tenant,
                    store,
                    request: None,
                    confirming: None,
                }));
            }
            Claim::Follow(waiter) if mode == Mode::Normal => {
                let outcome = waiter.wait(self.collapse_timeout).await;
                if matches!(outcome, Some(Outcome::Stored | Outcome::Revalidated))
                    && let Lookup::Hit(entry) = store.lookup(key, &cx.session.req_header().headers)
                {
                    cx.cache.count(app, "hit");
                    self.serve(cx, earlier, &entry, entry.standing(), "hit")
                        .await?;
                    return Ok(Flow::Respond);
                }
                cx.cache.count(app, "miss");
            }
            Claim::Follow(_) | Claim::Crowded => cx.cache.count(app, "miss"),
        }
        Ok(Flow::Continue)
    }

    /// A stale entry that can be checked, or used if the upstream is down: ask the origin through
    /// a subrequest (see [`crate::cache::refresh`]) and wait for it, or wait for the subrequest
    /// another request already started.
    async fn revalidate(
        &self,
        cx: &mut RoutedCx<'_>,
        key: &ResourceKey,
        entry: &Arc<Entry>,
    ) -> Revalidated {
        let waiter = match cx.cache.claim(key) {
            Claim::Lead(lead) => {
                let waiter = lead.watch();
                if !Self::start_refresh(cx, key, entry, lead) {
                    return Revalidated::Forward;
                }
                waiter
            }
            Claim::Follow(waiter) => waiter,
            Claim::Crowded => return Revalidated::Forward,
        };
        match waiter.wait(self.collapse_timeout).await {
            Some(Outcome::Stored) => Revalidated::Again,
            Some(Outcome::Revalidated) => Revalidated::Serve("revalidated"),
            Some(Outcome::Failed) if entry.standing().usable_on_error => {
                Revalidated::Serve("stale")
            }
            Some(Outcome::Failed | Outcome::NotStored) | None => Revalidated::Forward,
        }
    }

    /// Starts a refresh subrequest that holds `lead`. `false` when none could be started; `lead`
    /// is released then.
    fn start_refresh(
        cx: &mut RoutedCx<'_>,
        _key: &ResourceKey,
        entry: &Arc<Entry>,
        lead: Lead,
    ) -> bool {
        let inherited = Inherited {
            forwarded: cx.forwarded.clone(),
            tls: cx.tls,
            entry_point: Arc::clone(cx.entry_point),
        };
        let refresh = Refresh {
            lead: Some(lead),
            entry: Arc::clone(entry),
            inherited,
        };
        let original = cx
            .original
            .clone()
            .unwrap_or_else(|| cx.session.req_header().clone());
        refresh::spawn(cx.session, &original, refresh)
    }

    /// Refreshes a stale entry that was just served, unless a refresh is already running.
    fn refresh_in_background(cx: &mut RoutedCx<'_>, key: &ResourceKey, entry: &Arc<Entry>) {
        if cx.cache.fetching(key) {
            return;
        }
        if let Claim::Lead(lead) = cx.cache.claim(key) {
            Self::start_refresh(cx, key, entry, lead);
        }
    }

    /// The refresh subrequest takes the fetch the request that spawned it holds.
    fn begin_refresh(&self, cx: &mut RoutedCx<'_>, state: &mut State) {
        let Some(tenant) = cx.tenant.map(Arc::clone) else {
            return;
        };
        let Some(key) = self.key(cx) else {
            return;
        };
        let store = cx.cache.tenant(cx.app.tenant());
        let Some(refresh) = refresh::of_mut(cx.session) else {
            return;
        };
        let Some(lead) = refresh.lead.take() else {
            return;
        };
        // The weighted pick may have chosen another revision than the one that holds the entry;
        // then this fetch is not the one the lead was claimed for.
        if lead.key() != &key {
            return;
        }
        let entry = Arc::clone(&refresh.entry);
        state.confirming = Some(Arc::clone(&entry));
        state.fetch = Fetch::Leading(Box::new(Leading {
            lead,
            key,
            tenant,
            store,
            request: None,
            confirming: Some(entry),
        }));
    }

    /// Decides, on the head the client is about to get, whether the response is stored, and
    /// starts copying it.
    fn decide(&self, head: &ResponseHeader, state: &mut State) {
        let Fetch::Leading(leading) = std::mem::take(&mut state.fetch) else {
            return;
        };
        if paged(&state.pages, head.status.as_u16()) {
            // Dropping the fetch ends the lead with nothing stored.
            return;
        }
        let Leading {
            lead,
            key,
            tenant,
            store,
            request,
            confirming: _,
        } = *leading;
        let Some(request) = request else {
            return;
        };
        let declared = head
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|declared| declared > self.max_object_bytes) {
            return;
        }
        let plan = match policy::judge(
            &self.settings,
            head.status.as_u16(),
            &head.headers,
            self.tag_header.as_ref(),
            SystemTime::now(),
        ) {
            Ok(plan) => plan,
            Err(skip) => {
                // What the origin says now replaces what was stored: an entry it no longer
                // allows must not be served again.
                if matches!(
                    skip,
                    Skip::NoStore | Skip::Private | Skip::SetCookie | Skip::VaryStar
                ) {
                    store.remove(&key);
                }
                return;
            }
        };
        let Some(variant) = policy::variant(&request, &plan.vary) else {
            return;
        };
        let mut stored = head.clone();
        for name in NOT_STORED {
            stored.remove_header(name);
        }
        if let Some(tag) = &self.tag_header {
            stored.remove_header(tag);
        }
        if plan.strip_cookies {
            stored.remove_header(&SET_COOKIE);
        }
        let tags: Box<[Box<str>]> = plan.tags.into();
        let head_bytes = Entry::head_footprint(&stored, &tags);
        let Some(fill) = Fill::begin(
            tenant,
            store,
            head_bytes,
            self.max_object_bytes,
            self.max_bytes,
        ) else {
            return;
        };
        state.fetch = Fetch::Copying(Box::new(Copying {
            lead,
            fill,
            head: stored,
            tags,
            done: Finished {
                key,
                vary: plan.vary.into(),
                variant,
                lifetimes: plan.lifetimes,
                age: policy::initial_age(&head.headers),
            },
            declared,
        }));
    }

    /// Writes `entry` as the response: its head with `Age` and `Cache-Status`, then its body,
    /// or a `304` when the request's validators match it.
    async fn serve(
        &self,
        cx: &mut RoutedCx<'_>,
        earlier: &mut Earlier<'_>,
        entry: &Entry,
        standing: Standing,
        result: &'static str,
    ) -> pingora::Result<()> {
        let request = cx.session.req_header();
        let head_only = request.method == Method::HEAD;
        let not_modified = precondition_met(request, entry);
        let mut head = if not_modified {
            let mut head = ResponseHeader::build(304, Some(NOT_MODIFIED_HEADERS.len() + 3))?;
            for name in NOT_MODIFIED_HEADERS {
                for value in entry.head.headers.get_all(name) {
                    head.append_header(name, value)?;
                }
            }
            head
        } else {
            let mut head = entry.head.clone();
            if !matches!(head.status.as_u16(), 204 | 304) {
                head.insert_header(CONTENT_LENGTH, entry.body_len.to_string())?;
            }
            head
        };
        head.insert_header("age", standing.age.to_string())?;
        head.append_header("cache-status", format!("podgate; {result}"))?;
        skew::set_cookie(cx.session, cx.table, Some(cx.selected), &mut head)?;
        if let Some(alt_svc) = cx.alt_svc {
            alt_svc.apply(&mut head, cx.app);
        }
        // As on a miss, the stages before the cache add their headers last: the stored copy
        // never held them, so HSTS, CSP, frame options and CORS follow this request.
        earlier.response(&mut head)?;
        let bodyless = not_modified || head_only || entry.body.is_empty();
        cx.session
            .write_response_header(Box::new(head), bodyless)
            .await?;
        if !bodyless {
            let last = entry.body.len() - 1;
            for (at, segment) in entry.body.iter().enumerate() {
                cx.session
                    .write_response_body(Some(segment.clone()), at == last)
                    .await?;
            }
        }
        Ok(())
    }
}

/// Whether `status` is one an `errors` stage of the chain replaces with a page.
fn paged(pages: &[std::ops::RangeInclusive<u16>], status: u16) -> bool {
    pages.iter().any(|range| range.contains(&status))
}

fn text(value: &http::HeaderValue) -> Option<&str> {
    value.to_str().ok().map(str::trim)
}

/// Whether the request's `If-None-Match` (else `If-Modified-Since`) says the client already has
/// `entry`.
fn precondition_met(request: &RequestHeader, entry: &Entry) -> bool {
    let headers = &request.headers;
    if let Some(wanted) = headers.get(IF_NONE_MATCH).and_then(text) {
        let Some(etag) = entry.head.headers.get(ETAG).and_then(text) else {
            return false;
        };
        let bare = |tag: &str| tag.strip_prefix("W/").unwrap_or(tag).to_owned();
        return wanted == "*"
            || wanted
                .split(',')
                .any(|candidate| bare(candidate.trim()) == bare(etag));
    }
    let Some(since) = headers
        .get(IF_MODIFIED_SINCE)
        .and_then(text)
        .and_then(|value| httpdate::parse_http_date(value).ok())
    else {
        return false;
    };
    entry
        .head
        .headers
        .get(LAST_MODIFIED)
        .and_then(text)
        .and_then(|value| httpdate::parse_http_date(value).ok())
        .is_some_and(|modified| modified <= since)
}
