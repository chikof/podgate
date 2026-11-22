//! The `quota` middleware: a source may make `limit` requests per calendar window, counted across
//! all nodes in the shared store. Reference: `docs/ref/mw-quota.md`; the counter is
//! [`crate::ratelimit_store::quota`].
//!
//! ```json
//! { "name": "plan", "type": "quota", "limit": 10000, "period": "month",
//!   "source": { "header": "x-api-key" }, "store": "main", "on_store_error": "allow",
//!   "store_timeout_ms": 20 }
//! ```
//!
//! - `period` is a fixed UTC calendar window: `minute`, `hour`, `day` or `month`. A source that
//!   has made `limit` requests in the window gets `429 {"error":"quota exceeded"}` with
//!   `retry-after` the seconds to the window end, and no upstream is contacted.
//! - Every answer the stage touches says what is left: `RateLimit-Limit`, `RateLimit-Remaining`
//!   and `RateLimit-Reset` (seconds to the window end), the names of the IETF draft. An upstream's
//!   own `RateLimit-*` headers are replaced.
//! - `source` is `ip`, `header` or `host` as for `rate_limit`, or `jwt_claim`: a claim a
//!   `jwt_auth` earlier in the chain copies into a header with `forward_claims`. The client's own
//!   copy of that header never counts: `jwt_auth` removes it before it verifies.
//! - There is no node scope: a quota that resets when the process restarts is not a quota. `store`
//!   and `on_store_error` are required. A store error is not a verdict: `allow` admits the request
//!   and counts it in `podgate_quota_unmetered_total`, `deny` answers `503` with `retry-after: 1`.
//! - The tenant names a store and sets the limit; the address, credentials and the tenants that
//!   may use a store are the operator's (`RATE_LIMIT_STORES_FILE`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use pingora::http::ResponseHeader;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::limits::{IpSource, Source, SourceConfig};
use super::{CompileCx, Flow, Kind, Named, RequestCx, Stage};
use crate::compile::{Invalid, Rejected};
use crate::error::AppError;
use crate::ratelimit_store::quota::{
    Admission, Counter, MAX_LIMIT, Period, SourceId, Usage, now_secs,
};
use crate::ratelimit_store::{MAX_TIMEOUT_MS, Mode, Store, StoreError, Stores};
use podgate_model::{App, Declared, Snapshot};

/// What an absent header counts as: a client cannot leave a quota by omitting the value.
const ABSENT: &[u8] = b"-";

/// Posture change kinds this middleware reports, see [`Kind::posture`].
pub mod kind {
    /// The middleware is gone: nothing counts the route.
    pub const REMOVED: &str = "quota_removed";
    /// More requests pass per unit of time: a higher limit, or a shorter period at the same limit
    /// (periods compare at their nominal length, a month counting 31 days).
    pub const LOOSENED: &str = "quota_loosened";
    /// Requests are counted per another source, which can let a client leave its count.
    pub const SOURCE_CHANGED: &str = "quota_source_changed";
    /// A quota that did not admit requests when its store fails now does.
    pub const FAIL_OPEN: &str = "quota_fail_open";
}

/// What a quota counts requests by.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum QuotaSource {
    /// The client address under an `ipStrategy`.
    Ip(IpSource),
    /// The first value of a request header.
    Header(String),
    /// The host of the request; only `true` is valid.
    Host(bool),
    /// A verified claim of a token, copied into a header by a `jwt_auth` earlier in the chain.
    JwtClaim(String),
}

impl QuotaSource {
    /// The source as `rate_limit` writes it, or `None` for a claim.
    fn common(&self) -> Option<SourceConfig> {
        match self {
            Self::Ip(ip) => Some(SourceConfig::Ip(ip.clone())),
            Self::Header(name) => Some(SourceConfig::Header(name.clone())),
            Self::Host(on) => Some(SourceConfig::Host(*on)),
            Self::JwtClaim(_) => None,
        }
    }

    fn describe(&self) -> Value {
        match self {
            Self::JwtClaim(claim) => json!({ "jwt_claim": claim }),
            other => other
                .common()
                .map_or(Value::Null, |common| common.describe()),
        }
    }
}

/// The configuration of a `quota` middleware.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// Requests one source may make per window: 1 to 2^40.
    limit: u64,
    /// The calendar window, UTC.
    period: Period,
    source: QuotaSource,
    #[serde(default)]
    store: Option<String>,
    #[serde(default)]
    on_store_error: Option<Mode>,
    #[serde(default)]
    store_timeout_ms: Option<u16>,
}

/// How a compiled quota finds the source of a request.
#[derive(Debug)]
enum Keyed {
    Common(Source),
    /// A claim and the header a `jwt_auth` copies it into, known once the chain is.
    Claim {
        claim: Box<str>,
        header: Option<HeaderName>,
    },
}

/// A compiled `quota` middleware.
#[derive(Debug)]
pub struct Quota {
    limit: u64,
    period: Period,
    store: Box<str>,
    mode: Mode,
    timeout_ms: Option<u16>,
    source_config: QuotaSource,
    keyed: Keyed,
    counter: Arc<Counter>,
}

/// What a request keeps of its `quota` stage.
#[derive(Debug, Default)]
pub struct State {
    /// What the source had left after this request, for the response headers.
    usage: Option<Usage>,
}

/// Why a request is not admitted.
enum Refusal {
    Exceeded(Usage),
    Unavailable,
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("quota: {message}"))
}

/// The `RateLimit-*` headers for `usage`.
fn headers(usage: &Usage) -> [(&'static str, String); 3] {
    [
        ("RateLimit-Limit", usage.limit.to_string()),
        ("RateLimit-Remaining", usage.remaining().to_string()),
        ("RateLimit-Reset", usage.reset_secs.to_string()),
    ]
}

impl Quota {
    /// The claim this quota counts by, when its source is one.
    fn claim(&self) -> Option<&str> {
        match &self.keyed {
            Keyed::Claim { claim, .. } => Some(&**claim),
            Keyed::Common(_) => None,
        }
    }

    fn source_id(&self, cx: &RequestCx<'_>) -> SourceId {
        let request = cx.session.req_header();
        match &self.keyed {
            Keyed::Common(source) => source.with_material(request, cx.forwarded, SourceId::of),
            Keyed::Claim { header, .. } => SourceId::of(
                header
                    .as_ref()
                    .and_then(|name| request.headers.get(name))
                    .map_or(ABSENT, HeaderValue::as_bytes),
            ),
        }
    }

    async fn decide(
        &self,
        store: Option<&Arc<Store>>,
        id: SourceId,
    ) -> Result<Option<Usage>, Refusal> {
        let Some(store) = store else {
            // The compiler checked the name against the same stores: this cannot be reached.
            return self.on_store_error(None, None);
        };
        match self.counter.bind(store, id).admit(1, now_secs()).await {
            Ok(Admission::Admitted(usage)) => Ok(Some(usage)),
            Ok(Admission::Exhausted(usage)) => Err(Refusal::Exceeded(usage)),
            Err(error) => self.on_store_error(Some(store), Some(&error)),
        }
    }

    fn on_store_error(
        &self,
        store: Option<&Arc<Store>>,
        error: Option<&StoreError>,
    ) -> Result<Option<Usage>, Refusal> {
        if let Some(store) = store {
            store.count_quota_error(self.mode);
            if let Some(error) = error {
                tracing::debug!(store = store.name(), %error, "quota store error");
            }
        }
        match self.mode {
            Mode::Allow => {
                if let Some(store) = store {
                    store.count_quota_unmetered();
                }
                Ok(None)
            }
            Mode::Deny => Err(Refusal::Unavailable),
        }
    }

    /// Gives a claim source the header its claim is copied into.
    fn bind(&mut self, found: HeaderName) {
        if let Keyed::Claim { header, .. } = &mut self.keyed {
            *header = Some(found);
        }
    }
}

impl Kind for Quota {
    type State = State;

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        if !declared.config.contains_key("store") {
            return Err(invalid(
                "`store` is required, the name of a store: a quota has no node scope, because a quota that resets when the process restarts is not a quota",
            ));
        }
        if !declared.config.contains_key("on_store_error") {
            return Err(invalid(
                "`on_store_error` is required: `allow` (requests pass, and are counted in podgate_quota_unmetered_total, while the store is unavailable) or `deny` (`503`); failing open removes the protection exactly when something is wrong, and failing closed turns a store outage into a site outage, so there is no default",
            ));
        }
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if !(1..=MAX_LIMIT).contains(&config.limit) {
            return Err(invalid(format!("`limit` must be 1 to {MAX_LIMIT}")));
        }
        let Some(store) = config.store.filter(|store| !store.is_empty()) else {
            return Err(invalid("`store` must name a store"));
        };
        let Some(mode) = config.on_store_error else {
            return Err(invalid("`on_store_error` must be `allow` or `deny`"));
        };
        if let Some(timeout_ms) = config.store_timeout_ms
            && !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms)
        {
            return Err(invalid(format!(
                "`store_timeout_ms` must be 1 to {MAX_TIMEOUT_MS}"
            )));
        }
        let keyed = match (config.source.common(), &config.source) {
            (Some(common), _) => Keyed::Common(Source::compile(&common).map_err(invalid)?),
            (None, QuotaSource::JwtClaim(claim)) if !claim.is_empty() => Keyed::Claim {
                claim: claim.as_str().into(),
                header: None,
            },
            (None, _) => return Err(invalid("`source.jwt_claim` must name a claim")),
        };
        // Only what names the counter: the limit, the timeout and the failure choice change
        // nothing a client has used. `admit` compares the count with the current limit, so a
        // lowered limit never hands out what was used already.
        let identity = json!({
            "period": config.period.name(),
            "source": config.source.describe(),
            "store": store,
        })
        .to_string();
        let fingerprint = u64::from_be_bytes(
            Sha256::digest(identity.as_bytes())[..8]
                .try_into()
                .unwrap_or_default(),
        );
        let timeout = config
            .store_timeout_ms
            .map(|millis| Duration::from_millis(u64::from(millis)));
        Ok(Self {
            limit: config.limit,
            period: config.period,
            store: store.into(),
            mode,
            timeout_ms: config.store_timeout_ms,
            source_config: config.source,
            keyed,
            counter: Counter::new(
                &cx.app.tenant,
                &cx.app.id,
                &declared.name,
                fingerprint,
                config.period,
                config.limit,
                timeout,
            ),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        let id = self.source_id(cx);
        let stores = cx.stores;
        let refusal = match self.decide(stores.get(&self.store), id).await {
            Ok(usage) => {
                state.usage = usage;
                return Ok(Flow::Continue);
            }
            Err(refusal) => refusal,
        };
        *cx.capacity_refusal = true;
        match refusal {
            Refusal::Exceeded(usage) => {
                let err = AppError::QuotaExceeded {
                    retry_after_secs: usage.reset_secs,
                };
                *cx.reason = Some(err.log_reason());
                crate::respond::write_error_with(cx.session, &err, &headers(&usage)).await?;
            }
            Refusal::Unavailable => {
                let err = AppError::QuotaUnavailable;
                *cx.reason = Some(err.log_reason());
                crate::respond::write_error(cx.session, &err).await?;
            }
        }
        Ok(Flow::Respond)
    }

    fn response(&self, response: &mut ResponseHeader, state: &mut State) -> pingora::Result<()> {
        if let Some(usage) = &state.usage {
            for (name, value) in headers(usage) {
                response.insert_header(name, value)?;
            }
        }
        Ok(())
    }

    /// Dropping the middleware stops counting; a higher limit lets more through; another source
    /// puts requests in other counts; a quota that starts failing open lets a client past its
    /// count while the store is down.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        let Some(new) = new else {
            return vec![kind::REMOVED];
        };
        let mut kinds = Vec::new();
        // new.limit / new.period > old.limit / old.period, as a cross product.
        if u128::from(new.limit) * u128::from(self.period.nominal_secs())
            > u128::from(self.limit) * u128::from(new.period.nominal_secs())
        {
            kinds.push(kind::LOOSENED);
        }
        if self.source_config != new.source_config {
            kinds.push(kind::SOURCE_CHANGED);
        }
        if new.mode == Mode::Allow && self.mode != Mode::Allow {
            kinds.push(kind::FAIL_OPEN);
        }
        kinds
    }

    fn describe(&self) -> Value {
        json!({
            "limit": self.limit,
            "period": self.period.name(),
            "source": self.source_config.describe(),
            "store": self.store,
            "on_store_error": match self.mode {
                Mode::Allow => "allow",
                Mode::Deny => "deny",
            },
            "store_timeout_ms": self.timeout_ms,
        })
    }
}

/// Refuses the quotas whose store the tenant may not use. A store that does not exist and one the
/// tenant is not listed for give the same answer, so a tenant cannot find out which stores other
/// tenants use.
pub(crate) fn check_snapshot(
    snapshot: &Snapshot,
    stages: &[&[Named]],
    stores: &Stores,
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, stages) in snapshot.apps.iter().zip(stages) {
        for named in *stages {
            let Stage::Quota(quota) = &named.stage else {
                continue;
            };
            if !stores.allows(&quota.store, &app.tenant) {
                rejected.push(Rejected::new(
                    app,
                    format!("middleware {}", named.name),
                    invalid(format!(
                        "store {:?} is not available to tenant {}; stores are listed in the operator's RATE_LIMIT_STORES_FILE",
                        quota.store, app.tenant
                    )),
                ));
            }
        }
    }
    rejected
}

/// Gives every quota whose source is a `jwt_claim` the header a `jwt_auth` earlier in each chain
/// that holds it copies the claim into. `chains` are the routers of `app` with their effective
/// chains (indices into `stages`).
///
/// A quota that no earlier `jwt_auth` feeds the claim, in some chain that runs it, would read a
/// header the client wrote, so it is refused; so is one whose chains disagree on the header.
pub(crate) fn bind_claims(
    app: &App,
    stages: &mut [Named],
    chains: &[(&str, Vec<usize>)],
) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    let mut found: HashMap<usize, HeaderName> = HashMap::new();
    for (router, chain) in chains {
        for (position, &index) in chain.iter().enumerate() {
            let Some(Named {
                name,
                stage: Stage::Quota(quota),
            }) = stages.get(index)
            else {
                continue;
            };
            let Some(claim) = quota.claim() else {
                continue;
            };
            let header =
                chain[..position]
                    .iter()
                    .rev()
                    .find_map(|earlier| match stages.get(*earlier) {
                        Some(Named {
                            stage: Stage::JwtAuth(auth),
                            ..
                        }) => auth.claim_header(claim),
                        _ => None,
                    });
            let at = format!("router {router}");
            match header {
                None => rejected.push(Rejected::new(
                    app,
                    at,
                    invalid(format!(
                        "middleware {name}: `source.jwt_claim` {claim:?} needs a `jwt_auth` earlier in the chain of router {router} whose `forward_claims` copies that claim into a header; a header the client wrote is never a claim"
                    )),
                )),
                Some(header) => match found.get(&index) {
                    Some(other) if other != header => rejected.push(Rejected::new(
                        app,
                        at,
                        invalid(format!(
                            "middleware {name}: the `jwt_auth` before it copies claim {claim:?} into {header} in router {router} and {other} in another; one quota counts by one header"
                        )),
                    )),
                    _ => {
                        found.insert(index, header.clone());
                    }
                },
            }
        }
    }
    for (index, header) in found {
        if let Some(Named {
            stage: Stage::Quota(quota),
            ..
        }) = stages.get_mut(index)
        {
            quota.bind(header);
        }
    }
    rejected
}
