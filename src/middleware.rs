//! Middlewares: the per-route chain that runs between matching a router and choosing a backend.
//!
//! The effective chain of a router is the app's `default_chain`, then the router's own `chain`
//! (a `chain` middleware expands in place). Request hooks run in that order, response hooks in
//! the reverse order. Every kind is one type in its own file implementing [`Kind`]; the
//! `kinds!` list below is the only registry: it generates the [`Stage`] enum, the per-request
//! state enum and the dispatch, so a request pays no `dyn` call and no boxed future.
//!
//! # Adding a kind
//!
//! 1. Write `src/middleware/<kind>.rs`: a config struct with `#[serde(deny_unknown_fields)]` that
//!    derives `schemars::JsonSchema` (the schema `GET /v1/schema` serves), a type implementing
//!    [`Kind`] (only the hooks it needs; the rest do nothing), unit tests.
//! 2. In the `kinds!` list, replace `"<kind>" => unbuilt` by `"<kind>" => Variant(<kind>::Type)`
//!    and add `mod <kind>;` below; add `"<kind>" => <kind>::Config,` to the `schemas!` list (the
//!    test `every_built_kind_has_a_schema` fails without it). Nothing else in the crate changes:
//!    the compiler, explain, the plan's posture diff and the proxy callbacks already call the
//!    chain.
//! 3. Test it end to end in `tests/mw_<kind>.rs`.
//!
//! Until step 2, a snapshot that names the kind is refused with `middleware_not_built`.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use serde_json::Value;

use crate::budget::TenantBudget;
use crate::cache::Cache;
use crate::client_ip::ForwardedView;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::events::EventFeed;
use crate::route::Selected;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::table::{CompiledApp, RoutingTable};
use crate::wasm as engine;
use podgate_model::{App, Declared};

pub mod add_prefix;
pub mod basic_auth;
pub mod buffering;
pub mod cache;
pub mod circuit_breaker;
pub mod compress;
pub mod content_type;
pub mod digest_auth;
pub mod errors;
pub mod headers;
pub mod in_flight_req;
pub mod ip_allow_list;
pub(crate) mod limits;
pub mod pass_tls_client_cert;
mod path_rewrite;
pub mod rate_limit;
pub mod redirect;
pub mod redirect_regex;
pub mod redirect_scheme;
pub mod replace_path;
pub mod replace_path_regex;
pub mod respond;
pub mod state;
pub mod strip_prefix;
pub mod strip_prefix_regex;
pub mod wasm;

/// What a request hook decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Run the next stage, then forward the request.
    Continue,
    /// The hook wrote the response: the request ends here.
    Respond,
}

/// What a kind sees while it compiles.
#[derive(Debug)]
pub struct CompileCx<'a> {
    /// The app that declares the middleware.
    pub app: &'a App,
    /// The WASM engine shared by every module of this snapshot compile.
    pub engine: &'a mut engine::Compiler,
}

/// What a request hook sees.
pub struct RequestCx<'a> {
    /// The downstream session: request head, body and the response writer.
    pub session: &'a mut Session,
    /// The app the request was matched to.
    pub app: &'a CompiledApp,
    /// What the request's peer is trusted to say: scheme, host, port and client address.
    pub forwarded: &'a ForwardedView,
    /// The tenant's budget, to charge memory before allocating.
    pub tenant: Option<&'a Arc<TenantBudget>>,
    /// The bounded pool for WASM runs.
    pub executor: &'a engine::Executor,
    /// Set when the hook answers with a refusal auto-revert must not count
    /// ([`crate::AppError::is_capacity_refusal`]).
    pub capacity_refusal: &'a mut bool,
    /// The event feed, for a hook that tells the control plane something happened.
    pub events: &'a EventFeed,
    /// The bounded pool for password verifications (`basic_auth`).
    pub hashing: &'a basic_auth::Pool,
}

/// The stages of the chain that come before the one running a routed hook, with their per-request
/// state. A hook that answers the request from its own store calls [`Self::response`], so the
/// answer passes the response hooks of those stages exactly as a response from the upstream
/// does: security headers, CORS and the like are never skipped.
pub struct Earlier<'a> {
    stages: &'a [Named],
    chain: &'a [usize],
    states: &'a mut [StageState],
}

impl Earlier<'_> {
    /// Runs the response hooks of the earlier stages on `head`, last stage first, against the
    /// current request (their request hooks have already run, so their state is this request's).
    ///
    /// # Errors
    ///
    /// The first error a hook returns.
    pub fn response(&mut self, head: &mut ResponseHeader) -> pingora::Result<()> {
        for (position, index) in self.chain.iter().enumerate().rev() {
            if let (Some(named), Some(slot)) =
                (self.stages.get(*index), self.states.get_mut(position))
            {
                named.stage.response(head, slot)?;
            }
        }
        Ok(())
    }
}

/// What a routed hook sees: the request after the middleware chain's request hooks, with its
/// revision and server chosen and no admission taken yet.
pub struct RoutedCx<'a> {
    /// The downstream session: request head, body and the response writer.
    pub session: &'a mut Session,
    /// The table the request is served from.
    pub table: &'a RoutingTable,
    /// The app the request was matched to.
    pub app: &'a CompiledApp,
    /// The router, revision and server chosen for the request.
    pub selected: &'a Selected,
    /// What the request's peer is trusted to say: scheme, host, port and client address.
    pub forwarded: &'a ForwardedView,
    /// Whether the connection the request arrived on is TLS.
    pub tls: bool,
    /// The entry point the request arrived on.
    pub entry_point: &'a Arc<str>,
    /// The tenant's budget, to charge memory before allocating.
    pub tenant: Option<&'a Arc<TenantBudget>>,
    /// The response cache registry (see [`crate::cache`]).
    pub cache: &'a Cache,
    /// The request head as it arrived, before any middleware changed it. Set only when the chain
    /// has a stage that needs it (`cache`, to replay the request as a subrequest).
    pub original: Option<RequestHeader>,
    /// The statuses an `errors` stage of the chain replaces with a page for this request (none for
    /// a `HEAD`, which is never paged). A cache must neither store nor serve such a response: the
    /// page, not the stored copy, is the answer. Filled by [`run_routed`].
    pub pages: Vec<std::ops::RangeInclusive<u16>>,
}

/// What a finished request looks like to [`Kind::finished`].
#[derive(Debug)]
pub struct FinishCx<'a> {
    /// The event feed, for a hook that tells the control plane something happened.
    pub events: &'a EventFeed,
    /// The status the client got, when a response was written. `None` for a request the proxy
    /// refused for capacity ([`crate::AppError::is_capacity_refusal`]): busy is not a verdict on
    /// the downstream.
    pub status: Option<u16>,
    /// The request failed on the upstream side before an answer arrived (refused, reset, timed
    /// out).
    pub upstream_error: bool,
}

/// What a response-head hook sees.
pub struct ResponseCx<'a> {
    /// The request the response answers.
    pub request: &'a RequestHeader,
    /// The upstream's response head, before any hook of the chain has changed it.
    pub response: &'a ResponseHeader,
    /// The tenant's budget, to charge memory before allocating.
    pub tenant: Option<&'a Arc<TenantBudget>>,
}

/// What a page hook sees: the response that may be replaced and what a replacement needs.
pub struct PageCx<'a> {
    /// The client's request.
    pub request: &'a RequestHeader,
    /// The app the request was matched to.
    pub app: &'a CompiledApp,
    /// The revision the request was sent to (index into the app's revisions); `None` when none
    /// was chosen.
    pub revision: Option<usize>,
    /// The status of the response that may be replaced.
    pub status: u16,
    /// The tenant's budget: a page is charged to it before it is fetched.
    pub tenant: &'a Arc<TenantBudget>,
    /// The operator's rule for the addresses the proxy may dial.
    pub policy: &'a UpstreamPolicy,
    /// Dials page servers.
    pub fetcher: &'a errors::fetch::Fetcher,
}

/// A middleware type. Every hook has a default that does nothing.
pub trait Kind: Sized + fmt::Debug + Send + Sync + 'static {
    /// Per-request state, created with `Default` when the chain starts and handed to every hook
    /// of this stage.
    type State: Default + Send + fmt::Debug;

    /// Builds the stage from its declaration. The config struct must refuse unknown fields.
    ///
    /// # Errors
    ///
    /// [`Invalid`] with the stable code of the problem (`invalid_middleware` unless the kind
    /// documents another).
    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid>;

    /// Runs on the request head, before a revision or backend is chosen and before any tenant
    /// slot is taken. May rewrite the request or answer it ([`Flow::Respond`]).
    ///
    /// # Errors
    ///
    /// Fails when the response cannot be written.
    fn request(
        &self,
        _cx: &mut RequestCx<'_>,
        _state: &mut Self::State,
    ) -> impl Future<Output = pingora::Result<Flow>> + Send {
        std::future::ready(Ok(Flow::Continue))
    }

    /// Runs once the request's revision and server are chosen and before any in-flight slot or
    /// backend admission is taken, in chain order. May answer the request ([`Flow::Respond`]):
    /// the choice is dropped and nothing is charged. A request the proxy routes again (its
    /// revision drained) runs this hook again.
    ///
    /// # Errors
    ///
    /// Fails when the response cannot be written.
    fn routed(
        &self,
        _cx: &mut RoutedCx<'_>,
        _earlier: &mut Earlier<'_>,
        _state: &mut Self::State,
    ) -> impl Future<Output = pingora::Result<Flow>> + Send {
        std::future::ready(Ok(Flow::Continue))
    }

    /// Runs on the request head as it goes to the upstream.
    ///
    /// # Errors
    ///
    /// Fails when a header cannot be set.
    fn upstream_request(
        &self,
        _request: &mut RequestHeader,
        _state: &mut Self::State,
    ) -> pingora::Result<()> {
        Ok(())
    }

    /// Runs on the upstream's response head, in reverse chain order.
    ///
    /// # Errors
    ///
    /// Fails when a header cannot be set.
    fn response(
        &self,
        _response: &mut ResponseHeader,
        _state: &mut Self::State,
    ) -> pingora::Result<()> {
        Ok(())
    }

    /// Runs on every chunk of the upstream's response body, in reverse chain order.
    ///
    /// # Errors
    ///
    /// Fails when the chunk cannot be transformed.
    fn response_body(
        &self,
        _body: &mut Option<Bytes>,
        _end_of_stream: bool,
        _state: &mut Self::State,
    ) -> pingora::Result<()> {
        Ok(())
    }

    /// Runs once when the request is over, in chain order, for every stage of the chain,
    /// including those a request never reached (an earlier stage answered it): a stage keeps
    /// in its [`Self::State`] whether it ran.
    fn finished(&self, _cx: &FinishCx<'_>, _state: &mut Self::State) {}

    /// Runs on every chunk of the request body the proxy reads from the client, before it goes
    /// to the upstream. `bytes_read` is everything read from the client so far, counted by
    /// Pingora, so a replay of a buffered body to a second upstream does not count twice. May
    /// refuse the request; the refusal is written as the response when none was written yet.
    ///
    /// # Errors
    ///
    /// The [`AppError`] that ends the request.
    fn request_body(&self, _bytes_read: u64, _state: &mut Self::State) -> Result<(), AppError> {
        Ok(())
    }

    /// Runs on the upstream's response head before the client has seen any of it, in reverse
    /// chain order, ahead of [`Self::response`]. May refuse the response: the refusal is written
    /// instead of it.
    ///
    /// # Errors
    ///
    /// The [`AppError`] that replaces the response.
    fn response_head(
        &self,
        _cx: &ResponseCx<'_>,
        _state: &mut Self::State,
    ) -> Result<(), AppError> {
        Ok(())
    }

    /// Runs when the response is an error podgate may replace, before any of it has reached the
    /// client: a stage that serves a replacement page returns it. Only the first stage (last in
    /// chain order) that offers one counts. The default offers none.
    fn response_page(&self, _cx: &PageCx<'_>) -> impl Future<Output = Option<errors::Page>> + Send {
        std::future::ready(None)
    }

    /// The relaxations a plan must list when `new` replaces `self`, as stable `posture_changes`
    /// kinds; `None` means the stage is gone. Security kinds implement it; the default says
    /// nothing is relaxed.
    fn posture(&self, _new: Option<&Self>) -> Vec<&'static str> {
        Vec::new()
    }

    /// What explain shows for this stage besides its type.
    fn describe(&self) -> Value {
        Value::Null
    }
}

/// Generates [`Stage`] and its dispatch from one list: `"type" => Variant(path::Type),` for a
/// built kind, `"type" => unbuilt,` for a planned one. Keep one entry per line, a blank line
/// between entries, so parallel changes to different kinds never touch adjacent lines.
macro_rules! kinds {
    (@munch [$($built:tt)*] [$($unbuilt:tt)*]) => {
        kinds!(@emit [$($built)*] [$($unbuilt)*]);
    };
    (@munch [$($built:tt)*] [$($unbuilt:tt)*] $ty:literal => unbuilt, $($rest:tt)*) => {
        kinds!(@munch [$($built)*] [$($unbuilt)* $ty,] $($rest)*);
    };
    (@munch [$($built:tt)*] [$($unbuilt:tt)*] $ty:literal => $variant:ident($kind:ty), $($rest:tt)*) => {
        kinds!(@munch [$($built)* ($ty, $variant, $kind)] [$($unbuilt)*] $($rest)*);
    };
    (@emit [$(($ty:literal, $variant:ident, $kind:ty))*] [$($unbuilt:literal,)*]) => {
        /// A compiled middleware: one variant per built kind.
        #[derive(Debug)]
        pub enum Stage {
            $(
                #[doc = concat!("The `", $ty, "` middleware.")]
                $variant($kind),
            )*
        }

        /// The per-request state of one stage.
        #[derive(Debug)]
        enum StageState {
            $( $variant(<$kind as $crate::middleware::Kind>::State), )*
        }

        /// Types that are planned and not built yet.
        pub const UNBUILT: &[&str] = &[ $($unbuilt,)* ];

        #[allow(
            unreachable_patterns,
            reason = "with one kind built the (stage, state) pairing is exhaustive; a second kind makes the fallback arms reachable"
        )]
        impl Stage {
            /// Compiles one declared middleware.
            ///
            /// # Errors
            ///
            /// `middleware_not_built` for a planned type nobody has built, `unknown_middleware`
            /// for any other type, else whatever the kind's own compile refuses with.
            pub fn compile(
                declared: &podgate_model::Declared,
                cx: &mut $crate::middleware::CompileCx<'_>,
            ) -> Result<Self, $crate::compile::Invalid> {
                match &*declared.kind {
                    $(
                        $ty => <$kind as $crate::middleware::Kind>::compile(declared, cx)
                            .map(Self::$variant),
                    )*
                    other if UNBUILT.contains(&other) => Err($crate::compile::Invalid::new(
                        "middleware_not_built",
                        format!("middleware type {other} is planned and not built yet"),
                    )),
                    other => Err($crate::compile::Invalid::new(
                        "unknown_middleware",
                        format!("unknown middleware type {other}"),
                    )),
                }
            }

            /// Every built type name, as written in a snapshot.
            pub const BUILT: &[&str] = &[ $($ty,)* ];

            /// The type name, as written in a snapshot.
            #[must_use]
            pub fn kind(&self) -> &'static str {
                match self {
                    $( Self::$variant(_) => $ty, )*
                }
            }

            /// What explain shows for this stage besides its type.
            #[must_use]
            pub fn describe(&self) -> serde_json::Value {
                match self {
                    $( Self::$variant(kind) => $crate::middleware::Kind::describe(kind), )*
                }
            }

            /// The relaxations a plan lists when `new` (`None`: nothing) replaces this stage.
            #[must_use]
            pub fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
                match self {
                    $(
                        Self::$variant(kind) => $crate::middleware::Kind::posture(
                            kind,
                            match new {
                                Some(Self::$variant(next)) => Some(next),
                                _ => None,
                            },
                        ),
                    )*
                }
            }

            fn new_state(&self) -> StageState {
                match self {
                    $( Self::$variant(_) => StageState::$variant(Default::default()), )*
                }
            }

            async fn request(
                &self,
                cx: &mut $crate::middleware::RequestCx<'_>,
                state: &mut StageState,
            ) -> pingora::Result<$crate::middleware::Flow> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::request(kind, cx, state).await
                        }
                    )*
                    _ => Ok($crate::middleware::Flow::Continue),
                }
            }

            async fn routed(
                &self,
                cx: &mut $crate::middleware::RoutedCx<'_>,
                earlier: &mut $crate::middleware::Earlier<'_>,
                state: &mut StageState,
            ) -> pingora::Result<$crate::middleware::Flow> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::routed(kind, cx, earlier, state).await
                        }
                    )*
                    _ => Ok($crate::middleware::Flow::Continue),
                }
            }

            fn upstream_request(
                &self,
                request: &mut pingora::http::RequestHeader,
                state: &mut StageState,
            ) -> pingora::Result<()> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::upstream_request(kind, request, state)
                        }
                    )*
                    _ => Ok(()),
                }
            }

            fn response(
                &self,
                response: &mut pingora::http::ResponseHeader,
                state: &mut StageState,
            ) -> pingora::Result<()> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::response(kind, response, state)
                        }
                    )*
                    _ => Ok(()),
                }
            }

            fn response_body(
                &self,
                body: &mut Option<bytes::Bytes>,
                end_of_stream: bool,
                state: &mut StageState,
            ) -> pingora::Result<()> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::response_body(kind, body, end_of_stream, state)
                        }
                    )*
                    _ => Ok(()),
                }
            }

            fn finished(
                &self,
                cx: &$crate::middleware::FinishCx<'_>,
                state: &mut StageState,
            ) {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::finished(kind, cx, state)
                        }
                    )*
                    _ => {}
                }
            }

            fn request_body(
                &self,
                bytes_read: u64,
                state: &mut StageState,
            ) -> Result<(), $crate::error::AppError> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::request_body(kind, bytes_read, state)
                        }
                    )*
                    _ => Ok(()),
                }
            }

            fn response_head(
                &self,
                cx: &$crate::middleware::ResponseCx<'_>,
                state: &mut StageState,
            ) -> Result<(), $crate::error::AppError> {
                match (self, state) {
                    $(
                        (Self::$variant(kind), StageState::$variant(state)) => {
                            $crate::middleware::Kind::response_head(kind, cx, state)
                        }
                    )*
                    _ => Ok(()),
                }
            }

            async fn response_page(
                &self,
                cx: &$crate::middleware::PageCx<'_>,
            ) -> Option<$crate::middleware::errors::Page> {
                match self {
                    $(
                        Self::$variant(kind) => {
                            $crate::middleware::Kind::response_page(kind, cx).await
                        }
                    )*
                }
            }
        }
    };
    ($($body:tt)*) => {
        kinds!(@munch [] [] $($body)*);
    };
}

kinds! {
    "wasm" => Wasm(wasm::Wasm),

    "add_prefix" => AddPrefix(add_prefix::AddPrefix),

    "strip_prefix" => StripPrefix(strip_prefix::StripPrefix),

    "strip_prefix_regex" => StripPrefixRegex(strip_prefix_regex::StripPrefixRegex),

    "replace_path" => ReplacePath(replace_path::ReplacePath),

    "replace_path_regex" => ReplacePathRegex(replace_path_regex::ReplacePathRegex),

    "redirect_scheme" => RedirectScheme(redirect_scheme::RedirectScheme),

    "redirect_regex" => RedirectRegex(redirect_regex::RedirectRegex),

    "headers" => Headers(headers::Headers),

    "content_type" => ContentType(content_type::ContentType),

    "basic_auth" => BasicAuth(basic_auth::BasicAuth),

    "digest_auth" => DigestAuth(digest_auth::DigestAuth),

    "forward_auth" => unbuilt,

    "ip_allow_list" => IpAllowList(ip_allow_list::IpAllowList),

    "rate_limit" => RateLimit(rate_limit::RateLimit),

    "in_flight_req" => InFlightReq(in_flight_req::InFlightReq),

    "circuit_breaker" => CircuitBreaker(circuit_breaker::CircuitBreaker),

    "retry" => unbuilt,

    "buffering" => Buffering(buffering::Buffering),

    "cache" => Cache(cache::Cache),

    "compress" => Compress(compress::Compress),

    "errors" => Errors(errors::Errors),

    "pass_tls_client_cert" => PassTlsClientCert(pass_tls_client_cert::PassTlsClientCert),

    "grpc_web" => unbuilt,

    "respond" => Respond(respond::Respond),
}

/// Generates [`schemas`] from one list: `"type" => path::Config,` for a built kind, whose
/// configuration struct derives `schemars::JsonSchema`. Keep one entry per line, a blank line
/// between entries, like `kinds!`.
macro_rules! schemas {
    ($($ty:literal => $config:ty,)*) => {
        /// The JSON Schema of the configuration of every built middleware type, by type name.
        #[must_use]
        pub fn schemas() -> Vec<(&'static str, Value)> {
            vec![$(($ty, $crate::admin::schema::of::<$config>()),)*]
        }
    };
}

schemas! {
    "wasm" => wasm::Config,

    "add_prefix" => add_prefix::Config,

    "strip_prefix" => strip_prefix::Config,

    "strip_prefix_regex" => strip_prefix_regex::Config,

    "replace_path" => replace_path::Config,

    "replace_path_regex" => replace_path_regex::Config,

    "redirect_scheme" => redirect_scheme::Config,

    "redirect_regex" => redirect_regex::Config,

    "headers" => headers::Config,

    "content_type" => content_type::Config,

    "basic_auth" => basic_auth::Config,

    "digest_auth" => digest_auth::Config,

    "ip_allow_list" => ip_allow_list::Config,

    "rate_limit" => rate_limit::Config,

    "in_flight_req" => in_flight_req::Config,

    "circuit_breaker" => circuit_breaker::Config,

    "buffering" => buffering::Config,

    "cache" => cache::Config,

    "compress" => compress::Config,

    "errors" => errors::Config,

    "respond" => respond::Config,

    "pass_tls_client_cert" => pass_tls_client_cert::Config,
}

/// A compiled middleware and the name it was declared under.
#[derive(Debug)]
pub struct Named {
    /// The declared name, unique in the app.
    pub name: Box<str>,
    /// The compiled stage.
    pub stage: Stage,
}

/// The per-request state of a running chain: one entry per stage, created when the chain starts.
#[derive(Debug, Default)]
pub struct State {
    stages: Vec<StageState>,
    original: Option<RequestHeader>,
}

/// Runs the request hooks of `chain` (indices into `stages`), in order, until one answers.
///
/// # Errors
///
/// The first error a hook returns.
pub async fn run_request(
    stages: &[Named],
    chain: &[usize],
    cx: &mut RequestCx<'_>,
    state: &mut State,
) -> pingora::Result<Flow> {
    if chain.is_empty() {
        return Ok(Flow::Continue);
    }
    state.stages.clear();
    state.stages.extend(
        chain
            .iter()
            .filter_map(|index| stages.get(*index))
            .map(|named| named.stage.new_state()),
    );
    state.original = has_routed(stages, chain).then(|| cx.session.req_header().clone());
    for (position, index) in chain.iter().enumerate() {
        let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) else {
            continue;
        };
        if named.stage.request(cx, slot).await? == Flow::Respond {
            return Ok(Flow::Respond);
        }
    }
    Ok(Flow::Continue)
}

/// Checks the order of a `cache` stage in `chain`, which compiles into a router.
///
/// A hit is answered from the cache's own store, so a stage declared before the cache runs only
/// its response hooks on it ([`Earlier::response`]). Some stages cannot do that, and the chain
/// is refused rather than letting the hit skip them:
///
/// - A `buffering` before the cache with a response limit holds and counts the body as it
///   streams from the upstream, which a hit does not do.
/// - A `headers` with CORS after the cache: the stored copy would carry the
///   `Access-Control-Allow-Origin` the first client's `Origin` earned. Declare it before the
///   cache, which runs its response hook on every hit.
///
/// # Errors
///
/// `invalid_middleware` naming the stage.
pub(crate) fn check_cache_order(stages: &[Named], chain: &[usize]) -> Result<(), Invalid> {
    let Some(cache) = chain.iter().position(|index| {
        matches!(
            stages.get(*index).map(|named| &named.stage),
            Some(Stage::Cache(_))
        )
    }) else {
        return Ok(());
    };
    for (position, index) in chain.iter().enumerate() {
        let Some(named) = stages.get(*index) else {
            continue;
        };
        let reason = match &named.stage {
            Stage::Buffering(buffering) if position < cache && buffering.limits_response() => {
                "limits the response body, which a cache hit does not stream: declare it after the cache"
            }
            Stage::Headers(headers) if position > cache && headers.has_cors() => {
                "answers CORS after the cache, so the stored copy would carry the first client's Access-Control-Allow-Origin: declare it before the cache"
            }
            _ => continue,
        };
        return Err(Invalid::new(
            "invalid_middleware",
            format!("middleware {} {reason}", named.name),
        ));
    }
    Ok(())
}

/// Whether any stage of `chain` has a routed hook: only those kinds are listed here, so a
/// request through a chain without one pays nothing for the hook.
#[must_use]
pub fn has_routed(stages: &[Named], chain: &[usize]) -> bool {
    chain.iter().any(|index| {
        matches!(
            stages.get(*index),
            Some(Named {
                stage: Stage::Cache(_),
                ..
            })
        )
    })
}

/// Runs the routed hooks of `chain` in order, until one answers.
///
/// # Errors
///
/// The first error a hook returns.
pub async fn run_routed(
    stages: &[Named],
    chain: &[usize],
    cx: &mut RoutedCx<'_>,
    state: &mut State,
) -> pingora::Result<Flow> {
    cx.pages = page_statuses(stages, chain, cx.session.req_header());
    cx.original = state.original.take();
    let mut flow = Flow::Continue;
    for (position, index) in chain.iter().enumerate() {
        let Some(named) = stages.get(*index) else {
            continue;
        };
        let (before, rest) = state.stages.split_at_mut(position);
        let Some(slot) = rest.first_mut() else {
            continue;
        };
        let mut earlier = Earlier {
            stages,
            chain: chain.get(..position).unwrap_or_default(),
            states: before,
        };
        if named.stage.routed(cx, &mut earlier, slot).await? == Flow::Respond {
            flow = Flow::Respond;
            break;
        }
    }
    state.original = cx.original.take();
    Ok(flow)
}

/// The statuses the `errors` stages of `chain` replace for `request`.
fn page_statuses(
    stages: &[Named],
    chain: &[usize],
    request: &RequestHeader,
) -> Vec<std::ops::RangeInclusive<u16>> {
    if request.method == pingora::http::Method::HEAD {
        return Vec::new();
    }
    chain
        .iter()
        .filter_map(|index| match &stages.get(*index)?.stage {
            Stage::Errors(errors) => Some(errors.statuses().iter().cloned()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Runs the upstream-request hooks of `chain` on the request head going to the upstream.
///
/// # Errors
///
/// The first error a hook returns.
pub fn run_upstream_request(
    stages: &[Named],
    chain: &[usize],
    request: &mut RequestHeader,
    state: &mut State,
) -> pingora::Result<()> {
    for (position, index) in chain.iter().enumerate() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.upstream_request(request, slot)?;
        }
    }
    Ok(())
}

/// Runs the response hooks of `chain` on the upstream's response head, last stage first.
///
/// # Errors
///
/// The first error a hook returns.
pub fn run_response(
    stages: &[Named],
    chain: &[usize],
    response: &mut ResponseHeader,
    state: &mut State,
) -> pingora::Result<()> {
    for (position, index) in chain.iter().enumerate().rev() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.response(response, slot)?;
        }
    }
    Ok(())
}

/// Runs the response-body hooks of `chain` on one chunk, last stage first.
///
/// # Errors
///
/// The first error a hook returns.
pub fn run_response_body(
    stages: &[Named],
    chain: &[usize],
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    state: &mut State,
) -> pingora::Result<()> {
    for (position, index) in chain.iter().enumerate().rev() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.response_body(body, end_of_stream, slot)?;
        }
    }
    Ok(())
}

/// The settings of the `compress` stage that decides for `chain`: the last one, so a router's own
/// chain overrides the app's `default_chain`. `None` when the chain has no `compress`, which
/// leaves the platform default ([`crate::compress::Settings::platform`]).
#[must_use]
pub fn compression<'a>(
    stages: &'a [Named],
    chain: &[usize],
) -> Option<&'a crate::compress::Settings> {
    chain
        .iter()
        .rev()
        .find_map(|index| match &stages.get(*index)?.stage {
            Stage::Compress(compress) => Some(compress.settings()),
            _ => None,
        })
}

/// Runs the finish hooks of `chain` in order, once the request is over.
pub fn run_finished(stages: &[Named], chain: &[usize], cx: &FinishCx<'_>, state: &mut State) {
    for (position, index) in chain.iter().enumerate() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.finished(cx, slot);
        }
    }
}

/// Runs the request-body hooks of `chain` after the proxy read `bytes_read` bytes of the body.
///
/// # Errors
///
/// The first refusal a hook returns.
pub fn run_request_body(
    stages: &[Named],
    chain: &[usize],
    bytes_read: u64,
    state: &mut State,
) -> Result<(), AppError> {
    for (position, index) in chain.iter().enumerate() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.request_body(bytes_read, slot)?;
        }
    }
    Ok(())
}

/// Runs the response-head hooks of `chain` on the upstream's response head, last stage first.
///
/// # Errors
///
/// The first refusal a hook returns.
pub fn run_response_head(
    stages: &[Named],
    chain: &[usize],
    cx: &ResponseCx<'_>,
    state: &mut State,
) -> Result<(), AppError> {
    for (position, index) in chain.iter().enumerate().rev() {
        if let (Some(named), Some(slot)) = (stages.get(*index), state.stages.get_mut(position)) {
            named.stage.response_head(cx, slot)?;
        }
    }
    Ok(())
}

/// Runs the page hooks of `chain` for a response with status `cx.status`, last stage first, and
/// returns the first page a stage offers. `None` when no stage does: the response stands.
pub async fn run_page(stages: &[Named], chain: &[usize], cx: &PageCx<'_>) -> Option<errors::Page> {
    for index in chain.iter().rev() {
        if let Some(named) = stages.get(*index)
            && let Some(page) = named.stage.response_page(cx).await
        {
            return Some(page);
        }
    }
    None
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    /// A stub kind: the whole of "add a middleware" is this type and one line in a `kinds!` list.
    #[derive(Debug)]
    struct Stub {
        label: String,
    }

    impl Kind for Stub {
        type State = ();

        fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
            let label = declared
                .config
                .get("label")
                .and_then(Value::as_str)
                .ok_or_else(|| Invalid::new("invalid_middleware", "label is required"))?;
            Ok(Self {
                label: label.to_owned(),
            })
        }

        fn describe(&self) -> Value {
            json!({ "label": self.label })
        }
    }

    #[allow(
        dead_code,
        unreachable_pub,
        reason = "the stub registry only proves that one `kinds!` line adds a kind: it compiles and describes, it never serves a request"
    )]
    mod registry {
        use super::*;

        kinds! {
            "stub" => Stub(Stub),

            "later" => unbuilt,
        }

        pub(super) fn compile(declared: &Declared) -> Result<Stage, Invalid> {
            let app = podgate_model::App {
                id: "a".into(),
                tenant: "t".into(),
                declared_by: "test".into(),
                tls: serde_json::from_str(r#"{"mode": "acme"}"#).expect("valid tls policy"),
                routers: Vec::new(),
                middlewares: Vec::new(),
                default_chain: Vec::new(),
                services: Vec::new(),
                transports: Vec::new(),
                revisions: Vec::new(),
                allow_domain_fronting: false,
                record_bodies: false,
                scale_to_zero: None,
                canary: None,
                tcp: None,
                udp: None,
                forwarded: None,
            };
            let mut engine = engine::Compiler::default();
            Stage::compile(
                declared,
                &mut CompileCx {
                    app: &app,
                    engine: &mut engine,
                },
            )
        }
    }

    fn declared(kind: &str, label: Option<&str>) -> Declared {
        let mut value = json!({ "name": "n", "type": kind });
        if let Some(label) = label {
            value["label"] = json!(label);
        }
        serde_json::from_value(value).expect("declared")
    }

    #[test]
    fn a_kind_is_one_type_and_one_list_line() {
        let stage = registry::compile(&declared("stub", Some("hi"))).expect("compiles");
        assert_eq!(stage.kind(), "stub");
        assert_eq!(stage.describe(), json!({ "label": "hi" }));
        assert!(stage.posture(None).is_empty());
    }

    #[test]
    fn unbuilt_unknown_and_malformed_kinds_are_refused_with_their_codes() {
        let code = |kind: &str, label: Option<&str>| {
            registry::compile(&declared(kind, label))
                .expect_err(kind)
                .code
        };
        assert_eq!(code("later", None), "middleware_not_built");
        assert_eq!(code("nonsense", None), "unknown_middleware");
        assert_eq!(code("stub", None), "invalid_middleware");
    }
}
