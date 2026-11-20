//! Entry point request policy: what the snapshot says about one listener.
//!
//! `EntryPointPolicy` is snapshot data and the operator's: the control plane writes it, an app
//! owner cannot (an app declares routers and middlewares only; `tenants` limits who may attach
//! routers, it does not give anyone the policy). [`check_all`] refuses what cannot be applied,
//! [`build`] compiles the rest into one [`Policy`] per entry point that the routing table keeps
//! and the request path reads.
//!
//! Every knob is either applied through a real Pingora setting or refused with
//! `unsupported_setting` (`docs/ref/entry-policy.md` has the table and the Pingora source each
//! row rests on):
//!
//! - `redirect`: answered by the request path ([`Policy::redirect`]) with the status pair and the
//!   `Location` guard of [`crate::middleware::redirect`].
//! - `timeouts.read_secs`, `timeouts.write_secs`: `HttpSession::set_read_timeout` and
//!   `set_write_timeout` per request ([`Policy::apply_timeouts`]).
//! - `timeouts.idle_secs`: the HTTP/1 keep-alive wait ([`Policy::idle_secs`], set before each request
//!   is read) and the HTTP/2 connection idle timeout ([`super::app`]).
//! - `http2.max_concurrent_streams`, `max_header_bytes` on HTTP/2: the `h2` connection builder
//!   ([`Policy::h2_options`], read per connection by [`super::app`]).
//! - `max_header_bytes`: also a check of the parsed head ([`Policy::check_head`]).
//! - `allow_encoded_slash`: the path normalization ([`Policy::allow_encoded_slash`]).
//! - `underscore_headers`: [`Policy::check_head`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;
use std::time::Duration;

use http::Method;
use pingora::http::RequestHeader;
use pingora::protocols::http::v2::server::{H2Options, default_h2_options};
use pingora::proxy::Session;
use podgate_model::{EntryPointPolicy, Snapshot, UnderscoreHeaders};
use serde::Deserialize;
use serde_json::Value;

use super::{CompileContext, Protocol};
use crate::client_ip::ForwardedView;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::middleware::redirect::{self, Decision, Origin};
use crate::respond;
use crate::table::RoutingTable;

/// The `kind` strings of the posture changes an entry point policy reports in a plan.
pub mod kind {
    /// The entry point now accepts an encoded `/` in the path.
    pub const ALLOW_ENCODED_SLASH: &str = "allow_encoded_slash";
    /// The entry point dealt with headers named with an underscore more strictly before.
    pub const UNDERSCORE_HEADERS_RELAXED: &str = "underscore_headers_relaxed";
    /// The entry point redirected to an `https` entry point and no longer does.
    pub const ENTRY_POINT_HTTPS_REDIRECT_REMOVED: &str = "entry_point_https_redirect_removed";
}

/// Longest timeout, in seconds. Also bounds the HTTP/2 idle options the process keeps (one per
/// distinct value, see [`super::app`]).
pub const MAX_SECS: u32 = 3600;
/// Largest `http2.max_concurrent_streams`.
pub const MAX_STREAMS: u32 = 10_000;
/// Largest `max_header_bytes`: Pingora's HTTP/1 parser refuses a head over 1048575 bytes
/// (`pingora-core` `protocols/http/v1/common.rs`, `MAX_HEADER_SIZE`) and nothing raises it.
pub const MAX_HEADER_BYTES: u32 = 1_048_575;

/// An entry point's redirect, resolved against the listener it points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    to: Box<str>,
    scheme: &'static str,
    /// The target's port; `None` when it is the scheme's default (`80`, `443`).
    port: Option<u16>,
    permanent: bool,
}

impl Redirect {
    /// The entry point it redirects to.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// The status the redirect answers a request with `method` with: [`redirect::status_for`].
    #[must_use]
    pub fn status_for(&self, method: &Method) -> u16 {
        redirect::status_for(method, self.permanent).as_u16()
    }

    /// The scheme of the target, `http` or `https`.
    #[must_use]
    pub fn scheme(&self) -> &'static str {
        self.scheme
    }

    /// The target's port, `None` when it is the default of its scheme.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

/// The timeouts that apply, each already range-checked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Timeouts {
    read: Option<Duration>,
    write: Option<Duration>,
    idle: Option<Duration>,
}

/// The compiled policy of one entry point. [`Policy::none`] is what an entry point without one
/// gets: every field off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    redirect: Option<Redirect>,
    timeouts: Timeouts,
    h2_streams: Option<u32>,
    max_header_bytes: Option<u32>,
    allow_encoded_slash: bool,
    underscore: UnderscoreHeaders,
}

/// How many of a head's bytes `max_header_bytes` counts per header besides name and value:
/// `": "` and the line break.
const HEADER_FRAMING: usize = 4;

impl Policy {
    /// The policy of an entry point with none in the snapshot.
    #[must_use]
    pub fn none() -> &'static Self {
        static NONE: LazyLock<Policy> = LazyLock::new(Policy::default);
        &NONE
    }

    /// The redirect, when the entry point answers every request with one.
    #[must_use]
    pub fn redirect_to(&self) -> Option<&Redirect> {
        self.redirect.as_ref()
    }

    /// Whether the path normalization keeps an encoded `/` instead of refusing it.
    #[must_use]
    pub fn allow_encoded_slash(&self) -> bool {
        self.allow_encoded_slash
    }

    /// The idle (keep-alive) timeout in whole seconds, for HTTP/1 sessions and HTTP/2
    /// connections.
    #[must_use]
    pub fn idle_secs(&self) -> Option<u32> {
        self.timeouts
            .idle
            .and_then(|idle| u32::try_from(idle.as_secs()).ok())
    }

    /// The `h2` connection settings this policy changes, `None` when it changes none (Pingora's
    /// defaults then apply).
    #[must_use]
    pub fn h2_options(&self) -> Option<H2Options> {
        if self.h2_streams.is_none() && self.max_header_bytes.is_none() {
            return None;
        }
        let mut options = default_h2_options();
        if let Some(streams) = self.h2_streams {
            options.max_concurrent_streams(streams);
        }
        if let Some(bytes) = self.max_header_bytes {
            options.max_header_list_size(bytes);
        }
        Some(options)
    }

    /// Sets the downstream read and write timeouts of `session`. Pingora's read timeout is the
    /// wait for the next piece of the body, per read; HTTP/2 has none (compile refuses it on
    /// an entry point that serves HTTP/2).
    pub fn apply_timeouts(&self, session: &mut Session) {
        if let Some(read) = self.timeouts.read {
            session.set_read_timeout(Some(read));
        }
        if let Some(write) = self.timeouts.write {
            session.set_write_timeout(Some(write));
        }
    }

    /// Enforces `max_header_bytes` and `underscore_headers` on a parsed request head.
    ///
    /// # Errors
    ///
    /// [`AppError::HeadersTooLarge`] for a head over `max_header_bytes`;
    /// [`AppError::BadRequest`] for a header named with an underscore under `reject`.
    pub fn check_head(&self, request: &mut RequestHeader) -> Result<(), AppError> {
        if let Some(limit) = self.max_header_bytes
            && head_bytes(request) > limit as usize
        {
            return Err(AppError::HeadersTooLarge);
        }
        if self.underscore == UnderscoreHeaders::Keep {
            return Ok(());
        }
        let underscored: Vec<_> = request
            .headers
            .keys()
            .filter(|name| name.as_str().contains('_'))
            .cloned()
            .collect();
        if underscored.is_empty() {
            return Ok(());
        }
        if self.underscore == UnderscoreHeaders::Reject {
            return Err(AppError::BadRequest(
                "a request header name contains an underscore".into(),
            ));
        }
        for name in underscored {
            request.remove_header(&name);
        }
        Ok(())
    }

    /// Answers the request with the entry point's redirect, when it has one. The target is the
    /// request's own host, path and query on the target entry point's scheme and port, built by
    /// the same [`Origin`] and checked by the same guard as the redirect middlewares: the host
    /// must be a valid host, and a control character anywhere is a `400`. Call it after the
    /// path is normalized and the forwarded view is settled, before routing. `true` when the
    /// request was answered.
    ///
    /// # Errors
    ///
    /// Fails when the response cannot be written.
    pub async fn redirect(
        &self,
        session: &mut Session,
        forwarded: &ForwardedView,
    ) -> pingora::Result<bool> {
        let Some(redirect) = &self.redirect else {
            return Ok(false);
        };
        let decision = if session.req_header().uri.path().starts_with('/') {
            match Origin::of(session, forwarded) {
                Ok(origin) => Decision::target(&origin.with(redirect.scheme, redirect.port)),
                Err(refused) => Decision::Refuse(refused),
            }
        } else {
            let err = AppError::BadRequest("a redirect needs an absolute path".into());
            respond::write_error(session, &err).await?;
            return Ok(true);
        };
        redirect::answer(session, redirect.permanent, decision).await?;
        Ok(true)
    }

    /// The ways this policy is less strict than `before`, as [`kind`]s.
    #[must_use]
    pub fn relaxations(&self, before: &Self) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if self.allow_encoded_slash && !before.allow_encoded_slash {
            kinds.push(kind::ALLOW_ENCODED_SLASH);
        }
        if strictness(self.underscore) < strictness(before.underscore) {
            kinds.push(kind::UNDERSCORE_HEADERS_RELAXED);
        }
        let https = |policy: &Self| {
            policy
                .redirect
                .as_ref()
                .is_some_and(|r| r.scheme == "https")
        };
        if https(before) && !https(self) {
            kinds.push(kind::ENTRY_POINT_HTTPS_REDIRECT_REMOVED);
        }
        kinds
    }
}

fn strictness(strategy: UnderscoreHeaders) -> u8 {
    match strategy {
        UnderscoreHeaders::Keep => 0,
        UnderscoreHeaders::Delete => 1,
        UnderscoreHeaders::Reject => 2,
    }
}

/// The size of the request head as an HTTP/1 client sent it: request line, every header with its
/// separator and line break, and the blank line.
fn head_bytes(request: &RequestHeader) -> usize {
    // " HTTP/1.1\r\n": the version is not kept for HTTP/2, which has no request line; the same
    // 11 bytes stand for its pseudo-headers.
    const LINE_FRAMING: usize = 11;
    let line = request.method.as_str().len() + 1 + request.raw_path().len() + LINE_FRAMING;
    let headers: usize = request
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + HEADER_FRAMING)
        .sum();
    line + headers + 2
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectConfig {
    to: Box<str>,
    #[serde(default)]
    permanent: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeoutsConfig {
    read_secs: Option<u32>,
    write_secs: Option<u32>,
    idle_secs: Option<u32>,
    header_secs: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Http2Config {
    max_concurrent_streams: Option<u32>,
}

fn parse<T: for<'de> Deserialize<'de>>(
    value: &Value,
    code: &'static str,
    field: &str,
) -> Result<T, Invalid> {
    serde_json::from_value(value.clone())
        .map_err(|err| Invalid::new(code, format!("{field}: {err}")))
}

fn unsupported(field: &str, why: &str) -> Invalid {
    Invalid::new("unsupported_setting", format!("{field}: {why}"))
}

fn seconds(field: &str, secs: u32) -> Result<Duration, Invalid> {
    if (1..=MAX_SECS).contains(&secs) {
        Ok(Duration::from_secs(u64::from(secs)))
    } else {
        Err(Invalid::new(
            "invalid_timeouts",
            format!("{field} must be 1 to {MAX_SECS} seconds, got {secs}"),
        ))
    }
}

/// Compiles the policy of one entry point, or lists every reason it cannot be applied.
fn compile_one(
    policy: &EntryPointPolicy,
    context: &CompileContext,
    redirect_targets: &HashMap<&str, &str>,
) -> Result<Policy, Vec<Invalid>> {
    let mut problems = Vec::new();
    let mut compiled = Policy::default();
    let name = &*policy.name;
    let protocol = context.protocol_of(name);
    let serves_http = protocol.is_none_or(Protocol::is_http);
    let serves_h2 = protocol == Some(Protocol::Https);
    let carries_http_policy = policy.redirect.is_some()
        || policy.timeouts.is_some()
        || policy.http2.is_some()
        || policy.allow_encoded_slash == Some(true)
        || policy.max_header_bytes.is_some()
        || policy.underscore_headers.is_some();
    if !serves_http && carries_http_policy {
        problems.push(Invalid::new(
            "entry_point_protocol",
            format!(
                "entry point {name} is {}: redirect, timeouts, http2, allow_encoded_slash, \
                 max_header_bytes and underscore_headers are for http and https entry points",
                protocol.map_or("not http", Protocol::as_str)
            ),
        ));
        return Err(problems);
    }
    if let Some(value) = &policy.timeouts {
        match parse::<TimeoutsConfig>(value, "invalid_timeouts", "timeouts") {
            Err(invalid) => problems.push(invalid),
            Ok(config) => {
                if config.header_secs.is_some() {
                    problems.push(unsupported(
                        "timeouts.header_secs",
                        "Pingora 0.9 has no separate request-header timeout: its HTTP/1 parser \
                         reads the head under the keep-alive timeout, one value for the wait for \
                         the first byte and for every read after it (`timeouts.idle_secs`), and \
                         HTTP/2 headers arrive in frames with no timeout",
                    ));
                }
                if let Some(secs) = config.read_secs {
                    if serves_h2 {
                        problems.push(unsupported(
                            "timeouts.read_secs",
                            "Pingora 0.9 reads an HTTP/2 request body with no timeout \
                             (`set_read_timeout` is a no-op for HTTP/2), and a TLS entry point \
                             serves HTTP/2",
                        ));
                    } else {
                        match seconds("timeouts.read_secs", secs) {
                            Ok(read) => compiled.timeouts.read = Some(read),
                            Err(invalid) => problems.push(invalid),
                        }
                    }
                }
                for (field, secs, slot) in [
                    (
                        "timeouts.write_secs",
                        config.write_secs,
                        &mut compiled.timeouts.write,
                    ),
                    (
                        "timeouts.idle_secs",
                        config.idle_secs,
                        &mut compiled.timeouts.idle,
                    ),
                ] {
                    if let Some(secs) = secs {
                        match seconds(field, secs) {
                            Ok(value) => *slot = Some(value),
                            Err(invalid) => problems.push(invalid),
                        }
                    }
                }
            }
        }
    }
    if let Some(value) = &policy.http2 {
        match parse::<Http2Config>(value, "invalid_http2", "http2") {
            Err(invalid) => problems.push(invalid),
            Ok(config) => {
                if let Some(streams) = config.max_concurrent_streams {
                    if !serves_h2 {
                        problems.push(unsupported(
                            "http2.max_concurrent_streams",
                            "this entry point does not serve HTTP/2: only a TLS entry point \
                             negotiates it, and Pingora's h2c is not enabled",
                        ));
                    } else if (1..=MAX_STREAMS).contains(&streams) {
                        compiled.h2_streams = Some(streams);
                    } else {
                        problems.push(Invalid::new(
                            "invalid_http2",
                            format!(
                                "http2.max_concurrent_streams must be 1 to {MAX_STREAMS}, got {streams}"
                            ),
                        ));
                    }
                }
            }
        }
    }
    match policy.max_header_bytes {
        Some(0) => problems.push(Invalid::new(
            "invalid_max_header_bytes",
            "max_header_bytes must be at least 1",
        )),
        Some(bytes) if bytes > MAX_HEADER_BYTES => problems.push(unsupported(
            "max_header_bytes",
            &format!(
                "Pingora 0.9's HTTP/1 parser refuses a request head over {MAX_HEADER_BYTES} \
                 bytes and nothing raises it, so {bytes} cannot be honoured"
            ),
        )),
        Some(bytes) => compiled.max_header_bytes = Some(bytes),
        None => {}
    }
    compiled.allow_encoded_slash = policy.allow_encoded_slash == Some(true);
    compiled.underscore = policy.underscore_headers.unwrap_or_default();
    if let Some(value) = &policy.redirect {
        match redirect_of(value, name, context, redirect_targets) {
            Ok(redirect) => compiled.redirect = Some(redirect),
            Err(invalid) => problems.push(invalid),
        }
    }
    if problems.is_empty() {
        Ok(compiled)
    } else {
        Err(problems)
    }
}

fn redirect_of(
    value: &Value,
    from: &str,
    context: &CompileContext,
    targets: &HashMap<&str, &str>,
) -> Result<Redirect, Invalid> {
    let config: RedirectConfig = parse(value, "invalid_redirect", "redirect")?;
    let to = &*config.to;
    if to == from {
        return Err(Invalid::new(
            "redirect_loop",
            format!("entry point {from} redirects to itself"),
        ));
    }
    let scheme = match context.protocol_of(to) {
        None => {
            return Err(Invalid::new(
                "unknown_entry_point",
                format!("redirect.to names entry point {to}, which this node does not bind"),
            ));
        }
        Some(Protocol::Http) => "http",
        Some(Protocol::Https) => "https",
        Some(other) => {
            return Err(Invalid::new(
                "entry_point_protocol",
                format!(
                    "redirect.to names entry point {to}, which is {}: a redirect goes to an http or https entry point",
                    other.as_str()
                ),
            ));
        }
    };
    if let Some(cycle) = cycle_through(from, targets) {
        return Err(Invalid::new(
            "redirect_loop",
            format!("entry points redirect in a circle: {}", cycle.join(" -> ")),
        ));
    }
    let addr = context.addr_of(to).ok_or_else(|| {
        Invalid::new(
            "invalid_redirect",
            format!("the node did not tell the compiler where entry point {to} listens"),
        )
    })?;
    let default = if scheme == "https" { 443 } else { 80 };
    Ok(Redirect {
        to: config.to,
        scheme,
        port: Some(addr.port()).filter(|port| *port != default),
        permanent: config.permanent,
    })
}

/// The entry points a redirect starting at `start` visits, closed by `start` again, when it comes
/// back to it. Follows `targets` (entry point to the entry point it redirects to).
fn cycle_through<'a>(start: &'a str, targets: &HashMap<&'a str, &'a str>) -> Option<Vec<&'a str>> {
    let mut path = vec![start];
    let mut at = start;
    while let Some(&next) = targets.get(at) {
        path.push(next);
        if next == start {
            return Some(path);
        }
        if path.len() > targets.len() + 1 {
            return None;
        }
        at = next;
    }
    None
}

/// The `redirect.to` of every policy that has a readable one.
fn redirect_targets(policies: &[EntryPointPolicy]) -> HashMap<&str, &str> {
    policies
        .iter()
        .filter_map(|policy| {
            let to = policy.redirect.as_ref()?.get("to")?.as_str()?;
            Some((&*policy.name, to))
        })
        .collect()
}

/// Every reason an entry point policy of `policies` cannot be applied by a process that bound
/// `context`, with the entry point it is about. An entry point the process did not bind is the
/// caller's `unknown_entry_point`, not repeated here.
#[must_use]
pub fn check_all(
    policies: &[EntryPointPolicy],
    context: &CompileContext,
) -> Vec<(Box<str>, Invalid)> {
    let targets = redirect_targets(policies);
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for policy in policies {
        if !seen.insert(&*policy.name) || !context.knows(&policy.name) {
            continue;
        }
        if let Err(problems) = compile_one(policy, context, &targets) {
            found.extend(
                problems
                    .into_iter()
                    .map(|invalid| (policy.name.clone(), invalid)),
            );
        }
    }
    found
}

/// The compiled policy of every entry point of `snapshot` that has one. A policy that cannot be
/// applied is left out; [`check_all`] refused such a snapshot before a table is built from it.
#[must_use]
pub fn build(snapshot: &Snapshot, context: &CompileContext) -> HashMap<Box<str>, Policy> {
    let targets = redirect_targets(&snapshot.entry_points);
    snapshot
        .entry_points
        .iter()
        .filter_map(|policy| {
            let compiled = compile_one(policy, context, &targets).ok()?;
            Some((policy.name.clone(), compiled))
        })
        .collect()
}

/// The posture changes between two tables' entry point policies: the entry point and what got
/// less strict. An entry point that lost its policy is compared with [`Policy::none`].
#[must_use]
pub fn relaxations(live: &RoutingTable, candidate: &RoutingTable) -> Vec<(Box<str>, &'static str)> {
    let names: BTreeSet<&str> = live
        .entry_policies()
        .chain(candidate.entry_policies())
        .map(|(name, _)| name)
        .collect();
    names
        .into_iter()
        .flat_map(|name| {
            candidate
                .entry_policy(name)
                .relaxations(live.entry_policy(name))
                .into_iter()
                .map(move |kind| (Box::from(name), kind))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn policies(list: Value) -> Vec<EntryPointPolicy> {
        serde_json::from_value(list).expect("policies")
    }

    fn context() -> CompileContext {
        CompileContext::of_entry_points(
            &super::super::parse_list("web=0.0.0.0:80/http,sec=0.0.0.0:8443/https,db=0.0.0.0:5432/tcp,other=0.0.0.0:8080/http")
                .expect("entry points"),
        )
    }

    fn codes(list: Value) -> Vec<&'static str> {
        check_all(&policies(list), &context())
            .into_iter()
            .map(|(_, invalid)| invalid.code)
            .collect()
    }

    #[test]
    fn a_policy_without_settings_compiles_to_nothing() {
        let list = policies(json!([{ "name": "web" }]));
        let compiled = build(
            &Snapshot {
                entry_points: list,
                ..Snapshot::default()
            },
            &context(),
        );
        assert_eq!(compiled.get("web"), Some(&Policy::default()));
    }

    #[test]
    fn the_redirect_target_comes_from_the_bound_address() {
        let snapshot = Snapshot {
            entry_points: policies(json!([
                { "name": "web", "redirect": { "to": "sec" } },
                { "name": "other", "redirect": { "to": "web", "permanent": true } },
            ])),
            ..Snapshot::default()
        };
        let compiled = build(&snapshot, &context());
        let to_sec = compiled["web"].redirect_to().expect("redirect");
        assert_eq!(
            (
                to_sec.to(),
                to_sec.scheme(),
                to_sec.port(),
                to_sec.status_for(&Method::GET)
            ),
            ("sec", "https", Some(8443), 302)
        );
        let to_web = compiled["other"].redirect_to().expect("redirect");
        assert_eq!(
            (
                to_web.scheme(),
                to_web.port(),
                to_web.status_for(&Method::GET)
            ),
            ("http", None, 301)
        );
    }

    #[test]
    fn a_circle_of_any_length_is_found() {
        let two = codes(json!([
            { "name": "web", "redirect": { "to": "other" } },
            { "name": "other", "redirect": { "to": "web" } },
        ]));
        assert_eq!(two, ["redirect_loop", "redirect_loop"]);
        let three = codes(json!([
            { "name": "web", "redirect": { "to": "other" } },
            { "name": "other", "redirect": { "to": "sec" } },
            { "name": "sec", "redirect": { "to": "web" } },
        ]));
        assert_eq!(three, ["redirect_loop"; 3]);
        assert_eq!(
            codes(json!([{ "name": "web", "redirect": { "to": "web" } }])),
            ["redirect_loop"]
        );
        let chain = codes(json!([
            { "name": "web", "redirect": { "to": "other" } },
            { "name": "other", "redirect": { "to": "sec" } },
        ]));
        assert!(chain.is_empty(), "a chain is not a loop: {chain:?}");
    }

    #[test]
    fn every_knob_is_checked_against_what_pingora_can_do() {
        let cases = [
            (
                json!({ "name": "web", "timeouts": { "header_secs": 5 } }),
                "unsupported_setting",
            ),
            (
                json!({ "name": "sec", "timeouts": { "read_secs": 5 } }),
                "unsupported_setting",
            ),
            (
                json!({ "name": "web", "timeouts": { "read_secs": 0 } }),
                "invalid_timeouts",
            ),
            (
                json!({ "name": "web", "timeouts": { "idle_secs": 3601 } }),
                "invalid_timeouts",
            ),
            (
                json!({ "name": "web", "timeouts": { "typo": 1 } }),
                "invalid_timeouts",
            ),
            (
                json!({ "name": "web", "http2": { "max_concurrent_streams": 10 } }),
                "unsupported_setting",
            ),
            (
                json!({ "name": "sec", "http2": { "max_concurrent_streams": 0 } }),
                "invalid_http2",
            ),
            (
                json!({ "name": "web", "max_header_bytes": 0 }),
                "invalid_max_header_bytes",
            ),
            (
                json!({ "name": "web", "max_header_bytes": 2_000_000 }),
                "unsupported_setting",
            ),
            (
                json!({ "name": "db", "allow_encoded_slash": true }),
                "entry_point_protocol",
            ),
            (
                json!({ "name": "web", "redirect": { "to": "web", "scheme": "https" } }),
                "invalid_redirect",
            ),
            (
                json!({ "name": "web", "redirect": { "to": "db" } }),
                "entry_point_protocol",
            ),
            (
                json!({ "name": "web", "redirect": { "to": "nowhere" } }),
                "unknown_entry_point",
            ),
        ];
        for (policy, code) in cases {
            assert_eq!(codes(json!([policy.clone()])), [code], "{policy}");
        }
        let fine = codes(json!([
            { "name": "web", "timeouts": { "read_secs": 5, "write_secs": 5, "idle_secs": 5 }, "max_header_bytes": 8192 },
            { "name": "sec", "timeouts": { "write_secs": 5, "idle_secs": 5 }, "http2": { "max_concurrent_streams": 50 } },
        ]));
        assert!(fine.is_empty(), "{fine:?}");
    }

    #[test]
    fn a_redirect_needs_an_address_for_its_target() {
        let bare = CompileContext::default();
        let list = policies(json!([{ "name": "web", "redirect": { "to": "websecure" } }]));
        let problems = check_all(&list, &bare);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].1.code, "invalid_redirect");
    }

    fn head(path: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        for (name, value) in headers {
            request
                .append_header((*name).to_owned(), *value)
                .expect("header");
        }
        request
    }

    #[test]
    fn the_head_size_counts_the_line_and_every_header() {
        let request = head("/a", &[("Host", "a.test"), ("X-A", "1")]);
        // "GET /a HTTP/1.1\r\n" 17, "Host: a.test\r\n" 14, "x-a: 1\r\n" 8, "\r\n" 2.
        assert_eq!(head_bytes(&request), 17 + 14 + 8 + 2);
    }

    #[test]
    fn underscore_headers_are_kept_deleted_or_rejected() {
        let underscored = [
            ("Host", "a.test"),
            ("X_Forwarded_For", "1.2.3.4"),
            ("X-Ok", "1"),
        ];
        let strategy = |underscore| Policy {
            underscore,
            ..Policy::default()
        };
        let mut kept = head("/", &underscored);
        strategy(UnderscoreHeaders::Keep)
            .check_head(&mut kept)
            .expect("keep");
        assert!(kept.headers.contains_key("x_forwarded_for"));
        let mut deleted = head("/", &underscored);
        strategy(UnderscoreHeaders::Delete)
            .check_head(&mut deleted)
            .expect("delete");
        assert!(!deleted.headers.contains_key("x_forwarded_for"));
        assert!(deleted.headers.contains_key("x-ok") && deleted.headers.contains_key("host"));
        let mut rejected = head("/", &underscored);
        let err = strategy(UnderscoreHeaders::Reject)
            .check_head(&mut rejected)
            .expect_err("reject");
        assert_eq!(err.status().as_u16(), 400);
        let mut clean = head("/", &[("Host", "a.test")]);
        strategy(UnderscoreHeaders::Reject)
            .check_head(&mut clean)
            .expect("clean");
    }

    #[test]
    fn an_oversized_head_is_refused_with_431() {
        let policy = Policy {
            max_header_bytes: Some(64),
            ..Policy::default()
        };
        let mut small = head("/", &[("Host", "a.test")]);
        policy.check_head(&mut small).expect("small");
        let long = "x".repeat(100);
        let mut big = head("/", &[("Host", "a.test"), ("X-Long", long.as_str())]);
        let err = policy.check_head(&mut big).expect_err("big");
        assert_eq!(err.status().as_u16(), 431);
    }

    #[test]
    fn relaxations_name_what_got_weaker() {
        let strict = Policy {
            underscore: UnderscoreHeaders::Reject,
            ..Policy::default()
        };
        let loose = Policy {
            allow_encoded_slash: true,
            underscore: UnderscoreHeaders::Keep,
            ..Policy::default()
        };
        assert_eq!(
            loose.relaxations(&strict),
            [kind::ALLOW_ENCODED_SLASH, kind::UNDERSCORE_HEADERS_RELAXED]
        );
        assert!(strict.relaxations(&loose).is_empty());
        assert!(Policy::default().relaxations(Policy::none()).is_empty());
    }
}
