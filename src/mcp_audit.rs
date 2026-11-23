//! The MCP audit log: one record for every `tools/call` an `mcp_gateway` handles, kept
//! in memory per app for the operator and, with `MCP_AUDIT_FILE`, appended to a file. Full
//! reference: `docs/ref/mcp-audit.md`.
//!
//! # What is kept
//!
//! A [`Record`] says who called which tool of which server, how it ended and how long it took. It
//! never holds a result. It holds the call's `arguments` only when the gateway sets
//! `record_arguments`, at most [`ARGS_CAP`] bytes, with every value under a key that looks secret
//! ([`looks_secret`]) replaced by `[redacted]` before anything is stored. The caller is its
//! verified `sub` and the MCP session appears only as a hash.
//!
//! # Where it goes
//!
//! [`Audit::record`] pushes the record into the ring of its app ([`RING_CAP`] records, and at
//! most [`TENANT_BYTES`] retained by all rings of one tenant) and, when a file is configured,
//! into a bounded queue a background writer drains ([`crate::observe::access_log::LineQueue`]),
//! so a sink that stalls costs lines, never latency. The rings are for the operator's admin
//! socket only (`crate::admin`); a ring remembers its tenant and never serves another's.
//!
//! The ring is the failed-request recorder's pattern (`crate::failures`) with what an MCP call
//! needs and a failure recorder does not: an MCP error is an HTTP `200` the gateway answers
//! itself, listing pages by sequence number, and a byte bound per tenant.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::observe::access_log::{LineQueue, REDACTED, Render};
use crate::table::RoutingTable;

/// Records kept per app; the oldest is dropped first.
pub const RING_CAP: usize = 1000;

/// What all rings of one tenant may retain together, in bytes.
pub const TENANT_BYTES: usize = 8 * 1024 * 1024;

/// The most bytes of `arguments` that are parsed and kept.
pub const ARGS_CAP: usize = 16 * 1024;

/// Lines the file queue holds before it drops the oldest.
pub const QUEUE_LINES: usize = 1024;

/// The longest tool name a record keeps: what the client sent, cut.
pub const NAME_CAP: usize = 128;

/// The longest `sub` a record keeps.
pub const SUB_CAP: usize = 256;

/// Words that make a key secret, matched against the key lower-cased with `_`, `-` and spaces
/// removed. Deliberately wide: a value lost costs a `422` on replay, a value leaked costs a
/// secret.
const SECRET_WORDS: [&str; 9] = [
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "apikey",
    "credential",
    "cookie",
    "privatekey",
];

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The server answered a result.
    Ok,
    /// The server answered a result with `isError: true`.
    ToolError,
    /// A JSON-RPC error: the server's, or the gateway's for bad params and an unknown tool.
    RpcError,
    /// Authorization refused the call.
    Denied,
    /// The exchange with the server failed, or its catalog could not be had.
    UpstreamFailed,
}

/// What a record holds of the call's `arguments`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentsState {
    /// The call had none.
    Absent,
    /// Stored as sent.
    Kept,
    /// Stored, with at least one value replaced by `[redacted]`.
    Redacted,
    /// The gateway does not set `record_arguments`, or they could not be parsed.
    NotRecorded,
    /// Over [`ARGS_CAP`] bytes.
    TooLarge,
}

/// One `tools/call`.
#[derive(Debug, Serialize)]
pub struct Record {
    /// Increasing across the process, from 1; [`Audit::record`] assigns it.
    pub seq: u64,
    /// When the call finished, milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
    /// The tenant of the app.
    pub tenant: Box<str>,
    /// The app.
    pub app: Box<str>,
    /// The router that carried the request; empty for a replay.
    pub router: Box<str>,
    /// The name of the `mcp_gateway` middleware, which a replay finds the gateway by.
    pub middleware: Box<str>,
    /// The tool name the client sent, cut to [`NAME_CAP`] bytes.
    pub name: Box<str>,
    /// The registered server the name resolved to; `null` when it did not.
    pub server: Option<Box<str>>,
    /// The tool, as that server reports it; `null` when the name did not resolve.
    pub tool: Option<Box<str>>,
    /// The `sub` of the token `jwt_auth` or `oidc` verified; `null` without one.
    pub sub: Option<Box<str>>,
    /// The first 16 hex characters of the SHA-256 of the MCP session id; `null` for a replay.
    pub session: Option<Box<str>>,
    /// How the call ended.
    pub outcome: Outcome,
    /// Why, for `rpc_error` (`server`, `invalid_params`, `unknown_tool`) and `upstream_failed`
    /// (the failure code); `null` otherwise.
    pub reason: Option<&'static str>,
    /// The JSON-RPC code of an error the server answered.
    pub rpc_code: Option<i64>,
    /// From the start of handling the call to its answer.
    pub duration_ms: u64,
    /// Bytes of the client's `params`.
    pub request_bytes: u64,
    /// Bytes of the server's `result` or `error`; `0` when there was none.
    pub response_bytes: u64,
    /// What is kept of `arguments`.
    pub arguments_state: ArgumentsState,
    /// The stored arguments, `null` unless kept or redacted.
    pub arguments: Option<Box<RawValue>>,
    /// The `seq` of the record a replay sent again.
    pub replay_of: Option<u64>,
}

impl Record {
    /// A record of a call of `app` of `tenant` through the middleware `middleware` of `router`,
    /// before anything is known of its outcome: it reads as a call with bad params.
    #[must_use]
    pub fn new(tenant: &str, app: &str, router: &str, middleware: &str, name: &str) -> Self {
        Self {
            seq: 0,
            at_unix_ms: 0,
            tenant: tenant.into(),
            app: app.into(),
            router: router.into(),
            middleware: middleware.into(),
            name: cut(name, NAME_CAP).into(),
            server: None,
            tool: None,
            sub: None,
            session: None,
            outcome: Outcome::RpcError,
            reason: Some("invalid_params"),
            rpc_code: None,
            duration_ms: 0,
            request_bytes: 0,
            response_bytes: 0,
            arguments_state: ArgumentsState::Absent,
            arguments: None,
            replay_of: None,
        }
    }

    /// Notes the tool name the client sent, cut to [`NAME_CAP`] bytes.
    pub fn set_name(&mut self, name: &str) {
        self.name = cut(name, NAME_CAP).into();
    }

    /// Notes the verified `sub`, cut to [`SUB_CAP`] bytes.
    pub fn set_sub(&mut self, sub: &str) {
        self.sub = Some(cut(sub, SUB_CAP).into());
    }

    /// Notes the session by its hash; the id itself is never kept.
    pub fn set_session(&mut self, id: &str) {
        let digest = Sha256::digest(id.as_bytes());
        let mut hash = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            hash.push(char::from(HEX[usize::from(byte >> 4)]));
            hash.push(char::from(HEX[usize::from(byte & 15)]));
        }
        self.session = Some(hash.into());
    }

    /// Notes the arguments as [`arguments`] stored them.
    pub fn set_arguments(&mut self, kept: Arguments) {
        self.arguments_state = kept.state;
        self.arguments = kept.value;
    }

    /// What the record holds in memory: a bound, not an exact size.
    fn weight(&self) -> usize {
        let text = |text: &str| text.len();
        let option = |text: &Option<Box<str>>| text.as_deref().map_or(0, str::len);
        std::mem::size_of::<Self>()
            + text(&self.tenant)
            + text(&self.app)
            + text(&self.router)
            + text(&self.middleware)
            + text(&self.name)
            + option(&self.server)
            + option(&self.tool)
            + option(&self.sub)
            + option(&self.session)
            + self.arguments.as_deref().map_or(0, |raw| raw.get().len())
    }
}

impl Render for Record {
    fn render(&self, out: &mut String) {
        if let Ok(line) = serde_json::to_string(self) {
            out.push_str(&line);
            out.push('\n');
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// `text` cut to at most `max` bytes at a character boundary.
#[must_use]
pub fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

/// The arguments of a call as a record stores them.
#[derive(Debug)]
pub struct Arguments {
    /// What is kept.
    pub state: ArgumentsState,
    /// The stored value, redacted.
    pub value: Option<Box<RawValue>>,
}

/// Whether a key names a secret: lower-cased with `_`, `-` and spaces removed, it contains one of
/// `password`, `passwd`, `token`, `secret`, `authorization`, `apikey`, `credential`, `cookie` or
/// `privatekey`.
#[must_use]
pub fn looks_secret(key: &str) -> bool {
    let normal: String = key
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect();
    SECRET_WORDS.iter().any(|word| normal.contains(word))
}

/// Replaces every value under a secret-looking key, at any depth, whatever its type. Whether
/// anything was replaced.
fn scrub(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let mut changed = false;
            for (key, inner) in map.iter_mut() {
                if looks_secret(key) {
                    *inner = Value::String(REDACTED.into());
                    changed = true;
                } else {
                    changed |= scrub(inner);
                }
            }
            changed
        }
        Value::Array(items) => items.iter_mut().fold(false, |changed, inner| {
            // Not short-circuited: every element is scrubbed.
            scrub(inner) | changed
        }),
        _ => false,
    }
}

/// The arguments of a call as a record stores them. `record` is the gateway's
/// `record_arguments`. Text over [`ARGS_CAP`] bytes is never parsed.
#[must_use]
pub fn arguments(raw: Option<&RawValue>, record: bool) -> Arguments {
    let nothing = |state| Arguments { state, value: None };
    let Some(raw) = raw else {
        return nothing(ArgumentsState::Absent);
    };
    if !record {
        return nothing(ArgumentsState::NotRecorded);
    }
    if raw.get().len() > ARGS_CAP {
        return nothing(ArgumentsState::TooLarge);
    }
    let Ok(mut value) = serde_json::from_str::<Value>(raw.get()) else {
        return nothing(ArgumentsState::NotRecorded);
    };
    let redacted = scrub(&mut value);
    match serde_json::value::to_raw_value(&value) {
        Ok(value) => Arguments {
            state: if redacted {
                ArgumentsState::Redacted
            } else {
                ArgumentsState::Kept
            },
            value: Some(value),
        },
        Err(_) => nothing(ArgumentsState::NotRecorded),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// The records of one app and what it knows of the ring.
#[derive(Debug)]
struct Ring {
    tenant: Box<str>,
    records: VecDeque<Arc<Record>>,
    bytes: usize,
    /// The highest `seq` this ring has dropped.
    evicted_through: u64,
}

#[derive(Debug, Default)]
struct State {
    next: u64,
    rings: HashMap<Box<str>, Ring>,
    /// Bytes retained by all rings of each tenant.
    tenants: HashMap<Box<str>, usize>,
}

impl State {
    fn charge(&mut self, tenant: &str, bytes: usize) {
        *self.tenants.entry(tenant.into()).or_default() += bytes;
    }

    fn release(&mut self, tenant: &str, bytes: usize) {
        if let Some(held) = self.tenants.get_mut(tenant) {
            *held = held.saturating_sub(bytes);
            if *held == 0 {
                self.tenants.remove(tenant);
            }
        }
    }

    fn drop_ring(&mut self, app: &str) {
        if let Some(ring) = self.rings.remove(app) {
            self.release(&ring.tenant, ring.bytes);
        }
    }
}

/// One page of a ring.
#[derive(Debug)]
pub struct Page {
    /// The records after the cursor, oldest first.
    pub records: Vec<Arc<Record>>,
    /// The highest `seq` the ring has dropped; a reader whose cursor is below it lost records.
    pub evicted_through: u64,
}

/// The file queue's counters, for `GET /metrics`.
static FILE: OnceLock<LineQueue<Record>> = OnceLock::new();

/// The audit log: the rings and, when `MCP_AUDIT_FILE` is set, the queue to the file. Cheap to
/// clone; every clone is the same log.
#[derive(Debug, Clone, Default)]
pub struct Audit {
    state: Arc<Mutex<State>>,
    file: Option<LineQueue<Record>>,
}

impl Audit {
    /// An audit log with rings only.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An audit log that also queues every record for a file writer, from `queue`; see
    /// [`Self::queue`].
    #[must_use]
    pub fn with_file(mut self, queue: LineQueue<Record>) -> Self {
        // The first queue of the process feeds the metrics; a second exists only in a test.
        let _ = FILE.set(queue.clone());
        self.file = Some(queue);
        self
    }

    /// The queue the file writer drains: [`QUEUE_LINES`] lines.
    #[must_use]
    pub fn queue() -> LineQueue<Record> {
        LineQueue::with_capacity(QUEUE_LINES)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stores `record` as the newest of its app, assigning `seq` and the time, and queues it for
    /// the file. A ring of the same app id that belongs to another tenant is replaced. Returns
    /// the stored record.
    #[must_use]
    pub fn record(&self, mut record: Record) -> Arc<Record> {
        record.at_unix_ms = now_unix_ms();
        let weight = record.weight();
        let stored = {
            let mut state = self.lock();
            state.next += 1;
            record.seq = state.next;
            let stored = Arc::new(record);
            if state
                .rings
                .get(&*stored.app)
                .is_some_and(|ring| ring.tenant != stored.tenant)
            {
                state.drop_ring(&stored.app);
            }
            state.charge(&stored.tenant, weight);
            let held = state.tenants.get(&*stored.tenant).copied().unwrap_or(0);
            let ring = state
                .rings
                .entry(stored.app.clone())
                .or_insert_with(|| Ring {
                    tenant: stored.tenant.clone(),
                    records: VecDeque::new(),
                    bytes: 0,
                    evicted_through: 0,
                });
            ring.records.push_back(Arc::clone(&stored));
            ring.bytes += weight;
            // The new record always stays: a ring is trimmed to the count, and to its tenant's
            // bytes, from its own oldest end.
            let mut freed = 0;
            while ring.records.len() > 1
                && (ring.records.len() > RING_CAP || held - freed > TENANT_BYTES)
            {
                if let Some(old) = ring.records.pop_front() {
                    ring.evicted_through = old.seq;
                    freed += old.weight();
                }
            }
            ring.bytes -= freed;
            state.release(&stored.tenant, freed);
            stored
        };
        if let Some(file) = &self.file {
            file.record(Arc::clone(&stored));
        }
        stored
    }

    /// Up to `limit` records of `app` after `after`, oldest first. A ring of another tenant is
    /// never read: it is empty.
    #[must_use]
    pub fn list(&self, app: &str, tenant: &str, after: u64, limit: usize) -> Page {
        let state = self.lock();
        let Some(ring) = state.rings.get(app).filter(|ring| &*ring.tenant == tenant) else {
            return Page {
                records: Vec::new(),
                evicted_through: 0,
            };
        };
        let start = ring.records.partition_point(|record| record.seq <= after);
        Page {
            records: ring
                .records
                .iter()
                .skip(start)
                .take(limit)
                .cloned()
                .collect(),
            evicted_through: ring.evicted_through,
        }
    }

    /// The record `seq` of `app`, when the ring belongs to `tenant`.
    #[must_use]
    pub fn get(&self, app: &str, tenant: &str, seq: u64) -> Option<Arc<Record>> {
        let state = self.lock();
        let ring = state
            .rings
            .get(app)
            .filter(|ring| &*ring.tenant == tenant)?;
        let at = ring.records.partition_point(|record| record.seq < seq);
        ring.records
            .get(at)
            .filter(|record| record.seq == seq)
            .cloned()
    }

    /// Drops the rings of apps `table` does not have, and of apps it now gives to another
    /// tenant, so apps that come and go cannot grow the log without bound or hand their records
    /// on.
    pub fn retain_apps(&self, table: &RoutingTable) {
        let live: HashMap<&str, &str> = crate::failures::apps(table)
            .map(|app| (app.id(), app.tenant()))
            .collect();
        let mut state = self.lock();
        let gone: Vec<Box<str>> = state
            .rings
            .iter()
            .filter(|(app, ring)| {
                live.get(&***app)
                    .is_none_or(|tenant| *tenant != &*ring.tenant)
            })
            .map(|(app, _)| app.clone())
            .collect();
        for app in gone {
            state.drop_ring(&app);
        }
    }

    /// Records held and bytes retained, for a test.
    #[cfg(test)]
    fn totals(&self) -> (usize, usize) {
        let state = self.lock();
        (
            state.rings.values().map(|ring| ring.records.len()).sum(),
            state.tenants.values().sum(),
        )
    }
}

/// `podgate_mcp_audit_lines_total` and `podgate_mcp_audit_dropped_total`, when the process
/// writes an audit file.
pub fn render(out: &mut String) {
    let Some(queue) = FILE.get() else { return };
    out.push_str(&format!(
        "# HELP podgate_mcp_audit_lines_total MCP audit records written to MCP_AUDIT_FILE.\n\
         # TYPE podgate_mcp_audit_lines_total counter\n\
         podgate_mcp_audit_lines_total {}\n\
         # HELP podgate_mcp_audit_dropped_total MCP audit records dropped because the queue was full or the file could not be written.\n\
         # TYPE podgate_mcp_audit_dropped_total counter\n\
         podgate_mcp_audit_dropped_total {}\n",
        queue.written(),
        queue.dropped(),
    ));
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn record(tenant: &str, app: &str) -> Record {
        Record::new(tenant, app, "r", "tools", "alpha__search")
    }

    fn raw(value: &Value) -> Box<RawValue> {
        serde_json::value::to_raw_value(value).expect("raw")
    }

    #[test]
    fn mcp_audit_redacts_secret_keys() {
        let kept = arguments(
            Some(&raw(&json!({
                "query": "cats",
                "Password": "p",
                "nested": {"API_KEY": "k", "list": [{"auth-token": "t", "ok": 1}], "x": {"y": {"Secret": [1, 2]}}},
                "Authorization": {"scheme": "Bearer", "value": "v"},
                "max_tokens": 5,
                "private key": "pk",
                "cookies": "c",
                "credentials": {"u": 1},
                "passwd": "q",
            }))),
            true,
        );
        assert_eq!(kept.state, ArgumentsState::Redacted);
        let value: Value = serde_json::from_str(kept.value.expect("kept").get()).expect("json");
        assert_eq!(value["query"], "cats");
        assert_eq!(value["Password"], REDACTED);
        assert_eq!(value["nested"]["API_KEY"], REDACTED);
        assert_eq!(value["nested"]["list"][0]["auth-token"], REDACTED);
        assert_eq!(value["nested"]["list"][0]["ok"], 1);
        assert_eq!(value["nested"]["x"]["y"]["Secret"], REDACTED);
        assert_eq!(
            value["Authorization"], REDACTED,
            "an object is replaced whole"
        );
        assert_eq!(
            value["max_tokens"], REDACTED,
            "the match is deliberately wide"
        );
        assert_eq!(value["private key"], REDACTED);
        assert_eq!(value["cookies"], REDACTED);
        assert_eq!(value["credentials"], REDACTED);
        assert_eq!(value["passwd"], REDACTED);

        let plain = arguments(Some(&raw(&json!({"a": [1, {"b": "c"}]}))), true);
        assert_eq!(plain.state, ArgumentsState::Kept);
        assert!(!looks_secret("query") && !looks_secret("path") && !looks_secret("name"));
    }

    #[test]
    fn mcp_audit_arguments_over_cap_not_kept() {
        let big = raw(&json!({"text": "x".repeat(ARGS_CAP)}));
        assert!(big.get().len() > ARGS_CAP);
        let kept = arguments(Some(&big), true);
        assert_eq!(kept.state, ArgumentsState::TooLarge);
        assert!(kept.value.is_none());
        let off = arguments(Some(&raw(&json!({"a": 1}))), false);
        assert_eq!(off.state, ArgumentsState::NotRecorded);
        assert!(off.value.is_none());
        assert_eq!(arguments(None, true).state, ArgumentsState::Absent);
    }

    #[test]
    fn mcp_audit_ring_bounded() {
        let audit = Audit::new();
        for _ in 0..RING_CAP + 25 {
            let _ = audit.record(record("t1", "a"));
        }
        let page = audit.list("a", "t1", 0, RING_CAP + 100);
        assert_eq!(page.records.len(), RING_CAP);
        assert_eq!(page.records[0].seq, 26);
        assert_eq!(page.evicted_through, 25);
        let (count, bytes) = audit.totals();
        assert_eq!(count, RING_CAP);
        assert!(bytes > 0);
        // The ring of another app is not affected.
        let _ = audit.record(record("t1", "b"));
        assert_eq!(
            audit.list("a", "t1", 0, RING_CAP + 100).records.len(),
            RING_CAP
        );
    }

    #[test]
    fn mcp_audit_tenant_bytes_bounded() {
        let audit = Audit::new();
        let mut big = record("t1", "noisy");
        big.arguments = Some(raw(&json!({"text": "x".repeat(ARGS_CAP - 64)})));
        let weight = big.weight();
        let mut quiet = record("t1", "quiet");
        quiet.name = "quiet".into();
        let _ = audit.record(quiet);
        let fits = TENANT_BYTES / weight;
        for _ in 0..fits * 2 {
            let mut next = record("t1", "noisy");
            next.arguments = big.arguments.clone();
            let _ = audit.record(next);
        }
        let (_, bytes) = audit.totals();
        assert!(bytes <= TENANT_BYTES + weight, "{bytes} bytes retained");
        let noisy = audit.list("noisy", "t1", 0, RING_CAP);
        assert!(noisy.records.len() < fits * 2, "the noisy ring was trimmed");
        assert!(noisy.evicted_through > 0);
        assert_eq!(
            audit.list("quiet", "t1", 0, RING_CAP).records.len(),
            1,
            "another app's records are not evicted"
        );
        // A tenant is bounded alone.
        let _ = audit.record(record("t2", "other"));
        assert_eq!(audit.list("other", "t2", 0, 10).records.len(), 1);
    }

    #[test]
    fn mcp_audit_ring_is_keyed_by_tenant() {
        let audit = Audit::new();
        let first = audit.record(record("t1", "a"));
        assert!(audit.list("a", "t2", 0, 10).records.is_empty());
        assert!(audit.get("a", "t2", first.seq).is_none());
        assert!(audit.get("a", "t1", first.seq).is_some());
        // The app id is handed to another tenant: the new tenant starts empty.
        let second = audit.record(record("t2", "a"));
        assert!(audit.list("a", "t1", 0, 10).records.is_empty());
        assert!(audit.get("a", "t1", first.seq).is_none());
        let seen = audit.list("a", "t2", 0, 10);
        assert_eq!(seen.records.len(), 1);
        assert_eq!(seen.records[0].seq, second.seq);
        let (count, bytes) = audit.totals();
        assert_eq!(count, 1);
        assert_eq!(
            bytes,
            second.weight(),
            "the old tenant's bytes were released"
        );
    }

    #[test]
    fn mcp_audit_list_pages_by_seq() {
        let audit = Audit::new();
        let seqs: Vec<u64> = (0..5)
            .map(|_| audit.record(record("t1", "a")).seq)
            .collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
        let page = audit.list("a", "t1", 2, 2);
        assert_eq!(
            page.records.iter().map(|r| r.seq).collect::<Vec<_>>(),
            [3, 4]
        );
        assert!(audit.list("a", "t1", 5, 2).records.is_empty());
        assert_eq!(audit.get("a", "t1", 4).map(|r| r.seq), Some(4));
        assert!(audit.get("a", "t1", 9).is_none());
    }

    #[test]
    fn mcp_audit_session_and_names_are_cut_and_hashed() {
        let mut one = Record::new("t", "a", "r", "m", &"é".repeat(200));
        assert!(one.name.len() <= NAME_CAP);
        assert!(one.name.is_char_boundary(one.name.len()));
        one.set_session("0123456789abcdef0123456789abcdef");
        let hash = one.session.clone().expect("hash");
        assert_eq!(hash.len(), 16);
        assert!(!hash.contains("0123456789abcdef0123"));
        one.set_sub(&"s".repeat(400));
        assert_eq!(one.sub.as_deref().map(str::len), Some(SUB_CAP));
        let mut text = String::new();
        one.render(&mut text);
        assert!(text.ends_with('\n') && text.matches('\n').count() == 1);
        let line: Value = serde_json::from_str(&text).expect("json line");
        assert_eq!(line["outcome"], "rpc_error");
        assert!(line["arguments"].is_null());
    }
}
