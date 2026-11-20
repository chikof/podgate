//! WASM request filters: an app attaches proxy-wasm modules that run on the request headers,
//! without being able to hurt the proxy or other tenants.
//!
//! # Lifecycle
//!
//! The engine behind the `wasm` middleware ([`crate::middleware::wasm`]). Each `wasm` middleware
//! of a snapshot is decoded, validated and compiled once, in
//! [`RoutingTable::compile`](crate::table::RoutingTable::compile). A module that is not valid
//! WebAssembly, lacks a required export, imports anything podgate does not provide, or declares
//! more initial memory than its `max_memory_bytes` rejects the whole snapshot with `422`, code
//! `wasm_invalid` or `wasm_forbidden_import`. Compiled modules live in the immutable routing
//! table, so a request keeps the filters it started with.
//!
//! Per request, in the middleware chain, [`run_filter`] runs the filter. Every run gets a fresh
//! `Store` and instance: nothing carries over between requests or filters.
//!
//! - Fuel: the store starts with `fuel` units. Running out traps the guest.
//! - Memory: a `ResourceLimiter` ([`StoreLimits`]) caps every linear memory at
//!   `max_memory_bytes`. A `memory.grow` past it traps the guest (it does not return
//!   `-1`, so a filter that ignores the result is stopped too). Modules that declare a larger
//!   initial memory never get past snapshot compile.
//! - Any trap, failed call or `false` from `proxy_on_vm_start` or `proxy_on_configure` answers
//!   the request `500 {"error": "internal error"}` and logs the cause. Other requests are
//!   unaffected.
//! - Where it runs: on tokio's blocking pool (`spawn_blocking`), not on the proxy's reactor
//!   threads. Fuel bounds a run, but a large budget can still take milliseconds to seconds, and
//!   the proxy must keep serving other connections meanwhile.
//! - What bounds it: an [`Executor`] (see the `executor` submodule). A run needs one of
//!   `WASM_MAX_CONCURRENT` worker permits, waiting at most `WASM_QUEUE_TIMEOUT_MS`, so filters
//!   never take more than that many threads of the blocking pool that snapshot compiles share.
//!   It also reserves the filter's `max_memory_bytes` from the tenant's `max_buffer_bytes`
//!   (the budget response compression also draws on, 640 KiB per compressed response) before
//!   the store is created, and holds the charge until the run ends. A request that gets no
//!   permit in time, or whose tenant cannot afford the memory, answers
//!   `503` with `retry-after: 1` (`wasm filter pool is busy`, `wasm filter memory is over the
//!   tenant's budget`); the filter does not run, not even partly. Only the pool-busy refusal is a
//!   capacity refusal that auto-revert ignores (see [`AppError::is_capacity_refusal`]).
//!
//! # The host ABI (proxy-wasm 0.2.x subset)
//!
//! The filter is a proxy-wasm module, built for `wasm32-unknown-unknown` or `wasm32-wasip1`.
//! The imports below are the whole host surface. From module `env`: the proxy-wasm functions
//! in the table. From `wasi_snapshot_preview1`: a few harmless stubs (clocks, entropy, empty
//! environment and arguments, `fd_write` to the log, `proc_exit` as a trap), listed in the
//! `wasi` submodule. There are no sockets, no files, no shared data, no callouts. Statuses are
//! the proxy-wasm `WasmResult` codes: `0` ok, `1` not found, `2` bad argument, `6` invalid
//! memory access, `10` internal failure.
//!
//! | Import | Behaviour |
//! |---|---|
//! | `proxy_log(level, msg_ptr, msg_len)` | `tracing` event tagged with `app` and `tenant`; a run logs at most 32 lines and 4 KiB of payload in total, the rest is cut (`truncated = true`) |
//! | `proxy_get_header_map_value(map, key_ptr, key_len, out_ptr, out_len)` | values of one header, joined with `,` |
//! | `proxy_get_header_map_pairs(map, out_ptr, out_len)` | all headers, serialized as in proxy-wasm |
//! | `proxy_add_header_map_value(map, key_ptr, key_len, val_ptr, val_len)` | append a header |
//! | `proxy_replace_header_map_value(map, key_ptr, key_len, val_ptr, val_len)` | replace all values of a header |
//! | `proxy_remove_header_map_value(map, key_ptr, key_len)` | remove a header |
//! | `proxy_send_local_response(status, details_ptr, details_len, body_ptr, body_len, headers_ptr, headers_len, grpc_status)` | answer the request without forwarding it |
//!
//! Only map type `0` (request headers) exists; any other map answers status `2`. The pseudo
//! headers `:method`, `:path`, `:authority` and `:scheme` are readable and not writable.
//! Header names are matched case-insensitively. At most 256 header changes per run.
//!
//! The module must export `memory`, `proxy_abi_version_0_2_1` (or `_0_2_0`),
//! `proxy_on_memory_allocate(size) -> ptr` (the host allocates results in guest memory through
//! it) and `proxy_on_request_headers(context_id, num_headers, end_of_stream) -> action`.
//! `proxy_on_request_headers` is the ABI name of the SDKs' `on_http_request_headers`.
//! Optional exports, called when present, in this order: `_initialize`,
//! `proxy_on_context_create(1, 0)` (root), `proxy_on_vm_start(1, 0)`,
//! `proxy_on_configure(1, 0)` (no configuration), `proxy_on_context_create(2, 1)` (the request),
//! then `proxy_on_request_headers(2, n, end_of_stream)`.
//!
//! The returned action does not matter: a filter either sent a local response (the request ends
//! there) or the request continues with the header changes it made. A filter that returns
//! `Pause` without a local response therefore does not stall the request.

mod executor;
mod wasi;

pub use executor::{Executor, RunSlot};

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use thiserror::Error;
use wasmtime::{
    Caller, Config, Engine, ExternType, FuncType, Instance, InstancePre, Linker, Memory, Module,
    Store, StoreLimits, StoreLimitsBuilder, ValType, WasmParams, WasmResults,
};

use crate::budget::TenantBudget;
use crate::compile::Invalid;
use crate::error::AppError;
use crate::middleware::wasm::Config as FilterConfig;
use crate::respond;

/// Module that provides the proxy-wasm host functions.
const HOST_MODULE: &str = "env";

/// The proxy-wasm host functions a filter may import from [`HOST_MODULE`].
const ENV_IMPORTS: [&str; 7] = [
    "proxy_log",
    "proxy_get_header_map_value",
    "proxy_get_header_map_pairs",
    "proxy_add_header_map_value",
    "proxy_replace_header_map_value",
    "proxy_remove_header_map_value",
    "proxy_send_local_response",
];

/// Whether a filter may import `module.name`: the whole surface of [`link`].
fn is_allowed(module: &str, name: &str) -> bool {
    match module {
        HOST_MODULE => ENV_IMPORTS.contains(&name),
        wasi::MODULE => wasi::IMPORTS.contains(&name),
        _ => false,
    }
}

/// Accepted ABI marker exports, newest first.
const ABI_MARKERS: [&str; 2] = ["proxy_abi_version_0_2_1", "proxy_abi_version_0_2_0"];

/// proxy-wasm `MapType::HttpRequestHeaders`.
const MAP_REQUEST_HEADERS: u32 = 0;
/// Context id of the root context.
const ROOT_CONTEXT: i32 = 1;
/// Context id of the request context.
const HTTP_CONTEXT: i32 = 2;
/// Most header changes one run may make.
const MAX_HEADER_OPS: usize = 256;
/// Most log lines one run may emit, and most payload bytes in total (guest memory is never
/// copied past this).
const MAX_LOG_LINES: u8 = 32;
const MAX_LOG_BYTES: usize = 4096;
/// Table limits of one instance; compiled code needs one table for indirect calls.
const MAX_TABLES: usize = 8;
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// proxy-wasm `WasmResult` codes the host returns.
mod status {
    pub(super) const OK: i32 = 0;
    pub(super) const NOT_FOUND: i32 = 1;
    pub(super) const BAD_ARGUMENT: i32 = 2;
    pub(super) const INVALID_MEMORY_ACCESS: i32 = 6;
    pub(super) const INTERNAL_FAILURE: i32 = 10;
}

/// Why one filter of an app is refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Reason {
    /// `wasm_base64` is not standard base64.
    #[error("wasm_base64 is not valid base64")]
    NotBase64,
    /// The bytes are not a valid WebAssembly module, or its imports do not type-check.
    #[error("not a valid module: {0}")]
    Invalid(Box<str>),
    /// The module imports something other than the host functions podgate provides.
    #[error("imports {module}.{name}, which podgate does not provide")]
    ForbiddenImport {
        /// Module of the import, for example `wasi_snapshot_preview1`.
        module: Box<str>,
        /// Name of the import.
        name: Box<str>,
    },
    /// A required export is missing, or an export has the wrong type.
    #[error("missing or mistyped export {0}")]
    Export(&'static str),
    /// The limits cannot work: no fuel, or more initial memory than allowed.
    #[error("{0}")]
    Limits(Box<str>),
    /// The WASM engine could not start.
    #[error("the WASM engine could not start: {0}")]
    Engine(Box<str>),
}

impl Reason {
    /// The refusal for the `422` body: code `wasm_forbidden_import` (with `module` and `name`)
    /// or `wasm_invalid`.
    #[must_use]
    pub fn into_invalid(self) -> Invalid {
        let invalid = Invalid::new(
            match self {
                Self::ForbiddenImport { .. } => "wasm_forbidden_import",
                _ => "wasm_invalid",
            },
            self.to_string(),
        );
        match self {
            Self::ForbiddenImport { module, name } => {
                invalid.with("module", &*module).with("name", &*name)
            }
            _ => invalid,
        }
    }
}

/// A request header change a filter made, replayed on the real request after the run.
#[derive(Debug)]
enum HeaderOp {
    Add(HeaderName, HeaderValue),
    Replace(HeaderName, HeaderValue),
    Remove(HeaderName),
}

/// A response a filter asked for with `proxy_send_local_response`.
#[derive(Debug)]
struct LocalResponse {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

/// What one filter run decided.
#[derive(Debug)]
enum Verdict {
    /// Forward the request with these header changes applied.
    Continue(Vec<HeaderOp>),
    /// Answer the request with this response and do not forward it.
    Respond(LocalResponse),
}

/// The `Store` data of one run.
struct HostState {
    limits: StoreLimits,
    app: Arc<str>,
    tenant: Arc<str>,
    /// Request headers as the filter sees them, pseudo headers first. Names are lowercase.
    headers: Vec<(String, Vec<u8>)>,
    ops: Vec<HeaderOp>,
    local: Option<LocalResponse>,
    log_budget: u8,
    /// Payload bytes the run may still log.
    log_bytes_left: usize,
    /// When the run started: the monotonic clock of the WASI stubs counts from here.
    started: Instant,
}

impl HostState {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut found = self
            .headers
            .iter()
            .filter(|(name, _)| name.as_bytes().eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_slice());
        let mut joined = found.next()?.to_vec();
        for value in found {
            joined.push(b',');
            joined.extend_from_slice(value);
        }
        Some(joined)
    }

    fn has_room(&self) -> bool {
        self.ops.len() < MAX_HEADER_OPS
    }

    fn add(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers
            .push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        self.ops.push(HeaderOp::Add(name, value));
    }

    fn replace(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers.retain(|(have, _)| have != name.as_str());
        self.headers
            .push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        self.ops.push(HeaderOp::Replace(name, value));
    }

    fn remove(&mut self, name: HeaderName) {
        self.headers.retain(|(have, _)| have != name.as_str());
        self.ops.push(HeaderOp::Remove(name));
    }
}

/// A compiled filter: the module, linked against the host functions, and its limits.
pub struct CompiledFilter {
    app: Arc<str>,
    tenant: Arc<str>,
    pre: InstancePre<HostState>,
    fuel: u64,
    max_memory: usize,
}

impl fmt::Debug for CompiledFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledFilter")
            .field("app", &self.app)
            .field("fuel", &self.fuel)
            .field("max_memory", &self.max_memory)
            .finish_non_exhaustive()
    }
}

impl CompiledFilter {
    /// Linear memory this filter may use, in bytes: what a run charges to its tenant.
    pub(crate) fn max_memory(&self) -> u64 {
        u64::try_from(self.max_memory).unwrap_or(u64::MAX)
    }

    /// Runs the filter on `headers` in a fresh store. Blocking: call it off the reactor.
    fn run(
        &self,
        headers: Vec<(String, Vec<u8>)>,
        end_of_stream: bool,
    ) -> wasmtime::Result<Verdict> {
        let count = i32::try_from(headers.len()).unwrap_or(i32::MAX);
        let state = HostState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.max_memory)
                .memories(1)
                .tables(MAX_TABLES)
                .table_elements(MAX_TABLE_ELEMENTS)
                .instances(1)
                .trap_on_grow_failure(true)
                .build(),
            app: Arc::clone(&self.app),
            tenant: Arc::clone(&self.tenant),
            headers,
            ops: Vec::new(),
            local: None,
            log_budget: MAX_LOG_LINES,
            log_bytes_left: MAX_LOG_BYTES,
            started: Instant::now(),
        };
        let mut store = Store::new(self.pre.module().engine(), state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(self.fuel)?;
        let instance = self.pre.instantiate(&mut store)?;

        call_optional::<(), ()>(instance, &mut store, "_initialize", ())?;
        call_optional::<(i32, i32), ()>(
            instance,
            &mut store,
            "proxy_on_context_create",
            (ROOT_CONTEXT, 0),
        )?;
        for hook in ["proxy_on_vm_start", "proxy_on_configure"] {
            let started =
                call_optional::<(i32, i32), i32>(instance, &mut store, hook, (ROOT_CONTEXT, 0))?;
            if started == Some(0) {
                return Err(wasmtime::format_err!("{hook} returned false"));
            }
        }
        call_optional::<(i32, i32), ()>(
            instance,
            &mut store,
            "proxy_on_context_create",
            (HTTP_CONTEXT, ROOT_CONTEXT),
        )?;
        instance
            .get_typed_func::<(i32, i32, i32), i32>(&mut store, "proxy_on_request_headers")?
            .call(&mut store, (HTTP_CONTEXT, count, i32::from(end_of_stream)))?;

        let state = store.data_mut();
        Ok(match state.local.take() {
            Some(local) => Verdict::Respond(local),
            None => Verdict::Continue(std::mem::take(&mut state.ops)),
        })
    }
}

/// Calls the export `name` when the module has it.
fn call_optional<P: WasmParams, R: WasmResults>(
    instance: Instance,
    store: &mut Store<HostState>,
    name: &str,
    params: P,
) -> wasmtime::Result<Option<R>> {
    let Some(func) = instance.get_func(&mut *store, name) else {
        return Ok(None);
    };
    Ok(Some(
        func.typed::<P, R>(&*store)?.call(&mut *store, params)?,
    ))
}

/// The engine and linker shared by every filter of one snapshot compile. Built on the first
/// filter, so a snapshot without filters never starts an engine.
#[derive(Default)]
pub struct Compiler {
    runtime: Option<(Engine, Linker<HostState>)>,
}

impl fmt::Debug for Compiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compiler")
            .field("started", &self.runtime.is_some())
            .finish()
    }
}

impl Compiler {
    /// Compiles one filter of app `app`, owned by `tenant` (both only name the filter in log
    /// lines).
    ///
    /// # Errors
    ///
    /// The [`Reason`] the module is refused for.
    pub fn compile(
        &mut self,
        app: (&str, &str),
        filter: &FilterConfig,
    ) -> Result<CompiledFilter, Reason> {
        let (engine, linker) = self.runtime()?;
        compile_filter(engine, linker, app, filter)
    }

    fn runtime(&mut self) -> Result<&(Engine, Linker<HostState>), Reason> {
        if self.runtime.is_none() {
            let engine = engine().map_err(|err| Reason::Engine(err.to_string().into()))?;
            let linker = link(&engine).map_err(|err| Reason::Engine(err.to_string().into()))?;
            self.runtime = Some((engine, linker));
        }
        self.runtime
            .as_ref()
            .ok_or_else(|| Reason::Engine("not initialized".into()))
    }
}

fn engine() -> wasmtime::Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    Engine::new(&config)
}

fn compile_filter(
    engine: &Engine,
    linker: &Linker<HostState>,
    (app, tenant): (&str, &str),
    filter: &FilterConfig,
) -> Result<CompiledFilter, Reason> {
    if filter.fuel == 0 {
        return Err(Reason::Limits("fuel must be greater than 0".into()));
    }
    let wasm = STANDARD
        .decode(&filter.wasm_base64)
        .map_err(|_| Reason::NotBase64)?;
    let module =
        Module::new(engine, &wasm).map_err(|err| Reason::Invalid(err.to_string().into()))?;
    for import in module.imports() {
        let allowed = is_allowed(import.module(), import.name())
            && matches!(import.ty(), ExternType::Func(_));
        if !allowed {
            return Err(Reason::ForbiddenImport {
                module: import.module().into(),
                name: import.name().into(),
            });
        }
    }
    check_exports(engine, &module)?;
    let initial = match module.get_export("memory") {
        Some(ExternType::Memory(memory)) => memory.minimum().saturating_mul(memory.page_size()),
        _ => return Err(Reason::Export("memory")),
    };
    if initial > filter.max_memory_bytes {
        return Err(Reason::Limits(
            format!(
                "declares {initial} bytes of initial memory, over max_memory_bytes {}",
                filter.max_memory_bytes
            )
            .into(),
        ));
    }
    let pre = linker
        .instantiate_pre(&module)
        .map_err(|err| Reason::Invalid(err.to_string().into()))?;
    Ok(CompiledFilter {
        app: Arc::from(app),
        tenant: Arc::from(tenant),
        pre,
        fuel: filter.fuel,
        max_memory: usize::try_from(filter.max_memory_bytes).unwrap_or(usize::MAX),
    })
}

/// Checks the exports the host calls: the required ones exist, every one present has the
/// proxy-wasm signature.
fn check_exports(engine: &Engine, module: &Module) -> Result<(), Reason> {
    const I32: ValType = ValType::I32;
    let check = |name: &'static str,
                 params: &[ValType],
                 results: &[ValType],
                 required: bool|
     -> Result<(), Reason> {
        match module.get_export(name) {
            None if required => Err(Reason::Export(name)),
            None => Ok(()),
            Some(ExternType::Func(actual))
                if FuncType::eq(
                    &actual,
                    &FuncType::new(engine, params.iter().cloned(), results.iter().cloned()),
                ) =>
            {
                Ok(())
            }
            Some(_) => Err(Reason::Export(name)),
        }
    };
    let abi = ABI_MARKERS
        .iter()
        .find(|name| module.get_export(name).is_some())
        .ok_or(Reason::Export(ABI_MARKERS[0]))?;
    check(abi, &[], &[], true)?;
    check("proxy_on_memory_allocate", &[I32], &[I32], true)?;
    check("proxy_on_request_headers", &[I32, I32, I32], &[I32], true)?;
    check("_initialize", &[], &[], false)?;
    check("proxy_on_context_create", &[I32, I32], &[], false)?;
    check("proxy_on_vm_start", &[I32, I32], &[I32], false)?;
    check("proxy_on_configure", &[I32, I32], &[I32], false)
}

/// The linker with every host function [`is_allowed`] accepts and nothing else.
fn link(engine: &Engine) -> wasmtime::Result<Linker<HostState>> {
    let mut linker = Linker::new(engine);
    linker.func_wrap(HOST_MODULE, "proxy_log", proxy_log)?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_get_header_map_value",
        proxy_get_header_map_value,
    )?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_get_header_map_pairs",
        proxy_get_header_map_pairs,
    )?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_add_header_map_value",
        proxy_add_header_map_value,
    )?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_replace_header_map_value",
        proxy_replace_header_map_value,
    )?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_remove_header_map_value",
        proxy_remove_header_map_value,
    )?;
    linker.func_wrap(
        HOST_MODULE,
        "proxy_send_local_response",
        proxy_send_local_response,
    )?;
    wasi::link(&mut linker)?;
    Ok(linker)
}

fn memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    caller.get_export("memory")?.into_memory()
}

/// `len` bytes at `ptr`, when they lie inside `memory`.
fn region(memory: &[u8], ptr: u32, len: u32) -> Option<&[u8]> {
    let start = usize::try_from(ptr).ok()?;
    memory.get(start..start.checked_add(usize::try_from(len).ok()?)?)
}

fn put_u32(memory: &mut [u8], at: u32, value: u32) -> Option<()> {
    let start = usize::try_from(at).ok()?;
    memory
        .get_mut(start..start.checked_add(4)?)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// Hands `data` to the guest the proxy-wasm way: allocate with the guest's
/// `proxy_on_memory_allocate`, copy, and store the pointer and size at the two return slots.
fn return_bytes(
    caller: &mut Caller<'_, HostState>,
    data: &[u8],
    ptr_slot: u32,
    len_slot: u32,
) -> wasmtime::Result<i32> {
    let Ok(len) = u32::try_from(data.len()) else {
        return Ok(status::INTERNAL_FAILURE);
    };
    let Some(alloc) = caller
        .get_export("proxy_on_memory_allocate")
        .and_then(wasmtime::Extern::into_func)
    else {
        return Ok(status::INTERNAL_FAILURE);
    };
    let alloc = alloc.typed::<i32, i32>(&*caller)?;
    let at = alloc.call(&mut *caller, i32::try_from(len).unwrap_or(i32::MAX))?;
    // The guest's allocator may have grown the memory, so look it up only now.
    let Some(memory) = memory(caller) else {
        return Ok(status::INTERNAL_FAILURE);
    };
    let guest = memory.data_mut(&mut *caller);
    let at = u32::from_ne_bytes(at.to_ne_bytes());
    let start = usize::try_from(at).ok();
    let target = start.and_then(|start| guest.get_mut(start..start.checked_add(data.len())?));
    let Some(target) = target else {
        return Ok(status::INVALID_MEMORY_ACCESS);
    };
    target.copy_from_slice(data);
    Ok(
        if put_u32(guest, ptr_slot, at)
            .and_then(|()| put_u32(guest, len_slot, len))
            .is_some()
        {
            status::OK
        } else {
            status::INVALID_MEMORY_ACCESS
        },
    )
}

fn proxy_log(mut caller: Caller<'_, HostState>, level: u32, ptr: u32, len: u32) -> i32 {
    let Some(memory) = memory(&mut caller) else {
        return status::INTERNAL_FAILURE;
    };
    let (guest, state) = memory.data_and_store_mut(&mut caller);
    let Some(message) = region(guest, ptr, len) else {
        return status::INVALID_MEMORY_ACCESS;
    };
    emit(state, level, message, false);
    status::OK
}

/// Takes what a log line may carry from the run's budget: the kept prefix of `message` and
/// whether anything was cut (`cut` says the caller already cut it). `None` once the run has
/// used its lines or its bytes.
fn budgeted<'a>(state: &mut HostState, message: &'a [u8], cut: bool) -> Option<(&'a [u8], bool)> {
    if state.log_budget == 0 || state.log_bytes_left == 0 {
        return None;
    }
    state.log_budget -= 1;
    let keep = message.len().min(state.log_bytes_left);
    state.log_bytes_left -= keep;
    Some((message.get(..keep)?, cut || keep < message.len()))
}

/// Logs `message` at `level` (`0` trace to `4` error), tagged with the app and tenant, within
/// the run's budget.
fn emit(state: &mut HostState, level: u32, message: &[u8], cut: bool) {
    let Some((kept, truncated)) = budgeted(state, message, cut) else {
        return;
    };
    let message = String::from_utf8_lossy(kept);
    let (app, tenant) = (&*state.app, &*state.tenant);
    match level {
        0 => tracing::trace!(app, tenant, truncated, "wasm filter: {message}"),
        1 => tracing::debug!(app, tenant, truncated, "wasm filter: {message}"),
        2 => tracing::info!(app, tenant, truncated, "wasm filter: {message}"),
        3 => tracing::warn!(app, tenant, truncated, "wasm filter: {message}"),
        _ => tracing::error!(app, tenant, truncated, "wasm filter: {message}"),
    }
}

fn proxy_get_header_map_value(
    mut caller: Caller<'_, HostState>,
    map: u32,
    key_ptr: u32,
    key_len: u32,
    out_ptr: u32,
    out_len: u32,
) -> wasmtime::Result<i32> {
    if map != MAP_REQUEST_HEADERS {
        return Ok(status::BAD_ARGUMENT);
    }
    let Some(memory) = memory(&mut caller) else {
        return Ok(status::INTERNAL_FAILURE);
    };
    let value = {
        let (guest, state) = memory.data_and_store_mut(&mut caller);
        let Some(key) = region(guest, key_ptr, key_len) else {
            return Ok(status::INVALID_MEMORY_ACCESS);
        };
        state.get(key)
    };
    match value {
        Some(value) => return_bytes(&mut caller, &value, out_ptr, out_len),
        None => Ok(status::NOT_FOUND),
    }
}

fn proxy_get_header_map_pairs(
    mut caller: Caller<'_, HostState>,
    map: u32,
    out_ptr: u32,
    out_len: u32,
) -> wasmtime::Result<i32> {
    if map != MAP_REQUEST_HEADERS {
        return Ok(status::BAD_ARGUMENT);
    }
    let pairs = serialize_pairs(&caller.data().headers);
    return_bytes(&mut caller, &pairs, out_ptr, out_len)
}

/// A header name and value read from guest memory, validated.
fn read_header(
    guest: &[u8],
    key: (u32, u32),
    value: (u32, u32),
) -> Result<(HeaderName, HeaderValue), i32> {
    let key = region(guest, key.0, key.1).ok_or(status::INVALID_MEMORY_ACCESS)?;
    let value = region(guest, value.0, value.1).ok_or(status::INVALID_MEMORY_ACCESS)?;
    let name = HeaderName::from_bytes(key).map_err(|_| status::BAD_ARGUMENT)?;
    let value = HeaderValue::from_bytes(value).map_err(|_| status::BAD_ARGUMENT)?;
    Ok((name, value))
}

/// Shared body of add and replace: read the header, apply `change` to the run state.
fn write_header(
    mut caller: Caller<'_, HostState>,
    map: u32,
    key: (u32, u32),
    value: (u32, u32),
    change: fn(&mut HostState, HeaderName, HeaderValue),
) -> i32 {
    if map != MAP_REQUEST_HEADERS {
        return status::BAD_ARGUMENT;
    }
    let Some(memory) = memory(&mut caller) else {
        return status::INTERNAL_FAILURE;
    };
    let (guest, state) = memory.data_and_store_mut(&mut caller);
    if !state.has_room() {
        return status::BAD_ARGUMENT;
    }
    match read_header(guest, key, value) {
        Ok((name, value)) => {
            change(state, name, value);
            status::OK
        }
        Err(code) => code,
    }
}

fn proxy_add_header_map_value(
    caller: Caller<'_, HostState>,
    map: u32,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> i32 {
    write_header(
        caller,
        map,
        (key_ptr, key_len),
        (value_ptr, value_len),
        HostState::add,
    )
}

fn proxy_replace_header_map_value(
    caller: Caller<'_, HostState>,
    map: u32,
    key_ptr: u32,
    key_len: u32,
    value_ptr: u32,
    value_len: u32,
) -> i32 {
    write_header(
        caller,
        map,
        (key_ptr, key_len),
        (value_ptr, value_len),
        HostState::replace,
    )
}

fn proxy_remove_header_map_value(
    mut caller: Caller<'_, HostState>,
    map: u32,
    key_ptr: u32,
    key_len: u32,
) -> i32 {
    if map != MAP_REQUEST_HEADERS {
        return status::BAD_ARGUMENT;
    }
    let Some(memory) = memory(&mut caller) else {
        return status::INTERNAL_FAILURE;
    };
    let (guest, state) = memory.data_and_store_mut(&mut caller);
    if !state.has_room() {
        return status::BAD_ARGUMENT;
    }
    let Some(key) = region(guest, key_ptr, key_len) else {
        return status::INVALID_MEMORY_ACCESS;
    };
    match HeaderName::from_bytes(key) {
        Ok(name) => {
            state.remove(name);
            status::OK
        }
        Err(_) => status::BAD_ARGUMENT,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the proxy-wasm ABI fixes this signature"
)]
fn proxy_send_local_response(
    mut caller: Caller<'_, HostState>,
    status_code: u32,
    _details_ptr: u32,
    _details_len: u32,
    body_ptr: u32,
    body_len: u32,
    headers_ptr: u32,
    headers_len: u32,
    _grpc_status: i32,
) -> i32 {
    let Some(memory) = memory(&mut caller) else {
        return status::INTERNAL_FAILURE;
    };
    let (guest, state) = memory.data_and_store_mut(&mut caller);
    let Some(body) = region(guest, body_ptr, body_len) else {
        return status::INVALID_MEMORY_ACCESS;
    };
    let Some(raw_headers) = region(guest, headers_ptr, headers_len) else {
        return status::INVALID_MEMORY_ACCESS;
    };
    let Some(status_code) = u16::try_from(status_code)
        .ok()
        .and_then(|code| StatusCode::from_u16(code).ok())
    else {
        return status::BAD_ARGUMENT;
    };
    let headers = if raw_headers.is_empty() {
        Some(Vec::new())
    } else {
        parse_pairs(raw_headers)
    };
    let Some(headers) = headers else {
        return status::BAD_ARGUMENT;
    };
    state.local = Some(LocalResponse {
        status: status_code,
        headers,
        body: Bytes::copy_from_slice(body),
    });
    status::OK
}

/// The proxy-wasm serialization of header pairs: a `u32` count, a `(u32 key length, u32 value
/// length)` per pair, then each key and value followed by a NUL, all little endian.
fn serialize_pairs(pairs: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(pairs.len()).unwrap_or(u32::MAX).to_le_bytes());
    for (key, value) in pairs {
        out.extend_from_slice(&u32::try_from(key.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_le_bytes());
    }
    for (key, value) in pairs {
        out.extend_from_slice(key.as_bytes());
        out.push(0);
        out.extend_from_slice(value);
        out.push(0);
    }
    out
}

/// Reads what [`serialize_pairs`] writes into validated headers; `None` when it is malformed or
/// a name or value is not a valid header.
fn parse_pairs(raw: &[u8]) -> Option<Vec<(HeaderName, HeaderValue)>> {
    let word = |at: usize| -> Option<usize> {
        let bytes: [u8; 4] = raw.get(at..at.checked_add(4)?)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(bytes)).ok()
    };
    let count = word(0)?;
    // Every pair needs 8 length bytes, so a count the buffer cannot hold is malformed.
    if count > raw.len() / 8 {
        return None;
    }
    let mut data = 4 + count * 8;
    let mut pairs = Vec::with_capacity(count);
    for index in 0..count {
        let key_len = word(4 + index * 8)?;
        let value_len = word(4 + index * 8 + 4)?;
        let key = raw.get(data..data.checked_add(key_len)?)?;
        data += key_len;
        (*raw.get(data)? == 0).then_some(())?;
        data += 1;
        let value = raw.get(data..data.checked_add(value_len)?)?;
        data += value_len;
        (*raw.get(data)? == 0).then_some(())?;
        data += 1;
        pairs.push((
            HeaderName::from_bytes(key).ok()?,
            HeaderValue::from_bytes(value).ok()?,
        ));
    }
    Some(pairs)
}

/// The request as a filter sees it: pseudo headers, then every header.
fn capture(session: &Session) -> Vec<(String, Vec<u8>)> {
    let request = session.req_header();
    let tls = session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some());
    let authority = request
        .uri
        .authority()
        .map(|authority| authority.as_str().as_bytes())
        .or_else(|| request.headers.get("host").map(HeaderValue::as_bytes));
    let path = request
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let mut headers = Vec::with_capacity(request.headers.len() + 4);
    headers.push((
        ":method".to_owned(),
        request.method.as_str().as_bytes().to_vec(),
    ));
    headers.push((":path".to_owned(), path.as_bytes().to_vec()));
    if let Some(authority) = authority {
        headers.push((":authority".to_owned(), authority.to_vec()));
    }
    headers.push((
        ":scheme".to_owned(),
        if tls { &b"https"[..] } else { &b"http"[..] }.to_vec(),
    ));
    headers.extend(
        request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec())),
    );
    headers
}

fn apply(request: &mut RequestHeader, ops: Vec<HeaderOp>) -> pingora::Result<()> {
    for op in ops {
        match op {
            HeaderOp::Add(name, value) => {
                request.append_header(name, value)?;
            }
            HeaderOp::Replace(name, value) => request.insert_header(name, value)?,
            HeaderOp::Remove(name) => {
                request.remove_header(&name);
            }
        }
    }
    Ok(())
}

async fn write_local(session: &mut Session, local: LocalResponse) -> pingora::Result<()> {
    let mut header = ResponseHeader::build(local.status, Some(local.headers.len() + 1))?;
    for (name, value) in local.headers {
        header.append_header(name, value)?;
    }
    header.insert_header("content-length", local.body.len().to_string())?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session.write_response_body(Some(local.body), true).await
}

/// Runs one WASM filter on the request.
///
/// Header changes the filter makes are applied to the request. A filter that sends a local
/// response ends the request: the response is written and the request is not forwarded. A
/// filter that traps, runs out of fuel or exceeds its memory limit answers `500`. Before the run
/// `executor` takes a worker and charges the filter's `max_memory_bytes` to `tenant` (the
/// request's tenant, `None` for no charge); when either is unavailable the request answers
/// `503` with `retry-after` and the filter does not run; `capacity_refusal` is set when that
/// refusal is one auto-revert must not count ([`AppError::is_capacity_refusal`]). Returns `true`
/// when the request was answered here and must not go on, `false` when it continues.
///
/// # Errors
///
/// Fails when a response cannot be written to the client or a header change cannot be applied.
pub async fn run_filter(
    session: &mut Session,
    filter: &Arc<CompiledFilter>,
    tenant: Option<&Arc<TenantBudget>>,
    executor: &Executor,
    capacity_refusal: &mut bool,
) -> pingora::Result<bool> {
    let headers = capture(session);
    let end_of_stream = session.is_body_empty();
    let slot = match executor.admit(tenant, filter.max_memory()).await {
        Ok(slot) => slot,
        Err(err) => {
            tracing::warn!(
                app = &*filter.app,
                "wasm filter refused: no worker or memory budget"
            );
            *capacity_refusal = err.is_capacity_refusal();
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
    };
    let run = Arc::clone(filter);
    let outcome = tokio::task::spawn_blocking(move || {
        // Held until the run ends, even when the request is gone.
        let _slot = slot;
        run.run(headers, end_of_stream)
    })
    .await;
    let verdict = match outcome {
        Ok(Ok(verdict)) => verdict,
        failed => {
            let cause = match failed {
                Ok(Err(err)) => err.to_string(),
                Err(err) => err.to_string(),
                Ok(Ok(_)) => String::new(),
            };
            tracing::warn!(app = &*filter.app, %cause, "wasm filter failed");
            let err = AppError::Internal(anyhow::anyhow!("wasm filter failed"));
            respond::write_error(session, &err).await?;
            return Ok(true);
        }
    };
    match verdict {
        Verdict::Continue(ops) => {
            apply(session.req_header_mut(), ops)?;
            Ok(false)
        }
        Verdict::Respond(local) => {
            write_local(session, local).await?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pairs_round_trip() {
        let pairs = vec![
            ("x-a".to_owned(), b"1".to_vec()),
            ("x-b".to_owned(), b"two words".to_vec()),
            ("x-c".to_owned(), Vec::new()),
        ];
        let parsed = parse_pairs(&serialize_pairs(&pairs)).expect("well formed");
        let shown: Vec<_> = parsed
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        assert_eq!(shown, pairs);
    }

    #[test]
    fn malformed_pairs_are_refused() {
        assert!(parse_pairs(&[]).is_none());
        assert!(parse_pairs(&u32::MAX.to_le_bytes()).is_none(), "huge count");
        let mut truncated = serialize_pairs(&[("x-a".to_owned(), b"1".to_vec())]);
        truncated.pop();
        assert!(parse_pairs(&truncated).is_none());
        assert!(parse_pairs(&serialize_pairs(&[("bad name".to_owned(), Vec::new())])).is_none());
    }

    fn state() -> HostState {
        HostState {
            limits: StoreLimits::default(),
            app: "a".into(),
            tenant: "t".into(),
            headers: Vec::new(),
            ops: Vec::new(),
            local: None,
            log_budget: MAX_LOG_LINES,
            log_bytes_left: MAX_LOG_BYTES,
            started: Instant::now(),
        }
    }

    #[test]
    fn the_linker_provides_exactly_the_allowed_imports() {
        let engine = engine().expect("engine");
        let linker = link(&engine).expect("linker");
        let mut store = Store::new(&engine, state());
        let mut provided: Vec<_> = linker
            .iter(&mut store)
            .map(|(module, name, _)| format!("{module}.{name}"))
            .collect();
        provided.sort();
        let mut allowed: Vec<_> = ENV_IMPORTS
            .iter()
            .map(|name| format!("{HOST_MODULE}.{name}"))
            .chain(
                wasi::IMPORTS
                    .iter()
                    .map(|name| format!("{}.{name}", wasi::MODULE)),
            )
            .collect();
        allowed.sort();
        assert_eq!(provided, allowed);
        assert!(provided.iter().all(|name| {
            let (module, import) = name.split_once('.').expect("module.name");
            is_allowed(module, import)
        }));
        assert!(!is_allowed(wasi::MODULE, "path_open"));
        assert!(!is_allowed(wasi::MODULE, "sock_accept"));
        assert!(!is_allowed(wasi::MODULE, "fd_read"));
    }

    #[test]
    fn a_run_logs_at_most_4_kib_whatever_the_filter_writes() {
        let mut state = state();
        let megabyte = vec![b'x'; 1 << 20];
        let mut logged = 0;
        for _ in 0..100 {
            if let Some((kept, truncated)) = budgeted(&mut state, &megabyte, false) {
                assert!(truncated, "a 1 MiB line is cut");
                logged += kept.len();
            }
        }
        assert_eq!(logged, 4096);

        let mut state = self::state();
        let lines = (0..100)
            .filter_map(|_| budgeted(&mut state, b"ab", false))
            .count();
        assert_eq!(lines, usize::from(MAX_LOG_LINES));
    }
}
