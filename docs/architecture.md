# Architecture

podgate is a reverse proxy on Pingora, configured only by snapshots the PaaS control plane pushes over a unix-socket admin API. One package with a library (testable) and a thin binary. `## Target architecture` is the design every spec builds on; `## Layout` and the sections after it describe what exists today.

## Layout

| Path | Role |
|---|---|
| `src/main.rs` | Thin: `Config::from_env()`, `init_tracing`, `run(&config)`. |
| `src/lib.rs` | Module declarations, re-exports, `init_tracing`, and `run(config)`, which builds the Pingora `Server`. |
| `src/config.rs` | `Config` and `LogFormat` read from environment variables; `ConfigError` names the bad variable. |
| `src/error.rs` | `AppError`: the one error clients see, `{"error": "..."}` with a status. Conversions from `ApplyError` and `RouteError`; a rejected snapshot lists its `conflicts` as objects. |
| `src/snapshot.rs` | `Snapshot` and the entities under it: the serde model of `PUT /v1/snapshot`. |
| `src/host.rs` | Host patterns (`HostPattern`), request host normalization, `HostMap` (exact beats one-label wildcard). |
| `src/table.rs` | `RoutingTable` (compiled snapshot, weighted pick over `serving` revisions), `TableHandle` (atomic swap, `apply`), `CompileError`, `ApplyError`. |
| `src/conflict.rs` | `Conflict`: one typed variant per conflict code (`host_conflict`, `tls_policy_conflict`, `cross_tenant_wildcard`) and the pass that finds all of them in a snapshot. |
| `src/route.rs` | Core host routing: `resolve(table, request) -> Selected`. Pure; no Pingora session. |
| `src/events.rs` | `EventFeed` (bounded ring of 4096, `emit`, long-poll `poll`, per-process `boot_id`), `Event`, `EventKind`. Features emit into it. |
| `src/inflight.rs` | `Inflight`: per-revision in-flight counters keyed by (app id, revision id), lock-free atomics on the request path (one registry swap per `sync`), `InflightGuard`, and the `revision_drained` event. |
| `src/proxy.rs` | `Gateway` (the Pingora `ProxyHttp`), the per-request `Ctx`, and `middleware_chain`: the ordered request-path stages, which `GET /v1/explain` reports. A new stage adds one line there. |
| `src/explain.rs` | `Target::parse` (the `url` and `method` of an explain query) and `explain(table, target)`: why a request goes where it goes, read from the live `RoutingTable` (`lookup`, `nearest_wildcard`, `effective_weight`). |
| `src/respond.rs` | `write_error`: answers a proxied request with an `AppError`. |
| `src/budget.rs` | `Budgets` (per-tenant registry that survives snapshot swaps), `TenantBudget`, the `TenantSlot` and `BufferGuard` RAII charges, `admit`, and the Prometheus rendering. |
| `src/compress.rs` | Gzip response compression on `miniz_oxide` (pure Rust) with its memory charged up front: `start`, `filter`, `RESERVATION_BYTES`. |
| `src/tls.rs` | `CertStore` (certificates of a snapshot) and the TLS listener settings that choose the certificate by SNI per handshake. |
| `src/sni.rs` | The TLS check that a request's `Host` and `:authority` equal the connection's SNI: `CaptureServerName` (handshake hook that records the SNI on the connection) and `check`, called first in `request_filter`. |
| `src/pool.rs` | Upstream connection pool isolation: `isolate` sets the peer's `group_key` from `(tenant, app, revision)` (Pingora adds the upstream address), and pins connections that carried `Authorization: NTLM` or `Negotiate` to their downstream connection (`State`, carried across keepalive requests by `persist`/`restore`). Called from `upstream_peer`. |
| `src/skew.rs` | Skew protection: `SkewSecret`, the signed `__podgate_rev` cookie, `pinned` (called by `route::resolve`) and `set_cookie` (called by `response_filter`). |
| `src/wake.rs` | Scale to zero: `Wake` holds requests for an app with no upstream (`hold`, woken by `TableHandle::subscribe`), emits `wake_requested` once per wake cycle, hands the held tenant slot on in `admit`, and `sweep` emits `app_idle`; `WakeService` runs the sweep as a background service; `State` is the per-request field of `Ctx`. |
| `src/wasm.rs` | WASM request filters: compile and validate the `App.filters` modules at snapshot compile, `run_filters` runs them per request with fuel and a memory limit, the proxy-wasm host functions. |
| `src/admin.rs` | The admin router (`router`), `AppState`, the unix socket (`bind`, mode `0600`) and `AdminService`, a Pingora background service. |
| `src/admin/*.rs` | One module per endpoint group, each with `fn routes() -> Router<AppState>`: `health.rs`, `metrics.rs`, `snapshot.rs`, `events.rs`, `explain.rs`, `failures.rs`. |
| `src/failures.rs` | `Failures`: per-app rings of failed requests (header redaction, opt-in bodies via `Capture`), and `replay`. `Gateway::with_failures` and `AppState::with_failures` share one recorder; hooks in `request_filter`, `request_body_filter`, `response_filter`, `response_body_filter` and `logging`; see `### Failed requests` for the order against compression. |
| `tests/common/mod.rs` | Test harness: `Podgate::start()` spawns the built binary on free ports with a temp admin socket; `push_snapshot`, `get`, `https_get`; `Upstream::start(body)`; `TestCert`; snapshot builders. Include with `mod common;`. |
| `tests/proxy.rs` | End-to-end tests through the real binary. New features add their own `tests/<feature>.rs`. |
| `tests/sni.rs` | SNI against Host: 421 on mismatch over HTTP/1.1 and HTTP/2 (including `:scheme http`), the `allow_domain_fronting` opt-in, matching hosts served. |
| `tests/explain.rs` | End-to-end: `GET /v1/explain` for known, wildcard and unknown hosts, bad queries, and answers that follow a snapshot swap. |
| `tests/skew.rs` | Skew protection end to end: cookie set and HMAC-signed, `serving` and `retiring` revisions pin, `draining`, removed, tampered and other-app cookies fall back, no cookie without `skew_secret`. |
| `tests/wake.rs` | Scale to zero through the real binary: one `wake_requested` per cycle, release on snapshot, `503` after `wake_timeout_secs`, `app_idle`, and held requests counting against `max_inflight`. |
| `tests/conflict.rs` | End-to-end: conflicting snapshots get a `422` naming every conflict, and the previous snapshot keeps serving. |
| `tests/pool.rs` | Pool isolation through the real binary with an upstream that numbers its connections: per tenant, app and revision, and NTLM/Negotiate pinning. |
| `tests/failures.rs` | Failed-request ring, redaction, opt-in bodies, replay and the method guard, with an upstream that returns 5xx on demand. |
| `tests/wasm.rs` | Filters written in WAT through the real binary: headers edited, fuel exhaustion and memory limit end in `500` while other requests are served, forbidden imports are `422`, local responses. |
| `Dockerfile`, `.dockerignore` | Multi-stage image on distroless. |

### Adding a feature

Features are added by extension, so parallel work merges as one-line changes:

- **Proxy callback.** Each `ProxyHttp` callback in `src/proxy.rs` is a short sequence of calls into per-feature modules. A feature adds `src/<feature>.rs` with its logic as plain functions, one field on `Ctx` (default in `Gateway::new_ctx`), and one line in each callback it hooks. Core host routing stays in `route.rs`.
- **Admin endpoint.** A feature adds `src/admin/<feature>.rs` with `fn routes() -> Router<AppState>` and one `.merge(<feature>::routes())` line in `admin::router`. Handlers return `Result<_, AppError>`.
- **Snapshot field.** Add the field to the entity in `snapshot.rs` with `#[serde(default)]`, never `deny_unknown_fields`; compile it in `table.rs`. An absent field means the feature is off.
- **Test.** Use `tests/common`; one `tests/<feature>.rs` per feature, unit tests in a `mod test` leaf of the module.

## Target architecture

### Planes

One `podgate` process per node. It has a proxy listener (Pingora, TLS via the `rustls` feature) and an admin API on a unix socket. The PaaS agent on the same node is the only client of the admin API, which `ADMIN_SOCKET` sets (default `/run/podgate/admin.sock`, mode `0600`). The admin socket serves `/healthz`, `/readyz` and `PUT /v1/snapshot`. podgate never opens a connection to the control plane. Everything it reports goes out through the event feed. The only outbound traffic is to upstreams and to the ACME server. There is no Docker socket and no service discovery.

### Snapshot

The control plane sends `PUT /v1/snapshot` with a JSON snapshot. Entities:

|Entity|Fields|
|---|---|
|`Snapshot`|`version` (u64, strictly increasing), `tenants`, `apps`|
|`Tenant`|`id`, `weight` (fair-share weight), `budget` (`max_inflight`, `max_buffer_bytes`)|
|`App`|`id`, `tenant`, `declared_by` (free text naming the source, used in errors and explain), `hosts` (exact names, or one leading `*.` wildcard), `tls` (`mode`: `acme` or `on_demand`; optional `client_ca_pem`), `revisions`|
|`Revision`|`id`, `upstreams` (socket addresses), `weight` (u16), `state` (`serving`, `retiring` or `draining`)|

`Snapshot` also takes an optional `certificates` list (`hosts`, `cert_pem`, `key_pem`), served on the TLS listener by SNI; change 0014 fills it from ACME. Later specs add optional fields to these entities. An absent optional field means the feature is off.

`App` also takes an optional `allow_domain_fronting` (bool, default `false`). By default a TLS request whose `Host` or `:authority` differs from the SNI of its connection is refused with `421 {"error":"misdirected request"}` before routing; the app the request names decides, so `true` on the target app lets it through. The SNI is read from the connection's TLS state, never from the request scheme, so an HTTP/2 request with `:scheme http` is checked too. A TLS connection with no SNI is treated as a mismatch. Plain HTTP is not checked.
`Snapshot` also takes an optional `skew_secret` (string, at least 16 bytes; a shorter one rejects the snapshot with a `422` and the code `invalid_skew_secret`). Absent means skew protection is off. With it, the first response of a session carries `Set-Cookie: __podgate_rev=<value>; Path=/; HttpOnly; SameSite=Lax` (plus `Secure` on TLS connections), where `<value>` is `base64url(len(app) || app || revision || mac)` and `mac = HMAC-SHA256(skew_secret, len(app) || app || revision)`; `len(app)` is two bytes, big-endian. Later requests that present the cookie go to that revision while it is `serving` or `retiring` (weight ignored), and are not re-pinned. A cookie whose revision is `draining` or gone, whose MAC fails, or that names another app is ignored: the request is routed by weight and gets a fresh cookie. Every node that shares the secret accepts every node's cookie. The secret is never logged and `Debug` hides it.

`App` also takes an optional `record_bodies` (bool, default `false`): failed requests of the app keep their request and response bodies, up to 64 KiB each, for replay.

### Failed requests

`src/failures.rs` keeps a ring of the last 100 failed requests per app, in memory only; nothing is written to disk. The rings are keyed by app id, so they survive snapshot swaps, and a snapshot that no longer has the app drops its ring.

- **What counts.** A request that was routed to an app and got a 5xx, whether the upstream sent it (`"origin": "upstream"`) or podgate did, for example a `502` after the upstream refused the connection (`"origin": "podgate"`). A request answered before routing (404, 421, `503 no upstream available`) is not recorded. The 5xx is judged by the response podgate wrote to the client.
- **Record.** `id` (increasing per process), `at_unix_ms`, `origin`, `method`, `uri` (path and query), `host`, `revision`, `upstream`, `request_headers`, `status`, `response_headers`, and `request_body` and `response_body` (text, `null` unless kept), plus `request_body_too_large` and `response_body_too_large`. Headers are `{"name","value"}` lists in wire order.
- **Redaction.** The values of `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie` are replaced by `[redacted]` before the record is stored, in requests and responses alike.
- **Bodies.** Only for apps with `record_bodies: true`, and only when at most 64 KiB; a larger body is dropped and its `*_too_large` flag is `true`. The response body is kept only for a 5xx from the upstream. Capture copies chunks while they stream past: at most 64 KiB per direction per request is buffered, and nothing is held back from the upstream or the client. Non-UTF-8 bytes are shown lossy in JSON; replay uses the exact bytes. For an upstream 5xx, `response_headers` and `response_body` are what the upstream sent, captured before response compression; `status` is what the client got.
- **Replay.** A new HTTP/1.1 connection to the first upstream of the named revision, which may be in any state. The redacted headers are dropped, not sent as `[redacted]`, so a request that needed credentials may be refused by the upstream. Connection and framing headers are rebuilt; when the body was not kept the request goes without one. The reply body is cut at 64 KiB (`body_truncated`). Connect, read and write each give up after 10 seconds.

`App` also takes an optional `scale_to_zero` (`idle_secs`, `wake_timeout_secs`, default `30`). An app with it may have no upstream. A request for it is held, not refused, while the live table gives the app no serving revision with a weight and an upstream; the first held request of a wake cycle emits `wake_requested {app}`, later ones emit nothing, and the cycle ends when the app has no held request left. A snapshot that gives the app an upstream releases the held requests, which route with the live table. After `wake_timeout_secs` a held request answers `503 {"error":"app did not wake in time"}` with `retry-after: 5`. Held requests keep a tenant in-flight slot, so they count against `max_inflight` and the tenant gets the usual `503` beyond it. `app_idle {app}` is emitted once when an awake app has had no request in flight or started for `idle_secs`; a new request starts a new idle period. Without `scale_to_zero` an app with no upstream answers `503` at once.
`App` also takes an optional `filters` list, `[{wasm_base64, fuel, max_memory_bytes}]` (default empty): WASM request filters that run in order after routing; see `### WASM filters`.

### Compile and swap

The snapshot is compiled into an immutable routing table and swapped atomically. Requests in flight keep the table they started with. A rejected snapshot leaves the current one live.

### Revision states

`serving` revisions get new sessions by weight. `retiring` revisions get no new sessions but still serve sessions pinned to them. `draining` revisions get no new requests at all. In-flight requests finish.

### Event feed

`GET /v1/events?after=<seq>&timeout_secs=<n>` is a long poll. It returns the ordered events with sequence numbers greater than `after`, or an empty list after the timeout. The event kinds are `revision_drained`, `config_reverted`, `canary_regressed`, `wake_requested`, `app_idle`, `acme_challenge` and `certificate_issued`.

### Error shape

Admin API errors are `{"error": "<message>"}`, the same shape `AppError` renders today. A snapshot rejected by the compiler returns `422` with `{"error": "snapshot rejected", "conflicts": [...]}`.

Every entry of `conflicts` is an object with a stable `code` and a human `message`. Conflicts between declarations carry the fields documented in `### Snapshot conflicts`; other compile failures use the codes `invalid_host`, `unknown_tenant` and `invalid_certificate`.

WASM filter failures use the codes `wasm_invalid` and `wasm_forbidden_import`; see `### WASM filters`.

### Snapshot conflicts

Declarations are never merged. The compiler checks every host pattern of every app (an exact name, or a `*.` wildcard that covers exactly one extra label) and refuses the whole snapshot, listing all conflicts at once. A claim is *under* a wildcard when the name it is about (the host itself, or the base of a wildcard) is one label below the wildcard's base: `x.a.test` and `*.x.a.test` are under `*.a.test`; `a.test` and `p.q.a.test` are not. An app repeating its own host is not a conflict.

|Code|When|Fields|
|---|---|---|
|`host_conflict`|Two apps claim the same exact host or the same wildcard, whatever their tenants.|`host`, `apps`, `declared_by`: the first claimant, then the second.|
|`cross_tenant_wildcard`|A claim lies under a wildcard of another tenant.|`host`, `wildcard`, `tenants`, `apps`, `declared_by`: the claim first, then the wildcard.|
|`tls_policy_conflict`|A claim lies under a wildcard of the same tenant in another app, and the two `tls.client_ca_pem` differ (compared as written, absent against present included). Exact wins over wildcard when routing, so without this rule an app could drop the client-certificate requirement of its wildcard.|`host`, `wildcard`, `apps`, `declared_by`: the claim first, then the wildcard.|

Example: `{"code":"host_conflict","message":"host dup.test is claimed by app one (src/one) and app two (src/two)","host":"dup.test","apps":["one","two"],"declared_by":["src/one","src/two"]}`.

### WASM filters

An app attaches request filters as proxy-wasm modules (`App.filters`: `wasm_base64`, standard base64 of the binary module; `fuel`, instructions per request; `max_memory_bytes`, linear memory cap). Each module is decoded, validated and compiled once when the snapshot compiles. Per request, after routing, `wasm::run_filters` runs every filter of the app in order, each in a fresh instance, on tokio's blocking pool so a long run never occupies a proxy reactor thread. Fuel bounds a run; a `memory.grow` past `max_memory_bytes` traps the guest. A trap, fuel exhaustion, a failed call or a `false` from `proxy_on_vm_start` or `proxy_on_configure` answers that request `500 {"error":"internal error"}` and logs the cause; other requests are unaffected. Header changes a filter made are applied before the next filter runs; a filter that sends a local response ends the chain and the request is not forwarded.

**Compile-time rejection.** A snapshot with a bad filter is refused whole with `422`, listing every bad filter with `app`, `declared_by` and `filter` (the index). Code `wasm_forbidden_import` (also `module` and `name`): the module imports anything other than the host functions below, in particular every `sock_*` and `path_*` function, every `fd_*` function except `fd_write`, and anything unknown. Code `wasm_invalid`: not base64, not a valid module, a required export missing or mistyped, zero fuel, or more initial memory than `max_memory_bytes`.

**Host ABI.** proxy-wasm 0.2.x, built for `wasm32-unknown-unknown` or `wasm32-wasip1` (the Rust and Go SDK default), so existing Envoy filters load unchanged. The proxy-wasm functions come from module `env`:

|Import|Behaviour|
|---|---|
|`proxy_log`|`tracing` event tagged with `app` and `tenant`. A run logs at most 32 lines and 4 KiB of payload in total, counting `fd_write` too; the rest is cut, and a cut line carries `truncated = true`.|
|`proxy_get_header_map_value`|Values of one header, joined with `,`. Status `1` when absent.|
|`proxy_get_header_map_pairs`|All headers in the proxy-wasm pair serialization.|
|`proxy_add_header_map_value`, `proxy_replace_header_map_value`, `proxy_remove_header_map_value`|Change a request header; at most 256 changes per run.|
|`proxy_send_local_response`|Answer with the given status, body and headers; the request is not forwarded.|

A filter built for `wasm32-wasip1` may also import these functions from `wasi_snapshot_preview1`, which are harmless stubs:

|Import|Behaviour|
|---|---|
|`clock_time_get`, `clock_res_get`|Real-time clock (id `0`) or time since the run started (ids `1` to `3`); other ids `EINVAL`.|
|`random_get`|OS entropy.|
|`proc_exit`|Traps the guest: the request answers `500`.|
|`environ_sizes_get`, `environ_get`, `args_sizes_get`, `args_get`|Empty.|
|`sched_yield`|No-op.|
|`fd_write`|fd `1` (info) and `2` (warn) go to the log under the same 4 KiB budget, reading guest memory only up to the remaining budget; any other fd is `EBADF`.|

Only map type `0` (request headers) exists. The pseudo headers `:method`, `:path`, `:authority` and `:scheme` can be read, not written. Required exports: `memory`, `proxy_abi_version_0_2_1` (or `_0_2_0`), `proxy_on_memory_allocate` and `proxy_on_request_headers(context_id, num_headers, end_of_stream)`, which is the ABI name of the SDKs' `on_http_request_headers`. Optional exports called when present, in order: `_initialize`, `proxy_on_context_create(1, 0)`, `proxy_on_vm_start(1, 0)`, `proxy_on_configure(1, 0)`, `proxy_on_context_create(2, 1)`. The returned action is ignored: the request continues unless a local response was sent.

**Limits.** The engine uses wasmtime with Cranelift; there is no async and no component model. Snapshot compile (and so the admin `PUT`) pays for compiling the modules, on the blocking pool. The number of concurrent filter runs is bounded only by tokio's blocking pool.

### Not built yet

Change 0001 built the planes (without ACME and the event feed); change 0004 built the feed with `revision_drained`, the other event kinds arrive with their specs, the snapshot model, compile and swap, revision states for new requests, and the error shape; `Snapshot.certificates` is an addition that lets HTTPS work before ACME. The rest of this section is the target; each part is described below.

## Run

```sh
cargo run                         # proxy on 127.0.0.1:8080, admin socket /run/podgate/admin.sock
ADMIN_SOCKET=/tmp/podgate.sock cargo run   # no /run/podgate access: pick another path
devenv up                         # same, as a devenv process with RUST_LOG set
curl --unix-socket /tmp/podgate.sock http://x/readyz
curl --unix-socket /tmp/podgate.sock -X PUT http://x/v1/snapshot -d @snapshot.json
curl -H 'Host: a.test' http://127.0.0.1:8080/
check                             # fmt, clippy, tests, docs, deny: the full gate (scripts/check.sh)
```

## Configuration

All settings are environment variables, read once at startup by `Config::from_env()`. An invalid value stops startup with an error that names the variable (`invalid PROXY_ADDR: ...`). Defaults suit local development; copy `.env.example` to `.env` to override (devenv loads it).

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_ADDR` | `127.0.0.1:8080` | Plain HTTP proxy listener. The container image sets `0.0.0.0:8080`. |
| `PROXY_TLS_ADDR` | unset | HTTPS proxy listener (HTTP/2 and HTTP/1.1). Unset means no TLS listener. The certificate comes from the snapshot's `certificates`, chosen by SNI. |
| `ADMIN_SOCKET` | `/run/podgate/admin.sock` | Unix socket of the admin API. Created with mode `0600`; its directory is created if missing; a stale socket file is replaced. |
| `REQUEST_TIMEOUT_SECS` | `30` | Whole seconds in 1..=3600. Admin requests longer than this get `408`. Connecting to, reading from and writing to an upstream each give up after it. It is also the shutdown grace period. |
| `LOG_FORMAT` | `pretty` | `pretty` or `json`. Use `json` in production. |
| `RUST_LOG` | `info` | Log filter, `tracing-subscriber` env-filter syntax (`info,podgate=debug`). Pingora's own `log` records are filtered by the same variable. |

Add a setting: field on `Config`, a branch in `Config::from_lookup` that returns `ConfigError { var, .. }`, a row here and in `.env.example`, a case in the `test` module.

## Endpoints

Proxy listeners (`PROXY_ADDR`, `PROXY_TLS_ADDR`): a request is routed by its `Host` (HTTP/1.1) or `:authority` (HTTP/2), compared case-insensitively without the port. An exact host beats a `*.` wildcard, and a wildcard matches exactly one label (`*.a.test` matches `x.a.test`, not `a.test` or `x.y.a.test`). New requests go only to `serving` revisions, split by weight; the backends of a revision take turns.

| Proxy answer | When |
|---|---|
| the upstream's response | the host has a route |
| `404 {"error":"not found"}` | no app claims the host, or the request has no host; also before the first snapshot |
| `503 {"error":"no upstream available"}` | the app has no `serving` revision with a positive weight and a backend |
| `421 {"error":"misdirected request"}` | a TLS request names a host other than its SNI and the app it names does not set `allow_domain_fronting` |
| `503 {"error":"tenant is over its in-flight limit"}` with `retry-after: 1` | the app's tenant already has `max_inflight` requests in flight |
| Pingora's `502`/`504` | the upstream refuses, resets or times out |

Admin API (unix socket `ADMIN_SOCKET`; only the PaaS agent on the node connects):

| Route | Answer |
|---|---|
| `GET /healthz` | Liveness. `200 {"status":"ok"}` whenever the process answers. Checks no dependency. |
| `GET /readyz` | Readiness. `200 {"status":"ready"}` while the admin API serves; `503 {"status":"not ready"}` before startup completes and while draining. It does not probe the proxy listeners: Pingora binds them on its own schedule and retries while a port is busy. |
| `PUT /v1/snapshot` | Replaces the routing table. `200 {"version":N}` when applied; `400` for malformed JSON; `409` when `version` is not greater than the live one (the table is unchanged); `422 {"error":"snapshot rejected","conflicts":[...]}` when it does not compile: conflicting declarations (see `### Snapshot conflicts`), an unknown tenant, a bad host, an unusable certificate, a `skew_secret` shorter than 16 bytes. Every entry of `conflicts` is an object with a `code` and a `message`. Bodies up to 16 MiB. The live version starts at `0`, so the first snapshot needs `version >= 1`. |
| `GET /metrics` | Prometheus text (`text/plain; version=0.0.4`): the per-tenant series listed under `## Memory budgets`. |
| `GET /v1/events?after=<seq>&timeout_secs=<n>` | Long poll of the event feed. `200 {"boot_id":"...","events":[{"seq":N,"kind":"revision_drained","app":"...","revision":"..."}]}` (other kinds: `{"kind":"wake_requested","app":"..."}`, `{"kind":"app_idle","app":"..."}`): events with `seq` greater than `after` (default `0`), oldest first; an empty list when none arrive within `timeout_secs` (default `0`: answer at once; capped at `REQUEST_TIMEOUT_SECS - 1` so the poll ends before the `408`). `410 {"error":"...","boot_id":"...","oldest":N}` when `after` is older than the 4096-event ring: resync. `400` for a malformed query. Sequence numbers start at `1` and restart with the process; compare `boot_id` to detect a restart. |
| `GET /v1/explain?url=<url>&method=<m>` | Why a request goes where it goes, read from the live routing table. `url` is absolute `http` or `https` (only scheme and host are read; `https` adds the TLS-only stages); `method` defaults to `GET`. `200 {"version":N,"host":"...","method":"...","app":"...","tenant":"...","declared_by":"...","matched":{"pattern":"*.a.test","kind":"exact"|"wildcard"},"revisions":[{"id":"...","state":"...","weight":W,"effective_weight":E,"upstreams":[...]}],"middleware":["route",...]}`. `effective_weight` is the weight new requests are picked with now: `0` unless the revision is `serving` with a positive weight and a backend. `middleware` is `proxy::middleware_chain`, in the order `request_filter` runs the stages; a stage that cannot act for the app (`sni_check` with `allow_domain_fronting`) is left out. `404 {"error":"not found","nearest_wildcard":"*.a.test"|null}` when no app answers for the host; the nearest wildcard is the declared one whose suffix is the longest suffix of the host, the host itself included (so `a.test` is nearest to `*.a.test`, which never matches it). `400` for a missing or invalid `url` or `method`. Read-only: it picks no backend and moves no counter. |
| `GET /v1/apps/{app}/failures` | `200 {"failures": [...]}`: the last 100 requests of the app that got a 5xx, newest first (see `### Failed requests`). `404` when the live table has no such app. |
| `POST /v1/apps/{app}/failures/{id}/replay?revision=<r>[&force=true]` | Re-sends a recorded request to the first upstream of revision `r` in the live table. `200 {"status","headers","body","body_truncated"}` with the upstream's new response, whatever its status; `400` without `revision`; `404` for an unknown app, record or revision; `409` for a method other than `GET` or `HEAD` unless `force=true`; `502` when the upstream cannot be reached; `503` when the revision has no upstream. |
| anything else | `404 {"error":"not found"}`. |

Errors: handlers return `Result<_, AppError>`. `AppError` renders `{"error": "<message>"}` with the matching status. `Internal` logs the cause and sends only `internal error`. No `unwrap()` outside tests.

## Requests in flight and the table

`Gateway::new_ctx` calls `TableHandle::load()` once and stores the `Arc<RoutingTable>` in the request's `Ctx`. Every callback of that request reads `ctx.table`, never the handle, so a snapshot swap mid-request cannot change its routing. `request_filter` resolves the route (`route::resolve`) into `ctx.route`; `upstream_peer` connects to `ctx.route.upstream`. `TableHandle::apply` takes a lock, checks the version, compiles, then swaps with `ArcSwap::store`; a failed compile or a stale version leaves the live table in place.

Counting and draining: once `request_filter` has a route it takes an `InflightGuard` for (app id, revision id) from `Inflight` and keeps it in `ctx.inflight`; it is released when the request ends and its `Ctx` drops. Counters live outside the table, so they survive swaps. After every successful apply, `PUT /v1/snapshot` calls `Inflight::sync` with the live table. A `draining` revision gets exactly one `revision_drained {app, revision}` per draining period: at once when `sync` finds it idle, otherwise when its last guard drops. A period ends when a later snapshot makes the revision non-draining, so draining it again emits again. A request that routed with a table older than the one that drained its revision is refused a guard and routes again with the live table (three attempts, then `503`).

## Memory budgets

`Tenant.budget` limits what one tenant can take from the proxy. `Budgets` (`src/budget.rs`) holds one `TenantBudget` per tenant id; it lives outside the routing table, so usage survives a snapshot swap, and `Budgets::tenant` refreshes the limits from the live table on every lookup.

- `max_inflight`: `request_filter` takes a slot after routing and after the revision is counted (`budget::admit`) and keeps the `TenantSlot` in `ctx.tenant_slot` until `logging`. A tenant at the cap gets `503 {"error":"tenant is over its in-flight limit"}` with `retry-after: 1`.
- `max_buffer_bytes`: the only buffer the proxy allocates per response is the gzip encoder (`src/compress.rs`). `response_filter` charges `compress::RESERVATION_BYTES` (640 KiB) to the tenant before it allocates the encoder. A charge that does not fit means the response goes out as the upstream sent it: compression degrades to identity encoding, nothing is refused. The charge ends when the stream ends or the request is logged.
- Compression applies to `200` responses to `GET` and `POST` over HTTP/1.1 and HTTP/2 whose content type is text-like, that carry no `content-encoding` or `cache-control: no-transform`, and whose `content-length`, when known, is at least 256. Only gzip is offered.
- `GET /metrics` reports every tenant: `podgate_tenant_buffer_bytes` (charged now), `podgate_tenant_buffer_bytes_peak` (highest since start; never above the limit), `podgate_tenant_inflight`, `podgate_tenant_inflight_rejected_total` and `podgate_tenant_compression_skipped_total`.

## Middleware

Admin API only. Outermost first: request id (`x-request-id`: keep the caller's, else a UUID), `TraceLayer` (span per request with method, path, request id), request id copied to the response, timeout.

Timeouts return `408 Request Timeout` with an empty body, always. On the admin API, `503` is reserved for readiness, so the two never get confused in dashboards.

## Shutdown

Pingora owns signals. SIGTERM (graceful): `/readyz` turns `503` at once, the proxy listeners stop accepting, and the process exits after `REQUEST_TIMEOUT_SECS` (Pingora's grace period is a fixed wait, so a SIGTERM always takes that long) so in-flight requests finish. SIGINT exits immediately; SIGQUIT is Pingora's graceful upgrade signal. The admin socket file stays behind after exit; the next start replaces it. Set the orchestrator's kill timeout above `REQUEST_TIMEOUT_SECS` (Kubernetes: `terminationGracePeriodSeconds`, Docker: `--stop-timeout`).

## Observability

- Logging uses `tracing`. `LOG_FORMAT=json` gives one JSON object per line on stdout; otherwise pretty output. Filter with `RUST_LOG`.
- Admin request spans carry `request_id`.
- Libraries and handlers only emit events (`tracing::info!`, `error!`); `init_tracing` in the binary owns output. Pingora logs through `log`, which `tracing-subscriber` bridges.

## Deploy

```sh
docker build -t podgate .
docker run --rm -p 8080:8080 -v podgate-admin:/run/podgate podgate
```

- Build stage `rust:1.99-slim` installs `cmake` (Pingora's zlib-ng build needs it) and runs `cargo build --release --locked`, so `Cargo.lock` must be committed.
- Runtime stage `gcr.io/distroless/cc-debian12:nonroot`: no shell, runs as non-root, proxy on 8080, admin socket `/run/podgate/admin.sock` (a directory owned by `nonroot`).
- The admin API is a unix socket, so there is no HTTP port to probe. The PaaS agent shares the socket directory (a volume) and calls `/healthz` and `/readyz` there.
- Bump the `rust:` tag together with `rust-toolchain.toml`.

## Conventions

- Lints in `Cargo.toml` (`docs/rust-style.md`); `exhaustive_*` allowed because this is application code.
- Dependencies: add only when std cannot do it in a few lines; `cargo deny check` gates licences and advisories. Pingora is built with `proxy`, `lb` and `rustls`: no C TLS stack in the binary.
- Tests: unit tests in a `mod test` leaf, end-to-end tests in `tests/<feature>.rs` on `tests/common`.
