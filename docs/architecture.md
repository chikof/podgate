# Architecture

podgate is a reverse proxy on Pingora, configured only by snapshots the PaaS control plane pushes over a unix-socket admin API. A Cargo workspace: the daemon is the root package (a library, testable, and a thin binary) and the other crates live under `crates/`. `## Target architecture` is the design every spec builds on; `## Snapshot model v2` is the routing, service and middleware model that replaces the v1 snapshot entities and assigns every module to an owner; `## Layout` and the sections after it describe what exists today.

## Layout

| Path | Role |
|---|---|
| `src/main.rs` | Thin: `Config::from_env()`, `init_tracing`, `run(&config)`. |
| `src/lib.rs` | Module declarations, re-exports, `init_tracing`, and `run(config)`, which builds the Pingora `Server`. |
| `src/config.rs` | `Config` and `LogFormat` read from environment variables; `ConfigError` names the bad variable. |
| `src/error.rs` | `AppError`: the one error clients see, `{"error": "..."}` with a status. Conversions from `ApplyError` and `RouteError`; a rejected snapshot lists its `conflicts` as objects. |
| `crates/podgate-model/` | The `podgate-model` crate: `Snapshot` and the entities under it (`App`, `Router`, `Declared`, `Revision`, `SkewSecret`, entry point policies, L4 and observability models), the serde model of `PUT /v1/snapshot`. Depends on `serde` and `serde_json` only (`schemars` behind the `schema` feature), so the daemon, `podgate-provider` and tools that build snapshots share the types without compiling Pingora or wasmtime. Files: `src/lib.rs` (envelope entities), `src/{entry_point,l4,observe,secret}.rs`. Kind configuration stays an opaque `serde_json::Map` in `Declared`; the daemon's kind modules parse it. Import path: `podgate_model::{Snapshot, App, ...}`. New crates go under `crates/` (`podgate-provider` in change 0069); the root `Cargo.toml` is `[workspace]` plus the daemon `[package]`, with `[workspace.lints]` shared by every member. |
| `src/host.rs` | Host patterns (`HostPattern`), request host normalization, `HostMap` (exact beats one-label wildcard). |
| `src/table.rs` | `RoutingTable` (compiled snapshot: apps with routers, middleware stages, services and revisions; weighted pick over `serving` revisions; `rematch`), `TableHandle` (atomic swap, `apply`), `CompileError`, `ApplyError`. |
| `src/conflict.rs` | `Conflict`: one typed variant per conflict code (`host_conflict`, `route_ambiguity`, `tls_policy_conflict`, `cross_tenant_wildcard`, `cross_tenant_catch_all`) and the pass that finds all of them in the routers of a snapshot. |
| `src/route.rs` | Core routing: `matching(table, request, entry_point, tls) -> Option<Matched>` and `select(table, matched, request) -> Selected` (revision, skew pin, server). Pure; no Pingora session. |
| `src/router.rs`, `src/router/*.rs` | Routers: `CompiledRouter`, the host `Index`, the order `Key` (priority, host rank, specificity, names), tenant isolation of fallback routers, path normalization (`path.rs`), the matcher tree (`matcher.rs`, one file per leaf in `matcher/`). |
| `src/compile.rs` | The compile passes (`build`) and what they refuse with: `Invalid` (a kind's code and message) and `Rejected` (placed in the snapshot, listed in the `422`). |
| `src/middleware.rs`, `src/middleware/*.rs` | The per-route middleware chain: the `Kind` trait, the `kinds!` registry that generates `Stage` and its dispatch, `run_request` and the response hooks; one file per kind (`wasm.rs` today). |
| `src/service.rs`, `src/service/*.rs` | Services: `loadbalancer` with `round_robin` (`lb/`), `ServerState`; empty modules for health, outlier ejection, sticky, transports and DNS. |
| `src/entry.rs`, `src/pipeline.rs`, `src/l4.rs`, `src/observe.rs` | Entry points (`CompileContext`, `normalize_request`), the platform stage list for explain, and the L4 and observability models with their `*_not_built` rejections. |
| `src/events.rs` | `EventFeed` (bounded ring of 4096, `emit`, long-poll `poll`, per-process `boot_id`), `Event`, `EventKind`. Features emit into it. |
| `src/inflight.rs` | `Inflight`: per-revision in-flight counters keyed by (app id, revision id), lock-free atomics on the request path (one registry swap per `sync`), `InflightGuard`, and the `revision_drained` event. |
| `src/proxy.rs` | `Gateway` (the Pingora `ProxyHttp`) and the per-request `Ctx`. `request_filter` runs the platform stages in the order `src/pipeline.rs` documents and reports to explain. |
| `src/explain.rs` | `Target::parse` (the `url`, `method` and `entry_point` of an explain query) and `explain(table, target)`: why a request goes where it goes, read from the live `RoutingTable` and its router index (`find_all`, `nearest_wildcard`, `effective_weight`). |
| `src/outcomes.rs` | `Outcomes`: response outcomes (total, `5xx`) per (app id, revision id) over a sliding window, recorded in `Gateway::logging` by `record_request`. Read by auto-revert; the canary reads per revision. |
| `src/plan.rs` | `diff(live, candidate) -> Plan` (added, removed, changed hosts, posture changes) and `changed_apps`: the diff of two compiled tables. |
| `src/revert.rs` | `Reverter`: after every snapshot push, watches the `5xx` ratio of the apps it changed and restores the previous table on a spike. |
| `src/canary.rs` | SLO-driven canary: `Canary` policy validation (`canary_*` codes), the live share and verdict kept in a `Registry` outside the table (`Fingerprint`-keyed, settled on every swap), `judge` (ramp, hold, regress and the `canary_regressed` event) and `CanaryService`, the background ticker. `CompiledApp::reweigh` in `table.rs` is the one place effective weights are defined. |
| `src/respond.rs` | `write_error`: answers a proxied request with an `AppError`. |
| `src/budget.rs` | `Budgets` (per-tenant registry that survives snapshot swaps), `TenantBudget`, the `TenantSlot` and `BufferGuard` RAII charges, `admit`, and the Prometheus rendering. |
| `src/fairq.rs` | Backend admission: `Backends` (limiters per upstream address), `Limiter` (adaptive gradient limit plus weighted fair queues), `Permit` and the per-request `Slot`; see `## Backend admission`. |
| `src/compress.rs` | Gzip response compression on `miniz_oxide` (pure Rust) with its memory charged up front: `start`, `filter`, `RESERVATION_BYTES`. |
| `src/tls.rs` | `CertStore` (certificates of a snapshot) and the TLS listener settings that choose the certificate by SNI per handshake. |
| `src/sni.rs` | The TLS check that a request's `Host` and `:authority` equal the connection's SNI: `CaptureServerName` (handshake hook that records the SNI on the connection) and `check`, called first in `request_filter`. |
| `src/clientauth.rs` | Client certificates per app: `ClientAuth` (the app's compiled CA), `HandshakeVerifier` (asks for a certificate by SNI), `admit` (per-request check against the routed app, called after `sni::check`), `ClearDecision` (pre-TLS wrapper), `Rejection`. |
| `src/acme.rs`, `src/acme/*.rs` | HA ACME and on-demand TLS. `acme.rs`: `Acme` (the node's handle: a background service for the issuer loop and Pingora's pre-TLS hook) and `PrivateKeyPem`. `plan.rs`: `Plan`, the ACME view compiled with each snapshot (HTTP-01 answers, hosts lacking a certificate, certificates' validity). `issuer.rs`: the loop that orders and renews. `handshake.rs`: reads the ClientHello and waits for an on-demand certificate. `http01.rs`: `serve_challenge`, called first in `request_filter`. |
| `src/pool.rs` | Upstream connection pool isolation: `isolate` sets the peer's `group_key` from `(tenant, app, revision)` (Pingora adds the upstream address), and pins connections that carried `Authorization: NTLM` or `Negotiate` to their downstream connection (`State`, carried across keepalive requests by `persist`/`restore`). Called from `upstream_peer`. |
| `src/skew.rs` | Skew protection: `SkewSecret`, the signed `__podgate_rev` cookie, `pinned` (called by `route::resolve`) and `set_cookie` (called by `response_filter`). |
| `src/wake.rs` | Scale to zero: `Wake` holds requests for an app with no upstream (`hold`, woken by `TableHandle::subscribe`), emits `wake_requested` once per wake cycle, hands the held tenant slot on in `admit`, and `sweep` emits `app_idle`; `WakeService` runs the sweep as a background service; `State` is the per-request field of `Ctx`. |
| `src/wasm.rs` | The WASM engine behind the `wasm` middleware: `Compiler` validates and compiles a module at snapshot compile, `run_filter` runs it per request with fuel and a memory limit, the proxy-wasm host functions. |
| `src/wasm/executor.rs` | `Executor`: the bounded filter pool (`WASM_MAX_CONCURRENT` permits, `WASM_QUEUE_TIMEOUT_MS` wait) and the per-run memory charge; `Gateway::with_wasm`. |
| `src/wasm/wasi.rs` | The `wasi_snapshot_preview1` stubs a filter may import (clock, entropy, `proc_exit`, empty environment and arguments, `fd_write` to the log). |
| `src/admin.rs` | The admin router (`router`), `AppState`, the unix socket (`bind`, mode `0600`) and `AdminService`, a Pingora background service. |
| `src/admin/*.rs` | One module per endpoint group, each with `fn routes() -> Router<AppState>`: `health.rs`, `metrics.rs`, `snapshot.rs`, `plan.rs`, `events.rs`, `explain.rs`, `failures.rs`. |
| `src/failures.rs` | `Failures`: per-app rings of failed requests (header redaction, opt-in bodies via `Capture`), and `replay`. `Gateway::with_failures` and `AppState::with_failures` share one recorder; hooks in `request_filter`, `request_body_filter`, `response_filter`, `response_body_filter` and `logging`; see `### Failed requests` for the order against compression. |
| `tests/common/mod.rs` | Test harness: `Podgate::start()` spawns the built binary on free ports with a temp admin socket; `push_snapshot`, `get`, `https_get`; `Upstream::start(body)`; `TestCert`; snapshot builders. Include with `mod common;`. |
| `tests/proxy.rs` | End-to-end tests through the real binary. New features add their own `tests/<feature>.rs`. |
| `tests/sni.rs` | SNI against Host: 421 on mismatch over HTTP/1.1 and HTTP/2 (including `:scheme http`), the `allow_domain_fronting` opt-in, matching hosts served. |
| `tests/mtls.rs` | Client certificates end to end: valid client served over TLS 1.3 and 1.2, missing or foreign certificate gets 403, no certificate request for hosts without a CA, invalid CA rejected with 422, fronting cannot bypass, the subject header. |
| `tests/explain.rs` | End-to-end: `GET /v1/explain` for known, wildcard and unknown hosts, bad queries, and answers that follow a snapshot swap. |
| `tests/skew.rs` | Skew protection end to end: cookie set and HMAC-signed, `serving` and `retiring` revisions pin, `draining`, removed, tampered and other-app cookies fall back, no cookie without `skew_secret`. |
| `tests/wake.rs` | Scale to zero through the real binary: one `wake_requested` per cycle, release on snapshot, `503` after `wake_timeout_secs`, `app_idle`, and held requests counting against `max_inflight`. |
| `tests/canary.rs` | Canary through the real binary: ramp and promotion with the observed traffic split, regression and the single event, explain, rejected policies, reset by a changed policy or serving set, survival across pushes that touch only other apps, and sessions unpinned from a regressed canary. |
| `tests/conflict.rs` | End-to-end: conflicting snapshots get a `422` naming every conflict, and the previous snapshot keeps serving. |
| `tests/pool.rs` | Pool isolation through the real binary with an upstream that numbers its connections: per tenant, app and revision, and NTLM/Negotiate pinning. |
| `tests/failures.rs` | Failed-request ring, redaction, opt-in bodies, replay and the method guard, with an upstream that returns 5xx on demand. |
| `tests/wasm.rs` | Filters written in WAT through the real binary: headers edited, fuel exhaustion and memory limit end in `500` while other requests are served, forbidden imports are `422`, local responses. |
| `tests/plan.rs` | `POST /v1/snapshot/plan`: the host diff, posture changes, and that nothing is applied. |
| `tests/revert.rs` | Auto-revert through the real binary: a `5xx` spike reverts and emits `config_reverted`; an unrelated app's outage does not. |
| `tests/budget.rs` | Tenant budgets through the real binary, observed on `GET /metrics`: the buffer budget holds under concurrent compressible responses, `max_inflight` answers `503`. |
| `tests/events.rs` | Event feed and drain handshake through the real binary: `revision_drained` only after the in-flight request ends, once per draining period, long poll timeout and wake-up, `after` resume, `boot_id`, malformed queries. |
| `tests/fairq.rs` | Requests pass through the per-backend limiter, visible as `podgate_backend_*` on `GET /metrics`. The weighted order and the limit are unit tests in `src/fairq.rs`. |
| `tests/inflight_alloc.rs` | The in-flight hot path allocates nothing. Its own test binary, with a counting global allocator. |
| `tests/wasm_budget.rs` | Filter memory charged to the tenant (`503` over budget, peak and refusal metrics) and the bounded filter pool (queued filter runs refused, snapshot pushes and other tenants unaffected). |
| `tests/acme.rs` | End-to-end against `pebble` (with `pebble-challtestsrv` as its DNS, so HTTP-01 is validated for real): the test plays the control plane. A missing `pebble` fails the tests. |
| `examples/slow_upstream.rs` | A backend with a fixed latency and capacity (`slow_upstream <addr> <latency_ms> <capacity>`), for `scripts/load-fairness.sh`. |
| `scripts/load-fairness.sh` | Load test of the per-tenant fair queue: tenant A floods at 1000 rps, tenant B sends 10 rps, with `oha` against the `podgate` binary and `slow_upstream`; see `## Backend admission`. |
| `scripts/bench-proxies.sh`, `bench/` | Benchmark of podgate against Caddy and Traefik on one machine: the script, the Caddy and Traefik configs and the podgate snapshot it renders. `examples/fast_upstream.rs` is its backend and `examples/bench_cert.rs` writes the shared certificate. Method and results: `docs/benchmarks.md`. |
| `Dockerfile`, `.dockerignore` | Multi-stage image on distroless; the dependency-cache layer copies each workspace member's manifest, so a new crate adds one `COPY` line. |

### Adding a feature

Features are added by extension, so parallel work merges as one-line changes:

- **Proxy callback.** Each `ProxyHttp` callback in `src/proxy.rs` is a short sequence of calls into per-feature modules. A feature adds `src/<feature>.rs` with its logic as plain functions, one field on `Ctx` (default in `Gateway::new_ctx`), and one line in each callback it hooks. Core host routing stays in `route.rs`.
- **Admin endpoint.** A feature adds `src/admin/<feature>.rs` with `fn routes() -> Router<AppState>` and one `.merge(<feature>::routes())` line in `admin::router`. Handlers return `Result<_, AppError>`.
- **Snapshot field.** Add the field to the entity in `crates/podgate-model/src/lib.rs` with `#[serde(default)]`, never `deny_unknown_fields`; compile it in `table.rs`. An absent field means the feature is off.
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
|`App`|`id`, `tenant`, `declared_by` (free text naming the source, used in errors and explain), `hosts` (exact names, or one leading `*.` wildcard), `tls` (`mode`: `acme` or `on_demand`; optional `client_ca_pem` and `pass_client_cert`), `revisions`|
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

`Snapshot` also takes an optional `revert_window_secs` (u64, default `60`, `0` turns auto-revert off, values above `300` are treated as `300`); see `## Plan and auto-revert`.

`App` also takes an optional `canary` (`revision`, `step_percent`, `interval_secs`, `max_error_permille`); see `### Canary`.

`Snapshot` also takes an optional `acme` object (issuer node, directory URL, HTTP-01 answers, ...); see `## ACME and on-demand TLS`. Absent, podgate orders nothing and serves only `certificates`.

### Compile and swap

The snapshot is compiled into an immutable routing table and swapped atomically. Requests in flight keep the table they started with. A rejected snapshot leaves the current one live.

### Revision states

`serving` revisions get new sessions by weight. `retiring` revisions get no new sessions but still serve sessions pinned to them. `draining` revisions get no new requests at all. In-flight requests finish.

### Canary

`App.canary` ramps one `serving` revision up while its own `5xx` rate stays low. The snapshot owns the policy; podgate owns the live share. It is kept outside the table, in a registry owned by `TableHandle` and settled at its one swap site, keyed by app id and a fingerprint of the canary policy plus the app's serving set (every revision's id, state and weight; never its backends, so autoscaling does not reset a verdict). A swap that leaves the fingerprint as it was hands the new table the same runtime, so a push that only changes other apps (the snapshot is global across tenants) neither restarts a ramp nor revives a regressed canary. A change to the policy or the serving set, including an auto-revert that restores a different one, starts the canary over; entries of apps that lost their canary are dropped. The revisions' effective weights are shared with the runtime, so tables still held by in-flight requests follow the share too.

- Weights: the canary gets `share` percent of new, unpinned sessions; the other `serving` revisions with a weight split the rest by their configured weights. The canary's own `weight` is ignored. The share starts at `step_percent`. While an app has a canary, `effective_weight` counts in parts of 10000 shared by its revisions (the canary at 25 percent shows `2500`); the picker and `GET /v1/explain` read the same value. If no other revision takes requests, the canary takes all of them while its share is above `0`.
- Judging: every `interval_secs` (the first one second after the snapshot goes live) the canary's `5xx` rate comes from `Outcomes::window` for its revision, over the time since the last decision. With fewer than 20 requests the share holds and the window keeps growing. Below `max_error_permille` the share grows by `step_percent` up to `100`, where judging stops (promoted). At or above it the share drops to `0` for good and `canary_regressed {app, revision, error_permille}` is emitted once. Only a change to the canary policy or the app's serving set gives the canary traffic again.
- Sessions: a regressed canary is refused by skew protection (`pick_pinned`), so sessions pinned to it fall back to the weighted pick and get a fresh cookie.
- Auto-revert: while the pushed snapshot has a canary policy, the canary revision's `5xx` do not count toward auto-revert of its app; the other revisions still do.
- Compile: a policy that names no revision, a revision that is not `serving`, a `step_percent` outside `1..=100`, an `interval_secs` of `0`, a `max_error_permille` outside `1..=1000`, or no other serving revision with a weight to share traffic with, is refused with `422` and the codes `canary_revision_missing`, `canary_revision_not_serving`, `canary_step_invalid`, `canary_interval_invalid`, `canary_threshold_invalid` and `canary_no_baseline`, each with `app` and `declared_by`.

### Event feed

`GET /v1/events?after=<seq>&timeout_secs=<n>` is a long poll. It returns the ordered events with sequence numbers greater than `after`, or an empty list after the timeout. The event kinds are `revision_drained`, `wake_requested`, `app_idle`, `config_reverted`, `config_revert_failed`, `canary_regressed`, `acme_challenge`, `certificate_issued` and `certificate_requested`.

`canary_regressed` carries `app`, `revision` and `error_permille` (the canary's `5xx` per thousand requests over the judged window).

`config_reverted` carries `from_version` (the snapshot that was reverted; the live version stays at this number) and `to_version` (the version of the snapshot serving again). `config_revert_failed` carries `from_version`, `to_version` and `error`: a `5xx` spike called for a revert but the previous snapshot no longer compiles (a certificate that expired meanwhile, say); the current table stays live and the change is no longer watched.

Change 0014 adds the payloads of `acme_challenge`, `certificate_issued` and a new `certificate_requested`; see `## ACME and on-demand TLS`.

### Error shape

Admin API errors are `{"error": "<message>"}`, the same shape `AppError` renders today. A snapshot rejected by the compiler returns `422` with `{"error": "snapshot rejected", "conflicts": [...]}`.

Every entry of `conflicts` is an object with a stable `code` and a human `message`. Conflicts between declarations carry the fields documented in `### Snapshot conflicts`; other compile failures use the codes `invalid_host`, `unknown_tenant` and `invalid_certificate`.

WASM filter failures use the codes `wasm_invalid` and `wasm_forbidden_import`; see `### WASM filters`.

Canary policy failures use the codes `canary_revision_missing`, `canary_revision_not_serving`, `canary_step_invalid`, `canary_interval_invalid`, `canary_threshold_invalid` and `canary_no_baseline`; see `### Canary`.

A bad `acme` object or an unreadable certificate validity is code `invalid_acme`.

A `tls.client_ca_pem` that holds no certificate or an unusable one is code `invalid_client_ca`, one entry per app with its `app` and `declared_by`; see `## Client certificates`.

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

**Limits.** The engine uses wasmtime with Cranelift; there is no async and no component model. Snapshot compile (and so the admin `PUT`) pays for compiling the modules, on the blocking pool. Filter runs are bounded separately by `wasm::Executor`: at most `WASM_MAX_CONCURRENT` run at once, a run waits up to `WASM_QUEUE_TIMEOUT_MS` for a worker, and each run reserves its `max_memory_bytes` from the tenant's `max_buffer_bytes` first (see `## Memory budgets`). Over either limit the request gets `503` with `retry-after: 1` and the filter does not run, so filters can neither fill the blocking pool snapshot compiles need nor hold more memory than the tenant's budget.

### Not built yet

HTTP/3: Pingora 0.9 has no HTTP/3 server. Every other part of this section is built; each part is described below.

## Snapshot model v2

Design of change 0022, the shared contract for the feature specs after it. The v1 model (`App.hosts`, `App.revisions[].upstreams`, `App.filters`) is gone; no v1 reader is kept. The sections `### Snapshot`, `### WASM filters` and `### Canary` above describe the v1 field names for their features; read `hosts` as the `host` matchers of routers and `filters` as `wasm` middlewares. Nothing in this section changes `## Target architecture`: one process per node, one writer, push only.

### Invariants

1. **Push only, one writer.** A node's snapshot has exactly one writer: either podkit's agent or `podgate-provider` (a program in this repository that merges Docker and Podman labels, Kubernetes Gateway API, Ingress and CRDs, Nomad and a file into one snapshot), never both on one node. Providers run outside the proxy, and `declared_by` keeps the provenance of every merged piece. podgate never merges: conflicting declarations reject the snapshot whole.
2. **Fail closed.** A setting podgate cannot honour is rejected at compile with `422`, never ignored. An unknown middleware, service or matcher kind, an unknown field inside a kind's configuration, an unknown name, and a knob Pingora cannot apply are all rejections. Envelope entities (`Snapshot`, `App`, `Router`, `Revision`) still ignore unknown fields, so an older podgate accepts a newer snapshot that only adds optional envelope fields.
3. **Tenancy is structural.** Every router, service, middleware and transport lives inside one app, and an app belongs to one tenant. Names resolve inside the app only. No object refers to an object of another app, so a tenant cannot reach another tenant's configuration, and the control plane copies a shared middleware into every app that uses it.
4. **Absent means off.** An absent optional field turns its feature off, as in v1.
5. **One compiled table.** Routing, explain, plan, auto-revert, canary, wake and failures all read the compiled `RoutingTable`, never the snapshot.

### Entities

|Entity|Fields (`?` = optional, absent means off)|
|---|---|
|`Snapshot`|`version`, `tenants`, `apps`, `certificates?`, `skew_secret?`, `revert_window_secs?`, `acme?`, `entry_points?` (policies), `observability?`. Unchanged from v1 except the last two.|
|`Tenant`|`id`, `weight`, `budget` (`max_inflight`, `max_buffer_bytes`). Unchanged.|
|`App`|`id`, `tenant`, `declared_by`, `tls` (unchanged: `mode`, `client_ca_pem?`, later TLS options), `allow_domain_fronting?`, `record_bodies?`, `scale_to_zero?`, `canary?`, `default_chain?`, `routers`, `middlewares?`, `services?`, `transports?`, `revisions`, `tcp?`, `udp?`. The v1 fields `hosts` and `filters` are gone: hosts are matchers of routers, filters are middlewares of type `wasm`.|
|`Router`|`name`, `entry_points?`, `match` (matcher tree), `priority?`, `chain?` (names of middlewares), `service` (service reference), `observability?`, `declared_by?` (defaults to the app's).|
|`Declared`|The shape of every kind-tagged object: `{"name": "...", "type": "...", <the kind's own fields>}`. Used by `middlewares`, `services`, `transports` and the L4 equivalents. The envelope holds the kind's fields as an opaque JSON map; the kind's module owns their type and parses them with `deny_unknown_fields`.|
|`Revision`|`id`, `state` (`serving`, `retiring`, `draining`), `weight`, `services` (the `Declared` services of this release). The v1 `upstreams` become a service of type `loadbalancer`.|
|`Server`|`url` (`http://ip:port`, `https://...`, `h2c://...`), `weight?` (default 1). Used by load balancers.|
|`EntryPointPolicy`|`name`, `tenants?` (allowed tenants), `forwarded_headers?`, `proxy_protocol?`, `timeouts?`, `http2?`, `redirect?`, `allow_encoded_slash?`. Request-time policy of a listener that the process configuration declared.|

Shape of one app (revision `r7` serving, a strip-prefix middleware, two routers, one service):

```json
{
  "id": "shop", "tenant": "acme", "declared_by": "podkit/agent",
  "tls": { "mode": "acme" },
  "default_chain": ["security-headers"],
  "middlewares": [
    { "name": "security-headers", "type": "headers", "response": { "hsts_max_age_secs": 31536000 } },
    { "name": "no-api-prefix", "type": "strip_prefix", "prefixes": ["/api"] }
  ],
  "routers": [
    { "name": "api", "match": { "all": [ { "host": "shop.example.com" }, { "path_prefix": "/api" } ] },
      "chain": ["no-api-prefix"], "service": "web" },
    { "name": "site", "match": { "host": ["shop.example.com", "www.shop.example.com"] }, "service": "web" }
  ],
  "revisions": [
    { "id": "r7", "state": "serving", "weight": 100,
      "services": [ { "name": "web", "type": "loadbalancer", "algorithm": "round_robin",
                      "servers": [ { "url": "http://10.0.0.5:8080" } ] } ] }
  ]
}
```

Names (`routers`, `middlewares`, `services`, `transports`) are unique inside an app per kind of object (`duplicate_name`). Hosts keep the v1 grammar: an exact name or one leading `*.`, which covers exactly one label.

### Entry points

**Decision: bind-time facts stay process configuration, request-time policy goes in the snapshot.** Pingora binds its sockets before the server runs, so a snapshot cannot open a port; Traefik has the same split (static entry points, dynamic routers). `ENTRY_POINTS` (new) lists them: `name=address/protocol`, comma separated, protocol one of `http`, `https` (TLS termination, HTTP/2 and HTTP/1.1), `tcp`, `udp`; an option after the protocol, `;proxy_protocol`, accepts a PROXY protocol header from the peers the snapshot trusts. `PROXY_ADDR` and `PROXY_TLS_ADDR` stay as the shorthand for the built-in entry points `web` (`http`) and `websecure` (`https`); setting them together with `ENTRY_POINTS` stops startup with an error that names both.

- A router lists `entry_points`; absent means every `http` and `https` entry point, which is what a v1 app did. Naming an entry point the node did not bind is `unknown_entry_point`. The compiler learns the bound names from `CompileContext`, which `TableHandle` carries (default: `web`, `websecure`), so a snapshot written for another node fails closed instead of exposing a router on the wrong port.
- `EntryPointPolicy.tenants` limits which tenants may attach routers to it (`entry_point_forbidden`). A raw `tcp` or `udp` entry point such as a database port belongs to one tenant; the HTTP entry points default to all.
- `forwarded_headers.trusted_ips`: peers whose `X-Forwarded-*` and `Forwarded` headers are kept. For every other peer podgate overwrites them. `insecure: true` keeps them from everyone and is a posture change in a plan.
- `redirect {to, permanent}`: answer every request on this entry point with a redirect to another entry point, after the ACME HTTP-01 answer and before routing (Traefik's entry point redirection).
- `timeouts` (`read_secs`, `write_secs`, `idle_secs`, `header_secs`) and `http2` (`max_concurrent_streams`): applied if Pingora exposes the knob, `unsupported_setting` otherwise. The owner of that spec reads `pingora-core` before promising either.
- `allow_encoded_slash`: see path normalization below.

### Routers and matchers

A router is a matcher tree, a middleware chain and a service reference. The matcher is JSON, not a rule string like Traefik's `Host(...) && PathPrefix(...)`: it is typed, needs no escaping, and can be canonicalized, which the ambiguity check relies on. A provider that reads Traefik rules translates them.

Every matcher is an object with exactly one key; anything else is `invalid_matcher`.

|Matcher|Meaning|Module (`src/router/matcher/`)|
|---|---|---|
|`{"host": "a.test"}`, `{"host": ["a.test", "*.b.test"]}`|Exact or one-label wildcard; a list is any-of. Compared lowercase without port or trailing dot.|`host.rs`|
|`{"host_regexp": "..."}`|Regular expression over the normalized host. Combine it with a literal `host` in an `all` to narrow a claim; on its own it is a catch-all router and needs the entry point or the operator to allow it (`catch_all_not_allowed`).|`host_regexp.rs`|
|`{"path": "/x"}`, `{"path_prefix": "/api"}`, `{"path_regexp": "..."}`|Over the normalized path. A prefix matches whole segments: `/api` and `/api/x`, not `/apix`.|`path.rs`, `path_prefix.rs`, `path_regexp.rs`|
|`{"method": ["GET", "HEAD"]}`|Any-of, case-sensitive tokens.|`method.rs`|
|`{"header": {"name": "x-env", "value": "canary"}}`, `{"header_regexp": {"name": "...", "regex": "..."}}`|Header names are case-insensitive, values exact or regex. Several headers of one name match if any does.|`header.rs`, `header_regexp.rs`|
|`{"query": {"name": "debug", "value": "1"}}`, `{"query_regexp": {...}}`|Decoded query parameter.|`query.rs`, `query_regexp.rs`|
|`{"client_ip": ["10.0.0.0/8", "::1"]}`|The peer address, or the address behind the trusted forwarded headers of the entry point.|`client_ip.rs`|
|`{"all": [...]}`, `{"any": [...]}`, `{"not": {...}}`|Boolean combination; nest freely, depth at most 8.|`combinator.rs`|

L4 routers (below) use the same tree with the leaves `sni`, `sni_regexp`, `alpn` and `client_ip`. Built today: `host`, `host_regexp`, `path`, `path_prefix`, `path_regexp`, `method` and the combinators. `header`, `header_regexp`, `query`, `query_regexp` and `client_ip` are planned and refused with `matcher_not_built`; any other key is `invalid_matcher` (`invalid_host` for a bad host).

Regular expressions use the Rust `regex` crate: linear time, no backreferences, no lookaround, so a tenant cannot write a ReDoS, and the syntax is close to the RE2 that Traefik's Go uses. Each regex has a compiled-size limit; over it is `invalid_matcher`.

**Path normalization.** Matchers see the path with percent-encoded unreserved characters decoded, dot segments removed and empty segments collapsed, and the upstream receives that same path, so the path that was authorised is the path that is served. A request whose path contains an encoded `/` or `\`, a NUL, or an encoded dot segment that decodes to `..` after one decode is refused with `400` before routing, unless the entry point sets `allow_encoded_slash` (a posture change).

### Priority, ambiguity and conflicts

Routers of all apps form one match structure per entry point, indexed by host for exact and wildcard hosts, with a short list for routers with no literal host (host regexp or none). A request takes the first router in this order that matches:

1. `priority` (`i32`, absent counts as `0`), higher first. This is Traefik's explicit priority. A Traefik translator sets it to the rule length to reproduce Traefik's default order; podgate itself never orders by rule length.
2. Specificity, a tuple compared left to right: host (exact `3`, wildcard `2`, regexp `1`, none `0`), path (exact `4`, prefix `3` and then more segments first, regexp `2`, none `0`), then the count of other constraints (method, header, query, client IP). `all` takes the largest per component, `any` the smallest, `not` counts as none. So an exact host beats a wildcard, as in v1.
3. `(app id, router name)`, so the order is total and the same on every node.

**Ambiguity.** Two routers that share a host claim (or have none) and have the same `(priority, specificity)` are *ambiguous* unless they are provably disjoint. Disjoint means some leaf pair can never both match: two different exact paths, prefixes that are not nested, different exact values of one header, disjoint method sets or CIDR ranges. Each leaf file implements `disjoint(other)`; regular expressions are never provably disjoint. Ambiguity rejects the snapshot. It lists both routers and both `declared_by` values.

Host ownership: a literal host pattern is claimed by the positive `host` leaves of routers (a leaf under `not` claims nothing). A tenant owns the patterns it claims.

**Priority never orders routers across tenants.** Two rules make that hold:

- A literal host is claimed by one tenant only (`host_conflict`), and no tenant may claim a host under another's wildcard (`cross_tenant_wildcard`), so for any host all routers with a literal claim belong to one tenant, and priority only orders those.
- A *fallback* router (a `host_regexp` with no literal host beside it, or no host constraint) can match hosts nobody claims right now: an app in a redeploy gap, a deleted app, a lookalike domain. Whoever declared it first would receive that traffic, and browsers would send it the cookies of the real app, a subdomain takeover. So it compiles only if every entry point it listens on has a policy whose `tenants` names that tenant alone, or the operator lists the tenant in `CATCH_ALL_TENANTS`; otherwise the snapshot is refused with `catch_all_not_allowed`. Even then it matches only hosts that no other tenant claims with a literal host, so it cannot capture another tenant's host or paths whatever its priority: with `{"host_regexp": ".*"}` at `i32::MAX`, tenant B still loses `a.test` (claimed by tenant A) on every path, including paths A has no router for (`404`). Fallbacks of two tenants on a shared entry point are refused (`cross_tenant_catch_all`), because no order between them would be fair.
- A `host_regexp` that sits in an `all` next to a literal `host` is not a fallback. The literal claim (an exact name or a `*.` wildcard the tenant owns under the rules above) bounds the router, it is indexed and matched under that claim only, and the regexp can only narrow it, never widen it. podgate never reads the regexp text to decide what it may match: `{"all": [{"host": "*.a.test"}, {"host_regexp": "^(other\\.test|x\\.a\\.test)$"}]}` serves `x.a.test` and never `other.test`. A `host_regexp` that cannot be tied to a literal claim this way is a fallback.

|Code|When|v1 rule it extends|
|---|---|---|
|`host_conflict`|Two tenants claim the same pattern, whatever the other matchers. Or two apps of one tenant claim it with routers that are ambiguous.|Two apps claiming one host. Two apps of one tenant that share a host and split by path are now allowed.|
|`route_ambiguity`|Two routers of one app are ambiguous, or two fallback routers of one tenant are.|New.|
|`cross_tenant_wildcard`|A claim lies under another tenant's wildcard.|Unchanged.|
|`cross_tenant_catch_all`|Fallback routers of two tenants share an entry point.|New.|
|`catch_all_not_allowed`|A fallback router (no host constraint, or a `host_regexp` with no literal host beside it) of a tenant the operator has not allowed (`CATCH_ALL_TENANTS`), on an entry point whose `tenants` policy does not name that tenant alone.|New.|
|`tls_policy_conflict`|A claim lies under a wildcard of the same tenant in another app, or two apps of one tenant share a pattern, and their `tls.client_ca_pem` differ (compared as written). A later TLS option that restricts clients joins the comparison.|v1 compared the same field for wildcards only. TLS is decided per host at the handshake, before any path is known, so it is a property of the app and cannot vary per router.|

### Services

A router's `service` is a name resolved inside the revision the request picked (see the pipeline), then in `App.services`. A name defined in `App.services` may not be redefined in a revision (`duplicate_name`). `name@revision` names a service of another revision, for mirroring a release to its successor. Every `serving` or `retiring` revision must define every service a router references (`unknown_service`), so a pinned session never lands on a revision that lacks its route. A service graph with a cycle is `service_cycle`.

|Type|Fields|Module (`src/service/`)|
|---|---|---|
|`loadbalancer`|`servers`, `algorithm?` (default `round_robin`), `health_check?`, `passive?`, `sticky?`, `pass_host_header?` (default true), `transport?` (name)|`loadbalancer.rs`|
|`weighted`|`services: [{service, weight}]`, `sticky?`|`weighted.rs`|
|`mirroring`|`service`, `mirrors: [{service, percent}]`, `mirror_body?`, `max_body_size?`|`mirroring.rs`|
|`failover`|`service`, `fallback`|`failover.rs`|

Algorithms, one file each in `src/service/lb/`: `round_robin` (built in 0022: v1's behaviour), `weighted_round_robin`, `least_conn`, `p2c_ewma` (power of two choices on EWMA latency), `random`, `ip_hash`, `uri_hash`, `header_hash`. They implement `Balancer`; see the extension contract.

- **Health.** `health_check {path, method?, interval_secs, timeout_secs, expect_status?, headers?, hostname?, scheme?}` (`src/service/health.rs`) probes the declared servers from a background service, the only outbound traffic besides upstream requests and ACME. `passive {consecutive_failures, ejection_secs, max_ejection_percent}` (`src/service/outlier.rs`) ejects servers that fail real requests. Both write one flag per server, so `loadbalancer.rs` and every balancer read it and none re-implements it. A service with every server unhealthy answers `503` and is not asleep: only a service with no server at all wakes a `scale_to_zero` app.
- **Sticky.** `sticky {cookie: {name?, secure?, http_only?, same_site?, max_age_secs?}}` (`src/service/sticky.rs`). The value is an HMAC of the server's URL under `skew_secret` with its own domain label, so it leaks no address, and a snapshot with `sticky` and no `skew_secret` is `invalid_service`. A sticky server that is gone or unhealthy falls back to the balancer.
- **Transports.** `App.transports` are `Declared` with type `servers_transport`: `server_name` (SNI), `ca_pem`, `client_cert {cert_pem, key_pem}` (redacted in `Debug` like `Certificate`), `insecure_skip_verify`, `min_tls_version`, `http2`, `dial_timeout_secs`, `read_timeout_secs`, `write_timeout_secs`, `idle_timeout_secs`, `max_idle_per_host` (`src/service/transport.rs`). `insecure_skip_verify: true` is allowed and is a posture change in a plan. The pool key of change 0008 gains the transport's fingerprint, so two transports never share a connection.
- **Retries** are the middleware `retry`, as in Traefik: Pingora retries only before the upstream has produced a response (connect errors, a reused connection that died).
- **Servers by DNS name.** `url` may carry a host name in the model. Until its spec, the compiler accepts IP literals only and rejects a name with `dns_upstream_not_built`; the resolver service (TTL, refresh, address families) lives in `src/service/resolve.rs`.

### Middlewares

The effective chain of a router is the app's `default_chain`, then the router's `chain`, in that order, with `chain` middlewares expanded in place. The request hooks run in that order; the response hooks run in the reverse order. A name used twice runs twice. An undefined name is `unknown_middleware_ref`.

|Type|Fields (summary)|Module (`src/middleware/`)|Hooks|
|---|---|---|---|
|`chain`|`middlewares: [names]`|`chain.rs`|none, expands|
|`add_prefix`|`prefix`|`add_prefix.rs`|request|
|`strip_prefix`, `strip_prefix_regex`|`prefixes`, `regexes`|`strip_prefix.rs`, `strip_prefix_regex.rs`|request|
|`replace_path`, `replace_path_regex`|`path`, or `regex` and `replacement`|`replace_path.rs`, `replace_path_regex.rs`|request|
|`redirect_scheme`|`scheme`, `port?`, `permanent?`|`redirect_scheme.rs`|request, answers|
|`redirect_regex`|`regex`, `replacement`, `permanent?`|`redirect_regex.rs`|request, answers|
|`headers`|request and response `custom` and `remove`, security headers (HSTS, CSP, frame options, nosniff, referrer policy, permissions policy), CORS|`headers.rs`|request, response|
|`content_type`|`auto_detect: false` (never sniff)|`content_type.rs`|response|
|`basic_auth`|`users` (htpasswd entries, bcrypt or argon2 only), `realm?`, `header_field?`, `remove_header?`|`basic_auth.rs`|request, answers|
|`digest_auth`|`users`, `realm?`|`digest_auth.rs`|request, answers|
|`forward_auth`|`address` (URL of the auth service), `trust_forward_header?`, `request_headers?`, `response_headers?`, `timeout_secs`, `transport?`|`forward_auth.rs`|request, async, answers|
|`ip_allow_list`|`source_range`, `ip_strategy {depth?, excluded?}`|`ip_allow_list.rs`|request, answers|
|`rate_limit`|`average`, `period_secs?`, `burst`, `source {ip_depth, header, host}`, `max_sources`|`rate_limit.rs`|request, answers|
|`in_flight_req`|`amount`, `source`|`in_flight_req.rs`|request, response end|
|`circuit_breaker`|`trip_when {network_error_ratio?, response_code_ratio?, latency_ms?}` (any-of, structured, no expression language), `check_period_ms`, `fallback_secs`, `recovery_secs`|`circuit_breaker.rs`|request, response|
|`retry`|`attempts`, `initial_interval_ms?`|`retry.rs`|upstream error|
|`buffering`|`max_request_body_bytes`, `mem_request_body_bytes`, `max_response_body_bytes`|`buffering.rs`|request body, response body|
|`compress`|`algorithms` (`gzip`, `brotli`, `zstd`), `min_bytes?`, `exclude_content_types?`, `include_content_types?`|`compress.rs`|response, response body|
|`errors`|`status` ranges, `service` (reference), `query?`|`errors.rs`|response, async|
|`pass_tls_client_cert`|`pem?`, `info {subject, issuer, serial, sans, ...}`|`pass_tls_client_cert.rs`|upstream request|
|`grpc_web`|`allow_origins?`|`grpc_web.rs`|request, response, body|
|`wasm`|`wasm_base64`, `fuel`, `max_memory_bytes` (the v1 `Filter`, same limits and validation)|`wasm.rs` (moved from `src/wasm.rs`)|request|
|`respond`|`status`, `headers?`, `body?` (a static answer, from Caddy's `respond`)|`respond.rs`|request, answers|

Platform behaviour that exists without being declared, and how a declaration replaces it: gzip compression of text responses within the tenant's buffer budget. A `compress` middleware in the effective chain replaces that default with its own configuration, and `algorithms: []` turns compression off. A type that a spec has not built yet is recognized and rejected as `middleware_not_built`; a type no spec plans is `unknown_middleware`.

### TCP and UDP

`App.tcp {routers, services, middlewares}` and `App.udp {routers, services}`, with the same naming and tenancy rules.

- **TCP router**: `name`, `entry_points`, `match` (leaves `sni`, `sni_regexp`, `alpn`, `client_ip`, combinators), `tls?` (`{"passthrough": true}` forwards the TLS stream untouched, otherwise podgate terminates with the app's certificates), `chain?` (`ip_allow_list`, `in_flight_conn`), `service`. TCP routers may attach to `http` or `https` entry points; the TLS ClientHello is peeked (the pre-TLS hook of change 0014 already reads it) and a passthrough router wins over HTTP routers for its SNI. A host claimed by a passthrough router and by an HTTP router on a shared entry point is `host_conflict`.
- **TCP service**: `loadbalancer` (`servers: [{address, tls?}]`, `proxy_protocol {version}?`, `termination_delay_ms?`) and `weighted`. L4 services have no revisions in this model.
- **UDP router**: `name`, `entry_points`, `service`. UDP has no match criteria, so an entry point carries one UDP router. **UDP service**: `loadbalancer` with `servers` and `session_timeout_secs`.
- Pingora has no UDP support and no L4 router, so these run as podgate's own Pingora `Service`s on tokio (`src/l4/`). Their owners check what `pingora-core` gives for TCP before promising it. Each L4 connection charges the tenant's `max_inflight`.

### TLS

`App.tls` stays the one place for certificate source and client authentication (change 0021 enforces `client_ca_pem`). It gains optional fields owned by the TLS spec: `min_version`, `max_version`, `cipher_suites`, `curves`, `alpn`, `client_auth` (`request`, `require`, `verify_if_given`, `require_and_verify`; absent with a CA means `require_and_verify`), `sni_strict`. Traefik's "TLS options per router" cannot be honoured literally, because the handshake runs before the router is known; the per-host equivalent is a separate host, which the host and `tls_policy_conflict` rules above already enforce. `Snapshot.certificates` gains `default: true` for the certificate served when no SNI matches (Traefik's default certificate). The ACME plan reads each app's claimed hosts from its routers (the positive exact `host` leaves; a regexp claims no certificate).

### Observability

`Snapshot.observability {access_log?, metrics?, tracing?}`, overridable per router with `observability {access_log?, metrics?, tracing?}` (booleans).

- **Access log** (`src/observe/access_log.rs`): one JSON line per request through `tracing` target `access`, with `fields` (`default` keep or drop, per field `keep`, `drop`, `redact`; headers likewise, with `authorization`, `proxy-authorization`, `cookie` and `set-cookie` redacted unless kept explicitly), `filters {status_codes, min_duration_ms, retry_attempts}` and `sampling_percent`.
- **Metrics** (`src/observe/metrics.rs`): the existing `GET /metrics` series stay. New series are labelled by entry point, app, router and service, with a series cap per tenant: past it the labels collapse into `other`, so a tenant cannot grow the registry by inventing names. Each feature registers its series through one `render` function; the endpoint only concatenates.
- **Tracing** (`src/observe/tracing.rs`): the OTLP exporter endpoint is process configuration (`OTEL_EXPORTER_OTLP_ENDPOINT`), never part of a snapshot, so a snapshot cannot make podgate call an address. The snapshot sets `sample_percent`, `propagate`, and an allow-list of request headers recorded as attributes.

### Request pipeline

Platform stages are fixed and not configurable; the chain is the tenant's. Order of `request_filter` (`src/pipeline.rs` lists it for explain):

1. `acme_http01`.
2. `entry_point`: path normalization (the request is rewritten to the path that is matched) and refusal of unsafe paths with `400`. Forwarded-header sanitizing and entry point `redirect` join here when built.
3. `route`: pick the router (`Matched {app, router}`) with `route::matching`.
4. `sni_check`, on the matched router's app: over TLS, a request whose host differs from the SNI is refused with `421` unless the matched app sets `allow_domain_fronting`. It runs for requests no router matched too, so a misdirected request gets `421` and never learns whether a route exists.
5. `client_cert`, on the matched router's app, however the router matched (exact host, wildcard, `host_regexp`, no host): an app with a client CA gets `403` without a chain it accepts. No match is `404`, after this.
6. `failure_capture` begins. A matched request that ends in `5xx` is recorded, unless podgate refused it for capacity or for lack of an upstream (`503 no upstream available`). A request a middleware answered is recorded with `revision` and `upstream` `null`.
7. `chain`: the effective chain's request hooks, before any slot is taken or any app is woken, so unauthenticated or rate-limited traffic cannot take a tenant slot, queue for a backend, or wake a sleeping app.
8. `select`: pick the revision (skew cookie, canary share, weights), resolve the router's service in it, pick a server (`route::select`). No server in a `scale_to_zero` app: `wake_hold`. When the revision drained or a request waited, the router is found again in the live table (`RoutingTable::rematch`) only if its app, tenant, TLS policy and middleware chain are unchanged; otherwise the request answers `503`, so a request never continues under a chain it did not start with.
9. `inflight_admit`, `tenant_admit`, `backend_admit`, as in v1.

Then `upstream_peer` (pool key), the chain's `upstream_request` hooks, the response hooks in reverse order, body hooks, and `logging`. A request keeps the one `Arc<RoutingTable>` it loaded, as in v1.

v1 ran `wasm_filters` after the admissions. It now runs in the chain, before them: a filter run no longer holds a tenant in-flight slot, and its memory is charged to the tenant looked up by the app's tenant instead of through a slot the request does not yet hold.

### Compile and rejection codes

`TableHandle::apply` compiles in passes, each owned by one module, and collects every rejection of a pass before it stops (the `422` lists all): tenants, names, hosts and matchers (`router/`), conflicts (`conflict.rs`), services (`service/`), middlewares (`middleware/`), transports, TLS and certificates (`tls.rs`), entry points, L4, observability, canary, ACME. A rejection is `{"code", "message", ...fields}` in the `conflicts` list, as today. Kind modules do not add enum variants: they return `Invalid {code, at, message}`, which the compiler wraps with the app and object name.

|Code|When|
|---|---|
|`invalid_matcher`|A matcher with zero or several keys, an unknown leaf, a leaf of the wrong dialect, a bad regex or CIDR, nesting beyond 8.|
|`unknown_middleware`, `middleware_not_built`, `invalid_middleware`, `unknown_middleware_ref`|A type no spec plans; a planned type not built yet; a kind's configuration that does not parse or validate (including unknown fields); a `chain` entry naming nothing.|
|`unknown_service`, `invalid_service`, `service_cycle`, `service_not_built`, `dns_upstream_not_built`|As named.|
|`unknown_transport`, `invalid_transport`|As named.|
|`unknown_entry_point`, `entry_point_forbidden`, `entry_point_protocol`, `unsupported_setting`|A router on an unbound entry point; on one reserved for another tenant; an HTTP router on a `tcp` entry point; a knob Pingora cannot apply.|
|`duplicate_name`|Two objects of one kind with one name in one app.|
|`host_conflict`, `route_ambiguity`, `cross_tenant_wildcard`, `tls_policy_conflict`|See above.|
|`invalid_host`, `unknown_tenant`, `invalid_certificate`, `invalid_skew_secret`, `invalid_acme`, `wasm_*`, `canary_*`|Unchanged.|

### Extension contract

The feature specs rely on this. Everything per kind lives in that kind's file.

```rust
/// Implemented by one type per file in `src/middleware/`.
pub trait Kind: Sized + fmt::Debug + Send + Sync + 'static {
    /// Per-request state, created with `Default` when the chain starts.
    type State: Default + Send + fmt::Debug;
    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid>;
    // Hooks; every one defaults to doing nothing. `Flow::Respond` means the hook wrote the response.
    fn request(&self, cx: &mut RequestCx<'_>, state: &mut Self::State)
        -> impl Future<Output = pingora::Result<Flow>> + Send;
    fn upstream_request(&self, request: &mut RequestHeader, state: &mut Self::State) -> pingora::Result<()>;
    fn response(&self, response: &mut ResponseHeader, state: &mut Self::State) -> pingora::Result<()>;
    fn response_body(&self, body: &mut Option<Bytes>, end_of_stream: bool, state: &mut Self::State)
        -> pingora::Result<()>;
    /// Relaxations a plan lists when `new` replaces `self`; `None`: the stage is gone.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str>;
    /// What explain shows for this stage besides its type.
    fn describe(&self) -> serde_json::Value;
}
```

`RequestCx` holds the downstream `Session`, the matched `CompiledApp`, the tenant's `TenantBudget`, the WASM `Executor` and the `capacity_refusal` flag. `CompileCx` holds the declaring `App` and the shared WASM engine. A kind that needs more adds a field there, a shared one-line change. An upstream-error hook (for `retry`) is added by the spec that needs it, because it must decide what Pingora retries.

`src/middleware.rs` generates, from one list, the `Stage` enum, the per-request state enum and the dispatch, so there is no `dyn` and no boxed future on the request path:

```rust
kinds! {
    "wasm" => Wasm(wasm::Wasm),

    "add_prefix" => unbuilt,

    "basic_auth" => unbuilt,
}
```

One entry per line, a blank line between entries; a spec replaces `unbuilt` on its own line with `Variant(path::Type)` and adds `mod <kind>;`. An unbuilt entry is refused with `middleware_not_built`. Services, balancers and matcher leaves have few variants and no per-request state, so each is a plain enum with `match` arms in `service.rs`, `service/lb.rs` and `router/matcher.rs`; an unbuilt name sits in that file's `UNBUILT` list and is refused with `service_not_built` or `matcher_not_built`. A spec edits its own file, one variant, one arm per `match`, and removes its name from the list.

Rules for every kind:

1. **Strict configuration.** The kind's config struct has `deny_unknown_fields`; a misspelt option on a security feature must not turn it off.
2. **Bounded memory.** State per request or per key declares its cap and charges the tenant's `max_buffer_bytes` before allocating (change 0009's mechanism). The kind degrades or refuses as it documents; it never grows without a bound (`rate_limit.max_sources`, `buffering` limits, `compress` reservation).
3. **No blocking and no unbounded waits.** Async hooks carry a deadline, from their config or `REQUEST_TIMEOUT_SECS`. CPU-heavy work (wasm) runs on the blocking pool through its bounded executor.
4. **Outbound only to declared addresses.** `forward_auth`, `errors` and `mirroring` call addresses and services written in the same app's configuration, never an address derived from the request.
5. **Runtime state outside the table.** Counters, buckets, health and ejection live in a registry keyed by (app, object name, fingerprint of its declaration) and settled at the one swap site, like the canary: a push that does not change the object keeps its state, a changed object starts fresh. (`ServerState` and the round-robin counter still live in the table; the health and rate-limit specs move their state out.)
6. **Security kinds implement `posture`.** Removing or loosening an `ip_allow_list`, `basic_auth`, `digest_auth`, `forward_auth`, `rate_limit`, the security options of `headers`, `wasm`, a client CA, or turning on `insecure_skip_verify` appears in `posture_changes` of `POST /v1/snapshot/plan`. The plan compares one fingerprint per app (everything but `declared_by`) for `changed` and asks each used stage for its `posture`, so a kind needs no diff code of its own. The `wasm` kind reports `filters_removed` and `filters_changed`.
7. **One test file.** `tests/mw_<kind>.rs` (or `tests/lb_<name>.rs`, `tests/svc_<kind>.rs`), written against the `tests/common` v2 builders. A kind never reads another kind's `Ctx` state.

The server state that a balancer, the health checker and the outlier detector share is fixed in `service/loadbalancer.rs` by 0022: per server `healthy`, `ejected_until_ms`, `active` and `ewma_us`, all atomics, so each of those specs writes its own slot and none reshapes the struct.

### Runtime state outside the table

Already outside, keyed by app and revision: in-flight counters (`inflight.rs`), tenant budgets (`budget.rs`), backend limiters (`fairq.rs`), outcomes, canary runtime, failure rings, wake state. New: server health and ejection per (app, revision, service, server URL); rate-limit and circuit-breaker state per (app, middleware name). Sticky needs none. The key of a limiter in `fairq.rs` stays the resolved socket address, so apps that name one address still share a backend limiter.

### How today's features map

|Feature (spec)|In v2|
|---|---|
|Tenants, budgets, fair queuing|`Tenant` unchanged. `Selected` knows its app, so `tenant_admit` and `backend_admit` are unchanged.|
|Revisions, states, drain|`App.revisions`. `inflight.rs` keys (app, revision) as today; a draining revision is one no router selects.|
|Canary, skew|`App.canary` names a revision; the share, fingerprint and registry are untouched. The skew cookie pins an (app, revision) and applies to every router of the app.|
|Scale to zero|`App.scale_to_zero`. "No upstream" means the selected revision's service for the matched router has no server; the wake hold runs in `select`.|
|Failures|`App.record_bodies`; the ring is per app. A record's `revision` and `upstream` become `null` for a request a middleware answered before `select`.|
|WASM filters|Middleware `wasm`, same module validation, same codes (`wasm_forbidden_import`, `wasm_invalid`), now with `router` and `middleware` in the rejection.|
|ACME, on-demand TLS|`Snapshot.acme`, `App.tls.mode`; hosts come from router claims.|
|Conflicts|Table above; the same codes and field names.|
|Plan, posture, auto-revert|`plan::diff` compares the app fingerprint per claimed host; posture kinds `filters_removed` and `filters_changed` become the `wasm` kind's `posture`.|
|Explain|See below.|
|SNI check|Pipeline stage 3.|
|Pool isolation|Key (tenant, app, revision, transport fingerprint, address); the NTLM pin is unchanged.|

### Explain

`GET /v1/explain?url=<url>&method=<m>[&entry_point=<name>]` reads the path and query of `url` too. `200` carries `version`, `host`, `method`, `path`, `entry_point`, `app`, `tenant`, `declared_by`, `matched {router, priority, pattern, kind}` (`pattern` is the literal host that matched, `null` for a router with none; `kind` is `exact`, `wildcard`, `regexp` or `none`), `considered` (every router that matches, best first, so a shadowed route is visible), `service` (the matched router's service name), `revisions [{id, state, weight, effective_weight, servers [{url, weight, available}]}]` (the servers of that service in each revision), `canary` when the app has one, and `pipeline` (every platform stage as `{"stage": "<name>"}` and every chain entry as `{"stage": "chain", "middleware": "<name>", "type": "<type>", ...describe()}`). `404` keeps `nearest_wildcard`. Header and client-IP inputs arrive with the leaves that read them. It reads the compiled table and runs the same router index as the proxy, so it cannot drift.

### Ownership map

0022 creates every file below, filled or an empty module with its doc comment, so the feature specs after it edit only their own files. "Shared" files accept one-line additions: a line in the `kinds!` list, one `.merge(...)`, one field on `Ctx`.

|Area|Files|Built by 0022|Feature specs that fill it|
|---|---|---|---|
|Model (shared)|`crates/podgate-model/src/{lib,entry_point,l4,observe,secret}.rs`|All envelope types; `Declared`|Add optional envelope fields only|
|Compile (shared)|`src/compile.rs`, `src/table.rs`, `src/conflict.rs`, `src/error.rs`|The passes, `Invalid` and `Rejected`, `CompileContext`, all conflict codes|None; new codes go through `Invalid`|
|Router|`src/router.rs`, `src/router/{tree,priority,path}.rs`|Index, order key, path normalization, tenant isolation of fallbacks|Specificity or ambiguity corrections|
|Matcher leaves|`src/router/matcher.rs`, `src/router/matcher/*.rs`|`host`, `host_regexp`, `path`, `path_prefix`, `path_regexp`, `method`, `all`, `any`, `not`|One spec for `header`, `header_regexp`, `query`, `query_regexp`; one for `client_ip` (needs forwarded-header trust)|
|Pipeline (shared)|`src/pipeline.rs`, `src/proxy.rs`, `src/route.rs`, `src/entry.rs`|Stages 1 to 9, chain runner, `Ctx.chain`, `route::matching`, `route::select`, `RoutingTable::rematch`|Add a platform stage: one line each|
|Middleware kinds|`src/middleware.rs`, `src/middleware/*.rs`|Registry (`kinds!`), `Kind` trait, `chain` expansion, `wasm` (the adapter in `middleware/wasm.rs` over the engine in `src/wasm.rs`)|One spec per row of the middleware table, grouped as you like: path rewriting, redirects, headers and content type, auth, limits, resilience, body and compression, errors and respond, `pass_tls_client_cert`, `grpc_web`. The `retry` spec adds an upstream-error hook to `Kind`. Today's gzip stays a platform default until a `compress` spec replaces it.|
|Services|`src/service.rs`, `src/service/{loadbalancer,weighted,mirroring,failover}.rs`|`loadbalancer` with `round_robin`, `ServerState`|`weighted` and `failover`; `mirroring`. A spec that needs health or outlier state outside the table adds the registry.|
|Balancers|`src/service/lb.rs`, `src/service/lb/*.rs`|`round_robin`|`weighted_round_robin`, `least_conn`, `p2c_ewma`, the hashing group|
|Health|`src/service/{health,outlier}.rs`|Empty|Active health checks; passive ejection|
|Sticky|`src/service/sticky.rs`|Empty|Sticky cookie|
|Transports|`src/service/transport.rs`|Empty: every upstream is plain HTTP/1.1|Upstream TLS, h2 and h2c, timeouts, pool size|
|Resolver and upstream policy|`src/service/resolve.rs`|Empty; IP literals only, host names are `dns_upstream_not_built`|DNS upstreams, and the upstream address policy: an allowlist of CIDRs per tenant and source in operator configuration, with link-local, loopback and the admin and agent addresses denied by default. It is checked at compile for literal IPs and on every DNS resolution before a connection is made. The resolver spec owns it.|
|TLS|`src/tls.rs`, `src/sni.rs`, `src/clientauth.rs`|Client auth and the SNI check decide on the matched router's app|TLS options; default certificate|
|Entry points|`src/entry.rs`, `src/config.rs`|`web` and `websecure`, `CompileContext`, policy `tenants` enforced|`ENTRY_POINTS`, the other policy fields, proxy protocol, forwarded headers, timeouts, HTTP/2|
|L4|`src/l4.rs`, `src/l4/{tcp,udp}.rs`|Model and compile rejection (`l4_not_built`)|TCP routers and services; UDP|
|Observability|`src/observe.rs`, `src/observe/{access_log,metrics,tracing}.rs`|Model and compile rejection (`observability_not_built`)|Access log; per-router metrics; OTLP tracing|
|Admin API (shared)|`src/admin.rs`, `src/admin/*.rs`, `src/explain.rs`, `src/plan.rs`|`explain` v2; plan compares app fingerprints and asks each middleware for its posture|`GET /v1/schema` (JSON Schema of the snapshot, generated from the types); `POST /v1/snapshot/validate` (compile without the version check)|
|Providers|One `podgate-provider` crate (a workspace member) with one sub-module per source (`docker`, `kubernetes`, `nomad`, `file`) and a shared core that merges them into one snapshot|None|The node's snapshot writer is either podkit's agent or `podgate-provider`, never both. Providers translate Traefik rules and set explicit priorities. Extracting a `podgate-model` crate for the daemon and the provider to share is the first provider spec's decision.|
|Tests (shared)|`tests/common/mod.rs`|v2 builders: `app`, `router`, `service`, `revision`, `revision_on`, `middleware`, `with_filters`, `snapshot`|Each spec adds `tests/<area>.rs`|

### Deferred, with reasons

- **HTTP/3**: Pingora 0.9 has no HTTP/3 server.
- **ACME DNS-01**: needs DNS-provider credentials in the proxy.
- **Cluster-wide rate limits**: state is per node, as Traefik's is without Redis. The control plane can divide a limit by node count.
- **Static files and FastCGI** (Caddy's `file_server`, `php_fastcgi`): a PaaS app serves its own files; podgate keeps no disk state.
- **Response flush interval**: Pingora streams chunks as they arrive.
- **Revision-aware L4 services**: nothing asks for blue/green on raw TCP.
- **Plugins that run native code** (Traefik's Yaegi): replaced by the `wasm` middleware.
- **Rule strings**: providers translate them.

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
| `NODE_NAME` | unset | Name of this node. The node whose name equals the snapshot's `acme.issuer_node` orders certificates; unset never does. |
| `ACME_CA_FILE` | unset | PEM file with the root certificate to trust for the ACME server, for a private or test CA. Unset: the platform's roots. Operator-provided, never read from a snapshot. |
| `RUST_LOG` | `info` | Log filter, `tracing-subscriber` env-filter syntax (`info,podgate=debug`). Pingora's own `log` records are filtered by the same variable. |
| `WASM_MAX_CONCURRENT` | available cores, at most 256 | WASM filter runs that may execute at once across all tenants, 1..=256. Filters run through `spawn_blocking`, and this bounds how many threads of tokio's 512-thread blocking pool (which snapshot compiles also use) they can hold. |
| `WASM_QUEUE_TIMEOUT_MS` | `1000` | Milliseconds a filter run waits for a free worker, 1..=60000. After that the request gets `503` with `retry-after: 1`. |
| `CATCH_ALL_TENANTS` | unset | Comma-separated tenant ids the operator lets declare catch-all routers (a host-free router, or a `host_regexp` with no literal host beside it) on a shared entry point. Only the operator can allow it; a snapshot cannot. Empty: no tenant can. See `### Priority, ambiguity and conflicts`. |

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
| `200` with the key authorization | a plain HTTP `GET /.well-known/acme-challenge/<token>` for a token in the snapshot's `acme.challenges`; any host, answered before routing |
| Pingora's `502`/`504` | the upstream refuses, resets or times out |

Admin API (unix socket `ADMIN_SOCKET`; only the PaaS agent on the node connects):

| Route | Answer |
|---|---|
| `GET /healthz` | Liveness. `200 {"status":"ok"}` whenever the process answers. Checks no dependency. |
| `GET /readyz` | Readiness. `200 {"status":"ready"}` while the admin API serves; `503 {"status":"not ready"}` before startup completes and while draining. It does not probe the proxy listeners: Pingora binds them on its own schedule and retries while a port is busy. |
| `PUT /v1/snapshot` | Replaces the routing table. `200 {"version":N}` when applied; `400` for malformed JSON; `409` when `version` is not greater than the live one (the table is unchanged); `422 {"error":"snapshot rejected","conflicts":[...]}` when it does not compile: conflicting declarations (see `### Snapshot conflicts`), an unknown tenant, a bad host, an unusable certificate, a `skew_secret` shorter than 16 bytes. Every entry of `conflicts` is an object with a `code` and a `message`. Bodies up to 16 MiB. The live version starts at `0`, so the first snapshot needs `version >= 1`. |
| `POST /v1/snapshot/plan` | Same body as `PUT /v1/snapshot`; applies nothing. `200` with `{"from_version","to_version","added":[...],"removed":[...],"changed":[...],"posture_changes":[{"host","app","kind"}]}` (hosts are declared patterns, sorted); `400`, `409` and `422` exactly as the `PUT` answers the same body, because the plan runs the same version check and compiler. See `## Plan and auto-revert`. |
| `GET /metrics` | Prometheus text (`text/plain; version=0.0.4`): the per-tenant series listed under `## Memory budgets`, then the per-backend series listed under `## Backend admission`. |
| `GET /v1/events?after=<seq>&timeout_secs=<n>` | Long poll of the event feed. `200 {"boot_id":"...","events":[{"seq":N,"kind":"revision_drained","app":"...","revision":"..."}]}` (other kinds: `{"kind":"wake_requested","app":"..."}`, `{"kind":"app_idle","app":"..."}`): events with `seq` greater than `after` (default `0`), oldest first; an empty list when none arrive within `timeout_secs` (default `0`: answer at once; capped at `REQUEST_TIMEOUT_SECS - 1` so the poll ends before the `408`). `410 {"error":"...","boot_id":"...","oldest":N}` when `after` is older than the 4096-event ring: resync. `400` for a malformed query. Sequence numbers start at `1` and restart with the process; compare `boot_id` to detect a restart. |
| `GET /v1/explain?url=<url>&method=<m>` | Why a request goes where it goes, read from the live routing table. `url` is absolute `http` or `https` (only scheme and host are read; `https` adds the TLS-only stages); `method` defaults to `GET`. `200 {"version":N,"host":"...","method":"...","app":"...","tenant":"...","declared_by":"...","matched":{"pattern":"*.a.test","kind":"exact"|"wildcard"},"revisions":[{"id":"...","state":"...","weight":W,"effective_weight":E,"upstreams":[...]}],"middleware":["route",...]}`. `effective_weight` is the weight new requests are picked with now: `0` unless the revision is `serving` with a positive weight and a backend. An app with a canary adds `"canary":{"revision","share_percent","regressed","step_percent","interval_secs","max_error_permille"}` and its effective weights count in parts of 10000 (`### Canary`). `middleware` is `proxy::middleware_chain`, in the order `request_filter` runs the stages; a stage that cannot act for the app (`sni_check` with `allow_domain_fronting`) is left out. `404 {"error":"not found","nearest_wildcard":"*.a.test"|null}` when no app answers for the host; the nearest wildcard is the declared one whose suffix is the longest suffix of the host, the host itself included (so `a.test` is nearest to `*.a.test`, which never matches it). `400` for a missing or invalid `url` or `method`. Read-only: it picks no backend and moves no counter. |
| `GET /v1/apps/{app}/failures` | `200 {"failures": [...]}`: the last 100 requests of the app that got a 5xx, newest first (see `### Failed requests`). `404` when the live table has no such app. |
| `POST /v1/apps/{app}/failures/{id}/replay?revision=<r>[&force=true]` | Re-sends a recorded request to the first upstream of revision `r` in the live table. `200 {"status","headers","body","body_truncated"}` with the upstream's new response, whatever its status; `400` without `revision`; `404` for an unknown app, record or revision; `409` for a method other than `GET` or `HEAD` unless `force=true`; `502` when the upstream cannot be reached; `503` when the revision has no upstream. |
| anything else | `404 {"error":"not found"}`. |

Errors: handlers return `Result<_, AppError>`. `AppError` renders `{"error": "<message>"}` with the matching status. `Internal` logs the cause and sends only `internal error`. No `unwrap()` outside tests.

## ACME and on-demand TLS

podgate keeps no state on disk and never calls the control plane, so certificates travel through the snapshot and the event feed. The control plane is the shared store; the TLS listener reads certificates only from `Snapshot.certificates`. HTTP-01 only: DNS-01 would put DNS-provider credentials in the proxy, and a wildcard host of an `acme` app therefore gets no certificate (supply one in `certificates`).

**Snapshot field `acme`** (optional; absent means no ordering):

|Field|Meaning|
|---|---|
|`issuer_node`|`NODE_NAME` of the one node that orders. Every node serves answers; only this one talks to the CA.|
|`directory_url`|ACME directory, `https://...`.|
|`contact`|Contact URIs of the account (`mailto:...`). Used when podgate creates the account.|
|`account_key_pem`|PKCS#8 PEM of the account key, so restarts and issuer changes keep one account. Absent: a fresh in-memory account per issuer start (mind the CA's account rate limit). Excludes `eab`.|
|`eab`|`{key_id, hmac_key}` external account binding (base64url key) for CAs that require one. Excludes `account_key_pem`: a CA binds only at account creation.|
|`challenges`|`[{token, key_authorization}]` the control plane pushes back after `acme_challenge` events. Every node serves them.|
|`requested_hosts`|Exact hosts of `on_demand` apps the control plane approves for ordering (see below).|

**Issuing.** For each `acme` app, the exact hosts that no certificate in the snapshot answers for are ordered together (one certificate). The issuer opens the order and emits `acme_challenge {token, key_authorization}` once per pending authorization. The control plane pushes a snapshot whose `acme.challenges` holds them. The issuer waits (up to 5 minutes) until its own table serves every token, tells the CA, finalizes and emits `certificate_issued {hosts, cert_pem, key_pem}`. The control plane stores `{hosts, cert_pem, key_pem}` under `certificates` and pushes it; a certificate for the same hosts replaces the old one. `key_pem` is a private key: the feed is reachable only through the `0600` admin socket, and `PrivateKeyPem` hides it from `Debug`.

Push the challenge snapshot to every node, the issuer last: the issuer starts validation when its own table has the token, and the CA may reach any node. Until the control plane stores the certificate, the issuer does not repeat the job for 10 minutes. A failed order backs off from 1 minute, doubling to 1 hour, per job. At most 8 orders run at once.

**HTTP-01.** `GET /.well-known/acme-challenge/<token>` on the plain HTTP listener returns the key authorization (`200`, `application/octet-stream`) when the live table holds the token. It runs first in `request_filter` and needs no route for the host. A token the table does not hold, a non-`GET` and a TLS connection are routed like any request, so an app keeps its own `/.well-known` paths.

**Renewal and ARI.** For every served certificate whose hosts are all exact and still claimed by an app, the issuer asks the CA for its renewal window (RFC 9773 `renewalInfo`, identified by authority key identifier and serial). It picks one random time inside the window, never later than a tenth of the lifetime before expiry, and renews then with the new order's `replaces` set. It asks again after the CA's `Retry-After` (between 1 minute and 24 hours); a changed window gets a new pick. A window that is already in the past renews at once, which is how a revoked certificate is replaced. The CA without ARI, a certificate without an authority key identifier, and an ARI error all fall back to two thirds of the lifetime. A certificate whose ARI answer is still pending is never renewed on the fallback.

**On-demand.** A host that routes to an `on_demand` app and has no certificate gets one at its first TLS handshake, once the control plane approves it. The handshake emits `certificate_requested {host}` (every node does, the issuer too; once per host per pending period, not per handshake) and waits up to 30 seconds for the certificate to appear in the live table, then fails like any handshake without a certificate. The control plane approves by listing the host in `acme.requested_hosts` of the snapshot it pushes to the issuer; that list is the only thing that makes the issuer order an on-demand host, so a client sending random SNIs cannot spend the CA's rate limits. A host that routes to no app, to an `acme` app, or lies two labels under a wildcard never waits and never gets a certificate. The control plane is the gate on every path: it decides which `acme_challenge` events it answers. At most 256 handshakes wait at once and at most 256 hosts are pending.

Why before the handshake: Pingora's rustls backend has no async certificate callback (`certificate_callback` is OpenSSL only) and rustls' `ResolvesServerCert` is synchronous. `Acme` is Pingora's pre-TLS hook: when an `on_demand` app exists it reads the ClientHello (rustls' `Acceptor` parses it), looks at the SNI, waits if needed, and rewinds the bytes into the handshake. Without an `on_demand` app the hook reads nothing.

**Events** (all in `GET /v1/events`):

|Kind|Fields|Emitted by|
|---|---|---|
|`acme_challenge`|`token`, `key_authorization`|the issuer, per pending authorization|
|`certificate_issued`|`hosts`, `cert_pem` (chain, leaf first), `key_pem` (PKCS#8)|the issuer|
|`certificate_requested`|`host`|any node, on an on-demand handshake; once per host per pending period (until its certificate arrives, at most 10 minutes), not per handshake|

Tests: `tests/acme.rs` against `pebble` with `pebble-challtestsrv` as its DNS (every name resolves to 127.0.0.1) and the issuer's HTTP port as its HTTP-01 port.

## Requests in flight and the table

`Gateway::new_ctx` calls `TableHandle::load()` once and stores the `Arc<RoutingTable>` in the request's `Ctx`. Every callback of that request reads `ctx.table`, never the handle, so a snapshot swap mid-request cannot change its routing. `request_filter` resolves the route (`route::resolve`) into `ctx.route`; `upstream_peer` connects to `ctx.route.upstream`. `TableHandle::apply` takes a lock, checks the version, compiles, then swaps with `ArcSwap::store`; a failed compile or a stale version leaves the live table in place.

Counting and draining: once `request_filter` has a route it takes an `InflightGuard` for (app id, revision id) from `Inflight` and keeps it in `ctx.inflight`; it is released when the request ends and its `Ctx` drops. Counters live outside the table, so they survive swaps. After every successful apply, `PUT /v1/snapshot` calls `Inflight::sync` with the live table. A `draining` revision gets exactly one `revision_drained {app, revision}` per draining period: at once when `sync` finds it idle, otherwise when its last guard drops. A period ends when a later snapshot makes the revision non-draining, so draining it again emits again. A request that routed with a table older than the one that drained its revision is refused a guard and routes again with the live table (three attempts, then `503`).

## Client certificates

An app with `tls.client_ca_pem` (PEM of one or more CA certificates) only serves TLS clients whose certificate chains to that CA. Two layers enforce it, because Pingora builds one rustls config for the whole listener:

1. **Handshake.** The listener asks a client for a certificate only when the SNI it sent belongs to an app with a client CA (`ClientAuth` on the compiled app, found with the same host lookup routing uses, wildcards included). Hosts without a CA never send a `CertificateRequest`. The handshake proves the client holds the key of the certificate it sends but does not judge the chain, and it never fails a client that sends none: the listener cannot know the app yet. The certificate request carries no CA hints.
2. **Request.** Before routing, `clientauth::admit` checks the certificate chain the connection presented against the CA of the app the request is routed to. A request with no chain, a chain from another CA, an expired chain, or arriving on the plain HTTP listener gets `403 {"error":"client certificate required"}`. This runs whatever the SNI was, so a client that handshook with the SNI of an app without a CA and names an mTLS app in `Host` (allowed when that app sets `allow_domain_fronting`) is refused the same way. The verdict is memoized per connection for 30 seconds.

`tls.pass_client_cert: true` adds the verified leaf's subject (one line of printable ASCII, for example `CN=alice`) to the request as `x-forwarded-tls-client-cert-subject`. The header is removed from every incoming request first, so it is never client-controlled. Without the opt-in the app never sees it.

A snapshot whose `client_ca_pem` is not a usable CA bundle is rejected with `422` and code `invalid_client_ca`; the previous snapshot keeps serving. Resuming a TLS session made before an app gained a client CA carries no certificate and gets `403` until the client handshakes anew.

## Plan and auto-revert

`POST /v1/snapshot/plan` compiles the candidate with the same compiler as `PUT`, then `plan::diff` compares it with the live table by host pattern. A host is *added* when only the candidate answers for it, *removed* when only the live table does, and *changed* when both do but the app, its tenant, its TLS policy, `allow_domain_fronting`, or any revision's id, upstreams, weight or state differs (`declared_by` never counts). `posture_changes` lists hosts present on both sides that got less strict, one entry per kind: `client_ca_removed`, `client_ca_changed` (a different CA is a different trust set), `domain_fronting_enabled` (the SNI-versus-Host check of change 0007 is off) and `on_demand_tls_enabled` (`tls.mode` went from `acme` to `on_demand`), `filters_removed` (the app runs fewer WASM filters) and `filters_changed` (it had filters and a module or limit differs; a diff of compiled modules cannot tell whether the check loosened, so any change is listed; adding filters to an app that had none is not). New hosts and tightenings are not listed. 

Auto-revert: after every successful `PUT`, `Reverter::applied` keeps the snapshot that was live before (`Replaced::previous_snapshot`) and the apps the new one serves differently (`plan::changed_apps`: new apps, apps whose serving config changed, apps that gained or lost a host). A watcher checks those apps twice a second for `revert_window_secs`. When at least 20 requests were answered since the swap and more than 5% of them were `5xx`, the previous snapshot is compiled again and goes live, `config_reverted {from_version, to_version}` is emitted and `Inflight::sync` runs; if the recompile fails, `config_revert_failed` is emitted instead and the change is no longer watched. Apps the snapshot did not touch are never looked at. The minimum of 20 keeps one failure in one request from reverting a deploy, and means an app with less traffic than that in the window is not reverted. Only the newest push is watched (a later push cancels the earlier watch; its revert goes back to the table it replaced, which may itself be unvetted), and the first snapshot after a start is not watched because there is nothing but the empty table to go back to.

Version semantics after a revert: the previous snapshot is recompiled with its `version` set to the reverted snapshot's and swapped in as a new table through `TableHandle::swap` (`TableHandle::revert_to`; tables never change once built, so a request holding the reverted table keeps seeing it). The routing is the previous snapshot's, the live version stays the reverted snapshot's. The next push must be newer than it, so the control plane cannot replay the bad snapshot by accident (the `409` names the version) and must publish a new version to try again. The version never goes down, which `Inflight::sync` relies on.

Outcomes (`src/outcomes.rs`): `Gateway::logging` calls `record_request` once per request with the status of the response podgate wrote. An upstream `5xx` and a `5xx` podgate made itself (`502`/`504`, the `503` of an app without a serving revision) both count as errors. Capacity refusals do not: the tenant `503` (`max_inflight`), the `503` of a scale-to-zero app that did not wake in time and the `503` of a busy WASM filter pool and the `503` of a saturated backend (`backend is saturated`, which a tenant sharing the address can cause) say busy or cold rather than broken, and are left out, so a slow cold start, a busy tenant or a saturated shared filter pool cannot roll back a correct deploy. One rule decides: `Ctx::capacity_refusal`, set wherever podgate answers one (`AppError::is_capacity_refusal`), not a `retry-after` header check. A filter that does not fit its own tenant's buffer budget (`wasm filter memory is over the tenant's budget`) is not a capacity refusal and counts. A request with a route counts under its (app, revision); one refused before routing counts under the app alone, so a deploy that leaves an app without a serving revision still shows; an unknown host and a request the client abandoned before any response count nowhere. Each series is a ring of 300 one-second buckets of atomic counters (window queries are capped at 300 s). The request path is an `ArcSwap` map lookup without allocation plus two relaxed increments; the map changes only when a revision gets its first request or when `Outcomes::sync` forgets revisions a snapshot removed. A request landing exactly while its bucket rolls into a new second can be lost, never double counted. API: `Outcomes::record(app, revision, status)` and `Outcomes::window(app, revision, span) -> Counts { total, errors_5xx }`; `revision: None` means the whole app, and `Counts::error_permille()` gives `5xx` per thousand.

## Memory budgets

`Tenant.budget` limits what one tenant can take from the proxy. `Budgets` (`src/budget.rs`) holds one `TenantBudget` per tenant id; it lives outside the routing table, so usage survives a snapshot swap, and `Budgets::tenant` refreshes the limits from the live table on every lookup.

- `max_inflight`: `request_filter` takes a slot after routing and after the revision is counted (`budget::admit`) and keeps the `TenantSlot` in `ctx.tenant_slot` until `logging`. A tenant at the cap gets `503 {"error":"tenant is over its in-flight limit"}` with `retry-after: 1`.
- `max_buffer_bytes`: the only buffer the proxy allocates per response is the gzip encoder (`src/compress.rs`). `response_filter` charges `compress::RESERVATION_BYTES` (640 KiB) to the tenant before it allocates the encoder. A charge that does not fit means the response goes out as the upstream sent it: compression degrades to identity encoding, nothing is refused. The charge ends when the stream ends or the request is logged.
- WASM filter runs draw on the same `max_buffer_bytes`: before each filter run `wasm::Executor::admit` reserves that filter's `max_memory_bytes` (`TenantBudget::reserve_filter`) and holds it until the run ends. A run that does not fit is not run: the request gets `503 {"error":"wasm filter memory is over the tenant's budget"}` with `retry-after: 1`, counted in `podgate_tenant_wasm_refused_total`. Compression and filters share the budget: a filter with a 64 MiB limit needs 64 MiB of `max_buffer_bytes`, and each compressed response in flight needs another 640 KiB. Give a tenant that uses filters a `max_buffer_bytes` of at least its largest filter limit plus 640 KiB per concurrent compressed response.
- Compression applies to `200` responses to `GET` and `POST` over HTTP/1.1 and HTTP/2 whose content type is text-like, that carry no `content-encoding` or `cache-control: no-transform`, and whose `content-length`, when known, is at least 256. Only gzip is offered.
- `GET /metrics` reports every tenant: `podgate_tenant_buffer_bytes` (charged now), `podgate_tenant_buffer_bytes_peak` (highest since start; never above the limit), `podgate_tenant_inflight`, `podgate_tenant_inflight_rejected_total`, `podgate_tenant_compression_skipped_total` and `podgate_tenant_wasm_refused_total` (filter runs refused for lack of buffer budget).

## Backend admission

`src/fairq.rs` keeps one `Limiter` per upstream socket address in `Backends`, a registry that outlives snapshot swaps. `request_filter` calls `Backends::admit` after the tenant slot (stage `backend_admit`), so a request that waits still counts against its tenant's `max_inflight`. Revisions with their own addresses (the usual case) get their own limiter; apps that name the same address share one, and so do their tenants.

- Adaptive limit: a gradient limit driven by the time from "connected to the upstream" to "upstream response headers". Every 16 samples the mean latency is compared with the lowest window mean seen (the baseline; it creeps up 0.01% per window, and at the floor limit it adopts the current latency, so a permanently slower backend becomes the new normal). Latency beyond 1.25x the baseline shrinks the limit (at most halving per window before smoothing); otherwise it grows by `sqrt(limit)`. The limit starts at 32 and stays within 4 to 2048. It does not grow while the backend is under-used. `5xx` responses are not sampled; a `101` upgrade frees its slot at once. There are no static rate limits.
- Fair queuing: when the limit is reached a request waits in its tenant's queue (512 entries at most) and slots go to the waiter with the smallest start tag, so tenants are served in proportion to `Tenant.weight` and an idle tenant starts at the current virtual time. A full queue, or a wait past 5 seconds, answers `503 {"error":"backend is saturated"}` with `retry-after: 1`.
- The slot is freed when the upstream response ends (or in `logging`), not when the client has read it all.
- Hot path: with the limit not reached and nobody waiting, admitting is one compare-and-swap and releasing one subtraction; the queue lock is taken only to wait, to hand a slot over and when a waiter gives up.
- `GET /metrics` adds, per backend address: `podgate_backend_limit`, `podgate_backend_inflight`, `podgate_backend_queued`, `podgate_backend_waited_total` and `podgate_backend_refused_total`.
- `scripts/load-fairness.sh [separate|shared]` is the load test (`oha`, the `podgate` binary and `examples/slow_upstream.rs`): tenant A floods at 1000 rps, tenant B sends 10 rps, with and without the flood.

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

- Lints in the root `Cargo.toml` `[workspace.lints]`, inherited by every crate (`docs/rust-style.md`); `exhaustive_*` allowed because this is application code.
- Dependencies: add only when std cannot do it in a few lines; `cargo deny check` gates licences and advisories. Pingora is built with `proxy`, `lb` and `rustls`: no C TLS stack in the binary.
- Tests: unit tests in a `mod test` leaf, end-to-end tests in `tests/<feature>.rs` on `tests/common`.
