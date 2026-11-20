# Architecture

podgate is becoming a reverse proxy on Pingora. The sections below describe today's axum scaffold; `## Target architecture` describes where it is going.

HTTP service on axum and tokio. One package with a library (testable) and a thin binary.

## Layout

| Path | Role |
|---|---|
| `src/main.rs` | Thin: `Config::from_env()`, `init_tracing`, `serve(config, shutdown_signal())`. |
| `src/lib.rs` | `Config`, `router`, `serve`/`serve_on`, `AppError`, `AppState`, `shutdown_signal`, `init_tracing`. |
| `tests/http.rs` | In-process tests via `router(..).oneshot(..)` plus one real-socket test with graceful shutdown. |
| `Dockerfile`, `.dockerignore` | Multi-stage image on distroless. |

When `lib.rs` grows, split it into modules named after their main item (`config.rs`, `error.rs`, `routes/`), keeping `router` as the one place that wires them.

## Target architecture

### Planes

One `podgate` process per node. It has a proxy listener (Pingora, TLS via the `rustls` feature) and an admin API on a unix socket. The PaaS agent on the same node is the only client of the admin API, which `ADMIN_SOCKET` sets (default `/run/podgate/admin.sock`, mode `0600`). The admin socket serves `/healthz` and `/readyz`. podgate never opens a connection to the control plane. Everything it reports goes out through the event feed. The only outbound traffic is to upstreams and to the ACME server. There is no Docker socket and no service discovery.

### Snapshot

The control plane sends `PUT /v1/snapshot` with a JSON snapshot. Entities:

|Entity|Fields|
|---|---|
|`Snapshot`|`version` (u64, strictly increasing), `tenants`, `apps`|
|`Tenant`|`id`, `weight` (fair-share weight), `budget` (`max_inflight`, `max_buffer_bytes`)|
|`App`|`id`, `tenant`, `declared_by` (free text naming the source, used in errors and explain), `hosts` (exact names, or one leading `*.` wildcard), `tls` (`mode`: `acme` or `on_demand`; optional `client_ca_pem`), `revisions`|
|`Revision`|`id`, `upstreams` (socket addresses), `weight` (u16), `state` (`serving`, `retiring` or `draining`)|

Later specs add optional fields to these entities. An absent optional field means the feature is off.

### Compile and swap

The snapshot is compiled into an immutable routing table and swapped atomically. Requests in flight keep the table they started with. A rejected snapshot leaves the current one live.

### Revision states

`serving` revisions get new sessions by weight. `retiring` revisions get no new sessions but still serve sessions pinned to them. `draining` revisions get no new requests at all. In-flight requests finish.

### Event feed

`GET /v1/events?after=<seq>&timeout_secs=<n>` is a long poll. It returns the ordered events with sequence numbers greater than `after`, or an empty list after the timeout. The event kinds are `revision_drained`, `config_reverted`, `canary_regressed`, `wake_requested`, `app_idle`, `acme_challenge` and `certificate_issued`.

### Error shape

Admin API errors are `{"error": "<message>"}`, the same shape `AppError` renders today. A snapshot rejected by the compiler returns `422` with `{"error": "snapshot rejected", "conflicts": [...]}`.

### Not built yet

Everything in this section is the target; each part is described below.

## Run

```sh
cargo run                         # listens on 127.0.0.1:8080
devenv up                         # same, as a devenv process with RUST_LOG set
curl -i localhost:8080/healthz
check                             # fmt, clippy, tests, docs, deny: the full gate (scripts/check.sh)
```

## Configuration

All settings are environment variables, read once at startup by `Config::from_env()`. An invalid value stops startup with an error that names the variable (`invalid BIND_ADDR: ...`). Defaults suit local development; copy `.env.example` to `.env` to override (devenv loads it).

| Variable | Default | Meaning |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8080` | Socket address to listen on. The container image sets `0.0.0.0:8080`. |
| `REQUEST_TIMEOUT_SECS` | `30` | Per-request limit, whole seconds in 1..=3600. |
| `LOG_FORMAT` | `pretty` | `pretty` or `json`. Use `json` in production. |
| `RUST_LOG` | `info` | Log filter, `tracing-subscriber` env-filter syntax (`info,podgate=debug`). |

Add a setting: field on `Config`, a branch in `Config::from_lookup` that returns `ConfigError { var, .. }`, a row here, a case in the `test` module.

## Endpoints

| Route | Answer |
|---|---|
| `GET /healthz` | Liveness. `200 {"status":"ok"}` whenever the process answers. Checks no dependency, so a dead database never gets the pod killed. |
| `GET /readyz` | Readiness. `200 {"status":"ready"}` while accepting traffic; `503 {"status":"not ready"}` before startup completes and while draining. Wire dependency checks into `AppState`. |
| `GET /v1/greet/{name}` | Example JSON route. Replace it. `400` when the name is empty or over 64 bytes. |
| anything else | `404 {"error":"not found"}`. |

Errors: handlers return `Result<_, AppError>`. `AppError` renders `{"error": "<message>"}` with the matching status. `Internal` logs the cause and sends only `internal error`. No `unwrap()` outside tests.

## Middleware

Outermost first: request id (`x-request-id`: keep the caller's, else a UUID), `TraceLayer` (span per request with method, path, request id), request id copied to the response, timeout.

Timeouts return `408 Request Timeout` with an empty body, always. `503` is reserved for readiness, so the two never get confused in dashboards.

## Shutdown

`shutdown_signal()` completes on SIGINT or SIGTERM. Then `serve_on` flips `/readyz` to 503, stops accepting connections, lets in-flight requests finish (bounded by `REQUEST_TIMEOUT_SECS`), and returns `Ok(())`. A second signal is not handled specially; the orchestrator's kill timeout is the backstop. Set it above `REQUEST_TIMEOUT_SECS` (Kubernetes: `terminationGracePeriodSeconds`, Docker: `--stop-timeout`). `tests/http.rs` proves the clean exit.

## Observability

- Logging uses `tracing`. `LOG_FORMAT=json` gives one JSON object per line on stdout; otherwise pretty output. Filter with `RUST_LOG`.
- Every request span carries `request_id`. Send the same id to downstream calls to correlate logs.
- Libraries and handlers only emit events (`tracing::info!`, `error!`); `init_tracing` in the binary owns output.

## Deploy

```sh
docker build -t podgate .
docker run --rm -p 8080:8080 -e RUST_LOG=info podgate
```

- Build stage `rust:1.99-slim` runs `cargo build --release --locked`, so `Cargo.lock` must be committed.
- Runtime stage `gcr.io/distroless/cc-debian12:nonroot`: no shell, runs as non-root, listens on 8080.
- The image has no Docker `HEALTHCHECK`: distroless has no shell or HTTP client. Point the orchestrator's probes at `/healthz` (liveness) and `/readyz` (readiness).
- Bump the `rust:` tag together with `rust-toolchain.toml`.

## Conventions

- Lints in `Cargo.toml` (`docs/rust-style.md`); `exhaustive_*` allowed because this is application code.
- Dependencies: add only when std cannot do it in a few lines; `cargo deny check` gates licences and advisories.
- Tests: unit tests in a `mod test` leaf, HTTP tests in `tests/http.rs`.
