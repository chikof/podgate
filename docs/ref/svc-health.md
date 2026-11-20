# Active health checks

A `loadbalancer` with a `health_check` is probed by podgate: a server that fails its probe stops receiving new requests and takes them again when it passes, without any request having to fail first. The probe writes the `healthy` flag of the server, which every balancer already reads (`docs/ref/lb-algorithms.md`).

```json
{ "name": "web", "type": "loadbalancer",
  "health_check": { "path": "/healthz", "interval_secs": 5, "timeout_secs": 2,
                    "expect_status": [200, "300-399"], "expect_body_regex": "\"status\":\\s*\"up\"",
                    "unhealthy_threshold": 3, "healthy_threshold": 2 },
  "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" } ] }
```

## Fields

| Field | Default | Meaning | Traefik | Caddy |
|---|---|---|---|---|
| `path` | required | Origin-form path with an optional query, starting with `/`, at most 2048 bytes. | `path` | `health_uri` |
| `interval_secs` | required | Seconds from the end of one probe to the start of the next, 1..=3600. | `interval` | `health_interval` |
| `timeout_secs` | required | A probe that has not finished by then fails, 1..=300. | `timeout` | `health_timeout` |
| `method` | `GET` | Any HTTP method but `CONNECT`. A method other than `GET`, `HEAD` or `OPTIONS` is sent with `Content-Length: 0`. | `method` | none |
| `expect_status` | `200` to `399` | A list of codes (`204`) or ranges (`"200-299"`), 100..=599. Redirects are not followed, so a `3xx` is judged by this list. | `status` | `health_status` |
| `expect_body_regex` | none | The probe passes only if the regex matches the first 4 KiB of the body. Not allowed with `HEAD`. Matching is linear time and the compiled size is capped. | none | `health_body` |
| `headers` | none | Extra request headers, at most 32. `Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Upgrade`, `TE`, `Trailer`, `Expect`, `Keep-Alive` and `Proxy-Connection` cannot be set. | `headers` | `health_headers` |
| `hostname` | the address probed | The `Host` header, with an optional `:port`. | `hostname` | `health_headers` |
| `scheme` | `http` | Overrides the server's scheme: `https` probes over TLS with the service's transport (trust anchors, SNI, client certificate), `http` probes in the clear. Unset: the scheme of the server URL. | `scheme` | `health_uri` scheme |
| `port` | the server's port | Probe another port of the same IP, such as a management port. | `port` | `health_port` |
| `healthy_threshold` | `1` | Consecutive passes that mark a down server up, 1..=100. | none | `health_passes` |
| `unhealthy_threshold` | `1` | Consecutive failures that mark an up server down, 1..=100. | none | `health_fails` |

A field that is missing, unknown or out of range is `invalid_service`, and the whole snapshot is rejected. A service may declare at most 256 servers (with or without a check): more is `invalid_service`.

## Semantics

- **A new server starts healthy**, as in Traefik and Caddy. Traffic is never held back for a probe, because that would turn every deploy into a gap. The first probe runs within one `timeout_secs` (a jitter derived from the server's identity spreads the probes of a large service).
- **Thresholds count consecutive results.** An up server goes down after `unhealthy_threshold` failures in a row, a down server up after `healthy_threshold` passes in a row; a result that agrees with the current verdict resets the count. A failure is a connect error, a timeout, a status outside `expect_status`, a body that does not match, a head over 8 KiB or a reply that is not HTTP/1.x.
- **Every server unhealthy.** The service answers `503` (`no healthy upstream available`) and does not wake a `scale_to_zero` app: only an app with no server at all is asleep.
- **Revisions.** The services of `serving` and `retiring` revisions are probed (a retiring revision still serves pinned sessions); `draining` revisions are not.
- **Probes are not requests.** They take no tenant slot, no backend slot, are not counted in the response outcomes that auto-revert reads, and do not appear in failed requests. The load balancer's `active` count is untouched.

## What a probe can reach

- Only the declared servers: the IP of the server, on `port` when the check sets one. Nothing from a request, a response header or a `Location` is ever dialled; a redirect is read and not followed.
- Every probe calls the upstream address policy (`docs/ref/upstream-policy.md`) with the tenant and the exact IP it is about to dial. A refusal fails the probe and counts in `podgate_upstream_refused_total{tenant}`.
- Probes connect through Pingora's `TransportConnector`, the connect path of the proxy. The peer comes from the service's transport (`Check::peer`, via `Upstream::peer`), so an `https://` server is probed with the trust anchors, SNI and client certificate of its requests, and the dialled IP is still checked against the policy.

## Bounds

- At most `HEALTH_MAX_CONCURRENT` probes (default 64) run at once across the whole process and all tenants; the others wait for a permit. A tenant that declares thousands of servers can queue probes but never hold more than the cap, and never the budget of another tenant's requests.
- Each probe is cut at `timeout_secs`. It reads at most 8 KiB to find the end of the response head and at most 4 KiB of the body; without `expect_body_regex` it stops at the end of the head. The connection is closed after one exchange (`Connection: close`).
- One tokio task per probed server, plus a few hundred bytes of state; at most 256 servers per service.

## State

The verdict is two things. The flag `ServerState::healthy` is in the registry of `docs/ref/lb-algorithms.md`, kept across pushes for a service whose declaration did not change. The streak (how many consecutive results point the other way) is in the scheduler under the key `(owner, app, revision, service, server URL, fingerprint of the check)`:

- A push that does not touch the check keeps the streak and the flag.
- A changed check is a new key: the old probe stops and the new one starts fresh, healthy until it fails. (The registry also starts the flag fresh, because the declaration changed.)
- A push that changes another part of the service (its algorithm, say) gives the servers a fresh flag; the scheduler writes its verdict into it at the next reconcile, which follows the swap within milliseconds.

## Metrics

`GET /metrics` on the admin socket: `podgate_service_server_up{app,revision,service,server}` is `1` for a server the check has not marked down and `0` for one it has, for every server of every service. `revision` is empty for a service the app shares between revisions.

## For other specs

`podgate::service::health::Scheduler` is generic: it runs any async probe. Change 0095 (L4 health) registers its TCP probes with

```rust
scheduler.register(key, schedule, server.state.clone(), probe_fn);
```

where `Key.owner` names the registrar (`"http"` here), `Schedule` holds interval, timeout and thresholds, and `ProbeFn` is `Arc<dyn Fn() -> ProbeFuture>` returning a `Verdict`. The scheduler adds the initial jitter, the global concurrency cap (one semaphore for every registrar), the timeout around each probe, the streak and the write of `healthy`. `Scheduler::retain(owner, keep)` removes an owner's probes that a reconcile no longer wants without touching another owner's. `HealthService::scheduler()` hands out the shared instance; `HealthService::reconcile(&table)` is the HTTP registrar to copy from.
