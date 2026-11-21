# Cluster-wide `rate_limit` with a shared store

Reference for `src/middleware/rate_limit/cluster.rs` (the middleware side) and `src/ratelimit_store.rs` with its submodules (the store client: RESP2, connection pool, script loading, circuit). The rest of `rate_limit` (source, buckets, bounded table, node scope) is in `docs/ref/mw-limits.md`. Traefik has this only in its Enterprise and Hub editions (`rateLimit` with a Redis store); Caddy has it in plugins. The difference that matters: **what happens when the store fails is a required choice**, not a default.

A node-scope limit counts per node, and the control plane divides a global limit by the node count. A cluster-scope limit counts once for all nodes through a Redis-compatible store (Redis, Valkey, KeyDB, Dragonfly), at the price of one store round trip per request that passes the node's local pre-filter. Use it on the routes that need an exact global count (a login, a paid API); leave the rest at node scope.

```json
{
  "name": "login-limit", "type": "rate_limit",
  "average": 100, "period_secs": 60, "burst": 20,
  "source": { "ip": {} },
  "scope": "cluster", "store": "main",
  "on_store_error": "allow",
  "local_fallback": { "average": 25, "burst": 5 },
  "store_timeout_ms": 20
}
```

|Field|Meaning|
|---|---|
|`scope`|`"node"` (default) or `"cluster"`.|
|`store`|Required for cluster scope: the name of a store in the operator's `RATE_LIMIT_STORES_FILE`, usable by the app's tenant.|
|`on_store_error`|Required for cluster scope: `"allow"` or `"deny"`. There is no default, and absence is `invalid_middleware`: failing open without a local limit removes the protection exactly when something is wrong, and failing closed turns a store outage into a site outage.|
|`local_fallback`|`{average, burst}`, same bounds as `average` and `burst`, over the same `period_secs`. Required with `allow`, refused with `deny`. The limit this node applies alone while the store is unavailable, so the cluster limit degrades to a per-node one instead of disappearing. The control plane sets it to the cluster limit divided by the node count.|
|`store_timeout_ms`|Optional, 1 to 200. How long one store call may take. Default: the store entry's `timeout_ms`.|

A cluster field on a node-scope limit is `invalid_middleware`, like every other setting a limit would ignore. `in_flight_req` has its own cluster scope, which uses leases instead of a release a crashed node never sends: `docs/ref/inflight-cluster.md`.

## Where the store lives

The store's address and credentials are process configuration, never part of a snapshot: a snapshot-chosen address would be an outbound-connection primitive. `RATE_LIMIT_STORES_FILE` is read once at startup:

```json
{
  "main": {
    "url": "rediss://cache.internal:6379",
    "username": "podgate",
    "password_file": "/run/secrets/limits-password",
    "tls_ca_file": "/etc/podgate/cache-ca.pem",
    "tenants": ["acme"],
    "max_connections": 16,
    "timeout_ms": 20
  }
}
```

|Field|Meaning|
|---|---|
|`url`|Required. `redis://host[:port]` or `rediss://host[:port]`, port default 6379. No credentials, database or path: the file refuses them.|
|`password_file`|Optional. The file holds the password (one trailing newline is dropped). Sent as `AUTH [username] password` on every new connection. Read once: restart to rotate it.|
|`username`|Optional, needs `password_file` (an ACL user).|
|`tls_ca_file`|Required for `rediss://`, refused for `redis://`. PEM CA certificates the store's certificate must chain to, for the host in `url`. The platform's roots are never used.|
|`tenants`|Required, not empty. The tenant ids that may use the store. A snapshot names a store only for those tenants.|
|`max_connections`|1 to 256, default 16. Connections the node keeps to the store.|
|`timeout_ms`|1 to 200, default 20. The deadline of one call: connect, TLS, `AUTH`, the script and the reply.|

A bad file, a missing password or CA file, or an entry that breaks a rule stops startup with `invalid RATE_LIMIT_STORES_FILE: <path>: store "<name>": <reason>`; the reason never quotes a credential. No store is contacted at startup: a store that is down does not stop the proxy.

**Who may use a store.** A snapshot that names a store that does not exist, or one the app's tenant is not listed for, is refused with `invalid_middleware` and the same message in both cases, so a tenant cannot learn which stores other tenants use. A snapshot cannot carry an address: unknown fields are refused, and a store name that looks like a URL is only a name nobody configured.

**The upstream address policy does not apply to a store.** The policy (`docs/ref/upstream-policy.md`) guards the addresses a *tenant* can aim podgate at. The store's address is chosen by the operator, and it usually lives on a private network the default policy denies. The tenant's only influence is choosing among the stores the operator listed for it.

**Passwords and TLS.** The password is held in a type whose `Debug` prints `[redacted]`, is never in a log line, an error, explain, the overview or a metric label, and never reaches a snapshot. A `password_file` with `redis://` to a host that is not loopback (an address in `127.0.0.0/8` or `::1`, or `localhost`) stops startup with `invalid RATE_LIMIT_STORES_FILE: <path>: store "<name>": ...`, because it would send the credential in clear text across the network; use `rediss://` with `tls_ca_file`. Loopback and `rediss://` are allowed, and a store without a password may use `redis://` anywhere. The password and the `AUTH` command are not zeroized from memory.

## The algorithm

One Lua script, one atomic round trip (`EVALSHA`, with `SCRIPT LOAD` when the store answers `NOSCRIPT`, after a restart or a flush). It is the generic cell rate algorithm of `rate_limit`: the key holds the time at which the bucket would be full again; the script reads the time from the store (`TIME`), so nodes with skewed clocks agree; a request is allowed when taking a token leaves the bucket within `burst`; an allowed request writes the new time with an expiry of the time the bucket needs to refill, so idle sources cost nothing. A refused request writes nothing and the store tells the node how long to wait: that is `retry-after`.

The store's clock counts microseconds, so the time per token is `period_secs / average` rounded **up** to a microsecond: a cluster limit is never looser than configured, and a rate above one million a second per source is capped at it. A `burst` whose refill time exceeds 2^52 microseconds (about 142 years) is `invalid_middleware`.

**Key.** `podgate:rl:<tenant>:<app>:<middleware name>:<fingerprint>:<source>`.

- Tenant, app and middleware name are percent-escaped (`%` and `:`), so no two tenants can build the same key, and every key of a tenant starts with its own prefix.
- `fingerprint` is the digest of the middleware's whole declaration (the one that keeps node-local state across pushes), so a changed limit starts fresh counters instead of inheriting the old ones.
- `source` is the first 16 bytes, in hex, of the SHA-256 of what identifies the source (the family and the subnet of the resolved client, the header value, or the host). No address or header value reaches the store. A hash of an IPv4 address can be reversed by trying every address: it keeps values out of key listings, it does not hide who the sources are from someone who can read the store.

The source and its IPv6 prefix (`ipv6_subnet_bits`, default 64) are the ones `rate_limit` uses at node scope (`docs/ref/client-ip.md`).

**Order.** A request first takes a token from the node-local bucket, configured with the cluster limit: a cheap pre-filter, so a source that is clearly over the limit never reaches the store. Then the store decides. A request refused locally is a `429` and costs no store call.

## When the store fails

A call that errors (connection, TLS or protocol failure, an error reply such as `WRONGPASS` or `OOM`), times out, finds the circuit open, or finds too many calls in flight is a *store error*, not a verdict.

|`on_store_error`|What the request gets|
|---|---|
|`allow`|Admitted only if the node's `local_fallback` bucket allows it, else `429` with `retry-after`. The fallback bucket has its own table (same `max_sources`), allocated with the main one on the first request, so an outage never meets a failed allocation; the tenant's `max_buffer_bytes` pays for both and the apply-time budget check counts both.|
|`deny`|`503 {"error":"rate limiter unavailable"}` with `retry-after: 1`.|

Both are capacity refusals: the proxy's own answer, not the deploy's, so auto-revert does not count them.

**The circuit.** After 5 consecutive errors a store's circuit opens for 5 seconds: calls fail at once, without touching the network, so a dead store costs one timeout per period instead of one per request. After that one request probes the store; its success closes the circuit, its failure reopens it for another 5 seconds. A probe whose request is cancelled counts as a failure. Recovery is automatic.

**Bounds.** A request never waits for the store longer than its deadline (`store_timeout_ms`, at most 200 ms), whatever the store does. At most 256 calls are in flight to one store; beyond that the call is a store error. When a store lists more than one tenant its in-flight slots are split evenly between them (two tenants: 128 each), so one tenant's flood cannot use up the slots of the others. A call that fails on an idle connection the store had closed is retried once on a new connection within the same deadline.

## Metrics and explain

|Series|Meaning|
|---|---|
|`podgate_ratelimit_store_up{store}`|`1` when the last call succeeded and the circuit is closed, `0` when it failed or the circuit is open. Absent until the first call.|
|`podgate_ratelimit_store_errors_total{store,mode}`|Requests that met a store error, by the `on_store_error` of their middleware.|
|`podgate_limiter_table_bytes`, `_rejected_total`, `_overflow_total`|As for node scope; for an `allow` limit they include the fallback table.|

Explain shows `scope`, `store`, `on_store_error`, `local_fallback` and `store_timeout_ms` of each cluster-scope stage, and never anything about the store's address or credentials.

## Posture changes

On top of the kinds in `docs/ref/mw-limits.md`, `POST /v1/snapshot/plan` lists:

|Kind|When|
|---|---|
|`rate_limit_cluster_fail_open`|A limit that did not fail open (node scope, or `deny`) now has `scope: "cluster"` with `on_store_error: "allow"`: while the store is down only the local fallback limits requests.|
|`rate_limit_scope_node`|A cluster limit became a per-node one: a client can use every node's share.|
|`rate_limit_loosened`|Also: both limits fail open and the new `local_fallback` has a higher rate or a bigger burst.|

## Not covered

Redis Cluster (`MOVED` and `ASK` redirections), Sentinel and replica reads are not followed: point the store at one primary, or at a proxy such as Envoy or a managed endpoint that does. A redirection is an error reply, so a store error. Cluster-wide `in_flight_req` is in `docs/ref/inflight-cluster.md`.
