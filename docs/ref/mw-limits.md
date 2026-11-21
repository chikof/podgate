# Middlewares `rate_limit` and `in_flight_req`

Reference for `src/middleware/rate_limit.rs`, `src/middleware/in_flight_req.rs` and `src/middleware/limits.rs` (the source and the bounded table they share). The model they plug into is in `docs/architecture.md` (`### Middlewares`). They match Traefik's `rateLimit {average, period, burst, sourceCriterion}` and `inFlightReq {amount, sourceCriterion}`; Caddy has a rate limiter only as a plugin. Limits are per node; the control plane divides a global limit by the node count. A `rate_limit` can instead count cluster-wide through a shared Redis-compatible store (`scope: "cluster"`, with a required `on_store_error`): `docs/ref/ratelimit-cluster.md`.

```json
{
  "name": "rl", "type": "rate_limit",
  "average": 100, "period_secs": 1, "burst": 200,
  "source": { "ip": { "depth": 1, "excluded": ["10.0.0.0/8"] } },
  "max_sources": 10000
}
{
  "name": "cap", "type": "in_flight_req",
  "amount": 10, "source": { "header": "x-api-key" }, "max_sources": 10000
}
```

|Field|Meaning|
|---|---|
|`average`|`rate_limit`, required, 1 to 10,000,000. Tokens added to a bucket per `period_secs`. `0` is `invalid_middleware`: Traefik reads it as unlimited, and a limiter that limits nothing is a mistake.|
|`period_secs`|`rate_limit`, optional, 1 to 86,400, default 1.|
|`burst`|`rate_limit`, required, at least 1. The bucket's capacity; a source that has been idle can send this many requests at once.|
|`amount`|`in_flight_req`, required, at least 1. Requests one source may have in flight.|
|`source`|Required. What requests are counted per: `{"ip": {depth?, excluded?, ipv6_subnet_bits?}}`, `{"header": "<name>"}` or `{"host": true}`. `ipv6_subnet_bits` is 1 to 128, default 64.|
|`max_sources`|Optional, 1 to 1,000,000, default 10,000. The table holds this many sources.|

Unknown fields (`sourceCriterion`, a misspelt option), numbers out of range or of the wrong type, a bad header name and `{"host": false}` are `invalid_middleware`, so a typo never turns a limit off.

## Source

The limiter counts per source. The key never leaves the process and never names a client in a response.

- **`{"ip": {...}}`.** `ClientIp::resolve(view, strategy)` over the request's `ForwardedView` (`docs/ref/client-ip.md`), the same function `ip_allow_list` uses. With no strategy that is the entry point's own decision: the connection's peer, or, when `forwarded_headers` trusts that peer, the first untrusted address from the right of the chain it sent. A peer the entry point does not trust cannot name its own address. The middleware never reads `X-Forwarded-For` itself. IPv4-mapped IPv6 addresses count as IPv4. A connection with no IP peer is one source. An IPv6 client is counted by the first `ipv6_subnet_bits` bits of its address (default 64, as `ip_allow_list`'s `ipv6_subnet_bits`): a client that owns a `/64` has 2^64 addresses and would otherwise spread over every set of the table and push other clients into the shared overflow bucket. IPv4 addresses are never merged. Use `128` to count every IPv6 address on its own.
- **`{"header": "x-api-key"}`.** The first value of that request header.
- **`{"host": true}`.** The host a trusted proxy reported in `X-Forwarded-Host`, else the request's own host, lowercase without port.
- **An absent value** (no such header, no host) is the source `-`, and so is a header whose value is `-`. A client cannot leave a limit by omitting the value.

Header and host values are hashed under keys chosen at random when the middleware is compiled, so a client cannot aim two sources at one table entry. A hash collision merges two sources, which limits them more, never less.

## `rate_limit`

A bucket holds up to `burst` tokens and gains `average` tokens per `period_secs`. Every request takes one. With none left the request is answered

```
HTTP/1.1 429 Too Many Requests
retry-after: <whole seconds until a token, at least 1>
content-type: application/json

{"error":"rate limit exceeded"}
```

and no upstream is contacted. A refusal does not take a token.

The bucket is the generic cell rate algorithm: one 64-bit number per source, the time at which its bucket would be full again, moved by one request at a time on one atomic step under the source's lock. The time per token is `period_secs / average` rounded up to a nanosecond, so a source never gets more than configured; at the largest `average` and one second the rounding moves the rate by under one percent, and for the usual values it is exact.

## `in_flight_req`

A request takes one slot of its source when it enters the chain. Over `amount` it is answered `429` with `retry-after: 1` and `{"error":"too many requests in flight"}`. The slot is returned when the request ends: the response completed, the upstream failed, the client went away, or a later stage answered. It is held in the request's state and returned by a `Drop` guard, so no exit path can leak it. A WebSocket holds its slot until the connection closes.

## Where it runs

Both run in the middleware chain (pipeline stage 7), before revision and server selection and before every admission, so a refused request reaches no upstream and takes no tenant `max_inflight` slot, no backend permit and does not wake a sleeping app. Both refusals set the capacity-refusal flag: auto-revert does not count them as a deploy's failure.

## Bounded state

Per-source state can never grow without a bound, and a flood of invented sources cannot evict a source that is being limited.

- **A fixed table.** `max_sources` entries in sets of eight, each entry 16 bytes (a 64-bit key and a 64-bit value), each set behind its own mutex: about 17 bytes per source. A request locks one set for a few instructions, never waits on a request that hashes to another set, never allocates, and takes no lock shared by the table.
- **Entries expire without a sweep.** An entry is free for another source when it holds nothing the limit still needs: for `rate_limit` its bucket is full again, for `in_flight_req` no request is in flight. A source whose set holds a free entry takes it.
- **When the eight entries of a source's set all hold live sources, the source uses the table's one overflow bucket** (rate limit: one bucket with the same `average` and `burst`; in-flight: one count capped at `amount`). Sources that already have an entry are untouched. An attacker rotating addresses or header values fills sets and is then limited together as one source; this degrades towards over-limiting, never towards unlimited. `podgate_limiter_overflow_total` counts the requests that used it. A table with `max_sources` of 8 or fewer is one set, so it is full exactly when `max_sources` sources are live; larger tables spread sources over sets, and a source can reach the overflow before every entry of the table is taken. **The trade-off:** the sources that share the overflow bucket are limited together, so an innocent client whose set a flood of distinct sources filled is throttled by sources that are not its own. That limits more, never less, and it is the price of a fixed memory bound. Counting IPv6 clients by prefix keeps one network from filling sets with its addresses; a flood of distinct header values or of IPv4 addresses from many hosts still can, so size `max_sources` for the legitimate number of sources and watch `podgate_limiter_overflow_total`.
- **Memory is charged to the tenant.** A table takes `ceil(max_sources / 8) * 136 + 40` bytes. It is allocated on the first request that reaches the middleware, after that amount was charged to the tenant's `max_buffer_bytes`, and freed when the middleware's state is dropped. A snapshot whose limiter tables, added up for one tenant, do not fit the tenant's declared `max_buffer_bytes` is refused at apply time with `invalid_middleware` (the conflict carries `table_bytes` and `max_buffer_bytes`); every declared limiter counts, used or not. If the tenant's budget is full right now when the first request arrives, that request is answered `503` with `retry-after: 1` (a capacity refusal) and the charge is tried again by the next one. A configuration change leaves the old table charged until the requests that still use it end, so a tenant close to its budget can see this `503` briefly after changing a limiter, or for as long as a WebSocket of the old table lives.

## State across pushes

State is kept in `middleware::state::Registry`, keyed by app, middleware name and a fingerprint of its declaration. A push that does not change the middleware keeps its buckets and counts; a changed declaration (any field, including `max_sources`) starts with empty ones. Requests that began under the old table return their in-flight slots to the counts they took them from.

## Posture changes

`POST /v1/snapshot/plan` lists, under `posture_changes`:

|Kind|When|
|---|---|
|`rate_limit_removed`, `in_flight_req_removed`|The middleware is no longer used by the app.|
|`rate_limit_loosened`|A higher rate (`average` over `period_secs`) or a bigger `burst`.|
|`in_flight_req_loosened`|A higher `amount`.|
|`rate_limit_source_changed`, `in_flight_req_source_changed`|`source` differs: requests are counted per something else, which can let a client leave its bucket.|
|`rate_limit_cluster_fail_open`, `rate_limit_scope_node`|A cluster-scope limit starts failing open, or becomes per-node: see `docs/ref/ratelimit-cluster.md`.|

A stricter limit, a smaller table or a bigger table list nothing.

## Metrics

|Series|Meaning|
|---|---|
|`podgate_limiter_rejected_total{app,middleware,type}`|Requests the middleware refused with `429`.|
|`podgate_limiter_overflow_total{app,middleware,type}`|Requests counted in the shared overflow bucket because the table was full.|
|`podgate_limiter_table_bytes{app,middleware,type}`|Bytes charged to the tenant for the table; `0` until the first request.|

Explain shows each stage's `average`, `period_secs`, `burst`, `amount`, `source`, `max_sources` and `table_bytes`.
