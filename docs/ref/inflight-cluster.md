# Cluster-wide `in_flight_req` with leases

Reference for `src/middleware/in_flight_req/cluster.rs` (the middleware side). The store client (RESP2, connection pool, script loading, circuit, the stores file) is the one of cluster-scope `rate_limit`, `src/ratelimit_store.rs`, and everything about it is in `docs/ref/ratelimit-cluster.md`; the rest of `in_flight_req` is in `docs/ref/mw-limits.md`. Traefik has no concurrency limit that spans nodes (its Redis-backed limits are rate limits, and enterprise); Caddy has none. The difference that matters: **a slot is a lease**. A count that depends on every node saying goodbye is wrong after the first crash, so a slot a node never returns expires by itself, and **what happens when the store fails is a required choice**.

A node-scope `in_flight_req` counts per node. A cluster-scope one counts once for all nodes through a Redis-compatible store, at the price of one store round trip per request (plus one when it ends, and one per half lease while it lasts). Use it on the routes whose backend has one global limit (a licensed worker pool, a rate-limited upstream); leave the rest at node scope.

```json
{
  "name": "cap", "type": "in_flight_req",
  "amount": 100, "source": { "header": "x-api-key" },
  "scope": "cluster", "store": "main",
  "on_store_error": "allow",
  "local_fallback": { "amount": 25 },
  "lease_secs": 60
}
```

|Field|Meaning|
|---|---|
|`scope`|`"node"` (default) or `"cluster"`.|
|`store`|Required for cluster scope: the name of a store in the operator's `RATE_LIMIT_STORES_FILE`, usable by the app's tenant. Same rules as for `rate_limit`: an unknown store and a forbidden one give the same `invalid_middleware`.|
|`on_store_error`|Required for cluster scope: `"allow"` or `"deny"`. No default, and absence is `invalid_middleware`.|
|`local_fallback`|`{amount}`, 1 to 10,000. Required with `allow`, refused with `deny`. The cap this node applies alone to a source while the store is unavailable. The control plane sets it to `amount` divided by the node count.|
|`lease_secs`|Optional, 10 to 3600, default 60. How long a slot lasts without being extended.|

`amount` of a cluster-scope cap is at most 10,000: every slot is a member of a set in the store. A node-scope cap has no such ceiling. `scope: "node"` (or no scope) with any of `store`, `on_store_error`, `local_fallback` or `lease_secs` is `invalid_middleware`, like every other setting a limit would ignore. There is no `store_timeout_ms`: a call ends within the store entry's `timeout_ms`.

## The algorithm

One sorted set per key. A member is one request in flight (a random 128-bit id); its score is the lease deadline in milliseconds on the **store's** clock (`TIME`, so nodes with skewed clocks agree). Three Lua scripts, each one atomic round trip (`EVALSHA`, loaded on `NOSCRIPT`, like the rate limit's):

|Script|What it does|
|---|---|
|acquire|Removes the members whose deadline has passed. If the set holds fewer than `amount` members it adds the request's id with deadline `now + lease_secs`, and answers taken; otherwise it answers refused and adds nothing. Either way the key's expiry is set to one lease, so a source that stops sending costs nothing.|
|release|Removes the id. A set with no members is no key.|
|renew|Removes expired members; if the id is still there, moves its deadline to `now + lease_secs`. If it is not (its lease had run out) it adds nothing: a renewal that reaches the store after the release must not bring the slot back.|

So **the set never holds more than `amount` members**, whatever the nodes do, and the memory of a key is bounded by `amount` members of 32 bytes.

**When a slot is returned.** A request takes a slot when it enters the middleware chain and returns it when it ends: the response is done, the upstream failed, the client went away. Like the node-scope slot it is a guard held in the request's state, so every exit drops it; dropping it sends the release in a task of its own, so ending a request never waits for the store. A WebSocket holds its slot until the connection closes.

**A release that fails is not retried.** The store is down, slow or saturated: the lease expires by itself, within `lease_secs`.

**A request that outlives half its lease renews it**, one call per half lease, until it ends. A renewal that fails (store error) is tried again a half lease later; a renewal that finds the lease gone stops renewing, and the request is no longer counted in the store.

**A node that dies leaks at most `amount` slots for at most `lease_secs`.** Nobody releases them and nobody renews them. The first acquire after the deadlines removes them. A long request on a node that restarts is therefore forgotten by the cluster after one lease, which is what a lease is for.

**Key.** `podgate:ifr:<tenant>:<app>:<middleware name>:<fingerprint>:<source>`.

- Tenant, app and middleware name are percent-escaped (`%` and `:`), so no two tenants can build the same key.
- `fingerprint` is the digest of the middleware's whole declaration, so a changed cap (a new `amount`, store or lease) counts apart from the old one, whose leases run out by themselves.
- `source` is the first 16 bytes, in hex, of the SHA-256 of what identifies the source, as for `rate_limit`: no address or header value reaches the store.

**The node's own count.** Every request also takes a slot in the node's own table (the one the node scope uses, `max_sources`, charged to the tenant), after the store gave it one. That count is always kept, whether the store answers or not: it is what limits requests while the store gives no verdict, and an outage never loses track of what this node is serving. There is no node-local pre-filter in front of the store: a request over the cap costs one store call.

## When the store fails

A call that errors, times out, finds the circuit open, or finds too many calls in flight is a *store error*, not a verdict (`docs/ref/ratelimit-cluster.md`: the circuit opens after 5 errors for 5 seconds, a call never waits longer than the store's `timeout_ms`, 256 calls in flight per store shared fairly by the tenants it lists).

|`on_store_error`|What the request gets|
|---|---|
|`allow`|Admitted only if the node's own count of the source is under `local_fallback.amount`, else `429` with `retry-after: 1`. The request takes the node's slot and no store slot.|
|`deny`|`503 {"error":"in-flight limiter unavailable"}` with `retry-after: 1`; the access log's `reason` is `inflight_store_unavailable`.|

Both are capacity refusals: auto-revert does not count them. Like every in-flight refusal they are answered before any tenant `max_inflight` slot, backend permit or upstream is taken.

**Recovery is automatic**, and the node's current requests are re-registered lazily: new requests acquire in the store as usual, while the requests already in flight are not counted in the store. After a store outage (and after a store that lost its data) the cluster can therefore exceed `amount` for a while, by what the nodes served meanwhile; it comes back under as those requests end. If this matters, use `deny`.

## Metrics, explain and posture changes

|Series|Meaning|
|---|---|
|`podgate_inflight_store_up{store}`|`1` when the last call to the store succeeded and the circuit is closed, `0` otherwise. Present for a store once a cluster `in_flight_req` has used it; absent until its first call.|
|`podgate_inflight_store_errors_total{store,mode}`|Requests that met a store error, by the `on_store_error` of their middleware.|
|`podgate_inflight_lease_renewals_total`|Leases this node extended because their request outlived half the lease.|
|`podgate_limiter_*`|As for node scope.|

Explain shows `scope`, `store`, `on_store_error`, `local_fallback` and `lease_secs`, and never anything about the store's address or credentials.

`POST /v1/snapshot/plan` lists, on top of the kinds in `docs/ref/mw-limits.md`:

|Kind|When|
|---|---|
|`in_flight_req_cluster_fail_open`|A cap that did not fail open (node scope, or `deny`) now has `scope: "cluster"` with `on_store_error: "allow"`.|
|`in_flight_req_scope_node`|A cluster cap became a per-node one: a client can use every node's share.|
|`in_flight_req_loosened`|Also: both caps fail open and the new `local_fallback.amount` is higher.|

## Not covered

Redis Cluster redirections, Sentinel and replica reads (see `docs/ref/ratelimit-cluster.md`).
