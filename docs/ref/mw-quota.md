# The `quota` middleware

Reference for `src/middleware/quota.rs` (the middleware) and `src/ratelimit_store/quota.rs` (the counter). A quota gives each source (an API key, a client address, a JWT claim) a number of requests over a calendar minute, hour, day or month, counted across all nodes in the shared store. It matches the quota limits of Traefik Hub's API management. `rate_limit` is a different tool: a per-second bucket that smooths bursts and may count per node. A quota is the plan page: 10,000 requests a month, resets at 00:00 UTC on the 1st.

```json
{
  "name": "plan", "type": "quota",
  "limit": 10000, "period": "month",
  "source": { "header": "x-api-key" },
  "store": "main",
  "on_store_error": "allow",
  "store_timeout_ms": 20
}
```

|Field|Meaning|
|---|---|
|`limit`|Required. Requests one source may make per window, 1 to 2^40.|
|`period`|Required. `minute`, `hour`, `day` or `month`: a fixed UTC calendar window.|
|`source`|Required. What a request is counted by: `{"ip": {...}}`, `{"header": "<name>"}`, `{"host": true}` (exactly as for `rate_limit`, `docs/ref/mw-limits.md`) or `{"jwt_claim": "<claim>"}` (below).|
|`store`|Required. The name of a store in the operator's `RATE_LIMIT_STORES_FILE` that the app's tenant may use (`docs/ref/ratelimit-cluster.md`).|
|`on_store_error`|Required: `"allow"` or `"deny"`. There is no default, and absence is `invalid_middleware`.|
|`store_timeout_ms`|Optional, 1 to 200. How long one store call may take. Default: the store entry's `timeout_ms`.|

There is no node scope. A quota that resets when the process restarts, or counts only what one node saw, is not a quota, so a quota without a store is `invalid_middleware`. A field the middleware does not know (`scope`, `local_fallback`, an address) is `invalid_middleware` too.

## Windows

Windows are fixed UTC calendar windows, not rolling ones: one counter per window is one key and one `INCRBY`, and "resets on the 1st" is what a customer can read. The window is named by the node's UTC clock. Nodes whose clocks differ by a second or two near a boundary count that second in the neighbouring window. The count for a source in the window that ended is gone a short grace after it ends (a minute for a minute window, ten minutes for an hour, an hour for a day or month).

|Period|Window|Resets|
|---|---|---|
|`minute`|a calendar minute|at second 0|
|`hour`|a calendar hour|at minute 0|
|`day`|a calendar day|at 00:00 UTC|
|`month`|a calendar month (28 to 31 days, leap years included)|at 00:00 UTC on the 1st|

## What a request sees

Every answer the quota touches says what is left, with the names of the IETF rate limit headers draft:

|Header|Value|
|---|---|
|`RateLimit-Limit`|`limit`.|
|`RateLimit-Remaining`|What the source has left in the window, after this request. 0 on the `429`.|
|`RateLimit-Reset`|Seconds to the end of the window, at least 1.|

An upstream's own `RateLimit-*` headers are replaced: podgate's count is the one the client is held to. A source that has made `limit` requests gets `429 {"error":"quota exceeded"}` and `Retry-After` equal to `RateLimit-Reset`, the seconds to the next window. No upstream is contacted, and the refusal is a capacity refusal, so auto-revert does not count it as a broken deploy. A request that a later middleware refuses (a `403`, say) still used a unit.

## The key

`podgate:q:<tenant>:<app>:<middleware>:<fingerprint>:<window id>:<source>`

- Tenant, app and middleware are percent-escaped (`:` and `%`), so two tenants can never build the same key.
- The fingerprint digests `period`, `source` and `store`: a changed period, source or store starts fresh counts. The limit, the failure choice and the timeout are not part of it. A limit change applies to the counts already used: `admit` compares the count with the current limit, so lowering 10,000 to 5,000 in mid-month does not hand anyone up to 5,000 more requests, and raising it frees exactly the difference.
- The window id is `202611` for a month, `20261122` for a day, `2026112214` for an hour, `202611221430` for a minute.
- The source is the first 16 bytes of the SHA-256 of what identifies it, in hex. No address, header value or claim reaches the store.
- The key expires at the window end plus the grace.

Isolation follows: another tenant, app, middleware, period, source or store is another key, and so is another source.

## Source: a JWT claim

`{"jwt_claim": "sub"}` counts by a verified claim of the caller's token. The claim must be one a `jwt_auth` earlier in the same chain copies into a request header (`forward_claims`, `docs/ref/mw-jwt.md`); the quota reads that header. `jwt_auth` removes the client's own copy of every header it writes before it verifies the token, so a client cannot choose its own count by sending the header. A token with no such claim counts under one shared source, which limits more, never less. A quota whose chain has no earlier `jwt_auth` copying the claim, or whose chains disagree on the header, is `invalid_middleware` naming the router.

## When the store fails

A store error (down, slow, saturated, circuit open, an error reply) is not a verdict, and what to do about it is a choice the snapshot must make:

|`on_store_error`|A request that meets a store error|
|---|---|
|`allow`|Is admitted, without `RateLimit-*` headers (what is left is unknown), and counted in `podgate_quota_unmetered_total`. A quota that fails open lets a client past its limit while the store is down: alert on that series.|
|`deny`|Is answered `503 {"error":"quota unavailable"}` with `retry-after: 1`.|

The store's circuit (`docs/ref/ratelimit-cluster.md`) opens after five consecutive errors and probes again after five seconds, so a dead store costs one timeout per period and both modes recover on their own when the store returns. The store that comes back may be empty: counts it lost start again at zero.

## Who sets what

The tenant names a store and sets `limit`, `period`, `source`, `on_store_error` and `store_timeout_ms`. The store's address, credentials, TLS and the tenants that may use it, and its connection and in-flight caps, are the operator's (`RATE_LIMIT_STORES_FILE`); nothing in a snapshot can carry an address. A snapshot that names a store that does not exist, or one the app's tenant is not listed for, is refused with `invalid_middleware` and the same message in both cases. One tenant's quota calls share the store's in-flight cap fairly with the others', so a flood of quota checks from one tenant does not starve another's.

## Charging by amounts the response tells

The counter behind the middleware (`podgate::ratelimit_store::quota`) has a second call for limits whose cost is known only after the response, such as the AI token limit (`ai_token_limit`, `docs/ref/mw-ai-token-limit.md`, which counts the tokens a model reports):

```rust
let bound = counter.bind(&store, SourceId::of(material));
// Before the request: refuse when nothing is left, take nothing.
bound.admit(0, now_secs()).await?;
// After the response: add what it cost, with no check.
bound.charge(tokens, now_secs()).await?;
```

`admit(cost, now)` refuses when the source has used its limit up, and otherwise adds `cost` in the same script call. `charge(amount, now)` adds without a check, so an over-spend is allowed once and shows on the next `admit`. Both take the time as an argument: the middleware passes the node clock, tests pass a chosen time. A charge lands in the window that holds `now`, which is when the units are spent. A `Bound` is `Clone + Send + 'static`, so a task can own it after the request has ended.

## Metrics

|Series|Meaning|
|---|---|
|`podgate_quota_store_up{store}`|1 when the last call to a store a quota uses succeeded, 0 when it failed or its circuit is open. Absent before the first call.|
|`podgate_quota_store_errors_total{store,mode}`|Requests of a quota that met a store error, by what their `on_store_error` did.|
|`podgate_quota_unmetered_total{store}`|Requests a quota admitted without counting them, because the store gave no verdict and `on_store_error` is `allow`.|

## Posture

`POST /v1/snapshot/plan` lists these under `posture_changes`:

|Kind|When|
|---|---|
|`quota_removed`|The middleware is gone: nothing counts the route.|
|`quota_loosened`|A higher limit, or a shorter period at the same limit (periods compare at their nominal length, a month counting 31 days).|
|`quota_source_changed`|Requests are counted by another source, which can let a client leave its count.|
|`quota_fail_open`|A quota that did not admit requests when its store fails now does (`on_store_error: "allow"`).|

`GET /v1/explain` shows the limit, period, source, store, `on_store_error` and timeout of the stage.
