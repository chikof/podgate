# Middleware `retry`

Reference for the kind in `src/middleware/retry.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

```json
{
  "name": "r",
  "type": "retry",
  "attempts": 3,
  "initial_interval_ms": 100,
  "methods": ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"]
}
```

| Field | Meaning |
|---|---|
| `attempts` | Required. Attempts including the first, `1` to `5`. `1` never retries. Above `5` is `invalid_middleware`. |
| `initial_interval_ms` | Wait before the first retry, doubled for each further one. Default `100`, at most `10000`. `0` retries at once. Traefik's `initialInterval`. |
| `methods` | Methods retried after a reused connection died (see below). Default: the idempotent set of RFC 9110. An empty list retries connect errors only. Case does not matter. |

Unknown fields are `invalid_middleware`. `retry_statuses` is `unsupported_setting`: once an upstream has produced a response head Pingora cannot retry, and replaying after a response started is how requests are duplicated. There is no `retry_match` expression and no retry on a response status; this is the deliberate difference to Caddy's `retry_match`.

## What is retried

Pingora marks an attempt retryable only when no response byte arrived. `retry` narrows that to two cases.

| Failure | Retried when |
|---|---|
| Connect: refused, unreachable, handshake failed | Any method, as long as no part of the body was streamed to a server. Nothing was sent. |
| Reused connection: a pooled connection died before a response byte | The method is in `methods` **and** the whole body can be sent again: the request has no body, or the `buffering` middleware holds it (`buffer_request`, at most 64 KiB). A streamed body is never replayed. |

A connection that is fresh and fails after the request was written is not retried at all: the server may have acted on it. A failure after the response started is not retried either.

A request with no `retry` in its chain keeps Pingora's own rule: an idempotent request is retried on the same server when a reused connection died. A `retry` stage replaces that rule for its routes.

## Where the next attempt goes

The next attempt goes to the same revision and service, to a server that the balancer's `PickCx::allows` accepts: available (healthy, not ejected) and not already tried by this request. The balancer's own choice still applies, so a hashing or sticky service falls back to its next server.

When only one server exists, or every other one was tried or is down, a connect error is tried again on a server already tried, after the backoff. A dead reused connection is not: the request ends with the original error.

Before the attempt starts:

1. The next server must pass the upstream address policy (`docs/ref/upstream-policy.md`). When it does not, the request is not retried and ends with the original error.
2. The failed attempt is counted: against its server for passive ejection (`docs/ref/svc-outlier.md`), and as one network error for every `circuit_breaker` in the chain (`docs/ref/mw-circuit-breaker.md`). The last attempt is counted once, when the request ends, so a request that was tried three times is three outcomes.
3. The backend slot of the failed attempt is returned, the backoff is waited out, and the request is admitted to the next server's backend again: it can wait in its tenant's fair queue like a new request and is answered `503` with `retry-after: 1` when the queue is full. The tenant's `max_inflight` slot is taken once per request, so retries never raise it.

`upstream_request` hooks run again for every attempt, on a fresh copy of the request head.

## Bounds

- `attempts` is at most 5, so a request is tried at most five times, whatever the servers.
- The wait before retry `n` is `initial_interval_ms * 2^(n-1)`, cut by jitter to between half and all of it, so successive waits grow even in the worst case.
- A retry whose wait would not end before the request deadline is not made. The deadline is `REQUEST_TIMEOUT_SECS` (default 30) from the start of the middleware chain. An attempt that itself times out uses up that time, so a connect timeout is rarely retried.

## Visibility

The number of retries of a request is `retry_attempts` in the access log (`docs/ref/access-log.md`): `0` when the first attempt was the only one, `1` when the request went to a second server. The filter `filters.retry_attempts` selects requests retried at least that many times. `server` is the server of the last attempt. `GET /v1/explain` shows the middleware with its settings.

## Differences to Traefik and Caddy

| | Traefik `retry` | Caddy | podgate |
|---|---|---|---|
| Attempts | `attempts` (includes the first), no cap | `lb_retries` | `attempts`, at most 5 |
| Backoff | exponential from `initialInterval` | `lb_try_interval`, fixed, `lb_try_duration` | exponential with jitter, bounded by the request deadline |
| What retries | network errors | by default requests that never connected, else `retry_match` | connect errors for any method; a dead reused connection only for `methods` with a replayable body |
| Response statuses | not retried | `retry_match` can | never |
| Request body | not replayed | not replayed | replayed only when `buffering` holds it |
