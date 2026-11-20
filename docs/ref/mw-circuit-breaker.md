# Middleware `circuit_breaker`

Reference for the kind in `src/middleware/circuit_breaker.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

A circuit breaker stops sending traffic to a failing downstream for a while when its error ratio or latency crosses a threshold, then lets traffic back gradually.

```json
{
  "name": "cb",
  "type": "circuit_breaker",
  "trip_when": {
    "network_error_ratio": 0.30,
    "response_code_ratio": { "from": 500, "to": 600, "over_from": 0, "over_to": 600, "ratio": 0.25 },
    "latency_quantile_ms": { "quantile": 50.0, "ms": 100 }
  },
  "check_period_ms": 100,
  "fallback_secs": 10,
  "recovery_secs": 10,
  "min_requests": 20,
  "response_code": 503
}
```

`trip_when` is required and needs at least one trigger; any one of them opens the circuit. Every other field is optional and shown with its default. Unknown fields, a ratio outside `0..=1`, a quantile outside `0..=100`, an empty status range, a `min_requests` of `0`, a `fallback_secs` of `0` and a `response_code` that is not `4xx` or `5xx` are `invalid_middleware`.

## Against Traefik

Traefik writes the triggers as one expression string, `circuitBreaker.expression`. podgate has no expression language: the three functions Traefik documents are typed fields, joined by "any of" (Traefik's `||`; there is no `&&`).

|Traefik|podgate|
|---|---|
|`NetworkErrorRatio() > 0.30`|`"network_error_ratio": 0.30`|
|`ResponseCodeRatio(500, 600, 0, 600) > 0.25`|`"response_code_ratio": {"from": 500, "to": 600, "over_from": 0, "over_to": 600, "ratio": 0.25}`|
|`LatencyAtQuantileMS(50.0) > 100`|`"latency_quantile_ms": {"quantile": 50.0, "ms": 100}`|
|`checkPeriod`, `fallbackDuration`, `recoveryDuration`|`check_period_ms`, `fallback_secs`, `recovery_secs`|
|`responseCode`|`response_code`|

The status ranges are half open, as in Traefik: `from..to` over `over_from..over_to`. The string is never parsed by the proxy, so there is nothing to inject into and nothing to evaluate per request. A translator from Traefik's string belongs to the Traefik translators: it maps these three shapes and refuses the rest.

One addition: `min_requests` (default `20`). A window with fewer requests never trips, so one failed request out of one cannot open the circuit; Traefik has no such floor. The response-code trigger counts the requests in its `over` range against the floor, the other two count every request.

## What counts

- A request counts when it passed the breaker and ended with a response or with an upstream failure: refused connection, reset, timeout (`network_error_ratio` counts those; the `502` or `504` podgate then answers counts in the status ranges too).
- A request refused for capacity (tenant in-flight limit, backend saturated, wake timeout) says the proxy is busy, not that the downstream is broken: it is not counted.
- A request the breaker itself refused is not counted.
- Latency runs from the request reaching the breaker to the end of the request, in a histogram of 64 log-scale buckets (25% wide from 1 ms); the quantile is read at the middle of its bucket, so it is off by up to 12%.

## States

|State|Requests|Leaves when|
|---|---|---|
|closed|pass, and are counted in a window of ten one-second buckets|the window is judged (at most every `check_period_ms`) and a trigger is breached with at least `min_requests` requests in it: opens|
|open|answered at once with `response_code` (default `503`), `Retry-After` set to the seconds left, no upstream contacted|`fallback_secs` have passed: recovering|
|recovering|the window starts empty; the share that passes rises linearly from 0% to 100% over `recovery_secs`, the rest are answered as when open|the first breach: open again. `recovery_secs` passed: closed|

The moves out of open and out of recovering happen on the first request after their time is up. A circuit nobody calls stays where it is until somebody does. With `recovery_secs: 0` the circuit closes as soon as the fallback is over.

The answer is `{"error": "circuit breaker open"}`. It counts as a `5xx` for auto-revert like any other answer podgate gives, and a request it refuses is recorded as a failed request when the status is a `5xx`.

## State and cost

State belongs to (app, middleware name) and is shared by every router that uses the middleware by name. A snapshot swap hands the new table the existing breaker when the middleware's configuration is equal, so an unrelated push neither closes an open circuit nor forgets the window. Any change to the configuration (including a ratio) starts a closed circuit with an empty window. A removed middleware loses its state.

A breaker costs a few kilobytes whatever the traffic. The request path takes no lock and allocates nothing: one atomic word holds the state and moves by compare-and-swap, the counters are relaxed atomics (`cargo nextest run circuit_hot_path_allocates_nothing`). A request that lands exactly while its bucket rolls over to the next second can be lost from the count; that is a rounding error for a ratio, never an overcount.

## Events

`GET /v1/events` reports `circuit_opened {app, middleware}` every time the circuit opens (a re-open during recovery is another opening) and `circuit_closed {app, middleware}` when recovery completes, so the control plane learns without scraping metrics. Each transition is won by exactly one request, so each is emitted once.

`GET /v1/explain` lists the stage with its configuration and its current `phase` (`closed`, `open` or `recovering`).
