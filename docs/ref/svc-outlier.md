# Passive outlier ejection

`passive` on a `loadbalancer` takes a server out of rotation after it fails real requests, without
waiting for a probe. The code is `src/service/outlier.rs`. It is the passive half of server health;
the active half (probes) is change 0033, and both write one flag per server that every balancer
reads (`ServerState::available`).

```json
{
  "name": "web", "type": "loadbalancer",
  "servers": [{ "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" }],
  "passive": {
    "consecutive_failures": 5, "ejection_secs": 30, "max_ejection_percent": 50,
    "failure_statuses": [502, 503, 504], "latency_ms": 2000
  }
}
```

## Fields

Unknown fields are refused (`invalid_service`), so a misspelt option is never ignored.

| Field | Meaning |
|---|---|
| `consecutive_failures` | Failures in a row that eject a server. At least 1. Required. |
| `ejection_secs` | Length of the first ejection in seconds. At least 1. Required. |
| `max_ejection_percent` | Ceiling on the share of the service's servers that may be ejected at once, `1` to `100`, rounded down. Required. |
| `failure_statuses` | Upstream statuses that count as a failure, each `400` to `599`. Default `[502, 503, 504]`. |
| `latency_ms` | A request that takes longer than this counts as a failure. Off by default. |

## What counts

Failure:

- A connect error, a timeout or a reset on the upstream connection (podgate answers `502` or
  `504`).
- An upstream answer whose status is in `failure_statuses`.
- With `latency_ms`, a request whose whole duration, from the pick of the server to the end of the
  response, is longer than the limit. Upgraded connections (`101`) are exempt, because their
  length is up to the client. A streaming response that legitimately takes longer than
  `latency_ms` counts too, so set it above the longest response you serve.

Not counted, and they do not reset the counter either:

- Capacity refusals: the tenant or backend `503`. Those requests never reach a server.
- Client aborts and proxy-internal errors (the upstream address policy, a filter that failed).
- Requests that were in flight when the server was ejected.

Any other answer is a success and resets the failure counter. The counter is per server and
consecutive.

## Ejection time

The n-th consecutive ejection of a server lasts `ejection_secs * min(n, 8)`. The count goes back to
zero after one full `ejection_secs` of success: counted from the end of the last ejection or the
last failure, whichever is later. A server that comes back and fails again is therefore ejected for
longer, and a flapping server is tried less and less often. It returns at full share when its
ejection ends; its next `consecutive_failures` failures eject it again.

## The ceiling

`max_ejection_percent` is hard. A server is ejected only when, afterwards,

- no more than `max_ejection_percent` of the service's servers are ejected (rounded down, so 50%
  of three servers is one), and
- at least one other server is available (healthy and not ejected).

The second rule holds even at `100`: when every server fails, the last one keeps taking traffic
and its failures reach the clients, instead of the whole service answering `503`. A service where
every server is ejected would look like an outage.

When the ceiling blocks an ejection the server keeps its failure count at the threshold, so the
next failure asks again and it is ejected as soon as there is room.

## State

The counters live in `ServerState::outlier` and share the registry's lifetime (see
`src/service/state.rs`): a push that does not touch the service keeps ejections and counters, and
a push that changes the service declaration (any field except `servers`, `passive` included)
starts every server fresh. Adding or removing a server keeps the state of the others.

## Seeing it

- `GET /v1/explain` lists each server with `available`, and `ejected_for_ms` while it is ejected.
- `GET /metrics` has the gauge `podgate_outlier_ejected_servers{tenant,app,revision,service}` for
  each service with `passive` (`revision` is empty for a service shared by all revisions).

## Differences from Envoy and Caddy

Envoy's `consecutive_5xx` and `base_ejection_time` are the same idea; podgate's ceiling also
keeps one server alive. Caddy's `max_fails` with `fail_duration` counts failures in a time window
and has no growing ejection time. Traefik has no equivalent (its circuit breaker is a middleware
per router).
