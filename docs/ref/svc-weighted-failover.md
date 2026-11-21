# The `weighted` and `failover` services

Two services that pick among other services of the same app instead of among servers. `weighted` splits traffic between services by weight (traffic shifting between whole services, Traefik's `weighted`); `failover` uses a main service while it has a healthy server and a fallback otherwise (Traefik v3's `failover`). Caddy has no service of services: it uses several upstream blocks and `lb_policy`.

```json
{ "name": "split", "type": "weighted",
  "services": [ { "service": "web-v1", "weight": 90 }, { "service": "web-v2@r2", "weight": 10 } ],
  "sticky": { "cookie": { "name": "__podgate_svc" } } }

{ "name": "safe", "type": "failover", "service": "web", "fallback": "standby",
  "fallback_hold_secs": 10 }
```

A router names either like any other service. They nest: a `weighted` may hold a `failover` that holds a `weighted`, to four services on one path (`weighted -> failover -> weighted -> loadbalancer`).

## Fields

| Type | Field | Meaning |
|---|---|---|
| `weighted` | `services` | One to 32 children `{service, weight}`. `weight` is `0` to `65535` and required; at least one is above `0`. A child of weight `0` never receives a request. |
| `weighted` | `sticky` | Pins a client to one child with a cookie, see below. Same fields as a `loadbalancer`'s `sticky`; the cookie is called `__podgate_svc` unless `cookie.name` says otherwise. Needs the snapshot's `skew_secret`. |
| `failover` | `service` | The main service. |
| `failover` | `fallback` | The service that takes requests while the main one has no healthy server. |
| `failover` | `fallback_hold_secs` | Seconds the fallback keeps serving after the main service was last seen without a healthy server, `0` to `3600`, default `10`. |

A child is a `loadbalancer`, `weighted` or `failover` service of the same app, written `name` (the revision the request picked, else the app's own services) or `name@revision` (that revision, else the app's). The names resolve when the snapshot compiles, once per revision, so a `weighted` service the app shares by all its revisions splits between each revision's own `web`.

A field that is unknown or out of range is `invalid_service`; a child nothing defines is `unknown_service` (a `draining` revision, which takes no request, may lack one).

## What counts as an eligible child

A service is **ready** when some server below it may take this request: healthy (`health_check`), not ejected (`passive`), not already tried by this request (a retry) and with a weight above `0`. Everything below is decided by that one rule, which the split between revisions of an app uses as well.

| State | Meaning |
|---|---|
| ready | Some server below it may take the request. |
| down | It has servers and none may take the request. |
| asleep | It has no server anywhere below it: the app has nobody running (`scale_to_zero`). |

## `weighted`

Weights are relative among the ready children. A child that is not ready receives nothing and its share goes to the others in proportion to their weights, so a `weighted` service never sends to a dead child while another lives. Within a turn of `sum of weights` requests each ready child gets exactly its weight, and the children alternate instead of taking runs (the same spreading the revisions of an app use). When no child is ready the service has no server: `503` `no healthy upstream available`, or a wake when every child is asleep.

### Sticky

`sticky` on a `weighted` service pins a client to one child. The first response carries a cookie keyed like a server's cookie (`docs/ref/svc-sticky.md`) with the name of the child as written in `services` in place of the server URL, so the cookie names no service and cannot be forged. While that child is ready the client goes to it; otherwise the weighted choice decides and the response carries a cookie for the child chosen. A child that is itself sticky pins a server inside the child with its own cookie, so a client has two cookies. Two sticky services on one path must use different cookie names (`__podgate_svc` and `__podgate_srv` by default): the same name twice is `invalid_service`, because the two would overwrite each other.

## `failover`

The main service takes the request while it is ready. Otherwise the fallback does. Flapping is damped: every request that finds the main service down (not merely tried by a retry) keeps the fallback in use for `fallback_hold_secs` from then on, so the fallback keeps serving that long after the main service recovers. The hold is runtime state kept outside the table, so a push that does not change the service keeps it.

A main service with **no server at all** is asleep and does **not** trigger the fallback: the app is woken instead (`scale_to_zero`, `wake_requested`), because a service nobody has started is not a broken one. A main service whose servers are all unhealthy does trigger it. When neither service is ready the answer is `503`.

## Rules the compiler enforces

- A cycle is `service_cycle`, including through `name@revision` and through another revision.
- More than four services on one path is `invalid_service`, and so is a graph that reaches more than 128 services counting each way to reach one (the pick walks the graph, so its size is bounded).
- A `static` service or a `mirroring` service as a child is `invalid_service`: a static service answers from disk, and a mirroring service as a child would hide its copies from the posture checks (`mirroring::exposure` counts the services a router names). The other way round is allowed: a `mirroring` service may mirror a `weighted` or `failover` main service, and the router names the mirroring service.
- A `weighted` or `failover` service as the page source of an `errors` middleware is `invalid_middleware`: a page comes from one `loadbalancer`.
- Every literal server address of every `loadbalancer` passes the upstream address policy as before (`upstream_forbidden`).

## Retry

`retry` repeats the pick from the router's service with the servers already tried excluded, so a retry may move to another child of a `weighted` service, or from the last server of a `failover` main service to its fallback. A retry that only skips servers it already tried does not start a fallback hold.

## Accounting

The request counts on the revision it picked, whichever revision a `name@revision` child lives in: drain (`revision_drained`) and the revision counters follow the router's revision, and the server's own in-flight count follows the server. Passive ejection, health state and the adaptive limit belong to the servers of the `loadbalancer` that took the request.

## Explain

`GET /v1/explain` adds `graph` to each revision whose router service is a `weighted` or `failover` service:

```json
{ "path": "top -> safe -> web-v2",
  "root": { "service": "top", "kind": "weighted", "state": "ready", "on_path": true, "children": [
    { "service": "safe", "kind": "failover", "weight": 9, "effective_weight": 9, "state": "ready", "on_path": true,
      "children": [ { "service": "web-v2", "kind": "loadbalancer", "role": "primary", "weight": 1, "effective_weight": 1, "state": "ready", "on_path": true },
                    { "service": "web-v1", "role": "fallback", "weight": 1, "effective_weight": 1, "state": "ready", "on_path": false } ] },
    { "service": "asleep", "kind": "loadbalancer", "weight": 5, "effective_weight": 0, "state": "asleep", "on_path": false } ] } }
```

`path` is the way a request would go now: at a `weighted` service the ready child with the largest weight, at a `failover` the side that would serve. `effective_weight` is what the parent's pick uses right now: the weight while the child is ready, `0` otherwise. The servers of each `loadbalancer` are in `GET /v1/overview`. Reading explain changes no counter and starts no hold.

## Differences to Traefik and Caddy

| | Traefik | Caddy | podgate |
|---|---|---|---|
| Weighted children | `weighted.services` | none | the same, with a dead child skipped by the one readiness rule |
| Sticky on the parent | `weighted.sticky` | none | the cookie keyed by the child's name |
| Failover | `failover.service`/`fallback`, health check required | `lb_try_duration` partly | a hold against flapping, and a sleeping main service wakes the app |
| Depth and cycles | unbounded | none | four services deep, `service_cycle` |
