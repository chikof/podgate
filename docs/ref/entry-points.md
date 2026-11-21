# Entry points

An entry point is a named listener. Where it listens is process configuration; which routers answer on it, and which tenants may attach routers to it, is snapshot data. Design: `docs/architecture.md ### Entry points`.

## `ENTRY_POINTS`

```sh
ENTRY_POINTS='public=0.0.0.0:80/http,internal=127.0.0.1:8081/http,secure=0.0.0.0:443/https'
```

Syntax: `name=address/protocol[;proxy_protocol]`, entries comma separated.

| Part | Rule |
|---|---|
| `name` | 1 to 63 letters, digits, `-` or `_`. Unique. Routers, policies and explain refer to it. |
| `address` | A socket address (`0.0.0.0:80`, `[::1]:8443`). Two entries may not use the same address on the same transport (TCP for `http`, `https` and `tcp`; UDP for `udp`). |
| `protocol` | `http`: plain HTTP/1.1. `https`: TLS termination, HTTP/2 and HTTP/1.1, certificates from the snapshot chosen by SNI. `tcp`, `udp`: raw listeners. |
| `;proxy_protocol` | Every connection starts with a PROXY protocol header from a peer the snapshot's `entry_points[].proxy_protocol` trusts; anything else is closed. `http` and `https` entry points only. See `docs/ref/proxy-protocol.md`. |

`tcp` and `udp` are parsed and then refused at startup with an error naming the entry point, because the listeners that serve them are not built yet.

`PROXY_ADDR` and `PROXY_TLS_ADDR` are the shorthand for `web=<addr>/http` and `websecure=<addr>/https`. With neither variable nor `ENTRY_POINTS` set, the process has `web=127.0.0.1:8080/http`. Setting `ENTRY_POINTS` together with `PROXY_ADDR` or `PROXY_TLS_ADDR` stops startup with an error that names both.

Any invalid value stops startup with `invalid ENTRY_POINTS: entry "<the entry>": <reason>`.

## What runs

Each `http` or `https` entry point is one Pingora proxy service, built from the same `Gateway` (so the same table, budgets, admission and certificate store), with its name in `Ctx.entry_point`. A request is matched only among routers that listen on that name. An `https` entry point shares the certificate store and the SNI hooks with every other `https` entry point.

Pingora gives every service its own worker pool, so each additional entry point adds one pool of `available_parallelism` threads.

## In the snapshot

| Field | Meaning |
|---|---|
| `router.entry_points` | The entry points the router listens on. Absent: every `http` and `https` entry point the tenant may use. Empty or naming an unbound entry point: `unknown_entry_point`. |
| `entry_points[].tenants` | The tenants that may attach routers to the entry point. Absent: all. |

| Code | When |
|---|---|
| `unknown_entry_point` | A router or a policy names an entry point this node did not bind. A snapshot written for another node fails closed instead of exposing a router on the wrong port. |
| `no_reachable_entry_point` | A router lists no entry points and no `http` or `https` entry point of this node admits its tenant. |
| `entry_point_forbidden` | A router names an entry point whose `tenants` policy does not list its tenant. |
| `entry_point_protocol` | An HTTP router names a `tcp` or `udp` entry point. |
| `catch_all_not_allowed` | A router with no literal host (a bare `host_regexp`, or no host constraint) listens on an entry point that is not exclusive to its tenant. An entry point is exclusive when its `tenants` policy names that tenant alone; the operator can also list the tenant in `CATCH_ALL_TENANTS`. |

A router with no `entry_points` list skips the entry points that do not admit its tenant, and the `tcp` and `udp` ones. If that leaves no entry point, the snapshot is rejected with `no_reachable_entry_point` naming the router and its tenant: a deploy that serves nothing must not answer `200`. A list that names only entry points excluding the tenant is `entry_point_forbidden` for each of them.

## Explain

`GET /v1/explain?url=<url>&entry_point=<name>` evaluates the request as arriving on that entry point (`400` when the node did not bind it). Without `entry_point`, the entry points of the URL's scheme are tried in the order `ENTRY_POINTS` lists them. `200` carries `entry_point` (where it matched) and `reachable_on` (every `http` and `https` entry point the matched router listens on). `404` carries `routed_on` when other entry points would route the request.

## Compared with Traefik and Caddy

- Traefik's static `entryPoints.<name>.address` and a router's `entryPoints` list, with the same default of all entry points when a router lists none. Traefik silently never serves a router that names an entry point that does not exist; podgate rejects the snapshot.
- Caddy's site address and `bind`. Caddy listens where the Caddyfile says; podgate keeps the sockets in process configuration and the access rules in the snapshot.
- `entry_points[].tenants` has no Traefik or Caddy counterpart.
