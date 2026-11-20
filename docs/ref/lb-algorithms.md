# Load balancing algorithms and server state

A `loadbalancer` service picks one server per request with the algorithm named in `algorithm` (default `round_robin`). Every algorithm skips servers that are unhealthy, ejected or already tried by this request, and finds no server when none is left (the request answers `503`; a service with no servers at all wakes a `scale_to_zero` app). A pick takes no lock and allocates nothing (`tests/lb_alloc.rs`).

```json
{ "name": "web", "type": "loadbalancer", "algorithm": "weighted_round_robin",
  "servers": [ { "url": "http://10.0.0.5:8080", "weight": 5 }, { "url": "http://10.0.0.6:8080" } ] }
```

## Algorithms

| `algorithm` | Picks | Weights | Traefik | Caddy |
|---|---|---|---|---|
| `round_robin` | The next server in declaration order | refused | none (it always weights) | `round_robin` |
| `weighted_round_robin` | Servers in proportion to `weight`, interleaved smoothly | used | the default strategy | `weighted_round_robin` |
| `least_conn` | The server with the fewest requests in flight | refused | `leasttime` family (by time) | `least_conn` |
| `p2c_ewma` | Of two random servers, the lower `ewma_latency * (active + 1)` | refused | none (`strategy: p2c` compares connections) | none (`random_choose` is two random servers by connections) |
| `random` | Any available server with equal probability | refused | none | `random` |

An algorithm that does not use weights refuses a server whose `weight` is not `1` with `invalid_service`, because ignoring a setting is how a configuration silently stops meaning what it says.

- **`weighted_round_robin`.** Smooth weighted round robin as in nginx: weights 5, 1 and 1 give `a a b a c a a`, never `a a a a a b c`. A server with weight `0` receives nothing (Traefik treats `0` as `1`). The weights divided by their greatest common divisor must add up to at most 4096, and at least one weight must be above `0`, or the service is `invalid_service`. While a server is down the turns that would have gone to it are skipped, so the others keep their proportions.
- **`least_conn`.** Up to 8 servers are all compared, from a rotating start so ties share the load. Above 8 two random servers are compared and the less loaded one wins (power of two choices), which keeps a pick cheap on a long list. A slow server holds requests longer, so it holds more of them and gets fewer new ones.
- **`p2c_ewma`.** Peak-EWMA, as in Finagle and Linkerd. The average is updated when a response header arrives for any status below `500`: it rises at once to a slower sample and falls toward faster ones with a time constant of 10 seconds. The score also decays with the time since the last sample, so a server that was slow and then got no traffic is tried again after a while. A server with no sample yet is scored like the other candidate, so load alone decides between them.
- **`random`.** Counts the available servers and takes the n-th of them for a random n, so the choice stays uniform when some are down.

## State that survives a push

`src/service/state.rs` holds what outlives a snapshot swap:

| Type | Per | Fields |
|---|---|---|
| `ServerState` | server | `healthy` (health checks), `ejected_until_ms` (outlier ejection, 0034), `active` (every `Lease`), `ewma_us` and `ewma_at_ms` (`p2c_ewma`). All atomics. |
| `ServiceState` | service | The turn counter (`turn()`), and `random()` built on it. Used by `round_robin`, `weighted_round_robin`, `least_conn` (tie rotation, random pair) and `random`. |
| `Lease` | request | Counts the request in `active` from the pick until dropped; `responded(status)` hands a latency to the algorithm. It owns an `Arc<ServerState>`, so it stays valid after a swap and after its server left the table. |

`service::Registry` is called by `TableHandle::swap`, next to the canary registry, just before a compiled table goes live (`settle(&mut table.apps)`). A server or service takes over the state of the previous table when both have the same key:

```text
(app, revision or none, service, server URL, fingerprint)
```

`revision` is none for a service the app declares for all its revisions. `fingerprint` (`state::fingerprint`) digests the service declaration without its `servers` list, so adding or removing a server keeps the state of the others, and changing the algorithm, a health check or any other field of the service starts all its servers fresh. Entries the new table lacks are dropped; requests that still hold one keep it through their `Lease`. Two servers with the same URL in one service share a state.

## For specs that build on it

- **Reading availability.** Use `Server::available()` (healthy and `ejected_until_ms` not in the future, in `state::now_ms()` terms, milliseconds since the process started and at least `1`) or `PickCx::allows(&server)`, which adds the exclusion. A balancer never reads health flags itself.
- **Writing health or ejection**. Store into `server.state.healthy` or `server.state.ejected_until_ms` of the servers of the live table (`Service::servers()`); the `Arc` is shared with every later table whose service declaration does not change. To keep health across a change of another field of the declaration, refine `state::fingerprint`; do not add a second registry.
- **New per-server state.** An atomic field on `ServerState` with its initial value in `Default`. Never replace the `Arc`.
- **A request's server.** `route::select` returns `(Selected, Lease)`; `Ctx.lease` keeps the lease until `logging`. Code that needs the server of a finished request (outlier detection) uses `Lease::server()`.
- **Retries**. `PickCx.excluded` is the list of addresses the request already went to; set it before `CompiledApp::pick`. `PickCx::new(request)` is a first attempt.
- **A new algorithm.** A file in `src/service/lb/` with `compile(servers)` and `pick(cx, servers, shared) -> Option<usize>`, one variant and one arm per `match` in `lb.rs`, and its name removed from `UNBUILT`. Take turns or random numbers from the `ServiceState`; never keep a counter in the algorithm. A latency hook is `Balancer::observe`.
- **A new service type with state.** One arm in the `match` of `Registry::settle`.
