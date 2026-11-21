# UDP routers and services

A `udp` entry point forwards datagrams to a load-balanced set of UDP servers, one session per client address. Pingora has no UDP support, so podgate runs one tokio socket loop per `udp` entry point as a Pingora background service (`src/l4/udp/`).

Matches Traefik's `udp.routers` and `udp.services.loadBalancer.servers[].address` on a `:53/udp` entry point, and Caddy's `listen udp/` (`layer4` plugin).

## Configuration

The entry point is process configuration: `ENTRY_POINTS=dns=0.0.0.0:53/udp`. A `udp` entry point cannot take `;proxy_protocol` (the process refuses to start: PROXY protocol is for stream connections). Its policy in the snapshot must reserve it to one tenant:

```json
{
  "entry_points": [{ "name": "dns", "tenants": ["acme"] }],
  "apps": [{
    "id": "resolver", "tenant": "acme", "declared_by": "…", "tls": { "mode": "acme" },
    "routers": [], "revisions": [],
    "udp": {
      "routers":  [{ "name": "dns", "entry_points": ["dns"], "service": "resolvers",
                     "max_sessions": 4096, "max_reply_ratio": 3 }],
      "services": [{ "name": "resolvers", "type": "loadbalancer", "session_timeout_secs": 30,
                     "servers": [{ "address": "10.0.0.5:53" }, { "address": "10.0.0.6:53" }] }]
    }
  }]
}
```

| Field | Meaning |
|---|---|
| router `entry_points` | The `udp` entry points it listens on; at least one. |
| router `service` | A UDP service of the same app. |
| router `max_sessions` | Sessions held per entry point. Default 4096, 1 to 65,536. |
| router `max_reply_ratio` | Optional. See [Reflection](#reflection-and-spoofed-sources). 1 to 1000. |
| service `type` | `loadbalancer` only. |
| service `servers[].address` | `ip:port` of an IP literal, 1 to 256 of them. A host name is `invalid_service`: the resolver is not wired for UDP yet. |
| service `session_timeout_secs` | Idle time before a session expires. Default 30, 1 to 3600. |

A UDP router has no match criteria, so an entry point carries one router: a second router on it, in the same app or another, is `route_ambiguity` (with `entry_point`, `apps`, `routers`, `declared_by`). The entry point must be bound by the node (`unknown_entry_point`), be `udp` (`entry_point_protocol`) and have a policy whose `tenants` lists only the router's tenant (`entry_point_forbidden`). A server the upstream address policy forbids is `upstream_forbidden`, and the policy is checked again with the exact address before each session connects. TCP routers are in `docs/ref/l4-tcp.md`.

## Sessions

The first datagram of a client address opens a session: the next server in turn (round robin), a connected upstream socket from an ephemeral port, and a relay task that sends each datagram the upstream returns back to the client from the entry point's socket. The client keeps its server until the session has been idle (no datagram either way) for `session_timeout_secs`; a later datagram opens a new session, which may pick another server. A snapshot that removes a session's server, router, or moves its app to another tenant closes the session at once (`server_removed`, `router_removed`); the client's next datagram opens a new one.

Nothing is queued. A datagram that cannot be forwarded now is dropped and counted.

## Bounds

| What | Bound |
|---|---|
| Datagram size | 4096 bytes, either direction. A larger datagram is dropped (`oversize`), never cut. |
| Sessions per router per entry point | `max_sessions`. |
| Sessions per tenant | 8192 across its UDP entry points (`TENANT_MAX_SESSIONS`). |
| Sessions per node | 32,768 (`NODE_MAX_SESSIONS`). Each session holds one file descriptor, so the process's descriptor limit must stay above this plus the proxy listeners. |
| Buffer budget | Each session charges a fixed 4 KiB to the tenant's `max_buffer_bytes` before its socket opens, and gives it back when the session ends. |
| `max_inflight` | Not used. UDP sessions take no slot, so a flood on a UDP entry point cannot make the same tenant's HTTP requests answer `503`. |

When a bound is reached for a new client (the router's `max_sessions`, a cap or the buffer budget), podgate gives up the least recently used session whose client has sent only one datagram, once, and retries. That session may have been answered: an upstream reply proves nothing about a client address. A session whose client has sent two or more datagrams is never given up for a newcomer. When no one-datagram session exists, the new client's datagram is dropped.

## Reflection and spoofed sources

UDP sources are not authenticated: anyone can send a datagram that claims to come from someone else.

- **Session exhaustion.** A flood from spoofed addresses opens one-datagram sessions, whether or not the upstream answers them (DNS answers every source). They are the only sessions a newcomer may evict, so spoofed sources cannot push out clients that keep sending, and a real new client still gets a session. They can fill the one-datagram part of the table, each costing a socket until it is evicted or expires. The limit: an attacker who sends two datagrams from each spoofed address makes those sessions unevictable until they expire, at twice the packet rate. Keep `session_timeout_secs` and `max_sessions` small for a service that answers anyone, and filter spoofed sources at the network edge.
- **Datagram amplification.** podgate sends a datagram to a client only as the relay of that client's session, one for each datagram the upstream sent on that session's socket. It has no path to send to an address the upstream did not answer for.
- **Byte amplification.** A 40 byte query can draw a 4 KiB answer, and the answer goes to whoever the source address says. `max_reply_ratio` limits it: until a client has sent a second datagram, at most that multiple of its first datagram's bytes is returned (`reply_ratio` drops count the excess). It is off by default, because single-datagram protocols such as DNS never send a second datagram and a default cap would break them. **For a protocol that sends a second datagram early (QUIC's handshake and similar), set `max_reply_ratio` to 3.** For DNS and other query/response protocols, filtering spoofed sources belongs at the network edge (reverse path filtering, rate limits per source on the upstream), and a session timeout of a few seconds shortens the time a spoofed session lives.

Datagrams from a source address of `0.0.0.0`, multicast or port 0 are dropped (`bad_source`).

## Metrics

On `GET /metrics`, process-wide and labelled by fixed reasons only:

- `podgate_udp_sessions`: sessions open now.
- `podgate_udp_dropped_total{reason}`: dropped datagrams. Reasons: `no_route`, `table_full`, `tenant_limit`, `node_limit`, `over_budget`, `upstream_forbidden`, `oversize`, `reply_ratio`, `bad_source`, `socket_error`, `send_error`.
- `podgate_udp_sessions_closed_total{reason}`: `expired`, `evicted`, `server_removed`, `router_removed`, `shutdown`.
- `podgate_udp_datagrams_total{direction}` and `podgate_udp_bytes_total{direction}`: `in` from clients, `out` back to them.

The tenant's buffer charge shows in `podgate_tenant_buffer_bytes`. `GET /v1/overview` lists an app's UDP routers and services under `udp`.

## Shutdown

The socket loop ends on Pingora's shutdown signal. Every session is closed, its relay stopped and its reservations released. UDP has no in-flight request to finish, so it does not wait out the grace period.
