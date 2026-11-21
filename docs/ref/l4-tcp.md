# TCP routers and services

A `tcp` entry point forwards raw TCP connections to a load-balanced set of servers, chosen by a TCP router (a client address match, or a catch-all). Pingora has no L4 router, so podgate runs its own `ServerApp` on a `pingora-core` listening service (`src/l4/tcp/`).

Matches Traefik's `tcp.routers` and `tcp.services.loadBalancer.servers[].address` on a `:5432/tcp` entry point, and Caddy's `layer4` plugin. Not here: TLS (`HostSNI`, passthrough, termination: change 0059), PROXY protocol towards the servers and `termination_delay_ms`, TCP middlewares.

## Configuration

The entry point is process configuration: `ENTRY_POINTS=pg=0.0.0.0:5432/tcp`. Its policy in the snapshot must reserve it to one tenant:

```json
{
  "entry_points": [{ "name": "pg", "tenants": ["acme"] }],
  "apps": [{
    "id": "db", "tenant": "acme", "declared_by": "…", "tls": { "mode": "acme" },
    "routers": [], "revisions": [],
    "tcp": {
      "routers":  [
        { "name": "office", "entry_points": ["pg"], "service": "replica",
          "match": { "client_ip": ["10.0.0.0/8"] } },
        { "name": "rest", "entry_points": ["pg"], "service": "primary" }
      ],
      "services": [
        { "name": "primary", "type": "loadbalancer", "idle_timeout_secs": 300,
          "servers": [{ "address": "10.0.1.5:5432" }] },
        { "name": "replica", "type": "loadbalancer", "algorithm": "least_conn",
          "servers": [{ "address": "10.0.1.6:5432" }, { "address": "db-replica.internal:5432" }] }
      ]
    }
  }]
}
```

| Field | Meaning |
|---|---|
| router `entry_points` | The `tcp` entry points it listens on; at least one. |
| router `service` | A TCP service of the same app. |
| router `match` | Optional. A matcher tree whose only leaf is `client_ip` (`all`, `any`, `not` combine them; the leaf is the one of `docs/ref/match-request.md`). Another leaf is `invalid_matcher`: matching the TLS server name or ALPN is change 0059. Absent: a catch-all. |
| router `tls`, `chain` | `l4_not_built` (changes 0059 and TCP middlewares). |
| service `type` | `loadbalancer` only. `weighted` and `failover` choose among the app's HTTP services by name and have no TCP form: `invalid_service`. |
| service `servers[].address` | `host:port`, 1 to 256 of them: an IP literal (`10.0.0.5:5432`, `[2001:db8::5]:5432`) or a DNS name (`db.internal:5432`). `weight` is optional and only `weighted_round_robin` and `hrw` take one. With `"resolve": "srv"` the address is a full SRV owner name without a port (`_db._tcp.shop.service.consul`), as in `docs/ref/dns-srv.md`: the records choose the targets, ports, priorities and weights, and a `weight` is `invalid_service`. A server `tls`, and the service fields `proxy_protocol` and `termination_delay_ms`, are `service_not_built`. |
| service `algorithm` | `round_robin` (default), `weighted_round_robin`, `least_conn`, `random` or `hrw` (the client address picks the server, and the same client keeps it). The others (`ip_hash`, `uri_hash`, `header_hash`, `p2c_ewma`) read an HTTP request or response; `ip_hash` also builds a ring: `invalid_service`. |
| service `idle_timeout_secs` | Seconds without a byte in either direction before the connection is closed. Default 300, 1 to 86,400. |

A TCP service is the HTTP load balancer over `http://host:port` servers: the same code, balancing state that survives a snapshot push, and the same DNS handling. There is no `health_check`, `passive`, `sticky` or `transport` for TCP.

## Which router takes a connection

The client address is the TCP peer's, or the source of the PROXY protocol header when the entry point has `;proxy_protocol` (`docs/ref/proxy-protocol.md`: the header comes first on the wire and only a trusted peer may send one). A router with a `match` ranks above a catch-all, and among routers with a `match` the one with more constraints wins. The routers of one entry point, in any of the tenant's apps, that can match the same connection and have the same rank are `route_ambiguity` (with `apps`, `routers`, `declared_by`): two catch-all routers are one, and so are two `client_ip` matches that overlap with equal specificity. A connection no router takes is closed and counted `podgate_l4_refused_total{reason="no_route"}`.

The entry point must be bound by the node (`unknown_entry_point`), be `tcp` (`entry_point_protocol`) and have a policy whose `tenants` lists only the router's tenant (`entry_point_forbidden`). That makes every TCP entry point exclusive to one tenant, so a catch-all router needs no further allowance and `catch_all_not_allowed` cannot arise. A TCP listener has no host to tell tenants apart by.

## One connection

1. The router is chosen from the live table.
2. The tenant's `max_inflight` takes one slot and its `max_buffer_bytes` is charged 32 KiB (two 16 KiB copy buffers). A refused connection is closed at once and counted `over_inflight` or `over_budget`. The charge and the slot are returned when the connection ends.
3. Up to 3 servers are tried. The balancer picks one it has not tried yet and that is healthy, the upstream address policy (`docs/ref/upstream-policy.md`) checks its exact address, and that address is dialled with a timeout of `REQUEST_TIMEOUT_SECS`. A failed connect (refused, unreachable, timed out, or an address the policy refuses) moves on to the next server. When no server connects the client's connection is closed (`no_server` or `upstream_forbidden`). Once a connect succeeds there is no retry: bytes may already have gone to the server, and a protocol cannot take them twice.
4. The bytes are copied both ways with the two buffers and nothing else, so a 100 MiB transfer holds 32 KiB of podgate memory. When one side sends FIN, podgate shuts down the write half of the other and keeps copying the opposite direction, so half-close works in both directions. The connection ends when both directions have finished, when a read or write fails, or when no byte has moved either way for `idle_timeout_secs`.

A name in `servers` is resolved off the connection path by the DNS resolver (`docs/ref/dns-resolver.md`): it expands into one server per address, each address passes the upstream policy when the answer arrives and again before each dial, and the connection dials the checked IP, never the name. The names count against the 64 per app and 256 per tenant of the HTTP services. An SRV server goes through the same expansion: the SRV port rules of the upstream policy (`srv_deny_ports`, `srv_allow_ports`) and the address policy apply to every target before it becomes a server, and the connection dials the checked address and the record's port.

A snapshot that removes a router or a service, moves it to another tenant, or changes its servers affects the next connection only. A connection already open keeps its server, its slot and its buffers, and finishes.

## Shutdown

On SIGTERM the entry point stops accepting. Connections already open go on for `REQUEST_TIMEOUT_SECS`, like requests in flight, and are closed then.

## Metrics

On `GET /metrics`, process-wide and labelled by fixed reasons only:

- `podgate_tcp_connections`: connections open now (the ones that reached a server).
- `podgate_tcp_connections_total`: connections accepted.
- `podgate_l4_refused_total{reason}`: closed before a server was dialled. Reasons: `no_route`, `over_inflight`, `over_budget`, `no_server`, `upstream_forbidden`.
- `podgate_tcp_connect_failures_total`: failed connects, each one a try of the next server.
- `podgate_tcp_closed_total{reason}`: connections that reached a server and ended: `done`, `idle`, `error`, `shutdown`.
- `podgate_tcp_bytes_total{direction}`: `in` from clients, `out` back to them.

The tenant's slot and buffers show in `podgate_tenant_inflight` and `podgate_tenant_buffer_bytes`. `GET /v1/overview` lists an app's TCP routers and services under `tcp`.

## How it is wired

- `pingora-core`'s `ServerApp::process_new(self: &Arc<Self>, stream: Stream, shutdown: &ShutdownWatch) -> Option<Stream>` is what a `listening::Service` calls for each accepted connection; returning `None` ends the connection. The service owns the accept loop, the socket options (`TCP_NODELAY`) and the shutdown broadcast; podgate adds the service with `add_tcp` for each `tcp` entry point.
- `TransportConnector::new_stream(&BasicPeer)` makes a new connection to a server and never reuses one, with `connection_timeout` and `total_connection_timeout` set on the peer. Nothing is written to the stream it returns, so the header of change 0061 goes there, before the copy starts.
- `;proxy_protocol` wraps the application in the same `Fronted` the HTTP entry points use. It is generic over `ServerApp`: it reads the header from the accepted `Stream`, replaces the socket digest's peer address with the source, and calls the inner application once. The application returns `None`, so `Fronted`'s keep-alive loop never runs.
