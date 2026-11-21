# TCP routers and services

A `tcp` entry point forwards raw TCP connections to a load-balanced set of servers, chosen by a TCP router (a client address match, or a catch-all). Pingora has no L4 router, so podgate runs its own `ServerApp` on a `pingora-core` listening service (`src/l4/tcp/`).

Matches Traefik's `tcp.routers` and `tcp.services.loadBalancer.servers[].address` on a `:5432/tcp` entry point, and Caddy's `layer4` plugin. TLS on TCP routers (`HostSNI`, passthrough, termination) is in `docs/ref/l4-tls.md`; the router `chain`, the PROXY header towards the servers, TLS to the servers and `termination_delay_ms` are change 0061 (`docs/ref/l4-middleware.md`, `docs/ref/l4-middleware.md`).

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
| router `match` | Optional. A matcher tree of the TCP dialect: the leaves `client_ip` (the one of `docs/ref/match-request.md`), `sni`, `sni_regexp` and `alpn` (`docs/ref/l4-tls.md`), combined with `all`, `any`, `not`. An HTTP leaf is `invalid_matcher`. Absent: a catch-all. |
| router `tls` | `{"passthrough": true}` or `{}`: the router takes TLS connections and forwards them untouched or terminates them (`docs/ref/l4-tls.md`). Absent: the router does not look at TLS. |
| router `chain` | Names of the app's `tcp.middlewares` (`ip_allow_list`, `in_flight_conn`), run in this order before the connection is taken. An unknown name is `unknown_middleware_ref`, a name listed twice `duplicate_name`. `docs/ref/l4-middleware.md`. |
| service `type` | `loadbalancer` only. `weighted` and `failover` choose among the app's HTTP services by name and have no TCP form: `invalid_service`. |
| service `servers[].address` | `host:port`, 1 to 256 of them: an IP literal (`10.0.0.5:5432`, `[2001:db8::5]:5432`) or a DNS name (`db.internal:5432`). `weight` is optional and only `weighted_round_robin` and `hrw` take one. With `"resolve": "srv"` the address is a full SRV owner name without a port (`_db._tcp.shop.service.consul`), as in `docs/ref/dns-srv.md`: the records choose the targets, ports, priorities and weights, and a `weight` is `invalid_service`. |
| service `servers[].tls` | `true`: the server is reached over TLS, with the service's `transport` (the platform roots, and the DNS name of the address as SNI, when it names none). Default `false`. A transport that sets TLS fields with a plain server is `invalid_service`. |
| service `algorithm` | `round_robin` (default), `weighted_round_robin`, `least_conn`, `random` or `hrw` (the client address picks the server, and the same client keeps it). The others (`ip_hash`, `uri_hash`, `header_hash`, `p2c_ewma`) read an HTTP request or response; `ip_hash` also builds a ring: `invalid_service`. |
| service `idle_timeout_secs` | Seconds without a byte in either direction before the connection is closed. Default 300, 1 to 86,400. |
| service `proxy_protocol` | `{"version": 1\|2}`: every new connection to a server starts with a PROXY protocol header carrying the client's real address and the entry point's. The same object as the `proxy_protocol` of a `servers_transport`. Another version, a missing one or an unknown field is `invalid_service`. `docs/ref/l4-middleware.md`. |
| service `termination_delay_ms` | Milliseconds the server's side of a connection lives on after the client half-closed, so a late reply is not cut. 0 to 86,400,000, default 100. |
| service `transport` | The name of a `servers_transport` of the app that reaches the servers with `tls: true`: its `server_name`, `ca_pem`, `client_cert`, `insecure_skip_verify` and `dial_timeout_secs` apply. A transport that sets `http2`, `read_timeout_secs`, `write_timeout_secs`, `idle_timeout_secs`, `proxy_protocol` or a tunnel limit is `invalid_transport`: a TCP service cannot use them. `unknown_transport` for a name the app does not declare. |
| service `health_check` | Optional: probe each server (a connect, optionally a `send` and `expect` exchange, TLS, a PROXY header) and skip the ones that fail. `docs/ref/l4-health.md`. |

A TCP service is the HTTP load balancer over `http://host:port` and `https://host:port` servers (a `tls: true` server is the latter): the same code, balancing state that survives a snapshot push, and the same DNS handling. `health_check` probes the servers and skips the ones that fail (`docs/ref/l4-health.md`). There is no `passive` or `sticky` for TCP.

## Which router takes a connection

The client address is the TCP peer's, or the source of the PROXY protocol header when the entry point has `;proxy_protocol` (`docs/ref/proxy-protocol.md`: the header comes first on the wire and only a trusted peer may send one). A router with a `match` ranks above a catch-all, and among routers with a `match` the one with more constraints wins. The routers of one entry point, in any of the tenant's apps, that can match the same connection and have the same rank are `route_ambiguity` (with `apps`, `routers`, `declared_by`): two catch-all routers are one, and so are two `client_ip` matches that overlap with equal specificity. A connection no router takes is closed and counted `podgate_l4_refused_total{reason="no_route"}`. With TLS routers on the entry point the ranking also looks at the server name, and the connection's first bytes are read before it is routed: see `docs/ref/l4-tls.md`.

The entry point must be bound by the node (`unknown_entry_point`), be `tcp` (`entry_point_protocol`) and have a policy whose `tenants` lists only the router's tenant (`entry_point_forbidden`). That makes the entry point of a router without `tls` exclusive to one tenant, so a catch-all router needs no further allowance and `catch_all_not_allowed` cannot arise for it: a TCP listener has no host to tell tenants apart by. A router with `tls` and literal `sni` names does have one, and may share the entry point (`docs/ref/l4-tls.md`, who may claim a name).

## One connection

1. The router is chosen from the live table.
2. The router's `chain` runs on the client address, before the tenant's slot is taken and before any server is dialled (`docs/ref/l4-middleware.md`). A connection it refuses is closed without a byte and counted `ip_not_allowed` or `in_flight_conn`.
3. The tenant's `max_inflight` takes one slot and its `max_buffer_bytes` is charged 32 KiB (two 16 KiB copy buffers). A refused connection is closed at once and counted `over_inflight` or `over_budget`. The charge and the slot are returned when the connection ends.
4. Up to 3 servers are tried. The balancer picks one it has not tried yet and that is healthy, the upstream address policy (`docs/ref/upstream-policy.md`) checks its exact address, and that address is dialled with a timeout of `REQUEST_TIMEOUT_SECS` (the transport's `dial_timeout_secs` for a service that names one). With `proxy_protocol` the PROXY header is the first thing written to the new connection, then the TLS handshake of a `tls: true` server (`docs/ref/l4-middleware.md`). A failed connect (refused, unreachable, timed out, a header that could not be written, a failed handshake, or an address the policy refuses) moves on to the next server. When no server connects the client's connection is closed (`no_server` or `upstream_forbidden`). Once a connect succeeds there is no retry: bytes may already have gone to the server, and a protocol cannot take them twice.
5. The bytes are copied both ways with the two buffers and nothing else, so a 100 MiB transfer holds 32 KiB of podgate memory. When one side sends FIN, podgate shuts down the write half of the other and keeps copying the opposite direction, so half-close works in both directions. After the client's FIN the server's direction has `termination_delay_ms` (default 100) more, so a reply still on its way is not cut, and is then closed. The connection ends when both directions have finished, when a read or write fails, when that delay has passed, or when no byte has moved either way for `idle_timeout_secs`.

A name in `servers` is resolved off the connection path by the DNS resolver (`docs/ref/dns-resolver.md`): it expands into one server per address, each address passes the upstream policy when the answer arrives and again before each dial, and the connection dials the checked IP, never the name. The names count against the 64 per app and 256 per tenant of the HTTP services. An SRV server goes through the same expansion: the SRV port rules of the upstream policy (`srv_deny_ports`, `srv_allow_ports`) and the address policy apply to every target before it becomes a server, and the connection dials the checked address and the record's port.

A snapshot that removes a router or a service, moves it to another tenant, or changes its servers affects the next connection only. A connection already open keeps its server, its slot and its buffers, and finishes.

## Shutdown

On SIGTERM the entry point stops accepting. Connections already open go on for `REQUEST_TIMEOUT_SECS`, like requests in flight, and are closed then.

## Metrics

On `GET /metrics`, process-wide and labelled by fixed reasons only:

- `podgate_tcp_connections`: connections open now (the ones that reached a server).
- `podgate_tcp_connections_total`: connections accepted.
- `podgate_l4_refused_total{reason}`: closed before a server was dialled. Reasons: `no_route`, `over_inflight`, `over_budget`, `no_server`, `no_healthy_server` (the service's `health_check` has marked every server down), `upstream_forbidden`, for TLS routers `hello_timeout`, `hello_invalid`, `tls_handshake`, `tls_policy`, `client_cert` (`docs/ref/l4-tls.md`), and for the TCP middlewares of a router's `chain` `ip_not_allowed` and `in_flight_conn` (`docs/ref/l4-middleware.md`; `over_budget` also covers a table of `in_flight_conn` the tenant's buffer budget cannot take right now).
- `podgate_tcp_connect_failures_total`: failed connects, each one a try of the next server.
- `podgate_tcp_closed_total{reason}`: connections that reached a server and ended: `done`, `idle`, `error`, `shutdown`, and `termination_delay` (the client closed its side and the service's `termination_delay_ms` ran out).
- `podgate_tcp_bytes_total{direction}`: `in` from clients, `out` back to them.

The tenant's slot and buffers show in `podgate_tenant_inflight` and `podgate_tenant_buffer_bytes`. `GET /v1/overview` lists an app's TCP routers (with their `chain`), services (with `proxy_protocol` and `termination_delay_ms`) and middlewares under `tcp`. The tables of `in_flight_conn` middlewares show in the `podgate_limiter_*` series with `type="in_flight_conn"` (`docs/ref/l4-middleware.md`).

## How it is wired

- `pingora-core`'s `ServerApp::process_new(self: &Arc<Self>, stream: Stream, shutdown: &ShutdownWatch) -> Option<Stream>` is what a `listening::Service` calls for each accepted connection; returning `None` ends the connection. The service owns the accept loop, the socket options (`TCP_NODELAY`) and the shutdown broadcast; podgate adds the service with `add_tcp` for each `tcp` entry point.
- `TransportConnector::new_stream(&HttpPeer)` makes a new connection to a server and never reuses one, with `connection_timeout` and `total_connection_timeout` set on the peer. The peer is the HTTP load balancer's own (`Upstream::base_peer`): plain TCP, or TLS with the transport's name, CA and client certificate for a server with `tls: true`. A PROXY header is written by the peer's `custom_l4` dial (`service::extras::set_client_header`, the code of change 0098), so it is the first thing on the wire, before the TLS handshake and before the copy starts.
- `;proxy_protocol` wraps the application in the same `Fronted` the HTTP entry points use. It is generic over `ServerApp`: it reads the header from the accepted `Stream`, replaces the socket digest's peer address with the source, and calls the inner application once. The application returns `None`, so `Fronted`'s keep-alive loop never runs.
