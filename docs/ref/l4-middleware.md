# TCP middlewares and what a TCP service does towards its servers

Two middlewares run on a TCP connection before it reaches a server, and a TCP service can write a PROXY protocol header, speak TLS to its servers and give a late reply time to arrive. It matches Traefik's `tcp.middlewares` (`inFlightConn`, `ipAllowList`) and `proxyProtocol`, `terminationDelay` and servers with `tls` and `serversTransport` of `tcp.services`, and the `proxy` handler of Caddy's `layer4` with `proxy_protocol`. The router and service they belong to are in `docs/ref/l4-tcp.md`.

```json
{ "tcp": {
  "middlewares": [
    { "name": "office", "type": "ip_allow_list", "source_range": ["203.0.113.0/24", "2001:db8::/32"] },
    { "name": "cap", "type": "in_flight_conn", "amount": 20,
      "source": { "ip": { "ipv6_subnet_bits": 64 } }, "max_sources": 10000 } ],
  "routers":  [ { "name": "db", "entry_points": ["pg"], "service": "primary", "chain": ["office", "cap"] } ],
  "services": [ { "name": "primary", "type": "loadbalancer", "transport": "internal",
                  "proxy_protocol": { "version": 2 }, "termination_delay_ms": 100,
                  "servers": [ { "address": "10.0.0.5:5432", "tls": true } ] } ]
} }
```

## The chain

`App.tcp.middlewares` are `Declared` objects like the HTTP ones, with a `name` unique in the app and a `type` that is `in_flight_conn` or `ip_allow_list`. A router's `chain` lists the names to run, in order. The kinds of the HTTP chain are `invalid_middleware` here (there is no request to run them on), a name that is not declared is `unknown_middleware_ref`, a name listed twice in one chain is `duplicate_name`, and a middleware no router names does nothing. There is no `default_chain` and no nested `chain` middleware for TCP.

What a middleware sees is the address of the client, and nothing else: no bytes have been read for it, and there are no headers. It is the TCP peer, or the source of the PROXY protocol header when the entry point has `;proxy_protocol` (`docs/ref/proxy-protocol.md`), the one place a trusted peer may name the client. On a router with `tls` the ClientHello was read first to choose the router (`docs/ref/l4-tls.md`); the chain runs right after that and before the TLS handshake of a terminating router.

The chain of the router that took the connection runs before the tenant's `max_inflight` slot is taken, before its buffers are charged and before any server is dialled, so a refused connection costs the tenant nothing and no server ever sees it. A refusal closes the connection without a byte and counts `podgate_l4_refused_total{reason}`, and the slots the earlier middlewares of the chain took go back. A connection that passes holds its slots until it ends, whatever ends it: a close by either side, a reset, the idle timeout, the shutdown.

## `ip_allow_list`

`source_range` is 1 to 4,096 CIDR blocks or single addresses, IPv4 and IPv6, as in `docs/ref/mw-ip-allow-list.md`, and the same type holds them (`client_ip::set::CidrSet`). An IPv4-mapped IPv6 peer is compared as the IPv4 address. There is no `ip_strategy`: with no headers there is no chain of addresses to pick from. A peer outside the list is refused as `ip_not_allowed`. An empty list is `invalid_middleware`: a list that admits nobody is a mistake, so remove the router.

## `in_flight_conn`

`amount` (at least 1) is how many connections one source may hold open at once; the next one is refused as `in_flight_conn`. A source is a client address; `source: {"ip": {"ipv6_subnet_bits": n}}` counts an IPv6 client by its first `n` bits (1 to 128, default 64), as `in_flight_req` does. Any other `source` (`header`, `host`) is `invalid_middleware`: there is no HTTP.

The counts live in the table of `in_flight_req` (`src/middleware/limits.rs`, `docs/ref/mw-limits.md`), the same code with the same rules:

- `max_sources` (1 to 1,000,000, default 10,000) entries, in sets of eight, each behind its own mutex; the table never grows.
- It is allocated by the first connection that reaches the middleware, after its whole size was charged to the tenant's `max_buffer_bytes`. A snapshot whose tables, those of `rate_limit`, `in_flight_req` and `in_flight_conn` together, do not fit the tenant's `max_buffer_bytes` is refused with `invalid_middleware`. A first connection that finds the budget full right now is refused as `over_budget`, a capacity refusal, and the next one charges again.
- An entry with a connection open is never evicted. A source whose set is full counts in one shared overflow value, which limits more, never less; connections that used it are `podgate_limiter_overflow_total`.
- The counts survive a snapshot push that leaves the middleware's declaration alone, so a connection that started under the old table returns its slot to the counts the new one uses. A changed declaration starts empty.

Series, with `app`, `middleware` and `type="in_flight_conn"`: `podgate_limiter_rejected_total`, `podgate_limiter_overflow_total`, `podgate_limiter_table_bytes`. The refusals also show as `podgate_l4_refused_total{reason="ip_not_allowed"}` and `{reason="in_flight_conn"}`.

## Posture

A plan (`POST /v1/snapshot/plan`) lists a relaxation of the TCP routers of an app, once for the app, under the host `tcp:<app id>` (a TCP router has no host) with `app` the id:

| `kind` | When |
|---|---|
| `ip_allow_list_removed` | An `ip_allow_list` that some router of the live table runs is no longer run by any router. |
| `ip_allow_list_widened` | Its `source_range` covers addresses it did not. |
| `in_flight_conn_removed` | An `in_flight_conn` that some router runs is no longer run by any router. |
| `in_flight_conn_loosened` | A higher `amount`. |
| `in_flight_conn_source_changed` | Another `ipv6_subnet_bits`, which can let a client leave its count. |
| `upstream_tls_verification_disabled` | A TCP service that verified its `tls: true` servers' certificates now has a transport with `insecure_skip_verify`. |

Tightening is not listed. The middleware is matched by name in the candidate among the ones a router of it runs.

## `proxy_protocol`

`{"version": 1|2}` on a service writes a PROXY protocol header as the first bytes of every new connection to a server (any other version, a missing one or another field is `invalid_service`; the object is the one a `servers_transport` takes, `docs/ref/transport-extras.md`). The header names the client (its address and port, the PROXY protocol source when the entry point reads a header) and the entry point's socket as the destination. A client and an entry point of different families (an IPv4 client of a dual-stack listener) are both written as IPv6, the IPv4 one as an IPv4-mapped address. The codec is the one that reads a header at an entry point (`src/entry/proxy_protocol.rs`), so what podgate writes it reads back.

The header is written by the dial: after the TCP connect, before anything else. For a `tls: true` server it is before the TLS handshake, as HAProxy's `send-proxy` does with `ssl`, so the server reads the header in clear and then the handshake. For a passthrough router it is before the client's ClientHello, the first payload byte. A header that cannot be written, like any other failure of the dial, is a failed connect and the next server is tried; no client byte has been read yet.

## TLS to the servers

A server with `"tls": true` is reached over TLS. The transport is the service's `transport`, a `servers_transport` of the app (`docs/ref/transports.md`), or the default one when it names none:

- SNI and the name the certificate is checked for: the transport's `server_name`, else the DNS name the server was declared by. An IP literal sends no SNI and the certificate must carry the address as a SAN.
- Trust: the transport's `ca_pem` only, else the platform roots.
- A client certificate: its `client_cert`, presented to a server that asks.
- `insecure_skip_verify` skips both checks, and a plan lists it as `upstream_tls_verification_disabled`.
- `dial_timeout_secs` bounds the connect, the header and the handshake together; else `REQUEST_TIMEOUT_SECS`.

The handshake offers ALPN `http/1.1` only (raw TCP has no ALPN of its own, and the connector has no way to offer another). A handshake that fails is a failed connect, the next server is tried, and when none connects the client is closed as `no_server`. What a TCP service cannot use of a transport is refused, never ignored: `http2`, `read_timeout_secs`, `write_timeout_secs`, `idle_timeout_secs`, `proxy_protocol` and the tunnel limits are `invalid_transport` (the service's own `proxy_protocol` is the one header), and TLS fields with only plain servers are `invalid_service`. TLS options set on a transport that is also used by HTTP services keep their meaning there.

A TCP service's `health_check` keeps its own `tls` and `send_proxy_header` (`docs/ref/l4-health.md`).

## `termination_delay_ms`

0 to 86,400,000, default 100. After the client half-closes (its FIN), the server's direction has this long more to finish, and the connection is then closed; a server that finishes first ends it at once. A reply that was still on its way is not cut, and a server that never ends does not hold the connection until the idle timeout. A connection cut this way is `podgate_tcp_closed_total{reason="termination_delay"}`. `0` closes as soon as the client has. It applies only to the client's FIN: a server that closes first leaves the client's direction open until `idle_timeout_secs`, as in `docs/ref/l4-tcp.md`. Traefik's `terminationDelay` has the same default (100 ms).

## How it is wired

- `src/l4/middleware.rs`: `Stage` (`InFlightConn`, `IpAllowList`), `compile_all`, `admit` (runs a chain and returns the `Held` permits), `relaxations` for the plan, and `Registry`, which settles the counts at the swap site through the shared `middleware::state::Registry` (`settle_entries`). The tables and permits are `middleware::limits::{Limiter, SourceTable, Permit}`, which `in_flight_req` uses too.
- `src/l4/upstream.rs`: `Settings` (the checked `proxy_protocol` and `termination_delay_ms`) and `Settings::peer`, which builds the `HttpPeer` of a dial: `Upstream::base_peer` of the HTTP balancer (TLS, SNI, CA, client certificate), the dial timeout, and `service::extras::set_client_header` for the header.
- `src/l4/tcp/app.rs` runs the chain between routing and the tenant's slot, builds the peer per attempt, and passes the delay to `copy::relay`, which watches the client's FIN.
