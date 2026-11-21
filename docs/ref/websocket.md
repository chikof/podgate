# WebSockets

podgate proxies a WebSocket the way it proxies everything else: the request is routed, runs the
route's middleware chain and is admitted, and when the upstream answers `101 Switching
Protocols` the connection becomes a byte tunnel until either side closes it. Nothing here is
configured per route; this page records what a tunnel does under each setting, and the tests
that pin it (`tests/ws.rs`, with a raw frame client and an echo upstream in
`tests/common/ws.rs`; no WebSocket library). Traefik and Caddy proxy WebSockets transparently
too; the differences are in `docs/parity.md`.

## What a tunnel is

- **Upgrade.** An HTTP/1.1 request with `Connection: Upgrade` and `Upgrade: websocket` goes to
  the upstream with `Upgrade`, `Connection`, `Sec-WebSocket-Key`, `-Version`, `-Protocol`,
  `-Extensions` and `Origin` as the client sent them (`ws_echo_plain`). The `101` comes back
  with the upstream's `Sec-WebSocket-Accept`, subprotocol and headers. podgate does not check
  `Origin` and does not look at frames: both are the application's.
- **TLS.** The same over an `https` entry point (`ws_echo_tls`); the upstream gets
  `X-Forwarded-Proto: https`. A client that negotiates HTTP/1.1 is tunnelled, one that
  negotiates `h2` is not (see below).
- **Frames.** After the `101` podgate copies bytes in both directions and never parses them:
  masked and unmasked frames, fragments, ping and pong, and close frames reach the other side
  exactly as sent (`ws_ping_pong`, `ws_upstream_close_ends_tunnel`). A 1 MiB message and the same
  megabyte as 64 KiB fragments pass with the tenant's `max_buffer_bytes` at 1 KiB, so a tunnel
  is not buffered and is not charged to that budget (`ws_large_message`). A hang-up by either
  side ends the other side's connection.
- **Over HTTP/2.** Not supported, refused cleanly. RFC 8441 needs the server to send
  `SETTINGS_ENABLE_CONNECT_PROTOCOL`. Pingora 0.9.1 builds its HTTP/2 server from
  `default_h2_options` (`pingora-core/src/protocols/http/v2/server.rs:69-74`), which never calls
  `h2::server::Builder::enable_connect_protocol`, and `Policy::h2_options`
  (`src/entry/policy.rs`) starts from the same defaults. `h2` 0.4.20 then resets any stream with
  a `:protocol` pseudo-header with `PROTOCOL_ERROR` (`h2/src/proto/streams/recv.rs:244-250`):
  the stream, not the connection. Browsers see no setting and open the WebSocket on HTTP/1.1,
  which works. `ws_over_h2_supported_or_refused` pins this: no setting, an extended `CONNECT`
  reset with `PROTOCOL_ERROR`, the connection still serves requests, and the upstream saw no
  upgrade. WebSockets over HTTP/3 are out of scope (`docs/parity.md`).
- **Upstream HTTP/2.** An upgrade request to an `https://` server asks for HTTP/1.1 even when
  the transport offers `h2`, because Pingora's HTTP/2 client has no `Upgrade`
  (`src/proxy.rs`, `upstream_peer`; `an_upgrade_request_asks_a_tls_server_for_http1` in
  `tests/transport_h2.rs`).

## Idle behaviour

A tunnel has no lifetime limit and no timer of its own: an active tunnel is never closed by
podgate (change 0098 adds an opt-in `max_stream_lifetime_secs`). A tunnel with no traffic in
either direction is closed by the read timeouts of the two sockets it joins, whichever is
shorter:

| Setting | Effect on an idle tunnel | Default | Test |
|---|---|---|---|
| Transport `read_timeout_secs` | The wait for the upstream's next bytes. Closes the tunnel when it passes | `REQUEST_TIMEOUT_SECS` (30) | `ws_idle_timeout_closes` |
| Entry point `timeouts.read_secs` | The wait for the client's next bytes. Closes the tunnel when it passes | Pingora's 60 s | `ws_entry_read_timeout_closes_idle_tunnel` |
| Entry point `timeouts.idle_secs` | None: it is the HTTP keep-alive wait between requests | | `ws_idle_timeout_closes` (all three of these set to 1 s next to a 2 s read timeout; the tunnel lives 2 s) |
| Entry point `timeouts.write_secs` | None unless a write stalls | | `ws_idle_timeout_closes` |
| Transport `idle_timeout_secs` | None: it is the idle time of pooled connections | | `ws_idle_timeout_closes` |

So by default a WebSocket with no traffic for `REQUEST_TIMEOUT_SECS` (30 s) is closed. Apps that
stay quiet longer must send pings (a ping from either side counts, and its pong is traffic),
or the operator raises the transport's `read_timeout_secs` (and `read_secs` above 60 s). Any
traffic in either direction restarts both clocks: one-way client traffic and one-way server push
both keep a tunnel alive (`ws_one_way_client_traffic_keeps_tunnel_alive`,
`ws_server_push_keeps_tunnel_alive`), because Pingora's duplex loop starts the read again after
every event. An active tunnel outlives the timeout any number of times
(`ws_active_tunnel_survives_idle_timeout`).

A tunnel closed by a timeout is closed as a connection, with no close frame, and nothing is
written into it (`ws_idle_timeout_closes`). Pingora logs the close as `Fail to proxy ...
ReadTimedout ... status: 504` (upstream timeout) or `status: 400` (client timeout) at `ERROR`;
the status was never sent, because the `101` is the final response.

## Middlewares on an upgrade

The chain sees the upgrade request first and the `101` response last, like any request:

| Middleware | On an upgrade | Test |
|---|---|---|
| `basic_auth`, `forward_auth`, `jwt_auth` | A missing or wrong credential gets the middleware's own status (`401`, or the auth service's) and the upstream sees no connection. Never `101` | `ws_basic_auth_refuses_upgrade`, `ws_forward_auth_refuses_upgrade`, `ws_jwt_auth_refuses_upgrade` |
| `rate_limit` | The upgrade takes a token like any request | `ws_rate_limit_counts_upgrade` |
| `in_flight_req` | The upgrade takes a slot and holds it until the tunnel closes (also `in_flight_req_held_for_websocket_lifetime` in `tests/mw_limits.rs`) | `ws_in_flight_held_for_life` |
| `headers` | Response rules apply to the `101` | `ws_headers_on_101` |
| `strip_prefix` and the other rewrites | The upstream sees the rewritten path and query | `ws_path_rewrite` |
| `buffering` | Exempt in both directions (`docs/ref/mw-buffering.md`) | `ws_not_buffered_or_compressed` |
| `compress` | A `1xx` is never compressed, and the frames are not touched | `ws_not_buffered_or_compressed` |
| `retry` | A failed connect before the `101` moves to another server. After the `101` nothing is retried: a tunnel that breaks is not opened again | `ws_retry_not_after_101` |
| `cache` | An upgrade bypasses the cache (the `Upgrade` request header), even for a path with a fresh entry | `ws_upgrade_bypasses_cache` |
| `mirroring` | With `mirror_body` the upgrade is not mirrored (`podgate_mirror_dropped_total{reason="upgrade"}`). Without it the copy is a plain `Connection: close` request with no `Upgrade`, so the shadow cannot upgrade it; the `Sec-WebSocket-*` headers stay on the copy, and are meaningless without `Upgrade` | `ws_upgrade_not_mirrored` |

## Accounting, drain, swap, shutdown

- **Tenant and revision.** An open tunnel is one request of the tenant's `max_inflight` and one
  in-flight request of its revision for as long as it is open: at `max_inflight: 1` a second
  request gets `503` with `retry-after: 1`, and the slot comes back when the tunnel closes
  (`ws_counts_against_tenant_inflight`). The backend's concurrency slot is released at the
  `101` (`src/fairq.rs`, `Slot::responded`), because a tunnel's length says nothing about the
  backend's latency.
- **Drain.** A revision with a tunnel open stays `draining`: its `revision_drained` event (spec
  0004) is not sent until the last tunnel closes, new requests leave it at once, and the tunnel
  keeps working meanwhile (`ws_delays_revision_drained`). podgate never ends a tunnel to finish
  a drain. A control plane that wants a hard stop sets its own deadline and retires the
  container, which closes the tunnel from the upstream side. Caddy's `stream_close_delay` is
  the equivalent knob; it is deferred to change 0098 as an opt-in.
- **Snapshot swap.** A request keeps the routing table it started with, so a tunnel survives
  any later snapshot: a swap, its revision going `draining`, its revision leaving the snapshot,
  even its app leaving (`ws_survives_snapshot_swap`). New upgrades use the new table.
- **Shutdown.** On SIGTERM `/readyz` turns `503` and the process keeps serving existing
  connections, tunnels included, until `REQUEST_TIMEOUT_SECS` has passed, then exits and every
  tunnel ends with the process (`ws_graceful_shutdown_grace`). Move new connections to another
  node before sending SIGTERM; a longer grace needs a larger `REQUEST_TIMEOUT_SECS`, which also
  lengthens the default idle timeout above.

## Known limitation: an upstream that answers at once

Pingora 0.9.1 can close a tunnel whose `101` arrives within microseconds of the request head.
The upstream half of its HTTP/1 proxy loop (`pingora-proxy/src/proxy_h1.rs:268` and `326-333`)
polls "read the response" and "next task from the downstream" in one `select!`. The downstream
queues an end-of-body task for the upgrade request (a `GET` has no body) right after the head
was sent. Normally the loop takes that task first and, on the `101`, reopens the request side
(`request_done = false`). If it reads the `101` first, the end-of-body task arrives on an
upgraded request and ends it (`if request_done && was_upgraded { response_done = true }`): the
tunnel is closed, with the first client frames unread. It showed as about 12% of runs of
`ws_basic_auth_refuses_upgrade` against an echo that answered in under 100 microseconds, and
the proxy log reads `upstream closed true` right after `ok upgrade handshake`.

A real application takes far longer than the proxy's next poll to accept a WebSocket, so the
tests' echo upstream waits 50 ms before it writes the `101` (`UPGRADE_LATENCY` in
`tests/common/ws.rs`) and measures podgate, not that race. podgate has no hook that can order
those two events: the end-of-body task is queued by Pingora before any `ProxyHttp` callback that
sees it can delay it, and the response is read by the loop itself. The fix is in Pingora; until
then a tunnel to an upstream that upgrades instantly (a local test server) may be dropped at
the start, and the client reconnects.
