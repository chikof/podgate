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

A tunnel has no lifetime limit and no idle limit by default, as in the two proxies podgate is
measured against. One WebSocket through each at its default configuration, upstream and client
both silent after the `101`, was still open after 250 s on Traefik 3.7.16 and on Caddy 2.11.9
(Traefik's `readTimeout` and `idleTimeout` end at the hijack; Caddy's `stream_timeout` is unset).
Before change 0098 podgate was the odd one out: an idle tunnel closed at the shorter of the
transport's `read_timeout_secs` (default `REQUEST_TIMEOUT_SECS`) and the entry point's
`timeouts.read_secs`. Now, after the `101`, only these end a tunnel that nobody closed, and each
is opt-in (`docs/ref/transport-extras.md`):

| Setting | Effect on a tunnel | Default | Test |
|---|---|---|---|
| Transport `tunnel_idle_timeout_secs` | No traffic in either direction for this long closes it. It replaces the transport's read timeout after the `101` | unlimited | `tunnel_idle_timeout_applies_after_upgrade`, `ws_idle_timeout_closes` |
| Transport `max_stream_lifetime_secs` | Closes it this long after the `101`, busy or not | unlimited | `tunnel_closed_at_max_lifetime` |
| Transport `stream_close_delay_secs` | Closes it this long after a snapshot removed its server | unlimited | `tunnel_closed_after_server_removed_delay` |
| Entry point `timeouts.read_secs` | A ceiling on the idle time: the wait for the client's next bytes closes the tunnel when it passes. An operator's value, so a transport cannot lengthen it | none for a tunnel (Pingora's 60 s default no longer applies) | `ws_entry_read_timeout_closes_idle_tunnel` |
| Transport `read_timeout_secs` | The wait for the response head, the `101` included. None after it | `REQUEST_TIMEOUT_SECS` (30) | `tunnel_idle_timeout_applies_after_upgrade` |
| Entry point `timeouts.idle_secs` | None: it is the HTTP keep-alive wait between requests | | `ws_idle_timeout_closes` |
| Entry point `timeouts.write_secs` | None unless a write stalls | | `ws_idle_timeout_closes` |
| Transport `idle_timeout_secs` | None: it is the idle time of pooled connections | | `ws_idle_timeout_closes` |

So by default a WebSocket with no traffic stays open (`tunnels_unbounded_by_default`: with
`REQUEST_TIMEOUT_SECS=1` an idle tunnel is open after 4 s). An app that wants quiet tunnels
reaped sets `tunnel_idle_timeout_secs` on its transport, or sends pings. Any traffic in either
direction restarts both clocks: one-way client traffic and one-way server push both keep a tunnel
alive (`ws_one_way_client_traffic_keeps_tunnel_alive`, `ws_server_push_keeps_tunnel_alive`),
because Pingora's duplex loop starts the read again after every event. An active tunnel outlives
the idle timeout any number of times (`ws_active_tunnel_survives_idle_timeout`).

A tunnel closed by a timeout is closed as a connection, with no close frame, and nothing is
written into it (`ws_idle_timeout_closes`). Pingora logs the close as `Fail to proxy ...` at
`ERROR`; the status was never sent, because the `101` is the final response. Each close is
counted in `podgate_tunnel_closed_total{reason}` (`closed`, `idle_timeout`, `max_lifetime`,
`server_removed`, `error`).

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
  the equivalent knob: a transport's `stream_close_delay_secs` closes a tunnel that long after
  its server left the table, and `max_stream_lifetime_secs` bounds any tunnel (both off by
  default, `docs/ref/transport-extras.md`).
- **Snapshot swap.** A request keeps the routing table it started with, so a tunnel survives
  any later snapshot: a swap, its revision going `draining`, its revision leaving the snapshot,
  even its app leaving (`ws_survives_snapshot_swap`). New upgrades use the new table. A
  transport that sets `stream_close_delay_secs` makes the swap that removes the tunnel's
  server start that delay.
- **Shutdown.** On SIGTERM `/readyz` turns `503` and the process keeps serving existing
  connections, tunnels included, until `REQUEST_TIMEOUT_SECS` has passed, then exits and every
  tunnel ends with the process (`ws_graceful_shutdown_grace`). Move new connections to another
  node before sending SIGTERM; a longer grace needs a larger `REQUEST_TIMEOUT_SECS`.

## Upstreams that answer at once

Pingora 0.9.1 closes a tunnel at random when the upstream's `101` arrives within microseconds of
the request head. The upstream half of its HTTP/1 proxy loop
(`pingora-proxy/src/proxy_h1.rs:266-268`) polls "read the response" and "next task from the
downstream" in one `select!`. The downstream queues an end-of-body task for the upgrade request
(a `GET` has no body) before that loop starts. If the loop took that task first, the `101` reopened
the request side. If it read the `101` first, the end-of-body task then arrived on an upgraded
request and ended it: the tunnel closed with the first client frames unread, and the proxy log read
`upstream closed true` right after `ok upgrade handshake`. A local echo server lost about 10% of
tunnels.

podgate carries the fix in a vendored `pingora-proxy` (`vendor/pingora-proxy`, wired with
`[patch.crates-io]`): only an `UpgradedBody` task or a closed pipe ends an upgraded connection, and
the plain end-of-body task queued before the `101` no longer does. The WebSocket tests' echo
upstream answers the upgrade immediately and is stressed 200 times without a lost tunnel. Spec
0114 holds the upstream issue text; drop the vendored copy once Pingora releases the fix.

The same vendored copy carries one more change: a `ProxyHttp::tunnel` hook, called
once for an upgrade request, that returns the upstream read timeout to use after the `101` and a
`Notify` that ends the tunnel. It is what lets a transport's `tunnel_idle_timeout_secs` replace
the read timeout after the `101` and lets the lifetime and close-delay timers end a tunnel from
outside the proxy loop. A `ProxyHttp` that does not implement it behaves as stock Pingora.

A third change: `ProxyHttp::response_body_before_trailers`, called once when an HTTP/2
upstream response ends in trailers, just before the trailer task. A filter that holds the body until
its end (the `buffering` middleware) returns it there, and it is written as body data ahead of the
trailers, which still go out as trailers (`docs/ref/mw-buffering.md`, `### Trailers`). A
`ProxyHttp` that does not implement it behaves as stock Pingora.
