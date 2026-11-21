# Transport extras: PROXY protocol and tunnel limits

Four more fields of a `servers_transport` (`docs/ref/transports.md`), all optional and off by
default. The code is `src/service/transport/extras.rs`; the tests are `tests/transport_extras.rs`.

```json
{
  "name": "legacy", "type": "servers_transport",
  "proxy_protocol": { "version": 2 },
  "tunnel_idle_timeout_secs": 300,
  "max_stream_lifetime_secs": 3600,
  "stream_close_delay_secs": 30
}
```

| Field | Meaning |
|---|---|
| `proxy_protocol` | `{"version": 1\|2}`. Every new connection to the transport's servers starts with a PROXY protocol header. Any other version, a missing one, or an unknown field is `invalid_transport`. The same object a TCP service takes. |
| `tunnel_idle_timeout_secs` | 1..=86400. A tunnel with no traffic in either direction this long is closed. Replaces the transport's read timeout after the `101`. Default: unlimited. |
| `max_stream_lifetime_secs` | 1..=86400. A tunnel is closed this long after the `101`, however busy. Default: unlimited. |
| `stream_close_delay_secs` | 1..=86400. A tunnel is closed this long after a snapshot left its server out of the table. Default: unlimited. |

Zero, more than a day, a negative or a fractional number is `invalid_transport`. Explain shows
the fields a transport sets next to its other settings.

## PROXY protocol to the upstream

An upstream behind its own PROXY-aware listener (HAProxy-style, an nginx `proxy_protocol`
listener) wants the client's address in a header it reads before the HTTP request. podgate
writes it with the encoder of the entry point's PROXY protocol (`Header::encode`, see
`docs/ref/proxy-protocol.md`).

- **What is written, and when.** Once per new upstream connection, as its first bytes: before the
  request line on `http://` and `h2c://` servers, and before the ClientHello on `https://`
  servers (the TLS session runs over the connection the header opened, as HAProxy's
  `send-proxy` does). A reused connection writes nothing: the header was already sent.
- **Which addresses.** The source is the client's address, `Session::client_addr`: the TCP peer,
  or the address a PROXY header on the entry point decoded. The destination is the entry point's
  address the client connected to. When one is IPv4 and the other IPv6 (an IPv4 client on a
  dual-stack listener), the IPv4 one is written as an IPv4-mapped IPv6 address. Without a client
  address the header is `LOCAL` (v1: `PROXY UNKNOWN`). No authority TLV is written.
- **How it is done.** Pingora 0.9.1 lets a peer carry its own dial (`PeerOptions::custom_l4`,
  `pingora-core/src/upstreams/peer.rs:557`; called for every new upstream connection at
  `connectors/l4.rs:120-121`). podgate's dial connects, sets `TCP_NODELAY`, writes the header and
  hands the stream back for TLS and HTTP to run on. The dial is bounded by the transport's
  `dial_timeout_secs` (default `REQUEST_TIMEOUT_SECS`), and the upstream address policy
  (`docs/ref/upstream-policy.md`) is applied to the address as for any request.
- **Pool.** A connection that carries a client's address belongs to that address: the pool key
  gains the client's address, ip and port (`pool::isolate`, `docs/ref/transports.md`
  `Connection pool`). A request of another client, or of the same client on another connection,
  never draws it, so no client's address is shown to another's request. The price is that such a
  transport does not pool across clients, one upstream connection per downstream connection at
  most. A connection that is bound to a client is dropped after 60 s idle (`PINNED_IDLE_TIMEOUT`,
  a transport's shorter `idle_timeout_secs` wins), because it is of no use once its client left.
- **Retries.** A retry (`retry` middleware) runs the connection step again for the same
  request, so each attempt writes the header of the client that made the request
  (`proxy_protocol_retry_sends_same_client`).
- **Probes and internal requests.** Health probes, the page fetch of the `errors` middleware,
  `forward_auth` calls and failure replay are not a client's request. They connect with a `LOCAL`
  header (v2 `LOCAL`, v1 `PROXY UNKNOWN`), the one HAProxy sends for its own checks, so a server
  that requires the header does not drop them (`proxy_protocol_probes_send_local`).
- **Mirrors.** A `mirroring` service whose mirror reaches servers through a transport with
  `proxy_protocol` is refused with `invalid_service`: a copy leaves after its request on its own
  connection and carries no session, so it could not show the right client
  (`proxy_protocol_mirror_refused`).

The header the upstream receives is the only place the client's address crosses; the usual
forwarding headers (`docs/ref/forwarded-headers.md`) are written as before.

## Tunnels

A tunnel is an upgraded connection: a WebSocket, or any `Upgrade` the upstream accepts with a
`101`. What ends one:

| What | Closes the tunnel | Test |
|---|---|---|
| a side hangs up | the other side, as a normal close (`closed`) | `ws_upstream_close_ends_tunnel` |
| `tunnel_idle_timeout_secs` | no traffic in either direction for that long (`idle_timeout`) | `tunnel_idle_timeout_applies_after_upgrade` |
| `max_stream_lifetime_secs` | that long after the `101` (`max_lifetime`) | `tunnel_closed_at_max_lifetime` |
| `stream_close_delay_secs` | that long after a snapshot removed its server (`server_removed`) | `tunnel_closed_after_server_removed_delay` |
| the entry point's `timeouts.read_secs` | the client side is quiet that long (`idle_timeout`) | `ws_entry_read_timeout_closes_idle_tunnel` |

Nothing else does: with none of the fields set a tunnel lives until a side hangs up
(`tunnels_unbounded_by_default`). That is what Traefik 3.7.16 and Caddy 2.11.9 do, measured: one
WebSocket through each at the default configuration, both ends silent after the `101`, was
still open when the 250 s run ended. Before change 0098 podgate closed an idle tunnel at the
shorter of the transport's `read_timeout_secs` and the entry point's `timeouts.read_secs`.

- **Idle.** After the `101` the upstream read timeout is `tunnel_idle_timeout_secs`, and the
  client read timeout is the shorter of that and the entry point's `timeouts.read_secs`, when the
  operator set one. The entry point's value stays a ceiling because it is operator policy and
  the transport is an app's: a tenant cannot lengthen what the operator bounded. Pingora's own
  60 s client default no longer applies to a tunnel. Traffic in either direction restarts both
  clocks. The transport's `read_timeout_secs` still bounds the wait for the `101`
  (`tunnel_idle_timeout_applies_after_upgrade`: a mute upstream answers `504` after 1 s while the
  tunnel idle timeout is 30 s).
- **Lifetime and close delay.** Each is a timer task started when the `101` arrives and stopped
  when the request ends. When it fires it ends the tunnel through the vendored
  `pingora-proxy`'s `ProxyHttp::tunnel` hook (`docs/ref/websocket.md`, `Upstreams that answer at
  once`): the upstream half of the proxy loop stops and the client's connection is closed, with
  no close frame (a generic upgrade has none). The close delay starts when a swap leaves the
  tunnel's server out of the table (its app, revision, or the server of the revision's services
  is gone; a revision that is only `draining` still has it). It is decided from the live table at
  each swap, so a server that comes back after the delay started does not rescue the tunnel.
  A transport's DNS name that stops resolving to the tunnel's address counts as the server
  leaving.
- **Drain.** A closed tunnel counts as any request that finished: its revision's in-flight count
  falls, and a `draining` revision emits `revision_drained` after the last tunnel
  closed (`drained_event_after_tunnel_close`). Its tenant slot and backend slot come back with
  it.
- **Metric.** `podgate_tunnel_closed_total{reason}` counts every tunnel that was open, by how it
  ended: `closed` (a side hung up), `idle_timeout`, `max_lifetime`, `server_removed`, `error`.
  A request that is refused or fails before the `101` is not a tunnel.

## Compared with Traefik and Caddy

- Caddy: `transport http { proxy_protocol v1|v2 }`, `stream_timeout`, `stream_close_delay`.
  podgate's `max_stream_lifetime_secs` is `stream_timeout` (the maximum lifetime of a tunnel, not
  an idle time) and `stream_close_delay_secs` is `stream_close_delay`. The idle timeout of a
  tunnel has no Caddy or Traefik equivalent.
- Traefik: no PROXY protocol towards an HTTP service (its `proxyProtocol` is for TCP services),
  no tunnel lifetime.
