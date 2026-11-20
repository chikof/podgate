# Forwarded headers to upstreams

An upstream behind podgate needs to know who the client was, which scheme and host it used and which port it reached. podgate writes the headers every migrating app already reads, built from the trust decision of [client IP](client-ip.md), so a client can never forge them. Code: `src/forwarded.rs`.

## What is written

Default set (an app with no `forwarded` object):

|Header|Value|
|---|---|
|`X-Forwarded-For`|A peer the entry point trusts: the chain it sent, then the peer's address. Any other peer: the peer's address alone.|
|`X-Forwarded-Proto`|`https` when the connection is TLS (HTTP/3 counts), else `http`. Taken from the connection's TLS state, never the request line, `:scheme` or an inbound header; only a trusted peer's own `X-Forwarded-Proto` overrides it.|
|`X-Forwarded-Host`|The `Host` header or `:authority` the client sent, lowercase, with its port when it had one. A trusted peer's value is kept (its last well-formed one).|
|`X-Forwarded-Port`|The port of the entry point the request arrived on. A trusted peer's `X-Forwarded-Port`, else the port in its `X-Forwarded-Host`, is kept.|
|`X-Real-IP`|The resolved client: the peer, or for a trusted peer the first address from the right of its chain that is not trusted.|

Opt-in:

|Header|Switch|Value|
|---|---|---|
|`Forwarded`|`rfc7239: true`|RFC 7239: one `for=` element per chain entry, the last one for the peer with `proto=` and `host="..."`. IPv6 is bracketed and quoted: `for="[2001:db8::1]"`.|
|`X-Forwarded-Server`|`server: true`|The node's name (`NODE_NAME`). Without `NODE_NAME` the header is left out. Off by default because it tells the app which host proxies it, a deliberate difference from Traefik.|

```json
{ "id": "shop", "forwarded": { "x_forwarded": true, "real_ip": true, "rfc7239": false, "server": false } }
```

All four fields are optional and shown with their defaults; `{}` is the default set. An unknown field is refused. `x_forwarded: false` stops the four `X-Forwarded-*` headers, `real_ip: false` stops `X-Real-IP`.

## Rules

- **Replace, never duplicate.** Every header podgate writes is set with replace semantics: whatever copies the request carried, several lines included, become one.
- **Untrusted peers cannot say anything.** Their `X-Forwarded-*`, `X-Real-IP` and `Forwarded` were removed before routing (client IP stage), so none of their values can reappear. A peer the entry point trusts is believed: its chain is extended, never replaced.
- **An opt-out stops podgate writing, not the trusted peer.** With `x_forwarded: false` a trusted proxy's own `X-Forwarded-*` headers pass through unchanged; an untrusted client's were already removed.
- **Only validated bytes.** Addresses are written from parsed values (IPv6 without brackets, IPv4-mapped as IPv4), hosts only when they are 1 to 255 letters, digits and `-._:[]`, so no CR, LF, NUL or any other byte a client chose reaches a value. A host that fails the check is not forwarded.
- **Bounded chains.** `X-Forwarded-For` and `Forwarded` are at most 1024 bytes; the oldest entries go first. `podgate_forwarded_chain_truncated_total` counts them.
- **No address, no header.** A connection with no IP peer (a unix socket) gets no `X-Forwarded-For`, `X-Real-IP` or `Forwarded`.
- **Upgrades too.** The headers are written on `Upgrade` requests.
- **Written before the middleware chain.** The stage `forwarded_headers` sits after `failure_capture` and before the chain, so a `headers` middleware can override or remove them explicitly and a `wasm` filter sees them. A request a middleware answers never reaches an upstream.
- **`Connection` cannot strip them.** A request whose `Connection` header names `X-Real-IP`, `X-Forwarded-Port`, `Forwarded` or `X-Forwarded-Server` (a header podgate writes for that app) is refused with `400`, as Pingora refuses the nominations of `Host`, `X-Forwarded-For`, `-Host` and `-Proto` it protects itself.
- **Other headers are not touched.** `X-Forwarded-Prefix` and `X-Forwarded-Tls-Client-Cert*` belong to their features.
- **Explain.** `GET /v1/explain` lists the stage `forwarded_headers` with the header names the matched app sends.

Cost: values are built in stack buffers and copied once into the request, so a request allocates its header values and what Pingora's case-preserving header map needs for the names; nothing is formatted on the heap (`forwarded_allocates_only_values`).

## What Traefik and Caddy send

Recorded on 2026-11-20 with the pinned binaries (Caddy v2.11.9, Traefik 3.7.16), default configuration, a loopback client and an echo upstream; the raw recording is `tests/fixtures/forwarded/recorded.json`, and `forwarded_matches_recorded_proxies` reads it.

|Proxy|Added to a plain request|Added to a TLS request|
|---|---|---|
|Traefik|`X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host: a.test:<port>`, `X-Forwarded-Port: <port>`, `X-Forwarded-Proto: http`, `X-Forwarded-Server: main`, `X-Real-Ip: 127.0.0.1`, `Accept-Encoding: gzip`|the same with `X-Forwarded-Proto: https`|
|Caddy|`Via: 1.1 Caddy`, `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host: a.test:<port>`, `X-Forwarded-Proto: http`, `Accept-Encoding: gzip`|the same with `https` (`Via: 2.0 Caddy` over HTTP/2)|

Both keep the port in `X-Forwarded-Host`, and so does podgate. Sent by a client from an untrusted address (`X-Forwarded-For: 1.2.3.4`, `X-Forwarded-Proto: https`, `X-Forwarded-Host: evil.test`, `X-Real-IP: 9.9.9.9`, `Forwarded: for=8.8.8.8`):

|Proxy|Result|
|---|---|
|Traefik|`X-Forwarded-For`, `-Proto`, `-Host` replaced by the connection's values; `X-Real-Ip` replaced; the forged `Forwarded: for=8.8.8.8` is passed on to the upstream.|
|Caddy|`X-Forwarded-For`, `-Proto`, `-Host` replaced; the forged `X-Real-Ip: 9.9.9.9` and `Forwarded: for=8.8.8.8` are passed on to the upstream.|

podgate removes all of them from an untrusted peer. Its default set is a superset of Caddy's and equals Traefik's minus `X-Forwarded-Server`. Neither proxy sends `Accept-Encoding` or `Via` because of forwarding; podgate adds neither.

## Operating

- Which peers are trusted: `entry_points[].forwarded_headers` ([client IP](client-ip.md)). Behind a load balancer, trust it there, or the app sees the balancer's address.
- Behind PROXY protocol the address in the PROXY header is the peer; the writer reads only the request's view.
- Migrating from Traefik: apps reading `X-Forwarded-Server` need `"forwarded": {"server": true}` and `NODE_NAME`.
