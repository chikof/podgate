# Client IP and forwarded headers

podgate decides who the client is once per request, in the stage that normalizes the path, and every feature that needs a client address reads that decision. Code: `src/client_ip.rs`, `src/router/matcher/client_ip.rs`.

## Entry point policy

```json
"entry_points": [{
  "name": "websecure",
  "forwarded_headers": { "trusted_ips": ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"], "insecure": false }
}]
```

|Field|Meaning|
|---|---|
|`trusted_ips`|Peers (CIDR blocks or single addresses, IPv4 and IPv6 mixed) whose forwarding headers are believed. Default: none.|
|`insecure`|`true` believes every peer. A posture change in a plan (`forwarded_headers_insecure`); so is a wider `trusted_ips` (`forwarded_trusted_ips_widened`). Default `false`.|

An entry point with no policy trusts nobody. Unknown fields and entries that are not an address or block are `422` `invalid_forwarded_headers`. Matches Traefik's `entryPoints.<n>.forwardedHeaders {trustedIPs, insecure}` and Caddy's `trusted_proxies`.

## What the request path believes

The peer is the connection's address (`Session::client_addr`; PROXY protocol, replaces it there). IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are rewritten to IPv4 everywhere an address is compared, so an IPv4 list cannot be bypassed by writing the address in IPv6.

- **Peer not trusted.** `X-Forwarded-*` (every header with that prefix), `X-Real-IP` and `Forwarded` are removed from the request. The view comes from the connection: the client is the peer, the scheme is `https` exactly when the connection is TLS (never the request line or an inbound header), the port is the local port, and the host is the request's own.
- **Peer trusted.** The headers are kept. The chain is `X-Forwarded-For`, else the `for` parameters of `Forwarded` (RFC 7239), else `X-Real-IP`; entries may carry a port or brackets. It is walked from the right, skipping trusted addresses; the first untrusted address is the client. When every entry is trusted the leftmost one is. Without any usable entry the client is the peer. `X-Forwarded-Proto` (`http` or `https`), `X-Forwarded-Host` and `X-Forwarded-Port` are read from their last well-formed value, the one the nearest trusted proxy wrote, and fall back to the connection.
- **Malformed entries** (not an address, a bad port, an obfuscated `Forwarded` node such as `_hidden` or `unknown`) are skipped. They never become the client and never panic. At most the rightmost 64 entries of a chain are kept.

The result is `Ctx.forwarded: ForwardedView`:

|Field|Meaning|
|---|---|
|`peer`|The connection's peer, normalized; `UNKNOWN` (`::`) when the connection has no IP peer.|
|`client_ip`|The resolved client. `known_client()` is `None` for `UNKNOWN`.|
|`proto`|`Proto::Http` or `Proto::Https`.|
|`host`|The host a trusted peer reported, lowercase without port; `None` means the request's own `Host`.|
|`port`|The port a trusted peer reported, else the local port.|
|`chain`|The addresses a trusted peer forwarded, leftmost first, without the peer. Empty for an untrusted peer.|
|`trusted`|Whether the peer was trusted.|
|`port_reported`|Whether `port` is the one a trusted peer reported in `X-Forwarded-Port`, not the local port. Readers use this, not the presence of the header: podgate writes `X-Forwarded-Port` itself before the middleware chain.|

Change 0097 writes the headers the upstream sees from this view.

## For other features

`ClientIp::resolve(&view, &IpStrategy { depth, excluded }) -> IpAddr` is the one function for `ip_allow_list`, `rate_limit` and the hash balancers. With the default strategy it returns `view.client_ip`. Otherwise it reads the chain from the right with `excluded` addresses removed (blocks or addresses), and `depth` picks the Nth address (`1` is the last; absent is the first). A peer that is not trusted has no chain and a chain that runs out gives the connection's peer, so a feature never gets an address a trusted proxy did not write. `IpStrategy` reads from JSON (`{"depth": 2, "excluded": ["10.0.0.0/8"]}`, unknown fields refused). Matches Traefik's `ipStrategy {depth, excludedIPs}`.

## The `client_ip` matcher

`{"client_ip": ["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]}` (one string or a list, never empty) matches when the resolved client is in any block. It is `invalid_matcher` for a bad entry.

- Traefik's `ClientIP` compares the peer; podgate's compares the resolved client. With an entry point that trusts nobody (the default) these are the same.
- An IPv4 block contains the IPv4-mapped form of its addresses; a block written as `::ffff:10.0.0.0/104` is the IPv4 block `10.0.0.0/8`. A native IPv6 block such as `::/0` does not contain IPv4 addresses.
- A request whose client is unknown (no IP peer) matches no `client_ip` leaf.
- Specificity: a `client_ip` leaf counts as one other constraint, like `method`, so a router with one beats one without. Two routers whose `client_ip` leaves have no overlapping block are provably disjoint and do not make each other ambiguous; overlapping blocks (one contains the other) do.
- `GET /v1/explain` takes `client_ip=<addr>`; without it no `client_ip` router matches.
