# PROXY protocol

An entry point behind a load balancer reads the real client address from a PROXY protocol header (HAProxy's v1 text line and v2 binary header). The same codec writes a header towards a TCP upstream. Design: `docs/architecture.md ### Entry points`.

## Turning it on

Two things, owned by two people:

| Where | What | Owner |
|---|---|---|
| `ENTRY_POINTS`, `name=address/http;proxy_protocol` or `/https;proxy_protocol` | The entry point reads a header on every connection. | The operator, at process start. |
| Snapshot `entry_points[].proxy_protocol` | Which peers may send it: `{"trusted_ips": ["10.0.0.0/8", "2001:db8::1"], "insecure": false}`, both fields optional. | The control plane, never an app or tenant. |

```json
{"entry_points": [{"name": "edge", "proxy_protocol": {"trusted_ips": ["10.0.0.0/8"]}}]}
```

## What a connection must do

With `;proxy_protocol` every connection starts with a header from a trusted peer. There is no fallback to serving without one, because a fallback lets a client that can reach the port directly choose its own address. These close the connection with nothing written back:

- the peer's own (TCP) address is not in `trusted_ips` and `insecure` is off, or the snapshot has no `proxy_protocol` policy for the entry point (it then trusts nobody, so a node that has not received its snapshot yet serves nothing on that port);
- no header, garbage, a TLS ClientHello or an HTTP request line where the header should be (rejected at the first wrong byte);
- a header over its limit, truncated, or invalid (below);
- no complete header within 3 seconds.

Pingora logs a closed connection as `Downstream handshake error` for TLS entry points; podgate adds a `debug` event with the entry point, the peer and the reason.

## What is accepted

| Header | Accepted | Refused |
|---|---|---|
| v1 | `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`, `PROXY TCP6 ...`, `PROXY UNKNOWN[ ...]\r\n`, at most 107 bytes. | a line end other than CRLF, a repeated space, a trailing field, an address of the other family, a port with a sign, a leading zero, or over 65535, any other protocol word. |
| v2 | The 12-byte signature, version 2, command `PROXY` or `LOCAL`, family `INET` or `INET6` over `STREAM`, or `UNSPEC`, or `UNIX` over `STREAM`; at most 2048 bytes in all. | another version or command, a datagram transport, a family with no matching transport, an address block shorter than its family needs, a TLV that runs past the payload. |

- `LOCAL` (a health check by the balancer itself), `PROXY UNKNOWN` and a v2 `PROXY` with an unspecified or unix family are accepted and keep the peer's own address.
- TLVs are walked for their bounds and dropped, except the authority TLV (`PP2_TYPE_AUTHORITY`, the server name the client asked for): it is kept, up to 255 bytes of UTF-8, one per header, and read with `Header::authority()`. A second authority or an invalid one is refused. No cloud link metadata (AWS, Azure) is kept.
- The header is read byte-exactly: the TLS or HTTP bytes behind it are never consumed by the reader, and a header split across TCP reads is decoded the same.

## What the address does

The decoded source replaces the peer address of the connection (`Session::client_addr`), so everything that asks who the client is sees it:

- `ip_allow_list`, rate limits and the `client_ip` matcher, through the request's `ForwardedView`;
- the forwarding headers an upstream receives (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`): the PROXY address is the peer they write and extend;
- the access log.

**Forwarded-header trust is judged on the PROXY address.** The entry point's `forwarded_headers.trusted_ips` is tested against the address the header carries, not against the balancer's address. A client behind the balancer that forges `X-Forwarded-For` is therefore not believed unless its own address is in that list. `proxy_protocol.trusted_ips` (who may send a header) is tested against the TCP peer, before the header is read.

## Plans

`proxy_protocol.insecure: true` trusts every peer, so any client that can reach the port chooses its own address. It is reported in `posture_changes` as `proxy_protocol_insecure`, and a `trusted_ips` that covers more addresses than the live one as `proxy_protocol_trusted_ips_widened` (host `entry_point:<name>`). Removing the policy or narrowing the list is not a relaxation.

| Code | When |
|---|---|
| `invalid_proxy_protocol` | The policy has an unknown field or an entry that is not an address or CIDR block. |
| `unsupported_setting` | The entry point has a `proxy_protocol` policy but no `;proxy_protocol` in `ENTRY_POINTS`: the header would be served as an HTTP request. |

## With TLS

On a TLS entry point the header comes first on the wire, before the ClientHello. Pingora has a pre-TLS hook only for TLS listeners (`pingora-core` `listeners/mod.rs`, `UninitializedStream::handshake`), so there one hook runs the PROXY check and then the existing ClientHello reader (TLS policy refusals, on-demand certificate waits, TLS-ALPN-01 answers) on the same stream. A plaintext entry point has no hook: its service wraps the proxy application, reads the header before the first request and runs the keep-alive loop itself, so the header is read once per connection.

## Library use

`podgate::entry::proxy_protocol`:

- `parse(&[u8]) -> Result<Parse, DecodeError>`: the decoder, no I/O. `Parse::Header(header, used)` or `Parse::More(n)` (needs at least `n` bytes in total).
- `read_header(&mut impl AsyncRead + Unpin, Duration)`: reads exactly one header within the deadline (`READ_TIMEOUT`, 3 s, in the listener).
- `Header::encode(&self, Version, &mut Vec<u8>)`: writes v1 or v2; v1 cannot carry an authority. `Header::Local` is `PROXY UNKNOWN` in v1 and `LOCAL` in v2.
- `Addresses::new(source, destination)`: one family for both, or `None`.

## Compared with Traefik and Caddy

- Traefik: `entryPoints.<n>.proxyProtocol {trustedIPs, insecure}`. Same fields. podgate never serves a connection that has no header from a trusted peer.
- Caddy: the `proxy_protocol` listener wrapper with `timeout`, `allow` and `fallback_policy`. podgate has the timeout (fixed at 3 s) and the allow list; it has no fallback policy, by design.
