# HTTP/3 and QUIC

An HTTPS entry point with `;http3` also speaks HTTP/3 over QUIC on the same port number (UDP), and tells HTTP/1.1 and HTTP/2 clients about it with `Alt-Svc`. Matches Traefik's `entryPoints.<n>.http3 {advertisedPort}`; Caddy turns HTTP/3 on by default.

Pingora has no HTTP/3 server, so podgate runs the QUIC side as its own tokio service (`src/h3.rs`, `src/h3/`): a `quinn` endpoint that speaks HTTP/3 with the `h3` crate and hands every request to the entry point's normal pipeline. Routing, middlewares, rate limits, budgets, the access log and metrics are the pipeline's own, so HTTP/3 requests are judged exactly as the same request over HTTPS.

## Turning it on

```
ENTRY_POINTS=web=0.0.0.0:80/http,secure=0.0.0.0:443/https;http3
```

`;http3` is an option of an `https` entry point. `;http3=8443` advertises another port in `Alt-Svc`, for a UDP port that is mapped. It cannot be combined with `;proxy_protocol`: QUIC carries no PROXY header, so the client address would be the load balancer's. A `udp` entry point on the same address is `ENTRY_POINTS` error, the UDP port is taken.

Per app, in the snapshot:

|Setting|Meaning|
|---|---|
|`tls.http3`|`false` keeps the app off HTTP/3: no `Alt-Svc`, the QUIC handshake for its names is refused, a request that reaches it through another app's connection is `421`. Absent: on, unless the app has `client_ca_pem` or `client_auth`, `cipher_suites`, or an `alpn` without `h2`. `true` together with one of those is `422` `unsupported_setting`, so mutual TLS and suite policies are never silently dropped.|

Apps that share a host must agree on `http3` (`tls_policy_conflict`).

## Alt-Svc

`Alt-Svc: h3=":<port>"; ma=86400` is added to responses of apps that allow HTTP/3 on an HTTPS entry point with `;http3`. Never on a response over HTTP/3, on a plain HTTP entry point, or on an HTTPS entry point without the option. The response cache never stores the header (an upstream's own `Alt-Svc` is dropped from stored heads) and a hit gets the live entry point's, so a copy cached through one entry point never names another's port.

## TLS

The QUIC handshake serves the certificates of the live snapshot, with their OCSP staples, chosen by SNI. TLS 1.3 only, ALPN `h3` only, no client certificates, **0-RTT off** (a 0-RTT request can be replayed). A handshake is refused when the ClientHello has no server name, no app claims the name, an app that may serve the name does not allow HTTP/3, or no certificate covers it.

A host with no certificate yet is refused even when it belongs to an `on_demand` app. rustls asks for the certificate synchronously inside the handshake, so waiting for an issuance would stall the endpoint's connection state, and a QUIC client's address is not proven at that point, so a spoofed source could make podgate order certificates. The TCP listener waits and orders; a browser learns about HTTP/3 from `Alt-Svc` on a response the name already got over TCP, by which time the certificate exists.

Connection migration is off: the client address is fixed when the internal connection opens and is the source of every `ip_allow_list` and rate limit, so a connection that changes address must start over.

## The internal connection

For each QUIC connection the front opens, on its first request, one HTTP/2 cleartext connection to `h3-<entry>.sock` next to `ADMIN_SOCKET`, and sends each HTTP/3 request through it as an HTTP/2 stream into the same Pingora application the HTTPS entry point runs. Bodies and trailers stream both ways with flow control on each side, never buffered. A request without a body is sent with its headers alone. Reconnects once if the pipeline closed the connection.

The connection starts with a 32-byte credential (random per process) and a PROXY protocol v2 header: the client's address as the source and the server name of the QUIC handshake as the authority TLV. The pipeline reads the header only on this socket. The client address is then what `X-Forwarded-For`, `ip_allow_list`, rate limits, tracing and the access log see; the connection counts as TLS, so `X-Forwarded-Proto` is `https` and a `Host` that is not the SNI is `421`.

The socket is `0600`, owned by the user podgate runs as. A peer is closed before any HTTP is read unless its uid is that user's (`SO_PEERCRED`), it sent the credential (compared in constant time) and then a valid header with a server name, within three seconds. Pingora offers no per-connection slot for a non-TLS stream, so the server name travels in the digest's `organization` field under a cipher name no TLS handshake produces (`podgate-h3-link`).

## Limits

Set before a packet is read; nothing a peer sends changes them.

|Limit|Value|
|---|---|
|Connections|`H3_MAX_CONNECTIONS`, default 10000, handshakes included. Past it a new connection is turned away.|
|Handshakes in flight|`H3_MAX_HANDSHAKES`, default 256, each at most 10 seconds.|
|Retry token|`H3_RETRY`: `on_load` (default) demands it of unproven addresses when handshakes in flight reach half of the cap or connections reach 80%; `always`; `never`. An address nobody proved is never answered when a cap turns it away, so podgate cannot be used to reflect traffic.|
|Request streams|`H3_MAX_STREAMS`, default 100 per connection; 3 unidirectional streams (control and the two QPACK streams).|
|Windows|`H3_CONNECTION_WINDOW`, default 256 KiB, for receiving and for sending; each stream may receive half.|
|Idle|30 seconds, keep-alive off.|
|Datagrams, WebTransport, extended CONNECT, WebSockets|Off.|
|UDP receive buffer|`H3_UDP_RECV_BUFFER`, default 2 MiB; the kernel caps it at `net.core.rmem_max`, and podgate logs when it was capped. quinn reads a bounded number of datagrams per wakeup, and `ServerConfig::max_incoming` and the incoming buffer sizes (64 KiB each, 4 MiB in all) cap what an unaccepted connection can hold.|

### Memory

A connection can hold at most its receive window, its send window and the 64 KiB of the internal connection's flow control: with the defaults 2 × 262144 + 65535 = **589,823 bytes**. That is what the tenant is charged, from the handshake to the close, against its `max_buffer_bytes`, so 1,000 connections of one tenant are charged 589,823,000 bytes and `H3_MAX_CONNECTIONS` of them at most 5.9 GB. The tenant is the one that claims the server name; a tenant that cannot take another connection gets it closed with `H3_EXCESSIVE_LOAD` (0x107) after the handshake. A connection that only idles costs no file descriptor and no pipeline state, because the internal connection opens with its first request.

### QPACK and field sections

The `h3` crate decodes QPACK statelessly: podgate advertises a dynamic table capacity of 0 and no blocked streams, stricter than the 4096 bytes and 16 streams the spec allows. A header block that names a dynamic table entry is a connection error (`QPACK_DECOMPRESSION_FAILED`, 0x200). `SETTINGS_MAX_FIELD_SECTION_SIZE` is 64 KiB; a larger request header section gets `431` and the connection lives. A request stream that sends no complete header section in 10 seconds is dropped.

### Stream resets

More than 200 streams reset by the client in one second on one connection close it with `H3_EXCESSIVE_LOAD`: the HTTP/3 form of the rapid reset attack.

## Metrics

|Series|Meaning|
|---|---|
|`podgate_h3_connections`, `podgate_h3_handshakes`|Open now.|
|`podgate_h3_refused_total{reason}`|`connection_cap`, `handshake_cap`, `over_budget`, `no_tenant`.|
|`podgate_h3_handshake_refused_total{reason}`|`no_name`, `unknown_host`, `not_allowed`, `no_certificate`.|
|`podgate_h3_retries_total`|Retry tokens demanded.|
|`podgate_h3_closed_total{reason}`|`rapid_reset`, `over_budget`.|
|`podgate_h3_requests_total`|Requests sent into the pipeline.|

The tenant's charge shows in `podgate_tenant_buffer_bytes`.

## Not supported

Client certificates (an app with `client_ca_pem` is not advertised and its handshake is refused), WebSockets and CONNECT over HTTP/3 (`501`), 0-RTT, and QUIC with `;proxy_protocol`.
