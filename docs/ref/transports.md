# Upstream transports (TLS, HTTP/2, timeouts)

A `loadbalancer` service reaches its servers through a transport: a `servers_transport`
object in `App.transports`, named by the service's `transport` field. It sets the TLS details of
an `https://` server, whether HTTP/2 is offered, the timeouts and the idle time of pooled
connections. The code is `src/service/transport.rs`.

```json
{
  "transports": [{
    "name": "internal", "type": "servers_transport",
    "server_name": "backend.internal",
    "ca_pem": "-----BEGIN CERTIFICATE-----...",
    "client_cert": { "cert_pem": "-----BEGIN CERTIFICATE-----...", "key_pem": "-----BEGIN PRIVATE KEY-----..." },
    "insecure_skip_verify": false,
    "min_tls_version": "1.2",
    "http2": true,
    "dial_timeout_secs": 5,
    "read_timeout_secs": 30,
    "write_timeout_secs": 30,
    "idle_timeout_secs": 90
  }],
  "revisions": [{ "id": "r1", "state": "serving", "weight": 100, "services": [{
    "name": "web", "type": "loadbalancer", "transport": "internal",
    "servers": [{ "url": "https://10.0.0.5:8443" }]
  }]}]
}
```

## Fields

All fields are optional. Unknown fields are refused (`invalid_transport`), so a misspelt option is
never ignored.

| Field | Meaning |
|---|---|
| `server_name` | The name sent as SNI and the name the certificate must carry. Must be a valid DNS name or IP address. |
| `ca_pem` | PEM bundle of the only trust anchors. It replaces the platform roots; it never adds to them. |
| `client_cert` | `{cert_pem, key_pem}`: the chain (leaf first) and key presented to a server that asks. PKCS#8, PKCS#1 or SEC1 keys. |
| `insecure_skip_verify` | `true` connects without checking the certificate or its name. |
| `min_tls_version` | `"1.2"` only. See below. |
| `http2` | Default `true`. An `https://` server is offered `h2` and `http/1.1` by ALPN and gets whatever it picks; `false` offers only `http/1.1`. See below. |
| `dial_timeout_secs` | TCP connect and TLS handshake together, 1..=3600. Default `REQUEST_TIMEOUT_SECS`. A timeout answers `504`. |
| `read_timeout_secs` | The wait for the response head, then for each read of the body, 1..=3600. Default `REQUEST_TIMEOUT_SECS`. A timeout before a response started answers `504`. |
| `write_timeout_secs` | Each write of the request to the server, 1..=3600. Default `REQUEST_TIMEOUT_SECS`. |
| `idle_timeout_secs` | How long an unused pooled connection is kept open, 1..=3600. Default: until the server closes it or the pool evicts it. |
| `max_idle_per_host` | Refused with `unsupported_setting`, whatever the value. See `Connection pool`. |

## Defaults

- A server named `https://` with no `transport`, or a transport with no `server_name`, uses the
  URL host. For a host name (`https://app.internal:8443`, see `docs/ref/dns-resolver.md`) the name
  is the SNI and the name the certificate is verified against, while the connection goes to the
  address the name resolved to. For an IP literal **no SNI is sent**, and the certificate must
  carry the IP as a SAN. Verification is on: it is never skipped for lack of a name.
- With neither `ca_pem` nor `insecure_skip_verify`, the server certificate is verified against the
  platform roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` count, as in Pingora).
- `http://` and `h2c://` servers ignore transports with no TLS fields. A transport that sets any
  TLS field and is named by a service with an `http://` server is refused (`invalid_service`), and
  with an `h2c://` server `invalid_transport`: a setting is never silently unused. `http2: false`
  with an `h2c://` server is `invalid_transport` too, since `h2c://` is HTTP/2 only. One address
  cannot be a server of the same service under two schemes.
- A server with no transport behaves as a transport with none of the fields set.

## `insecure_skip_verify`

Traefik and Caddy allow it, so podgate does. It cannot slip into a snapshot unnoticed: when a
candidate makes a service on an existing host connect to an `https://` server without
verification, `POST /v1/snapshot/plan` lists `{"kind": "upstream_tls_verification_disabled"}`
under `posture_changes`, and explain shows `"insecure_skip_verify": true` for the server. Setting
it together with `ca_pem` is refused: the CA would have no effect.

## `min_tls_version`

Pingora's rustls connector offers TLS 1.2 and 1.3 and has no knob for the minimum version.
`"1.2"` therefore describes what always happens and is accepted. `"1.3"` would be silently
weaker than written, so it is refused with `unsupported_setting`. Any other value is
`invalid_transport`.

## HTTP/2

| Server | What podgate speaks |
|---|---|
| `http://ip:port` | HTTP/1.1, always. A plain server is never sent the HTTP/2 preface, whatever the transport says. |
| `https://ip:port` | ALPN offers `h2` and `http/1.1` (`http2: false`: `http/1.1` only) and podgate speaks what the server selects. A server that selects nothing gets HTTP/1.1. |
| `h2c://ip:port` | Cleartext HTTP/2 by prior knowledge (the connection starts with the HTTP/2 preface, no `Upgrade`). Only this scheme ever does this; it never becomes TLS and an `https://` server is never spoken cleartext to. This is the scheme for gRPC services. |

Up to 100 requests share one HTTP/2 connection (`PeerOptions::max_h2_streams`); the server's own
`SETTINGS_MAX_CONCURRENT_STREAMS` applies when it is lower. Pingora does not single-flight dials:
requests that arrive while no connection exists yet each open one, and requests that arrive at
the very moment another takes the pooled connection can also miss it, so a cold burst opens more
connections than a steady stream does.

A WebSocket (`Upgrade`) request is made in HTTP/1.1 even when the transport offers `h2`:
Pingora's HTTP/2 client has no `Upgrade`. It cannot be made to an `h2c://` server at all.

Health probes (`health_check`), the page fetch of the `errors` middleware and failure replay write
HTTP/1.1 by hand, so they always ask a TLS server for `http/1.1` and never use `h2`. An
`h2c://` server cannot answer them: a service with an `h2c://` server and a `health_check` is
`service_not_built`, an `errors` middleware naming such a service is `invalid_middleware`, and a
failure replay to one answers `409`. Use a TCP health check for gRPC servers.

## Timeouts

Each field is a Pingora setting of the peer, so it applies to HTTP/1.1 and HTTP/2 alike:

| Field | Pingora setting |
|---|---|
| `dial_timeout_secs` | `PeerOptions::connection_timeout` (TCP connect, `connectors/l4.rs`) and `total_connection_timeout` (connect and TLS handshake, `connectors/mod.rs`) |
| `read_timeout_secs` | `PeerOptions::read_timeout`: HTTP/1.1 `protocols/http/v1/client.rs` (head and body reads), HTTP/2 `protocols/http/v2/client.rs` (head, body and trailers) |
| `write_timeout_secs` | `PeerOptions::write_timeout` (HTTP/1.1 head and body writes, HTTP/2 body writes) |
| `idle_timeout_secs` | `PeerOptions::idle_timeout`, passed to the pool when the connection is released (`pingora-proxy` `lib.rs`, `ConnectionPool::idle_timeout`) |

A dial, handshake, read or write timeout is answered `504 Gateway Timeout` (it is an upstream
error, so with `passive` ejection it counts as a failure like a `502`). A timeout after the
response started cannot change the status, so the connection is cut. The answer is the same for
every transport, whether it sets the timeout or takes the default.

A connection that carried `Authorization: NTLM` or `Negotiate` is pinned to its client and kept
idle for at most 60 seconds (`pool::PINNED_IDLE_TIMEOUT`); a shorter `idle_timeout_secs` wins.

## Errors

| Code | When |
|---|---|
| `invalid_transport` | Unknown type or field; `ca_pem`, `client_cert` or `server_name` that does not parse; a key that does not match its certificate; `ca_pem` with `insecure_skip_verify`; a timeout outside 1..=3600 or not a whole number; `http2` that is not a boolean; TLS fields or `http2: false` on a transport named by a service with an `h2c://` server. |
| `unsupported_setting` | `min_tls_version: "1.3"`; `max_idle_per_host`. |
| `unknown_transport` | A service names a transport the app does not declare. |
| `invalid_service` | TLS options on a transport named by a service with an `http://` server; one address under two schemes. |
| `service_not_built` | `health_check` on a service with an `h2c://` server. |

Everything is checked when the snapshot is compiled. Pingora's rustls connector panics on a
malformed certificate or key, and skips verification when the SNI is empty, so neither can reach
it.

## Secrets

`client_cert.key_pem` is never part of `Debug` output (`Declared`, `Transport`), the explain
answer (it shows `"client_cert": "[redacted]"`), error messages, or logs. A 422 for a malformed
`client_cert` does not quote what was sent.

## Connection pool

The pool key is `(tenant, app, revision, transport, upstream address)` (`src/pool.rs`). The
transport part is a SHA-256 digest of every field (client certificate and key, the HTTP version
and every timeout included) mixed with whether the server is `https://` or `h2c://`, so TLS,
plain and HTTP/2 prior-knowledge connections, connections made with two different client
certificates and connections of two transports that differ in anything, never share a
connection. Pingora's own reuse hash names a client certificate by its serial number alone and
knows nothing of timeouts; `transport_pool_isolated` uses two certificates with the same serial
and `pooled_connections_are_never_shared_across_transports` two services that differ only in HTTP
version or one timeout. Two services of an app that name the same transport share connections to
the same address. A connection of one pool partition keeps the idle timeout it was made for.

### Why there is no `max_idle_per_host`

Traefik's `maxIdleConnsPerHost` and Caddy's `keepalive_idle_conns_per_host` cap the idle
connections to one server. Pingora 0.9 has no such cap:

- the idle HTTP/1.1 connections and the idle HTTP/2 connections are each one `ConnectionPool`,
  a single LRU for the whole process (`pingora-core` `connectors/mod.rs`,
  `connectors/http/v2.rs`), sized by `ConnectorOptions::keepalive_pool_size`;
- that size is `ServerConf::upstream_keepalive_pool_size` times the number of worker threads
  (`ConnectorOptions::from_server_conf`), and `HttpProxy::new` builds its connector from the
  server configuration (`pingora-proxy` `lib.rs`);
- `PeerOptions` has no pool field, so a peer cannot ask for a smaller share.

So a per-host value would be accepted and ignored. podgate refuses it with `unsupported_setting`
instead, and the pool is sized for the whole process with `UPSTREAM_POOL_SIZE` (default 128 per
worker thread, 1..=65536): once the pool holds more idle connections than that, the least
recently used one is closed. It sets `upstream_keepalive_pool_size` of the Pingora server
configuration. Use `idle_timeout_secs` to bound how long a connection waits.

## Failure replay

`POST /v1/apps/{app}/failures/{id}/replay` connects to the revision's first server through the
same transport as live traffic, so a replay against an `https://` upstream does the TLS
handshake with the same settings. It is written in HTTP/1.1 (ALPN `http/1.1`) and is refused with
`409` when that server is `h2c://`.

