# Upstream transports (TLS)

A `loadbalancer` service reaches an `https://` server through a transport: a `servers_transport`
object in `App.transports`, named by the service's `transport` field. The code is
`src/service/transport.rs`.

```json
{
  "transports": [{
    "name": "internal", "type": "servers_transport",
    "server_name": "backend.internal",
    "ca_pem": "-----BEGIN CERTIFICATE-----...",
    "client_cert": { "cert_pem": "-----BEGIN CERTIFICATE-----...", "key_pem": "-----BEGIN PRIVATE KEY-----..." },
    "insecure_skip_verify": false,
    "min_tls_version": "1.2"
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

## Defaults

- A server named `https://` with no `transport`, or a transport with no `server_name`, uses the
  URL host. Today the host is always an IP literal (servers by DNS name are
  `dns_upstream_not_built`): **no SNI is sent**, and the certificate must carry the IP as a SAN.
  Verification is on: it is never skipped for lack of a name.
- With neither `ca_pem` nor `insecure_skip_verify`, the server certificate is verified against the
  platform roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` count, as in Pingora).
- `http://` servers ignore transports with no TLS fields. A transport that sets any TLS field and
  is named by a service with an `http://` server is refused (`invalid_service`): a setting is
  never silently unused. One address cannot be both an `http://` and an `https://` server of the
  same service.

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

## Errors

| Code | When |
|---|---|
| `invalid_transport` | Unknown type or field; `ca_pem`, `client_cert` or `server_name` that does not parse; a key that does not match its certificate; `ca_pem` with `insecure_skip_verify`. |
| `unsupported_setting` | `min_tls_version: "1.3"`. |
| `unknown_transport` | A service names a transport the app does not declare. |
| `invalid_service` | TLS options on a transport named by a service with an `http://` server. |

Everything is checked when the snapshot is compiled. Pingora's rustls connector panics on a
malformed certificate or key, and skips verification when the SNI is empty, so neither can reach
it.

## Secrets

`client_cert.key_pem` is never part of `Debug` output (`Declared`, `Transport`), the explain
answer (it shows `"client_cert": "[redacted]"`), error messages, or logs. A 422 for a malformed
`client_cert` does not quote what was sent.

## Connection pool

The pool key is `(tenant, app, revision, transport, upstream address)` (`src/pool.rs`). The
transport part is a SHA-256 digest of every field (client certificate and key included) mixed
with whether the connection is TLS, so TLS and plain connections, or connections made with two
different client certificates, never share a connection. Pingora's own reuse hash names a client
certificate by its serial number alone; `transport_pool_isolated` uses two certificates with the
same serial.

## Failure replay

`POST /v1/apps/{app}/failures/{id}/replay` connects to the revision's first server through the
same transport as live traffic, so a replay against an `https://` upstream does the TLS
handshake with the same settings.

