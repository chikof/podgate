# TLS options and the default certificate

TLS policy belongs to the app, and a host belongs to one policy. Code: `src/tls.rs`, `src/tls/options.rs`, `src/tls/hello.rs`, `src/clientauth.rs`. Matches Traefik's `tls.options.<name>` and `tls.stores.default.defaultCertificate`, and Caddy's `tls { protocols, ciphers, curves, alpn, client_auth }` and `default_sni`.

## Fields

All fields are optional on `App.tls`; absent means the listener's baseline.

```json
"tls": {
  "mode": "acme",
  "min_version": "1.3",
  "cipher_suites": ["TLS13_AES_256_GCM_SHA384", "TLS13_CHACHA20_POLY1305_SHA256"],
  "alpn": ["h2", "http/1.1"],
  "client_auth": "verify_if_given",
  "client_ca_pem": "-----BEGIN CERTIFICATE-----...",
  "sni_strict": true
}
```

|Field|Meaning|
|---|---|
|`min_version`|`1.2` or `1.3`. Connections below it are refused. Cannot be below the process floor `TLS_MIN_VERSION` (default `1.2`); an app can only raise it.|
|`cipher_suites`|Names from the rustls `ring` provider (`TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, and the other `TLS_ECDHE_*` GCM and ChaCha20 suites). Connections that negotiate another suite are refused. An unknown name is `422` `unsupported_setting` and the message lists the supported names. TLS 1.2 CBC suites are not offered by rustls and cannot be requested.|
|`alpn`|`h2` and `http/1.1`. A request on a connection that negotiated another protocol is refused. Any other protocol is `422` `unsupported_setting`.|
|`client_auth`|`request` (ask, trust nothing), `require` (some certificate, the chain is not judged), `verify_if_given` (a certificate, when sent, must chain to `client_ca_pem`; none is fine), `require_and_verify` (a chain to `client_ca_pem` is required). With `client_ca_pem` and no mode: `require_and_verify`, the behaviour of change 0021. `verify_if_given` and `require_and_verify` need `client_ca_pem`; `request` and `require` refuse one; `pass_client_cert` needs a mode that verifies. A violation is `422` `invalid_client_auth`. A request that fails its mode gets `403` `client certificate required`.|
|`sni_strict`|A handshake for a name this app may serve that no certificate covers fails instead of getting the default certificate. See below.|
|`max_version`, `curves`, `session_tickets`|Rejected: `422` `unsupported_setting`. A version cap only helps downgrade attacks, and key exchange groups and session tickets are listener wide (tickets stay on).|

A certificate carries `default: true` to be the default certificate. At most one; a second is `422` `invalid_certificate`. Its `hosts` may be empty.

## Why per app and not per router

Traefik lets a router choose TLS options. The handshake runs before any router is known, so podgate cannot do that literally. The per-host equivalent is that the TLS policy belongs to the app that owns the host, and apps that share a host (an exact name under another app's wildcard, within one tenant) must agree on all of it: `tls_policy_conflict` compares `client_ca_pem`, `client_auth`, `min_version`, `cipher_suites`, `alpn`, `sni_strict` and the rejected fields as written. A snapshot where they differ is refused whole.

## How it is enforced

Pingora 0.9 builds one rustls `ServerConfig` per listener and has no hook to choose another per connection. Versions, suites and ALPN therefore cannot be set per app at handshake time. The listener config is the operator's baseline: TLS 1.2 and 1.3, the `ring` provider's suites, `h2` and `http/1.1`. An app's options narrow it in two places:

1. **ClientHello.** The pre-TLS hook reads the hello and, when every app that may serve its SNI has options the hello cannot satisfy (no TLS 1.3 suite under `min_version: 1.3`, no allowed suite, no allowed ALPN protocol), sends a fatal alert (`protocol_version`, `handshake_failure` or `no_application_protocol`) and closes. The client sees the handshake fail. The hook reads hellos only while some app has such options, `TLS_MIN_VERSION` is `1.3`, or on-demand TLS is on; otherwise it reads nothing.
2. **Request.** Before routing continues, the version, suite and protocol the connection really negotiated are compared with the options of the app the request matched. A violation is `421` `{"error":"tls policy"}`. This is the authority: a client offering `[TLS 1.2, TLS 1.3 suites]` that the hook let through, or one whose preferred suite is not allowed although it offered an allowed one, is refused here. For `alpn: ["http/1.1"]`, a client offering `h2` and `http/1.1` negotiates `h2` and then gets `421`; a client offering only `h2` fails the handshake.

Plain HTTP requests pass this check: there is no TLS to judge, and the entry point decides what plain HTTP gets.

`TLS_MIN_VERSION=1.3` applies the same two layers to every app, not only to those with options.

## Default certificate and strict SNI

The resolver picks the certificate covering the SNI. For a name no certificate covers, and for a handshake with no SNI, it serves the `default: true` certificate if the snapshot has one and no app that may serve the name is `sni_strict`; otherwise the handshake fails, as it did before this spec. `sni_strict` is scoped to the names its app may serve (its hosts, wildcards and `host_regexp` routers), so one tenant cannot take the default certificate away from names it does not own. A name that no app serves is not strict.

The SNI check still applies: a request whose `Host` is not the SNI is `421` unless the app allows domain fronting, so the default certificate never serves an app's content under a name that is not its own.

## Posture changes

A plan (`POST /v1/snapshot/plan`) lists under `posture_changes`, for a host that exists on both sides:

|Kind|Meaning|
|---|---|
|`tls_min_version_lowered`|The effective minimum version is lower.|
|`tls_cipher_suites_widened`|A suite is allowed that was not, or the restriction is gone.|
|`sni_strict_disabled`|The app was strict and is not.|
|`client_auth_relaxed`|`client_auth` went away, or to a mode that asks less (for example `require_and_verify` to `verify_if_given`). Dropping or swapping the CA is `client_ca_removed` and `client_ca_changed`.|

Tightening is never listed. Wider ALPN is not either: it changes the protocol, not who may connect.
