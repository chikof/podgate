# ACME TLS-ALPN-01

An app can get a certificate through the TLS-ALPN-01 challenge (RFC 8737), which needs only port 443. Deployments that cannot open port 80 can still use ACME, and every node answers the CA. Code in `src/acme/alpn01.rs`, the hook in `src/tls/hello.rs`, the issuer branch in `src/acme/issuer.rs`. It builds on the HTTP-01 round trip of change 0014 and the DNS-01 `challenge` setting of change 0081 (`docs/architecture.md ## ACME and on-demand TLS`).

Matches Traefik `tlsChallenge`. Caddy turns TLS-ALPN-01 on by default. Deliberate difference: it is opt-in per app (`tls.challenge: "tls-alpn-01"`), so nothing changes for an app that never asks.

## Turning it on

| Where | Setting | Meaning |
|---|---|---|
| Snapshot | `App.tls.challenge: "tls-alpn-01"` | Prove the app's hosts over TLS-ALPN-01. Needs `tls.mode` `acme` and exact hosts. |
| Snapshot | `Snapshot.acme.challenges` | Entries `{name, key_authorization}` for TLS-ALPN-01 (entries `{token, key_authorization}` stay HTTP-01). Exactly one of `token` and `name` per entry. At most 1024 `name` entries. |

The issuer is the node whose `NODE_NAME` equals `acme.issuer_node`, as for HTTP-01.

## The round trip

1. The issuer opens an order, finds a `tls-alpn-01` challenge for each pending authorization and emits one event per host:

   ```json
   {"seq": 7, "kind": "acme_challenge", "type": "tls-alpn-01",
    "name": "a.example.com", "key_authorization": "token.thumbprint"}
   ```

2. The control plane pushes a snapshot whose `acme.challenges` lists `{"name": "a.example.com", "key_authorization": "token.thumbprint"}`. Every node, the issuer included, now answers an `acme-tls/1` handshake for that name.
3. The issuer waits until its own live table holds the answer with the same key authorization, then tells the CA to validate. The CA connects to port 443 (any node can receive it), offers only the ALPN protocol `acme-tls/1` and checks the certificate; the node closes the connection after the handshake.
4. The issuer finalizes and emits `certificate_issued {hosts, cert_pem, key_pem}` as for HTTP-01. The control plane stores it in `certificates`. The answer in `acme.challenges` can go once the certificate is stored.

Order timeouts and backoff are those of HTTP-01 (an order is abandoned after 10 minutes; a failed job waits 1 minute, doubling to 1 hour).

## How a node answers

The challenge certificate is self-signed for the host, with the host as its only subject alternative name and the critical `id-pe-acmeIdentifier` extension (`1.3.6.1.5.5.7.1.31`) holding the DER OCTET STRING of `SHA-256(key authorization)`. It and its key are generated once per pushed answer, in memory, on the first handshake that needs them. They are never added to `certificates`, to the overview or to the expiry gauge, and they disappear with the table that holds the answer.

A node answers only when all of these hold:

- the ClientHello offers exactly one ALPN protocol, `acme-tls/1`;
- the SNI is a name an `acme` app claims exactly, and that app chose `tls-alpn-01`;
- the live snapshot holds a pushed `{name, key_authorization}` for it.

Any other ClientHello that offers only `acme-tls/1` gets a fatal `no_application_protocol` alert and the connection closes: no certificate, and no on-demand certificate request either. A client that offers `acme-tls/1` next to `h2` or `http/1.1` is a normal client: the listener never selects `acme-tls/1`, so it gets the protocol and the certificate it would have got anyway.

## Why the pre-TLS hook answers it (the alpn01 finding)

Pingora 0.9.1's rustls listener cannot carry `acme-tls/1` in its own ALPN list, and no certificate resolver can fix that:

- `TlsSettings::build` makes one rustls `ServerConfig` per listener (`pingora-core-0.9.1/src/listeners/tls/rustls/mod.rs`). Its `alpn_protocols` come only from `set_alpn(ALPN)`, whose variants are `H1`, `H2`, `H2H1` and `Custom`. `Custom` replaces the list, and `CustomALPN::new` panics on `h2` and `http/1.1` (`protocols/tls/mod.rs`), so `acme-tls/1` cannot sit next to them.
- rustls fails a hello that shares no protocol with a non-empty server list with a fatal `no_application_protocol` alert (`rustls-0.23.46/src/server/hs.rs`, the ALPN block). `ResolvesServerCert` returns only a certificate and cannot change the config or the protocol list.
- `Acceptor::from_server_config` exists, but `Listeners` takes `TlsSettings` only, so a second config cannot be injected into the listener.

What works without forking Pingora is `PreTlsProcess`, which `PreHandshake` already implements: it runs on the raw connection before the handshake and an error from it drops the connection. When the hello offers only `acme-tls/1` and a challenge is pending, the hook runs a handshake of its own on that connection with a dedicated `ServerConfig` (ALPN list `["acme-tls/1"]`, the challenge certificate) through `tokio-rustls`, sends `close_notify` and returns an error, so the connection never reaches the listener, routing or `request_filter`. The SNI check is unaffected, since no request is read.

Pingora logs the returned error as `Downstream handshake error` at `error` level for each answered challenge. That is one line per validation; it is the price of ending the connection from the hook.

## Cost

The hook reads a ClientHello only when something needs it. A TLS-ALPN-01 answer in the live snapshot is one of those things, so while a snapshot holds one, every handshake on the node pays the one read that on-demand TLS and TLS options already cost (the hello is put back untouched). With no answer pushed, an app without options reads nothing: `hello_reads` stays at 0. The control plane removes the answer after the certificate is stored.

## What the compiler rejects

All are `422` with the code in `conflicts[].code`, naming the app and `declared_by`.

| Code | When |
|---|---|
| `tls_alpn_wildcard` | A `*.` wildcard host on a `tls-alpn-01` app. The CA forbids it; use `dns-01`. `host` names it. |
| `tls_alpn_needs_acme_mode` | `challenge: tls-alpn-01` on an `on_demand` app, whose certificates are ordered over HTTP-01. |
| `tls_policy_conflict` | Two apps of one tenant share a pattern with different `tls.challenge` (as for every `tls` field). |

A snapshot whose `acme.challenges` has an entry that sets both or neither of `token` and `name`, or a `name` that is not an exact host, is rejected with `422` (`acme.challenges`).

## Threat model

- **No certificate for strangers.** The challenge certificate carries only the host and a digest the CA already knows; it is public by design. It is served only for a name that an app claims and the control plane asked to prove, so a client cannot learn whether any other name is hosted here.
- **Tenancy.** A host's challenge kind comes from the app that claims it, and conflicting claims already fail the snapshot. One tenant cannot answer for another's name.
- **Normal traffic is untouched.** The listener's ALPN list is the same as before. A pending challenge never changes what an `h2` or `http/1.1` client negotiates or receives.
- **Memory and CPU.** At most 1024 answers per snapshot; each costs one key generation, on the first handshake, and the handshake and close are bounded to 10 seconds.

## Tests

`tests/acme_alpn.rs` runs `pebble` with `pebble-challtestsrv` as its DNS and `tlsPort` pointed at the issuer node's TLS listener. The test plays the control plane: it reads the event feed, pushes each challenge back in `acme.challenges` and stores the certificate. pebble validates for real. Unit tests in `src/acme/alpn01.rs` check the certificate (critical extension, digest, only SAN); `src/tls/hello.rs` checks that no hello is read without a pending challenge.
