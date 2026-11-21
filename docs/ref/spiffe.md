# SPIFFE workload identity

podgate can fetch its identity from a SPIFFE Workload API (SPIRE and compatible agents), present
that identity to upstreams that require mutual TLS, verify those upstreams by SPIFFE ID, and
verify the SVIDs of clients of selected apps. Code in `src/spiffe.rs` and
`src/spiffe/`. Traefik's counterpart is `serversTransport.spiffe`; Caddy has none in core.

## One identity per tenant

podgate is one workload with, usually, one SVID. If every tenant's upstream connections
presented it, a tenant that can name an address a mesh service trusts would act with the
platform's authority (a confused deputy). So the operator gives each tenant **its own** SVID, by
the agent's `hint`, and the server IDs it may talk to. A tenant the policy does not list has no
SPIFFE at all. A snapshot selects within what the policy allows; it cannot name an SVID, a hint, a
socket or a policy.

## Process configuration

Both variables are needed together (one without the other stops startup), and neither can be
set by a snapshot.

| Variable | Meaning |
|---|---|
| `SPIFFE_ENDPOINT_SOCKET` | The agent's unix socket: `/run/spire/sockets/agent.sock` or `unix:///run/spire/sockets/agent.sock`. |
| `SPIFFE_POLICY_FILE` | JSON, read once at startup; no hot reload. |

```json
{ "tenants": {
    "acme": {
      "svid_hint": "acme",
      "allowed_server_ids": ["spiffe://prod.example/ns/acme/*", "spiffe://prod.example/ns/shared/**"],
      "allowed_client_trust_domains": ["prod.example"],
      "allow": { "upstream_mtls": true, "client_identity": true }
    }
} }
```

- `svid_hint`: which of the identities the agent gives podgate this tenant uses. SPIRE labels
  several SVIDs of one workload with hints. Required when `allow.upstream_mtls` is true.
- `allowed_server_ids`: patterns the tenant's upstream IDs must fall under.
- `allowed_client_trust_domains`: the trust domains whose clients the tenant's apps may verify.
- `allow.upstream_mtls`, `allow.client_identity`: both default to `false`.
- A flag that is off with its list set, a list that is needed and missing, an ID that does not
  parse, and unknown fields stop startup with `invalid SPIFFE_POLICY_FILE: <path>: <entry>: <reason>`.

A SPIFFE ID is `spiffe://<trust domain>/<segment>/...` (letters, digits, `.`, `-`, `_` in
segments; lowercase trust domain). In a pattern, a whole segment `*` stands for exactly one
segment and a final `**` for one or more. `spiffe://td/ns/acme/*` matches `.../acme/web`, not
`.../acme` and not `.../acme/a/b`. The trust domain is always literal.

## Upstream mutual TLS

```json
{ "name": "mesh", "type": "servers_transport",
  "spiffe": { "ids": ["spiffe://prod.example/ns/acme/sa/db"], "trust_domain": "prod.example" } }
```

A service whose servers are `https://` and which names this transport connects like this:

1. podgate presents the tenant's SVID (the one with the tenant's hint) as the client
   certificate.
2. The server's certificate must chain to the live bundle of `trust_domain` and carry exactly one
   URI SAN that is a SPIFFE ID matching an entry of `ids` **and** a pattern of the tenant's
   `allowed_server_ids`. The DNS name is not checked: a SPIFFE identity replaces it. A wrong ID or
   a certificate from another CA fails the handshake, before any request byte is sent, and the
   request gets `502`.
3. HTTP/2 is offered as for any `https://` server (`http2` applies).

`spiffe` replaces `ca_pem`, `client_cert` and `insecure_skip_verify`, so combining them is
`invalid_transport`; it also cannot be combined with `proxy_protocol` (`invalid_transport`). It is
for HTTP services only: a TCP service that names such a transport is refused. Unknown fields,
including `socket`, `svid_hint` or `policy`, are `invalid_transport`.

Compile-time codes (`422`): `spiffe_not_allowed` (SPIFFE is not configured, the tenant is not in
the policy or has `upstream_mtls` off), `spiffe_server_id_not_allowed` (an entry of `ids` is not
covered by the tenant's `allowed_server_ids`), `invalid_transport` (an ID or the trust domain does
not parse, an ID is outside `trust_domain`, no `ids`, more than 64).

### No identity, no request

- No SVID with the tenant's hint, an expired one, or no bundle for the trust domain: the request
  gets `502` and **no connection is opened**. podgate never falls back to another tenant's SVID,
  to the first SVID the agent issued, or to no client certificate.
- The agent going away does not stop traffic at once: podgate keeps the last SVIDs and bundles
  and serves with them until each SVID expires. It reconnects with backoff (200 ms up to 10 s).
- Rotation is picked up without a restart: the agent streams every change, and the next request
  presents the new SVID.

### Connection pool

The pool key (`docs/ref/transports.md`, `Connection pool`) gains a digest of the SVID's
certificate (its serial included) and of the bundle's roots, read from the very peer the request
dials with. A rotated SVID or bundle opens a new connection; a connection made with the old one
is never reused for the new one, and a connection never crosses tenants (the tenant is part of the
key anyway).

## Client identity

```json
{ "tls": { "mode": "acme",
           "spiffe_client": { "trust_domain": "prod.example",
                              "allowed_ids": ["spiffe://prod.example/ns/acme/**"] } } }
```

For a tenant with `allow.client_identity` and a trust domain in `allowed_client_trust_domains`.
The client's certificate must chain to the **live** bundle of the trust domain (it rotates
without a snapshot push; a connection's verdict is reused for 30 seconds) and carry one URI SAN
in `allowed_ids`. `tls.client_auth` is `require_and_verify` unless it says `verify_if_given`;
`request` and `require` do not judge and are refused. `tls.client_ca_pem` excludes
`spiffe_client`. Like any client authentication it keeps the app off HTTP/3.

The verified ID reaches the app in `x-forwarded-tls-client-spiffe-id`. The header is removed from
every incoming request, in every spelling (`_` counts as `-`), before routing; only a certificate
the app's rule accepted writes it. With a `pass_tls_client_cert` middleware the certificate's SANs,
the ID included, are also in its info header.

## Posture changes

A plan (`POST /v1/snapshot/plan`) lists under `posture_changes`:

| `kind` | When |
|---|---|
| `spiffe_trust_added` | An upstream `ids` entry not covered by the live ones, or a client trust domain added or changed. |
| `spiffe_client_loosened` | Same trust domain, `allowed_ids` that admit IDs the live ones did not. |
| `spiffe_client_removed` | The app no longer verifies clients as SPIFFE SVIDs (the generic `client_auth_relaxed` is listed as well). |

## Secrets

SVID private keys are held in memory only. They never appear in logs, in `Debug` output, in
explain (which shows the trust domain and the IDs) or in metrics.

## Implementation notes

- The Workload API client is hand-written on `h2` and `prost`, both already dependencies: the
  service is two server-streaming calls (`FetchX509SVID`, `FetchX509Bundles`) with the header
  `workload.spiffe.io: true` and one empty request each, so a gRPC framework would bring a second
  HTTP stack for nothing. No new dependency (the `spiffe` crate and `tonic` were not needed).
- Pingora 0.9.1's rustls connector has no hook for a custom server certificate verifier and the
  handshake-complete hook exists only for OpenSSL. The workspace therefore patches `pingora-core`
  (`vendor/pingora-core`, wired by `[patch.crates-io]` like `vendor/pingora-proxy`) with one
  field, `PeerOptions::server_cert_verifier`, which the rustls connector installs as the
  verifier of that connection. The check runs inside the handshake. Drop the copy once Pingora has
  such a hook.
