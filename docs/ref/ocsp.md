# OCSP stapling

podgate staples a verified OCSP response to the certificate it serves when the certificate asks for it (must-staple) or the operator turns it on, so a client learns the certificate's status in the handshake and the CA's responder never sees the client. Code in `src/tls/ocsp.rs` and `src/tls/ocsp/`.

**Context.** Public CAs are retiring OCSP: Let's Encrypt ended it in 2025 and other CAs are following. Stapling therefore matters for certificates from the CAs that still publish OCSP and for private CAs that issue must-staple certificates. Traefik does not staple (it relies on Go's `crypto/tls`); Caddy staples automatically for the certificates it manages.

## When a certificate is stapled

The `ocsp` field of a `certificates` entry is `auto` (the default), `on` or `off`.

| Mode | A staple is fetched when |
|---|---|
| `auto` | the leaf carries the TLS Feature extension (RFC 7633) with `status_request`, which is what must-staple means |
| `on` | the leaf names an OCSP responder with an `http` or `https` URL in its Authority Information Access |
| `off` | never |

Certificates that podgate's ACME flow orders arrive in `certificates` like any other and default to `auto`. A must-staple certificate that names no responder, and a chain that lacks the issuer certificate (the issuer is taken from the served chain, second certificate), cannot be stapled: nothing is fetched and the reason is counted once as `no_responder` or `no_issuer`. A snapshot can set the mode and nothing else. The responder URL is read from the certificate and no snapshot field can set it, change it or turn verification off.

## Fetching

A fetch starts when a certificate enters the table. The TLS handshake never waits for it: until a response has been verified the certificate is served without a staple. The refresher runs every half second, so a new certificate waits at most that long for its first fetch.

The responder URL is text the certificate's supplier chose, and in `certificates` that can be a tenant, so it is fetched like any other address a tenant influences:

- Only `http` or `https`; no user information and no query. The request is the `GET` form of RFC 6960 appendix A.1 (`<url path>/<percent-encoded base64 of the DER request>`), under 512 bytes, one `CertID` hashed with SHA-1, no nonce (RFC 5019).
- The exact IP is checked against the upstream address policy (`docs/ref/upstream-policy.md`) immediately before it is dialled, on every attempt. Loopback, link-local, metadata and the other built-in denied ranges are refused unless the operator's policy permits them.
- The policy applied is the one of the tenant that owns the certificate. A snapshot certificate carries no tenant, so it is derived from the table: the tenants of every app whose hosts overlap the certificate's hosts, and the address must pass the policy of each of them. The `default: true` certificate is the operator's: it is checked as the policy's `default` entry. A certificate that is neither default nor claimed by any app has no owner and is not fetched (`unowned`).
- No redirect is followed: a `3xx` is a failed fetch (`http_status`). The exchange (connect, request, response) has 5 seconds. The response is at most 64 KiB and its `Content-Type` must be `application/ocsp-response`.
- At most 8 fetches run at once node-wide, and at most one per certificate.
- `OCSP_ALLOWED_HOSTS` (comma-separated suffixes such as `ocsp.example.com` or `.example.org`; a name matches itself and anything under it) restricts the responder host further. Unset means any host the address policy allows.

## Verification

Nothing is stapled unless every one of these holds, because a bad staple is worse than none: with must-staple a client refuses the whole connection.

- The body is a well-formed `successful` `BasicOCSPResponse` with exactly one single response, with nothing after it.
- The single response names this certificate's serial and its issuer (SHA-1 or SHA-256 name hash and key hash of the issuer in the served chain).
- The status is `good`. `revoked` is logged at warn level, counted and never stapled; the certificate keeps serving without a staple and any earlier staple is dropped. `unknown` is refused.
- `thisUpdate` is not in the future, `nextUpdate` is present and in the future.
- The signature verifies with the issuer's key, or with a delegated responder's key when the response includes that certificate, the certificate was signed by the issuer, is valid now and carries `id-kp-OCSPSigning`. A signer that is neither is refused.

The structures are parsed by the RustCrypto `x509-ocsp` crate; signatures are verified with the signature algorithms of the rustls crypto provider (ring), the code that verifies TLS certificates.

## Schedule

A staple is refreshed at the midpoint between `thisUpdate` and `nextUpdate`, moved by up to 5% of the window either way. A response that is already past its midpoint is refreshed after a minute (or half of what is left when less), and never later than nine tenths of what is left. A failed attempt backs off from one minute, doubling, to one hour (shortened by up to 10% so certificates do not retry in step). The old staple is kept while refreshes fail, but only until its `nextUpdate`: then it is dropped, and the certificate is served without one.

Staples live in a registry keyed by the SHA-256 fingerprint of the leaf, outside the routing table. An unrelated snapshot push keeps them (a staple is not refetched when its certificate is in the new table), and the entry of a certificate that left the table is dropped on the next refresher tick. A certificate whose chain changed keeps its staple on the new chain.

The registry holds one slot per certificate of the live table that wants a staple, so it is bounded by the table: at most as many slots as the 16 MiB snapshot limit leaves room for certificates, each with one staple of at most 64 KiB (a real response is a few KiB). Reads by the handshake are lock-free.

## Metrics

On `GET /metrics`:

| Series | Meaning |
|---|---|
| `podgate_ocsp_staples` (gauge) | Certificates that carry a verified, unexpired staple. |
| `podgate_ocsp_stapled_total` | Responses that passed verification. |
| `podgate_ocsp_fetches_total` | Responder fetches started. |
| `podgate_ocsp_fetches_in_flight` (gauge) | Fetches running now (at most 8). |
| `podgate_ocsp_rejected_total{reason}` | Responses discarded and fetches that failed, by reason. |

Reasons: `no_issuer`, `no_responder`, `unowned`, `scheme`, `host_not_allowed`, `unresolved`, `policy`, `connect`, `timeout`, `http_status`, `oversized`, `content_type`, `http_malformed`, `malformed`, `not_successful`, `not_basic`, `response_count`, `wrong_serial`, `wrong_issuer`, `revoked`, `unknown_status`, `not_yet_valid`, `expired`, `no_next_update`, `bad_signature`, `responder_not_authorized`, `unsupported_algorithm`. A refusal by the address policy also counts in `podgate_upstream_refused_total{tenant}`.

## Limits

- Responder URLs that name a host (not an IP address) are not fetched yet: they are counted as `unresolved` until DNS resolution is wired.
- Only the TLS listener entry points staple. TCP passthrough routers never terminate TLS.
