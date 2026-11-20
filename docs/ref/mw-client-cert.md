# Middleware `pass_tls_client_cert`

Reference for the kind in `src/middleware/pass_tls_client_cert.rs`. It passes the client certificate that podgate verified for the routed app, or fields of it, to the upstream. Matches Traefik's `passTLSClientCert` header for header; Caddy does the same with `header_up` and the `{http.request.tls.client.*}` placeholders. The model it plugs into is in `docs/architecture.md` (`### Middlewares`); client authentication itself is `tls.client_ca_pem` and `tls.client_auth` (`docs/ref/tls-options.md`).

```json
{
  "name": "cert",
  "type": "pass_tls_client_cert",
  "pem": true,
  "info": {
    "not_after": true,
    "not_before": true,
    "sans": true,
    "serial_number": true,
    "subject": {
      "country": true, "province": true, "locality": true, "organization": true,
      "organizational_unit": true, "common_name": true, "serial_number": true,
      "domain_component": true
    },
    "issuer": {
      "country": true, "province": true, "locality": true, "organization": true,
      "common_name": true, "serial_number": true, "domain_component": true
    }
  }
}
```

Every field is optional and defaults to `false`. Field names are Traefik's in snake case (`notAfter` is `not_after`, `commonName` is `common_name`). Unknown fields are `invalid_middleware`. As in Traefik, `issuer` has no `organizational_unit`.

## Compile rules

| Code | When |
|---|---|
| `invalid_middleware` | The configuration selects nothing (`pem` false and no `info` field true; Traefik accepts it and does nothing). An unknown field. The app has no `tls.client_ca_pem`, so it verifies no client certificate (the modes `request` and `require` refuse a CA, so they land here too). |

An app that wants the headers sets `tls.client_ca_pem` and a `tls.client_auth` that verifies (`verify_if_given`, or `require_and_verify`, the default with a CA). The middleware itself never makes a certificate mandatory: with `verify_if_given` a client without a certificate is served and the upstream gets no header.

## The headers

Checked against the pinned `traefik` (3.7.16, `devenv.nix`) with `RequireAndVerifyClientCert`, chains of one and two certificates, and every field selection below.

| Header | Set when | Value |
|---|---|---|
| `X-Forwarded-Tls-Client-Cert` | `pem: true` | The standard base64 of the DER of every certificate the client sent, leaf first, joined with `,`. No `-----BEGIN` lines, no line breaks, no further escaping (the characters `+`, `/` and `=` stay as they are). |
| `X-Forwarded-Tls-Client-Cert-Info` | at least one `info` field is true and has a value | For each certificate, its fields in the order below joined with `;`; the certificates joined with `,`; the whole string URL-escaped like Go's `url.QueryEscape` (a space is `+`, every byte but letters, digits and `-_.~` is `%XX`). |

Fields of one certificate, in this order. Each is `Name="value"`:

| Field | From | Value |
|---|---|---|
| `Subject` | `info.subject` | The selected attributes as `KEY=value` joined with `,`, in the order `DC`, `C`, `ST`, `L`, `O`, `OU`, `SN` (the subject's own serialNumber attribute), `CN`; several values of one attribute (two `DC`) come out in certificate order. Omitted when no selected attribute exists. |
| `Issuer` | `info.issuer` | The same for the issuer name, without `OU`. |
| `SerialNumber` | `info.serial_number` | The certificate serial in decimal. |
| `NB` | `info.not_before` | Start of validity, Unix seconds. |
| `NA` | `info.not_after` | End of validity, Unix seconds. |
| `SAN` | `info.sans` | DNS names, then e-mail addresses, IP addresses, then URIs, joined with `,`. Omitted when the certificate has none. |

Example for one certificate with every field selected, before URL-escaping (one line):

```text
Subject="DC=example,C=DE,ST=Bavaria,L=Munich,O=Acme GmbH,OU=Eng,SN=42,CN=alice";Issuer="CN=trusted ca";SerialNumber="1234567890";NB="1577836800";NA="2208988800";SAN="alice.example.com,alice@example.com,10.0.0.1,spiffe://x/y"
```

A header carries only what the client's TLS connection presented; if no field of any certificate is selected and present, the header is not sent.

### Differences from Traefik

- The PEM header: change 0055 asked for URL-escaped PEM bodies, but the pinned Traefik 3.7.16 sends the base64 unescaped (the captured value holds `+`, `/` and `=`). podgate matches the binary, so an app moving from this Traefik sees the same bytes. Do not run a form-style URL decoder over it: that turns `+` into a space.
- Quoted values: a `"` or `\` inside a value is written as `\"` or `\\`, and a control character as `?`. Traefik writes the raw value. A certificate's own subject (a CA may issue one with any text) therefore cannot end its field and start another, for example `CN=x";SAN="admin`.
- An empty selection is refused at compile time instead of doing nothing.

## What is passed, and what never is

- **Only a verified certificate.** The chain is the one the connection presented, and it is passed only when the CA of the app the request is routed to accepted it (`clientauth::verified_chain`, the same memoized verdict `403 client certificate required` comes from). It is never taken from the handshake's SNI app: a client that handshook with the name of app A and names app B in `Host` (B allows domain fronting) gets B's verdict, and `403` if B's CA did not sign it. Modes that do not judge the chain (`request`, `require`) never pass anything.
- **Only the first certificate is judged.** The CA signed the leaf. Later certificates are what the client sent along; they are passed as sent, like Traefik's `PeerCertificates`, and an app must trust only the first entry.
- **Plain HTTP and no certificate: nothing.** The middleware sets no header. Plain HTTP reaches an app with `verify_if_given` and no certificate, and the upstream sees none of the headers.

## No client can forge the headers

Every request loses every header whose name starts with `x-forwarded-tls-client-cert` in the entry stage (stage 2, `pass_tls_client_cert::strip`, called from `Gateway::request_filter` right after the path is normalized), before routing. It runs on every route whether or not it has this middleware, with or without a certificate, over TLS or plain HTTP, from a trusted proxy or not. The match ignores case and treats `_` as `-` (CGI-style upstreams map both to one variable), so these are all removed:

`X-Forwarded-Tls-Client-Cert`, `X-Forwarded-Tls-Client-Cert-Info`, `x_forwarded_tls_client_cert`, `X-Forwarded-Tls-Client-Cert-Subject` (the header that change 0021 used to write), and any other name with that prefix, every copy of each.

A route's own `headers` middleware runs later in the chain and may set any of these names to a fixed value of the tenant's choice; that is the tenant's own app, not a client.

## Limits and counter

A header value over 8 KiB (8192 bytes, after base64 or URL-escaping) is not sent, and the other header still is. A value is never cut. Each omission counts in `podgate_client_cert_header_omitted_total{header="pem"|"info"}` on `GET /metrics` (process-wide, not per tenant, since it counts something a client's certificate size decides).

## Replaces `tls.pass_client_cert`

Change 0021 added `tls.pass_client_cert`, which sent the subject in `x-forwarded-tls-client-cert-subject`. It is gone: a snapshot that still sets it is accepted and the field is ignored, like any unknown field. The equivalent is a `pass_tls_client_cert` middleware with `info: {"subject": {...}}`, which writes `X-Forwarded-Tls-Client-Cert-Info`. The old header is stripped like the others, so an app that still reads it gets nothing and cannot be fed a forged value.

## Explain and plan

`GET /v1/explain` lists the middleware in the chain with its configuration. The middleware has no `posture` of its own: removing it relaxes nothing, because the unconditional strip stays.
