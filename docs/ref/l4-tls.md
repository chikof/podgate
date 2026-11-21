# TLS on TCP routers

A TCP router can match the TLS server name and ALPN of a connection, and either forward the encrypted stream untouched (passthrough) or end TLS with the app's certificates and forward plain bytes (termination). It builds on the TCP routers of `docs/ref/l4-tcp.md` and lives on `tcp` entry points; sharing a port with HTTP routers is change 0060.

Matches Traefik's `HostSNI`, `HostSNIRegexp`, `ALPN` and `tls {passthrough}` on TCP routers, and Caddy's `layer4` `tls` matcher with `proxy`. Not here: TLS options per router (the app's `tls` settings of `docs/ref/tls-options.md` apply, as for its HTTP hosts), `acme-tls/1` on a `tcp` entry point (use `http-01` on the HTTP entry point), and TCP middlewares.

## Configuration

```json
{
  "entry_points": [{ "name": "edge" }],
  "certificates": [{ "hosts": ["app.test"], "cert_pem": "…", "key_pem": "…" }],
  "apps": [{
    "id": "shop", "tenant": "acme", "declared_by": "…", "tls": { "mode": "acme" },
    "routers": [], "revisions": [],
    "tcp": {
      "routers": [
        { "name": "db", "entry_points": ["edge"], "service": "pg",
          "match": { "all": [{ "sni": "db.shop.test" }, { "alpn": "postgresql" }] },
          "tls": { "passthrough": true } },
        { "name": "app", "entry_points": ["edge"], "service": "plain",
          "match": { "sni": ["app.test", "*.app.test"] }, "tls": {} }
      ],
      "services": [
        { "name": "pg",    "type": "loadbalancer", "servers": [{ "address": "10.0.1.5:5432" }] },
        { "name": "plain", "type": "loadbalancer", "servers": [{ "address": "10.0.1.6:8080" }] }
      ]
    }
  }]
}
```

| Field | Meaning |
|---|---|
| router `tls` | Absent: the router does not look at TLS, as in `l4-tcp.md`. `{"passthrough": true}`: the encrypted stream is forwarded as it is and the server completes the handshake. `{}`: podgate terminates TLS with the app's certificates and forwards the decrypted bytes. Any other field is `invalid_router`. |
| `sni` | `{"sni": "a.test"}` or a list: the server name in the ClientHello is an exact name or one label under a `*.` wildcard, the grammar of `host`. Names fold to lowercase. A connection that sent no server name matches no `sni` leaf. |
| `sni_regexp` | A regular expression over the normalized server name, unanchored (write `^` and `$`). Never matches a connection with no server name. |
| `alpn` | `{"alpn": "h2"}` or a list: the ClientHello offers at least one of the protocols. No ALPN extension, no match. |
| `client_ip`, `all`, `any`, `not` | As in `l4-tcp.md`. |

A TCP router matches the TCP dialect: `client_ip`, `sni`, `sni_regexp`, `alpn` and the combinators. An HTTP leaf (`host`, `path_prefix`, `header`, ...) on a TCP router, and an `sni`, `sni_regexp` or `alpn` leaf on an HTTP router, are `invalid_matcher`. A TCP router that uses `sni`, `sni_regexp` or `alpn` without `tls` is `invalid_router`: a connection with no TLS has no server name to read.

## What a connection goes through

An entry point with at least one router that has `tls` reads the start of every connection before it picks a router:

1. **Read.** Up to 16 KiB in at most 5 seconds, parsed by the same ClientHello reader as the HTTPS listener (`src/tls/hello.rs`, rustls' `Acceptor`; there is no second parser). If the connection has the PROXY protocol gate (`;proxy_protocol`), that header is read first and the ClientHello after it.
   - A ClientHello: its server name and ALPN protocols are what the matchers see.
   - A first byte that is not a TLS handshake record: the connection is not TLS. Only routers without `tls` can take it.
   - Nothing complete in 5 seconds, a malformed hello, one over 16 KiB, or a client that leaves first: the connection is closed (`hello_timeout`, `hello_invalid`).
2. **Route.** The routers of the entry point are ranked and the first that matches wins (below). No match closes the connection (`no_route`).
3. **Admit.** The tenant takes one `max_inflight` slot and is charged the two copy buffers (32 KiB), as for any TCP connection. The bytes read go back to the stream.
4. **Handshake**, for a terminating router only. See below. A refusal closes the connection before any server is dialled.
5. **Dial and copy**, as in `l4-tcp.md`: the same servers, balancer, upstream address policy and idle timeout. A terminating router copies the decrypted stream; a passthrough router copies the TLS records and the ClientHello is the first thing the server receives (after a PROXY header towards the server).

An entry point with no router that has `tls` reads nothing and behaves as in `l4-tcp.md`: a server-first protocol (SMTP, MySQL) still works there. On an entry point that has TLS routers a connection that sends nothing for 5 seconds is closed, so a server-first protocol does not belong on it.

### Memory

The peek buffer holds at most 16 KiB, one copy buffer. It exists before a router, and so a tenant, is known, so it is charged to no tenant: that is bounded by the 5 second deadline, the cap, and the fact that it grows with what the client sends. Once the router is chosen the tenant is charged the usual 32 KiB, and the bytes are copied into the stream's own buffer (16 KiB twice, inside that charge). The peek buffer is dropped before the copy starts, so a connection never holds it together with the copy buffers. A terminating handshake also allocates rustls' own state, which is not charged, as on the HTTPS listener.

## Which router takes a connection

Routers on one entry point are ranked: a router with a `match` or `tls` over one without, then by the most specific name leaf (exact `sni` over a wildcard `sni` over `sni_regexp`), then by the number of other leaves (`alpn`, `client_ip`). Of two routers of the same rank, any that can match one connection are `route_ambiguity`; `sni` leaves with no name in common, and `client_ip` blocks that do not overlap, are provably disjoint. `alpn` leaves are never disjoint: a client can offer both.

A router with `tls` matches only a connection that starts with a ClientHello. With no server name, only routers without an `sni` leaf match (`not` and `any` can make a router match without one; a `not {"sni": ...}` router matches a hello that has none).

## Who may claim a name

A plain `sni` leaf claims its names, the way `host` does, across every router of every app:

- Two tenants claiming one name, or one claiming a name under the other's wildcard, is `host_conflict` or `cross_tenant_wildcard`, whether the other claim is a TCP or an HTTP router, with both `declared_by` values. One tenant can own both.
- A name's owner is the one whose router may receive its connections. In passthrough the server name is whatever the client sent and no certificate is involved, so these claims are the only thing that keeps tenant A's router from receiving tenant B's connections.
- `sni_regexp` claims nothing and follows `host_regexp`: it compiles only when it narrows a literal `sni` of the same tenant in an `all`, or the router sits on an entry point reserved to the tenant, or the operator lists the tenant in `CATCH_ALL_TENANTS`; otherwise `catch_all_not_allowed`. The text of the regular expression is never inspected. The same holds for a router that no literal `sni` bounds: only an `alpn` leaf, `not`, an `any` of a name and a regular expression, or no `match` at all.
- At run time a router that no literal name bounds never takes a connection whose name another tenant claims: it does not match, so a catch-all cannot capture a name that its owner's router declined (for example by `client_ip`).
- Two tenants that can both take any name on one entry point are `cross_tenant_catch_all`.

A router with `tls` may share a `tcp` entry point between tenants when its policy `tenants` is absent or lists them: the entry point must exist and be `tcp` (`unknown_entry_point`, `entry_point_protocol`) and admit the tenant (`entry_point_forbidden`). A router without `tls` still needs an entry point reserved to its tenant alone (`l4-tcp.md`). A TLS router that no literal name bounds needs the same reservation, or the operator's allowance.

## Termination

A terminating router completes the handshake with the app's certificates and settings, then dials the server and copies the decrypted stream.

- **Certificate.** From the live snapshot's certificates (`certificates`, issued by ACME for the names the router serves, or on demand: a handshake for an `on_demand` name waits for its certificate like the HTTPS listener), with the OCSP staple of `docs/ref/ocsp.md` when there is one. The names an app's terminating routers serve are the app's hosts: they get certificates, staples and an owner like an HTTP host. A name the tenant does not claim is never served a certificate, even when the snapshot has one for it (another tenant's); it gets the default certificate (`default: true`), or the handshake fails when the app is `sni_strict`. A hello with no server name gets the default certificate. This is the HTTPS resolver's choice with the tenant of the router bound in: it cannot hand out another tenant's key.
- **ALPN.** The protocol negotiated is the first protocol the router's `alpn` leaves name (outside `not`) that the client offered; a router with none negotiates none. The `h2` and `http/1.1` allowance of the app's `tls.alpn` is about HTTP and does not apply here.
- **TLS options** (`docs/ref/tls-options.md`): a hello that offers no version or suite the app allows is answered with a fatal alert and closed before the handshake (`tls_policy`), and the negotiated version and suite are checked after it.
- **Client authentication** (`docs/ref/mw-client-cert.md`, `tls.client_auth` and `tls.client_ca_pem`): the client is asked for a certificate when the app has client authentication, and the connection is closed (`client_cert`) when the chain does not satisfy the mode: none for `require` and `require_and_verify`, a chain the CA refuses for `verify_if_given` and `require_and_verify`. `request` asks and trusts nothing. Unlike HTTPS there is no request to answer `403` to; the connection ends after the handshake.
- **Resumption is off.** Every handshake is a full one, so a resumed session never skips the client certificate check of the app the connection routes to.
- **Time.** The handshake has 10 seconds. The tenant's slot and buffers are held meanwhile.

The server then sees plain bytes. To tell it who the client was, use the PROXY protocol towards the server.

## Metrics

On `GET /metrics`, in `podgate_l4_refused_total{reason}`, besides the reasons of `l4-tcp.md`:

| Reason | Closed because |
|---|---|
| `hello_timeout` | No complete ClientHello within 5 seconds. |
| `hello_invalid` | A malformed hello, one over 16 KiB, or the client left before finishing it. |
| `tls_handshake` | A terminating handshake failed or took over 10 seconds. |
| `tls_policy` | The hello or the negotiated connection broke the app's TLS options. |
| `client_cert` | The client certificate did not satisfy the app's `client_auth`. |

## How it is wired

- `tcp::App::serve` (`src/l4/tcp/app.rs`) peeks, routes, runs the router's `chain`, charges, replays and terminates. The PROXY header towards the server of change 0061 is written by the dial itself, before the first byte is copied, so it comes before the ClientHello of a passthrough connection (`docs/ref/l4-middleware.md`).
- `src/l4/tls.rs`: `peek` (the 16 KiB, 5 second read through `crate::tls::hello::read_hello`), `Owners` (which tenant claims each name of a table), `Terminator` (the handshake).
- The server name and ALPN reach the matcher through `View::hello` (`src/router/matcher.rs`), which is `Hello::NONE` for an HTTP request.
- A passthrough connection is replayed with `Stream::rewind`, not `try_peek`: `try_peek` reads and rewinds too, but the hello reader needs several reads, so the bytes are collected and rewound once.
