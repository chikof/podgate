# Middleware `forward_auth`

Reference for the kind in `src/middleware/forward_auth.rs` (with its HTTP/1.1 client in `src/middleware/forward_auth/client.rs`). The model it plugs into is in `docs/architecture.md` (`### Middlewares`, rule 4).

Delegates the decision to an auth service of the same app: podgate asks it first, lets the request continue when it answers `2xx`, relays its answer otherwise, and **closes the door when the auth service cannot answer**. Traefik's `forwardAuth` and Caddy's `forward_auth`, with a stricter call and a failure that never opens.

```json
{
  "name": "sso",
  "type": "forward_auth",
  "address": "http://10.0.0.5:9091/verify",
  "response_headers": ["x-user", "x-groups"],
  "response_headers_regex": "^x-auth-",
  "timeout_secs": 5,
  "transport": "internal"
}
```

| Field | Meaning |
|---|---|
| `address` | Required. An absolute `http://` or `https://` URL whose host is an IP literal (a host name is `invalid_middleware`: the DNS resolver of change 0042 serves load balancer servers and is not wired for `forward_auth` yet). A port defaults to 80 or 443. Credentials in the URL, `h2c://` (the call is written as HTTP/1.1, which an h2c server cannot answer), a relative address or anything else that is not an absolute `http(s)` URL is `invalid_middleware`. The path and query are sent as written. Fixed configuration: never derived from the request. |
| `trust_forward_header` | Default `false`. When `true` and the entry point trusts the peer (`forwarded_headers`, `docs/ref/client-ip.md`), `X-Forwarded-For` carries the whole chain the peer sent, then the peer. Otherwise it carries the resolved client. A raw `X-Forwarded-*` of the client is never copied. |
| `request_headers` | Allow list of the client's request headers sent to the auth service, case-insensitive, 1 to 64 names. Default: every header except the reserved ones below. |
| `response_headers` | Names copied from a `2xx` answer into the request that goes on, case-insensitive, at most 64. Default none (the middleware then only gates). |
| `response_headers_regex` | A regular expression (at most 256 bytes, case-insensitive, matched unanchored against the lower-case header name) of more names to copy. Anchor it: `^x-auth-`. |
| `timeout_secs` | One bound for connecting, sending and reading the whole answer. Default 5, 1 to 3600; a call also never runs past the process's `REQUEST_TIMEOUT_SECS`. |
| `transport` | Name of a `servers_transport` of the app: CA, SNI and client certificate of an `https://` address, the same as for a service. The call is always HTTP/1.1 (ALPN `http/1.1`), so its `http2` and pool settings do not apply. A transport with TLS options on an `http://` address is `invalid_middleware`; an undeclared name is `unknown_transport`. |
| `max_response_bytes` | The cap of the answer's body. Default 65536, at most 1048576. |
| `max_concurrent` | Calls in flight at once for this middleware. Default 64, at most 4096. |

Unknown fields (Traefik's `forwardBody`, `addAuthCookiesToResponse`, `authRequestHeaders` under its own name) are `invalid_middleware`: a setting is never ignored.

## The call

```
GET <path and query of address> HTTP/1.1
Host: <authority of address>
Connection: close
X-Forwarded-Method: <the client's method>
X-Forwarded-Proto: http | https
X-Forwarded-Host: <the host the client asked for>
X-Forwarded-Uri: <the client's path and query>
X-Forwarded-For: <the resolved client; see trust_forward_header>
<the client's request headers that request_headers allows>

```

- **From the connection.** `Proto` is the connection's TLS state (or what a trusted peer reported), `Host` the request's own host (or a trusted peer's `X-Forwarded-Host`), `For` the resolved client (`docs/ref/client-ip.md`). A client's own `X-Forwarded-*`, `Forwarded` and `X-Real-IP` are never sent: for an untrusted peer they are removed before any middleware runs, and the call writes its own set in any case.
- **Never the body.** The request is a `GET` with no body and no `Content-Length`. The client's body goes to the upstream only after a `2xx`.
- **Reserved headers.** Never sent, never copied back and never accepted in `request_headers` or `response_headers`: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Http2-Settings`, `Proxy-*`, `Forwarded`, `X-Real-IP`, `Expect` and `X-Forwarded-For`, `-Proto`, `-Host`, `-Port`, `-Uri`, `-Method`. `Authorization` and `Cookie` are not reserved: the auth service is a service of the same app and normally needs them.
- **A request head over 32 KiB** is not sent: the request is refused with `503`.

## What comes back

| The auth service answers | The client gets |
|---|---|
| `2xx` | The request continues to the upstream, with the headers named by `response_headers` (or matching `response_headers_regex`) copied in, every value of each. Nothing else of the answer is used. |
| any other status (`401`, `403`, a `302` to a login page, a `500`) | That status, the answer's headers except the connection's own, `Content-Encoding`, `Alt-Svc`, `Server`, `Date`, `Proxy-*`, `Forwarded` and `X-Real-IP`, and its body (at most `max_response_bytes`). `Set-Cookie`, `Location` and `WWW-Authenticate` are relayed. |
| a failure (below) | `503` with `{"error":"auth service unavailable"}`. The request never reaches the upstream. |

A failure is: the upstream address policy refuses the address (`docs/ref/upstream-policy.md`, counted in `podgate_upstream_refused_total{tenant}`), no connection, a timeout, a body over `max_response_bytes` (whatever the status), a head over 8 KiB or with more than 100 headers, an answer that is not clean HTTP/1.x (two `Content-Length` headers, both framings, a transfer coding other than `chunked`, a content coding, a folded header, a `1xx` or a status outside `200..=599`), no free permit of `max_concurrent`, and a tenant buffer budget that is full right now. The last two also send `retry-after: 1` and are capacity refusals (auto-revert does not count them). Traefik answers `500` when the call fails; podgate answers `503` so an operator can tell "the auth service is down" from "the app is down" in one glance.

### No forged identity

Before the call, the middleware removes from the client's request every header `response_headers` names and every header `response_headers_regex` matches. A client that sends `X-User: admin` cannot have it survive when the auth service leaves it out, and the auth service never sees the forged copy. This also removes a value an earlier middleware of the chain set under such a name: pick names that only the auth service owns. A regular expression such as `.*` would remove every header; anchor it.

Differences from Traefik: `Set-Cookie` of a `2xx` answer is not forwarded to the client (there is no `addAuthCookiesToResponse`; a name listed in `response_headers` goes to the upstream request only), and there is no `forwardBody`.

## Bounds and safety

- **Memory.** Before connecting, podgate charges the tenant's buffer budget `max_response_bytes` plus a 48 KiB allowance (32 KiB for the request head, 8 KiB for the answer's head, 8 KiB of read buffers). A budget that is full right now answers `503` and nothing is dialled. A call that could never fit the tenant's whole `max_buffer_bytes` is refused at compile (`invalid_middleware`, naming the tenant, `needed_bytes` and `max_buffer_bytes`): with the default cap a tenant needs at least 112 KiB.
- **Time.** `timeout_secs` covers connect, request and answer.
- **Concurrency.** One permit of `max_concurrent` is held for the call. The count survives a snapshot push that leaves the middleware's declaration as it was.
- **Where.** Only the address in the configuration. The exact IP is checked against the upstream address policy on every call. The connection is never reused and a redirect is never followed.
- **Order.** The chain runs before a revision, a tenant slot or a backend permit is taken: a refused request costs the tenant no in-flight slot and reaches no backend. The auth call itself holds the budget charge and the permit above while it runs.

## Plan and explain

Removing the middleware shows in `POST /v1/snapshot/plan` as `forward_auth_removed`; copying fewer headers (a name or the regex dropped or changed) as `forward_auth_response_headers_removed`; a transport that stops verifying the auth service's certificate as `upstream_tls_verification_disabled`. Changing the address is not a loosening. Explain shows the address without its query string.

## With `cache`

A request into which this stage copied at least one header (an identity such as `X-User`) is a credentialed request: the `cache` stage bypasses it exactly as it does a request with `Authorization`, with no lookup and no store, and `Cache-Status` says `bypass`. The cache key does not hold the copied headers, so without this a page built for one user would be stored and served to the next. A request whose answer copied nothing (a gate with no `response_headers`, or an answer that leaves them out) is not credentialed and is cached normally. The stage still runs on a request that would have been a hit: the chain's request hooks run before the cache answers.
