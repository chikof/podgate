# Middlewares `errors` and `respond`

Reference for the kinds in `src/middleware/errors.rs` (with its page fetcher in `src/middleware/errors/fetch.rs`) and `src/middleware/respond.rs`. The model they plug into is in `docs/architecture.md` (`### Middlewares`, rule 4).

## `errors`

Replaces an error response with a page served by another service of the same app. Traefik's `errors`, with a smaller request: the page server gets no credentials.

```json
{
  "name": "pages",
  "type": "errors",
  "status": ["500-599", "404"],
  "service": "pages",
  "query": "/{status}.html",
  "max_body_bytes": 262144,
  "timeout_secs": 3
}
```

| Field | Meaning |
|---|---|
| `status` | Required, 1 to 32 entries: a code (`404` or `"404"`) or a range (`"500-599"`). Every code must be in `400..=599`; anything else is `invalid_middleware`. |
| `service` | Required. A service of the revision the request was sent to (the revision's own, else the app's), or `name@revision` for a service of that revision. Resolved when the snapshot compiles: a name no live revision can resolve is `unknown_service`, the same rule as a router's service. |
| `query` | The request path of the page. Default `/{status}.html`. Must start with one `/`, be printable ASCII without `#`, at most 256 bytes. `{status}` is replaced by the three digits of the status. Any other `{` or `}` is `invalid_middleware`: no other request data is ever interpolated. A `?query` part is allowed and sent as written. |
| `max_body_bytes` | The cap of the page body. Default 262144 (256 KiB), at most 1048576 (1 MiB). |
| `timeout_secs` | One bound for connecting, sending and reading the page. Default 3, at most 30. |

### What is replaced

A response that passes through the middleware on its way out and has a listed status:

- a response the upstream sent, whatever its body (even none);
- an error podgate made after it chose a revision and a server (`502` when the connection is refused, reset or times out, the policy refuses the address, ...).

Not replaced: an answer an earlier middleware gave (a `basic_auth` `401`, an `ip_allow_list` `403`, a `respond`), anything podgate answers before a revision is chosen (no route, no serving revision, tenant and backend admission refusals) and every `HEAD` response. When two `errors` stages are in a chain, the one nearest the end of the chain is asked first, and only one page is fetched per request.

The page is written with the status of the response it replaces. Its headers are `Content-Type` (the page server's, when it sent one), `Content-Length`, the cookies podgate itself sets (session pinning, sticky servers) and whatever the chain's response hooks (`headers`) add. The original response's headers are dropped: its `Set-Cookie`, `Location`, `Retry-After` and every other header do not reach the client. The response ends the downstream connection's reuse, like any error podgate writes.

### The page request

podgate connects to a server of the named service picked by the service's own balancer (unhealthy and ejected servers are skipped), through the service's transport (`https://` servers use their CA, SNI and client certificate), and sends

```
GET <query with {status}> HTTP/1.1
Host: <the host the client asked for>
Accept: <the client's Accept, else */*>

```

and nothing else: no `Authorization`, `Cookie`, forwarding header or any other header of the client's request, and no part of its path or query. The client's `Accept` is passed only when it is at most 256 printable ASCII bytes. Traefik's error service receives the request's original headers; podgate's does not, so a tenant's page server never sees credentials.

The answer is used only when it is `200..=299` (not `204` or `205`), has a body of at least one byte and at most `max_body_bytes`, is not content-encoded and is well formed HTTP/1.x with `Content-Length`, chunked or close-delimited framing. Anything else (a connection error, a timeout, `404`, `500`, a redirect, an over-cap body) leaves the original response as it was. A failed fetch is not retried and not logged above debug level.

### Bounds and safety

- **Memory.** Before connecting, podgate charges the tenant's buffer budget `max_body_bytes` plus a 16 KiB allowance for the head and read buffers (`TenantBudget::charge`). A tenant that cannot pay keeps the original response and nothing is dialled. The charge is released when the page has been written. With the default cap a tenant needs at least 272 KiB of `max_buffer_bytes` to get any page; tenants with small budgets lower `max_body_bytes`.
- **Time.** `timeout_secs` covers the connect, the request and the whole answer.
- **Where.** Only servers of the app's declared services. Every fetch checks the exact IP it is about to dial against the upstream address policy (`docs/ref/upstream-policy.md`), counted in `podgate_upstream_refused_total{tenant}`; a refused address means no page. The compiler already refuses literal addresses outside the policy (`upstream_forbidden`).
- **Loops.** One request tries one page, once. The fetch is a direct connection and never runs the middleware chain again, and a flag in the request context (not a header) stops the page from being fetched twice for one request, whatever fails. A page server that answers an error is therefore never replaced by a page of its own. If an operator allows podgate's own proxy address in the upstream policy and a service points at it, the fetch re-enters podgate as an ordinary request; the tenant's budget charge and the timeout bound that, and the policy should deny podgate's listeners (`deny_extra`).
- **Posture.** Removing or weakening `errors` changes no security property, so it is not a `posture_changes` entry.

Explain and the overview show `status`, `service`, the path of `query` (without any `?` part), `max_body_bytes` and `timeout_secs`.

## `respond`

Answers the request with a fixed response and ends it: Caddy's `respond`, and the building block of closed routes. It never contacts an upstream and runs before any tenant slot is taken.

```json
{
  "name": "closed",
  "type": "respond",
  "status": 403,
  "headers": { "content-type": "text/plain; charset=utf-8" },
  "body": "closed"
}
```

| Field | Meaning |
|---|---|
| `status` | Required, `200..=599`. `1xx` is `invalid_middleware`: a `1xx` is an interim response and cannot end a request (`101` would need an upgrade). `204`, `205` and `304` may not have a body. |
| `headers` | Optional map. Names are valid header names (case-insensitive, no duplicates), values 1 to 8192 ASCII bytes without line breaks or other control characters (so a value cannot inject a header). At most 64. The headers that frame the message or belong to the connection (`Content-Length`, `Transfer-Encoding`, `Connection`, `Host`, `Upgrade`, `TE`, `Trailer`, `Keep-Alive`, `Proxy-*`, pseudo headers) cannot be set: `Content-Length` is always the length of `body`. |
| `body` | Optional text, at most 65536 bytes (it may hold line breaks). A body without a `content-type` header is `text/plain; charset=utf-8`. |

A `HEAD` request gets the headers, the length of the body and no body. Everything is checked when the snapshot compiles; any problem is `invalid_middleware`.

A closed route is a router that matches the paths to close, with `respond` in its chain, in front of an open router:

```json
{ "name": "closed",
  "match": { "all": [ { "host": "a.test" }, { "not": { "path_prefix": "/public" } } ] },
  "chain": ["closed"], "service": "web" }
```

The overview and explain show the status, the header names and the length of the body, never a header value or the body.
