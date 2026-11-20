# Middlewares `headers` and `content_type`

Reference for the two kinds in `src/middleware/headers.rs` and `src/middleware/content_type.rs`. The model they plug into is in `docs/architecture.md` (`### Middlewares`).

## `headers`

```json
{
  "name": "web-headers",
  "type": "headers",
  "request":  { "set": { "x-tenant": "acme" }, "remove": ["x-debug"] },
  "response": {
    "set": { "x-served-by": "podgate" },
    "remove": ["x-powered-by"],
    "security": {
      "hsts": { "max_age_secs": 31536000, "include_subdomains": true, "preload": false },
      "csp": "default-src 'self'",
      "csp_report_only": "default-src 'none'; report-uri /csp",
      "frame_options": "DENY",
      "content_type_nosniff": true,
      "referrer_policy": "no-referrer",
      "permissions_policy": "camera=()",
      "cross_origin_opener_policy": "same-origin",
      "cross_origin_resource_policy": "same-site"
    }
  },
  "cors": {
    "allow_origins": ["https://app.example.com"],
    "allow_origin_regexes": ["https://[a-z0-9]+\\.preview\\.example\\.com"],
    "allow_methods": ["GET", "POST"],
    "allow_headers": ["content-type", "x-token"],
    "expose_headers": ["x-request-id"],
    "allow_credentials": true,
    "max_age_secs": 600,
    "add_vary": true
  }
}
```

Every field is optional. Unknown fields are `invalid_middleware`.

### Edits

- `request.set` and `response.set` overwrite: whatever value the client or the upstream sent for that name is replaced, never appended to. Names are case-insensitive and may appear once per direction.
- `remove` runs before `set`. A name in both is `invalid_middleware`.
- `request` edits run when the chain runs, so a later middleware sees the edited request and the upstream receives it. `response` edits run on the upstream's response head, in reverse chain order. A response that podgate or another middleware writes itself (an error, a redirect, a refusal) does not pass through them; the CORS preflight answer below carries its own headers.
- An empty value is `invalid_middleware`. Traefik removes the header for an empty value; here removal is only `remove`.

### What cannot be set or removed

`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `HTTP2-Settings`, every `Proxy-*` header and every `:` pseudo header, in `set` and in `remove`, in both directions. They decide how a message is framed or which connection carries it; a tenant that could change them could desynchronize podgate and its upstream (request smuggling, response splitting). The list is closed on purpose: it names what is refused, so a header added to HTTP later is not silently allowed by being forgotten from an allow list.

Names must be HTTP tokens. Values must be non-empty ASCII without control characters; a CR, LF or NUL in a name or value is refused when the snapshot compiles, so a value can never carry a second header or a body.

### Security headers

| Field | Header |
|---|---|
| `hsts {max_age_secs, include_subdomains, preload}` | `Strict-Transport-Security`, **only on responses to TLS connections** |
| `csp` | `Content-Security-Policy` |
| `csp_report_only` | `Content-Security-Policy-Report-Only` |
| `frame_options` | `X-Frame-Options` |
| `content_type_nosniff: true` | `X-Content-Type-Options: nosniff` |
| `referrer_policy` | `Referrer-Policy` |
| `permissions_policy` | `Permissions-Policy` |
| `cross_origin_opener_policy` | `Cross-Origin-Opener-Policy` |
| `cross_origin_resource_policy` | `Cross-Origin-Resource-Policy` |

A field that is absent adds nothing. A configured header overwrites the upstream's value. `response.set` and `response.remove` may not name a header that `security` or `cors` writes (`invalid_middleware`): the intent would be ambiguous. HSTS is not added over plain HTTP (Traefik needs `forceSTSHeader` for that; browsers ignore HSTS received over HTTP, so podgate has no such switch). The obsolete `X-XSS-Protection` option does not exist.

### CORS

- `allow_origins` lists exact origins, `scheme://host[:port]` with scheme `http` or `https`, no path (`https://a.test/` is `invalid_middleware`). Comparison is case-insensitive on the whole origin, so `https://a.test` does not match `https://a.test:8443` or `http://a.test`. The entry `*` allows any origin.
- `allow_origin_regexes` are regular expressions that must match the **whole** origin (podgate anchors them; Traefik's are unanchored). An origin they match is echoed back in `Access-Control-Allow-Origin`.
- An origin that matches nothing gets **no** CORS headers at all. podgate never reflects the `Origin` of a request it did not match, and never copies `Access-Control-Request-Headers` into the answer. With `*` the answer is the literal `*`.
- A request with more than one `Origin` header is treated as having none.
- `allow_credentials: true` together with `*` is `invalid_middleware`: browsers reject that pair, and echoing the origin instead would turn the policy into a bypass. List the origins. A regular expression with credentials is the tenant's responsibility: `.*` allows every site to make credentialed requests.
- A **preflight** (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) from an allowed origin is answered by the middleware with `204`, `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Allow-Credentials`, `Access-Control-Max-Age` (each only when configured) and `Vary: Origin`. It never reaches the upstream, so place the middleware before authentication in the chain. A preflight from any other origin passes on like a normal request.
- An actual request from an allowed origin gets `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` and `Access-Control-Expose-Headers` on the upstream's response.
- `add_vary` (default `true`, unlike Traefik) adds `Vary: Origin` to every response when the answer depends on the origin (that is, unless `*` is configured), including responses to requests that sent no `Origin` or a disallowed one, so a shared cache cannot hand one origin's answer to another. An existing `Vary` is kept and `Origin` appended once.

### Plan and posture

`POST /v1/snapshot/plan` lists these under `posture_changes` for a host that exists on both sides:

| Kind | When |
|---|---|
| `hsts_removed`, `hsts_weakened` | HSTS gone; a smaller `max_age_secs`, or `include_subdomains` or `preload` dropped |
| `csp_removed`, `csp_changed` | `csp` gone, or changed (a policy can be compared, not ranked) |
| `frame_options_removed`, `frame_options_changed` | likewise for `frame_options` |
| `nosniff_removed` | `content_type_nosniff` no longer true |
| `cors_widened` | a new origin or regular expression, credentials turned on, or CORS added |

Removing the middleware from the chain lists the `*_removed` kinds of what it had set. Narrowing CORS and tightening headers list nothing.

### Explain

`GET /v1/explain` shows, for the stage, the names of the headers it sets and removes in each direction, the security headers it writes, and the CORS origins. Header values are not shown: they may carry secrets.

## `content_type`

```json
{ "name": "no-sniff", "type": "content_type", "auto_detect": false }
```

Traefik's `contentType`. Pingora never guesses a content type, so a response without `Content-Type` stays without one, and the default `auto_detect: false` is what podgate always does. `auto_detect: true` is `unsupported_setting` (sniffing is a vulnerability class, and a setting podgate cannot honour is never ignored). The kind has no hook; it exists so configurations that declare it migrate and so a sniffing request is refused loudly. To tell browsers not to sniff either, use `headers` with `content_type_nosniff: true`.
