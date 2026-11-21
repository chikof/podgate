# Dashboard

Reference for `src/dashboard.rs` and `dashboard/`. A read-only web UI that shows what podgate is serving and answers "why does this URL go where it goes". It is off unless `DASHBOARD_ADDR` is set. Matches Traefik's dashboard (`api.dashboard`, served on the `traefik` entry point); Caddy has none. The deliberate differences are that it is read-only by construction, off by default, and that nothing it can show contains a secret (`docs/ref/overview.md`, `## What is never shown`).

|Setting|Meaning|
|---|---|
|`DASHBOARD_ADDR`|A TCP address, such as `127.0.0.1:9200`. Unset: no dashboard. Never read from a snapshot, so a tenant cannot open a port.|
|`DASHBOARD_AUTH_FILE`|An htpasswd file, one `user:hash` per line, blank lines and `#` comments skipped. Hashes are bcrypt or argon2 with the limits of `basic_auth` (`docs/ref/mw-basic-auth.md`): MD5, SHA1, crypt and plaintext entries stop startup. Required when the address is not loopback.|
|`DASHBOARD_HOSTS`|Comma separated host names the `Host` header may carry besides the bound address, such as `dash.example`. See [Host check](#host-check). Not part of the spec's two settings, added because the recommended setup below needs it.|

## What it serves

A second TCP listener, like `METRICS_ADDR` (`docs/ref/metrics.md`), because a browser cannot reach the admin unix socket. The admin socket stays unreachable: the dashboard runs the admin endpoints' own code in the same process, on the same state, so there is no network hop and no way to reach any other admin route.

|Request|Answer|
|---|---|
|`GET /`, `GET /app.js`, `GET /style.css`, `GET /favicon.svg`|The embedded assets.|
|`GET /api/overview`|`GET /v1/overview` of the admin API, byte for byte: same parameters (`section`, `tenant`, `app`, `limit`, `after`), same bounds, same `400` and `503`.|
|`GET /api/explain?url=...`|`GET /v1/explain` of the admin API, byte for byte.|
|`POST /api/explain`|The same question as a JSON body `{"url": "...", "method": "GET", "entry_point": "web", "client_ip": "203.0.113.7"}`; only `url` is required. Unknown fields are `400`. It reads the table and changes nothing; it exists for URLs a query string handles badly and so the URL stays out of logs that record query strings.|
|any other path|`404 {"error": "not found"}`, whatever the method.|
|another method on a path above|`405 {"error": "method not allowed"}` with `allow: GET` (`GET, POST` for `/api/explain`). `HEAD` and `OPTIONS` are included.|

Not served here, ever: `/v1/events` (it carries certificate private keys), failed-request records, the snapshot, the plan and validate endpoints, the purge endpoint, the metrics, `/healthz` and `/readyz`. They are not routes, so they answer `404`; no page can show them because they do not exist on this listener.

`POST /api/explain` takes at most 16 KiB (`413` above) and only `application/json` (`400` otherwise). Parsing, validation and answers are the admin endpoint's: the handler is the same function.

At most 4 API requests (overview and explain together) run at once; a fifth gets `503 {"error": "dashboard is busy"}` with `retry-after: 1`. That is half the admin API's cap of 8 overview computations, so a busy browser cannot take every slot. Each request ends with `408` after `REQUEST_TIMEOUT_SECS`.

## Access control

Two gates run before anything is routed, read or hashed, in this order, so an unauthenticated client learns nothing, not even which paths exist.

### Host check

The `Host` header must be one of:

- a literal of the bound IP (`127.0.0.1`, or `[::1]` in brackets); when the bind is a wildcard address (`0.0.0.0`, `[::]`) any IP literal passes, because DNS rebinding needs a name;
- `localhost`, when the bind is loopback or a wildcard;
- a name listed in `DASHBOARD_HOSTS`.

Names are compared lowercase without a trailing dot. The port is not compared: a published container port or a proxy may differ, and rebinding changes the name, not the port. A missing `Host`, a `Host` with userinfo (`a@b`), and everything else is refused with `421 Misdirected Request` (the answer podgate gives for a mismatched TLS request, `docs/ref/entry-policy.md`; `403` would also do). This is what stops DNS rebinding: a page on `evil.test` that re-resolves its name to `127.0.0.1` reaches the loopback dashboard with `Host: evil.test` and gets `421`, so it can read nothing.

### Credentials

With `DASHBOARD_AUTH_FILE`, every request needs HTTP Basic credentials of a listed user, `401` with `www-authenticate: Basic realm="podgate dashboard"` otherwise. The check is the `basic_auth` middleware's own code (`Htpasswd` in `src/middleware/basic_auth.rs`), so the guarantees are the same ones:

- bcrypt cost at most 14, argon2 memory at most 64 MiB, time and lanes at most 4, checked when the file is read;
- hashing runs on a bounded pool of at most 4 workers (fewer when `BASIC_AUTH_MAX_CONCURRENT` is lower; the dashboard has its own pool, so it cannot take a tenant's workers) and waits at most a second for one, then `503` with `retry-after: 1`;
- a source with five failed attempts in a minute waits a second before each further attempt is verified (an IPv6 source counts by its `/64`);
- an unknown user costs one hash verification, so timing does not say which users exist;
- a verified credential is remembered for 30 seconds under a keyed hash.

The source is the TCP peer of the dashboard connection. Forwarding headers are never read: the dashboard has no proxy to trust.

### Startup rules

| Settings | Result |
|---|---|
| `DASHBOARD_ADDR` loopback (`127.0.0.0/8`, `::1`), no file | Serves without credentials. |
| `DASHBOARD_ADDR` not loopback, no file | Startup stops: `invalid DASHBOARD_ADDR: <addr> is not a loopback address, so DASHBOARD_AUTH_FILE is required ...`. |
| `DASHBOARD_AUTH_FILE` unreadable, empty or holding a weak hash | Startup stops naming `DASHBOARD_AUTH_FILE` and the user, never the hash. |
| `DASHBOARD_AUTH_FILE` or `DASHBOARD_HOSTS` without `DASHBOARD_ADDR` | Startup stops: a setting for something that is off is a mistake. |

### Plain HTTP

The dashboard listens on plain HTTP. HTTP Basic sends the password in clear, so a non-loopback dashboard with credentials is only as private as the network between the browser and podgate. A dashboard bound beyond loopback logs, at startup, `the dashboard listens beyond loopback over plain HTTP, so Basic credentials travel in clear; ...`. A non-loopback dashboard should sit behind podgate's own TLS entry point.

## Recommended setup

Leave the dashboard on loopback and expose it through podgate itself, as an app of an operator tenant:

```
DASHBOARD_ADDR=127.0.0.1:9200
DASHBOARD_HOSTS=dash.example
```

```json
{
  "id": "dashboard", "tenant": "ops", "declared_by": "ops",
  "tls": { "mode": "acme" },
  "middlewares": [
    { "name": "office", "type": "ip_allow_list", "source_range": ["203.0.113.0/24"] },
    { "name": "sso", "type": "forward_auth", "address": "http://127.0.0.1:4180/verify" }
  ],
  "routers": [{ "name": "dash", "match": { "host": "dash.example" }, "chain": ["office", "sso"], "service": "dash" }],
  "revisions": [{ "id": "r1", "state": "serving", "weight": 100,
    "services": [{ "name": "dash", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:9200" }] }] }]
}
```

TLS, the IP allow list and single sign-on (`forward_auth` or `jwt_auth`) then apply as they do to any app. Two things follow from podgate's own rules.

- podgate passes the client's `Host` through to the upstream, so the dashboard has to accept `dash.example`: that is `DASHBOARD_HOSTS`.
- The upstream address policy denies loopback by default (`docs/ref/upstream-policy.md`), and a deny range beats an allow range. To let this one tenant dial it, the operator replaces the built-in `deny` list (keeping the metadata and link-local ranges) and restricts every other tenant with an `allow` list, so loopback is reachable by `ops` only:

```json
{
  "deny": ["0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8", "100.100.100.200/32", "192.0.0.192/32", "fd00:ec2::254/128"],
  "default": { "allow": ["10.0.0.0/8"] },
  "tenants": { "ops": { "allow": ["127.0.0.1/32"] } }
}
```

The alternative that needs no policy change is to bind the dashboard to a private address of the node with `DASHBOARD_AUTH_FILE`, and accept plain HTTP on that network.

## Browser hardening

Every answer, including `401`, `404`, `405`, `421` and a timeout, carries:

|Header|Value|
|---|---|
|`Content-Security-Policy`|`default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`|
|`X-Content-Type-Options`|`nosniff`|
|`Referrer-Policy`|`no-referrer`|
|`Cache-Control`|`no-store` on every answer but the assets, which get `no-cache`.|

The dashboard sets no cookie. The page has no inline script, no inline style, no event handler attribute and no `style` attribute, and loads nothing from another origin: no third-party JavaScript, CSS, font or image. All text from the API is inserted with `textContent` (text nodes), never `innerHTML`, so a router name, a host or a header name chosen by a tenant cannot inject markup. The tests below fail when `index.html` gets an inline script or handler, when `app.js` uses an HTML-parsing API, and when any asset names an `http(s)://` URL (the SVG namespace of `favicon.svg` is the one identifier excepted).

## Assets

`dashboard/` holds `index.html`, `app.js` (plain ES modules, no build step, no npm), `style.css` and `favicon.svg`. They are compiled into the binary with `include_bytes!` (`ASSETS` in `src/dashboard.rs`), so the UI always matches the API of the same build and needs no directory at run time. `GET /` is `index.html`; the others are served at their own name and nowhere else. Serving them through the `static` service was rejected for that reason; an operator who wants their own UI can call `GET /v1/overview` directly.

## Pages

The address bar fragment picks the page; the page refreshes every 5 seconds, and the Pause button stops it.

|Page|Shows|
|---|---|
|Summary|Snapshot version, when it was applied, the writer, boot id, counts, servers by `healthy`, `unhealthy` and `ejected`, the entry points, the tenants with their live in-flight and buffer use against their budgets.|
|Apps and routes|Search by app, host, router or service; filter by tenant. Per app: declaring source, TLS, domain fronting, scale to zero, canary, revisions with state and weights, routers with matcher, entry points and chain, middlewares with what they describe about themselves, recent requests and 5xx.|
|Services and servers|One row per server: state (available, unavailable, unhealthy, ejected with the time left), in-flight requests, weight; a filter for servers that are not available.|
|Certificates|Soonest expiry first, with days left (a warning under 14 days), issuer and whether the ACME issuer renews it.|
|Explain|A form for URL, method, entry point and client address, posted to `/api/explain`: the matched router, the routers it shadows, near misses, revisions with effective weights and servers, and the pipeline in order. Explain takes no request headers, so a router that matches on a header shows as failing, as on the admin endpoint (`docs/ref/match-request.md`).|

The Apps page follows `next` through the overview's pages so a large fleet shows in full; an app too large for one answer shows as a stub, as the overview has it.

Screenshots of a running daemon with a sample snapshot (three apps, two tenants, one unhealthy server, two certificates), taken with a headless browser against the embedded assets: `docs/ref/dashboard/summary.png`, `docs/ref/dashboard/apps.png`, `docs/ref/dashboard/explain.png`, `docs/ref/dashboard/services.png` and `docs/ref/dashboard/certificates.png`.

## Tests

`tests/dashboard.rs`: `dashboard_off_by_default`, `dashboard_serves_assets_and_apis`, `dashboard_never_serves_events`, `dashboard_only_read_routes`, `dashboard_rejects_non_get`, `dashboard_non_loopback_requires_auth`, `dashboard_basic_auth_and_throttle`, `dashboard_security_headers`, `dashboard_host_check`, `dashboard_no_inline_script`, `dashboard_overview_equals_admin`, `dashboard_explain_equals_admin`, `dashboard_assets_embedded_match_files`, `dashboard_no_external_references`.

## Against Traefik and Caddy

| | Traefik | Caddy | podgate |
|---|---|---|---|
| Dashboard | `api.dashboard`, on the `traefik` entry point | none | `DASHBOARD_ADDR`, its own listener |
| Writable | no | | no, and no route that could be |
| Off by default | `insecure` mode exposes it and is discouraged | | yes |
| Authentication | a router with middlewares in front of `api@internal` | | `DASHBOARD_AUTH_FILE` (bcrypt or argon2, bounded cost, throttled), or podgate's own middlewares in front |
| Secrets on screen | shown as configured | | never shown (`docs/ref/overview.md`) |
| DNS rebinding | no `Host` check | | `Host` check, `421` |
