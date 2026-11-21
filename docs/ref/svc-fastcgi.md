# The `fastcgi` service

A service of type `fastcgi` runs PHP, or any FastCGI application, through a PHP-FPM socket the
operator declared. It is Caddy's `php_fastcgi` and `reverse_proxy` with `transport fastcgi`;
Traefik has nothing like it. The script that runs is derived from an operator-declared code root,
never from the request, and the classic path-info and header tricks are closed.

```json
{ "name": "app", "type": "fastcgi", "upstream": "php",
  "index": "index.php",
  "split_path_info": true,
  "try_files": ["{path}", "{path}/index.php", "/index.php"],
  "extensions": [".php"],
  "deny": ["vendor", "uploads"],
  "env": { "APP_ENV": "production" },
  "max_request_body_bytes": 8388608 }
```

Every field except `upstream` is optional; the values above are the defaults, `deny` being
empty by default.

## One pool per tenant

PHP code runs with the rights of the PHP-FPM pool that executes it. podgate decides which file a
request runs; it cannot decide what that file may read. **Run one PHP-FPM pool per tenant, under
that tenant's own uid, and declare it only for that tenant.** One pool for two tenants lets the
code of one read the files of the other, however well podgate keeps the paths apart. Set
`cgi.fix_pathinfo = 0` in every pool as well: podgate never relies on PHP guessing a script from
a path, and a pool that does not guess has nothing to be tricked into.

## Where the application and the code are

An address and a directory are two things a snapshot must never choose, so they are **process
configuration**: `FASTCGI_FILE`, a JSON file read once at startup.

```json
{ "<tenant id>": { "<name>": {
    "address": "unix:/run/php/acme.sock",
    "root": "/srv/php/acme",
    "max_connections": 16,
    "dial_timeout_secs": 3,
    "read_timeout_secs": 30 } } }
```

- `address` is `unix:/absolute/path` or `host:port` (a name is looked up when the pool connects).
  `root` is an absolute directory. `max_connections` is 1 to 256 (default 16),
  `dial_timeout_secs` defaults to 3, `read_timeout_secs` to `REQUEST_TIMEOUT_SECS`. Another
  field, a tenant or name that is empty, a relative root, a root that is not a directory, an
  address of another shape or a limit out of range stops startup with
  `invalid FASTCGI_FILE: <file>: tenant "<id>" upstream "<name>": <reason>`.
- A service says `"upstream": "<name>"`. The name is resolved only among the entries of the
  app's own tenant: another tenant's name, an address, a path and an unknown name are all
  `unknown_fastcgi_upstream` (`422`). Any other field that is not listed here (`address`,
  `root`, `servers`, ...) is `invalid_service`. A snapshot therefore cannot send a request to
  another tenant's pool, point the application at another tenant's code, or make podgate dial an
  address of its choosing.
- Each root is opened once, at startup, as the same `cap-std` directory handle `static` services
  use (`docs/ref/svc-static.md`), and the same rules apply: no `..`, no symlink out, no hidden
  names. The roots of `fastcgi` and `static` are **separate declarations**: a directory a
  `static` service may serve never becomes executable because of that, and a code root is not
  reachable from a `static` service by a mistake in `STATIC_ROOTS_FILE`.
- The upstream address policy of change 0041 does **not** apply to these addresses: the operator
  wrote them, and a tenant cannot influence them.

## Which file runs

The request path is normalized (`router::path`; the chain's path rewrites apply) and
then used only as a key. Each `try_files` candidate, with `{path}` replaced by the request path,
is tried in order, relative to the root handle:

- A candidate that names a directory runs its `index`.
- With `split_path_info` (the default), a candidate such as `/app.php/orders/7` runs `/app.php`
  with `PATH_INFO` `/orders/7`. The script is the part up to the **first** segment that ends in
  an allowed extension, and that file must exist exactly there.
- A file runs only if it is a regular file whose name ends in one of `extensions` (default
  `.php`, case-sensitive) **and** whose real path (symlinks resolved) is under the root, still
  ends in an allowed extension and is not under a `deny` path. Everything else is skipped, and
  when no candidate runs the answer is `404`. The default list ends in `/index.php`, the front
  controller of most frameworks; a list that does not is a site that serves only the files it
  has.
- `index` must itself end in an allowed extension; `deny` entries are paths of plain names
  under the root (`vendor`, `uploads/private`) that never run, however they are named.

Nothing a client sends can name a file outside that rule:

| Request | What runs |
|---|---|
| `/uploads/evil.jpg/x.php` | looks for `x.php` inside the file `evil.jpg`, which cannot exist; with the default `try_files`, the index script runs and `evil.jpg` never does |
| `/uploads/evil.jpg` | not an allowed extension: skipped |
| `/up.php`, a symlink to `../secret.php` | `404`: the link leaves the root |
| `/alias.php`, a symlink to `note.txt` | `404`: the file it leads to may not run |
| `/.env`, `/.git/config` | `404`: hidden names never resolve |
| `/%2e%2e/x.php`, `/a%2f..%2fx.php` | `400`: refused by path normalization |

`SCRIPT_FILENAME` is the file's real path under the root, `SCRIPT_NAME` its URL path,
`DOCUMENT_ROOT` the real root and `PATH_INFO` the decoded remainder. PHP has nothing to guess,
which is why `cgi.fix_pathinfo = 0` is the right setting. There is **no `PATH_TRANSLATED`**:
with `cgi.fix_pathinfo = 0` PHP-FPM takes the script from it when `PATH_INFO` is set, and would
refuse `<root>/<path info>` as a script nobody asked for. An upload directory should be in `deny`
anyway: a user who can upload a file named `.php` there must not be able to run it.

The lookup runs on the blocking pool, once per request, before any connection to the application
is taken.

## Parameters

podgate sends `GATEWAY_INTERFACE`, `SERVER_SOFTWARE`, `SERVER_PROTOCOL`, `REQUEST_METHOD`,
`REQUEST_URI`, `QUERY_STRING`, `SCRIPT_*`, `DOCUMENT_*`, `PATH_*`, `SERVER_NAME`, `SERVER_PORT`,
`REMOTE_ADDR` (the client resolved by `docs/ref/client-ip.md`), `HTTPS=on` when the client's
connection is TLS (or a trusted peer said so), `CONTENT_TYPE` and `CONTENT_LENGTH`, then `HTTP_*`
from the request headers under these rules:

- **`Proxy` is dropped** (httpoxy): `HTTP_PROXY` is the variable many HTTP clients read as their
  proxy setting, and a header must not be able to set it.
- **An underscore in a name drops the header, and a name that collides drops both.** `X_Foo` and
  `X-Foo` both become `HTTP_X_FOO`, and the application could not tell which one it got, so
  neither is passed.
- A value with a NUL or another control character refuses the request with `400`.
- Repeated headers are joined with `, ` (`; ` for `Cookie`).
- The parameters in all are capped at 64 KiB; beyond that the request is refused with `431`.

`env` entries are added after these. A name matches `^[A-Z][A-Z0-9_]{0,63}$` and is none of the
variables podgate sets, none that starts with `HTTP_`, `SCRIPT_`, `PATH_`, `REQUEST_`,
`SERVER_`, `REMOTE_`, `CONTENT_`, `PHP_` or `LD_`, and none of `PHPRC`, `PATH`, `HOME`, `TMPDIR`,
`IFS`, `HTTPS`, `QUERY_STRING`, `DOCUMENT_ROOT`: a tenant must not set PHP's configuration
(`PHP_INI_SCAN_DIR`, `PHPRC`) or the loader's (`LD_PRELOAD`) through the environment. A bad name
is `invalid_service` at compile time. At most 32 entries; a value is at most 4096 bytes.

## Bodies

- A body with a known `Content-Length` is streamed to the application in `FCGI_STDIN` records of
  at most 64 KiB, as the client sends it. A length over `max_request_body_bytes` (default 8 MiB)
  is refused with `413` before anything is read; a client that sends more or fewer bytes than it
  declared gets `400`.
- A chunked body (or any body without a length) is **held whole** before the application is
  contacted, so a slow client never occupies a PHP worker: `CONTENT_LENGTH` is the length that
  was held. Every byte is charged to the tenant's `max_buffer_bytes` before it is stored (in
  steps of at least 64 KiB), a body over `max_request_body_bytes` is `413`, and one the budget
  cannot take is `503` with `retry-after: 1`. A client that takes more than 30 seconds to send
  it gets `408`.
- Every request charges 128 KiB, one request chunk and one response chunk, for as long as it
  runs. A tenant whose whole `max_buffer_bytes` is below that is refused at compile
  (`invalid_service`); one whose budget is merely full right now gets `503` with `retry-after: 1`.
- The body is sent before the response is read. An application that answers before it has read
  the whole body is read after the body is sent; one that closes early ends the request.

## The answer

The output is parsed as CGI: header lines, a blank line, the body.

- `Status: 404 Not Found` sets the status (200 to 599). With no `Status`, a `Location` makes it
  `302` and anything else `200`.
- Names and values are validated. A line without a colon, a name that is not a token, a folded
  line, a value with a control character, a status outside 200 to 599, more than 256 headers
  and a head over 64 KiB are all `502`, as is an answer with no head at all (an application that
  ended without output). Nothing of the body is sent then.
- Hop-by-hop and framing headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`,
  `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Content-Length`) are
  dropped; podgate frames the answer itself (chunked on HTTP/1.1, as HTTP/2 frames it). Repeated
  headers such as `Set-Cookie` are all passed.
- **`X-Sendfile` and `X-Accel-*` are dropped and never acted on.** Those headers ask a front
  server to read a file named by the application; podgate never does, and does not tell the
  client the application asked.
- The body is streamed in the records the application sent (at most 64 KiB each). The answer
  goes through the router's response middlewares (`headers`, compression, error pages) like a
  proxied one. A `HEAD` request gets the head only.
- `FCGI_STDERR` is logged at `warn` with the app and upstream names, at most 4 KiB per request.
- An application that stops in the middle of the body ends the client's connection: the head
  has been sent, so the failure cannot be reported with a status.

## Connections and limits

- One request per connection (no multiplexing). Every connection asks for `FCGI_KEEP_CONN`, so
  a request that ends cleanly leaves its connection idle for the next one, at most 10 seconds.
  PHP-FPM binds a worker to every open connection, idle ones included: keep `max_connections`
  at or below the pool's `pm.max_children`.
- At most `max_connections` sockets, in use and idle together. A request waits at most
  **1 second** for a free one, then answers `503` with `retry-after: 1`.
- `dial_timeout_secs` bounds the connect (`504` past it); an address that refuses the
  connection or a socket that is gone is `502`. The next request dials again, so an application
  that comes back is served without a new snapshot. `read_timeout_secs` bounds every wait for
  the application (a write of the body and a read of the answer): `504` past it.
- The request counts against the tenant's `max_inflight` like any other. A `fastcgi` service has
  no server: the access log shows none, and active health checks, outlier detection, retries
  and mirroring do not apply. It cannot be a child of `weighted` or `failover`, a mirror, or
  carry gRPC.

## Explain and posture

`GET /v1/explain` and `GET /v1/overview` show `fastcgi: {"upstream": "php", "index":
"index.php"}` for the service. The service has no posture: it adds no access beyond the declared
root.

## Not built

FastCGI authorizer and filter roles, multiplexed connections, `FCGI_ABORT_REQUEST` (podgate
closes the connection instead), `chroot`-style root mapping to the application's file system
(the root and the pool must see the same path), and per-request `PHP_VALUE` / `PHP_ADMIN_VALUE`
(a tenant must not set PHP's configuration; put it in the pool).

Settings: `FASTCGI_FILE`; see the configuration table in `docs/architecture.md`.
