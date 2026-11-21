# CEL expression matcher

The `cel` leaf matches a request with a [CEL](https://github.com/google/cel-spec) expression, for what the typed leaves cannot say. It sits in an HTTP router's `match` tree next to `host`, `path_prefix`, `header` and the combinators (`docs/architecture.md`, `### Routers and matchers`). Code: `src/router/matcher/cel.rs` and `src/router/matcher/cel/{parse,env,cost,value}.rs`.

```json
{ "all": [
  { "host": "shop.test" },
  { "cel": "request.method == 'GET' && request.headers['x-env'] == 'canary'" }
] }
```

The argument is the expression, or an object to raise the cost limit: `{"cel": {"expression": "...", "max_cost": 300}}`. Anything else, an empty expression, a `max_cost` outside 1 to 1000 and any other field are `422` `invalid_matcher`. It is a leaf of HTTP routers only; a TCP router has no request to read.

## Environment

Everything is read-only and a pure function of one request. There is no clock, no randomness and no I/O, and no way to name a function that is not listed here.

|Name|Type|Value|
|---|---|---|
|`request.method`|string|The method, as sent.|
|`request.host`|string|The normalized host: lower-case, no port.|
|`request.path`|string|The normalized path (`path normalization`), without the query.|
|`request.query`|map(string, string)|The first decoded value of each query parameter, as `query` reads them.|
|`request.headers`|map(string, string)|The first value of each header, by lower-case name. A value that is not UTF-8 is absent.|
|`request.scheme`|string|`https` when the connection is TLS, else `http`.|
|`request.client_ip`|string|The resolved client address, after the forwarded-header trust of `docs/ref/client-ip.md`; `""` when it is not known.|
|`entry_point`|string|The entry point the request arrived on.|
|`tls.sni`|string|The server name the TLS handshake carried; `""` without TLS or without a name.|
|`tls.version`|string|The negotiated version as the TLS stack names it (`TLSv1.3`); `""` without TLS.|

`GET /v1/explain` has no handshake, so there `tls.sni` and `tls.version` are `""` and `request.headers` holds only `host`.

Operators: `|| && ! == != < <= > >= in + - * / % ?:`, indexing (`request.headers['x']`), selecting a map key (`request.query.debug`), and list literals. Integers are 64 bit and checked: an overflow or a division by zero is an evaluation error. `+` joins strings. `<` and friends compare two integers or two strings. Strings are compared by code point.

Functions and methods:

|Call|Meaning|
|---|---|
|`size(x)`, `x.size()`|Code points of a string, elements of a list, entries of a map.|
|`has(m.key)`|Whether the map has the key: `has(request.headers.etag)`. Take a dashed name with `'etag' in request.headers`.|
|`k in m`, `x in list`|Map key or list membership.|
|`s.startsWith(p)`, `s.endsWith(p)`, `s.contains(p)`|String scans.|
|`s.matches('re')`, `matches(s, 're')`|Unanchored Rust `regex` match. The pattern is a string literal compiled with the snapshot, under the 1 MiB limit of every matcher regexp.|
|`ip(s)`|Parses an address. `ip(request.client_ip)` is the client.|
|`cidr('10.0.0.0/8')`|A block; a bare address is a block of one. The argument is a literal.|
|`a.in_cidr('10.0.0.0/8')`, `a.in_cidr(cidr(...))`|Whether the address is in the block; an IPv4-mapped IPv6 address counts as its IPv4 address.|

Not available: `now`, `timestamp`, `duration` and the time accessors, floating point, unsigned integers, `null`, bytes, map and message literals, `string()`, `int()`, and the comprehension macros `all`, `exists`, `exists_one`, `map` and `filter`. Each is refused when the snapshot is compiled (an undeclared reference, or `cel_comprehension`).

The expression is type-checked: there is no dynamic type, so `request.method == 1` is a compile error and not a surprise at request time.

## Sandbox and cost

- **Size.** At most 2048 bytes of source. A deeper nesting than 32 is refused.
- **Compile-time rejection.** A syntax error, a type error, an unknown name or function, a comprehension, a `matches` pattern or `cidr` block that is not a literal (or does not compile) is `422` `invalid_matcher` whose message starts `cel:` and names the column.
- **Static cost.** There are no loops and no recursion, so evaluation visits each node once and the cost of the tree is a real bound. Each node costs 1. A `contains`, `matches`, `size` of a string or string `+` also costs one per 256 bytes of the longest string it can read (8192 for anything from the request); `matches` adds one per 32 characters of the pattern, and `x in [list]` one per element. Both branches of `&&`, `||` and `?:` are charged. The total must not exceed `max_cost`, default 100 and at most 1000, else `invalid_matcher` with `cel_cost_exceeded` in the message. `request.headers['x'] == 'a'` costs 5; one `matches` on a header costs about 37.
- **Input bounds at run time.** A request string longer than 8192 bytes (a header value, the path, the host, the SNI, a query) makes the evaluation an error. `request.headers` is readable only when the request has at most 100 header lines (`host` included), and a name with an upper-case letter is never in it. `request.query` is readable only when the query is at most 8192 bytes. A string built with `+` is at most 64 KiB. The inputs are read in place: a header value or the path is never copied, a map is a lookup into the request's headers or query, and an evaluation allocates only what the expression itself produces (a list literal, a joined string, the text of the client address). Nothing is built per request for a leaf, so there is nothing to share between leaves.
- **Regular expressions** are the Rust `regex` crate: linear time, no backtracking.

## Errors at run time

An evaluation that fails is a non-match, never a response error. The failures are a missing key read without `has` (`request.headers['x-env']` on a request without it), a list index out of range, a request input over its bound, a `request.client_ip` that is not known when `ip(request.client_ip)` is read, `ip()` of text that is not an address, an integer overflow or a division by zero. CEL's own error rule holds: `false && <error>` is `false` and `true || <error>` is `true` in either order, so `request.method == 'GET' || request.headers['x'] == 'a'` matches a GET without the header. Each evaluation that ends in an error counts in `podgate_cel_errors_total{app}` (the app that owns the router; the counter belongs to the process and survives a snapshot push, and it is listed for every app of the live table that has had a `cel` leaf). `GET /v1/explain` evaluates leaves too, so what it evaluates counts.

## Routing rules

- **No host claim.** A `cel` leaf claims no host, so an expression can never take or widen a host claim: `host_conflict`, `cross_tenant_wildcard` and the fallback rules see only the `host`, `host_regexp` leaves. A router whose only constraint is a `cel` leaf (or whose host is under an `any` with one, or a `not`) is a catch-all router: `catch_all_not_allowed` unless its entry point is exclusive to the tenant or the tenant is in `CATCH_ALL_TENANTS`. Write `{"host": ...}` next to it.
- **Specificity.** A `cel` leaf counts as one constraint, however long the expression: the "other constraints" count that `method`, `header`, `query` and `client_ip` share. On equal priority and host rank a router with a `cel` leaf beats one with none; as for every leaf, an `all` takes the largest count of its children.
- **Ambiguity.** Two expressions are never provably disjoint, so two routers of one tenant with `cel` leaves that share a host and priority are `route_ambiguity`; give them different priorities.
- **The request as the client sent it.** Like the other request leaves it reads the request before any middleware runs: a header a `headers` middleware sets later is invisible, and a rewrite cannot change the route. A header the client sends itself is believed; `x-forwarded-*` headers of an untrusted peer are already gone (`docs/ref/client-ip.md`).

## Explain

`near_misses` shows the expression of a `cel` leaf that failed:

```json
"near_misses": [
  { "app": "a", "router": "canary", "failed": ["cel request.method == 'POST' && request.headers['x-env'] == 'canary'"] }
]
```

A leaf that errored is shown the same way, since an error is a non-match. Explain builds a request with `Host` only, so a header read fails there.

## Compared with Caddy and Traefik

Matches Caddy's `expression` matcher, which is CEL; the environment differs. Caddy writes `{http.request.host}` placeholders and offers a larger library, and its expressions are not bounded in cost. Here the environment is the table above, the cost is checked at compile, and an evaluation error is a non-match. Traefik has no equivalent. Deliberate: no clock and no I/O, so a route is a pure function of the request and explain can always say why.
