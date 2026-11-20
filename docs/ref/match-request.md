# Header and query matchers

Four matcher leaves look at the request head: `header`, `header_regexp`, `query` and `query_regexp`. They sit in a router's `match` tree next to `host`, `path_prefix`, `method` and the combinators (`docs/architecture.md`, `### Routers and matchers`). Code: `src/router/matcher/{header,header_regexp,query,query_regexp}.rs`.

```json
{ "all": [
  { "host": "shop.test" },
  { "header": { "name": "X-Env", "value": "canary" } },
  { "query_regexp": { "name": "id", "regex": "^[0-9]+$" } }
] }
```

## Leaves

|Leaf|Fields|Matches when|
|---|---|---|
|`header`|`name`, `value?`|Some header called `name` has exactly `value`. Without `value`: the header is present, whatever its value.|
|`header_regexp`|`name`, `regex`|Some header called `name` has a value the regular expression matches.|
|`query`|`name`, `value?`|Some decoded query parameter called `name` has exactly `value`. Without `value`: the parameter is present (`?debug` and `?debug=` count).|
|`query_regexp`|`name`, `regex`|Some decoded value of the parameter `name` matches the regular expression.|

An argument that is not an object, a missing or empty `name`, a missing `regex`, a field that is not a string and any field other than the two listed are `422` `invalid_matcher`. So is a header name that is not a valid header name and a regular expression that does not compile or whose compiled form is over 1 MiB (the limit every matcher regexp has).

## Rules

- **Header names are case-insensitive**, header values and query names and values are case-sensitive.
- **Repeats match on any.** A header sent twice or a parameter repeated matches when any occurrence does. A header value is never split on commas; to look into a list (`Accept`, `Cookie`) write the regexp for it. A header value that is not UTF-8 matches no `header_regexp`.
- **Query decoding** follows `application/x-www-form-urlencoded`: `&` separates parameters, `+` is a space, `%XX` is decoded in names and values. A malformed escape (`%zz`) stays as written and is never an error, so a hostile query can only fail to match. The query is read from the request line as sent; the path is a separate matter (`path normalization`).
- **Regexps are unanchored**, like `host_regexp` and `path_regexp`: write `^` and `$` when you mean them. They use the Rust `regex` crate, so there is no backtracking and no ReDoS.
- **The request as the client sent it.** Routing runs before any middleware, so a header a `headers` middleware sets (or removes) later is invisible to these leaves, and a rewrite cannot change the route. A header that a client sends itself is believed, like every other client input: do not route security decisions on a header the client controls. `X-Forwarded-*` headers of an untrusted peer are already removed before routing (`docs/ref/client-ip.md`).
- **No host claim.** None of these leaves names a host. A router whose matcher uses only them is a catch-all and needs an exclusive entry point or `CATCH_ALL_TENANTS` (`catch_all_not_allowed`); next to a literal `host` in an `all` it just narrows.

## Order and ambiguity

Each of the four leaves counts as one constraint in a router's specificity (the "other constraints" count, next to `method` and `client_ip`), so on equal priority and host rank a router with a header or query constraint beats one with none. As for every leaf, an `all` takes the largest count of its children, not the sum: `all` of a header and a query counts as one, and two such routers that can overlap need different priorities.

For the ambiguity check, two `header` leaves with the same name (any case) and different values are disjoint, and so are two `query` leaves with the same name and different values. A request that carries both values (`x-env: a` and `x-env: b`, or `?tag=a&tag=b`) matches both routers; the router order, then the names, picks one, as for any two routers that overlap. A regexp, a presence-only leaf, or leaves of different names are never proved disjoint.

## Explain

`GET /v1/explain` lists, under `near_misses`, the routers that fit the request's host and entry point and fail on some other leaf, with the leaf:

```json
"near_misses": [
  { "app": "a", "router": "canary", "failed": ["header x-env = \"canary\""] }
]
```

The field is absent when there is none, and it appears on the `404` answer too, which is where it helps: the host is declared, so the request failed on the header, query or method. Leaves read `header <name> = "<value>"`, `header <name> is present`, `header_regexp <name> ~ "<regex>"`, and the same with a quoted name for `query`; other leaves are named by key (`method`, `path_prefix`, `client_ip`, `not`). Explain sends the headers it can build from its arguments, which are `Host` only, so a header leaf always shows as failing there; the `url` carries the query for the query leaves.

Matches Traefik `Header`, `HeaderRegexp`, `Query` and `QueryRegexp`, and Caddy `header`, `header_regexp` and `query`. No Caddy glob or `!` negation: wrap the leaf in `not`.
