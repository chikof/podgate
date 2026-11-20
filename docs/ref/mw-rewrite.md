# Path rewrite middlewares

Reference for the five kinds `add_prefix`, `strip_prefix`, `strip_prefix_regex`, `replace_path` and `replace_path_regex` (`src/middleware/{add_prefix,strip_prefix,strip_prefix_regex,replace_path,replace_path_regex}.rs`, shared code in `src/middleware/path_rewrite.rs`). The model they plug into is in `docs/architecture.md` (`### Middlewares`).

```json
{ "name": "api",   "type": "add_prefix",         "prefix": "/api" }
{ "name": "no-v1", "type": "strip_prefix",       "prefixes": ["/api", "/v1"] }
{ "name": "no-t",  "type": "strip_prefix_regex", "regexes": ["^/t-[a-z0-9]+"] }
{ "name": "index", "type": "replace_path",       "path": "/index.html" }
{ "name": "v1",    "type": "replace_path_regex", "regex": "^/api/(.*)", "replacement": "/v1/$1" }
```

Unknown fields, and every other problem in the configuration, are `invalid_middleware`.

## What a rewrite changes

- Only the request that goes to the upstream. Routing, every matcher, the SNI check and the failure capture saw the original path. A rewritten path that looks like another router's path does not move the request to that router.
- The query string is kept as it is.
- Each rewrite sees the path the previous middleware in the chain left (the chain is the app's `default_chain`, then the router's `chain`).
- A request target that is not an absolute path (`OPTIONS *`) is left alone by every rewrite.

## Every result is normalized again

Whatever a rewrite computes goes through the function the entry point used before routing (`src/router/path.rs`), so the path that was authorised is the path that is served:

- dot segments are resolved (`/base/../a` is `/a`) and empty segments collapse;
- a result that starts with `//` collapses to one slash, so a rewrite can never produce an authority-form target such as `//evil.test/x`;
- a result without a leading slash gets one, and an empty result is `/`;
- unreserved escapes are decoded and other escapes get uppercase hex, as at the entry point.

A result that cannot be a safe path fails the request with `500` and a log line naming the kind and the middleware (`path rewrite refused, answering 500`); the request is never forwarded and the client sees no cause. That covers an encoded slash or backslash (`%2F`, `%5C`), an encoded NUL, an encoded dot segment (`%2e%2e`), a broken escape, a control character, a space, `?`, `#`, a raw backslash, a byte outside ASCII, and a result more than 16 KiB longer than the path it replaces (a replacement can repeat a capture; this bounds the memory one request can make podgate allocate). The `500` is the only outcome: there is no fallback to the original path.

The three kinds whose result is fixed (`add_prefix`, `replace_path`, and the prefixes of `strip_prefix`) are checked when the snapshot compiles instead, so the same problems are `invalid_middleware` there. Literals (prefix, path, regex, replacement) are at most 1024 bytes.

## `add_prefix`

`prefix` (starts with `/`) is put in front of the path: `/users` becomes `/api/users`, `/` becomes `/api/`. A trailing slash in the prefix does not double up (`/api/` and `/api` behave the same for `/users`).

## `strip_prefix`

`prefixes` lists one to 32 prefixes, each starting with `/`. The first one, in the order written, that the path starts with **as whole segments** is removed: `/api` strips `/api/users` to `/users`, turns `/api` and `/api/` into `/`, and leaves `/apix` and `/other/api` alone. (Traefik strips the raw string, so `/api` also turns `/apix` into `x`.) A prefix is normalized when the snapshot compiles and its trailing slash is dropped; `/` alone strips nothing and is `invalid_middleware`. Matching is case sensitive.

Sets `X-Forwarded-Prefix` to the prefix that was removed, as Traefik does.

## `strip_prefix_regex`

`regexes` lists one to 32 regular expressions (Rust `regex` syntax, so matching is linear time and a hostile path cannot make it slow). Each is unanchored, as written: the first one whose leftmost match is non-empty **and starts at the first byte of the path** has that match removed. A match elsewhere does nothing; write `^` to be explicit. The remainder gets a leading `/` if it lost it (`^/api` on `/apix` leaves `/x`: a regex strips exactly what it matched, use `^/api(?:/|$)` to keep whole segments).

Sets `X-Forwarded-Prefix` to the text that matched, as Traefik does.

## `replace_path`

`path` (starts with `/`) replaces the whole path. Sets `X-Replaced-Path`.

## `replace_path_regex`

`regex` (unanchored) and `replacement`: every match in the path is replaced, `$1`, `${1}`, `$name`, `${name}` insert groups and `$$` is a dollar sign (exactly the `regex` crate's replacement syntax). A path with no match is left alone and gets no `X-Replaced-Path`.

At compile time the template is read the way the `regex` crate reads it and every group it uses must exist, else `invalid_middleware` ("the replacement uses $2, which the regex does not define"). `$1a` means the group named `1a`, so write `${1}a` to mean group 1 followed by `a`. An empty regex is refused. The replacement cannot hold a character a path cannot hold (`?`, `#`, a space, a control character, `\`, a byte outside ASCII). A template that inserts an encoded slash (`%2F`) compiles, and any request it applies to gets the `500` described above.

Sets `X-Replaced-Path`.

## The two headers

- `X-Forwarded-Prefix` is set by the stripping kinds when they strip. Two stripping middlewares in one chain add their prefixes after each other, so `/a` then `/b` give `/a/b`.
- `X-Replaced-Path` is set by the replacing kinds when they replace, to the path (no query) the client sent, before any rewrite. A later replacement keeps the first value.
- Any copy of these headers the client sent is removed, whenever a middleware of the family that owns the header is in the chain, whether or not it rewrites this request: an upstream that trusts them to say what the proxy did must never read what the client wrote. Without such a middleware in the chain the headers are not touched.

## Plan and explain

A rewrite adds no access, so it lists no `posture_changes`; adding, changing or removing one still shows the app under `changed` in `POST /v1/snapshot/plan`. `GET /v1/explain` shows each rewrite in the chain with its parameters: `prefix`, `prefixes`, `regexes`, `path`, or `regex` and `replacement` (a replace path is shown normalized).

## Traefik and Caddy

| podgate | Traefik | Caddy |
|---|---|---|
| `add_prefix` | `addPrefix` | `uri prefix` |
| `strip_prefix` | `stripPrefix` (strips the raw string) | `uri strip_prefix`, `handle_path` |
| `strip_prefix_regex` | `stripPrefixRegex` | `uri path_regexp` |
| `replace_path` | `replacePath` | `rewrite`, `uri path` |
| `replace_path_regex` | `replacePathRegex` | `uri replace`, `uri path_regexp` |
