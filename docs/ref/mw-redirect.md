# Redirect middlewares

`redirect_scheme` and `redirect_regex` answer a request with a redirect from the router's middleware chain, before a revision, a service or an upstream is chosen. No upstream connection is made, no tenant slot is taken.

## Traefik check

The status codes were checked against Traefik 3.7.16, the binary pinned in `devenv.nix` (`pkgs.traefik`), with a file provider and one router per middleware:

|Middleware|Request|Answer|
|---|---|---|
|`redirectScheme {scheme: https, permanent: true}`|`GET /p1/x?q=1`, `Host: Ex.test:28931`|`301`, `Location: https://Ex.test/p1/x?q=1`|
|`redirectScheme {scheme: https}`|same|`302`, `Location: https://Ex.test/p2/x?q=1`|
|`redirectScheme {scheme: https, port: "8443"}`|same|`302`, `Location: https://Ex.test:8443/p3/x?q=1`|
|`redirectRegex {permanent: true}`|same|`301`|
|`redirectRegex {replacement: "//evil.test$2"}`|same|`302`, `Location: //evil.test/z` (protocol-relative target, no check)|
|`redirectScheme` on `GET /p2/a%0d%0ab`|`Host: 127.0.0.1`|`302`, `Location: https://127.0.0.1/p2/a%0D%0Ab` (the escape is kept; podgate refuses it)|

Those rows are all `GET`. A second check sent `POST`, `PUT` and `HEAD` to the same middlewares, with and without `permanent`:

|Middleware|`GET`|`POST`, `PUT`, `HEAD`|
|---|---|---|
|`redirectScheme`, `redirectRegex`|`302`|`307`|
|`redirectScheme`, `redirectRegex` with `permanent: true`|`301`|`308`|

So podgate answers `GET` with `301` for `permanent: true` and `302` otherwise, and every other method, `HEAD` included, with the method-preserving `308` and `307` ([`podgate::middleware::redirect::status_for`](../../src/middleware/redirect.rs)), so a client does not replay a `POST` as a `GET`. The entry point redirect of change 0030 calls the same function, and Traefik's entry point redirection answers the same way. `permanent` defaults to `false`, because a cached permanent redirect is hard to take back (Traefik's `redirectScheme` without `permanent` answered `302` in the check above).

## The URL

A redirect works on `scheme://host[:port]/path?query`:

- `scheme` is the client's, from the request's `ForwardedView`: `https` over TLS, `http` otherwise, unless the peer is listed in the entry point's `forwarded_headers.trusted_ips`, in which case its `X-Forwarded-Proto` counts. A TLS-terminating load balancer therefore does not loop: it reaches podgate over plain HTTP with `X-Forwarded-Proto: https`, and a `redirect_scheme` to `https` passes that request on. The same trusted peer's `X-Forwarded-Host` replaces the host and its `X-Forwarded-Port` the port (the scheme's default port is not written). For any other peer these headers were removed before routing, so a client cannot choose any of them.
- `host` is the URI authority (HTTP/2, absolute-form) or else the `Host` header, lowercase, without a trailing dot. A host with anything but letters, digits, `-`, `.`, `_` (and the brackets and colons of an IPv6 literal), or with `user@`, is `400`.
- `:port` is written when the request named one.
- `path?query` is the path the request was normalized to (dot segments and duplicate slashes removed, unreserved escapes decoded), then the query as sent.

## `redirect_scheme`

```json
{ "name": "to-https", "type": "redirect_scheme", "scheme": "https", "port": 8443, "permanent": true }
```

|Field|Meaning|
|---|---|
|`scheme`|`http` or `https`. Required.|
|`port`|Target port, 1 to 65535. A port that is the scheme's default (`443` for `https`, `80` for `http`) is not written in the URL.|
|`permanent`|`301` instead of `302` for a `GET`, `308` instead of `307` for other methods. Default `false`.|

The target is the request's host, path and query on `scheme` (and `port`). The port the request named is dropped (a request for `a.test:8080` goes to `https://a.test/`), as in Traefik.

A request that already has the target scheme is passed on, so the redirect cannot loop. When `port` is set it must match too: the request's port is its `Host` port, or the scheme's default when it names none. Without `port`, the scheme alone decides. Traefik would send `https://a.test:8443` to `https://a.test/`; podgate leaves it, because behind a port mapping that redirect breaks the client.

## `redirect_regex`

```json
{ "name": "moved", "type": "redirect_regex", "regex": "^http://old\\.test/(.*)$", "replacement": "https://new.test/$1", "permanent": true }
```

|Field|Meaning|
|---|---|
|`regex`|Pattern over the URL above. Unanchored; write `^` and `$` when you mean them. Rust `regex` syntax: linear time, no look-around, no back-references. A pattern whose compiled form exceeds 1 MiB is refused.|
|`replacement`|Target. `$1`, `${1}`, `$name`, `${name}` insert a group (`$0` the whole match), `$$` is a dollar sign.|
|`permanent`|`301` instead of `302` for a `GET`, `308` instead of `307` for other methods. Default `false`.|

Every match of the regex in the URL is replaced, like Go's `ReplaceAllString` that Traefik uses. A request the regex does not match, or whose result equals the original URL, is passed on. A group that did not take part in the match inserts nothing.

At compile time, `invalid_middleware` names the problem when: the regex does not compile; the replacement is empty; the replacement names a group the regex lacks (`$2` for one group, `${nope}`, and `$1x`, which names the group `1x`: write `${1}x`); a `$` is not followed by a name or another `$`; the replacement holds a control character or a percent escape of one.

## What reaches `Location`

Both kinds build the value with one function, `redirect::finish`:

- A control byte (below `0x20`), a DEL (`0x7f`), or a percent escape of one (`%00` to `%1F`, `%7F`, any case) anywhere in the target answers `400` with `{"error":"redirect target has a control character"}`. No `Location` and no `Set-Cookie` can come out of a request. The legitimate encoded newline in a query (`?text=a%0Ab`) is refused too when it would be redirected.
- Only `http` and `https` targets, protocol-relative (`//host/...`) targets and paths are sent. `javascript:`, `data:` and any other scheme are `400`.
- A target whose authority has `user@` is `400`.
- Bytes that are not valid in a URL, or that a browser reads as something else (space, `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}`, and non-ASCII), are percent-encoded. A backslash can therefore not turn `https:\\evil.test` into a host. Escapes already in the target are kept.
- A target over 8 KiB is `400`. A replacement that repeats a group for every match is stopped at that cap.

## Redirects to other hosts

A `redirect_regex` replacement may produce an absolute URL, or a `//host` URL, for a host the app does not claim. Traefik allows it and so does podgate: a tenant moving a domain needs it, and the target is whatever the author's replacement produces. The same author already controls where the app's traffic goes. The one thing a visitor can steer is a *captured* part of the URL: `^http://[^/]+/(.*)$` with `https://$1` puts the path in the host position, so `GET /evil.test` redirects to `https://evil.test`. Write the host literally, or capture it from the host part (`^http://([^/]+)/(.*)$` with `https://$1/$2`). podgate does not try to guess which captures are safe, because both look the same to it.

A redirect only answers for the router it is on, and the replacement can only use the URL of the request it answers, so one tenant's redirect never changes what another tenant's host serves.

## Plans

Removing a `redirect_scheme` that redirects to `https`, or changing its scheme to `http`, is listed as `https_redirect_removed` in `posture_changes` of `POST /v1/snapshot/plan`: plain HTTP is then served. `redirect_regex` has no posture entry; a redirect is not a restriction.

`GET /v1/explain` lists the stage with its settings (`scheme`, `port`, `permanent`; `regex`, `replacement`, `permanent`).
