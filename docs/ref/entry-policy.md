# Entry point policy

What a snapshot says about one listener. `ENTRY_POINTS` decides where a listener binds (Pingora binds its sockets before it runs); the policy in `Snapshot.entry_points` decides how it treats requests. An entry point without a policy behaves as it did before this feature: no redirect, Pingora's timeouts and limits, an encoded slash refused, underscored header names passed on.

```json
{
  "entry_points": [
    {
      "name": "web",
      "redirect": { "to": "websecure", "permanent": false },
      "max_header_bytes": 16384,
      "underscore_headers": "delete"
    },
    {
      "name": "websecure",
      "timeouts": { "write_secs": 30, "idle_secs": 120 },
      "http2": { "max_concurrent_streams": 100 },
      "allow_encoded_slash": false
    }
  ]
}
```

## Who owns it

The policy is the operator's. It sits at the top of the snapshot, next to `certificates` and `acme`, which the control plane writes; an app (and so a tenant) declares routers, middlewares and services and has no field that reaches an entry point's policy. `tenants` in the policy is a different thing: it limits which tenants may attach routers to the entry point (`entry_point_forbidden`), it does not hand them the policy. A program that merges snapshots from several tenants' sources (the provider) must therefore take `entry_points` from the operator's source only; a tenant source that sets it is a bug there, and the node would apply it to every tenant on a shared entry point.

A policy for an entry point the node did not bind is `unknown_entry_point`. HTTP policy on a `tcp` or `udp` entry point is `entry_point_protocol`.

## Knobs and what Pingora 0.9 does with them

Every knob is applied through a real Pingora setting or refused with `unsupported_setting` that names it. Sources are `pingora-core-0.9.1` and `pingora-proxy-0.9.1`.

|Knob|`http` entry point|`https` entry point|Pingora setting|
|---|---|---|---|
|`redirect {to, permanent}`|applied|applied|podgate's own answer in `request_filter`; no Pingora knob involved|
|`timeouts.read_secs`|applied (HTTP/1); `unsupported_setting` with `http2.h2c`|`unsupported_setting`|`HttpSession::set_read_timeout` (`protocols/http/server.rs`). A no-op for HTTP/2, whose `read_body_bytes` reads with no timeout (`protocols/http/v2/server.rs`, `// TODO: timeout`), and a TLS entry point, or an `http` one with `http2.h2c`, serves HTTP/2|
|`timeouts.write_secs`|applied|applied|`HttpSession::set_write_timeout`, implemented for HTTP/1 and HTTP/2|
|`timeouts.idle_secs`|applied (HTTP/1 keep-alive)|applied (HTTP/1 keep-alive and HTTP/2 connection idle)|`HttpSession::set_keepalive` before the request is read (`Policed::process_new_http`), and `HttpServerOptions::h2_idle_timeout` (`apps/mod.rs`)|
|`timeouts.header_secs`|`unsupported_setting`|`unsupported_setting`|none. HTTP/1 reads the head under the keep-alive timeout, one value for the wait for the first byte and for every later read (`protocols/http/v1/server.rs` `read_request_buf`); HTTP/2 headers are frames with no timeout|
|`http2.max_concurrent_streams`|applied with `http2.h2c`, else `unsupported_setting` (no HTTP/2 without it)|applied|`h2::server::Builder::max_concurrent_streams` through `HttpServerApp::h2_options`, read per connection (`apps/mod.rs`)|
|`http2.h2c`|applied (`true`)|`unsupported_setting` (TLS negotiates HTTP/2 by ALPN)|`HttpServerOptions::h2c` through `HttpServerApp::server_options`, read per connection (`apps/mod.rs`): Pingora peeks at the first bytes of a cleartext connection and serves HTTP/2 when they are the connection preface, HTTP/1.1 otherwise, so one port serves both. `docs/ref/grpc.md`|
|`max_header_bytes`|applied|applied|HTTP/2: `Builder::max_header_list_size` through `h2_options`. HTTP/1: a check of the parsed head (`431`). Above 1048575 it is `unsupported_setting`: Pingora's HTTP/1 parser refuses a head over `MAX_HEADER_SIZE = 1048575` and nothing raises it|
|`allow_encoded_slash`|applied|applied|podgate's path normalization (`src/router/path.rs`)|
|`underscore_headers`|applied|applied|podgate, on the parsed head|

Pingora's own defaults stay for everything a policy does not set: HTTP/1 read and keep-alive timeout 60 s, no write timeout, at most 100 concurrent HTTP/2 streams and a 64 KiB HTTP/2 header list.

Where a podgate knob differs from the Traefik one it is named after:

- `read_secs` is Pingora's wait for the next piece of the request body, per read. Traefik's `readTimeout` bounds the whole request. A client that sends a byte every few seconds is not cut off by `read_secs`.
- Nothing bounds the wait for a slow request head except `idle_secs` (and Pingora's 60 s without it), per read, for the same reason `header_secs` is refused.
- Ranges: timeouts are 1 to 3600 seconds, `http2.max_concurrent_streams` 1 to 10000, `max_header_bytes` 1 to 1048575. Out of range is `invalid_timeouts`, `invalid_http2` or `invalid_max_header_bytes`. Unknown fields and a `redirect` field other than `to` and `permanent` are the same `invalid_*` codes.
- Traefik's `transport.lifeCycle` is process-level in podgate (`REQUEST_TIMEOUT_SECS` is the shutdown grace period); `http.encodeQuerySemicolons` and the other `encodedCharacters` are not offered.

## `redirect`

`{"to": "<entry point>", "permanent": false}` answers every request on this entry point, after the ACME HTTP-01 answer (a validation request on a redirecting entry point still gets its token) and after the path is normalized and the client is settled, with a redirect to the same host, path and query on the target entry point.

- Status: [`middleware::redirect::status_for`](../../src/middleware/redirect.rs), the one function the redirect middlewares use: `GET` gets `302`, or `301` with `permanent: true`; every other method, `HEAD` included, gets `307`, or `308` with `permanent: true`, so a client keeps the method and body of a `POST`. This is what the pinned Traefik 3.7.16 does (checked, see below, and for its middlewares in `mw-redirect.md`).
- `permanent` defaults to `false`. Traefik's entry point redirection defaults to `permanent: true` (`--entrypoints.<name>.http.redirections.entrypoint.permanent (Default: "true")`); a cached permanent redirect is hard to undo, so podgate asks for it.
- `Location` is `scheme://host[:port]` + path and query. The scheme is the target's protocol (`http` or `https`; Traefik's `scheme` option is not offered, a protocol decides it). The port is the one the target is bound to (`ENTRY_POINTS`), left out when it is the scheme's default (`80` for `http`, `443` for `https`). The host is the request's: it is built by `redirect::Origin` from the connection's scheme and the `Host` or authority, lowercase, no trailing dot, only host characters; `X-Forwarded-Host` counts only from a peer the entry point trusts (`forwarded_headers`). `redirect::finish` then refuses a control character or an escape of one anywhere in the target (`400`), a target with userinfo, and anything longer than 8 KiB. A host that is not a host, or a request with no absolute path (`OPTIONS *`), is `400`; no byte of the request reaches `Location` otherwise.
- The port the request named is dropped (`a.test:9999` goes to `https://a.test:<target port>/`), as in Traefik.
- Compile checks: `to` must be a bound `http` or `https` entry point (`unknown_entry_point`, `entry_point_protocol`), and the redirects must not circle, directly or through a chain (`redirect_loop`, naming the circle). A chain that ends is allowed and costs the client one redirect per hop. The target's bound address must be known to the compiler (it always is in a running node).
- A router attached to a redirecting entry point never sees a request. Explain reports the redirect as `entry_redirect` (`to`, `status`, `scheme`, `port`).
- A plan lists `entry_point_https_redirect_removed` when an entry point stops redirecting to an `https` entry point.

### Traefik 3.7.16, entry point redirection (checked)

|Config|Request|Answer|
|---|---|---|
|`permanent: true` (the default)|`GET /a/./b//c%2fd?q=1`, `Host: Ex.test:28101`|`301`, `Location: https://Ex.test:28443/a/b/c%2Fd?q=1&r=%0d` (path normalized, host case kept, port replaced)|
|`permanent: true`|`POST /p`|`308`|
|`permanent: false`|`GET /a`|`302`|
|`permanent: false`|`POST /p`, `HEAD /p`|`307`|

## `allow_encoded_slash`

Path normalization (`docs/ref/match-request.md`) refuses a path with an encoded `/` or `\`, an encoded NUL, an encoded dot segment or a broken escape, with `400`. `allow_encoded_slash: true` changes one thing: `%2F` and `%2f` are accepted and kept as the escape `%2F` inside their segment. They are never decoded into a separator: `/api%2Fadmin` is one segment, so a router with `path_prefix: "/api"` does not match it, a router for `/api%2Fadmin` (the same escape) does, and the upstream receives `/api%2Fadmin`. An encoded backslash, an encoded NUL and an encoded dot segment stay refused. An upstream that decodes `%2F` itself will treat it as a separator; that is the risk the opt-in takes, and a plan lists it as `allow_encoded_slash` under `posture_changes` (`host: "entry_point:<name>"`).

## `underscore_headers`

`keep` (the default), `delete` or `reject`. `delete` removes every request header whose name holds an `_` and serves the request; `reject` answers `400` and serves nothing. This is what keeps `X_Forwarded_For` from reaching a CGI-style upstream, which reads it as `X-Forwarded-For`.

The pinned Traefik 3.7.16 (`--entrypoints.<name>.http.underscoreheadersstrategy`, deprecated for `aliasHeadersStrategy`, default empty) passed `X-Under_score: v` to the upstream unchanged and sent no `X_Forwarded_For` through (its own `X-Forwarded-For` was set from the connection). podgate's default is `keep` because an entry point without a policy must behave as before; `delete` is the recommended setting. A plan lists `underscore_headers_relaxed` when a stricter strategy becomes a laxer one.

## Limits that apply on every request

`max_header_bytes` is checked on the parsed head: the request line, each header as `name: value\r\n`, and the final blank line. Over it is `431` (`headers_too_large` in the access log). On HTTP/2 the connection also carries the limit as `SETTINGS_MAX_HEADER_LIST_SIZE`, which counts 32 extra bytes per header, so h2 may refuse slightly earlier.

## Tests

`tests/entry_policy.rs`: `redirect_entry_point_keeps_path_and_query`, `entry_redirect_post_keeps_method`, `redirect_target_port`, `redirect_refuses_unsafe_hosts_and_paths`, `redirect_spares_acme_challenge`, `redirect_loop_rejected`, `redirect_unknown_target_rejected`, `policy_unknown_entry_point_rejected`, `policy_unsupported_knob_rejected`, `policy_read_timeout_closes_slow_client`, `policy_idle_timeout`, `policy_idle_timeout_h2`, `policy_http2_stream_limit`, `policy_write_timeout_closes_stalled_reader`, `underscore_headers_delete`, `underscore_headers_reject`, `max_header_bytes_refuses_a_large_head`, `encoded_slash_allowed_by_policy`, `encoded_slash_is_never_a_separator_for_matching`, `plan_lists_allow_encoded_slash`, `plan_lists_a_removed_https_redirect`, `explain_reports_the_entry_point_redirect`.
