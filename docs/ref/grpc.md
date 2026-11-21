# gRPC through podgate

podgate proxies gRPC as what it is: HTTP/2 requests whose bodies are streams of length-prefixed messages and whose responses end in trailers. There is no gRPC-specific code in the proxy path; this page says what a gRPC client and server can rely on, what podgate answers when it fails a call itself, and which settings matter for long calls. Every statement here is checked by `tests/grpc.rs` (the names are in [Tests](#tests)), against a frame-level HTTP/2 server and client in `tests/common/grpc.rs` (the `h2` crate, no `tonic`). gRPC-Web is the `grpc_web` middleware (`docs/ref/mw-grpc-web.md`).

Traefik and Caddy do the same: gRPC is an HTTP/2 route to an `h2c://` server (Traefik) or a `transport http { versions h2c }` (Caddy), and neither writes gRPC trailers for its own errors.

## What goes through

|Path|How|
|---|---|
|Client to podgate|HTTP/2 over TLS (ALPN `h2` on an `https` entry point), or cleartext HTTP/2 with prior knowledge on an `http` entry point whose policy sets `http2.h2c` (below). HTTP/1.1 is not gRPC and is not served as such.|
|podgate to the server|`h2c://ip:port` (cleartext HTTP/2 by prior knowledge), or `https://ip:port` with ALPN `h2` (the default of a transport; `http2: false` offers only `http/1.1`, which cannot carry gRPC). A `grpc_web` route refuses a server that cannot speak HTTP/2 at compile time (`invalid_middleware`); a plain route has no way to know it carries gRPC, so a `http://` server there fails at the server.|
|Calls|Unary, client streaming, server streaming and bidirectional, one HTTP/2 stream each. Messages above 4 MiB and DATA frames of 64 KiB pass unchanged; a message is never held whole.|
|Head, messages, trailers|`content-type`, `te: trailers`, `grpc-timeout`, `grpc-encoding`, `grpc-accept-encoding` and custom metadata reach the server as sent. `grpc-status`, `grpc-message` and custom trailers reach the client, after the data or, for a trailers-only error, in the response head.|
|Compressed messages|The flag byte and the bytes of a message that the server compressed (`grpc-encoding: gzip`) pass untouched. podgate does not encode or decode messages.|

One HTTP/2 connection to a server carries up to 100 streams (`docs/ref/transports.md`); a downstream connection carries as many as the entry point allows (`http2.max_concurrent_streams`, default 100). A client that opens more waits on its own side until a stream ends.

## Cleartext HTTP/2 on an entry point: `http2.h2c`

`entry_points[].http2.h2c: true` on an `http` entry point makes Pingora look at the first bytes of every connection: the HTTP/2 connection preface is served as HTTP/2 (prior knowledge, no `Upgrade`), anything else as HTTP/1.1, on the same port. It is off by default, and it is refused with `unsupported_setting` on an `https` entry point (TLS negotiates HTTP/2 by ALPN, so the field would do nothing) and with `invalid_http2` when it is not a boolean.

With `h2c` on, the entry point serves HTTP/2, so the knobs that only apply to HTTP/2 become available on it (`http2.max_concurrent_streams`, the HTTP/2 idle timeout of `timeouts.idle_secs`, `max_header_bytes` on HTTP/2) and `timeouts.read_secs`, which Pingora does not apply to an HTTP/2 request body, becomes `unsupported_setting` there, as on an `https` entry point. See `docs/ref/entry-policy.md`.

## What podgate answers itself

When podgate fails a call before or instead of the server, the answer is an ordinary HTTP response with a status, no body that is a gRPC message and **no `grpc-status`**. A gRPC client derives the code from the HTTP status with the mapping every gRPC implementation shares ([`http-grpc-status-mapping.md`](https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md)). podgate writes no gRPC trailers of its own, as Traefik does not.

|podgate answered|HTTP status|Body|gRPC code the client derives|Test|
|---|---|---|---|---|
|No router matches the host or path|`404`|`{"error":"not found"}`|`UNIMPLEMENTED` (12)|`grpc_unknown_host_unimplemented`|
|The service has no server|`503`|`{"error":...}`|`UNAVAILABLE` (14)|`grpc_no_upstream_unavailable`|
|The connection to the server is refused|`502`|none (Pingora's answer)|`UNAVAILABLE` (14)|`grpc_upstream_refused_unavailable`|
|The server did not answer in `read_timeout_secs`|`504`|none (Pingora's answer)|`UNAVAILABLE` (14)|`grpc_upstream_read_timeout_gateway_timeout`|
|`rate_limit` or `in_flight_req` refused|`429` with `retry-after`|`{"error":...}`|`UNAVAILABLE` (14)|`grpc_rate_limited_unavailable`, `grpc_in_flight_held_for_stream`|
|Any other `4xx` or `5xx`|as written|as written|`400` `INTERNAL` (13), `401` `UNAUTHENTICATED` (16), `403` `PERMISSION_DENIED` (7), `502`, `503`, `504` `UNAVAILABLE` (14), the rest `UNKNOWN` (2)||

A `502` or `504` that podgate makes while the server's response has already started cannot be a status: the response head is out. The stream is reset instead, and the client sees a stream error with no `grpc-status`, which it reports as `UNAVAILABLE` or `INTERNAL`. A response that the server itself ends with `grpc-status` (trailers-only or after data) is the server's and passes through unchanged, including `UNIMPLEMENTED` for a method it does not know.

## Deadlines and cancellation

- **`grpc-timeout` goes to the server unchanged.** podgate does not enforce it (neither Traefik nor Caddy does): the client that set the deadline resets the stream when it expires, and the server sees the cancel.
- **A reset cancels the server's stream.** When the client resets a stream (`RST_STREAM`), podgate resets the stream to the server with `CANCEL`: `tests/grpc.rs` checks it arrives within one second, both before and after the server sent its response head.
- **The transport's `read_timeout_secs` bounds a silent stream.** It is the longest podgate waits for the response head (counted from the start of the call, so a client-streaming call that uploads for longer than this before the server answers is cut with `504`) and for each next read of the body (a server stream that pauses longer is reset towards both sides, and the client gets no `grpc-status`). The default is `REQUEST_TIMEOUT_SECS` (30 s), at most 3600. Set it on the transport of a service that carries long calls: `grpc_upstream_read_timeout_gateway_timeout` and `grpc_idle_stream_cut_by_read_timeout` show both cuts. Keepalive pings between the connections do not count as stream data.

## Middlewares

|Middleware|A gRPC call|Test|
|---|---|---|
|`compress`, and the platform's default gzip|Never encodes `application/grpc*`, whatever `Accept-Encoding` and the lists say.|`grpc_not_compressed_or_buffered`|
|`buffering`|`buffer_request` and `buffer_response` do not hold a gRPC call: a held request would wait for a body that a bidirectional or client-streaming call only finishes after the response, and a held response would withhold every message and lose the trailers. The limits that do not need holding (`max_request_body_bytes`) still count the stream.|`grpc_not_compressed_or_buffered`|
|`retry`|A connect error is retried on another server (nothing was sent). A call whose response started is never repeated, and neither is one whose request body was streamed, whatever `methods` says.|`grpc_retry_connect_error`, `grpc_no_retry_after_start`|
|`in_flight_req`|A call holds its slot until the stream ends, trailers included, not until the response head is out.|`grpc_in_flight_held_for_stream`|
|`rate_limit`|A call takes a token when it starts, and a refusal is the `429` above.|`grpc_rate_limited_unavailable`|
|`cache`|A `POST` is never stored or served; a `GET` with a gRPC content type is not either.|`grpc_cache_bypassed`|
|`mirroring`|A copy is plain HTTP/1.1 with the request head only, or with the body up to `max_body_size`: a streaming call that outgrows the limit, or that the client abandons, is dropped (`body_too_large`, `incomplete`) and the real call is untouched.|`grpc_mirroring_bounded`|
|`grpc_web`|A browser's gRPC-Web calls reach the same server, binary and text, unary and streaming.|`grpc_web_through_route`|

## Memory

A stream costs the proxy a few HTTP/2 windows, not its length. `grpc_stream_memory_bounded` streams 100 MiB down, 100 MiB up and 100 MiB each way in a call through the running binary (a slow reader for the first messages of the download) and asserts that the process's peak resident size grew by less than 48 MiB.

## Tests

`tests/grpc.rs`: `grpc_unary_h2c`, `grpc_unary_tls_h2`, `grpc_client_streaming`, `grpc_server_streaming`, `grpc_bidi_streaming`, `grpc_large_messages`, `grpc_trailers_reach_client`, `grpc_trailers_only_error`, `grpc_timeout_propagated`, `grpc_client_reset_cancels_upstream`, `grpc_upstream_read_timeout_gateway_timeout`, `grpc_idle_stream_cut_by_read_timeout`, `grpc_downstream_h2_over_tls`, `grpc_downstream_h2c`, `grpc_h2c_policy_rejections`, `grpc_entry_point_stream_limit`, `grpc_unknown_host_unimplemented`, `grpc_no_upstream_unavailable`, `grpc_upstream_refused_unavailable`, `grpc_rate_limited_unavailable`, `grpc_not_compressed_or_buffered`, `grpc_no_retry_after_start`, `grpc_retry_connect_error`, `grpc_in_flight_held_for_stream`, `grpc_cache_bypassed`, `grpc_mirroring_bounded`, `grpc_web_through_route`, `grpc_http2_false_refused`, `grpc_stream_memory_bounded`.
