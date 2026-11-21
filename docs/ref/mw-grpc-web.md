# Middleware `grpc_web`

Reference for the kind in `src/middleware/grpc_web.rs` (wire pieces in `src/middleware/grpc_web/codec.rs`). The model it plugs into is in `docs/architecture.md` (`### Middlewares`). Traefik calls it `grpcWeb {allowOrigins}`; Caddy has it only as a plugin.

A browser cannot speak gRPC: it cannot read HTTP/2 trailers and cannot stream a request body. It speaks gRPC-Web instead, which is gRPC with the trailers moved into the body. This middleware converts a gRPC-Web request to gRPC for an HTTP/2 upstream, and the response back, without buffering a message.

```json
{
  "name": "web",
  "type": "grpc_web",
  "allow_origins": ["https://app.example.com"]
}
```

| Field | Meaning |
|---|---|
| `allow_origins` | Origins that may call from a browser: exact `scheme://host[:port]` (scheme `http` or `https`), or `*`. Absent or empty: no CORS headers and no preflight answer. |

Unknown fields are `invalid_middleware`. The schema is served at `GET /v1/schema` under `middleware.grpc_web`.

## Request

A request whose `Content-Type` (parameters ignored, case-insensitive) is one of these is gRPC-Web:

| Content type | Body |
|---|---|
| `application/grpc-web`, `application/grpc-web+proto` | binary gRPC frames |
| `application/grpc-web-text`, `application/grpc-web-text+proto` | the same, base64 |

It goes to the upstream with `Content-Type: application/grpc`, `te: trailers` and a body that ends with a DATA frame, never with the headers. For the text kind the body is decoded as it streams and `Content-Length` is dropped (the decoded body is shorter). A body that is not base64 is answered `400` before anything is sent on; the upstream may already have received the messages that came before the bad byte.

Every other request, `application/grpc` and `application/grpc-web+json` included, passes untouched: no header is rewritten, no CORS header is added.

The decoder accepts `=` padding in the middle of the stream (a client that encodes each message on its own) and a last group without padding.

## Response

When the request was gRPC-Web and the upstream answers with `application/grpc` or `application/grpc+...`:

- The content type becomes `application/grpc-web+proto` (binary) or `application/grpc-web-text` (text). `Content-Length` is dropped; the body is chunked.
- Body chunks pass through as they arrive. In text mode they are base64 encoded as one stream: at most 2 bytes of an unfinished group are carried to the next chunk, and padding appears once, at the end.
- The HTTP/2 trailers (`grpc-status`, `grpc-message`, custom ones) become the last frame of the body: the flag byte `0x80`, the length of the lines as a big-endian `u32`, then one `name: value\r\n` line per value. In text mode that frame is encoded with the rest and the stream is closed with padding.
- A **trailers-only** response (the headers carry `grpc-status`, there is no body) becomes a response whose body is that frame alone, with a `Content-Length`. The `grpc-status` and `grpc-message` headers stay in the head as well, so a client that reads them there still can. Headers that describe the message (`Content-Type`, `Content-Length`, `Content-Encoding`, `Transfer-Encoding`, `Connection`, `Date`, `Server`, `Vary`, `Via`, `access-control-*`) are not trailers and stay out of the frame.
- A response that ends without any trailers ends with a frame that says `grpc-status: 2` (unknown). A call never looks successful because a server forgot its trailers.
- A response that is not gRPC (an HTML `404` from a proxy in front of the server, say) passes through; only CORS headers are added to it.

Compression (`compress`, the platform default) and `buffering` leave `application/grpc*` alone, so they never touch these bodies.

## Memory

No gRPC message is buffered. The state of a request is the stage's `State`: the mode, a base64 remainder (at most 3 characters in, 2 bytes out), the allowed origin and, for a trailers-only response, its small body. At the end of a response one trailer frame is built from the trailers, which Pingora already holds: it is capped at **8 KiB** of lines (`codec::MAX_TRAILER_BYTES`), and a response with more trailers than that gets `grpc-status: 13` and `grpc-message: trailers exceed 8192 bytes` instead, so it fails loudly. This transient frame is not charged to `max_buffer_bytes`: it is at most 8 KiB per response that is ending, and the response is already counted against `max_inflight`.

`tests/mw_grpc_web.rs` `grpc_web_bounded_memory` drives 100 MiB through the hooks in each direction with a counting allocator and asserts the peak stays within one chunk plus that frame; `grpc_web_streams_100_mib_through_the_proxy` streams 100 MiB through the running proxy and checks the process's peak size.

## HTTP/2 upstream required

gRPC cannot be spoken over HTTP/1.1, so a router whose chain has a `grpc_web` stage must reach services whose servers all speak HTTP/2: `h2c://host:port`, or `https://host:port` through a transport that does not set `http2: false` (the default offers `h2`). Anything else, and a `static` service, is `invalid_middleware` naming the middleware, the router, the revision and the server. A `draining` revision takes no requests and is not checked. An `https://` server that is offered `h2` and picks `http/1.1` is not detectable at compile time: its calls fail at the upstream like any other protocol mismatch.

## CORS

With `allow_origins`, the stage answers a CORS preflight itself (`OPTIONS` with `Access-Control-Request-Method` and a listed `Origin`) with `204` and never forwards it:

| Header | Value |
|---|---|
| `Access-Control-Allow-Origin` | the request's origin, only when it is listed (`*` when `*` is listed) |
| `Access-Control-Allow-Methods` | `POST` |
| `Access-Control-Allow-Headers` | `*, authorization` (`*` does not cover `Authorization`, so it is named) |
| `Access-Control-Max-Age` | `600` |
| `Vary` | `Origin` |

A gRPC-Web response to a listed origin carries `Access-Control-Allow-Origin` and `Access-Control-Expose-Headers: grpc-status, grpc-message`, and `Vary: Origin`. An origin that is not listed gets nothing: no header, and its preflight is passed on like any request. The origin is compared exactly (`https://app.example.com.evil.test` and `http://app.example.com` are not `https://app.example.com`) and is never reflected from the request into an unlisted answer. Credentials are not allowed (`Access-Control-Allow-Credentials` is never sent), so cookies do not cross origins; a bearer token in `Authorization` does.

The code is the `headers` middleware's CORS code (`src/middleware/headers.rs`), configured with fixed values, so the two cannot disagree about what a listed origin is. Use one of the two on a route: a `headers` stage with its own `cors` and a `grpc_web` with `allow_origins` would both write the headers.

## Plan and explain

`GET /v1/explain` shows the stage as `{"type": "grpc_web", "allow_origins": [...]}`. A plan lists `cors_widened` in `posture_changes` when a new snapshot lists an origin the live one did not.

## How Pingora carries the trailers

The proxy needs three hooks the other kinds did not, added to `Kind` in `src/middleware.rs` and called from `src/proxy.rs`:

- `request_body_chunk(body, end_of_stream, state)`: rewrites each request body chunk (the base64 decoder), after the counting hooks.
- `response_trailers(trailers, state) -> Option<Bytes>`: called from `ProxyHttp::response_trailer_filter`. Pingora 0.9.1 reads the h2 upstream's trailers in `pingora-proxy/src/proxy_h2.rs:1238-1270`, calls the filter at `:993-1021` and writes a returned buffer as the last body chunk (`HttpTask::Body(Some(buffer), true)`, documented at `proxy_trait.rs:485-497`). That converted body does not pass `response_body_filter`, so the stage flushes its own base64 remainder inside this hook. An error here is only logged by Pingora and the raw trailers go on, so the hook never fails.
- `response_complete(state) -> Option<Bytes>`: for a head that is all the upstream sent. A trailers-only response arrives as `HttpTask::Header(resp, true)` (`proxy_h2.rs:1153`), and an HTTP/2 or HTTP/1.1 downstream ends the stream on that header (`pingora-core/src/protocols/http/v2/server.rs:757-760`), so no hook can add a body to it. `response_filter` therefore writes the converted head and the body itself and ends the request with an error Pingora does not send, the same way an `errors` page replaces a response. The access log and metrics see the response that was written. The downstream HTTP/1.1 connection is not reused after such a response.
