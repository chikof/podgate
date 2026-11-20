# Middleware `buffering`

Reference for the kind in `src/middleware/buffering.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

```json
{
  "name": "uploads",
  "type": "buffering",
  "max_request_body_bytes": 65536,
  "buffer_request": true,
  "max_response_body_bytes": 1048576,
  "buffer_response": true
}
```

Every field is optional; at least one limit is required. Unknown fields are `invalid_middleware`, so Traefik's `mem_request_body_bytes`, `mem_response_body_bytes` and `retry_expression` are refused rather than ignored.

## Memory only

podgate keeps no disk state, so nothing spills to disk and the `mem_*` sizes do not exist. A body that is held lives in memory, and every byte is charged to the tenant's `max_buffer_bytes` before it is allocated (`TenantBudget::reserve_buffering`). A refusal is counted in `podgate_tenant_buffering_refused_total`. Replay to a second server is the `retry` middleware's job, not an expression here.

## Request

| Setting | Effect |
|---|---|
| `max_request_body_bytes` | A `Content-Length` above it is answered `413 {"error":"request body too large"}` before any body is read, and the upstream is never dialled. A chunked body is counted as it streams: the chunk that passes the limit is not forwarded and the request is answered `413`. If the response has already started, the connection is reset instead. |
| `buffer_request` | The whole body is read before the upstream is chosen or dialled, so a slow client never holds an upstream connection and the upstream sees the request only once it is complete. Needs `max_request_body_bytes`, which may not exceed 65536 with it (see below). The body goes upstream with the framing it came in with. It stays in Pingora's replay buffer for the whole request, so a retry can send it to a second server from the same copy. |

`Expect: 100-continue` with a declared length over the limit is answered `417` before the client sends the body. Within the limit and with `buffer_request`, podgate answers `100 Continue` itself and removes the `Expect` header, because the upstream gets a complete body. Without `buffer_request`, the header goes to the upstream as before.

A held request has `30` seconds to arrive; a slower client gets `408`.

Charge: the declared `Content-Length`, taken before the first body byte is read, or `max_request_body_bytes` for a chunked body. It is held until the request ends. A tenant that cannot take it gets `503 {"error":"buffering is over the tenant's budget"}` with `retry-after: 1`. That answer is a capacity refusal, so auto-revert does not count it.

### Why `buffer_request` stops at 64 KiB

Pingora can send a body that was read ahead of the upstream request only through its request replay buffer, which holds 64 KiB. A larger body cannot be handed over, so `max_request_body_bytes` above 65536 with `buffer_request: true` is `invalid_middleware` (a limit without `buffer_request` can be any size). Traefik's buffering has no such cap; this is the difference to know when moving a route over.

## Response

| Setting | Effect |
|---|---|
| `max_response_body_bytes` | A `Content-Length` above it is answered `502 {"error":"upstream response too large"}` instead of the response, before the client has seen any of it. Needs `buffer_response: true`. |
| `buffer_response` | The whole body is held and sent in one piece once the upstream has finished. Needs `max_response_body_bytes`, so the memory is bounded. |

A response of unknown length (chunked, or ended by the upstream closing) cannot be refused once it has started, only held back. Pingora sends the response head before the body, so when such a body passes the limit the client already has the head: podgate drops the body and resets the connection. The client sees a failed transfer, not a `502`. This is why a limit without `buffer_response` is refused when the snapshot compiles: unbuffered, an oversized chunked response would already be on its way.

The charge for a held response is its `Content-Length` before the head goes out (an over-budget answer is a clean `503` with `retry-after: 1`), or 64 KiB at a time as a chunked body arrives. The limit judges the response as the upstream sent it, before compression. A `HEAD` request, `1xx`, `204` and `304` have no body and are not limited.

## Exempt

`Upgrade` requests and `CONNECT` are exempt from every limit in both directions: a WebSocket is not a body.

## Plan

Removing the stage, removing a limit or raising it lists `request_body_limit_loosened` or `response_body_limit_loosened` in `posture_changes` of `POST /v1/snapshot/plan`.

## Errors

| Code | When |
|---|---|
| `invalid_middleware` | An unknown field; no limit at all; `buffer_request` without `max_request_body_bytes`, or with one over 65536; `buffer_response` without `max_response_body_bytes`; `max_response_body_bytes` without `buffer_response`. |
