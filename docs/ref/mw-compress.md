# Middleware `compress`

Reference for the kind in `src/middleware/compress.rs` and the encoders in `src/compress.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`).

```json
{
  "name": "z",
  "type": "compress",
  "algorithms": ["zstd", "br", "gzip"],
  "min_bytes": 1024,
  "include_content_types": ["text/*", "application/json"],
  "exclude_content_types": ["text/css"],
  "level": 2
}
```

Every field is optional. Unknown fields are `invalid_middleware`, so Traefik's `excludedContentTypes`, `encodings` and `defaultEncoding` spellings are refused rather than ignored.

| Field | Meaning |
|---|---|
| `algorithms` | Preference order. The first one the client accepts wins, not the client's own order. `gzip`, `brotli` (or `br`) and `zstd`. Default `["gzip"]`. `[]` turns compression off for the chain. A name twice is `invalid_middleware`. |
| `min_bytes` | A response whose `Content-Length` is smaller stays as it is. Default `1024`. |
| `include_content_types` | When set, only these types are compressed, and the text-like default no longer applies. `type/subtype` or `type/*`, case-insensitive, no parameters, at most 64. |
| `exclude_content_types` | Never compressed. Beats `include_content_types`. Same syntax. |
| `level` | Effort, `1` (fast) to `3` (small), default `2`. |

## What replaces what

Without a `compress` middleware in the effective chain a response gets the platform default: gzip, level 2, `min_bytes` 1024, text-like types (`text/*`, `application/json`, `application/javascript`, `application/xml`, `application/x-ndjson`, `*+json`, `*+xml`). A `compress` in the chain replaces that whole default with its own settings. When a chain holds several, the last one in chain order decides, so a router's own `chain` overrides the app's `default_chain`.

## Negotiation

`Accept-Encoding` is read with q-values: a coding named with `q=0` is refused, an unnamed coding is allowed by `*` when `*` has a non-zero quality, and a quality that does not parse refuses. Of `algorithms`, the first the client accepts is used. A client that sends no `Accept-Encoding` gets the identity encoding.

A response is never compressed when:

- the request is `HEAD`, or the status is `1xx`, `204`, `205`, `206` or `304`,
- it already has `Content-Encoding`, or `Content-Range`, or `Cache-Control: no-transform`,
- its type is `text/event-stream` or `application/grpc*`, whatever the lists say: compressing a stream holds its events back,
- its declared `Content-Length` is under `min_bytes`,
- its type fails the lists (no `Content-Type` fails them too),
- the tenant's buffer budget cannot take the reservation below.

A response that is compressed loses `Content-Length` and `Accept-Ranges`, gains `Content-Encoding`, and `Transfer-Encoding: chunked` over HTTP/1.1. A strong `ETag` becomes weak (`W/"..."`).

`Vary: Accept-Encoding` is added to every response that could be compressed, whoever asks and whether or not the budget allowed it, so a cache never serves one form for the other. It is not added when `Vary` already names `Accept-Encoding` or `*`, and not to responses that are never candidates (a `206`, an image, an event stream).

**Unknown length.** `min_bytes` is judged on a declared `Content-Length`. Pingora writes the response head before it reads any of the body, so a body of unknown length cannot be sized in time and is compressed whatever its size; a small one costs the encoder's framing (a few dozen bytes). Holding the first `min_bytes` back to decide would be a per-response allocation the tenant's budget did not cover. The content-type lists apply to unknown-length bodies as to any other.

## Memory

Compression is the one place the proxy allocates per response, and every byte is charged to the tenant's `max_buffer_bytes` before it exists (`TenantBudget::reserve`). The charge is a fixed number per algorithm, measured in `tests/compress_alloc.rs` with a counting allocator: the highest live heap one response reached from `start` to the end of the stream, over 8 MiB of text and 8 MiB of incompressible bytes in 64 KiB chunks, at every level.

| Algorithm | Peak measured | Reserved | Encoder |
|---|---|---|---|
| gzip | 466,880 bytes | 640 KiB | `miniz_oxide`, deflate level 1, 4 or 6 |
| brotli | 825,788 bytes | 896 KiB | `brotli` crate, quality 1 to 3, 32 KiB window |
| zstd | 790,148 bytes | 896 KiB | `ruzstd`, its `Fastest` level, 32 KiB frames |

A response that does not fit is sent as the upstream sent it (counted in `podgate_tenant_compression_skipped_total`); compression never refuses a request. A tenant with `max_buffer_bytes` under 896 KiB never gets brotli or zstd, and one under 640 KiB never gets gzip. Size the budget to the concurrency you want compressed: 100 concurrent brotli responses need 87.5 MiB.

### Why the levels stop at 3

The `brotli` crate measured, at a 32 KiB window and on the same input: quality 1 to 3 hold 0.4 to 0.8 MiB, quality 4 holds 1.8 MiB, and quality 5 holds 35 MiB of match tables. A reservation that large is not one a tenant can plan for, so the levels are 1 to 3: brotli quality 1 to 3, deflate level 1, 4 and 6. zstd has one level, so `level` does not change it.

### Why zstd is frames

`ruzstd` 0.9 has no push-style encoder: it pulls one whole frame from a reader. podgate cuts the body into frames of at most 32 KiB, each compressed with a fresh match window. Concatenated frames are one valid zstd stream (RFC 8878 section 3.1), and `tests/mw_compress.rs` decodes them with libzstd. Every frame declares a window of at most 128 KiB, so a decoder's memory is bounded too. A bounded encoder is the point: Traefik's advisory GHSA-x5pf-cqh3-2gv8 is about roughly 18 MiB of zstd memory per response. The price is ratio: matches never reach across a frame, so zstd compresses a large body somewhat worse than the reference encoder.

The 32 KiB frame is what sets the memory: `ruzstd` allocates one 8-byte slot per byte of the frame, rounded up to a power of two (256 KiB at 32 KiB, 512 KiB at 64 KiB). With 64 KiB frames the peak measured 998,170 bytes on text; with 32 KiB, 665,630.

## Order against the other response hooks

In `response_filter` the chain's `response_head` hooks (the `buffering` response limit) run first and judge the response as the upstream sent it, then `compress` decides and rewrites the head, then the chain's `response` hooks run in reverse chain order. A response that `buffering` refuses is never compressed, and a response whose compressed form would fit under a limit is still judged by its upstream size.

The failure capture sees the upstream's bytes before compression, so a recorded 5xx is replayable as it was.

An HTTP/2 upstream response may end in trailers, so its last DATA frame does not end the stream. The encoder is finished just before the trailers (`ProxyHttp::response_body_before_trailers`), and its last bytes go through the chain's response body hooks like every other compressed byte: a `buffering` stage that holds the body holds them too, then releases everything ahead of the trailers. The client gets a whole encoding followed by the trailers.

## Differences from Traefik and Caddy

- `min_bytes` is not applied to bodies of unknown length (above).
- Brotli quality is at most 3 and zstd runs in frames (above).
- The order of `algorithms` is the server's, whatever q-values the client gives its accepted codings.
- `include_content_types` and `exclude_content_types` take `type/subtype` and `type/*`; there are no regular expressions.
