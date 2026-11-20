# Middleware `cache`

Reference for the kind in `src/middleware/cache.rs` and the store in `src/cache.rs` and `src/cache/`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`, `## Memory budgets`).

An in-memory response cache for a route: it honours `Cache-Control` and `Vary`, collapses concurrent misses into one upstream request, charges every cached byte to the tenant's `max_buffer_bytes`, caps the share of that budget the cache may take, and has an admin API to purge by URL, prefix, tag or app. Memory only: there is no disk tier and no distributed mode.

```json
{
  "name": "c",
  "type": "cache",
  "max_bytes": 1048576,
  "max_object_bytes": 262144,
  "default_ttl_secs": 60,
  "tag_header": "Cache-Tag"
}
```

Every field is optional. Unknown fields are `invalid_middleware`.

| Field | Meaning |
|---|---|
| `max_bytes` | The most bytes the tenant's cache may hold when this middleware stores. Default a quarter of the tenant's `max_buffer_bytes`. At most `CACHE_TENANT_MAX_PERCENT` percent of it (default 50), or the snapshot is rejected with `cache_max_bytes_over_cap`. |
| `max_object_bytes` | Largest response kept (body counted as it streams). Default 1 MiB or `max_bytes`, whichever is lower; may not pass `max_bytes`. |
| `statuses` | Statuses that may be stored. Default `200 203 204 301 308 404 410`. Only 2xx, 3xx and 4xx; not `206` or `304`. |
| `default_ttl_secs` | Freshness for a response that names none. Absent: only explicit freshness (`s-maxage`, `max-age`, `Expires`) is stored, never a heuristic. |
| `max_ttl_secs` | Longest an entry stays fresh. Default `86400`. |
| `max_stale_secs` | `{ "while_revalidate": 60, "if_error": 300 }`: the longest the response's own `stale-while-revalidate` and `stale-if-error` are honoured. |
| `cache_set_cookie` | `true` stores a `Set-Cookie` response with the cookie removed from the stored copy. Default `false`: such responses are never stored. |
| `ignore_request_cookies` | `true` serves and stores for requests that carry `Cookie`. Default `false`: they bypass the cache. |
| `respect_request_cache_control` | `true` obeys a client's `no-cache`, `max-age=0` and `Pragma: no-cache` (the request goes to the upstream and refreshes the entry) and `no-store` (bypass). Default `false`: letting any client skip the cache turns it into an amplifier against the origin. |
| `share_across_revisions` | `true` shares entries between the revisions of the app. Default `false`: the revision is in the key, so a rollout or canary never serves one release's page to another. |
| `normalize_query` | `true` sorts the query parameters before they are part of the key. Default `false`: the query is part of the key as sent. |
| `collapse_timeout_ms` | How long a request waits for the upstream fetch another request leads, then goes to the upstream itself. Default `3000`, `1..=10000`. At most 64 requests wait per key; the rest go at once. |
| `tag_header` | The response header that lists purge tags (for example `Cache-Tag` or `Surrogate-Key`), separated by commas or spaces. At most 16 tags of 128 bytes per entry; a response over that is not stored, because a purge by tag could miss it. The header is removed before the response reaches the client. |

## Where it goes in the chain

Place `cache` after authentication. A hit is answered from the chain's `routed` hook: after every request hook of the chain has run (so after `basic_auth`, a redirect or an IP filter), and after the revision and the server were chosen, but before the tenant's in-flight slot and the backend's admission. A hit therefore costs the tenant no slot and the backend no connection, and the revision is known for the key.

A hit does not run the response hooks of the stages that come *before* `cache` in the chain. The response hooks of the stages after it, and compression, have already run on what was stored. To apply a `headers` middleware to hits, put it after `cache`.

## What is stored, and as what

The entry is the response as the client received it on the miss that stored it: status, headers (without hop-by-hop headers, `Age`, `Content-Length` and the tag header) and body.

**Compression.** Compression runs before the cache sees the body, so the entry holds the encoded bytes the client got together with the `Vary: Accept-Encoding` that `compress` adds. A later client whose `Accept-Encoding` is equivalent gets the stored bytes with no recompression; a client that accepts other codings is another variant. `Accept-Encoding` is canonicalised for the variant key (lowercase, sorted, `q=1` dropped), so `gzip, deflate` and `deflate,GZIP` are one variant. Every other `Vary` header is keyed as sent.

Not stored: `Cache-Control: no-store` or `private`; `Set-Cookie` responses (unless `cache_set_cookie`); `Vary: *`; statuses outside `statuses`; a response with no explicit freshness and no `default_ttl_secs`; a body over `max_object_bytes` (counted while it streams: the copy is abandoned, the client still gets the whole response); a body shorter than its declared length. `no-cache` responses are stored only with a validator (`ETag` or `Last-Modified`) and are revalidated before every use. A response that says `no-store`, `private` or sets a cookie also removes the entry that was stored before for that key.

Not served from, and not stored for: methods other than `GET` and `HEAD` (a `HEAD` is answered from the `GET` entry and stores nothing); requests with `Authorization`, `Proxy-Authorization`, `Range`, `If-Range`, `If-Match`, `If-Unmodified-Since`, `Upgrade`, a body, or `Cookie` (unless `ignore_request_cookies`). These are `bypass`. A request with `If-None-Match` or `If-Modified-Since` is answered `304` from a matching entry, and goes to the upstream, without leading a fetch, when there is none.

## The key

`(tenant, app, router, revision?, scheme, host, normalized path and query, vary variant)`. The tenant and the app are in every key; every entry also lives in its tenant's own store, so no code path can look at another tenant's entries. `HEAD` and `GET` share entries. The path is the one the proxy normalized before routing. The scheme is `https` when the request arrived over TLS (or a trusted peer said so), so a redirect-to-HTTPS app does not serve its `http` answer to `https` clients. Request headers the response does not name in `Vary` (`X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`) are not part of the key, which is why `Vary` is honoured exactly and `Vary: *` is never stored.

When a host moves to another tenant or another app in a snapshot, the old entries stay under the old app's key, can never match the new app, and are dropped when the snapshot is applied (the app is gone, moved to another tenant, or the revision is `draining` or gone).

## Budget

Cache memory is retained memory, so it is charged to the same `max_buffer_bytes` as everything else a tenant can make podgate hold (`TenantBudget::charge`, held by the entry, released when the entry goes). There is one number per tenant, and the cache can never be the reason a compression or WASM run is refused beyond its own share.

- **Per-tenant cap.** The tenant's cache holds at most `max_bytes` of the middleware that stores, and `max_bytes` is at most `CACHE_TENANT_MAX_PERCENT` percent of the budget.
- **Entry size.** Body bytes, plus headers, plus 512 bytes of overhead, plus 64 bytes per body chunk (the chunks are kept as the upstream sent them, so a body of tiny chunks cannot hide behind its length). Everything is charged *before* it is copied.
- **Making room.** An insert that does not fit evicts the tenant's own least recently used entries, never another tenant's. Needing budget for a copy in progress evicts the same way. If it still does not fit, the response is served and not stored.
- **Release.** Purging or evicting an entry releases its charge when the last response still reading it ends, which for an idle entry is at once.
- **Compile time.** A `max_bytes` over the operator's share is `cache_max_bytes_over_cap` (`422`).

## Behaviour

Hits carry `Age` and `Cache-Status: podgate; hit`; the other results are `miss`, `stale`, `bypass` and `revalidated`. (RFC 9211 defines the header; the bare result words are podgate's own vocabulary.) A hit is answered with `Content-Length` of the stored body.

- **Collapsed misses.** One request fetches; the others wait up to `collapse_timeout_ms` for it and are then answered from the new entry. If the leader's response was not stored, or the wait times out, they go to the upstream themselves. Counted in `podgate_cache_collapsed_total`.
- **Revalidation.** A stale entry with a validator, or one still inside `stale-if-error`, is checked with a *subrequest*: a copy of the client's request that runs the whole pipeline (route, chain, admission, upstream) and ends in a sink, with `If-None-Match` and `If-Modified-Since` taken from the entry. The client waits for it, then gets the entry (`revalidated` after a `304`, `miss` after a new `200`). Pingora cannot answer a `304` from the origin with a stored body on the request's own path, which is why it is a subrequest. The subrequest has no connection of its own, so the SNI, client certificate and ACME checks that read the client's connection are skipped for it (the original request already passed them); it appears in the access log and the outcome counters like any request.
- **`stale-while-revalidate`.** Inside the window the stale entry is served at once (`stale`) and one subrequest refreshes it in the background; requests that find the refresh running just get the stale entry.
- **`stale-if-error`.** If the revalidating subrequest fails (the upstream refused, reset, timed out or answered 5xx) and the entry is inside its `stale-if-error` window, the stale entry is served (`stale`). Past the window the error is the answer.
- **Bounds.** Both allowances come from the response's own directives, capped by `max_stale_secs`, and are zero for `must-revalidate`, `proxy-revalidate` and `no-cache`.
- **Revisions and refresh.** A refresh subrequest picks its revision like any request. If it picks another revision than the one that holds the entry (a weighted canary), it does not refresh that entry; the entry then expires and the next request fetches. Pin the entry with `share_across_revisions: true` if that matters.

## Purge API

Admin socket only (`POST /v1/cache/purge`, mode `0600`; a request on the proxy port is just a `POST` to the app).

```json
{ "app": "shop", "url": "https://shop.test/a/b?x=1" }
{ "app": "shop", "prefix": "/blog/" }
{ "app": "shop", "tag": "product-42" }
{ "app": "shop", "all": true }
```

Exactly one selector, always scoped to the named app: an app of another tenant that has the same host or path is never touched. `url` and `prefix` accept an absolute path or an `http(s)` URL; the path is normalized like a request's, a path alone matches under every host of the app, and a URL with a host matches that host only. A `url` matches every variant, revision and scheme of that URL; a `prefix` matches the start of the path and query. `200 {"purged": N}`; the charge of the purged entries is released before the answer. `400` for malformed JSON, no selector or several, or a bad URL; `404` for an app the live table does not have.

Purging scans the tenant's entries (bounded by its cap), not an index, so it costs time in proportion to the tenant's cache size.

## Metrics

| Series | Meaning |
|---|---|
| `podgate_cache_requests_total{app,result}` | Requests by result: `hit`, `miss`, `stale`, `bypass`, `revalidated`. Dropped with the app. |
| `podgate_cache_bytes{tenant}` | Bytes of entries held now. Also part of `podgate_tenant_buffer_bytes`. |
| `podgate_cache_evictions_total{tenant}` | Entries evicted to make room. Purges are not evictions. |
| `podgate_cache_collapsed_total` | Requests that waited for another request's fetch. |

## Limits and notes

- Entries are copied as they stream; a response that fails halfway is not stored.
- A snapshot push drops entries of removed apps and retired revisions. An auto-revert does not run that sweep; the next push does, and the cap bounds the memory meanwhile.
- A hit does not set `Set-Cookie` from the stored copy, but the session-pinning cookie of `skew_secret` is added to it as to any response.
- Not built: disk tiers, a distributed cache, purge by header, request coalescing across nodes.
