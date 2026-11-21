# The `static` service

A service of type `static` answers requests from a directory on the node instead of dialling a
server. It is the file-serving half of Caddy's `file_server` and `try_files`. Directory listings
(`browse`) are change 0101 and `php_fastcgi` is change 0100.

```json
{ "name": "site", "type": "static", "root": "site",
  "index": ["index.html"],
  "try_files": ["{path}", "/index.html"],
  "status_pages": { "404": "/404.html" },
  "cache_control": { "default": "no-cache",
                     "by_extension": { "js": "public, max-age=31536000, immutable" } },
  "precompressed": ["br", "gzip"],
  "max_file_bytes": 1073741824 }
```

## Where the files come from

A path is the one thing a snapshot must never choose, so the directories are **process
configuration**: `STATIC_ROOTS_FILE`, a JSON file read once at startup.

```json
{ "<tenant id>": { "<root name>": "/srv/static/<tenant>/<name>" } }
```

- Every path must be absolute and name a directory. A file that is unreadable or malformed, an
  empty tenant or root name, a relative path or a path that is not a directory stops startup with
  `invalid STATIC_ROOTS_FILE: <file>: tenant "<id>" root "<name>": <reason>`.
- A service says `"root": "<root name>"`. The name is resolved only among the roots of the app's
  own tenant: another tenant's name, an unknown name and a path (`/etc`, `../x`) are all
  `unknown_static_root` (`422`). Any other field that is not listed below, a `path` for example,
  is `invalid_service`.
- A revision can carry its own service with its own `root`, so a rolling deploy of a static site
  swaps directories with the revision.
- Each root is opened **once, at startup**, as a directory handle. Replacing the directory behind
  the path later does not move the handle: restart podgate, or declare the new release under a new
  root name and let the new revision name it.

## No escape

Every file is opened **relative to the root's directory handle** with the `cap-std` crate (no
`unsafe` in podgate). On Linux the kernel resolves the path with `openat2(RESOLVE_BENEATH)`;
`cap-std` walks the components itself when the kernel cannot. A `..` that leaves the root or a
symlink that leads out (relative or absolute) is an error, never a file, so a symlink planted in
the tree after startup is checked at each open. Symlinks that stay inside the root are followed.
Every refusal, whatever its cause, answers `404`: a client cannot tell a missing file from a
refused one.

In front of that, the request path:

1. is normalized by `router::path` before routing: dot segments and empty segments
   collapse, an encoded `/`, `\`, NUL or dot segment is refused with `400`;
2. is parsed again by the static module, which refuses `.` and `..` segments, backslash and NUL
   (raw or after decoding), a decoded `/`, a broken escape and bytes that are not UTF-8. The
   escapes are decoded **once**: `%252e%252e` names a file called `%2e%2e`, never a dot;
3. refuses **hidden names**: a segment that starts with a dot answers `404`, except
   `.well-known`. The rule applies to request paths, `try_files` results, index names and status
   pages alike. There is no override: a hidden file cannot be served.

A FIFO, socket or device in a root is opened without blocking and then refused (`404`): only
regular files and directories are served. A directory is never listed: without an index file it is
`404`.

The mount points a root crosses are not detected: a bind mount inside the tree is part of the tree.
That is the operator's tree to keep.

## What is answered

Only `GET` and `HEAD`; any other method is `405` with `Allow: GET, HEAD`. `HEAD` has the headers
of the `GET` and no body.

| Request | Answer |
|---|---|
| a file | `200` with the file |
| a directory with a trailing `/` | its first existing `index` file, else `404` |
| a directory without the `/`, with an index file | `308` to the same path plus `/` (query kept) |
| nothing found, `try_files` set | the first template that opens (see below), else its status |
| nothing found | `404` and `{"error":"not found"}`, or the `status_pages` file |

`try_files` is a list of path templates. `{path}` stands for the normalized request path and is the
only placeholder; a template starts with `/` or `{path}`. The first template whose file opens is
served (a directory is served as its index). The last entry may be a status (`404`) answered when
no template matched. `["{path}", "/index.html"]` is the single page app fallback.

`status_pages` (`{"404": "/404.html"}`) names, per error status from 400 to 599, a file of the same
root. It is served with that status, without validators or ranges. A page that is missing falls back
to the JSON error.

**Headers.** `Content-Type` from a built-in extension table (`application/octet-stream` for an
unknown one; nothing is sniffed), `X-Content-Type-Options: nosniff`, `Accept-Ranges: bytes`, a weak
`ETag` (`W/"<size hex>-<mtime nanoseconds hex>"`), `Last-Modified`, and `Cache-Control` from
`cache_control.by_extension` (the file's lowercase extension) or `cache_control.default`; none when
neither says.

**Conditional requests.** `If-None-Match` (weak comparison, a list, or `*`) and, when it is absent,
`If-Modified-Since` answer `304` with the validators and `Cache-Control`. `If-Match` and
`If-Unmodified-Since` are not evaluated.

**Ranges.** One satisfiable `bytes` range is `206` with `Content-Range`; an unsatisfiable one is
`416` with `Content-Range: bytes */<len>`. Several ranges, another unit and broken syntax get the
whole file (RFC 9110 lets a server ignore `Range`; multipart answers are an amplification vector).
`If-Range` compares strongly and our `ETag` is weak, so an entity tag never matches and the whole
file is sent; a date matches when it equals `Last-Modified`.

**Precompressed variants.** With `"precompressed": ["br", "gzip"]`, a request that accepts an
encoding gets `file.br` or `file.gz` (when the sidecar exists and is a regular file) with
`Content-Encoding`, the original file's `Content-Type`, its own `ETag` and `Vary: Accept-Encoding`.
The client's quality decides, then the order of the list. Without a sidecar the plain file is sent.
A response that already has a `Content-Encoding` is not compressed again by the `compress` stage;
a plain text file is still gzipped on the fly when the client accepts it and the tenant's budget
allows.

**Size.** A file larger than `max_file_bytes` (default 4 GiB) is not served: `404` and a warning in
the log.

## Memory and CPU

- A file is never read whole. Reads are `pread` calls of 64 KiB on the blocking pool, and the next
  chunk is read while the previous one is written to the client.
- A response in flight holds at most two chunks. podgate charges them (128 KiB) to the tenant's
  `max_buffer_bytes` **before the file is opened**. A tenant whose budget is full at
  that moment gets `503` with `retry-after: 1` (a capacity refusal: auto-revert does not count
  it); other tenants are unaffected. The charge ends when the response is finished or the
  client has gone. A tenant whose whole `max_buffer_bytes` is below 131072 could never serve a
  file, so a snapshot that gives it a static service is `invalid_service` (422), naming the
  tenant, the bytes needed and the budget.
- `STATIC_MAX_CONCURRENT_READS` (default four per core, at most 256) bounds the file-system
  operations (an open, or one chunk read) the whole process runs at once. An operation that finds
  no free slot within a second answers `503` with `retry-after: 1` (mid-response it cuts the
  connection). A slot is held while the disk works, never while a slow client drains its socket.
- There is no open-file cache.

## In the pipeline

A static service has no server, so there is no backend admission and no wake: the request takes
its revision slot and the tenant's in-flight slot, then is answered from `request_filter`. The
router's middlewares run as for any router: request hooks (auth, rewrites, redirects) before, and
the response hooks (`headers`, compression, failure capture) on the static response. A static
service is never failed over. `mirroring` (`docs/ref/svc-mirroring.md`) refuses a static service
as the mirrored service or as a mirror (`invalid_service`), because a copy of a request has no
server to dial.

Settings: `STATIC_ROOTS_FILE`, `STATIC_MAX_CONCURRENT_READS`; see the configuration table in
`docs/architecture.md`.
