# Directory listings for `static` roots

A `static` service (`docs/ref/svc-static.md`) can list a directory that has no index file, so an
operator can publish a download directory. It is Caddy's `file_server browse` with three
deliberate differences: the listing is opt-in **twice**, there are no custom templates, and no
hidden file is ever shown. Traefik has nothing like it.

```json
{ "name": "downloads", "type": "static", "root": "dl",
  "browse": true, "hide": ["*.bak", "*.tmp"], "max_entries": 500 }
```

## The two opt-ins

| Who | Where | Setting |
|---|---|---|
| The operator | `STATIC_ROOTS_FILE` | the root is `{"path": "/srv/static/t1/dl", "browse": true}` |
| The service | the snapshot | `"browse": true` |

The string form of a root entry (`"dl": "/srv/static/t1/dl"`) is unchanged and never lists. A
snapshot that sets `browse: true` on a root the operator did not open is `422`
`static_browse_not_allowed`, so a tenant cannot turn listings on for a directory the operator did
not allow, and the refusal is at compile time, never a silent `404`. `hide` and `max_entries`
without `browse: true` are `invalid_service`, like every other setting that would be ignored.

An object entry accepts only `path` (absolute, required) and `browse` (boolean, default `false`);
any other key stops startup like a malformed string entry does.

## When a listing is answered

| Request | Answer |
|---|---|
| a file | the file, as before |
| a directory with an index file | the index file (`/dir/`), or `308` to `/dir/` without the slash: as before |
| `try_files` names something that opens | that, before any listing |
| a directory with a trailing `/` and no index | the listing |
| a directory without the `/` and no index | `308` to the same path plus `/` (query kept) |
| a hidden directory (`/.git/`, and `/.well-known/`: it is served but never listed), a missing path | `404`, or the `status_pages` file |

The index file always wins, including an index that cannot be served (over `max_file_bytes`): it
is never replaced by a listing. `try_files` and `status_pages` are tried first, so a single page
app fallback shadows listings by design.

## Format

HTML for browsers; JSON for `Accept: application/json` or `?format=json` (`?format=html` forces
HTML, and wins over `Accept`). Both are sorted with directories first, then files:
`?sort=name|size|mtime` (default `name`) and `?order=asc|desc` (default `asc`); an unknown value
falls back to the default. Directories have no size and sort among themselves by the chosen key
and then by name. Names compare as bytes.

```json
{ "path": "/docs/",
  "entries": [
    { "name": "img", "type": "dir",  "size": null, "modified": "2026-11-21T10:00:00Z", "href": "img/" },
    { "name": "a b.txt", "type": "file", "size": 12, "modified": "2026-11-20T08:30:00Z", "href": "a%20b.txt" } ],
  "truncated": false }
```

`path` is the request path (as the router passes it on), never a file-system path. `modified` is
UTC (`RFC 3339`); the page shows the same text. The page has a link to `../` below the root.

## What is left out

- every name that starts with a dot (so `.well-known` too), and every name that matches a `hide`
  glob. A glob is matched against the entry's name only: `*` any run of characters, `?` one
  character, anything else itself; it cannot contain `/`;
- anything that is not a regular file or a directory (FIFOs, sockets, devices);
- a symlink that does not resolve **inside the root**. The check is the one that serves files: the
  link is opened through the root's `cap-std` handle, so a link out of the root (relative,
  absolute, through `..`) and a dangling link are omitted. A link that stays inside is listed as
  what it points at (its kind, size and time); **its target is never shown**. A symlink whose name
  is not valid UTF-8 is omitted, because it cannot be resolved through a text path.

## Hostile names

A file name is attacker-controlled text. The page treats every name as hostile:

- HTML-escaped (`& < > " '`) in the page and in the title;
- percent-encoded **by bytes** in `href`: every byte but `A-Z a-z 0-9 - . _ ~` is `%XX`, so a name
  like `javascript:alert(1)` is the link `javascript%3Aalert%281%29`, never a scheme, and a name
  like `%2e%2e` is `%252e%252e`;
- control characters (including DEL and the C1 range) and bidirectional controls (U+202A to
  U+202E, U+2066 to U+2069, plus the marks U+061C, U+200E and U+200F) are shown as visible
  escapes (`\u202e`), so a name cannot reorder the page text or spoof an extension;
- invalid UTF-8 is shown lossily (U+FFFD) and linked by its percent-encoded bytes. Request paths
  must be valid UTF-8 (`docs/ref/svc-static.md`), so following such a link is a `404`;
- JSON keeps the exact name (lossy for invalid UTF-8; `href` is the faithful identifier), but the
  same characters are written as JSON `\uXXXX` escapes, so the bytes on the wire cannot reorder
  text in a terminal that prints them.

The page has no script and no inline style. Headers: `Content-Security-Policy: default-src
'none'`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-cache`, `Vary: Accept`. The listing
never contains the root's absolute path.

## Bounds

- `max_entries` (default 1000, 1 to 10000) entries are rendered. A larger directory shows the
  first entries in the requested order, with a visible `truncated` notice (`"truncated": true` in
  JSON). The directory is streamed and only the best `max_entries + 1` entries are kept (never
  more than twice that during the scan), so a directory of a million names does not cost a
  million entries of memory.
- At most 20000 directory entries are examined per request, hidden ones included; a directory
  with more is cut off after the first 20000 the file system returns (and is `truncated`). The
  order of the entries shown is then the order within that prefix.
- The read runs on the bounded blocking pool of the static service
  (`STATIC_MAX_CONCURRENT_READS`), as one operation; no slot within a second is `503` with
  `retry-after: 1`.
- Before the directory is read, `max_entries * 512 + 65536` bytes are charged to the tenant's
  `max_buffer_bytes`, on top of the 131072 bytes every static response reserves. The charge ends
  when the page has been written. A tenant whose budget cannot take it right now gets `503` with
  `retry-after: 1`, which is a capacity answer that auto-revert does not count. A tenant whose
  whole `max_buffer_bytes` is below `131072 + max_entries * 512 + 65536` could never list, so a
  snapshot that gives it such a service is `invalid_service` (422), naming the tenant, the bytes
  needed and the budget. With the defaults that is 708608 bytes.

## Tests

`tests/svc_static_browse.rs` (the real binary), plus unit tests in
`src/service/static_files/browse.rs` for globs, escapes, encoding, dates, sorting and the roots
file forms.
