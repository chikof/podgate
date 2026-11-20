# Access log

One structured line per request, with the fields, filters and sampling the snapshot chooses, on stdout or in a file. It never waits for its sink, never writes a credential unless the operator names it, and request data cannot forge a field or a line. Code: `src/observe/access_log.rs` and `src/observe/access_log/{policy,format,sink}.rs`.

## Turning it on

The log is off until the snapshot says otherwise. `observability.access_log` is an object (or `true` for the defaults); a router overrides the switch with `observability: {"access_log": false}` (or `true`).

```json
"observability": {
  "access_log": {
    "format": "json",
    "fields": {
      "default": "keep",
      "names": { "client_ip": {"action": "mask", "ipv4_bits": 24, "ipv6_bits": 48}, "query": "keep", "user_agent": "keep" },
      "query_redact": ["token", "api_key"]
    },
    "headers": { "default": "drop", "names": { "x-request-source": "keep", "cookie": "drop" } },
    "filters": { "status_codes": ["400-599"], "min_duration_ms": 1000, "retry_attempts": 1 },
    "sampling_percent": 10
  }
}
```

Unknown settings, bad actions, ranges or percentages are `422` `invalid_access_log`; per-router settings that are not a boolean `access_log` are `invalid_observability`. `metrics` and `tracing` stay `observability_not_built`.

|Setting|Meaning|
|---|---|
|`format`|`json` (default) or `common` (Common Log Format).|
|`fields.default`|`keep` (default): the default fields are written. `drop`: only fields named below are.|
|`fields.names.<field>`|`keep`, `drop`, `redact` (`"[redacted]"`) or `mask` (`client_ip` only). `mask` may be an object `{"action": "mask", "ipv4_bits": 0..=32, "ipv6_bits": 0..=128}`; the defaults are 24 and 48, so an operator logs a /24. Matches Caddy's `ip_mask`.|
|`fields.query_redact`|Query parameter names whose values are replaced by `[redacted]` when `query` is kept.|
|`headers.default`|`drop` (default), `keep` or `redact` for every header. `keep` still redacts `authorization`, `proxy-authorization`, `cookie` and `set-cookie`.|
|`headers.names.<header>`|`keep`, `drop` or `redact` for one header (case-insensitive). A name wins over the default and over the credential rule: only `"authorization": "keep"` logs an `Authorization` header.|
|`filters`|A line is written when **any** filter matches; none set means every request. `status_codes`: statuses or ranges (`"404"`, `"400-599"`). `min_duration_ms`: at least this long. `retry_attempts`: at least this many retries. Matches Traefik's `filters`.|
|`sampling_percent`|0..=100 (fractions allowed, hundredths of a percent). Applied after the filters. Deterministic: see below.|

## Fields

Default fields, in this order: `time` (RFC 3339 UTC, milliseconds), `request_id`, `entry_point`, `tenant`, `app`, `router`, `service`, `revision`, `server` (upstream address), `method`, `host`, `path` (never the query), `proto` (`HTTP/1.1`, `HTTP/2.0`), `status`, `bytes_in`, `bytes_out` (body bytes), `duration_ms`, `upstream_duration_ms` (from the connection to the end of the upstream's response body; `null` when no upstream was used), `client_ip`, `tls_version`, `sni`, `retry_attempts`, `origin`, `reason`. A value a request does not have is `null` (a request that matched no router has no `tenant`).

Optional fields, written only when named `keep` or `redact`: `query`, `user_agent`, `referer`. Headers go under `request_headers` and `response_headers` (names lowercase, repeated headers joined with `, `, at most 64 each). `truncated` lists the fields that were cut.

- `client_ip` is the address podgate resolved behind trusted proxies (`docs/ref/client-ip.md`), never a header an untrusted peer sent.
- `entry_point` is the name of the entry point the request arrived on (`Ctx.entry_point`).
- `origin` is `upstream` when an upstream answered, else `podgate`. `reason` says why podgate itself refused or failed the request: a stage notes it (`ctx.access.reason`, `ctx.access.refused(&err)`), else it is derived from how far the request got: `bad_request`, `misdirected`, `client_cert_required`, `no_route`, `no_upstream`, `no_healthy_upstream`, `over_budget`, `backend_saturated`, `wake_timeout`, `filter_busy`, `middleware`, `upstream_unavailable`, `no_response` (the client left before an answer). Middlewares that refuse for their own reason set it: `rate_limited`, `circuit_open`, `auth_failed`.
- `request_id` is the `X-Request-Id` a **trusted** peer sent (a short string of visible ASCII), else a generated id. An untrusted client never picks it, so it cannot choose whether sampling logs it.
- `retry_attempts` counts retries the retry middleware made.

### Deliberate differences

Traefik logs the full request path with its query and drops headers by default; credentials often live in queries. podgate drops the query and every header by default, and redacts the four credential headers unless named `keep`. A log nobody configured must not become a credential store. Sampling is deterministic from the request id (a hash of it), so a request and its retries agree.

## Never in the way, never forged

- Lines go into a queue of 8192 and one writer task takes them in batches. The request path only appends; when the queue is full the **oldest** line is dropped and `podgate_access_log_dropped_total` rises. A write error also counts its batch as dropped. `podgate_access_log_lines_total` counts lines written. Both are on `GET /metrics`.
- The write happens on a blocking thread, so a sink that never returns (a pipe nobody reads) stalls only the writer.
- JSON strings escape `"`, `\`, every control character (`\u00XX`, so a newline is never a newline), DEL, U+2028 and U+2029. Common Log Format escapes `"` and `\` with a backslash and controls as `\xHH`. A request cannot add a field or a line.
- Every request-controlled string is cut at 2048 bytes when it is copied (so a hostile path costs 2 KiB of queue, not its length), and its field is listed in `truncated` (Common format appends `...`).

## Where lines go

`ACCESS_LOG_FILE` unset: standard output, one write per batch, the raw JSON line (not wrapped in a `tracing` event, so a collector reads the same object whether `LOG_FORMAT` is `json` or `pretty`). Set: that file, created with mode `0640` if missing and opened for append. The file is reopened when the path names another inode, checked at most once a second, so renaming it (move-and-create rotation) and `copytruncate` both work without a signal; Pingora owns the signals, so there is no reopen signal. A file that cannot be opened or written drops its lines and logs one warning until it recovers.

## Common Log Format

`host ident authuser [time] "method path proto" status bytes`, for example `203.0.113.7 - - [20/Nov/2026:12:34:56 +0000] "GET /p HTTP/1.1" 200 5`. `ident` and `authuser` are `-`; `bytes` is `-` for an empty body. The field actions apply (`drop` writes `-`, `redact` writes `[redacted]`, `client_ip` masks); the other fields do not exist in this format.
