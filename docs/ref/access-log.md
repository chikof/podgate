# Access log

One structured line per request, with the fields, filters and sampling the snapshot chooses, on stdout or in a file, and optionally as OTLP log records (`## Export over OTLP`). It never waits for its sink, never writes a credential unless the operator names it, and request data cannot forge a field or a line. Code: `src/observe/access_log.rs` and `src/observe/access_log/{policy,format,sink,otlp,export}.rs`.

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

Unknown settings, bad actions, ranges or percentages are `422` `invalid_access_log`; per-router settings that are not a boolean `access_log` are `invalid_observability`. `metrics` stays `observability_not_built`; tracing is in `docs/ref/tracing.md`.

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

## Export over OTLP

`OTEL_LOGS_EXPORTER=otlp` also sends every record to an OpenTelemetry collector as an OTLP log record, beside the stdout or file sink. It matches Traefik's `accessLog.otlp`. Code: `src/observe/access_log/{otlp,export}.rs` on the shared transport in `src/observe/otlp/`.

The destination is the operator's, never a snapshot's: a snapshot is tenant-influenced data, and letting it name an address podgate calls would be an SSRF primitive. A snapshot that tries (`otlp`, `endpoint`, `headers` or anything else unknown under `observability.access_log`) is `422` `invalid_access_log`. What a record may contain is the tenant's policy, as for the line.

|Variable|Default|Meaning|
|---|---|---|
|`OTEL_LOGS_EXPORTER`|`none`|`none` or `otlp`. Anything else (`console`, a list such as `otlp,none`, an empty value) stops startup naming the variable, because an ignored exporter would leave the operator without logs they believe they have. `otlp` needs `OTEL_EXPORTER_OTLP_ENDPOINT`: podgate has no default collector address.|

The collector is the one the span and metric exporters use: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf` or `grpc`), `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY`, `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_EXPORTER_OTLP_TIMEOUT` and `OTEL_SERVICE_NAME` (the `service.name` resource attribute). They behave as for spans (`docs/ref/tracing.md`, `docs/ref/tracing-grpc.md`). HTTP goes to `<endpoint>/v1/logs` as protobuf; gRPC calls `opentelemetry.proto.collector.logs.v1.LogsService/Export`. There is no per-signal endpoint variable (`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is not read) and no `OTEL_BLRP_*` batch setting: the batch is fixed.

### What a record holds

A record is built from the same copy as the line, after the snapshot's filters and sampling, so a request the line does not log has no record. The encoder applies the policy's actions to the fields: a dropped field is absent, a redacted one reads `[redacted]`, `client_ip` is masked as the line masks it, and a value the request does not have is left out (the JSON `null`). Header values are the line's: the credential headers read `[redacted]` unless the policy names them `keep`. `format` (`json` or `common`) only shapes the line; the record is the same under both.

|Field|Record|
|---|---|
|`time`|`time_unix_nano` and `observed_time_unix_nano`, the instant the request finished; both `0` when the policy drops or redacts `time`.|
|`request_id`, `entry_point`|`podgate.request.id`, `podgate.entry_point`|
|`tenant`, `app`, `router`, `service`, `revision`|`podgate.tenant`, `podgate.app`, `podgate.router`, `podgate.service`, `podgate.revision`|
|`server`|`podgate.upstream.address`, `ip:port`|
|`method`, `host`|`http.request.method`, `server.address`|
|`path`, `query`|`url.path`, `url.query`|
|`proto`|`network.protocol.version`: `1.1`, `2`, `3`|
|`status`|`http.response.status_code` (integer)|
|`bytes_in`, `bytes_out`|`http.request.body.size`, `http.response.body.size` (integer)|
|`duration_ms`, `upstream_duration_ms`|`podgate.duration_ms`, `podgate.upstream.duration_ms`: doubles, the number the line prints|
|`client_ip`|`client.address`|
|`tls_version`, `sni`|`tls.protocol.version` (`1.3`), `tls.client.server_name`|
|`retry_attempts`, `origin`, `reason`|`podgate.retry_attempts` (integer), `podgate.origin`, `podgate.reason`|
|`user_agent`, `referer`|`user_agent.original`, `http.request.header.referer` (a list of one)|
|`request_headers`, `response_headers`|`http.request.header.<name>`, `http.response.header.<name>`: a list of one string, repeated headers joined with `, ` as in the line.|
|`truncated`|`podgate.truncated`, a list of field names|

The record's own parts: `severity_number` and `severity_text` are `ERROR` (17) for a `5xx` or for a request that got no response, `WARN` (13) for a `4xx` and `INFO` (9) otherwise; when the policy drops or redacts `status` every record is `INFO`, so the severity cannot give the status away. `body` is a short summary of the kept `method`, `path` and `status` (`GET /p 200`, `[redacted]` for a redacted part, `request` when none is kept). `event_name` is `podgate.access_log`.

`trace_id`, `span_id` and `flags` correlate the record with its span (`docs/ref/tracing.md`): they are set whenever the request's router is traced, `span_id` is the proxy's server span of that request, `flags` is `1` when the trace was sampled and `0` when it was not. A request on a router that is not traced has none. They identify the trace, not the request, so `fields` does not govern them; the trace id is the caller's when the request continued a trace, as for spans.

### Never in the way

Records go into a second queue of 8192, beside the line queue: the request path appends to each under a short lock and never waits. One background service takes up to 512 records when 512 have queued or every two seconds and sends them. An export gives up after `OTEL_EXPORTER_OTLP_TIMEOUT` and is retried twice (250 ms, then 500 ms, or the delay a gRPC collector asks for) when the collector is unreachable, slow or answers `429`, `502`, `503`, `504` or `UNAVAILABLE`; a batch that still fails, a batch the collector refuses, and a single record over the 4 MiB message limit are dropped. A full queue drops its **oldest** record. Everything dropped counts in `podgate_access_log_otlp_dropped_total`, so a collector that is down, hanging or refusing costs records and never request latency; the line sink is another queue and keeps writing. The two queues share the records, so the second adds pointers, not copies, and memory stays bounded by 8192 records. One queue serves every tenant, as the line queue does: a tenant that logs a flood pushes out other tenants' oldest records when it is full, and `filters` and `sampling_percent` are the tenant's tools against that. At shutdown the exporter tries the last four batches once and drops the rest.

|Metric|Meaning|
|---|---|
|`podgate_access_log_otlp_exported_total`|Records the collector accepted.|
|`podgate_access_log_otlp_dropped_total`|Records dropped by a full queue, a failed or refused export, or at shutdown.|
|`podgate_access_log_otlp_queue_records`|Records waiting (gauge).|

The three series exist only when `OTEL_LOGS_EXPORTER=otlp`.
