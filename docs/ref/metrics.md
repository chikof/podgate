# Prometheus metrics

Reference for `src/observe/metrics.rs` and `src/observe/metrics/`. The model it plugs into is in `docs/architecture.md` (`### Observability`, `### Runtime state outside the table`).

podgate exposes Prometheus text (`text/plain; version=0.0.4`) in two places, with the same body:

|Where|What it is for|
|---|---|
|`GET /metrics` on the admin socket|The local agent. Always on, never reachable over TCP.|
|`GET /metrics` on `METRICS_ADDR`|Prometheus, which cannot scrape a unix socket. A TCP address, unset by default. Read-only: the only route is `GET /metrics` (and `HEAD`); every other path is `404`, every other method on `/metrics` is `405`. It has no route to the snapshot or to any other admin endpoint, so the admin API never gets a TCP listener.|

`METRICS_SERIES_PER_TENANT` (default `500`) is the cap below. Neither setting can come from a snapshot: a snapshot must not be able to open a port or lift its own cap.

## Series

Names carry the `podgate_` prefix. `code_class` is `1xx` to `5xx`.

|Series|Type|Labels|
|---|---|---|
|`entry_point_requests_total`|counter|`entry_point`, `code_class`|
|`entry_point_request_duration_seconds`|histogram|`entry_point`|
|`entry_point_open_connections`|gauge|`entry_point`|
|`router_requests_total`|counter|`app`, `router`, `code_class`|
|`router_request_duration_seconds`|histogram|`app`, `router`|
|`service_requests_total`|counter|`app`, `service`, `code_class`|
|`service_request_duration_seconds`|histogram|`app`, `service`|
|`service_retries_total`|counter|`app`, `service`|
|`service_server_up`|gauge|`app`, `revision`, `service`, `server`|
|`tls_cert_not_after_seconds`|gauge|`host`|
|`snapshot_version`|gauge||
|`otlp_metrics_failed_total`|counter||
|`mcp_denied_total`|counter|`tenant`, `app` (calls an `mcp_gateway`'s `tool_access` refused; one series per app with `tool_access`, the apps past `METRICS_SERIES_PER_TENANT` summed into `app="other"`)|
|`snapshot_applied_timestamp_seconds`|gauge||
|`snapshot_rejected_total`|counter|`code`|
|`metrics_collapsed_total`|counter|`tenant`|

The per-tenant (`tenant_*`), per-backend (`backend_*`) and `upstream_refused_total` series are unchanged in name, labels and values; they come first in the body, in the order `docs/architecture.md` lists them, then the series above.

What each one counts:

- A request is recorded when its response has been written, so the duration covers the whole exchange, as Traefik's does. A request that ended before any response (the client left) is not recorded. Every request counts on its entry point, matched or not; a request a router matched counts on that router; one that got as far as choosing a server (it passed the middleware chain and the revision pick) also counts on the router's service. A `404` for an unknown host therefore moves only the entry point series.
- A service series is keyed by app and service name, so every router that names the service and every revision that defines it record into one series. A deploy that replaces a revision's service does not reset it.
- `entry_point_open_connections` is the number of requests being served on the entry point now. That is what Traefik's `traefik_entrypoint_open_connections` measures too (its gauge rises and falls with the request, not with the TCP connection). Pingora gives no hook for a downstream connection closing, so a count of idle keep-alive connections is not available.
- `service_server_up` is `1` while the server may take a new request (not marked down by an active health check and not ejected) and `0` otherwise. It is read from the live table at scrape time. It carries the `revision` that defines the service (empty for a service the app shares), because health and ejection are state of a revision's server; this is the label set change 0033 introduced, and `observe::metrics::render` is the only producer of the series.
- `tls_cert_not_after_seconds` is the Unix time the snapshot's certificate stops being valid, once per host the snapshot declares for it (a wildcard keeps its `*.` form). The hosts are what the snapshot declares, never what a client sent.
- `snapshot_rejected_total{code}` counts refused snapshots once per distinct rejection code (`stale`, or the codes of the `422` body such as `host_conflict`). A snapshot refused for two codes counts once under each.
- `service_retries_total` counts the attempts the `retry` middleware (`docs/ref/mw-retry.md`) repeated on another server of the service: one per retry, so a request tried three times adds two. A service that never retried has no sample.

Only status classes that were seen have a sample, and a router or service that has seen no request has no series line at all, as in a client library that creates label children on first use. Histograms are always complete: every finite bucket, `+Inf`, `_sum` and `_count`.

## Histogram buckets

Fixed for every series, in seconds: `0.005 0.01 0.025 0.05 0.1 0.25 0.5 1 2.5 5 7.5 10` and `+Inf`. A snapshot cannot change them, so a series costs the same whatever its tenant does. `_sum` is exact to the microsecond.

## Deliberate differences from Traefik and Caddy

- Status is a class by default, not the exact code, and the method is not a label: each multiplies every series by tens. The exact status of an individual failure is in the failed-request ring (`GET /v1/apps/{app}/failures`).
- Traefik labels by `protocol`; podgate has no such label, because a protocol is a property of the entry point, which is already a label.
- Caddy's `metrics` directive labels by handler and, with `per_host`, by host. A host is client input or tenant input and is never a label here; the `host` label of `tls_cert_not_after_seconds` is the one exception and takes only hosts a snapshot declares for a certificate.

## Cardinality

A label value is always a name the operator or the snapshot declared: entry point names come from `ENTRY_POINTS`, `app`, `router`, `service` and `server` from the snapshot, `tenant` from the snapshot's tenants, `code` from a fixed set of rejection codes. No client address, path, query, header or request host is ever a label.

A snapshot can still declare as many routers as it likes, so each tenant is capped. A router, a service and a server each cost one series of the tenant's `METRICS_SERIES_PER_TENANT` (the status classes and histogram buckets are fixed multipliers of one series, not extra label sets). Routers and the services they name are counted first, in declaration order, apps in snapshot order and per app the routers before the services; the servers of the tenant's apps get what is left.

An object past the cap does not get its own series:

- a router records into `{app, router="other"}` and a service into `{app, service="other"}`, shared by every collapsed object of the app. A router or service really named `other` shares that series;
- servers past the cap are not reported on `service_server_up`;
- `metrics_collapsed_total{tenant}` rises by one for each object that newly collapsed. The same object collapsing again at the next push does not count again.

The `other` series (two per app) are not counted against the cap.

## Lifetime across snapshots

The series live in a registry beside the routing table, not in it. When a table goes live, each router and service gets its handle from the registry:

- An object the registry knows keeps its counters. A router is identified by app, name and a fingerprint of its matcher, priority, entry points and service: a push that touches another app, or other parts of this one (a middleware, a revision, another router) loses nothing, and a router whose matcher changed is another route and starts at zero.
- An object the snapshot no longer declares is still reported for ten minutes, then forgotten. If it comes back within that time with the same fingerprint it carries on.
- A tenant that churns names cannot grow the registry through that retention: at the cap, a new object takes the place of the oldest retained one, and only collapses when there is none.

## Cost on the request path

The handles are resolved when the table compiles (`TableSeries`, one `Arc<Series>` per router and service, indexed by the router the request matched). Recording a finished request is a handful of relaxed atomic increments per series (the status class, one histogram bucket, the latency sum): no lookup, no lock and no allocation (`metrics_hot_path_allocates_nothing` counts allocations with a counting global allocator). The registry's lock is taken when a snapshot lands and when a scrape renders, never by a request.

## Export over OTLP

An operator who sets `OTEL_METRICS_EXPORTER=otlp` gets every series `GET /metrics` renders pushed to an OTLP collector as well, with the same names, labels and values. This matches Traefik's `metrics.otlp`; Caddy has no such option. Code: `src/observe/metrics/{scrape,otlp,export}.rs`, on the transport every signal shares (`src/observe/otlp/`, `docs/ref/tracing-grpc.md`).

### Settings

Process environment only. A snapshot cannot turn the exporter on, name a collector, change the interval or reach the transport.

|Variable|Default|Meaning|
|---|---|---|
|`OTEL_METRICS_EXPORTER`|`none`|`none` or `otlp`. Anything else (`prometheus`, `console`, a list) stops startup naming the variable, because an ignored exporter would leave the operator without metrics they believe they have. `otlp` needs `OTEL_EXPORTER_OTLP_ENDPOINT`: podgate has no default collector address.|
|`OTEL_METRIC_EXPORT_INTERVAL`|`60000`|Milliseconds between pushes, 100..=3600000. Checked even when the exporter is `none`, so a typo is found before it is switched on.|

The collector is the one the span exporter uses: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf` or `grpc`), `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY`, `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_EXPORTER_OTLP_TIMEOUT` and `OTEL_SERVICE_NAME` (the `service.name` resource attribute). They behave exactly as for spans, including the plaintext-off-loopback rule for gRPC. HTTP goes to `<endpoint>/v1/metrics` as protobuf; gRPC calls `opentelemetry.proto.collector.metrics.v1.MetricsService/Export`. There is no per-signal endpoint variable (`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` is not read), so the plaintext and loopback checks live in one place.

### What is sent

Every interval the service renders the same text `GET /metrics` serves, reads it back into families and encodes one `ExportMetricsServiceRequest` (split in halves if it would pass 4 MiB). Converting the scrape, instead of keeping a second view of the registry, means the exported names, types, labels and values are the scrape's by construction. One resource (`service.name`) and one scope (`podgate`, the crate version).

|Prometheus|OTLP|
|---|---|
|counter|`Sum`, monotonic, cumulative temporality (`as_int` when the text is an integer)|
|gauge, or a sample with no `# TYPE`|`Gauge`|
|histogram|`Histogram`, cumulative temporality, explicit bounds `0.005 ... 10` seconds, 13 bucket counts (the last is the overflow), `sum` in seconds, `count`|

Names are the Prometheus names, `_total` and `_seconds` included, so a dashboard or an alert written against one reads the other. `description` is the `# HELP` text and `unit` is empty. Labels are string attributes with the same keys and values. `start_time_unix_nano` is when the process started counting (counters restart at zero with the process, which is what a collector needs to know) and `time_unix_nano` is when the text was rendered.

The series cap holds. The registry applies `METRICS_SERIES_PER_TENANT` and the `other` collapse before the text exists, and the exporter keeps no copy of a label, so a tenant that invents router names cannot raise the exported series count past what a scrape shows.

### A collector that is down

Metrics are cumulative, so a skipped interval loses nothing: the next one carries everything. Each interval therefore makes one attempt (no retry loop, which would still be running when the next interval starts), bounded by `OTEL_EXPORTER_OTLP_TIMEOUT`. A failed interval (a timeout, a refused or broken connection, `UNAVAILABLE`, `RESOURCE_EXHAUSTED`, an HTTP `429`, `502`, `503` or `504`, any refusal, a metric too large for one message) adds one to `podgate_otlp_metrics_failed_total` and logs a warning with the reason, never the collector's own text and never a header value. An interval that is still running when the next one is due makes that one skipped, not queued. A partial success is a warning, not a failure. The counter is present with value 0 when the exporter is off, so an alert needs no existence check.

There is no `exported_total`: it would change on every interval and so make the exported values differ from a scrape taken a moment later.

### Cost

One `render`, one parse and one encode every interval, on the blocking pool, and one connection to the collector. A scrape does the same work. A request never touches the exporter: the registry's atomics are read exactly as a scrape reads them, so a slow or dead collector costs exported points and nothing else (`otlp_metrics_collector_down_does_not_slow_requests`). On a planned stop the service sends the last interval once more.

### Tests

`tests/otlp_metrics.rs`, through the real binary against `tests/common/otlp.rs` (a collector that records raw OTLP calls over HTTP and gRPC, with optional mutual TLS): `otlp_metrics_match_prometheus_http`, `otlp_metrics_match_prometheus_grpc`, `otlp_metrics_grpc_tls`, `otlp_metrics_collector_down_does_not_slow_requests`, `otlp_metrics_recover`, `otlp_metrics_respect_series_cap`, `otlp_metrics_off_by_default`, `otlp_metrics_bad_settings_stop_startup`. Unit tests: `prometheus_text_*` (`scrape.rs`), `otlp_metrics_encode_*` (`otlp.rs`), `otlp_metrics_settings_*` (`export.rs`).
