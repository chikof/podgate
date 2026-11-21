# Tracing over OTLP/gRPC

Change 0112 adds a second wire to the span exporter of change 0067 (`docs/ref/tracing.md`): the unary `opentelemetry.proto.collector.trace.v1.TraceService/Export` call to a collector's gRPC port (4317 by default). The spans, the sampling, the per-node and per-tenant rate caps, the queue of 2048, the batch of 512 and the retry loop are 0067's and are shared; only the call that carries one encoded batch differs. Code: `src/observe/tracing/grpc.rs` (the channel), `src/observe/tracing/export.rs` (settings, the shared loop).

The client is `h2` over `tokio-rustls`, with the OTLP messages already in `src/observe/tracing/otlp.rs`. No `tonic` and no new gRPC framework: one unary call needs a length-prefixed message, a few headers and trailers, which `h2` carries.

## Process configuration

Never a snapshot, as for OTLP/HTTP: a snapshot that names a protocol or an address is `422` `invalid_tracing`.

|Variable|Default|Meaning|
|---|---|---|
|`OTEL_EXPORTER_OTLP_PROTOCOL`|`http/protobuf`|`http/protobuf` or `grpc`. Any other value (`http/json` included) stops startup.|
|`OTEL_EXPORTER_OTLP_ENDPOINT`|unset|For `grpc`: `http://host:4317` or `https://host:4317`, without a path, query or credentials. A missing port is the scheme's (80 or 443). Unset: nothing is exported.|
|`OTEL_EXPORTER_OTLP_HEADERS`|unset|`name=value,...` sent as gRPC metadata on every call. Names are lowercased. `content-type`, `content-length`, `content-encoding`, `te`, `host`, `connection`, `transfer-encoding` and `grpc-*` are refused. Values are sensitive: never logged, and never indexed by HTTP/2 header compression.|
|`OTEL_EXPORTER_OTLP_CERTIFICATE`|platform roots|PEM roots to trust for an `https` endpoint.|
|`OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_KEY`|unset|PEM chain and key for mutual TLS. Set both or neither.|
|`OTEL_EXPORTER_OTLP_COMPRESSION`|`none`|`gzip` or `none`. `gzip` sends each message with the compressed flag and `grpc-encoding: gzip`.|
|`OTEL_EXPORTER_OTLP_INSECURE`|`false`|`true` allows a plaintext (`http://`) endpoint that is not on loopback. Logged at warn level at startup.|
|`OTEL_EXPORTER_OTLP_TIMEOUT`|`3000`|Milliseconds one call may take, connecting and TLS included, 1..=10000. Sent as `grpc-timeout`. Applies to OTLP/HTTP too.|

Spans carry hostnames and paths, so a plaintext endpoint is refused unless its host is `localhost` or a loopback address, or `OTEL_EXPORTER_OTLP_INSECURE=true` says the operator accepts it. `https` always works. A name is not resolved to decide: `collector.internal` over `http://` needs the variable.

`OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`, `_CLIENT_KEY`, `_COMPRESSION` and `_INSECURE` apply to `grpc` only; with `http/protobuf` they stop startup instead of being ignored. Every invalid value stops startup with an error naming the variable; header values are never quoted in it.

## The call

One HTTP/2 connection is made on demand and reused. A call is `POST /opentelemetry.proto.collector.trace.v1.TraceService/Export` with `content-type: application/grpc`, `te: trailers`, `grpc-timeout`, `user-agent: podgate/<version>`, the metadata, and one message: the `ExportTraceServiceRequest` of spans, the same bytes the HTTP exporter POSTs, in a 5-byte frame. A request over 4 MiB (collectors refuse more by default) is split in halves until each fits; a single span over it is dropped and counted.

A connection that fails, breaks, is closed by the collector (`GOAWAY`) or times out is forgotten, and the next attempt connects again. The attempts and their backoff are 0067's: three sends, waiting 250 ms and 500 ms between them. There is no connection kept alive in the background: a dead collector costs only the attempts a batch makes.

|Answer|What the exporter does|
|---|---|
|`OK`|Spans are exported. A `partial_success` counts `rejected_spans` of them in `podgate_trace_dropped_total` and the rest in `podgate_trace_spans_exported_total`; a partial success is not retried.|
|`UNAVAILABLE`, `RESOURCE_EXHAUSTED`, `DEADLINE_EXCEEDED`|Retried. When the trailers carry `grpc-status-details-bin` with a `google.rpc.RetryInfo`, its delay replaces the backoff, at most 5 seconds.|
|`INVALID_ARGUMENT`, `UNAUTHENTICATED`, and every other status|The batch is dropped and counted in `podgate_trace_dropped_total`.|
|No `grpc-status`: HTTP `429`, `502`, `503`, `504`; a stream that ends without trailers; a reset or broken connection|Retried.|
|No `grpc-status`: any other HTTP status|The batch is dropped and counted.|

After the last attempt a batch that never got through is dropped and counted too. The log line (`dropped a batch of spans: export failed`) names the status, never the collector's `grpc-message` (it is the collector's own text and could echo what it was sent), and never a header value. The answer is read up to 1 MiB.

## Latency and bounds

The exporter is a background service: the request path only takes a rate-cap token and pushes into the bounded queue under a short lock. A collector that is down, hangs after accepting a call, answers slowly, refuses every call or closes the connection after each one costs spans (`podgate_trace_dropped_total`) and nothing else. The queue (2048) drops new spans when full, and `OTEL_MAX_SPANS_PER_SEC` (with each tenant's half) bounds how many are traced at all, exactly as for OTLP/HTTP.

## Compared with Traefik and Caddy

Traefik's `tracing.otlp.grpc {endpoint, insecure, tls, headers}` is `OTEL_EXPORTER_OTLP_ENDPOINT`, `_INSECURE`, `_CERTIFICATE` with the client certificate and key, and `_HEADERS` here, selected by `OTEL_EXPORTER_OTLP_PROTOCOL=grpc`. Caddy selects the OTLP exporter through the same standard variables. Not built: per-signal variables such as `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `http/json`, and a persistent stream of spans (each batch is its own unary call).

## Tests

`tests/tracing_grpc.rs`, through the real binary against a fake collector written on `h2` (and a small OTLP/HTTP one, to compare the wires): `grpc_export_reaches_collector`, `grpc_spans_match_http_exporter`, `grpc_headers_as_metadata`, `grpc_gzip_compression`, `grpc_tls_and_client_cert`, `grpc_plaintext_remote_refused`, `grpc_retry_on_unavailable`, `grpc_drop_on_invalid_argument`, `grpc_partial_success_counted`, `grpc_collector_down_does_not_slow_requests`, `grpc_queue_bounded`, `grpc_rate_cap_holds`, `grpc_protocol_only_from_environment`, `snapshot_cannot_set_otlp_endpoint` and `grpc_headers_never_logged`. The settings and the pure parts (retry delay, framing, gzip, the plaintext rule) have unit tests in `src/observe/tracing/{export,grpc}.rs`.
