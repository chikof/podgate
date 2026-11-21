# Tracing

podgate continues W3C trace context, tells the upstream a child span, and exports spans over OTLP/HTTP, or OTLP/gRPC (`docs/ref/tracing-grpc.md`), to a collector the operator names. Tracing never waits for the collector, and a client cannot make a node export more than the operator allows. Code: `src/observe/tracing.rs` and `src/observe/tracing/{context,policy,tracer,export,grpc,otlp,span}.rs`.

## Process configuration

The collector is configured on the node, never in a snapshot: a snapshot is tenant-influenced data, and letting it name an address podgate calls would be a way to reach internal hosts. A snapshot that tries (`endpoint`, `headers`, anything unknown under `tracing`) is `422` `invalid_tracing`.

|Variable|Default|Meaning|
|---|---|---|
|`OTEL_EXPORTER_OTLP_PROTOCOL`|`http/protobuf`|`http/protobuf` or `grpc`. With `grpc` the endpoint, headers, TLS, compression and timeout settings are those of `docs/ref/tracing-grpc.md`.|
|`OTEL_EXPORTER_OTLP_ENDPOINT`|unset|Base URL, `http://` or `https://`, without credentials or query. Spans are POSTed to `<endpoint>/v1/traces` as `application/x-protobuf`. Unset: no span is recorded; requests are still sampled and their context propagated.|
|`OTEL_EXPORTER_OTLP_HEADERS`|unset|`name=value,name2=value2` sent with every export. Values are used as written (no percent-decoding) and never logged.|
|`OTEL_EXPORTER_OTLP_CERTIFICATE`|unset|PEM roots to trust for an `https` endpoint instead of the platform's.|
|`OTEL_SERVICE_NAME`|`podgate`|`service.name` of exported spans.|
|`OTEL_MAX_SPANS_PER_SEC`|`1000`|The node's cap on traced spans a second, 1..=1000000; each tenant may use half of it. A traced request costs two (server and upstream), charged when the request starts. The bucket holds one second of tokens.|

An invalid value stops startup with an error naming the variable. The endpoint is not checked against the upstream address policy: it is the operator's own setting, and a collector on loopback or a sidecar is the normal case that the policy denies for tenants.

## Snapshot settings

`observability.tracing` is an object (or `true` for the defaults); a router overrides it with `observability: {"tracing": false}` (or `true`). Tracing is off until a snapshot or a router turns it on. The wire (`OTEL_EXPORTER_OTLP_PROTOCOL`) is process configuration, never a snapshot setting.

```json
"observability": {
  "tracing": { "sample_percent": 10, "parent_based": true, "propagate": true, "attribute_headers": ["x-request-id", "user-agent"] }
}
```

|Setting|Default|Meaning|
|---|---|---|
|`sample_percent`|`100`|Share of root requests sampled, 0..=100, hundredths allowed.|
|`parent_based`|`true`|A valid incoming `traceparent` decides by its sampled flag, but only from a trusted peer (the entry point's `forwarded_headers`, the trust that believes `X-Forwarded-*`). From any other peer the trace id is continued and `sample_percent` decides. `false`: no caller's flag counts.|
|`propagate`|`true`|The upstream request gets a `traceparent`. `false`: podgate adds and changes nothing; the client's headers pass as they are.|
|`attribute_headers`|none|Request headers recorded on the server span as `http.request.header.<name>` (a list of values). At most 16. `authorization`, `proxy-authorization`, `cookie` and `set-cookie` are refused with `invalid_tracing`: a tenant cannot copy credentials into the operator's trace store.|

Unknown fields, a percentage outside 0..=100 and a non-boolean router switch are `invalid_tracing`.

## What happens to a request

1. Once a router matches, its effective policy decides whether the request is traced. A request no router matched is never traced, so unknown hosts create no spans.
2. A `traceparent` is accepted when exactly one such header is present and it parses (version `00`, or a newer version's first four fields; lowercase hex; neither id all zero; version `ff` refused). Otherwise a new trace starts, and the client's `tracestate` is dropped because it belongs to a trace that does not exist.
3. The verdict is `sampled` by the caller's flag (`parent_based`, a valid parent, and a peer the entry point trusts) or else by `sample_percent`, and then by the rate caps: the tenant's share (half the node cap) and the node cap. A request over either is not sampled; `podgate_trace_rate_limited_total` counts it.
4. The upstream request gets `traceparent: 00-<trace id>-<upstream span id>-<01|00>` carrying that verdict, whether or not this node exports. `tracestate` passes through unchanged when the trace is continued; podgate adds no entry. The header is written after the middleware chain, so a middleware cannot hide the context from the upstream.
5. After the response, a sampled request on a node with a collector queues two spans. Nothing is copied from a request that is not sampled.

Trust: any caller may continue a trace (its trace id and parent span id are kept, so it can correlate its own traces), but its sampled flag is believed only when the peer is trusted by the entry point's `forwarded_headers`. An untrusted client therefore cannot force sampling. Each tenant may use at most half of `OTEL_MAX_SPANS_PER_SEC` (a bucket of its own, charged with the node's), so one tenant's flood, forced or sampled locally, cannot take every other tenant's traces. A tenant that is alone on a node is held to that half too.

## Spans

Server span, named `<METHOD> <router>` (`<METHOD>` when no router matched, which is never traced), with exactly these attributes when they exist:

|Attribute|Value|
|---|---|
|`http.request.method`|The method.|
|`url.path`|The path as matched, at most 256 bytes. The query is never recorded.|
|`http.response.status_code`|The status the client got; absent when no response was written.|
|`server.address`|The request host, without a port.|
|`network.peer.address`|The address of the connection's peer (with PROXY protocol, the one it carries), no port.|
|`podgate.tenant`, `podgate.app`, `podgate.router`, `podgate.service`|The matched router's names.|
|`podgate.revision`|The revision that served it, when one was chosen.|
|`http.request.header.<name>`|Each `attribute_headers` entry the request carried, at most 8 values of 256 bytes.|

Its status is error for a `5xx`, or for a request Pingora ended with an error before any response. Its parent is the caller's span when the trace is continued. A request a middleware answered (a `401`, say) has a server span and no upstream span.

Upstream span (kind client), a child of the server span, from the request being sent to the end of the response body: `http.request.method`, `http.response.status_code`, `server.address` and `server.port` (the upstream server), `podgate.revision`. Its span id is the one the upstream was told. A request retried on another server has one upstream span, started at the first attempt.

The client IP, query, cookies, credentials and every header not in `attribute_headers` are never attributes. Every string is cut at 256 bytes when it is copied, so a hostile request cannot make the queue hold more than a bounded amount of text.

## Export

Spans queue in memory, at most 2048; one background service takes up to 512 at a time, when 512 have queued or two seconds have passed, and POSTs them. An export gives up after 3 seconds (connecting included) and is retried twice after 250 ms and 500 ms when the collector is unreachable, slow, or answers `429`, `502`, `503` or `504`; any other answer drops the batch. A full queue drops the new spans. Everything dropped counts in `podgate_trace_dropped_total`. At shutdown the exporter tries the queued spans once more and drops the rest.

Because the request path only takes a token and pushes into the queue under a short lock, a collector that is down, hanging or refusing connections costs spans, never request latency.

|Metric|Meaning|
|---|---|
|`podgate_trace_spans_exported_total`|Spans the collector accepted.|
|`podgate_trace_dropped_total`|Spans dropped by a full queue or a failed export.|
|`podgate_trace_rate_limited_total`|Requests not traced because the cap was spent.|
|`podgate_trace_queue_spans`|Spans waiting (gauge).|

## Compared with Traefik and Caddy

Traefik's `tracing.otlp.http {endpoint, headers, tls}` is `OTEL_EXPORTER_OTLP_ENDPOINT`, `_HEADERS` and `_CERTIFICATE` here (`tracing.otlp.grpc` is in `docs/ref/tracing-grpc.md`); `sampleRate` is `sample_percent`; `serviceName` is `OTEL_SERVICE_NAME`; `capturedRequestHeaders` is `attribute_headers`. Not built: `capturedResponseHeaders`, `safeQueryParams` (the query is never recorded), and Caddy's per-route `span` name.
