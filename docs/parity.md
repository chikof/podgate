# Parity with Traefik and Caddy

Where podgate stands against Traefik (v3) and Caddy (v2), feature by feature. Each row names the spec that builds it (in `the project history`, `done/` once merged), or the decision that it is deferred or declined, with a recommendation. "Built" means merged changes 0001 to 0019; everything else is a todo spec until it moves to `done/`.

Reading the last column: a spec id is the plan; `deferred` and `declined` rows say why and what to do next. Deliberate differences from Traefik's behaviour are in the spec of the feature (Context, "Deliberate differences") and not repeated here.

Model, for orientation: podgate is push-only. A control-plane writer (podkit's agent, or `podgate-provider`, never both on one node) pushes one JSON snapshot; podgate compiles it, rejects what it cannot honour, and serves it. Providers, rule strings and dynamic discovery live outside the daemon.

## Entry points

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Forwarded-header trust | `forwardedHeaders.trustedIPs`, `insecure` | `trusted_proxies`, `client_ip_headers` | built: `forwarded_headers {trusted_ips, insecure}` per entry point; untrusted peers' headers are removed |
| Several named listeners | `entryPoints.<n>.address` | listener addresses, `bind` | built (`ENTRY_POINTS`, process config; `PROXY_ADDR` and `PROXY_TLS_ADDR` stay as the `web` and `websecure` shorthand) |
| Per-router entry point list | `entryPoints` on a router | site address | built (unbound names rejected as `unknown_entry_point`, `tcp` and `udp` ones as `entry_point_protocol`) |
| Per-tenant entry point access | none | none | built (`EntryPointPolicy.tenants`, `entry_point_forbidden`) |
| TCP and UDP listeners | `/tcp`, `/udp` suffix | `layer4` plugin | Built: `udp`, `tcp` |
| `X-Forwarded-*` and `X-Real-IP` sent to upstreams | yes (adds `-Server`) | `X-Forwarded-For`, `-Proto`, `-Host` | built: X-Forwarded-For, -Proto, -Host, -Port and X-Real-IP by default (Traefik's set minus -Server, which is `forwarded.server: true`); `forwarded.rfc7239` adds `Forwarded`; forged inbound values of untrusted peers are removed |
| PROXY protocol in | `proxyProtocol.trustedIPs` | `proxy_protocol` wrapper | built: strict, no fallback; `docs/ref/proxy-protocol.md` |
| HTTP to HTTPS redirect on an entry point | `http.redirections.entryPoint` | automatic HTTPS redirects | built: `redirect {to, permanent}`, `302`/`301` for `GET` and `307`/`308` for other methods, as Traefik, default not permanent |
| Read, write and idle timeouts | `transport.respondingTimeouts` | `servers { timeouts }` | built: `write_secs`, `idle_secs`, and `read_secs` on plain entry points; `header_secs`, and `read_secs` on a TLS entry point, are `unsupported_setting` (Pingora 0.9) |
| HTTP/2 stream limit, max header size | `http2.maxConcurrentStreams`, `http.maxHeaderBytes` | `max_header_size`, `protocols` | built: `http2.max_concurrent_streams` on TLS entry points, `max_header_bytes` up to 1048575 |
| Underscore and alias header names | `aliasHeadersStrategy`, `underscoreHeadersStrategy` | none | built: `underscore_headers` `keep` (default), `delete`, `reject` |
| Encoded characters policy | `http.encodedCharacters` | none | built (normalization and refusal of encoded slashes, NUL, encoded dot segments), built: `allow_encoded_slash` accepts `%2F` only, kept inside its segment |
| Graceful shutdown | `transport.lifeCycle` | `grace_period` | built (`REQUEST_TIMEOUT_SECS`, SIGTERM) |
| HTTP/3 and QUIC | `http3` | default | built: a QUIC front inside the process (`quinn`, `h3`) bridged into the entry point's pipeline, `;http3` on an `https` entry point, `Alt-Svc` only for apps that allow it, per-connection and per-tenant memory budgets, retry tokens under load, no 0-RTT; no mTLS, on-demand certificates or WebSockets over h3; `docs/ref/http3.md` |

## Routing

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Host exact and wildcard | `Host` | `host`, site names | built |
| Host regexp | `HostRegexp` | `header_regexp Host` | built: a regexp only narrows a literal claim; a bare one needs an exclusive entry point or the operator's allowance (`catch_all_not_allowed`) |
| Path, prefix, regexp | `Path`, `PathPrefix`, `PathRegexp` | `path`, `path_regexp` | built (prefix is whole-segment) |
| Method | `Method` | `method` | built |
| Header, header regexp | `Header`, `HeaderRegexp` | `header`, `header_regexp` | built: `header`, `header_regexp`, `query`, `query_regexp` leaves; names case-insensitive for headers, query decoded as form-urlencoded; unanchored regexps; no Caddy glob or `!`, use `not` |
| Query, query regexp | `Query`, `QueryRegexp` | `query` | built: `header`, `header_regexp`, `query`, `query_regexp` leaves; names case-insensitive for headers, query decoded as form-urlencoded; unanchored regexps; no Caddy glob or `!`, use `not` |
| Client IP | `ClientIP` (peer) | `remote_ip`, `client_ip` | built: `client_ip` resolves through the entry point's trusted proxies, IPv4-mapped normalized |
| Boolean combination | `&&`, `||`, `!` in a rule string | `not`, named matchers | model (`all`, `any`, `not`), 0022; rule strings are translated by 0071 |
| Explicit priority | `priority` | route order | 0022 (within a tenant); Traefik's order reproduced by 0071 |
| Ambiguity detection | none | none | 0022 (`route_ambiguity`) |
| `protocol` matcher (http, grpc, ws) | none | `protocol` | not a leaf: `header` and `header_regexp` leaves or a CEL expression express it |
| Expression matchers (CEL) | none | `expression` | 0105 (sandboxed, static cost limit, claims no host) |
| Per-route TLS options | `tls.options` on a router | per-site `tls` | declined as written: TLS is decided before routing, so policy belongs to the app and hosts (`tls_policy_conflict`) |

## Services

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Round robin, weights | default WRR | `round_robin`, `weighted_round_robin` | built (`round_robin` in 0022, smooth `weighted_round_robin` in 0031; weight `0` receives nothing, where Traefik treats it as 1) |
| Least connections | `leasttime`, p2c | `least_conn` | built (full scan up to 8 servers, then two random candidates) |
| Power of two choices | `strategy: p2c` | `random_choose` | built (0031 `p2c_ewma`: latency-aware peak-EWMA, which neither has) |
| Random | none | `random` | built |
| Hash policies | `strategy: hrw` | `ip_hash`, `uri_hash`, `header`, `query`, `cookie` | built: `ip_hash`, `uri_hash`, `header_hash`, `hrw` (consistent hashing on a keyed ketama ring, rendezvous for `hrw`, client address resolved by 0026, random fallback without a key); `query` and `cookie` declined, sticky cookies are 0036 |
| Active health checks | `healthCheck` | `health_uri` and friends | built (`health_check` with thresholds, status ranges, body regex, per-server jitter and a global probe cap; HTTPS probes use the service's transport: private CA, SNI, client certificate) |
| Passive ejection | none (circuit breaker only) | `max_fails`, `fail_duration`, `unhealthy_*` | built (`passive` on `loadbalancer`; connect failures, timeouts, 5xx and slow responses eject a server for a growing time, capped by a percentage and never the last available server; see `docs/ref/svc-outlier.md`) |
| Retries | `retry` middleware | `lb_retries`, `lb_try_duration` | built (0035 done: connect errors for any method; a dead reused connection only for listed methods and a replayable body; no retry on a response status) |
| Sticky sessions | `sticky.cookie` | `lb_policy cookie` | built (HMAC cookie on `loadbalancer`, falls back and re-pins when the server is gone, unhealthy or ejected; see `docs/ref/svc-sticky.md`) |
| Weighted service of services | `weighted` | none | built (children `name` or `name@revision`, dead and asleep children skipped by one eligibility rule, sticky by cookie on the parent, depth 4, `service_cycle`; see `docs/ref/svc-weighted-failover.md`) |
| Failover service | `failover` | `lb_try_duration` partly | built (fallback while the main service has no healthy server, `fallback_hold_secs` against flapping, a main service with no server wakes the app instead; see `docs/ref/svc-weighted-failover.md`) |
| Mirroring | `mirroring` | none in core | built (copies of a percentage to loadbalancers of the same app, `name@revision` for the successor release, body copy capped at `max_body_size` and charged to the tenant before it exists, shed first and never queued, marker `x-podgate-mirrored`, credentials off by default; see `docs/ref/svc-mirroring.md`) |
| Pass host header | `passHostHeader` | `header_up Host` | model (`pass_host_header`), 0022 |
| Revision-aware rollout, canary, skew pinning | weighted services by hand | none | built |
| Scale to zero with wake | none | none | built |
| Request shadow and replay of failures | none | none | built |
| DNS names as servers | yes (dialer) | yes, plus dynamic upstreams | built (A and AAAA, TTL, policy on every answer; SRV in 0096), see docs/ref/dns-resolver.md |
| SRV upstreams | none | `srv` dynamic upstreams | built (`resolve: "srv"` with priorities, weights, the TTL, a port deny list because DNS then chooses the port, and the address policy on every target), see docs/ref/dns-srv.md; `multi` and other sources declined |
| Upstream address policy (SSRF) | none | none | built: operator allow and deny CIDRs per tenant; loopback, link-local, metadata, unspecified and multicast denied by default; checked at compile and before every dial |
| Response flush interval | `responseForwarding.flushInterval` | `flush_interval` | declined: Pingora streams chunks as they arrive |
| Tunnel lifetime and close delay | n/a | `stream_timeout`, `stream_close_delay` | built: `max_stream_lifetime_secs`, `stream_close_delay_secs`, and `tunnel_idle_timeout_secs` (neither Traefik nor Caddy has an idle timer: both kept an idle WebSocket open past 250 s, measured on 3.7.16 and 2.11.9); all off by default, an explicit entry point `timeouts.read_secs` stays a ceiling; `docs/ref/transport-extras.md` |
| WebSocket proxying | transparent | transparent | built and verified (`docs/ref/websocket.md`; upgrade, frames, TLS, the middleware matrix, drain and shutdown tested end to end) |

## Transports

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Upstream TLS, SNI, CA, client certificate | `serversTransport` | `transport http { tls_* }` | built (`min_tls_version` 1.3 is `unsupported_setting`, see `docs/ref/transports.md`) |
| `insecureSkipVerify` | yes | `tls_insecure_skip_verify` | built (allowed, listed as a posture change) |
| HTTP/2 and h2c upstream | `h2c://`, `disableHTTP2` | `versions h2 h2c` | built (`http2`, ALPN for `https://`, `h2c://` by prior knowledge, see `docs/ref/transports.md`) |
| h2c on entry points, gRPC | automatic h2c on plain entry points | `protocols h1 h2c` | built: `entry_points[].http2.h2c`; gRPC verified end to end, `docs/ref/grpc.md` |
| Dial, response and idle timeouts, pool size | `forwardingTimeouts`, `maxIdleConnsPerHost` | `dial_timeout`, `keepalive_*` | built (dial, read, write and idle timeouts; `max_idle_per_host` is `unsupported_setting`, pool size is `UPSTREAM_POOL_SIZE`) |
| SPIFFE and `peerCertURI` | `spiffe`, `peerCertURI` | none | 0104 (Workload API client, one SVID per tenant, upstream mTLS and client identity) |
| PROXY protocol to HTTP upstreams | none | `proxy_protocol` in transport | built: `proxy_protocol {version: 1\|2}` on a `servers_transport`, per-client pool key, `LOCAL` for probes and internal callers, refused for mirrors; `docs/ref/transport-extras.md` |

## Middlewares

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Add and strip prefix, replace path (and regexp) | `addPrefix`, `stripPrefix*`, `replacePath*` | `uri`, `rewrite`, `handle_path` | built: `src/middleware/{add_prefix,strip_prefix,strip_prefix_regex,replace_path,replace_path_regex}.rs`; `strip_prefix` strips whole segments, every result is re-normalized (no `//` authority, no dot segments, an encoded slash is a `500`), regexes are linear time with groups checked at compile |
| Redirect scheme and regexp | `redirectScheme`, `redirectRegex` | `redir` | built: `302`/`301` for `GET` and `307`/`308` for other methods (`middleware::redirect::status_for`), measured on the pinned Traefik 3.7.16; the Location is refused on control characters (also escaped), other schemes and userinfo; a `redirect_scheme` removal is a plan posture change |
| Custom headers, security headers | `headers` | `header`, `request_header` | built: `src/middleware/headers.rs`; framing headers cannot be set; HSTS only over TLS |
| CORS | in `headers` | plugin | built: exact origins or anchored regexes, never reflected; `*` with credentials refused |
| Content type sniffing | `contentType` | none | built: never sniffs; `auto_detect: true` refused |
| Basic auth | `basicAuth` (MD5, SHA1, bcrypt) | `basic_auth` | built: `src/middleware/basic_auth.rs`; bcrypt and argon2 only, costs capped; verification bounded by `BASIC_AUTH_MAX_CONCURRENT`, a tenant share and the tenant's `max_buffer_bytes` |
| Digest auth | `digestAuth` | none | built: `src/middleware/digest_auth.rs`; SHA-256 and MD5 by HA1 length, qop=auth only, stateless HMAC nonces, bounded charged nc table, state kept across pushes; Authorization stripped upstream by default |
| Forward auth | `forwardAuth` | `forward_auth` | built (fail closed) |
| IP allow list | `ipAllowList` | `remote_ip` plus `respond` | built |
| Rate limit | `rateLimit` | plugin | built: `src/middleware/rate_limit.rs`; per node, bounded table charged to the tenant; the control plane divides a global limit by the node count |
| Cluster-wide rate limit | Hub or Enterprise (Redis) | plugins | built: `scope: "cluster"` on `rate_limit` through a Redis-compatible store from `RATE_LIMIT_STORES_FILE`; a required per-route `on_store_error` (`allow` with a local fallback bucket, or `deny`), a circuit and a bounded call; the address and credentials only from that file, never a snapshot; measured ceiling about 107,000 req/s through one store; `docs/ref/ratelimit-cluster.md` |
| In-flight request limit | `inFlightReq` | none | built (per node); 0102 (cluster-wide with leases) |
| Circuit breaker | `circuitBreaker` (expression) | none | built: `src/middleware/circuit_breaker.rs`; structured `trip_when`, no expression language; `min_requests` floor |
| Buffering, body size limits | `buffering` | `request_body max_size`, `request_buffers` | built: memory only, charged to `max_buffer_bytes` (no `mem_*`, no disk spill); `buffer_request` holds a body of at most 64 KiB before the upstream request starts; response limits need `buffer_response`; a chunked response over its limit is reset, not a `502` (Pingora sends the head first); a held response that ends in HTTP/2 trailers is released ahead of them |
| Compression | `compress` (gzip, brotli, zstd) | `encode` | built (gzip 0009; gzip, brotli, zstd 0053, pure Rust, bounded; `min_bytes` not applied to unknown-length bodies) |
| Custom error pages | `errors` | `handle_errors` | built: `src/middleware/errors.rs`; the page comes from a service of the same app, with only `Host` and `Accept` sent (Traefik forwards the request headers), a bounded body charged to the tenant, and the original response kept on any failure |
| Fixed response | none | `respond`, `error`, `abort` | built (`respond`): `src/middleware/respond.rs`; `1xx` refused, header values checked at compile |
| Pass TLS client certificate | `passTLSClientCert` | placeholders | built: `pass_tls_client_cert` middleware, Traefik's two headers; forged headers are always stripped |
| gRPC-Web | `grpcWeb` | plugin | built: `grpc_web` middleware, binary and text, streaming, trailers as a body frame (trailers-only too, `grpc-status: 13` over 8 KiB, `2` when a response ends without trailers), `allow_origins` never reflected; every service reachable from the router must speak HTTP/2 (`invalid_middleware` otherwise) |
| Chain of middlewares | `chain` | `route`, `handle` | 0022 |
| Plugins | Yaegi (Go) plugins | Go modules | WASM filters in process; 0099 out-of-process plugins over a unix socket (no native code in podgate, any language); 0113 runs Traefik Go plugins through a Yaegi host. `dlopen` plugins are rejected |
| JWT verification | Traefik Hub only | plugins | `jwt_auth` built (JWKS fetched through the upstream policy; names are resolved per call since 0090) |
| OIDC login (authorization code, PKCE) | Traefik Hub only | `caddy-security` plugin | built (stateless encrypted cookie sessions; no refresh tokens) |
| Response caching | Hub only | `cache` plugin | built: memory only, bounded per tenant (charged to `max_buffer_bytes`, capped share), no disk tier, no distributed mode, purge API |
| Templating (`templates`), `map`, `vars` | none | yes | declined: snapshots are generated data; templating belongs in the writer |
| Static files: `file_server`, `try_files`, precompressed | none | yes | built: operator-declared per-tenant roots opened as `cap-std` handles (`STATIC_ROOTS_FILE`), no `..` or symlink escape, no hidden files, `index`, `try_files`, status pages, validators, ranges, `br`/`gzip` sidecars, file buffers charged to `max_buffer_bytes`; see `docs/ref/svc-static.md` |
| Directory listings (`browse`) | none | `file_server browse` | 0101 (opt-in by operator root and service, escaped names, no hidden files) |
| `php_fastcgi` and FastCGI | none | `php_fastcgi` | 0100 (operator-declared pools and code roots, `.php` only, httpoxy and path-info defences) |
| Rule strings in the configuration | the native syntax | none | 0106 (`rule` on a router, parsed by the 0071 crate at compile; same tenant and catch-all rules) |

## TLS and certificates

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Certificates from the control plane | `tls.certificates` | `tls cert key` | built (`certificates`) |
| ACME HTTP-01 | `httpChallenge` | default | built (HA, ARI, on-demand) |
| ACME TLS-ALPN-01 | `tlsChallenge` | default | built (opt-in per app; answered by the pre-TLS hook because Pingora's listener cannot carry `acme-tls/1`, see `docs/ref/acme-alpn01.md`) |
| ACME DNS-01 and wildcard certificates | `dnsChallenge` | `acme_dns` plugins | built (0081 in podgate; 0082 adds the provider's ACME broker and the solver hook, 0083 the solvers); no DNS credential in podgate, see `docs/ref/acme-dns01.md` |
| ACME options (key type, preferred chain, profile, EAB) | `keyType`, `preferredChain`, `profile`, `eab` | `key_type`, `preferred_chains`, `acme_eab` | partly built (EAB, account key in 0014); recommend a small follow-up for key type and preferred chain |
| On-demand certificates | none | `on_demand_tls` with `ask` | built (the control plane approves through `acme.requested_hosts`) |
| Internal CA (`tls internal`) | none | yes | 0103 (key material in the provider and offline root, name-constrained intermediate, short-lived leaves) |
| OCSP stapling | none | automatic | built (verified staples, fetched through the upstream policy; must-staple by default, `ocsp: on` for any certificate with a responder, see `docs/ref/ocsp.md`) |
| Mutual TLS (client auth) | `clientAuth` | `client_auth` | built (0021 enforcement, 0057 modes) |
| Min and max version, cipher suites, curves, ALPN | `tls.options` | `protocols`, `ciphers`, `curves`, `alpn` | built (`max_version` and `curves` are rejected, not ignored) |
| Default certificate, strict SNI | `tls.stores.default`, `sniStrict` | `default_sni`, `fallback_sni` | built (strict SNI is per app) |
| SNI against Host check | none (domain fronting possible, GHSA-fh26-gfpp-7xxx) | `strict_sni_host` | built, on by default |
| Session ticket control | `disableSessionTickets` | `session_tickets` | built as a refusal: tickets are listener wide and stay on; `session_tickets` is rejected with `unsupported_setting` |
| TLS passthrough | `tls.passthrough` on TCP routers | `layer4` | built on `tcp` entry points; shared port with HTTP routers 0060 (measured) |

## TCP and UDP

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| TCP routers by SNI, ALPN, client IP | `HostSNI`, `ALPN`, `ClientIP` | `layer4` | Built: `ClientIP`, `HostSNI`, `HostSNIRegexp`, `ALPN` and passthrough or termination |
| TCP load balancing, proxy protocol out, termination delay | `tcp.services` | `layer4 proxy` | built: load balancing with half-close, idle timeout and connect failover; PROXY v1/v2 towards servers, TLS to servers through a `servers_transport`, `termination_delay_ms`; `docs/ref/l4-tcp.md`, `docs/ref/l4-middleware.md` |
| TCP middlewares | `inFlightConn`, `ipAllowList` | none | built: `in_flight_conn` per source with the bounded table of `in_flight_req`, `ip_allow_list` on the peer or PROXY source, run before the tenant's slot and any dial; `docs/ref/l4-middleware.md` |
| TCP health checks | `healthCheck` (v3) | `layer4` passive | built (connect, `send`/`expect` including a banner, TLS, other port, PROXY v2 header, thresholds, `unhealthy_interval_secs`; `no_healthy_server` refusal) |
| UDP routers and services | `udp.*` | `layer4` | built (sessions, idle timeout, bounded table, tenant buffer charge, eviction of one-datagram sessions, optional reply byte ratio) |

## Providers and discovery

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Docker and Podman labels | Docker provider | `caddy-docker-proxy` | 0070 (`podgate.*`), 0071 (`traefik.*` subset) |
| Traefik rule strings | native | none | 0071 (translated; priority equals rule length) |
| Kubernetes Ingress | yes | ingress controller | 0072 |
| Gateway API | HTTPRoute, GRPCRoute, TLSRoute, TCPRoute | none first-party | 0073, 0074 (status), 0075 (L4 routes) |
| Kubernetes custom resources | `IngressRoute` and friends | none | 0076 (`PodgateRoute`, `PodgateMiddleware`) |
| Nomad | Nomad provider | none | 0077 |
| File | File provider (watch, templates) | Caddyfile, JSON | built (YAML, TOML and JSON, a file or a directory, polling watch, last good content on a broken file, no templating; reference `docs/ref/provider-file.md`); Traefik files via 0079 (also a migration linter) |
| Certificate storage and cluster issuance | `storage` (`acme.json`) in the proxy; clusters need a KV store or Enterprise | `storage` file, clustering through a shared storage module | built (the provider's broker keeps certificates, account key and answers in a `0700` state directory, persisted before pushed; follower providers read it; podgate stays stateless) |
| Consul Catalog | yes | none | 0093 |
| Amazon ECS | yes | none | 0107 |
| Docker Swarm | yes | `caddy-docker-proxy` | 0108 |
| etcd, Redis (key trees) | yes | none | 0109 (shared key-value layer), 0110 |
| HTTP provider | yes | `--config <url>` | 0111 |
| Marathon, Rancher, Nomad-less legacy providers | Marathon, Rancher (removed in v3) | none | not planned: end-of-life platforms |
| One writer per node | not applicable (providers merge in-process) | not applicable | built (refused by name, takeover by the operator; 0069: the provider pushes as `podgate-provider` and stops with an error naming another writer), 0080 |
| Tenants, budgets, host claims | none | none | built; provider side built (a tenant claims only its configured `hosts`, labels only from `label_sources`, catch-all preflight, quarantine of rejected objects; reference `docs/ref/provider.md`) |

## Observability and operations

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Access log (fields, filters, JSON and CLF) | `accessLog` | `log` | built (query and headers dropped by default, credential headers redacted, never blocks a request) |
| Prometheus metrics per entry point, router, service | `metrics.prometheus` | `metrics` | built (separate metrics listener, cardinality caps) |
| OpenTelemetry tracing | `tracing.otlp` | `tracing` | built (OTLP over HTTP; `capturedResponseHeaders`, `safeQueryParams` not built), 0112 (OTLP over gRPC) |
| Health endpoint | `ping` | none | built (`/healthz`, `/readyz` on the admin socket) |
| JSON schema of the configuration | none | `caddy adapt`, JSON docs | built (`GET /v1/schema`, generated from the model types) |
| Validate without applying | none | `caddy validate` | built (`POST /v1/snapshot/validate`, the same compile as the push), plan built |
| Explain a route | none | none | built, extended by 0022 |
| Read-only overview API | `/api/*` | admin API | built (one document with filters and a cursor, 4 MiB cap, no secrets, `GET` only; `summary.writer` shows the pinned writer) |
| Dashboard (web UI) | `dashboard` | none | Built: embedded, read-only, separate listener, Host check and optional Basic auth, never shows events or secrets (`docs/ref/dashboard.md`) |
| Config reload without dropping connections | yes | yes | built (atomic swap) |
| Auto-revert of a bad config | none | none | built |
| Benchmark against both | n/a | n/a | 0020 |

## Not planned, with a recommendation

Every item the earlier passes deferred or declined now has a spec in the matrix. What remains is not planned on purpose.

| Item | Why it is not planned | Recommendation |
|---|---|---|
| Native plugins by `dlopen` | Native code in the proxy's address space breaks memory safety and every budget (0099 records the rejection) | Use out-of-process plugins or WASM filters |
| Templating, `map`, `vars` (Caddy) | Snapshots are generated data | Template in the snapshot writer |
| Per-route TLS options | TLS is decided before routing | Per-app policy; separate hosts for different policies |
| Marathon, Rancher providers | End-of-life platforms | None |
| WebSockets over HTTP/2 and HTTP/3 | Pingora 0.9.1 does not send `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441), so an extended `CONNECT` is reset with `PROTOCOL_ERROR` and clients use HTTP/1.1 (`docs/ref/websocket.md`); no WebSockets over h3 | Use HTTP/1.1 WebSockets; revisit when Pingora enables the setting |
| `flush_interval` | Pingora streams chunks as they arrive | Nothing to do |
