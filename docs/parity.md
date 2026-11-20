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
| TCP and UDP listeners | `/tcp`, `/udp` suffix | `layer4` plugin | 0028 parses them (startup stops naming the entry point), 0058, 0062 |
| `X-Forwarded-*` and `X-Real-IP` sent to upstreams | yes (adds `-Server`) | `X-Forwarded-For`, `-Proto`, `-Host` | 0097 (Traefik's set minus `-Server`, which is opt-in; found missing by the 0020 benchmark) |
| PROXY protocol in | `proxyProtocol.trustedIPs` | `proxy_protocol` wrapper | 0029 (strict, no fallback) |
| HTTP to HTTPS redirect on an entry point | `http.redirections.entryPoint` | automatic HTTPS redirects | 0030 |
| Read, write and idle timeouts | `transport.respondingTimeouts` | `servers { timeouts }` | 0030 (each knob works or is rejected as `unsupported_setting`) |
| HTTP/2 stream limit, max header size | `http2.maxConcurrentStreams`, `http.maxHeaderBytes` | `max_header_size`, `protocols` | 0030 (same rule) |
| Underscore and alias header names | `aliasHeadersStrategy`, `underscoreHeadersStrategy` | none | 0030 (`underscore_headers`) |
| Encoded characters policy | `http.encodedCharacters` | none | built (normalization and refusal of encoded slashes, NUL, encoded dot segments), 0030 (`allow_encoded_slash` opt-in) |
| Graceful shutdown | `transport.lifeCycle` | `grace_period` | built (`REQUEST_TIMEOUT_SECS`, SIGTERM) |
| HTTP/3 and QUIC | `http3` | default | 0086 (a QUIC front inside the process, per-connection and per-tenant memory budgets; no mTLS or WebSockets over h3) |

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
| Hash policies | `strategy: hrw` | `ip_hash`, `uri_hash`, `header`, `query`, `cookie` | 0032 (`ip_hash`, `uri_hash`, `header_hash`, `hrw`; `query` and `cookie` declined, sticky is 0036) |
| Active health checks | `healthCheck` | `health_uri` and friends | built (`health_check` with thresholds, status ranges, body regex, per-server jitter and a global probe cap; HTTPS probes use the service's transport: private CA, SNI, client certificate) |
| Passive ejection | none (circuit breaker only) | `max_fails`, `fail_duration`, `unhealthy_*` | built (`passive` on `loadbalancer`; connect failures, timeouts, 5xx and slow responses eject a server for a growing time, capped by a percentage and never the last available server; see `docs/ref/svc-outlier.md`) |
| Retries | `retry` middleware | `lb_retries`, `lb_try_duration` | 0035 (connect errors; idempotent replay only; no retry on a response status) |
| Sticky sessions | `sticky.cookie` | `lb_policy cookie` | built (HMAC cookie on `loadbalancer`, falls back and re-pins when the server is gone, unhealthy or ejected; see `docs/ref/svc-sticky.md`) |
| Weighted service of services | `weighted` | none | 0037 |
| Failover service | `failover` | `lb_try_duration` partly | 0037 |
| Mirroring | `mirroring` | none in core | 0038 (bounded, shed first) |
| Pass host header | `passHostHeader` | `header_up Host` | model (`pass_host_header`), 0022 |
| Revision-aware rollout, canary, skew pinning | weighted services by hand | none | built |
| Scale to zero with wake | none | none | built |
| Request shadow and replay of failures | none | none | built |
| DNS names as servers | yes (dialer) | yes, plus dynamic upstreams | 0042 (A and AAAA, TTL, policy on every answer) |
| SRV upstreams | none | `srv` dynamic upstreams | 0096 (with a port deny list, because DNS then chooses the port); `multi` and other sources declined |
| Upstream address policy (SSRF) | none | none | built: operator allow and deny CIDRs per tenant; loopback, link-local, metadata, unspecified and multicast denied by default; checked at compile and before every dial |
| Response flush interval | `responseForwarding.flushInterval` | `flush_interval` | declined: Pingora streams chunks as they arrive |
| Tunnel lifetime and close delay | n/a | `stream_timeout`, `stream_close_delay` | 0098 (opt-in per transport; default never closes a tunnel) |

## Transports

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Upstream TLS, SNI, CA, client certificate | `serversTransport` | `transport http { tls_* }` | built (`min_tls_version` 1.3 is `unsupported_setting`, see `docs/ref/transports.md`) |
| `insecureSkipVerify` | yes | `tls_insecure_skip_verify` | built (allowed, listed as a posture change) |
| HTTP/2 and h2c upstream | `h2c://`, `disableHTTP2` | `versions h2 h2c` | 0040 |
| Dial, response and idle timeouts, pool size | `forwardingTimeouts`, `maxIdleConnsPerHost` | `dial_timeout`, `keepalive_*` | 0040 (pool size works or is rejected) |
| SPIFFE and `peerCertURI` | `spiffe`, `peerCertURI` | none | 0104 (Workload API client, one SVID per tenant, upstream mTLS and client identity) |
| PROXY protocol to HTTP upstreams | none | `proxy_protocol` in transport | 0098 (rejected as `unsupported_setting` if Pingora has no hook) |

## Middlewares

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Add and strip prefix, replace path (and regexp) | `addPrefix`, `stripPrefix*`, `replacePath*` | `uri`, `rewrite`, `handle_path` | built: `src/middleware/{add_prefix,strip_prefix,strip_prefix_regex,replace_path,replace_path_regex}.rs`; `strip_prefix` strips whole segments, every result is re-normalized (no `//` authority, no dot segments, an encoded slash is a `500`), regexes are linear time with groups checked at compile |
| Redirect scheme and regexp | `redirectScheme`, `redirectRegex` | `redir` | built: `301`/`302` as the pinned Traefik sends; the Location is refused on control characters (also escaped), other schemes and userinfo; a `redirect_scheme` removal is a plan posture change |
| Custom headers, security headers | `headers` | `header`, `request_header` | built: `src/middleware/headers.rs`; framing headers cannot be set; HSTS only over TLS |
| CORS | in `headers` | plugin | built: exact origins or anchored regexes, never reflected; `*` with credentials refused |
| Content type sniffing | `contentType` | none | built: never sniffs; `auto_detect: true` refused |
| Basic auth | `basicAuth` (MD5, SHA1, bcrypt) | `basic_auth` | built: `src/middleware/basic_auth.rs`; bcrypt and argon2 only, costs capped; verification bounded by `BASIC_AUTH_MAX_CONCURRENT`, a tenant share and the tenant's `max_buffer_bytes` |
| Digest auth | `digestAuth` | none | built: `src/middleware/digest_auth.rs`; SHA-256 and MD5 by HA1 length, qop=auth only, stateless HMAC nonces, bounded charged nc table, state kept across pushes; Authorization stripped upstream by default |
| Forward auth | `forwardAuth` | `forward_auth` | 0048 (fail closed) |
| IP allow list | `ipAllowList` | `remote_ip` plus `respond` | built |
| Rate limit | `rateLimit` | plugin | 0050 (bounded table, per node) |
| Cluster-wide rate limit | Hub or Enterprise (Redis) | plugins | 0094 (Redis-compatible store, per-route `on_store_error: allow` with local fallback, or `deny`) |
| In-flight request limit | `inFlightReq` | none | 0050 (per node), 0102 (cluster-wide with leases) |
| Circuit breaker | `circuitBreaker` (expression) | none | built: `src/middleware/circuit_breaker.rs`; structured `trip_when`, no expression language; `min_requests` floor |
| Buffering, body size limits | `buffering` | `request_body max_size`, `request_buffers` | built: memory only, charged to `max_buffer_bytes` (no `mem_*`, no disk spill); `buffer_request` holds a body of at most 64 KiB before the upstream request starts; response limits need `buffer_response`; a chunked response over its limit is reset, not a `502` (Pingora sends the head first) |
| Compression | `compress` (gzip, brotli, zstd) | `encode` | built (gzip 0009; gzip, brotli, zstd 0053, pure Rust, bounded; `min_bytes` not applied to unknown-length bodies) |
| Custom error pages | `errors` | `handle_errors` | 0054 |
| Fixed response | none | `respond`, `error`, `abort` | 0054 (`respond`) |
| Pass TLS client certificate | `passTLSClientCert` | placeholders | 0055 (always strips forged headers) |
| gRPC-Web | `grpcWeb` | plugin | 0056 |
| Chain of middlewares | `chain` | `route`, `handle` | 0022 |
| Plugins | Yaegi (Go) plugins | Go modules | WASM filters in process; 0099 out-of-process plugins over a unix socket (no native code in podgate, any language); 0113 runs Traefik Go plugins through a Yaegi host. `dlopen` plugins are rejected |
| JWT verification | Traefik Hub only | plugins | 0089 (JWKS fetched through the upstream policy) |
| OIDC login (authorization code, PKCE) | Traefik Hub only | `caddy-security` plugin | 0090 (stateless encrypted cookie sessions; no refresh tokens) |
| Response caching | Hub only | `cache` plugin | 0091 (memory only, charged to the tenant's `max_buffer_bytes`, capped share, purge API) |
| Templating (`templates`), `map`, `vars` | none | yes | declined: snapshots are generated data; templating belongs in the writer |
| Static files: `file_server`, `try_files`, precompressed | none | yes | 0085 (operator-declared per-tenant roots, no symlink escape) |
| Directory listings (`browse`) | none | `file_server browse` | 0101 (opt-in by operator root and service, escaped names, no hidden files) |
| `php_fastcgi` and FastCGI | none | `php_fastcgi` | 0100 (operator-declared pools and code roots, `.php` only, httpoxy and path-info defences) |
| Rule strings in the configuration | the native syntax | none | 0106 (`rule` on a router, parsed by the 0071 crate at compile; same tenant and catch-all rules) |

## TLS and certificates

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Certificates from the control plane | `tls.certificates` | `tls cert key` | built (`certificates`) |
| ACME HTTP-01 | `httpChallenge` | default | built (HA, ARI, on-demand) |
| ACME TLS-ALPN-01 | `tlsChallenge` | default | 0084 (needs the `acme-tls/1` ALPN on Pingora's listener; rejected with the finding if impossible) |
| ACME DNS-01 and wildcard certificates | `dnsChallenge` | `acme_dns` plugins | built (0081 in podgate; 0082 and 0083 add control-plane solvers); no DNS credential in podgate, see `docs/ref/acme-dns01.md` |
| ACME options (key type, preferred chain, profile, EAB) | `keyType`, `preferredChain`, `profile`, `eab` | `key_type`, `preferred_chains`, `acme_eab` | partly built (EAB, account key in 0014); recommend a small follow-up for key type and preferred chain |
| On-demand certificates | none | `on_demand_tls` with `ask` | built (the control plane approves through `acme.requested_hosts`) |
| Internal CA (`tls internal`) | none | yes | 0103 (key material in the provider and offline root, name-constrained intermediate, short-lived leaves) |
| OCSP stapling | none | automatic | 0092 (verified staples, fetched through the upstream policy; must-staple by default) |
| Mutual TLS (client auth) | `clientAuth` | `client_auth` | built (0021 enforcement, 0057 modes) |
| Min and max version, cipher suites, curves, ALPN | `tls.options` | `protocols`, `ciphers`, `curves`, `alpn` | built (`max_version` and `curves` are rejected, not ignored) |
| Default certificate, strict SNI | `tls.stores.default`, `sniStrict` | `default_sni`, `fallback_sni` | built (strict SNI is per app) |
| SNI against Host check | none (domain fronting possible, GHSA-fh26-gfpp-7xxx) | `strict_sni_host` | built, on by default |
| Session ticket control | `disableSessionTickets` | `session_tickets` | built as a refusal: tickets are listener wide and stay on; `session_tickets` is rejected with `unsupported_setting` |
| TLS passthrough | `tls.passthrough` on TCP routers | `layer4` | 0059 (own port), 0060 (shared port, measured) |

## TCP and UDP

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| TCP routers by SNI, ALPN, client IP | `HostSNI`, `ALPN`, `ClientIP` | `layer4` | 0058, 0059 |
| TCP load balancing, proxy protocol out, termination delay | `tcp.services` | `layer4 proxy` | 0058, 0061 |
| TCP middlewares | `inFlightConn`, `ipAllowList` | none | 0061 |
| TCP health checks | `healthCheck` (v3) | `layer4` passive | 0095 (connect, send and expect, TLS) |
| UDP routers and services | `udp.*` | `layer4` | 0062 |

## Providers and discovery

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Docker and Podman labels | Docker provider | `caddy-docker-proxy` | 0070 (`podgate.*`), 0071 (`traefik.*` subset) |
| Traefik rule strings | native | none | 0071 (translated; priority equals rule length) |
| Kubernetes Ingress | yes | ingress controller | 0072 |
| Gateway API | HTTPRoute, GRPCRoute, TLSRoute, TCPRoute | none first-party | 0073, 0074 (status), 0075 (L4 routes) |
| Kubernetes custom resources | `IngressRoute` and friends | none | 0076 (`PodgateRoute`, `PodgateMiddleware`) |
| Nomad | Nomad provider | none | 0077 |
| File | File provider (watch, templates) | Caddyfile, JSON | 0078; Traefik files via 0079 (also a migration linter) |
| Consul Catalog | yes | none | 0093 |
| Amazon ECS | yes | none | 0107 |
| Docker Swarm | yes | `caddy-docker-proxy` | 0108 |
| etcd, Redis (key trees) | yes | none | 0109 (shared key-value layer), 0110 |
| HTTP provider | yes | `--config <url>` | 0111 |
| Marathon, Rancher, Nomad-less legacy providers | Marathon, Rancher (removed in v3) | none | not planned: end-of-life platforms |
| One writer per node | not applicable (providers merge in-process) | not applicable | 0068 (refused, not conventional), 0069, 0080 |
| Tenants, budgets, host claims | none | none | built, providers 0069 |

## Observability and operations

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Access log (fields, filters, JSON and CLF) | `accessLog` | `log` | built (query and headers dropped by default, credential headers redacted, never blocks a request) |
| Prometheus metrics per entry point, router, service | `metrics.prometheus` | `metrics` | built (separate metrics listener, cardinality caps) |
| OpenTelemetry tracing | `tracing.otlp` | `tracing` | 0067 (OTLP over HTTP), 0112 (OTLP over gRPC) |
| Health endpoint | `ping` | none | built (`/healthz`, `/readyz` on the admin socket) |
| JSON schema of the configuration | none | `caddy adapt`, JSON docs | 0068 (`GET /v1/schema`) |
| Validate without applying | none | `caddy validate` | 0068 (`POST /v1/snapshot/validate`), plan built |
| Explain a route | none | none | built, extended by 0022 |
| Read-only overview API | `/api/*` | admin API | built (one document with filters and a cursor, 4 MiB cap, no secrets, `GET` only; the writer name joins with 0068) |
| Dashboard (web UI) | `dashboard` | none | 0088 (embedded, read-only, separate listener, never shows events or secrets) |
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
| WebSockets over HTTP/2 and HTTP/3 | Depends on Pingora and the h3 crate; 0063 records the HTTP/2 result | Follow the finding of 0063 |
| `flush_interval` | Pingora streams chunks as they arrive | Nothing to do |
