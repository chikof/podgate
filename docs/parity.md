# Parity with Traefik and Caddy

Where podgate stands against Traefik (v3) and Caddy (v2), feature by feature. Each row names the spec that builds it (in `the project history`, `done/` once merged), or the decision that it is deferred or declined, with a recommendation. "Built" means merged changes 0001 to 0019; everything else is a todo spec until it moves to `done/`.

Reading the last column: a spec id is the plan; `deferred` and `declined` rows say why and what to do next. Deliberate differences from Traefik's behaviour are in the spec of the feature (Context, "Deliberate differences") and not repeated here.

Model, for orientation: podgate is push-only. A control-plane writer (podkit's agent, or `podgate-provider`, never both on one node) pushes one JSON snapshot; podgate compiles it, rejects what it cannot honour, and serves it. Providers, rule strings and dynamic discovery live outside the daemon.

## Entry points

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Several named listeners | `entryPoints.<n>.address` | listener addresses, `bind` | 0028 (`ENTRY_POINTS`, process config) |
| Per-router entry point list | `entryPoints` on a router | site address | 0028; unbound names rejected |
| Per-tenant entry point access | none | none | 0028 |
| TCP and UDP listeners | `/tcp`, `/udp` suffix | `layer4` plugin | 0028 (parse), 0058, 0062 |
| Forwarded-header trust | `forwardedHeaders.trustedIPs`, `insecure` | `trusted_proxies`, `client_ip_headers` | 0026 |
| PROXY protocol in | `proxyProtocol.trustedIPs` | `proxy_protocol` wrapper | 0029 (strict, no fallback) |
| HTTP to HTTPS redirect on an entry point | `http.redirections.entryPoint` | automatic HTTPS redirects | 0030 |
| Read, write and idle timeouts | `transport.respondingTimeouts` | `servers { timeouts }` | 0030 (each knob works or is rejected as `unsupported_setting`) |
| HTTP/2 stream limit, max header size | `http2.maxConcurrentStreams`, `http.maxHeaderBytes` | `max_header_size`, `protocols` | 0030 (same rule) |
| Underscore and alias header names | `aliasHeadersStrategy`, `underscoreHeadersStrategy` | none | 0030 (`underscore_headers`) |
| Encoded characters policy | `http.encodedCharacters` | none | 0024 (normalization, refusal) and 0030 (`allow_encoded_slash` opt-in) |
| Graceful shutdown | `transport.lifeCycle` | `grace_period` | built (`REQUEST_TIMEOUT_SECS`, SIGTERM) |
| HTTP/3 | `http3` | default | deferred, see Deferred |

## Routing

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Host exact and wildcard | `Host` | `host`, site names | built |
| Host regexp | `HostRegexp` | `header_regexp Host` | 0027, with the cross-tenant capture rule |
| Path, prefix, regexp | `Path`, `PathPrefix`, `PathRegexp` | `path`, `path_regexp` | 0024 (prefix is whole-segment) |
| Method | `Method` | `method` | 0025 |
| Header, header regexp | `Header`, `HeaderRegexp` | `header`, `header_regexp` | 0025 |
| Query, query regexp | `Query`, `QueryRegexp` | `query` | 0025 |
| Client IP | `ClientIP` (peer) | `remote_ip`, `client_ip` | 0026 (`client_ip` resolves through trusted proxies) |
| Boolean combination | `&&`, `||`, `!` in a rule string | `not`, named matchers | model (`all`, `any`, `not`), 0022; rule strings are translated by 0071 |
| Explicit priority | `priority` | route order | 0022 (within a tenant); Traefik's order reproduced by 0071 |
| Ambiguity detection | none | none | 0022 (`route_ambiguity`) |
| `protocol` matcher (http, grpc, ws) | none | `protocol` | declined: a `header` or `header_regexp` leaf on `Upgrade` or `Content-Type` does the same |
| Expression matchers (CEL) | none | `expression` | deferred: a typed tree is analysable (ambiguity, claims); revisit only for a case the tree cannot express |
| Per-route TLS options | `tls.options` on a router | per-site `tls` | declined as written: TLS is decided before routing, so policy belongs to the app and hosts (`tls_policy_conflict`) |

## Services

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Round robin, weights | default WRR | `round_robin`, `weighted_round_robin` | built (round robin), 0031 (weighted) |
| Least connections | `leasttime`, p2c | `least_conn` | 0031 |
| Power of two choices | `strategy: p2c` | `random_choose` | 0031 (`p2c_ewma`: latency-aware) |
| Random | none | `random` | 0031 |
| Hash policies | `strategy: hrw` | `ip_hash`, `uri_hash`, `header`, `query`, `cookie` | 0032 (`ip_hash`, `uri_hash`, `header_hash`, `hrw`; `query` and `cookie` declined, sticky is 0036) |
| Active health checks | `healthCheck` | `health_uri` and friends | 0033 |
| Passive ejection | none (circuit breaker only) | `max_fails`, `fail_duration`, `unhealthy_*` | 0034 |
| Retries | `retry` middleware | `lb_retries`, `lb_try_duration` | 0035 (connect errors; idempotent replay only; no retry on a response status) |
| Sticky sessions | `sticky.cookie` | `lb_policy cookie` | 0036 (HMAC cookie) |
| Weighted service of services | `weighted` | none | 0037 |
| Failover service | `failover` | `lb_try_duration` partly | 0037 |
| Mirroring | `mirroring` | none in core | 0038 (bounded, shed first) |
| Pass host header | `passHostHeader` | `header_up Host` | model (`pass_host_header`), 0022 |
| Revision-aware rollout, canary, skew pinning | weighted services by hand | none | built |
| Scale to zero with wake | none | none | built |
| Request shadow and replay of failures | none | none | built |
| DNS names as servers | yes (dialer) | yes, plus dynamic upstreams | 0042 (A and AAAA, TTL, policy on every answer) |
| SRV and other dynamic upstreams | none | `srv`, `a`, `aaaa`, `multi` | deferred: A and AAAA only in 0042; add SRV when a Consul or Nomad DNS setup needs it |
| Upstream address policy (SSRF) | none | none | 0041 |
| Response flush interval | `responseForwarding.flushInterval` | `flush_interval` | declined: Pingora streams chunks as they arrive |
| Streams outliving a config change | n/a | `stream_close_delay` | deferred: podgate never kills tunnels on a timer (0063 states the drain rule); the control plane sets its own deadline. Recommend a `max_stream_lifetime_secs` transport field only if a PaaS needs forced closes |

## Transports

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Upstream TLS, SNI, CA, client certificate | `serversTransport` | `transport http { tls_* }` | 0039 |
| `insecureSkipVerify` | yes | `tls_insecure_skip_verify` | 0039 (allowed, listed as a posture change) |
| HTTP/2 and h2c upstream | `h2c://`, `disableHTTP2` | `versions h2 h2c` | 0040 |
| Dial, response and idle timeouts, pool size | `forwardingTimeouts`, `maxIdleConnsPerHost` | `dial_timeout`, `keepalive_*` | 0040 (pool size works or is rejected) |
| SPIFFE and `peerCertURI` | `spiffe`, `peerCertURI` | none | deferred: needs a workload API client; recommend only when a mesh requires it |
| PROXY protocol to HTTP upstreams | none | `proxy_protocol` in transport | deferred: `X-Forwarded-For` serves HTTP; TCP upstreams get it in 0061 |

## Middlewares

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Add and strip prefix, replace path (and regexp) | `addPrefix`, `stripPrefix*`, `replacePath*` | `uri`, `rewrite`, `handle_path` | 0043 |
| Redirect scheme and regexp | `redirectScheme`, `redirectRegex` | `redir` | 0044 |
| Custom headers, security headers | `headers` | `header`, `request_header` | 0045 |
| CORS | in `headers` | plugin | 0045 |
| Content type sniffing | `contentType` | none | 0045 (never sniffs; `auto_detect: true` refused) |
| Basic auth | `basicAuth` (MD5, SHA1, bcrypt) | `basic_auth` | 0046 (bcrypt and argon2 only; bounded, charged cost) |
| Digest auth | `digestAuth` | none | 0047 |
| Forward auth | `forwardAuth` | `forward_auth` | 0048 (fail closed) |
| IP allow list | `ipAllowList` | `remote_ip` plus `respond` | 0049 |
| Rate limit | `rateLimit` | plugin | 0050 (bounded table, per node) |
| In-flight request limit | `inFlightReq` | none | 0050 |
| Circuit breaker | `circuitBreaker` (expression) | none | 0051 (structured, no expression language) |
| Buffering, body size limits | `buffering` | `request_body max_size`, `request_buffers` | 0052 (memory only, charged) |
| Compression | `compress` (gzip, brotli, zstd) | `encode` | built (gzip, 0009), 0053 (brotli; zstd only if boundable in pure Rust) |
| Custom error pages | `errors` | `handle_errors` | 0054 |
| Fixed response | none | `respond`, `error`, `abort` | 0054 (`respond`) |
| Pass TLS client certificate | `passTLSClientCert` | placeholders | 0055 (always strips forged headers) |
| gRPC-Web | `grpcWeb` | plugin | 0056 |
| Chain of middlewares | `chain` | `route`, `handle` | 0022 |
| Plugins | Yaegi (Go) plugins | Go modules | built as WASM filters; native plugins declined (memory safety) |
| JWT or OIDC authentication | Traefik Hub only | plugins | declined in core: `forward_auth` to an auth service covers it. Recommend a `jwt_auth` middleware only if a tenant needs offline verification at the edge |
| Response caching | Hub only | `cache` plugin | declined: not a PaaS ingress job; recommend a CDN in front |
| Templating (`templates`), `map`, `vars` | none | yes | declined: snapshots are generated data; templating belongs in the writer |
| `try_files`, `file_server`, `php_fastcgi` | none | yes | deferred, see Deferred |

## TLS and certificates

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Certificates from the control plane | `tls.certificates` | `tls cert key` | built (`certificates`) |
| ACME HTTP-01 | `httpChallenge` | default | built (HA, ARI, on-demand) |
| ACME TLS-ALPN-01 | `tlsChallenge` | default | deferred: recommend a spec after 0057; works when port 80 is closed, needs no credentials, fits the ClientHello hook of 0014 |
| ACME DNS-01, wildcard certificates | `dnsChallenge` | `acme_dns` plugins | deferred: needs DNS provider credentials in the proxy. Recommendation: the control plane obtains wildcards (it can hold DNS credentials) and pushes them in `certificates`; revisit if podkit wants podgate to do it |
| ACME options (key type, preferred chain, profile, EAB) | `keyType`, `preferredChain`, `profile`, `eab` | `key_type`, `preferred_chains`, `acme_eab` | partly built (EAB, account key in 0014); recommend a small follow-up for key type and preferred chain |
| On-demand certificates | none | `on_demand_tls` with `ask` | built (the control plane approves through `acme.requested_hosts`) |
| Internal CA, self-signed (`tls internal`) | none | yes | declined: the control plane issues private certificates and pushes them |
| OCSP stapling | none | automatic | deferred: needs outbound OCSP fetches (outside the outbound allow list); Let's Encrypt ended OCSP, revisit if a CA requires it |
| Mutual TLS (client auth) | `clientAuth` | `client_auth` | 0021 (enforcement), 0057 (modes) |
| Min and max version, cipher suites, curves, ALPN | `tls.options` | `protocols`, `ciphers`, `curves`, `alpn` | 0057 (rustls-supported values only) |
| Default certificate, strict SNI | `tls.stores.default`, `sniStrict` | `default_sni`, `fallback_sni` | 0057 |
| SNI against Host check | none (domain fronting possible, GHSA-fh26-gfpp-7xxx) | `strict_sni_host` | built, on by default |
| Session ticket control | `disableSessionTickets` | `session_tickets` | 0057 (rustls rotating ticketer; `session_tickets: false`) |
| TLS passthrough | `tls.passthrough` on TCP routers | `layer4` | 0059 (own port), 0060 (shared port, measured) |

## TCP and UDP

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| TCP routers by SNI, ALPN, client IP | `HostSNI`, `ALPN`, `ClientIP` | `layer4` | 0058, 0059 |
| TCP load balancing, proxy protocol out, termination delay | `tcp.services` | `layer4 proxy` | 0058, 0061 |
| TCP middlewares | `inFlightConn`, `ipAllowList` | none | 0061 |
| TCP health checks | `healthCheck` (v3) | `layer4` passive | deferred: connect failover only; recommend an L4 health check when a database service asks |
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
| Consul Catalog, ECS, Docker Swarm, Marathon, etcd, Redis, HTTP provider | yes | none | declined: podgate has no discovery in the daemon; a source for any of them is a new module of `podgate-provider`. Recommend Consul only if Nomad users need it |
| One writer per node | not applicable (providers merge in-process) | not applicable | 0068 (refused, not conventional), 0069, 0080 |
| Tenants, budgets, host claims | none | none | built, providers 0069 |

## Observability and operations

| Feature | Traefik | Caddy | podgate |
|---|---|---|---|
| Access log (fields, filters, JSON and CLF) | `accessLog` | `log` | 0065 (query and headers dropped by default) |
| Prometheus metrics per entry point, router, service | `metrics.prometheus` | `metrics` | 0066 (separate metrics listener, cardinality caps) |
| OpenTelemetry tracing | `tracing.otlp` | `tracing` | 0067 (OTLP over HTTP; gRPC export deferred) |
| Health endpoint | `ping` | none | built (`/healthz`, `/readyz` on the admin socket) |
| JSON schema of the configuration | none | `caddy adapt`, JSON docs | 0068 (`GET /v1/schema`) |
| Validate without applying | none | `caddy validate` | 0068 (`POST /v1/snapshot/validate`), plan built |
| Explain a route | none | none | built, extended by 0022 |
| Dashboard and API | `api`, `dashboard` | admin API | deferred, see Deferred |
| Config reload without dropping connections | yes | yes | built (atomic swap) |
| Auto-revert of a bad config | none | none | built |
| Benchmark against both | n/a | n/a | 0020 |

## Deferred or declined, with a recommendation

For the human to decide. Nothing here is built or planned unless a spec id appears above.

| Item | Why it is not in the plan | Recommendation |
|---|---|---|
| ACME DNS-01 | Would put DNS provider credentials into a proxy that runs tenant-influenced configuration; HTTP-01 only by design | Keep. Let the control plane issue wildcard certificates and push them as `certificates`. Revisit only if podkit asks podgate to order wildcards itself, and then only on the issuer node |
| Static file serving (Caddy `file_server`, `try_files`, `php_fastcgi`) | A PaaS app serves its own files; podgate keeps no disk state | Keep declined. A static site is an app container (or a CDN origin) behind podgate |
| HTTP/3 and QUIC | Pingora 0.9 has no HTTP/3 server; Caddy and Traefik ship one | Wait for Pingora. If demand appears first, a spec for a QUIC terminator in front (separate crate, `h3` and `quinn`) with an explicit memory budget per connection, and do not advertise `Alt-Svc` before it exists |
| Web dashboard | Traefik's dashboard is a UI on its API | Do not build a UI in the daemon. A read-only `GET /v1/overview` (compiled routers, services, server health, middleware descriptions, from the same table as explain, 0006) is a small spec after 0066; the UI belongs in podkit |
| ACME TLS-ALPN-01 | Not needed while port 80 is open | Small spec after 0057 if a deployment cannot open port 80 |
| SRV and dynamic DNS upstreams | A and AAAA cover container DNS | Add SRV to 0042's resolver when a Consul or Nomad DNS setup needs it |
| Cluster-wide rate limits | State is per node (as Traefik without Redis) | Divide a global limit by node count in the control plane; a shared store would put a network dependency on the request path |
| Native plugins (Yaegi, Go modules) | Native code in the proxy breaks the memory-safety goal | Keep declined; WASM filters with fuel and capability limits are the extension point |
| JWT and OIDC middleware | Hub only in Traefik; plugins in Caddy | `forward_auth` to an auth service first; an edge `jwt_auth` kind only on demand |
| Response caching | Not an ingress job | Keep declined; put a CDN in front |
| OCSP stapling, internal CA | Outbound fetches and a CA are out of the outbound allow list and the trust model | Keep declined |
| Consul, ECS, Swarm, etcd, Redis, HTTP providers | Each is a new source module and a new trust analysis | Add as `podgate-provider` modules on demand; Consul first if Nomad users need it |
| SPIFFE, mesh identity | Needs a workload API client | On demand |
| WebSockets over HTTP/2 (RFC 8441) | Depends on Pingora support; 0063 records the result | Follow the finding of 0063 |
| `stream_close_delay` for tunnels | podgate never kills tunnels on a timer | A transport `max_stream_lifetime_secs` if a PaaS needs forced drain |
| L4 health checks | Connect failover covers the common case | Add when a database or queue service needs it |
| PROXY protocol to HTTP upstreams | No known consumer | Add to `servers_transport` when one appears |
