# TCP health checks

A TCP `loadbalancer` with a `health_check` is probed by podgate: a server that fails its probe stops receiving new connections and takes them again when it passes, so a dead database replica is skipped before a client finds out. The probe writes the `healthy` flag of the server, which every balancer already reads (`docs/ref/lb-algorithms.md`); TCP services are the HTTP load balancer, so the balancers have no code for it.

```json
{ "name": "primary", "type": "loadbalancer",
  "health_check": { "interval_secs": 5, "timeout_secs": 2, "unhealthy_interval_secs": 1,
                    "unhealthy_threshold": 3, "send": "UElORwo=", "expect": "UE9ORw==" },
  "servers": [{ "address": "10.0.1.5:5432" }, { "address": "db.internal:5432" }] }
```

Traefik's TCP `healthCheck` (`port`, `send`, `expect`, `interval`, `unhealthyInterval`, `timeout`) is the model. Caddy's `layer4` has passive checks only.

## Fields

| Field | Default | Meaning |
|---|---|---|
| `interval_secs` | required | Seconds from the end of one probe to the start of the next, 1..=3600. |
| `timeout_secs` | required | A probe that has not finished by then fails, 1..=300. The connect, the TLS handshake, the write and the read share it. |
| `unhealthy_interval_secs` | `interval_secs` | Seconds between probes of a server that is marked down, 1..=3600. Probe a dead server faster or slower than a live one. |
| `port` | the server's port | Probe another port of the same IP, such as a management port. |
| `send` | none | Base64 of the bytes written after the connect: 1 to 256 bytes once decoded. |
| `expect` | none | Base64 of the bytes the reply must start with: 1 to 256 bytes once decoded. Without `send` the server speaks first (an SMTP `220 ` banner, an SSH `SSH-2.0-`). |
| `healthy_threshold` | `1` | Consecutive passes that mark a down server up, 1..=100. |
| `unhealthy_threshold` | `1` | Consecutive failures that mark an up server down, 1..=100. |
| `tls` | `false` | Connect with TLS through the service's transport (trust anchors, SNI, client certificate: `docs/ref/transports.md`). The probe passes on a completed handshake, and then on `expect` when it is set. |
| `send_proxy_header` | `false` | Write a PROXY protocol v2 `LOCAL` header (`docs/ref/proxy-protocol.md`) before anything else, so a server that requires the header does not log an error for every probe. |

With neither `send` nor `expect` a successful connect is a pass. With `send` only, a successful connect and write is. A field that is missing, unknown or out of range is `invalid_service` and the whole snapshot is rejected: a `send` or `expect` that is not base64, is empty or decodes to more than 256 bytes, a `port` of `0`, `tls` together with `send_proxy_header`. The last one is refused because on the wire the PROXY header comes before the TLS handshake and the probe's connector does the handshake inside the dial; use the header on a cleartext check, or `tls` without it.

## Semantics

- **A new server starts healthy**, as with HTTP checks: connections are never held back for a probe. The first probe runs within one `timeout_secs` (a jitter derived from the server's identity spreads the probes of a large service).
- **Thresholds count consecutive results.** An up server goes down after `unhealthy_threshold` failures in a row, a down server up after `healthy_threshold` passes in a row. A failure is a connect error, a refusal by the upstream address policy, a timeout, a reply that does not start with `expect` (it fails as soon as a byte differs, not at the timeout) or a close before the reply is complete.
- **Every server unhealthy.** New connections are closed at once and counted `podgate_l4_refused_total{reason="no_healthy_server"}`; no server is dialled. A service whose servers all failed to connect is `no_server` instead.
- **Probes are not connections.** They take no tenant slot, no buffer budget, and do not count in `podgate_tcp_connections_total`. The balancer's `active` count is untouched.
- **UDP has no health check.** A datagram service cannot be probed without a protocol, so `health_check` on a UDP service is `invalid_service`. When the servers also listen on TCP, put a TCP check on that port in the TCP service of the same servers.

## What a probe can reach

- Only the servers of the service, as the balancer holds them: an IP literal, each address a DNS name resolved to (`docs/ref/dns-resolver.md`), each target of an SRV name (`docs/ref/dns-srv.md`). The probes follow the answers: a new address is probed, a gone one stops. The port is the server's, or `port` when the check sets one.
- Every probe calls the upstream address policy (`docs/ref/upstream-policy.md`) with the tenant and the exact IP it is about to dial. A refusal fails the probe and counts in `podgate_upstream_refused_total{tenant}`.
- Probes connect through Pingora's `TransportConnector`, the connect path of the proxy. With `tls` the peer comes from the service's transport, so the certificate is verified against the trust anchors and the name of the service. A TCP service has the default transport today (platform roots; the server's DNS name as SNI, or the IP, which is checked against the certificate's IP SAN), so a private CA needs the transport of a later spec. A verification failure is a failed probe.

## Bounds

- At most `HEALTH_MAX_CONCURRENT` probes (default 64) run at once across the whole process, HTTP and TCP checks together; the others wait for a permit.
- A probe is cut at `timeout_secs`.
- A probe writes at most 256 bytes of `send` (plus the 16-byte PROXY header) and never reads more bytes than `expect` is long, at most 256. A server that streams a gigabyte at the probe is read for the length of `expect` and closed on.
- One tokio task per probed server and a few hundred bytes of state; at most 256 servers per service.

## State

The verdict is two things. The flag `ServerState::healthy` is in the registry of `docs/ref/lb-algorithms.md`. The streak (how many consecutive results point the other way) is in the scheduler of `docs/ref/svc-health.md` under the key `(owner "tcp", app, service, server address, fingerprint of the check)`.

- A push that does not touch the service keeps the streak and the flag, so a server that is down stays down across a push that changes another app.
- A changed check is a new key, and the registry's key for the service carries the check's fingerprint too: the old probe stops, the servers start healthy, and the new probe runs from a clean streak. The check changes whenever any of its fields does, `interval_secs` included.
- A push that changes the service otherwise (its algorithm, say) gives the servers a fresh flag; the scheduler writes its verdict into it when it next reconciles, which follows the swap within milliseconds.

## Metrics

On `GET /metrics`:

- `podgate_l4_service_servers{app,service,state}`: for each TCP service with a `health_check`, how many servers may take a new connection (`up`) and how many may not (`down`), for the addresses the service holds now.
- `podgate_l4_refused_total{reason="no_healthy_server"}`: connections closed at once because every server of the service is down.
- `podgate_upstream_refused_total{tenant}`: includes probes the address policy refused.

A change of verdict is logged at `warn` with the app, the service, the server address and the reason (`connect: ...`, `the probe timed out`, `the reply does not start with the expected bytes`). The reply bytes themselves are never logged.
