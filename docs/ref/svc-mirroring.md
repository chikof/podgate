# The `mirroring` service

A service of type `mirroring` answers every request with another service and sends a copy of a
share of them to other services of the same app, a candidate release or a shadow environment,
without ever affecting the real response. It is Traefik's `mirroring`; Caddy has nothing like it
in core.

```json
{ "name": "m", "type": "mirroring", "service": "web",
  "mirrors": [ { "service": "web@r2", "percent": 10 },
               { "service": "shadow", "percent": 0.5 } ],
  "mirror_body": true, "max_body_size": 65536,
  "mirror_timeout_secs": 10, "forward_credentials": false }
```

A router names the mirroring service like any other (`"service": "m"`). The request is answered
exactly as if the router had named `service`.

| Field | Meaning |
|---|---|
| `service` | The service that answers: a `loadbalancer` of the revision the request picked, else of the app. |
| `mirrors[].service` | Where a copy goes: a `loadbalancer` of the same app, `name` (in the revision the request picked, else the app) or `name@revision` (in that revision, else the app). One to eight entries. |
| `mirrors[].percent` | The share of requests copied, `0` to `100`, with up to four decimals (`0.1` is one in a thousand). `0` copies nothing and `100` copies everything, exactly. Each mirror is sampled on its own. |
| `mirror_body` | Send the request body to the mirrors too. Default `false`: the copy has the method, path and headers, and an empty body. |
| `max_body_size` | The most body bytes copied, default 1 MiB (Traefik's default is unlimited), at most 16 MiB. Larger bodies are not mirrored. Needs `mirror_body`. |
| `mirror_timeout_secs` | How long one copy may take in all (connect, write, the shadow's answer head), default 10, at most 60. |
| `forward_credentials` | Send `Authorization`, `Proxy-Authorization` and `Cookie` to the mirrors. Default `false` (Traefik copies them). |

## Compile-time rules

- `service` and every mirror must be a `loadbalancer`. A `static` service is `invalid_service`
  both as the mirrored service and as a mirror: a copy of a request needs a server to dial.
  Another `mirroring` service is `invalid_service`, one that mirrors to itself `service_cycle`.
- Names resolve per revision when the snapshot compiles. A name nothing defines is
  `unknown_service`, naming the revision; `name@revision` needs the revision and the service to
  exist. A `draining` revision takes no new request, so it may lack a name.
- A copy that could never be charged is `invalid_service`, naming the tenant, the bytes and the
  budget: the head allowance (16 KiB) plus, with `mirror_body`, `max_body_size`, against the
  tenant's `max_buffer_bytes`. The default cap of 1 MiB needs a tenant budget above 1 MiB plus
  16 KiB.
- Every literal server address of a mirror's service passes the upstream address policy like any
  other server (`upstream_forbidden`).
- Unknown fields are `invalid_service`; so is `max_body_size` without `mirror_body`.

## What a mirror may cost

A mirror may only consume what real traffic leaves unused. A copy is **shed**, counted and never
queued, at the first of these that says no:

1. The process already runs 256 copies.
2. The tenant has used three quarters of its `max_inflight` (a copy holds an in-flight slot while
   it runs, so real requests keep the last quarter). Refusing a copy is not a rejected request.
3. The mirror's service has no available server.
4. The server's adaptive concurrency limit is reached, or someone already
   waits for it. A copy never queues behind real requests.

Copies are charged to the tenant's `max_buffer_bytes` **before** they exist: 16 KiB for the head,
then the body in blocks of 16 KiB, each charged before it is allocated, so a stream of tiny
chunks costs what it weighs. A block that does not fit drops the copy (`budget`); the request is
not touched. The charge stays until the last copy of the request ended. A request whose head is
over 16 KiB is not mirrored.

## What a copy is

The copy is sent after the request was routed, from its own task:

- It is the request that goes to the main service (every middleware rewrite included), with
  the connection-level headers (`Connection` and the headers it names, `Keep-Alive`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`, `Expect`, `Proxy-*`) removed, `Content-Length`
  set by the sender, credentials removed unless `forward_credentials`, and
  **`x-podgate-mirrored: 1`** added so the shadow can avoid side effects (Traefik adds nothing).
  A request that already carries the marker is itself a copy and is not mirrored again.
- It is plain HTTP/1.1 with `Connection: close`, dialled through the connect path of the proxy,
  so an `https://` shadow is reached with the transport of its own service
  (`Upstream::peer`). The exact IP about to be dialled passes the upstream address policy every
  time; a refusal drops the copy (`policy`).
- The shadow's answer is read only to the end of its head and dropped with the connection;
  status and body are never used. The copy never sets a header on the real response.
- Sampling is deterministic: `hash(request key, mirror index)` against `percent`, where the key
  is the `X-Request-Id` a trusted peer sent, else a counter. The proxy's own retry of the
  upstream request does not mirror a second time.
- With `mirror_body`, a request with `Upgrade` or `Expect` is not mirrored (`upgrade`); a body
  over `max_body_size` (declared or counted while it streams) is not mirrored
  (`body_too_large`); a body the client never finishes is not sent (`incomplete`). Without
  `mirror_body` such requests are mirrored without body, and without `Upgrade` and `Expect`.

## Metrics

On `GET /metrics`:

- `podgate_mirror_sent_total{result}`: copies sent; `ok` (the shadow answered with any status),
  `error` (connect, write or read failed), `timeout`.
- `podgate_mirror_dropped_total{reason}`: copies not sent; `inflight`, `tenant`, `budget`,
  `backend`, `no_server`, `policy`, `body_too_large`, `head_too_large`, `upgrade`, `mirror`,
  `incomplete`.
- `podgate_mirror_inflight`: copies running now.

## In the pipeline

Routing, admissions and the real request are unchanged. `begin` runs in
`upstream_request_filter` (a request with no body to copy is sent there), `tee` in
`request_body_filter` (copies the body and, at its end, sends) and `finish` in `logging` (drops
and counts a body that never ended). The mirroring service itself has no server: the table routes
to `service`, so health checks, outlier ejection, `explain` and `overview` see the real service.
