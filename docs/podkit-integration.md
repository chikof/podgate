# podkit integration contract

This page tells the author of podkit's agent how to put podgate in front of podkit's applications in place of Traefik: what to run, what to push, and what to do with each answer. It describes podgate only. Nothing in `~/Projects/podkit` has been changed; [What changes in podkit](#what-changes-in-podkit) lists the work.

The page is tested. Every labelled JSON block below is compared with the real daemon by [tests/podkit_contract.rs](../tests/podkit_contract.rs): fixtures byte for byte with `tests/fixtures/podkit/<name>.json`, replies and event shapes against what the binary sends. If podgate changes and this page does not, the test fails. The snapshot model itself is in [architecture.md](architecture.md) (`## Snapshot model v2`); the admin tools used here are in [ref/admin-tools.md](ref/admin-tools.md).

## What stays and what changes

podkit runs one Traefik container per server today (`agent/src/ingress.rs`), reading Docker labels from the Podman socket. podgate keeps the shape (one proxy container per server, on the `podkit` network, `web` and `websecure` entry points, ACME HTTP-01) and removes three things on purpose.

| | Traefik today | podgate |
|---|---|---|
| Routing source | labels on the containers, read through the Podman socket | a snapshot the agent pushes over a unix socket; no label provider, no Podman socket in the proxy |
| Rolling deploy | start, health check, sleep `SWAP_DELAY` (3 s), stop the old container | start, health check, push, wait for `revision_drained`, stop the old container; no sleep |
| Certificates | ACME HTTP-01, resolver `le`, `acme.json` under `<data_dir>/traefik-acme` | ACME HTTP-01 through the event feed; the certificates live in podkit, podgate keeps nothing on disk |
| Duplicate host | Traefik serves one of the routers | podgate refuses the whole snapshot with `host_conflict` |

## Running podgate

One podgate container per server, named like the Traefik one is (`podkit-podgate`), on the `podkit` network, from the image the `Dockerfile` of this repository builds. Pin the image literal the way `TRAEFIK_IMAGE` is pinned.

```env env:podgate
ENTRY_POINTS=web=0.0.0.0:8080/http,websecure=0.0.0.0:8443/https
ADMIN_SOCKET=/run/podgate/admin.sock
NODE_NAME=srv-1
UPSTREAM_POLICY_FILE=/etc/podgate/upstream-policy.json
```

- **Entry points.** The routers below name `web` and `websecure`. The container listens on 8080 and 8443 so it runs as the image's non-root user; publish `ingress.http_port` to 8080 and, only when `acme_email` is set, `ingress.https_port` to 8443, as `ensure_traefik` publishes 80 and 443 today. The image sets `PROXY_ADDR=0.0.0.0:8080`, and `ENTRY_POINTS` refuses to start next to it. Either create the container without `PROXY_ADDR` (`podman create --unsetenv PROXY_ADDR`), or skip `ENTRY_POINTS` and set `PROXY_TLS_ADDR=0.0.0.0:8443`: that shorthand names the same two entry points, `web` and `websecure`.
- **Admin socket.** Bind-mount a directory of the server's data directory at `/run/podgate`. The socket `admin.sock` appears there with mode `0600`, owned by the container's user. The agent is the only client. Check that the agent's user can open it under rootless Podman.
- **`NODE_NAME`.** The name of this server. It is the value of `acme.issuer_node` (see [Certificates](#certificates)).
- **Upstream policy.** The operator's file, never part of a snapshot. podkit writes container addresses only, so the policy is a second lock: allow the subnet of the `podkit` network (`podman network inspect podkit`), and deny the network's gateway, which is where the agent's own API listens. `deny_extra` keeps the built-in deny list, which holds loopback and the cloud metadata addresses; `deny` would replace it.

```json policy:upstream
{
  "deny_extra": ["10.89.0.1/32"],
  "default": { "allow": ["10.89.0.0/24"] }
}
```

- **Readiness.** `GET /readyz` answers `200 {"status":"ready"}` as soon as the admin API serves, which is before the first snapshot. Until a snapshot is pushed the proxy answers every request `404 {"error":"not found"}` and a TLS handshake finds no certificate. So the agent starts the container, waits for `/readyz`, and pushes the full state before it reports the ingress as up. Do the same after every podgate restart.

## The writer rule

A node has one writer. On a podkit server it is the agent.

- Every `PUT /v1/snapshot` (and `POST /v1/snapshot/plan`) carries `podgate-writer: podkit-agent`. The first accepted push pins that name to the live snapshot.
- Never run `podgate-provider` on the same node. It names itself `podgate-provider` and is refused as any other writer.
- Another name, or no name once one is pinned, is refused and changes nothing:

```json reply:writer_owned
{"error":"snapshot is owned by writer podkit-agent","writer":"podkit-agent"}
```

- **Takeover.** An operator who must push by hand sends `PUT /v1/snapshot?takeover=true` with their own name in `podgate-writer`. It needs a name (`400` without), must compile and must be newer than the live version. When accepted the pin moves, podgate logs a warning, and the feed gets:

```json shape:writer_changed
{"seq": 3, "kind": "writer_changed", "from": "podkit-agent", "to": "operator-chiko"}
```

- After a takeover the agent's pushes get `409` with the new owner in `writer`. The agent must stop pushing, report the ingress as taken over, and never take the node back by itself. Giving it back is the same push by the agent's name with `?takeover=true`, which podkit can offer as an operator command.
- The pin lives in memory next to the live snapshot. A podgate restart clears it and the next push pins again. Auto-revert (below) does not change it.

## Mapping

| podkit | podgate | Value |
|---|---|---|
| team `7` | `Tenant` | `id: "team-7"`, `weight`, `budget` |
| application `42` | `App` | `id: "app-42"` (the `DeploySpec.service`), `tenant: "team-7"`, `declared_by: "podkit/agent"` |
| `Routing.http_hosts` | router `web` | `entry_points: ["web"]`, `match: {"host": [...]}` |
| `Routing.https_hosts` | router `websecure` | `entry_points: ["websecure"]`, `match: {"host": [...]}` |
| custom domain | one more host of `https_hosts` | same app, same router |
| deployment (`instance_id` `1002`) | `Revision` | `id: "d-1002"`, `state`, `weight` |
| container `podkit-app-42-1002`, `container_port` | server of service `web` | `{"url": "http://<ip>:<container_port>"}` in a `loadbalancer` |
| `Ingress.acme_email` | `acme.contact: ["mailto:<email>"]` | no email: no `acme` object and no `websecure` router |
| `Ingress.http_port`, `https_port` | nothing | host ports published by the podgate container |

How the builder reads this table:

- **The snapshot is the whole state of the server.** Every application with a `Routing` becomes an `App`, every team that owns one becomes a `Tenant`. An application that is deleted is absent from the next snapshot; that replaces what removing the labels did.
- **Tenants.** podkit has no per-team limits today. The builder uses one default from the server's configuration: `weight: 1`, `max_inflight: 1000`, `max_buffer_bytes: 67108864` (64 MiB), the values of the fixtures.
- **Hosts.** Lowercase, one router per entry point. Today custom domains are on `websecure` only; this page keeps that. A router whose list is empty is left out, not sent with an empty `host`.
- **Custom domains.** Add them to the application's `https_hosts`. Make a separate app only when its TLS policy differs, for example a client CA (`tls.client_ca_pem`) or `on_demand` certificates.
- **One certificate per app.** With `tls.mode: "acme"` podgate orders one certificate for every exact host of the app that no certificate covers, so the platform host and the custom domains share it, as the walk-through below shows. If the platform host must stay off a customer's certificate, give it its own app.
- **A host belongs to one application.** If two applications claim a host, podgate refuses the snapshot with `host_conflict` instead of serving one of them.
- **Services.** The routers name service `web`; each revision declares it, so the servers of a deployment live and die with that revision. `Strategy::Recreate` has no draining revision: push the snapshot with the new revision only, after the health check.
- **Address.** After the health check the agent reads the container's address on the `podkit` network from `inspect` and writes `http://<ip>:<container_port>`. An address changes when the supervisor restarts a container, so the agent pushes again when `agent/src/supervisor.rs` restarts one. Servers also accept a name (`http://podkit-app-42-1002:3000`), which podgate resolves itself and re-resolves on the record's TTL (`docs/ref/dns-resolver.md`); the fixtures use addresses because the agent has the address in hand.
- **State across an agent restart.** Today the Traefik labels are the routing state, so a restart loses nothing. Keep that property: put the team id, the hosts, the port and the instance id in `podkit.*` labels, which users cannot set (`validate_options` in `agent/src/deploy.rs` rejects them), and rebuild the snapshot from the `podkit-app-*` containers after a restart. The highest `instance_id` of an application is its serving deployment; older ones are draining.

The `steady` fixture is one application with one deployment. Its custom domain is `shop.acme-corp.dev`; the platform host is `shop.apps.example.com`; the container is at `10.89.0.21`.

```json fixture:steady
{
  "version": 41,
  "tenants": [
    { "id": "team-7", "weight": 1, "budget": { "max_inflight": 1000, "max_buffer_bytes": 67108864 } }
  ],
  "apps": [
    {
      "id": "app-42", "tenant": "team-7", "declared_by": "podkit/agent",
      "tls": { "mode": "acme" },
      "routers": [
        { "name": "web", "entry_points": ["web"],
          "match": { "host": ["shop.apps.example.com"] }, "service": "web" },
        { "name": "websecure", "entry_points": ["websecure"],
          "match": { "host": ["shop.acme-corp.dev"] }, "service": "web" }
      ],
      "revisions": [
        { "id": "d-1001", "state": "serving", "weight": 100,
          "services": [ { "name": "web", "type": "loadbalancer",
                          "servers": [ { "url": "http://10.89.0.21:3000" } ] } ] }
      ]
    }
  ]
}
```

## Versions and restarts

`version` is strictly increasing per node, and the agent owns the counter.

- After an agent restart, `GET /v1/snapshot/version` and push `version + 1`:

```json shape:version
{"version": 41, "writer": "podkit-agent", "boot_id": "7c1a5d54-0d4c-4b9e-9c0e-2f3a6f0d7e11"}
```

- After a podgate restart the version is `0` and the writer is free. `boot_id` tells: it is on every event feed answer and on `/v1/snapshot/version`. When it changes, push the complete state again (certificates included) and restart the event poll from `after=0`, because sequence numbers start over.
- After an auto-revert the live version stays at the number that was reverted, so the next push must be above it (below).

## Rolling deploy

Traefik needed a sleep because it learned about a new container by polling the Podman socket. podgate is told, and tells back. The three fixtures are the three states of one rolling deploy. The old deployment is `d-1001`, the new one `d-1002`.

1. **Start and health-check the new container**, unchanged (`agent/src/deploy.rs`). The old container keeps serving from the `steady` snapshot.
2. **Push `rolling`.** The new revision is `serving` with weight `100`; the old one is `draining` with weight `0`. From the moment the push is answered, a new request goes to `d-1002` and none to `d-1001`. Requests already running on `d-1001` finish there.

```json fixture:rolling
{
  "version": 42,
  "tenants": [
    { "id": "team-7", "weight": 1, "budget": { "max_inflight": 1000, "max_buffer_bytes": 67108864 } }
  ],
  "apps": [
    {
      "id": "app-42", "tenant": "team-7", "declared_by": "podkit/agent",
      "tls": { "mode": "acme" },
      "routers": [
        { "name": "web", "entry_points": ["web"],
          "match": { "host": ["shop.apps.example.com"] }, "service": "web" },
        { "name": "websecure", "entry_points": ["websecure"],
          "match": { "host": ["shop.acme-corp.dev"] }, "service": "web" }
      ],
      "revisions": [
        { "id": "d-1002", "state": "serving", "weight": 100,
          "services": [ { "name": "web", "type": "loadbalancer",
                          "servers": [ { "url": "http://10.89.0.22:3000" } ] } ] },
        { "id": "d-1001", "state": "draining", "weight": 0,
          "services": [ { "name": "web", "type": "loadbalancer",
                          "servers": [ { "url": "http://10.89.0.21:3000" } ] } ] }
      ]
    }
  ]
}
```

3. **Wait for the drain.** podgate emits one `revision_drained` when the draining revision has no request in flight: at once if it is idle, otherwise when its last request ends.

```json shape:revision_drained
{"seq": 12, "kind": "revision_drained", "app": "app-42", "revision": "d-1001"}
```

4. **Retire the old container** (`retire` in `agent/src/deploy.rs`), then **push `retired`**: the snapshot without `d-1001`.

```json fixture:retired
{
  "version": 43,
  "tenants": [
    { "id": "team-7", "weight": 1, "budget": { "max_inflight": 1000, "max_buffer_bytes": 67108864 } }
  ],
  "apps": [
    {
      "id": "app-42", "tenant": "team-7", "declared_by": "podkit/agent",
      "tls": { "mode": "acme" },
      "routers": [
        { "name": "web", "entry_points": ["web"],
          "match": { "host": ["shop.apps.example.com"] }, "service": "web" },
        { "name": "websecure", "entry_points": ["websecure"],
          "match": { "host": ["shop.acme-corp.dev"] }, "service": "web" }
      ],
      "revisions": [
        { "id": "d-1002", "state": "serving", "weight": 100,
          "services": [ { "name": "web", "type": "loadbalancer",
                          "servers": [ { "url": "http://10.89.0.22:3000" } ] } ] }
      ]
    }
  ]
}
```

The agent has one poller per server. It calls `GET /v1/events?after=<last seq>&timeout_secs=20` in a loop, remembers the last `seq`, and hands each `revision_drained {app, revision}` to whichever deploy waits for that pair. Always poll with the last `seq`, never with the time of the push: the event can arrive before the agent starts waiting.

```json shape:events
{"boot_id": "7c1a5d54-0d4c-4b9e-9c0e-2f3a6f0d7e11", "events": []}
```

- **Deadline.** Wait for the drain for the deployment's `stop_timeout_s` plus a margin of 10 seconds. On the deadline retire the old container anyway and log that requests were still running: stopping the container cuts them at `stop_timeout_s` in any case, and a long-lived connection would otherwise hold a deploy forever.
- **`408`.** A long poll that outlasts the admin timeout answers `408` and consumes nothing. Poll again with the same `after`.
- **`410`.** `after` is older than the ring of 4096 events. Some events are lost: treat every pending drain as unknown and let its deadline decide, then continue with `after` set to the `oldest` the answer names minus one.
- **A changed `boot_id`.** podgate restarted. Push the whole state again, then treat the pending drains as done: a restart ended every request.
- **`config_reverted`.** podgate watches the apps a push changed for `revert_window_secs` (60 by default; `0` turns it off). If their `5xx` ratio spikes it restores the previous snapshot, which makes the old revision `serving` again, and tells:

```json shape:config_reverted
{"seq": 14, "kind": "config_reverted", "from_version": 42, "to_version": 41}
```

  An agent that is still waiting treats it as a failed deploy: keep the old container, remove the new one, fail the deployment. The live version stays at 42, so the next push is 43 or more. The net only covers the time until the old container is retired. A deploy that retires the old container as soon as it is drained, as above, has the health check as its only gate; keeping the old container for the revert window is a memory cost podkit can choose to pay.
- **A crash between push and retire.** After the restart the agent finds both containers. The highest `instance_id` serves; push `rolling`, wait (the old one is already idle, so the drain comes at once), retire.

### Canary and skew protection

Both are optional and are fields of the same snapshot.

A canary replaces the instant switch. Both revisions are `serving`; `canary` names the new one, whose `weight` is then ignored. podgate gives it `step_percent` of new sessions, adds `step_percent` every `interval_secs` while its `5xx` rate stays below `max_error_permille`, and pulls it back to `0` for good on a breach, emitting `canary_regressed {app, revision, error_permille}` once. The agent reacts to that event by failing the deploy and pushing the old revision alone. When the canary has reached 100 percent the agent pushes `rolling`; podgate sends no event for a promotion.

```json snippet:canary
{ "canary": { "revision": "d-1002", "step_percent": 20, "interval_secs": 30, "max_error_permille": 20 } }
```

This goes into the app object next to `revisions`.

Skew protection pins a browser to the revision that served its first request. The cookie is signed with a snapshot-level `skew_secret` (at least 16 bytes: podkit generates it once and keeps it). While a session's revision is `serving` or `retiring` it stays there. So the old revision is first pushed as `retiring` for a grace period, then as `draining`, and the agent waits for `revision_drained` as above.

```json snippet:skew
{ "skew_secret": "0123456789abcdef-example-only" }
```

This goes at the top level of the snapshot.

## Certificates

podgate keeps nothing on disk. The control plane, here the agent, is the shared store: it hears about certificates from the feed and gives them back in the snapshot. The `acme` fixture is the `retired` state plus the `acme` object, and is where the walk-through starts.

```json fixture:acme
{
  "version": 44,
  "tenants": [
    { "id": "team-7", "weight": 1, "budget": { "max_inflight": 1000, "max_buffer_bytes": 67108864 } }
  ],
  "apps": [
    {
      "id": "app-42", "tenant": "team-7", "declared_by": "podkit/agent",
      "tls": { "mode": "acme" },
      "routers": [
        { "name": "web", "entry_points": ["web"],
          "match": { "host": ["shop.apps.example.com"] }, "service": "web" },
        { "name": "websecure", "entry_points": ["websecure"],
          "match": { "host": ["shop.acme-corp.dev"] }, "service": "web" }
      ],
      "revisions": [
        { "id": "d-1002", "state": "serving", "weight": 100,
          "services": [ { "name": "web", "type": "loadbalancer",
                          "servers": [ { "url": "http://10.89.0.22:3000" } ] } ] }
      ]
    }
  ],
  "acme": {
    "issuer_node": "srv-1",
    "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
    "contact": ["mailto:ops@example.com"]
  }
}
```

| Field | Value |
|---|---|
| `acme.issuer_node` | `NODE_NAME` of the one node that orders. There is one podgate per server, so it is this server's own name. |
| `acme.directory_url` | The CA, `https://...`. |
| `acme.contact` | `mailto:` plus `Ingress.acme_email`. |
| `acme.account_key_pem` | Not in the fixture. The agent generates one P-256 PKCS#8 key per server, stores it, and adds it to every push, so a restart keeps the CA account. Without it podgate makes a new account in memory on every start. |
| `acme.challenges` | `[{token, key_authorization}]`, added after `acme_challenge` events. |
| `certificates` | `[{hosts, cert_pem, key_pem}]`, added after `certificate_issued` events. |

The walk-through, as `podkit_acme_walkthrough` runs it against `pebble`:

1. **Push the `acme` fixture** (with the account key). The node named in `issuer_node` opens an order for the exact hosts of the app that no certificate covers.
2. **Read `acme_challenge`**, one per pending authorization, from the feed.

```json shape:acme_challenge
{"seq": 1, "kind": "acme_challenge", "type": "http-01", "token": "<token>", "key_authorization": "<token>.<account thumbprint>"}
```

3. **Push the answers.** Copy `token` and `key_authorization` into `acme.challenges` and push, version plus one. Push after every poll that returned challenges, not once at the end: the agent does not know how many there are. Every node serves `GET /.well-known/acme-challenge/<token>` on its plain HTTP entry point for any host, so the published host port 80 must reach it. The issuer starts validation when its own table holds the token.
4. **Read `certificate_issued`.**

```json shape:certificate_issued
{"seq": 3, "kind": "certificate_issued", "hosts": ["shop.acme-corp.dev", "shop.apps.example.com"], "cert_pem": "-----BEGIN CERTIFICATE-----...", "key_pem": "-----BEGIN PRIVATE KEY-----..."}
```

5. **Store it and push it.** Keep `{hosts, cert_pem, key_pem}` where `<data_dir>/traefik-acme` was, with the protection of the other secrets: `key_pem` is a private key. Add it to `certificates` (replacing the entry with the same `hosts`), drop the finished challenges from `acme.challenges`, and push. Store it before anything else: until the control plane stores a certificate the issuer does not order that job again for 10 minutes, and when the store fails the certificate is lost.
6. **Renewal** needs nothing new. The issuer renews inside the CA's renewal window (ARI) and emits another `certificate_issued` for the same hosts; step 5 replaces the stored one. A host added to the app later is ordered by itself; drop a stored certificate when no app claims its hosts any more.
7. **After a restart** of the agent or of podgate, the first snapshot already holds every stored certificate, so podgate serves TLS at once and orders nothing for hosts it has a certificate for.

## Failure behaviour

| Answer | What it means | The agent |
|---|---|---|
| `200 {"version":N}` | applied | goes on |
| `400` | not JSON, or a bad header or query | a bug in the builder: fail the operation and log the body |
| `409` with `writer` | another writer owns the node ([The writer rule](#the-writer-rule)) | stops pushing, reports the ingress as taken over, alerts |
| `409` without `writer` | the version is not newer than the live one | reads `GET /v1/snapshot/version`, pushes `version + 1` once; a second `409` is a failure |
| `422` | the compiler refused the whole snapshot; the live one is unchanged and keeps serving | fails the deploy that caused it, shows the `conflicts` in the deploy log, removes the new container, does not retry the same input |
| `503` with `retry-after` | busy (`validate` only) | retries after the time given |
| no answer | podgate is down or restarting | retries with backoff; after it is back, pushes the whole state ([Versions and restarts](#versions-and-restarts)) |

The version `409` after the agent lost its counter:

```json reply:stale_version
{"error":"stale snapshot: version 41 is not newer than live version 41"}
```

A `422` lists every conflict at once, each with a stable `code` and a `message`. A second application (`app-43`) claiming `shop.apps.example.com`:

```json reply:rejected
{
  "error": "snapshot rejected",
  "conflicts": [
    {
      "code": "host_conflict",
      "host": "shop.apps.example.com",
      "apps": ["app-42", "app-43"],
      "declared_by": ["podkit/agent", "podkit/agent"],
      "message": "host shop.apps.example.com is claimed by app app-42 (podkit/agent) and app app-43 (podkit/agent)"
    }
  ]
}
```

The upstream policy of this page refusing an address the builder wrote, here the network gateway `10.89.0.1`. The metadata address `169.254.169.254` is refused the same way, with another `rule`:

```json reply:upstream_forbidden
{
  "error": "snapshot rejected",
  "conflicts": [
    {
      "code": "upstream_forbidden",
      "app": "app-42",
      "declared_by": "podkit/agent",
      "at": "revision d-1002 service web",
      "service": "web",
      "server": "http://10.89.0.1:3000",
      "rule": "deny 10.89.0.1/32",
      "message": "app app-42 (podkit/agent) revision d-1002 service web: service web server http://10.89.0.1:3000: 10.89.0.1 is in the denied range 10.89.0.1/32 (rule: deny 10.89.0.1/32)"
    }
  ]
}
```

`POST /v1/snapshot/validate` takes the same body as the push and answers `200 {"valid":true,"warnings":[]}` or the same `400` and `422`, without a version, a writer or a side effect. Use it in podkit's own tests: all four fixtures pass it. `GET /v1/schema` is the JSON Schema of a snapshot, generated from the model, for the builder's tests.

## What changes in podkit

- `agent/src/ingress.rs`: `ensure_traefik` becomes `ensure_podgate`. The container is `podkit-podgate` with the environment above, the admin socket directory mounted, and no Podman socket. `config_hash` covers the image, the ports, the policy file and `NODE_NAME`. `routing_labels` and `secure_routing_labels` are removed.
- `agent/src/deploy.rs`: `SWAP_DELAY` and its sleep become the drain wait. `container_spec` writes `podkit.*` labels instead of `traefik.*` ones, and `validate_options` reserves them as it reserves `traefik.` today.
- A new module in the agent builds the snapshot from the containers (the mapping above), pushes it, and runs the event poller and the certificate store.
- `agent/src/supervisor.rs`: a restarted container whose address changed triggers a push.
- `agent/src/routes.rs`: `delete_service` pushes the snapshot without the application.
- `crates/proto/src/lib.rs`: `DeploySpec` carries the team id, which the server knows and the agent does not; `Routing` and `Ingress` stay.

## Checklist

- [ ] podgate runs as `podkit-podgate` with `ENTRY_POINTS` (or the shorthand), `NODE_NAME`, the admin socket directory and the upstream policy file.
- [ ] The agent waits for `/readyz`, then pushes the full state with `podgate-writer: podkit-agent`.
- [ ] The builder maps team, application, hosts and deployment as in [Mapping](#mapping); each of its outputs passes `POST /v1/snapshot/validate`.
- [ ] The version counter survives an agent restart (`GET /v1/snapshot/version`, then `+1`) and a podgate restart (`boot_id`).
- [ ] A rolling deploy pushes `rolling`, waits for `revision_drained` with the deadline, retires the old container and pushes `retired`.
- [ ] `config_reverted`, `408`, `410` and a changed `boot_id` are handled in the poller.
- [ ] `409` and `422` end the operation the way [Failure behaviour](#failure-behaviour) says.
- [ ] Certificates are stored on `certificate_issued`, pushed back, and part of the first push after any restart; challenges are pushed back after every poll that returned some.
- [ ] `ensure_traefik`, the labels, the Podman socket bind and the sleep are gone.

## Tests

| Test | Proves |
|---|---|
| `podkit_doc_examples_match_fixtures` | the fixtures in this page are the files the tests use |
| `podkit_fixtures_compile` | the daemon validates and accepts all four fixtures, the policy file above works, the snippets are accepted |
| `podkit_rolling_deploy_sequence` | no request fails, the drain waits for the in-flight request, the old revision is gone after `retired` |
| `podkit_rolling_deploy_reverts` | `config_reverted` arrives and the old revision serves again |
| `podkit_acme_walkthrough` | the certificate round trip against `pebble`, and the replay on a fresh podgate |
| `podkit_writer_rules` | the second writer is refused, the takeover works, the replies quoted here |
| `podkit_documented_environment` | the environment block parses to the two entry points |
