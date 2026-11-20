# Read-only overview API

Reference for `GET /v1/overview` (`src/overview.rs`, `src/admin/overview.rs`). It answers "what is configured and how is it doing" on the admin socket. The model it reads is in `docs/architecture.md` (`### Explain`).

```
GET /v1/overview?tenant=<id>&app=<id>&limit=<n>&after=<cursor>&section=<name>[,<name>]
```

It reads the live compiled routing table and the runtime registries (server health and ejection, in-flight counters, tenant budgets, response outcomes, circuit breaker phase, canary share). It never reads a snapshot, so what it shows is what the proxy routes with, and it cannot drift from [explain](#against-explain). It changes nothing: only `GET` is accepted, anything else is `405` with `allow: GET`.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `section` | all | Comma separated: `summary`, `tenants`, `apps`, `entry_points`, `certificates`. An unknown name is `400`. |
| `tenant` | none | Only this tenant's entry in `tenants` and its apps. |
| `app` | none | Only the app with this id. |
| `limit` | 50 | Most items in each of `tenants`, `certificates` and `apps`. Above 500 it is 500; `0` is `400`. |
| `after` | none | Cursor for `apps`: apps whose id sorts after this one. Use the `next` of the previous page. |

## Response

Every list is `{"total": n, "items": [...]}`. `total` counts what the filters select, wherever the cursor is.

| Section | Content |
|---|---|
| `summary` | `version`, `applied_at` (seconds since the Unix epoch when the live table was compiled; a revert counts), `boot_id` (as on the event feed), `metrics_addr` (when the process has a `METRICS_ADDR` listener), counts of `tenants`, `apps`, `routers`, `services`, and `servers` by `healthy`, `unhealthy` and `ejected`. The counts cover the whole node, whatever the filters say. |
| `entry_points` | Per listener: `name`, `protocol`, `address`, `proxy_protocol` (only when on), `forwarded_headers` (`nobody`, `listed_peers` or `everyone`). |
| `tenants` | `id`, `weight`, `budget`, `apps`, and live `inflight` and `buffer_bytes`. |
| `certificates` | `hosts`, `issuer`, `not_after` (seconds since the Unix epoch), `source` (`acme` when the issuer renews it, else `snapshot`). Never a chain or a key. |
| `apps` | Sorted by id. Per app: `id`, `tenant`, `declared_by`, `tls` (`mode`, `challenge`, `client_auth`, `pass_client_cert`), `hosts`, `allow_domain_fronting`, `scale_to_zero`, `canary`, `routers`, `revisions`, `services`, `middlewares`, `recent`. |

An app has:

- `routers`: `name`, `declared_by`, `entry_points` (absent: every HTTP entry point), `match` (the matcher tree as written), `priority`, `chain` (middleware names, in order), `service`.
- `revisions`: `id`, `state`, `weight`, `effective_weight` (what the picker uses now, as in explain), `inflight`, `recent`.
- `services`: `name`, `revision` (absent for a service every revision shares), `type`, `algorithm`, `servers`. Per server: `url`, `weight`, `available`, `active` (requests in flight to it), and, only when the feature is configured, `healthy` (the active health check's verdict, with `health_check: true` on the service) and `ejected_for_ms` (while passive outlier detection holds it out, with `outlier_detection: true`).
- `middlewares`: `name`, `type`, and `config`, which is the kind's `describe()` output. A circuit breaker shows its `phase` there.
- `recent`: `window_secs` (300), `requests` and `errors_5xx` from the same counters auto-revert and the canary read.

A field of a feature that is not configured is absent, not `null`: a service without `health_check` has no `healthy`, an app without a canary has no `canary`. The snapshot's writer name is not on the node yet and is absent too.

## Bounds

- The body is at most 4 MiB. `tenants` and `certificates` each take at most an eighth of it; `apps` take the rest. A list that stopped early carries `"truncated": true`, and `apps` also `"next"`, the id to pass as `after`. An app that alone is larger than the room becomes a stub, `{"id", "tenant", "too_large": true, "routers", "revisions", "services", "middlewares"}` with the counts, so a listing always makes progress. Asking for that app alone with `app=<id>` still gives the stub: the cap holds for every request.
- At most 8 overview computations run at once; the ninth gets `503 {"error": "overview is busy"}` with `retry-after: 1`. The work runs on the blocking pool, off the admin runtime's workers.
- Reading the view clones nothing from the request path: it takes the current table once and then reads atomics.

## What is never shown

| Never shown | How |
|---|---|
| `client_ca_pem`, certificate chains and keys, ACME account keys and external account binding keys, `skew_secret` | The view types have no field for them; `tls` shows `client_auth: true`. |
| `basic_auth` and `digest_auth` users and hashes, WASM module bytes, header values set by `headers` | A kind reaches the view only through `describe()`: `basic_auth` and `digest_auth` show the user count, `wasm` shows `fuel` and `max_memory_bytes`, `headers` shows header names. |
| The value of a `header` or `query` matcher leaf | Replaced by `[value]` for every name, in `header`, `header_regexp`, `query` and `query_regexp`; the names stay. Hosts, paths, methods and client IP ranges are shown as written. |
| The event feed | It carries `certificate_issued` with private keys; `section=events` is `400`. |
| Request data | Failed requests have their own endpoint, `GET /v1/apps/{app}/failures`. |

Protection is an allowlist plus one value test, not a list of bad names. The view types list the fields they show, and a service or router is never serialized as declared. A middleware shows only its own `describe()`. The integration test `overview_redacts_secrets` pushes one snapshot in which every built middleware kind, every matcher leaf that carries a client's value, the sticky cookie, a transport's client key, the client CA, a certificate and key, `skew_secret` and the ACME account key hold a unique planted string, and fails when any of them appears anywhere in the answer (all sections, all pages). The same fixture function fails when a kind is built (`Stage::BUILT`) without a fixture, so a new kind cannot skip the check: add it to `every_kind` in `tests/overview.rs` with a planted secret in every field that holds one. `every_describe_is_secret_free` is a secondary check that no `describe()` names a field `password`, `secret`, `key_pem`, `token` or `hash`.

## Against explain

Explain answers "where does this request go" for one URL; the overview answers "what is there". Both read the same `RoutingTable`, so `app`, `tenant`, `declared_by`, the router, the revisions with their effective weights and the servers agree (`overview_matches_explain`).

## Against Traefik and Caddy

| | Traefik | Caddy | podgate |
|---|---|---|---|
| Routers, services, middlewares | `/api/http/routers`, `/services`, `/middlewares` | `GET /config/` | One document with filters and a cursor |
| Counts | `/api/overview` | none | `summary` |
| Entry points | `/api/entrypoints` | none | `entry_points` |
| Writable | no | yes (`POST /load`, `PATCH`) | no |
| Secrets | shown as configured | shown as configured | never shown |
