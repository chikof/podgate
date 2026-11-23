# Multi-cluster federation

Reference for `crates/podgate-federation`. One read-only view of the API catalogs (`docs/ref/catalog.md`) and the status of several podgate clusters, every entry labelled by its cluster. It matches the multi-cluster management of Traefik Hub; Caddy has none. The deliberate differences: it is a view only (it never routes a request across clusters, never writes to a peer, never merges a peer's entries into a snapshot), it needs no account with a vendor, and nothing in the proxy changes unless the operator asks for a read socket.

## Pieces

|Piece|Runs|Does|
|---|---|---|
|The daemon's read socket|in `podgate`, only when `ADMIN_READ_SOCKET` is set|Serves `GET /v1/overview?section=summary` and `GET /v1/catalog` on a second unix socket (`docs/ref/admin-tools.md`, `## The read socket`).|
|`podgate-federation export`|on each cluster node, as a user that can open the read socket and not the admin socket|Reads those two routes and serves them to hubs over mutual TLS.|
|`podgate-federation hub`|anywhere the operator likes|Pulls every peer the operator listed, and serves the combined view over mutual TLS.|
|`podgate-federation check`|anywhere|Parses and validates a file, reads every certificate and key, opens nothing.|

The crate depends on no podgate crate and no podgate crate depends on it. A program that holds text peers wrote must not have the model types to build a snapshot, and the daemon has no federation code at all. The daemon's whole share is the read socket, off unless set.

```
podgate-federation export --config /etc/podgate/federation-export.toml
podgate-federation hub    --config /etc/podgate/federation.toml
podgate-federation check hub    --config /etc/podgate/federation.toml
podgate-federation check export --config /etc/podgate/federation-export.toml
```

Annotated examples: `deploy/federation-export.example.toml` and `deploy/federation.example.toml`.

## The exporter file

|Key|Default|Meaning|
|---|---|---|
|`read_socket`|required|The daemon's `ADMIN_READ_SOCKET`. A path that serves the full admin API is refused (see [Read socket probe](#read-socket-probe)).|
|`admin_slots`|`2`|Requests to the read socket at once, 1 to 4. The daemon has 8 overview slots, shared with the local agent and the dashboard.|
|`[serve] addr`|required|The address hubs connect to, such as `10.0.0.5:9443`.|
|`[serve] cert_file`, `key_file`|required|The exporter's server certificate chain and key (PEM).|
|`[serve] client_ca_file`|required|The CA a hub's certificate must chain to. This is the whole access list: dedicate a CA to federation.|
|`[serve] max_connections`|`8`|TLS connections at once, 1 to 64. One over is closed before the handshake.|

Unknown keys are errors. A bad value stops startup with `<field>: <reason>` and never quotes a file.

## The peers file (the hub)

|Key|Default|Meaning|
|---|---|---|
|`[view] addr`, `cert_file`, `key_file`, `client_ca_file`, `max_connections`|as `[serve]`|Where the combined view listens, its certificate, and the CA of the operators who may read it.|
|`[client] cert_file`, `key_file`|required|The hub's identity towards every peer.|
|`[pull] poll_secs`|`30`|Wait between pulls of one peer, 5 to 3600. After failures the wait doubles per failure up to 300 s, never below `poll_secs`, with 10% jitter.|
|`[pull] timeout_secs`|`20`|The whole pull of one peer, from resolving to the last page, 1 to 120.|
|`[pull] stale_after_secs`|`3 x poll_secs`|How old a success may be before the cluster shows as stale, at least `poll_secs + timeout_secs`, at most 86400.|
|`[pull] max_bytes`|`8388608`|Bytes read from one peer per pull, 1 MiB to 64 MiB.|
|`[pull] max_entries`|`20000`|Catalog entries kept per peer, 1 to 200000.|
|`[[peer]] name`|required|The cluster label: `[a-z0-9][a-z0-9._-]{0,62}`, unique. It comes from this file and only from it.|
|`[[peer]] url`|required|`https://host[:port]`. No path, query, fragment or userinfo; no plain `http`.|
|`[[peer]] ca_file`|required|The CA this peer's certificate must chain to. The platform's roots are never used.|
|`[[peer]] server_name`|host of `url`|The name the peer's certificate must carry.|

At most 32 peers. Files are read once at start; rotating a certificate is a restart.

## The peer wire

Two `GET` routes on the exporter, JSON, `format_version: 1`. A new optional field does not change the version; a change a reader would break on does, and the exporter then serves both paths for a window. The hub reads `format_version` first and alone, accepts only the versions it lists (`1`), and shows any other as `unsupported_format`.

|Route|Answer|
|---|---|
|`GET /federation/v1/status`|`{"format_version", "snapshot_version", "applied_at", "boot_id", "writer"?, "counts": {"tenants", "apps", "routers", "services", "servers": {"healthy", "unhealthy", "ejected"}}}`, from `GET /v1/overview?section=summary`.|
|`GET /federation/v1/catalog?limit=<n>&after=<cursor>`|`{"format_version", "snapshot_version", "total", "items", "truncated", "next"?}`. `limit` defaults to 100, at most 200, `0` is `400`. `items` are the catalog items of `docs/ref/catalog.md` (same fields, absent when not declared); the daemon's top-level `version` is renamed `snapshot_version`. A page ends at 3 MiB of items.|

Everything else is `404 {"error": "not found"}`; another method on those paths is `405` with `allow: GET`; a request with a body is `400`; an unknown or repeated parameter is `400`. The exporter parses the daemon's answers and writes its own closed shape, so a field the daemon adds never leaves the cluster, and every string is capped again (below). The `after` cursor is `<tenant>/<id>/<version>`; it is validated (at most 512 bytes, three non-empty parts, no control character) before the read socket is touched, and a daemon `503` is answered `503 {"error": "busy"}` with `retry-after: 1`. A daemon that cannot be reached is `502 {"error": "the daemon is unavailable"}`.

## What a pull does

One TLS connection, kept alive, under one deadline: the status, then the catalog from the start in pages of 100. The hub builds every `after` itself from the last key it was sent and never repeats a cursor the peer named; a `next` that differs is `malformed`. Keys must be strictly ascending within and across pages, a page must make progress, and `snapshot_version` must be the same on every page. When it changes the walk restarts once; a second change is `unstable`. A pull replaces the peer's entries all at once or not at all: after a failure the last good list stays.

Parameters are fixed. No filter of a reader of the view and no tenant text is ever sent to a peer, and no peer text becomes a URL: a redirect is a failed pull, never followed. The only requests are `GET /federation/v1/status` and `GET /federation/v1/catalog?limit=100[&after=<cursor>]`.

## Freshness and failure

Freshness uses the hub's clock only. A cluster is `fresh` when its last pull succeeded and ended less than `stale_after_secs` ago, `stale` otherwise, and a peer that never succeeded is `stale` with `last_success: null` and no entries. A stale cluster keeps its last good entries, flagged `stale: true`, until the hub restarts or the peer leaves the file. One peer's trouble delays no other: each has its own task, connection and deadline.

The error is a class, never peer text:

|Class|Meaning|
|---|---|
|`connect`|No connection, or it broke.|
|`tls`|The handshake failed: a certificate the pinned CA does not vouch for, a name that does not match, or the peer refused the hub's certificate.|
|`timeout`|The pull did not end within `timeout_secs`.|
|`status`|Any answer but `200`, a redirect included; the number is shown.|
|`too_large`|More bytes than `max_bytes` or a page cap, or more entries than `max_entries`.|
|`malformed`|Not the documented shape, not ascending, no progress, a `next` that is not the cursor, a body that is not declared JSON.|
|`unsupported_format`|A `format_version` this hub does not read; the version is shown as `peer_format_version`.|
|`unstable`|The catalog changed under the pull twice.|

The hub logs a cluster's change of state once (name and class), not every poll.

## The view

Mutual TLS only, on `[view].addr`; there is no plaintext mode and no loopback exemption. `GET` only (`405` with `allow: GET`), any other path `404`, a request with a body `400`. Every answer carries `content-type: application/json`, `x-content-type-options: nosniff`, `content-security-policy: default-src 'none'; sandbox`, `referrer-policy: no-referrer` and `cache-control: no-store`. No route renders HTML and a peer's text is a JSON string and nothing else.

|Route|Answer|
|---|---|
|`GET /v1/clusters`|`{"now", "items": [{"name", "state", "last_success", "last_attempt", "error", "snapshot_version", "boot_id", "applied_at", "writer", "peer_format_version", "entries", "dropped", "counts"}]}`, sorted by name, every cluster. `state` is `fresh` or `stale`; `last_success` and `last_attempt` are seconds since the Unix epoch or `null`; `error` is `null` or `{"class", "status"?}`; `dropped` counts entries the last good pull left out.|
|`GET /v1/catalog?cluster=&tenant=&lifecycle=&limit=&after=`|`{"total", "items": [{"cluster", "stale", ...the catalog item}], "stale_clusters", "truncated"?, "next"?}`. Sorted by `(cluster, tenant, id, version)` as text. `limit` defaults to 50, at most 500, `0` is `400`. `lifecycle` is `draft`, `preview`, `stable`, `deprecated`, `retired` or `unknown` (a stage a newer peer added). `next` and `after` are `<cluster>/<tenant>/<id>/<version>`. A page ends at 4 MiB. The filters run on local data. An unknown `cluster` is an empty list.|

## Bounds on a peer

|Bound|Value|
|---|---|
|The pull|`timeout_secs`, one deadline around the whole call, so a peer that trickles bytes ends at it|
|Bytes per pull|`max_bytes`; a page is read at most 4 MiB, the status 64 KiB|
|Entries per peer|`max_entries`|
|A page|at most 500 items; the parser stops reading at the 501st, so a body of empty objects costs nothing|
|Tenant, app, id, `declared_by`|128 bytes; version 64; host 253; OpenAPI name, title and version 256|
|Title, description|cut at 256 and 2,048 bytes on a character boundary; control characters other than line breaks and tabs in a description drop the entry|
|Routers, hosts per entry|at most 64 each, the rest cut|
|A key field over its cap or with a control character|drops the entry, counted in `dropped`; text is never cut into a key, so a cut cannot make two entries collide|
|Peers|at most 32, one task and one connection each|
|Retained memory|about twice `max_bytes` per peer at worst; with the defaults at most 512 MiB for 32 hostile peers|
|Exporter|`max_connections`, 5 s handshake, 10 s for a request head, 16 KiB head, no request body, 30 s a request, 5 min a connection|

There is no `allow_local` rule as in the provider's HTTP source: the address is the operator's, the certificate must chain to the peer's pinned CA and carry `server_name`, and nothing a peer sends can choose another address. The shared rule of the program (outbound calls through the upstream policy and the tenants' budgets) does not apply: the policy covers connections a tenant can influence (`docs/ref/upstream-policy.md`), and a peer call is the operator's, made by a program that is not the daemon, with no tenant in it. The bounds above replace the budget.

## Who can read what

Federation is operator-wide and entries keep their tenant: the key is `(cluster, tenant, id, version)`, and the catalog is the operator's view. Two clusters may both hold a tenant `acme`; they are two rows.

|Reader|Sees|
|---|---|
|A holder of a certificate from the exporter's `client_ca_file`|That cluster's catalog and summary counts, every tenant. No events, snapshot, plan, failures, metrics, schema, or other overview section: they are not routes on the read socket.|
|A holder of a certificate from the hub's `[view].client_ca_file`|Every cluster listed in the peers file.|
|A tenant|Nothing. The portal (`docs/ref/portal.md`) reads only the local catalog with its own `published` filter, never a federated entry.|

The CA is the access list; revocation is rotating the certificate or the CA and restarting. The catalog holds no secret (`docs/ref/catalog.md`).

## Trust

|Actor|Can|Cannot|
|---|---|---|
|A hostile or compromised peer|Lie about its own entries and status; send huge, slow, malformed, unordered or repeated data.|Rename or change another cluster's rows (the label is the file's, its text is never an address); exhaust the hub (everything above is capped per peer); delay another peer's pull; write anything (the hub sends only `GET`); redirect the hub; learn the hub's key (TLS 1.3 sends the hub's certificate, never its key).|
|A hub, as seen by an exporter|Read the catalog and summary at a rate bounded by `max_connections` and `admin_slots`.|Reach any other route, inject a path or a query into the read socket (only a number and a validated cursor cross), write.|
|The exporter process|Read two routes of the read socket.|Push a snapshot, read the event feed or purge a cache, when it runs as a user that cannot open the admin socket. Nothing is parsed before the TLS handshake completes with a certificate from its client CA, so the surface before authentication is `rustls`'s handshake.|
|A compromised daemon|Feed the exporter hostile JSON.|Get past the exporter's own caps and closed types, which then also bound what the hub sees.|

Credentials are certificates and keys, only as files named in the two configuration files; never an environment variable, a flag or a snapshot. A key is read into the TLS configuration at start and dropped; no type that holds one prints it. An error names the setting (`client.key_file: holds no private key`), never a file's content or a URL. The hub logs a cluster's name and a failure class and never a peer's body, headers or cursor.

### Read socket probe

On its first use the exporter sends `GET /healthz` to `read_socket`. A read socket answers `404`; `200` means the path serves the full admin API, and the exporter stops with `read_socket serves the full admin API; set it to the daemon's ADMIN_READ_SOCKET`. At start the probe runs at once when the socket answers; a daemon that is not up yet is not an error. The probe catches a wrong path. It does not stop an exporter run as the daemon's user from opening the admin socket itself, which is why the setup below runs it as another user.

## Setup

```
# daemon (environment)
ADMIN_READ_SOCKET=/run/podgate-read/read.sock
ADMIN_READ_SOCKET_MODE=0660
```

Create `/run/podgate-read` owned by the daemon's user with a dedicated group and the setgid bit (`install -d -o podgate -g podgate-fed -m 2750 /run/podgate-read`), so the socket takes that group. Run the exporter as a user `podgate-fed` that is in `podgate-fed` and in no group that can open `ADMIN_SOCKET` (mode `0600`, the daemon's user). Give the exporter's `[serve] client_ca_file` a CA used for federation only. Run the hub with its own client certificate, signed by each exporter's CA, and let it pin each peer's server CA in `ca_file`.

## What it does not do

No cross-cluster routing: a view that decided where a request goes would make one cluster's failure or compromise a routing input for the others. No write to a peer and no merge of a peer's entries into a snapshot. No web page (the view is an API behind mutual TLS; a page would need a client certificate in a browser). No per-client scoping (every certificate of a CA sees every tenant of that cluster). No CRL or `SIGHUP` reload; rotate by restarting.

## Against Traefik and Caddy

| | Traefik Hub | Caddy | podgate |
|---|---|---|---|
| Multi-cluster view | a SaaS platform with an agent per cluster | none | `podgate-federation hub`, self-hosted, one binary |
| Direction | agents dial out to the platform | | the hub pulls; an exporter listens |
| Routes across clusters | no | | no |
| A peer can write to the view's owner | agents report | | no: read only, capped and typed |
| Peer text on screen | rendered by the platform | | JSON strings only |

## Tests

`crates/podgate-federation/tests/hub.rs`: `federation_combined_view`, `federation_filters`, `federation_peer_down_is_stale`, `federation_peer_slow_bounded`, `federation_old_format_degrades`, `federation_peer_error_status`, `federation_hostile_peer_oversized`, `federation_hostile_peer_malformed_json`, `federation_hostile_peer_unordered_pages`, `federation_hostile_peer_duplicate_keys`, `federation_hostile_peer_no_progress`, `federation_hostile_peer_lies_about_next`, `federation_hostile_peer_long_strings`, `federation_hostile_peer_cannot_rename`, `federation_peer_text_as_text`, `federation_peer_version_flip_is_unstable`, `federation_only_gets`, `federation_files_are_read_once`, `federation_view_requires_client_cert`, `federation_view_methods_405`, `federation_view_headers`. `tests/export.rs`: `federation_export_requires_client_cert`, `federation_export_only_two_routes`, `federation_export_validates_cursor`, `federation_export_reencodes_closed_shape`, `federation_export_steps_over_dropped_entries`, `federation_export_caps_admin_concurrency`, `federation_export_daemon_down_is_502`, `federation_export_refuses_full_admin_socket`, `federation_does_not_touch_routing`, `federation_hub_reads_exporter`, `federation_export_reads_live_daemon`. `tests/config.rs`: `federation_bad_peers_file`, `federation_bad_export_file`, `federation_crate_depends_on_no_podgate_crate`. `tests/cli.rs`: `federation_cli_usage_and_check`, `federation_credentials_never_logged`. Unit tests next to the code: `federation_wire_*`, `federation_freshness_rules`, `federation_backoff_bounds`, `federation_view_*`.
