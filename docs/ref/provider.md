# podgate-provider

Reference for `crates/podgate-provider`: the separate program that merges the declarations of any number of sources into one snapshot, decides who may claim which host, and pushes the result to podgate's admin socket. Source modules (Docker, Kubernetes, Nomad, files) are separate specs and plug into the contract below. Example configuration: `deploy/podgate-provider.example.toml`.

podgate never merges: two declarations that conflict on security reject the whole snapshot (`docs/architecture.md`, `### Priority, ambiguity and conflicts`). Everything that Traefik's providers do silently inside the proxy (merge, first writer wins, a label on a container decides the router) is done here, in the open, before a snapshot exists. podgate does not depend on this crate and this crate does not depend on podgate: both speak the `podgate-model` types and the admin API of `docs/ref/admin-tools.md`. `cargo tree -p podgate-provider` has no `podgate`, and `cargo tree -p podgate` has no `podgate-provider`.

The provider is the one writer on its node (`docs/ref/admin-tools.md`, `## The single writer`). It pushes as `podgate-provider`. If the podkit agent owns the node, the provider stops with an error naming it; it never takes the node over.

## Program

```
podgate-provider run   --config <file>
podgate-provider print --config <file>
podgate-provider check --config <file>
```

| Command | What it does |
|---|---|
| `run` | Starts the sources, merges, pushes, keeps pushing. Stops on SIGTERM or Ctrl-C, or with an error when another writer owns the snapshot. |
| `print` | One merge pass: waits for every source to report once (30 s), prints the canonical snapshot JSON (version `0`) on stdout. Pushes nothing. Findings go to the log on stderr. |
| `check` | One merge pass, then `POST /v1/snapshot/validate`. Exit `0` and `valid` when podgate would accept it, exit `1` and `rejected: [conflicts]` when not. |

A source that is unreachable during `print` or `check` is an error: a partial merge would mislead. `RUST_LOG` sets the log filter, `LOG_FORMAT=json` the format.

Source kinds are registered in `main.rs` (`register_sources`); a kind that is not built into the binary stops the program with `source "x": kind "y" is not built into this binary`. A missing source must never silently delete its routes.

## Configuration

TOML. Unknown keys are errors. Every error names its field (`tenant[1].hosts[0]: "a b" is not a host name or a *. wildcard`).

| Key | Default | Meaning |
|---|---|---|
| `admin_socket` | required | podgate's `ADMIN_SOCKET`. |
| `upstream_policy_file` | none | The operator's upstream policy, the file podgate reads. Absent: the built-in deny list. |
| `debounce_ms` | `500` | Updates within this window are one push. |
| `max_delay_ms` | `5000` | A steady stream cannot hold a push back longer than this. Not below `debounce_ms`. |
| `resync_secs` | `30` | Interval of the live-version check; also how long a quarantined object waits for a retry. At least 1. |
| `[default_tenant]` | weight 1, `max_inflight` 256, `max_buffer_bytes` 64 MiB | `weight`, `budget {max_inflight, max_buffer_bytes}`, `catch_all`, `exclusive_entry_points`. Its id is `default`. |
| `[[tenant]]` | | `id`, `hosts` (required, not empty), `weight`, `budget`, `label_sources`, `catch_all`, `exclusive_entry_points`. |
| `[[source]]` | | `kind`, `name`, and the source's own keys. |
| `[snapshot]` | absent | The operator's part of the snapshot, copied into every snapshot as written: `revert_window_secs`, `observability` (access log, metrics, tracing), and `skew_secret_file`, a path to a file holding the skew secret (at least 16 bytes, one trailing newline removed). The secret is never written in the TOML: an inline `skew_secret` is an unknown key. An unreadable or short file fails the configuration load. Unset means the field is absent from the snapshot. `print` shows every secret (`skew_secret`, certificate keys, the ACME account key) as `[redacted]`; the logs never carry snapshot bodies. The `acme` object is not a key of `[snapshot]`: ACME is configured in `[acme]` below, which also runs the broker that answers podgate's ACME events. |
| `[acme]` | absent | `enabled`, `mode` (`broker` or `follower`), `state_dir`, `directory_url`, `issuer_node`, `contact`, `eab`, `account_key_file`, `challenge_lead_ms`, `[acme.on_demand]`. Writes the snapshot's `acme` object and the certificates podgate issues. See `docs/ref/provider-acme.md`. |

Rules the loader checks: tenant and source names are `[a-z0-9][a-z0-9._-]{0,63}`; a tenant is not called `default`; ids and source names are unique; weights and budgets are at least 1; two tenants' `hosts` never overlap (a wildcard that reaches another tenant's exact name is an error); `label_sources` names configured sources; an entry point is exclusive to one tenant.

`catch_all = true` is the same operator decision as listing the tenant in the daemon's `CATCH_ALL_TENANTS`. `exclusive_entry_points` is written into the snapshot as an entry point policy whose `tenants` names that tenant alone, which is what lifts the fallback restriction in the daemon.

## Sources

```rust
pub trait Source: Send + 'static {
    fn name(&self) -> &str;
    fn run(self, updates: tokio::sync::mpsc::Sender<Update>) -> impl Future<Output = ()> + Send;
}
```

A source sends an `Update`: the complete desired state of the source (`Update::state(source, apps, certificates)`), which replaces its previous one, or `Update::outage(source, error)`, which keeps the previous state and reports the error. A source that cannot reach its backend sends an outage and retries; it never sends an empty state to mean "unreachable". An outage of Docker must not delete every route.

An object is a `SourceApp {origin, tenant, app}` or a `SourceCertificate {origin, tenant, certificate}`:

- `Origin {source, object, first_seen}`: `object` is the source's own name (unique per kind within the source). `first_seen` is a number that orders objects by age (unix seconds when the backend knows, `0` when not): it decides which of two conflicting objects is the older and stays. Equal stamps order by source and object name. The core reads no clock.
- `TenantClaim {mapped, label}`: `mapped` is the tenant the source's own configuration assigns (network, namespace, fixed): the operator's decision. `label` is the tenant the object names for itself in a label or annotation: the deployer's claim.
- The `App` is a standard `podgate-model` app. The core overwrites `id`, `tenant` and `declared_by`; the source fills in the rest.

`Engine::add_source(source)` registers a source whose `name` is in the configuration.

## Merge

`Merger::merge(states, excluded) -> Merged` is a pure function of the sources' states, the configuration and the quarantined objects.

- App ids are `<source>-<local id>`, lowercased, every character outside `a-z 0-9 . _ -` turned into `-`. `a`/`b-c` and `a-b`/`c` both spell `a-b-c`: the older object keeps the id, the newer is dropped with `app_id_collision`.
- `declared_by` is `<source kind>/<source name>:<object>`, for example `docker/local:web-1`. It is what podgate names in its conflict lists, and what quarantine maps back to objects.
- Tenants come from the configuration only: every configured tenant and the default tenant, sorted. An object that names a tenant that is not configured is dropped with `unknown_tenant`; it is never defaulted, so a typo cannot change a tenant.
- Output is canonical: tenants, apps and certificates sorted, every object's keys sorted at every depth. Identical inputs give identical bytes (`Merged::fingerprint()`), and the fingerprint decides whether anything has to be pushed. The version is not part of it.
- Objects are processed oldest first, so a collision or a duplicate costs the newer one.

## Trust

`trust.rs` is the security boundary of the provider.

| Rule | Detail |
|---|---|
| A tenant claims hosts inside its `hosts` | Every positive `host` leaf of every router of the object (the daemon's own reading of the matcher: `all`, `any`, `not`, `host_regexp` beside a literal host narrows it). `x.a.test` and `*.x.a.test` are inside `*.a.test`, `a.b.a.test` is not, `a.test` is not (a wildcard matches one extra label). Outside: the object is dropped with `foreign_host_claim`. |
| The default tenant claims what nobody owns | A host that no configured tenant's patterns reach in either direction. |
| Certificates follow the same rule | The hosts of a certificate must lie where the tenant may claim hosts. |
| A label is honoured per source | A `label` naming a tenant counts only when that tenant lists the object's source in `label_sources`. Otherwise it is ignored (finding `label_ignored`, the object is not dropped by it) and the object takes the tenant its source maps, or the default tenant. A label naming the default tenant is always allowed, since it can only lower what the object may claim. A label naming a tenant that does not exist drops the object (`unknown_tenant`). |
| Catch-all preflight | A router whose matcher claims no literal host (a `host_regexp` without a literal host beside it in an `all`, `not`, only path or header leaves, ...) matches every host nobody claims. It is allowed only when the tenant has `catch_all = true`, or every entry point it lists is in the tenant's `exclusive_entry_points`; otherwise `catch_all_not_allowed`. |
| Matchers are read strictly | Not an object with one key, an unknown key, an empty `all`/`any`, a bad host, more than 8 levels: dropped with `invalid_matcher` or `invalid_host`. A key the provider does not know could claim hosts, so it never passes unexamined. |

A spoofed label therefore gains nothing: a user who labels a container `podgate.tenant=acme` on a source that acme does not list gets the default tenant, and a host of acme's is `foreign_host_claim`. The daemon remains the authority: its own checks (`cross_tenant_wildcard`, `host_conflict`, `catch_all_not_allowed`) run on whatever the provider lets through.

## Upstream preflight

`policy.rs` reads the same JSON file as the daemon (`docs/ref/upstream-policy.md`) and applies the same rule to the literal server addresses (`http://`, `https://`, `h2c://` followed by an IP and a port) of every `servers` list in the app's services and in each revision's services, at any depth. A refused address drops the object with `upstream_forbidden`, naming the server and the rule. A server named by a DNS name is not checked: the daemon checks every address a name resolves to. The vectors both implementations must agree on are in `crates/podgate-provider/tests/fixtures/upstream_policy_cases.json`.

## Push

`push.rs` (client, debounce, backoff) and `engine.rs` (the loop). The program reads no clock to number snapshots and keeps no state on disk.

- One writer name: `podgate-writer: podgate-provider`.
- The version of a push is the live version plus one, read from `GET /v1/snapshot/version`, across all sources.
- Debounce: an update starts a window of `debounce_ms`; each further update moves its end; a push is never later than `max_delay_ms` after the first update of the burst. The state machine is `push::Debounce`, over plain millisecond counts.
- An unchanged snapshot (same canonical text) is not pushed. This includes the resync tick: a push resets canary state in podgate, so a periodic identical push would undo a canary ramp.
- Retries, with backoff from 1 to 30 seconds (`push::Backoff`): socket missing or refused, a broken connection, a timeout (30 s per request), `5xx`. The next update is merged in; a retry always pushes the newest state.
- `409` stale: the version is read again and the push repeats, up to 3 times in a row, then it is a retry.
- `409` owned by another writer: the engine stops with `RunError::WriterConflict`, naming the writer. No retry loop, no takeover (`?takeover=true` is the operator's decision).
- Podgate restart: `boot_id` changed, or the live version is below the one pushed. The whole snapshot is pushed again at live `+ 1`. The check runs on every push and on every `resync_secs` tick, so a restart is noticed within one interval even when nothing changed. A live version that differs from the last pushed one (another writer pushed) is repaired the same way.
- Startup: while podgate already serves a snapshot, the first push waits until every configured source has reported once (the status says `waiting for every source to report before replacing a live snapshot`). A source that is slow to start must not delete its routes from a node that is serving them. On a node with no snapshot yet, whatever is known is pushed at once.
- `400` and other `4xx` answers are not retried until a source changes something or `resync_secs` pass; they are reported.

`Engine::status()` is a `tokio::sync::watch::Receiver<Status>`: findings, quarantined objects, source outages, the last pushed version, the count of accepted pushes and the reason the last round did not push.

## Quarantine

podgate stays fail-closed: one wrong object rejects the whole snapshot with `422`. The provider knows the objects, so it leaves out the one that is wrong and pushes the rest. One bad label cannot block every deploy, and cannot hide in the merged snapshot: every quarantined object is in the status and in the log (`object quarantined`, with its `declared_by` and the conflict).

1. **By `declared_by`.** Every conflict of the `422` that carries `declared_by` (a string or a list) points at objects. Conflicts are read in order; one that names an object already chosen is skipped. A conflict between two or more objects keeps the oldest (`first_seen`, then names) and drops the others; a conflict about one drops it. The push repeats without them.
2. **By bisection.** When no conflict names an object (a snapshot-level rejection), the culprits are among the objects that changed since the last accepted snapshot. `quarantine::bisect` validates (`POST /v1/snapshot/validate`) the base (the changed objects left out), then finds, by binary search over the changed objects oldest first, the first one whose addition makes the snapshot rejected, leaves it out and goes on after it. It asks at most `1 + k * (ceil(log2 n) + 1)` questions for `k` culprits among `n` changed objects (`quarantine::bisect_bound`). A conflict between two changed objects therefore costs the newer one. `503` busy answers of validate are waited out (5 times, 1 s).
3. **Never loop.** If the base is rejected too, if nothing changed, or if the changed objects do not explain the rejection, the provider reports `podgate rejected the snapshot and no object can be blamed` with the first conflicts, keeps the last accepted snapshot live, and does not try the same snapshot again until a source changes something or `resync_secs` pass. Every round of step 1 or 2 quarantines at least one of finitely many objects or ends the push.

An object leaves quarantine when its source changes it (a different object, or it is gone) and after `resync_secs`. The bisection assumes that adding an object never cures a rejection; an object it names was confirmed to break a snapshot that was accepted.

## Findings

Codes in the status and the log. `dropped` means the object stayed out of the snapshot.

| Code | Dropped | Meaning |
|---|---|---|
| `unknown_tenant` | yes | The label or the mapping names a tenant that is not configured. |
| `label_ignored` | no | A tenant label from a source that is not in the tenant's `label_sources`. |
| `foreign_host_claim` | yes | A host (or a certificate host) outside what the tenant may claim. |
| `catch_all_not_allowed` | yes | A fallback router without `catch_all` or exclusive entry points. |
| `upstream_forbidden` | yes | A literal server address refused by the upstream policy. |
| `invalid_matcher`, `invalid_host` | yes | A matcher the provider cannot read. |
| `invalid_app`, `invalid_certificate` | yes | An empty app id, a certificate without hosts. |
| `app_id_collision` | yes | Another, older object has the id. |
| `duplicate_object`, `origin_mismatch`, `unknown_source` | yes | A source sent an object twice, under another source's name, or the update is from a source that is not configured. |

## Against Traefik

| | Traefik | podgate-provider |
|---|---|---|
| Where providers merge | inside the proxy, silently | in a separate program, with a report per object |
| A conflicting declaration | the first one wins, or the last, depending on the provider | the older object wins, the newer is quarantined and named |
| Who may claim a host | whoever writes the label | the tenant's configured `hosts`; labels only from `label_sources` |
| A bad label | breaks the provider's whole configuration | one object quarantined |
| A provider outage | provider routes disappear on some backends | the source's last state stays |

## Not covered

The source modules; DNS names in the upstream preflight. Certificate issuance is covered: with `[acme]` enabled the provider reads podgate's event feed and keeps the certificates (`docs/ref/provider-acme.md`).
