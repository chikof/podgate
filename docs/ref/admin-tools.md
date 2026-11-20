# Admin API tools for snapshot builders

Reference for `GET /v1/schema`, `POST /v1/snapshot/validate`, `GET /v1/snapshot/version` and the `podgate-writer` guard (`src/admin/schema.rs`, `src/admin/validate.rs`, `src/admin/writer.rs`). They are for programs that build snapshots: the podkit agent, `podgate-provider`, an editor, a CI check. They live on the admin unix socket (`ADMIN_SOCKET`) next to `PUT /v1/snapshot`; the snapshot model is in `docs/architecture.md` (`## Snapshot model v2`).

## `GET /v1/schema`

`200` with a JSON Schema (2020-12), content type `application/schema+json`. The document is built once per process.

| Part | Content |
|---|---|
| root | The schema of a `Snapshot`, generated from the `podgate-model` types with `schemars` (the crate's `schema` feature), so it cannot drift from what the daemon parses. Doc comments of the model are the `description`s. |
| `$defs.<Type>` | One entry per model type (`Tenant`, `App`, `Router`, `Revision`, `TlsPolicy`, ...). |
| `$defs.middleware.<type>`, `$defs.service.<type>`, `$defs.transport.<type>` | One entry per built kind. It describes the whole declared object: the kind's own fields (generated from the kind's configuration struct), plus `name` and `type` (`const`). Unknown fields are refused, as the compiler refuses them. |
| `$defs.matcher.<key>`, `$defs.matcher` | One entry per matcher key (`host`, `path_prefix`, `all`, ...), and the one-of over them. A router's `match` refers to `$defs.matcher`. Written by hand in `src/router/matcher/schema.rs`, because a leaf reads its argument from raw JSON. |
| `kinds` | The index: `kinds.<category>.<type>` is the JSON pointer of the entry, for `middleware`, `service`, `transport` and `matcher`. An editor validates a declared object by its `type`. |
| `unbuilt` | The kinds that are planned and refused with `<category>_not_built`: `unbuilt.middleware`, `unbuilt.service`, `unbuilt.matcher`. A kind is in `kinds` or in `unbuilt`, never both. |
| `podgate_version` | The version of the daemon that served it. |

The schema checks shape, not meaning: a router naming a service that does not exist, two apps claiming one host, an unreadable certificate or a regular expression that does not compile are `422`s of the compiler. Use `POST /v1/snapshot/validate` for those. A kind entry that is extracted from the document refers to `#/$defs/matcher` inside its combinators, so it needs the document around it.

### Adding a kind

A new middleware or service type derives `schemars::JsonSchema` on its configuration struct and adds one line to `schemas!` (`src/middleware.rs`, `src/service.rs`); a new matcher key adds its entry to `src/router/matcher/schema.rs`. The test `every_built_kind_has_a_schema` fails when a built kind has no schema: the `$defs` are compared with `Stage::BUILT`, `service::BUILT` and `matcher::BUILT`. The last two are lists the code itself uses: `Service::compile` and the matcher parser refuse a name that is not listed before they look at their arms, and a unit test in each module compiles one declaration per listed name and checks that an unlisted name is refused, so a list cannot drift from its parser. A new service type or matcher key therefore also adds its name to `BUILT`.

## `POST /v1/snapshot/validate`

Takes the body of `PUT /v1/snapshot` and answers whether it would be accepted, without applying it.

| Answer | When |
|---|---|
| `200 {"valid":true,"warnings":[]}` | The snapshot parses and compiles. `warnings` is reserved and always empty today: the compiler accepts or refuses. |
| `400` | The body is not a snapshot, exactly as `PUT` answers. |
| `422 {"error":"snapshot rejected","conflicts":[...]}` | The compiler refuses it, exactly as `PUT` answers: the same `conflicts`, in the same order. |
| `503 {"error":"validate is busy"}` with `retry-after: 1` | Four validations already compile. |

It runs the same parse (`admin::snapshot::parse`) and the same compile (`TableHandle::validate`, which `apply`, `plan` and `revert` compile through too) as `PUT`; there is no second code path. It leaves out two checks:

- The version. A candidate need not be newer than the live snapshot, so a builder can check a snapshot before it knows the live version, and an old one.
- The writer. Any tool may validate; it never pins a writer and sends no header.

It touches no state: nothing is swapped, no event is emitted, no registry (canary, server state, circuit breakers, metrics) is written, no ACME order starts, and a refusal is not counted in the snapshot metrics. The compile runs on the blocking pool; the slot is held until it ends, so the cap of 4 holds when the client goes away.

## `GET /v1/snapshot/version`

`200 {"version":N,"writer":"<name>"|null,"boot_id":"..."}`.

- `version` is the live version, `0` before the first snapshot. After an auto-revert it is the version that was reverted (the live version never goes down; see `docs/architecture.md`, `## Plan and auto-revert`).
- `writer` is the pinned writer (below), `null` when none is pinned or the pinned writer sent no name.
- `boot_id` is the event feed's, so a restart is visible here too.

A writer reads it after a restart of its own to resume its sequence (`version + 1`), and after a restart of podgate to see that the sequence starts again at `0`.

## The single writer

A node has one writer. Podgate now refuses a second one instead of trusting everyone to follow the rule. A push names itself with the header `podgate-writer: <name>`, 1 to 64 characters of `[a-z0-9._-]`; anything else is `400`, as is a repeated header. The podkit agent sends `podkit-agent`, `podgate-provider` sends `podgate-provider`.

| State | Push | Answer |
|---|---|---|
| nothing pinned (no snapshot yet since the process started) | any, with or without a name | accepted; the writer that sent it is pinned, a name or "no name" |
| pinned to `X` | from `X` | accepted |
| pinned to `X` | from another name, or with no name | `409 {"error":"snapshot is owned by writer X","writer":"X"}`, nothing changes |
| pinned to no name | with no name | accepted |
| pinned to no name | with a name | `409 {"error":"snapshot is owned by an unnamed writer","writer":null}`, nothing changes |

Clients that send no header keep working while nothing else has pinned: they pin "no name" and continue. The moment another writer is wanted, an operator takes the snapshot over.

`POST /v1/snapshot/plan` is checked in the same way (it applies nothing, so it pins nothing). `validate`, `GET /v1/schema` and `GET /v1/snapshot/version` are not.

### Changing the writer

`PUT /v1/snapshot?takeover=true` with the new name in `podgate-writer`. It is a push like any other, so it must compile and be newer than the live version; a refused takeover changes nothing. When it is accepted:

- the pin moves to the new name, from the first push on;
- a warning is logged (`snapshot writer taken over`, with `from` and `to`);
- the event feed gets `{"kind":"writer_changed","from":"<old>"|null,"to":"<new>"}`. `from` is `null` when the old writer sent no name. Nothing is emitted when the first push of a process only pins, or when the owner itself passes `takeover=true`.

A takeover needs a name (`400` otherwise): moving to "no name" would reopen the node to everyone. `takeover` is `true` or `false`.

### What keeps and what resets the pin

| Event | The pinned writer |
|---|---|
| a refused push (`409`, `422`, `400`) | unchanged |
| auto-revert (`config_reverted`) | kept: the revert is podgate undoing a push, not a new writer. The next push must still come from the owner, at a version above the reverted one. |
| a podgate restart | reset: the table is empty and the next writer pins again, at any version |
| a takeover | replaced |

The pin lives in memory next to the live snapshot. Nothing is written to disk, so it works across containers and namespaces, and a restart cannot leave a stale lock behind.

The check, the apply and the pin are one step under one gate, so two first pushes racing for an empty node cannot both win, and a client that disconnects while the snapshot compiles cannot leave a new snapshot live under the old pin: the gate moves into the blocking task that applies the snapshot.

## Against Traefik and Caddy

| | Traefik | Caddy | podgate |
|---|---|---|---|
| Schema of the configuration | `/api/rawdata`, the dynamic configuration types; Kubernetes CRDs with OpenAPI schemas | `/config/`, `adapt` | `GET /v1/schema`, generated from the model types |
| Dry-run of a candidate | no | `adapt` converts, `POST /load` applies | `POST /v1/snapshot/validate`, the same compile as the push |
| Live version | none (providers merge) | none (ETag on `/config/`) | `GET /v1/snapshot/version` |
| Single writer | none: providers are merged | none: `POST /load` replaces | refused by name, takeover by the operator |
