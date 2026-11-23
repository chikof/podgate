# API catalog and lifecycle

Reference for the `apis` list of an app, the lifecycle guard and `GET /v1/catalog` (`src/catalog.rs` with `src/catalog/`, `src/middleware/lifecycle.rs`, `src/admin/catalog.rs`). It matches the API catalog, versioning and lifecycle of Traefik Hub's API management; Caddy has nothing like it. The model it plugs into is in `docs/architecture.md` (`## Snapshot model v2`).

The catalog does not route. A version is a path or a host the routers already match, and a second routing layer would be a second place for the same decision. The catalog describes each API and enforces its lifecycle on the routers it names.

## Declaring an API

`apis` is a list on the app. Absent or empty: the app declares none.

```json
{
  "id": "pets",
  "tenant": "acme",
  "apis": [
    {
      "id": "pets", "version": "1", "lifecycle": "deprecated",
      "routers": ["pets-v1"], "sunset": "2027-03-01",
      "successor": { "id": "pets", "version": "2" }
    },
    {
      "id": "pets", "version": "2", "lifecycle": "stable",
      "title": "Pets", "description": "The pet store API.",
      "routers": ["pets-v2"], "openapi": "pets-api", "published": true
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id`, `version` | 1 to 128 bytes of `A-Z a-z 0-9 . _ -` and 1 to 64 bytes of `A-Z a-z 0-9 . _ + -`. `(tenant, id, version)` is unique across the tenant's apps. |
| `lifecycle` | `draft`, `preview`, `stable`, `deprecated` or `retired`. |
| `routers` | One to 64 routers of the same app. A router belongs to at most one entry. |
| `title`, `description` | Free text, at most 256 and 2048 bytes. |
| `openapi` | The name of an `openapi` middleware of the app. The catalog shows the document's title, version, dialect and operation count, never the document. |
| `published` | The tenant's consent to appear on the developer portal. Default `false`. The operator's catalog lists every entry either way. The portal shows an entry only to viewers of its own tenant (`docs/ref/portal.md`). |
| `sunset` | `YYYY-MM-DD`, UTC, from 1970. Required for `deprecated`, allowed for `retired`, refused for the other stages. |
| `successor` | `{id, version}` of another entry of the same tenant. Allowed for `deprecated` and `retired`. |

Unknown fields are refused, so a misspelt field is an error and not a lifecycle that silently does nothing.

### Rejected at compile

Every problem is listed in the `422` with the app, its `declared_by` and `at: "api <id>@<version>"`. Nothing is merged: one bad entry rejects the snapshot and the previous one keeps serving.

| Code | When |
|---|---|
| `duplicate_api_version` | Two entries of one tenant have the same `id` and `version`. The message names the app and `declared_by` of the first. |
| `unknown_router` | `routers` names a router the app does not have. |
| `router_in_two_apis` | A router is named by two entries, or twice by one: a router has one lifecycle, and the compiler does not pick one for the tenant. |
| `unknown_successor` | `successor` names no entry of the same tenant. |
| `unknown_openapi` | `openapi` is not the name of an `openapi` middleware of the app. |
| `invalid_sunset` | The sunset is not a real date, is missing for `deprecated`, or is set on `draft`, `preview` or `stable`. |
| `invalid_api` | An id, version, title or description out of bounds, no router or more than 64, more than 256 entries in an app, a `successor` on `draft`, `preview` or `stable`, or an entry that is its own successor. |

## What the routers answer

| Lifecycle | The named routers |
|---|---|
| `draft` | `404 {"error":"not found"}`. The upstream is not dialled. |
| `preview`, `stable` | Nothing changes. They cost a request nothing. |
| `deprecated` | They serve, and every response gets `Deprecation: true`, `Sunset: <HTTP-date>` (RFC 8594, 00:00:00 UTC of the sunset day) and, when the successor has a router with a literal path, `Link: <path>; rel="successor-version"`. |
| `retired` | `410 {"error":"api retired"}`. The upstream is not dialled. |

`draft` and `retired` answer every method, `OPTIONS` included, before the request takes a tenant slot. The access log `reason` is `api_draft` or `api_retired`. A `410` is not a `5xx`, so auto-revert does not count it.

The path of the `Link` is the first of the successor's routers that has a `path` or `path_prefix` leaf, or an `all` that has one (`any`, `not` and regexps have no single path). It is a relative reference; no host is added. Without such a router the header is not sent.

`Deprecation: true` is the form this spec fixed. RFC 9745 defines the header as a date (`@<unix seconds>`), and the model has no deprecation date. Podgate never reads the clock for a lifecycle: nothing changes when the sunset day passes, because the snapshot owns the lifecycle and the compiled table stays a function of the snapshot.

### Where the guard sits

The compiler pushes one stage per guarded router, named `lifecycle:<router>`, and puts it first in the router's chain. A snapshot cannot declare it (`type: "lifecycle"` is `unknown_middleware`), and a chain only names declared middlewares, so a tenant cannot remove it or move a stage of its own ahead of it. It is first for the request hook, and so last for the response hooks, which run in reverse chain order: a tenant's `headers` middleware that sets or removes `Deprecation`, `Sunset` or `Link` runs before the guard and cannot undo it. `Deprecation` and `Sunset` are overwritten; `Link` is appended once, so an upstream's own `Link` (pagination) stays. A response the cache serves passes the guard too (`Earlier::response`).

The guard shows in `GET /v1/overview` and `GET /v1/explain` as a middleware of type `lifecycle` in the app's `middlewares` and in the router's `chain`.

Known edge: the `deprecated` headers are written by the response hook, so they are on every response that passes the router's response hooks: the upstream's answers, cache hits and error pages. A refusal another stage of the chain writes in its own request hook (an authentication `401`, a rate limit `429`, a `respond` middleware) never passes a response hook and does not carry them.

A router no entry names is untouched. A tenant can still route a path to another router, since which version a request reaches is the routers' decision; the catalog describes the routers it names.

## The plan

Reopening an API is a posture change in `POST /v1/snapshot/plan`: `kind: "api_reopened"` for the host of the app when a router that was `draft` or `retired` is now `preview`, `stable` or `deprecated`, or its entry is gone or no longer names it. Closing an API, deprecating a stable one and `retired` staying `retired` list nothing.

## `GET /v1/catalog`

On the admin socket, for the operator. `GET` only (`405` with `allow: GET`). Built from the live compiled table, never from a snapshot: after a swap it changes with the table, and a rejected snapshot leaves it as it was.

```
GET /v1/catalog?tenant=<id>&app=<id>&lifecycle=<word>&limit=<n>&after=<cursor>
```

| Parameter | Default | Meaning |
|---|---|---|
| `tenant` | none | Only this tenant's entries. |
| `app` | none | Only the entries of the app with this id. |
| `lifecycle` | none | One of the five words. Anything else is `400`. |
| `limit` | 50 | Most entries in the page. Above 500 it is 500; `0` is `400`. |
| `after` | none | The `next` of the previous page. |

```json
{
  "version": 12,
  "total": 3,
  "items": [
    {
      "tenant": "acme", "app": "pets", "declared_by": "podkit",
      "id": "pets", "version": "1", "title": "Pets", "description": "The pet store API.",
      "lifecycle": "deprecated", "sunset": "2027-03-01",
      "successor": { "id": "pets", "version": "2" },
      "routers": ["pets-v1"], "hosts": ["api.acme.test"], "published": true,
      "openapi": { "name": "pets-api", "title": "Pets", "version": "1.0.0", "dialect": "3.1", "operations": 14 }
    }
  ],
  "truncated": true,
  "next": "acme/pets/1"
}
```

- `version` is the live snapshot's version. `total` counts the entries the filters select, wherever the cursor is.
- Always present on an item: `tenant`, `app`, `declared_by`, `id`, `version`, `lifecycle`, `routers`, `hosts` (the literal hosts the named routers claim, sorted, `*.base` for a wildcard), `published`. Absent, never `null`, when not declared: `title`, `description`, `sunset`, `successor`, `openapi`.
- Entries are sorted by `(tenant, id, version)` as text, which is unique, so it is the cursor: `next` and `after` are `<tenant>/<id>/<version>`. It is a key, not an offset: a swap between two pages never repeats or skips an entry that stays, and a cursor whose entry is gone still works. A cursor that is not three parts is `400`.
- `truncated` and `next` appear together when the page ended before the selection did, by `limit` or by the cap.
- Fields are only ever added. A reader ignores the ones it does not know. The federation exporter (`docs/ref/federation.md`) reads `version`, `total`, `items`, `truncated` and `next` and every item field above from this answer, on the read socket too (`docs/ref/admin-tools.md`, `## The read socket`), so a field is never renamed or removed.

### Bounds and what is never shown

- The body is at most 4 MiB, the overview's cap, written by the overview's page writer. An entry that alone does not fit becomes a stub, `{"tenant","app","id","version","lifecycle","too_large":true}`, so a listing always makes progress.
- The catalog shares the overview's 8 slots of concurrent work: the ninth request gets `503 {"error":"catalog is busy"}` with `retry-after: 1`. The work runs on the blocking pool.
- No secret: the item type lists its fields. The OpenAPI document, middleware configuration, header values and certificates have no field in it (`catalog_shows_no_document`).
- A tenant has no catalog endpoint. The admin socket is the operator's.

## Against Traefik Hub and Caddy

Traefik Hub's API management has an API catalog with versions and lifecycle stages; Caddy has none. Podgate keeps the catalog in the snapshot, next to the routers it describes, so it is reviewed, planned and rolled back with them. The lifecycle is enforced by the proxy itself, not only listed: a `retired` API cannot be reached by a tenant's mistake in another middleware, and reopening one shows in the plan.
