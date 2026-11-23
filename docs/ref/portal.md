# Developer portal

Reference for the `portal` middleware in `src/middleware/portal.rs` and `src/middleware/portal/` (`access.rs`: who sees what; `list.rs`: the list; `document.rs`: the view of an OpenAPI document; `pin.rs`: the operator's pin), and the page in `portal/`. A read-only web site where API consumers browse the APIs their own tenant published and read each API's OpenAPI description. It matches the API portal of Traefik Hub's API management; Caddy has none. The deliberate differences: it has no accounts and no secret of its own, a viewer sees one tenant's APIs only, a document is shown through a filter, and it is off unless the operator lists an app for it.

```json
{ "name": "portal", "type": "portal", "tenant_claim": "tenant" }
```

| Field | Meaning |
|---|---|
| `tenant_claim` | The string claim of the login's verified claims that names the viewer's tenant. Default `tenant`. 1 to 64 letters, digits and `-_.:`. Unknown fields are `invalid_middleware`. |

## What it is

A middleware kind: a stage in the chain of a router that answers the request itself, like `respond`, so it never dials an upstream and takes no tenant slot. There is no second listener, no address to bind and no `Host` check of its own: the route's entry point, TLS, hosts and the other stages of the chain apply as they do to any route. The router still names a service, as every router does, and it is never used.

It has no login, session or user store. The login is the `jwt_auth` or `oidc` stage in front of it, and the stage reads the viewer's tenant from the claims that stage verified (`RequestCx::claims`, the object `opa` also reads). It never reads a header, the query or the path to decide who is asking. Accounts and API key issuance need a user store podgate, which keeps no state on disk, does not have, and are not built.

## What is served

| Request | Answer |
|---|---|
| `GET /`, `GET /app.js`, `GET /style.css` | The page, compiled into the binary from `portal/`. The same bytes for every viewer, so a person whose login names no tenant still gets the page, which tells them so. `cache-control: no-cache`. |
| `GET /api/catalog?limit=&after=&q=` | The viewer's entries, sorted by `(id, version)` as text. See below. |
| `GET /api/catalog/{tenant}/{id}/{version}/openapi` | The portal's view of the entry's OpenAPI document, `application/json`. |
| any other path | `404 {"error":"not found"}`, whatever the method. |
| another method on a path above | `405 {"error":"method not allowed"}` with `allow: GET, HEAD`. `HEAD` has the headers and no body. |

Not served, ever: the admin API, the event feed (which carries certificate private keys), failed-request records, audit records, the snapshot, the plan, metrics, `/healthz` and `/readyz`. They are not routes of this stage, so they answer `404`; the page cannot show them because they are not reachable from it.

### The list

`limit` (default 25, 1 to 100, larger is 100), `after` (`<id>/<version>`, the `next` of the previous page, at most 512 bytes) and `q` (a case-insensitive part of the id, title or description, at most 64 bytes). Any other parameter, a repeated one, a bad value or a query over 2 KiB is `400 {"error":"invalid query"}`; the text never says what was wrong or repeats anything the client sent.

```json
{
  "total": 3,
  "items": [
    {
      "tenant": "acme", "id": "pets", "version": "1",
      "title": "Pets", "description": "The pet store API.",
      "lifecycle": "deprecated", "sunset": "2027-03-01",
      "successor": { "id": "pets", "version": "2" },
      "hosts": ["api.acme.test"],
      "openapi": { "title": "Pets", "version": "1.0.0", "dialect": "3.1", "operations": 14 }
    }
  ],
  "truncated": true,
  "next": "pets/1"
}
```

- `total` counts the viewer's own entries that match `q`, wherever the cursor is.
- Shown per entry: `tenant` (the viewer's own), `id`, `version`, `title`, `description`, `lifecycle`, `sunset`, `successor`, `hosts`, `openapi` (the title, version, dialect and operation count of the described document). Never shown: the app id, the declaring source, router and middleware names, `published`, any configuration, the snapshot version, anything about another entry or tenant.
- Absent, never `null`, when not declared: `title`, `description`, `sunset`, `successor`, `openapi`. `description_cut: true` says the description was cut at 4096 bytes; a `title` is cut at 256 and at most 16 `hosts` are listed, with `hosts_more` for the rest.
- `successor` is shown only when the viewer may see the successor too. An unpublished successor is unpublished: naming it would say it exists.
- A page ends early, with `truncated` and `next`, at the limit or when the next entry would take it over 1 MiB.

## Who sees what

A viewer sees an entry when all of these hold, in this order:

1. The viewer is a tenant: the claim `tenant_claim` of the login's verified claims is a string of 1 to 128 visible ASCII characters with no whitespace. A missing claim, a number, a list, an object, a blank or oversized string, a value such as `a, b` and no claims at all make the viewer anonymous.
2. The entry's tenant is that tenant, by exact byte equality.
3. The entry is published (`published: true`, `docs/ref/catalog.md`): the tenant's consent to appear on the portal.
4. Its lifecycle is `preview`, `stable` or `deprecated`. A `draft` and a `retired` entry are never shown.

There is no operator view and no cross-tenant view: `published` is a tenant's consent to appear on the portal, not an audience. An operator reads every tenant's entries on the admin socket (`GET /v1/catalog`). A shared or public portal needs an audience on the entry and a decision of its own, and is not built.

An anonymous viewer gets `401 {"error":"unauthorized"}` on every `/api/` path, whatever exists. For a viewer, an entry of another tenant, an unpublished one, a `draft`, a `retired` one and one that does not exist are the same `404 {"error":"not found"}`, byte for byte, with no echo of the path, the tenant, the id or the query. A tenant in the path must be the viewer's tenant.

It is enforced where entries are produced, not where they are printed. `access.rs` is the only file of the portal that reads the compiled catalog: it tests the viewer's tenant on an app before it reads any of that app's entries, and it hands the rest of the portal a `Visible` value, so the code that writes a list or a document cannot be given another tenant's entry. The test `portal_reads_catalog_only_through_access` fails when another file names the catalog's accessors. The portal reads the live table once per request and keeps nothing: there is no server-side cache, nothing is keyed by viewer, and every `/api/` answer is `cache-control: no-store` with no `ETag` or `Last-Modified`.

## Who may declare it

Only the operator's apps may, and only behind the operator's own login. The setting is in the process environment, which a snapshot cannot write:

| Setting | Meaning |
|---|---|
| `PORTAL_APPS` | Comma separated `tenant/app=<issuer>\|<source>\|<audience>` entries, one per app that may declare a `portal` middleware. `<source>` is `jwks:<url>` (a `jwt_auth` stage with exactly that `jwks_uri`), `keys:<64 hex digits>` (a `jwt_auth` stage with exactly those inline keys, no `jwks_uri`) or `oidc` (an `oidc` stage; its keys come from the discovery document of the issuer). `<audience>` is the one audience the login accepts: the `jwt_auth` `audiences` list is exactly `[<audience>]`, the `oidc` `client_id` is `<audience>`. Unset or empty: no app may, so the portal is off. A malformed entry (no `=`, no `/` or more than one, no `\|`, a missing or empty audience, an unknown source, a `keys:` that is not 64 hex digits, a repeated app) stops startup naming the entry's position in `PORTAL_APPS` and never printing it. A comma inside a URL is not supported. |

```
PORTAL_APPS=ops/portal=https://idp.example/realms/main|oidc|podgate-portal
```

**List only apps whose login you control.** The claims the portal trusts come from the login stage of the listed app, so whoever can change that stage's issuer or keys can mint any viewer. That is why the pin is checked, not trusted.

Three checks run when a snapshot compiles, and a snapshot that fails one is refused whole with `422`:

| Code | When |
|---|---|
| `portal_not_allowed` | An app that is not listed declares a `portal` middleware. The app is matched by its tenant and id as two whole strings, so an id with `/`, `=`, `\|` or `,` never matches a listed pair. The message names nothing of the operator's list. |
| `portal_needs_login` | In some router chain of a listed app the portal has no `jwt_auth` or `oidc` stage before it. The compiler reads the compiled stages, so a `chain` middleware or a renamed declaration does not hide it. |
| `portal_login_not_pinned` | A stage before the portal that fills claims does not verify with exactly the pinned issuer, key source and audience. The text is fixed (`the login in front of the portal is not the one the operator pinned for this app`) and names neither the pin nor the stage's settings. |

The pin is over the issuer, the key source and the audience together. The issuer alone would not be enough: the owner of the app could keep the issuer string and point `jwks_uri` or the inline keys at keys of their own. The issuer and keys alone would not be enough either: they could keep both and take tokens issued to another client of the same provider.

- A `jwks:` pin accepts a `jwt_auth` with that `issuer` and that `jwks_uri` and no inline `keys`. A `keys:` pin accepts a `jwt_auth` with that `issuer` and inline `keys` whose fingerprint it is, and no `jwks_uri`. An `oidc` pin accepts an `oidc` stage with that `issuer`. The pin names the stage kind: `jwks:` and `keys:` accept `jwt_auth` only, `oidc` accepts `oidc` only. The issuer and the URL are compared as written, byte for byte.
- A login that cannot be written down as a pin never matches: a `jwt_auth` with no `issuer`, with an `HS*` algorithm or an `oct` key (a shared secret is not a pin), with both `keys` and `jwks_uri`, with no `audiences` or more than one, or naming a `transport` (its CA and server name are part of where the keys come from); an `oidc` naming a `transport`. A private CA for the identity provider is therefore not supported.
- The audience is pinned too: a `jwt_auth` must have `audiences` exactly `[<audience>]`, one entry, so it cannot accept a second client's tokens, and an `oidc` stage must have `client_id` equal to `<audience>`. Without it the owner of the login could keep the issuer and the keys and use another client of the same identity provider, whose claim mapping the operator does not control, to mint any `tenant` claim.
- Every stage before the portal that fills claims must match, not just the last one. A stage kind that puts claims into the request state must say how it verifies (`Kind::login`); `jwt_auth` and `oidc` do, and the test `portal_claims_writers_report_login` fails when another kind sets claims without it.
- `oidc` has no JWKS or discovery override, and its configuration refuses unknown fields, so no setting changes where its keys come from.

The fingerprint of an inline key set is the SHA-256, as 64 lowercase hex digits, of the RFC 7638 thumbprints of its keys, sorted as text and joined by a newline. It covers public members only (`e`, `kty`, `n` for RSA; `crv`, `kty`, `x`, `y` for EC; `crv`, `kty`, `x` for OKP), so a `kid`, `use` or `alg` does not change it. Compute it from a JWK set in `keys.json`:

```
jq -r '.keys[] | if .kty=="RSA" then {e,kty,n} elif .kty=="EC" then {crv,kty,x,y} else {crv,kty,x} end | tojson' keys.json \
  | while read -r key; do printf %s "$key" | openssl dgst -sha256 -binary | basenc --base64url | tr -d =; echo; done \
  | LC_ALL=C sort | { printf %s "$(cat)"; } | sha256sum | cut -d' ' -f1
```

Where the secrets and trust anchors are. The portal needs no secret and adds none. The trust anchors are `PORTAL_APPS` (ids, an issuer, a key source and an audience: public values, kept in the environment so a snapshot cannot change them, never printed in an answer, an event, a log line or an error), the issuer, keys or `jwks_uri` and audience of the login stage in the operator's snapshot (checked against the pin on every compile), the existing `skew_secret` and `client_secret` of an `oidc` stage (redacted as for any `oidc` stage), and the claim name `tenant_claim`.

## The login in front

The operator's app declares the login, then the portal. The `oidc` stage copies a claim into its session only when the declaration names it, so name the tenant claim in `forward_claims` (the header it writes is of no use to the portal, which answers itself) or in `required_claims`.

```json
{
  "id": "portal", "tenant": "ops", "declared_by": "ops",
  "tls": { "mode": "acme" },
  "middlewares": [
    { "name": "login", "type": "oidc", "issuer": "https://idp.example/realms/main",
      "client_id": "podgate-portal", "client_secret": "...", "allowed_algorithms": ["ES256"],
      "forward_claims": { "tenant": "x-tenant" } },
    { "name": "portal", "type": "portal", "tenant_claim": "tenant" }
  ],
  "default_chain": ["login", "portal"],
  "routers": [{ "name": "portal", "match": { "host": "apis.example" }, "service": "unused" }],
  "revisions": [{ "id": "r1", "state": "serving", "weight": 100,
    "services": [{ "name": "unused", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:9" }] }] }]
}
```

with `PORTAL_APPS=ops/portal=https://idp.example/realms/main|oidc|podgate-portal` and the snapshot's `skew_secret`. This is the snapshot the test `portal_behind_oidc_route` pushes: a browser that has not signed in is sent to the provider and never reaches the portal; after login the page lists the tenant of the person's `tenant` claim and no other. A script's request without a session gets the login stage's own `401`.

With a token instead of a browser login, `jwt_auth` in front reads the claim from the verified token:

```json
{ "name": "login", "type": "jwt_auth", "jwks_uri": "https://10.0.0.7:8443/.well-known/jwks.json",
  "algorithms": ["ES256"], "issuer": "https://idp.example", "audiences": ["portal-web"] }
```

with `PORTAL_APPS=ops/portal=https://idp.example|jwks:https://10.0.0.7:8443/.well-known/jwks.json|portal-web` and `"audiences": ["portal-web"]` in the `jwt_auth` stage. An `oidc` session hands to the stages after it the claims that were verified from the ID token at login and sealed into its session cookie, and nothing else: a cookie the client changed, made up, took from another host or another declaration, or that has expired, does not open and yields no claims. The `opa` stage after an `oidc` stage sees those claims too (`docs/ref/mw-opa.md`).

Two things follow from the stage answering the request itself. The response hooks of the chain do not run on its answers, so a `headers` stage with HSTS does not add `Strict-Transport-Security`: set it on the entry point or in front. And a shared cache the operator runs elsewhere in front of the portal would serve one viewer's answer to another: `no-store` is on every `/api/` answer, so do not override it.

## What a document shows

The portal never shows the stored document as stored. It reads the compact text the compiled document keeps (`Document::source`) and shows a view of it: an allow list over the OpenAPI structure, so a keyword added to OpenAPI later is withheld until the list names it.

| Part | Shown |
|---|---|
| `openapi`, `info` (`title`, `version`, `summary`, `description`, `termsOfService`, `contact`, `license`), `tags`, `paths` with their operations, parameters, request bodies, responses and headers, `components` (`schemas`, `parameters`, `requestBodies`, `responses`, `headers`, `securitySchemes`, `pathItems`), `security`, `externalDocs` | Kept. |
| Schema keywords: `type`, `format`, `title`, `description`, `enum`, `const`, the numeric, string, array and object limits, `required`, `nullable`, `readOnly`, `writeOnly`, `deprecated`, `items`, `prefixItems`, `properties`, `additionalProperties`, `allOf`, `anyOf`, `oneOf`, `not`, `discriminator`, `$ref`, `$defs` | Kept. |
| `servers` and their variables | Removed. They hold internal addresses and often default tokens. The entry's `hosts` say where the API is served. |
| `example`, `examples`, `default`, `externalValue`, vendor extensions (`x-*`), `webhooks`, `callbacks`, `links`, `jsonSchemaDialect`, `$schema`, `$comment` | Removed. A property that is merely named `example` or `default` is a name, not a keyword, and stays. |
| The URLs of an OAuth flow and `openIdConnectUrl` | Removed. The scheme's `type`, `scheme`, `bearerFormat`, `in`, `name`, `description` and the scopes stay. |
| Every string that stays | Scrubbed: a PEM block, a JSON Web Token, a long credential after `Bearer`, `Basic` or `Token`, the password in `scheme://user:password@host`, and the keys of the common providers (AWS access keys, GitHub tokens, Slack tokens) become `[redacted]`. |

The scrub is a heuristic that catches the shapes credentials are pasted in. It cannot see a secret written as ordinary prose in a `description`. A tenant that sets `published: true` consents to the descriptions in its documents being read by its own users, and should write them accordingly. Links in a document (`externalDocs`, `contact.url`, `license.url`, `termsOfService`) are shown as text, never as links. The view only removes or shortens, so it is never larger than the 1 MiB the compiled document is capped at (`docs/ref/mw-openapi.md`).

## Browser hardening

Every answer, `401`, `404`, `405` and `400` included, carries:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'` (the dashboard's, `docs/ref/dashboard.md`) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` on every answer but the files of the page, which get `no-cache` |

The portal sets no cookie. The page is `portal/index.html`, `portal/app.js` (plain ES module, no build step) and `portal/style.css`, compiled in with `include_bytes!`. It has no inline script, no inline style, no event handler attribute and no `style` attribute, and loads nothing from another origin. Every string from the API was written by a tenant and is inserted as a text node with `textContent`, never parsed as HTML: the page script uses no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `new Function`. The one link the script writes is the document download, built from `encodeURIComponent` parts after `/api/catalog/`, which cannot be a `javascript:` URL. There is no "try it" button: a browser sending requests to an API is a separate decision.

## Limits

| What | Limit |
|---|---|
| Entries per page | 100 (default 25) |
| A page | 1 MiB; an entry that does not fit ends the page with `truncated` and `next` |
| A title, a description, hosts per entry | 256 bytes, 4096 bytes, 16 |
| Query string, cursor, search text | 2 KiB, 512 bytes, 64 bytes |
| A document | the 1 MiB of the `openapi` middleware, and the view is never larger |
| Answers computed at once, per stage | 4 (the work runs on the blocking pool); a fifth is `503 {"error":"portal is busy"}` with `retry-after: 1`, a capacity refusal that auto-revert does not count |

## Tests

`tests/portal.rs`: `portal_off_by_default`, `portal_only_listed_apps_may_declare`, `portal_tenant_cannot_mint_viewer`, `portal_needs_login_in_chain`, `portal_listed_app_other_issuer_refused`, `portal_listed_app_same_issuer_other_keys_refused`, `portal_listed_app_other_audience_refused`, `portal_unpinnable_login_refused`, `portal_pinned_login_accepted`, `portal_pin_not_in_errors_or_logs`, `portal_rule_names_only_the_asking_app`, `portal_claims_writers_report_login`, `portal_identity_only_from_verified_claims`, `portal_ignores_tenant_headers_and_query`, `portal_claim_must_be_a_string`, `portal_anonymous_gets_401`, `portal_lists_only_published`, `portal_viewer_sees_only_own_tenant`, `portal_same_id_in_two_tenants`, `portal_other_tenant_document_404`, `portal_other_tenant_search_empty`, `portal_other_tenant_cursor_leaks_nothing`, `portal_errors_echo_nothing`, `portal_never_caches_across_viewers`, `portal_unpublished_equals_unknown`, `portal_path_traversal_404`, `portal_follows_live_table`, `portal_serves_openapi_document`, `portal_document_withholds_servers_and_examples`, `portal_scrubs_credential_shapes`, `portal_shows_deprecation`, `portal_hides_unpublished_successor`, `portal_serves_assets_with_headers`, `portal_csp_on_every_response`, `portal_renders_tenant_text_as_text`, `portal_no_inline_script`, `portal_no_external_references`, `portal_script_never_parses_html`, `portal_methods_405`, `portal_admin_routes_are_404`, `portal_bounds_page_and_document`, `portal_reads_catalog_only_through_access`, `portal_claims_never_recorded_or_logged`, `portal_overview_and_schema_show_settings_only`. `tests/mw_oidc.rs`: `portal_behind_oidc_route`, `oidc_hands_session_claims_to_later_stages`, `oidc_claims_from_verified_session_only`, `portal_oidc_login_must_be_pinned`, `portal_oidc_other_client_refused`. Unit tests next to the code: `viewer_comes_only_from_a_string_tenant_claim`, `visible_needs_tenant_published_and_shown_lifecycle`, `find_compares_only_own_entries`, the projection and scrub tests of `document.rs`, `list_item_bounds_hold_the_page_under_the_cap`, `cursor_round_trips`, `portal_slots_cap_concurrent_answers`, `portal_apps_setting_parses_pins`, `portal_login_anchor_of_jwt_and_oidc`, `a_stage_holding_no_grant_cannot_compile_portal`, `openapi_document_keeps_source`.

## Against Traefik Hub and Caddy

| | Traefik Hub | Caddy | podgate |
|---|---|---|---|
| API portal | yes, with accounts and API keys | none | pages served by podgate from the catalog; no accounts, no keys |
| Who may see an API | the portal's own users and groups | | the viewers of the tenant that published it, decided from the verified claims of the login in front |
| Documents | shown as stored | | shown through a filter: no servers, examples, extensions or credential-shaped text |
| Off by default | | | yes: no app may declare it until `PORTAL_APPS` lists it |
| Who may turn it on | the operator | | the operator, and only behind the login the operator pinned |
