# Middleware `openapi`

Reference for the kind in `src/middleware/openapi.rs` (with `src/middleware/openapi/`). The model it plugs into is in `docs/architecture.md` (`### Middlewares`). It matches the OpenAPI request validation of Traefik Hub: a route carries an OpenAPI description, and a request that does not fit it is answered before it reaches the upstream.

```json
{
  "name": "api",
  "type": "openapi",
  "max_body_bytes": 65536,
  "document": {
    "openapi": "3.1.0",
    "info": { "title": "Pets", "version": "1.0" },
    "paths": {
      "/pets/{id}": {
        "get": { "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } }
        ] }
      }
    }
  }
}
```

`document` is the OpenAPI 3.0.x or 3.1.x document as a JSON object, inline in the snapshot (YAML is not accepted; the control plane converts it). It is not fetched and is not an operator file. `max_body_bytes` (default and ceiling 65536) is the largest JSON body that is checked. Unknown fields are `invalid_middleware`.

Responses are not validated: that needs the whole response held, which costs memory and latency for a check that finds bugs in the tenant's own service rather than attacks. `security`, `servers`, `webhooks`, `callbacks` and `responses` are not read (authentication is `jwt_auth`, `oidc` and the other auth kinds).

## What is checked, in this order

The first failure wins. The answer is `{"error": "request does not match the API description", "violations": [...]}` with at most 10 violations (`"truncated": true` when there were more). A violation is `{"in", "name"?, "pointer"?, "message"}`: where the problem is, the declared parameter name or a JSON pointer into the body, and a message built from the document, never a value from the request. The upstream is never dialled.

| # | Check | Status | Access log `reason` |
|---|---|---|---|
| 1 | No path template matches. Matching is on the normalized path the chain sees, exact, case-sensitive, a trailing slash counts. `{name}` fills a whole segment; `/files/{name}.json` is a mixed segment. A template with fewer templated segments is tried first, so `/pets/mine` beats `/pets/{id}`. | `404` | `openapi_unknown_path` |
| 2 | The path has no operation for the method (`HEAD` is not implied by `GET`). | `405` with `allow` listing the path's methods | `openapi_method` |
| 3 | The request has a body and the operation declares no `requestBody`: `400`. Or its `Content-Type` is missing or matches no media type of `requestBody.content` (exact, `type/*`, `*/*`, parameters ignored, the most specific wins): `415`. | `400`, `415` | `openapi_body`, `openapi_media_type` |
| 4 | A JSON body with a schema declares a length over `max_body_bytes` (`Expect: 100-continue` gets `417`, as with `buffering`). | `413` | `openapi_body_too_large` |
| 5 | Parameters: required ones present, every present one valid for its schema. | `400` | `openapi_parameter` |
| 6 | `requestBody.required` and the request has no body. | `400` | `openapi_body` |
| 7 | A JSON media type with a schema: the body is held, parsed strictly and checked. | `400`; `413` when a chunked body passes `max_body_bytes`; `408` after 30 seconds; `503` with `retry-after: 1` over budget | `openapi_body`, `openapi_body_too_large`, `openapi_too_complex` |

### Parameters

Path, query, header and cookie parameters by `required` and `schema`. A text value is tried as an integer, a number, a boolean and a string, in that order, and is valid when the schema accepts one of them, so `type` needs no special case: `{"type": "string"}` accepts `123`, `{"type": "integer", "minimum": 5}` refuses `3`. A schema that admits only arrays reads the value as a list: `form` repeated keys (`a=1&a=2`, the default for query and cookie), `form` with `explode: false` (comma), `spaceDelimited`, `pipeDelimited`, and `simple` for path and header. A scalar parameter given twice is a violation: a backend may read the first and the validator the other. Header names are case-insensitive; `Accept`, `Content-Type` and `Authorization` parameters are ignored, as the standard says. Query parameters the document does not declare pass.

Refused when the snapshot compiles (`unsupported_setting`): a parameter with `content`, `style` `deepObject`, `matrix` or `label`, an object schema, `allowEmptyValue: true`.

### The body

Only a JSON body (`application/json`, `application/*+json`) with a `schema` is held and checked. Any other media type, and a JSON media type with no schema, is checked for the media type only and streamed; the `buffering` middleware limits it. The held body is the one `buffering` and `plugin` use: Pingora's replay buffer, so `max_body_bytes` stops at 64 KiB, `retry` can send it to a second server, and the upstream gets it with the framing it came in with. When an earlier stage already holds the body, its bytes are used and nothing more is read or charged.

Fails closed: a body that is not valid JSON or not UTF-8, nested over 128 levels, that repeats an object key (a validator that reads the last value while a backend reads the first is a bypass), that breaks its schema, or that is too much to check (200,000 schema applications) is answered `400` and never forwarded.

Memory: the declared `Content-Length`, or `max_body_bytes` for a chunked body, is charged to the tenant's `max_buffer_bytes` (`TenantBudget::reserve_buffering`) before the first byte is read and held until the request ends. The parsed value is far larger than its text, so `length + 64 * (number of [ { and , bytes)` more is charged before the parse and released after the check; a tenant has to size `max_buffer_bytes` for about 2 MiB at the worst. A tenant that cannot take either charge gets `503 {"error":"buffering is over the tenant's budget"}` with `retry-after: 1`, a capacity refusal that auto-revert does not count. Refusals are counted in `podgate_tenant_buffering_refused_total`.

## Schemas

Both dialects are checked as written. Local `$ref` only (`#/components/...`); a remote one is `invalid_middleware`, because podgate never fetches a tenant's URL. A `$ref` cycle is `invalid_middleware`: recursive schemas are not supported, unroll the recursion to a fixed depth. Every schema keyword is either enforced, an accepted annotation, or refused when the snapshot compiles (`unsupported_setting` for a keyword the standard has, `invalid_middleware` for one it does not): a misspelled keyword is an error, not a hole.

| | Keywords |
|---|---|
| Both dialects | `type`, `enum`, `format`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`, `minLength`, `maxLength`, `pattern`, `items`, `minItems`, `maxItems`, `uniqueItems`, `properties`, `required`, `additionalProperties` (boolean or schema), `minProperties`, `maxProperties`, `allOf`, `anyOf`, `oneOf`, `not`, `$ref` |
| 3.0 only | `nullable` (with `type`; `null` still has to pass `enum`), boolean `exclusiveMinimum` and `exclusiveMaximum`; a single string `type`; an integer is a number without fraction or exponent; a `$ref` takes no siblings except annotations |
| 3.1 only | `type` as a string or an array (with `"null"`), `const`, `prefixItems`, numeric `exclusiveMinimum` and `exclusiveMaximum`, boolean schemas, a `$ref` with siblings (both apply), `1.0` is an integer, `jsonSchemaDialect` only the 2020-12 base dialect; `nullable` is refused |
| Annotations, accepted and not interpreted | `title`, `description`, `default`, `example`, `examples` (3.1), `deprecated`, `readOnly`, `writeOnly`, `xml`, `externalDocs`, `discriminator` (the `oneOf` it accompanies is what is enforced), `$comment`, `$defs` (3.1), `x-*` |
| Refused | `if`, `then`, `else`, `contains`, `patternProperties`, `propertyNames`, `dependencies`, `dependentRequired`, `dependentSchemas`, `unevaluatedProperties`, `unevaluatedItems`, `$id`, `$anchor`, `$dynamicRef`, `$schema`, `contentEncoding`, `contentMediaType`, and any other |

`format` is checked for `int32`, `int64`, `uuid`, `date`, `date-time` (RFC 3339), `ipv4` and `ipv6`; every other format is an annotation, as both standards allow. `pattern` runs on the `regex` crate (linear time, no look-around or back-references) and is refused when it does not compile within 256 KiB. `multipleOf` is exact for integers and tolerant (1e-9 relative) for floats. Numbers compare exactly for integers and as `f64` otherwise; `1` equals `1.0` in `enum`, `const` and `uniqueItems`.

## Limits

Constants, not settings: a tenant cannot raise them. Each is `invalid_middleware` when the snapshot compiles, except the last two, which refuse the request.

| Limit | Value |
|---|---|
| Serialized `document` | 1 MiB |
| `openapi` middlewares of one app, and their documents together | 16, 4 MiB |
| Nesting of the document | 64 |
| Paths, operations | 1,000, 4,000 |
| Parameters of one operation (path level included) | 64 |
| Compiled schemas of one document | 20,000 |
| Nodes one schema expands to once every `$ref` is followed (stops `$ref` fan-out) | 20,000 |
| Schema nesting, counting each `$ref` | 64 |
| `enum` values, `required` names, `properties` of one schema | 1,000 each |
| `allOf`, `anyOf`, `oneOf`, `prefixItems` branches | 100 |
| Media types of one request body | 32 |
| `pattern`: length, compiled size; patterns per document | 1,024, 256 KiB; 256 |
| JSON body nesting | 128 |
| Schema applications for one request | 200,000 |

## Order in the chain

The path the stage sees is the path it matches: put `openapi` after `strip_prefix` when the document's paths are relative to a base path (`servers[].url` is not applied). Put it after the auth kinds, so unauthenticated traffic is refused before a body is held, and after a `headers` stage that answers CORS preflights (a preflight is an `OPTIONS` request the document has no operation for, so it would be `405`).

## Plan

Removing the stage lists `openapi_validation_removed` and raising `max_body_bytes` lists `openapi_body_limit_loosened` in `posture_changes` of `POST /v1/snapshot/plan`. A changed document is not listed: schemas cannot be ordered by strength.

## For the API catalog

The compiled `Document` (`crate::middleware::openapi::Document`) is what change 0135 reads: `title()`, `version()`, `dialect()`, `operation_count()` and `operations()`. `GET /v1/explain` shows `{title, version, dialect, operations, max_body_bytes}` for the stage, never the document.

## Errors

| Code | When |
|---|---|
| `invalid_middleware` | An unknown field; `max_body_bytes` outside 1 to 65536; a `document` that is not OpenAPI 3.0.x or 3.1.x, has no `info.title`, `info.version` or `paths`, is over a limit above, has a remote `$ref`, a `$ref` that names nothing, a `$ref` cycle, an unknown schema keyword, a path parameter that is not in the template or not `required`, a `pattern` that does not compile |
| `unsupported_setting` | A schema keyword that is refused (table above), a `$ref` on a path item, a parameter style or `content` podgate does not enforce, `allowEmptyValue`, a `jsonSchemaDialect` other than 2020-12 |
