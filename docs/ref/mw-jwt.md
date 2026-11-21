# Middleware `jwt_auth`

Reference for the kind in `src/middleware/jwt_auth.rs` and `src/middleware/jwt_auth/` (`verify.rs`: tokens, keys, signatures; `claims.rs`: the claim rules; `jwks.rs`: the JWKS fetch and its cache). The model it plugs into is in `docs/architecture.md` (`### Middlewares`, rules 2 to 5).

Lets a request through only when it carries a valid JSON Web Token, signed with a key from a static set or a JWKS endpoint. It is a resource-server verifier: it checks tokens somebody else issued and never issues one (login flows are another middleware). Traefik has no JWT middleware outside Traefik Hub, and Caddy needs a plugin (`caddy-jwt`).

```json
{
  "name": "api-auth",
  "type": "jwt_auth",
  "jwks_uri": "https://10.0.0.7:8443/.well-known/jwks.json",
  "transport": "internal",
  "algorithms": ["RS256", "ES256"],
  "issuer": "https://idp.example",
  "audiences": ["api"],
  "required_claims": {"role": ["admin", "ops"]},
  "forward_claims": {"sub": "X-User", "email": "X-Email"},
  "remove_token": true
}
```

| Field | Meaning |
|---|---|
| `algorithms` | Required. A non-empty list of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `EdDSA`, `HS256`, `HS384`, `HS512`. `none` and anything else is `invalid_middleware`, as is a repeat. More than 4 of `RS*` and `PS*` together are refused: each costs a modular exponentiation per request. `HS*` needs an `oct` key in `keys`. |
| `keys` | An inline JWK set, `{"keys": [...]}`: RSA, EC (`P-256`, `P-384`), OKP (`Ed25519`) and `oct`. At most 100 keys; a `kid` may not repeat. A key that cannot verify is `invalid_middleware`, never skipped: RSA under 2048 or over 8192 bits, an exponent under 65537 or even, a curve this verifier lacks, a private part (`d`, `p`, `q`...), a `use` other than `sig`, `key_ops` without `verify`, an `alg` the key type cannot serve, an `oct` key under 32 bytes. |
| `jwks_uri` | A JWKS endpoint, fetched in the background. An absolute `http://` or `https://` URL whose host is an IP literal; a host name is `invalid_middleware` (the resolver is not wired for JWKS yet), as are `h2c://` and credentials in the URL. `keys`, `jwks_uri` or both are required. A plain `http://` URL is allowed only for an address the upstream address policy permits the tenant (it always checks, see below). |
| `transport` | Name of a `servers_transport` of the app: CA, SNI and client certificate of an `https://` `jwks_uri`. Without `jwks_uri` it is `invalid_middleware`; an undeclared name is `unknown_transport`. |
| `jwks_refresh_secs` | How long a fetched set is fresh. Default 3600, clamped to 60 to 86400. |
| `issuer` | When set, `iss` must be this string. |
| `audiences` | When set, `aud` (a string or a list) must hold one of these. |
| `required_claims` | `{name: value}` or `{name: [values]}`: the claim must equal the value, or one of them. A claim that is a list matches when it holds one. Values are strings, numbers or booleans. At most 32. |
| `leeway_secs` | Clock skew allowed on `exp`, `nbf` and `iat`. Default 30, at most 300. |
| `max_token_age_secs` | When set, `iat` is required and the token may be at most this old (plus the leeway). |
| `token_sources` | The places a token may be, in order: `{"header": "authorization", "scheme": "Bearer"}`, `{"cookie": name}`, `{"query": name}`. Default the Bearer header. A `header` other than `authorization` may leave out `scheme` (the whole value is the token). The first place that holds a token decides; a place that holds two (two `Authorization` headers, a cookie or a parameter twice) is refused, never guessed at. **A token in a query string is logged by every proxy, browser history and referrer on the way: use it only where a client cannot send a header.** |
| `forward_claims` | `{claim: header}`. Copies a verified claim into a request header. A string as it is, a number or boolean as JSON writes it, a list of those joined with `, `. An object, `null` or a value that is not printable ASCII is not copied. Reserved headers (`docs/ref/mw-forward-auth.md`), `Authorization`, `Cookie`, `Host` and a header that holds the token are `invalid_middleware`. |
| `remove_token` | Removes the credential from the request that goes on, from every configured source: the header, the cookie pair (the other cookies stay), the query parameter (the rest of the query stays). |

Unknown fields are `invalid_middleware`: a setting is never ignored.

## What is checked

1. The token is read from the first place that has one, up to 8 KiB. Missing is `401`.
2. The header is read. `crit` is refused whole. `alg` must be a string in `algorithms`; `none`, an unknown name and an unlisted one fail here, before any key is touched. `kid` must be a string.
3. The key is chosen by `kid`. A token without `kid` is tried against the keys whose type fits its `alg`, at most 4. A key has a type and an algorithm needs one: an RSA key serves `RS*` and `PS*` only, an EC key the one curve of its algorithm, an Ed25519 key `EdDSA`, an `oct` key `HS*` only (and only when it is as long as the hash). The classic algorithm confusion, an HS256 token signed with an RSA public key as the secret, finds no key. A key whose JWK names an `alg` serves that algorithm only.
4. The signature is checked by `ring` (RSA PKCS#1 and PSS with 2048 to 8192 bit moduli, ECDSA with fixed-size signatures, Ed25519, HMAC in constant time). Base64url is strict: no padding, no stray bits.
5. The claims. `exp` is required (a missing or non-numeric one is `401`) and the token is expired from `exp + leeway` on. `nbf` and `iat` may not be in the future beyond the leeway. `iss`, `aud` and `max_token_age_secs` when configured. All of these are `401`.
6. `required_claims`. A token that passed everything above and lacks one is `403`.

The signature checks run on the request task: they cost tens of microseconds for ES256 and RS256, and the algorithm list is bounded for that reason.

## What the client and the upstream see

| Outcome | Answer |
|---|---|
| no token, or any check of 1 to 5 failed | `401`, `WWW-Authenticate: Bearer realm="podgate", error="invalid_token"`, `{"error":"unauthorized"}`, `Cache-Control: no-store`. The body never says which check failed. |
| signature valid, `required_claims` do not match | `403 {"error":"forbidden"}` |
| no keys: the JWKS cannot be had and nothing is cached | `503 {"error":"authentication unavailable"}` |
| accepted | The request continues. The headers named in `forward_claims` are first removed from the client's request, then set from the verified claims. |

The reason is in the access log field `reason` (`jwt_missing`, `jwt_oversized`, `jwt_malformed`, `jwt_alg_not_allowed`, `jwt_crit`, `jwt_unknown_kid`, `jwt_no_key`, `jwt_bad_signature`, `jwt_missing_exp`, `jwt_expired`, `jwt_not_yet_valid`, `jwt_issued_in_future`, `jwt_too_old`, `jwt_bad_issuer`, `jwt_bad_audience`, `jwt_claims_forbidden`, `jwks_unavailable`) and in the metrics below. The token is never logged, and the headers a stage copies from it are the only part of it that leaves the proxy.

The stage runs in the chain, before a revision is chosen and before any tenant slot, backend permit or wake-up: unauthenticated traffic costs a signature check and nothing else. A `401` or `403` is a `4xx`, so it does not move the `5xx` ratio auto-revert watches; a `503` for missing keys is not a capacity refusal and does.

## The cache

A request whose token was accepted carries an identity (the copied claims, whatever the `Authorization` header said) that the cache key does not hold. The `cache` stage therefore neither serves nor stores it, whatever the token source and also after `remove_token`, as for `forward_auth` and for a request with `Authorization` or `Cookie`.

## Mirrors

The headers `forward_claims` writes, and the header the token came in when `remove_token` is off, are identity: a copy of the request sent to a `mirroring` service drops them unless the mirroring is set to `forward_credentials` (`Kind::carries_identity`). A token read from a query parameter that is not removed stays in the URL of the copy: set `remove_token` where a mirror is in use.

## The JWKS

- **Fetch.** One `GET` through the bounded HTTP/1.1 client of `forward_auth`: the connection of the peer a service would use (so the named transport gives an `https://` endpoint its CA, name and client certificate), the exact IP checked against the upstream address policy (`docs/ref/upstream-policy.md`) before every dial, a body cap of 256 KiB, a timeout of 5 seconds, no redirects (a `3xx` is a failure), at most 100 keys used. The policy is also checked when the snapshot is compiled: a `jwks_uri` the policy refuses for the tenant (loopback, link-local, outside its allow list) is `upstream_forbidden`. The fetch is made on behalf of the tenant of the app that declares the middleware, so one tenant's policy never approves a fetch for another.
- **Memory.** A fetch charges 256 KiB plus 14 KiB of buffers to the tenant's `max_buffer_bytes` before it dials. A tenant whose budget is under that is `invalid_middleware` at compile time; a budget that is only full right now fails that fetch. A tenant uses at most 8 distinct `jwks_uri`.
- **Single flight.** One fetch per middleware is in flight at a time; every request that needs keys then waits for it. The keys are cached per middleware and survive a snapshot push that leaves the declaration as it was.
- **When.** A set younger than `jwks_refresh_secs` is used as it is. An older one is used while one request starts a refresh in the background. The set a failed refresh leaves is kept (stale) for 24 hours past its refresh time; a failed refresh is not retried for 10 seconds. A token whose `kid` no key has refreshes the set once, at most once per 10 seconds, and waits for it. With no keys at all the request gets `503`.
- **Keys.** A key of the endpoint that cannot be used (too weak or too strong an RSA key, a private part, an unsupported type or curve, an `oct` key: a shared secret never comes from an endpoint) is left out; an answer with no usable key is a failure and keeps the old set. `keys` and the endpoint's keys are both used, the inline ones first.
- **Not a fallback.** When `jwks_uri` is set and no keys can be had, even a token that an inline key would verify gets `503`: the stage fails closed on a keyset it cannot complete.

## Posture

`POST /v1/snapshot/plan` lists in `posture_changes`, per host:

| Kind | When |
|---|---|
| `jwt_auth_removed` | the middleware is gone |
| `jwt_auth_algorithm_added` | an algorithm a token could not name before |
| `jwt_auth_required_claims_loosened` | a required claim is gone or accepts more values |
| `jwt_auth_leeway_increased` | `leeway_secs` grew |
| `jwt_auth_issuer_loosened` | `issuer` was set and is gone or another |
| `jwt_auth_audience_loosened` | `audiences` were set and are gone or accept one more |
| `jwt_auth_key_added` | an inline key, or a `jwks_uri`, that was not trusted |
| `jwt_auth_max_token_age_loosened` | `max_token_age_secs` was set and is gone or longer |
| `jwt_auth_token_source_added` | a place a token is read from that was not |
| `upstream_tls_verification_disabled` | the transport of an `https://` `jwks_uri` stopped verifying |

## Metrics

| Series | Type | Labels |
|---|---|---|
| `podgate_jwt_auth_verified_total` | counter | `app`, `middleware` |
| `podgate_jwt_auth_rejected_total` | counter | `app`, `middleware`, `reason` (only reasons seen) |
| `podgate_jwt_auth_jwks_fetches_total` | counter | `app`, `middleware`, `result` (`ok`, `error`) |
| `podgate_jwt_auth_jwks_keys` | gauge | `app`, `middleware` |

## Explain

`GET /v1/explain` shows the stage's algorithms, the `kid` and type of its inline keys (never the key material), the `jwks_uri` without its query, the rules (`max_token_age_secs` shown as `max_age_secs`), the `sources` (`token_sources`), `forward_claims` and `remove_credential` (`remove_token`): the overview refuses a field named like a secret.
