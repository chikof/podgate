# Middleware `oidc`

Protects a web app with an OpenID Connect login (authorization code flow with PKCE). Code: `src/middleware/oidc.rs` and `src/middleware/oidc/{flow,session,discovery}.rs`; tests `tests/mw_oidc.rs`.

**The session is the cookie.** It is encrypted under a key derived from the snapshot's `skew_secret`; podgate keeps nothing per user. The price: logout is local (the provider is not told), and a person whose access is revoked at the provider stays signed in until their cookie ends (at most `session.max_age_secs`, and never past the ID token's `exp`).

Traefik has no OIDC outside Traefik Hub (and a community forward-auth pattern with `oauth2-proxy`); Caddy needs the `caddy-security` plugin. Not built, on purpose: refresh tokens, a `userinfo` call, dynamic client registration, single logout from the provider, any flow but the authorization code flow.

```json
{ "name": "login", "type": "oidc", "issuer": "https://idp.example/realms/main",
  "client_id": "podgate-app", "client_secret": "...", "scopes": ["openid", "email"],
  "allowed_algorithms": ["ES256"], "forward_claims": {"email": "X-Email"},
  "required_claims": {"email_verified": true}, "session": {"max_age_secs": 28800} }
```

## Configuration

| Field | Meaning |
|---|---|
| `issuer` | Required. An absolute `http(s)` URL (IP literal or host name, no query or fragment). Its discovery document is `<issuer>/.well-known/openid-configuration`; the document's `issuer` must equal this string byte for byte. |
| `client_id` | Required. Must be the ID token's `aud`. |
| `client_secret` | Optional. Absent: a public client, PKCE only. Present: sent with `client_secret_basic` (both parts form-encoded). Redacted in `Debug`, explain (`client_authentication`) and the overview. |
| `scopes` | Default `["openid"]`; must include `openid`. |
| `redirect_path` | Default `/_podgate/oidc/callback`. Reserved on the route: the middleware answers it itself. The redirect URI is the request's scheme and host plus this path. |
| `logout_path` | Optional, reserved the same way. Clears the session cookie and answers `302` (`303` for a non-`GET`) to `/`. |
| `allowed_algorithms` | Default `["RS256"]`; as `jwt_auth` (`HS*` refused: a provider's JWKS never holds a shared secret). |
| `session` | `max_age_secs` (default 28800, 1 to 604800), `cookie_name` (default `__Host-podgate_oidc`), `same_site` (`Lax` default, `Strict`, `None`). Give two `oidc` apps on one host different cookie names. |
| `forward_claims` | `{claim: header}`, as `jwt_auth`. The headers are removed from the client's request first. |
| `required_claims` | As `jwt_auth`; a signed-in person who lacks one gets `403` at the callback. |
| `allow_subjects` | Optional list of admitted `sub` values (1 to 256). |
| `transport` | A `servers_transport` of the app for the calls to the provider (CA, SNI, client certificate). |

`skew_secret` must be in the snapshot (`invalid_middleware` otherwise). A tenant uses at most 4 distinct issuers, and its `max_buffer_bytes` must cover one call (about 270 KiB).

## The flow

1. A request without a valid session that can follow a redirect (`GET`, `Accept` has `text/html`, no `X-Requested-With`) gets `302` to the `authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, a random `state` and `nonce` (128 bits each) and the S256 `code_challenge`. Every other request without a session gets `401` with `WWW-Authenticate: Bearer`, so a script never receives an HTML redirect.
2. The flow cookie `__Secure-podgate_oidc_flow` (`Path=<redirect_path>`, `Max-Age=300`, `HttpOnly`, `Secure`, `SameSite=Lax`) holds the state, the PKCE verifier, the nonce and the requested path, sealed with ChaCha20-Poly1305. A second login in another tab replaces it.
3. The callback checks the cookie (opens, not expired, this host, this app and middleware) and the `state`, then redeems the code at the `token_endpoint` and verifies the ID token with the `jwt_auth` machinery: signature from the provider's JWKS, `iss`, `aud`, `exp`, then `nonce`, `azp` when there are several audiences, `sub`, `allow_subjects`, `required_claims`.
4. The session cookie (`Path=/`, `HttpOnly`, `Secure`, no `Domain`, `SameSite` as set) holds `sub` and the claims named in `forward_claims` and `required_claims`, ends at the smaller of the ID token's `exp` and `max_age_secs`, and is at most 3584 bytes: over it, only `sub` stays and `podgate_oidc_claims_dropped_total` counts it. Then `302` to the stored path. A stored target that is not a relative path starting with exactly one `/` (no `//`, no `/\`, no control character, at most 2000 bytes) is replaced with `/`.

A session that does not open, is expired, was issued for another host, another app or another middleware, or under another declaration of this middleware (any change of its configuration) starts the flow again. A session cookie never reaches the upstream.

## Answers

| Case | Answer |
|---|---|
| no session, cannot redirect | `401`, `WWW-Authenticate: Bearer` |
| callback without flow cookie, with another `state`, repeated or missing parameters, not a `GET` | `400 {"error":"bad request"}` |
| provider refused the code, ID token invalid, nonce differs | `401 {"error":"unauthorized"}` |
| provider answered the authorization request with `error`, `required_claims` or `allow_subjects` not met | `403 {"error":"forbidden"}` |
| provider, document or keys cannot be had | `503 {"error":"authentication unavailable"}`; existing sessions keep working |
| no room for a token call (32 per node, or the tenant's budget) | `503`, `retry-after: 1` |

The access log `reason` names the cause (`oidc_state_mismatch`, `jwt_bad_signature`, ...). The stage runs before a revision and before any tenant slot: unauthenticated traffic costs a redirect and nothing else.

## Calls to the provider

Discovery (cached 1 hour, stale up to 24 hours when refreshing fails), JWKS (as `jwt_auth`) and token calls use the bounded HTTP/1.1 client of `forward_auth`: a host name is resolved once per call and every answer is checked against the upstream address policy for the tenant, the first permitted address is dialled, the name is `Host` and SNI, no redirects, 256 KiB and 5 seconds, charged to `max_buffer_bytes`. An `https` issuer never delegates to an `http` endpoint. A provider whose document lists what it supports must support `code`, `authorization_code`, PKCE `S256` and the client authentication in use.

## Caches, logs, mirrors

A request with a session is credentialed: the `cache` stage neither serves nor stores it. The claim headers are identity headers a mirror does not get. The code and state of a callback are `[redacted]` in the access log and failed-request records (`jwt_auth::Credentials`); `Cookie` is redacted or dropped everywhere; the client secret appears only in the token request.

## Posture

`oidc_removed`, `oidc_session_longer`, `oidc_required_claims_loosened`, `oidc_subjects_loosened`, `oidc_algorithm_added`, `oidc_provider_changed` (issuer or client), `upstream_tls_verification_disabled`.

## Metrics

`podgate_oidc_logins_total{result=started|completed}`, `podgate_oidc_sessions_total`, `podgate_oidc_refused_total{reason}`, `podgate_oidc_claims_dropped_total`, `podgate_oidc_fetches_total{what,result}`; all with `app`, `middleware`.
