# Middleware `digest_auth`

Reference for the kind in `src/middleware/digest_auth.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`). It matches Traefik's `digestAuth` (Caddy has none) for clients that cannot send Basic credentials, with stateless nonces and a bounded replay table. Prefer `basic_auth` over TLS when the client can send it; Digest exists for clients and devices that can only do Digest.

```json
{
  "name": "auth",
  "type": "digest_auth",
  "users": [
    "alice:podgate:5b3c...64 hex digits, SHA-256...",
    "bob:podgate:0f9a...32 hex digits, MD5..."
  ],
  "realm": "podgate",
  "header_field": "x-user",
  "remove_header": true
}
```

| Field | Meaning |
|---|---|
| `users` | htdigest entries `user:realm:HA1`, where `HA1` is `hex(H(user:realm:password))`. Required, at most 4096, no duplicate user. |
| `realm` | The realm of the challenge, default `podgate`. Every entry's realm must equal it (`invalid_middleware` otherwise): an entry for another realm could never verify. |
| `qop` | Optional. Only `auth` is accepted. `auth-int` digests the request body, which podgate does not buffer for authentication, so it is `invalid_middleware`. |
| `header_field` | A request header that receives the user name once the user has authenticated. Whatever the client sent for it is replaced. `Host`, the framing headers, `Proxy-*` and `Authorization` are refused. |
| `remove_header` | Remove `Authorization` before the request goes to the upstream. **Default `true`**, unlike Traefik: the upstream has no use for the response, and one it could keep is not worth handing out. Set `false` to forward it. |

Unknown fields are `invalid_middleware`. There is no `usersFile`: podgate keeps no disk state, the control plane inlines the entries.

## Algorithms

The algorithm of a user is the length of its `HA1`: 64 hex digits is `SHA-256`, 32 is `MD5` (upper or lower case). Any other length, or a non-hex digit, is `invalid_middleware`; the message never repeats the entry.

MD5 is accepted only because existing htdigest files are MD5 and the protocol was designed around it. It is a weak hash: prefer `SHA-256` entries (`printf 'user:realm:password' | sha256sum`). A user is verified only with the algorithm of its own `HA1`: a client that answers a SHA-256 user with an MD5 digest, or the other way round, is refused, so MD5 cannot be used to downgrade a SHA-256 user. `-sess` variants and `userhash` are not supported.

The challenge carries one `WWW-Authenticate` header per offered algorithm (RFC 7616 section 3.7), `SHA-256` first and `MD5` after it. An algorithm is offered only when some user has an `HA1` for it, so a client that picks the first one it understands is never sent to a digest nobody can answer. A client that sends no `algorithm` is taken to mean `MD5`, as RFC 7616 says.

## Nonces and replay

- A nonce is `base64url(timestamp || serial || HMAC-SHA256(secret, timestamp || serial || client_ip))`. Nothing is stored when one is issued. The serial is a per-middleware counter, so two clients that ask in the same second never share a nonce (and an `nc` counter). The client IP is the resolved client (`docs/ref/client-ip.md`), so a nonce cannot be used from another address.
- The secret, the replay table and the failure counter are one piece of state per (app, middleware name, fingerprint of its declaration), kept outside the compiled table in the shared `middleware::state::Registry` and settled in `TableHandle::swap` (rule 5 of the extension contract). A push that leaves the middleware alone keeps all three: outstanding nonces stay valid, spent `nc` values stay spent and failures stay counted, so a push is not a free reset for an attacker and does not re-challenge every client. A change to the middleware's own declaration starts fresh (new secret, empty table), and a removed middleware's state is freed with the last table that held it. The secret is random per state, not per process, and moves together with the replay table, so a nonce is never valid against a table that has forgotten it.
- A nonce is good for five minutes. An older nonce that was issued by this middleware and answered with a **correct** digest gets `401` with `stale=true`: the client retries with the new nonce without asking the user again. Stale is not announced for a wrong digest, so it tells a prober nothing. A nonce dated in the future, or one with a wrong tag, is simply invalid.
- `nc` must be eight hex digits and strictly greater than the last `nc` accepted for that nonce. The highest `nc` per nonce is kept in a table of at most **4096** nonces per middleware. An entry is created only after a correct digest, so only a client that knows a password adds entries, and it lives until its nonce expires (then it is swept, at most once a second). Each entry is **charged 128 bytes to the tenant's `max_buffer_bytes`**.
- When the table is full of unexpired nonces, or the tenant's budget has no room for another entry right now, the request is answered `503` with `retry-after: 1` (`password verification is busy`, a capacity refusal that auto-revert does not count): the digest was right, so the client is not told to try again with a new nonce, which could loop. If the tenant's `max_buffer_bytes` could never hold one entry (under 128 bytes) the answer is `503` with `password verification memory is over the tenant's budget`, which auto-revert counts: the deploy gave the tenant a budget it cannot authenticate with. The table never grows. A request that reuses a lower or equal `nc` gets a fresh `401` challenge.
- A browser that sends several requests in parallel may put `nc=3` on the wire before `nc=2`. The late one is answered with a fresh challenge and the client retries; that is the price of refusing replays without per-request state.

## Verification

- `qop=auth` is required; a request without `qop` (RFC 2069 style), with `auth-int`, with `username*` or `userhash=true`, a repeated parameter, a header over 4 KiB or a value over 2 KiB is refused.
- The `uri` the client signed must name the request: its request target (path and query), the absolute form, or the path as the client sent it before podgate normalized it (`//a/./b` and `/a/b` are one request). Put `digest_auth` **before** any middleware that rewrites the path (`strip_prefix`, `replace_path`), because the digest covers the path the client sent.
- The digest is compared in constant time. An unknown user, or a user whose `HA1` is of the other algorithm, goes through the same hashing with a dummy `HA1` and the result is thrown away, so the time taken does not say which users exist.
- A source with five failed attempts in a minute waits one second before each further attempt is verified (a table of at most 4096 sources; an IPv6 source is its /64). A request without credentials, a replay and a full table do not count as failures. The counter is private to the middleware (not shared with `basic_auth`) and survives pushes that leave it alone.
- Neither an `HA1` nor a response is logged, printed in `Debug`, shown by explain, or kept in a failure record (the `Authorization` header is redacted there by name). Explain shows the realm, the number of users, the offered algorithms, `header_field` and `remove_header`.

## Answers

A refusal is `401` with `WWW-Authenticate` (one header per algorithm, each with `realm`, `qop="auth"`, `algorithm`, a fresh `nonce`, and `stale=true` when the cause was an expired nonce), `Cache-Control: no-store` and the body `{"error":"unauthorized"}`. It is answered before a revision, a backend or a tenant slot is chosen, so unauthenticated traffic never reaches an upstream.

## Plan and posture

`POST /v1/snapshot/plan` lists these under `posture_changes` for a host that exists on both sides:

| Kind | When |
|---|---|
| `digest_auth_removed` | The middleware is no longer in the chain of the router. |
| `digest_auth_users_removed` | A user that could authenticate before is gone. |
