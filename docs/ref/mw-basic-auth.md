# Middleware `basic_auth`

Reference for `src/middleware/basic_auth.rs`. The model it plugs into is in `docs/architecture.md` (`### Middlewares`). Matches Traefik's `basicAuth {users, realm, removeHeader, headerField}` and Caddy's `basic_auth`, with the deliberate differences below.

```json
{
  "name": "admin-auth",
  "type": "basic_auth",
  "users": [
    "alice:$2b$10$...",
    "bob:$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$..."
  ],
  "realm": "admin",
  "header_field": "x-authenticated-user",
  "remove_header": true
}
```

|Field|Meaning|
|---|---|
|`users`|Required, 1 to 4096 htpasswd entries `user:hash`. A user name is 1 to 255 bytes, has no `:` and no control characters, and appears once.|
|`realm`|The realm of the challenge. Default `podgate`. Not empty, no control characters, no `"` and no `\`.|
|`header_field`|A request header that receives the user name after a successful check. A value the client sent for it is replaced, never forwarded. It cannot be a header that frames the message or belongs to the connection (`Host`, `Content-Length`, `Proxy-*`, ...) or `Authorization`.|
|`remove_header`|`true` removes `Authorization` before the request goes to the upstream. Default `false`, as in Traefik: the credentials are forwarded unless you say otherwise.|

Unknown fields are `invalid_middleware`. There is no `usersFile`: podgate keeps no state on disk, so the control plane inlines the users.

## Hashes

Only these are accepted; anything else is `invalid_middleware` and the message names the user, never the hash.

- **bcrypt**: `$2a$`, `$2b$`, `$2y$`, cost 4 to 14. A password of 72 bytes or more never matches a bcrypt hash (the bcrypt algorithm would silently ignore the rest, so podgate does not verify it).
- **argon2**: `$argon2id$`, `$argon2i$`, `$argon2d$` in PHC form, memory at most 64 MiB (`m=65536`), time at most 4 and parallelism at most 4.

Apache MD5 (`$apr1$`), `{SHA}`, `crypt` and plaintext entries (Traefik accepts the first three) are refused: they are not safe to store. Generate entries with `htpasswd -nbB user password` (bcrypt) or any argon2 tool.

## What a request sees

|Request|Answer|
|---|---|
|No `Authorization`, another scheme, malformed base64, no `:`, more than one `Authorization` header, a user name over 255 bytes or a password over 1024 bytes|`401`, no hashing.|
|Unknown user, wrong password|`401`, after one verification (see below).|
|Known user, right password|The request continues; `header_field` and `remove_header` apply.|
|No verification worker in time, or the tenant over its share of them|`503` with `retry-after: 1`, `password verification is busy`. Not counted by auto-revert (a capacity refusal).|
|An argon2 hash whose memory is more than the tenant's whole `max_buffer_bytes`|`503` with `retry-after: 1`, `password verification memory is over the tenant's budget`. Counted by auto-revert: the deploy declared a hash the tenant can never pay for, so a push that does this can be reverted. A hash that fits but finds the budget full right now (other buffers, filters or verifications hold it) is the busy `503` above instead, and is not counted.|

Every `401` carries `WWW-Authenticate: Basic realm="<realm>", charset="UTF-8"`, `Cache-Control: no-store` and the body `{"error":"unauthorized"}`. The scheme name is matched case-insensitively.

The middleware runs in the chain, before any tenant slot is taken, a revision is chosen or a backend is contacted: unauthenticated traffic never costs the tenant an in-flight slot and never reaches an upstream.

## Cost bounds

Password hashing is attacker-triggered CPU and memory, so it is bounded and charged like any other resource a tenant can make podgate spend.

- **Workers.** Verifications run on the blocking pool behind `BASIC_AUTH_MAX_CONCURRENT` permits (default: available cores, at most 256), never on the async reactor. A tenant may hold at most half of the permits (at least one), so a flood from one tenant cannot take them all; a tenant over its share is refused at once. A verification waits at most one second for a permit, then the request answers `503` with `retry-after: 1`. A started verification runs to its end even when the client disconnects.
- **Memory.** An argon2 verification reserves `m` KiB from the tenant's `max_buffer_bytes` before it starts (the budget of change 0009) and releases it when it ends. A hash that does not fit gets `503`. A bcrypt verification needs about 4 KiB and is not charged.
- **Failures.** A source with five failed verifications in a minute waits a second before each further verification. The source is the resolved client address (`docs/ref/client-ip.md`), grouped by IPv4 address or IPv6 /64; the table holds at most 4096 sources and evicts the oldest. Requests that fail before any hashing (no header, malformed) are not counted. The waiting happens before a permit is taken, so it holds no worker. A success does not clear the count.
- **Cache.** A verified credential is remembered for 30 seconds under an HMAC-SHA256 of user and password with a random per-process key, at most 4096 per middleware (oldest evicted), so a client that re-sends its credentials does not rehash on every request.
- **Lifetime of the failure table and the cache.** Both live outside the routing table, keyed by (app, middleware name, fingerprint of its whole declaration) and settled at the swap site like the service state. A push that leaves the middleware as declared, whatever else it changes, keeps the failure counts and the cache, so pushing snapshots does not reset a brute-force throttle. Changing the middleware (a user, the realm, any field) starts both fresh, so a changed or removed password is never honoured from the cache.

## Timing and secrets

- An unknown user is verified against the hash of one configured user, and the result is discarded, so response time does not say which names exist. Users whose hashes have different costs still differ in time; use one cost for all users when that matters.
- Password comparison is constant-time: the `bcrypt` and `argon2` libraries compare with `subtle`-style constant-time equality.
- Hashes are redacted in `Debug`, in `GET /v1/explain` (which shows the realm, the number of users, `header_field` and `remove_header`) and in failure records (`Authorization` is `[redacted]` there). Credentials and hashes are never logged.

## Posture

In `POST /v1/snapshot/plan`, `posture_changes` lists `basic_auth_removed` when the middleware is gone from a host's chain and `basic_auth_users_removed` when a user it declared is no longer declared.
