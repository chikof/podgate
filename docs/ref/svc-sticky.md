# Sticky cookie

A `loadbalancer` service can pin a client to one server with a signed cookie. The first response of a client carries the cookie; later requests that present it go to the same server for as long as that server can take them. Code in `src/service/sticky.rs`, tests in `tests/svc_sticky.rs`.

```json
{ "name": "web", "type": "loadbalancer",
  "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" } ],
  "sticky": { "cookie": { "name": "__podgate_srv", "same_site": "lax", "max_age_secs": 3600 } } }
```

The snapshot must set `skew_secret`: a sticky service in a snapshot without one is rejected with `invalid_service`.

## Fields

`sticky.cookie` is required (`sticky: {}` is `invalid_service`) and takes only these fields; an unknown one is `invalid_service`.

| Field | Default | Meaning |
|---|---|---|
| `name` | `__podgate_srv` | Cookie name. Must be an HTTP token. `__podgate_rev` (the skew protection cookie) is refused. |
| `secure` | off | `true`: always `Secure`. Otherwise `Secure` is added on TLS connections only, so a cookie over plain HTTP stays usable. There is no way to drop `Secure` from a TLS response. |
| `http_only` | `true` | `false` drops `HttpOnly`. |
| `same_site` | `lax` | `lax`, `strict` or `none` (any case). `none` needs `secure: true`, because browsers drop `SameSite=None` without `Secure`; the snapshot is refused otherwise. |
| `max_age_secs` | session cookie | `Max-Age` in seconds, above `0`. Not refreshed while the pin holds. |
| `path` | `/` | `Path`: absolute, no spaces, `;` or control characters. |

This is Traefik's `sticky.cookie {name, secure, httpOnly, sameSite, maxAge, path}` with snake_case names; Caddy's equivalent is `lb_policy cookie`.

## The cookie value

```text
value = base64url(HMAC-SHA256(skew_secret,
          "podgate/sticky/v1" || len(app) || app || len(service) || service || server_url)[..16])
```

`len` is two bytes, big-endian, so no choice of names makes two different (app, service) pairs sign the same bytes. The value is always 22 characters.

- It reveals no address: an attacker who reads the cookie learns nothing about the server, its network or how many there are.
- A client cannot choose a server it was not given: it would need the key. (Traefik's value is a hash of the server URL that a client can replay but cannot forge; the HMAC adds a key, and an attacker who knows an upstream URL cannot compute its cookie.)
- It is bound to the app and the service. A cookie from another app, from another service of the same app, or signed with another `skew_secret` pins nothing. Rotating `skew_secret` unpins every client once.
- Its label differs from the revision cookie's (`__podgate_rev`, `src/skew.rs`), which the same secret signs, so one cookie cannot be replayed as the other.

The server is found by recomputing the value for each server of the service (at most 256 HMAC-SHA256 over a short input, only when a cookie of that name is present) and comparing in constant time. A cookie that is not exactly the canonical 22 characters is ignored without any computation.

## Pinning and fallback

Inside `LoadBalancer::pick`, before the algorithm, the pinned server is used if it:

- is in the service (a server removed by a push is gone),
- is available: healthy and not ejected,
- was not already tried by this request (a retry, moves on),
- has a weight above `0` (`weighted_round_robin` only).

Otherwise the algorithm picks and the response carries a fresh cookie for the server that was chosen. A response never repeats a cookie the request already carried for that server.

State that belongs to the algorithm (the turn counter of `round_robin`, the latency average) is not advanced by a pinned request.

## Interplay

- **Skew protection.** The revision cookie `__podgate_rev` pins a revision; the sticky cookie pins a server inside the service of that revision. Both are set on the first response and both are honored on later ones. Their names must differ, which the compiler enforces. A sticky cookie never selects a revision, and the revision pin never selects a server.
- **One cookie per service name.** Two sticky services of one app that keep the default name share a cookie name but not a value, so a client that uses both has its cookie replaced on each switch. Give them distinct `name`s.
- **Caches.** The cookie is not set on a response with `Cache-Control: public`, so a shared cache cannot hand one client's pin to everyone. A `private` or absent `Cache-Control` still gets it. The revision cookie of 0011 has no such rule.
- **`weighted` services.** The cookie belongs on the parent and is kept per child service; until that spec lands `sticky` is a `loadbalancer` field only.
- **Per-process.** The secret, not memory, carries the pin: every node with the same `skew_secret` and the same server list honors every node's cookie, and a restart keeps all pins.

## Not built

Cookies for other algorithms' hashing (`ip_hash`, `uri_hash`, `header_hash`) are change 0032. There is no `Domain` attribute and no cookie other than this one.
