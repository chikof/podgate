# Hash balancers: `ip_hash`, `uri_hash`, `header_hash`, `hrw`

A `loadbalancer` service can pin a request to a server by a hash of the client address, the path or a header, so the same key keeps landing on the same server (a warm cache, a session held in memory) and removing one server moves only the keys that lived on it. They are algorithms of the service next to the ones in `lb-algorithms.md`: they skip servers that are unhealthy, ejected or already tried by this request, and a pick takes no lock and allocates nothing (`tests/lb_alloc.rs`).

```json
{ "name": "web", "type": "loadbalancer",
  "algorithm": { "type": "header_hash", "header": "x-tenant" },
  "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080", "weight": 3 } ] }
```

`algorithm` is a name (`"ip_hash"`) or an object with the name as `type`. An unknown field, an option that belongs to another algorithm and a missing required option are `invalid_service`: nothing is ignored.

| `algorithm` | Hashes | Options | Traefik | Caddy |
|---|---|---|---|---|
| `ip_hash` | The resolved client address | none | none | `ip_hash`, `client_ip_hash` |
| `uri_hash` | The normalized path | `include_query` (default `false`) | none | `uri_hash` |
| `header_hash` | The value of one request header | `header` (required) | none | `header` |
| `hrw` | The resolved client address, by highest random weight | none | `strategy: hrw` | none |

Caddy's `query` and `cookie` policies are not provided; sticky cookies are `sticky`, which pins a client before the algorithm runs.

## Keys

- **The client address** is the one the entry point's forwarding policy resolved (`client_ip.md`): the connection's peer unless that peer is trusted to speak for the client, never a raw `X-Forwarded-For`. A client behind an untrusted proxy cannot choose its server by forging the header. An IPv6 client is keyed by its `/64`, so a host that rotates the rest of its address keeps its server. A request with no IP peer (a unix socket) has no key.
- **The path** is the one the proxy normalized before routing (`match-request.md`), so `/a/../b` and `/b` are one key. The query is left out unless `include_query` is `true`.
- **The header value** is read as bytes. A header sent twice is hashed with both values in order. The header name must be a valid one.
- **No key** (no header, no address, no path) is not an error: the request goes to a random available server, so a client that omits the header still gets an answer.

## Consistent hashing and rendezvous

`ip_hash`, `uri_hash` and `header_hash` use a ketama ring (`pingora-ketama`). A server owns `weight / gcd` times 160 points; a pick hashes the key, finds the first point at or after it and takes that point's server. When that server is not allowed the pick walks on to the next point, so only the keys of the server that is out move, they spread over the others, and they return when it recovers. Health flaps do not reshuffle the ring: the ring is built once per compiled service and never from the current health.

`hrw` scores every server with a hash of the client and the server's address, scaled by its weight (`weight / -ln(u)` for a uniform `u`), and takes the best allowed score: a server of weight 3 wins three times as many clients as one of weight 1, and removing a server moves only the clients it won. It costs a hash and a logarithm per server on every pick, against a binary search for the ring, so prefer the ring algorithms for services with many servers.

## Weights

Weights shape the ring: a server of weight 3 gets three times the points. A server of weight `0` receives nothing (as in `weighted_round_robin`); every server at `0` is `invalid_service`. The weights are divided by their greatest common divisor first and must add up to at most 1024 afterwards (a ring of that size holds about 164 thousand points, 1.3 MB), or the service is `invalid_service`. Two servers with the same address are one server with their weights added.

## The hash is keyed

The ring's own hash (CRC-32) is not secret, so with it a client could choose paths or header values that all land on one server of an app. Every key is therefore hashed first with SipHash under a secret that lives in the service's state (`ServiceState::keyed_hash`): random per service and process, kept across snapshot pushes that leave the service alone (and across a change of its `servers`), replaced when the service's declaration changes.

The consequence is a deliberate choice: the same key maps to the same server on one podgate process for as long as the service is unchanged, and **not** across a restart and **not** between nodes. A fleet that wants one key on one server across nodes needs a shared secret, which this version does not offer (it would mean a secret in the snapshot).

## What a pick costs and when it fails

A pick reads atomics only. A ring pick walks to the first allowed point; the first refused point asks once whether any server could take the request, so a service whose servers are all down answers `503` without walking the ring. A retry (`PickCx.excluded`) skips the servers it already tried.

## Errors

| Code | When |
|---|---|
| `invalid_service` | `algorithm` is neither a name nor an object with a `type`; an unknown field; `header_hash` without `header` or with something that is no header name; `header` on another algorithm or `include_query` on another one; every weight `0`; weights that add up to more than 1024 after dividing by their common divisor |
