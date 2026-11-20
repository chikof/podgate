# Servers named by DNS

A `loadbalancer` server `url` may carry a host name instead of an IP address. podgate resolves the name itself, keeps the answer fresh on the record's TTL, balances over every address the name returns, and checks every address against the upstream address policy (`docs/ref/upstream-policy.md`) before it can be dialled.

```json
{ "name": "web", "type": "loadbalancer", "algorithm": "round_robin",
  "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://app.internal:8080" } ] }
```

`http://app.internal:8080` expands into one server per address the name resolves to (`10.0.0.6:8080`, `10.0.0.7:8080`), each with the weight of the entry, and the algorithm is rebuilt over the expanded list whenever the answer changes. Requests in flight keep the servers they chose from.

## Settings

Operator settings (`docs/architecture.md ## Configuration`), never part of a snapshot.

| Setting | Default | Meaning |
|---|---|---|
| `DNS_SERVERS` | system configuration | Comma-separated name servers (`10.0.0.2`, `10.0.0.2:5353`, `[fd00::2]:53`). |
| `DNS_MIN_TTL_SECS` | `1` | An answer is kept at least this long whatever its TTL says. |
| `DNS_MAX_TTL_SECS` | `60` | An answer is kept at most this long before the name is resolved again. |
| `DNS_TIMEOUT_MS` | `2000` | One lookup (UDP, then TCP on truncation) never takes longer. |
| `DNS_MAX_STALE_SECS` | `300` | How long after its TTL ran out the last good answer is still used while resolution fails. |
| `DNS_MAX_QUERIES_PER_SEC` | `200` | Lookups a second this node sends in all, for every name and tenant. |

## Behaviour

- **Single flight.** One resolution task per distinct (name, address family: `A` or `AAAA`) across the node, however many services, apps and tenants name it. The task starts when the live table uses the name and stops when it does not.
- **TTL.** The task runs again when the answer's TTL, clamped to `DNS_MIN_TTL_SECS..=DNS_MAX_TTL_SECS`, has run out. A changed answer adds and removes servers at that point.
- **Failure keeps the last good set.** A failed (`SERVFAIL`, timeout, network error) or empty answer keeps the last good addresses until `DNS_MAX_STALE_SECS` after their TTL ran out, then the name has no address. Retries back off from the minimum to the maximum TTL.
- **Limits.** At most 64 distinct names per app and 256 per tenant (more is `invalid_service`, naming the count), at most 32 addresses per name (the rest are ignored), at most 32 lookups in flight, and `DNS_MAX_QUERIES_PER_SEC` lookups a second for the node. A name that is not a syntactically valid host name (labels of letters, digits, `-` and `_`, at most 63 bytes each, 253 in all) is `invalid_service`.
- **A name that has not resolved** (never, or not since the stale time ran out) is a server without an address. The compile does not fail. Requests get `503`, and the app is not asleep: a `scale_to_zero` app is not woken by it, only an app with no server at all is.
- **Compile never resolves.** Whether a snapshot is accepted does not depend on what a resolver answers. Where an algorithm cannot take the addresses a name returns (a hash ring heavier than its cap), the answer is not used and the previous servers stay.

## Rebinding and the address policy

The balancer holds addresses, not names. The connection dials the address that was checked, never the name, so a resolver cannot answer differently between the check and the connect. The name is only used for the TLS SNI and certificate verification of an `https://` server and as the `Host` of a health probe (`name:port`, unless the check sets `hostname`).

Every answer is checked with the upstream policy for each tenant that names the host, on every resolution. A refused address is dropped from the set, never dialled, counted in `podgate_upstream_refused_total{tenant}` and logged with the tenant and the name. The default policy refuses loopback, link-local and metadata addresses, so a record that answers `127.0.0.1` cannot reach the proxy host or its admin socket. The connect path checks the address again, as a second line.

## Hash rings

A service whose servers are named and whose algorithm builds a hash ring (`ip_hash`, `uri_hash`, `header_hash`, `hrw`) is charged for the largest ring a service can hold (`MAX_SERVICE_POINTS`, 40 960 points) against the tenant and snapshot ring budgets at compile time, because how many addresses a name has is not known until it resolves. A re-resolution that would build a ring heavier than the service cap is refused: the previous servers stay and a warning is logged. The budgets therefore hold whatever the names resolve to.

## What is not here

`SRV` records (Caddy's `srv` dynamic upstream) are not resolved; they are listed in `docs/parity.md`. The DNS resolution of a name never happens at request time. Traefik resolves on each new connection through the Go dialer without caching; podgate resolves on the TTL and holds the answer.
