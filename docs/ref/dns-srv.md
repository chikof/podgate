# SRV upstreams

A `loadbalancer` server can be named by a DNS `SRV` record, such as a Consul or Nomad DNS name. The record decides the targets, their ports, priorities and weights. podgate resolves it on the record's TTL, balances over every address of every usable target, and checks each address and each port against the operator's upstream policy before it can become a server. Change 0096, on top of the resolver of change 0042 (`docs/ref/dns-resolver.md`) and the policy of change 0041 (`docs/ref/upstream-policy.md`). Code in `src/service/resolve/srv.rs`.

```json
{ "name": "web", "type": "loadbalancer", "algorithm": "weighted_round_robin",
  "servers": [ { "url": "http://_web._tcp.shop.service.consul", "resolve": "srv" } ] }
```

Matches Caddy's `dynamic upstreams` with `srv`. Traefik has no SRV upstream; its Consul Catalog provider supplies addresses instead.

## The server entry

| Field | Meaning |
|---|---|
| `url` | `http://owner.name`, `https://owner.name` or `h2c://owner.name`. The host is the **full owner name** the author wrote: podgate never builds `_service._proto` itself. There is no port. The scheme decides TLS and h2c for every target. |
| `resolve` | `"srv"` for an SRV name, `"a"` (the default) for the host-name servers of `dns-resolver.md`. Any other value is `invalid_service`. |
| `weight` | Not allowed with `resolve: "srv"`: the weights come from the records. |

A port in the URL, an owner that is not a syntactically valid host name (labels of letters, digits, `-` and `_`, at most 63 bytes each, 253 in all), an IP address, or a `weight` is `invalid_service`. A service may mix SRV servers with IP and host-name servers.

## From records to servers

1. **Records.** The SRV records of the owner name. A record is dropped when its port is `0` (RFC 2782's "the service is not available here"), when its target is the root `.`, or when its target is not a valid host name. At most **64** records are kept per name: the lowest priority values first, then the highest weights, then by name.
2. **Target addresses.** Each target host is resolved to `A` and `AAAA` addresses through the same resolver, never dialled by name: the address records in the answer's **additional section** when it holds some for the host, else two follow-up lookups per host, counted against `DNS_MAX_QUERIES_PER_SEC` like any lookup. At most 32 addresses per target. A target that is a `CNAME` is **refused** (RFC 2782 forbids it) and its records are dropped, whether the alias shows in the additional section or in the follow-up answer.
3. **Policy.** For each tenant that uses the name, every target passes `UpstreamPolicy::check_port` (the port rules below), and every address passes `UpstreamPolicy::check` (`dns-resolver.md`, `upstream-policy.md`), on every resolution. A refused target or address is dropped, counted and logged with the tenant, the name and the target. The same verdict is applied again when a balancer takes the addresses, so nothing refused is ever a server, and there is no gap between the check and the connection.
4. **Priority.** Only the targets of the **lowest priority value that has at least one usable address** are used. A higher value serves only while every target of the lower ones is unusable (it has no address, or the policy refused it). Health is the balancer's job (`svc-health.md`): a lower-priority target that is unhealthy is not skipped here.
5. **Servers.** One server per address, `ip:port` with the record's port, all with the entry's scheme. Two targets that resolve to the same `ip:port` are one server.

An SRV name that has not resolved is a server without an address, as for any name: requests get `503` and the app is not asleep.

## Weights

A record of weight `w` gives each of its addresses the balancer weight `max(1, w)`. A weight `0` therefore becomes `1`, the lowest weight, whether or not the other records are zero too (RFC 2782 asks for "a very small chance", and `1` is the smallest share a weighted algorithm has). A target that has `n` addresses splits its weight, `max(1, w / n)` each, so a multi-address target is only approximate.

What the algorithm does with the weights decides how exact they are:

| `algorithm` | SRV weights |
|---|---|
| `weighted_round_robin` | **Exact** while the weights, divided by their greatest common divisor, add up to at most 4096; scaled down (rounded) above that. |
| `hrw` | **Exact**, any weights. |
| `ip_hash`, `uri_hash`, `header_hash` | **Approximate**: a ring takes at most 256 weight units, so the weights are divided by their greatest common divisor and, when they still add up to more, scaled down with every target keeping at least one unit. Weights of 300 and 100 stay 3 and 1; weights of 65 535 and 100 lose their ratio to rounding. |
| `round_robin`, `least_conn`, `p2c_ewma`, `random` | **Ignored**: these algorithms have no weights, so every address gets `1`. Priorities still apply. |

The cap counts the whole service. A service that mixes SRV servers with other weighted servers can exceed it; the balancer then cannot be rebuilt, a warning is logged and the previous servers stay.

## The port policy

With `A` records the author of the snapshot chooses the port and DNS chooses the address. With `SRV` whoever edits the zone chooses both, so the address allow list alone would let a record point a tenant's server at an allowed host's database port. The operator's policy file (`UPSTREAM_POLICY_FILE`, never part of a snapshot) therefore has a port dimension:

```json
{ "srv_deny_ports": [22, 25, 5432],
  "default": { "allow": ["10.0.0.0/8"], "srv_allow_ports": [8000, 8080] },
  "tenants": { "acme": { "allow": ["10.4.0.0/16"], "srv_allow_ports": [9000] } } }
```

| Key | Meaning |
|---|---|
| `srv_deny_ports` | Ports no SRV target may use. Replaces the default list (`[]` denies nothing). Default: `22, 23, 25, 110, 143, 465, 587, 993, 995, 2375, 2376, 3306, 5432, 5984, 6379, 9200, 9300, 11211, 27017`. |
| `tenants.<id>.srv_allow_ports` | The only ports that tenant's SRV targets may use, on top of the deny list. A tenant entry without it uses the `default` entry's list, if any. |
| `default.srv_allow_ports` | The same for every tenant without a `srv_allow_ports` of its own. |

A port is refused when it is in `srv_deny_ports`, or when the tenant (else `default`) has `srv_allow_ports` and the port is not in it: a deny entry always beats an allow entry. A `0` in a list stops startup, naming the entry (`srv_deny_ports[1]: 0 is not a port`). The ports of IP and host-name servers are chosen by the snapshot's author and are not restricted by these lists.

A refused port drops the record's targets, logs a warning naming the tenant, the name, the target and the port, and counts in `podgate_upstream_refused_total{tenant,reason="port"}`. An address refused by the address rules keeps counting in `podgate_upstream_refused_total{tenant}` as before.

## Limits and failure

- At most **32** distinct SRV names per app and **128** per tenant (over every app), counted by the compiler next to the 64 and 256 host names of `dns-resolver.md`; more is `invalid_service` naming the count. At most 64 records per name, 32 addresses per target.
- One resolution task per distinct owner name across the node, however many services, apps and tenants use it. It runs again when the smallest TTL among the SRV records and the target addresses it used, clamped to `DNS_MIN_TTL_SECS..=DNS_MAX_TTL_SECS`, has run out. A changed answer adds and removes servers at that point.
- A failed answer (`SERVFAIL`, timeout, `NXDOMAIN`) or an answer with no SRV record keeps the last good targets until `DNS_MAX_STALE_SECS` after their TTL ran out, then the name has no target. A target host that fails to resolve while its record is still listed keeps its last addresses on the same terms. Records that are all unusable (port `0`, a `CNAME` target) are an answer: the name has no target.
- A name with no SRV record when nothing was known before is cached empty for the negative TTL of the answer.
- **Hash rings.** A hash service (`ip_hash`, `uri_hash`, `header_hash`) with an SRV server is charged for the largest ring a service can hold against the tenant and snapshot ring budgets at compile time, as for host names (`dns-resolver.md ## Hash rings`).
- **Compile never resolves.** Whether a snapshot is accepted does not depend on what DNS answers.

## Schemes, TLS and connections

`http://`, `https://` and `h2c://` work as for host names. The connection dials the checked `ip:port`; the owner name is only the TLS server name and certificate name of an `https://` server, so set the transport's `server_name` to the name the targets' certificates carry (an owner such as `_web._tcp.shop.service.consul` is not one). Pooled connections never cross apps, revisions or tenants (`dns-resolver.md`), and two targets share a connection only when they are the same `ip:port`.

## Retries and mirrors

A `retry` reselects among the resolved, checked targets, excluding the ones already tried. A `mirroring` target that is a load balancer with SRV servers copies requests to the resolved targets that passed the policy. A mirror cannot reach an address or a port a request cannot.

## What is not here

`multi` and other dynamic-upstream sources of Caddy are not provided. Caddy's `service`, `proto` and `name` fields are one owner name here, and `refresh` is the record's TTL clamped by `DNS_MIN_TTL_SECS` and `DNS_MAX_TTL_SECS`; its `resolvers` are `DNS_SERVERS` and its `dial_timeout` the transport's `dial_timeout_secs`. A name is never resolved at request time.
