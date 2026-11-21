# The Nomad source

Reference for `crates/podgate-provider/src/nomad/`: the provider source that turns Nomad service registrations tagged for podgate into apps, taking servers from the registered address and port of each allocation, and follows registration changes with blocking queries. It matches Traefik's Nomad provider (`endpoint`, `namespaces`, `exposedByDefault`, `stale`, tags as labels). Caddy has no first-party equivalent.

The tags are the Docker labels written `key=value`: they go through the same parser ([`docker::labels::parse`](provider-docker.md#labels) and `assemble`), so every `podgate.*` key means what it means in [the Docker source](provider-docker.md). Only what is Nomad's differs: where the server comes from, how the tenant is chosen, and how changes arrive. Nomad-native service registrations only. Services registered in Consul are out of scope: the Consul catalog needs its own source and its own trust analysis.

## Configuration

```toml
[[source]]
kind = "nomad"
name = "nomad-prod"
address = "http://127.0.0.1:4646"
token_file = "/etc/podgate/nomad-token"
namespaces = ["default", "team-a"]
namespace_tenants = { team-a = "acme" }
default_tenant = "default"
exposed_by_default = false
resync_secs = 30
```

| Key | Default | Meaning |
|---|---|---|
| `address` | required | The origin of the Nomad HTTP API: `http://host:4646` or `https://host:4646`. No path, query or credentials. An `https://` server's certificate is verified against the platform's root certificates (`SSL_CERT_FILE` and `SSL_CERT_DIR` apply), so a private CA must be installed there. |
| `token_file` | none | A file that holds the ACL token. It is read once at start, trimmed, and sent as `X-Nomad-Token` on every request. It is never logged, never in an error text, never in `Debug` output. Over `http://` the token travels in clear: use `https://` unless the server is on the same host. |
| `namespaces` | `["default"]` | The namespaces to read. One request series per namespace; `*` is not accepted, so a namespace nobody mapped to a tenant is never read. |
| `namespace_tenants` | none | `{ team-a = "acme" }`: the tenant of a namespace. Every key must be one of `namespaces`. |
| `default_tenant` | `default` | The tenant of a namespace that `namespace_tenants` does not list. |
| `exposed_by_default` | `false` | Whether a service without a `podgate.enable` tag counts. `podgate.enable=false` always excludes. |
| `stale` | `false` | Send `stale` with every query, so any server, not only the leader, answers. Nomad's own default is consistent reads. |
| `resync_secs` | `30` | The longest the source goes without reading all registrations again. At least `1`. |

Unknown keys are errors, so a misspelt `namespace_tenants` cannot move the source's apps to the default tenant.

The token needs the `read-job` capability (or `read`) on the namespaces listed; the source only ever sends `GET`.

## Tags

A tag is split at the first `=`, so values may hold more (`podgate.router.web.match={"host":["a.test"]}`). Tags without `=` that do not start with `podgate.` are ignored (`urlprefix-/shop`, `v2`). Keys are those of [the Docker labels](provider-docker.md#labels), with these differences:

- `podgate.port` is **not accepted**: the port is the registration's. A registration that carries it is rejected with a report.
- A `podgate.*` tag must be a pair, and none may be given twice: Nomad tags are a list, and with a repeated key one value would silently win. Either mistake rejects the registration.
- `podgate.app` defaults to the service name. In the snapshot an app is called `<source name>-<namespace>.<app>` (`nomad-prod-default.shop`), so the same service name in two namespaces is two apps. The whole id may be at most 63 characters.
- `podgate.tenant` is the job's own claim; see [Tenants](#tenants).

Any other `podgate.*` key, a value that does not parse, a router without `match`, a `chain` entry that no tag defines: the registration is rejected and reported. The daemon behaves the same on unknown fields, so a misspelt tag cannot silently turn a rule off.

The Traefik tags (`traefik.http.routers.<r>.rule=...`) are read through the translator of change 0071; see [the Traefik subset](#traefik-tags).

## The address rule

A server is `http://<Address>:<Port>` of the registration, the address and port Nomad has for the allocation, one per instance of one revision, in address order. Nothing a tag says can change that. A registration is rejected, with a report, when:

- its `Address` is not an IP address (a hostname is not a server: a name would be resolved by whoever runs the job's DNS);
- its `Port` is `0`;
- a tag names an address, a URL or a `host:port` where a name or an id is expected, or JSON with a key named like a destination, as in [the Docker source](provider-docker.md#the-address-rule);
- it carries `podgate.port`.

**A job decides what address it advertises.** Nomad registers whatever the task's `service` block says (`address`, `address_mode`), and so a job in a namespace can register a service at `169.254.169.254:80`, at a database's address, or at another tenant's allocation. The source cannot tell that from a legitimate address. The protection is the operator's upstream address policy: the provider checks every server of every app against it in the merge (`upstream_forbidden`, `docs/ref/upstream-policy.md`), per tenant, and the daemon checks every connection it opens. For a Nomad cluster, allow each tenant only the networks where its allocations run, for example when Nomad hands out addresses from `10.4.0.0/16` and `10.5.0.0/16` per node pool:

```json
{
  "tenants": {
    "acme":   { "allow": ["10.4.0.0/16"] },
    "globex": { "allow": ["10.5.0.0/16"] }
  }
}
```

With this policy a job in acme's namespace that advertises `10.5.0.7:80` is dropped from the snapshot and reported; with the built-in deny list alone, link-local, loopback and metadata addresses are refused but a neighbour tenant's address is not. Write the allow list.

## Services, instances and revisions

- Every instance of a service in a namespace is read: `GET /v1/service/<name>?namespace=<ns>` returns one registration per allocation, with its `Address`, `Port`, `Tags`, `AllocID`, `JobID` and `Namespace`. A registration whose namespace differs from the one asked for is rejected.
- Instances of one app (the same `podgate.app` or service name in one namespace) are the servers of its services. Two services of one job can name the same `podgate.app` and form one app.
- The instances of one revision must agree on their routing, services and revision state; the oldest instance (by Nomad's create index, then allocation id) is the reference, and one that differs is left out and reported. This is the same rule as for Docker containers.
- Revision: one revision `default`. Nomad's rolling updates remove allocations that fail their health checks from the registration, so no revision states are produced. A job that wants explicit revisions uses `podgate.revision` and `podgate.revision.state` tags, exactly as with Docker labels.
- An app's `first_seen` is `0`: a service registration carries only raft indexes (`CreateIndex`), which are not times and cannot be ordered against another source's apps, and the allocation's `CreateTime` would cost one `GET /v1/allocation/<id>` per allocation. A conflict between two apps over a host is therefore decided by source name, then app id (`<namespace>.<app>`), which is the same after every restart of the provider and independent of the order Nomad lists registrations in.

## Tenants

Each namespace maps to a tenant: `namespace_tenants`, else `default_tenant`. That is the operator's decision. A job's `podgate.tenant` tag is only a claim, and the core honours it under its trust rule (`docs/ref/provider.md`): only for a tenant whose `label_sources` list this source. Whatever the tenant, a registration may claim only the hosts the tenant may claim (`foreign_host_claim`), so a tag cannot take another tenant's host.

## Following Nomad

One watcher per namespace holds a blocking query on `GET /v1/services?namespace=<ns>&index=<n>&wait=60s` open. Nomad answers when the registrations of the namespace change, or after the wait, with `X-Nomad-Index`; the next query carries that index. The first query has index `0` and answers at once. A changed index wakes the source, which reads again:

- 50 ms after the first wake (changes inside that window share one read);
- when the watcher connects or reconnects, because a change between the last read and the connect would otherwise wait;
- every `resync_secs`.

A read lists the services of each namespace (`GET /v1/services?namespace=<ns>`) and then, only for the services that may be exposed, their instances. A service whose tags hold no `podgate.enable` other than `false` is not read at all unless `exposed_by_default`. An index that goes backwards starts the query over from `0`. A failing watcher reconnects with a backoff of 100 ms doubling to 5 s. The first state is sent only after a complete read succeeded.

The provider's own debounce (`debounce_ms`) then coalesces the update with the other sources' before one push.

## Reports and outages

A registration that carries tags but is not used is named in an outage text sent after the state, and logged:

```
service default/shop (job shop, alloc 4f2a91c0): unknown label podgate.hots: ...; service default/db (job db, alloc 77b1e2aa): registered address "db.internal" is not an IP address; ...
```

The next state replaces it. A server that cannot be reached, refuses the token (`Nomad answered 403 to GET /v1/services: Permission denied`) or sends something unparsable is an outage: the last state stays in force, an outage never means "nothing is registered", and the source retries with backoff. `print` and `check` run one pass and fail on an outage, so a start with Nomad down is an error there.

## Read only

The client sends `GET` and nothing else (`client.rs` has one way to send a request): list services, read instances, block on the list. It cannot register or deregister anything.
