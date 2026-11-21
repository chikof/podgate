# The Consul source

Reference for `crates/podgate-provider/src/consul/`: the provider source that turns Consul catalog services tagged for podgate into apps, takes their servers from healthy instances and follows registrations and health changes with blocking queries. It matches Traefik's Consul Catalog provider (`exposedByDefault`, `namespaces`, `partition`, `stale`, `connectAware`, `refreshInterval`, tags as labels). Caddy has no first-party counterpart.

A service tag describes routing, never destinations. The only address that can become a server is the one the instance registered itself, and the operator's upstream address policy decides whether it may be used.

## Configuration

```toml
[[source]]
kind = "consul"
name = "consul-prod"
address = "http://127.0.0.1:8500"
token_file = "/etc/podgate/consul.token"
datacenter = "dc1"
tenant_from = "fixed"
tenant = "acme"
exposed_by_default = false
resync_secs = 30
```

| Key | Default | Meaning |
|---|---|---|
| `address` | required | The agent or server, `http://host:port` or `https://host:port`, with no path. HTTPS is verified against the platform's root certificates; there is no key for a private CA or a client certificate yet. |
| `token_file` | none | A file that holds an ACL token, sent as `X-Consul-Token` and never logged (below). Must not be readable by group or others, like every secret file of the provider. One trailing newline is removed. Read once, at start. |
| `datacenter` | the agent's | Passed as `dc`. One source watches one datacenter: a service of the same name in two datacenters is two sources. |
| `namespaces`, `partitions` | none | Enterprise. Passed as `ns` and `partition`. With either, the source asks once for every partition and namespace pair, and an app id is led by them (`team-a.web`, `p1.team-a.web`) so two namespaces cannot make one app. Without them the id is the service name. |
| `tenant_from` | `fixed` | Where an instance's tenant comes from: `fixed`, `meta` or `namespace` (below). |
| `tenant` | `default` | For `fixed`, the tenant of every instance. For `meta`, the tenant of an instance whose service names none. Not allowed with `namespace`. |
| `namespace_tenants` | none | For `namespace` only: `{ "team-a" = "acme" }`. Every namespace in `namespaces` needs an entry and no other namespace may appear. |
| `meta_key` | `podgate-tenant` | For `meta` only: the `Service.Meta` key that names the tenant. |
| `exposed_by_default` | `false` | Whether an instance without `podgate.enable` counts. `podgate.enable=false` always excludes. |
| `connect` | `false` | Whether Connect sidecar proxies (`Service.Kind = "connect-proxy"`) count. See [Connect](#connect). |
| `stale` | `false` | Adds `stale` to every query, so any server answers, not only the leader. |
| `resync_secs` | `30` | The longest the source goes without reading everything again, whatever the blocking queries said. At least `1`. |
| `wait_secs` | `60` | The `wait` of a blocking query, `1` to `600`. Consul's own default is `5m`; a shorter wait notices a half-open connection sooner. |

Unknown keys are errors, so a misspelt `tenant` cannot move the source's apps to the default tenant.

## Tags

A Consul tag is one string. The source reads the tags written `key=value`, split at the first `=`, with the keys of the Docker labels (`docs/ref/provider-docker.md ## Labels`), through the same parser:

```
podgate.enable=true
podgate.host=shop.acme.example, www.acme.example
podgate.router.api.match={"all": [{"host": "api.acme.example"}, {"path_prefix": "/v1"}]}
podgate.middleware.strip.type=strip_prefix
podgate.middleware.strip.config={"prefixes": ["/v1"]}
```

Tags that are not `key=value` (`v2`, `primary`) and tags of other keys are the deployer's own business and are skipped. Differences from Docker labels:

- A `podgate.*` tag with no `=`, or the same `podgate.*` key twice, rejects the instance: which of two values counted would depend on tag order.
- `podgate.port` is rejected. The port of a server is the one the service registered, never a tag.
- `podgate.app` must be absent or the service's name. The app of a Consul service is its name; a tag cannot move an instance into another service's app.
- `podgate.tenant` is not read. The tenant of an instance is decided by `tenant_from`.
- Any other `podgate.*` key, a value that does not parse, a router without `match` and the rest of what rejects a container (`docs/ref/provider-docker.md ## Labels`) reject the instance, and the report names it.

## The address rule

A server is `http://<address>:<port>` where

- `<address>` is `Service.Address`, or `Node.Address` when that is empty, and
- `<port>` is `Service.Port`.

Nothing a tag says can change that. The instance is left out, with a report, when the address is not an IP address (a name would be resolved by the proxy, outside this source's view), when the service registered no port, and when a tag names an address, a URL or another app's service, as for Docker.

A service registers its own address, so a tenant that can register services in Consul can advertise any address, including one that belongs to nobody it should reach. The protection is not in this source: it is the operator's upstream address policy (`docs/ref/upstream-policy.md`), which the provider applies before every push (`upstream_forbidden`) and podgate again at connect time. For a datacenter whose services live in `10.20.0.0/16` and whose tenants own parts of it:

```json
{
  "deny_extra": ["10.20.255.0/24"],
  "default": { "allow": ["10.20.0.0/16"] },
  "tenants": {
    "acme":   { "allow": ["10.20.1.0/24", "10.20.2.0/24"] },
    "globex": { "allow": ["10.20.3.0/24"] }
  }
}
```

Loopback, link-local and the metadata addresses stay denied by the built-in list. With `tenant_from = "meta"` the per-tenant list is what stops a service from naming a tenant and then another tenant's addresses.

## Instances and apps

- The instances of a service come from `GET /v1/health/service/<name>?passing=true`. Only instances whose checks are all `passing` serve, and the source checks that itself too, so a Consul that ignores the filter changes nothing. An instance with a `warning` or `critical` check, on a node with a failing `serfHealth`, or in maintenance mode (which Consul turns into a critical check) is not a server and is not reported.
- A service whose instances are all down has no app: its routes answer as an unknown host does.
- One service in one datacenter, namespace and partition is one app, `<source name>-<service name>` in the snapshot. The app has one revision `default` unless `podgate.revision` and `podgate.revision.state` say otherwise (`docs/ref/provider-docker.md ## Containers, apps and revisions`): the instances of a service may carry different revisions, which is how a rolling deploy shows.
- The instances of one revision must agree on their routing; the oldest by `Service.CreateIndex` is the reference, and one that differs is left out and reported. A bad tag on the new instances of a rollout therefore leaves the old ones serving.
- At most 256 instances of a service are used, the first by address order; the rest are reported.
- An app's `first_seen` is the time this source first saw it, kept while the app exists. Consul has no creation time, and a raft index cannot be compared with another source's time, so a restart of the provider makes its Consul apps newer than the objects of other sources: an older file or Docker app wins a host conflict.
- A service whose name cannot be an app id (1 to 63 letters, digits, `-`, `_` or `.`, with its partition and namespace) is reported.

## Tenants

| `tenant_from` | The tenant is | `Service.Meta` | `podgate.tenant` tag |
|---|---|---|---|
| `fixed` | `tenant`, the operator's decision | ignored | ignored |
| `meta` | the `meta_key` value, honoured only for tenants that list the source in `label_sources` (`docs/ref/provider.md`); otherwise `tenant`, else the default tenant | read | ignored |
| `namespace` | the one `namespace_tenants` gives for the namespace the service lives in | ignored | ignored |

`meta` is the Consul form of Docker's `label` mode and follows the same trust rule (`docs/ref/provider.md`): whoever can register a service can write its `Meta`, so a tenant named there counts only for tenants that trust this source. A meta value that is not a name is reported and the instance is left out. Whatever the tenant, an instance may claim only the hosts its tenant may claim (`foreign_host_claim`).

## Following Consul

The source holds blocking queries open, `?index=<n>&wait=<wait_secs>s`, which Consul answers when the data changes or the wait ends:

- one on `GET /v1/catalog/services` per namespace and partition, which says which services exist and which tags they carry;
- one on `GET /v1/health/service/<name>?passing=true` for each service worth watching: those with a `podgate.enable` tag that is not `false`, or every service with `exposed_by_default`. A service that did not ask is not read at all.

A change reaches the source at once; the source then waits 50 ms for more changes and builds the state once. It reads everything again (a query with no index) every `resync_secs`, after every error, and when an index goes backwards, which happens after a restore from a snapshot or when `stale` reads reach another server; an index that is `0` is replaced by `1`, as Consul's guide for blocking queries says. After an error the query is repeated with a backoff of 100 ms doubling to 5 s, up to a quarter longer so that many watchers do not return together. A server that answers a blocking query at once with the index it was given is not blocking: the source pauses a second instead of spinning.

The first state is sent only after the catalog and the instances of every watched service were read once. Services come and go with the catalog: a new one gets a query, a removed one loses it.

Caps, per source: **512 watched services**, in name order (the rest are reported and not read), and 256 instances per service. Every watched service is a connection held to Consul, and a Consul agent limits connections per client address (`limits.http_max_conns_per_client`, 200 by default): to watch more than that, raise the limit, or tag fewer services and leave `exposed_by_default` off.

## Reports and outages

An instance that asks to be used but is not is named in an outage text sent after the state, like a container in the Docker source, and logged:

```
service web instance web-2 on node n2: unknown label podgate.hosts: ...; service api instance api-1 on node n1: address "api.internal" is not an IP address ...
```

The next state replaces it. A Consul that cannot be reached, answers an error (a `403` from an ACL change, a `500` from a datacenter with no leader) or sends something unparsable is an outage too: the last state stays in force, an outage never means "no services", and the source retries with backoff. When only some queries fail, the others keep delivering and the failing ones keep their last data; the report groups the errors by text and names the first few queries. `print` and `check` run one pass and fail on an outage, so a start with Consul down is an error there.

## Token and ACLs

The token goes in the `X-Consul-Token` header, marked sensitive, and in nothing else: not the URL, not a log line, not a report, not the `Debug` output of the source. Consul echoes what it refuses (`Permission denied: token ... lacks permission`), so the text of an error answer is quoted with the token replaced by `[redacted]`. The file is read once at start; rotate the token by restarting the provider.

The client issues `GET` and nothing else (`client.rs` has one way to send a request). The token needs read access to services and nodes only:

```hcl
service_prefix "" { policy = "read" }
node_prefix    "" { policy = "read" }
```

Narrow `service_prefix` to the prefixes podgate should see, and namespaces and partitions to the ones configured. A service the token cannot read is an error for that service alone.

## Connect

With `connect = false`, an instance whose `Service.Kind` is not empty is ignored: the sidecar proxies Consul registers with their service's tags would otherwise appear as a second app with the same hosts. With `connect = true`, instances of kind `connect-proxy` count like any other service (the app is the proxy's own service name, `web-sidecar-proxy`); gateways of any kind never do. There is no mesh support: podgate does not speak mTLS to a sidecar, so this is for sidecars that accept plain connections, or for a podgate deployed as a mesh gateway's peer.

## Not supported

- Consul's DNS interface and SRV lookups: that is the SRV resolver (`docs/ref/dns-srv.md`), which a Consul user can choose instead of this source for a plain list of upstreams.
- A rule template (`defaultRule`): a service says its hosts with `podgate.host` or a router.
- Names as servers (`Service.Address` that is a DNS name) and `TaggedAddresses`.
- A private CA or client certificate for the agent connection, and HTTP basic auth to it.
- Service mesh, `health/connect`, intentions and mTLS to sidecars.
- Watching several datacenters from one source, and key-value stores.
