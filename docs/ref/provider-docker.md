# The Docker and Podman source

Reference for `crates/podgate-provider/src/docker/`: the provider source that turns running Docker or Podman containers into apps through `podgate.*` labels and follows container start, stop and health changes. It matches Traefik's Docker provider (`exposedByDefault`, `network`, container labels, health awareness; Swarm is excluded, see below) and Caddy's `caddy-docker-proxy`. The `traefik.*` labels are read too, next to the `podgate.*` ones, by the translator of change 0071 (`docs/ref/provider-traefik.md`) that [`labels::parse`](#where-the-label-parser-lives) calls: `traefik.enable` exposes a container like `podgate.enable`, and a label that cannot be translated exactly is reported with its exact key.

Labels describe routing, never destinations. The only address that can become a server is one the runtime itself assigned to the container that carries the labels.

## Configuration

```toml
[[source]]
kind = "docker"
name = "docker-prod"
socket = "/var/run/docker.sock"
network = "podgate"
tenant_from = "fixed"
tenant = "acme"
exposed_by_default = false
resync_secs = 30
```

| Key | Default | Meaning |
|---|---|---|
| `socket` | `/var/run/docker.sock` | The daemon's unix socket. Podman: `/run/podman/podman.sock` (rootful) or `$XDG_RUNTIME_DIR/podman/podman.sock` (rootless), its Docker-compatible API. |
| `network` | required | The network whose container addresses podgate can reach. A name, or a list of names; the first one a container has an address on gives its server. A network the daemon does not have is reported. |
| `tenant_from` | `fixed` | Where a container's tenant comes from: `fixed`, `network` or `label` (below). |
| `tenant` | `default` | For `fixed`, the tenant of every container. For `label`, the tenant of a container that names none. Not allowed with `network`. |
| `network_tenants` | none | For `network` only: `{ "net-a" = "acme" }`. Every network in `network` needs an entry and no other network may appear. |
| `exposed_by_default` | `false` | Whether a container without `podgate.enable` counts. `podgate.enable=false` always excludes. |
| `resync_secs` | `30` | The longest the source goes without listing the containers again. At least `1`. |

Unknown keys are errors, so a misspelt `tenant` cannot move the source's apps to the default tenant.

## Labels

|Label|Meaning|
|---|---|
|`podgate.enable`|`true` or `false`. Required unless `exposed_by_default`.|
|`podgate.app`|The app id. Default: the compose service name (`com.docker.compose.service`), else the container name. In the snapshot the id is `<source name>-<app>`.|
|`podgate.tenant`|The tenant the container names for itself. Only read with `tenant_from = "label"`.|
|`podgate.host`|Comma separated hosts (`a.test, *.b.test`): a router named `default` that matches them and uses the service `web`.|
|`podgate.port`|The port the container listens on. Required: the source does not guess one from the image.|
|`podgate.revision`, `podgate.revision.state`|The revision id (default `default`) and its state: `serving` (default), `retiring` or `draining`.|
|`podgate.tls`|`acme` (default) or `on_demand`.|
|`podgate.router.<name>.match`|A matcher as JSON, as in `docs/architecture.md` (`### Routers and matchers`). Required for a router.|
|`podgate.router.<name>.priority`, `.entry_points`, `.chain`, `.service`|Priority (a number), comma separated entry points, comma separated middleware names, and the service name (default `web`).|
|`podgate.middleware.<name>.type`, `.config`|A middleware of the app: its type, and its fields as a JSON object (default `{}`).|
|`podgate.service.<name>.config`|A service of the container's revision as a JSON object: `algorithm`, `health_check`, `passive`, `sticky`, `transport`, or another service `type` (`weighted`, `failover`, `mirroring`) that names the app's other services. `type` defaults to `loadbalancer`. The service `web` exists without a label.|
|`podgate.transport.<name>.config`|A `servers_transport` of the app as a JSON object, which a service names in `transport`. Labels are the only place a container can declare one, so the reference has something to point at.|

A router needs a matcher: `podgate.host` or `podgate.router.<name>.match`. A router whose matcher has no literal host (a `host_regexp` alone, or a matcher with no host) is a catch-all, and the provider's merge applies the catch-all preflight to it like to any other source's router (`docs/ref/provider.md`).

Any other `podgate.*` key, a value that does not parse, a router without `match`, a middleware without `type`, a `chain` entry that no label defines: the container is rejected and reported. The daemon behaves the same on unknown fields, so a misspelt key cannot silently turn a rule off. Labels that do not start with `podgate.` are not read.

## The address rule

The `servers` of every `loadbalancer` service of a revision are `http://<container IP on the configured network>:<podgate.port>`, one per container of that revision, in address order. The IP is the address the daemon assigned (`NetworkSettings.Networks.<network>.IPAddress`, else `GlobalIPv6Address`). Nothing a label says can change that. The container is rejected, with a report, when a label:

- is an address, a URL or a `host:port` where a name or id is expected: `podgate.host=10.0.0.5`, `podgate.router.main.service=http://10.0.0.5:80`, `podgate.app=db:5432`;
- carries JSON with a key named like a destination at any depth: one that ends in `url`, `uri`, `address`, `addr`, `endpoint`, `issuer`, `server(s)`, `upstream(s)` or `container(s)`, so `servers` and a `forward_auth` `address` are out, or a string value that is `ip:port` or starts with `unix:`;
- names a service, middleware or transport that the container's own labels do not define, or one of another app (`other/web`, `victim`, a container name). A name resolves inside its own app, so a label cannot make a router, a chain or a failover reach another tenant's container.

A middleware that needs an address of its own (`forward_auth`, a JWKS or OIDC issuer) is therefore not available through labels: declare it in a file source, where an operator wrote it. Redirects and headers work, except where a field's name looks like a destination.

A server's address still passes the operator's upstream address policy in the merge (`upstream_forbidden`, `docs/ref/upstream-policy.md`): the source decides which address, the policy decides whether it is allowed.

## Containers, apps and revisions

- Only `running` containers count, and when the image defines a health check only `healthy` ones. `created`, `paused`, `restarting`, `exited`, and `starting` or `unhealthy` containers are not servers and are not reported.
- A container with labels but no address on `network` is skipped with a report. This also covers a container that only sits on another network.
- All containers of one app and revision are the servers of its services.
- The containers of one revision must agree on their routing (routers, middlewares, transports, TLS), their services and the revision state. The oldest container (by creation time, then name) is the reference; one that differs is left out and reported.
- The routing of the app (routers, middlewares, transports, TLS) comes from the newest serving revision, or the newest revision when none serves, so during a rolling deploy the old containers may carry older labels. Every revision contributes its own services.
- Every serving or retiring revision must define the services the routers name, and the transports its services name, because a pinned session must never meet a revision without its route (`unknown_service` in the daemon). A revision that does not is left out and reported. A draining revision gets no requests and is exempt.
- All revisions get weight `1`: the weight only splits traffic between serving revisions.
- Containers of one app must belong to one tenant. One that names another is left out and reported.
- An app's `first_seen` is the creation time of its oldest container when the source first saw it, kept while the app exists, so an older app wins a host conflict.

## Tenants

| `tenant_from` | The tenant is | `podgate.tenant` |
|---|---|---|
| `fixed` | `tenant`, the operator's decision | ignored |
| `network` | the one `network_tenants` gives for the network the container is on | ignored |
| `label` | the label, honoured only for tenants that list the source in `label_sources` (`docs/ref/provider.md`); otherwise `tenant`, else the default tenant | read |

A container attached to the networks of two tenants is rejected: it must belong to one. Whatever the tenant, a container may claim only the hosts the tenant may claim (`foreign_host_claim`), so a user-set tenant label cannot take another tenant's host.

## Following the daemon

The source starts an event stream, `GET /events` filtered to container `start`, `stop`, `die`, `health_status` and `destroy`, and lists the containers (`GET /containers/json`, then `GET /containers/<id>/json` for each). It lists again:

- 50 ms after a relevant event (events inside that window share one list);
- when the stream (re)connects, because a change between the last list and the connect would otherwise wait;
- every `resync_secs`.

An event of another type, or another container action, does not cause a list. A stream that breaks reconnects with a backoff of 100 ms doubling to 5 s. The first state is sent only after a complete list succeeded.

The provider's own debounce (`debounce_ms`) then coalesces the update with the other sources' before one push.

## Reports and outages

A container that carries labels but is not used is named in an outage text sent after the state, like a broken file in the file source, and logged:

```
container shop-2 (2b0c4e91a7d3): podgate.hosts: unknown label ...; container db-1 (...): skipped: no address on podgate ...
```

The next state replaces it. A daemon that cannot be reached, answers an error or sends something unparsable is an outage too: the last state stays in force, an outage never means "no containers", and the source retries with backoff. A container that disappears between the list and its inspect is skipped, not an error. `print` and `check` run one pass and fail on an outage, so a start with the daemon down is an error there.

## Read only

The client issues `GET` and nothing else (`client.rs` has one way to send a request): list, inspect, events and networks. It cannot create, start or stop a container. Put a socket proxy that allows only these in front of the daemon when the provider does not run next to it, for example one that permits `GET /containers/*`, `GET /networks` and `GET /events` and denies the rest, so a compromised provider holds no more than read access to container metadata. `GET /networks` is advisory: when a proxy refuses it, the source only loses the "network does not exist" report.

## Rootless Podman

With rootless Podman the host has no route to container addresses (measured for podkit in `~/Projects/podkit/docs/gateway.md`: a request from the host process to a container at `10.89.0.13` timed out). A source that runs on the host would list the containers and then hand podgate addresses it cannot reach. **The provider and the podgate daemon must therefore run as containers on the container network**, the one `network` names. Rootful Docker and rootful Podman make container addresses routable from the host, and need no such arrangement.

A Quadlet layout (`~/.config/containers/systemd/`), with the image names yours:

```ini
# podgate.network
[Network]
NetworkName=podgate

# podgate.container
[Container]
Image=localhost/podgate:latest
Network=podgate.network
PublishPort=80:8080
PublishPort=443:8443
Volume=%t/podgate:/run/podgate
Environment=ADMIN_SOCKET=/run/podgate/admin.sock

# podgate-provider.container
[Container]
Image=localhost/podgate-provider:latest
Network=podgate.network
Volume=%t/podgate:/run/podgate
Volume=%t/podman/podman.sock:/run/docker.sock
Volume=%E/podgate/provider.toml:/etc/podgate/provider.toml:ro
Exec=run --config /etc/podgate/provider.toml
```

with `socket = "/run/docker.sock"` and `network = "podgate"` in the provider's `[[source]]`. Both containers share the admin socket directory, as they would share the unix socket on a host. The labelled containers join `podgate.network`. Enable `podman.socket` in the user's session (`systemctl --user enable --now podman.socket`) for the API socket.

## Not supported

- Docker Swarm (services, tasks, the ingress network): this source reads containers. Swarm is change 0108.
- Picking the port from the image's `EXPOSE`: set `podgate.port`.
- Labels that name a destination (above) and `scheme` for servers: servers are `http://`. A gRPC backend that needs `h2c://` or an HTTPS backend belongs in a file source.
- Changing labels of a running container: Docker does not allow it, so a revision changes state by recreating the container.

## Where the label parser lives

`podgate_provider::docker::labels` knows nothing about Docker; Nomad and any other source whose objects carry key-value metadata read the same keys through it:

```rust
pub fn parse<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Labels, Rejection>;
pub fn assemble(id: &str, members: &[Member<'_>]) -> Result<Assembled, Rejection>;
```

`parse` reads one object's `podgate.*` and `traefik.*` pairs (other keys are skipped) and returns the app's routing and the object's own services, or a typed `Rejection` (`unknown_label`, `invalid_label`, `address_label`, `foreign_reference`, `no_router`, `app_conflict`, and for Traefik labels `unsupported_rule` and `unsupported_label`, via `Rejection::code`). `Labels::problems` lists the Traefik labels that were left out. `assemble` takes the parsed labels of every object of one app, each with its server address and tenant claim, and returns the `App` (servers filled in from those addresses only) and the members it left out. The Docker-specific decisions (health, networks, tenants) are in `docker/apps.rs`.
