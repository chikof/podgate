# The Docker Swarm source

Reference for `crates/podgate-provider/src/swarm/`: the provider source that turns Docker Swarm services labelled for podgate into apps, takes servers from the addresses of their tasks on one overlay network (or from the service's virtual IP), and follows rolling updates, scaling and node loss. It matches Traefik's Swarm provider (`endpoint`, `network`, `exposedByDefault`, `refreshSeconds`, `watch`, labels on the service's `deploy.labels`) and Caddy's `caddy-docker-proxy`, which also reads Swarm service labels. Labels, tenants, trust and the upstream address policy work as for the Docker source (`docs/ref/provider-docker.md`); this page covers what Swarm changes.

Labels describe routing, never destinations. The only address that can become a server is one the engine itself assigned: a task's address on the configured overlay network, or the service's own virtual IP on it.

## Configuration

```toml
[[source]]
kind = "swarm"
name = "swarm-prod"
socket = "/var/run/docker.sock"
network = "podgate_overlay"
endpoint = "tasks"
tenant_from = "fixed"
tenant = "acme"
exposed_by_default = false
refresh_secs = 5
resync_secs = 60
```

| Key | Default | Meaning |
|---|---|---|
| `socket` | `/var/run/docker.sock` | A manager node's unix socket, or a read-only socket proxy in front of it (below). Only a manager answers the Swarm endpoints. |
| `network` | required | The overlay network podgate is attached to. A name, or a list of names; the first one a task (or service) has an address on gives its server. Network ids work too. |
| `endpoint` | `tasks` | `tasks` or `vip` (below). |
| `tenant_from` | `fixed` | `fixed`, `network` or `label`, as for Docker. |
| `tenant` | `default` | For `fixed`, the tenant of every service. For `label`, the tenant of a service that names none. Not allowed with `network`. |
| `network_tenants` | none | For `network` only: `{ "net-a" = "acme" }`. Every network in `network` needs an entry and no other network may appear. |
| `exposed_by_default` | `false` | Whether a service without `podgate.enable` counts. `podgate.enable=false` always excludes. |
| `refresh_secs` | `5` | How often the source reads the manager again. At least `1`. |
| `resync_secs` | `60` | The longest the source goes without telling the core its state again even if nothing changed. At least `refresh_secs`. |

Unknown keys are errors, so a misspelt `tenant` cannot move the source's apps to the default tenant.

## Labels come from the service

The labels are the service's own (`Spec.Labels`: `docker service create --label`, a stack file's `deploy.labels`), with the keys of the Docker source: `podgate.*`, and `traefik.*` through the translator of `docs/ref/provider-traefik.md`. The labels of the containers (`Spec.TaskTemplate.ContainerSpec.Labels`, a stack file's `labels:` under the service, or the image's `LABEL`) are never read: they are what an image author can set, while the service spec is what the deployer wrote. A service whose only `podgate.*` labels are container labels is not exposed.

The rules are the Docker source's, applied to the service:

- Any other `podgate.*` key rejects the service.
- A label that names an address, a URL, a `host:port` or a task or service (`servers`, `url`, `upstream_container`, ...) rejects the service.
- A `service`, `chain` or transport name that is not defined by the same service's labels, or that names another app (`other/web`), rejects the service. This includes the Swarm service name of another app.

A rejected service is left out and reported (below); the app of the other services is not affected.

The app id is `podgate.app`, else the Swarm service name (`shop_web` for the service `web` of the stack `shop`). Several services that name the same app contribute their tasks to it, like several containers of one Docker app, and must agree on routing and revision state. `podgate.port` is required: it is the port the tasks listen on. `podgate.revision` and `podgate.revision.state` give explicit revisions; without them every serving task of a service is one revision, so during a rolling update old and new tasks are all served until the old ones stop.

## The address rule

`endpoint = "tasks"` (default): one server per serving task, the task's address on the configured network (`NetworksAttachments`), plus the port label. podgate balances and health checks per task, and outlier detection works. The address on any other network, the ingress network included, is never used. podgate must be attached to the overlay network, or its connections to the task addresses fail.

`endpoint = "vip"`: one server, the service's virtual IP on the configured network (`Endpoint.VirtualIPs`), plus the port label. The Swarm routing mesh balances between the tasks behind it, so podgate has no per-task health check and no outlier detection in this mode, and a retry may reach the same task again. The service still needs at least one serving task; a service scaled to zero has no server instead of a dead address. A service that publishes no virtual IP (`endpoint_mode: dnsrr`) is reported, and `endpoint = "tasks"` serves it.

The virtual IP names its network by id. The source finds the id of the configured network in `GET /networks` and in the attachments of the tasks, so a socket proxy that hides `/networks` still works for services that have tasks.

An address is used only if it is the service's own task or virtual IP on a configured network, as the engine reports it. A label cannot add one.

## Which tasks serve

A task serves when its state is `running`, and its health status is `healthy` when the engine reports one (Swarm itself keeps a task in `starting` until its health check passes). Tasks that are `starting`, `preparing`, `failed`, `shutdown`, `complete` or `rejected` are not servers, quietly. The desired state is not looked at: during a rolling update an old task that has been told to stop but still runs keeps serving until it stops.

A task on a node the engine reports as anything but `ready` is not served and is reported: the tasks of a lost node keep their last state until the orchestrator replaces them, and the state alone would send traffic to an address nobody answers on. This needs `GET /nodes`; without it (below) tasks are judged by their state alone.

A serving task without an address on a configured network is left out and reported, naming the networks it is attached to.

## Tenants

As for Docker, with the service in the place of the container: `fixed` gives every service the same tenant, `network` takes it from the configured network the service has addresses on (a service on the networks of several tenants is rejected), and `label` honours `podgate.tenant` only for tenants that list the source in `label_sources`. The core refuses a host the tenant may not claim, so a service labelled with another tenant's host never reaches the snapshot. The upstream address policy is applied by the core to every task address and virtual IP.

## Following the manager

The source reads `/services`, `/tasks`, `/nodes` and `/networks` every `refresh_secs`, and subscribes to `/events` for `service` and `node` events as a hint: an event refreshes after a quiet window of 50 ms, so a burst of events is one refresh. Task changes do not raise events of their own, so a task that stops or turns healthy shows at the next poll (at most `refresh_secs`) or with the service's next event; a rolling update raises service events as it goes. Every `resync_secs` the state is told to the core again whether or not it changed.

A manager that cannot be reached (a leader election, a restart, a dead socket) keeps the last state in force and is reported as an outage; the retry delays grow from 100 ms to 5 s with jitter. A source that starts while the manager is down sends no state until one read is complete. `/services` and `/tasks` are required; `/nodes` and `/networks` are optional: an answer with an error status (a socket proxy that does not allow the path) means the source goes without that list, while a connection error is still an outage.

`Origin::first_seen` of an app is the creation time of its oldest service, as unix seconds, never the time the source first saw it.

## Reports and outages

A service or task that carries labels but cannot be used is left out and reported next to the state, as an outage text naming it (`service shop_web (4kd9...): ...`, `task shop_web.2: skipped: no address on ...`), like the Docker source does for containers. The next state clears it.

## Read only

The client only ever sends `GET`. The recommended socket proxy allows `GET` on `/services`, `/tasks`, `/networks` and `/events`, plus `/nodes` if you want tasks of lost nodes dropped at once; every other path and method stays denied. The source needs no secrets, configs, containers or volumes.

## Not supported

- Swarm jobs (`replicated-job`, `global-job`): they are not long-running servers.
- Docker's `PublishPort` ingress and `useBindPortIP`: podgate reaches tasks on the overlay network, not through the node's published ports.
- A server over `https://` or `h2c://`: labels cannot name one; a backend that needs it belongs in a file source.
- Per-task health checks and outlier detection in `vip` mode.
