# Gateway API status and leader election

Reference for `crates/podgate-provider/src/kubernetes/gateway/{status,writer}.rs` and `kubernetes/lease.rs`: the conditions the provider writes onto the Gateway API objects it serves, and the Lease that makes one replica the only writer. It extends `docs/ref/provider-gateway.md`. Traefik's Gateway API provider writes status the same way; without it `kubectl describe` and the conformance suite show nothing, and a user cannot tell an unsupported filter from a typo.

The provider runs once per node, so a cluster has many replicas. Every replica serves its own podgate from its own view of the cluster; only the status writes are leader-only.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `gateway_status` | `true` | Write status. `false` leaves the Gateway API objects untouched and starts no election. Needs `gateway_api`. |
| `lease_name` | `podgate-provider-status` | The `coordination.k8s.io/v1` Lease. |
| `lease_namespace` | the pod's namespace (`/var/run/secrets/kubernetes.io/serviceaccount/namespace`), else `default` | Where the Lease lives. Set it when the provider runs out of cluster. |

RBAC is in `docs/ref/provider-gateway.md`, `## RBAC`. Status is written only when the source runs under the engine (`podgate-provider run`); `print` and `check` write nothing. A refused write or Lease (`403`) is logged once and retried; routing is not affected.

## What is written

| Object | Written |
|---|---|
| `GatewayClass` of `gateway_class`, with `spec.controllerName: podgate.io/gateway-controller` | condition `Accepted` |
| `Gateway` of that class | conditions `Accepted`, `Programmed`; per listener `name`, `supportedKinds`, `attachedRoutes` and conditions `Accepted`, `Conflicted`, `ResolvedRefs`, `Programmed` |
| `HTTPRoute`, `GRPCRoute` naming such a Gateway | one `parents` entry per `parentRefs` entry that names a Gateway of ours, with `parentRef`, `controllerName: podgate.io/gateway-controller` and conditions `Accepted`, `ResolvedRefs` |

Every condition carries `observedGeneration` (the object's `metadata.generation`) and a `lastTransitionTime` that changes only when its `status` does. Other controllers are never touched: a route's `parents` entry whose `controllerName` is not podgate's is copied through as it is, with its position. Our entries of a `parentRef` the route no longer names, or whose Gateway is not ours any more (another class, deleted), are removed. Objects of other classes are not touched at all.

### Route parents

The reasons are the ones the translation found (`docs/ref/provider-gateway.md`).

| Situation | `Accepted` | `ResolvedRefs` |
|---|---|---|
| attached to a listener of the parent | `True`, `Accepted` | `True`, `ResolvedRefs` |
| no `sectionName` or `port` match, a listener that refuses the route (`allowedRoutes`, protocol, entry point, tenant, conflict) or host names that do not intersect | `False`, `NoMatchingParent`, `NotAllowedByListeners` or `NoMatchingListenerHostname`, with the listener's message | `True` |
| attached, but a backend does not exist, has no such port, or is a Service the source may not read | `True` | `False`, `BackendNotFound` |
| attached, but a reference crosses tenants or lacks a `ReferenceGrant` | `True` | `False`, `RefNotPermitted` |
| attached, but a backend kind is not `Service` | `True` | `False`, `InvalidKind` |
| attached, but the route says something podgate cannot (an unsupported filter, `timeouts`, a regular expression that does not compile) or its tenant may not have its routers | `False`, `UnsupportedValue` or `NotAllowedByListeners`, naming the field | `True` |
| podgate quarantined or dropped the route when it merged the snapshot | `False`, `UnsupportedValue`, `podgate rejected this route: <the daemon's reason>` | `True` |

A route with an unresolved reference is not served (the whole route is refused, `docs/ref/provider-gateway.md`, `### Backends`), though its `Accepted` is true: the API means by `Accepted` that the route is valid for the parent, and by `ResolvedRefs` that its references are. `attachedRoutes` counts the routes attached to a listener, so a route with `ResolvedRefs: False` counts and a route with `Accepted: False` does not.

### Listeners and Gateways

| Condition | Value |
|---|---|
| listener `Accepted` | `True`, `Accepted`; `False` with `UnsupportedProtocol` (not `HTTP` or `HTTPS`, or `HTTPS` without TLS termination) or `PortUnavailable` (the port has no entry point in `listener_entry_points`) |
| listener `Conflicted` | `True` with `HostnameConflict` or `ProtocolConflict`; else `False`, `NoConflicts` |
| listener `ResolvedRefs` | `True`; `False` with `InvalidRouteKinds` (`allowedRoutes.kinds` names a kind other than `HTTPRoute` and `GRPCRoute`), `InvalidCertificateRef` (not a Secret, or missing, or not `kubernetes.io/tls`) or `RefNotPermitted` (another namespace without a `ReferenceGrant`, or another tenant) |
| listener `Programmed` | see below |
| `supportedKinds` | `HTTPRoute` and `GRPCRoute` on `HTTP` and `HTTPS` listeners, narrowed by `allowedRoutes.kinds`; none otherwise |
| Gateway `Accepted` | `True`, `Accepted`; with a listener that is not usable (not accepted, in conflict or with unresolved references) `ListenersNotValid`, still `True` while another listener is usable and `False` when none is |

### Conflicts

Two listeners of one Gateway conflict when

- they share a port and a protocol family and have the same `hostname` (none counts as one), `HostnameConflict`; the families are `HTTP`, `HTTPS` and `TLS` together, `TCP`, `UDP`;
- they share a port and use protocols of different families (`HTTP` and `HTTPS`), `ProtocolConflict`; or two `TCP` (or two `UDP`) listeners share a port, also `ProtocolConflict`.

**Every** listener of a conflict is refused: `Conflicted: True`, `Programmed: False`, no route attaches to it (`NotAllowedByListeners`, the message names the conflict) and no certificate is ordered for it. The API says a conflicted listener's port must not be configured, and no listener of a conflict outranks another. Different host names on one port (including a wildcard next to an exact name) are not a conflict. The other listeners of the Gateway keep working.

### Programmed

`Programmed` says whether podgate has what the object orders. The provider learns it from the engine (`Source::observe`, which hands a source `watch::Receiver<engine::Status>`): the objects podgate **accepted** in the last snapshot it pushed (`engine::Accepted`, matched by the source's own fingerprint of each object, so an object that changed since is not accepted yet), the objects it quarantined or the merge dropped (with the reason), and why the last push failed.

| What the engine says | `Programmed` |
|---|---|
| podgate accepted the snapshot with all of the source's current objects, or left out the ones it quarantined | `True`, `Programmed` |
| podgate refused the snapshot, or the push failed, while objects of the source are not in (`podgate refused the snapshot with 400: ...`, the daemon's reason) | `False`, `Invalid`, with that text |
| a certificate of the listener was quarantined or dropped | listener `False`, `Invalid`, `podgate rejected the certificate: <reason>` |
| the listener is not usable (not accepted, in conflict, unresolved references) | `False`, `Invalid`, `the listener is not used: <why>` |
| the push is still to happen | the condition stays as it was; a new object gets `Unknown`, `Pending` |

A Gateway is `Programmed` when one of its listeners is, `False` when every listener is not. A quarantined *route* does not make a Gateway unprogrammed: the route says so on its own `Accepted`. A provider restart does not flap conditions: until the first push is judged, existing conditions stay.

One edge: the engine reports "waiting for every source to report before replacing a live snapshot" as the push's problem while it holds the first push back (up to its patience of 30 seconds). During that time a new Gateway is `False`; it turns `True` with the push.

## Patches

A patch is a JSON merge patch of the `status` subresource, `PATCH .../status` with `application/merge-patch+json`, and it carries the `metadata.resourceVersion` of the object it was computed from. Arrays (`conditions`, `listeners`, `parents`) replace the old array in a merge patch, so a patch must be computed from the version it replaces; the precondition makes the server answer `409` when someone else (another controller on a route's `parents`, a user, the leader before this one) wrote in between. The writer then waits for the object's next version from the watch and the plan is made again: no write is ever lost to a stale read, and nothing of another writer is overwritten.

Server-side apply was the alternative. The spec asks for merge patches, they need one verb (`patch`), and the precondition plus copying other controllers' `parents` entries through gives the same safety without depending on how a CRD version declares its list keys.

The writer does the rest:

- **Skipped when nothing changed.** The plan holds only the objects whose status differs from what the watch last showed (every field the plan writes is compared). A resync, a bookmark, an engine update that changes no condition, writes nothing.
- **Rate limited and coalesced.** At most one patch per object per second. The planner replaces the whole list of pending patches whenever something changes; a patch overtaken before it is sent is never sent, and after a patch the newest plan for that object goes out one second later. Seven changes within a second give two patches, the second carrying the last generation.
- **Never the same patch twice.** A patch is the same until the object's version changes, so a slow watch does not cause repeats. After a `409` the writer waits for the new version; after any other failure it retries after five seconds.
- **Leader only.** Before every patch the writer asks the elector whether this replica holds the lease at that moment. See below.

## Leader election

A `coordination.k8s.io/v1` Lease (`lease_name` in `lease_namespace`) elects the writer; the protocol is client-go's:

| Timing | |
|---|---|
| lease duration | 15 s |
| renew deadline | 10 s |
| retry period | 2 s |

Every 2 seconds each replica reads the Lease. If it holds it, it renews (`renewTime` now). If nobody holds it (empty `holderIdentity`, or no Lease: the first replica creates it), or the record has not changed for 15 seconds *measured on the reader's own clock from when it first saw that record* (another node's clock is never trusted), it takes it over: `holderIdentity` is its identity, `leaseTransitions` plus one, `acquireTime` now. Every write carries the Lease's `resourceVersion`, so two replicas racing for a free Lease get one `409`. Identity is the pod's `HOSTNAME` and a random suffix.

The leader counts as leader for 10 seconds after each successful renewal, never longer. **A lost lease stops writes at once**: the writer checks that deadline before every patch, so a leader that cannot reach the API server, or whose elector is stuck, stops writing when the deadline passes without anybody telling it; a leader that sees another holder stops within the retry period. Ten seconds is shorter than the 15 a candidate waits, so no other replica can have taken the lease while this one still believes it holds it. The Lease is not released at shutdown: a replacement takes over after at most 15 seconds, and status stays as the last leader left it.

Nothing else is leader-only: every replica watches, translates and pushes for its own podgate. A replica that is not the leader computes the same plans and sends them nowhere.

## Not built

The Ingress status address; `TLSRoute`, `TCPRoute` and `UDPRoute` status; status conditions `PartiallyInvalid` and the `Gateway.status.addresses`; `BackendTLSPolicy` status; a Lease released at shutdown.
