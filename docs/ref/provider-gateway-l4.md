# Gateway API L4 routes

Reference for the experimental Gateway API routes `TLSRoute`, `TCPRoute` and `UDPRoute` in `crates/podgate-provider/src/kubernetes/gateway/{l4,tlsroute,tcproute,udproute}.rs`. They are the L4 half of the Gateway API source (`docs/ref/provider-gateway.md`): one Gateway can expose raw TCP, TLS (passthrough or terminated) and UDP backends next to its HTTP listeners. They become the `tcp` and `udp` routers and services of `docs/ref/l4-tcp.md`, `docs/ref/l4-tls.md` and `docs/ref/l4-udp.md`. Matches Traefik's Gateway API provider, which serves `TLSRoute` and `TCPRoute`; Caddy has no Gateway API provider.

Everything that holds for an `HTTPRoute` holds here too unless this page says otherwise: attachment (`parentRefs`, `allowedRoutes` kinds and namespaces, listener host names), tenancy, `ReferenceGrant`s for backends in other namespaces (the referring kind is the route's own: `TLSRoute`, `TCPRoute` or `UDPRoute`), the status writer and the leader election of `docs/ref/provider-gateway-status.md`, and the rule that what podgate cannot say rejects the route with a reason.

## Which CRDs

| Kind | API version | Channel |
|---|---|---|
| `TLSRoute` | `gateway.networking.k8s.io/v1` | standard since Gateway API 1.5 |
| `TCPRoute` | `gateway.networking.k8s.io/v1alpha2` | experimental |
| `UDPRoute` | `gateway.networking.k8s.io/v1alpha2` | experimental |

A cluster that does not install a kind answers `404` to its list. The source then treats the kind as empty: it is not held back (the first state is sent without waiting for it), nothing is reported, and the kind is not watched. It asks again after the client's longest retry delay (30 seconds), so a CRD installed later is picked up without a restart, and routes of a kind whose CRD is removed leave the snapshot. `HTTPRoute`, `GRPCRoute`, `Gateway` and `GatewayClass` stay required: a cluster without them is an outage, as before.

A cluster that serves `TLSRoute` only as `v1alpha2` or `v1alpha3` (Gateway API 1.4 and older) has no `v1`: its `TLSRoute`s are not seen, silently, like any kind whose CRD is missing. Upgrade the CRDs to 1.5.

## Listeners

The port of a listener maps to an entry point through `listener_entry_points`, as for HTTP listeners (`docs/ref/provider-gateway.md`). A route attaches to a listener of the protocol it is made for:

| Listener `protocol` | Route | `supportedKinds` |
|---|---|---|
| `TLS`, `tls.mode: Passthrough` | `TLSRoute` | `TLSRoute` |
| `TLS`, `tls.mode: Terminate` (the default) | `TLSRoute` | `TLSRoute` |
| `TCP` | `TCPRoute` | `TCPRoute` |
| `UDP` | `UDPRoute` | `UDPRoute` |
| `HTTP`, `HTTPS` | `HTTPRoute`, `GRPCRoute` | both |

A route of another kind that names the listener is rejected (`NotAllowedByListeners`, "the protocol carries no TCPRoute"), and `allowedRoutes.kinds` naming a kind the listener's protocol does not carry makes the listener's `ResolvedRefs` false (`InvalidRouteKinds`).

**An entry point of its own.** podgate does not share an HTTP or HTTPS entry point with TLS, TCP or UDP routers (change 0060 built a front that read the ClientHello first and measured 40 to 46 percent more CPU per request, so it refused the design). A `TLS`, `TCP` or `UDP` listener whose port maps to the entry point of an `HTTP` or `HTTPS` listener of any Gateway of the class is therefore not used: its `Accepted` condition is false with the reason `PortUnavailable`, and its routes are rejected with the reason in their parent status. This is the Gateway API's "HTTPS and TLS passthrough on one port, told apart by host name" arrangement, which podgate does not offer: give the TLS listener a port of its own and map it to a `tcp` entry point. Whether the entry point is of the right protocol (`tcp` for `TLS` and `TCP`, `udp` for `UDP`) is the daemon's check (`entry_point_protocol`); a snapshot it refuses shows in `Programmed` and in the route's `Accepted` condition as for any quarantined object.

## What a route becomes

One route is one app, as for an `HTTPRoute`: its id is `tlsroute_<namespace>_<name>` (`tcproute_…`, `udproute_…`), its object `TLSRoute/<namespace>/<name>`, and `first_seen` is the route's `metadata.creationTimestamp` (0 when it has none). The app has a `tcp` or a `udp` section and no HTTP router.

| Route | Router |
|---|---|
| `TLSRoute`, `Passthrough` | `tcp.routers[]` with `match {sni}` over the route's host names and `tls {passthrough: true}` |
| `TLSRoute`, `Terminate` | the same with `tls {}`, and the listener's certificates (below) |
| `TCPRoute` | `tcp.routers[]` with no `match` and no `tls`: every connection of the entry point |
| `UDPRoute` | `udp.routers[]`: the one router of the entry point |

A router is named `r<n>`; a route attached through listeners that differ in host names or in TLS mode gets one router for each and lists the entry points of all listeners with the same names and mode.

**One rule.** A rule of these routes has no match, so rules cannot be told apart. A route with several rules is rejected (`UnsupportedValue`); a route with no rule or no backend is accepted and gets no router, so the daemon closes the connections it gets no route for.

### Host names

A `TLSRoute`'s `hostnames` are the `sni` leaf, intersected with the listener's `hostname` exactly as for an `HTTPRoute`; a route with none inherits the listener's. They are claims like `host` names (`docs/ref/l4-tls.md`, who may claim a name): the tenant of the route's namespace must own them, otherwise the route is rejected with `foreign_host_claim`. A name nobody else may claim is what keeps tenant A's router from receiving tenant B's connections in passthrough, where no certificate is involved.

podgate's wildcard covers one label (`docs/ref/provider-gateway.md`); the Gateway API's covers any depth. As for HTTP, a wildcard route matches fewer names than the API says, never more.

### Catch-all routes and tenants

A `TCPRoute` takes every connection of its entry point, and so does a `TLSRoute` that names no host. That needs an entry point reserved to the route's tenant (`exclusive_entry_points`, `docs/ref/provider.md`) or the tenant's `catch_all` allowance; otherwise the route is rejected with `catch_all_not_allowed`. A `UDPRoute` has no match either and needs a reserved entry point, which the daemon requires (`entry_point_forbidden`). A route of a tenant other than the one an entry point is reserved to is rejected with `entry_point_forbidden`, whatever `allowedRoutes` says. A TLS route with literal host names can share a `tcp` entry point between tenants.

### Backends

`backendRefs` name Services; the servers are the ready endpoints of the Service's EndpointSlices (`docs/ref/provider-gateway.md`), as plain `address:port`. The Service port must be of the protocol of the route (`TCP` for `TLSRoute` and `TCPRoute`, `UDP` for `UDPRoute`); `appProtocol` is not read. An `ExternalName` Service is a DNS name and needs `allow_external_name`; it is refused for `UDPRoute`, whose servers are IP literals only. Backend filters, other kinds and cross-namespace references without a `ReferenceGrant` are rejected as for HTTP.

The daemon has no weighted L4 service (`docs/ref/l4-tcp.md`: a TCP or UDP service is a `loadbalancer` only), so the backends become **one** `loadbalancer` over the servers of every backend with a weight above 0 and at least one ready endpoint. A backend of weight `w` with `n` servers gives each `w / n`, scaled to whole numbers and reduced, so every backend gets the share its weight says however many endpoints it has:

| Backends | Service |
|---|---|
| one backend, or equal weight per server | `round_robin`, no weights |
| other proportions, `TLSRoute` and `TCPRoute` | `algorithm: weighted_round_robin` and a `weight` per server |
| other proportions, `UDPRoute` | rejected (`UnsupportedValue`): a UDP service has no weights |

A backend with no ready endpoint gives up its share to the others (HTTP routes answer `500` for it; L4 has nothing to answer with); with no endpoint at all the connections are closed. The same address named twice adds up. More than 256 servers are rejected.

### Certificates of a terminating listener

A `TLS` listener in mode `Terminate` takes `certificateRefs` as an `HTTPS` listener does: the same Secret rules, `ReferenceGrant`s, tenant check and `Origin` (`Gateway/<namespace>/<name>#<listener>-<index>`), and the certificate holds the host names the accepted routes use on the listener, or the listener's `hostname`. A bad reference makes the listener's `ResolvedRefs` false. A terminating router presents only certificates for names its tenant claims (`docs/ref/l4-tls.md`).

## Conflicts

One TCP entry point carries one catch-all router, one UDP entry point carries one router, and one TLS entry point carries one router for each server name; the daemon refuses a second (`route_ambiguity`) and does not keep the one the Gateway API keeps. The translation settles it first: the **oldest** route wins (`metadata.creationTimestamp`, then the first `namespace/name`) and the others are rejected with the reason `NotAllowedByListeners` and a message that starts with `route_ambiguity` and names the winner. Their parent is still attached, so the route's `Accepted` condition is false and its listener does not count it in `attachedRoutes`. Two `TLSRoute`s conflict only for the same name; `a.example.com` and `*.example.com` are different claims and coexist, the exact one ranking first as in the daemon.

## Status

L4 routes report through the writer of `docs/ref/provider-gateway-status.md`: the same `Accepted` and `ResolvedRefs` conditions per `parentRef`, the same `Programmed` of the listeners, written by the elected replica only. `supportedKinds` of a listener lists the kind of its protocol. A route the daemon quarantines (for instance a terminating router with no certificate it accepts) has `Accepted` false with `UnsupportedValue` and the daemon's reason.

## Not built

Several rules per route; backend weights of a UDP service (it has none); HTTPS and TLS passthrough on one port; `TLSRoute` through `v1alpha2` or `v1alpha3` on clusters older than Gateway API 1.5; SCTP.
