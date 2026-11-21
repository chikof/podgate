# The Gateway API source

Reference for `crates/podgate-provider/src/kubernetes/gateway`: the half of the Kubernetes source that implements the HTTP part of the Gateway API. It accepts the `Gateway`s of its class, attaches `HTTPRoute`s and `GRPCRoute`s to their listeners and translates matches, filters and weighted backends into podgate routers, middlewares and services. It matches Traefik's Kubernetes Gateway provider (an experimental feature there, `gatewayClass`, HTTPRoute and GRPCRoute with the supported filters). Caddy has no first-party Gateway API controller. The client, the Ingress mapping, tenancy and RBAC of the Kubernetes source are in `docs/ref/provider-kubernetes.md`; status written back to the cluster is change 0074, TLSRoute, TCPRoute and UDPRoute are change 0075.

## Configuration

```toml
[[source]]
kind = "kubernetes"
name = "k8s"
gateway_api = true
gateway_class = "podgate"

[source.listener_entry_points]
80 = "web"
443 = "websecure"
```

| Key | Default | Meaning |
|---|---|---|
| `gateway_api` | `false` | Read Gateway API objects. Off by default: a cluster without the Gateway API CRDs answers `404` to every list, which would keep the first state from ever being sent. |
| `gateway_class` | `podgate` | The `GatewayClass` whose Gateways are served. Needs `gateway_api`. |
| `listener_entry_points` | `80 = "web"`, `443 = "websecure"` | Listener port to podgate entry point. Needs `gateway_api`. The node binds ports, so a listener names the entry point of its port; a port with no entry point makes the listener unusable and the routes that name it are rejected, with the reason `port N has no entry point; add it to listener_entry_points`. |

`namespaces`, `namespace_tenants`, `default_tenant` and the client settings are the Kubernetes source's own. A `GatewayClass` called `gateway_class` must exist with `spec.controllerName: podgate.io/gateway-controller`. Without it (or with another controller name) no Gateway is served and no route is reported: the class is somebody else's.

A Gateway of another class is ignored entirely: its routes are neither served nor reported, and a route with a `parentRef` to it is not ours.

## Attachment

A Gateway of the class produces nothing by itself. A route attaches to a **listener** when all of these hold; a route that attaches to none is rejected with the reason of each parent.

| Condition | Rejection reason |
|---|---|
| a `parentRefs` entry names the Gateway, and the listener by `sectionName` or `port` when it does | `NoMatchingParent` |
| the listener's protocol is `HTTP`, or `HTTPS` that terminates TLS, and its port has an entry point | `NotAllowedByListeners` |
| `allowedRoutes.kinds` (default: `HTTPRoute` and `GRPCRoute`) lists the route's kind | `NotAllowedByListeners` |
| `allowedRoutes.namespaces.from` is `All`, or `Same` (the default) and the route is in the Gateway's namespace, or `Selector` and the namespace's labels match | `NotAllowedByListeners` |
| the route's host names intersect the listener's `hostname` | `NoMatchingListenerHostname` |
| the tenant of the route's namespace may use the listener's entry point | `NotAllowedByListeners` |

A route with no `hostnames` inherits the listener's `hostname`. Otherwise each route host name is intersected with the listener's: equal names, an exact name inside the other's wildcard, or the more specific of two wildcards, which is the result; a route host name that intersects nothing drops out. With neither, the route has no host and is a catch-all (below). A route attached to several listeners becomes one set of routers per distinct host name list, each on the entry points of the listeners that share it.

**Wildcards are one label.** The Gateway API's `*.example.com` also covers `a.b.example.com`; podgate's wildcard covers exactly one label (`docs/architecture.md`, `### Snapshot model v2`). The translation keeps podgate's rule, so a wildcard route matches fewer hosts than the API says, never more. Write the deeper names out when they matter.

### Tenancy on the listener

The tenant of a route is the tenant of its namespace (`namespace_tenants`, else `default_tenant`). `exclusive_entry_points` of a tenant (`docs/ref/provider.md`) is how an operator reserves a listener port: a route of another tenant on an entry point exclusive to a tenant is rejected (`entry_point_forbidden`). The merge's rules apply to every route before it is sent: a host the tenant may not claim rejects the route (`foreign_host_claim`), a route with no host of a tenant without `catch_all` and no exclusive entry point has its routers left out (`catch_all_not_allowed`, the route is rejected when none is left). Tenant labels in annotations are not read for Gateway API objects.

## What a route becomes

One route is one app. Its id is `httproute_<namespace>_<name>` or `grpcroute_<namespace>_<name>` (the `_` is one no namespace has, so no Ingress app, `<namespace>.<name>`, can share an id), its object is `HTTPRoute/<namespace>/<name>`, and it has the one revision `k8s`. `first_seen` is the route's creation time.

Each **match** of each **rule** is its own router, named `r<rule>m<match>` (plus `g<group>` when the route attaches with different host names). The matches of a rule are alternatives with the same service and chain, which is `any`; separate routers give each match its own precedence. A duplicate match is dropped (the first serves).

### HTTPRoute matches

| `matches[]` | podgate |
|---|---|
| no match at all, or no `path` | `{"path_prefix": "/"}` |
| `path` `Exact` | `{"path": p}` |
| `path` `PathPrefix` | `{"path_prefix": p}`. The API's element-wise prefix is podgate's whole-segment prefix; a trailing `/` is ignored by both. |
| `path` `RegularExpression` | `{"path_regexp": "^(?:re)$"}`: **anchored**. The API leaves regular expressions to the implementation; the Traefik rules of change 0071 are unanchored, these are not. The expression must compile (Rust `regex`, linear time, no look-around), else the route is rejected. |
| `headers` `Exact` / `RegularExpression` | `header` / `header_regexp` (anchored). Several entries with one name: the first counts (the API). |
| `queryParams` `Exact` / `RegularExpression` | `query` / `query_regexp` (anchored) |
| `method` | `{"method": "GET"}` |

The leaves of one match, and the host, are an `all`.

### GRPCRoute matches

A gRPC call is an HTTP/2 `POST` to `/<service>/<method>`, so every match carries a `content-type` leaf that accepts `application/grpc`, `application/grpc+proto` and the like, never `application/grpc-web`.

| `matches[].method` | podgate |
|---|---|
| `Exact` service and method | `{"path": "/<service>/<method>"}` |
| `Exact` service only | `{"path_prefix": "/<service>"}` |
| `Exact` method only | `{"path_regexp": "^/[^/]+/<method>$"}` |
| `RegularExpression` | `{"path_regexp": "^/(?:<service>)/(?:<method>)$"}`, a missing part is `[^/]+` |
| none | the content-type leaf alone |
| `headers` | as for HTTP |

The plain `http://` servers of a GRPCRoute backend become `h2c://`: gRPC needs HTTP/2 and a Service port without `appProtocol` carries it as prior-knowledge HTTP/2, like `appProtocol: kubernetes.io/h2c`.

### Filters

| Filter | podgate |
|---|---|
| `RequestHeaderModifier`, `ResponseHeaderModifier` | a `headers` middleware: `set` overwrites, `remove` removes. **`add` refuses the route**: podgate cannot append to a header. The names `headers` refuses (`Host`, framing and connection headers, `Proxy-*`) refuse the route here, and so does a name repeated. |
| `RequestRedirect` | `redirect_scheme` when only the scheme (and port) change; else `redirect_regex` over the request URL, keeping what is not set (the host, the port when the scheme is not set, the path, the query). `statusCode` 301 is `permanent`, 302 (the default) is not. |
| `URLRewrite` `ReplaceFullPath` | `replace_path` |
| `URLRewrite` `ReplacePrefixMatch` | `replace_path_regex`: `^<prefix>(?P<rest>/.*)?$` to `<new>${rest}`, which keeps `/foo` to `/bar`, `/foo/x` to `/bar/x` and `/foo/` to `/bar/` (a `strip_prefix` and an `add_prefix` would turn `/foo` into `/bar/`). The prefix is the one of the match, so every match of the rule must be a `PathPrefix`; the middleware is made per match. |
| `URLRewrite` `hostname` | **refuses the route**: podgate sends the client's `Host` upstream. |
| `RequestMirror` | a `mirroring` service around the rule's service, `mirror_body: true`; `percent` or `fraction` (`numerator/denominator`, to four decimals), 100 when neither. A mirror is HTTP/1.1, so a gRPC mirror or an `h2c` target refuses the route. |
| `ExtensionRef` | refuses the route until the podgate `Middleware` object exists. |

The filters of a rule run in the order they are written. Each filter type may appear once in a rule (`RequestMirror` and `ExtensionRef` may repeat), `RequestRedirect` and `URLRewrite` do not mix, and a gRPC route has no redirect or rewrite. These status codes of redirect differ from the API in one way: podgate answers a method other than `GET` with `307` or `308` so that a client does not replay a `POST` as a `GET` (`docs/ref/mw-redirect.md`).

### Backends

`backendRefs` are Services of the core group with a port. Each becomes a `loadbalancer` service `<namespace>.<service>.<port>` whose servers are the ready pod addresses of the Service's EndpointSlices, exactly as for an Ingress (`docs/ref/provider-kubernetes.md`, `### Servers`; `allow_external_name` applies too). One backend with a weight above 0 is the rule's service; several are a `weighted` service `r<rule>-split` with their weights. A **weight of 0** sends nothing and the backend is not declared. A rule with no backend that can take a request, and no redirect, answers `500`, as the API says (`respond`, service `none`, which has no server).

A backend that does not exist, has no such port or belongs to a Service the source may not read **rejects the route**, naming it (`BackendNotFound`). The API would instead send that backend's share of requests a `500` and keep the rest; a rollout that creates its Service after its route would see none of it served here until the Service exists. A `backendRefs[].filters` entry refuses the route (podgate has chains per router, not per backend).

### Refused, never ignored

Everything the API lets a route say that podgate cannot say rejects the route with `UnsupportedValue` and a message that names the field: rule `timeouts`, `sessionPersistence` and `retry`, a filter or match type outside the lists above, a backend kind that is not `Service`, and a path or header value podgate cannot send. The routes that are rejected are named in the source's outage report (`HTTPRoute team-a/shop rejected: UnsupportedValue: rules[0].timeouts is not supported`), and the rest keeps being served. `translate` returns the report of every route that names a Gateway of ours, with the reason of each `parentRefs` entry, for the status that change 0074 writes.

## Precedence

The Gateway API orders what can answer one request; podgate orders routers by `priority` first, so the translation computes an explicit `priority` per router and never relies on podgate's own tuple. The order, most specific first:

1. the host name: exact, then wildcard (a longer suffix first), then none;
2. the path: `Exact`, then `RegularExpression`, then `PathPrefix` by length (the API leaves regular expressions open, and a regular expression that always lost to a `/` prefix would never run);
3. a `method`;
4. more header matches;
5. more query matches;
6. the older route, then `namespace/name`; within a route the rule written first, then its first match.

A `GRPCRoute` compares the characters of the service, then of the method, then the headers; every gRPC match counts its content-type leaf as a header match, so it beats a plain HTTP match of the same path.

Priorities are `n` down to `1` per **tenant**, over all of its routers. The numbers of one tenant do not depend on any other tenant's routers, so no tenant can outrank another through a priority (`docs/architecture.md`, `### Priority, ambiguity and conflicts`). A host-first order differs from the API in one case: the API picks the most specific host name's routes only, while podgate falls through to the next router when none of those matches.

## Certificates

`tls.certificateRefs` of an `HTTPS` listener are read like Ingress Secrets (`docs/ref/provider-kubernetes.md`, `### Certificates`): a `kubernetes.io/tls` Secret becomes a certificate of the Gateway's tenant. Its hosts are the listener's `hostname`, or, without one, the host names that accepted routes of the Gateway's own tenant use on the listener. An `HTTPS` listener with no `certificateRefs` orders nothing up front: certificates come on demand when the ACME broker allows it. A problem with one certificate (a missing Secret, another type, hosts the tenant may not claim) is reported in the outage text and leaves the Gateway and its routes alone. Secret values are never put in a log line.

## Cross-namespace references

A `backendRef` or a certificate reference into another namespace needs a `ReferenceGrant` in the target namespace that allows the referrer's kind (`HTTPRoute`, `GRPCRoute` or `Gateway`) from the referrer's namespace to the target's kind and, when it names one, its name. **And** the target's namespace must belong to the same tenant as the referrer's: a grant to another tenant's namespace is refused (`RefNotPermitted`, "a reference never crosses tenants, with a ReferenceGrant or without"). Tenancy is structural; a grant is only the owner's consent inside a tenant.

## RBAC

On top of `docs/ref/provider-kubernetes.md`, cluster-wide, read-only:

```yaml
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gatewayclasses", "gateways", "httproutes", "grpcroutes"]
  verbs: ["list", "watch"]
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["referencegrants"]
  verbs: ["list", "watch"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["list", "watch"]
```

`gatewayclasses` and `namespaces` are cluster-scoped, so `gateway_api` needs a `ClusterRole` for them whatever `namespaces` says; the namespaced kinds follow `namespaces` as usual. The Gateway API CRDs (standard channel: `GatewayClass`, `Gateway`, `HTTPRoute`, `GRPCRoute` at `v1`, `ReferenceGrant` at `v1beta1`) must be installed.

## Not built

Status of Gateways and routes and leader election; `TLSRoute`, `TCPRoute` and `UDPRoute`; `ExtensionRef` and the podgate objects; `BackendTLSPolicy`; listener conflict detection (two listeners that overlap are both used); the Gateway API's `500` for a single unresolvable backend of a weighted set.
