# The podgate custom resources

`PodgateRoute` and `PodgateMiddleware` let an operator write podgate's own routing in Kubernetes: routers with matcher trees, per-route middlewares, any service type, transports. They are read by the Kubernetes source of `podgate-provider` (`crates/podgate-provider/src/kubernetes/crd/`) next to Ingresses (`docs/ref/provider-kubernetes.md`). The model they mirror is `docs/architecture.md ## Snapshot model v2`.

Group `podgate.io`, version `v1alpha1`, both namespaced. Matches Traefik's `IngressRoute` and `Middleware` CRDs; Caddy has no first-party CRD. Not built: `TraefikService`, `ServersTransport` and `TLSOption` equivalents as separate kinds (a route carries its own services and transports; TLS options are `spec.tls`), and cross-namespace references (Traefik's `allowCrossNamespace`).

## Install and enable

```sh
kubectl apply --server-side -f deploy/crd/
```

`--server-side`: the manifests are large (the whole schema of every middleware kind), and client-side apply stores a copy of the object in an annotation that is capped at 256 KiB. Then set `crds = true` in the Kubernetes `[[source]]` entry of the provider:

```toml
[[source]]
kind = "kubernetes"
name = "k8s"
crds = true            # default false: read PodgateRoute and PodgateMiddleware
namespaces = ["team-a", "team-b"]
```

The default is off because a cluster without the CRDs answers `404` to the lists, which the source reports as an outage and which would hold back the state of the Ingresses too. The provider's service account needs `list` and `watch` on `podgateroutes` and `podgatemiddlewares` (group `podgate.io`) in the watched namespaces.

## `PodgateRoute`

One object becomes one app, `route_<namespace>.<name>` (the core prefixes the source name), with one revision `k8s`: Kubernetes rolls pods out through readiness, so podgate sees no revision states. The source object is `route/<namespace>/<name>` in quarantine and reports, distinct from an Ingress's `<namespace>/<name>`.

| `spec` field | Meaning |
|---|---|
| `tenant?` | A tenant label claim, as the `podgate.io/tenant` annotation of an Ingress: honoured only for tenants that list the source in `label_sources` |
| `tls?` | The model's `TlsPolicy` (`mode`, `client_ca_pem`, `challenge`, ...). Absent: `{"mode": "on_demand"}`, as for an Ingress without a Secret |
| `default_chain?` | Middlewares that run before every router's own chain |
| `routers` | The model's routers: `name`, `match` (a matcher tree), `priority?`, `entry_points?`, `chain?`, `service`, `observability?`. Not `declared_by`: provenance is the provider's to write |
| `services` | The model's services. A `loadbalancer` has `serviceRef {name, port}` in place of `servers` |
| `transports?` | The model's transports. `clientCertSecret` (the name of a `kubernetes.io/tls` Secret) takes the place of `client_cert` |
| `middlewares?` | Middlewares of this app only, inline |

Fields are the snapshot model's, in its spelling (`default_chain`, not `defaultChain`); `serviceRef` and `clientCertSecret` are the two Kubernetes-style additions. `status` is written by the status writer of change 0074 (`Accepted`, `ResolvedRefs`); the CRDs enable the `status` subresource for it.

### `serviceRef`

`{name, port}`: the Service in the route's own namespace and one of its ports, by number or by name. The servers are the ready addresses in the Service's EndpointSlices, resolved as for an Ingress backend (`docs/ref/provider-kubernetes.md`): `terminating` and unready endpoints are out, the container port of that Service port is used, and `allow_external_name` governs `ExternalName` Services. The state follows the slices with no change to the route. A Service that does not exist, a port it does not have, or a name with a `/` or a `.` rejects the whole route with the reason.

An address never comes from a manifest: `servers` on a service is rejected, by the schema at `kubectl apply` and by the translator.

### Middlewares and chains

A name in `default_chain` or in a router's `chain` is, in this order:

1. a middleware of `spec.middlewares` of the same route;
2. a `PodgateMiddleware` of the same namespace.

`<namespace>/<name>` names the `PodgateMiddleware` only, and only when the namespace is the route's own. Anything else rejects the route: a name nobody declares, a namespace that is not the route's, a `PodgateMiddleware` that cannot be read.

The daemon has no cross-app references (invariant 3 of the snapshot model), so the provider **copies** each referenced PodgateMiddleware into the app, under its plain name, and writes the plain name in the chain. A PodgateMiddleware that no route names is in no app. Changing it changes every copy.

### Tenants and hosts

As for an Ingress (`docs/ref/provider-kubernetes.md`): the namespace decides the tenant (`namespace_tenants`, `default_tenant`); the hosts a route's routers claim, including those inside `all`/`any`/`not`, must lie where that tenant may claim hosts, or the route is rejected with `foreign_host_claim`; a catch-all router of a tenant that may not have one is left out and reported, and the rest of the route is served. Two routes claiming one host conflict in the merge, as two Ingresses do.

## `PodgateMiddleware`

`spec: {type, config}`: the kind (`strip_prefix`, `headers`, ...) and the kind's own fields without `name` and `type`; the object's name is the middleware's name. `config` holds neither `name` nor `type`. The provider checks that the object is readable; the kind's fields are checked by the schema at apply and by the daemon at push.

## Samples

```yaml
apiVersion: podgate.io/v1alpha1
kind: PodgateMiddleware
metadata:
  name: strip-api
  namespace: team-a
spec:
  type: strip_prefix
  config:
    prefixes: ["/api"]
---
apiVersion: podgate.io/v1alpha1
kind: PodgateRoute
metadata:
  name: shop
  namespace: team-a
spec:
  tls:
    mode: acme
  routers:
    - name: api
      match:
        all:
          - host: shop.acme.test
          - path_prefix: /api
      chain: [strip-api]
      service: web
    - name: site
      match:
        host: shop.acme.test
      service: web
  services:
    - name: web
      type: loadbalancer
      algorithm: p2c_ewma
      serviceRef:
        name: web
        port: http
```

## Generated schema

The manifests in `deploy/crd/` are generated, not written: the schema is the daemon's `GET /v1/schema` (`docs/ref/admin-tools.md`), so a middleware that lands changes the manifest and a second description of the model cannot drift.

```sh
# from a running daemon; also saves the schema the staleness test compares with
podgate-provider print-crd --socket /run/podgate/admin.sock \
  --save-schema crates/podgate-provider/tests/fixtures/snapshot-schema.json --out deploy/crd

# from the saved schema
podgate-provider print-crd --schema crates/podgate-provider/tests/fixtures/snapshot-schema.json --out deploy/crd
```

Without `--out` both manifests go to stdout as one YAML stream. The generator is `crd/schema.rs`; its header lists the rules. The tests:

| Test | Proves |
|---|---|
| `crd_manifests_not_stale` | The committed manifests are what the generator makes of the fixture |
| `crd_manifests_match_the_daemon` | The fixture is the running daemon's schema, and `print-crd --socket` writes what is committed |
| `crd_manifests_are_structural` | The manifests follow the rules of the API server for structural schemas, and fit under the annotation cap |
| `crd_schema_validates_samples` | The sample resources, this page's included, validate |
| `crd_schema_rejects_unknown_fields` | Typos, unknown fields and kinds, addresses and keys are refused |

A new middleware or service kind therefore fails `crd_manifests_match_the_daemon` until the fixture and the manifests are regenerated in the same commit.

### What the schema checks, and what it leaves to others

A CRD schema is OpenAPI v3 in its structural form, which is less than JSON Schema:

- **Unknown fields** are rejected by the API server's strict field validation (`kubectl apply` asks for it by default since Kubernetes 1.27), because the schema declares every field and has no `x-kubernetes-preserve-unknown-fields` outside the places named below. `additionalProperties: false` cannot be written in a CRD, so the tests add it to simulate that validation. A client that asks the server to ignore unknown fields has them pruned, never stored: the provider cannot see a typo the API server removed.
- **A middleware, service or transport** is `{name, type, <the kind's fields>}`. The structural part lists the union of every kind's fields; a field two kinds describe differently is free-form there. A `oneOf` over `type` adds each kind's required fields and value limits. So `prefixs` in a `strip_prefix` fails at apply, and a missing `prefixes` does too; a field that belongs to another kind passes, and the daemon refuses it at push.
- **The matcher tree** is unrolled three levels (`all`, `any` and `not` nest) and free-form below that; every level checks that an object has exactly one key and that the key is a known matcher.
- **Free-form nodes**: a field that takes several shapes (`host` is a string or a list, `algorithm` a name or an object) is not shape-checked at apply. The daemon does that at push (`podgate-provider check`, `POST /v1/snapshot/validate`).
- **No** `format`, `pattern` or `default`: the daemon's regular expressions are Rust's and the API server's are Go's, and the daemon applies its own defaults.

## Rejections

A route that cannot be mapped is left out whole and named in the provider's outage report, `PodgateRoute <namespace>/<name> rejected: <reason>`; the other routes and Ingresses are served on. The reasons: an unreadable `spec`; `routers` empty; `declared_by` on a router; `servers` or a missing `serviceRef` on a `loadbalancer`; a Service that does not exist or lacks the port; a middleware reference that is undeclared, in another namespace or unreadable; a `client_cert` in a transport, or a `clientCertSecret` that is no `kubernetes.io/tls` Secret of the namespace; a host outside the tenant's claims.
