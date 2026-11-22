# The Kubernetes source

Reference for `crates/podgate-provider/src/kubernetes`: the provider source that turns `networking.k8s.io/v1` Ingresses into routers and the pod addresses in their Services' EndpointSlices into servers, and follows the cluster live. It matches Traefik's Kubernetes Ingress provider (`ingressClass`, `allowExternalNameServices`, the `router.*` annotations) and Caddy's `caddy-ingress-controller`. The Gateway API is `docs/ref/provider-gateway.md` and its status and leader election `docs/ref/provider-gateway-status.md`; both build on the client described at the end.

## Configuration

```toml
[[source]]
kind = "kubernetes"
name = "k8s"
kubeconfig = "/etc/podgate/kubeconfig"
context = "prod"
namespaces = ["team-a", "team-b"]
ingress_class = "podgate"
default_tenant = "acme"
allow_external_name = false

[source.namespace_tenants]
team-a = "acme"
team-b = "globex"
```

| Key | Default | Meaning |
|---|---|---|
| `kubeconfig` | the pod's service account | Path of a kubeconfig. Without it the source reads `KUBERNETES_SERVICE_HOST` and `_PORT` and the token and CA under `/var/run/secrets/kubernetes.io/serviceaccount`. |
| `context` | the file's `current-context` | Which context of the kubeconfig. Needs `kubeconfig`. |
| `namespaces` | all | The namespaces watched, one watch per kind and namespace (so a `Role` per namespace is enough). A name listed twice counts once. Empty is an error: leave the key out for all. |
| `ingress_class` | `podgate` | Only Ingresses of this class are used. |
| `namespace_tenants` | none | Namespace to tenant. The operator's decision; every tenant must exist in the provider configuration. |
| `default_tenant` | none | The tenant of a namespace not listed above. With neither, the object belongs to the provider's default tenant. Must exist. |
| `gateway_status` | `true` | With `gateway_api`: write the Gateway API status back, from the replica that holds the Lease. See `docs/ref/provider-gateway-status.md`. |
| `lease_name` | `podgate-provider-status` | The `coordination.k8s.io` Lease that elects the status writer. Needs `gateway_api` and `gateway_status`. |
| `lease_namespace` | the pod's namespace, else `default` | The Lease's namespace. Needs `gateway_api` and `gateway_status`. |
| `allow_external_name` | `false` | Serve `ExternalName` Services and slices not written by the Kubernetes controller; see Refusals. |

Unknown keys are errors, and so is a tenant that is not configured: a misspelt name must not move a namespace to another tenant. A kubeconfig that cannot be used stops the provider at start with the file and the reason.

The kubeconfig is read once. Supported credentials: `token`, `tokenFile` (read again on every request, so a rotated service account token is picked up), and a client certificate and key (`client-certificate(-data)`, `client-key(-data)`). The cluster needs `certificate-authority` or `certificate-authority-data`; the API server's certificate is always verified. These are refused at start, never ignored: `insecure-skip-tls-verify`, `proxy-url`, `tls-server-name`, `exec` plugins, `auth-provider`, basic authentication. A plain `http://` server is accepted on a loopback address only (`kubectl proxy`), so a token never crosses a network in clear text. TLS is rustls; there is no OpenSSL.

## What an Ingress becomes

One Ingress is one app, id `<namespace>.<name>` (the core prefixes the source name), object `<namespace>/<name>`, with one revision `k8s`. Kubernetes performs rollouts through readiness, so the source produces no revision states. `first_seen` is the Ingress's `creationTimestamp`, which decides which of two conflicting objects is the older one.

| Ingress | podgate |
|---|---|
| `rules[].host`, exact or `*.` wildcard (one label, as in Kubernetes) | `{"host": ...}`; the name is lower-cased |
| `Exact` path | `{"path": p}` |
| `Prefix` path | `{"path_prefix": p}`. Kubernetes matches a prefix element by element (`/foo` matches `/foo/bar`, not `/foobar`; a trailing `/` is ignored), which is podgate's whole-segment rule. The test `ingress_prefix_semantics_match_k8s` proves it against the real daemon. |
| `ImplementationSpecific` | `path_prefix`, or `path_regexp` with `podgate.io/path-type: regexp` (unanchored, as every podgate regular expression) |
| empty `path` | `/` |
| `defaultBackend` | a host-less `{"path_prefix": "/"}` router named `default` at the lowest priority (`i32::MIN`), so every rule of the tenant goes first |
| rule without `host` | the path matcher alone |
| `backend.service {name, port}` with a port number or a port name | a `loadbalancer` service `<service>.<port>` whose servers are the ready addresses below |
| `tls[].secretName` | a certificate (below); the app's `tls.mode` is `acme`, or the annotation's |

A router is named `r<rule>p<path>`. A second rule and path that would produce an identical matcher is skipped (the first wins, as in Kubernetes; a duplicate would be an ambiguity podgate refuses).

### Servers

The only source of an address is the EndpointSlices of the backend Service, in the Ingress's own namespace. An Ingress has no field that names an address and none is read from an annotation: a namespace member must not be able to aim podgate at any pod of the cluster.

- The slices of a Service are the ones labelled `kubernetes.io/service-name`. Only slices the Kubernetes controller wrote (`endpointslice.kubernetes.io/managed-by: endpointslice-controller.k8s.io`) count: anyone who may write EndpointSlices can fill a hand-made one with any address.
- A backend names a port by number (the Service's port) or by name. The source finds the Service port, then the slice port with the same name (slices key their ports by the Service port's name, and carry the container port), so each slice may use its own container port, as during a rollout that changes it. Only TCP ports. `appProtocol` unset or `http` gives `http://`, `kubernetes.io/h2c` gives `h2c://`; any other value rejects the Ingress.
- Only `IPv4` and `IPv6` slices; `FQDN` slices are ignored. An endpoint serves when `conditions.ready` is not `false` (nil means ready, as the API documents) and `conditions.terminating` is not `true`. A terminating pod drops out as soon as its slice says so, before it is gone.
- Servers are sorted and deduplicated, so a state changes only when the set does. A Service with no ready endpoint has no servers: that is a normal state (scaled to zero, rolling), not an error; the daemon answers `503`, or wakes a `scale_to_zero` app.
- Every address that reaches a snapshot still passes the operator's upstream policy in the merge (`docs/ref/upstream-policy.md`): an address it refuses drops that Ingress's app with `upstream_forbidden` (naming the Ingress), not the others. Cluster pod ranges are private addresses; the built-in deny list leaves them alone, but an operator with an `allow` list must list the pod range.

### Certificates

`spec.tls[]` with a `secretName` reads the `kubernetes.io/tls` Secret of the Ingress's namespace (`tls.crt` and `tls.key`, base64 as the API sends them) into a certificate for `hosts` (empty means the Ingress's rule hosts). A certificate's object is `<namespace>/<name>#tls-<index>`, its tenant the Ingress's, and the merge applies the same host rule to it as to routes. A renewed Secret reaches the next state.

The source asks the API server only for Secrets of type `kubernetes.io/tls` (`fieldSelector=type=kubernetes.io/tls`), so no other Secret of the cluster ever reaches the provider's memory. A Secret that is missing, of another type, or without `tls.crt` or `tls.key` rejects only the Ingress that names it; the report says `no Secret <ns>/<name> of type kubernetes.io/tls (it is missing, or has another type)`. Secret values are never put in a log line, a message or a `Debug` output.

Without a Secret the hosts are ordered when the snapshot is pushed: the app's mode is `acme`, as Traefik's certresolver and Caddy's automatic HTTPS do, so the first visitor never waits on issuance. `podgate.io/tls: on_demand` orders a host only when a handshake asks and the ACME broker approves it (`docs/ref/provider-acme.md`), for hosts that may never get traffic, such as previews, so they never spend the CA's rate limits.

The exception is a wildcard rule host (`*.example.com`) that no Secret of the Ingress names: the mode stays `on_demand`, because HTTP-01 cannot prove a wildcard and the daemon refuses an `acme` app claiming one (`wildcard_needs_dns01`, `docs/ref/acme-dns01.md`). Each name under the wildcard is then ordered on its first handshake. The Ingress source cannot choose the DNS-01 challenge, so a wildcard certificate for an Ingress comes only from a Secret.

## Annotations

| Annotation | Effect |
|---|---|
| `podgate.io/tenant` | A tenant label claim; honoured only for tenants that list this source in `label_sources` (`docs/ref/provider.md`), otherwise the namespace's tenant stays and the merge reports `label_ignored` |
| `podgate.io/entry-points`, `traefik.ingress.kubernetes.io/router.entrypoints` | Comma-separated entry point names for every router |
| `podgate.io/priority`, `traefik.ingress.kubernetes.io/router.priority` | The routers' `priority`, a 32-bit integer |
| `podgate.io/middleware.<name>` | A middleware of the app, as JSON `{"type": "...", ...}` (a name inside must match) |
| `podgate.io/chain` | Comma-separated middleware names run on every router, in order |
| `podgate.io/tls: acme\|on_demand`, `traefik.ingress.kubernetes.io/router.tls.certresolver` | The certificate mode of hosts without a Secret (a Traefik resolver name means `acme`) |
| `podgate.io/path-type: regexp` | `ImplementationSpecific` paths are regular expressions |
| `traefik.ingress.kubernetes.io/router.tls` | Accepted and ignored: TLS follows `spec.tls` |
| `kubernetes.io/ingress.class` | The class, when `spec.ingressClassName` is unset (the spec field wins when both are set) |

Every other `podgate.io/*` annotation rejects the Ingress, and so does every other `traefik.ingress.kubernetes.io/*` one. A middleware, redirect or authentication that is silently ignored would publish the service without the protection the manifest asks for. Annotations of other controllers (`nginx.ingress.kubernetes.io/*`, `kubectl.kubernetes.io/*`) are not podgate's business and are ignored.

## Tenancy and refusals

The tenant is the namespace's (`namespace_tenants`, else `default_tenant`, else the provider's default tenant). The source applies the merge's rules to each Ingress before it sends it, so one bad Ingress is refused with a report that names it instead of dropping something else by object name later:

| Case | Result |
|---|---|
| a host outside what the tenant may claim | the Ingress is rejected, `foreign_host_claim` |
| an unknown tenant in `podgate.io/tenant` | rejected, `unknown_tenant` |
| `defaultBackend`, or a rule without `host`, of a tenant that has no `catch_all = true` (and no exclusive entry point for the routers' entry points) | that router is left out and reported `catch_all_not_allowed`; the rest of the Ingress is served. An Ingress left with no router is rejected |
| a backend name with `/` or `.`, or a Service that does not exist in the Ingress's namespace | rejected: a backend can only name a plain Service of its own namespace |
| an `ExternalName` Service | rejected unless `allow_external_name` (its target is a DNS name a tenant picks; with the option it becomes `http://<externalName>:<port>`, which changes 0041 and 0042 govern) |
| a Service with no controller-written EndpointSlices | rejected unless `allow_external_name`, which then also accepts hand-written slices (and an empty server list) |
| a `resource` backend, a path that is not `/`-led for `Exact` or `Prefix`, an unknown `pathType`, a port that is both or neither number and name, an unsupported `appProtocol` | rejected |
| an unknown `podgate.io/*` or unsupported Traefik annotation, or an invalid value | rejected |

Rejections are sent as an outage of the source right after its state, naming each Ingress (`Ingress team-a/shop rejected: ...`), so `Status.outages` and the log show them while everything else keeps being served. A rejected Ingress that is fixed leaves the report with the next state.

## Watching

For every kind (Ingress, Service, EndpointSlice, TLS Secret) and every namespace scope the source runs one watcher: a list, then a watch from the list's `resourceVersion`. Any change to any of them, after a 100 ms settle time that merges a burst (a rollout touches slices many times a second), recomputes the whole state; it is sent when it differs from the last one. The provider's debounce then coalesces the push.

- **First state.** Only after every list has succeeded once. A half-loaded cache would delete routes, so until then the source sends an outage and no state.
- **Outage.** An API server that cannot be reached, answers an error status (`401`, `5xx`), resets connections or sends garbage is an outage of the source: the last state stays in force, nothing is deleted, and the watchers retry with a growing, jittered delay (1 s up to 30 s, back to the minimum after the first good event). When the cluster is back the source sends a state, which clears the outage.
- **`410 Gone`.** A watch version the server no longer keeps (as an HTTP status or an `ERROR` frame) is not an outage: the watcher lists again and the new list replaces what the source held. Objects deleted while disconnected disappear with it.
- **Bookmarks.** Requested on every watch; a bookmark moves the remembered version, so a reconnect after a quiet period resumes near now and needs no list.
- **Server timeouts.** Watches are opened with `timeoutSeconds=240`. When the server ends one, the watcher resumes from its version. A watch silent for more than that plus 30 seconds is treated as dead. A watch that ends at once, with no frame, counts as a failure, so a server that closes every watch cannot make the source spin.
- **Limits.** A list page is read up to 64 MiB, an error body up to 64 KiB, one watch frame (one object) up to 8 MiB; more is an error. Lists are paged (500 objects per request).

## RBAC

The Ingress and Gateway API sources only read. Cluster-wide:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: podgate-provider
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["list", "watch"]
  - apiGroups: [""]
    resources: ["services", "secrets"]
    verbs: ["list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["list", "watch"]
```

Reading Secrets is the sensitive part. The source asks for `kubernetes.io/tls` Secrets only, but RBAC cannot filter by type: the grant is `list` and `watch` of every Secret. Prefer `namespaces = [...]` with a `Role` and `RoleBinding` per namespace, granting `secrets` only in the namespaces that hold certificates, over a `ClusterRole`. A deployment that serves certificates from ACME needs no Secret access at all: leave `secrets` out of the rule; an Ingress that names a Secret is then rejected as missing, which is the safe failure.

With `gateway_api` the provider also writes: `update` and `patch` on the `status` subresource of the Gateway API objects, and `get`, `create` and `update` on one Lease. Both are in `docs/ref/provider-gateway.md`, `## RBAC`. Without them the source keeps serving: a refused status write or Lease is logged and the status is not written.

## The client, for changes 0073 to 0076

`kubernetes::client` is generic over resource kinds and has no Ingress knowledge. A later source implements `Resource` for its kinds (plain serde structs) and runs its own watchers:

```rust
pub trait Resource: DeserializeOwned + Send + 'static {
    const GROUP: &'static str;        // "" for the core group
    const VERSION: &'static str;
    const PLURAL: &'static str;
    const KIND: &'static str;
    const NAMESPACED: bool = true;
    fn meta(&self) -> &ObjectMeta;
}

ClientConfig::in_cluster() -> Result<ClientConfig, ClientError>
ClientConfig::from_kubeconfig(path: &Path, context: Option<&str>) -> Result<ClientConfig, ClientError>
ApiClient::new(config: ClientConfig, tuning: Tuning) -> ApiClient          // Clone
ApiClient::list::<R>(&self, query: &Query) -> Result<Listing<R>, ClientError>   // all pages
Query::all() / Query::in_namespace(ns) / .with_field_selector("type=...")
Watcher::<R>::new(client: ApiClient, query: Query)
Watcher::next(&mut self) -> Event<R>   // Reset(Vec<R>) | Applied(R) | Deleted(R) | Outage(Box<str>)
Store::<R>::new(); store.apply(event) -> bool; get(ns, name); values(); is_synced()
```

`Watcher::next` never returns an error and never gives up: a failure is an `Event::Outage` and the next call retries after the backoff; `410` and a server-ended watch are handled inside. `Event::Reset` replaces everything the consumer holds. `ObjectMeta` carries `name`, `namespace`, `resourceVersion`, `generation`, `creationTimestamp`, `annotations` and `labels`; a kind that needs more reads them from its own struct. Lists and watches send `GET`. Single objects have a write path next to `list` (on the same URL and bearer token code):

```rust
ApiClient::read::<R>(&self, namespace: Option<&str>, name: &str) -> Result<R, ClientError>      // GET
ApiClient::create::<R>(&self, namespace: Option<&str>, object: &Value) -> Result<R, ClientError> // POST
ApiClient::replace::<R>(&self, namespace: Option<&str>, name: &str, subresource: Option<&str>, object: &Value) -> Result<R, ClientError> // PUT
ApiClient::merge_patch::<R>(&self, namespace: Option<&str>, name: &str, subresource: Option<&str>, patch: &Value) -> Result<R, ClientError> // PATCH, application/merge-patch+json
ClientError::http_status(&self) -> Option<u16>   // 404, 409 and the like
```

`subresource` is `Some("status")` for the status subresource. A `metadata.resourceVersion` in the body of `replace` or `merge_patch` is a precondition: the server answers `409` when the object has moved on. `namespace` is ignored for a cluster-scoped kind.

The source in `mod.rs` shows the pattern: one `Store` per kind and scope, `Event::Outage` kept per watcher, state recomputed from the stores when they change, an outage sent after the state when something was left out, and no state before every watcher has listed.

## Not built

The Ingress status address (`ingressEndpoint` in Traefik) is not written: change 0074 writes the status of Gateway API objects only. `IngressClass` objects and the default-class annotation are not read: an Ingress without a class is not ours. Resource backends, Service `ExternalName` through CNAME flattening and `https` upstream ports (they need a servers transport) are refused with a reason.
