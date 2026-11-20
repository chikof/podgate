# Upstream address policy

podgate connects to addresses a tenant's snapshot names. Without a rule, a tenant could aim the proxy at loopback, the cloud metadata service, the admin plane or another tenant's network. The operator owns that rule. It is a JSON file named by `UPSTREAM_POLICY_FILE`, read once at startup. It is never part of a snapshot, and no snapshot field can add an allowed range (the fields are ignored if present). Code in `src/service/upstream_policy.rs`.

## The file

```json
{
  "deny": ["10.9.0.0/16"],
  "default": { "allow": ["10.0.0.0/8"] },
  "tenants": { "acme": { "allow": ["10.4.0.0/16", "192.168.7.0/24"] } }
}
```

| Key | Meaning |
|---|---|
| `deny` | Ranges nobody may dial. Replaces the built-in list. |
| `deny_extra` | Ranges added to the built-in list. Cannot be combined with `deny`. |
| `default.allow` | Ranges every tenant without its own entry may dial. |
| `tenants.<id>.allow` | Ranges that tenant may dial. Replaces `default` for it. |

An address is permitted when it is in no `deny` range and, if the tenant (else `default`) has an `allow` list, inside it. A deny range always beats an allow range. With no `allow` list anything not denied is permitted: private ranges are the normal upstreams, so they are not denied by default. An `allow` key is required inside an entry, and an empty list allows nothing. Unknown keys, a repeated tenant, a CIDR with host bits set (`10.0.0.1/8`) and a bad prefix all stop startup.

A CIDR is `address/prefix`, or a bare address for one host. `::ffff:a.b.c.d/N` with `N >= 96` is read as the IPv4 range it carries.

**Built-in deny list** (used when `deny` is absent): `127.0.0.0/8`, `::1/128`, `0.0.0.0/8`, `::/128`, `169.254.0.0/16` (link-local, which holds the metadata address `169.254.169.254`), `fe80::/10`, `224.0.0.0/4`, `ff00::/8`, and three more metadata addresses: `100.100.100.200/32` (Alibaba), `192.0.0.192/32` (Oracle), `fd00:ec2::254/128` (AWS over IPv6).

Setting `deny` drops the built-in list. An operator who writes `"deny": ["10.9.0.0/16"]` has allowed loopback again; use `deny_extra` to add to the list. Add the podkit agent's address, the admin plane and any control-plane address through one of the two.

IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) IPv6 addresses are checked as the IPv4 address they carry. For deny the address is also checked as written, so a custom `deny` of `::1/128` still matches `::1`. Ports are not restricted. NAT64 (`64:ff9b::/96`) and other embeddings are not unwrapped.

No hot reload: restart to change the policy. A bad file stops startup with `invalid UPSTREAM_POLICY_FILE: <path>: <entry>: <reason>`, for example `... : deny[1]: "nope" is not an IP address`. The entry is `deny[i]`, `deny_extra[i]`, `default.allow[i]`, `tenants.<id>.allow[i]`, or `file` for a syntax or structure error.

## Enforcement

- **Compile.** Every literal server address of every service of every revision is checked with the app's tenant. A refused address rejects the snapshot with `422` and code `upstream_forbidden`, with `app`, `declared_by`, `at`, `service`, `server` and `rule` (`deny 127.0.0.0/8` or `not in the allow list of tenant acme`).
- **Connect.** `Gateway::upstream_peer` checks the address it is about to dial, whatever produced it. A refusal answers `502` and counts in `podgate_upstream_refused_total{tenant}` on `GET /metrics`. The compile check gives a friendly error; the connect check is the authority, because the snapshot's writer is not trusted to have run it.

## API for other outbound users

Anything that opens a connection a tenant can influence calls the policy first: health probes, mirrors, forward auth, error pages, the DNS resolver, L4 services.

```rust
use podgate::service::upstream_policy::{Refused, UpstreamPolicy};

impl UpstreamPolicy {
    /// The operator's rule: file named by UPSTREAM_POLICY_FILE, else the built-in deny list.
    pub fn builtin() -> Self;
    pub fn parse(json: &str) -> Result<Self, PolicyError>;
    pub fn load(path: &Path) -> Result<Self, PolicyError>;

    /// Connect time. Counts a refusal in podgate_upstream_refused_total{tenant} and logs it.
    pub fn check(&self, tenant: &str, ip: IpAddr) -> Result<(), Refused>;
    /// The same verdict with no side effect, for compile-time and dry-run checks.
    pub fn evaluate(&self, tenant: &str, ip: IpAddr) -> Result<(), Refused>;
    /// Prometheus text of the refusal counter; already part of GET /metrics.
    pub fn render(&self) -> String;
}
```

`UpstreamPolicy` is `Clone` and cheap to clone: clones share the counters. The process has one instance, made by `Config::upstream_policy()` in `run`. Get it from where your service is built: `AppState::upstream_policy()` for the admin API, a `.with_upstream_policy(policy)` builder on `Gateway`, `CompileContext::upstream_policy()` in the compiler. A new background service takes a clone in its constructor and `run` passes `upstream_policy.clone()`.

Rules for callers:

1. Call `check(tenant, ip)` immediately before the connect, with the address you will dial, on every dial. A resolver checks each address of each answer. Never check a name and then let the connector resolve it again: dial the `IpAddr` you checked (this is what defeats DNS rebinding).
2. `tenant` is the tenant of the app that declared the service, mirror, auth endpoint or error page, never a value from a request.
3. On `Err`, do not connect. Probes mark the server unhealthy and log; a mirror drops the copy; forward auth fails closed (the request is refused); an error page is skipped. Do not retry another address of the same tenant without checking it too.
4. The caller names a test that shows a refused address is never dialled, using `UpstreamPolicy::parse` with a small policy.

`CompileContext::default()` (used by `RoutingTable::compile` in tests and tools) refuses nothing; `run` always installs the operator's policy, and `Gateway::new` defaults to the built-in list.

In tests, the harness (`tests/common/mod.rs`) writes a policy file that allows `127.0.0.0/8`, so local upstreams work. A test about the policy passes its own `UPSTREAM_POLICY_FILE` through `Podgate::start_with_env`.
