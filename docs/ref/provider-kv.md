# The key-value layer

Reference for `crates/podgate-provider/src/kv.rs`: what the key-value sources share. [The etcd source](provider-etcd.md) is the first; the Redis and HTTP sources read their own backend and hand the pairs to the same code. A source finds keys and values; this layer decides what they mean, who wrote them, and which of them are used.

It matches Traefik's key-value providers (etcd, Redis, Consul KV, ZooKeeper) and their key tree. Caddy has config storage backends, which hold certificates and locks, not routes; there is nothing to match.

## Prefixes and tenants

A key-value source has one `[[source.prefix]]` entry per tenant that writes keys:

```toml
[[source.prefix]]
prefix = "podgate/acme"      # the keys under "podgate/acme/"
tenant = "acme"              # the tenant that writes them
layout = "podgate-json"      # or "traefik-kv"
app = "acme-site"            # traefik-kv only: the id of the app, default the tenant
```

**The tenant comes from the prefix mapping and from nowhere else.** The writer of a key is the tenant that owns its prefix. A document that names a tenant, even its own, is ignored and reported; a key outside every prefix is ignored and reported. Unknown keys in an entry are errors, so a misspelt `tenant` cannot move apps to another tenant.

The trailing slash of `prefix` is implied and always part of the match: `podgate/acme` never reads the keys of `podgate/acme2`, and a store is asked for `podgate/acme/`. A prefix of only slashes (the whole store) is refused. Prefixes may not overlap (equal, or one inside the other), because the writer of a key would be ambiguous.

## Layouts

### `podgate-json`

| Key | Value |
|---|---|
| `<prefix>/apps/<id>` | One app as JSON, in the shape of [the file source](provider-file.md): the `App` of `podgate-model` without `tenant`. `id` may be left out; if given it must equal the key's `<id>`. `declared_by` is overwritten. |
| `<prefix>/certificates/<name>` | One certificate object: `hosts`, `cert_pem`, `key_pem`, `default`, `ocsp`. |

`<id>` and `<name>` are 1 to 63 letters, digits, `-`, `_` or `.`. A key of any other shape under the prefix (`<prefix>/junk`, `<prefix>/apps/a/b`) is ignored and reported. The app id in the snapshot is `<source name>-<id>`.

### `traefik-kv`

Traefik's key tree, with the prefix as its root key: `<prefix>/http/routers/<r>/rule`, `<prefix>/http/services/<s>/loadbalancer/servers/0/url`, `<prefix>/http/middlewares/<m>/...`. With Traefik's own default root key, `prefix = "traefik"`.

1. Every key is flattened to the label form: `<prefix>/http/routers/r/rule` becomes `traefik.http.routers.r.rule`. A key segment that is empty or holds `.` or a space cannot be written as a label and is ignored and reported.
2. A list is written `<key>/0`, `<key>/1`, ...: the values, in index order, become one comma separated value under `<key>`. `servers/<n>/url` is not a list of values and stays as it is.
3. The labels go to [the Traefik translator](provider-traefik.md), which turns rules, middlewares and services into routers and middlewares exactly as it does for Docker labels. What it cannot express exactly is left out with the exact key in the report.
4. The one thing the translator refuses is a server address, because a container's address is the runtime's. Here the tenant that owns the prefix writes the data, so `servers/<n>/url` is accepted: `http`, `https` or `h2c`, with a host and a port, and no path, query or credentials. Any other field under `servers/<n>` (`weight`, `preservePath`) is not translated and rejects its service. A service with no usable server is left out, and so is every router that names it.

The whole tree is one app (`app`, default the tenant) with one `default` revision in `serving` state, weight 1. A tree with no router that can be served is no app. `traefik.enable=false` hides it. TLS is `acme` (a router with `tls.certresolver` also means `acme`). `traefik.tcp`, `traefik.udp`, `tls` stores and `serversTransport` are not translated and are reported.

## The allowlist requirement

Explicit server addresses are accepted in key-value data, so the provider **refuses to start** a key-value source for a tenant that has no `allow` list of its own in the upstream policy file (`kv_source_requires_tenant_allowlist`):

```json
{ "tenants": { "acme": { "allow": ["10.4.0.0/16"] } } }
```

The `default` entry does not count: it is shared by every tenant. Without the list a tenant could point its servers at any address the default policy permits, including another tenant's containers. With it, the provider's preflight rejects every literal server address outside the list (`upstream_forbidden`, naming the server and the rule), and the daemon checks the same list again when it compiles the snapshot and on every connection, including addresses a DNS name resolves to. The safe configuration is the only one that starts.

## What the merge still decides

Everything above produces the same objects any source produces, and the merge judges them by the same rules ([provider.md](provider.md)): a host the tenant may not claim is `foreign_host_claim`, a router that matches hosts nobody claims needs `catch_all = true` or an exclusive entry point (`catch_all_not_allowed`), a server outside the allow list is `upstream_forbidden`, a conflict between sources is decided by age. An object that the merge rejects is left out on its own; the rest of the source stays.

## Limits

Each is per object: the object is left out and reported, and nothing else is.

| Limit | Value | Applies to |
|---|---|---|
| `MAX_DOCUMENT_BYTES` | 1 MiB | one JSON document; a whole `traefik-kv` tree (keys and values) |
| `MAX_APPS_PER_PREFIX` | 256 | apps of a `podgate-json` prefix; the ones past it, in key order, are left out |
| `MAX_CERTIFICATES_PER_PREFIX` | 256 | the same, for certificates |
| `MAX_KEYS_PER_PREFIX` | 4096 | keys a store client reads from one prefix; a prefix that holds more is unreadable (an outage naming it), so a tenant cannot make the provider hold an unbounded amount |

**Unknown fields are rejected**, at any depth of the model's own structures (`tls.client_ca` instead of `client_ca_pem`, `routers[0].serv`): such a typo would otherwise silently turn a protection off. Which fields exist comes from the model's JSON schema (`podgate-model` with the `schema` feature), so a field added to the model is known here without a second list. The free-form parts (a middleware's or service's own configuration, a matcher) are not walked; their kind validates them.

A report names the key and what is wrong, and never quotes a value: error texts have every quoted string removed, so a mistyped `key_pem` cannot reach a log.

## Public API

```rust
pub const MAX_DOCUMENT_BYTES: usize;
pub const MAX_APPS_PER_PREFIX: usize;
pub const MAX_CERTIFICATES_PER_PREFIX: usize;
pub const MAX_KEYS_PER_PREFIX: usize;

pub enum Layout { PodgateJson, TraefikKv }          // "podgate-json", "traefik-kv"

pub struct RawPrefix {                               // one [[source.prefix]], deny_unknown_fields
    pub prefix: String, pub tenant: String, pub layout: Layout, pub app: Option<String>,
}

pub struct Prefix { pub path: Box<str> /* ends in '/' */, pub tenant: Box<str>, pub layout: Layout, pub app: Box<str> }

pub enum ConfigError { NoPrefix, Prefix { index: usize, reason: Box<str> }, NoAllowlist { tenant: Box<str> } }
impl ConfigError { pub fn code(&self) -> &'static str }

impl Mapping {
    pub fn new(raw: Vec<RawPrefix>, policy: &UpstreamPolicy) -> Result<Mapping, ConfigError>;
    pub fn prefixes(&self) -> &[Prefix];
    pub fn build<K: AsRef<[u8]>, V: AsRef<[u8]>>(&self, source: &str, entries: impl IntoIterator<Item = (K, V)>) -> Built;
}

pub struct Built { pub apps: Vec<SourceApp>, pub certificates: Vec<SourceCertificate>, pub reports: Vec<Box<str>> }
impl Built { pub fn report_text(&self) -> Option<Box<str>>; pub fn into_state(self) -> State }
```

A source deserializes its `prefix` array into `Vec<RawPrefix>`, calls `Mapping::new` once at start (so a tenant without an allowlist fails there), reads every key under each `Prefix::path` from its backend, and calls `Mapping::build` with every pair it holds, in any order, whenever something changed. The result is the complete state of the source: `into_state()` is what goes into the update, `report_text()` is what goes next to it as an outage text, as the Docker and Nomad sources do.
