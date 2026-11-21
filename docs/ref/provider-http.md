# The HTTP source

Reference for `crates/podgate-provider/src/http.rs`: the provider source that polls an HTTP(S) endpoint the operator chose and merges what it returns, apps in podgate's own format or a Traefik dynamic configuration. It matches Traefik's HTTP provider (`endpoint`, `pollInterval`, `pollTimeout`, `headers`, `tls`) and Caddy's `caddy run --config <url>` style loading. It polls; there is no push and no long poll.

The trust rules are [the key-value layer's](provider-kv.md), unchanged. The podgate format is read by [the file source's](provider-file.md) shape of document; the Traefik format goes through [the Traefik file converter](provider-traefik-file.md) in its no-disk mode.

## Configuration

```toml
[[source]]
kind = "http"
name = "web"
url = "https://config.internal/podgate.json"
poll_secs = 30
timeout_secs = 10
max_bytes = 4194304
format = "podgate"
tenant = "acme"

[source.headers]
Authorization = "file:/etc/podgate/config-token"

[source.tls]
ca_file = "/etc/podgate/config-ca.pem"
cert_file = "/etc/podgate/config-client.pem"
key_file = "/etc/podgate/config-client-key.pem"
```

| Key | Default | Meaning |
|---|---|---|
| `url` | required | `http://` or `https://`, with a host, without credentials. The operator's choice, in the provider's own file: nothing the endpoint returns can change it. A loopback or link-local host is refused (see below). |
| `tenant` | required | The tenant of everything the endpoint returns, the only place a tenant comes from. There is no default tenant to fall back to. |
| `format` | `podgate` | `podgate` or `traefik`. |
| `poll_secs` | `30` | The interval between polls, measured from the end of one to the start of the next. At least `5`. |
| `timeout_secs` | `10` | The whole poll: DNS, connect, TLS, redirects and the body. `1` to `300`. |
| `max_bytes` | `4194304` | The largest answer, `1` to `16777216` (16 MiB). |
| `headers` | none | A table of request headers. A value `file:/path` is read at start (its trailing newline dropped), anything else is used as written; both are treated as secrets. |
| `tls.ca_file` | platform roots | The authority that signs the server's certificate. It replaces the platform's roots. |
| `tls.cert_file`, `tls.key_file` | none | A client certificate and key, for an endpoint that demands one. Both or neither. A `tls` table needs an `https://` URL. |
| `allow_local` | `false` | `true` accepts a loopback or link-local server, for a configuration sidecar on the same machine. |

Unknown keys are errors: a misspelt `tenant` must not move the apps to another tenant. The header files, the CA, the certificate and the key are read once at start; a rotated token or certificate needs a restart.

A source for a tenant that has no `allow` list of its own in the upstream policy file refuses to start (`kv_source_requires_tenant_allowlist`, see [the allowlist requirement](provider-kv.md#the-allowlist-requirement)). The source asks [`kv::Mapping::new`](provider-kv.md) with one `podgate-json` prefix for the tenant, so the rule has one implementation.

### Headers

Names that the source sets itself are refused: `Host`, `Accept`, `Connection`, `Content-Length`, `Transfer-Encoding`, `TE` and the `If-*` conditions. Headers over a plain `http://` URL are refused unless the host is on this machine: a token that crosses a network in clear is not a token. A header file that is missing, empty or not UTF-8 is a start error naming the file and never a value. Header values, the URL's path and query (a token may sit there) and the key are never in a log line, an outage text or the `Debug` output of the source, which shows the scheme, host and port and the header names only.

### Local addresses

A URL whose host is `localhost`, `*.localhost`, a loopback address, an unspecified address or a link-local address (`169.254.0.0/16`, `fe80::/10`, including IPv4-mapped IPv6 forms) is refused unless `allow_local = true`. A cloud metadata endpoint on `169.254.169.254` is the case this is for. The check is repeated at every connection on the addresses the name resolves to, so a name that starts to resolve to a local address stops being fetched (an outage: `the host resolves to a loopback or link-local address`). Private addresses (`10.0.0.0/8`, ...) are fine: a configuration server on the cluster network is the normal case.

## The poll

One request per poll, `GET`, one connection per request (`Connection: close`), HTTP/1.1.

- `Accept: application/json, application/yaml;q=0.9`. `If-None-Match` and `If-Modified-Since` carry the validators (`ETag`, `Last-Modified`) of the last answer that parsed. A `304` keeps the state and sends nothing. A `304` to a request that was not conditional is an error. Validators are replaced only by a document that parses, so a server that starts serving a broken document is asked again, and heard again, on the next poll.
- Redirects (`301`, `302`, `303`, `307`, `308`) are followed only inside the same origin (scheme, host and port equal), at most 3 times. A redirect to another origin is refused and is not requested; the error says so and does not quote the target.
- Only `200` carries a document. Any other status is an error naming the status.
- The `Content-Type` must be `application/json`, `application/yaml`, `application/x-yaml`, `text/yaml`, `text/x-yaml` or a `+json` or `+yaml` type, with no charset other than UTF-8. A missing or other type is an error. A `Content-Encoding` other than `identity` is an error: it was not asked for.
- The body is read while it streams and the poll fails the moment it passes `max_bytes`; `Content-Length` over the limit fails before any byte is read. A document is also parsed on a blocking thread, so a large one does not stall the other sources.
- A body identical to the last good one is not parsed again.

YAML (by content type) is accepted for convenience, but **aliases are refused**: nested aliases expand a few kilobytes into gigabytes, and the document is not the operator's. A `*` that starts a token and names something makes the answer an error (`the answer uses YAML aliases, which are not accepted`); a quoted `"*.acme.test"` is fine. It errs on the side of refusing, so write the document out in full or serve JSON.

A decode error names the line and column and never quotes the text.

## Formats

### `podgate`

A partial snapshot, the shape of [the file source](provider-file.md): `{"apps": [...], "certificates": [...]}`.

- `apps` is required, even when it is empty. See below.
- Unknown top-level keys are errors. `tenants` is ignored with a warning: tenants, weights and budgets come from the provider's configuration only.
- Every app and certificate goes through [the key-value layer](provider-kv.md) as a document of the `podgate-json` layout, so its rules apply and its limits: 1 MiB per document, 256 apps and 256 certificates. **Unknown fields reject the object** (`tls.client_ca` instead of `client_ca_pem`), checked against the model's schema. A document that **names a tenant**, even the source's own, is left out and reported, so the tenant comes from `tenant` and nowhere else; `declared_by` is overwritten. This is the strictest reading of "file-declared tenants are ignored": the file source turns a tenant label into a claim that a tenant must opt into, which has no meaning for one endpoint mapped to one tenant.
- An app needs a text `id`. An id declared twice is left out entirely (both declarations, reported): nothing decides which one the author meant. The app id in the snapshot is `<source name>-<id>`.
- A certificate is named `certificate-<index>`.
- What is wrong with one object is reported and leaves out that object only; the rest of the document stays. A document that cannot be decoded at all is an error (below).

### `traefik`

A Traefik dynamic configuration (`http`, `tcp`, `udp`, `tls`) in JSON or YAML, one app with the id `traefik` (snapshot id `<source name>-traefik`). It is translated by [the converter](provider-traefik-file.md), never a second one: what podgate cannot express exactly is reported with its path in the document (`http.middlewares.m.plugin`) and the object it belongs to is left out with everything that names it. A document of more than 1 MiB (the converter's limit) is an error whatever `max_bytes` says.

**No option of the document may name a file.** The answer is remote and may be wrong or hijacked, so `certFile`, `keyFile`, `usersFile` and the CA options that take a path are refused by `traefik_file::convert_inline` with the fixed reason `file_reference_not_allowed: this option names a file; give the PEM or the text inline`, before any filesystem call and the same for every path, so the answer says nothing about which paths exist on this machine and no file of it can end up in a snapshot. An inline PEM is accepted. The object that held the reference is left out (a certificate whose files are named is no certificate), the rest stays.

A Traefik answer is the same document in either syntax; JSON is read as YAML.

## Failures keep the last good state

A failed poll (a connection error, a timeout, a non-`200` status, a bad content type, an oversize body, a body that is not valid JSON or YAML, a document that is not valid for its format) is an **outage** of the source: it is reported (`Status::outages`, a `poll failed` warning with the scheme, host and port), and **the last good state stays in force**. The source never sends an empty state to mean "unreachable". A source that has never had a good document reports the outage and pushes nothing for itself.

After a failure the next poll waits longer: `poll_secs`, then twice that, doubling up to 5 minutes (at least `poll_secs`), each wait up to a quarter longer at random so a fleet of providers does not retry in step. A success returns to `poll_secs`. Identical outcomes are told once; a recovered source sends its state again, which clears the report.

Objects of a good document that were left out and reported (`reports` of [`kv::Built`](provider-kv.md)) are an outage text next to the state, as with the other sources.

## The empty answer

An endpoint that starts returning `{}` after an outage or a bad deploy would delete every route of its tenant. So an answer replaces the state only when it is a valid document:

- An empty body, `null`, `{}`, a list, or a document with no `apps` key is an error, and the last good state stays.
- `{"apps": []}` is a valid document that declares nothing, and it does replace the state: the deliberate way to remove every app.
- For `format = "traefik"` the same rule: a document that names none of `http`, `tcp`, `udp` or `tls` is an error; `http: {}` is a document.

## What the merge decides

The same as for every source ([provider.md](provider.md)): a host the tenant may not claim is `foreign_host_claim`, a router that matches hosts nobody claims needs `catch_all = true` or an exclusive entry point (`catch_all_not_allowed`), a server outside the tenant's allow list is `upstream_forbidden`, a conflict between sources is decided by age. `Origin::first_seen` is `0` for every object: an HTTP body has no creation time per object, and the time the provider fetched it would reorder the winners of a conflict after every restart.

## Public API

```rust
pub const MIN_POLL_SECS: u64;          // 5
pub const DEFAULT_MAX_BYTES: u64;      // 4 MiB
pub const LIMIT_MAX_BYTES: u64;        // 16 MiB

pub struct HttpConfigError { pub name: Box<str>, pub reason: Box<str> }

impl HttpSource {
    pub fn from_config(config: &SourceConfig, policy: &UpstreamPolicy) -> Result<Self, HttpConfigError>;
    /// The poll interval and the longest wait after failures; bypasses MIN_POLL_SECS. For tests.
    pub fn with_timing(self, poll: Duration, backoff_max: Duration) -> Self;
}
impl Source for HttpSource { /* the loop above */ }

// podgate_provider::traefik_file
pub fn convert_inline(id: &str, text: &str, syntax: Syntax) -> Result<Converted, ConvertError>;
```

Tests: `tests/http_source.rs` against a scripted endpoint (`tests/common/http_endpoint.rs`); `tests/http_logs.rs` for the secrets, in its own binary; the no-disk converter in `tests/traefik_file.rs`.
