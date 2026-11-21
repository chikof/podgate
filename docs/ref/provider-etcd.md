# The etcd source

Reference for `crates/podgate-provider/src/etcd/`: the provider source that reads podgate configuration from etcd key prefixes, one per tenant, and follows changes with a watch. It matches Traefik's etcd provider (`endpoints`, `rootKey`, `username`, `password`, `tls`, and its key tree). Caddy has config storage backends, which hold certificates and locks, not routes.

What the keys mean, who may write which, the layouts (`podgate-json`, `traefik-kv`) and the limits are [the key-value layer's](provider-kv.md); this page is the connection.

## Configuration

```toml
[[source]]
kind = "etcd"
name = "etcd"
endpoints = ["https://etcd-1.internal:2379", "https://etcd-2.internal:2379"]
username = "podgate"
password_file = "/etc/podgate/etcd-password"
watch = true
resync_secs = 60

[source.tls]
ca_file = "/etc/podgate/etcd-ca.pem"
cert_file = "/etc/podgate/etcd-client.pem"
key_file = "/etc/podgate/etcd-client-key.pem"

[[source.prefix]]
prefix = "podgate/acme"
tenant = "acme"
layout = "podgate-json"
```

| Key | Default | Meaning |
|---|---|---|
| `endpoints` | required | The origins of the gateway: `https://host:2379`, no path, query or credentials. `http://` is accepted for a loopback host only (`127.0.0.0/8`, `::1`, `localhost`): the credentials and the configuration of a tenant do not cross a network unprotected. With several, a request goes to the one that answered last and moves on to the next when an endpoint cannot be reached or answers with a server error. |
| `username`, `password_file` | none | Both or neither. The provider authenticates with `POST /v3/auth/authenticate` and renews the token. The file is read once at start; its trailing newline is dropped. A `password` key does not exist: passwords are never in the configuration. |
| `tls.ca_file` | platform roots | The certificate authority that signs the servers' certificates. It replaces the platform's roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` apply when it is absent). |
| `tls.cert_file`, `tls.key_file` | none | The client certificate and key for an etcd that demands them (`--client-cert-auth`). Both or neither. |
| `[[source.prefix]]` | required | One entry per tenant that writes keys; see [the layer](provider-kv.md#prefixes-and-tenants). |
| `watch` | `true` | Follow the prefixes with a watch. With `false` the source reads them every `resync_secs` and changes show at the next read. |
| `resync_secs` | `60` | The longest the source goes without reading a prefix whole. At least `1`. |

Unknown keys are errors. The files are read once at start: a rotated certificate or password needs a restart.

The provider refuses to start for a tenant that has no `allow` list of its own in the upstream policy file; see [the allowlist requirement](provider-kv.md#the-allowlist-requirement).

## What it does with etcd

It talks to etcd's gRPC JSON gateway (the HTTP/JSON mapping that every etcd v3 server offers), over HTTP/1.1, with three calls:

| Call | Used for |
|---|---|
| `POST /v3/kv/range` | Reads every key under `<prefix>/` (`key` the prefix with its slash, `range_end` the prefix with its last byte incremented, `limit` one more than `MAX_KEYS_PER_PREFIX`), and learns the store revision of the read. |
| `POST /v3/watch` | A `create_request` for the same range, starting at that revision plus one, so no change falls between the read and the watch. The answer is a stream; each message is a JSON object. |
| `POST /v3/auth/authenticate` | Buys a token when a user is configured. The token goes into the `Authorization` header of every later call. |

The client has no way to call anything else: its only entry point takes one of those three. A read-only etcd user is therefore enough, and the documentation of the deployment should create one: a role with `read` permission on the prefixes (`etcdctl role grant-permission podgate-read read --prefix podgate/`) and nothing else. The tests assert the source never calls a path other than these three, and the fake etcd records anything that would write.

## Following changes

Every prefix has its own reader. It reads the prefix whole, sends the keys to the source, then watches from the revision of the read and sends each change. The source keeps a copy of every prefix, applies the changes, and rebuilds the state when changes stop arriving for 50 ms (at most 250 ms after the first). Nothing is sent until every prefix has been read once, so a state is never missing a tenant's apps.

A full read replaces the copy and happens again

- when the watch ends or breaks (the server closed the stream, the connection dropped, an error message);
- when etcd answers that the revision the watch needs has been compacted;
- every `resync_secs`, whatever the watch says: a watch that died without anyone noticing (a half-open connection, a missed event) is repaired by the next full read.

**An outage keeps the last state.** When etcd cannot be read (no endpoint answers, an error status, a token that cannot be obtained, more than `MAX_KEYS_PER_PREFIX` keys), the source sends an outage naming the prefix and the reason, the engine keeps the previous state in force, and the reader retries with delays from 100 ms to 5 s. The source never sends an empty state to say "unreachable". When etcd answers again, the new state replaces the old and the outage ends.

A key, document or tree that cannot be used is reported next to the state as an outage text naming it, like the other sources do; the rest of the source stays.

## Authentication and secrets

A token expires (the server's TTL, or when the auth store changes) and etcd answers `401 invalid auth token` or `400 revision of auth store is old`; the client asks for a new token once and repeats the call. A dozen readers that see the refusal together buy one token. A wrong password is not retried: it is an outage with etcd's own message.

The password, the token and the client key are never part of a log line, an outage text, an error or `Debug` output: the password and token live in a redacted `Secret`, the header is marked sensitive, and error texts quote only what etcd answered.

## Tests

`crates/podgate-provider/tests/etcd.rs`, `etcd_logs.rs` and `kv_layouts.rs` run against a fake etcd gateway (`tests/common/etcd.rs`) that implements range, watch (chunked stream, compaction), authenticate and TLS with an optional client certificate. No test needs an `etcd` binary.
