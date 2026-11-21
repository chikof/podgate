# The Redis source

Reference for `crates/podgate-provider/src/redis/`: the provider source that reads podgate configuration from key prefixes of a Redis-compatible store (Redis, Valkey, KeyDB, Dragonfly), one prefix per tenant, and refreshes when the store says something changed. It matches Traefik's Redis provider (`endpoints`, `rootKey`, `username`, `password`, `db`, `tls`) with the same key tree as its etcd one, except `sentinel`: Sentinel and Redis Cluster are not supported (point `url` at a replica or a proxy). Caddy has config storage backends, which hold certificates and locks, not routes.

What the keys mean, who may write which, the layouts (`podgate-json`, `traefik-kv`) and the limits are [the key-value layer's](provider-kv.md); this page is the connection. The etcd source reads the same layouts: [the etcd source](provider-etcd.md).

## Configuration

```toml
[[source]]
kind = "redis"
name = "redis"
url = "rediss://redis.internal:6379"
username = "podgate"
password_file = "/etc/podgate/redis-password"
db = 0
notify_channel = "podgate:changed"
keyspace_notifications = false
refresh_secs = 30

[source.tls]
ca_file = "/etc/podgate/redis-ca.pem"
cert_file = "/etc/podgate/redis-client.pem"
key_file = "/etc/podgate/redis-client-key.pem"

[[source.prefix]]
prefix = "podgate/acme"
tenant = "acme"
layout = "podgate-json"
```

| Key | Default | Meaning |
|---|---|---|
| `url` | required | `redis://host[:port]` or `rediss://host[:port]` (TLS), default port `6379`. No credentials, path or query in it: the password goes in `password_file`, the database in `db`. `redis://` is accepted for a loopback host only (`127.0.0.0/8`, `::1`, `localhost`): the credentials and the configuration of a tenant do not cross a network unprotected. |
| `username`, `password_file` | none | `password_file` alone logs in as the default user (`AUTH <password>`); with `username` it is `AUTH <username> <password>`. `username` without `password_file` is an error. The file is read once at start; its trailing newline is dropped. A `password` key does not exist: passwords are never in the configuration. |
| `db` | `0` | The database to read (`SELECT`, sent only when not `0`). |
| `tls.ca_file` | platform roots | The certificate authority that signs the server's certificate. It replaces the platform's roots. Only with `rediss://`; with `redis://` it is an error. |
| `tls.cert_file`, `tls.key_file` | none | The client certificate and key for a server that demands them (`tls-auth-clients yes`). Both or neither. |
| `[[source.prefix]]` | required | One entry per tenant that writes keys; see [the layer](provider-kv.md#prefixes-and-tenants). |
| `notify_channel` | `podgate:changed` | The pub/sub channel the writer publishes to after updating keys. Any message means "read again". |
| `keyspace_notifications` | `false` | Also follow `__keyspace@<db>__:<prefix>*` for every prefix. Works only if the operator enabled keyspace notifications on the store (`notify-keyspace-events` with at least `K` and the classes of the commands that write: `$` for strings and `g` for `DEL`); the provider never changes a server setting. |
| `refresh_secs` | `30` | The poll: the longest the source goes without reading every prefix. At least `5`. |

Unknown keys are errors. The files are read once at start: a rotated certificate or password needs a restart. The provider refuses to start for a tenant that has no `allow` list of its own in the upstream policy file; see [the allowlist requirement](provider-kv.md#the-allowlist-requirement).

## Commands

The client sends only these commands and cannot send anything else (the only way to send is a closed set of variants; `redis_only_allowed_commands` runs the source through a recording proxy and asserts the set):

| Command | Used for |
|---|---|
| `AUTH` | Logging in, when `password_file` is set. |
| `SELECT` | Choosing `db`, when it is not `0`. |
| `SCAN <cursor> MATCH <prefix>* COUNT 512` | Finding the keys of a prefix, page by page. The prefix is glob-escaped and ends with `/`, so `podgate/acme` never matches `podgate/acme2/...`. Never `KEYS`, which blocks the server. |
| `MGET` | Reading the values of the keys found, 32 at a time. A key that vanished or is not a string reads as absent. |
| `SUBSCRIBE` | Following `notify_channel`. |
| `PSUBSCRIBE` | Following the keyspace channels, with `keyspace_notifications = true`. |
| `PING` | The heartbeat of the subscription, every `refresh_secs` or every 10 s if that is shorter. A subscription that stays silent for three intervals is dropped and reopened. |

`GET` needs no place in the list: `MGET` reads one key as well. The provider never runs `CONFIG SET`, writes a key or publishes.

A read-only ACL user for the provider, for a `podgate/acme` prefix, the default channel and `db = 1`:

```
ACL SETUSER podgate on >password resetkeys ~podgate/acme/* resetchannels &podgate:changed -@all +scan +mget +get +subscribe +psubscribe +ping +select
```

With `keyspace_notifications = true` add `&__keyspace@1__:podgate/acme/*` (the channel carries the database number). `redis_auth_and_tls` runs the source as that user.

## What it reads

Every prefix is read whole: `SCAN` until the cursor is `0` (duplicates the server may return are dropped), then `MGET`. All pairs go to `Mapping::build` of [the layer](provider-kv.md), which returns the complete state of the source.

| Limit | Value | When it is passed |
|---|---|---|
| value size | 256 KiB | The value is discarded as it arrives, never held; its key is left out and reported (`key "...": the value is larger than 262144 bytes; ignored`). |
| keys per prefix | `MAX_KEYS_PER_PREFIX` (4096) | The prefix is not read: an outage line names it. |
| value bytes per prefix | 32 MiB | The same. |
| apps per prefix | `MAX_APPS_PER_PREFIX` (256, the layer's) | The ones past it, in key order, are left out and reported. |

A prefix that is past a limit keeps what it held at its last good read (nothing on the first read) and does not hold back the other prefixes. `Origin::first_seen` is `0`: a key has no creation time.

## Following changes

The source reads every prefix on start, and again

- on every message of `notify_channel` (and of the keyspace channels when enabled). Messages that arrive within 50 ms of the first are one read.
- every `refresh_secs`, whatever the subscription says: a subscription that is down or silent (pub/sub is fire and forget, so a message published while the connection is down is lost) is repaired by the poll.
- right after a subscription is (re)established, because messages may have been missed meanwhile.

The subscription has its own connection and reconnects with growing delays (200 ms to 5 s, with jitter); the read connection does the same.

**An outage keeps the last state.** When the store cannot be reached or answers an error (no connection, a failed TLS handshake, refused credentials, `NOAUTH`, a timeout of 10 s per command or 60 s per pass), the source sends an outage naming the address and the reason, the engine keeps the previous state in force, and the source retries. It never sends an empty state to say "unreachable". When the store answers again, the new state replaces the old and the outage ends. A key, document or tree that cannot be used is reported next to the state as an outage text naming it; the rest of the source stays.

A writer that wants prompt updates publishes after changing keys:

```
SET podgate/acme/apps/site '{"routers": [...], ...}'
PUBLISH podgate:changed updated
```

## Secrets

The password, the client key and the credentials of the ACL user are never part of a log line, an outage text, an error or `Debug` output: the password lives in a redacted `Secret`, a server that refuses the login is reported with a fixed text (`the store refused the credentials`) instead of its own, and the TLS errors name the setting, not the file content. `redis_secrets_never_logged` (its own test binary, with a log capture) runs a wrong password, a TLS server with a client certificate and an outage, and searches the logs, outages and `Debug` output for every secret.

## Not built

- Redis Sentinel and Redis Cluster. Point `url` at a replica or a proxy; a cluster redirection (`MOVED`) is an error, reported as an outage.
- Unix sockets and `redis+unix://`.
- Keys that hold a hash, list or set: only string values are configuration, so they read as absent.

## Client

The RESP2 client (`redis/resp.rs`, `redis/client.rs`) is the provider's own: no Redis crate is a dependency. The daemon's rate-limit store has a RESP2 reader, but it lives in the daemon crate, which the provider must not depend on, and its bounds (4 KiB bulk strings, no nested arrays) are those of a script reply, not of `SCAN` and `MGET`. Every read here is bounded: lines, array sizes and nesting, and bulk strings (past 256 KiB the bytes are discarded as they arrive).

## Tests

`crates/podgate-provider/tests/redis_source.rs` and `redis_logs.rs` run against a real `valkey-server` (the daemon's harness `tests/common/valkey.rs`, included by path in the provider's `tests/common/mod.rs`; `valkey-server` and `valkey-cli` are on `PATH` in `devenv shell`, and a missing binary fails the test). A recording TCP forwarder in the test asserts the commands.
