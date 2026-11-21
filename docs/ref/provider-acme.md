# podgate-provider ACME broker

Reference for `crates/podgate-provider/src/acme`: the part of the provider that turns podgate's ACME events into certificates in the snapshot. A node whose writer is `podgate-provider` needs no podkit agent to get certificates.

podgate keeps no state and never calls the control plane (`docs/architecture.md`, `## ACME and on-demand TLS`). The issuer node emits `acme_challenge`, `certificate_issued` and `certificate_requested` on its event feed (`GET /v1/events`), and orders only what its snapshot lets it. Someone has to answer: push the challenge answers back in `acme.challenges`, store each certificate and push it in `certificates`, approve on-demand hosts in `acme.requested_hosts`. On a provider-only node that someone is the broker. It is a control-plane program, so it may keep state on disk; the daemon may not. Keeping the two apart is what lets podgate stay restartable with nothing to restore.

The rule that makes the broker necessary: without an answer an order never completes and podgate orders again, burning the CA's failed-validation and duplicate-certificate rate limits. So the `acme` object cannot be written by hand: it is not a key of `[snapshot]`, it comes from `[acme]` and always comes with the broker.

## Configuration

```toml
[acme]
enabled = true
mode = "broker"                                   # or "follower"
state_dir = "/var/lib/podgate-provider/acme"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
issuer_node = "node-1"                            # NODE_NAME of the podgate that orders
contact = ["mailto:ops@example.com"]
# account_key_file = "/etc/podgate/acme-account.pem"

[acme.on_demand]
max_per_tenant_per_hour = 10
max_pending = 100
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off: no broker, no `acme` object, the section is checked and ignored. |
| `mode` | `broker` | `broker` reads its own podgate's feed and owns `state_dir`. `follower` reads the directory of a broker (see [Follower](#follower)). |
| `state_dir` | required | Where the broker keeps its state. Created with mode `0700`. An existing directory that group or others can read is refused. |
| `directory_url` | required | The ACME directory, `https://...`. |
| `issuer_node` | required | The `NODE_NAME` of the podgate that orders. Written into `acme.issuer_node`. |
| `contact` | none | Contact URIs of the account. |
| `account_key_file` | none | A PKCS#8 PEM key the operator keeps, mode `0600`. Absent (and no `eab`): the broker makes a P-256 key once and keeps it as `state_dir/account.key`, so every restart and every issuer node uses one account. |
| `[acme.eab]` | none | `key_id` and `hmac_key_file` (the base64url key, mode `0600`) for a CA that needs external account binding. Excludes an account key: a CA binds only when it creates the account, so podgate makes the account itself. |
| `challenge_lead_ms` | `0` | How long an HTTP-01 or TLS-ALPN-01 answer waits in the shared directory before the broker pushes it to its own podgate. With followers, set it above a follower's poll (1 s) plus its debounce, so every node has the answer before the issuer starts validating. |
| `[acme.on_demand]` | 10 an hour, 100 pending | `max_per_tenant_per_hour`, `max_pending`. At least 1 each. |

Secrets are files, never values: an inline key is an unknown key, a key file that group or others can read stops the load, and the keys never reach a log or `print`.

## The loop

The broker long-polls `GET /v1/events?after=<seq>&timeout_secs=20` with the sequence number it stored.

| Answer | The broker |
|---|---|
| `200`, new `boot_id` | podgate restarted: its orders are gone and its sequence numbers start again. The broker drops its pending answers, forgets the position, polls from `0`, and makes the engine look at the live snapshot at once (a new `boot_id` means the whole snapshot is pushed again, certificates included, before podgate could order). It does not wait for the next `resync_secs` tick. |
| `200`, same `boot_id` | Applies the events in order, then moves the cursor. |
| `410` | The feed no longer holds the events after the cursor (its ring keeps 4096). The broker continues from `oldest - 1` and makes the engine check the live snapshot. What was lost is lost; the issuer orders again after its ten minutes. |
| `408`, an error | Polls again, with the push client's backoff (1 s doubling to 30 s) for errors. |

An event the broker does not act on only moves the cursor. An event it acts on but cannot read is skipped with an error that names the field and never the value.

| Event | What the broker does |
|---|---|
| `acme_challenge` `http-01` | Adds `{token, key_authorization}` to `acme.challenges`. |
| `acme_challenge` `tls-alpn-01` | Adds `{name, key_authorization}` to `acme.challenges`. |
| `acme_challenge` `dns-01` | Hands `{name, value}` to the DNS solver. The record goes into `acme.dns_ready` only after the solver reports it visible on the authoritative servers. Without a solver it is reported (`no_solver`) and never answered. |
| `acme_challenge_done` | `dns-01`: removes the entry from `acme.dns_ready` and asks the solver to clean up. |
| `certificate_issued` | Writes the certificate to the state directory, then adds it to `certificates`. A set whose hosts the new one holds is replaced (a renewal). Approvals for its hosts end, and TLS-ALPN-01 answers for its names go. |
| `certificate_requested` | Approves or refuses, below. |

An answer for HTTP-01 stays 30 minutes. podgate says when a DNS-01 record is done, but not when an HTTP-01 token is, and tying a token to an order is not possible from the feed, so a time limit is the honest rule. A token is unguessable and serving a stale one answers nothing.

Certificates are pushed only when an app of the merged snapshot claims one of their hosts. A certificate nobody claims stays in the store and is dropped 30 days after the last time an app claimed it, so an app that is gone for a while keeps its certificate when it returns.

## State directory

```
<state_dir>/            mode 0700
  index.json            the certificate index: the commit point of every certificate
  certs/<id>.cert.pem   the chain, leaf first
  certs/<id>.key.pem    the private key
  cursor.json           boot id and last processed sequence number
  challenges.json       HTTP-01 and TLS-ALPN-01 answers, with the time each arrived
  approvals.json        on-demand approvals with their times
  account.key           the account key, when the broker made it
```

Every file is mode `0600` and is replaced atomically: written to a temporary file in the same directory, `fsync`ed, renamed, and the directory `fsync`ed. A certificate is two files and an index entry, the index written last: a crash leaves the old state or the new one plus orphan files, which are removed at the next start.

**Persisted before pushed.** A certificate reaches the snapshot only through the broker's view, and the view is updated after the write returned. When the write fails (a full disk, a read-only mount) the broker stops with an error, the engine goes on with the last view, and the status says so (`Status.acme_error`, and a log line). Nothing the broker could not persist is ever pushed: the issuer does not order the same job again for ten minutes, so a certificate that was pushed but lost would be lost with its key. The cursor does not move past an event that was not persisted. The sources keep working and what was pushed keeps serving; restart the provider after fixing the disk.

## On-demand approval

podgate emits `certificate_requested {host}` when a handshake names a host of an `on_demand` app that has no certificate, and orders it only when `acme.requested_hosts` lists it. The name in the handshake is chosen by whoever connects, so approving is a security decision. The broker lists a host only when all of these hold:

1. It is a plain host name: no wildcard, no IP address, only `a-z 0-9 - _ .`.
2. An app of the merged snapshot declares `tls.mode = on_demand` for it: a router host that is the name itself or a wildcard one label above it.
3. The tenant of that app has `hosts` patterns that cover it (the trust rule of `docs/ref/provider.md`, checked again here although the merge already dropped any app outside its tenant's patterns).
4. The tenant has fewer than `max_per_tenant_per_hour` approvals in the last hour.
5. Fewer than `max_pending` approved hosts wait for their certificate, over all tenants.

Otherwise the host is not listed, the handshake fails after 30 seconds as it does without a control plane, and the host is asked about again after podgate's pending period (10 minutes). An approved host stays listed until its certificate arrives, for at most an hour. The approvals and their times are kept in the state directory, so a restart neither forgets what is pending nor resets the rate window. A request that arrives before the engine has published what the apps claim waits for it, then is decided.

## Follower

A cluster runs one broker, beside the issuer's podgate. The other nodes run `mode = "follower"` on the same `state_dir` (a shared volume). A follower reads `index.json`, the certificates and `challenges.json` once a second and pushes them to its own podgate, so every node serves the same certificates and answers the CA's challenge on whichever node it reaches. It writes nothing, reads no event feed, and puts neither the account key nor an EAB key into its snapshot: only the issuer's podgate uses them.

- Followers are not told when the broker has written; they poll. A new answer is therefore on a follower within about two seconds (its poll plus its debounce). To keep "the issuer last", set the broker's `challenge_lead_ms` above that: the broker writes the answer to the directory at once and pushes it to its own podgate after the lead.
- On-demand requests are read from the broker's own podgate only. A handshake on another node emits its request on that node's feed, which nobody reads, and fails after 30 seconds; the same host on the broker's node, or an app with `tls.mode = acme`, gets a certificate that every node then serves. Forwarding a follower's requests is not built.
- The directory is the only link between the nodes. A directory that is not private to the provider's user is refused.

## DNS-01 hook

The broker owns the hook; change 0083 owns the solvers. `acme::events::Solver` has `present(challenge, claims)`, which publishes the record and returns once it is visible, and `cleanup(challenge)`. `Engine::with_dns_solver` registers one. `claims` says which app claims which host, for the solver's own trust check.

## Against Traefik

| | Traefik | podgate-provider |
|---|---|---|
| Where certificates live | `acme.json` inside the proxy | the provider's state directory; the proxy keeps nothing |
| Several nodes | a cluster needs a KV store or a paid edition | a shared directory read by follower providers |
| On-demand issuance | not built in (Caddy has it, with an `ask` endpoint) | per-tenant approval and rate limits, in the open |
| A full disk | the proxy cannot save the certificate | the broker stops, nothing unsaved is pushed |

## Tests

`crates/podgate-provider/tests/acme_broker.rs`; the store's own in `src/acme/store.rs`.

| Test | Proves |
|---|---|
| `broker_http01_end_to_end` | a real podgate behind the provider gets a certificate from `pebble`, with no human step, and a TLS client that trusts only pebble's root gets the backend's answer |
| `broker_survives_restarts` | the certificate comes back after a provider restart and a podgate restart, and no new order is made |
| `broker_persists_before_push` | every certificate the fake podgate sees in a snapshot is already on disk |
| `broker_store_failure_keeps_last_state` | an unwritable store stops the broker, the last pushed certificates keep being pushed, the failed one never is |
| `broker_event_resume`, `broker_resync_on_410_and_boot_id` | the cursor resumes without duplicates; `410` and a new `boot_id` resync |
| `on_demand_approved_for_owning_tenant`, `on_demand_refused_for_foreign_host`, `on_demand_rate_limited`, `on_demand_trust_rule_and_rate_window` | the approval rule and its limits |
| `store_permissions`, `broker_keys_never_logged` | `0700` and `0600`, and no key in a log, `print` or the status |
| `follower_serves_shared_store` | a follower pushes the broker's certificates and answers without reading a feed |

The end-to-end tests need `pebble` and `pebble-challtestsrv` on `PATH` (`devenv shell`) and the daemon binary (`target/debug/podgate`, or `PODGATE_BIN`); a missing one fails them. `pebble` reuses an authorization for 1 percent of identifiers even with `PEBBLE_AUTHZREUSE=0`, and an order that reuses one has no challenge to answer, so the tests compare the challenges they saw with the authorizations pebble created, never with a fixed number.
