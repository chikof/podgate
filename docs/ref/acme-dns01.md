# ACME DNS-01 and wildcard certificates

An app can get a wildcard certificate, and certificates for hosts that cannot answer HTTP-01, through the DNS-01 challenge. podgate never holds a DNS credential. The issuer asks the control plane to publish a TXT record and tells the CA to validate only after the control plane confirms through the snapshot. Code in `src/acme/dns01.rs`, `src/acme/issuer.rs` and `src/acme/plan.rs`. It builds on the HTTP-01 round trip of change 0014 (`docs/architecture.md ## ACME and on-demand TLS`).

Matches Traefik `certificatesResolvers.<n>.acme.dnsChallenge` and Caddy `tls { dns <provider> }`, with one deliberate difference: those call a DNS provider from the proxy with a credential from its environment. podgate has no provider code and no credential. The control plane (the PaaS agent, or `podgate-provider` through change 0083) holds them.

## Turning it on

Two switches, one for each side that must agree.

| Where | Setting | Meaning |
|---|---|---|
| Operator | `ACME_DNS_ZONES=example.com,example.org` | The zones DNS-01 may be used for. A host is allowed when it is a zone or lies under one. Unset: DNS-01 is off. |
| Snapshot | `App.tls.challenge` | `http-01` (default, as before) or `dns-01`. Needs `tls.mode` `acme`. |
| Snapshot | `Snapshot.acme.dns_ready` | `[{name, value}]` the control plane has published and sees on the zone's authoritative servers. |

The issuer is the node whose `NODE_NAME` equals `acme.issuer_node`, as for HTTP-01. Every other node ignores the ordering fields.

A `dns-01` app orders all its hosts in one certificate: exact names and `*.` wildcards alike. `example.com` plus `*.example.com` is one order with two authorizations.

## The round trip

1. The issuer opens an order, finds a `dns-01` challenge for each pending authorization, computes the TXT value `base64url(SHA-256(key authorization))` and emits one event per authorization:

   ```json
   {"seq": 7, "kind": "acme_challenge", "type": "dns-01",
    "name": "_acme-challenge.example.com", "value": "q3hQ...43 characters"}
   ```

   `name` is `_acme-challenge.<base domain>`: for `*.example.com` the base domain is `example.com`. For `example.com` and `*.example.com` in one order both events carry the same `name` and two different `value`s, so the control plane must publish both records. The event does not carry the key authorization, only the digest that is published anyway. HTTP-01 events gain `"type": "http-01"`, next to `token` and `key_authorization`.
2. The control plane publishes the TXT record, waits until it is visible on the zone's authoritative servers, then pushes a snapshot whose `acme.dns_ready` lists `{name, value}`. The value tells apart the records of one name.
3. Only when the issuer's own live table lists a challenge in `dns_ready` does it tell the CA to validate that authorization. Never before: the CA validates once, on the first query, so an early answer would burn the authorization and the order. The issuer waits up to 10 minutes, then abandons the order and retries with the backoff of HTTP-01 (1 minute, doubling to 1 hour, per job).
4. When the validation ends, whether it passed or failed, the issuer emits `acme_challenge_done {type, name, value}` for each record, so the control plane removes it. An order that is abandoned, cancelled or timed out emits it too, so no record outlives its order. Then it finalizes and emits `certificate_issued {hosts, cert_pem, key_pem}` as for HTTP-01. For the wildcard certificate `hosts` is `["*.example.com", "example.com"]` (sorted).

Push the confirmation to the issuer. Other nodes do not need it: a DNS challenge is answered by DNS, not by a node.

Renewal is the same round trip. The issuer renews a wildcard certificate in the ARI window of the CA like any other (`docs/architecture.md`, Renewal and ARI), and a certificate renews only while a `dns-01` app still claims all its hosts.

## What the compiler rejects

All are `422` with the code in `conflicts[].code`, naming the app and `declared_by`.

| Code | When |
|---|---|
| `dns01_not_enabled` | `challenge: dns-01` while `ACME_DNS_ZONES` is unset. |
| `dns01_zone_not_allowed` | A host (or the base of a wildcard) outside every listed zone. `host` names it. |
| `dns01_needs_acme_mode` | `challenge: dns-01` on an `on_demand` app. Its certificate is wanted at the handshake, long before a record can be published. |
| `dns01_too_many_hosts` | More than 4 hosts on one `dns-01` app (one pending challenge per host). |
| `wildcard_needs_dns01` | With `acme` settings present, an `acme` app with `challenge: http-01` claims a wildcard that no certificate in `certificates` covers. Before this spec such a host silently got no certificate. Either set `challenge: dns-01` or supply the certificate. |
| `tls_policy_conflict` | Two apps of one tenant share a pattern with different `tls.challenge` (as for every `tls` field). |

## Limits

- At most 8 orders at once.
- At most 100 pending DNS challenges per node and 4 per app, counted from the `acme_challenge` event to the order's end. An order over the limit fails and backs off.
- `acme.dns_ready` lists at most 1024 records. Each name must be `_acme-challenge.<host name>` and each value base64url, at most 128 characters; anything else rejects the snapshot with `422`.

## Threat model

- **Credentials.** None in the daemon, the snapshot, the events or the logs. `DnsReady` takes `name` and `value` and refuses any other field, so a credential has no place to travel. The only secrets in this flow are the ACME account key (redacted in `Debug`, never logged) and the certificate private key (in `certificate_issued`, as today). The TXT value is public by design.
- **Who may request a name.** Only a name an app claims, so the host conflict rules already stop one tenant requesting another's names. In addition the operator lists the zones in `ACME_DNS_ZONES`; a host outside every zone is rejected. That bounds how much of the CA's rate limit a tenant can burn with names the control plane would refuse to publish anyway. A snapshot cannot change the zones.
- **The control plane decides whether to publish.** A control plane that published any name the daemon asks for would let a tenant control a TXT record in the operator's zone. The solver must apply the tenant trust rule of change 0069: the requesting app's tenant must own the base domain. podgate cannot check that; it never sees the DNS. Recommended: CNAME `_acme-challenge.<zone>` to a dedicated validation zone, so the solver's credential can touch nothing else.
- **A wrong `dns_ready`** cannot issue a certificate for a name the CA does not validate. The worst case is a failed order and backoff. A `dns_ready` that comes too early costs the order, as the CA's single attempt is spent.
- **Stale records.** `acme_challenge_done` fires however the order ends, so the control plane can always remove what it published.
- **Memory.** Pending challenges are bounded per node and per app; `dns_ready` is bounded in the snapshot.

## Tests

`tests/acme_dns01.rs` runs `pebble` with `pebble-challtestsrv` as its DNS. The test plays the control plane: it reads the event feed, publishes each record through challtestsrv's management API (`/set-txt`, which appends a value to a name) and confirms it in the snapshot. pebble validates for real. The proof that podgate does not answer the CA early is twofold: pebble's log has no `/chalZ/` request, and challtestsrv's DNS history has no TXT query for the name, until the snapshot confirms. The wait's timeout and backoff are unit tests (`src/acme/dns01.rs`, `src/acme/issuer.rs`), because the real wait is 10 minutes.
