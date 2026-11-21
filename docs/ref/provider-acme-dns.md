# DNS-01 solvers of the provider

Reference for `crates/podgate-provider/src/acme/dns`: how the provider's ACME broker publishes the TXT records of `dns-01` challenges, and when it says they are ready. It is the control-plane half of `docs/ref/acme-dns01.md`: podgate holds no DNS credential, so the program that writes the operator's DNS is this one, and the credential lives in files next to it.

Matches Traefik `certificatesResolvers.<n>.acme.dnsChallenge` and Caddy `tls { dns <provider> }`, which ship dozens of DNS providers (lego, libdns) and call them from the proxy with a credential from its environment. Deliberate difference: two generic mechanisms, no vendor SDK. An RFC 2136 update covers BIND, Knot, PowerDNS and CoreDNS with the `rfc2136` plugin, and Route 53 and others through a bridge. The webhook covers everything else with a few lines of glue, and speaks lego's `httpreq` contract. Vendor-specific solvers are new modules on demand.

## Configuration

One `[[acme.dns]]` table per zone, inside the `[acme]` section of `docs/ref/provider-acme.md`.

```toml
[[acme.dns]]
zone = "example.com"
kind = "rfc2136"
server = "ns1.example.com:53"          # the zone's primary; port 53 when absent
tsig_key_name = "podgate-key.example.com"
tsig_algorithm = "hmac-sha256"         # or hmac-sha384, hmac-sha512
tsig_secret_file = "/etc/podgate/tsig.key"   # base64, mode 0600

[[acme.dns]]
zone = "validation.example.net"
kind = "webhook"
url = "https://dns-bridge.internal/acme"
bearer_token_file = "/etc/podgate/bridge.token"  # mode 0600
timeout_secs = 10
```

| Key | Default | Meaning |
|---|---|---|
| `zone` | required | The zone, a plain domain name. Zones are unique. |
| `kind` | required | `rfc2136` or `webhook`. A key of the other kind is an error. |
| `server` | required (`rfc2136`) | `host:port` of the zone's primary. |
| `tsig_key_name`, `tsig_algorithm`, `tsig_secret_file` | required (`rfc2136`) | The TSIG key. Only `hmac-sha256` and stronger are accepted. The file holds the base64 key, as BIND writes it. |
| `url`, `bearer_token_file` | required (`webhook`) | The base URL (`http://` or `https://`) and the file with the bearer token. |
| `timeout_secs` | `10` (`webhook`) | The deadline of one webhook call. |
| `propagation_timeout_secs` | `120` | How long to wait for every authoritative server to serve a published record, per attempt. |
| `check_resolvers` | none | The servers asked to confirm a record, `ip` or `ip:port`. Empty: the authoritative servers of the zone, found by an NS lookup through the system resolver. A list is used as given and no NS lookup is made (split-horizon views, or a lab). |
| `cname_follow` | `true` | A `CNAME` at the challenge name is followed, and the record goes to the zone of its target. |

Secrets are files, never values: an inline secret is an unknown key, a file that group or others can read stops the provider at start (`DnsError::Secret` names the path and the mode), and no secret reaches a log, an error, `print` or a `Debug` output.

## What happens to a challenge

For each `dns-01` event the broker hands `{name, value}` to the solver. The broker reports `acme.dns_ready` only after the solver returns `Ok`.

1. **Zone.** The zone is the configured one with the longest name that the challenge name equals or lies under. None: `no_solver`, never a guess.
2. **Trust.** `_acme-challenge.<base>` is published only when an app of the merged snapshot claims `<base>` or `*.<base>` and the tenant of that app owns the claim under the tenant rules of `docs/ref/provider.md` (its configured `hosts` cover it). Otherwise `foreign_name`. A solver that published whatever it is asked would let a tenant write TXT records into the operator's zone, and podgate cannot check that: it never sees the DNS. Both refusals are final and are not retried.
3. **Delegation.** When `cname_follow` is on, the solver asks the zone's servers for the name. A `CNAME` points to a validation zone: the record goes there, and the zone of the target is picked the same way (a target outside every configured zone is `no_solver`). The CA follows the same `CNAME`, so it finds the record. At most 8 hops.
4. **Publish.** TTL 60. `rfc2136` adds the TXT value to the RRset with an RFC 2136 update over TCP signed with TSIG, and accepts only an answer that verifies. `webhook` calls `POST <url>/present` with `{"fqdn": "_acme-challenge.example.com.", "value": "..."}` (the contract of lego's `httpreq`) and `Authorization: Bearer <token>`. Any `2xx` succeeds. A timeout, a connection error, `408`, `425`, `429` and `5xx` are retried; any other status is final. The answer body is read up to 64 KiB and dropped.
5. **Verify.** Every authoritative server is asked directly (recursion off, UDP with a TCP retry) until all return the exact value at the exact name, or `propagation_timeout_secs` passes. The CA validates once, on its first query, so a record that only the primary has would spend the order.

A transient failure at step 3 to 5 is logged (`DNS-01 record not published yet: ...`) and retried with backoff (1 s doubling to 60 s) until the challenge ends or 15 minutes pass; the issuer abandons an order after 10. Publishing again is safe: adding a value that exists is a no-op.

On `acme_challenge_done` the solver removes exactly the value it published (`rfc2136`: a delete of that one RR; `webhook`: `POST <url>/cleanup`). Other values at the name stay: an apex and its wildcard share one name with two values, and the operator's own records are never touched. A challenge that ends while its record is still being published stops the publish first, then removes what may have been written.

## What the solver does not do

- It keeps no state. After a provider restart a record published earlier stays until its TTL ends or the operator removes it, because podgate's `acme_challenge_done` is matched against the challenges this process saw.
- It does not apply the upstream address policy to the webhook or the DNS servers: the operator wrote those addresses.
- An `https://` webhook is not tested end to end; the tests use `http://`.
- `check_resolvers`, when set, replaces the NS lookup.
- An unreachable webhook or server is retried, never skipped: no `dns_ready` is ever reported for a record that is not visible.

## Tests

`tests/acme_dns.rs` runs the solver against `tests/common/dns_server.rs`, an in-process authoritative server that accepts RFC 2136 updates with TSIG, answers TXT and CNAME queries over UDP and TCP, and hosts a webhook stand-in. `wildcard_issued_through_provider_rfc2136` runs the real daemon and `pebble` with that server as pebble's resolver: the provider publishes by RFC 2136 and pebble validates what it finds. `tests/acme_dns_logs.rs` is a binary of its own because it captures logs with a thread-local subscriber (see `tests/acme_logs.rs`).
