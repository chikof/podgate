# Internal CA

Reference for `crates/podgate-provider/src/ca`: certificates for internal names (`*.internal`, `svc.cluster.local`, a lab domain) from a CA the operator runs, instead of ACME. Public CAs do not issue for these names, and `tls.mode = "acme"` for them just fails.

The CA lives in the control-plane program, never in `podgate`. The daemon stays stateless and holds no CA key. Its only part is the `internal` value of `tls.mode`: serve the certificates the snapshot carries and order nothing. The provider's `[ca]` section makes the certificates.

```
 offline                        provider node (state dir 0700)                 podgate
 ┌──────────┐  signs once       ┌────────────────────────────┐   certificates   ┌─────────┐
 │ root key │ ───────────────►  │ intermediate key + cert    │ ───────────────► │ serves  │
 │  10 y    │   name-constrained│ leaves (14 days, P-256)    │   in the snapshot│ them    │
 └──────────┘   intermediate    └────────────────────────────┘                  └─────────┘
```

## Configuration

```toml
[ca]
enabled = true
dir = "/var/lib/podgate-provider/ca"
allowed_suffixes = ["internal", "svc.cluster.local"]
# allow_wildcards = false
# leaf_days = 14
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Off: no CA, the section is checked and ignored. An app with `tls.mode = "internal"` is then refused with `internal_ca_not_configured`. |
| `dir` | required | The CA directory `ca init` makes (mode `0700`). Holds the intermediate and the leaves, never the root key. |
| `allowed_suffixes` | required | The suffixes the CA certifies names under: `internal` covers `internal` and `a.b.internal`, not `notinternal`. At least one. |
| `allow_wildcards` | `false` | Whether an app may claim `*.name` hosts and get a wildcard leaf. |
| `leaf_days` | `14` | The lifetime of a leaf, 1 to 90. |

An app asks for the CA with `tls.mode = "internal"` (Docker label `podgate.tls=internal`, the same value in a file source's `tls.mode`).

## The `ca` command

`podgate-provider ca <command> --config <file>` reads `[ca]` of the provider's configuration, so the directory and suffixes are the ones the running provider uses.

| Command | Does |
|---|---|
| `init --root-key-out <path> [--allow-public-suffix] [--root-days N] [--intermediate-days N]` | Makes a root (10 years) and an intermediate (5 years, name-constrained). The root key is written once to `<path>` (mode `0600`, a new file, outside the CA directory): store it offline and remove it from the node. The intermediate's key and certificate go into `dir`. Refuses a CA directory that already holds a CA. |
| `export-root [--pem-only]` | Prints the root certificate (PEM) preceded by a comment line with its SHA-256 fingerprint; `--pem-only` prints the PEM alone. |
| `status` | Prints the expiry of the root, the intermediate and every stored leaf (date, days left, renewal time) and what the intermediate permits. |
| `issue --out <dir> [--days N] <name>...` | An operator-only leaf: one certificate for the names, written to `<dir>` as `<first name>.cert.pem` (leaf, then intermediate) and `<first name>.key.pem`. Same suffix and wildcard rules as the provider's. Not stored, never pushed. |
| `rotate --root-key <path> [--intermediate-days N]` | A new intermediate under the same root with the same constraints; see [Rotation](#rotation). |

## Name constraints

The intermediate carries a **critical** `NameConstraints` extension whose permitted DNS subtrees are exactly `allowed_suffixes`, and whose excluded subtrees are every IPv4 and IPv6 address. A stolen intermediate key can therefore only mint certificates for names under the suffixes, even for clients that trust the root: a client that enforces name constraints (OpenSSL, rustls through webpki, Go, Chrome, Firefox, Java) rejects `www.example.com` signed by it. The test `ca_name_outside_constraints_fails_openssl` signs such a certificate with the intermediate key and shows `openssl verify` refusing it with `permitted subtree violation`.

The provider checks the same list itself and refuses to issue outside it (`internal_name_not_allowed`), so a mistake is caught before a certificate exists, and the constraint is what is left when the provider is bypassed. The provider also refuses to start when:

- `allowed_suffixes` lists a suffix the intermediate's certificate does not permit (the configuration may be narrower than the certificate, never wider);
- the intermediate has no critical `NameConstraints` with permitted DNS subtrees (an unconstrained intermediate is refused);
- the intermediate's key is not the certificate's key (a half-finished rotation).

`ca init` refuses suffixes that are public suffixes: a TLD (`com`) or a registry suffix (`co.uk`, `github.io` is in the private section and not refused). The list is the ICANN section of the [public suffix list](https://publicsuffix.org/list/), embedded in the binary (`crates/podgate-provider/src/ca/public_suffixes.txt`, ASCII rules only, a name is checked in its punycode form). A name that is not on the list, such as `internal`, `lan`, `home.arpa` or `svc.cluster.local`, is private. `--allow-public-suffix` overrides the refusal: a CA for `com` is a CA that can certify anyone's domain for every client that trusts it, so do it only for a test.

## Issuance

For every app of the merged snapshot with `tls.mode = "internal"`, the CA issues one leaf that holds all the exact hosts the app claims:

- ECDSA P-256, `dNSName` subject alternative names only, `serverAuth` as the only extended key usage, no CA capability, the common name is the first host when it fits;
- valid from five minutes before issue to `leaf_days` after it, never past the intermediate's expiry;
- stored with its key in the CA directory before it can be pushed, then added to the snapshot's `certificates` (the chain: leaf, then intermediate);
- renewed when two thirds of the lifetime have passed (day 9.3 of 14); the old leaf keeps being pushed until the new one is stored, and an expired leaf is never pushed.

The merge pushes a stored leaf only while an app of the same merge claims exactly its hosts, so an app that switches to `acme`, or loses a host, stops getting the leaf at once. A leaf nobody has claimed for seven days is deleted from the directory.

### What is refused

| Code | When | Effect |
|---|---|---|
| `internal_name_not_allowed` | A host of an `internal` app lies outside `allowed_suffixes`, or is a wildcard while `allow_wildcards` is off. | The merge drops the app and reports it (the findings of `Status` and the log). An app without a certificate could not serve TLS, so it is not half-served. |
| `internal_ca_not_configured` | An app asks for `internal` and no `[ca]` section is enabled. | Dropped and reported. |
| `foreign_host_claim` | The trust rule of `docs/ref/provider.md`: a host outside the tenant's `hosts`. | Dropped by the merge before the CA is asked; the CA checks the tenant again when it issues (`foreign_host_claim`, `unknown_tenant`) and issues nothing. |
| `internal_issue_failed` | Signing failed (the intermediate expired). | The app keeps the leaf it has, and the provider logs an error. |

Because an app's tenant can only claim hosts it owns, a tenant cannot get a certificate for another tenant's host. A wildcard claim `*.x.internal` is a claim like any other under the trust rule.

If the CA directory cannot be written (a full disk, a read-only mount), the CA task stops with an error, `Status.ca_error` says so, and what was pushed keeps serving. Nothing that was not persisted is pushed.

## State directory

The CA directory is the ACME broker's state directory layout (`docs/ref/provider-acme.md`, `## State directory`): `0700`, every file `0600`, every write atomic (temporary file, `fsync`, rename, `fsync` of the directory), the leaf index written after its files. The code is shared with the broker's, not copied.

```
<dir>/                       mode 0700
  intermediate.key.pem       the online CA key
  intermediate.cert.pem      the commit point of `ca init`
  root.cert.pem              the root certificate; the root key is never here
  index.json                 the leaf index
  certs/<id>.cert.pem        a leaf chain
  certs/<id>.key.pem         its key
```

A directory or a key file that group or others can read stops the provider. Keys never reach a log, `Debug` output or `print`: `Secret` shows `[redacted]`, and `print` replaces every `key_pem` of the snapshot.

## Revocation

By expiry only. Leaves live 14 days by default (90 at most), so a leaked leaf key is useful for at most that long; there is no CRL and no OCSP responder. For a compromised intermediate key, rotate it (below); the name constraints already bound what it could have signed.

## Distributing the root

`podgate-provider ca export-root > root.pem` prints the root and its fingerprint. Compare the fingerprint on each client against the one `ca init` printed. The root is valid for ten years; the intermediate (five years by default) is what rotates.

**Debian and Ubuntu**

```sh
sudo cp root.pem /usr/local/share/ca-certificates/podgate-internal.crt
sudo update-ca-certificates
```

**Alpine**

```sh
cp root.pem /usr/local/share/ca-certificates/podgate-internal.crt
update-ca-certificates
```

**RHEL, Fedora, Rocky**

```sh
sudo cp root.pem /etc/pki/ca-trust/source/anchors/podgate-internal.pem
sudo update-ca-trust
```

**Containers.** Mount the root read-only and point the runtime at it:

```sh
docker run -v /etc/podgate/root.pem:/etc/ssl/podgate-root.pem:ro \
  -e SSL_CERT_FILE=/etc/ssl/podgate-root.pem my-image
```

`SSL_CERT_FILE` replaces the system bundle for OpenSSL-based clients; for a client that must keep the public roots too, build the bundle (`cat /etc/ssl/certs/ca-certificates.crt root.pem`) into the image or the volume. Go reads `SSL_CERT_FILE`; Node.js needs `NODE_EXTRA_CA_CERTS=/etc/ssl/podgate-root.pem`; Python `requests` needs `REQUESTS_CA_BUNDLE`.

**Kubernetes.** Put the root in a ConfigMap and mount it:

```sh
kubectl create configmap podgate-root --from-file=root.pem=root.pem
```

```yaml
spec:
  containers:
    - name: app
      env:
        - { name: SSL_CERT_FILE, value: /etc/podgate/root.pem }
      volumeMounts:
        - { name: podgate-root, mountPath: /etc/podgate, readOnly: true }
  volumes:
    - name: podgate-root
      configMap: { name: podgate-root }
```

**Browsers.** Firefox: Settings, Privacy and Security, Certificates, View Certificates, Authorities, Import, tick "Trust this CA to identify websites". Chrome and Edge on Linux use the system store through NSS (`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n podgate-internal -i root.pem`); on macOS and Windows import the file into the system keychain or the "Trusted Root Certification Authorities" store.

**curl**

```sh
curl --cacert root.pem https://app.internal/
```

## Rotation

The root is the long-lived trust anchor; the intermediate is what rotates, under the same root, so no client changes anything.

1. Bring the root key back for this one command and run `podgate-provider ca rotate --config provider.toml --root-key /path/to/root.key`. It writes a new intermediate (new key, five years) with the same name constraints, signed by the same root.
2. Remove the root key from the machine again.
3. Restart the provider. It issues new leaves under the new intermediate as they come due (two thirds of their life). Leaves under the old intermediate stay valid until they expire, since each leaf's chain carries its own intermediate, and the old intermediate stays valid until its own `notAfter`: the overlap is the time both are valid, which needs no action from clients.

A suspected theft of the intermediate key is the same procedure plus shortening `leaf_days` until the old leaves have expired: nothing revokes them earlier, and the constraints bound what they cover. Rotating the root means a new `ca init` and a new distribution of the root, with the old root trusted next to the new one until the last old leaf has expired.

## Against Caddy and Traefik

| | Caddy | Traefik | podgate-provider |
|---|---|---|---|
| Internal CA | `tls internal`: a local root and intermediate in the proxy's data directory | none: bring your own certificates | `[ca]` in the control plane, the CA key outside the proxy |
| Where the keys are | beside the proxy | n/a | the root offline, the intermediate in a `0700` directory of the provider; the proxy holds only leaves |
| Name constraints | none | n/a | critical, the allowed suffixes, IP addresses excluded |
| Leaf lifetime | 12 hours | n/a | 14 days by default, 90 at most |
| Trust installation | `caddy trust` installs the root on the local machine | n/a | `ca export-root` and the recipes above |
| ACME server for internal clients | `acme_server` | n/a | not built: a possible follow-up |

## Tests

`crates/podgate-provider/tests/internal_ca.rs`. The chain tests need `openssl` on `PATH` (`devenv shell` provides it) or `OPENSSL_BIN`, and the daemon test the daemon binary; a missing one fails them.

| Test | Proves |
|---|---|
| `ca_init_creates_chain`, `ca_intermediate_has_critical_name_constraints` | the root and intermediate have the documented attributes; the constraints are critical and match the suffixes |
| `ca_leaf_verifies_with_openssl`, `ca_name_outside_constraints_fails_openssl` | a leaf verifies against the root through the intermediate; a name outside the constraints fails `openssl verify` even when signed by the intermediate key |
| `ca_refuses_names_outside_suffixes`, `ca_init_refuses_public_suffix` | the provider and the merge refuse names outside the suffixes; `ca init` refuses public suffixes |
| `ca_internal_app_gets_certificate`, `ca_leaf_renewed_at_two_thirds`, `ca_certificates_repushed_after_restart`, `ca_daemon_serves_internal_certificate` | an `internal` app gets a leaf in `certificates`; renewal at two thirds; the leaf is pushed again after a podgate and a provider restart; the real daemon serves it to a client that trusts only the root |
| `ca_tenant_cannot_get_foreign_host`, `ca_wildcard_requires_setting` | no leaf for a host the tenant does not claim; wildcards need `allow_wildcards` |
| `ca_root_key_not_in_state_dir`, `ca_state_permissions`, `ca_keys_never_logged` | no root key in the directory; `0700` and `0600`; no key in a log, `Debug` or `print` |
| `ca_export_root`, `ca_status_reports_expiry` | the command prints the root and its fingerprint (as openssl computes it) and the expiries |
| `ca_rotates_the_intermediate_under_the_same_root`, `ca_provider_refuses_suffixes_wider_than_its_intermediate`, `ca_section_is_validated` | rotation under the same root; the provider never exceeds its certificate; the `[ca]` section's checks |
