# Traefik dynamic configuration files

Reference for `crates/podgate-provider/src/traefik_file/`: the translator of Traefik's dynamic configuration file (YAML or TOML: `http`, `tcp`, `udp`, `tls`) to one podgate app. It runs in two places: the file source with `format = "traefik"` (the files are picked up and re-read when they change), and the one-off `podgate-provider convert-traefik` command, which is also a migration linter. The rule grammar is `docs/ref/provider-traefik.md` (`podgate-rule`) and the middleware options of that page's label table are translated by the same code; this page is what is specific to a file.

**Translate or reject, never approximate.** An option podgate cannot express exactly is a problem that names its path in the file (`http.middlewares.m.plugin`) and a code (`unsupported_label`, `unsupported_rule`, `invalid_label`, `foreign_reference`, the codes of `docs/ref/provider-traefik.md`). The object it belongs to is left out, together with every object that names it: a router whose middleware did not translate is not served without that middleware. The other objects of the file are converted and served. An object nobody reads is a problem too, so a typo or a new Traefik option can never switch a protection off silently. Keys are case-insensitive, as in Traefik's file provider, and the report spells them as the file does.

## The file source

```toml
[[source]]
kind = "file"
name = "traefik"
path = "/etc/traefik/dynamic"   # a file, or a directory of *.yml, *.yaml, *.toml and *.json
format = "traefik"              # default "podgate"
tenant = "acme"
```

One file is one app: its id is the file stem (`shop.yml` is the app `shop`, `traefik-shop` in the snapshot), its tenant the source's. Everything else of `docs/ref/provider-file.md` holds: polling, the limits, a broken file keeping its last good content, an empty file being an error. `Origin::first_seen` is `0`: a file has no creation time a source can rely on (`docs/ref/provider.md`).

- A file that decodes is converted whole. The problems of rejected objects are logged as warnings (`rejected: <path>: <reason> (<code>)`) on every change of the file, and the rest is served. Run `convert-traefik` to see them before switching.
- The files a conversion reads (certificates, keys, CAs, users files) are watched with the file: renewing a certificate on disk is a change.
- Relative paths in the file are read from the directory of the file. The converter reads only what the file names, never more than 1 MiB per file, and a certificate, key or CA file must hold a PEM block (a path that names some other file does not end up in a snapshot).

## `convert-traefik`

```sh
podgate-provider convert-traefik [--lenient] <file>...
```

The snapshot JSON (`{"apps": [...], "certificates": [...]}`, the shape the file source reads, so it can be saved as a `.json` file) goes to stdout and the report to stderr, one line per problem: `<file>: <path>: <reason> (<code>)`. The apps have no `tenant` and no `declared_by`: they are the source's to set. **The output holds the private keys of the certificates it inlined**; treat it like the keys.

|Exit status|Meaning|
|---|---|
|`0`|Everything converted, or `--lenient` and the report was printed|
|`1`|Something was rejected (the partial snapshot is still on stdout)|
|`2`|A file cannot be read or decoded, has no known extension, two files have the same stem, or the arguments are wrong|

## What a file becomes

|Traefik|podgate|
|---|---|
|`http.routers.<r>`|a router. `rule` through `podgate_rule::parse` (`ruleSyntax: v2` is refused), `priority` or the rule's length, `entryPoints`, `middlewares` (the router's `chain`, in order), `service`, `observability {accessLogs, metrics, tracing}`. A router with `tls` and no `entryPoints` listens on `websecure` only, so a router that asked for TLS is never served in clear text. `tls.certResolver` is accepted (podgate has one issuer), `tls.domains` is refused, `tls.options` below|
|`http.services.<s>.loadBalancer`|`loadbalancer`: `servers[].url` (`http`, `https` or `h2c`, host and port, no path), `weight` (any weight but 1 selects `weighted_round_robin`; 0 is refused), `passHostHeader`, `healthCheck`, `sticky.cookie` (the options of the label table), `serversTransport`. `strategy` other than `wrr`, `responseForwarding` and `preservePath` are refused|
|`weighted`, `mirroring`, `failover`|the services of the same names. `weighted.sticky` as above. `mirroring`: `mirrorBody` defaults to true as in Traefik and then `maxBodySize` is required (1 to 16 MiB: Traefik's default has no limit, podgate caps it); mirrors get the request's credentials, as in Traefik (`forward_credentials: true`). `failover` returns to the main service as soon as it is healthy (`fallback_hold_secs: 0`). `healthCheck: {}` is accepted, podgate always propagates health|
|`http.serversTransports.<t>`|`servers_transport`: `serverName`, `insecureSkipVerify`, `rootCAs` (files or PEM, inlined as `ca_pem`), one `certificates` entry (`client_cert`), `disableHTTP2`, `forwardingTimeouts.dialTimeout` and `idleConnTimeout` (whole seconds, never zero). `maxIdleConnsPerHost`, `peerCertURI`, `spiffe` and `responseHeaderTimeout` are refused: podgate's read timeout also bounds every read of the body, which Traefik's does not|
|`http.middlewares.<m>`|a middleware, by the table below|
|`tcp.routers.<r>`|an `App.tcp` router. `rule` in the TCP dialect (`HostSNI`, `HostSNIRegexp`, `ALPN`, `ClientIP`; `HostSNI(`*`)` is no matcher), `tls: {passthrough: true}` forwards the stream, `tls: {}` terminates. `entryPoints` is required (podgate reserves a TCP entry point to a tenant) and `priority` is refused (podgate ranks TCP routers by their constraints)|
|`tcp.services.<s>.loadBalancer`|a TCP `loadbalancer`: `servers[].address` and `tls`, `serversTransport`, `proxyProtocol.version`, `terminationDelay`. `weighted` is refused|
|`tcp.middlewares`|`ipAllowList.sourceRange` and `inFlightConn.amount`|
|`tcp.serversTransports`|`servers_transport`: `dialTimeout` and the `tls` section as above. `dialKeepAlive` and `terminationDelay` are refused|
|`udp.routers`, `udp.services`|`App.udp` routers (`entryPoints` required) and load balancers over IP literals|
|`tls.certificates[]`|a snapshot certificate: `certFile` and `keyFile` read and inlined; its `hosts` are the DNS names in the certificate (the common name when it has none), which is how Traefik picks one. `stores` other than `default` is refused|
|`tls.stores.default.defaultCertificate`|the same with `default: true`. Other stores and `defaultGeneratedCert` are refused|
|`tls.options.<o>`|the app's `tls`, see below|

Names (of routers, services, middlewares, transports) are 1 to 63 letters, digits, `-` or `_`; another name is `invalid_label` for that object. A transport name is unique across `http` and `tcp`, because podgate has one namespace for them.

### References

A name may carry its provider. `name@file` is the file itself and the suffix is dropped. Any other provider (`auth@docker`, `api@internal`, `x@kubernetescrd`) names an object podgate cannot see, and is `foreign_reference` at the option that names it. A name the file does not define is `invalid_label`. A service that names a service, and a chain that names a chain, are built after the ones they name; a cycle is `invalid_label` on every member.

### Middlewares

|Traefik|podgate|
|---|---|
|`stripPrefix`, `stripPrefixRegex`, `addPrefix`, `replacePath`, `replacePathRegex`, `redirectScheme`, `redirectRegex`, `headers`, `compress`, `rateLimit`, `ipAllowList`, `basicAuth`, `retry`, `circuitBreaker`|the label translator, with the options and refusals of the table in `docs/ref/provider-traefik.md` (`circuitBreaker.expression` by its three shapes). The file is flattened to `traefik.http.middlewares.<m>.<type>.<path>` labels and translated one object at a time. `compress: {}` is Traefik's default set. `basicAuth.usersFile` is read and its lines added to `users`. A list entry that holds a comma is refused (a label list splits at commas, so an Argon2 hash such as `$argon2id$v=19$m=65536,t=3,p=4$...` needs the podgate file format)|
|`chain`|`chain` (`middlewares` by name)|
|`forwardAuth`|`forward_auth`: `address`, `trustForwardHeader`, `authResponseHeaders`, `authResponseHeadersRegex`, `authRequestHeaders`. A `tls` section becomes a transport named `<m>-forward-auth` (`ca`, `cert`, `key`, `insecureSkipVerify`). `addAuthCookiesToResponse`, `forwardBody`, `maxBodySize`, `headerField`, `preserveLocationHeader`, `preserveRequestMethod` and `tls.caOptional` are refused|
|`digestAuth`|`digest_auth`: `users` and `usersFile` (read), `realm` (Traefik's default `traefik` is written out), `headerField`, `removeHeader` (written out: Traefik's default keeps `Authorization`, podgate's removes it)|
|`buffering`|`buffering`: `maxRequestBodyBytes` (with `buffer_request` up to 64 KiB, a limit that streams above it), `maxResponseBodyBytes` (with `buffer_response`). At least one is required. `memRequestBodyBytes`, `memResponseBodyBytes` (podgate buffers in memory only) and `retryExpression` are refused|
|`errors`|`errors`: `status`, `service` (a service of the file), `query` (required, `{status}` only). `statusRewrites` is refused|
|`passTLSClientCert`|`pass_tls_client_cert`: `pem` and `info` in snake case|
|`grpcWeb`|`grpc_web`: `allowOrigins`|
|`contentType`|`content_type`; `autoDetect: true` is refused|
|`inFlightReq`|`in_flight_req`: `amount` and `sourceCriterion` (the criterion of the rate limit, translated by the same code)|
|`ipWhiteList`, `plugin`, any other type|refused|

### TLS options

Traefik applies `tls.options` per router; the handshake runs before any router is known, so podgate's TLS policy belongs to the app (`docs/ref/tls-options.md`). The converter takes the option each TLS router asks for (its own `tls.options`, else `default`), applies the one most routers ask for to the app and leaves out the routers that ask for another, with `unsupported_label` at their `tls.options`: put them in a file of their own. The options map to `min_version` (`VersionTLS12`, `VersionTLS13`), `cipher_suites`, `alpn`, `sni_strict` and `clientAuth` (`clientAuthType` to `client_auth`, `caFiles` inlined as `client_ca_pem`). `maxVersion` other than TLS 1.3, `curvePreferences` and `disableSessionTickets` are refused. `preferServerCipherSuites` has no effect in Traefik and is ignored. The app's `tls.mode` is always `acme`.

## The no-disk mode

`convert_inline(id, text, syntax)` converts a document that does not come from this machine (an HTTP answer). It is `convert` with no directory: every option that names a file (`certFile`, `keyFile`, `usersFile`, the CA options) is refused with the fixed reason `file_reference_not_allowed: this option names a file; give the PEM or the text inline`, **before any filesystem call** and the same for every path, so the answer says nothing about which paths exist and no file of this machine can end up in a snapshot. An inline PEM is accepted. `Converted::files` is empty. The object that held the reference is left out like any other rejected object. `convert` and the file source are unchanged.

## Differences to know

- Traefik ranks routers by rule length and podgate by the priority the converter writes, which is the same number; for TCP routers podgate ranks by constraints instead and refuses a `priority`.
- `buffering` above 64 KiB enforces the limit while the body streams instead of holding it, and `forwardAuth` calls time out after 5 seconds.
- Only the options named above exist. A Traefik option added after this page is an `unsupported_label` until it is translated.

## Tests

`cargo nextest run -p podgate-provider --test traefik_file`: the representative file against the expected app, the remaining middleware kinds, TCP and UDP, transports, certificates and TLS options with generated certificates, every refusal with its path, `@provider` references, TOML, the exit codes of `convert-traefik`, the file source reading a Traefik file, and the converted file against the real daemon's `POST /v1/snapshot/validate`.
