# Traefik rules and labels

Reference for `crates/podgate-rule/` (the rule grammar) and `crates/podgate-provider/src/traefik/` (the label translator). A PaaS that labels containers for Traefik v3 today (podkit does: `~/Projects/podkit/agent/src/ingress.rs`, `routing_labels` and `secure_routing_labels`) can switch to podgate without relabelling. The Docker and Podman source reads `traefik.*` labels next to `podgate.*` ones (`docs/ref/provider-docker.md`); a Nomad source and the Traefik file translator call the same function.

**Translate or reject, never approximate.** A rule or label podgate cannot express exactly is reported with its exact label, and the router, service or middleware it belongs to is left out, together with every router that names it. A matcher that differs from the rule is a different set of reachable hosts, and a router that lost its middleware is a route without its protection.

## The entry point

```rust
// crates/podgate-provider/src/traefik/labels.rs, re-exported as podgate_provider::traefik
pub fn translate<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Translation
```

It takes plain `(key, value)` pairs and skips every key that does not start with `traefik.` (any case). Docker labels pass their map as is; Nomad service tags (`traefik.http.routers.web.rule=Host(...)`) are split at the first `=`. `Translation` holds what the labels say in podgate's terms:

|Field|Meaning|
|---|---|
|`enabled`|`traefik.enable`, when given|
|`tls`|`Some(Acme)` when an emitted router names a `tls.certresolver`|
|`port`|`loadbalancer.server.port`: a container has one|
|`routers`, `middlewares`, `services`|podgate `Router` and `Declared` objects. Services have no servers: the runtime's address and the port are the only server (`docs/ref/provider-docker.md`, the address rule)|
|`schemes`|`https` or `h2c` for services whose `server.scheme` says so|
|`problems`|`Problem {code, key, reason, fatal}`: what was left out, naming the label|

The Docker source calls it from `docker::labels::parse`, so a container may carry both spellings. A name defined by both (`podgate.router.web.*` and `traefik.http.routers.web.*`) is `invalid_label`, as are two different ports. A container with `traefik.enable=true` is exposed even when `exposed_by_default` is off, `traefik.enable=false` (or `podgate.enable=false`) hides it, and `podgate.enable` wins when both are set. A problem that is not `fatal` is reported next to the state, named after the container, and the rest of the container is used. A `fatal` one (a label naming an address, a `traefik.enable` that is no boolean) rejects the whole container like it does for `podgate.*`. A container whose routers all failed is rejected with every reason.

## Rules

`podgate_rule::parse(rule, dialect) -> Result<Rule, RuleError>` returns the matcher JSON of `docs/architecture.md ### Routers and matchers`, every regular expression it checked, and the rule's length in bytes. It does no I/O and depends only on `serde_json` and `regex`; the daemon can use the same parser for rule strings in a snapshot.

|Rule|Matcher|
|---|---|
|`Host(`a.test`)`, `Host(`*.a.test`)`|`{"host": "a.test"}`, lower case; one leading `*.` covers one label, as in Traefik. Several arguments are any-of: `{"host": [...]}`|
|`HostRegexp(`^x`)`|`{"host_regexp": "^x"}`|
|`Path(`/x`)`, `PathPrefix(`/api`)`, `PathRegexp(`...`)`|`path`, `path_prefix`, `path_regexp`; several arguments are an `any` of leaves|
|`Method(`GET`)`|`{"method": "GET"}`, upper case (Traefik ignores case here); several are a list|
|`Header(`X-Env`, `v`)`, `HeaderRegexp(`X-Env`, `re`)`|`header`, `header_regexp` with a lower case name|
|`Query(`a=b`)`, `Query(`a`, `b`)`, `QueryRegexp(`a`, `re`)`|`query`, `query_regexp`. A bare `Query(`a`)` only tests presence, which podgate has no matcher for: refused|
|`ClientIP(`10.0.0.0/8`)`|`{"client_ip": [...]}`|
|`A && B`, `A \|\| B`, `!A`, `( )`|`all`, `any`, `not`. `!` binds tighter than `&&`, which binds tighter than `\|\|`. `Host(a) \|\| Host(b)` is one `host` leaf with both names, the shape `podgate.host` produces|
|TCP: `HostSNI`, `HostSNIRegexp`, `ALPN`, `ClientIP`|`sni`, `sni_regexp`, `alpn`, `client_ip`. `HostSNI(`*`)` is no matcher at all (`match` absent, a catch-all), and drops out of `&&`; a negated one matches nothing and is refused|

Arguments are in backticks or double quotes (Go escapes `\\`, `\"`, `\n`, `\t`, `\r`). Function names are case-insensitive, as in Traefik 3.7. Whitespace, line breaks included, separates tokens.

Refused with code `unsupported_rule` and a message that names the byte offset: a syntax error, Traefik v2 syntax (`Headers()`, `HeadersRegexp()`, `HostHeader()`, `PathStrip()`, `PathPrefixStrip()`, `PathPrefixStripRegex()`, `{name:regex}` groups in `HostRegexp`; `ruleSyntax=v2`), an unknown function, a function of the other dialect, a `Host` with a wildcard anywhere but the front or a non-ASCII name, a bad CIDR, a rule over 16 KiB or nested over 64 levels, and any regular expression the Rust `regex` crate does not compile (lookaround, backreferences and the like: Go's RE2 and `regex` agree on the rest, but the daemon compiles with `regex`, so only what compiles is passed on). Character classes such as `\d` and `\w` are Unicode-aware in `regex` and ASCII in RE2; a host or path that is ASCII matches the same.

Two differences to Traefik 3.7 are on purpose. Traefik refuses several arguments to `Host`, `Method`, `Path*` and `ClientIP` (v2 allowed them); podgate reads them as any-of, which is what v2 meant. And `PathPrefix` matches whole segments in podgate (`/api` and `/api/x`, not `/apix`), while Traefik's is a plain string prefix: a request Traefik would have sent to `/apix` is a `404` here, never the other way round.

### HostRegexp only narrows

`Host(`a.test`) && HostRegexp(`^x`)` is an `all` of the literal `host` and the `host_regexp`: the literal claim bounds the router and the regexp narrows it. A rule with `HostRegexp` and no literal host from the same rule is a catch-all. The provider's catch-all preflight (`docs/ref/provider.md`) quarantines it with `catch_all_not_allowed` unless the tenant has `catch_all = true` or every entry point the router names is in the tenant's `exclusive_entry_points`; the translator emits it and never decides that, and the regexp text is never read to prove it anchored.

## Priority

A router without `priority` gets the length of its rule string in bytes, as written (spaces and multi-byte characters count), which is what Traefik does: podgate itself never orders by length, this reproduces Traefik's order. An explicit `priority` label wins; it must fit in 32 bits. `crates/podgate-provider/tests/traefik_rules.rs` starts the pinned `traefik` (3.7.16, `pkgs.traefik` in `devenv.nix`) with a file provider, reads `/api/http/routers` and compares its priority with the fixture table `tests/fixtures/traefik_rules.json` and with the translator's.

## Router labels

|Label|Result|
|---|---|
|`rule`|Required. Parsed as above|
|`rulesyntax`|`v3` and `default` are the grammar above; `v2` is `unsupported_rule`|
|`priority`|The router's `priority`|
|`entrypoints`|The router's `entry_points`, one to one. `web` and `websecure` are podgate's built-in names. A router with `tls` (or a `tls.certresolver`) and no `entrypoints` listens on `websecure` only, so a router that asked for TLS is never served in clear text|
|`service`|A service of the labels (`name` or `name@docker`). With none and exactly one service in the labels, that one; with none in the labels, `web`, which exists without a label; otherwise required|
|`middlewares`|The router's `chain`, in order. Every name must be a middleware of the labels that translated|
|`tls`, `tls.certresolver`|`tls=true` keeps the app's certificates the snapshot's (`certificates`) and sets nothing; a `certresolver` sets the app's `tls.mode` to `acme` (podgate has one issuer, the resolver's name is not kept)|
|`tls.options`, `tls.domains.*`, `observability.*`|`unsupported_label`: TLS options are per host in podgate, the handshake runs before any router; certificates cover the router's hosts|

A name with another provider (`auth@file`, `api@internal`) is `foreign_reference`: a label cannot name an object that the container's own labels do not define.

## Service labels

`traefik.http.services.<s>.loadbalancer.*`:

|Label|Result|
|---|---|
|`server.port`|The container's port. Services with different ports in one container: the later one is `invalid_label`|
|`server.scheme`|`http` (default), `https` or `h2c`, the scheme of the servers|
|`server.url`, `servers.*`|`address_label`, fatal: labels never carry addresses|
|`passhostheader`|`pass_host_header`|
|`healthcheck.{path,interval,timeout,method,scheme,hostname,port,status,headers.*}`|`health_check`. `path` is required. Defaults are Traefik's: 30 s and 5 s (the daemon wants them written), healthy on 200 to 399. Durations are Go durations or seconds and must be whole seconds. `followredirects=false` is accepted, `true` is not (podgate's probe never follows); `mode` (gRPC) is refused|
|`sticky.cookie` and `.name`, `.secure`, `.httponly`, `.samesite`, `.maxage`, `.path`|`sticky.cookie`. A snapshot with `sticky` needs a `skew_secret`. `.domain` is refused|
|`serverstransport`, `responseforwarding.*`, `strategy`, other service types|`unsupported_label`|

## Middleware labels

`traefik.http.middlewares.<m>.<type>.*` with the type and option names in any case. One type per middleware. Every option is read by name; an option nobody reads is an `unsupported_label` naming its key, so a typo or an unsupported option can never turn a protection off.

|Traefik|podgate type|Notes|
|---|---|---|
|`stripprefix.prefixes`|`strip_prefix`|`forceslash` is refused|
|`stripprefixregex.regex`|`strip_prefix_regex`|checked with `regex`|
|`addprefix.prefix`|`add_prefix`||
|`replacepath.path`|`replace_path`||
|`replacepathregex.{regex,replacement}`|`replace_path_regex`||
|`redirectscheme.{scheme,port,permanent}`|`redirect_scheme`||
|`redirectregex.{regex,replacement,permanent}`|`redirect_regex`||
|`headers.{customrequestheaders.*,customresponseheaders.*}`|`headers.request`, `.response`|an empty value removes the header|
|`headers.{stsseconds,stsincludesubdomains,stspreload,contenttypenosniff,framedeny,customframeoptionsvalue,referrerpolicy,permissionspolicy,contentsecuritypolicy,contentsecuritypolicyreportonly}`|`headers.response.security`|`stsseconds=0` sends no header; `forcestsheader=true` is refused (podgate sends HSTS on TLS connections only)|
|`headers.accesscontrol*`, `addvaryheader`|`headers.cors`|`Vary: Origin` only when `addvaryheader=true`, as in Traefik (podgate's own default adds it)|
|`compress.{encodings,minresponsebodybytes,includedcontenttypes,excludedcontenttypes}`|`compress`|encodings default to `gzip, br, zstd`, Traefik's set; `defaultencoding` is refused|
|`ratelimit.{average,period,burst,sourcecriterion.*}`|`rate_limit`|`average` of 0 or none is refused (Traefik reads it as unlimited); `burst` defaults to 1; one source criterion: `ipstrategy.{depth,excludedips,ipv6subnet}`, `requestheadername` or `requesthost`|
|`ipallowlist.{sourcerange,ipstrategy.*}`|`ip_allow_list`||
|`basicauth.{users,realm,headerfield,removeheader}`|`basic_auth`|`usersfile` is refused: a path inside the proxy|
|`retry.{attempts,initialinterval}`|`retry`||
|`circuitbreaker.{expression,checkperiod,fallbackduration,recoveryduration,responsecode}`|`circuit_breaker`|`NetworkErrorRatio() > r`, `ResponseCodeRatio(from, to, over_from, over_to) > r` and `LatencyAtQuantileMS(q) > ms` map to `trip_when`; combined expressions and other comparisons are `unsupported_rule`|

Refused as `unsupported_label`: `forwardauth` (it names an address, which no label may; declare it in the file source), `chain` (name the middlewares in the router's `middlewares`), plugins, `ipwhitelist` (deprecated in Traefik) and every type not listed. A type whose daemon spec is not built is still emitted; the daemon answers `middleware_not_built` and the provider reports it.

## Not translated

`unsupported_label` with the exact key, reported and not applied: TCP and UDP labels (`traefik.tcp.*`, `traefik.udp.*`: the file translator covers L4), `traefik.tls.*`, `traefik.docker.*` (the network is the source's `network`), plugins, and `serverstransport` references (declare the transport with `podgate.transport.<name>.config`).

## Tests

`cargo nextest run -p podgate-provider --test traefik_rules` (the rule table, nesting, negation, v2 syntax, unknown functions, bad regexps, `HostRegexp`, priorities against the real `traefik`, podkit's labels, every middleware, unsupported labels, address labels, the Docker source, and the translated apps against the real daemon's `POST /v1/snapshot/validate`), and the unit tests of `podgate-rule`.
