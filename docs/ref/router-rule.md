# Router rule strings

A router can carry a Traefik rule string in `rule` instead of a `match` tree, for tooling and people who already write Traefik rules:

```json
{ "name": "api", "rule": "Host(`a.test`) && PathPrefix(`/api`) && !Method(`DELETE`)", "service": "web" }
```

Code: `src/router/rule.rs`. The grammar is `crates/podgate-rule` (`docs/ref/provider-traefik.md`, `## Rules`), the same parser the providers translate labels and files with; the daemon never reads rule text itself. The string is only an input syntax. The router compile pass in `src/compile.rs` replaces it with the matcher tree the parser returns before any other step looks at the router, so claims, specificity, disjointness, the catch-all rule, explain and the plan diff see one representation, and a rule can never get a check a tree would not.

## Fields

|Field|Meaning|
|---|---|
|`rule`|A Traefik v3 rule, at most 2048 bytes. Exactly one of `match` and `rule` is set: both, neither, or `"match": null` is `422` `invalid_router`.|
|`priority`|Explicit priority. Absent on a router with `rule`: the rule's length in bytes, as Traefik does. A router with `match` keeps the platform default `0`. Priority orders routers of one tenant only; it never lets a tenant take another tenant's host.|

The same field exists on a TCP router (`app.tcp.routers[]`), parsed with the L4 functions `HostSNI`, `HostSNIRegexp`, `ALPN` and `ClientIP`. A TCP router has no `priority`, so the length rule does not apply. A TCP router with neither `match` nor `rule` is still the entry point's catch-all (`docs/ref/l4-tcp.md`), and ``HostSNI(`*`)`` is the same catch-all; both set is `invalid_router`. An HTTP function on a TCP router and an L4 function on an HTTP router are `invalid_rule`.

## Errors

Every error is a `422` entry with `at` (`router NAME` or `tcp router NAME`), `app`, `declared_by` and, when the text has a place for it, `position`: the byte offset in the rule.

|Code|When|
|---|---|
|`invalid_router`|Both or neither of `match` and `rule`.|
|`invalid_rule`|A rule over 2048 bytes. A syntax error. A function of the other dialect, or with the wrong number of arguments. A regular expression the `regex` crate does not compile, or one whose compiled form is over the size limit that every regexp matcher leaf has (1 MiB; `position` is where the pattern starts). A tree the matcher refuses, such as nesting deeper than eight levels.|
|`unsupported_rule`|Traefik syntax podgate does not translate: Traefik v2 functions (`Headers`, `HostHeader`, ...), `{name:regex}` groups, a bare `Query(`name`)` (presence only), unknown function names.|
|`catch_all_not_allowed`, `host_conflict`, `cross_tenant_wildcard`, ...|The ordinary rules on the tree: `HostRegexp` alone is a catch-all and needs an entry point reserved to the tenant or `CATCH_ALL_TENANTS`; `Host && HostRegexp` is a narrowing; another tenant's host is a conflict. Rule text is never inspected to decide whether a regexp is anchored.|

## Explain and plan

`GET /v1/explain` shows `matched.rule` and `matched.match`, the rule and the tree it compiled to, side by side; both are absent for a router declared with `match`. `matched.priority` is the effective one.

The plan diff and the app's fingerprint compare the compiled tree with the operands of `all`/`any` and the name lists put in a fixed order, and the effective priority. So changing spacing, the order of arguments (`Method(`GET`, `POST`)`), the order of operands or redundant parentheses is not a change when `priority` is explicit. Without a `priority`, the rule's length is one: a rewrite that changes the length changes the order the router takes, and is a change.

## Providers

Providers keep translating (`docs/ref/provider-traefik.md`) so they can quarantine one object and emit trees. A provider that forwards `rule` instead loses no checks: the daemon applies the same ones.
