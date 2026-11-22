# Middleware `opa`

Reference for the kind in `src/middleware/opa.rs` (with its answer reader in `src/middleware/opa/verdict.rs`). The model it plugs into is in `docs/architecture.md` (`### Middlewares`, rule 4). Change 0126.

Asks an [Open Policy Agent](https://www.openpolicyagent.org/), or any server that speaks its REST Data API, whether a request may continue. Allowed requests go on, denied ones get `403`, and **a policy server that fails closes the door**. This is Traefik Hub's OPA middleware; Caddy has none. The policy and its data live in OPA; podgate only asks.

```json
{
  "name": "policy",
  "type": "opa",
  "address": "http://10.0.0.7:8181/v1/data/podgate/authz",
  "request_headers": ["x-api-key"],
  "response_headers": ["x-user"],
  "include_query": false,
  "timeout_secs": 2,
  "transport": "internal"
}
```

| Field | Meaning |
|---|---|
| `address` | Required. The Data API URL of one policy: an absolute `http://` or `https://` URL whose host is an IP literal or a host name (same rules as `forward_auth`, `docs/ref/mw-forward-auth.md`), ending in `/v1/data/<policy path>`. A prefix before `/v1/data/` is allowed. No query string (`?pretty`, `?explain` and the like are `invalid_middleware`), no credentials, no `h2c://`. Fixed configuration: never derived from the request. |
| `include_query` | Default `false`. When `true`, `input.query` holds the request's raw query string. A query often carries tokens, so it is not sent unless asked for. |
| `request_headers` | Client headers sent as `input.headers`: case-insensitive names, at most 64. Default none, so `authorization` and `cookie` are sent only when listed. The reserved names of `forward_auth` (`Host`, `Content-Length`, `Connection`, `Proxy-*`, `Forwarded`, `X-Forwarded-*` and so on) are `invalid_middleware`; `input.source_ip` and `input.host` carry what they would say. |
| `response_headers` | Names the policy may set in its result (see below), at most 64, none reserved, none also in `request_headers` (the client's copy is removed before the call, so the policy would never see it). Default none. |
| `timeout_secs` | One bound for connecting, sending and reading the whole answer. Default 2, 1 to 10; a call also never outlives the process's `REQUEST_TIMEOUT_SECS`. |
| `transport` | Name of a `servers_transport` of the app: CA, SNI and client certificate of an `https://` address. Use it for mutual TLS to OPA; there is no bearer token option. The call is always HTTP/1.1. A transport with TLS options on an `http://` address is `invalid_middleware`; an undeclared name is `unknown_transport`. |
| `max_response_bytes` | The cap of the answer's body. Default 16384, at most 1048576. |
| `max_concurrent` | Calls in flight at once for this middleware. Default 64, at most 4096. |

Unknown fields (`include_body`, a bundle or data push) are `invalid_middleware`: a setting is never ignored.

## The call

```
POST /v1/data/podgate/authz HTTP/1.1
Host: 10.0.0.7:8181
Connection: close
Content-Type: application/json
Accept: application/json
Content-Length: <n>

{"input": { ... }}
```

The `input` has these keys and no others:

| Key | Value |
|---|---|
| `method` | The request method. |
| `path` | The request path as this stage sees it: already normalized by the entry stage, and after any rewrite stage (`strip_prefix`, `replace_path`) placed before this one. |
| `query` | The raw query string, only with `include_query` and only when the request has one. |
| `host` | The host the client asked for: a trusted peer's `X-Forwarded-Host`, else the request's authority or `Host`. Lower case, no port. |
| `source_ip` | The resolved client address (`docs/ref/client-ip.md`), as text. Omitted when the connection has no IP peer. |
| `tenant`, `app` | The ids of the tenant and the app the request was routed to. |
| `headers` | `{name: [values]}` for the names of `request_headers` the request has, lower-case names, `{}` when none. Always lists, never a string: a header that turned from a string into an array when a client repeated it would let a duplicate slip past a deny rule. A value that is not UTF-8 is sent with replacement characters, so the header stays present. |
| `claims` | The verified claims object of a `jwt_auth` stage placed **before** this one in the chain. Present only when such a stage verified a token; otherwise the key is absent, so `input.claims.role` is undefined in Rego and denies. With two `jwt_auth` stages the last one that verified wins. |

The request body is never sent. A call whose head and body pass 32 KiB is not sent and the request gets `503`.

### Claims cannot be forged

`claims` comes from the `jwt_auth` stage's own verification, handed to this stage inside the proxy. It is never read from a request header, so a client that sends `X-Claims: {"role":"admin"}` gets that text under `input.headers` (when listed), where the policy can see it is the client's, and never under `input.claims`. An `opa` stage placed before the `jwt_auth` stage sees no claims, which fails safe. Put `jwt_auth` first.

## What comes back

The answer is read as strictly as the HTTP framing. It must be `200` with one JSON object body. `result` decides:

| Body | The client gets |
|---|---|
| no `result` key (OPA's answer for an undefined document: `{}`) | `403` |
| `{"result": true}` | the request continues |
| `{"result": false}` | `403 {"error":"forbidden"}` |
| `{"result": {"allow": bool, "status"?, "headers"?}}` | by `allow` |
| anything else | `503 {"error":"authorizer unavailable"}` |

For an object result, `allow` must be a boolean; other keys (`reason`, a debugging field) are ignored. `status` is an integer in `401..=499` and the status of a deny (default `403`); it is checked even when `allow` is true and ignored there. `headers` is an object of string values whose names are all in `response_headers`; each goes where the verdict goes:

- **Allow.** Into the request that goes on to the upstream.
- **Deny.** Into the client's response (`www-authenticate` on a `401`, `retry-after` on a `429`), except names a refusal never relays (`Content-Encoding`, `Alt-Svc`, `Server`, `Date`). The body (`{"error":"unauthorized"}`, the lower-case reason phrase of the status), its `content-type`, `content-length` and `cache-control: no-store` are podgate's own.

A deny is `403` or the policy's `status`, and a failure is always `503`, never the same code, so an operator can tell a policy from an outage. The access log `reason` is `opa_denied`, `opa_unavailable` or `opa_saturated`.

### No forged identity

Before the call, the middleware removes from the client's request every header `response_headers` names. A client that sends `X-User: admin` cannot have it survive when the policy leaves it out. A request into which an allow put at least one header is a credentialed request: the `cache` stage bypasses it, as for `forward_auth`.

## Fail closed

Each of these answers `503 {"error":"authorizer unavailable"}` and the request never reaches the upstream:

- the upstream address policy refuses the address (`docs/ref/upstream-policy.md`, counted in `podgate_upstream_refused_total{tenant}`), or the host name does not resolve;
- no connection, or a timeout;
- an answer body over `max_response_bytes`, a head over 8 KiB or with more than 100 headers, or an answer that is not clean HTTP/1.1;
- a status other than `200` (a `404` for a policy path that does not exist is a failure, not a deny);
- a `result` that is not a verdict: not JSON, not an object, `null`, a string, a number, an array, an object with no boolean `allow`, a `status` outside `401..=499`, a header that is not in `response_headers`, an invalid header name or value;
- no free permit of `max_concurrent`, or a tenant buffer budget that is full right now. These two also send `retry-after: 1` and are capacity refusals (auto-revert does not count them).

There is no fail-open option and no decision cache: a stale allow is a security risk, and a cache needs its own invalidation rules.

## Bounds and safety

- **Where.** Only the address in the configuration. The exact IP is checked against the upstream address policy of the calling tenant on every call, for a name on every answer of its resolution, so a tenant whose allow list excludes another tenant's authorizer cannot reach it. The connection is never reused and a redirect is never followed.
- **Memory.** Before connecting, podgate charges the tenant's buffer budget `max_response_bytes` plus a 48 KiB allowance (`docs/ref/mw-forward-auth.md`, Bounds and safety). A budget full right now answers `503` and nothing is dialled. A deploy whose tenant `max_buffer_bytes` could never hold one call is `invalid_middleware`.
- **Time and concurrency.** `timeout_secs` covers connect, request and answer; one permit of `max_concurrent` is held for the call and survives a push that leaves the declaration as it was.
- **Order.** The chain runs before a revision, a tenant slot or a backend permit is taken: a refused request costs the tenant no in-flight slot and wakes no sleeping app.

## An example policy

```rego
package podgate.authz

import rego.v1

default allow := false

# Admins may do anything.
allow if input.claims.role == "admin"

# Anyone with a verified token may read the public API.
allow if {
	input.method == "GET"
	startswith(input.path, "/api/public/")
	input.claims.sub
}

# A service key from the office network.
allow if {
	input.headers["x-api-key"][0] == "s3cret-key"
	net.cidr_contains("10.0.0.0/8", input.source_ip)
}
```

For this policy the Data API at `/v1/data/podgate/authz/allow` answers `{"result": true}` or `{"result": false}`. At `/v1/data/podgate/authz` (the package, as in the first example above) it answers `{"result": {"allow": true}}`, an object whose boolean `allow` is read and whose other rules are ignored. A policy that picks a status and headers returns an object; point `address` at the rule:

```rego
package podgate.authz

import rego.v1

decision := {"allow": true, "headers": {"x-user": input.claims.sub}} if {
	input.claims.sub
}

decision := {"allow": false, "status": 401, "headers": {"www-authenticate": "Bearer realm=\"podgate\""}} if {
	not input.claims
}
```

with `"address": ".../v1/data/podgate/authz/decision"` and `"response_headers": ["x-user", "www-authenticate"]`. When neither rule matches, `decision` is undefined and OPA answers `{}`, which is a deny.

## Plan and explain

In `POST /v1/snapshot/plan`, a change that gives the policy less to decide with, or another policy to decide, is a posture change:

| Kind | When |
|---|---|
| `opa_removed` | The middleware is gone (or replaced by another kind). |
| `opa_policy_changed` | The server or the path of `address` differs: another authorizer or another policy decides. |
| `opa_input_reduced` | A name of `request_headers` is dropped, or `include_query` goes from `true` to `false`: a rule that denied on it can no longer do so. |
| `upstream_tls_verification_disabled` | The transport stops verifying the policy server's certificate. |

Sending more (a header added, `response_headers`, a new timeout) lists nothing. Explain shows the whole configuration; the address carries no secret because a query is refused.

## Not here

No decision cache, no bundle or data push to OPA, no `?explain` or `?metrics`, no bearer token for the OPA server (use `transport` with a client certificate), no request body in the input, no gRPC, no claims from an `oidc` session.
