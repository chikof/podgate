# Middleware `mcp_gateway`

Reference for the kind in `src/middleware/mcp.rs` and its files under `src/middleware/mcp/` (`access.rs` the `tool_access` rules, `rpc.rs` the JSON-RPC envelope, `server.rs` the exchanges with one registered server, `sse.rs` the event-stream reader, `sessions.rs` the session table, `tools.rs` the tool names and catalogs). The model it plugs into is in `docs/architecture.md` (`### Middlewares`). Changes 0132 and 0133.

Presents several MCP servers to a client as one. An app declares a registry of servers; the router that carries the middleware is the endpoint; `tools/list` returns the tools of every registered server and `tools/call` goes to the server that owns the tool. A client needs one URL and one credential, whatever sits behind it. This is the MCP gateway of Traefik Hub; Caddy has none.

```json
{
  "name": "tools",
  "type": "mcp_gateway",
  "servers": [
    { "name": "search", "address": "http://10.0.0.5:8080/mcp" },
    { "name": "files", "address": "https://10.0.0.6/mcp", "timeout_ms": 5000, "max_concurrent": 8 }
  ],
  "allowed_origins": ["https://app.example.com"]
}
```

Put it on a router of its own (`{"path": "/mcp"}`, say) and declare the stages that judge a request before it in the chain: `jwt_auth`, `oidc`, `ip_allow_list`, `rate_limit`. A gateway with `tool_access` needs a `jwt_auth` or an `oidc` before it. The middleware answers every request it gets and never contacts the app's own service.

| Field | Meaning |
|---|---|
| `servers` | Required, 1 to 16. Each is `{name, address, timeout_ms?, max_concurrent?}`. |
| `servers[].name` | The name clients see before the tool. Unique in the middleware, 1 to 32 characters of `a-z`, `0-9` and `-`, starting and ending with a letter or digit. It holds no `_`, which keeps qualified names unambiguous. |
| `servers[].address` | The server's MCP endpoint: an absolute `http://` or `https://` URL whose host is an IP literal or a host name (the rules of `forward_auth.address`, at most 512 bytes). The query is sent and never shown. |
| `servers[].timeout_ms` | One bound for one exchange with the server (connect, send, read its whole answer). Default 30000, 100 to 600000; an exchange also never runs past `REQUEST_TIMEOUT_SECS`. |
| `servers[].max_concurrent` | Exchanges with the server at once. Default 32, 1 to 1024. |
| `allowed_origins` | At most 16 origins (`scheme://host[:port]`, lower-cased) that may call the endpoint from a browser besides its own host. |
| `tool_access` | Optional list of rules that say which tools a caller may see and call, by the claims of the caller's verified JWT or `oidc` session. Absent: every tool is open. Present, even `[]`: a tool is closed unless a rule opens it. See `## Tool access`. |
| `record_arguments` | Optional, default `false`. Keep the `arguments` of every `tools/call` in the audit log, secrets redacted. See `## Audit`. |

Unknown fields are `invalid_middleware`. A tenant whose `max_buffer_bytes` is below what one `tools/call` reserves (6 MiB and 48 KiB: the largest client body, the request to the server, the largest result and the exchange's buffers) is refused when the snapshot compiles, naming the tenant and the bytes.

## Protocol

Streamable HTTP, JSON-RPC 2.0, revisions `2025-11-25` and `2025-06-18` of the Model Context Protocol (`MCP-Protocol-Version` names the one in use; a version the gateway does not speak is `400`, and an absent header is accepted). The revision `2026-07-28` removes `initialize` and sessions and is not implemented; its clients fall back as its Backward Compatibility section says.

| Request | Answer |
|---|---|
| `POST` with one request | `200` and one JSON answer. |
| `POST` with a notification or a response | `202`, no body, nothing forwarded. |
| `POST` with a batch (an array) | `400`, JSON-RPC `-32600`. |
| `POST` that is not JSON | `400`, `-32700`. |
| `POST` that is not `application/json` | `415`. |
| `POST` body over 1 MiB | `413`. |
| `GET` (the standalone stream), `PUT`, `PATCH`, `OPTIONS` | `405` with `Allow: POST, DELETE`. The gateway offers no server-to-client stream. |
| `DELETE` with a session | `204` and the session is gone; an unknown one is `404`. |
| `Origin` that is neither the endpoint's own host nor in `allowed_origins` | `403` (the transport's rule against DNS rebinding). A request with no `Origin` is not a browser's and passes. |

| Method | What the gateway does |
|---|---|
| `initialize` | Answers itself: the version asked for when it is supported, else `2025-11-25`; `capabilities` with `tools` only (`listChanged: false`); `serverInfo` podgate. Opens a session and returns it in `Mcp-Session-Id`. |
| `ping` | `{}`. |
| `tools/list` | The tools of every server that answered, under qualified names, in registry order. Cursors are not supported: the list is whole and a `cursor` is `-32602`. |
| `tools/call` | Routed by the qualified name; see below. |
| any other | `-32601`. Resources, prompts and the requests a server sends to a client (sampling, elicitation) need the standalone stream and are not offered. |

Every request except `initialize` needs `Mcp-Session-Id`: none is `400`, an unknown, expired or foreign one is `404` (the client then starts a new session, as the transport says).

## Tool names

A tool is called `<server>__<tool>`: the registered server's name, two underscores, the tool's name as that server reports it. Two servers may both have a `search`; the client sees `alpha__search` and `beta__search`, and a call to one never reaches the other.

The gateway builds every name it lists, and a name a client sends resolves through the registry alone: the text before the first `__` must be a registered server's name exactly, and the rest a tool in that server's catalog. Nothing else of the request picks a server: not a `server` field of the params, not a header, not `_meta`. A tool name may hold `__` (`alpha__a__b` is alpha's `a__b`). A name that leads nowhere is `-32602 unknown tool`, and a name hidden from the caller by per-tool authorization gets the same answer, so a name reveals nothing about what exists.

Tools of a server that the catalog cannot carry are left out and counted as `skipped_tools`: an empty name, a name with a control character, a repeated name (the first stays), a name that makes the qualified name longer than 128 bytes, more than 512 tools.

`tools/call` is forwarded with the tool's own name and everything else of the client's params untouched (`arguments`, `_meta`), and the server's `result` (or `error`) comes back byte for byte, with the client's id. The catalog a call checks is the server's last list, trusted for 60 seconds; a cold or older one is fetched first (a `tools/list` to that server, never a `tools/call`). A call to a tool no fresh catalog has sends nothing.

## The servers

The gateway is an MCP client of every registered server, with a session of its own for each client session and server, opened on the first request that needs it (`initialize` with the newest version, then `notifications/initialized`) and kept until the client's session ends. A server that forgets it (`404`) is opened again once, invisibly. Every exchange is one HTTP/1.1 `POST` on a connection of its own, never pooled. What it sends is the gateway's: `Host`, `Accept: application/json, text/event-stream`, `Content-Type`, `Content-Length`, `MCP-Protocol-Version`, `Mcp-Session-Id` when the server issued one. Nothing of the client's request is copied, so the client's `Authorization` never reaches a server. A server that needs credentials is not supported yet.

The answer is `application/json` or `text/event-stream`. From a stream the gateway takes the event that holds the response to its request and stops reading there, so a server that leaves the stream open still answers; notifications before it are ignored. `tools/list` follows `nextCursor` up to 8 pages.

- **Where.** Every dial goes through the operator's upstream address policy (`UPSTREAM_POLICY_FILE`, `docs/ref/upstream-policy.md`) for the tenant, on the exact address about to be dialled; a host name is resolved once per exchange and each answer is checked. A refused address is a failed server.
- **How much.** An exchange holds one permit of the server's `max_concurrent` and charges its bytes (the exchange's buffers, the request, the answer's cap: 64 KiB for `initialize`, 1 MiB a `tools/list` page, 4 MiB a `tools/call`) to the tenant's buffer budget before it connects. A request body is charged its length. An answer over its cap is a failure.
- **Fail closed.** A server that is down, slow, refused by the policy, over a cap, answers a status other than `200`, is not speaking MCP, or answers a result that is not an object is left out of `tools/list` and its calls are `-32603` with `data: {"server": "...", "reason": "..."}`, the reason being one of `policy`, `connect`, `timeout`, `status`, `malformed`, `too_large`, `version`, `session`. No permit, or no room in the budget, is `-32000 server busy`. A JSON-RPC error a server chooses to answer a call with is passed on as its own.

## Tool access

Tool-based access control, as in Traefik Hub's MCP gateway; Caddy has none. A route that serves MCP says which tools a caller may see and call, by the claims of the token the `jwt_auth` stage verified, or of the session the `oidc` stage verified. Change 0133, and change 0139 for `oidc`.

```json
{
  "name": "tools",
  "type": "mcp_gateway",
  "servers": [
    { "name": "search", "address": "http://10.0.0.5:8080/mcp" },
    { "name": "files", "address": "http://10.0.0.6:8080/mcp" }
  ],
  "tool_access": [
    { "tools": ["search__*"], "allow": { "roles": ["dev", "admin"] } },
    { "tools": ["files__read_file", "files__list_dir"], "allow": { "roles": ["dev", "admin"] } },
    { "tools": ["files__*"], "allow": { "roles": ["admin"] } }
  ]
}
```

| Field | Meaning |
|---|---|
| `tool_access[].tools` | 1 to 64 entries. Each is `<server>__<tool>`, the name a client sees, or `<server>__*` for every tool of that server, including tools it adds later. The server must be in `servers`. A bare tool name, an unknown server, an empty tool and a `*` inside a name (`files__re*`) are `invalid_middleware`. A tool literally named `*` is reached only through the wildcard. |
| `tool_access[].allow` | 1 to 8 claims, each with 1 to 32 non-empty string values. The caller may use the rule's tools when every claim holds one of its values. An empty `allow` is `invalid_middleware`: it would open the tools to every verified token. To say that on purpose, name a claim every token holds, such as `iss`. |

At most 64 rules. A claim name is at most 64 bytes and a value at most 256.

**The default is deny once rules are in force.** `tool_access` absent means the feature is off and the gateway behaves as without it: every tool of every healthy server is listed and callable. `tool_access` present, even as `[]`, means a tool is open only when some rule lists it and the caller's claims hold. `[]` is a lockdown: the registry stays declared and serves nothing. Adding `tool_access` to a gateway tightens it. Removing it opens every tool again and is a posture change (`mcp_tool_access_removed`).

**What a rule matches.** A caller may use a tool when some rule lists it and the verified claims of the caller hold for that rule. The tool is the gateway's own `(server, tool)` pair, resolved from the registry: `files__read_file` is the tool `read_file` of the server `files`, and a rule for `search__query` never opens a `query` tool of another server. Nothing the client sends picks the server or grants a tool: not a header, not a `server` field of the params, not `_meta`. The claims are those a `jwt_auth` stage verified in the token, or an `oidc` stage verified at login and sealed into the user's session. A header or cookie the client wrote is never read, and a request with no verified token or session never reaches the rules (`jwt_auth` answers it `401`; `oidc` answers a browser with the redirect to its login and any other client `401`). The claim matching is the one of `jwt_auth`'s `required_claims`: a string claim equal to a value, or an array claim with an item equal to a value. A claim that is absent, a number, a boolean, an object, `null` or an empty array denies. A `scope` claim written as one space separated string is one value, so use an array claim. Values are compared exactly, with case.

Only the claims of a stage that verified them count: `jwt_auth` or `oidc`, whichever is earlier in the chain, the same stages the developer portal accepts as a login (`docs/ref/portal.md`). A `jwt_auth` the portal cannot pin (no issuer, several audiences, a private transport) still counts here. A session holds `sub` and the claims named in the `oidc` stage's `forward_claims` and `required_claims` only, so a claim a rule reads must be named in one of them, or it is absent and denies. A gateway with `tool_access` and neither a `jwt_auth` nor an `oidc` earlier in the chain of its router is `invalid_middleware` (`tool_access_requires_identity`), and so is one where only some of its routers have it.

**What a denied caller sees.** A tool the caller may not use is left out of `tools/list`. A `tools/call` for it answers `-32602 unknown tool`: the same code, text and bytes as a tool nobody registered, and nothing is dialled upstream. The same holds for a server none of whose tools the caller may use: calls under its name answer `-32602 unknown tool` without a catalog fetch, and `tools/list` does not ask that server, so a caller cannot learn which servers exist or which are down. A distinct `forbidden` answer would let any caller list the tools of every server by probing.

Rules run on the compiled rules in memory on every request: no outbound call and no cache. A session carries no authorization, so a new token on the same `Mcp-Session-Id` is judged by its own claims. A push that changes the declaration drops the sessions.

**Plan.** Widening `tool_access` is a posture change in `POST /v1/snapshot/plan`: `mcp_tool_access_widened` when a rule lets someone use a tool they could not (a tool, a value, a wildcard or a rule added, or a claim dropped from `allow`), and `mcp_tool_access_removed` when `tool_access` is gone. Tightening is not listed. The comparison is conservative: it does not unite two old rules, so merging two rules into one is listed although it opens nothing new.

**Explain and metrics.** `GET /v1/overview` and explain show the rules as `tool_access` beside `servers`: `null` when absent, else the rules in declaration order with their claims in name order. A denial is counted in `podgate_mcp_denied_total{tenant,app}`: the calls the rules refused, summed over the app's gateways, one series per app with `tool_access`. Past `METRICS_SERIES_PER_TENANT` apps of a tenant, the rest are summed into `app="other"`. A denial is logged at `info` with the `tool` the client named and the token's `sub`, each cut at 128 bytes. A name that leads nowhere for everyone is not counted. The counter restarts when the declaration changes.

**Not covered.** Rules on arguments (allow `delete_file` only under `/tmp`) need a policy language and the call's arguments. The `opa` middleware does not send the request body, so it cannot do that today.

## Sessions

The table holds at most 1024 sessions per tenant and expires a session after 30 minutes without a request. A tenant at its limit loses its own least recently used session; it never evicts another tenant's. A session belongs to the tenant, the app and the declaration that opened it: another tenant's id, another app's, or an id from before a push that changed the middleware is `404`. A push that leaves the declaration as it was keeps the sessions. The limits are the operator's (constants), not a tenant's setting.

## Overview

`GET /v1/overview` shows the registry in the `middlewares` of the app: each server with its `name`, `address` (without its query), `timeout_ms`, `max_concurrent` and `health`, and `tools` and `skipped_tools` once a catalog is known. `health` is what the last real exchange showed: `unknown` before any, `healthy` after a good answer, `down` with a `reason` after a failure. There is no background probe; a server nobody asked about stays `unknown`. A push that leaves the declaration as it was keeps the health and the catalogs; a changed one starts over.

## Audit

Every `tools/call` leaves a record for the operator (who, which server and tool, the outcome, the time it took), listed on the admin socket and, with `MCP_AUDIT_FILE`, appended to a file; the operator can also send a recorded call again. Nothing changes for a client. `record_arguments: true` also keeps the call's `arguments`, up to 16 KiB, with every value under a key that looks secret replaced by `[redacted]`; results are never kept. Reference: `docs/ref/mcp-audit.md`.
