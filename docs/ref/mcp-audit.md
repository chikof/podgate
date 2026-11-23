# MCP audit log and replay

Reference for `src/mcp_audit.rs` (the record, the redaction, the rings, the file queue), `src/admin/mcp_audit.rs` (the two admin routes) and the replay in `src/middleware/mcp.rs`. The gateway it records is `docs/ref/mw-mcp-gateway.md`.

Every `tools/call` an `mcp_gateway` handles leaves one record: who called which tool of which server, how it ended and how long it took. An operator can list the recent records and send a recorded call again. This is the audit side of Traefik Hub's MCP gateway; Caddy has none.

The log is for the operator. It is read on the admin unix socket and, with `MCP_AUDIT_FILE`, in a file. There is no tenant endpoint, the dashboard has no route for it, and the event feed carries nothing of it.

## The record

One record per `tools/call`, whatever way it ends: a call that never resolved to a tool is recorded too (a probe is worth seeing).

| Field | Meaning |
|---|---|
| `seq` | Increasing across the process, from 1. A listing pages by it. |
| `at_unix_ms` | When the call finished. |
| `tenant`, `app` | The app of the gateway. |
| `router` | The router that carried the request; empty for a replay. |
| `middleware` | The name of the `mcp_gateway` middleware. A replay finds its gateway by it. |
| `name` | The tool name the client sent, cut to 128 bytes. Client text. |
| `server`, `tool` | The registered server and the tool the name resolved to, as the registry and the server's catalog know them. `null` when the name did not resolve, and for a call that a rule of `tool_access` refused before its tool was known. Never client text. |
| `sub` | The `sub` of the token a `jwt_auth` stage verified, cut to 256 bytes. `null` without one. A header the client sends never sets it. |
| `session` | The first 16 hex characters of the SHA-256 of the `Mcp-Session-Id`, so the calls of one session correlate and the id is never kept. `null` for a replay. |
| `outcome` | See below. |
| `reason` | `null` for `ok`, `tool_error` and `denied`. `server`, `invalid_params` or `unknown_tool` for `rpc_error`. The failure code for `upstream_failed`: `busy`, `policy`, `connect`, `timeout`, `status`, `malformed`, `too_large`, `version`, `session`. |
| `rpc_code` | The JSON-RPC `code` of an error the server answered, else `null`. |
| `duration_ms` | From the start of handling the call to its answer. |
| `request_bytes`, `response_bytes` | The size of the client's `params` and of the server's `result` or `error` as it came; `0` when there was none. |
| `arguments_state` | `absent` (the call had none), `kept`, `redacted` (kept, with a value replaced), `not_recorded` (the gateway does not set `record_arguments`, or they were not valid JSON), `too_large` (over 16 KiB). |
| `arguments` | The stored arguments; `null` unless `kept` or `redacted`. |
| `replay_of` | The `seq` of the record a replay sent again; `null` otherwise. |

| `outcome` | Meaning |
|---|---|
| `ok` | The server answered a result. |
| `tool_error` | The server answered a result with `isError: true`. |
| `rpc_error` | A JSON-RPC error: the server's (`reason: server`, with its `rpc_code`), or the gateway's `-32602` for bad params (`invalid_params`) and a name that leads nowhere (`unknown_tool`). |
| `denied` | `tool_access` refused the caller the tool, or every tool of its server. The client got the answer of a tool nobody registered; the audit is where the difference is. Nothing was dialled. |
| `upstream_failed` | The exchange with the server failed, or its catalog could not be had. |

**Results are never stored.** The result is scanned for `isError` and measured, and nothing of it is kept, in the ring or in the file. `_meta` of the params is not stored either.

## Arguments

Off by default. An `mcp_gateway` with `"record_arguments": true` keeps the `arguments` of its calls, so a tenant opts in for its own app.

- Arguments over 16 KiB are not parsed and not kept (`too_large`).
- Otherwise every value under a key that looks secret is replaced by the string `[redacted]` before anything is stored, at any depth and in any array, whatever the value's type (an object under `token` is replaced whole). A key looks secret when, lower-cased with `_`, `-` and spaces removed, it contains `password`, `passwd`, `token`, `secret`, `authorization`, `apikey`, `credential`, `cookie` or `privatekey`. The match is deliberately wide: `max_tokens` is redacted too, because a lost value costs a `422` on replay and a leaked one costs a secret.
- A secret inside a free-text value (a prompt that holds a password) is not found. That is why recording is opt-in.

## The ring

The last 1000 records of each app, in memory, oldest dropped first. Three more bounds:

- **Bytes.** All rings of one tenant together retain at most 8 MiB (the size of a record plus its text and arguments). A record that pushes its tenant over trims the oldest records of its own app's ring, so one noisy app cannot evict another's. The overshoot is at most one record per app. The store is the operator's memory and is not charged to the tenant's request `max_buffer_bytes`. The limits are constants of the daemon, not a tenant's setting.
- **Apps.** A push that no longer has an app drops its ring, so apps that come and go cannot grow the log. An app id that a push gives to another tenant starts empty.
- **Tenants.** A ring remembers its tenant. It is only ever read with the tenant of the live app, so records never cross tenants.

The ring is not a durable log. A client can push other records out of its app's ring by calling tools that do not exist; `MCP_AUDIT_FILE` is the durable record and a `rate_limit` stage before the gateway is the brake.

## Listing

`GET /v1/apps/{app}/mcp/audit?after=<seq>&limit=<n>`, on the admin socket only.

`200 {"boot_id", "evicted_through", "records", "next_after"}`: the records after `after` (default 0), oldest first, at most `limit` (default 100, 1 to 1000). `next_after` is the last `seq` listed, or `after` when none, so `after=<next_after>` resumes without a gap or a repeat. `evicted_through` is the highest `seq` the ring of this app has dropped: a reader whose `after` is below it lost records. `boot_id` is the event feed's: when it changes the process restarted and `seq` starts again from 1.

`400` for an `after` or a `limit` that is not a number or out of range. `404` when the live table has no such app.

## The file

`MCP_AUDIT_FILE` unset: the rings only. Set: one JSON line per record, the object the listing returns, appended through the bounded queue of the access log. The file is created with mode `0600` and reopened when the path names another inode, so renaming it rotates it. The call path only appends to a queue of 1024 lines under a lock nobody holds for long; a full queue drops its oldest line and counts it, so a stalled sink costs lines, never latency. `podgate_mcp_audit_lines_total` and `podgate_mcp_audit_dropped_total` count what was written and what was dropped (a full queue, or a failed write); they exist only with the variable set.

The file is checked at startup: a path that is a directory, or that cannot be opened for append (a missing parent directory, no permission), stops startup with a message naming `MCP_AUDIT_FILE`. A FIFO is accepted without being opened, since opening one waits for a reader.

## Replay

`POST /v1/apps/{app}/mcp/audit/{id}/replay[?force=true]`, on the admin socket only. It sends the recorded `tools/call` again to the server it went to, through the gateway of the live app, and answers

```json
{ "audit_seq": 12, "replay_of": 7, "outcome": "ok", "reason": null, "result": { "content": [] } }
```

with the server's `result`, or its `error`, as it came, to the operator and not stored. The replay is audited as a record of its own with `replay_of`, `sub: null` and `session: null`; a replay can be replayed.

Replay is an admin action. It carries no caller identity, and the recorded `sub` is not an identity to act as. A tool's `readOnlyHint` is a hint the server states about itself, so it only lowers the friction of an operator's own replay; it grants a client nothing.

The checks, in order:

| Answer | When |
|---|---|
| `400` | `force` is not a boolean. |
| `404` | No such app, or no record `id` in the log of that app and its tenant. |
| `409 not_replayable` | The call never reached a server: it was `denied`, or its name did not resolve. A denied call is never run again with the operator's privilege. |
| `422 redacted_arguments` | `arguments_state` is `redacted`, `not_recorded` or `too_large`: what was sent cannot be rebuilt. A call with `absent` or `kept` arguments replays. |
| `409 gateway_gone` | The app no longer has the `mcp_gateway` the call went through. |
| `409 server_gone` | The server is no longer in its registry. |
| `503` with `retry-after: 1` | The tenant has no in-flight slot left. Nothing was sent and nothing is audited. |
| `409 tool_gone` | The server's catalog, fetched now, no longer lists the tool. |
| `409 not_permitted` | The gateway has `tool_access` and no rule lists the tool. Replay has no claims, so it cannot ask the per-caller rule; it asks only whether some rule could ever grant the tool, so an operator replay does not bring back a call that the default deny forbids to everyone. |
| `409 needs_force` | The tool's `annotations.readOnlyHint`, as the server lists it now, is not `true` and `force=true` is not given. |
| `502` | The exchange failed (`{"error": "replay failed: <code>", "audit_seq"}`, audited as `upstream_failed`). `503` with `retry-after: 1` for `busy`: the tenant's buffer budget or the server's `max_concurrent` has no room. |

The (server, tool) pair comes from the registry and the server's catalog as they are now, never from text of the request or the record. The exchange goes through the gateway's own client, so the operator's upstream address policy for the tenant (`UPSTREAM_POLICY_FILE`), the server's `max_concurrent`, the timeout and the tenant's buffer budget apply exactly as for a client's call. `_meta` is not replayed. The replay opens a session with the server of its own and does not use a client's.

## What a client sees

Nothing changes for a client. A call is answered as before; the audit is a side effect written after the answer is built.
