# Out-of-process plugins: the `plugin` middleware

Code: `src/middleware/plugin.rs` and `src/middleware/plugin/`. Protocol:
`proto/podgate_plugin.proto`. Example: `examples/echo_plugin.rs`. Tests: `tests/mw_plugin.rs`.

A plugin extends podgate without putting any foreign code in its process. It is a separate
process, written in any language, that serves a small gRPC protocol on a unix socket. podgate
asks it about requests and applies what it answers.

| | Traefik | Caddy | podgate |
|---|---|---|---|
| Extension | Yaegi: interpreted Go, in process | Go modules compiled in | A process, called over a unix socket |
| Can corrupt the proxy's memory | yes | yes | no |
| Can be bounded in memory, CPU and processes | no | no | yes (cgroup v2) |
| Who may load one | the operator | the builder | the operator; a snapshot names, never loads |

In-process filters with fuel and memory limits remain available as the `wasm` middleware. Spec
0113 hosts Traefik's Go plugins as one of these plugins.

## Threat model

- **Tenants never load code.** A plugin exists only in `PLUGINS_FILE`, which is process
  configuration, never part of a snapshot. A snapshot middleware names a plugin and can name only
  one that lists the app's tenant. It cannot name a socket, a command or an address: those keys
  are not options, so a snapshot that has them is rejected (`invalid_middleware`).
- **A plugin sees only what the middleware sends**: the request line, the headers selected by
  `request_headers` (without it, every header except `authorization`, `proxy-authorization`,
  `cookie`; the `host` goes in its own field), the app, tenant and router names, the client
  address, and the middleware's `config`. In the response phase also the status and the response
  headers selected by `response_headers` (without it, all but `set-cookie`). A body is sent only
  with the `request_body` phase and `body.max_bytes`.
- **`config` is the tenant's.** At most 16 KiB of JSON, passed as it is. The plugin must treat it
  as untrusted input. It is not shown by explain.
- **What a plugin can do**: continue, replace or remove request headers, add response headers, or
  answer the request. It cannot change the method, the target or the body, and cannot touch a
  header that frames the message or belongs to the connection (`host`, `content-length`,
  `transfer-encoding`, `connection`, `keep-alive`, `upgrade`, `te`, `trailer`, `http2-settings`,
  anything `proxy-`). Such a decision is a failed call.
- **Tenants share a plugin only if the operator lists them both.** podgate tags every call with
  its tenant and holds each tenant to its share of the plugin's calls in flight, but the plugin
  itself must keep tenants apart. An operator who cannot trust a plugin with that runs one
  instance per tenant (one entry per tenant in `PLUGINS_FILE`). A circuit is per plugin, so a
  tenant whose `config` makes a shared plugin fail can open it for the others; that is another
  reason for one instance per tenant.
- **A tenant can tell that a plugin exists.** `unknown_plugin` and `plugin_forbidden` are
  different answers.
- **Rejected design: `dlopen`.** Native code in the proxy's address space can corrupt every
  tenant's memory, bypass every budget, needs `unsafe` at the loading boundary and in every
  plugin, and cannot be bounded. The price of the process boundary is one local IPC hop per call;
  see [Cost](#cost).

## `PLUGINS_FILE`

A JSON object, plugin name to entry. Read once at startup. A bad entry stops startup and the
message names the plugin. Names are 1 to 64 characters of `a-z`, `0-9`, `-`, `_`.

```json
{"headeradder": {
   "socket": "/run/podgate/plugins/headeradder.sock",
   "tenants": ["acme"],
   "managed": true,
   "command": "/opt/plugins/headeradder",
   "args": ["--verbose"],
   "env": {"LANG": "C"},
   "user": "plugin", "group": "plugin",
   "limits": {"memory_max_bytes": 268435456, "pids_max": 64, "cpu_percent": 100},
   "max_concurrent": 256}}
```

| Key | Meaning |
|---|---|
| `socket` | Absolute path of the unix socket the plugin serves. Required. |
| `tenants` | Tenant ids allowed to use the plugin. Empty or absent: none. |
| `managed` | `true` (default): podgate starts and supervises the process. `false`: an operator or systemd runs it and podgate only connects. |
| `command`, `args`, `env` | Managed only. `command` is absolute. The environment is cleared and holds only `env` plus `PODGATE_PLUGIN_SOCKET` and `PODGATE_PLUGIN_NAME`. |
| `user`, `group` | Managed only: name or number. Needs podgate to run as root. A `user` without `group` takes the user's primary group from `/etc/passwd`; a numeric user needs a `group`. Supplementary groups of podgate are not dropped: run podgate with none you would not give the plugin. |
| `limits` | Managed only. `memory_max_bytes` (at least 1 MiB), `pids_max`, `cpu_percent` (100 is one core). Needs `PLUGINS_CGROUP_ROOT`; without it an entry that declares limits stops startup. |
| `max_concurrent` | Calls in flight at once, 1 to 65536, default 256. |

`PLUGINS_CGROUP_ROOT` names a delegated cgroup v2 directory. For each managed plugin podgate
creates `<root>/<plugin>/`, tries to enable `memory`, `pids` and `cpu` in the root's
`cgroup.subtree_control`, and writes `memory.max` (and `memory.swap.max` as `0`, so swap cannot
hide the limit), `pids.max` and `cpu.max` (`<percent*1000> 100000`). A limit the entry does not
declare is reset to `max`. A plugin that passes `memory.max` is killed by the kernel; podgate and
the other plugins are not affected, and the supervisor starts it again.

## Supervision (`managed: true`)

- podgate starts the process and waits until it answers `Describe`, at most 5 seconds, before it
  serves. A plugin that exits, never listens, or answers an error or another
  `protocol_version` stops startup, naming the plugin.
- The process is placed in the cgroup before its code runs: it starts as
  `sh -c 'read go && exec "$@"'` with a pipe on stdin, podgate writes its pid into `cgroup.procs`
  and then releases it with one line. This differs from `echo $$ > cgroup.procs` in the shell:
  only podgate writes the file, so a plugin running as another user needs no write access to the
  cgroup. A podgate that dies before the release leaves a shell that reads end of file and exits.
- Its stdout and stderr go to podgate's log, tagged with the plugin name, at most 50 lines a
  second and 1024 bytes a line.
- A plugin that exits is started again after 1 second, doubling on each failed start up to 60
  seconds, and back to 1 second once it stayed up 30 seconds. Until it answers `Describe` again
  no call is made: requests see the plugin as unavailable (below).
- At shutdown it gets `SIGTERM`, then `SIGKILL` after 5 seconds, and its cgroup is emptied with
  `cgroup.kill` and removed. When podgate itself is killed, the plugin keeps running: run podgate
  under a service manager that stops the whole control group, and note that podgate empties a
  leftover plugin cgroup (`cgroup.kill`) when it starts again.

An unmanaged plugin is never started or stopped. podgate waits for its socket for 5 seconds at
startup; later it simply fails calls while nothing listens, and the circuit does the rest.

## The middleware

```json
{"name": "headers-plugin", "type": "plugin", "plugin": "headeradder",
 "config": {"header": "x-hello"},
 "phases": ["request_headers", "response_headers"],
 "on_plugin_error": "fail_closed", "timeout_ms": 50,
 "request_headers": ["x-trace"], "response_headers": ["x-up"]}
```

The plugin's name is in `plugin`, not `name`: `name` is the middleware's own, next to `type`.
Unknown keys are refused.

| Key | Meaning |
|---|---|
| `plugin` | The operator's plugin. `unknown_plugin` if it is not declared, `plugin_forbidden` if it does not list the app's tenant. |
| `config` | Opaque JSON for the plugin, at most 16 KiB. |
| `phases` | Any of `request_headers` (default), `request_body`, `response_headers`. A phase the plugin's `Describe` does not list is refused at compile. |
| `body` | `{"max_bytes": n}`, 1 to 1 MiB; required by and only with `request_body`. |
| `on_plugin_error` | `fail_closed` (default) or `fail_open`. |
| `timeout_ms` | Deadline of one call, 1 to 1000 and at most `REQUEST_TIMEOUT_SECS`. Default 50. |
| `request_headers`, `response_headers` | Names to send; see the threat model. |

Phases: `request_headers` runs where the chain's request hooks run, before a revision or server is
chosen. `request_body` buffers the whole body up to `body.max_bytes` (a larger one is answered
`413`, a slow client `408`), sends it with the headers, and the buffered body is what goes to the
upstream. `response_headers` runs on the upstream's response head before the chain's other
response hooks; the plugin sees the response as the upstream sent it.

### When a call fails

| Cause | `fail_closed` | `fail_open` |
|---|---|---|
| Deadline passed, connection failed, error status, answer that is not a decision, decision over 64 KiB or that cannot be applied | `503 {"error":"plugin unavailable"}` | the request goes on without the plugin |
| Plugin starting or down, circuit open | `503 {"error":"plugin unavailable"}` | goes on |
| The plugin or the tenant is at its calls in flight | `503` with `retry-after: 1`, same body | goes on |
| The tenant's buffer budget cannot take the call | `503` with `retry-after: 1`, same body | `503`: the tenant's own memory ran out |

Switching a route from `fail_closed` to `fail_open`, removing the middleware, asking another
plugin and asking at fewer phases appear in `posture_changes` of `POST /v1/snapshot/plan` as
`plugin_fail_open`, `plugin_removed`, `plugin_changed` and `plugin_phases_removed`. A `fail_open`
route is unguarded while the plugin is down: a security plugin keeps the default.

### Bounds

- Message sizes: a call is at most 256 KiB (a larger one is not sent), a decision at most 64 KiB.
- At most `max_concurrent` calls in flight per plugin, and per tenant the tenant's weight over the
  sum of the weights of the plugin's tenants in the snapshot, at least 1 (alone, all).
- A call is charged to the tenant's `max_buffer_bytes` before it is built, at twice its size (the
  message and its encoding exist together); a decision is charged when its length prefix is read,
  before its bytes are, at twice its length. A decision's charge lasts as long as the request holds
  response headers from it. A held body is charged at its declared length, or `body.max_bytes`.
  A snapshot whose tenant budget cannot hold one call with its `config` and body is rejected.
- A per-plugin circuit opens after 5 consecutive failed calls for 5 seconds, then lets one probe
  through. Calls refused for room, budget or size are not failures.
- Explain shows the middleware's settings without its `config`.

## The protocol

`proto/podgate_plugin.proto`, package `podgate.plugin.v1`, `Plugin` service, both calls unary over
gRPC on HTTP/2 on the unix socket; podgate sets `grpc-timeout` to the call's deadline and sends
`grpc-accept-encoding: identity`, and a compressed message is refused.

- `Describe(DescribeRequest) -> DescribeResponse {name, protocol_version, phases}`: called after
  every start. `protocol_version` must be 1.
- `Process(Call) -> Decision`: one per phase of one request.
  - `Call {phase, tenant, app, router, middleware, config, client_addr, method, target, host,
    scheme, headers, body, status, response_headers}`.
  - `Decision {action, set_request_headers, remove_request_headers, add_response_headers,
    response}`. `ACTION_CONTINUE` (the default) applies the header changes, removals first;
    `ACTION_RESPOND` answers with `response {status 200..599, headers, body}` and carries nothing
    else. In the response phase only `add_response_headers` is allowed. `add_response_headers`
    from a request phase are added when the response arrives.

The generated Rust is committed as `src/middleware/plugin/gen.rs` and regenerated with
`scripts/gen-plugin-proto.sh`, which needs no `protoc` (it uses `protox` and `prost-build` in a
scratch crate). The messages are public as `podgate::middleware::plugin::wire`.

## Cost

One local IPC hop per call. See the measurement recorded in the commit history ("plugin
hop").
