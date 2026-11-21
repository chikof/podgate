# Traefik Go plugins: the Yaegi host

Code: `plugins/yaegi-host/` (a Go module). Build: `scripts/build-yaegi-host.sh`. Tests:
`tests/mw_plugin_yaegi.rs` and `go test ./...` in the module. Contract it implements:
[`mw-plugin.md`](mw-plugin.md) and `proto/podgate_plugin.proto`.

Traefik runs a Go middleware plugin by interpreting its source with Yaegi inside the Traefik
process. podgate runs the same source in a separate process: `yaegi-host`, a small Go program that
interprets one plugin and speaks the plugin protocol on a unix socket. To podgate it is one more
out-of-process plugin, with the limits (cgroup, user, deadline, circuit, `on_plugin_error`) every
plugin has. Nothing in podgate's process interprets foreign code.

| | Traefik | podgate with the host |
|---|---|---|
| Plugin source | interpreted in the proxy | interpreted in `yaegi-host`, a child process |
| A plugin that panics | `recover` in the proxy | recovered in the host, a failed call |
| A plugin that loops | stuck goroutine in the proxy | stopped at the call's deadline, a failed call |
| Memory and CPU bound | none | `limits` of the plugin entry (cgroup v2) |
| Standard library | all of it, plus `os`, `net`, `unsafe` | an allowlist (below) |
| Request edits | anything on the request | headers only; the rest is refused |
| Response edits | wrap the `ResponseWriter` | answer the request, or add response headers |
| Catalog | fetched at startup | none: the operator vendors the source |

## Running a plugin

Vendor the plugin: copy its repository (the Go files, `.traefik.yml`, and a `vendor/` directory if
it has dependencies) to a directory on the host's disk. There is no catalog client and no network
fetch. Declare the host in `PLUGINS_FILE` as a managed plugin, one entry per plugin:

```json
{"headeradder": {
   "socket": "/run/podgate/plugins/headeradder.sock",
   "tenants": ["acme"],
   "command": "/usr/local/bin/yaegi-host",
   "args": ["--plugin", "/opt/plugins/headeradder", "--name", "headeradder"],
   "user": "plugin", "group": "plugin",
   "limits": {"memory_max_bytes": 268435456, "pids_max": 64, "cpu_percent": 100},
   "max_concurrent": 64}}
```

A snapshot then uses it as any plugin (`"type": "plugin", "plugin": "headeradder", "config": {...}`).
`socket` is set by podgate in `PODGATE_PLUGIN_SOCKET`, which the host reads; `--socket` overrides it
for a host started by hand (`managed: false`).

| Flag | Meaning |
|---|---|
| `--plugin <dir>` | The vendored plugin. Required. |
| `--name <name>` | The name in `Describe` and in the `name` argument of the plugin's `New`. Default `$PODGATE_PLUGIN_NAME`, then `yaegi`. |
| `--socket <path>` | The unix socket to serve. Default `$PODGATE_PLUGIN_SOCKET`. |

The directory must hold `.traefik.yml` with `type: middleware` and `import: <module path>`, and a Go
package with

```go
func CreateConfig() *Config
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)
```

Only those two top level keys of `.traefik.yml` are read (the other keys, such as `summary` and
`testData`, are the catalog's). The host serves the `request_headers` phase only; a middleware that
asks for another phase is refused when the snapshot is compiled (`Describe` lists one phase).

The host starts only when the plugin passes the checks below. A plugin that does not stops the host
with the reason on stderr, which podgate logs under the plugin's name, and a managed plugin that
never answers `Describe` stops podgate's startup naming the plugin.

## What the plugin sees

For each call the host builds the `*http.Request` a Traefik plugin gets from Traefik: method,
`URL` (the target as path and query, nothing else), `RequestURI`, `Host`, the headers the
middleware sends (`request_headers` of the middleware selects them; by default all but
`authorization`, `proxy-authorization` and `cookie`), `RemoteAddr` (the client's IP and port `0`),
`TLS` (non-nil when the client's connection is `https`), `ContentLength` from the header, and an
empty `Body`. `ResponseWriter` and `next` are recorders.

The decision follows what the handler did:

| The handler | Decision |
|---|---|
| calls `next(rw, req)` | `continue`. The headers of `req` that differ from what was sent become `set_request_headers` and `remove_request_headers`. Headers set on `rw.Header()` become `add_response_headers`. |
| writes a response and does not call `next` | `respond` with that status (200 if only `Write` was called), headers and body. A body without `Content-Type` gets the sniffed one, as `net/http` does. A `Content-Length` equal to the body is dropped (podgate frames the message); any other is refused. |
| returns without either | `respond` 200, empty (a Go handler's default). |

A header the plugin did not receive cannot be removed or checked: to delete `X-Forwarded-For`, name
it in the middleware's `request_headers`.

## What it refuses: `plugin_unsupported_mutation`

The protocol carries header edits and answers. A plugin that does anything else is not run partially:
its call fails with a message that starts `plugin_unsupported_mutation:` and the middleware's
`on_plugin_error` decides (`fail_closed`: `503`; `fail_open`: the request goes on **as it arrived**,
without the plugin's change). The message is in podgate's log. A security plugin that rewrote a path
and was run without the rewrite would lie, so every one of these is refused:

- changing `req.URL` (path, query, anything), `req.Method` or `req.Host`, including on a clone passed
  to `next` (the request that reaches `next` is the one judged);
- reading `req.Body` or replacing it (a `request_headers` call has no body to read);
- setting `Host` or a header that frames the message or belongs to the connection, or `Proxy-*`, on
  the request, a response, or the response headers (the rule of the protocol);
- leaving one request header with several values after a change (`Header.Add` of a second value):
  the protocol replaces a header by one field;
- calling `next` twice, or writing a response and also calling `next`;
- a response over 64 KiB, or a status outside 200 to 599.

Passing a wrapped `ResponseWriter` to `next` does not fail: the wrapper has no effect on the
upstream's response, and the host logs that once per instance
(`passes its own ResponseWriter to next`). Plugins that edit the upstream response cannot be
expressed in the protocol.

## Config

The middleware's `config` JSON (at most 16 KiB) is decoded into the struct `CreateConfig()` returned,
before `New` runs. A key matches a field by its `mapstructure` or `json` tag name, or by its Go name,
ignoring case, as Traefik's decoder does. **A key that matches no field fails the call** (the log
names it: `unknown config field "nme"`), so a misspelled option never runs the plugin with its
default. A field tagged `-` cannot be set. Nested structs and pointers to structs are matched the
same way; values of slices and maps go through `encoding/json` with unknown fields refused (`json`
tags). An empty `config` leaves the defaults. A `New` that returns an error fails the call too.

## Isolation

- **Per tenant and config.** The host holds one interpreter, and one plugin instance in it, for each
  distinct pair of `tenant` (from the call) and the SHA-256 of the `config` bytes. Instances are never
  shared across tenants. At most **64** are kept; the least recently used goes first, and the next call
  of that tenant and config loads it again (its plugin state starts over). A config that fails keeps
  failing until its entry is evicted: the error is cached with it.
- **One call at a time per instance.** An interpreter is cancelled as a whole, so calls of one
  instance run one after the other; calls of different instances run in parallel. A plugin with slow
  handlers serializes its tenant's calls (`max_concurrent` and the call deadline bound the queue).
- **First call.** An instance loads on the first call of its tenant and config: about 1 to 3 ms for
  the example plugins on the development machine (measured from the host's log), more for a larger
  plugin. The load has its own 10 second limit, outside the call's deadline, so a call that times out
  while its instance loads fails and the next one finds the instance ready.
- **One host per tenant** is the option for an operator who does not trust a plugin: one entry, one
  socket, one cgroup per tenant in `PLUGINS_FILE`.

## Panics, loops and deadlines

A panic in the plugin is recovered and fails the call (`the plugin panicked while handling the
request: ...`). The call's deadline (podgate's `grpc-timeout`, the middleware's `timeout_ms`) bounds
the handler: when it passes the interpreter stops executing the plugin's code, including a `for {}`,
the call fails, and the instance is dropped (a stopped interpreter cannot run again; the next call
builds a fresh one; a call of that instance that was waiting for its turn fails with status 14 rather than run on the stopped interpreter). The host process does not exit and is not restarted. A plugin that spawns
goroutines that spin outside the interpreter's control is bounded by the plugin entry's cgroup
limits like any plugin.

## What a plugin may import

Yaegi's own sandbox only hides a few symbols; it still exports `os/exec`, `net`, `syscall` and the file
system. The host exports only the packages below, so an import of anything else fails, and
`LoadSource` reads every `.go` file of the plugin directory (including its `vendor/` tree) and refuses
the plugin before anything runs: `import "os/exec" is refused: it gives starting processes (in
plugin.go)`.

| Allowed | Notes |
|---|---|
| `bufio`, `bytes`, `cmp`, `container/*`, `context`, `errors`, `fmt`, `io`, `maps`, `slices`, `sort`, `strconv`, `strings`, `sync`, `sync/atomic`, `time`, `unicode*`, `regexp*`, `path`, `html`, `log`, `log/slog`, `text/tabwriter` | |
| `compress/{flate,gzip,zlib}`, `hash/*`, `math`, `math/{big,bits,cmplx,rand,rand/v2}` | |
| `crypto`, `crypto/{aes,cipher,ecdsa,ed25519,elliptic,hmac,md5,rand,rsa,sha1,sha256,sha512,subtle}` | no `crypto/tls`, no `crypto/x509` |
| `encoding`, `encoding/{base32,base64,binary,csv,hex,json,pem,xml}`, `mime`, `mime/multipart`, `mime/quotedprintable` | |
| `net/http` | without the client and the server: `Client`, `Transport`, `Get`, `Post`, `ListenAndServe`, `Serve`, `Server`, `DefaultClient`, `DefaultServeMux`, `Handle`, `Dir`, `FS`, `FileServer`, `ServeFile` and the like. Types and helpers for building requests and writing responses stay. |
| `net/netip`, `net/textproto`, `net/url` | |
| `os` | `Stdout` and `Stderr` (the host's, so logs reach podgate's log), the interpreter's own virtual environment (`Getenv`, `LookupEnv`, `Environ`, `Setenv`: empty at the start, never the host's) and `Args` (one word), `ErrNotExist`, `ErrExist`. No file, directory, process or `Exit`; no `Stdin`. |
| a package of the plugin's own module or its `vendor/` tree (the first element of the path has a dot) | its imports are checked like the plugin's |

Refused with a reason: `unsafe`, cgo (`import "C"`), `os/exec`, `os/signal`, `os/user`, `syscall`,
`net` and the other network packages (`net/rpc`, `net/smtp`, `net/http/httputil`, `net/http/httptest`,
`net/http/cgi`, `net/http/fcgi`, `crypto/tls`, `database/sql`, `log/syslog`), `plugin`, `runtime`,
`reflect` (it reaches unexported memory), file system packages (`io/fs`, `io/ioutil`,
`path/filepath`, `embed`), `text/template` and `html/template` (they read template files), `flag`,
`expvar`, `crypto/x509`. Any other standard library package fails as "not on the host's standard
library allowlist". A plugin that needs one of these does not run here.

The check is on source text. It is not a sandbox against hostile Go: the interpreter runs in the
host's process, with the host's user and cgroup. Run the host as an unprivileged `user` with
`limits`, and keep the socket's directory closed to other users.

## Build and test

```sh
scripts/build-yaegi-host.sh            # target/yaegi-host/yaegi-host
cd plugins/yaegi-host && go test ./...
cargo nextest run yaegi                # tests/mw_plugin_yaegi.rs
```

`devenv.nix` has `pkgs.go`. The build is offline: every Go module is committed under
`plugins/yaegi-host/vendor/`, `go.mod` and `go.sum` pin them, and the script sets
`GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local` and `CGO_ENABLED=0` (one static binary). The binary
goes to `${CARGO_TARGET_DIR:-target}/yaegi-host/yaegi-host`; `YAEGI_HOST_OUT` overrides the path and
`scripts/build-yaegi-host.sh --path` prints it. The Rust tests run the script themselves, once per
test process, so `cargo nextest run yaegi_...` builds what it needs and fails with the script's output
when `go` is missing; no test skips. `scripts/check.sh` also runs `go vet` and `go test` in the module.

Go modules (versions pinned in `go.mod`, sources in `vendor/`, `vendor/modules.txt` is the list):

| Module | Version | Licence | Why |
|---|---|---|---|
| `github.com/traefik/yaegi` | v0.16.3 | Apache-2.0 | the interpreter Traefik uses |
| `google.golang.org/protobuf` | v1.36.12 | BSD-3-Clause | `encoding/protowire` only, for the protocol's messages |

There is no gRPC library: the protocol is two unary calls, which `net/http` serves as HTTP/2 without
TLS on the unix socket (`Server.Protocols`, Go 1.24 and later), with the 5-byte message prefix and
`grpc-status` trailers written by `grpc.go`. The messages are encoded by `wire.go` with `protowire`
rather than generated: five small messages, and `wire_test.go` fails when a field number there differs
from `proto/podgate_plugin.proto`.

`cargo deny` does not see Go. When a module is added or updated, `go mod tidy && go mod vendor` in
the module, and record its licence here; the allow list of `deny.toml` is the one to follow.
