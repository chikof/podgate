# yaegi-host

Runs one Traefik middleware plugin, interpreted by [Yaegi](https://github.com/traefik/yaegi), as an
out-of-process podgate plugin (protocol: `docs/ref/mw-plugin.md`). Reference for operators:
`docs/ref/plugin-yaegi.md`.

```sh
yaegi-host --plugin /opt/plugins/headeradder --name headeradder   # socket from $PODGATE_PLUGIN_SOCKET
```

| File | Role |
|---|---|
| `main.go` | flags, the unix socket, graceful stop |
| `grpc.go` | the two unary gRPC calls on `net/http` (HTTP/2 without TLS) |
| `wire.go` | the protocol's messages, encoded with `protowire`; checked against `proto/podgate_plugin.proto` |
| `load.go` | reads the plugin directory and its `.traefik.yml`, scans every import |
| `symbols.go` | the packages a plugin may import, and what `net/http` and `os` leave out |
| `instance.go` | one Yaegi interpreter with one plugin, run under the interpreter's cancellation |
| `host.go` | the instance cache (per tenant and config, 64 at most) and the call path |
| `convert.go` | `*http.Request` from a call, the recorder, and the decision from what the handler did |
| `config.go` | the snapshot's `config` JSON into the struct `CreateConfig()` returned |
| `testdata/` | example plugins in source form, used by the Go tests and `tests/mw_plugin_yaegi.rs` |
| `vendor/` | the Go modules (`go mod vendor`): builds never download |

Build: `scripts/build-yaegi-host.sh` (offline, `-mod=vendor`). Test: `go test ./...` here, and
`cargo nextest run yaegi` at the repository root.

Updating a module: `go get <module>@<version> && go mod tidy && go mod vendor`, then check its licence
against `deny.toml`'s allow list and record it in `docs/ref/plugin-yaegi.md`.
