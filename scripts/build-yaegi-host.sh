#!/usr/bin/env bash
# Build the Yaegi host for Traefik Go plugins (plugins/yaegi-host).
#
# The binary goes to ${CARGO_TARGET_DIR:-<repo>/target}/yaegi-host/yaegi-host, the path
# tests/mw_plugin_yaegi.rs runs it from; YAEGI_HOST_OUT overrides the whole path. The build is
# offline: the Go modules are committed under plugins/yaegi-host/vendor (go.mod and go.sum pin
# them), GOFLAGS=-mod=vendor and GOPROXY=off make a missing module an error instead of a download,
# and GOTOOLCHAIN=local forbids fetching another Go. CGO is off: the host is one static binary,
# with no C code in it.
#
# Several test processes may run this at once. They take turns (flock), and the binary is written
# beside its target and renamed into place, so none of them sees a half-written file.
#
# Usage: scripts/build-yaegi-host.sh        build (go build reuses its cache, so a rerun is fast)
#        scripts/build-yaegi-host.sh --path  print where the binary goes and build nothing
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${YAEGI_HOST_OUT:-${CARGO_TARGET_DIR:-$root/target}/yaegi-host/yaegi-host}

if [ "${1:-}" = "--path" ]; then
  echo "$out"
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "build-yaegi-host.sh: go is not on PATH; run inside 'devenv shell' (devenv.nix has pkgs.go)" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
# One build at a time: test processes started together would each compile the Go standard library
# into a cold cache at once; the ones that wait find it warm.
exec 9>"$out.lock"
flock 9
tmp=$(mktemp "$out.XXXXXX")
trap 'rm -f "$tmp"' EXIT
(
  cd "$root/plugins/yaegi-host"
  CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local \
    go build -trimpath -o "$tmp" .
)
chmod 0755 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
