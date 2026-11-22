#!/usr/bin/env bash
# guest instructions per request of a podgate build, counted by callgrind.
#
# Machine load does not change an instruction count, so two builds (or two commits) compare
# exactly where wall-clock throughput cannot. One run: start the fast backend, start podgate under
# `valgrind --tool=callgrind`, push the snapshot, send WARMUP_REQUESTS requests (not counted), zero
# the counters, send REQUESTS requests with `oha`, dump the counters, stop podgate. Startup, the
# snapshot push and the warm-up are outside the counted window. Prints instructions per request and
# writes the dump, `callgrind_annotate` listings (inclusive and self cost) and `result.json` to OUT.
#
#   scripts/bench-callgrind.sh                  # target/release/podgate, forwarding off
#   PODGATE_BIN=/path/podgate SNAPSHOT_TEMPLATE=bench/podgate-snapshot-4b3834a.json.in scripts/bench-callgrind.sh
#
# Build with symbols first (the shipped profile strips them), into a target directory of its own:
#   CARGO_TARGET_DIR=target/cg CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false \
#     cargo build --release --bin podgate --example fast_upstream
# and hold `flock ~/.cache/podgate-cargo.lock` around this script: valgrind runs one thread at a
# time but the backend and `oha` still use CPUs. Run it inside `devenv shell` (valgrind, oha, jq).
#
# Settings, all optional:
#   PODGATE_BIN (default target/release/podgate)   UPSTREAM_BIN (default target/release/examples/fast_upstream)
#   SNAPSHOT_TEMPLATE (default bench/podgate-snapshot-noforward.json.in; bench/podgate-snapshot-4b3834a.json.in
#   is the same app in the first build's snapshot format)
#   REQUESTS 50000   WARMUP_REQUESTS 10000   CONNECTIONS 8   OUT (default: a fresh temp dir)
#   PROXY_CPUS 0-3   LOAD_CPUS 4-5   BACKEND_CPUS 6-7   (taskset lists; podgate starts one thread per
#   proxy CPU, as in scripts/bench-proxies.sh)   BASE_PORT (first of 2 loopback ports; default: random free)
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

PODGATE_BIN=${PODGATE_BIN:-target/release/podgate}
UPSTREAM_BIN=${UPSTREAM_BIN:-target/release/examples/fast_upstream}
SNAPSHOT_TEMPLATE=${SNAPSHOT_TEMPLATE:-bench/podgate-snapshot-noforward.json.in}
REQUESTS=${REQUESTS:-50000}
WARMUP_REQUESTS=${WARMUP_REQUESTS:-10000}
CONNECTIONS=${CONNECTIONS:-8}
PROXY_CPUS=${PROXY_CPUS:-0-3}
LOAD_CPUS=${LOAD_CPUS:-4-5}
BACKEND_CPUS=${BACKEND_CPUS:-6-7}
HOST=a.test

die() {
  echo "bench-callgrind: $*" >&2
  exit 1
}

for tool in valgrind callgrind_control callgrind_annotate oha jq curl taskset; do
  command -v "$tool" >/dev/null || die "$tool not found (run inside devenv shell)"
done
for bin in "$PODGATE_BIN" "$UPSTREAM_BIN"; do
  [ -x "$bin" ] || die "$bin missing"
done
[ -r "$SNAPSHOT_TEMPLATE" ] || die "$SNAPSHOT_TEMPLATE not readable"

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 30000))}
while listening "$BASE_PORT" || listening $((BASE_PORT + 1)); do BASE_PORT=$((20000 + RANDOM % 30000)); done
PROXY_PORT=$BASE_PORT
BACKEND_PORT=$((BASE_PORT + 1))

work=$(mktemp -d)
OUT=${OUT:-$(mktemp -d /tmp/podgate-callgrind.XXXXXX)}
mkdir -p "$OUT"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

sed -e "s|@BACKEND_PORT@|$BACKEND_PORT|g" "$SNAPSHOT_TEMPLATE" >"$work/snapshot.json"

taskset -c "$BACKEND_CPUS" "$UPSTREAM_BIN" "127.0.0.1:$BACKEND_PORT" &
pids+=($!)
for _ in $(seq 100); do
  listening "$BACKEND_PORT" && break
  sleep 0.1
done
listening "$BACKEND_PORT" || die "backend did not start listening on $BACKEND_PORT"

# valgrind replaces the shell's child by exec chain env -> taskset -> valgrind, so $! is valgrind's pid.
env -u PROXY_TLS_ADDR PROXY_ADDR="127.0.0.1:$PROXY_PORT" ADMIN_SOCKET="$work/admin.sock" RUST_LOG=warn \
  UPSTREAM_POLICY_FILE="$PWD/bench/upstream-policy.json" \
  taskset -c "$PROXY_CPUS" valgrind --tool=callgrind --callgrind-out-file="$OUT/callgrind.out.%p" \
  --separate-threads=no "$PODGATE_BIN" >"$OUT/podgate.log" 2>&1 &
podgate_pid=$!
pids+=("$podgate_pid")

for _ in $(seq 600); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$work/admin.sock" http://x/readyz || true)" = 200 ] && break
  sleep 0.5
done
status=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$work/admin.sock" -X PUT \
  -H 'content-type: application/json' --data-binary "@$work/snapshot.json" http://x/v1/snapshot)
[ "$status" = 200 ] || die "podgate snapshot push answered $status (log: $OUT/podgate.log)"

probe=$(curl -sS --max-time 30 -H "Host: $HOST" "http://127.0.0.1:$PROXY_PORT/" | wc -c)
[ "$probe" = 100 ] || die "probe returned $probe bytes, not the backend's 100"
code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' -H 'Host: unknown.test' "http://127.0.0.1:$PROXY_PORT/")
[ "$code" = 404 ] || die "unknown Host answered $code, not 404"

oha_run() { # requests out-file
  taskset -c "$LOAD_CPUS" oha --no-tui --output-format json -n "$1" -c "$CONNECTIONS" -w --disable-compression \
    --worker-threads 2 -H "Host: $HOST" "http://127.0.0.1:$PROXY_PORT/" >"$2" 2>"$2.err"
}
backend_stats() { curl -s "http://127.0.0.1:$BACKEND_PORT/__stats"; }

oha_run "$WARMUP_REQUESTS" "$OUT/oha-warmup.json"
callgrind_control -z "$podgate_pid" >/dev/null
stats0=$(backend_stats)
oha_run "$REQUESTS" "$OUT/oha.json"
stats1=$(backend_stats)
callgrind_control -d "$podgate_pid" >/dev/null
for _ in $(seq 600); do
  dump=$(find "$OUT" -maxdepth 1 -name "callgrind.out.$podgate_pid.*" -size +0 | sort | head -n1)
  [ -n "$dump" ] && break
  sleep 0.5
done
[ -n "${dump:-}" ] || die "callgrind wrote no dump"
sleep 2
kill -9 "$podgate_pid" 2>/dev/null || true
wait "$podgate_pid" 2>/dev/null || true

ok=$(jq '.statusCodeDistribution["200"] // 0' "$OUT/oha.json")
errors=$(jq '[.errorDistribution // {} | .[]] | add // 0' "$OUT/oha.json")
backend_requests=$(($(cut -d' ' -f2 <<<"$stats1") - $(cut -d' ' -f2 <<<"$stats0") - 1))
[ "$ok" = "$REQUESTS" ] && [ "$errors" = 0 ] || die "oha: $ok of $REQUESTS requests answered 200, $errors errors"
[ "$backend_requests" = "$REQUESTS" ] || die "the backend served $backend_requests requests, not $REQUESTS"

total=$(awk -F'[: ]+' '/^(summary|totals):/ { print $2; exit }' "$dump")
[ -n "$total" ] || die "no totals line in $dump"
callgrind_annotate --inclusive=yes --threshold=99.99 "$dump" >"$OUT/annotate-inclusive.txt"
callgrind_annotate --inclusive=no --threshold=99.99 "$dump" >"$OUT/annotate-self.txt"
jq -n -c --arg bin "$PODGATE_BIN" --arg snapshot "$SNAPSHOT_TEMPLATE" --argjson requests "$REQUESTS" \
  --argjson connections "$CONNECTIONS" --argjson total "$total" \
  '{bin: $bin, snapshot: $snapshot, requests: $requests, connections: $connections, total_ir: $total, ir_per_request: ($total / $requests | round)}' \
  >"$OUT/result.json"
cat "$OUT/result.json"
echo "instructions per request: $((total / REQUESTS)); dump and listings in $OUT"
