#!/usr/bin/env bash
# guest instructions per request of a podgate build, counted by callgrind.
# the same for HTTPS and HTTP/3 loads, and a native run for comparison.
#
# Machine load does not change an instruction count, so two builds (or two commits) compare
# exactly where wall-clock throughput cannot. One run: start the fast backend, start podgate under
# `valgrind --tool=callgrind`, push the snapshot, send WARMUP_REQUESTS requests (not counted), zero
# the counters, send REQUESTS requests, dump the counters, stop podgate. Startup, the snapshot push,
# the connections' handshakes and the warm-up are outside the counted window. Prints instructions per
# request and writes the dump, `callgrind_annotate` listings (inclusive and self cost) and
# `result.json` to OUT. scripts/bench-owners.sh groups a dump by owner (quinn, h3, the bridge, ...).
#
#   scripts/bench-callgrind.sh                  # target/release/podgate, plain HTTP/1.1, forwarding off
#   LOAD=tls-h1 scripts/bench-callgrind.sh      # HTTP/1.1 over TLS 1.3, 64 connections
#   LOAD=h3 scripts/bench-callgrind.sh          # HTTP/3, 64 connections, the `;http3` front
#   LOAD=h3 NATIVE=1 scripts/bench-callgrind.sh # the same load against podgate without valgrind
#   PODGATE_BIN=/path/podgate SNAPSHOT_TEMPLATE=bench/podgate-snapshot-4b3834a.json.in scripts/bench-callgrind.sh
#
# Build with symbols first (the shipped profile strips them), into a target directory of its own:
#   CARGO_TARGET_DIR=target/cg CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false \
#     cargo build --release --bin podgate --features h3-stats --example fast_upstream --example bench_cert --example load_bench
# and hold `flock ~/.cache/podgate-cargo.lock` around this script: valgrind runs one thread at a
# time but the backend and the load generator still use CPUs. Run it inside `devenv shell`
# (valgrind, oha, jq).
#
# Loads (LOAD):
#   h1      `oha` over plain HTTP/1.1, CONNECTIONS 8 (the default)
#   tls-h1  examples/load_bench tls-count: HTTP/1.1 keep-alive over TLS 1.3, CONNECTIONS 64, as the
#           `tls-h1` scenario of scripts/bench-proxies.sh. The HTTPS entry point has no `;http3`.
#   h3      examples/load_bench h3-count: HTTP/3, CONNECTIONS 64, as the `h3-c64` scenario. The
#           HTTPS entry point has `;http3`.
# For tls-h1 and h3 every connection is opened and every handshake done before the warm-up, and the
# counters are zeroed and dumped through files in a sync directory (LOAD_BENCH_SYNC), so the count
# holds the requests and nothing else.
#
# QUIC recovery. Under callgrind podgate runs 20 to 50 times slower while quinn's loss
# detection and timers keep wall-clock time, so it may count delays as loss and resend; those
# instructions would be counted as quinn's. A podgate built with `--features h3-stats` logs
# `quinn::ConnectionStats` of every HTTP/3 connection when it ends (target `podgate_h3_stats`); with
# LOAD=h3 this script collects them, and the load generator's own view of them (the `quic` object
# of examples/load_bench), into `quic.json` per request. Run it once under callgrind and once with
# NATIVE=1 (same build, same load, no valgrind) and compare the two `quic.json`: lost_packets,
# congestion_events, ping_frames_tx and the datagram and stream frame counts per request must match
# within noise, or lower CONNECTIONS (and raise REPLY_TIMEOUT_MS) until they do. quinn does not
# count probe timeouts: one shows as a ping frame, or as stream frames sent a second time.
#
# Settings, all optional:
#   LOAD h1   NATIVE (1: no valgrind; no dump, only the load's own numbers and quic.json)
#   PODGATE_BIN (default target/release/podgate)   UPSTREAM_BIN (default target/release/examples/fast_upstream)
#   CERT_BIN (target/release/examples/bench_cert)   LOAD_BIN (target/release/examples/load_bench)
#   SNAPSHOT_TEMPLATE (default bench/podgate-snapshot-noforward.json.in; bench/podgate-snapshot-4b3834a.json.in
#   is the same app in the first build's snapshot format)
#   REQUESTS 50000   WARMUP_REQUESTS 10000   CONNECTIONS (8 for h1, else 64)   OUT (default: a fresh temp dir)
#   REPLY_TIMEOUT_MS (how long one request may take: 600000 under valgrind, 5000 with NATIVE)
#   PROXY_CPUS 0-3   LOAD_CPUS 4-5   BACKEND_CPUS 6-7   (taskset lists; podgate starts one thread per
#   proxy CPU, as in scripts/bench-proxies.sh)   BASE_PORT (first of 3 loopback ports; default: random free)
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

LOAD=${LOAD:-h1}
NATIVE=${NATIVE:-}
PODGATE_BIN=${PODGATE_BIN:-target/release/podgate}
UPSTREAM_BIN=${UPSTREAM_BIN:-target/release/examples/fast_upstream}
CERT_BIN=${CERT_BIN:-target/release/examples/bench_cert}
LOAD_BIN=${LOAD_BIN:-target/release/examples/load_bench}
SNAPSHOT_TEMPLATE=${SNAPSHOT_TEMPLATE:-bench/podgate-snapshot-noforward.json.in}
REQUESTS=${REQUESTS:-50000}
WARMUP_REQUESTS=${WARMUP_REQUESTS:-10000}
PROXY_CPUS=${PROXY_CPUS:-0-3}
LOAD_CPUS=${LOAD_CPUS:-4-5}
BACKEND_CPUS=${BACKEND_CPUS:-6-7}
HOST=a.test

die() {
  echo "bench-callgrind: $*" >&2
  exit 1
}

case "$LOAD" in
h1) CONNECTIONS=${CONNECTIONS:-8} ;;
tls-h1 | h3) CONNECTIONS=${CONNECTIONS:-64} ;;
*) die "LOAD is h1, tls-h1 or h3, not $LOAD" ;;
esac
if [ -n "$NATIVE" ]; then
  REPLY_TIMEOUT_MS=${REPLY_TIMEOUT_MS:-5000}
else
  REPLY_TIMEOUT_MS=${REPLY_TIMEOUT_MS:-600000}
fi

tools=(curl taskset jq)
[ -n "$NATIVE" ] || tools+=(valgrind callgrind_control callgrind_annotate)
[ "$LOAD" != h1 ] || tools+=(oha)
for tool in "${tools[@]}"; do
  command -v "$tool" >/dev/null || die "$tool not found (run inside devenv shell)"
done
bins=("$PODGATE_BIN" "$UPSTREAM_BIN")
[ "$LOAD" = h1 ] || bins+=("$CERT_BIN" "$LOAD_BIN")
for bin in "${bins[@]}"; do
  [ -x "$bin" ] || die "$bin missing"
done
[ -r "$SNAPSHOT_TEMPLATE" ] || die "$SNAPSHOT_TEMPLATE not readable"
[ -z "$NATIVE" ] || [ "$LOAD" != h1 ] || die "NATIVE is for tls-h1 and h3: the h1 load has no counted window without callgrind"

# A build with `--features h3-stats` carries the target name of its log event.
stats_build=
if [ "$LOAD" = h3 ] && grep -qa podgate_h3_stats "$PODGATE_BIN"; then stats_build=1; fi

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
free_ports() { ! listening "$1" && ! listening $(($1 + 1)) && ! listening $(($1 + 2)); }
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 30000))}
while ! free_ports "$BASE_PORT"; do BASE_PORT=$((20000 + RANDOM % 30000)); done
PROXY_PORT=$BASE_PORT
BACKEND_PORT=$((BASE_PORT + 1))
TLS_PORT=$((BASE_PORT + 2))

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
if [ "$LOAD" != h1 ]; then
  "$CERT_BIN" "$work" "$HOST"
  jq --rawfile cert "$work/cert.pem" --rawfile key "$work/key.pem" --arg host "$HOST" \
    '.certificates = [{hosts: [$host], cert_pem: $cert, key_pem: $key}]' "$work/snapshot.json" >"$work/snapshot-tls.json"
  mv "$work/snapshot-tls.json" "$work/snapshot.json"
fi

taskset -c "$BACKEND_CPUS" "$UPSTREAM_BIN" "127.0.0.1:$BACKEND_PORT" &
pids+=($!)
for _ in $(seq 100); do
  listening "$BACKEND_PORT" && break
  sleep 0.1
done
listening "$BACKEND_PORT" || die "backend did not start listening on $BACKEND_PORT"

# The entry points, as scripts/bench-proxies.sh sets them: `web` always, `websecure` for the TLS loads,
# with `;http3` for HTTP/3.
case "$LOAD" in
h1) entry_env=(-u PROXY_TLS_ADDR "PROXY_ADDR=127.0.0.1:$PROXY_PORT") ;;
tls-h1) entry_env=(-u PROXY_ADDR -u PROXY_TLS_ADDR "ENTRY_POINTS=web=127.0.0.1:$PROXY_PORT/http,websecure=127.0.0.1:$TLS_PORT/https") ;;
h3) entry_env=(-u PROXY_ADDR -u PROXY_TLS_ADDR "ENTRY_POINTS=web=127.0.0.1:$PROXY_PORT/http,websecure=127.0.0.1:$TLS_PORT/https;http3") ;;
esac
log_env=(RUST_LOG=warn)
[ -z "$stats_build" ] || log_env=("RUST_LOG=warn,podgate_h3_stats=info" LOG_FORMAT=json)
runner=()
[ -n "$NATIVE" ] || runner=(valgrind --tool=callgrind "--callgrind-out-file=$OUT/callgrind.out.%p" --separate-threads=no)

# Under valgrind the shell's child is the chain env -> taskset -> valgrind (each one execs the next),
# so $! is valgrind's pid.
env "${entry_env[@]}" "${log_env[@]}" ADMIN_SOCKET="$work/admin.sock" \
  UPSTREAM_POLICY_FILE="$PWD/bench/upstream-policy.json" \
  taskset -c "$PROXY_CPUS" "${runner[@]}" "$PODGATE_BIN" >"$OUT/podgate.log" 2>&1 &
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

stats_lines() { grep -ac '"podgate_h3_stats"' "$OUT/podgate.log" || true; }
if [ "$LOAD" != h1 ]; then
  probe=$(curl -sS --max-time 60 --http1.1 --cacert "$work/cert.pem" --resolve "$HOST:$TLS_PORT:127.0.0.1" "https://$HOST:$TLS_PORT/" | wc -c)
  [ "$probe" = 100 ] || die "the TLS probe returned $probe bytes, not the backend's 100"
fi
if [ "$LOAD" = h3 ]; then
  LOAD_BENCH_REPLY_TIMEOUT_MS=$REPLY_TIMEOUT_MS "$LOAD_BIN" h3-count "127.0.0.1:$TLS_PORT" "$HOST" "$work/cert.pem" 1 1 1 2>/dev/null |
    jq -e '.statusCodeDistribution["200"] == 1 and (.errorDistribution | length) == 0' >/dev/null ||
    die "the HTTP/3 probe did not get the backend's 100 byte body (log: $OUT/podgate.log)"
  if [ -n "$stats_build" ]; then
    # Its connection's stats line is the first in the log; the loads' come after it.
    for _ in $(seq 1200); do
      [ "$(stats_lines)" -ge 1 ] && break
      sleep 0.5
    done
    [ "$(stats_lines)" -ge 1 ] || die "the HTTP/3 probe's connection never logged its stats"
  fi
fi

backend_stats() { curl -s "http://127.0.0.1:$BACKEND_PORT/__stats"; }
dump=
# Waits for a file the load generator creates; fails when the generator is gone.
wait_for() { # file pid
  for _ in $(seq 36000); do
    [ -e "$1" ] && return 0
    kill -0 "$2" 2>/dev/null || die "the load generator ended before creating $1 (see $OUT/load.err)"
    sleep 0.1
  done
  die "timed out waiting for $1"
}
dump_counters() {
  [ -z "$NATIVE" ] || return 0
  callgrind_control -d "$podgate_pid" >/dev/null
  for _ in $(seq 600); do
    dump=$(find "$OUT" -maxdepth 1 -name "callgrind.out.$podgate_pid.*" -size +0 | sort | head -n1)
    [ -n "$dump" ] && break
    sleep 0.5
  done
  [ -n "$dump" ] || die "callgrind wrote no dump"
}
zero_counters() {
  [ -n "$NATIVE" ] || callgrind_control -z "$podgate_pid" >/dev/null
}

if [ "$LOAD" = h1 ]; then
  oha_run() { # requests out-file
    taskset -c "$LOAD_CPUS" oha --no-tui --output-format json -n "$1" -c "$CONNECTIONS" -w --disable-compression \
      --worker-threads 2 -H "Host: $HOST" "http://127.0.0.1:$PROXY_PORT/" >"$2" 2>"$2.err"
  }
  oha_run "$WARMUP_REQUESTS" "$OUT/oha-warmup.json"
  zero_counters
  stats0=$(backend_stats)
  oha_run "$REQUESTS" "$OUT/load.json"
  stats1=$(backend_stats)
  dump_counters
else
  mkdir "$work/sync"
  mode=tls-count
  [ "$LOAD" != h3 ] || mode=h3-count
  LOAD_BENCH_SYNC="$work/sync" LOAD_BENCH_REPLY_TIMEOUT_MS=$REPLY_TIMEOUT_MS \
    taskset -c "$LOAD_CPUS" "$LOAD_BIN" "$mode" "127.0.0.1:$TLS_PORT" "$HOST" "$work/cert.pem" \
    "$CONNECTIONS" "$WARMUP_REQUESTS" "$REQUESTS" >"$OUT/load.json" 2>"$OUT/load.err" &
  load_pid=$!
  pids+=("$load_pid")
  wait_for "$work/sync/warm" "$load_pid"
  zero_counters
  stats0=$(backend_stats)
  touch "$work/sync/go"
  wait_for "$work/sync/done" "$load_pid"
  stats1=$(backend_stats)
  dump_counters
  touch "$work/sync/release"
  wait "$load_pid" || die "the load generator failed (see $OUT/load.err)"
fi

if [ -n "$stats_build" ]; then
  # Every connection logs when podgate notices it closed, which valgrind makes slow.
  for _ in $(seq 7200); do
    [ "$(stats_lines)" -ge $((CONNECTIONS + 1)) ] && break
    sleep 0.5
  done
fi
[ -n "$NATIVE" ] || sleep 2
kill -9 "$podgate_pid" 2>/dev/null || true
wait "$podgate_pid" 2>/dev/null || true

ok=$(jq '.statusCodeDistribution["200"] // 0' "$OUT/load.json")
errors=$(jq '[.errorDistribution // {} | .[]] | add // 0' "$OUT/load.json")
backend_requests=$(($(cut -d' ' -f2 <<<"$stats1") - $(cut -d' ' -f2 <<<"$stats0") - 1))
[ "$ok" = "$REQUESTS" ] && [ "$errors" = 0 ] || die "$LOAD: $ok of $REQUESTS requests answered 200, $errors errors"
[ "$backend_requests" = "$REQUESTS" ] || die "the backend served $backend_requests requests, not $REQUESTS"

if [ -n "$stats_build" ]; then
  server=$(grep -a '"podgate_h3_stats"' "$OUT/podgate.log" | tail -n +2 | head -n "$CONNECTIONS" | jq -s -c '
    { connections: length,
      total: (map(.fields | del(.message)) | reduce .[] as $f ({}; reduce ($f | to_entries[]) as $e (.; .[$e.key] += $e.value))) }')
  jq -n -c --slurpfile load "$OUT/load.json" --argjson server "$server" '
    ($load[0].quic) as $q
    | ($q.warmup_requests + $q.counted_requests) as $n
    | { requests_total: $n, requests_counted: $q.counted_requests,
        server: { connections: $server.connections, total: $server.total, per_request: ($server.total | map_values(. / $n)) },
        client: { connections: $q.connections, total: $q.total, per_request: ($q.total | map_values(. / $n)),
                  window: $q.window, window_per_request: ($q.window | map_values(. / $q.counted_requests)) } }' >"$OUT/quic.json"
  echo "QUIC loss recovery per request (server = podgate's side, all requests of the connections):"
  jq -r '.server.per_request | to_entries | map("\(.key) \(.value * 1000 | round / 1000)") | join("  ")' "$OUT/quic.json"
fi

if [ -n "$NATIVE" ]; then
  jq -n -c --arg bin "$PODGATE_BIN" --arg load "$LOAD" --argjson requests "$REQUESTS" --argjson connections "$CONNECTIONS" \
    --slurpfile load_json "$OUT/load.json" \
    '{bin: $bin, load: $load, native: true, requests: $requests, connections: $connections, load_requests_per_sec: $load_json[0].summary.requestsPerSec}' >"$OUT/result.json"
  cat "$OUT/result.json"
  echo "native run, no instruction count; quic.json and logs in $OUT"
  exit 0
fi

total=$(awk -F'[: ]+' '/^(summary|totals):/ { print $2; exit }' "$dump")
[ -n "$total" ] || die "no totals line in $dump"
callgrind_annotate --inclusive=yes --threshold=99.99 "$dump" >"$OUT/annotate-inclusive.txt"
callgrind_annotate --inclusive=no --threshold=99.99 "$dump" >"$OUT/annotate-self.txt"
jq -n -c --arg bin "$PODGATE_BIN" --arg snapshot "$SNAPSHOT_TEMPLATE" --arg load "$LOAD" --argjson requests "$REQUESTS" \
  --argjson connections "$CONNECTIONS" --argjson total "$total" \
  '{bin: $bin, snapshot: $snapshot, load: $load, requests: $requests, connections: $connections, total_ir: $total, ir_per_request: ($total / $requests | round)}' \
  >"$OUT/result.json"
cat "$OUT/result.json"
echo "instructions per request: $((total / REQUESTS)); dump and listings in $OUT"
