#!/usr/bin/env bash
# tenant A floods the proxy while tenant B sends a trickle.
#
# Runs B alone, then A at FLOOD_RPS together with B at QUIET_RPS, each for DURATION, against real
# processes (the podgate binary and the slow_upstream example, a backend with fixed latency and
# capacity). Prints the raw `oha` summaries and a verdict: B's success rate and p99 alone and
# under the flood.
#
#   scripts/load-fairness.sh [separate|shared]
#
#   separate  A and B each have their own upstream process (default).
#   shared    A and B share one upstream address, so the proxy's fair queue is what splits it.
#
# Needs `oha`, `curl` and a built binary of each (see PODGATE_BIN, UPSTREAM_BIN). Build with
# `cargo build [--release] --bin podgate --example slow_upstream`. Settings, all optional:
#   PODGATE_BIN  target/release/podgate    UPSTREAM_BIN  target/release/examples/slow_upstream
#   DURATION 20s   LATENCY_MS 100   CAPACITY 64 (requests an upstream serves at once)
#   FLOOD_RPS 1000   QUIET_RPS 10   BASE_PORT (first of 3 loopback ports; default: random free)
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

mode=${1:-separate}
case "$mode" in
separate | shared) ;;
*)
  echo "usage: $0 [separate|shared]" >&2
  exit 2
  ;;
esac

PODGATE_BIN=${PODGATE_BIN:-target/release/podgate}
UPSTREAM_BIN=${UPSTREAM_BIN:-target/release/examples/slow_upstream}
DURATION=${DURATION:-20s}
LATENCY_MS=${LATENCY_MS:-100}
CAPACITY=${CAPACITY:-64}
FLOOD_RPS=${FLOOD_RPS:-1000}
QUIET_RPS=${QUIET_RPS:-10}
# Three consecutive free loopback ports, starting at BASE_PORT or a random one.
listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 30000))}
while listening "$BASE_PORT" || listening $((BASE_PORT + 1)) || listening $((BASE_PORT + 2)); do
  BASE_PORT=$((20000 + RANDOM % 30000))
done

proxy_port=$BASE_PORT
upstream_a_port=$((BASE_PORT + 1))
upstream_b_port=$((BASE_PORT + 2))
if [ "$mode" = shared ]; then
  upstream_b_port=$upstream_a_port
fi

work=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

admin() {
  curl -sS --unix-socket "$work/admin.sock" "$@"
}

"$UPSTREAM_BIN" "127.0.0.1:$upstream_a_port" "$LATENCY_MS" "$CAPACITY" &
pids+=($!)
if [ "$mode" = separate ]; then
  "$UPSTREAM_BIN" "127.0.0.1:$upstream_b_port" "$LATENCY_MS" "$CAPACITY" &
  pids+=($!)
fi

PROXY_ADDR="127.0.0.1:$proxy_port" ADMIN_SOCKET="$work/admin.sock" REQUEST_TIMEOUT_SECS=30 \
  RUST_LOG=warn,pingora_proxy=off "$PODGATE_BIN" &
pids+=($!)

ready=
for _ in $(seq 100); do
  if [ "$(admin -o /dev/null -w '%{http_code}' http://x/readyz 2>/dev/null || true)" = 200 ] &&
    listening "$proxy_port" && listening "$upstream_a_port" && listening "$upstream_b_port"; then
    ready=1
    break
  fi
  sleep 0.1
done
[ -n "$ready" ] || {
  echo "podgate or an upstream did not come up" >&2
  exit 1
}

tenant() {
  printf '{"id":"%s","weight":1,"budget":{"max_inflight":10000,"max_buffer_bytes":1048576}}' "$1"
}
app() {
  printf '{"id":"%s","tenant":"%s","declared_by":"scripts/load-fairness.sh","hosts":["%s.test"],"tls":{"mode":"acme"},"revisions":[{"id":"r1","upstreams":["127.0.0.1:%s"],"weight":100,"state":"serving"}]}' \
    "$1" "$1" "$1" "$2"
}
snapshot="{\"version\":1,\"tenants\":[$(tenant a),$(tenant b)],\"apps\":[$(app a "$upstream_a_port"),$(app b "$upstream_b_port")]}"
status=$(admin -o /dev/null -w '%{http_code}' -X PUT -H 'content-type: application/json' \
  --data "$snapshot" http://x/v1/snapshot)
[ "$status" = 200 ] || {
  echo "snapshot push answered $status" >&2
  exit 1
}

echo "== context"
echo "mode=$mode duration=$DURATION upstream=${LATENCY_MS}ms x capacity $CAPACITY flood=${FLOOD_RPS}rps quiet=${QUIET_RPS}rps"
echo "nproc=$(nproc) loadavg=$(cut -d' ' -f1-3 /proc/loadavg) $(uname -sr) $(oha --version)"
echo "podgate=$PODGATE_BIN upstream=$UPSTREAM_BIN"

oha_run() { # host rate connections outfile
  oha --no-tui -z "$DURATION" -q "$2" -c "$3" -H "Host: $1.test" "http://127.0.0.1:$proxy_port/" >"$4" 2>&1
}

ticks() { awk '{ print $14 + $15 }' "/proc/$1/stat"; }
cpu_report() { # CPU of podgate, the upstreams and the load generators, mid-flood
  sleep 5
  local watch=("${pids[@]}") before=() pid i=0 now hz
  mapfile -t loadgen < <(pgrep -x oha)
  watch+=("${loadgen[@]}")
  hz=$(getconf CLK_TCK)
  for pid in "${watch[@]}"; do before+=("$(ticks "$pid")"); done
  sleep 3
  for pid in "${watch[@]}"; do
    now=$(ticks "$pid")
    printf '%s pid %s: %d%% of one core\n' "$(cat "/proc/$pid/comm")" "$pid" \
      $(((now - before[i]) * 100 / (3 * hz)))
    i=$((i + 1))
  done
}

oha_run b "$QUIET_RPS" 20 "$work/b-alone.txt"
oha_run a "$FLOOD_RPS" 400 "$work/a-flood.txt" &
flood=$!
cpu_report >"$work/cpu.txt" &
sampler=$!
oha_run b "$QUIET_RPS" 20 "$work/b-flood.txt"
wait "$flood" "$sampler"

verdict() { # file label
  awk -v label="$2" '
    /\[[0-9]+\] [0-9]+ responses/ { gsub(/[\[\]]/, "", $1); codes[$1] = $2; total += $2 }
    /99.00% in/ { p99 = $3 " " $4 }
    END {
      ok = codes["200"] + 0
      printf "%s: %d of %d answered 200 (%.2f%%), p99 %s\n", label, ok, total, total ? 100 * ok / total : 0, p99
    }' "$1"
}

for file in b-alone b-flood a-flood; do
  echo "== oha $file"
  cat "$work/$file.txt"
done
echo "== backend metrics"
admin http://x/metrics | grep '^podgate_backend_\(limit\|waited_total\|refused_total\)' || true
echo "== verdict"
verdict "$work/b-alone.txt" "B alone      "
verdict "$work/b-flood.txt" "B under flood"
verdict "$work/a-flood.txt" "A flooding   "
echo "== cpu during the flood (what limits the run)"
cat "$work/cpu.txt"
