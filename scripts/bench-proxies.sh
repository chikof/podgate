#!/usr/bin/env bash
# podgate against Caddy and Traefik as a Host-routing reverse proxy.
#
# Starts one fast backend (examples/fast_upstream), the three proxies and `oha` on disjoint CPU
# sets, checks with curl that every proxy routes `a.test` to the backend and answers 404 for an
# unknown Host, then runs each scenario RUNS times with the proxies interleaved (podgate, caddy,
# traefik, podgate, ...). Prints a median and range table; results and per-run details land in
# OUT. Exits 1 when any run had a non-2xx response, an error, or a request count that does not
# match the backend's. Method and tuning: docs/benchmarks.md.
#
#   scripts/bench-proxies.sh                 # all scenarios, 5 runs of 15 s each
#   SCENARIOS="h1-c64" RUNS=1 DURATION=5 scripts/bench-proxies.sh   # a short dry run
#
# Run it inside `devenv shell` (oha, caddy, traefik, jq) after
#   cargo build --release --bin podgate --example fast_upstream --example bench_cert
# and hold `flock ~/.cache/podgate-cargo.lock` around it so no build competes for the CPUs.
#
# Scenarios (SCENARIOS, space separated):
#   h1-c64    plain HTTP/1.1 keep-alive, 64 connections, 100 B body, as fast as possible
#   rate      the same at RATE requests/s (default: half the slowest proxy's h1-c64 median)
#   h1-c256   as h1-c64 with 256 connections
#   h1-16k    as h1-c64 with a 16 KiB body
#   tls-h1    TLS 1.3, HTTP/1.1 keep-alive, 64 connections
#   tls-h2    TLS 1.3, HTTP/2, 16 connections x 4 streams
# `direct` (oha straight at the backend) joins the plain scenarios as the ceiling of the rig.
#
# Settings, all optional:
#   RUNS 5   DURATION 15 (seconds)   WARMUP 2 (seconds, not recorded)   SCENARIOS (above)
#   PROXIES "podgate caddy traefik"   RATE (requests/s)   OUT (default: a fresh temp dir)
#   PROXY_CPUS 0-3   LOAD_CPUS 4-5   BACKEND_CPUS 6-7   (taskset lists; the proxy gets one
#   thread per CPU: GOMAXPROCS for the Go proxies, available_parallelism for podgate)
#   BUSY_MAX 3 (CPUs busy with other work before a run) BUSY_WAIT 60 (seconds to wait for it)
#   BASE_PORT (first of 8 loopback ports; default: random free)
#   PODGATE_BIN UPSTREAM_BIN CERT_BIN  (target/release/...)
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

RUNS=${RUNS:-5}
DURATION=${DURATION:-15}
WARMUP=${WARMUP:-2}
SCENARIOS=${SCENARIOS:-h1-c64 rate h1-c256 h1-16k tls-h1 tls-h2}
PROXIES=${PROXIES:-podgate caddy traefik}
RATE=${RATE:-}
PROXY_CPUS=${PROXY_CPUS:-0-3}
LOAD_CPUS=${LOAD_CPUS:-4-5}
BACKEND_CPUS=${BACKEND_CPUS:-6-7}
BUSY_MAX=${BUSY_MAX:-3}
BUSY_WAIT=${BUSY_WAIT:-60}
PODGATE_BIN=${PODGATE_BIN:-target/release/podgate}
UPSTREAM_BIN=${UPSTREAM_BIN:-target/release/examples/fast_upstream}
CERT_BIN=${CERT_BIN:-target/release/examples/bench_cert}
HOST=a.test
CLK_TCK=$(getconf CLK_TCK)

die() {
  echo "bench-proxies: $*" >&2
  exit 1
}

for tool in oha caddy traefik jq curl taskset cmp; do
  command -v "$tool" >/dev/null || die "$tool not found (run inside devenv shell)"
done
for bin in "$PODGATE_BIN" "$UPSTREAM_BIN" "$CERT_BIN"; do
  [ -x "$bin" ] || die "$bin missing: cargo build --release --bin podgate --example fast_upstream --example bench_cert"
done

# "0-3,8" -> number of CPUs.
cpu_count() {
  local count=0 part
  IFS=, read -ra parts <<<"$1"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then count=$((count + ${part#*-} - ${part%-*} + 1)); else count=$((count + 1)); fi
  done
  echo "$count"
}
PROXY_THREADS=$(cpu_count "$PROXY_CPUS")
LOAD_THREADS=$(cpu_count "$LOAD_CPUS")

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
BASE_PORT=${BASE_PORT:-$((20000 + RANDOM % 30000))}
while :; do
  taken=
  for offset in 0 1 2 3 4 5 6; do
    if listening $((BASE_PORT + offset)); then taken=1; fi
  done
  [ -z "$taken" ] && break
  BASE_PORT=$((20000 + RANDOM % 30000))
done

declare -A HTTP_PORT TLS_PORT PID
HTTP_PORT[podgate]=$BASE_PORT
TLS_PORT[podgate]=$((BASE_PORT + 1))
HTTP_PORT[caddy]=$((BASE_PORT + 2))
TLS_PORT[caddy]=$((BASE_PORT + 3))
HTTP_PORT[traefik]=$((BASE_PORT + 4))
TLS_PORT[traefik]=$((BASE_PORT + 5))
BACKEND_PORT=$((BASE_PORT + 6))
HTTP_PORT[direct]=$BACKEND_PORT

work=$(mktemp -d)
OUT=${OUT:-$(mktemp -d /tmp/podgate-bench.XXXXXX)}
mkdir -p "$OUT"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ -z "${KEEP_WORK:-}" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT

# ---- start everything -------------------------------------------------------------------------

"$CERT_BIN" "$work" "$HOST"
head -c 100 /dev/zero | tr '\0' x >"$work/expect-small"
head -c 16384 /dev/zero | tr '\0' x >"$work/expect-large"

render() { # template
  sed -e "s|@BACKEND_PORT@|$BACKEND_PORT|g" \
    -e "s|@CADDY_HTTP_PORT@|${HTTP_PORT[caddy]}|g" -e "s|@CADDY_TLS_PORT@|${TLS_PORT[caddy]}|g" \
    -e "s|@TRAEFIK_HTTP_PORT@|${HTTP_PORT[traefik]}|g" -e "s|@TRAEFIK_TLS_PORT@|${TLS_PORT[traefik]}|g" \
    -e "s|@CERT_DIR@|$work|g" -e "s|@WORK_DIR@|$work|g" "$1"
}
render bench/Caddyfile.in >"$work/Caddyfile"
render bench/traefik.yml.in >"$work/traefik.yml"
render bench/traefik-dynamic.yml.in >"$work/traefik-dynamic.yml"
render bench/podgate-snapshot.json.in |
  jq --rawfile cert "$work/cert.pem" --rawfile key "$work/key.pem" --arg host "$HOST" \
    '.certificates = [{hosts: [$host], cert_pem: $cert, key_pem: $key}]' >"$work/snapshot.json"

taskset -c "$BACKEND_CPUS" "$UPSTREAM_BIN" "127.0.0.1:$BACKEND_PORT" &
PID[direct]=$!
pids+=("${PID[direct]}")

want() { [[ " $PROXIES " == *" $1 "* ]]; }

if want podgate; then
  PROXY_ADDR="127.0.0.1:${HTTP_PORT[podgate]}" PROXY_TLS_ADDR="127.0.0.1:${TLS_PORT[podgate]}" \
    ADMIN_SOCKET="$work/admin.sock" RUST_LOG=warn \
    taskset -c "$PROXY_CPUS" "$PODGATE_BIN" 2>"$work/podgate.log" &
  PID[podgate]=$!
  pids+=("${PID[podgate]}")
fi
if want caddy; then
  GOMAXPROCS=$PROXY_THREADS XDG_DATA_HOME="$work/caddy-data" XDG_CONFIG_HOME="$work/caddy-config" \
    taskset -c "$PROXY_CPUS" caddy run --config "$work/Caddyfile" --adapter caddyfile 2>"$work/caddy.log" &
  PID[caddy]=$!
  pids+=("${PID[caddy]}")
fi
if want traefik; then
  GOMAXPROCS=$PROXY_THREADS taskset -c "$PROXY_CPUS" traefik --configFile="$work/traefik.yml" 2>"$work/traefik.log" &
  PID[traefik]=$!
  pids+=("${PID[traefik]}")
fi

wait_listening() { # port name
  for _ in $(seq 100); do
    if listening "$1"; then return 0; fi
    sleep 0.1
  done
  die "$2 did not start listening on $1"
}
wait_listening "$BACKEND_PORT" backend
for proxy in $PROXIES; do wait_listening "${HTTP_PORT[$proxy]}" "$proxy"; done
if want podgate; then
  for _ in $(seq 100); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$work/admin.sock" http://x/readyz || true)" = 200 ] && break
    sleep 0.1
  done
  status=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$work/admin.sock" -X PUT \
    -H 'content-type: application/json' --data-binary "@$work/snapshot.json" http://x/v1/snapshot)
  [ "$status" = 200 ] || die "podgate snapshot push answered $status"
fi

# ---- helpers ----------------------------------------------------------------------------------

ticks() {
  [ -r "/proc/$1/stat" ] || die "process $1 ($(cat "/proc/$1/comm" 2>/dev/null)) vanished during a run"
  awk '{ print $14 + $15 }' "/proc/$1/stat"
}
# Resume: OUT=<an earlier output dir> skips the runs it already holds (after a crash or Ctrl-C).
recorded() { # scenario proxy run
  [ -s "$OUT/runs.jsonl" ] && jq -e -s --arg s "$1" --arg p "$2" --argjson r "$3" \
    'any(.[]; .scenario == $s and .proxy == $p and .run == $r)' "$OUT/runs.jsonl" >/dev/null
}
status_kb() { awk -v key="$2" '$1 == key { print $2 }' "/proc/$1/status"; }
backend_stats() { curl -s "http://127.0.0.1:$BACKEND_PORT/__stats"; } # "connections requests"

# Sum of user+nice+system ticks over a taskset CPU list ("all" for every CPU), from /proc/stat.
cpu_busy() {
  awk -v list="$1" '
    BEGIN {
      n = split(list, parts, ",")
      for (i = 1; i <= n; i++) {
        if (split(parts[i], range, "-") == 2) { for (c = range[1]; c <= range[2]; c++) want[c] = 1 }
        else want[parts[i]] = 1
      }
    }
    /^cpu[0-9]/ {
      id = substr($1, 4) + 0
      if (list == "all" || id in want) sum += $2 + $3 + $4
    }
    END { print sum + 0 }' /proc/stat
}

# Time on a taskset CPU list, in ticks: "user+nice system irq+softirq idle+iowait", from /proc/stat.
cpu_split() {
  awk -v list="$1" '
    BEGIN {
      n = split(list, parts, ",")
      for (i = 1; i <= n; i++) {
        if (split(parts[i], range, "-") == 2) { for (c = range[1]; c <= range[2]; c++) want[c] = 1 }
        else want[parts[i]] = 1
      }
    }
    /^cpu[0-9]/ {
      id = substr($1, 4) + 0
      if (id in want) { user += $2 + $3; system_t += $4; irq += $7 + $8; idle += $5 + $6 }
    }
    END { print user + 0, system_t + 0, irq + 0, idle + 0 }' /proc/stat
}

# CPUs busy with other work over 2 s, measured while our processes idle.
other_busy() {
  local before after
  before=$(cpu_busy all)
  sleep 2
  after=$(cpu_busy all)
  awk -v d=$((after - before)) -v hz="$CLK_TCK" 'BEGIN { printf "%.2f", d / (2 * hz) }'
}

# Waits up to BUSY_WAIT seconds for the machine to quiet down; prints the last reading.
quiet_machine() {
  local waited=0 busy
  busy=$(other_busy)
  while awk -v b="$busy" -v m="$BUSY_MAX" 'BEGIN { exit !(b > m) }' && [ "$waited" -lt "$BUSY_WAIT" ]; do
    sleep 3
    waited=$((waited + 5))
    busy=$(other_busy)
  done
  echo "$busy"
}

probe() { # proxy: the routed host returns the backend's body, an unknown host answers 404
  local proxy=$1 port=${HTTP_PORT[$1]} code
  curl -sS --max-time 5 -H "Host: $HOST" "http://127.0.0.1:$port/" | cmp -s - "$work/expect-small" ||
    die "$proxy: http://127.0.0.1:$port/ did not return the backend's 100 byte body"
  curl -sS --max-time 5 -H "Host: $HOST" "http://127.0.0.1:$port/16k" | cmp -s - "$work/expect-large" ||
    die "$proxy: /16k did not return the backend's 16 KiB body"
  [ "$proxy" = direct ] && return 0
  code=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' -H 'Host: unknown.test' "http://127.0.0.1:$port/")
  [ "$code" = 404 ] || die "$proxy: unknown Host answered $code, not 404"
  local tls=${TLS_PORT[$proxy]} version
  for flag in --http1.1 --http2; do
    curl -sS --max-time 5 "$flag" --cacert "$work/cert.pem" --resolve "$HOST:$tls:127.0.0.1" \
      "https://$HOST:$tls/" | cmp -s - "$work/expect-small" || die "$proxy: TLS $flag did not return the backend's body"
  done
  version=$(curl -sS --max-time 5 --http2 --cacert "$work/cert.pem" --resolve "$HOST:$tls:127.0.0.1" \
    -o /dev/null -w '%{http_version}' "https://$HOST:$tls/")
  [ "$version" = 2 ] || die "$proxy: TLS did not negotiate HTTP/2 (got $version)"
}

# Echo the podgate counters that say whether its admission control acted: summed over labels.
podgate_counters() {
  curl -s --unix-socket "$work/admin.sock" http://x/metrics | awk '
    /^podgate_backend_waited_total/ { waited += $NF }
    /^podgate_backend_refused_total/ { refused += $NF }
    /^podgate_tenant_inflight_rejected_total/ { rejected += $NF }
    /^podgate_backend_limit/ { if ($NF > limit) limit = $NF }
    END { printf "%d %d %d %d\n", waited, refused, rejected, limit }'
}

# Scenario table: path, port kind, oha arguments.
scenario_path() { if [ "$1" = h1-16k ]; then echo /16k; else echo /; fi; }
scenario_tls() { [[ $1 == tls-* ]]; }
scenario_args() {
  case "$1" in
  h1-c64 | h1-16k | tls-h1) echo "-c 64" ;;
  h1-c256) echo "-c 256" ;;
  rate) echo "-c 64 -q $RATE --latency-correction" ;;
  tls-h2) echo "-c 16 -p 4 --http2" ;;
  *) die "unknown scenario $1" ;;
  esac
}

oha_cmd() { # proxy scenario seconds -> prints the command words, one per line
  local proxy=$1 scenario=$2 secs=$3 path url port
  path=$(scenario_path "$scenario")
  local words=(oha --no-tui --output-format json -z "${secs}s" -w --disable-compression
    --worker-threads "$LOAD_THREADS")
  local scenario_words
  read -ra scenario_words <<<"$(scenario_args "$scenario")"
  words+=("${scenario_words[@]}")
  if scenario_tls "$scenario"; then
    port=${TLS_PORT[$proxy]}
    url="https://$HOST:$port$path"
    words+=(--insecure --connect-to "$HOST:$port:127.0.0.1:$port")
  else
    port=${HTTP_PORT[$proxy]}
    url="http://127.0.0.1:$port$path"
    words+=(-H "Host: $HOST")
  fi
  printf '%s\n' "${words[@]}" "$url"
}

measure() { # scenario proxy run -> appends one JSON line to $OUT/runs.jsonl
  local scenario=$1 proxy=$2 run=$3 words pid_p="" busy load1
  if recorded "$scenario" "$proxy" "$run"; then
    echo "  $scenario $proxy run $run: already in $OUT/runs.jsonl, skipped"
    return 0
  fi
  probe "$proxy"
  busy=$(quiet_machine)
  load1=$(cut -d' ' -f1 /proc/loadavg)
  mapfile -t words < <(oha_cmd "$proxy" "$scenario" "$WARMUP")
  taskset -c "$LOAD_CPUS" "${words[@]}" >/dev/null 2>&1 || true
  mapfile -t words < <(oha_cmd "$proxy" "$scenario" "$DURATION")

  [ "$proxy" = direct ] || pid_p=${PID[$proxy]}
  [ -z "$pid_p" ] || echo 5 >"/proc/$pid_p/clear_refs" # restart the peak RSS (VmHWM) here
  local stats0 stats1 counters0="0 0 0 0" counters1="0 0 0 0"
  stats0=$(backend_stats)
  if [ "$proxy" = podgate ]; then counters0=$(podgate_counters); fi

  taskset -c "$LOAD_CPUS" "${words[@]}" >"$OUT/oha-$scenario-$proxy-$run.json" 2>"$OUT/oha-$scenario-$proxy-$run.err" &
  local oha_pid=$!
  # Steady-state window: skip the first and last 2 seconds of the run.
  sleep 2
  local w0 w1 p0=0 p1=0 b0 b1 o0 o1 cpu_p0 cpu_p1 cpu_l0 cpu_l1 cpu_all0 cpu_all1 split0 split1
  w0=$(date +%s.%N)
  [ -z "$pid_p" ] || p0=$(ticks "$pid_p")
  b0=$(ticks "${PID[direct]}")
  o0=$(ticks "$oha_pid")
  cpu_p0=$(cpu_busy "$PROXY_CPUS")
  cpu_l0=$(cpu_busy "$LOAD_CPUS")
  cpu_all0=$(cpu_busy all)
  split0=$(cpu_split "$PROXY_CPUS")
  sleep $((DURATION - 4))
  w1=$(date +%s.%N)
  [ -z "$pid_p" ] || p1=$(ticks "$pid_p")
  b1=$(ticks "${PID[direct]}")
  o1=$(ticks "$oha_pid")
  cpu_p1=$(cpu_busy "$PROXY_CPUS")
  cpu_l1=$(cpu_busy "$LOAD_CPUS")
  cpu_all1=$(cpu_busy all)
  split1=$(cpu_split "$PROXY_CPUS")
  wait "$oha_pid" || true

  stats1=$(backend_stats)
  if [ "$proxy" = podgate ]; then counters1=$(podgate_counters); fi
  local peak_kb=0
  [ -z "$pid_p" ] || peak_kb=$(status_kb "$pid_p" VmHWM:)

  jq -n -c \
    --arg scenario "$scenario" --arg proxy "$proxy" --argjson run "$run" \
    --arg busy "$busy" --arg load1 "$load1" \
    --slurpfile oha "$OUT/oha-$scenario-$proxy-$run.json" \
    --arg stats0 "$stats0" --arg stats1 "$stats1" --arg c0 "$counters0" --arg c1 "$counters1" \
    --argjson peak_kb "$peak_kb" --argjson hz "$CLK_TCK" \
    --argjson w "$(awk -v a="$w0" -v b="$w1" 'BEGIN { printf "%.3f", b - a }')" \
    --argjson p "$((p1 - p0))" --argjson b "$((b1 - b0))" --argjson o "$((o1 - o0))" \
    --argjson cpu_p "$((cpu_p1 - cpu_p0))" --argjson cpu_l "$((cpu_l1 - cpu_l0))" \
    --arg split0 "$split0" --arg split1 "$split1" \
    --argjson cpu_all "$((cpu_all1 - cpu_all0))" '
    def nums: split(" ") | map(tonumber);
    ($oha[0]) as $o_
    | ($o_.statusCodeDistribution // {}) as $codes
    | ($codes | to_entries | map(.value) | add // 0) as $total
    | ($codes["200"] // 0) as $ok
    | ($o_.errorDistribution // {} | to_entries | map(.value) | add // 0) as $errors
    | ($stats0 | nums) as $s0 | ($stats1 | nums) as $s1
    | ($c0 | nums) as $k0 | ($c1 | nums) as $k1
    | {
        scenario: $scenario, proxy: $proxy, run: $run,
        rps: $o_.summary.requestsPerSec,
        p50_ms: ($o_.latencyPercentiles.p50 * 1000),
        p99_ms: ($o_.latencyPercentiles.p99 * 1000),
        p999_ms: ($o_.latencyPercentiles["p99.9"] * 1000),
        total: $total, ok: $ok, non_ok: ($total - $ok), errors: $errors,
        backend_requests: ($s1[1] - $s0[1]), backend_conns: ($s1[0] - $s0[0] - 1),
        proxy_cores: ($p / $hz / $w), oha_cores: ($o / $hz / $w), backend_cores: ($b / $hz / $w),
        cpu_s_per_100k: (if $p > 0 then ($p / $hz) / ($o_.summary.requestsPerSec * $w) * 100000 else null end),
        peak_rss_mb: ($peak_kb / 1024),
        other_cores_before: ($busy | tonumber), load1: ($load1 | tonumber),
        other_cores_on_proxy_cpus: (($cpu_p - $p) / $hz / $w),
        other_cores_all: (($cpu_all - $p - $b - $o) / $hz / $w),
        proxy_cpus_pct: (
          ($split1 | nums) as $t1 | ($split0 | nums) as $t0
          | ([range(0; 4)] | map($t1[.] - $t0[.])) as $d | ($d | add) as $sum
          | { user: ($d[0] * 100 / $sum), system: ($d[1] * 100 / $sum), irq: ($d[2] * 100 / $sum), idle: ($d[3] * 100 / $sum) }),
        podgate_waited: ($k1[0] - $k0[0]), podgate_refused: ($k1[1] - $k0[1]),
        podgate_tenant_rejected: ($k1[2] - $k0[2]), podgate_limit_max: $k1[3]
      }' >>"$OUT/runs.jsonl"
  jq -r '"  \(.scenario) \(.proxy) run \(.run): \(.rps|floor) req/s p50 \(.p50_ms*1000|floor) us p99 \(.p99_ms*1000|floor) us proxy \(.proxy_cores*100|floor)% oha \(.oha_cores*100|floor)% backend \(.backend_cores*100|floor)% other-on-proxy-cpus \(.other_cores_on_proxy_cpus*100|floor)% busy-before \(.other_cores_before) non-2xx \(.non_ok) errors \(.errors)"' <<<"$(tail -n 1 "$OUT/runs.jsonl")"
  jq -e '.non_ok == 0 and .errors == 0 and ((.backend_requests - .total) | fabs) <= (.total * 0.005 + 5)' \
    <<<"$(tail -n 1 "$OUT/runs.jsonl")" >/dev/null || {
    echo "!! FAILED RUN $scenario $proxy $run: non-2xx, errors, or a backend request count that does not match oha" >&2
    failed=1
  }
}

# ---- context ----------------------------------------------------------------------------------

failed=
echo "== context"
echo "date $(date -u +%FT%TZ)  kernel $(uname -sr)  nproc $(nproc)  load $(cut -d' ' -f1-3 /proc/loadavg)"
echo "podgate $(git rev-parse --short HEAD 2>/dev/null || echo unknown)  $(caddy version | cut -d' ' -f1)  traefik $(traefik version | awk '/^Version/ { print $2 }')  $(oha --version)"
echo "cpus: proxy $PROXY_CPUS ($PROXY_THREADS)  oha $LOAD_CPUS ($LOAD_THREADS)  backend $BACKEND_CPUS"
echo "ports: base $BASE_PORT  out $OUT"
sleep 3
for proxy in $PROXIES; do
  pid=${PID[$proxy]}
  echo "$proxy pid $pid threads $(find "/proc/$pid/task" -mindepth 1 -maxdepth 1 | wc -l)  idle RSS $(($(status_kb "$pid" VmRSS:) / 1024)) MiB"
  if ! recorded idle "$proxy" 1; then
    jq -n -c --arg proxy "$proxy" --argjson kb "$(status_kb "$pid" VmRSS:)" \
      '{scenario: "idle", proxy: $proxy, run: 1, idle_rss_mb: ($kb / 1024)}' >>"$OUT/runs.jsonl"
  fi
done
for proxy in $PROXIES; do probe "$proxy"; done
echo "probe passed for: $PROXIES"

# ---- runs -------------------------------------------------------------------------------------

median_field() { # scenario proxy field
  jq -s -r --arg s "$1" --arg p "$2" --arg f "$3" \
    '[.[] | select(.scenario == $s and .proxy == $p) | .[$f]] | sort | .[(length / 2 | floor)]' "$OUT/runs.jsonl"
}

for scenario in $SCENARIOS; do
  if [ "$scenario" = rate ] && [ -z "$RATE" ]; then
    slowest=
    for proxy in $PROXIES; do
      rps=$(median_field h1-c64 "$proxy" rps)
      [ "$rps" = null ] && die "scenario rate needs h1-c64 first, or RATE=<requests/s>"
      slowest=$(awk -v a="${slowest:-$rps}" -v b="$rps" 'BEGIN { print (a < b ? a : b) }')
    done
    RATE=$(awk -v s="$slowest" 'BEGIN { print int(s / 2 / 1000) * 1000 }')
    echo "rate = $RATE requests/s (half the slowest median h1-c64, rounded down to 1000)"
  fi
  echo "== $scenario ($(scenario_args "$scenario"), ${DURATION} s x $RUNS runs)"
  order=$PROXIES
  case "$scenario" in h1-c64 | h1-c256 | h1-16k | rate) order="$PROXIES direct" ;; esac
  for run in $(seq "$RUNS"); do
    for proxy in $order; do
      measure "$scenario" "$proxy" "$run"
    done
  done
done

# ---- summary ----------------------------------------------------------------------------------

echo "== results (median [min-max] of $RUNS runs; latencies in ms; CPU in cores of the proxy process)"
jq -s -r '
  def med: sort | if length == 0 then null else ((.[(length - 1) / 2 | floor] + .[length / 2 | floor]) / 2) end;
  def r($d): (. * pow(10; $d) | round) / pow(10; $d);
  def cell($f; $d): map(.[$f]) | "\(med | r($d)) [\(min | r($d))-\(max | r($d))]";
  def md: "| " + (map(tostring) | join(" | ")) + " |";
  (["scenario", "proxy", "req/s", "p50 ms", "p99 ms", "p99.9 ms", "proxy cores", "oha cores", "backend cores", "CPU s/100k req", "peak RSS MiB", "non-2xx", "errors", "other cores on proxy CPUs"] | md),
  (["---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---"] | md),
  ( map(select(.scenario != "idle")) | group_by([.scenario, .proxy]) | .[]
    | [ .[0].scenario, .[0].proxy, cell("rps"; 0), cell("p50_ms"; 3), cell("p99_ms"; 3), cell("p999_ms"; 3),
        cell("proxy_cores"; 2), cell("oha_cores"; 2), cell("backend_cores"; 2),
        (if .[0].cpu_s_per_100k == null then "-" else cell("cpu_s_per_100k"; 3) end),
        (if .[0].proxy == "direct" then "-" else cell("peak_rss_mb"; 0) end),
        (map(.non_ok) | add), (map(.errors) | add), cell("other_cores_on_proxy_cpus"; 2) ]
    | md )' "$OUT/runs.jsonl"
echo "== idle RSS (MiB, before any request)"
jq -r 'select(.scenario == "idle") | "\(.proxy)\t\(.idle_rss_mb | . * 10 | round / 10)"' "$OUT/runs.jsonl"
echo "== podgate admission counters per run (waited, refused, tenant rejected, highest backend limit)"
jq -r 'select(.proxy == "podgate" and .scenario != "idle") | "\(.scenario) run \(.run): waited \(.podgate_waited) refused \(.podgate_refused) rejected \(.podgate_tenant_rejected) limit \(.podgate_limit_max)"' "$OUT/runs.jsonl"
echo "== upstream connections opened per run (keep-alive proof: far fewer than requests; the stats query itself is not counted)"
jq -r 'select(.scenario != "idle") | "\(.scenario) \(.proxy) run \(.run): \(.backend_conns) connections for \(.backend_requests) requests"' "$OUT/runs.jsonl"
echo "results in $OUT (runs.jsonl, oha-*.json); set KEEP_WORK=1 to keep configs and logs"
if [ -n "$failed" ]; then
  echo "!! at least one run failed; see lines marked FAILED RUN above" >&2
  exit 1
fi
