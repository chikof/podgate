#!/usr/bin/env bash
# user against system CPU per request, HTTP/3 (`h3-c64`) against HTTPS (`tls-h1`).
#
# `STARTS` times, one fresh podgate per start and scenario, runs scripts/bench-proxies.sh with
# PROXIES=podgate, one run of DURATION seconds, the scenarios interleaved (the order flips on every
# other start so drift favours neither). `h3-c64` runs with PODGATE_H3=1 (the `;http3` front);
# `tls-h1` without it, the shipped HTTPS entry point. Every run records podgate's user and system
# ticks from /proc/<pid>/stat over the steady-state window (`cpu_user_s_per_100k`,
# `cpu_system_s_per_100k`) and the user, system and interrupt split of the proxy CPUs from
# /proc/stat (`proxy_cpus_pct`). The system part of a loopback UDP or TCP send includes the
# receiving side's softirq work, which the kernel runs in the sender's context; it is counted
# as the sender's system time or as softirq, depending on the kernel's accounting.
#
#   flock ~/.cache/podgate-cargo.lock scripts/bench-user-system.sh
#   STARTS=3 DURATION=8 scripts/bench-user-system.sh        # a short dry run
#
# Results go to OUT (default: a fresh temp dir): `timing.jsonl` (one line per run), `start-N-<scenario>.log`
# and the table on stdout. The file is not called runs.jsonl on purpose: scripts/bench-charts.sh draws
# the newest runs.jsonl under bench/results. Run it inside `devenv shell` (oha, jq) after
#   cargo build --release --bin podgate --example fast_upstream --example bench_cert --example load_bench
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

STARTS=${STARTS:-7}
DURATION=${DURATION:-15}
WARMUP=${WARMUP:-2}
OUT=${OUT:-$(mktemp -d /tmp/podgate-user-system.XXXXXX)}
mkdir -p "$OUT"
: >"$OUT/timing.jsonl"

failed=
for start in $(seq "$STARTS"); do
  scenarios=(h3-c64 tls-h1)
  if [ $((start % 2)) = 0 ]; then scenarios=(tls-h1 h3-c64); fi
  for scenario in "${scenarios[@]}"; do
    run_out=$OUT/start-$start-$scenario
    flags=()
    [ "$scenario" != h3-c64 ] || flags+=(PODGATE_H3=1)
    echo "start $start: $scenario"
    if ! env "${flags[@]}" PROXIES=podgate SCENARIOS="$scenario" RUNS=1 DURATION="$DURATION" WARMUP="$WARMUP" \
      OUT="$run_out" scripts/bench-proxies.sh >"$run_out.log" 2>&1; then
      echo "!! start $start $scenario failed or had errors: see $run_out.log" >&2
      failed=1
    fi
    [ -s "$run_out/runs.jsonl" ] || continue
    jq -c --argjson start "$start" 'select(.scenario != "idle") | . + {start: $start}' "$run_out/runs.jsonl" >>"$OUT/timing.jsonl"
  done
done

echo "== user against system CPU of podgate per 100k requests (median [min-max] of $STARTS starts)"
jq -s -r '
  def med: sort | if length == 0 then null else ((.[(length - 1) / 2 | floor] + .[length / 2 | floor]) / 2) end;
  def r($d): (. * pow(10; $d) | round) / pow(10; $d);
  def cell($f; $d): map(.[$f]) | "\(med | r($d)) [\(min | r($d))-\(max | r($d))]";
  def share($f): map(.proxy_cpus_pct | .[$f] * 100 / (.user + .system + .irq)) | "\(med | r(1)) [\(min | r(1))-\(max | r(1))]";
  def md: "| " + (map(tostring) | join(" | ")) + " |";
  (["scenario", "starts", "req/s", "CPU s/100k", "user s/100k", "system s/100k", "system share of process CPU %", "proxy CPUs: user % of busy", "system %", "irq+softirq %", "non-2xx", "errors"] | md),
  (["---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---", "---"] | md),
  ( group_by(.scenario) | .[]
    | [ .[0].scenario, length, cell("rps"; 0), cell("cpu_s_per_100k"; 3), cell("cpu_user_s_per_100k"; 3), cell("cpu_system_s_per_100k"; 3),
        (map(.cpu_system_s_per_100k * 100 / .cpu_s_per_100k) | "\(med | r(1)) [\(min | r(1))-\(max | r(1))]"),
        share("user"), share("system"), share("irq"),
        (map(.non_ok) | add), (map(.errors) | add) ]
    | md )' "$OUT/timing.jsonl"
echo "per-run lines in $OUT/timing.jsonl"
[ -z "$failed" ] || exit 1
