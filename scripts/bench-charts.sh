#!/usr/bin/env bash
# SVG charts for docs/benchmarks.md from the recorded benchmark results.
#
#   scripts/bench-charts.sh [results dir]            # write docs/benchmarks/*.svg
#   scripts/bench-charts.sh --check [results dir]    # regenerate into a temp dir, compare, exit 1 on stale charts
#
# The results dir defaults to the newest bench/results/<name>/ with a runs.jsonl (names sort by
# date). Per scenario and proxy every bar is the median of the runs and the whisker spans their
# min to max, because the verdicts in the doc depend on whether ranges overlap. The attribution
# chart reads attribution.jsonl from the results dir, or from the newest dir that has
# one. Series keep one colour and order in every chart: podgate, Caddy, Traefik, direct. The SVGs
# have no background and mid-grey text so they read on GitHub's light and dark themes, and the
# same input gives byte-identical output.
#
# Run it inside `devenv shell` (gnuplot, jq).
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

check=0
if [[ ${1:-} == --check ]]; then
  check=1
  shift
fi

results=${1:-}
if [[ -z $results ]]; then
  for d in bench/results/*; do
    [[ -f $d/runs.jsonl ]] && results=$d
  done
fi
[[ -f $results/runs.jsonl ]] || {
  echo "bench-charts.sh: no runs.jsonl in '${results:-bench/results/*}'" >&2
  exit 2
}
attribution=
if [[ -f $results/attribution.jsonl ]]; then
  attribution=$results/attribution.jsonl
else
  for d in bench/results/*; do
    [[ -f $d/attribution.jsonl ]] && attribution=$d/attribution.jsonl
  done
fi

dest=docs/benchmarks
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if ((check)); then out=$tmp/out; else out=$dest; fi
mkdir -p "$out"

# Aggregate one metric into $tmp/<name>.{dat,xt,ymax}.
#   agg <name> <metric> <scenarios json> <proxies json>
# dat: x, median, min, max, series index (1 podgate, 2 caddy, 3 traefik, 4 direct).
# A run without the metric (direct has no proxy CPU or memory) is left out.
agg() {
  local name=$1 metric=$2 scen=$3 prox=$4
  jq -s --arg metric "$metric" --argjson scen "$scen" --argjson prox "$prox" '
    def med: sort | length as $n
      | if $n % 2 == 1 then .[($n - 1) / 2] else (.[$n / 2 - 1] + .[$n / 2]) / 2 end;
    def nice: . as $m | ($m | log10 | floor) as $e | pow(10; $e) as $mag
      | (($m / $mag * 2 | ceil) / 2) * $mag;
    ["podgate", "caddy", "traefik", "direct"] as $all
    | . as $runs
    | (0.8 / ($prox | length)) as $w
    | [range(0; $scen | length) as $g
        | $scen[$g] as $sc
        | [$prox[] as $p
            | ($runs | map(select(.scenario == $sc and .proxy == $p and .[$metric] != null) | .[$metric])) as $v
            | select($v | length > 0)
            | {s: (($all | index($p)) + 1), med: ($v | med), lo: ($v | min), hi: ($v | max)}] as $present
        | ($present | length) as $m
        | $present | to_entries[]
        | [$g + 1 + (.key - ($m - 1) / 2) * $w, .value.med, .value.lo, .value.hi, .value.s]] as $dat
    | {dat: $dat,
       xt: [range(0; $scen | length) as $g | "\"\($scen[$g])\" \($g + 1)"] | join(", "),
       ymax: (([$dat[][3]] | max) * 1.16 | nice)}' "$results/runs.jsonl" >"$tmp/$name.json"
  jq -r '.dat[] | @tsv' "$tmp/$name.json" >"$tmp/$name.dat"
  jq -r '"set xtics (" + .xt + ")"' "$tmp/$name.json" >"$tmp/$name.xt"
  jq -r '.ymax' "$tmp/$name.json" >"$tmp/$name.ymax"
}

# One bars-and-whiskers panel, called from the chart scripts below.
cat >"$tmp/panel.gp" <<'GP'
# ARG1 name, 2 ylabel, 3 label format, 4 label scale, 5 groups, 6 title, 7 series, 8 key (0/1), 9 y tick format
dat = tmp . "/" . ARG1 . ".dat"
load tmp . "/" . ARG1 . ".xt"
ns = int(ARG7)
set title ARG6 offset 0,0.4
set ylabel ARG2
set yrange [0:real(system("cat " . tmp . "/" . ARG1 . ".ymax"))]
set xrange [0.4:real(ARG5) + 0.6]
set format y ARG9
if (ARG8 eq "1") { set key } else { unset key }
set style fill solid 0.65 noborder
set boxwidth 0.8 / ns * 0.9
plot for [s=1:ns] dat using (($5 == s) ? $1 : NaN):2 with boxes lc rgb word(colors, s) title word(names, s), \
     for [s=1:ns] dat using (($5 == s) ? $1 : NaN):2:3:4 with yerrorbars lc rgb word(colors, s) lw 2 pt 0 notitle, \
     for [s=1:ns] dat using (($5 == s) ? $1 : NaN):4:(sprintf(ARG3, $2 * real(ARG4))) with labels rotate by 90 left offset 0,0.4 textcolor rgb grey font ",9" notitle
GP

# Shared terminal and style. No background fill, mid-grey text and axes, fixed font family.
cat >"$tmp/style.gp" <<'GP'
grey = "#808080"
colors = "#ff7a1a #2fb36d #3d8bff #a78bfa"
names = "podgate Caddy Traefik direct"
set border 3 lc rgb grey
set xtics nomirror textcolor rgb grey
set ytics nomirror textcolor rgb grey
set tics scale 0.6
set ylabel textcolor rgb grey
set xlabel textcolor rgb grey
set title textcolor rgb grey font ",12"
set key textcolor rgb grey
set grid ytics lc rgb "#80808080" lw 0.5
GP

term() { # term <width> <height> <file>
  printf 'set terminal svg size %s,%s enhanced font "sans-serif,12"\nset output "%s"\n' "$1" "$2" "$3"
}

all_scen='["h1-c64","h1-c256","h1-16k","rate","tls-h1","tls-h2"]'
all_prox='["podgate","caddy","traefik","direct"]'
three_prox='["podgate","caddy","traefik"]'

agg rps rps "$all_scen" "$all_prox"
agg p99 p99_ms "$all_scen" "$all_prox"
agg p999 p999_ms '["rate"]' "$all_prox"
agg cpu cpu_s_per_100k "$all_scen" "$three_prox"
agg peak peak_rss_mb "$all_scen" "$three_prox"
agg idle idle_rss_mb '["idle"]' "$three_prox"

key_top='set key at screen 0.5, 0.975 center top horizontal'

{
  term 960 460 "$out/throughput.svg"
  cat <<GP
tmp = "$tmp"
load tmp . "/style.gp"
set lmargin at screen 0.09
set rmargin at screen 0.98
set tmargin at screen 0.84
set bmargin at screen 0.10
$key_top
call tmp . "/panel.gp" "rps" "requests per second" "%.0fk" "0.001" 6 "Throughput, median and min to max of the runs" 4 1 "%.0s%c"
GP
} >"$tmp/throughput.gp"

{
  term 960 460 "$out/latency.svg"
  cat <<GP
tmp = "$tmp"
load tmp . "/style.gp"
set tmargin at screen 0.84
set bmargin at screen 0.10
$key_top
set lmargin at screen 0.07
set rmargin at screen 0.76
set multiplot
call tmp . "/panel.gp" "p99" "p99 latency, ms" "%.2f" "1" 6 "p99 latency, median and min to max of the runs" 4 1 "%g"
set lmargin at screen 0.84
set rmargin at screen 0.98
call tmp . "/panel.gp" "p999" "p99.9 latency, ms" "%.1f" "1" 1 "rate: p99.9" 4 0 "%g"
unset multiplot
GP
} >"$tmp/latency.gp"

{
  term 960 460 "$out/cpu.svg"
  cat <<GP
tmp = "$tmp"
load tmp . "/style.gp"
set lmargin at screen 0.09
set rmargin at screen 0.98
set tmargin at screen 0.84
set bmargin at screen 0.10
$key_top
call tmp . "/panel.gp" "cpu" "proxy CPU seconds per 100k requests" "%.2f" "1" 6 "CPU cost per request, median and min to max of the runs" 3 1 "%g"
GP
} >"$tmp/cpu.gp"

{
  term 960 460 "$out/memory.svg"
  cat <<GP
tmp = "$tmp"
load tmp . "/style.gp"
set tmargin at screen 0.84
set bmargin at screen 0.10
$key_top
set lmargin at screen 0.09
set rmargin at screen 0.27
set multiplot
call tmp . "/panel.gp" "idle" "resident memory, MiB" "%.0f" "1" 1 "Idle RSS (one start)" 3 0 "%g"
set lmargin at screen 0.36
set rmargin at screen 0.98
call tmp . "/panel.gp" "peak" "peak RSS, MiB" "%.0f" "1" 6 "Peak RSS under load, median and min to max of the runs" 3 1 "%g"
unset multiplot
GP
} >"$tmp/memory.gp"

charts=(throughput latency cpu memory)

# Attribution: one point per process start (dir), x and y the median of its runs. Starts
# without per-thread switch counters (per_1k_req is null) are left out.
if [[ -n $attribution ]]; then
  jq -s '
    def med: sort | length as $n
      | if $n % 2 == 1 then .[($n - 1) / 2] else (.[$n / 2 - 1] + .[$n / 2]) / 2 end;
    def nice($step): . as $m | (($m / $step | ceil) * $step);
    . as $runs
    | ([$runs[] | select(.per_1k_req != null) | .variant] | reduce .[] as $v ([]; if any(.[]; . == $v) then . else . + [$v] end)) as $variants
    | [$runs | group_by(.dir)[]
        | select(all(.[]; .per_1k_req != null))
        | {variant: .[0].variant,
           x: (map(.per_1k_req.voluntary_switches) | med),
           y: (map(.rps) | med)}] as $starts
    | {starts: $starts,
       dat: [$starts[] | . as $s | [.x, .y, ($variants | index($s.variant)) + 1]],
       titles: [$variants | to_entries[]
                 | . as $e | ($starts | map(select(.variant == $e.value)) | length) as $n
                 | select($n > 0)
                 | {k: ($e.key + 1), t: "\($e.value) (\($n) starts)"}],
       total: ($runs | map(.dir) | unique | length),
       xmax: (([$starts[].x] | max) * 1.05 | nice(250)),
       ymax: (([$starts[].y] | max) * 1.05 | nice(50000))}' "$attribution" >"$tmp/attr.json"
  jq -r '.dat[] | @tsv' "$tmp/attr.json" >"$tmp/attr.dat"
  jq -r '.titles[] | "T[\(.k)] = \"\(.t)\""' "$tmp/attr.json" >"$tmp/attr.titles.gp"
  jq -r '"xmax = \(.xmax)\nymax = \(.ymax)\nnk = \(.titles | map(.k) | max)"' "$tmp/attr.json" >"$tmp/attr.limits.gp"
  nk=$(jq -r '.titles | map(.k) | max' "$tmp/attr.json")
  h=$((420 + 24 * nk))
  {
    term 960 "$h" "$out/attribution.svg"
    cat <<GP
tmp = "$tmp"
load tmp . "/style.gp"
load tmp . "/attr.limits.gp"
array T[nk]
load tmp . "/attr.titles.gp"
vcolors = "#e5484d #e6b800 #1fb6d4 #d6409f #8fbf3f #ff9f1c"
set lmargin at screen 0.09
set rmargin at screen 0.98
set tmargin at screen 0.90
set bmargin at screen $(awk -v n="$nk" -v h="$h" 'BEGIN { printf "%.3f", (24 * n + 70) / h }')
set title "Throughput against thread parking, one point per process start" offset 0,0.4
set xlabel "voluntary context switches per 1000 requests"
set ylabel "requests per second"
set xrange [0:xmax]
set yrange [0:ymax]
set format y "%.0s%c"
set key at screen 0.09, $(awk -v n="$nk" -v h="$h" 'BEGIN { printf "%.3f", (24 * n + 15) / h }') left top vertical Left reverse spacing 1.3 textcolor rgb grey
set grid xtics ytics lc rgb "#80808080" lw 0.5
plot for [k=1:nk] tmp . "/attr.dat" using (\$3 == k ? \$1 : NaN):2 with points pt (4 + 2 * (k % 5) + 1) ps 1.1 lc rgb word(vcolors, k) title T[k] noenhanced
GP
  } >"$tmp/attribution.gp"
  charts+=(attribution)
fi

for c in "${charts[@]}"; do
  gnuplot "$tmp/$c.gp"
done

# An SVG in the dest dir that no chart produces any more is stale: check names it, a redraw removes it.
orphans=()
for f in "$dest"/*.svg; do
  [[ -e $f ]] || continue
  name=$(basename "$f" .svg)
  [[ " ${charts[*]} " == *" $name "* ]] || orphans+=("$f")
done

if ((check)); then
  stale=("${orphans[@]/%/ (no longer generated)}")
  for c in "${charts[@]}"; do
    cmp -s "$out/$c.svg" "$dest/$c.svg" || stale+=("$dest/$c.svg")
  done
  if ((${#stale[@]})); then
    printf 'bench-charts.sh: stale chart, run scripts/bench-charts.sh (results: %s): %s\n' "$results" "${stale[@]}" >&2
    exit 1
  fi
  echo "bench-charts.sh: ${#charts[@]} charts up to date ($results)"
elif ((${#orphans[@]})); then
  rm -f -- "${orphans[@]}"
fi
