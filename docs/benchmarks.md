# Benchmarks: podgate, Caddy and Traefik

How podgate compares with Caddy and Traefik as a Host-routing reverse proxy on one machine: throughput, latency at a fixed rate, errors, CPU and memory, over plain HTTP and TLS. One script, `scripts/bench-proxies.sh`, runs everything. Method and tuning are below the results, so every number can be rerun.

This is a loopback measurement on one shared machine with the proxies as they ship (podgate with its admission controls on). It compares configurations, not only code. Read the caveats before quoting a number.

Measured four times. The first measurement (2026-11-20, podgate at commit `a22f5d2` plus the benchmark files of change 0020) is kept in [`bench/results/2026-11-20/`](../bench/results/2026-11-20/runs.jsonl). The second (2026-11-22, commit `9c075cc`) is in `bench/results/2026-11-22/` and the third (commit `074ad49`) in `bench/results/2026-11-22-0115/`. This page holds the fourth, 2026-11-22 on commit `5103970`: the request path since the first measurement gained forwarding headers and some 490 other commits (v2 routing model, upstream address policy, per-entry-point metrics, many middlewares, an HTTP/3 front), and the HTTP and HTTPS entry points now share one pool of worker threads. Several verdicts changed; the changes are in the tables and explained in "What changed since 2026-11-20".

## Verdicts

Each verdict is the median of 5 interleaved runs of 15 s, on one process start per proxy. A verdict says "faster" only when the run ranges do not overlap. The last two columns give the first measurement for comparison. The `h1-*` rows against Traefik have one more check: until change 0116 podgate's throughput moved by +-15% between fresh process starts (see "Where the 250 k went"), which the 5 runs of one start do not capture. `h1-c64` therefore also rests on 6 further fresh starts of this build with the same configuration (190.0 k, 198.5 k, 196.5 k, 197.9 k, 197.8 k, 196.9 k; the spread between starts is now 4%, against 140 k to 194 k before); `h1-c256` and `h1-16k` rest on one start each. Traefik's and Caddy's spread between starts was not measured.

|Scenario|podgate vs Caddy|podgate vs Traefik|Limiter|Before: vs Caddy|Before: vs Traefik|
|---|---|---|---|---|---|
|`h1-c64`: HTTP/1.1, 64 connections, 100 B body, max rate|faster (1.56x)|faster (1.06x): 195.8 k against 185.2 k, ranges apart (194.4 k to 197.3 k against 182.6 k to 186.7 k); the 6 further fresh starts (190.0 k to 198.5 k) are all above Traefik's highest run|proxy CPUs|2.1x|1.4x|
|`h1-c256`: as above, 256 connections|faster (1.51x)|faster (1.05x): ranges apart (193.4 k to 194.7 k against 178.0 k to 185.0 k); one start, and the spread between starts is 4% at `h1-c64`, below the gap|proxy CPUs|2.0x|1.5x|
|`h1-16k`: as `h1-c64`, 16 KiB body|faster (1.61x)|**inconclusive**: 1.02x, ranges overlap (163.6 k to 164.8 k against 158.3 k to 164.2 k)|proxy CPUs|1.9x|1.25x|
|`rate`: 62000 req/s fixed, 64 connections|same throughput (all three sustain it); p50 lower by 31%; p99 lower; p99.9 lower (2.67 ms against 7.26)|same throughput; **p50 higher (0.31 ms against 0.29)**; p99 lower (1.06 ms against 1.68); p99.9 no measurable difference (ranges overlap)|offered rate|p50 and p99 lower|p50 and p99 lower|
|`tls-h1`: TLS 1.3, HTTP/1.1, 64 connections|faster (1.54x)|faster (1.07x)|proxy CPUs|2.3x|1.4x|
|`tls-h2`: TLS 1.3, HTTP/2, 16 connections x 4 streams|faster (2.41x)|faster (1.74x)|proxy CPUs|3.4x|2.2x|
|CPU seconds per 100k requests|lower (1.7 to 2.0 against 2.7 to 4.2)|lower in every scenario (1.7 to 2.0 against 1.9 to 3.1; 3% to 8% in plain HTTP, 8% and 44% in TLS)|not applicable|lower|lower|
|Peak and idle memory|idle lower (16 MiB against 48 and 89); peak lower (32 to 66 MiB against 66 to 94)|lower (32 to 66 MiB against 119 to 176)|not applicable|lower|lower|

Podgate is now ahead of Traefik on `h1-c64` and `h1-c256` and level on `h1-16k`. The earlier fall at `h1-c64` (250 k to 160 k) had four parts, attributed in "Where the 250 k went" and "One pool for the HTTP entry points": forwarding headers (about 20 to 25%), the adaptive limiter (4 to 8%), a "slow regime" of thread parking that most fresh starts fell into (about 14%), and a 7% creep in cost per request. Change 0116 removed the slow regime: the second, idle pool of worker threads of the `websecure` entry point caused it, and the HTTP and HTTPS entry points now share one pool. What remains of the gap to the first build (250 k to 196 k) is the forwarding headers, the limiter and the creep. A podgate built from the first measurement's commit, run on the same rig beside the same Traefik, was 1.35x faster (250 k against 186 k req/s) in the `9c075cc` pass; today's podgate with forwarding headers on is 1.06x faster.

No scenario produced a non-2xx response or an error for any proxy (110 recorded runs, 0 non-2xx, 0 errors, backend request count equal to `oha`'s count within 1 request; the 98 runs of the attribution passes of change 0115 and the 34 runs of the change 0116 passes were checked the same way for non-2xx and errors by the script's `FAILED RUN` rule, none failed).

What this does not say: that podgate is faster or slower for your traffic. Caddy and Traefik do more per request by default (see Caveats), and the backend answers in microseconds, so these numbers measure proxy overhead only.

## Results

Median (min-max) of 5 runs per proxy and scenario, 15 s each, steady state, one process start per proxy, run 2026-11-22 on the tree of commit `5103970` (the script printed its parent, `62eae6d`, as the commit, since the tree was built before it was committed). `direct` is `oha` straight at the backend with the same settings, the ceiling of the rig. Latencies are from `oha`'s own histogram (the `rate` scenario uses `--latency-correction`). Raw per-run data: [`bench/results/2026-11-22-0116/runs.jsonl`](../bench/results/2026-11-22-0116/runs.jsonl). The earlier runs are in `bench/results/2026-11-22-0115/` and `bench/results/2026-11-22/`.

### Throughput and latency

![Bars of requests per second by scenario for podgate, Caddy, Traefik and the backend alone ("direct"), each bar a median with a min to max whisker over its runs. podgate is ahead of Traefik and Caddy in h1-c64, h1-c256 and both TLS scenarios: 196k against 185k and 125k at h1-c64, and 195k against 112k and 81k at tls-h2. At h1-16k its median is ahead of Traefik's (164k against 161k) but the run ranges overlap, so that row is not a verdict; in the fixed-rate scenario all three hold the 62k target. The backend alone reaches 334k to 458k.](benchmarks/throughput.svg)

![Bars of p99 latency in ms by scenario, with a median and a min to max whisker per proxy, and a small panel with the p99.9 of the rate scenario. podgate has the lowest median p99 of the three proxies in every scenario (0.47 to 1.56 ms, against 1.44 to 4.32 for Traefik and 1.92 to 5.49 for Caddy). In the p99.9 panel podgate (2.7 ms, range 2.4 to 5.0) and Traefik (3.6 ms, range 3.4 to 3.7) overlap; Caddy is higher at 7.3 ms.](benchmarks/latency.svg)

|Scenario|Proxy|req/s|p50 ms|p99 ms|p99.9 ms|
|---|---|---|---|---|---|
|h1-c64|podgate|195795 (194418-197271)|0.32 (0.32-0.33)|0.47 (0.47-0.51)|1.07 (0.91-1.39)|
|h1-c64|caddy|125241 (121549-125929)|0.37 (0.37-0.38)|1.92 (1.9-2.13)|4.14 (3.68-4.72)|
|h1-c64|traefik|185207 (182591-186709)|0.29 (0.29-0.29)|1.44 (1.41-1.47)|2.5 (2.25-2.91)|
|h1-c64|direct|416792 (379780-475663)|0.11 (0.11-0.11)|0.21 (0.18-4.11)|4.16 (4.12-4.18)|
|h1-c256|podgate|194442 (193366-194693)|1.31 (1.3-1.31)|1.56 (1.53-1.58)|2.63 (2.6-3.64)|
|h1-c256|caddy|128783 (128135-129977)|1.73 (1.72-1.74)|5.49 (5.31-5.56)|8.17 (7.92-8.47)|
|h1-c256|traefik|184309 (177966-185026)|1.25 (1.25-1.27)|4.32 (4.21-5.02)|6.47 (6.33-7.4)|
|h1-c256|direct|457547 (446480-497620)|0.48 (0.48-0.48)|4.48 (0.75-4.57)|5.62 (5.37-6.31)|
|h1-16k|podgate|163926 (163630-164834)|0.39 (0.39-0.39)|0.57 (0.55-0.58)|1.26 (1.16-1.33)|
|h1-16k|caddy|101915 (101846-105814)|0.48 (0.47-0.48)|2.33 (2.3-2.35)|4.33 (3.98-4.43)|
|h1-16k|traefik|160668 (158256-164217)|0.34 (0.34-0.34)|1.55 (1.37-1.6)|2.72 (2.63-3.01)|
|h1-16k|direct|334270 (309430-366248)|0.13 (0.13-0.13)|3.19 (0.29-4.1)|4.75 (4.19-5.13)|
|rate|podgate|61988 (61987-61992)|0.31 (0.31-0.31)|1.06 (1.01-1.31)|2.67 (2.42-4.97)|
|rate|caddy|61992 (61991-61995)|0.45 (0.44-0.45)|2.45 (2.22-3.96)|7.26 (6.22-19.35)|
|rate|traefik|61992 (61991-61994)|0.29 (0.29-0.29)|1.68 (1.67-1.82)|3.55 (3.4-3.75)|
|rate|direct|61991 (61988-61992)|0.15 (0.15-0.15)|0.34 (0.33-0.35)|1.59 (1.35-1.75)|
|tls-h1|podgate|190641 (189191-191310)|0.33 (0.33-0.33)|0.49 (0.48-0.49)|1.11 (1.09-1.17)|
|tls-h1|caddy|123572 (122919-125188)|0.38 (0.38-0.38)|2.01 (2.01-2.04)|4.34 (3.84-4.52)|
|tls-h1|traefik|178560 (177755-178917)|0.3 (0.3-0.3)|1.48 (1.47-1.5)|3.1 (2.85-3.16)|
|tls-h2|podgate|194752 (194502-195670)|0.33 (0.33-0.33)|0.49 (0.49-0.5)|1.04 (1.03-1.07)|
|tls-h2|caddy|80886 (80863-81290)|0.64 (0.64-0.65)|2.97 (2.94-2.99)|5.34 (5.2-5.43)|
|tls-h2|traefik|111922 (111418-112281)|0.51 (0.51-0.51)|1.86 (1.85-1.91)|4.25 (3.91-4.43)|

In `h1-c64` podgate's p50 (0.32 ms) is below Caddy's (0.37) and above Traefik's (0.29), while its p99 and p99.9 stay the lowest of the three: podgate's tail is tight, its median is not the best.

The rate of the `rate` scenario is 62000 req/s: half the slowest proxy's `h1-c64` median (Caddy), rounded down to 1000. It was 58000 in the 0115 run, 62000 in the `9c075cc` run and 56000 in the first measurement because Caddy's number differed.

### CPU and memory

![Bars of proxy CPU seconds per 100k requests by scenario, with a median and a min to max whisker per proxy. podgate costs 1.71 to 2.01 s, Traefik 1.85 to 3.10 s and Caddy 2.70 to 4.22 s. podgate's median is below Traefik's in every scenario, by the most in tls-h2 (1.75 against 3.10 s).](benchmarks/cpu.svg)

![Left, idle resident memory of one start per proxy: podgate 16 MiB, Caddy 48 MiB, Traefik 89 MiB. Right, peak resident memory per scenario with a median and a min to max whisker: Traefik is the highest in every scenario (119 to 176 MiB), and podgate is below Caddy in every scenario (32 to 66 MiB against 66 to 94).](benchmarks/memory.svg)

CPU is cores of the proxy process (`utime + stime` of the whole process over the steady-state window, so 4.0 is all four pinned CPUs). "CPU s/100k" is that CPU time divided by the requests served in the window. Peak RSS is `VmHWM` after resetting it once warm-up ended. "Other cores max" is the largest foreign load on the proxy CPUs in any of the 5 runs (a negative value is the accounting difference between the per-process and per-CPU counters, about 0.1 core, not load), and "disturbed" counts runs with more than 0.3 foreign cores.

|Scenario|Proxy|Proxy cores|oha cores (of 2)|Backend cores (of 2)|CPU s/100k req|Peak RSS MiB|Other cores max|Disturbed runs|
|---|---|---|---|---|---|---|---|---|
|h1-c64|podgate|3.37 (3.35-3.37)|0.79 (0.79-0.8)|0.48 (0.48-0.48)|1.71 (1.71-1.73)|32 (31-32)|-0.04|0|
|h1-c64|caddy|3.4 (3.3-3.43)|0.52 (0.5-0.53)|0.32 (0.3-0.32)|2.72 (2.71-2.73)|69 (68-70)|0.13|0|
|h1-c64|traefik|3.44 (3.39-3.45)|0.74 (0.73-0.75)|0.47 (0.46-0.47)|1.85 (1.85-1.86)|120 (119-121)|0.05|0|
|h1-c64|direct|0 (0-0)|1.16 (1.07-1.34)|0.78 (0.72-0.87)|-|-|0.09|0|
|h1-c256|podgate|3.36 (3.35-3.37)|0.8 (0.79-0.8)|0.47 (0.47-0.47)|1.73 (1.72-1.74)|66 (58-70)|-0.06|0|
|h1-c256|caddy|3.48 (3.47-3.5)|0.55 (0.55-0.56)|0.33 (0.33-0.33)|2.7 (2.69-2.71)|94 (92-97)|0|0|
|h1-c256|traefik|3.44 (3.32-3.46)|0.77 (0.74-0.77)|0.47 (0.45-0.48)|1.87 (1.87-1.88)|176 (176-180)|0.09|0|
|h1-c256|direct|0 (0-0)|1.36 (1.34-1.48)|0.85 (0.82-0.96)|-|-|0.1|0|
|h1-16k|podgate|3.3 (3.28-3.3)|0.9 (0.9-0.91)|0.48 (0.48-0.48)|2.01 (2-2.01)|63 (63-64)|-0.04|0|
|h1-16k|caddy|3.17 (3.16-3.19)|0.76 (0.76-0.79)|0.31 (0.31-0.32)|3.1 (3.01-3.11)|71 (69-76)|0.03|0|
|h1-16k|traefik|3.34 (3.31-3.36)|0.89 (0.88-0.92)|0.49 (0.48-0.5)|2.08 (2.03-2.09)|125 (124-160)|0.01|0|
|h1-16k|direct|0 (0-0)|1.13 (0.95-1.17)|0.82 (0.72-0.84)|-|-|0.1|0|
|rate|podgate|1.16 (1.15-1.16)|0.28 (0.28-0.28)|0.16 (0.16-0.16)|1.87 (1.86-1.88)|34 (33-35)|0.03|0|
|rate|caddy|1.75 (1.75-1.75)|0.27 (0.27-0.28)|0.16 (0.16-0.16)|2.83 (2.82-2.83)|66 (65-67)|0.25|0|
|rate|traefik|1.19 (1.19-1.2)|0.27 (0.27-0.27)|0.16 (0.15-0.16)|1.93 (1.93-1.94)|119 (119-119)|0.32|2|
|rate|direct|0 (0-0)|0.26 (0.26-0.26)|0.14 (0.14-0.15)|-|-|0.13|0|
|tls-h1|podgate|3.37 (3.37-3.39)|0.87 (0.86-0.87)|0.47 (0.46-0.47)|1.77 (1.77-1.78)|63 (63-63)|-0.06|0|
|tls-h1|caddy|3.43 (3.41-3.44)|0.56 (0.55-0.56)|0.31 (0.31-0.32)|2.78 (2.74-2.78)|72 (72-76)|0.01|0|
|tls-h1|traefik|3.44 (3.43-3.45)|0.78 (0.78-0.79)|0.45 (0.45-0.45)|1.93 (1.93-1.93)|129 (128-130)|0.01|0|
|tls-h2|podgate|3.42 (3.41-3.42)|0.86 (0.85-0.86)|0.48 (0.48-0.48)|1.75 (1.75-1.76)|63 (62-63)|-0.06|0|
|tls-h2|caddy|3.42 (3.41-3.43)|0.59 (0.59-0.6)|0.21 (0.21-0.21)|4.22 (4.21-4.24)|71 (70-72)|-0|0|
|tls-h2|traefik|3.47 (3.46-3.49)|0.81 (0.8-0.81)|0.29 (0.29-0.29)|3.1 (3.1-3.1)|127 (126-129)|-0|0|

Idle RSS before the first request: podgate 16.3 MiB, Caddy 47.5 MiB, Traefik 88.6 MiB. podgate's peak RSS under load is 31 to 70 MiB.

## What changed since 2026-11-20

Why podgate went from 232 k to 160 k req/s at `h1-c64` while Caddy and Traefik went the other way (113 k to 118 k, 163 k to 176 k). [INFERENCE] The first measurement's Go proxies had foreign load on their CPUs in some runs (its Noise section lists them); the later runs' machine had none on the proxy CPUs.

Change 0116 later took podgate back to 196 k at `h1-c64` with the same forwarding headers, and it is now ahead of Traefik (185 k) in that scenario; see "One pool for the HTTP entry points".

### Where the 250 k went

![Scatter of requests per second against voluntary context switches per 1000 requests, one point per process start. These are change 0115's starts, before change 0116 put the entry points on one worker pool; since then every start of the shipped build is fast (see "One pool for the HTTP entry points"). 34 of the 99 starts in the attribution passes have per-thread switch counters and are plotted; the other 65 have none and are left out. Nine starts make 160 to 248 switches per 1000 requests and run at 222k to 252k req/s, among them all six starts of the first measurement's build (206 to 248 switches, 227k to 252k req/s). The other 25 starts, all of the 074ad49 variants, make 361 to 1738 switches and run at 140k to 217k req/s.](benchmarks/attribution.svg)

`h1-c64`, forwarding headers off for the app, one fresh process start per measurement. Data: [`attribution.jsonl`](../bench/results/2026-11-22-0115/attribution.jsonl).

|podgate build|Starts|req/s, median of starts (range)|CPU s/100k req|
|---|---|---|---|
|`4b3834a`, the first measurement's code|5 (2 runs of 15 s each)|249.7 k (243.0 k to 253.2 k)|1.28 to 1.33|
|`074ad49` as it ships|5 (2 runs of 15 s each)|204.8 k (197.2 k to 206.6 k)|1.60 to 1.68|
|`074ad49`, limiter short-circuited|5 (2 runs of 15 s each)|212.5 k (209.1 k to 246.2 k); 4 starts at 209 k to 214 k (1.54 to 1.57), 1 at 246 k (1.32 to 1.34)|1.32 to 1.57|

The first-parent commits between them (496) were bisected with the limiter short-circuited, 3 starts of 15 s each:

|Commit (position from `4b3834a`)|Median of starts (range)|CPU s/100k req|
|---|---|---|
|`ef8adf7` model v2 (4)|250.5 k (221.6 k to 260.5 k)|1.24 to 1.36|
|`00e4732` (62)|261.0 k (256.2 k to 262.4 k)|1.24 to 1.26|
|`6f665e3` (124)|258.0 k (253.9 k to 260.9 k)|1.25 to 1.27|
|`5f598a2` (186)|250.0 k (244.4 k to 250.6 k)|1.30 to 1.33|
|`20bde33` (217)|240.5 k (239.7 k to 240.8 k)|1.35|
|`4054689` (232)|239.6 k (205.8 k to 244.6 k)|1.34 to 1.59|
|`75b7a69` (241)|246.5 k (213.8 k to 247.7 k)|1.31 to 1.54|
|`9eb9ae8` (248)|214.5 k (203.4 k to 250.0 k)|1.31 to 1.61|
|`074ad49` (496, from the table above)|212.5 k (209.1 k to 246.2 k)|1.32 to 1.57|

What this shows:

- **No single commit is the culprit.** Two things move. The cost per request in the fast regime creeps from 1.24 (positions 4 to 124) to 1.31 (186) and 1.35 (217) CPU s/100k and stays near 1.33 to the tip: about +7% over many commits, and the fast regime at the tip (242 k to 249 k, 1.31 to 1.34) is within 3% of `4b3834a` (1.28 to 1.33 CPU s/100k). On top of that comes a slow regime of 1.5 to 1.7 CPU s/100k. No start of 15 below position 232 was in it; at 232 it is 1 of 3, at 241 1 of 3, at 248 2 of 3 and at the tip 4 of 5. The code changes between 217 and 232 that touch the HTTP request path are small (a cookie call moved later in `response_filter`; the TCP routers and services in that range are not on it), so the slow regime is not a per-request code cost added there. [INFERENCE] Any change to the binary can shift which regime a start falls in.
- **The slow regime is thread parking.** Per-thread counters (`/proc/<pid>/task/*`) over 28 starts of tip-build variants (limiter on or short-circuited, forwarding on or off, work stealing off; 6 s each): the four busy `entry point web` threads each use 0.8 cores in both regimes, so the load is balanced, but a fast start makes 160 to 220 voluntary context switches per 1000 requests and a slow start 400 to 1750. A least-squares line over the 28 starts gives 1.285 CPU s/100k at zero switches and 6.5 us per switch (r = 0.91), so the intercept is the old build's whole cost (1.28 to 1.33). The old build makes 206 to 248 switches per 1000 requests in all 6 starts (1.26 to 1.33 CPU s/100k, 227 k to 252 k req/s). Traefik makes 7 to 26 per 1000 requests and Caddy 32 to 76 in the full run above; podgate as shipped 409 to 1257. [INFERENCE] Go's scheduler spins before it sleeps and tokio's workers sleep at once, which is the most likely reason the Go proxies are close even though podgate spends less per request in TLS.
- **Ruled out as the cause of the slow regime** (tip build, limiter short-circuited, 6 to 8 s per start): address space randomisation off (`setarch -R`, 6 starts: 1 fast start at 248 k, 5 at 210 k to 217 k), a single malloc arena (`MALLOC_ARENA_MAX=1`: 124 k to 130 k in all 6, far worse, so the proxy allocates a lot but the arenas are not what separates the regimes), jemalloc 5.4.0 preloaded (6 starts: 243 k and 242 k fast, 159 k to 207 k otherwise), Pingora's work stealing off (7 starts: 1 fast at 249 k, 185 k to 217 k otherwise). Then found, in change 0116: the second pool of 4 idle threads of the `websecure` entry point (the tip had 8 `entry point web` threads against 4 in the old build); see "One pool for the HTTP entry points". Not tried: anything that makes tokio spin before parking.
- **The limiter costs about 4 to 8%.** Short-circuited, the median start moves from 204.8 k to 212.5 k req/s with forwarding off (5 starts each), and from 161 k to 174 k with forwarding on (5 starts each of 6 s: 154 k, 161 k, 140 k, 163 k, 194 k against 164 k, 170 k, 204 k, 174 k, 174 k). With it on, none of the 5 starts of set A reached the fast regime; short-circuited, 1 of 5 did. That is a small sample. The limiter alone does not explain most of the gap, so no switch was built.
- **Forwarding headers cost about 20 to 25%**, as in the 9c075cc run: with the limiter on, the median start moves from 204.8 k (off) to 161 k (on). Before, the backend received about 70 B per request from podgate; now it receives 196 B (five more headers: `X-Forwarded-For`, `-Proto`, `-Host`, `-Port`, `X-Real-IP`). Caddy adds 165 B and Traefik 242 B, so the first measurement compared podgate doing less work; this one compares like with like.
- **The sum.** As shipped, a typical start is 161 k against 250 k: about -20% for forwarding, -4 to -8% for the limiter, -14% for the slow regime (212 k against 245 k), and the rest is the +7% creep. TLS shows no such loss because the same process does 184 k and 188 k there (1.8 CPU s/100k) against 160 k in plain `h1-c64` (2.1): the TLS verdicts stayed "faster" while the plain ones fell. [INFERENCE] Parking depends on how requests overlap in the closed loop between `oha`, podgate and the backend, and TLS changes that timing; this was not measured.

### One pool for the HTTP entry points

Hypothesis from 0115: the idle `websecure` pool, 4 more threads on the same 4 CPUs, is what puts most fresh starts into the slow regime. Measured with no code change, `h1-c64`, forwarding off, release build of commit `c80afcb` (the benchmark script gained `PODGATE_NO_TLS=1`, which starts podgate with the `web` entry point alone), 7 fresh process starts of 10 s per variant, interleaved (A1 B1 A2 B2 ...), loadavg 1.3 to 2.3, 0.23 to 0.42 foreign cores before each start (one A start 1.91). Fast and slow by 0115's switch counts: fast is 160 to 250 voluntary context switches per 1000 requests, slow 400 and up. Data: [`pool-ab.jsonl`](../bench/results/2026-11-22-0116/pool-ab.jsonl).

|Variant|Threads at idle|req/s, median of 7 starts (range)|CPU s/100k req|Voluntary switches per 1000 req (range)|Fast / slow starts|
|---|---|---|---|---|---|
|A: `web` + `websecure`, a pool each|21|203.9 k (193.7 k to 232.2 k)|1.63 (1.43 to 1.64)|534 (218 to 573)|2 / 5|
|B: `web` alone|17|232.8 k (220.2 k to 233.5 k)|1.42 (1.42 to 1.48)|232 (215 to 241)|7 / 0|

Per thread, a fast start (every B start, 2 A starts) has the same 52 to 62 switches per 1000 requests on each of the 4 busy threads; in the 5 slow A starts two threads make 159 to 188 and two 96 to 107. The 5 slow A starts (193.7 k to 204.7 k) are all below B's slowest start (220.2 k); A's 2 fast starts equal B's. A's range overlaps B's only through those 2 starts; the chance of 5 slow starts of 7 against 0 of 7 if the variants were the same is 1% (one-sided Fisher exact test). So the idle pool is the cause of the slow regime in this rig, and it costs 12% of the median start.

The fix is a vendored Pingora change, not a merged service: `Service::runtime_group` (`vendor/pingora-core`, `docs/ref/pingora-patches.md` section 5) makes the services of one group run on one runtime, and every HTTP and HTTPS entry point service joins the group `entry points`. Each keeps its own `Policed` app, `Gateway`, listeners, name, policy, PROXY protocol gate and `Alt-Svc`; no request or connection looks anything up. The one-service alternative needs the app to find the entry point from the accepted socket's local address (ambiguous for wildcard binds), and `HttpServerApp::h2_options` and `server_options`, which carry the per-entry-point HTTP/2 policy, do not receive the connection. TCP entry points joined the group in change 0118 (the next section); UDP entry points and the HTTP/3 front stay on runtimes of their own, and the benchmark does not use them, so nothing is measured or claimed for them.

After the change, the same measurement (release build of the same tree plus the runtime group, 7 interleaved starts per variant, loadavg 1.2 to 2.1, 0.26 to 0.68 foreign cores before each start). Data: [`pool-ab-after.jsonl`](../bench/results/2026-11-22-0116/pool-ab-after.jsonl).

|Variant|Threads at idle|req/s, median of 7 starts (range)|CPU s/100k req|Voluntary switches per 1000 req (range)|Fast / slow starts|
|---|---|---|---|---|---|
|A: `web` + `websecure`, one pool|17|233.9 k (232.6 k to 235.3 k)|1.415 (1.408 to 1.423)|230 (221 to 244)|7 / 0|
|B: `web` alone|17|234.2 k (232.1 k to 234.6 k)|1.418 (1.412 to 1.431)|228 (219 to 237)|7 / 0|

The two-listener podgate matches the single-listener one: the medians differ by 0.1%, the ranges overlap entirely, and the spread between starts fell from 19% of the median (A before) to 1%. The two-listener build gains 15% (203.9 k to 233.9 k). It stays 6% below the `4b3834a` median (249.7 k) at the same cost per request as the old fast regime plus the 7% creep (1.415 against 1.28 to 1.33 CPU s/100k), so the pool change recovers the slow regime and no more.

With forwarding headers on, as the verdicts run them, the full run's podgate does 195.8 k at `h1-c64` and 6 further fresh starts of 15 s do 190.0 k, 198.5 k, 196.5 k, 197.9 k, 197.8 k and 196.9 k (median of the 7 starts 196.9 k, range 190.0 k to 198.5 k; before the change 6 starts did 140 k to 194 k, median about 160 k). Data: [`pool-fwd-on.jsonl`](../bench/results/2026-11-22-0116/pool-fwd-on.jsonl). The 7 starts make 420 to 469 voluntary context switches per 1000 requests (in the 6 further starts 102 to 114 on each of the 4 threads), which is inside 0115's "slow" band of 400 and up, but the start-to-start spread is 4% and no start is bimodal, and the old build at forwarding off made 206 to 248. With forwarding on 0115 measured no fast start of the tip build, so there is no fast-regime figure to compare with; [INFERENCE] with the headers on the floor is about 430 switches per 1000 requests and the old slow state was a further step above it. This was not measured.

### One pool for the TCP entry points

Two questions, measured on release builds of the tree of change 0116 plus the benchmark script's `PODGATE_TCP=1` (a `tcp` entry point named `tcp` next to `web` and `websecure`; the snapshot reserves it to the tenant and routes every connection to the backend). `h1-c64`, forwarding off, 10 s runs after a 2 s warm-up, 7 fresh process starts per variant, interleaved (A0 A1 A2, A0 A1 A2, ...), the machine-wide build lock held for the whole series. "Own" is the shipped code before the change (the `tcp` entry point on a runtime of its own); "joined" is the same tree with `Service::runtime_group` set on the TCP service, as in the commit that followed. Fast and slow are 0115's bands on voluntary context switches per 1000 requests: fast 160 to 250, slow 400 and up. Data: [`tcp-pool-a.jsonl`](../bench/results/2026-11-22-0118/tcp-pool-a.jsonl), [`tcp-pool-b.jsonl`](../bench/results/2026-11-22-0118/tcp-pool-b.jsonl) and the console logs next to them.

**A. An idle `tcp` entry point, HTTP load through `web`.** The scenario is `h1-c64` against the `web` entry point; the `tcp` entry point receives nothing. Loadavg before each start 0.4 to 2.1, 0.23 to 0.42 foreign cores before each start, no foreign load on the proxy CPUs in any run (the per-CPU counters read 0.03 to 0.09 cores below the process's own, the accounting difference); 0 non-2xx and 0 errors in the 21 runs.

|Variant|Threads at idle|req/s, median of 7 starts (range)|CPU s/100k req|Voluntary switches per 1000 req (range)|Fast / slow starts|
|---|---|---|---|---|---|
|A0: `web` + `websecure`|17|233.5 k (232.0 k to 234.1 k)|1.414 (1.409 to 1.421)|230 (226 to 237)|7 / 0|
|A1: A0 + an idle `tcp`, own runtime|21|204.9 k (200.8 k to 208.1 k)|1.618 (1.595 to 1.650)|552 (485 to 610)|0 / 7|
|A2: A0 + an idle `tcp`, joined|17|232.9 k (231.0 k to 234.7 k)|1.424 (1.416 to 1.434)|215 (210 to 224)|7 / 0|

An idle `tcp` entry point on its own pool is the slow state of change 0115 again: every one of its 7 starts is below the slowest start of A0 (208.1 k against 232.0 k) and in the slow band, and it costs 12% of the median start and 14% more CPU per request. Joined, the ranges of A2 and A0 overlap (231.0 k to 234.7 k against 232.0 k to 234.1 k) and all 7 starts are fast: no measurable difference.

**B. TCP traffic, its own pool against the shared one.** The scenario `tcp-h1` is the same `oha` load (HTTP/1.1, 64 connections, 100 B body) through the `tcp` entry point to the backend; `web` and `websecure` stay idle. Loadavg before each start 1.5 to 1.9, 0.23 to 0.50 foreign cores before each start, 0.00 to 0.04 foreign cores on the proxy CPUs; 0 non-2xx and 0 errors in the 14 runs, the backend's request count within 0.5% of `oha`'s in each.

|Variant|Threads at idle|req/s, median of 7 starts (range)|CPU s/100k req|Voluntary switches per 1000 req (range)|Fast / slow starts|
|---|---|---|---|---|---|
|B1: `tcp` on its own runtime|21|468.9 k (461.8 k to 485.8 k)|0.478 (0.472 to 0.488)|469 (405 to 501)|not applicable|
|B2: `tcp` in the `entry points` group|17|480.1 k (463.8 k to 491.5 k)|0.476 (0.468 to 0.484)|454 (415 to 496)|not applicable|

The fast and slow bands come from the HTTP path and say nothing about the copy loop of a TCP connection: both variants sit at 405 to 501 switches per 1000 requests in every start, with no bimodal split. Sharing the pool loses nothing: the ranges overlap (the joined median is 2.4% higher, inside the spread between starts of 5% and 6%), the CPU per request is the same, and p50 and p99 are the same (0.125 ms and 0.358 ms in both). The limiter in B is not the proxy: podgate used 2.3 of its 4 CPUs (16% idle), `oha` 1.4 of its 2 and the backend 0.9 of its 2. [INFERENCE] With 64 connections in a closed loop through a proxy that copies bytes only, the round trip of `oha`, podgate and the backend bounds the rate; CPU per request is therefore the sensitive number in B, and it did not move.

Decision: TCP entry points join the group `entry points`. A shows the slow state (7 of 7 starts, 12% of the throughput of HTTP) for an entry point that carries nothing, B shows no loss for the TCP traffic, so the third criterion of change 0118 is met. `tests/entry_points.rs` `tcp_entry_point_shares_the_worker_pool` counts the threads (16 workers for `http`, `https` and `tcp` entry points where the separate pool gives 32 on the 16 CPUs of the test machine). UDP entry points and the HTTP/3 front still have their own pools; whether an idle one of them costs the same was not measured.

## What limited each result

Why not double? Each number has a limiter, measured and not assumed.

- **Max-rate scenarios (`h1-*`, `tls-*`): the proxy's CPUs.** On the 4 pinned proxy CPUs, `/proc/stat` over the steady-state window of every max-rate run shows the CPUs 94 to 98.5% busy (user, system, softirq):

  |Proxy|user|system|softirq|idle|
  |---|---|---|---|---|
  |podgate|54 to 65%|21 to 29%|11 to 15%|1.5 to 2.2%|
  |Caddy|56 to 72%|14 to 24%|8 to 15%|3.0 to 6.0%|
  |Traefik|57 to 70%|17 to 27%|10 to 15%|1.8 to 3.4%|

  The process counters (the "proxy cores" column, 3.2 to 3.5 of 4.0) undercount because the loopback softirq time is not charged to the proxy process. The generator and the backend are not limiting: `oha` used 0.8 to 0.9 of its 2 CPUs while driving podgate (1.0 to 1.5 when driving the backend directly, so it can go faster), and the backend used 0.5 of its 2 CPUs.
- **The rig's ceiling is 2.0 to 2.4x above the fastest proxy.** `direct` reaches 417 k and 458 k req/s at 64 and 256 connections (334 k with the 16 KiB body), against 196 k for the fastest proxy result. The backend is not the limiter for any proxy. `oha` straight at the backend is itself limited by `oha` and the backend sharing their 2 CPUs each, so the real ceiling is higher.
- **`rate`: the offered rate.** All proxies delivered 61990 req/s (the schedule), the table shows only their latency. The proxy CPU there was 1.2 (podgate), 1.8 (Caddy) and 1.2 (Traefik) cores of 4, so none was near its limit.
- **The ratios follow CPU cost per request.** podgate spent 1.7 to 2.0 CPU s per 100k requests, Traefik 1.9 to 3.1 and Caddy 2.7 to 4.2. With the CPU set saturated, throughput is the CPU budget divided by that cost. Counting softirq as well (the process counters miss it), the whole cost of a podgate `h1-c64` request is about 2.0 CPU s per 100k (3.9 busy cores over 196 k req/s). Where the cost differs from Traefik's: podgate pays 3% to 8% less per plain HTTP/1.1 request, 8% less per TLS HTTP/1.1 request and 44% less per TLS HTTP/2 request; before change 0116 it paid 6 to 14% more per plain HTTP/1.1 request, mostly thread parking, see "Where the 250 k went". [INFERENCE] Go's runtime, garbage collector and larger per-request header work are the likely sources of Caddy's and Traefik's extra cost in the TLS scenarios, particularly `tls-h2`; no profile was taken.
- **Scaling check not repeated.** The first measurement ran a pass with the proxy on 2 CPUs while another project loaded the machine; it was inconclusive and is not repeated here (`bench/results/2026-11-20/limiter-2cpu.jsonl`).
- **podgate's own admission control acted on most requests and did not refuse any.** `GET /metrics` before and after each run shows `podgate_backend_waited_total` rose for 81 to 100% of the requests (they queued for a slot), the learned limit peaked at 8 to 29 concurrent upstream requests (from 64 or 256 offered), `podgate_backend_refused_total` and `podgate_tenant_inflight_rejected_total` did not move in any run. Per-run values are in `runs.jsonl` (`podgate_waited`, `podgate_refused`, `podgate_tenant_rejected`, `podgate_limit_max`). Change 0115 measured what it costs with a throwaway build that skips it (no switch ships): about 4% of throughput at `h1-c64` with forwarding off (204.8 k against 212.5 k, median of 5 starts) and about 8% with forwarding on (161 k against 174 k, 5 starts), both before change 0116. That is the cost of queueing requests that would have run at once, since the 0 ms loopback backend never needed a limit. Whether to add an operator opt-out or to make the estimator less noise-sensitive is an open question, see the commit history.
- **Keep-alive to the backend held on all three.** The backend counts accepted connections. Over every measured run, podgate opened 1 or 2 new upstream connections in 6 runs (8 in all, in `h1-c64`, `h1-c256` and `tls-h1`), Caddy 21 in one run and Traefik 2 in one run, all other runs 0, while serving 0.93 to 7.5 million requests per run; `direct` opened one per `oha` connection. A pool that reconnected per request would show millions.

## Noise

The machine is shared (8 cores, 16 threads) and other projects' builds and tests can land on any CPU, including the pinned ones. The benchmark held `~/.cache/podgate-cargo.lock`, which keeps builds and tests that use it away, but other sessions can still run work that does not. Per run the script records the foreign CPU time on the proxy CPUs during the window (`other_cores_on_proxy_cpus`: busy time on those CPUs minus the proxy process's own), the foreign cores busy over 2 s before the run (`other_cores_before`) and the 1-minute load average (`load1`).

- Load average before the benchmark started: 2.06 (1 minute), 2.19 (5 minutes). Foreign cores busy before every run: 0.15 to 0.72 against the script's limit of 3; no run waited for the machine to quiet down. Today's Traefik (185 k) and Caddy (125 k) at `h1-c64` are within 1% of the `9c075cc` run (186 k and 126 k) and 5% to 6% above the change 0115 run (176 k and 118 k), so the 5% slowness noted then was the machine's, not the proxies'; the cause is not known (foreign work on the SMT siblings of the pinned cores is a suspect, not measured).
- `load1` per run ranged from 1.07 to 5.42. That is mostly the benchmark's own load (a 15 s run on 8 busy threads raises the 1-minute average by 2 or more and it stays raised across the next runs), so the gate is the 2 s CPU sample taken while the proxies idle, not `uptime`; `load1` is recorded but not gated on. Across all 98 runs of the attribution passes of change 0115 `load1` was 1.08 to 11.62 (the high end while another build ran) and the foreign cores before a run 0.21 to 6.17, with a gate of 3 on a 60 s wait; no attribution run had more than 0.17 foreign cores on the proxy CPUs. In the 28 starts of the change 0116 A/B passes `load1` was 1.22 to 2.29 and the foreign cores before a start 0.23 to 0.68, except one start of the first pass at 1.91 (it was a fast one), and none had more than 0.07 foreign cores on the proxy CPUs.
- Runs with more than 0.3 foreign cores on the proxy CPUs: 2 of 110 (largest 0.32), the Traefik `rate` runs 4 and 5; none is a podgate run. No run was removed or rerun. The run-to-run spread inside a verdict is up to 4% in throughput (largest: Traefik `h1-c256`, 178 k to 185 k req/s, and Caddy `h1-16k`, 102 k to 106 k); podgate's is at most 1.5%. The `rate` p99.9 ranges are wide (podgate 2.42 to 4.97 ms, Caddy 6.22 to 19.35 ms).
- No false start in this run. The false starts of the change 0115 run (a `jq` error in the per-thread counters on `direct` runs, loopback denied by the upstream address policy, a taken port) are fixed in the script.

## Versions and machine

|Item|Value|
|---|---|
|podgate|commit `074ad49`, `cargo build --release` (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`), rustc 1.99; `scripts/bench-proxies.sh` and `bench/podgate-snapshot-noforward.json.in` are the 0115 versions|
|Caddy|2.11.9 (as before)|
|Traefik|3.7.16 (as before)|
|oha|1.16.0 (as before)|
|Kernel|Linux 6.18.63|
|CPU|AMD Ryzen 7 9850X3D, 8 cores, 16 threads, `powersave` governor (as found, not changed)|
|Date|2026-11-22|

CPU sets (`taskset`), the same for every proxy: proxy on CPUs 0 to 3 (four threads on four different physical cores), `oha` on 4 and 5 (2 worker threads), the backend on 6 and 7. CPUs 8 to 15 are the SMT siblings of 0 to 7 and are left to the rest of the machine, so a foreign process can run on a sibling of a pinned core.

Thread counts: Caddy and Traefik run with `GOMAXPROCS=4`. podgate sets Pingora's `ServerConf.threads` to `std::thread::available_parallelism()` in `src/lib.rs`, which follows the CPU affinity, so it is 4 under `taskset`. At idle the processes had 17 (podgate; 21 before change 0116, 12 at `4b3834a`), 9 (Caddy) and 9 (Traefik) OS threads. Until change 0116 each podgate entry point was its own Pingora service with its own pool of 4 threads, so the benchmark's two listeners, `web` (`PROXY_ADDR`) and `websecure` (`PROXY_TLS_ADDR`), ran 8 proxy threads on the 4 pinned CPUs; `4b3834a` served both from one service. Now every HTTP and HTTPS entry point service runs on one pool of 4 threads named `entry points` (see "One pool for the HTTP entry points"). Under plain HTTP load each of the 4 takes 0.8 cores. podgate also has 9 background service threads.

## Tuning, per proxy

All three: loopback, one upstream address, one app `a.test`, HTTP/1.1 keep-alive to the backend, the same ECDSA P-256 self-signed certificate and key (`examples/bench_cert.rs`), TLS 1.3 negotiated, response compression off, no access log, no metrics, no dashboard. The configs are rendered from `bench/*.in`.

|Proxy|Config|Defaults changed, and why|
|---|---|---|
|podgate|`bench/podgate-snapshot.json.in`, pushed with `PUT /v1/snapshot` on the admin socket; the script adds the certificate|`RUST_LOG=warn` (production logging). `UPSTREAM_POLICY_FILE=bench/upstream-policy.json`: since change 0041 the built-in policy denies loopback, so the operator's file replaces the deny list with link-local only and allows `127.0.0.0/8` for the tenant; the check itself still runs on every connect, as in production. Tenant budget `max_inflight` 1,000,000 and `max_buffer_bytes` 1 GiB so no budget acts. No filters, canary, skew secret, scale-to-zero or recording. The app has no `forwarded` object, so the default forwarding headers are sent. Compression is the shipped gzip, which only compresses text-like types; the backend sends `application/octet-stream` and `oha` sends no `Accept-Encoding`, so it never runs. The HTTP/3 front is opt-in per entry point and stays off. Nothing else changed.|
|Caddy|`bench/Caddyfile.in`|`admin off`; `auto_https off` (the certificate is given); global log level `ERROR`; no `log` directive, so no access log; `servers { protocols h1 h2 }`, which drops HTTP/3 (Traefik's is off by default); `keepalive_idle_conns_per_host 1024` (the default 32 would reconnect at 64 and more connections); `versions 1.1` and `compression off` toward the backend; an explicit `respond 404` site for unknown Hosts, because Caddy answers an empty 200 when no site matches.|
|Traefik|`bench/traefik.yml.in`, `bench/traefik-dynamic.yml.in`|`checkNewVersion` and `sendAnonymousUsage` off; log level `ERROR`; no `accessLog`, `api`, `metrics` or `ping` (all off unless configured); `serversTransport.maxIdleConnsPerHost: 1024` (default 200); file provider with `watch: false`. HTTP/2 is on by default on TLS entry points.|

## Method

- **Backend.** `examples/fast_upstream.rs`: keep-alive HTTP/1.1, preformatted responses, no per-request allocation, `GET /` returns 100 bytes, `GET /16k` returns 16 KiB, `application/octet-stream`. It counts accepted connections and served requests (`GET /__stats`). The script reads these before and after each run: the backend's request count must match `oha`'s within 0.5% (all 110 runs matched within 1 request), which is the proof that the requests reached the backend.
- **Correctness probe.** Before every run, `curl` checks that each proxy returns the backend's exact 100 B and 16 KiB bodies for `Host: a.test`, answers 404 for `Host: unknown.test` over HTTP, and returns the body over TLS with HTTP/1.1 and with HTTP/2 (`curl` reports HTTP version 2). Any failure stops the script.
- **Load.** `oha 1.16 --output-format json -z 15s -w --disable-compression --worker-threads 2`, 2 s warm-up against the proxy under test (not recorded), then the measured 15 s. Plain scenarios use `http://127.0.0.1:<port>/` with `Host: a.test`; TLS scenarios use `https://a.test:<port>/` with `--connect-to` so the SNI is `a.test` and `--insecure` for the self-signed certificate. `tls-h2` is `-c 16 -p 4 --http2` (64 streams in flight). `rate` is `-c 64 -q 58000 --latency-correction`, 58000 being half the slowest proxy's median in the first `h1-c64` pass, rounded down to 1000.
- **Order.** Per scenario, 5 runs, each run going through podgate, Caddy, Traefik (and `direct` in plain scenarios) in that order. All three proxies stay running and idle while another is measured, each on the same CPUs; before every run the script waits up to 60 s for the machine to be quiet.
- **CPU and memory.** `utime + stime` from `/proc/<pid>/stat` of the proxy, `oha` and the backend at 2 s and 13 s into the run (an 11 s steady-state window); peak RSS from `VmHWM` after `echo 5 > /proc/<pid>/clear_refs` at the end of warm-up; idle RSS after start-up and the first probes. `/proc/stat` over the proxy CPUs gives the foreign load and the user/system/softirq/idle split.
- **Errors.** Any non-200 response, any `oha` error or a backend request count that differs from `oha`'s marks the run `FAILED RUN` and makes the script exit 1. 503s from rejections would count here, never as throughput; none occurred.
- **Statistics.** Median and range of 5. A gap smaller than the run-to-run range is called no measurable difference. No rank-sum test was run: the "faster" verdicts are the ones with non-overlapping ranges. One process start per proxy means start-to-start variation is not in those ranges; see "What changed since 2026-11-20".
- **Attribution passes.** `h1-c64` only, one `scripts/bench-proxies.sh` invocation (one fresh podgate process start) per measurement, `PROXIES=podgate`, the same CPU sets, forwarding headers off for the app (`bench/podgate-snapshot-noforward.json.in`) unless a row says otherwise. Set A: 5 starts per variant, 2 runs of 15 s each, variants interleaved. Bisection points: 3 starts of 1 run of 15 s per commit, first-parent commits of `4b3834a..074ad49` (496), each built with `cargo build --release` in one scratch worktree. Counter and mechanism passes: 4 to 8 starts of 6 to 8 s. "Limiter short-circuited" is a throwaway build where `Backends::admit` returns an empty slot at once (never committed, no switch ships); "old" is `git archive 4b3834a` with its own v1 snapshot. Per-thread counters come from `/proc/<pid>/task/*` at the start and end of the steady-state window.

## Caveats

- **Loopback, one machine.** No NIC, no packet loss, a 0 ms backend. The proxy's CPU cost is what is measured; real latency to a real backend, real TLS handshakes (all runs reuse connections) and many idle connections are not.
- **Shared box.** See Noise. This run was made on an idle machine; foreign work still lands on the SMT siblings of the pinned cores.
- **Not equal work, but closer.** Defaults kept: for a `curl` request the backend received 196 B from podgate (adds `X-Forwarded-For`, `-Proto`, `-Host`, `-Port` and `X-Real-IP`), 165 B from Caddy (adds `Via` and three `X-Forwarded-*` headers) and 242 B from Traefik (adds five `X-Forwarded-*`, `X-Real-Ip` and `Accept-Encoding: gzip`). The first measurement ran podgate with no forwarding headers; that is no longer true.
- **podgate's admission controls stayed on.** Adaptive limit and fair queue, tenant budgets, pool isolation, SNI check, the upstream address policy run as shipped. Change 0115 measured the limiter alone (about 4 to 8%, see below); what the others cost is not measured.
- **One process start per proxy in the verdicts.** podgate's `h1-*` numbers move by +-15% between fresh starts (see above); the verdict tables are one start's numbers.
- **Traefik sends `Accept-Encoding: gzip` upstream** (Go's transport default, not configurable in Traefik); the backend ignores it, so no response was compressed.
- **No HTTP/3.** podgate has an opt-in HTTP/3 front since change 0086; the benchmark leaves it off, and Caddy and Traefik were configured without it.
- **One workload.** 100 B and 16 KiB bodies, one host, one upstream, GET only, no request bodies, no long-lived connections, no slow clients, no WebSockets.
- **No profile.** `perf_event_open` is denied on this machine, so where the CPU goes inside podgate is attributed by bisection, per-thread counters and controlled experiments (see "Where the 250 k went"), not by a profile.

## Rerun

```
devenv shell
cargo build --release --bin podgate --example fast_upstream --example bench_cert
flock ~/.cache/podgate-cargo.lock scripts/bench-proxies.sh
```

Takes about 36 minutes. `SCENARIOS`, `RUNS`, `DURATION`, `PROXIES`, `PROXY_CPUS`, `LOAD_CPUS`, `BACKEND_CPUS`, `PODGATE_BIN`, `SNAPSHOT_TEMPLATE` and `PODGATE_NO_TLS` change the run (see the header of the script); `OUT=<dir>` resumes a stopped run. The results here are in `bench/results/2026-11-22-0116/`: `runs.jsonl` (every reported run, with per-thread CPU and context-switch counters of the proxy), `run-log.txt` (the console output), `pool-ab.jsonl` and `pool-ab-after.jsonl` (the 14 starts each of the change 0116 passes before and after the change, labelled by variant and start) and `pool-fwd-on.jsonl` (6 fresh starts with forwarding headers on). The 2026-11-22 run of change 0115 is in `bench/results/2026-11-22-0115/` (`attribution.jsonl` holds every run of its attribution passes), the run at `9c075cc` in `bench/results/2026-11-22/` and the first measurement's files in `bench/results/2026-11-20/`. The attribution and pool passes need a fresh process start per measurement: `PROXIES=podgate SCENARIOS=h1-c64 RUNS=1 DURATION=10 PODGATE_BIN=<binary> SNAPSHOT_TEMPLATE=bench/podgate-snapshot-noforward.json.in scripts/bench-proxies.sh`, repeated per start, with `PODGATE_NO_TLS=1` for the variant that has no `websecure` entry point.

The charts in `docs/benchmarks/` come from the same result files. `scripts/bench-charts.sh` redraws them from the newest `bench/results/<date>/runs.jsonl` (and the `attribution.jsonl` next to it, or the newest one there is), `scripts/bench-charts.sh <results dir>` from another run, and `scripts/bench-charts.sh --check` (part of `check`) fails when a chart no longer matches its results.
