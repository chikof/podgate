# Benchmarks: podgate, Caddy and Traefik

How podgate compares with Caddy and Traefik as a Host-routing reverse proxy on one machine: throughput, latency at a fixed rate, errors, CPU and memory, over plain HTTP and TLS. One script, `scripts/bench-proxies.sh`, runs everything. Method and tuning are below the results, so every number can be rerun.

This is a loopback measurement on one shared machine with the proxies as they ship (podgate with its admission controls on). It compares configurations, not only code. Read the caveats before quoting a number.

Measured three times. The first measurement (2026-11-20, podgate at commit `a22f5d2` plus the benchmark files of change 0020) is kept in [`bench/results/2026-11-20/`](../bench/results/2026-11-20/runs.jsonl). The second (2026-11-22, commit `9c075cc`) is in `bench/results/2026-11-22/`. This page holds the third, 2026-11-22 on commit `074ad49`: the request path since the first measurement gained forwarding headers and some 490 other commits (v2 routing model, upstream address policy, per-entry-point metrics, many middlewares, an HTTP/3 front). Several verdicts changed; the changes are in the tables and explained in "What changed since 2026-11-20".

## Verdicts

Each verdict is the median of 5 interleaved runs of 15 s, on one process start per proxy. A verdict says "faster" only when the run ranges do not overlap. The last two columns give the first measurement for comparison. The `h1-*` rows against Traefik are the exception: podgate's throughput moves by +-15% between fresh process starts (see "Where the 250 k went"), which the 5 runs of one start do not capture. `h1-c64` gives the direction over 6 starts of this build (160 k, 154 k, 161 k, 140 k, 163 k, 194 k); `h1-c256` and `h1-16k` rest on one start each, and their gap to Traefik is no larger than that spread.

|Scenario|podgate vs Caddy|podgate vs Traefik|Limiter|Before: vs Caddy|Before: vs Traefik|
|---|---|---|---|---|---|
|`h1-c64`: HTTP/1.1, 64 connections, 100 B body, max rate|faster (1.36x)|**probably slower**: Traefik 1.10x faster on the verdict start (176 k against 160 k, ranges apart); podgate slower at 5 of 6 starts, but its range over starts (140 k to 194 k) brackets Traefik's one start; see "Where the 250 k went"|proxy CPUs|2.1x|1.4x|
|`h1-c256`: as above, 256 connections|faster (1.35x)|**inconclusive**: Traefik 1.10x faster on one podgate start; the spread between starts (+-15% on `h1-c64`) is as large as the gap|proxy CPUs|2.0x|1.5x|
|`h1-16k`: as `h1-c64`, 16 KiB body|faster (1.38x)|**inconclusive**: Traefik 1.14x faster on one podgate start; the spread between starts (+-15% on `h1-c64`) is as large as the gap|proxy CPUs|1.9x|1.25x|
|`rate`: 58000 req/s fixed, 64 connections|same throughput (all three sustain it); p50 lower by 26%; p99 lower; p99.9 no measurable difference (ranges overlap)|same throughput; **p50 higher (0.36 ms against 0.30)**; p99 lower (ranges 0.001 ms apart); p99.9 no measurable difference (ranges overlap)|offered rate|p50 and p99 lower|p50 and p99 lower|
|`tls-h1`: TLS 1.3, HTTP/1.1, 64 connections|faster (1.59x)|faster (1.10x)|proxy CPUs|2.3x|1.4x|
|`tls-h2`: TLS 1.3, HTTP/2, 16 connections x 4 streams|faster (2.43x)|faster (1.79x)|proxy CPUs|3.4x|2.2x|
|CPU seconds per 100k requests|lower (1.8 to 2.5 against 2.9 to 4.4)|**higher in plain HTTP (2.1 to 2.5 against 1.9 to 2.2), lower in TLS (1.8 against 2.0 and 3.3)**|not applicable|lower|lower|
|Peak and idle memory|idle lower (16 MiB against 47 and 89); peak lower in plain HTTP (31 to 64 MiB against 66 to 95), 3 to 6 MiB higher in TLS (77 and 79 against 71 and 74)|lower (31 to 79 MiB against 118 to 171)|not applicable|lower|lower|

Podgate stays behind Traefik on the plain-HTTP rows, and the cause is attributed in "Where the 250 k went": against its own first build the fall at `h1-c64` (250 k to 160 k) is forwarding headers (about 20 to 25%), the adaptive limiter (4 to 8%), and a "slow regime" of thread parking that most fresh starts fall into (about 14%) on top of a 7% creep in cost per request. A podgate built from the first measurement's commit, run on the same rig beside the same Traefik, was 1.35x faster (250 k against 186 k req/s) in the `9c075cc` pass, so the loss is podgate's own, not the rig's.

No scenario produced a non-2xx response or an error for any proxy (110 recorded runs, 0 non-2xx, 0 errors, backend request count equal to `oha`'s count within 1 request; the 98 runs of the attribution passes were checked the same way for non-2xx and errors by the script's `FAILED RUN` rule, none failed).

What this does not say: that podgate is faster or slower for your traffic. Caddy and Traefik do more per request by default (see Caveats), and the backend answers in microseconds, so these numbers measure proxy overhead only.

## Results

Median (min-max) of 5 runs per proxy and scenario, 15 s each, steady state, one process start per proxy, run 2026-11-22 on commit `074ad49`. `direct` is `oha` straight at the backend with the same settings, the ceiling of the rig. Latencies are from `oha`'s own histogram (the `rate` scenario uses `--latency-correction`). Raw per-run data: [`bench/results/2026-11-22-0115/runs.jsonl`](../bench/results/2026-11-22-0115/runs.jsonl). The earlier run at `9c075cc` is in `bench/results/2026-11-22/`.

### Throughput and latency

|Scenario|Proxy|req/s|p50 ms|p99 ms|p99.9 ms|
|---|---|---|---|---|---|
|h1-c64|podgate|160075 (156932-165056)|0.39 (0.38-0.4)|0.63 (0.57-0.8)|1.57 (1.08-1.9)|
|h1-c64|caddy|117651 (112160-120665)|0.39 (0.38-0.41)|2.15 (2.11-2.4)|4.63 (4.45-4.85)|
|h1-c64|traefik|175714 (167270-178524)|0.3 (0.29-0.31)|1.59 (1.55-1.72)|3.45 (3.24-3.9)|
|h1-c64|direct|446470 (394930-473194)|0.12 (0.11-0.13)|0.22 (0.2-0.25)|4.14 (4.12-4.17)|
|h1-c256|podgate|158377 (153643-159886)|1.6 (1.59-1.63)|2.16 (2.02-2.44)|4.1 (3.58-4.52)|
|h1-c256|caddy|117071 (112732-123547)|1.86 (1.8-1.91)|7.09 (5.93-7.55)|11.57 (8.92-12.61)|
|h1-c256|traefik|173791 (160318-179605)|1.32 (1.28-1.39)|5.01 (4.48-5.74)|7.64 (6.75-9.06)|
|h1-c256|direct|452563 (418800-464326)|0.48 (0.48-0.49)|4.51 (4.48-4.57)|5.69 (5.59-6.34)|
|h1-16k|podgate|134278 (133636-135326)|0.47 (0.47-0.47)|0.73 (0.7-0.75)|1.57 (1.48-1.75)|
|h1-16k|caddy|97656 (96338-104494)|0.5 (0.47-0.5)|2.49 (2.36-2.58)|4.89 (4.36-4.96)|
|h1-16k|traefik|152489 (150734-162407)|0.35 (0.34-0.35)|1.72 (1.42-1.78)|3.58 (2.84-3.71)|
|h1-16k|direct|418723 (379907-436626)|0.13 (0.13-0.15)|0.23 (0.23-0.26)|4.14 (3.4-4.18)|
|rate|podgate|57992 (57991-57993)|0.36 (0.36-0.38)|1.57 (1.31-1.68)|3.99 (3.56-15.7)|
|rate|caddy|57992 (57991-57993)|0.48 (0.44-0.51)|2.71 (2.41-3.51)|7.07 (4.64-8.26)|
|rate|traefik|57989 (57989-57995)|0.3 (0.29-0.34)|1.94 (1.68-2.44)|4.15 (3.43-4.79)|
|rate|direct|57991 (57989-57995)|0.12 (0.12-0.12)|0.35 (0.32-0.43)|0.91 (0.8-1.58)|
|tls-h1|podgate|184081 (180965-186254)|0.34 (0.34-0.34)|0.55 (0.49-0.7)|1.64 (1.21-2.03)|
|tls-h1|caddy|115634 (114647-119832)|0.4 (0.39-0.4)|2.33 (2.14-2.41)|4.89 (4.77-5.08)|
|tls-h1|traefik|168004 (165795-172808)|0.31 (0.3-0.31)|1.66 (1.57-1.71)|3.9 (3.48-4.13)|
|tls-h2|podgate|187895 (176707-193492)|0.34 (0.33-0.35)|0.52 (0.5-0.88)|1.32 (1.14-1.92)|
|tls-h2|caddy|77439 (73056-80526)|0.67 (0.65-0.69)|3.4 (2.98-3.91)|5.73 (5.15-6.66)|
|tls-h2|traefik|105121 (103979-108669)|0.53 (0.52-0.54)|2.12 (2.01-2.16)|4.64 (4.48-4.67)|

In `h1-c64` podgate's p50 is the same as Caddy's (0.39 ms) and above Traefik's (0.30), while its p99 and p99.9 stay the lowest of the three: podgate's tail is tight, its median is not the best.

The rate of the `rate` scenario is 58000 req/s: half the slowest proxy's `h1-c64` median (Caddy), rounded down to 1000. It was 62000 in the 9c075cc run and 56000 in the first measurement because Caddy's number differed.

### CPU and memory

CPU is cores of the proxy process (`utime + stime` of the whole process over the steady-state window, so 4.0 is all four pinned CPUs). "CPU s/100k" is that CPU time divided by the requests served in the window. Peak RSS is `VmHWM` after resetting it once warm-up ended. "Other cores max" is the largest foreign load on the proxy CPUs in any of the 5 runs (a negative value is the accounting difference between the per-process and per-CPU counters, about 0.1 core, not load), and "disturbed" counts runs with more than 0.3 foreign cores.

|Scenario|Proxy|Proxy cores|oha cores (of 2)|Backend cores (of 2)|CPU s/100k req|Peak RSS MiB|Other cores max|Disturbed runs|
|---|---|---|---|---|---|---|---|---|
|h1-c64|podgate|3.33 (3.31-3.36)|0.69 (0.69-0.69)|0.41 (0.41-0.41)|2.08 (2.03-2.11)|31 (31-31)|-0.07|0|
|h1-c64|caddy|3.33 (3.29-3.37)|0.51 (0.51-0.52)|0.31 (0.3-0.31)|2.86 (2.76-2.93)|67 (67-69)|0.09|0|
|h1-c64|traefik|3.37 (3.36-3.4)|0.73 (0.72-0.74)|0.46 (0.45-0.46)|1.92 (1.89-2.02)|120 (118-124)|0.06|0|
|h1-c64|direct|0 (0-0)|1.32 (1.18-1.41)|0.84 (0.74-0.88)|-|-|0.43|2|
|h1-c256|podgate|3.33 (3.3-3.34)|0.69 (0.69-0.7)|0.41 (0.4-0.41)|2.1 (2.08-2.15)|59 (55-65)|-0.07|0|
|h1-c256|caddy|3.36 (3.3-3.46)|0.52 (0.51-0.55)|0.31 (0.31-0.32)|2.92 (2.78-2.96)|95 (93-97)|0.14|0|
|h1-c256|traefik|3.42 (3.32-3.46)|0.74 (0.7-0.76)|0.46 (0.43-0.47)|1.97 (1.93-2.07)|171 (170-172)|0.1|0|
|h1-c256|direct|0 (0-0)|1.43 (1.32-1.44)|0.85 (0.8-0.87)|-|-|0.48|3|
|h1-16k|podgate|3.29 (3.29-3.3)|0.79 (0.78-0.79)|0.41 (0.41-0.42)|2.46 (2.43-2.46)|64 (64-65)|-0.07|0|
|h1-16k|caddy|3.18 (3.17-3.21)|0.75 (0.75-0.78)|0.31 (0.31-0.32)|3.26 (3.07-3.29)|70 (70-76)|0.04|0|
|h1-16k|traefik|3.31 (3.28-3.34)|0.87 (0.86-0.92)|0.48 (0.48-0.5)|2.15 (2.06-2.18)|125 (124-156)|0.02|0|
|h1-16k|direct|0 (0-0)|1.41 (1.26-1.42)|1 (0.91-1.01)|-|-|0.25|0|
|rate|podgate|1.24 (1.23-1.28)|0.27 (0.26-0.27)|0.15 (0.15-0.15)|2.13 (2.12-2.2)|32 (32-32)|0.33|1|
|rate|caddy|1.71 (1.68-1.76)|0.27 (0.27-0.28)|0.15 (0.15-0.16)|2.95 (2.89-3.03)|66 (64-67)|0.55|3|
|rate|traefik|1.17 (1.15-1.27)|0.26 (0.26-0.27)|0.15 (0.15-0.16)|2.02 (1.98-2.18)|118 (118-118)|0.44|2|
|rate|direct|0 (0-0)|0.22 (0.2-0.22)|0.12 (0.11-0.12)|-|-|0.45|3|
|tls-h1|podgate|3.36 (3.34-3.37)|0.86 (0.86-0.87)|0.47 (0.47-0.48)|1.82 (1.81-1.85)|79 (77-79)|-0.04|0|
|tls-h1|caddy|3.4 (3.33-3.43)|0.55 (0.55-0.56)|0.31 (0.3-0.31)|2.89 (2.84-2.94)|74 (73-76)|0.08|0|
|tls-h1|traefik|3.39 (3.39-3.44)|0.77 (0.76-0.78)|0.45 (0.44-0.45)|2.02 (1.99-2.04)|131 (128-132)|0.03|0|
|tls-h2|podgate|3.4 (3.34-3.41)|0.87 (0.85-0.87)|0.48 (0.47-0.49)|1.8 (1.76-1.89)|77 (77-77)|-0|0|
|tls-h2|caddy|3.38 (3.31-3.44)|0.58 (0.57-0.6)|0.21 (0.2-0.21)|4.36 (4.27-4.53)|71 (70-76)|0.07|0|
|tls-h2|traefik|3.42 (3.41-3.43)|0.78 (0.77-0.79)|0.28 (0.28-0.29)|3.26 (3.15-3.3)|126 (125-127)|0.02|0|

Idle RSS before the first request: podgate 15.8 MiB, Caddy 46.7 MiB, Traefik 89.4 MiB. podgate's peak RSS under load is 31 to 79 MiB.

## What changed since 2026-11-20

Why podgate went from 232 k to 160 k req/s at `h1-c64` while Caddy and Traefik went the other way (113 k to 118 k, 163 k to 176 k). [INFERENCE] The first measurement's Go proxies had foreign load on their CPUs in some runs (its Noise section lists them); the later runs' machine had none on the proxy CPUs.

### Where the 250 k went

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
- **Ruled out as the cause of the slow regime** (tip build, limiter short-circuited, 6 to 8 s per start): address space randomisation off (`setarch -R`, 6 starts: 1 fast start at 248 k, 5 at 210 k to 217 k), a single malloc arena (`MALLOC_ARENA_MAX=1`: 124 k to 130 k in all 6, far worse, so the proxy allocates a lot but the arenas are not what separates the regimes), jemalloc 5.4.0 preloaded (6 starts: 243 k and 242 k fast, 159 k to 207 k otherwise), Pingora's work stealing off (7 starts: 1 fast at 249 k, 185 k to 217 k otherwise). Not tried: fewer or merged runtimes (the tip has 8 `entry point web` threads against 4 in the old build) and anything that makes tokio spin before parking.
- **The limiter costs about 4 to 8%.** Short-circuited, the median start moves from 204.8 k to 212.5 k req/s with forwarding off (5 starts each), and from 161 k to 174 k with forwarding on (5 starts each of 6 s: 154 k, 161 k, 140 k, 163 k, 194 k against 164 k, 170 k, 204 k, 174 k, 174 k). With it on, none of the 5 starts of set A reached the fast regime; short-circuited, 1 of 5 did. That is a small sample. The limiter alone does not explain most of the gap, so no switch was built.
- **Forwarding headers cost about 20 to 25%**, as in the 9c075cc run: with the limiter on, the median start moves from 204.8 k (off) to 161 k (on). Before, the backend received about 70 B per request from podgate; now it receives 196 B (five more headers: `X-Forwarded-For`, `-Proto`, `-Host`, `-Port`, `X-Real-IP`). Caddy adds 165 B and Traefik 242 B, so the first measurement compared podgate doing less work; this one compares like with like.
- **The sum.** As shipped, a typical start is 161 k against 250 k: about -20% for forwarding, -4 to -8% for the limiter, -14% for the slow regime (212 k against 245 k), and the rest is the +7% creep. TLS shows no such loss because the same process does 184 k and 188 k there (1.8 CPU s/100k) against 160 k in plain `h1-c64` (2.1): the TLS verdicts stayed "faster" while the plain ones fell. [INFERENCE] Parking depends on how requests overlap in the closed loop between `oha`, podgate and the backend, and TLS changes that timing; this was not measured.

## What limited each result

Why not double? Each number has a limiter, measured and not assumed.

- **Max-rate scenarios (`h1-*`, `tls-*`): the proxy's CPUs.** On the 4 pinned proxy CPUs, `/proc/stat` over the steady-state window of every max-rate run shows the CPUs 93 to 98% busy (user, system, softirq):

  |Proxy|user|system|softirq|idle|
  |---|---|---|---|---|
  |podgate|56 to 65%|21 to 28%|11 to 14%|2.1 to 3.3%|
  |Caddy|57 to 72%|14 to 24%|8 to 15%|3.9 to 6.9%|
  |Traefik|58 to 69%|17 to 26%|10 to 14%|1.9 to 3.8%|

  The process counters (the "proxy cores" column, 3.2 to 3.5 of 4.0) undercount because the loopback softirq time is not charged to the proxy process. The generator and the backend are not limiting: `oha` used 0.7 to 0.9 of its 2 CPUs while driving podgate (1.2 to 1.4 when driving the backend directly, so it can go faster), and the backend used 0.4 to 0.5 of its 2 CPUs.
- **The rig's ceiling is 2.4x above the fastest proxy.** `direct` reaches 446 k and 453 k req/s at 64 and 256 connections (419 k with the 16 KiB body), against 188 k for the fastest proxy result. The backend is not the limiter for any proxy. `oha` straight at the backend is itself limited by `oha` and the backend sharing their 2 CPUs each, so the real ceiling is higher.
- **`rate`: the offered rate.** All proxies delivered 57990 req/s (the schedule), the table shows only their latency. The proxy CPU there was 1.2 (podgate), 1.7 (Caddy) and 1.2 (Traefik) cores of 4, so none was near its limit.
- **The ratios follow CPU cost per request.** podgate spent 1.8 to 2.5 CPU s per 100k requests, Traefik 1.9 to 3.3 and Caddy 2.9 to 4.4. With the CPU set saturated, throughput is the CPU budget divided by that cost. Counting softirq as well (the process counters miss it), the whole cost of a podgate `h1-c64` request is about 2.4 CPU s per 100k (3.9 busy cores over 160 k req/s). Where the cost differs from Traefik's: podgate pays 6 to 14% more per plain HTTP/1.1 request, 10% less per TLS HTTP/1.1 request and 45% less per TLS HTTP/2 request. The plain-HTTP excess is mostly thread parking, see "Where the 250 k went". [INFERENCE] Go's runtime, garbage collector and larger per-request header work are the likely sources of Caddy's and Traefik's extra cost in the TLS scenarios, particularly `tls-h2`; no profile was taken.
- **Scaling check not repeated.** The first measurement ran a pass with the proxy on 2 CPUs while another project loaded the machine; it was inconclusive and is not repeated here (`bench/results/2026-11-20/limiter-2cpu.jsonl`).
- **podgate's own admission control acted on most requests and did not refuse any.** `GET /metrics` before and after each run shows `podgate_backend_waited_total` rose for 82 to 100% of the requests (they queued for a slot), the learned limit peaked at 7 to 29 concurrent upstream requests (from 64 or 256 offered), `podgate_backend_refused_total` and `podgate_tenant_inflight_rejected_total` did not move in any run. Per-run values are in `runs.jsonl` (`podgate_waited`, `podgate_refused`, `podgate_tenant_rejected`, `podgate_limit_max`). Change 0115 measured what it costs with a throwaway build that skips it (no switch ships): about 4% of throughput at `h1-c64` with forwarding off (204.8 k against 212.5 k, median of 5 starts) and about 8% with forwarding on (161 k against 174 k, 5 starts). That is the cost of queueing requests that would have run at once, since the 0 ms loopback backend never needed a limit. Whether to add an operator opt-out or to make the estimator less noise-sensitive is an open question, see the commit history.
- **Keep-alive to the backend held on all three.** The backend counts accepted connections. Over every measured run, podgate opened 3 new upstream connections in each of two runs (`h1-c64` and `tls-h1`), Caddy and Traefik none, all other runs 0, while serving 0.87 to 7.1 million requests per run; `direct` opened one per `oha` connection. A pool that reconnected per request would show millions.

## Noise

The machine is shared (8 cores, 16 threads) and other projects' builds and tests can land on any CPU, including the pinned ones. The benchmark held `~/.cache/podgate-cargo.lock`, which keeps builds and tests that use it away, but other sessions can still run work that does not. Per run the script records the foreign CPU time on the proxy CPUs during the window (`other_cores_on_proxy_cpus`: busy time on those CPUs minus the proxy process's own), the foreign cores busy over 2 s before the run (`other_cores_before`) and the 1-minute load average (`load1`).

- Load average before the benchmark started: 1.57 (1 minute), 2.17 (5 minutes). Foreign cores busy before every run: 0.26 to 1.95 against the script's limit of 3; no run waited for the machine to quiet down. The rig is about 5% slower today than in the `9c075cc` run (Traefik 176 k against 186 k and Caddy 118 k against 126 k at `h1-c64`); the cause is not known (foreign work on the SMT siblings of the pinned cores is a suspect, not measured).
- `load1` per run ranged from 1.33 to 6.92. That is mostly the benchmark's own load (a 15 s run on 8 busy threads raises the 1-minute average by 2 or more and it stays raised across the next runs), so the gate is the 2 s CPU sample taken while the proxies idle, not `uptime`; `load1` is recorded but not gated on. Across all 98 runs of the attribution passes `load1` was 1.08 to 11.62 (the high end while another build ran) and the foreign cores before a run 0.21 to 6.17, with a gate of 3 on a 60 s wait; no attribution run had more than 0.17 foreign cores on the proxy CPUs.
- Runs with more than 0.3 foreign cores on the proxy CPUs: 14 of 110 (largest 0.55). All 14 are `rate` runs of the three proxies (podgate run 1, Caddy runs 1, 2 and 5, Traefik runs 4 and 5) or `direct` runs; none is an `h1-*` or `tls-*` run of podgate, Caddy or Traefik. No run was removed or rerun. The `rate` p99.9 ranges are wide for that reason (podgate 3.56 to 15.7 ms, Caddy 4.64 to 8.26 ms). The run-to-run spread inside a verdict is 1 to 10% in throughput (largest: Traefik `h1-c256`, 160 k to 180 k req/s, and Caddy `h1-16k`, 96 k to 104 k).
- One false start: the first full attempt stopped after 3 runs on a `jq` error in the new per-thread counters of the script (the `direct` runs have no proxy process); fixed, and nothing from that attempt is in the data. The earlier false starts (loopback denied by the upstream address policy, a taken port) are fixed in the script.

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

Thread counts: Caddy and Traefik run with `GOMAXPROCS=4`. podgate sets Pingora's `ServerConf.threads` to `std::thread::available_parallelism()` in `src/lib.rs`, which follows the CPU affinity, so it is 4 under `taskset`. At idle the processes had 21 (podgate; 12 at `4b3834a`), 9 (Caddy) and 9 (Traefik) OS threads. Each podgate entry point is its own Pingora service with its own pool of 4 threads, so the benchmark's two listeners, `web` (`PROXY_ADDR`) and `websecure` (`PROXY_TLS_ADDR`), run 8 proxy threads on the 4 pinned CPUs; `4b3834a` served both listeners from one service, 4 `Pingora HTTP Proxy` threads. Linux cuts thread names at 15 characters, so all 8 show as `entry point web`. Under plain HTTP load only 4 of them take CPU (per-thread counters, 0.8 cores each), which fits the `web` pool serving and the `websecure` pool idling. podgate also has 9 background service threads.

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

Takes about 36 minutes. `SCENARIOS`, `RUNS`, `DURATION`, `PROXIES`, `PROXY_CPUS`, `LOAD_CPUS`, `BACKEND_CPUS`, `PODGATE_BIN` and `SNAPSHOT_TEMPLATE` change the run (see the header of the script); `OUT=<dir>` resumes a stopped run. The results here are in `bench/results/2026-11-22-0115/`: `runs.jsonl` (every reported run, with per-thread CPU and context-switch counters of the proxy), `run-log.txt` (the console output) and `attribution.jsonl` (every run of the change 0115 attribution passes, labelled by variant). The 2026-11-22 run at `9c075cc` is in `bench/results/2026-11-22/` and the first measurement's files are in `bench/results/2026-11-20/`. The attribution passes need a fresh process start per measurement: `PROXIES=podgate SCENARIOS=h1-c64 RUNS=2 PODGATE_BIN=<binary> SNAPSHOT_TEMPLATE=bench/podgate-snapshot-noforward.json.in scripts/bench-proxies.sh`, repeated per start.
