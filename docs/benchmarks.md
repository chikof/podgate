# Benchmarks: podgate, Caddy and Traefik

How podgate compares with Caddy and Traefik as a Host-routing reverse proxy on one machine: throughput, latency at a fixed rate, errors, CPU and memory, over plain HTTP and TLS. One script, `scripts/bench-proxies.sh`, runs everything. Method and tuning are below the results, so every number can be rerun.

This is a loopback measurement on one shared machine with the proxies as they ship (podgate with its admission controls on). It compares configurations, not only code. Read the caveats before quoting a number.

Measured twice. The first measurement (2026-11-20, podgate at commit `a22f5d2` plus the benchmark files of change 0020) is kept in [`bench/results/2026-11-20/`](../bench/results/2026-11-20/runs.jsonl). This page holds the second, 2026-11-22, on commit `9c075cc`: the request path since then gained forwarding headers and some 480 other commits (v2 routing model, upstream address policy, per-entry-point metrics, many middlewares, an HTTP/3 front). Several verdicts changed; the changes are in the tables and explained in "What changed since 2026-11-20".

## Verdicts

Each verdict is the median of 5 interleaved runs of 15 s, on one process start per proxy. A verdict says "faster" only when the run ranges do not overlap. The last two columns give the first measurement for comparison. The `h1-*` rows against Traefik are the exception: podgate's throughput moves by +-15% between fresh process starts (see "Start-to-start spread"), which the 5 runs of one start do not capture, so those rows give the direction over 10 starts instead of a firm verdict.

|Scenario|podgate vs Caddy|podgate vs Traefik|Limiter|Before: vs Caddy|Before: vs Traefik|
|---|---|---|---|---|---|
|`h1-c64`: HTTP/1.1, 64 connections, 100 B body, max rate|faster (1.32x)|**probably slower**: Traefik 1.12x faster on the verdict start; podgate slower at 8 of 10 starts (median 166 k against 186 k), but its range over starts (142 k to 198 k) overlaps Traefik's one start; see "Start-to-start spread"|proxy CPUs|2.1x|1.4x|
|`h1-c256`: as above, 256 connections|faster (1.28x)|**probably slower** (Traefik 1.14x faster on the verdict start; one start only, see above)|proxy CPUs|2.0x|1.5x|
|`h1-16k`: as `h1-c64`, 16 KiB body|faster (1.36x)|**probably slower** (Traefik 1.16x faster on the verdict start; one start only, see above)|proxy CPUs|1.9x|1.25x|
|`rate`: 62000 req/s fixed, 64 connections|same throughput (all three sustain it); p50 lower by 20%; p99 and p99.9 lower|same throughput; **p50 higher (0.36 ms against 0.29)**; p99 lower; p99.9 lower, ranges 0.14 ms apart|offered rate|p50 and p99 lower|p50 and p99 lower|
|`tls-h1`: TLS 1.3, HTTP/1.1, 64 connections|faster (1.53x)|faster (1.07x)|proxy CPUs|2.3x|1.4x|
|`tls-h2`: TLS 1.3, HTTP/2, 16 connections x 4 streams|faster (2.45x)|faster (1.75x)|proxy CPUs|3.4x|2.2x|
|CPU seconds per 100k requests|lower (1.8 to 2.4 against 2.7 to 4.3)|**higher in plain HTTP (2.0 to 2.4 against 1.9 to 2.1), lower in TLS (1.8 against 1.9 and 3.1)**|not applicable|lower|lower|
|Peak and idle memory|idle lower (17 MiB against 47 and 88); peak lower except `tls-h1` and `tls-h2`, where there is no measurable difference (72 to 74 MiB against 69 to 74)|lower (31 to 74 MiB against 116 to 169)|not applicable|lower|lower|

The three verdicts that were "faster" against Traefik are now "probably slower": plain HTTP at maximum rate, slower at 8 of 10 podgate starts but within its start-to-start spread. The regression against podgate's own earlier build is firmer and not a rig artifact: a podgate built from the first measurement's commit, run on the same rig today beside the same Traefik, is still 1.35x faster (250 k against 186 k req/s, 3 process starts, all above the best current start). The cause is podgate's own cost per request, see below; change 0115 bisects it.

No scenario produced a non-2xx response or an error for any proxy (110 recorded runs, 0 non-2xx, 0 errors, backend request count equal to `oha`'s count within 1 request; the 42 runs of the attribution pass below also had no non-2xx response and no error).

What this does not say: that podgate is faster or slower for your traffic. Caddy and Traefik do more per request by default (see Caveats), and the backend answers in microseconds, so these numbers measure proxy overhead only.

## Results

Median (min-max) of 5 runs per proxy and scenario, 15 s each, steady state. `direct` is `oha` straight at the backend with the same settings, the ceiling of the rig. Latencies are from `oha`'s own histogram (the `rate` scenario uses `--latency-correction`). Raw per-run data: [`bench/results/2026-11-22/runs.jsonl`](../bench/results/2026-11-22/runs.jsonl).

### Throughput and latency

|Scenario|Proxy|req/s|p50 ms|p99 ms|p99.9 ms|
|---|---|---|---|---|---|
|h1-c64|podgate|166061 (164453-167622)|0.38 (0.38-0.39)|0.57 (0.56-0.57)|1.07 (1.04-1.09)|
|h1-c64|caddy|125579 (125124-127320)|0.37 (0.37-0.37)|1.92 (1.85-1.96)|4.11 (3.58-4.23)|
|h1-c64|traefik|185593 (184518-187076)|0.29 (0.29-0.29)|1.44 (1.42-1.47)|2.33 (2.25-2.64)|
|h1-c64|direct|421589 (374072-451999)|0.11 (0.11-0.12)|0.23 (0.19-3.12)|4.17 (4.16-4.71)|
|h1-c256|podgate|162559 (162336-163250)|1.57 (1.56-1.57)|1.82 (1.8-1.85)|3.12 (2.77-3.62)|
|h1-c256|caddy|127139 (127018-128938)|1.75 (1.74-1.76)|5.58 (5.22-5.71)|8.22 (7.7-9.56)|
|h1-c256|traefik|185039 (183443-185847)|1.25 (1.24-1.25)|4.33 (4.26-4.5)|6.47 (6.37-6.76)|
|h1-c256|direct|448210 (423881-481483)|0.47 (0.47-0.47)|4.48 (2.05-4.55)|5.5 (5.4-5.61)|
|h1-16k|podgate|137501 (137093-138003)|0.46 (0.46-0.46)|0.68 (0.68-0.69)|1.19 (0.91-1.24)|
|h1-16k|caddy|101245 (100398-105165)|0.48 (0.47-0.48)|2.35 (2.3-2.39)|4.51 (4.08-4.63)|
|h1-16k|traefik|159989 (156993-163129)|0.34 (0.34-0.34)|1.57 (1.41-1.66)|2.84 (2.78-3.55)|
|h1-16k|direct|418234 (350278-462051)|0.13 (0.12-0.13)|0.21 (0.2-1.6)|4.14 (0.62-4.19)|
|rate|podgate|61993 (61988-61993)|0.36 (0.35-0.37)|0.81 (0.8-0.82)|3.1 (2.92-3.32)|
|rate|caddy|61991 (61988-61994)|0.45 (0.45-0.47)|2.38 (2.28-2.5)|5.56 (5.32-6.19)|
|rate|traefik|61992 (61991-61993)|0.29 (0.29-0.29)|1.73 (1.67-1.77)|3.66 (3.46-4.82)|
|rate|direct|61992 (61991-61994)|0.15 (0.15-0.15)|0.35 (0.34-0.37)|1.62 (1.14-1.71)|
|tls-h1|podgate|189264 (188398-190180)|0.34 (0.33-0.34)|0.48 (0.47-0.49)|1.05 (1.03-1.25)|
|tls-h1|caddy|123387 (122974-125822)|0.38 (0.38-0.38)|1.98 (1.96-2.02)|4.17 (3.75-4.27)|
|tls-h1|traefik|177393 (176884-177731)|0.3 (0.3-0.3)|1.51 (1.49-1.53)|3.23 (2.94-3.43)|
|tls-h2|podgate|194244 (193975-194998)|0.33 (0.33-0.33)|0.49 (0.49-0.5)|1.01 (0.96-1.08)|
|tls-h2|caddy|79383 (79155-80064)|0.65 (0.65-0.66)|3.07 (2.97-3.24)|5.42 (5.27-5.45)|
|tls-h2|traefik|110910 (110244-111614)|0.51 (0.51-0.51)|1.88 (1.85-1.93)|4.04 (3.93-4.19)|

In `h1-c64` podgate's p50 is the same as Caddy's (0.38 and 0.37 ms) and above Traefik's, while its p99 and p99.9 stay the lowest of the three: podgate's tail is tight, its median is not the best.

The rate of the `rate` scenario is 62000 req/s: half the slowest proxy's `h1-c64` median (Caddy), rounded down to 1000. It was 56000 in the first measurement because Caddy's number then was lower.

### CPU and memory

CPU is cores of the proxy process (`utime + stime` of the whole process over the steady-state window, so 4.0 is all four pinned CPUs). "CPU s/100k" is that CPU time divided by the requests served in the window. Peak RSS is `VmHWM` after resetting it once warm-up ended. "Other cores max" is the largest foreign load on the proxy CPUs in any of the 5 runs (a negative value is the accounting difference between the per-process and per-CPU counters, about 0.1 core, not load), and "disturbed" counts runs with more than 0.3 foreign cores.

|Scenario|Proxy|Proxy cores|oha cores (of 2)|Backend cores (of 2)|CPU s/100k req|Peak RSS MiB|Other cores max|Disturbed runs|
|---|---|---|---|---|---|---|---|---|
|h1-c64|podgate|3.36 (3.35-3.36)|0.69 (0.68-0.7)|0.41 (0.41-0.41)|2.02 (2-2.04)|31 (30-32)|-0.09|0|
|h1-c64|caddy|3.44 (3.42-3.46)|0.53 (0.52-0.53)|0.32 (0.32-0.32)|2.74 (2.71-2.76)|68 (67-70)|0|0|
|h1-c64|traefik|3.45 (3.43-3.46)|0.75 (0.75-0.76)|0.47 (0.47-0.47)|1.86 (1.85-1.87)|119 (118-120)|0.01|0|
|h1-c64|direct|0 (0-0)|1.22 (1.03-1.31)|0.82 (0.7-0.86)|-|-|0.11|0|
|h1-c256|podgate|3.34 (3.33-3.34)|0.69 (0.69-0.69)|0.41 (0.41-0.41)|2.05 (2.04-2.05)|66 (54-68)|-0.1|0|
|h1-c256|caddy|3.48 (3.46-3.52)|0.55 (0.54-0.55)|0.33 (0.32-0.33)|2.74 (2.72-2.74)|93 (93-96)|0.01|0|
|h1-c256|traefik|3.45 (3.44-3.47)|0.77 (0.77-0.77)|0.47 (0.47-0.48)|1.87 (1.86-1.88)|169 (169-171)|0.01|0|
|h1-c256|direct|0 (0-0)|1.37 (1.29-1.48)|0.88 (0.82-0.96)|-|-|0.14|0|
|h1-16k|podgate|3.3 (3.28-3.3)|0.79 (0.79-0.79)|0.41 (0.41-0.42)|2.39 (2.39-2.4)|67 (61-67)|-0.07|0|
|h1-16k|caddy|3.2 (3.17-3.24)|0.76 (0.76-0.79)|0.31 (0.31-0.33)|3.15 (3.08-3.16)|71 (71-74)|0.01|0|
|h1-16k|traefik|3.34 (3.3-3.36)|0.9 (0.88-0.92)|0.49 (0.48-0.5)|2.09 (2.06-2.1)|123 (122-156)|0.01|0|
|h1-16k|direct|0 (0-0)|1.37 (1.17-1.47)|0.99 (0.85-1.06)|-|-|0.13|0|
|rate|podgate|1.31 (1.3-1.31)|0.27 (0.27-0.28)|0.15 (0.15-0.15)|2.11 (2.09-2.12)|33 (32-34)|0.21|0|
|rate|caddy|1.77 (1.76-1.77)|0.28 (0.27-0.28)|0.16 (0.16-0.16)|2.85 (2.84-2.85)|66 (65-68)|0.22|0|
|rate|traefik|1.2 (1.2-1.21)|0.27 (0.27-0.27)|0.16 (0.15-0.16)|1.94 (1.93-1.95)|116 (116-117)|0.32|1|
|rate|direct|0 (0-0)|0.26 (0.26-0.26)|0.15 (0.14-0.15)|-|-|0.18|0|
|tls-h1|podgate|3.38 (3.38-3.39)|0.87 (0.87-0.87)|0.47 (0.47-0.47)|1.79 (1.78-1.79)|74 (72-74)|-0.05|0|
|tls-h1|caddy|3.46 (3.45-3.48)|0.57 (0.56-0.58)|0.32 (0.32-0.32)|2.8 (2.77-2.81)|72 (71-74)|0|0|
|tls-h1|traefik|3.45 (3.44-3.46)|0.78 (0.78-0.79)|0.45 (0.45-0.45)|1.94 (1.94-1.95)|127 (125-130)|0|0|
|tls-h2|podgate|3.41 (3.41-3.42)|0.86 (0.86-0.87)|0.48 (0.48-0.49)|1.76 (1.75-1.76)|72 (71-72)|-0.06|0|
|tls-h2|caddy|3.41 (3.38-3.41)|0.59 (0.59-0.6)|0.21 (0.21-0.21)|4.27 (4.26-4.31)|71 (69-72)|0|0|
|tls-h2|traefik|3.47 (3.45-3.5)|0.81 (0.8-0.81)|0.29 (0.29-0.29)|3.13 (3.13-3.13)|124 (124-125)|0|0|

Idle RSS before the first request: podgate 16.7 MiB (10.7 before), Caddy 46.7 MiB, Traefik 87.9 MiB. podgate's peak RSS under load also rose, from 21 to 53 MiB to 30 to 74 MiB.

## What changed since 2026-11-20

Why podgate went from 232 k to 166 k req/s at `h1-c64` while Caddy and Traefik went the other way (113 k to 126 k, 163 k to 186 k). [INFERENCE] The first measurement's Go proxies had foreign load on their CPUs in some runs (its Noise section lists them); this run's machine was idle.

An extra pass, not part of the verdict tables: `h1-c64`, 15 s, interleaved over fresh process starts of three podgate builds, Traefik as the control in the first pass. Data: [`podgate-variants.jsonl`](../bench/results/2026-11-22/podgate-variants.jsonl).

|podgate build|Process starts|req/s per start|CPU s/100k req|
|---|---|---|---|
|The first measurement's code (`4b3834a`)|3|250.7 k, 250.5 k, 250.1 k|1.30|
|Current, as shipped (forwarding headers on)|9 (plus the 10th in the main run)|141.9 k to 198.8 k; 8 of 10 starts at 166 k (165.4 k to 167.6 k)|1.69 to 2.36|
|Current, `forwarded: {x_forwarded: false, real_ip: false}` on the app|9|177.7 k to 232.9 k, median 202 k|1.41 to 1.88|
|Traefik beside them (control)|9 runs|185.0 k to 188.8 k|1.83 to 1.86|

- **The rig did not drift.** The old build still gets 250 k beside a Traefik that did 186 to 187 k in every pass, a 1.35x lead, close to the first measurement's 1.4x. Nothing about the machine explains a fall to 166 k.
- **podgate's cost per request rose by 55%** (1.30 to 2.02 CPU s per 100k requests at the typical start) and the throughput follows it, since the proxy CPUs are saturated.
- **Forwarding headers are the largest single part that was isolated.** Switching them off for the app moves the median start from 166 k to 202 k req/s (+22%, about 0.4 CPU s/100k). Before, the backend received about 70 B per request from podgate; now it receives 196 B (five more headers: `X-Forwarded-For`, `-Proto`, `-Host`, `-Port`, `X-Real-IP`), which is more work for podgate to build and write and for the backend to read. Caddy adds 165 B and Traefik 242 B, so the first measurement compared podgate doing less work; this one compares like with like.
- **The rest is not attributed.** With forwarding off podgate is still 20% below the old build (202 k against 250 k). The other 480 commits changed the request path (route matching, the upstream address policy check on every connect, per-entry-point, router and service metrics, header and middleware stages, the v2 service model). No profile was taken: every `perf_event_open` call was denied on this machine, including software clocks, so no tool could say which of them costs what. [INFERENCE] Several small per-request costs added up; this is not shown.
- **Start-to-start spread, unexplained.** A podgate process keeps its speed once started (the 5 runs of a verdict, and the 2 runs after each fresh start in the extra pass, agree within 2%), but a fresh start of the same binary lands on a different level: 142 k, 166 k or 198 k as shipped, 178 k to 233 k with forwarding off. CPU per request differs with it (1.69 to 2.36), so the slow starts burn more CPU for the same work. The old build did not show it in 3 starts (250 k each). The cause is not known; the thread layout on the four pinned CPUs and the allocator are suspects, nothing was measured to separate them. Consequence for the verdicts: the 5 runs of one process start do not pin down podgate's `h1-*` numbers better than about +-15%. Against Caddy (126 k) podgate is faster at every start seen (lowest 142 k). Against Traefik (186 k) podgate was slower at 8 of 10 starts as shipped and faster at 2 (196 k and 198 k). That is why the `h1` verdicts against Traefik read "slower" and not "slower by exactly 1.12x".
- **TLS is not slower than plain HTTP here.** In the same process podgate does 189 k and 194 k req/s over TLS (1.8 CPU s/100k) against 166 k in plain `h1-c64` (2.0). TLS cannot cost less than no TLS, so something in the plain-HTTP run costs podgate more than TLS terminates. It is probably the same unexplained effect as the spread above, and it is why podgate's TLS verdicts stayed "faster" while the plain ones fell.

## What limited each result

Why not double? Each number has a limiter, measured and not assumed.

- **Max-rate scenarios (`h1-*`, `tls-*`): the proxy's CPUs.** On the 4 pinned proxy CPUs, `/proc/stat` over the steady-state window of every max-rate run shows the CPUs 93 to 98% busy (user, system, softirq):

  |Proxy|user|system|softirq|idle|
  |---|---|---|---|---|
  |podgate|56 to 66%|21 to 28%|11 to 14%|1.6 to 2.9%|
  |Caddy|57 to 72%|14 to 24%|8 to 15%|3 to 6.5%|
  |Traefik|58 to 70%|17 to 26%|10 to 14%|1.8 to 3.5%|

  The process counters (the "proxy cores" column, 3.2 to 3.5 of 4.0) undercount because the loopback softirq time is not charged to the proxy process. The generator and the backend are not limiting: `oha` used 0.7 to 0.9 of its 2 CPUs while driving podgate (1.2 to 1.4 when driving the backend directly, so it can go faster), and the backend used 0.4 to 0.5 of its 2 CPUs.
- **The rig's ceiling is 2.2x above the fastest proxy.** `direct` reaches 422 k to 448 k req/s at 64 and 256 connections (418 k with the 16 KiB body), against 194 k for the fastest proxy result. The backend is not the limiter for any proxy. `oha` straight at the backend is itself limited by `oha` and the backend sharing their 2 CPUs each, so the real ceiling is higher.
- **`rate`: the offered rate.** All proxies delivered 61992 req/s (the schedule), the table shows only their latency. The proxy CPU there was 1.3 (podgate), 1.8 (Caddy) and 1.2 (Traefik) cores of 4, so none was near its limit.
- **The ratios follow CPU cost per request.** podgate spent 1.8 to 2.4 CPU s per 100k requests, Traefik 1.9 to 3.1 and Caddy 2.7 to 4.3. With the CPU set saturated, throughput is the CPU budget divided by that cost. Counting softirq as well (the process counters miss it), the whole cost of a podgate `h1-c64` request is about 2.35 CPU s per 100k (3.9 busy cores over 166 k req/s), which is why the process-only 3.36 cores / 166 k looks lower. This is a consistency check on the limiter, not a profile of where the CPU goes. Where the cost differs from Traefik's: podgate pays 9 to 14% more per plain HTTP/1.1 request, 8% less per TLS HTTP/1.1 request and 44% less per TLS HTTP/2 request. [INFERENCE] Go's runtime, garbage collector and larger per-request header work are the likely sources of Caddy's and Traefik's extra cost in the TLS scenarios, particularly `tls-h2`; no profile was taken.
- **Scaling check not repeated.** The first measurement ran a pass with the proxy on 2 CPUs while another project loaded the machine; it was inconclusive and is not repeated here (`bench/results/2026-11-20/limiter-2cpu.jsonl`).
- **podgate's own admission control acted on most requests and did not refuse any.** podgate has no switch for the per-backend adaptive limit and fair queue, so there is no "limiter off" run; the numbers are as shipped. `GET /metrics` before and after each run shows `podgate_backend_waited_total` rose for 80 to 100% of the requests (they queued for a slot), the learned limit peaked at 8 to 28 concurrent upstream requests (from 64 or 256 offered), `podgate_backend_refused_total` and `podgate_tenant_inflight_rejected_total` did not move in any run. Per-run values are in `runs.jsonl` (`podgate_waited`, `podgate_refused`, `podgate_tenant_rejected`, `podgate_limit_max`). With a 0 ms backend the limit settles low and requests wait briefly; with a real backend that takes milliseconds the limit would be far higher. Whether that wait costs podgate throughput was not measured.
- **Keep-alive to the backend held on all three.** The backend counts accepted connections. Over every measured run, each proxy opened few new upstream connections: podgate 3 in each of two runs, Caddy 47 in one run (`h1-c256` run 1) and Traefik 11 in one run (`h1-c256` run 1), all other runs 0, while serving 0.9 to 2.9 million requests per run; `direct` opened one per `oha` connection. A pool that reconnected per request would show millions.

## Noise

The machine is shared (8 cores, 16 threads) and other projects' builds and tests can land on any CPU, including the pinned ones. This run was made while nothing else was running: the benchmark held `~/.cache/podgate-cargo.lock` and no other session was building or testing. Per run the script records the foreign CPU time on the proxy CPUs during the window (`other_cores_on_proxy_cpus`: busy time on those CPUs minus the proxy process's own), the foreign cores busy over 2 s before the run (`other_cores_before`) and the 1-minute load average (`load1`).

- Load average before the benchmark started: 0.68 (1 minute), 1.26 (5 minutes). Foreign cores busy before every run: 0.24 to 0.51 (median 0.31) against the script's limit of 3; no run waited for the machine to quiet down.
- `load1` per run ranged from 0.78 to 5.49, and was above 4 for 69 of 110 runs. That is the benchmark's own load (a 15 s run on 8 busy threads raises the 1-minute average by 2 or more and it stays raised across the next runs), so the gate is the 2 s CPU sample taken while the proxies idle, not `uptime`; `load1` is recorded but not gated on. This is a deviation from "wait while the 1-minute load average is above 4": it could not be met with the benchmark running, and no foreign load was present.
- Runs with more than 0.3 foreign cores on the proxy CPUs: 1 of 110 (`rate` Traefik run 3, 0.32). No run was removed or rerun; the run-to-run spread inside a verdict is 1 to 5% in throughput for every proxy (largest: Caddy `h1-16k`, 100 k to 105 k req/s, and Traefik `h1-16k`, 157 k to 163 k) and `rate` Traefik p99.9 spans 3.46 to 4.82 ms.
- Two false starts: the first attempt stopped at the snapshot push with `422 upstream_forbidden` (podgate's upstream address policy, denies loopback by default, and the script had no policy: fixed, see Tuning), and the second stopped because a random loopback port was taken by another process (`127.0.0.1:49338 is in use`). Neither produced a run.

## Versions and machine

|Item|Value|
|---|---|
|podgate|commit `9c075cc` (`src/` as of that commit; the benchmark commit adds `bench/upstream-policy.json` and one line in `scripts/bench-proxies.sh`, and `tests/h3.rs` changes only a test), `cargo build --release` (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`), rustc 1.99|
|Caddy|2.11.9 (as before)|
|Traefik|3.7.16 (as before)|
|oha|1.16.0 (as before)|
|Kernel|Linux 6.18.63|
|CPU|AMD Ryzen 7 9850X3D, 8 cores, 16 threads, `powersave` governor (as found, not changed)|
|Date|2026-11-22|

CPU sets (`taskset`), the same for every proxy: proxy on CPUs 0 to 3 (four threads on four different physical cores), `oha` on 4 and 5 (2 worker threads), the backend on 6 and 7. CPUs 8 to 15 are the SMT siblings of 0 to 7 and are left to the rest of the machine, so a foreign process can run on a sibling of a pinned core.

Thread counts: Caddy and Traefik run with `GOMAXPROCS=4`. podgate sets Pingora's `ServerConf.threads` to `std::thread::available_parallelism()` in `src/lib.rs`, which follows the CPU affinity, so it is 4 under `taskset` [INFERENCE: from the std documentation, the worker count was not read back]. At idle the processes had 21 (podgate; 12 before), 9 (Caddy) and 9 (Traefik) OS threads.

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
- **Load.** `oha 1.16 --output-format json -z 15s -w --disable-compression --worker-threads 2`, 2 s warm-up against the proxy under test (not recorded), then the measured 15 s. Plain scenarios use `http://127.0.0.1:<port>/` with `Host: a.test`; TLS scenarios use `https://a.test:<port>/` with `--connect-to` so the SNI is `a.test` and `--insecure` for the self-signed certificate. `tls-h2` is `-c 16 -p 4 --http2` (64 streams in flight). `rate` is `-c 64 -q 62000 --latency-correction`, 62000 being half the slowest proxy's median in the first `h1-c64` pass, rounded down to 1000.
- **Order.** Per scenario, 5 runs, each run going through podgate, Caddy, Traefik (and `direct` in plain scenarios) in that order. All three proxies stay running and idle while another is measured, each on the same CPUs; before every run the script waits up to 60 s for the machine to be quiet.
- **CPU and memory.** `utime + stime` from `/proc/<pid>/stat` of the proxy, `oha` and the backend at 2 s and 13 s into the run (an 11 s steady-state window); peak RSS from `VmHWM` after `echo 5 > /proc/<pid>/clear_refs` at the end of warm-up; idle RSS after start-up and the first probes. `/proc/stat` over the proxy CPUs gives the foreign load and the user/system/softirq/idle split.
- **Errors.** Any non-200 response, any `oha` error or a backend request count that differs from `oha`'s marks the run `FAILED RUN` and makes the script exit 1. 503s from rejections would count here, never as throughput; none occurred.
- **Statistics.** Median and range of 5. A gap smaller than the run-to-run range is called no measurable difference. No rank-sum test was run: the "faster" verdicts are the ones with non-overlapping ranges. One process start per proxy means start-to-start variation is not in those ranges; see "What changed since 2026-11-20".
- **Attribution pass.** `h1-c64` only, 1 run (3 starts) or 2 runs (6 starts) of 15 s per fresh process start, each variant started in turn, with the script and the same CPU sets. The old build is `git archive 4b3834a` built with the same release profile; its own script and v1 snapshot were used. The forwarding-off variant is the same script and binary with `"forwarded": {"x_forwarded": false, "real_ip": false}` added to the app of a scratch copy of `bench/podgate-snapshot.json.in`.

## Caveats

- **Loopback, one machine.** No NIC, no packet loss, a 0 ms backend. The proxy's CPU cost is what is measured; real latency to a real backend, real TLS handshakes (all runs reuse connections) and many idle connections are not.
- **Shared box.** See Noise. This run was made on an idle machine; foreign work still lands on the SMT siblings of the pinned cores.
- **Not equal work, but closer.** Defaults kept: for a `curl` request the backend received 196 B from podgate (adds `X-Forwarded-For`, `-Proto`, `-Host`, `-Port` and `X-Real-IP`), 165 B from Caddy (adds `Via` and three `X-Forwarded-*` headers) and 242 B from Traefik (adds five `X-Forwarded-*`, `X-Real-Ip` and `Accept-Encoding: gzip`). The first measurement ran podgate with no forwarding headers; that is no longer true.
- **podgate's admission controls stayed on.** Adaptive limit and fair queue, tenant budgets, pool isolation, SNI check, the upstream address policy run as shipped; the benchmark does not say what each costs.
- **One process start per proxy in the verdicts.** podgate's `h1-*` numbers move by +-15% between fresh starts (see above); the verdict tables are one start's numbers.
- **Traefik sends `Accept-Encoding: gzip` upstream** (Go's transport default, not configurable in Traefik); the backend ignores it, so no response was compressed.
- **No HTTP/3.** podgate has an opt-in HTTP/3 front since change 0086; the benchmark leaves it off, and Caddy and Traefik were configured without it.
- **One workload.** 100 B and 16 KiB bodies, one host, one upstream, GET only, no request bodies, no long-lived connections, no slow clients, no WebSockets.
- **No profile.** Where the CPU goes inside podgate is not measured (see above).

## Rerun

```
devenv shell
cargo build --release --bin podgate --example fast_upstream --example bench_cert
flock ~/.cache/podgate-cargo.lock scripts/bench-proxies.sh
```

Takes about 36 minutes. `SCENARIOS`, `RUNS`, `DURATION`, `PROXIES`, `PROXY_CPUS`, `LOAD_CPUS` and `BACKEND_CPUS` change the run (see the header of the script); `OUT=<dir>` resumes a stopped run. The results here are in `bench/results/2026-11-22/`: `runs.jsonl` (every reported run), `run-log.txt` (the console output) and `podgate-variants.jsonl` (the attribution pass). The first measurement's files are in `bench/results/2026-11-20/`.
