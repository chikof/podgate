# Benchmarks: podgate, Caddy and Traefik

How podgate compares with Caddy and Traefik as a Host-routing reverse proxy on one machine: throughput, latency at a fixed rate, errors, CPU and memory, over plain HTTP and TLS. One script, `scripts/bench-proxies.sh`, runs everything. Method and tuning are below the results, so every number can be rerun.

This is a loopback measurement on one shared machine with the proxies as they ship (podgate with its admission controls on). It compares configurations, not only code. Read the caveats before quoting a number.

## Verdicts

Each verdict is the median of 5 interleaved runs of 15 s. A verdict says "faster" only when the run ranges do not overlap.

|Scenario|podgate vs Caddy|podgate vs Traefik|Limiter|
|---|---|---|---|
|`h1-c64`: HTTP/1.1, 64 connections, 100 B body, max rate|faster (2.1x)|faster (1.4x)|proxy CPUs|
|`h1-c256`: as above, 256 connections|faster (2.0x)|faster (1.5x)|proxy CPUs|
|`h1-16k`: as `h1-c64`, 16 KiB body|faster (1.9x)|faster (1.25x)|proxy CPUs|
|`rate`: 56000 req/s fixed, 64 connections|same throughput (all three sustain it); p50 and p99 lower; p99.9 no measurable difference|same throughput; p50 and p99 lower; p99.9 no measurable difference|offered rate|
|`tls-h1`: TLS 1.3, HTTP/1.1, 64 connections|faster (2.3x), inconclusive on the exact ratio (Caddy runs disturbed)|faster (1.4x)|proxy CPUs|
|`tls-h2`: TLS 1.3, HTTP/2, 16 connections x 4 streams|faster (3.4x), exact ratio inconclusive (Caddy runs disturbed)|faster (2.2x)|proxy CPUs|
|CPU seconds per 100k requests|lower (1.3 to 1.7 against 2.8 to 5.1)|lower (1.3 to 1.7 against 2.0 to 3.6)|not applicable|
|Peak and idle memory|lower (idle 11 MiB against 47 and 88 MiB)|lower|not applicable|

Where the ratio is "inconclusive" the direction holds in every run, but the Go proxies' runs were disturbed by another project's processes on the pinned CPUs (see Noise), so the size of the gap is not pinned down. No scenario produced a non-2xx response or an error for any proxy (110 recorded runs, 0 non-2xx, 0 errors, backend request count equal to oha's count within 1 request).

What this does not say: that podgate is faster for your traffic. Caddy and Traefik do more per request by default (see Caveats), and the backend answers in microseconds, so these numbers measure proxy overhead only.

## Results

Median (min-max) of 5 runs per proxy and scenario, 15 s each, steady state. `direct` is `oha` straight at the backend with the same settings, the ceiling of the rig. Latencies are from `oha`'s own histogram (the `rate` scenario uses `--latency-correction`). Raw per-run data: [`bench/results/2026-11-20/runs.jsonl`](../bench/results/2026-11-20/runs.jsonl).

### Throughput and latency

|Scenario|Proxy|req/s|p50 ms|p99 ms|p99.9 ms|
|---|---|---|---|---|---|
|h1-c64|podgate|232131 (218051-242575)|0.26 (0.25-0.27)|0.81 (0.69-1)|3.54 (3.21-4.18)|
|h1-c64|caddy|112958 (45509-119284)|0.4 (0.39-0.8)|2.47 (2.09-8.92)|4.9 (4.59-15.35)|
|h1-c64|traefik|162703 (61596-176460)|0.31 (0.3-0.62)|1.82 (1.56-6.13)|4.13 (3.21-11.54)|
|h1-c64|direct|450471 (425488-481051)|0.14 (0.11-0.14)|0.22 (0.2-0.23)|4.13 (4.12-4.13)|
|h1-c256|podgate|243293 (240641-249735)|1.01 (1-1.01)|3.56 (2.82-4.1)|4.73 (4.62-5.38)|
|h1-c256|caddy|120987 (116331-123410)|1.81 (1.8-1.86)|6.25 (5.64-6.74)|9.43 (8.26-10.5)|
|h1-c256|traefik|166995 (136721-176022)|1.36 (1.31-1.58)|5.44 (4.54-7.07)|8.51 (6.92-12.62)|
|h1-c256|direct|442092 (407789-465322)|0.48 (0.47-0.49)|4.49 (4.48-4.65)|5.71 (5.46-6.36)|
|h1-16k|podgate|180836 (170094-192491)|0.33 (0.31-0.34)|1.14 (1.07-1.73)|5.17 (5.16-5.18)|
|h1-16k|caddy|97082 (85810-101129)|0.5 (0.48-0.55)|2.52 (2.39-3.04)|4.65 (4.23-5.46)|
|h1-16k|traefik|144949 (131197-149862)|0.36 (0.35-0.39)|1.9 (1.76-2.27)|4.42 (3.52-4.82)|
|h1-16k|direct|355938 (333803-392072)|0.15 (0.13-0.16)|0.39 (0.27-2.45)|4.27 (4.18-5.13)|
|rate|podgate|55992 (55992-55993)|0.23 (0.23-0.26)|1.07 (0.95-1.59)|2.68 (2.29-6.75)|
|rate|caddy|55993 (55992-55996)|0.43 (0.43-0.48)|2.63 (2.38-3.76)|6.32 (5.23-8.29)|
|rate|traefik|55992 (55992-55994)|0.32 (0.29-575.08)|2.34 (1.81-3485.74)|5.45 (4.23-3507.07)|
|rate|direct|55992 (55988-55995)|0.14 (0.12-0.15)|0.43 (0.37-0.86)|1.39 (1.07-2.17)|
|tls-h1|podgate|200146 (185247-222501)|0.28 (0.26-0.29)|1.2 (0.93-2.54)|4.23 (4.17-4.41)|
|tls-h1|caddy|85970 (51666-116705)|0.5 (0.4-0.78)|3.59 (2.18-6.68)|6.12 (4.72-11.94)|
|tls-h1|traefik|143112 (91939-170450)|0.34 (0.31-0.48)|2.37 (1.6-3.95)|5.6 (3.58-7.89)|
|tls-h2|podgate|193472 (178429-207230)|0.29 (0.29-0.3)|1.08 (0.87-1.46)|3.84 (1.78-4.25)|
|tls-h2|caddy|57730 (54001-60795)|0.83 (0.81-0.86)|5.18 (4.76-5.69)|8.41 (8.02-9.51)|
|tls-h2|traefik|88262 (72294-95044)|0.6 (0.57-0.69)|3.28 (2.63-4.3)|7.22 (5.51-8.36)|

In `rate`, Traefik's worst run contains one 575 ms p50 and a 3.5 s p99 stall; that run had 1.75 cores of foreign load on the proxy CPUs (see Noise). The median is unaffected.

### CPU and memory

CPU is cores of the proxy process (`utime + stime` of the whole process over the steady-state window, so 4.0 is all four pinned CPUs). "CPU s/100k" is that CPU time divided by the requests served in the window. Peak RSS is `VmHWM` after resetting it once warm-up ended. "Other cores max" is the largest foreign load on the proxy CPUs in any of the 5 runs, and "disturbed" counts runs with more than 0.3 foreign cores.

|Scenario|Proxy|Proxy cores|oha cores (of 2)|Backend cores (of 2)|CPU s/100k req|Peak RSS MiB|Other cores max|Disturbed runs|
|---|---|---|---|---|---|---|---|---|
|h1-c64|podgate|3.09 (3.07-3.2)|0.93 (0.91-0.96)|0.59 (0.57-0.61)|1.35 (1.32-1.41)|26 (21-27)|0.03|0|
|h1-c64|caddy|3.33 (1.9-3.37)|0.52 (0.25-0.53)|0.31 (0.14-0.32)|2.9 (2.82-4.17)|68 (40-71)|1.59|1|
|h1-c64|traefik|3.29 (1.53-3.4)|0.7 (0.28-0.74)|0.44 (0.16-0.47)|2.01 (1.92-2.49)|120 (55-122)|1.84|1|
|h1-c64|direct|0 (0-0)|1.39 (1.35-1.41)|0.81 (0.73-0.9)|-|-|0.57|4|
|h1-c256|podgate|3.19 (3.14-3.23)|0.97 (0.96-0.98)|0.6 (0.6-0.61)|1.3 (1.29-1.31)|50 (48-53)|0.02|0|
|h1-c256|caddy|3.39 (3.33-3.48)|0.54 (0.53-0.56)|0.32 (0.32-0.33)|2.83 (2.8-2.86)|68 (64-94)|0.11|0|
|h1-c256|traefik|3.35 (3.21-3.46)|0.73 (0.63-0.76)|0.45 (0.39-0.47)|2.03 (1.96-2.35)|110 (109-112)|0.21|0|
|h1-c256|direct|0 (0-0)|1.39 (1.25-1.45)|0.82 (0.76-0.89)|-|-|0.76|2|
|h1-16k|podgate|3.07 (2.88-3.08)|0.96 (0.95-1.01)|0.58 (0.54-0.61)|1.7 (1.6-1.71)|25 (21-48)|0.11|0|
|h1-16k|caddy|3.16 (2.99-3.18)|0.75 (0.68-0.78)|0.32 (0.28-0.33)|3.26 (3.14-3.48)|69 (65-76)|0.24|0|
|h1-16k|traefik|3.18 (3.08-3.28)|0.84 (0.77-0.87)|0.48 (0.42-0.5)|2.23 (2.19-2.35)|121 (118-128)|0.25|0|
|h1-16k|direct|0 (0-0)|1.28 (1.1-1.36)|0.84 (0.81-0.92)|-|-|1.09|3|
|rate|podgate|0.82 (0.81-0.82)|0.26 (0.26-0.26)|0.14 (0.14-0.15)|1.46 (1.45-1.47)|22 (22-25)|0.3|0|
|rate|caddy|1.66 (1.65-1.68)|0.27 (0.27-0.27)|0.15 (0.15-0.15)|2.96 (2.95-3.01)|38 (36-65)|0.21|0|
|rate|traefik|1.2 (1.15-1.53)|0.26 (0.26-0.29)|0.15 (0.15-0.17)|2.14 (2.05-2.74)|54 (53-129)|1.76|1|
|rate|direct|0 (0-0)|0.22 (0.2-0.25)|0.12 (0.11-0.14)|-|-|0.55|2|
|tls-h1|podgate|2.86 (2.72-3.21)|0.9 (0.86-0.98)|0.51 (0.48-0.57)|1.45 (1.42-1.53)|24 (22-28)|0.19|0|
|tls-h1|caddy|2.97 (2.13-3.39)|0.48 (0.32-0.56)|0.26 (0.17-0.31)|3.45 (2.9-4.13)|69 (43-74)|1.19|3|
|tls-h1|traefik|3.24 (2.65-3.43)|0.69 (0.53-0.8)|0.4 (0.28-0.46)|2.27 (2.01-2.88)|123 (55-131)|0.74|1|
|tls-h2|podgate|3.01 (2.72-3.13)|0.9 (0.88-1.01)|0.51 (0.47-0.52)|1.53 (1.43-1.62)|23 (23-26)|0.29|0|
|tls-h2|caddy|2.93 (2.8-3.12)|0.5 (0.48-0.52)|0.18 (0.17-0.19)|5.13 (5.07-5.24)|45 (43-47)|0.57|4|
|tls-h2|traefik|3.2 (3.01-3.32)|0.68 (0.63-0.73)|0.25 (0.24-0.26)|3.63 (3.49-4.16)|117 (59-129)|0.37|1|

Idle RSS before the first request: podgate 10.7 MiB, Caddy 47.1 MiB, Traefik 88.1 MiB.

## What limited each result

Why not double? Each number has a limiter, measured and not assumed.

- **Max-rate scenarios (`h1-*`, `tls-*`): the proxy's CPUs.** On the 4 pinned proxy CPUs, `/proc/stat` over the steady-state window shows 91 to 97% of the time busy (user, system, softirq) for every proxy, in the extra pass `limiter-4cpu.jsonl`:

  |Proxy|user|system|softirq|idle|
  |---|---|---|---|---|
  |podgate|53 to 54%|24 to 25%|14 to 15%|7 to 9%|
  |Caddy|69 to 71%|14 to 15%|8%|5 to 8%|
  |Traefik|67 to 69%|18%|10 to 11%|3 to 5%|

  The process counters (the "proxy cores" column, 2.9 to 3.4 of 4.0) undercount because the loopback softirq time is not charged to the proxy process. The generator and the backend are not limiting: `oha` used 0.9 to 1.0 of its 2 CPUs while driving podgate (1.4 when driving the backend directly, so it can go faster), and the backend used 0.6 of its 2 CPUs.
- **The rig's ceiling is 1.8x above the fastest proxy.** `direct` reaches 450k req/s at 64 connections (355k with the 16 KiB body), against 243k for podgate at best. The backend is not the limiter for any proxy. `oha` straight at the backend is itself limited by `oha` and the backend sharing their 2 CPUs each, so the real ceiling is higher.
- **`rate`: the offered rate.** All proxies delivered 55992 req/s (the schedule), the table shows only their latency. The proxy CPU there was 0.8 (podgate), 1.7 (Caddy) and 1.2 (Traefik) cores of 4, so none was near its limit.
- **The ratios follow CPU cost per request.** podgate spent 1.3 to 1.7 CPU s per 100k requests, Traefik 2.0 to 3.6 and Caddy 2.8 to 5.1. With the CPU set saturated, throughput is the CPU budget divided by that cost: 4 cores / 1.35 CPU s per 100k = 296k req/s for podgate against the 232k measured (the gap is the softirq share and the idle 9%). This is a consistency check on the limiter, not a profile of where the CPU goes. [INFERENCE] Go's runtime, garbage collector and larger per-request header work are the likely sources of the difference; no profile was taken.
- **Scaling check, inconclusive.** A pass with the proxy on 2 CPUs (`limiter-2cpu.jsonl`, `h1-c64`, 3 runs) ran while another project loaded the machine (1 to 1.4 foreign cores on the pinned CPUs, `direct` dropped to 252k req/s). It shows 108k (podgate), 26k (Caddy) and 39k (Traefik) req/s with 3 to 5% idle, which fits CPU limits but is too disturbed to quote a scaling factor.
- **podgate's own admission control acted on most requests and did not refuse any.** podgate has no switch for the per-backend adaptive limit and fair queue, so there is no "limiter off" run; the numbers are as shipped. `GET /metrics` before and after each run shows `podgate_backend_waited_total` rose for 85 to 97% of the requests (they queued for a slot), the learned limit peaked at 6 to 25 concurrent upstream requests (from 64 or 256 offered), `podgate_backend_refused_total` and `podgate_tenant_inflight_rejected_total` did not move in any run. Per-run values are in `runs.jsonl` (`podgate_waited`, `podgate_refused`, `podgate_tenant_rejected`, `podgate_limit_max`). With a 0 ms backend the limit settles low and requests wait briefly; with this backend that did not reduce podgate's throughput below the others'. What it costs, or saves, against a limiter-off podgate is not measured.
- **Keep-alive to the backend held on all three.** The backend counts accepted connections. Over every measured run, each proxy opened at most 4 new upstream connections per run, and only podgate did (4 and 1 at `h1-c256`, 3, 1 and 2 at `tls-h2`; Caddy and Traefik opened 0 in every run), while serving 0.7 to 3.7 million requests per run; `direct` opened one per `oha` connection. A pool that reconnected per request would show millions.

## Noise

The machine is shared (8 cores, 16 threads) and another project's test runs (`cargo test` of a different crate) load it without pinning, so they land on any CPU, including the pinned ones. Per run the script records the foreign CPU time on the proxy CPUs during the window (`other_cores_on_proxy_cpus`: busy time on those CPUs minus the proxy process's own), the foreign cores busy over 2 s before the run (`other_cores_before`) and the 1-minute load average (`load1`).

- Load average per run ranged from 1 to 16; foreign cores before a run from 0.4 to 15.6 (the 15.6 runs waited the full 60 s and ran anyway, flagged).
- The script's own load pollutes the 1-minute load average (a 15 s run on 8 busy threads raises it, estimated by 2 or more), so the gate is the 2 s CPU sample taken while the proxies idle, not `uptime`; `load1` is recorded but not gated on. This is a deviation from "wait while 1-minute load is above 3".
- First pass: 27 runs had more than 0.3 foreign cores on the proxy CPUs. They were removed and rerun at the end of the sequence; a second pass did the same for 13 reruns that were still above 0.3 (the 40 removed runs are in `replaced-noisy-runs.jsonl`). Reruns break strict interleaving for those cells. After that, 13 runs were still above 0.3 (listed below) and stayed in the data.
- Disturbed runs that remain (foreign cores on the proxy CPUs): `h1-c64` Caddy run 3 (1.59), Traefik run 3 (1.84); `rate` Traefik run 2 (1.75); `tls-h1` Caddy runs 1, 4, 5 (1.18, 0.80, 0.34) and Traefik run 4 (0.73); `tls-h2` Caddy runs 1, 2, 4, 5 (0.57, 0.44, 0.37, 0.45) and Traefik run 4 (0.37). Four of five `tls-h2` Caddy runs were disturbed, so its absolute number is a lower bound and its ratio against podgate is inconclusive. The direction of every verdict holds in each of those runs against podgate's undisturbed median.
- One crash: the first full pass stopped in `h1-16k` at Traefik run 1 (`oha`'s process had vanished before a CPU sample; its JSON was complete, and a repeat of that exact scenario did not reproduce it). The cause is not known. The script gained resume (`OUT=<dir>`) and a clearer error, and the run continued from there. One restart was a port clash with another process on a random port.

## Versions and machine

|Item|Value|
|---|---|
|podgate|commit `a22f5d2` plus the benchmark files of this spec (no `src/` change), `cargo build --release` (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`), rustc 1.99|
|Caddy|2.11.9|
|Traefik|3.7.16 (go1.26.11)|
|oha|1.16.0|
|Kernel|Linux 6.18.63|
|CPU|AMD Ryzen 7 9850X3D, 8 cores, 16 threads, `powersave` governor (as found, not changed)|
|Date|2026-11-20|

CPU sets (`taskset`), the same for every proxy: proxy on CPUs 0 to 3 (four threads on four different physical cores), `oha` on 4 and 5 (2 worker threads), the backend on 6 and 7. CPUs 8 to 15 are the SMT siblings of 0 to 7 and are left to the rest of the machine, so a foreign process can run on a sibling of a pinned core.

Thread counts: Caddy and Traefik run with `GOMAXPROCS=4`. podgate sets Pingora's `ServerConf.threads` to `std::thread::available_parallelism()` in `src/lib.rs`, which follows the CPU affinity, so it is 4 under `taskset` [INFERENCE: from the std documentation, the worker count was not read back]. At idle the processes had 12 (podgate), 9 (Caddy) and 9 (Traefik) OS threads.

## Tuning, per proxy

All three: loopback, one upstream address, one app `a.test`, HTTP/1.1 keep-alive to the backend, the same ECDSA P-256 self-signed certificate and key (`examples/bench_cert.rs`), TLS 1.3 negotiated, response compression off, no access log, no metrics, no dashboard. The configs are rendered from `bench/*.in`.

|Proxy|Config|Defaults changed, and why|
|---|---|---|
|podgate|`bench/podgate-snapshot.json.in`, pushed with `PUT /v1/snapshot` on the admin socket; the script adds the certificate|`RUST_LOG=warn` (production logging). Tenant budget `max_inflight` 1,000,000 and `max_buffer_bytes` 1 GiB so no budget acts. No filters, canary, skew secret, scale-to-zero or recording. Compression is the shipped gzip, which only compresses text-like types; the backend sends `application/octet-stream` and `oha` sends no `Accept-Encoding`, so it never runs. Nothing else changed.|
|Caddy|`bench/Caddyfile.in`|`admin off`; `auto_https off` (the certificate is given); global log level `ERROR`; no `log` directive, so no access log; `servers { protocols h1 h2 }`, which drops HTTP/3 (Pingora has none and Traefik's is off by default); `keepalive_idle_conns_per_host 1024` (the default 32 would reconnect at 64 and more connections); `versions 1.1` and `compression off` toward the backend; an explicit `respond 404` site for unknown Hosts, because Caddy answers an empty 200 when no site matches.|
|Traefik|`bench/traefik.yml.in`, `bench/traefik-dynamic.yml.in`|`checkNewVersion` and `sendAnonymousUsage` off; log level `ERROR`; no `accessLog`, `api`, `metrics` or `ping` (all off unless configured); `serversTransport.maxIdleConnsPerHost: 1024` (default 200); file provider with `watch: false`. HTTP/2 is on by default on TLS entry points.|

## Method

- **Backend.** `examples/fast_upstream.rs`: keep-alive HTTP/1.1, preformatted responses, no per-request allocation, `GET /` returns 100 bytes, `GET /16k` returns 16 KiB, `application/octet-stream`. It counts accepted connections and served requests (`GET /__stats`). The script reads these before and after each run: the backend's request count must match `oha`'s within 0.5% (all 110 runs matched within 1 request), which is the proof that the requests reached the backend.
- **Correctness probe.** Before every run, `curl` checks that each proxy returns the backend's exact 100 B and 16 KiB bodies for `Host: a.test`, answers 404 for `Host: unknown.test` over HTTP, and returns the body over TLS with HTTP/1.1 and with HTTP/2 (`curl` reports HTTP version 2). Any failure stops the script.
- **Load.** `oha 1.16 --output-format json -z 15s -w --disable-compression --worker-threads 2`, 2 s warm-up against the proxy under test (not recorded), then the measured 15 s. Plain scenarios use `http://127.0.0.1:<port>/` with `Host: a.test`; TLS scenarios use `https://a.test:<port>/` with `--connect-to` so the SNI is `a.test` and `--insecure` for the self-signed certificate. `tls-h2` is `-c 16 -p 4 --http2` (64 streams in flight). `rate` is `-c 64 -q 56000 --latency-correction`, 56000 being half the slowest proxy's median in the first `h1-c64` pass, rounded down to 1000.
- **Order.** Per scenario, 5 runs, each run going through podgate, Caddy, Traefik (and `direct` in plain scenarios) in that order. All three proxies stay running and idle while another is measured, each on the same CPUs; before every run the script waits up to 60 s for the machine to be quiet.
- **CPU and memory.** `utime + stime` from `/proc/<pid>/stat` of the proxy, `oha` and the backend at 2 s and 13 s into the run (an 11 s steady-state window); peak RSS from `VmHWM` after `echo 5 > /proc/<pid>/clear_refs` at the end of warm-up; idle RSS after start-up and the first probes. `/proc/stat` over the proxy CPUs gives the foreign load and the user/system/softirq/idle split.
- **Errors.** Any non-200 response, any `oha` error or a backend request count that differs from `oha`'s marks the run `FAILED RUN` and makes the script exit 1. 503s from rejections would count here, never as throughput; none occurred.
- **Statistics.** Median and range of 5. A gap smaller than the run-to-run range is called no measurable difference. No rank-sum test was run: the "faster" verdicts are the ones with non-overlapping ranges.

## Caveats

- **Loopback, one machine.** No NIC, no packet loss, a 0 ms backend. The proxy's CPU cost is what is measured; real latency to a real backend, real TLS handshakes (all runs reuse connections) and many idle connections are not.
- **Shared box.** See Noise. 13 of the 110 runs saw more than 0.3 foreign cores on the proxy CPUs; foreign work also lands on the SMT siblings of the pinned cores.
- **Not equal work.** Defaults kept: for a `curl` request the backend received 165 B from Caddy (adds `Via` and three `X-Forwarded-*` headers), 242 B from Traefik (adds five `X-Forwarded-*`, `X-Real-Ip` and `Accept-Encoding: gzip`) and about 70 B from podgate (adds nothing). Production deployments need forwarding headers; podgate does not add them today. This is some of the difference and it was not equalized.
- **podgate's admission controls stayed on.** Adaptive limit and fair queue, tenant budgets, pool isolation, SNI check run as shipped; the benchmark does not say what each costs.
- **Traefik sends `Accept-Encoding: gzip` upstream** (Go's transport default, not configurable in Traefik); the backend ignores it, so no response was compressed.
- **No HTTP/3.** Pingora 0.9 has no HTTP/3 server; Caddy and Traefik were configured without it.
- **One workload.** 100 B and 16 KiB bodies, one host, one upstream, GET only, no request bodies, no long-lived connections, no slow clients, no WebSockets.
- **The 2-CPU scaling pass is inconclusive** (see above).

## Rerun

```
devenv shell
cargo build --release --bin podgate --example fast_upstream --example bench_cert
flock ~/.cache/podgate-cargo.lock scripts/bench-proxies.sh
```

Takes about 40 minutes. `SCENARIOS`, `RUNS`, `DURATION`, `PROXIES`, `PROXY_CPUS`, `LOAD_CPUS` and `BACKEND_CPUS` change the run (see the header of the script); `OUT=<dir>` resumes a stopped run. The results here are in `bench/results/2026-11-20/`: `runs.jsonl` (every reported run), `replaced-noisy-runs.jsonl` (the 40 disturbed runs that were replaced), `limiter-4cpu.jsonl`, `limiter-2cpu.jsonl` and `run-log.txt` (the console output of all passes).
