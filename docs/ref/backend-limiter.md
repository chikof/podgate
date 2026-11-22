# Backend limiter settings

podgate keeps one adaptive concurrency limit and one set of weighted fair queues per upstream socket address (`src/fairq.rs`, `docs/architecture.md` `## Backend admission`). The limit is learned from the latency the proxy observes, and tenants that wait for it share it by `Tenant.weight`. The operator can tune it without rebuilding podgate: turn it off, or change its limits, window, tolerance, queue size and queue wait, for every backend or for chosen upstream addresses. Code in `src/fairq/settings.rs`.

The settings are a JSON file named by `BACKEND_LIMITER_FILE`, read once at startup. They are never part of a snapshot and no snapshot field can change them: the limiter of an address is shared by every tenant behind it and carries the fairness between them, so no tenant may tune it. With the variable unset every backend runs with the built-in values, exactly as before the file existed.

## The file

```json
{
  "default": { "max_limit": 512, "queue_wait_ms": 2000 },
  "backends": {
    "10.0.0.0/8": { "initial_limit": 64 },
    "10.1.2.3:8080": { "enabled": false },
    "[fd00::5]:9000": { "queue_size": 64, "queue_wait_ms": 250 }
  }
}
```

| Key | Meaning |
|---|---|
| `default` | A block applied to every backend before any entry. Optional. |
| `backends` | Entries by address. Optional. A key is an exact `ip:port` (`10.1.2.3:8080`, `[fd00::5]:9000`), a CIDR (`10.0.0.0/8`) or a bare address (`10.1.2.3`, every port). |

A block (`default` or an entry) sets any of the fields below. A field it leaves out comes from the blocks below it.

## Fields

| Field | Built-in default | Range | Meaning |
|---|---|---|---|
| `enabled` | `true` | `true` or `false` | `false`: no adaptive limit and no queue. Every request to the backend is admitted at once and the latency it measures is ignored. The tenant's `max_inflight` still applies. |
| `initial_limit` | `32` | 1 to 1000000, between `min_limit` and `max_limit` | The concurrency limit a new backend starts with. Left unset it is 32 moved into the range of `min_limit` and `max_limit`. |
| `min_limit` | `4` | 1 to 1000000, at most `max_limit` | The limit never falls below this, so a backend with a bad window still gets traffic to measure. |
| `max_limit` | `2048` | 1 to 1000000, at least `min_limit` | The limit never grows past this. |
| `window_samples` | `16` | 1 to 65536 | Latency samples per estimate update. A smaller window reacts faster and is noisier. |
| `tolerance` | `1.25` | 1.0 to 10.0 | How far the window's mean latency may rise over the baseline before the limit shrinks. |
| `min_gradient` | `0.5` | 0.1 to 1.0 | The strongest shrink of one update: `0.5` halves the limit before smoothing, `1.0` never shrinks it. |
| `smoothing` | `0.2` | 0.01 to 1.0 | Share of the new target each update takes. `1.0` jumps straight to it. |
| `baseline_drift` | `1.0001` | 1.0 to 2.0 | Per-window upward creep of the baseline latency while the limit is above `min_limit`. A larger value accepts a slower backend as normal sooner. |
| `queue_size` | `512` | 0 to 65536 | Most requests one tenant may have waiting for the backend. The next one gets `503`. `0` means no queue: a request that finds the limit reached gets `503` at once. |
| `queue_wait_ms` | `5000` | 1 to 600000 | Longest a request waits for a slot, in milliseconds, before it gets `503`. |

The built-in values are the constants of `src/fairq.rs`. The fixed-point constants of the fair queue (`SCALE`, `MAX_WEIGHT`) are internal and have no setting. A `503` from the limiter carries `retry-after: 1` and `{"error":"backend is saturated"}`.

## Which entry applies

An address takes the built-in values, then the `default` block, then every entry that matches it, from the least to the most specific. The most specific is an exact `ip:port`, then the longest CIDR prefix; a bare address is a prefix of 32 (IPv4) or 128 (IPv6). A field a more specific entry sets wins; a field it leaves out keeps the value of the less specific entries. The order of the keys in the file does not matter.

With the example above, `10.1.2.3:8080` is not limited, `10.1.2.3:9090` has `initial_limit` 64, `max_limit` 512 and `queue_wait_ms` 2000, and `192.168.0.1:80` has only the `default` block's changes.

The values of an address are resolved once, when its limiter is created, which is the first request that picks the address. A limiter that exists keeps them; there is no hot reload, so restart podgate to change a setting.

## A backend with the limiter off

With `enabled: false` the backend's `podgate_backend_limit` is `4294967295` (`u32::MAX`, `UNLIMITED` in the code) and never changes, and `podgate_backend_queued`, `podgate_backend_waited_total` and `podgate_backend_refused_total` stay `0`. `podgate_backend_inflight` still counts the requests holding the backend. The series are rendered as for any backend. Mirrored copies of a request are not held back either. The tenant's `max_inflight` and `max_buffer_bytes` still apply.

## Errors

A bad file stops startup with `invalid BACKEND_LIMITER_FILE: <path>: <field>: <reason>`. The field is `default.<name>` or `backends["<key>"].<name>`, or the key itself, or `file` for a syntax or structure error. These stop startup:

- a value that is not a number of the field's kind, or outside its range (`default.max_limit: -1 is not a whole number from 1 to 1000000`);
- `min_limit` above `max_limit`, or an `initial_limit` outside them (checked on the values an address ends with after every entry that covers it is applied);
- an unknown field or an unknown top-level key (the message quotes it, like `unknown field "max_limits"`);
- a key that is neither an `ip:port` nor an address or CIDR, a CIDR with host bits set (`10.0.0.1/8`) or a bad prefix;
- two keys for one address or range (`10.0.0.1` and `10.0.0.1/32`), or a key that appears twice;
- a file that cannot be read.

## Notes for operators

- Change 0115 measured the limiter at 4 to 8% of the throughput of a backend that answers in 0 ms on loopback, because 82 to 100% of the requests queued while the learned limit sat at 7 to 29. It was not measured against a backend that takes milliseconds. For a backend that is fast and never saturates, raise `min_limit` or set `enabled: false`; the cost is that nothing protects that backend from a surge except the tenants' `max_inflight`.
- Disabling the limiter also removes the fair share between tenants for that backend: with no queue there is nobody to order. Keep it on for a backend that several tenants share and that can be saturated.
