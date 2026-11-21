# The file source

Reference for `crates/podgate-provider/src/file.rs`: the provider source that reads apps from YAML, TOML or JSON files and picks up edits without a restart. It matches Traefik's File provider (`filename`, `directory`, `watch`) and Caddy's JSON config. There is no templating: a generator that needs one runs outside podgate and writes the files.

## Configuration

```toml
[[source]]
kind = "file"
name = "files"
path = "/etc/podgate/apps.d"
poll_ms = 1000
tenant = "acme"
```

| Key | Default | Meaning |
|---|---|---|
| `path` | required | A file, or a directory. In a directory every `*.yaml`, `*.yml`, `*.toml` and `*.json` file counts (extension case-insensitive, no recursion). Files that start with `.` (editor swap and lock files), other extensions and sub-directories are ignored with a debug line. Symbolic links are followed, so Kubernetes ConfigMap mounts work. |
| `poll_ms` | `1000` | The interval of the watch. At least `10`. |
| `tenant` | `default` | The tenant the operator maps this source to. Every app and certificate of the source belongs to it. |
| `format` | `podgate` | `podgate`: the files are partial snapshots, as below. `traefik`: the files are Traefik dynamic configuration, one app per file, translated by the converter of `docs/ref/provider-traefik-file.md`. |

Unknown keys are errors: a misspelt `tenant` must not move the apps to the default tenant. An explicit `path` to a file with another extension is a parse error of that file.

Limits: a file of more than 1 MiB (`MAX_FILE_BYTES`) is reported like a broken file, and a directory with more than 256 matching files (`MAX_FILES`) is an outage. Dropping the extra files would delete their apps.

## File format

A partial snapshot in the shape of `podgate-model`: `{apps: [App...], certificates: [Certificate...]}`. All three formats decode into the same JSON value first, so one app is the same app in each. The example is `deploy/podgate-file.example.yaml`.

- Unknown top-level keys are errors, and so are unknown fields where the model denies them (the daemon rejects unknown kind fields as well).
- `tenants` is ignored with a warning: tenants, weights and budgets come from the provider configuration only (`docs/ref/provider.md`), so a file cannot invent a tenant or raise a budget.
- `tenant` and `declared_by` of an app are optional and never trusted. An app without `tenant` takes the source's tenant. An app that names another tenant makes a label claim, which only counts for tenants that list the source in `label_sources` (finding `label_ignored` otherwise). A name that is not a configured tenant drops the app (`unknown_tenant`); it is never defaulted.
- A file is operator-authored, so servers are explicit `url`s. The upstream policy (`docs/ref/upstream-policy.md`) and the provider's preflight apply to them, and a tenant's app may only claim the tenant's hosts (`foreign_host_claim`). The merge does both, not this source.
- A certificate belongs to the source's tenant and follows the same host rule.
- An empty file, or one with only comments, is an error, not "no apps": an editor that truncates before it writes would otherwise delete the apps for a moment. Write `apps: []` to declare none.

`declared_by` is `file/<source name>:<path>#<app id>`; podgate names it in conflicts. App ids in the snapshot are `<source name>-<app id>`. A certificate's object is `<path>#certificate-<index>`.

`first_seen` is `0` for every file object: a file has no creation time a source can rely on (mtime changes on every edit, birth time is not portable), and the time the provider first read it would reorder winners after a restart. A host conflict between file objects falls back to source and object name, which is stable across restarts.

## Watching

The source polls every `poll_ms`; it uses no new dependency and behaves the same on every filesystem, including the bind mounts containers use.

- A file is looked at again when its identity (device and inode), size, modification time or change time moved. The change time catches an in-place write that restores the modification time. The inode catches an atomic rename-replace.
- A file modified in the last 3 seconds is read on every poll, because a second write within one timestamp tick would leave the stamp unchanged.
- A read counts only when the stamp is the same before and after it, so a write that overlaps the read is picked up on the next poll rather than parsed half-way.
- A changed file is hashed; the content is parsed only when the hash differs from the last parsed one, so a `touch` sends nothing.
- One poll sends one update with the state of all files. The provider's debounce (`debounce_ms`) coalesces updates before the push, so an edit reaches podgate within about `poll_ms` plus `debounce_ms`.
- A removed file removes its apps. The configured path itself disappearing (a single file deleted, a directory unmounted) is an outage, not "no apps": the last state stays in force.
- The first scan sends a state only when every file parsed. Until then the source reports an outage and nothing is pushed: the broken file has no last good content, and a push without its apps would delete them.

## A broken file

A file that cannot be read or parsed keeps its last good content, is reported as an outage of the source (`Status::outages`, a warning in the log) naming the file and the error with its line, and does not block the other files, whose edits continue to be pushed. When the file parses again, the next state clears the report. A file that was never good contributes nothing until it is.

`check` and `print` run one pass and fail on an outage, so a broken file at startup is an error there.

## Why not inotify

A watcher misses events on bind mounts, network filesystems and some container runtimes, and needs a platform-specific crate. Polling stats a handful of files per interval; the content is read only when a stamp moved.
