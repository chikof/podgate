# podgate

podgate is the ingress proxy for our PaaS. It is written in Rust on Cloudflare's Pingora, so a parsing bug cannot become a memory-safety bug. It has no config files, no labels and no service discovery: the PaaS control plane pushes versioned snapshots of tenants, apps and revisions, and podgate compiles each one into an immutable routing table or rejects it as a whole.

## Why not Traefik or Caddy

Each row is a failure class that Traefik or Caddy leave open and that podgate closes by design. Every row is a task spec in [`the project history`](the project history); none is built yet.

|Idea|What it prevents or enables|
|---|---|
|Fail-closed snapshot compiler|Conflicting declarations are rejected whole instead of merged into a weaker policy. Traefik: GHSA-p8wx-ph99-xgcr, GHSA-rv2h-qh7j-xrjw, GHSA-qvj7-gq9c-hp7q, GHSA-ccgh-9g52-6vwg.|
|Event feed and drain handshake|The control plane learns when a draining revision has no requests left, with no metrics polling.|
|Snapshot plan, apply and auto-revert|A dry run lists every security relaxation. A change that spikes 5xx reverts itself.|
|Explain API with route provenance|Answers why a request goes where it goes, from the live routing table.|
|Enforce SNI matches Host|A TLS request whose Host differs from its SNI gets 421. Traefik: GHSA-fh26-gfpp-7xxx.|
|Isolated upstream connection pools|No upstream connection is shared across tenants, and NTLM or Negotiate connections never leave their client. Traefik: GHSA-hrpp-p4fc-wwf8, GHSA-p956-6gvv-mxqp, GHSA-53qr-784g-cj35, GHSA-xv5x-242w-7hf7.|
|Per-request and per-tenant memory budgets|Compression degrades to identity instead of exhausting memory. Traefik: GHSA-x5pf-cqh3-2gv8.|
|Per-tenant fair queuing and adaptive concurrency|One tenant's flood cannot starve another. Backend concurrency follows backend latency.|
|Skew protection|A browser session stays on the revision that served its first request during a rollout.|
|SLO-driven canary|A canary gains traffic only while healthy, and the control plane hears about a regression.|
|Scale-to-zero with wake on request|A sleeping app wakes on its first request instead of answering 503.|
|HA ACME with ARI and on-demand TLS|Certificates are issued and renewed without a single owning node. Preview hosts get certificates on first use.|
|Record failed requests for replay|The last failed requests per app are visible with secrets redacted, and replayable against another revision.|
|WASM extensions with fuel and capability limits|Apps attach request filters that cannot hang the proxy or reach sockets or files.|

No HTTP/3 yet: Pingora 0.9 has no HTTP/3 server, while Caddy and Traefik ship one.

## Setup

With Nix, `direnv allow` (or `devenv shell`) gives you the pinned Rust toolchain, the tools and the git hooks.
Without Nix, install the toolchain from `rust-toolchain.toml`, `cargo-deny`, `cargo-nextest`, `shellcheck`, `typos`, and for releases `git-cliff` and `cargo-edit`.

```sh
check                         # fmt, clippy, tests, docs, cargo-deny, shellcheck, typos (scripts/check.sh)
scripts/release.sh --dry-run  # next version and its changelog, from Conventional Commits
scripts/release.sh            # bump version, regenerate CHANGELOG.md with git-cliff, commit, tag
```

## Layout of the docs

- [`docs/architecture.md`](docs/architecture.md): code layout and where to add things.
- [`docs/rust-style.md`](docs/rust-style.md): style rules and which lint enforces each.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
