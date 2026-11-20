#!/usr/bin/env bash
# The one gate: `check` (devenv) runs this. Done means this exits 0.
set -euo pipefail

cd "$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

# Concurrent runs queue here instead of running several full gates at once (RAM thrash).
if [ -z "${VJ_GATE_LOCKED:-}" ]; then
  mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
  VJ_GATE_LOCKED=1 exec flock "${XDG_CACHE_HOME:-$HOME/.cache}/vj-gate.lock" "$0" "$@"
fi

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo deny check
shellcheck scripts/*.sh
typos
