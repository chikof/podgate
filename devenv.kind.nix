# Kind-specific devenv settings, merged into devenv.nix via `imports`.
{...}: {
  # podgate dev server: `devenv up` runs it; RUST_LOG feeds the tracing EnvFilter.
  processes.podgate.exec = "cargo run";
  env.RUST_LOG = "info,podgate=debug";
}
