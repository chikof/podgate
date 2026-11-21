{pkgs, ...}: {
  imports = [./devenv.kind.nix];

  languages.rust = {
    enable = true;
    # rustup reads the same file outside Nix.
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = [
    pkgs.git
    pkgs.shellcheck
    pkgs.typos
    pkgs.cargo-deny
    pkgs.cargo-nextest
    pkgs.bacon
    pkgs.git-cliff # CHANGELOG.md, scripts/release.sh
    pkgs.cargo-edit # cargo set-version, scripts/release.sh
    pkgs.cmake # libz-ng-sys: pingora-core forces its zlib-ng backend
    pkgs.pebble # test ACME server
    pkgs.oha # HTTP load generator
    pkgs.valkey # test Redis-compatible store
    pkgs.caddy # proxy benchmark baseline
    pkgs.traefik # proxy benchmark baseline
  ];

  # Secrets and local overrides come from the gitignored .env file. See .env.example.
  dotenv.enable = true;

  # scripts/check.sh is the single gate.
  scripts.check.exec = ''
    exec "$DEVENV_ROOT/scripts/check.sh"
  '';

  enterShell = ''
    echo "podgate: run 'check'"
  '';

  # rustfmt and clippy are not hooks on purpose: `check` covers them and commits stay fast.
  git-hooks.hooks = {
    # commit-msg: Conventional Commits.
    convco = {
      enable = true;
      # nixpkgs exports LIBGIT2_NO_VENDOR=1, but convco 0.7.2 needs libgit2-experimental, which nixpkgs lacks.
      package = pkgs.convco.overrideAttrs (old: {
        preBuild = (old.preBuild or "") + "export LIBGIT2_NO_VENDOR=0\n";
      });
    };
    ripsecrets.enable = true;
    typos.enable = true;
    shellcheck = {
      enable = true;
      excludes = ["^\\.envrc$"];
    };
  };
}
