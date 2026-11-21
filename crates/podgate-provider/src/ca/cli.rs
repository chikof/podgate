//! The `ca` command of `podgate-provider`: `init`, `export-root`, `status`, `issue`, `rotate`.
//!
//! Every subcommand reads the `[ca]` section of the provider's configuration (`--config`), so
//! the directory and the suffixes are the ones the running provider uses.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use super::init::{
    INTERMEDIATE_DAYS, InitOptions, ROOT_DAYS, RotateOptions, init, rotate, write_new_secret,
};
use super::settings::CaSettings;
use super::trust::{export_root, status};
use super::{Ca, unix_now};
use crate::config::Config;

const USAGE: &str = "usage: podgate-provider ca <command> --config <file> [options]

  init         --root-key-out <path> [--allow-public-suffix] [--root-days N] [--intermediate-days N]
               make the root and the name-constrained intermediate; the root key goes to <path>
  export-root  [--pem-only]
               print the root certificate and its SHA-256 fingerprint
  status       show the expiry of the root, the intermediate and every leaf
  issue        --out <dir> [--days N] <name>...
               sign a leaf for the names under the CA's own rules, into <dir>
  rotate       --root-key <path> [--intermediate-days N]
               new intermediate under the same root, with the root key brought back for this command";

/// Exit status of a command that failed.
pub const EXIT_FAILED: u8 = 1;
/// Exit status of a command with wrong arguments.
pub const EXIT_USAGE: u8 = 2;

struct Args {
    config: PathBuf,
    flags: Vec<(String, Option<String>)>,
    names: Vec<String>,
}

const VALUE_FLAGS: [&str; 7] = [
    "--config",
    "--root-key-out",
    "--root-key",
    "--root-days",
    "--intermediate-days",
    "--out",
    "--days",
];
const SWITCHES: [&str; 2] = ["--allow-public-suffix", "--pem-only"];

fn parse(args: &[String]) -> anyhow::Result<Args> {
    let mut config = None;
    let mut flags = Vec::new();
    let mut names = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if VALUE_FLAGS.contains(&arg.as_str()) {
            let value = args
                .next()
                .with_context(|| format!("{arg} needs a value"))?
                .clone();
            if arg == "--config" {
                config = Some(PathBuf::from(value));
            } else {
                flags.push((arg.clone(), Some(value)));
            }
        } else if SWITCHES.contains(&arg.as_str()) {
            flags.push((arg.clone(), None));
        } else if arg.starts_with("--") {
            bail!("unknown option {arg}");
        } else {
            names.push(arg.clone());
        }
    }
    Ok(Args {
        config: config.context("--config <file> is required")?,
        flags,
        names,
    })
}

impl Args {
    fn value(&self, flag: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(name, _)| name == flag)
            .and_then(|(_, value)| value.as_deref())
    }

    fn switch(&self, flag: &str) -> bool {
        self.flags.iter().any(|(name, _)| name == flag)
    }

    fn days(&self, flag: &str, default: u32) -> anyhow::Result<u32> {
        match self.value(flag) {
            None => Ok(default),
            Some(text) => text
                .parse::<u32>()
                .ok()
                .filter(|days| *days > 0)
                .with_context(|| format!("{flag} must be a whole number of days, at least 1")),
        }
    }

    fn required(&self, flag: &str) -> anyhow::Result<&str> {
        self.value(flag)
            .with_context(|| format!("{flag} is required"))
    }
}

fn settings(path: &Path) -> anyhow::Result<(Config, CaSettings)> {
    let config =
        Config::load(path).with_context(|| format!("invalid configuration {}", path.display()))?;
    let settings = config
        .ca
        .clone()
        .context("the configuration has no [ca] section with enabled = true")?;
    Ok((config, settings))
}

/// Runs `ca` with the arguments after its name, writing results to `out` and problems to `err`.
/// Returns the exit status.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let Some((command, rest)) = args.split_first() else {
        let _ = writeln!(err, "{USAGE}");
        return EXIT_USAGE;
    };
    let parsed = match parse(rest) {
        Ok(parsed) => parsed,
        Err(why) => {
            let _ = writeln!(err, "{why:#}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    let result = match command.as_str() {
        "init" => run_init(&parsed, out),
        "export-root" => run_export(&parsed, out),
        "status" => run_status(&parsed, out),
        "issue" => run_issue(&parsed, out),
        "rotate" => run_rotate(&parsed, out),
        other => {
            let _ = writeln!(err, "unknown command {other:?}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match result {
        Ok(()) => 0,
        Err(why) => {
            let _ = writeln!(err, "{why:#}");
            EXIT_FAILED
        }
    }
}

fn run_init(args: &Args, out: &mut dyn Write) -> anyhow::Result<()> {
    let (_, settings) = settings(&args.config)?;
    let mut options = InitOptions::new(
        settings.dir.clone(),
        PathBuf::from(args.required("--root-key-out")?),
        settings
            .allowed_suffixes
            .iter()
            .map(ToString::to_string)
            .collect(),
    );
    options.allow_public_suffix = args.switch("--allow-public-suffix");
    options.root_days = args.days("--root-days", ROOT_DAYS)?;
    options.intermediate_days = args.days("--intermediate-days", INTERMEDIATE_DAYS)?;
    let made = init(&options)?;
    let suffixes: Vec<&str> = made.suffixes.iter().map(|suffix| suffix.as_str()).collect();
    writeln!(
        out,
        "CA initialized in {}\nroot key written to {}: store it offline and remove it from this machine\npermitted names: {}\nroot SHA-256 fingerprint: {}",
        options.dir.display(),
        options.root_key_out.display(),
        suffixes.join(", "),
        made.root_fingerprint
    )?;
    Ok(())
}

fn run_export(args: &Args, out: &mut dyn Write) -> anyhow::Result<()> {
    let (_, settings) = settings(&args.config)?;
    let root = export_root(&settings.dir)?;
    if !args.switch("--pem-only") {
        writeln!(out, "# SHA-256 fingerprint: {}", root.fingerprint)?;
    }
    write!(out, "{}", root.pem)?;
    Ok(())
}

fn run_status(args: &Args, out: &mut dyn Write) -> anyhow::Result<()> {
    let (_, settings) = settings(&args.config)?;
    write!(out, "{}", status(&settings.dir)?.render(unix_now()))?;
    Ok(())
}

fn run_issue(args: &Args, out: &mut dyn Write) -> anyhow::Result<()> {
    let (config, settings) = settings(&args.config)?;
    if args.names.is_empty() {
        bail!("give at least one name");
    }
    let dir = PathBuf::from(args.required("--out")?);
    let days = args.days("--days", settings.leaf_days)?;
    let ca = Ca::open(&settings, &config)?;
    let names: Vec<&str> = args.names.iter().map(String::as_str).collect();
    let leaf = ca.issue(&names, unix_now(), days)?;
    // The key file is the sensitive one: it is made new, mode 0600, in a directory made 0700.
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let stem: String = args
        .names
        .first()
        .map(|name| name.replace('*', "_wildcard"))
        .unwrap_or_default();
    let (cert_path, key_path) = (
        dir.join(format!("{stem}.cert.pem")),
        dir.join(format!("{stem}.key.pem")),
    );
    write_new_secret(&key_path, leaf.key.expose())?;
    write_new_secret(&cert_path, &leaf.chain_pem)?;
    writeln!(
        out,
        "certificate (leaf, then intermediate): {}\nkey: {}\nnot after: {}",
        cert_path.display(),
        key_path.display(),
        leaf.not_after
    )?;
    Ok(())
}

fn run_rotate(args: &Args, out: &mut dyn Write) -> anyhow::Result<()> {
    let (_, settings) = settings(&args.config)?;
    let rotated = rotate(&RotateOptions {
        dir: settings.dir,
        root_key: PathBuf::from(args.required("--root-key")?),
        intermediate_days: args.days("--intermediate-days", INTERMEDIATE_DAYS)?,
        now: unix_now(),
    })?;
    writeln!(
        out,
        "new intermediate written under root {}; restart the provider to use it, then remove the root key from this machine",
        rotated.root_fingerprint
    )?;
    Ok(())
}
