//! The `podgate-provider` program: `run`, `print` and `check`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use podgate_provider::quarantine::Verdict;
use podgate_provider::{Config, Engine, UpstreamPolicy};
use tracing::error;
use tracing_subscriber::EnvFilter;

/// How long `print` and `check` wait for every source to report once.
const COLLECT_WAIT: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: podgate-provider <run|print|check> --config <file>

  run     merge the sources and keep pushing the snapshot to the admin socket
  print   merge once and print the snapshot JSON; pushes nothing
  check   merge once and ask podgate whether it would accept the snapshot";

#[derive(Clone, Copy)]
enum Command {
    Run,
    Print,
    Check,
}

fn parse_args(args: impl Iterator<Item = String>) -> anyhow::Result<(Command, PathBuf)> {
    let mut args = args.skip(1);
    let command = match args.next().as_deref() {
        Some("run") => Command::Run,
        Some("print") => Command::Print,
        Some("check") => Command::Check,
        _ => bail!("{USAGE}"),
    };
    let mut config = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().map(PathBuf::from),
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }
    let config = config.with_context(|| format!("--config <file> is required\n{USAGE}"))?;
    Ok((command, config))
}

/// Registers the sources of `config` with the engine.
///
/// Every source module adds one arm here. A kind that is not built into this binary is an
/// error, never skipped: a missing source would silently delete its routes.
fn register_sources(_engine: &mut Engine, config: &Config) -> anyhow::Result<()> {
    if let Some(source) = config.sources.first() {
        bail!(
            "source {:?}: kind {:?} is not built into this binary",
            source.name,
            source.kind
        );
    }
    Ok(())
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        // Without a SIGTERM handler the process still stops on Ctrl-C and on SIGKILL.
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn execute(command: Command, config_path: PathBuf) -> anyhow::Result<ExitCode> {
    let config = Config::load(&config_path)
        .with_context(|| format!("invalid configuration {}", config_path.display()))?;
    let policy = match &config.upstream_policy_file {
        Some(path) => UpstreamPolicy::load(path).context("invalid upstream policy file")?,
        None => UpstreamPolicy::builtin(),
    };
    let mut engine = Engine::new(config.clone(), policy);
    register_sources(&mut engine, &config)?;
    match command {
        Command::Run => {
            engine.run(shutdown()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Print => {
            let merged = engine.first_pass(COLLECT_WAIT).await?;
            println!("{}", merged.body(0));
            Ok(ExitCode::SUCCESS)
        }
        Command::Check => {
            let merged = engine.first_pass(COLLECT_WAIT).await?;
            match engine.validate(&merged).await {
                Ok(Verdict::Valid) => {
                    println!("valid: podgate would accept the snapshot");
                    Ok(ExitCode::SUCCESS)
                }
                Ok(Verdict::Rejected(conflicts)) => {
                    println!("rejected: {}", serde_json::Value::Array(conflicts));
                    Ok(ExitCode::FAILURE)
                }
                Err(why) => bail!("cannot validate: {why}"),
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    // `try_init` fails only when a subscriber is already set; keep the first one.
    let _ = if std::env::var("LOG_FORMAT").is_ok_and(|format| format == "json") {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
    let (command, config) = match parse_args(std::env::args()) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!("{err:#}");
            return ExitCode::from(2);
        }
    };
    match execute(command, config).await {
        Ok(code) => code,
        Err(err) => {
            error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}
