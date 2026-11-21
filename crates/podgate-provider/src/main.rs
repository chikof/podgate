//! The `podgate-provider` program: `run`, `print`, `check` and `print-crd`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, bail};
use podgate_provider::consul::ConsulSource;
use podgate_provider::docker::DockerSource;
use podgate_provider::ecs::EcsSource;
use podgate_provider::etcd::EtcdSource;
use podgate_provider::file::FileSource;
use podgate_provider::http::HttpSource;
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::crd::{SchemaSource, print, read_schema};
use podgate_provider::nomad::NomadSource;
use podgate_provider::quarantine::Verdict;
use podgate_provider::redis::RedisSource;
use podgate_provider::swarm::SwarmSource;
use podgate_provider::{Config, Engine, UpstreamPolicy};
use tracing::error;
use tracing_subscriber::EnvFilter;

/// How long `print` and `check` wait for every source to report once.
const COLLECT_WAIT: Duration = Duration::from_secs(30);

const USAGE: &str = "usage: podgate-provider <run|print|check> --config <file>

  run     merge the sources and keep pushing the snapshot to the admin socket
  print   merge once and print the snapshot JSON; pushes nothing
  check   merge once and ask podgate whether it would accept the snapshot

usage: podgate-provider print-crd (--socket <admin socket> | --schema <file>) [--out <dir>] [--save-schema <file>]

  print-crd   generate the PodgateRoute and PodgateMiddleware CRDs from the daemon's GET /v1/schema

usage: podgate-provider ca <init|export-root|status|issue|rotate> --config <file> [options]

  ca   the internal CA (docs/ref/internal-ca.md); `ca` alone lists the options

usage: podgate-provider convert-traefik [--lenient] <file>...

  convert-traefik   convert Traefik dynamic configuration files to the file source format";

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
fn register_sources(
    engine: &mut Engine,
    config: &Config,
    policy: &UpstreamPolicy,
) -> anyhow::Result<()> {
    for source in &config.sources {
        match &*source.kind {
            "consul" => engine.add_source(ConsulSource::from_config(source)?)?,
            "docker" => engine.add_source(DockerSource::from_config(source)?)?,
            "ecs" => engine.add_source(EcsSource::from_config(source)?)?,
            "etcd" => engine.add_source(EtcdSource::from_config(source, policy)?)?,
            "file" => engine.add_source(FileSource::from_config(source)?)?,
            "http" => engine.add_source(HttpSource::from_config(source, policy)?)?,
            "kubernetes" => engine.add_source(KubernetesSource::from_config(source, config)?)?,
            "nomad" => engine.add_source(NomadSource::from_config(source)?)?,
            "swarm" => engine.add_source(SwarmSource::from_config(source)?)?,
            "redis" => engine.add_source(RedisSource::from_config(source, policy)?)?,
            kind => bail!(
                "source {:?}: kind {kind:?} is not built into this binary",
                source.name
            ),
        }
    }
    Ok(())
}

/// `print-crd`: the CRD manifests from the daemon's schema, to stdout or to `--out`.
async fn print_crd(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let (mut socket, mut schema, mut out, mut save) = (None, None, None, None);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--socket" => &mut socket,
            "--schema" => &mut schema,
            "--out" => &mut out,
            "--save-schema" => &mut save,
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        };
        *slot = Some(PathBuf::from(
            args.next()
                .with_context(|| format!("{arg} needs a value\n{USAGE}"))?,
        ));
    }
    let source = match (&socket, &schema) {
        (Some(path), None) => SchemaSource::Socket(path),
        (None, Some(path)) => SchemaSource::File(path),
        _ => bail!("give exactly one of --socket and --schema\n{USAGE}"),
    };
    let document = read_schema(source).await?;
    let manifests = print(&document, out.as_deref(), save.as_deref())?;
    print!("{manifests}");
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
    let mut engine = Engine::new(config.clone(), policy.clone());
    register_sources(&mut engine, &config, &policy)?;
    match command {
        Command::Run => {
            let solver = podgate_provider::acme::dns::solver(&config)?;
            Box::pin(engine.with_dns_solver(solver).run(shutdown())).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Print => {
            let merged = engine.first_pass(COLLECT_WAIT).await?;
            println!("{}", merged.redacted_body(0));
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
    if std::env::args().nth(1).as_deref() == Some("print-crd") {
        return match print_crd(std::env::args().skip(2)).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                error!("{err:#}");
                ExitCode::from(2)
            }
        };
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("ca") {
        let code = podgate_provider::ca::cli::run(
            &args[2..],
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        );
        return ExitCode::from(code);
    }
    if args.get(1).map(String::as_str) == Some("convert-traefik") {
        let code = podgate_provider::traefik_file::cli::run(
            &args[2..],
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        );
        return ExitCode::from(code);
    }
    let (command, config) = match parse_args(std::env::args()) {
        Ok(parsed) => parsed,
        Err(err) => {
            error!("{err:#}");
            return ExitCode::from(2);
        }
    };
    match Box::pin(execute(command, config)).await {
        Ok(code) => code,
        Err(err) => {
            error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}
