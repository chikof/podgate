//! The `podgate-federation` program: `export`, `hub` and `check`.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, bail};
use podgate_federation::config::{ExportFile, PeersFile};
use podgate_federation::export::Exporter;
use podgate_federation::hub::Hub;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: podgate-federation <export|hub> --config <file>
       podgate-federation check <export|hub> --config <file>

  export   serve this node's catalog and status over mutual TLS (reads ADMIN_READ_SOCKET)
  hub      pull every peer of the file and serve the combined view over mutual TLS
  check    parse and validate a file, read every certificate and key, open nothing";

enum Command {
    Export(PathBuf),
    Hub(PathBuf),
    CheckExport(PathBuf),
    CheckHub(PathBuf),
}

fn parse_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<Command> {
    let first = args.next().context(USAGE)?;
    let (check, role) = if first == "check" {
        (true, args.next().context(USAGE)?)
    } else {
        (false, first)
    };
    if args.next().as_deref() != Some("--config") {
        bail!("{USAGE}");
    }
    let path = PathBuf::from(args.next().context(USAGE)?);
    if args.next().is_some() {
        bail!("{USAGE}");
    }
    match (check, role.as_str()) {
        (false, "export") => Ok(Command::Export(path)),
        (false, "hub") => Ok(Command::Hub(path)),
        (true, "export") => Ok(Command::CheckExport(path)),
        (true, "hub") => Ok(Command::CheckHub(path)),
        _ => bail!("{USAGE}"),
    }
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => drop(tokio::signal::ctrl_c().await),
    }
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::CheckExport(path) => {
            let file = ExportFile::load(&path).context("export file")?;
            println!(
                "ok: serves {}, reads {}",
                file.serve.addr,
                file.read_socket.display()
            );
        }
        Command::CheckHub(path) => {
            let file = PeersFile::load(&path).context("peers file")?;
            println!("ok: {} peers, view on {}", file.peers.len(), file.view.addr);
        }
        Command::Export(path) => {
            let file = ExportFile::load(&path).context("export file")?;
            let mut exporter = Exporter::start(file)
                .await
                .context("cannot start the exporter")?;
            tracing::info!(addr = %exporter.addr(), "exporter ready");
            tokio::select! {
                () = shutdown() => {}
                error = exporter.fatal() => bail!("{error}"),
            }
        }
        Command::Hub(path) => {
            let file = PeersFile::load(&path).context("peers file")?;
            let hub = Hub::start(file).await.context("cannot start the hub")?;
            tracing::info!(addr = %hub.view_addr(), "hub ready");
            shutdown().await;
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let command = match parse_args(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("{err:#}");
            return ExitCode::from(2);
        }
    };
    match run(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::FAILURE
        }
    }
}
