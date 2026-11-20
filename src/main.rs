//! `podgate` binary: read config, start logging, serve until SIGINT/SIGTERM.

use podgate::{Config, init_tracing, serve, shutdown_signal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    init_tracing(config.log_format);
    serve(&config, shutdown_signal()).await
}
