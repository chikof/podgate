//! `podgate` binary: read config, start logging, run the proxy until it is told to stop.

use podgate::{Config, init_tracing, run};

fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    init_tracing(config.log_format);
    run(&config)
}
