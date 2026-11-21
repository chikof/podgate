//! A plugin for podgate's `plugin` middleware, for the tests and as a model of the protocol.
//!
//! `echo_plugin` serves `podgate.plugin.v1` on the unix socket named by `PODGATE_PLUGIN_SOCKET`
//! (podgate sets it for a managed plugin; the name comes from `PODGATE_PLUGIN_NAME`). Each call
//! is answered from the middleware's `config`, so a snapshot steers it: set, remove and add
//! headers, answer the request, wait, use memory, exit. The keys are in the table of
//! `echo` in `tests/common/plugin.rs`, which this example shares with the tests.
//! `PLUGIN_PID_FILE`, when set, gets the process id appended on every start.
//!
//! It is not a product: it exists to exercise podgate's side of the protocol.

use std::path::Path;

#[allow(
    dead_code,
    unreachable_pub,
    reason = "the test helpers share this file; the example uses only the server"
)]
#[path = "../tests/common/plugin.rs"]
mod plugin;

#[tokio::main]
async fn main() {
    let Some(socket) = std::env::var_os("PODGATE_PLUGIN_SOCKET") else {
        eprintln!("PODGATE_PLUGIN_SOCKET is not set");
        std::process::exit(2);
    };
    let name = std::env::var("PODGATE_PLUGIN_NAME").unwrap_or_else(|_| "echo".to_owned());
    plugin::serve_forever(Path::new(&socket), &name).await;
}
