//! A task handle that stops its task when dropped.

use tokio::task::JoinHandle;

/// Stops its task when dropped, so a source that returns leaves no watcher behind.
pub(crate) struct Abort(pub(crate) JoinHandle<()>);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}
