//! The Pingora application of one entry point: [`Policed`] wraps the stock `HttpProxy` so the
//! per-connection settings of an entry point policy come from the live routing
//! table, not from a value frozen when the service was built.
//!
//! Pingora reads three things per connection from the application, not from the request:
//! [`HttpServerApp::h2_options`] (HTTP/2 stream and header limits), [`HttpServerApp::server_options`]
//! (the HTTP/2 idle timeout, and whether a cleartext listener serves HTTP/2: `http2.h2c`) and,
//! for HTTP/1, whatever the application sets on the session before it reads the first byte.
//! `HttpProxy` returns fixed values for the first two, so a
//! snapshot could never change them. `Policed` asks the table of the moment and delegates
//! everything else to the inner proxy.

use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::protocols::Stream;
use pingora::protocols::http::ServerSession;
use pingora::protocols::http::v2::server::H2Options;
use pingora::proxy::{HttpProxy, http_proxy};
use pingora::server::ShutdownWatch;
use pingora::server::configuration::ServerConf;
use pingora::services::listening::Service;

use super::policy::MAX_SECS;
use super::proxy_protocol::hook::{Fronted, Gate};
use crate::proxy::Gateway;
use crate::table::TableHandle;

/// An entry point's `HttpProxy` with the connection settings of its live policy.
pub struct Policed {
    inner: Arc<HttpProxy<Gateway>>,
    table: TableHandle,
    entry_point: Arc<str>,
}

/// The application of the entry point `entry_point` for `gateway`: the stock `HttpProxy` with the
/// live policy applied per connection.
#[must_use]
pub fn policed(
    conf: &Arc<ServerConf>,
    gateway: Gateway,
    table: TableHandle,
    entry_point: &str,
) -> Policed {
    Policed {
        inner: Arc::new(http_proxy(conf, gateway)),
        table,
        entry_point: Arc::from(entry_point),
    }
}

/// The runtime group every HTTP, HTTPS and TCP entry point service joins:
/// one pool of `ServerConf.threads` workers serves all of them. A pool per entry point put `n`
/// times as many workers as CPUs on the machine, and the idle ones made the busy ones park and
/// wake twice as often. The name is the workers' thread name, which Linux cuts at 15
/// characters.
pub const RUNTIME_GROUP: &str = "entry points";

/// The service for the entry point `gateway` serves; add its listeners to it as to any
/// `http_proxy_service`. It runs on the [`RUNTIME_GROUP`] pool. `gate` is the PROXY protocol check
/// of a plaintext entry point with `;proxy_protocol` (a TLS entry point checks in its pre-TLS hook
/// instead).
#[must_use]
pub fn service(
    conf: &Arc<ServerConf>,
    gateway: Gateway,
    table: TableHandle,
    entry_point: &str,
    name: &str,
    gate: Option<Gate>,
) -> Service<Fronted<Policed>> {
    let policed = policed(conf, gateway, table, entry_point);
    let mut service = Service::new(name.to_owned(), Fronted::new(gate, policed));
    service.runtime_group = Some(RUNTIME_GROUP.to_owned());
    service
}

/// The prebuilt options for a policy's `h2c` and HTTP/2 idle timeout of `idle` whole seconds;
/// `None` when it sets neither, or an idle timeout outside `1..=MAX_SECS`.
///
/// `HttpServerApp::server_options` returns a reference that must outlive the call, so there is
/// one prebuilt set per whole second a policy may name, with and without `h2c` (about 200 KiB
/// each, built on first use).
fn options_for(h2c: bool, idle: Option<u32>) -> Option<&'static HttpServerOptions> {
    /// Options for `h2c` and each idle timeout from `first` to [`MAX_SECS`] seconds (`0` is none).
    fn build(h2c: bool, first: u32) -> Box<[HttpServerOptions]> {
        (first..=MAX_SECS)
            .map(|secs| {
                let mut options = HttpServerOptions::default();
                options.h2c = h2c;
                options.h2_idle_timeout = (secs > 0).then(|| Duration::from_secs(u64::from(secs)));
                options
            })
            .collect()
    }
    static IDLE: LazyLock<Box<[HttpServerOptions]>> = LazyLock::new(|| build(false, 1));
    static H2C: LazyLock<Box<[HttpServerOptions]>> = LazyLock::new(|| build(true, 0));
    match (h2c, idle) {
        (false, None) => None,
        (false, Some(secs)) => IDLE.get(usize::try_from(secs.checked_sub(1)?).ok()?),
        (true, secs) => H2C.get(usize::try_from(secs.unwrap_or(0)).ok()?),
    }
}

#[async_trait]
impl HttpServerApp for Policed {
    // Not an `async fn`: `async_trait` boxes a future per request, and all this does is a lookup
    // before the inner future starts, so the inner future is returned as it is.
    fn process_new_http<'life0, 'life1, 'async_trait>(
        self: &'life0 Arc<Self>,
        mut session: ServerSession,
        shutdown: &'life1 ShutdownWatch,
    ) -> Pin<Box<dyn Future<Output = Option<ReusedHttpStream>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        // Before the first byte of this request is read: on HTTP/1 the keep-alive timeout is
        // the wait for the request (a no-op for HTTP/2, whose idle timeout is `server_options`).
        let table = self.table.load();
        if let Some(idle) = table.entry_policy(&self.entry_point).idle_secs() {
            session.set_keepalive(Some(u64::from(idle)));
        }
        drop(table);
        self.inner.process_new_http(session, shutdown)
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.table
            .load()
            .entry_policy(&self.entry_point)
            .h2_options()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        let table = self.table.load();
        let policy = table.entry_policy(&self.entry_point);
        options_for(policy.h2c(), policy.idle_secs())
    }

    async fn http_cleanup(&self) {
        self.inner.http_cleanup().await;
    }

    async fn process_custom_session(
        self: Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        Arc::clone(&self.inner)
            .process_custom_session(stream, shutdown)
            .await
    }
}
