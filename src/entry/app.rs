//! The Pingora application of one entry point: [`Policed`] wraps the stock `HttpProxy` so the
//! per-connection settings of an entry point policy come from the live routing
//! table, not from a value frozen when the service was built.
//!
//! Pingora reads three things per connection from the application, not from the request:
//! [`HttpServerApp::h2_options`] (HTTP/2 stream and header limits), [`HttpServerApp::server_options`]
//! (the HTTP/2 idle timeout) and, for HTTP/1, whatever the application sets on the session
//! before it reads the first byte. `HttpProxy` returns fixed values for the first two, so a
//! snapshot could never change them. `Policed` asks the table of the moment and delegates
//! everything else to the inner proxy.

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

/// The service for the entry point `gateway` serves; add its listeners to it as to any
/// `http_proxy_service`. `gate` is the PROXY protocol check of a plaintext entry point with
/// `;proxy_protocol` (a TLS entry point checks in its pre-TLS hook instead).
#[must_use]
pub fn service(
    conf: &Arc<ServerConf>,
    gateway: Gateway,
    table: TableHandle,
    entry_point: &str,
    name: &str,
    gate: Option<Gate>,
) -> Service<Fronted<Policed>> {
    let policed = Policed {
        inner: Arc::new(http_proxy(conf, gateway)),
        table,
        entry_point: Arc::from(entry_point),
    };
    Service::new(name.to_owned(), Fronted::new(gate, policed))
}

/// The options that carry an HTTP/2 idle timeout of `secs`, `None` outside `1..=MAX_SECS`.
///
/// `HttpServerApp::server_options` returns a reference that must outlive the call, so there is
/// one prebuilt set per whole second a policy may name (about 200 KiB, built on first use).
fn idle_options(secs: u32) -> Option<&'static HttpServerOptions> {
    static BY_SECS: LazyLock<Box<[HttpServerOptions]>> = LazyLock::new(|| {
        (1..=MAX_SECS)
            .map(|secs| {
                let mut options = HttpServerOptions::default();
                options.h2_idle_timeout = Some(Duration::from_secs(u64::from(secs)));
                options
            })
            .collect()
    });
    BY_SECS.get(usize::try_from(secs.checked_sub(1)?).ok()?)
}

#[async_trait]
impl HttpServerApp for Policed {
    async fn process_new_http(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        // Before the first byte of this request is read: on HTTP/1 the keep-alive timeout is
        // the wait for the request (a no-op for HTTP/2, whose idle timeout is `server_options`).
        let table = self.table.load();
        if let Some(idle) = table.entry_policy(&self.entry_point).idle_secs() {
            session.set_keepalive(Some(u64::from(idle)));
        }
        self.inner.process_new_http(session, shutdown).await
    }

    fn h2_options(&self) -> Option<H2Options> {
        self.table
            .load()
            .entry_policy(&self.entry_point)
            .h2_options()
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        let idle = self
            .table
            .load()
            .entry_policy(&self.entry_point)
            .idle_secs()?;
        idle_options(idle)
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
