//! HTTP/3 over QUIC for HTTPS entry points.
//!
//! Pingora has no HTTP/3 server, so the front is a separate tokio service in the podgate
//! process: a `quinn` endpoint on UDP at the entry point's address speaking HTTP/3 with the `h3`
//! crate. It does not reimplement the pipeline. Each QUIC connection is bridged, request by
//! request, into the Pingora application of the same entry point over an internal HTTP/2
//! cleartext connection on a unix socket, so routing, middlewares, budgets, access logs and
//! metrics apply to HTTP/3 requests unchanged. Reference: `docs/ref/http3.md`.
//!
//! - [`Service`]: the background service of one entry point with `;http3`; [`Parts`] is what it
//!   shares with the process.
//! - [`Settings`] and [`Retry`]: the operator's `H3_*` settings; [`render`] writes the
//!   `podgate_h3_*` metrics.
//! - [`AltSvc`]: the `Alt-Svc` header an HTTPS entry point adds for the apps that allow HTTP/3.
//! - [`link_path`]: where the internal socket of an entry point lives.
//!
//! The submodules: `alt_svc` (the header and which apps may be offered over HTTP/3), `bridge` (the
//! internal connection and its credential and PROXY header), `endpoint` (the UDP socket, the
//! TLS and transport configuration, the admission of new connections), `front` (connections,
//! requests, the bridge of bodies and trailers) and `limits` (settings, memory arithmetic,
//! counters and metrics).

pub(crate) mod alt_svc;
pub(crate) mod bridge;
mod endpoint;
mod front;
mod limits;

use std::path::{Path, PathBuf};

pub use alt_svc::AltSvc;
pub use front::{Parts, Service};
pub use limits::{Retry, Settings, render};

/// The internal socket of the entry point called `entry`: `h3-<entry>.sock` next to the admin
/// socket `admin_socket`. Entry point names are letters, digits, `-` and `_`, so the name is a
/// safe file name.
#[must_use]
pub fn link_path(admin_socket: &Path, entry: &str) -> PathBuf {
    admin_socket
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("h3-{entry}.sock"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_internal_socket_sits_next_to_the_admin_socket() {
        assert_eq!(
            link_path(Path::new("/run/podgate/admin.sock"), "websecure"),
            Path::new("/run/podgate/h3-websecure.sock")
        );
        assert_eq!(
            link_path(Path::new("admin.sock"), "web_2"),
            Path::new("h3-web_2.sock")
        );
    }
}
