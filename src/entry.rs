//! Entry points (listeners) as the request path sees them.
//!
//! Where an entry point listens is process configuration, because Pingora binds its sockets
//! before it runs; what it allows is snapshot data ([`podgate_model::EntryPointPolicy`]).
//! Today the process has two entry points, `web` (plain HTTP, `PROXY_ADDR`) and `websecure`
//! (TLS, `PROXY_TLS_ADDR`); the `ENTRY_POINTS` setting, proxy protocol, forwarded-header trust,
//! timeouts and the other policy fields belong to the entry point spec, which fills this file.
//!
//! - [`CompileContext`]: the entry point names the compiler checks routers and policies
//!   against, so a snapshot written for another node fails closed.
//! - [`of`]: the entry point a request arrived on.
//! - [`normalize_request`]: the first thing the request path does with a request: the path that
//!   is matched is rewritten to the path that is served.

use pingora::http::RequestHeader;
use pingora::proxy::Session;

use crate::router::path::{self, Refused};

/// The built-in plain HTTP entry point.
pub const WEB: &str = "web";
/// The built-in TLS entry point.
pub const WEBSECURE: &str = "websecure";

/// What the compiler knows about this process.
#[derive(Debug, Clone)]
pub struct CompileContext {
    entry_points: Vec<Box<str>>,
    catch_all_tenants: Vec<Box<str>>,
}

impl Default for CompileContext {
    /// The two built-in entry points, and no tenant allowed a catch-all router.
    fn default() -> Self {
        Self::new([WEB, WEBSECURE])
    }
}

impl CompileContext {
    /// A context with the entry points called `names`.
    #[must_use]
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            entry_points: names.into_iter().map(Box::from).collect(),
            catch_all_tenants: Vec::new(),
        }
    }

    /// Lets the tenants called `tenants` declare routers that match hosts nobody claims (a
    /// `host_regexp` or host-free router) on a shared entry point. Only the operator calls this
    /// (`CATCH_ALL_TENANTS`); a snapshot never can.
    #[must_use]
    pub fn with_catch_all_tenants<'a>(
        mut self,
        tenants: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        self.catch_all_tenants = tenants.into_iter().map(Box::from).collect();
        self
    }

    /// Whether the operator allows `tenant` catch-all routers on shared entry points.
    #[must_use]
    pub fn allows_catch_all(&self, tenant: &str) -> bool {
        self.catch_all_tenants
            .iter()
            .any(|allowed| &**allowed == tenant)
    }

    /// The bound entry point names.
    #[must_use]
    pub fn entry_points(&self) -> &[Box<str>] {
        &self.entry_points
    }

    /// Whether the process bound an entry point called `name`.
    #[must_use]
    pub fn knows(&self, name: &str) -> bool {
        self.entry_points.iter().any(|known| &**known == name)
    }
}

/// The entry point a request arrived on: `websecure` over TLS, `web` otherwise.
#[must_use]
pub fn of(tls: bool) -> &'static str {
    if tls { WEBSECURE } else { WEB }
}

/// Whether the request's connection is TLS: the connection has a TLS digest.
#[must_use]
pub fn is_tls(session: &Session) -> bool {
    session
        .digest()
        .is_some_and(|digest| digest.ssl_digest.is_some())
}

/// Normalizes the path of `request` (see [`crate::router::path`]) and rewrites the request with
/// the result, so routing, middlewares and the upstream all see one path.
///
/// # Errors
///
/// [`Refused`] for a path that cannot be normalized without changing what it names; the request
/// must be answered `400`.
pub fn normalize_request(request: &mut RequestHeader) -> Result<(), Refused> {
    let normalized = match path::normalize(request.uri.path())? {
        std::borrow::Cow::Borrowed(_) => return Ok(()),
        std::borrow::Cow::Owned(path) => path,
    };
    let target = match request.uri.query() {
        Some(query) => format!("{normalized}?{query}"),
        None => normalized,
    };
    let mut parts = request.uri.clone().into_parts();
    if let Ok(path_and_query) = target.parse() {
        parts.path_and_query = Some(path_and_query);
        if let Ok(uri) = http::Uri::from_parts(parts) {
            request.set_uri(uri);
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_request_is_rewritten_to_the_path_that_was_matched() {
        let mut request = RequestHeader::build("GET", b"/a/./b//c?x=1", None).expect("request");
        normalize_request(&mut request).expect("normalizes");
        assert_eq!(request.uri.path(), "/a/b/c");
        assert_eq!(request.uri.query(), Some("x=1"));
    }

    #[test]
    fn a_clean_request_is_untouched_and_a_bad_one_refused() {
        let mut clean = RequestHeader::build("GET", b"/a?x=1", None).expect("request");
        normalize_request(&mut clean).expect("clean");
        assert_eq!(
            clean.uri.path_and_query().map(|pq| pq.as_str()),
            Some("/a?x=1")
        );
        let mut bad = RequestHeader::build("GET", b"/a%2fb", None).expect("request");
        assert_eq!(normalize_request(&mut bad), Err(Refused::EncodedSeparator));
    }

    #[test]
    fn the_default_context_knows_web_and_websecure() {
        let context = CompileContext::default();
        assert!(context.knows("web") && context.knows("websecure") && !context.knows("db"));
    }
}
