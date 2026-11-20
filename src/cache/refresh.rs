//! Revalidating an entry as a Pingora subrequest.
//!
//! A conditional request cannot be answered from the cache on the request's own path: when the
//! origin says `304` Pingora has already decided the response has no body, so a stored body
//! cannot be sent after it. The cache therefore asks the origin through a subrequest, a copy of
//! the client's request that runs the whole pipeline (route match, middleware chain, admission,
//! upstream) and ends in a sink. The subrequest carries a [`Refresh`] that holds the right to
//! fetch the key ([`Lead`]) and the entry to confirm; when it ends the original request, or the
//! next one for a `stale-while-revalidate` refresh, finds the new entry.
//!
//! The subrequest has no connection of its own, so the checks that read the client's connection
//! (SNI against Host, client certificate, ACME challenges) are skipped for it: the original
//! request already passed them, and its entry point, scheme and forwarded view are carried in
//! [`Inherited`].

use std::sync::Arc;

use pingora::http::RequestHeader;
use pingora::proxy::Session;
use pingora::proxy::subrequest::Ctx as SubrequestCtx;

use crate::cache::Lead;
use crate::cache::store::Entry;
use crate::client_ip::ForwardedView;

/// What the subrequest takes over from the request that spawned it.
#[derive(Debug, Clone)]
pub(crate) struct Inherited {
    pub(crate) forwarded: ForwardedView,
    pub(crate) tls: bool,
    pub(crate) entry_point: Arc<str>,
}

/// The marker a refresh subrequest carries as its user context.
#[derive(Debug)]
pub(crate) struct Refresh {
    /// The right to fetch the key, taken by the cache stage of the subrequest.
    pub(crate) lead: Option<Lead>,
    /// The entry to confirm: its validators go to the origin.
    pub(crate) entry: Arc<Entry>,
    pub(crate) inherited: Inherited,
}

/// The refresh `session` is, when it is a subrequest the cache spawned.
pub(crate) fn of(session: &Session) -> Option<&Refresh> {
    session
        .subrequest_ctx
        .as_deref()?
        .user_ctx()?
        .downcast_ref::<Refresh>()
}

/// The same, mutably, so the cache stage can take the [`Lead`].
pub(crate) fn of_mut(session: &mut Session) -> Option<&mut Refresh> {
    session
        .subrequest_ctx
        .as_deref_mut()?
        .user_ctx_mut()?
        .downcast_mut::<Refresh>()
}

/// What a refresh subrequest inherits, or `None` when `session` is not one.
pub(crate) fn inherited(session: &Session) -> Option<Inherited> {
    of(session).map(|refresh| refresh.inherited.clone())
}

/// Starts a refresh subrequest of the request on `session`, as it arrived (`original`, the head
/// before any middleware changed it, so the chain does not run twice over a rewritten path).
/// `false` when Pingora cannot spawn one; `refresh` is dropped then, which frees its lead.
pub(crate) fn spawn(session: &mut Session, original: &RequestHeader, refresh: Refresh) -> bool {
    if session.subrequest_spawner.is_none() {
        return false;
    }
    let ctx = SubrequestCtx::builder().user_ctx(Box::new(refresh)).build();
    let mut head = original.clone();
    std::mem::swap(session.req_header_mut(), &mut head);
    // The subrequest copies the head synchronously; the task it spawns owns the copy.
    drop(
        session
            .subrequest_spawner
            .as_ref()
            .map(|spawner| spawner.spawn_background_subrequest(&session.downstream_session, ctx)),
    );
    std::mem::swap(session.req_header_mut(), &mut head);
    true
}
