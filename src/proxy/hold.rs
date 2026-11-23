//! Holding the upstream's response back until a stage of the chain has judged all of it (spec
//! 0130), on the vendored `ProxyHttp::hold_response` hook (`docs/ref/pingora-patches.md`
//! section 6).
//!
//! The hook sees every batch of raw upstream tasks before any filter runs. The first batch starts
//! with the response head: the chain's [`Kind::response_hold`](crate::middleware::Kind) hooks are
//! asked there, and when one says yes every task of this and the next batches is moved into a
//! stash, so nothing is written to the client and no response hook has seen any of it. The stash
//! is bounded here, on the raw path, before a task is moved into it: a body task that would take
//! it past the cap answers `502` with nothing written and drops the stash and its charges at once.
//! When a task ends the response, the stage hooks ([`Kind::response_held`](crate::middleware::Kind))
//! judge the whole response, and the tasks go back at the front of the batch, rebuilt from what
//! the hooks left, so the head and body hooks (the failed-request capture, compression, the
//! cache) run on the answer that was let through and on nothing else.

use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::protocols::http::HttpTask;
use pingora::proxy::Session;

use super::{Ctx, Gateway};
use crate::budget::{BufferGuard, TenantSlot};
use crate::error::AppError;
use crate::middleware::{self, HeldCx};
use crate::respond;

/// What the proxy knows about holding this request's response.
#[derive(Debug, Default)]
pub(crate) enum Held {
    /// No batch seen yet.
    #[default]
    Unasked,
    /// The response streams as usual (no stage asked, or it was already released).
    Off,
    /// The response is being held.
    Holding(Box<Stash>),
}

/// The tasks held so far and what pays for them.
#[derive(Debug)]
pub(crate) struct Stash {
    tasks: Vec<HttpTask>,
    /// Body bytes in `tasks`.
    bytes: u64,
    /// The most body bytes `tasks` may hold.
    max_body: u64,
    /// Released with the stash.
    _charges: Vec<BufferGuard>,
}

fn len(bytes: &Bytes) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

impl Gateway {
    /// One batch of raw upstream tasks: decides at the head whether to hold, stashes while
    /// holding, and puts the judged response back into `tasks` when it has ended.
    pub(super) async fn hold_tasks(
        &self,
        session: &mut Session,
        tasks: &mut Vec<HttpTask>,
        ctx: &mut Ctx,
    ) -> pingora::Result<()> {
        if matches!(ctx.held, Held::Off) {
            return Ok(());
        }
        if matches!(ctx.held, Held::Unasked) {
            ctx.held = match self.ask(session, tasks, ctx) {
                Ok(held) => held,
                Err(err) => {
                    self.observe_refused(session, ctx, tasks);
                    ctx.held = Held::Off;
                    ctx.capacity_refusal = err.is_capacity_refusal();
                    return Err(respond::abort(session, &err).await);
                }
            };
        }
        // Out of the context while it is filled: every early return drops it, and its charges
        // with it.
        let Held::Holding(mut stash) = std::mem::replace(&mut ctx.held, Held::Off) else {
            return Ok(());
        };
        let mut ended = false;
        for task in std::mem::take(tasks) {
            match &task {
                HttpTask::Body(Some(chunk), _) | HttpTask::UpgradedBody(Some(chunk), _) => {
                    // Before the task is kept: the stash never passes the cap.
                    if stash.bytes.saturating_add(len(chunk)) > stash.max_body {
                        self.observe_dropped(
                            session,
                            ctx,
                            &stash,
                            stash.bytes.saturating_add(len(chunk)),
                        );
                        return Err(
                            respond::abort(session, &AppError::UpstreamResponseTooLarge).await
                        );
                    }
                    stash.bytes += len(chunk);
                }
                HttpTask::Failed(_) => {
                    self.observe_dropped(session, ctx, &stash, stash.bytes);
                    // The upstream died before the answer was complete and nothing was written:
                    // the error goes out as an error, not as half an answer.
                    if let HttpTask::Failed(err) = task {
                        return Err(err);
                    }
                    return Ok(());
                }
                _ => {}
            }
            ended |= task.is_end();
            stash.tasks.push(task);
        }
        if !ended {
            ctx.held = Held::Holding(stash);
            return Ok(());
        }
        *tasks = self.judge(session, ctx, *stash).await?;
        Ok(())
    }

    /// Shows a hold that is dropped without a verdict to the stages that count what an answer
    /// cost: the head, and the body bytes that had arrived.
    fn observe_dropped(&self, session: &Session, ctx: &mut Ctx, stash: &Stash, body_bytes: u64) {
        if let Some(HttpTask::Header(head, _)) = stash.tasks.first() {
            self.observe_head(session, ctx, head, body_bytes);
        }
    }

    /// [`Self::observe_dropped`] for a head whose hold was refused before any body was kept: the
    /// model already answered, so it is counted by the length it declared.
    fn observe_refused(&self, session: &Session, ctx: &mut Ctx, tasks: &[HttpTask]) {
        if let Some(HttpTask::Header(head, _)) = tasks.first() {
            let declared = head
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            self.observe_head(session, ctx, head, declared);
        }
    }

    fn observe_head(&self, session: &Session, ctx: &mut Ctx, head: &ResponseHeader, bytes: u64) {
        let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) else {
            return;
        };
        let seen = middleware::HeldSeen {
            request: session.req_header(),
            head,
            body: None,
            body_bytes: bytes,
        };
        middleware::run_held_seen(app.stages(), router.chain(), &seen, &mut ctx.chain);
    }

    /// Looks at the first batch: when it starts with the response head and a stage of the chain
    /// asks to hold, the stash to fill.
    fn ask(&self, session: &Session, tasks: &[HttpTask], ctx: &mut Ctx) -> Result<Held, AppError> {
        let Some(HttpTask::Header(head, false)) = tasks.first() else {
            return Ok(Held::Off);
        };
        let Some((app, router)) = ctx
            .matched
            .and_then(|matched| ctx.table.router(matched))
            .filter(|(_, router)| !router.chain().is_empty())
        else {
            return Ok(Held::Off);
        };
        let cx = middleware::ResponseCx {
            request: session.req_header(),
            response: head,
            tenant: ctx.tenant_slot.as_ref().map(TenantSlot::tenant),
        };
        let plan =
            middleware::run_response_hold(app.stages(), router.chain(), &cx, &mut ctx.chain)?;
        Ok(plan.map_or(Held::Off, |plan| {
            Held::Holding(Box::new(Stash {
                tasks: Vec::new(),
                bytes: 0,
                max_body: plan.max_body,
                _charges: plan.charges,
            }))
        }))
    }

    /// Runs the held-response hooks on the whole response and rebuilds its tasks.
    async fn judge(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        stash: Stash,
    ) -> pingora::Result<Vec<HttpTask>> {
        let mut tasks = stash.tasks.into_iter();
        let Some(HttpTask::Header(mut head, _)) = tasks.next() else {
            return Ok(Vec::new());
        };
        let mut chunks: Vec<Bytes> = Vec::new();
        let mut body_ended = false;
        let mut rest: Vec<HttpTask> = Vec::new();
        for task in tasks {
            match task {
                HttpTask::Body(chunk, end) | HttpTask::UpgradedBody(chunk, end) => {
                    chunks.extend(chunk.filter(|chunk| !chunk.is_empty()));
                    body_ended |= end;
                }
                other => rest.push(other),
            }
        }
        let mut body = match chunks.len() {
            0 => Bytes::new(),
            1 => chunks.swap_remove(0),
            _ => Bytes::from(chunks.concat()),
        };
        if let Some((app, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
            let tenant = ctx.tenant_slot.as_ref().map(TenantSlot::tenant);
            let seen = middleware::HeldSeen {
                request: session.req_header(),
                head: &head,
                body: Some(&body),
                body_bytes: len(&body),
            };
            middleware::run_held_seen(app.stages(), router.chain(), &seen, &mut ctx.chain);
            let mut cx = HeldCx {
                request: session.req_header(),
                head: &mut head,
                body: &mut body,
                app,
                tenant,
                auth: &self.auth_client,
                policy: &self.upstream_policy,
            };
            if let Err(err) =
                middleware::run_held(app.stages(), router.chain(), &mut cx, &mut ctx.chain).await
            {
                ctx.capacity_refusal = err.is_capacity_refusal();
                return Err(respond::abort(session, &err).await);
            }
        }
        Ok(rebuild(head, body, body_ended, rest))
    }
}

/// The tasks of a judged response: the head, the body in one piece, and what followed it.
fn rebuild(
    head: Box<ResponseHeader>,
    body: Bytes,
    body_ended: bool,
    rest: Vec<HttpTask>,
) -> Vec<HttpTask> {
    let mut tasks = Vec::with_capacity(rest.len() + 2);
    tasks.push(HttpTask::Header(head, false));
    if body.is_empty() {
        if body_ended {
            tasks.push(HttpTask::Body(None, true));
        }
    } else {
        tasks.push(HttpTask::Body(Some(body), body_ended));
    }
    tasks.extend(rest);
    tasks
}

#[cfg(test)]
mod test {
    use super::*;

    fn head() -> Box<ResponseHeader> {
        Box::new(ResponseHeader::build(200, None).expect("head"))
    }

    fn kinds(tasks: &[HttpTask]) -> Vec<&'static str> {
        tasks.iter().map(HttpTask::type_str).collect()
    }

    #[test]
    fn rebuilt_tasks_keep_the_order_and_the_end() {
        let tasks = rebuild(
            head(),
            Bytes::from_static(b"abc"),
            true,
            vec![HttpTask::Done],
        );
        assert_eq!(kinds(&tasks), ["Header", "Body", "Done"]);
        assert!(matches!(&tasks[1], HttpTask::Body(Some(body), true) if &body[..] == b"abc"));

        let tasks = rebuild(head(), Bytes::new(), true, Vec::new());
        assert_eq!(kinds(&tasks), ["Header", "Body"]);
        assert!(matches!(&tasks[1], HttpTask::Body(None, true)));

        let trailers = vec![HttpTask::Trailer(None), HttpTask::Done];
        let tasks = rebuild(head(), Bytes::from_static(b"x"), false, trailers);
        assert_eq!(kinds(&tasks), ["Header", "Body", "Trailer", "Done"]);
        assert!(matches!(&tasks[1], HttpTask::Body(Some(_), false)));
    }
}
