//! The lifecycle guard: what the routers of a `draft`, `deprecated` or `retired` API answer
//!. Full reference: `docs/ref/catalog.md`.
//!
//! It is not a kind a snapshot declares. The compiler pushes one `lifecycle:<router>` stage per
//! router an `apis` entry names, and puts it first in the router's chain ([`attach`]): first for
//! the request hook, so a stage of the tenant cannot answer before it, and therefore last for the
//! response hooks, which run in reverse chain order, so no `headers` stage of the tenant can
//! remove or overwrite what it set. A chain only names declared middlewares and the guard is in
//! no name index, so a tenant can neither declare it nor take it out of a chain.
//!
//! - `draft` answers `404 {"error":"not found"}`, `retired` answers `410 {"error":"api retired"}`;
//!   both before the request takes any tenant slot, and the upstream is never dialled.
//! - `deprecated` serves, and puts `Deprecation: true`, `Sunset: <HTTP-date>` and, when the
//!   successor has a router with a path, `Link: <path>; rel="successor-version"` on every
//!   response that passes the response hooks. `Link` is appended, so an upstream's own `Link`
//!   header stays.
//! - `preview` and `stable` get no guard: they cost a request nothing.

use http::HeaderValue;
use pingora::http::ResponseHeader;
use serde_json::{Value, json};

use super::{CompileCx, Flow, Kind, Named, RequestCx, Stage};
use crate::catalog::{Links, Sunset};
use crate::compile::Invalid;
use crate::error::AppError;
use crate::respond;
use crate::router::CompiledRouter;
use podgate_model::{App, Declared, Lifecycle};

/// The plan's posture change for a router that was closed (`draft`, `retired`) and is open now.
pub const API_REOPENED: &str = "api_reopened";

/// What the guard does to its router.
#[derive(Debug, Clone)]
enum State {
    Draft,
    Retired,
    Deprecated {
        sunset: HeaderValue,
        link: Option<HeaderValue>,
    },
}

/// A compiled lifecycle guard.
#[derive(Debug, Clone)]
pub struct Guard {
    state: State,
}

impl Guard {
    /// The guard for an API at `lifecycle`, `None` for `preview` and `stable`. A `deprecated` API
    /// with no sunset gets none either: the compiler refuses that before it gets here.
    fn new(lifecycle: Lifecycle, sunset: Option<&Sunset>, link: Option<&str>) -> Option<Self> {
        let state = match lifecycle {
            Lifecycle::Draft => State::Draft,
            Lifecycle::Retired => State::Retired,
            Lifecycle::Deprecated => State::Deprecated {
                sunset: sunset?.header().clone(),
                link: link.and_then(successor_link),
            },
            Lifecycle::Preview | Lifecycle::Stable => return None,
        };
        Some(Self { state })
    }

    fn closed(&self) -> bool {
        matches!(self.state, State::Draft | State::Retired)
    }
}

/// `<path>; rel="successor-version"`, when the path can sit inside `<>` of a `Link` header.
fn successor_link(path: &str) -> Option<HeaderValue> {
    let clean = path
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'<' | b'>' | b'"' | b'\\'));
    if !clean {
        return None;
    }
    HeaderValue::from_str(&format!("<{path}>; rel=\"successor-version\"")).ok()
}

impl Kind for Guard {
    type State = ();

    /// Always refuses: the guard is built in, and a snapshot cannot declare it.
    fn compile(_declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        Err(Invalid::new(
            "unknown_middleware",
            "middleware type lifecycle is built in; declare the API under apis",
        ))
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let (error, reason) = match self.state {
            State::Draft => (AppError::NotFound, "api_draft"),
            State::Retired => (AppError::ApiRetired, "api_retired"),
            State::Deprecated { .. } => return Ok(Flow::Continue),
        };
        *cx.reason = Some(reason);
        respond::write_error(cx.session, &error).await?;
        Ok(Flow::Respond)
    }

    fn response(&self, response: &mut ResponseHeader, _state: &mut ()) -> pingora::Result<()> {
        if let State::Deprecated { sunset, link } = &self.state {
            response.insert_header("deprecation", "true")?;
            response.insert_header("sunset", sunset.clone())?;
            // A copy the cache stored after this hook ran already has the value: once is enough.
            if let Some(link) = link
                && !response
                    .headers
                    .get_all("link")
                    .iter()
                    .any(|have| have == link)
            {
                response.append_header("link", link.clone())?;
            }
        }
        Ok(())
    }

    /// A closed guard that is gone from the candidate, or has become `deprecated`, reopens its
    /// router. A `deprecated` guard going away reports nothing: it never closed the API.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        if self.closed() && !new.is_some_and(Self::closed) {
            vec![API_REOPENED]
        } else {
            Vec::new()
        }
    }

    fn describe(&self) -> Value {
        match &self.state {
            State::Draft => json!({"state": "draft"}),
            State::Retired => json!({"state": "retired"}),
            State::Deprecated { sunset, link } => json!({
                "state": "deprecated",
                "sunset": sunset.to_str().unwrap_or_default(),
                "link": link.as_ref().and_then(|link| link.to_str().ok()),
            }),
        }
    }
}

/// Puts a guard first in the chain of every router an `apis` entry of `app` names, for each entry
/// that is `draft`, `deprecated` or `retired`. `routers` are the compiled routers of `app`, in
/// declaration order; the guards are pushed onto `stages`, named `lifecycle:<router>`.
pub(crate) fn attach(
    app: &App,
    links: &Links,
    routers: &mut [CompiledRouter],
    stages: &mut Vec<Named>,
) {
    for api in &app.apis {
        let sunset = api
            .sunset
            .as_deref()
            .and_then(|text| Sunset::parse(text).ok());
        let link = api
            .successor
            .as_ref()
            .and_then(|successor| links.path(&app.tenant, &successor.id, &successor.version));
        let Some(guard) = Guard::new(api.lifecycle, sunset.as_ref(), link) else {
            continue;
        };
        let text = format!("{:?}", guard.state);
        for name in &api.routers {
            let Some(router) = app
                .routers
                .iter()
                .position(|router| router.name == *name)
                .and_then(|at| routers.get_mut(at))
            else {
                continue;
            };
            router.guard(stages.len(), &text);
            stages.push(Named {
                name: format!("lifecycle:{name}").into(),
                stage: Stage::Lifecycle(guard.clone()),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn guard(lifecycle: Lifecycle) -> Guard {
        let sunset = Sunset::parse("2027-03-01").expect("a date");
        Guard::new(lifecycle, Some(&sunset), Some("/v2")).expect("a guard")
    }

    #[test]
    fn lifecycle_guard_posture() {
        let draft = guard(Lifecycle::Draft);
        let retired = guard(Lifecycle::Retired);
        let deprecated = guard(Lifecycle::Deprecated);
        assert_eq!(draft.posture(None), [API_REOPENED]);
        assert_eq!(retired.posture(None), [API_REOPENED]);
        assert_eq!(retired.posture(Some(&deprecated)), [API_REOPENED]);
        assert!(retired.posture(Some(&draft)).is_empty());
        assert!(draft.posture(Some(&retired)).is_empty());
        assert!(deprecated.posture(None).is_empty());
        assert!(Guard::new(Lifecycle::Stable, None, None).is_none());
        assert!(Guard::new(Lifecycle::Preview, None, None).is_none());
    }

    #[test]
    fn successor_link_refuses_what_cannot_sit_in_angle_brackets() {
        let link = successor_link("/v2/pets").expect("a link");
        assert_eq!(link, "</v2/pets>; rel=\"successor-version\"");
        assert!(successor_link("/a>b").is_none());
        assert!(successor_link("/a b").is_none());
        assert!(successor_link("/\u{e9}").is_none());
    }
}
