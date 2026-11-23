//! The API catalog: the `apis` an app declares, compiled once per snapshot into
//! [`Api`] values that the table keeps next to its routers.
//!
//! The catalog describes and enforces a lifecycle; routing between versions stays the routers'
//! job. Three parts, one source: the rules in `check.rs` refuse entries that contradict each
//! other before anything compiles, the lifecycle guard ([`crate::middleware::lifecycle`]) makes
//! the routers answer as the lifecycle says, and [`render`] lists what the live table holds for
//! `GET /v1/catalog`. All three read the same compiled entries, so the catalog cannot say
//! `retired` while a router serves. Reference: `docs/ref/catalog.md`.

use std::sync::Arc;

use crate::host::HostPattern;
use crate::middleware::openapi::{Dialect, Document};
use crate::middleware::{Named, Stage};
use crate::router::CompiledRouter;
use podgate_model::{ApiRef, App, Lifecycle};

pub(crate) mod check;
mod links;
pub mod render;
mod sunset;

pub use links::Links;
pub use sunset::Sunset;

/// The OpenAPI description an entry names: the `openapi` middleware's name and its parsed
/// document. The catalog reads the document's title, version and operation count, never the
/// document.
#[derive(Debug)]
pub struct Description {
    name: Box<str>,
    document: Arc<Document>,
}

impl Description {
    /// The name of the app's `openapi` middleware.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The parsed document.
    #[must_use]
    pub fn document(&self) -> &Document {
        &self.document
    }

    /// `"3.0"` or `"3.1"`, the schema dialect of the document.
    #[must_use]
    pub fn dialect(&self) -> &'static str {
        match self.document.dialect() {
            Dialect::V30 => "3.0",
            Dialect::V31 => "3.1",
        }
    }
}

/// One compiled catalog entry of an app.
#[derive(Debug)]
pub struct Api {
    id: Box<str>,
    version: Box<str>,
    title: Option<Box<str>>,
    description: Option<Box<str>>,
    lifecycle: Lifecycle,
    routers: Box<[Box<str>]>,
    hosts: Box<[Box<str>]>,
    published: bool,
    sunset: Option<Sunset>,
    successor: Option<ApiRef>,
    openapi: Option<Description>,
}

const _: () = assert!(std::mem::size_of::<Api>() == 216);

impl Api {
    /// The API's id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The declared title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// The declared description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Where the API is in its life.
    #[must_use]
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }

    /// The names of the routers that serve the API.
    #[must_use]
    pub fn routers(&self) -> &[Box<str>] {
        &self.routers
    }

    /// The literal hosts the API's routers claim, sorted: `*.base` for a wildcard.
    #[must_use]
    pub fn hosts(&self) -> &[Box<str>] {
        &self.hosts
    }

    /// Whether the tenant agreed to list the API on the developer portal.
    #[must_use]
    pub fn published(&self) -> bool {
        self.published
    }

    /// The sunset day, when the entry has one.
    #[must_use]
    pub fn sunset(&self) -> Option<&Sunset> {
        self.sunset.as_ref()
    }

    /// The API that replaces this one.
    #[must_use]
    pub fn successor(&self) -> Option<&ApiRef> {
        self.successor.as_ref()
    }

    /// The OpenAPI description, when the entry names one.
    #[must_use]
    pub fn openapi(&self) -> Option<&Description> {
        self.openapi.as_ref()
    }
}

/// Builds the entries of `app` from its compiled `routers` (declaration order) and `stages`.
/// The compiler has refused every entry [`check`](check::check) finds wrong by now.
pub(crate) fn entries(app: &App, routers: &[CompiledRouter], stages: &[Named]) -> Vec<Api> {
    app.apis
        .iter()
        .map(|api| {
            let mut hosts: Vec<Box<str>> = api
                .routers
                .iter()
                .filter_map(|name| app.routers.iter().position(|router| router.name == *name))
                .filter_map(|at| routers.get(at))
                .flat_map(CompiledRouter::patterns)
                .map(|pattern| match pattern {
                    HostPattern::Exact(name) => name.clone(),
                    HostPattern::Wildcard(base) => format!("*.{base}").into(),
                })
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            let openapi = api.openapi.as_ref().and_then(|name| {
                stages.iter().find_map(|named| match &named.stage {
                    Stage::Openapi(openapi) if named.name == *name => Some(Description {
                        name: name.clone(),
                        document: Arc::clone(openapi.document()),
                    }),
                    _ => None,
                })
            });
            Api {
                id: api.id.clone(),
                version: api.version.clone(),
                title: api.title.clone(),
                description: api.description.clone(),
                lifecycle: api.lifecycle,
                routers: api.routers.clone().into_boxed_slice(),
                hosts: hosts.into_boxed_slice(),
                published: api.published,
                sunset: api
                    .sunset
                    .as_deref()
                    .and_then(|text| Sunset::parse(text).ok()),
                successor: api.successor.clone(),
                openapi,
            }
        })
        .collect()
}
