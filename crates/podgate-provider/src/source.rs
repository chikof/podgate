//! The contract between a source (Docker, Kubernetes, Nomad, a file) and the core.
//!
//! A source watches one backend and sends [`Update`]s on a channel. An update that carries a
//! [`State`] is the complete desired state of that source and replaces the previous one; an
//! update that carries an outage keeps the previous state (an outage of Docker must not delete
//! every route) and only reports the error.
//!
//! Objects are standard `podgate-model` entities. A source fills in what it knows (routers,
//! services, revisions, TLS) and leaves `tenant` and `declared_by` of the [`App`] to the core: the
//! tenant comes from the [`TenantClaim`] next to the object, `declared_by` from the [`Origin`].

use podgate_model::{App, Certificate};
use serde::Serialize;
use tokio::sync::mpsc::Sender;

/// What an object is. Part of an object's identity, so an app and a certificate of one source may
/// share a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectKind {
    /// An [`App`].
    App,
    /// A [`Certificate`].
    Certificate,
}

/// The identity of one object of one source: what quarantine, reports and conflicts point at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectRef {
    /// The name of the source (its `[[source]]` entry).
    pub source: Box<str>,
    /// Whether it is an app or a certificate.
    pub kind: ObjectKind,
    /// The source's own name for the object (a container name, `namespace/name`, a file stem).
    pub object: Box<str>,
}

/// Where an object came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The name of the source that sends it. Must equal the name of the update it travels in.
    pub source: Box<str>,
    /// The source's own name for the object. Unique among the source's objects of one kind.
    pub object: Box<str>,
    /// When the backend first saw the object, as a number that only has to order objects of one
    /// source against each other and against other sources' (unix seconds when the backend
    /// knows, `0` when it does not). It decides which of two conflicting objects is the older
    /// one and stays; equal values order by source name and object name. The core reads no
    /// clock.
    pub first_seen: u64,
}

/// Who an object says it belongs to.
///
/// Both parts are optional. `mapped` is the tenant the source's own configuration assigns (by
/// network, namespace or a fixed name): it is the operator's decision. `label` is a tenant named
/// by a label or annotation of the object itself: it is the deployer's claim, honoured only for
/// tenants that list the source in `label_sources` (see [`crate::trust`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TenantClaim {
    /// The tenant the source maps the object to.
    pub mapped: Option<Box<str>>,
    /// The tenant the object names for itself.
    pub label: Option<Box<str>>,
}

impl TenantClaim {
    /// No claim: the object belongs to the default tenant.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The source maps the object to `tenant`.
    #[must_use]
    pub fn mapped(tenant: &str) -> Self {
        Self {
            mapped: Some(tenant.into()),
            label: None,
        }
    }

    /// The object names `tenant` itself, on top of the mapping (if any).
    #[must_use]
    pub fn with_label(mut self, tenant: &str) -> Self {
        self.label = Some(tenant.into());
        self
    }
}

/// One app a source declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceApp {
    /// Where it came from.
    pub origin: Origin,
    /// Who it belongs to.
    pub tenant: TenantClaim,
    /// The app. `id` is the source's local id (the core prefixes it); `tenant` and `declared_by`
    /// are overwritten.
    pub app: App,
}

/// One certificate a source declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCertificate {
    /// Where it came from.
    pub origin: Origin,
    /// Who it belongs to. Its hosts must lie where that tenant may claim hosts.
    pub tenant: TenantClaim,
    /// The certificate.
    pub certificate: Certificate,
}

/// The complete desired state of one source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// Its apps.
    pub apps: Vec<SourceApp>,
    /// Its certificates.
    pub certificates: Vec<SourceCertificate>,
}

impl SourceApp {
    /// A text that changes whenever the object does: quarantine uses it to tell that a source
    /// changed an object. Never logged: it holds whatever the object holds.
    pub(crate) fn fingerprint(&self) -> Box<str> {
        fingerprint(&(&self.tenant, &self.app))
    }
}

impl SourceCertificate {
    /// See [`SourceApp::fingerprint`].
    pub(crate) fn fingerprint(&self) -> Box<str> {
        fingerprint(&(&self.tenant, &self.certificate))
    }
}

fn fingerprint(value: &impl Serialize) -> Box<str> {
    // Serializing plain data into a string cannot fail; an empty text would only make two
    // different objects compare equal, which `merge` then reports as unchanged, never wrongly
    // accepted.
    serde_json::to_string(value).unwrap_or_default().into()
}

/// What a source tells the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateBody {
    /// The complete current state of the source. Replaces the previous one.
    State(State),
    /// The backend cannot be reached. The previous state stays in force.
    Outage(Box<str>),
}

/// One message of a source to the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The name of the sending source.
    pub source: Box<str>,
    /// The state or the outage.
    pub body: UpdateBody,
}

impl Update {
    /// The complete state of `source`.
    #[must_use]
    pub fn state(source: &str, apps: Vec<SourceApp>, certificates: Vec<SourceCertificate>) -> Self {
        Self {
            source: source.into(),
            body: UpdateBody::State(State { apps, certificates }),
        }
    }

    /// `source` cannot reach its backend; its previous state stays.
    #[must_use]
    pub fn outage(source: &str, error: &str) -> Self {
        Self {
            source: source.into(),
            body: UpdateBody::Outage(error.into()),
        }
    }
}

/// A source of declarations: one backend, watched until the program ends.
pub trait Source: Send + 'static {
    /// The source's name: unique, the one in its `[[source]]` entry and in `declared_by`.
    fn name(&self) -> &str;

    /// Watches the backend and sends an [`Update`] at start and on every change, until the
    /// channel closes. A source that loses its backend sends [`Update::outage`] and keeps trying;
    /// it never sends an empty state to say "unreachable".
    fn run(self, updates: Sender<Update>) -> impl Future<Output = ()> + Send;
}
