//! Merging the states of all sources into one snapshot.
//!
//! The merge is a pure function of the sources' states, the configuration and the set of
//! quarantined objects. It never invents a tenant, never lets an object through that the trust
//! rule or the upstream policy refuses (those objects are dropped and reported), and writes the
//! snapshot in a canonical form: tenants, apps and certificates sorted, every object's keys
//! sorted. The same inputs give the same bytes, so a hash of them decides whether anything has to
//! be pushed.
//!
//! - App ids are `<source>-<local id>`, lowercased with every character outside `a-z 0-9 . _ -`
//!   turned into `-`. Two objects that still land on one id (`a`/`b-c` and `a-b`/`c`) are a
//!   collision; the older object keeps the id and the newer one is dropped and reported.
//! - `declared_by` is `<source kind>/<source name>:<object>`, for example `docker/local:web-1`.
//! - Tenants come from the configuration only: the configured ones plus the default tenant. An
//!   object naming a tenant that does not exist is dropped, never defaulted.

use std::collections::{BTreeMap, BTreeSet};

use podgate_model::{App, Certificate, EntryPointPolicy, Snapshot, Tenant};
use serde_json::{Map, Value};

use crate::config::{Config, Operator, TenantConfig};
use crate::policy::UpstreamPolicy;
use crate::source::{ObjectKind, ObjectRef, SourceApp, SourceCertificate, State, TenantClaim};
use crate::trust::{HostPattern, Problem, Resolved, RouterHosts, Trust};

/// Something the merge or a later stage noticed about an object, for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// A stable code: `foreign_host_claim`, `unknown_tenant`, `catch_all_not_allowed`,
    /// `upstream_forbidden`, `invalid_matcher`, `invalid_host`, `app_id_collision`,
    /// `label_ignored`, `quarantined`, `quarantine_released` and a few more, each documented in
    /// `docs/ref/provider.md`.
    pub code: &'static str,
    /// The object's source.
    pub source: Box<str>,
    /// The object's name in its source.
    pub object: Box<str>,
    /// `<kind>/<name>:<object>`.
    pub declared_by: Box<str>,
    /// What happened, in words.
    pub message: Box<str>,
    /// Whether the object stayed out of the snapshot because of it.
    pub dropped: bool,
}

/// An object that is in the merged snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Included {
    /// Its identity.
    pub object: ObjectRef,
    /// Its `declared_by`: what the daemon's conflict list names.
    pub declared_by: Box<str>,
    /// Its age stamp, see [`crate::source::Origin::first_seen`].
    pub first_seen: u64,
    /// The text that changes when the source changes the object.
    pub fingerprint: Box<str>,
}

/// The result of one merge.
#[derive(Debug, Clone)]
pub struct Merged {
    snapshot: Snapshot,
    findings: Vec<Finding>,
    included: Vec<Included>,
    fingerprint: Box<str>,
}

impl Merged {
    /// The snapshot, with version `0`: the version is the push's business.
    #[must_use]
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// What the merge noticed, in the order it processed the objects.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The objects in the snapshot, oldest first.
    #[must_use]
    pub fn included(&self) -> &[Included] {
        &self.included
    }

    /// The canonical text of the snapshot at version `0`. Equal text, equal snapshot.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The canonical JSON of the snapshot at `version`: the body of the push.
    #[must_use]
    pub fn body(&self, version: u64) -> String {
        let mut snapshot = self.snapshot.clone();
        snapshot.version = version;
        canonical(&snapshot)
    }

    /// Like [`Self::body`] with every secret shown as `[redacted]`: what `print` shows. The
    /// secrets are the skew secret, certificate and ACME account keys, and the EAB HMAC key.
    #[must_use]
    pub fn redacted_body(&self, version: u64) -> String {
        let mut snapshot = self.snapshot.clone();
        snapshot.version = version;
        let value = serde_json::to_value(&snapshot).unwrap_or(Value::Null);
        sorted(redact(value)).to_string()
    }
}

/// The canonical JSON text of `snapshot`: sorted object keys at every depth.
#[must_use]
pub fn canonical(snapshot: &Snapshot) -> String {
    // Serializing the model into a value cannot fail: it holds no non-string map keys.
    let value = serde_json::to_value(snapshot).unwrap_or(Value::Null);
    sorted(value).to_string()
}

fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect::<Map<String, Value>>(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// Keys whose string values are secrets in a snapshot.
const SECRET_KEYS: [&str; 4] = ["skew_secret", "key_pem", "account_key_pem", "hmac_key"];

fn redact(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if SECRET_KEYS.contains(&key.as_str()) && value.is_string() {
                        (key, Value::from("[redacted]"))
                    } else {
                        (key, redact(value))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        other => other,
    }
}

/// The rules and inputs that stay the same from one merge to the next.
#[derive(Debug, Clone)]
pub struct Merger {
    trust: Trust,
    policy: UpstreamPolicy,
    kinds: BTreeMap<Box<str>, Box<str>>,
    tenants: Vec<Tenant>,
    entry_points: Vec<EntryPointPolicy>,
    operator: Operator,
}

/// An object waiting to be looked at, in age order.
struct Candidate<'a> {
    source: &'a str,
    first_seen: u64,
    object: &'a str,
    payload: Payload<'a>,
}

enum Payload<'a> {
    App(&'a SourceApp),
    Certificate(&'a SourceCertificate),
}

impl Payload<'_> {
    fn kind(&self) -> ObjectKind {
        match self {
            Self::App(_) => ObjectKind::App,
            Self::Certificate(_) => ObjectKind::Certificate,
        }
    }

    fn origin_source(&self) -> &str {
        match self {
            Self::App(app) => &app.origin.source,
            Self::Certificate(cert) => &cert.origin.source,
        }
    }
}

fn tenant_entry(config: &TenantConfig) -> Tenant {
    Tenant {
        id: config.id.clone(),
        weight: config.weight,
        budget: config.budget,
    }
}

fn exclusive_entry(entry: &str, tenant: &str) -> EntryPointPolicy {
    EntryPointPolicy {
        name: entry.into(),
        tenants: Some(vec![tenant.into()]),
        forwarded_headers: None,
        proxy_protocol: None,
        timeouts: None,
        http2: None,
        redirect: None,
        allow_encoded_slash: None,
        max_header_bytes: None,
        underscore_headers: None,
    }
}

/// `<source>-<local id>` as an app id.
fn app_id(source: &str, local: &str) -> Box<str> {
    let slug: String = local
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{source}-{slug}").into()
}

impl Merger {
    /// The merger for `config`, checking upstreams against `policy`.
    #[must_use]
    pub fn new(config: &Config, policy: UpstreamPolicy) -> Self {
        let configured = config.tenants.iter().chain([&config.default_tenant]);
        let mut tenants: Vec<Tenant> = configured.clone().map(tenant_entry).collect();
        tenants.sort_by(|a, b| a.id.cmp(&b.id));
        let mut entry_points: Vec<EntryPointPolicy> = configured
            .flat_map(|tenant| {
                tenant
                    .exclusive_entry_points
                    .iter()
                    .map(|entry| exclusive_entry(entry, &tenant.id))
            })
            .collect();
        entry_points.sort_by(|a, b| a.name.cmp(&b.name));
        Self {
            trust: Trust::new(config),
            policy,
            kinds: config
                .sources
                .iter()
                .map(|source| (source.name.clone(), source.kind.clone()))
                .collect(),
            tenants,
            entry_points,
            operator: config.operator.clone(),
        }
    }

    /// Merges `states` (one per source name), leaving out the objects in `excluded`.
    #[must_use]
    pub fn merge(
        &self,
        states: &BTreeMap<Box<str>, State>,
        excluded: &BTreeSet<ObjectRef>,
    ) -> Merged {
        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        for (source, state) in states {
            let apps = state.apps.iter().map(|app| Candidate {
                source,
                first_seen: app.origin.first_seen,
                object: &app.origin.object,
                payload: Payload::App(app),
            });
            let certificates = state.certificates.iter().map(|cert| Candidate {
                source,
                first_seen: cert.origin.first_seen,
                object: &cert.origin.object,
                payload: Payload::Certificate(cert),
            });
            candidates.extend(apps.chain(certificates));
        }
        candidates.sort_by(|a, b| {
            (a.first_seen, a.source, a.payload.kind(), a.object).cmp(&(
                b.first_seen,
                b.source,
                b.payload.kind(),
                b.object,
            ))
        });

        let mut run = Run::default();
        for candidate in &candidates {
            self.consider(candidate, excluded, &mut run);
        }
        run.finish(self)
    }

    fn consider(&self, candidate: &Candidate<'_>, excluded: &BTreeSet<ObjectRef>, run: &mut Run) {
        let object = ObjectRef {
            source: candidate.source.into(),
            kind: candidate.payload.kind(),
            object: candidate.object.into(),
        };
        let Some(kind) = self.kinds.get(candidate.source) else {
            run.drop_object(
                &object,
                candidate.source,
                "unknown_source",
                format!("source {:?} is not in the configuration", candidate.source),
            );
            return;
        };
        let declared_by: Box<str> =
            format!("{kind}/{}:{}", candidate.source, candidate.object).into();
        if excluded.contains(&object) {
            return;
        }
        let mut notes = Notes::new(&object, &declared_by);
        if candidate.payload.origin_source() != candidate.source {
            notes.problem(Problem::new(
                "origin_mismatch",
                format!(
                    "the object says it comes from {:?} but arrived in an update of {:?}",
                    candidate.payload.origin_source(),
                    candidate.source
                ),
            ));
        }
        if !run.seen.insert(object.clone()) {
            notes.problem(Problem::new(
                "duplicate_object",
                "the source sent this object twice; the older one was used",
            ));
        }
        if !notes.dropped {
            match &candidate.payload {
                Payload::App(app) => self.app(app, &declared_by, run, &mut notes),
                Payload::Certificate(cert) => self.certificate(cert, run, &mut notes),
            }
        }
        run.findings.append(&mut notes.findings);
        if !notes.dropped {
            let fingerprint = match &candidate.payload {
                Payload::App(app) => app.fingerprint(),
                Payload::Certificate(cert) => cert.fingerprint(),
            };
            run.included.push(Included {
                object,
                declared_by,
                first_seen: candidate.first_seen,
                fingerprint,
            });
        }
    }

    fn resolve<'a>(
        &'a self,
        source: &str,
        claim: &'a TenantClaim,
        notes: &mut Notes,
    ) -> Option<Resolved<'a>> {
        match self.trust.resolve(source, claim) {
            Ok(resolved) => {
                if let Some(label) = resolved.ignored_label {
                    notes.note(
                        "label_ignored",
                        format!(
                            "the label names tenant {label:?}, which does not list source {source:?} in label_sources; the object belongs to tenant {} instead",
                            resolved.tenant.id
                        ),
                    );
                }
                Some(resolved)
            }
            Err(problem) => {
                notes.problem(problem);
                None
            }
        }
    }

    fn app(&self, source_app: &SourceApp, declared_by: &str, run: &mut Run, notes: &mut Notes) {
        let app = &source_app.app;
        if app.id.is_empty() {
            notes.problem(Problem::new("invalid_app", "the app has an empty id"));
        }
        let Some(tenant) = self.resolve(&source_app.origin.source, &source_app.tenant, notes)
        else {
            return;
        };
        let mut hosts_seen: BTreeSet<HostPattern> = BTreeSet::new();
        for router in &app.routers {
            let hosts = match RouterHosts::of(router) {
                Ok(hosts) => hosts,
                Err(err) => {
                    notes.problem(Problem::new(
                        err.code(),
                        format!("router {}: {err}", router.name),
                    ));
                    continue;
                }
            };
            for host in &hosts.hosts {
                if hosts_seen.insert(host.clone()) {
                    notes.check(self.trust.check_host(tenant, host));
                }
            }
            notes.check(Trust::check_catch_all(tenant, router, &hosts));
        }
        for forbidden in self.policy.forbidden_servers(&tenant.tenant.id, app) {
            notes.problem(Problem::new("upstream_forbidden", forbidden.message));
        }
        if notes.dropped {
            return;
        }
        let id = app_id(&source_app.origin.source, &app.id);
        if let Some(owner) = run.ids.get(&id) {
            notes.problem(Problem::new(
                "app_id_collision",
                format!("app id {id} is already taken by {owner}, the older object"),
            ));
            return;
        }
        run.ids.insert(id.clone(), declared_by.into());
        let mut app: App = app.clone();
        app.id = id;
        app.tenant = tenant.tenant.id.clone();
        app.declared_by = declared_by.into();
        run.apps.push(app);
    }

    fn certificate(&self, source_cert: &SourceCertificate, run: &mut Run, notes: &mut Notes) {
        let cert = &source_cert.certificate;
        if cert.hosts.is_empty() {
            notes.problem(Problem::new(
                "invalid_certificate",
                "the certificate lists no hosts",
            ));
        }
        let Some(tenant) = self.resolve(&source_cert.origin.source, &source_cert.tenant, notes)
        else {
            return;
        };
        for host in &cert.hosts {
            match HostPattern::parse(host) {
                Ok(pattern) => notes.check(self.trust.check_host(tenant, &pattern)),
                Err(err) => notes.problem(Problem::new("invalid_host", err.to_string())),
            }
        }
        if !notes.dropped {
            run.certificates.push(cert.clone());
        }
    }
}

/// The findings of one object, and whether it was dropped.
struct Notes {
    source: Box<str>,
    object: Box<str>,
    declared_by: Box<str>,
    findings: Vec<Finding>,
    dropped: bool,
}

impl Notes {
    fn new(object: &ObjectRef, declared_by: &str) -> Self {
        Self {
            source: object.source.clone(),
            object: object.object.clone(),
            declared_by: declared_by.into(),
            findings: Vec::new(),
            dropped: false,
        }
    }

    fn finding(&mut self, code: &'static str, message: impl Into<Box<str>>, dropped: bool) {
        self.dropped |= dropped;
        self.findings.push(Finding {
            code,
            source: self.source.clone(),
            object: self.object.clone(),
            declared_by: self.declared_by.clone(),
            message: message.into(),
            dropped,
        });
    }

    fn problem(&mut self, problem: Problem) {
        self.finding(problem.code, problem.message, true);
    }

    fn note(&mut self, code: &'static str, message: impl Into<Box<str>>) {
        self.finding(code, message, false);
    }

    fn check(&mut self, verdict: Result<(), Problem>) {
        if let Err(problem) = verdict {
            self.problem(problem);
        }
    }
}

#[derive(Default)]
struct Run {
    apps: Vec<App>,
    certificates: Vec<Certificate>,
    findings: Vec<Finding>,
    included: Vec<Included>,
    ids: BTreeMap<Box<str>, Box<str>>,
    seen: BTreeSet<ObjectRef>,
}

impl Run {
    fn drop_object(
        &mut self,
        object: &ObjectRef,
        source: &str,
        code: &'static str,
        message: String,
    ) {
        self.findings.push(Finding {
            code,
            source: source.into(),
            object: object.object.clone(),
            declared_by: format!("?/{source}:{}", object.object).into(),
            message: message.into(),
            dropped: true,
        });
    }

    fn finish(mut self, merger: &Merger) -> Merged {
        self.apps.sort_by(|a, b| a.id.cmp(&b.id));
        self.certificates
            .sort_by(|a, b| (&a.hosts, &a.cert_pem).cmp(&(&b.hosts, &b.cert_pem)));
        let snapshot = Snapshot {
            tenants: merger.tenants.clone(),
            apps: self.apps,
            certificates: self.certificates,
            entry_points: merger.entry_points.clone(),
            skew_secret: merger.operator.skew_secret.clone(),
            revert_window_secs: merger.operator.revert_window_secs,
            observability: merger.operator.observability.clone(),
            ..Snapshot::default()
        };
        Merged {
            fingerprint: canonical(&snapshot).into(),
            snapshot,
            findings: self.findings,
            included: self.included,
        }
    }
}
