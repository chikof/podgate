//! `networking.k8s.io/v1` Ingress to one podgate app.
//!
//! One Ingress becomes one app, `<namespace>.<name>`, with one revision `k8s` (Kubernetes rolls
//! pods out through readiness, so podgate sees no revision states). Each rule path becomes a
//! router, each distinct backend a `loadbalancer` service whose servers come from the Service's
//! EndpointSlices (see [`super::endpoints`]).
//!
//! | Ingress | podgate |
//! |---|---|
//! | `rules[].host`, exact or `*.` wildcard | `{"host": ...}` |
//! | `Exact` path | `{"path": p}` |
//! | `Prefix` path | `{"path_prefix": p}`; Kubernetes' element-wise prefix is podgate's whole-segment prefix, and a trailing `/` is ignored by both |
//! | `ImplementationSpecific` | `path_prefix`, or `path_regexp` with `podgate.io/path-type: regexp` |
//! | `defaultBackend` | a host-less `path_prefix: /` router at the lowest priority |
//! | `tls[]` with `secretName` | a certificate from the Secret |
//!
//! Anything that cannot be mapped faithfully rejects the whole Ingress with a reason: a route
//! that quietly differs from what the manifest says is worse than a missing one. The exceptions
//! are catch-all routers (the default backend and rules without a host) of a tenant that may not
//! have them, which are left out of the Ingress and reported; the rest of it is served.
//!
//! The annotations are in [`Annotations`]. Every `podgate.io/*` annotation that is not listed
//! rejects the Ingress, and so does every `traefik.ingress.kubernetes.io/*` one outside the
//! supported subset: a security annotation (an auth middleware, a redirect) that is silently
//! ignored would publish the service unprotected.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use podgate_model::{App, Declared, Router, TlsMode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::client::{ObjectMeta, Resource};
use super::endpoints::{PortRef, Secret, ServiceIndex};
use super::tenancy::Tenancy;
use crate::source::{Origin, SourceApp, SourceCertificate, TenantClaim};
use crate::trust::HostPattern;

/// The annotation Kubernetes used for the class before `spec.ingressClassName`.
const CLASS_ANNOTATION: &str = "kubernetes.io/ingress.class";

const PODGATE_PREFIX: &str = "podgate.io/";
const TRAEFIK_PREFIX: &str = "traefik.ingress.kubernetes.io/";
const MIDDLEWARE_PREFIX: &str = "podgate.io/middleware.";

/// The id of the one revision every Ingress app has.
pub const REVISION: &str = "k8s";

/// A `networking.k8s.io/v1` Ingress.
#[derive(Debug, Deserialize)]
pub struct Ingress {
    /// Name, namespace, annotations.
    pub metadata: ObjectMeta,
    /// The rules.
    #[serde(default)]
    pub spec: IngressSpec,
}

/// The parts of an Ingress spec the mapping reads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressSpec {
    /// The class that picks the controller.
    #[serde(default)]
    pub ingress_class_name: Option<String>,
    /// Where requests that match no rule go.
    #[serde(default)]
    pub default_backend: Option<Backend>,
    /// Host and path rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// TLS settings.
    #[serde(default)]
    pub tls: Vec<IngressTls>,
}

/// A host with its paths.
#[derive(Debug, Deserialize)]
pub struct Rule {
    /// The host; absent matches every host.
    #[serde(default)]
    pub host: Option<String>,
    /// The HTTP paths; a rule without them routes nothing.
    #[serde(default)]
    pub http: Option<HttpRule>,
}

/// The paths of one rule.
#[derive(Debug, Deserialize)]
pub struct HttpRule {
    /// The paths, in the order written.
    #[serde(default)]
    pub paths: Vec<HttpPath>,
}

/// One path and its backend.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpPath {
    /// The path text.
    #[serde(default)]
    pub path: Option<String>,
    /// `Exact`, `Prefix` or `ImplementationSpecific`.
    #[serde(default)]
    pub path_type: Option<String>,
    /// Where it goes.
    pub backend: Backend,
}

/// A backend: a Service, or a resource podgate does not support.
#[derive(Debug, Deserialize)]
pub struct Backend {
    /// The Service and port.
    #[serde(default)]
    pub service: Option<BackendService>,
    /// A custom resource reference (an object storage bucket, ...).
    #[serde(default)]
    pub resource: Option<Value>,
}

/// A Service backend.
#[derive(Debug, Deserialize)]
pub struct BackendService {
    /// The Service's name, in the Ingress's namespace.
    pub name: String,
    /// The port.
    #[serde(default)]
    pub port: BackendPort,
}

/// A port by number or by name.
#[derive(Debug, Default, Deserialize)]
pub struct BackendPort {
    /// The number.
    #[serde(default)]
    pub number: Option<u16>,
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
}

/// One `tls` entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressTls {
    /// The hosts the certificate covers; empty means the Ingress's rule hosts.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// The `kubernetes.io/tls` Secret that holds it.
    #[serde(default)]
    pub secret_name: Option<String>,
}

impl Resource for Ingress {
    const GROUP: &'static str = "networking.k8s.io";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "ingresses";
    const KIND: &'static str = "Ingress";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl Ingress {
    /// Whether the Ingress asks for the class `class`: by `spec.ingressClassName`, or, when that
    /// is unset, by the older `kubernetes.io/ingress.class` annotation.
    #[must_use]
    pub fn has_class(&self, class: &str) -> bool {
        match &self.spec.ingress_class_name {
            Some(name) => name == class,
            None => self
                .metadata
                .annotations
                .get(CLASS_ANNOTATION)
                .is_some_and(|name| name == class),
        }
    }
}

/// What the `podgate.io/*` and supported Traefik annotations ask for.
///
/// | Annotation | Meaning |
/// |---|---|
/// | `podgate.io/tenant` | A tenant label claim, honoured only for tenants that list the source in `label_sources` |
/// | `podgate.io/entry-points`, `traefik.ingress.kubernetes.io/router.entrypoints` | Comma-separated entry point names for every router |
/// | `podgate.io/priority`, `traefik.ingress.kubernetes.io/router.priority` | The routers' `priority` (an integer) |
/// | `podgate.io/middleware.<name>` | A middleware, as a JSON object `{"type": ..., ...}`, declared in the app |
/// | `podgate.io/chain` | Comma-separated middleware names for every router, in order |
/// | `podgate.io/tls`, `traefik.ingress.kubernetes.io/router.tls.certresolver` | `acme` or `on_demand` for hosts without a Secret (Traefik's resolver name means `acme`) |
/// | `podgate.io/path-type` | `regexp`: `ImplementationSpecific` paths are regular expressions |
/// | `traefik.ingress.kubernetes.io/router.tls` | Accepted and ignored: TLS follows the `tls` section |
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Annotations {
    /// `podgate.io/tenant`.
    pub tenant: Option<Box<str>>,
    /// The entry points.
    pub entry_points: Option<Vec<Box<str>>>,
    /// The router priority.
    pub priority: Option<i32>,
    /// The declared middlewares.
    pub middlewares: Vec<Declared>,
    /// The chain.
    pub chain: Vec<Box<str>>,
    /// The certificate mode of hosts without a Secret.
    pub tls: Option<TlsMode>,
    /// Whether `ImplementationSpecific` paths are regular expressions.
    pub path_regexp: bool,
}

fn list(value: &str) -> Vec<Box<str>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(Into::into)
        .collect()
}

impl Annotations {
    /// Reads the annotations of one Ingress.
    ///
    /// # Errors
    ///
    /// A message naming the annotation when it is unknown, has an invalid value, or is a
    /// Traefik annotation podgate does not implement.
    pub fn parse(annotations: &BTreeMap<String, String>) -> Result<Self, String> {
        let mut parsed = Self::default();
        for (key, value) in annotations {
            let bad = |why: &str| format!("annotation {key}: {why}");
            if let Some(name) = key.strip_prefix(MIDDLEWARE_PREFIX) {
                if name.is_empty() {
                    return Err(bad("the middleware needs a name after the dot"));
                }
                parsed
                    .middlewares
                    .push(middleware(name, value).map_err(|why| bad(&why))?);
                continue;
            }
            match key.as_str() {
                "podgate.io/tenant" => {
                    if value.is_empty() {
                        return Err(bad("is empty"));
                    }
                    parsed.tenant = Some(value.as_str().into());
                }
                "podgate.io/entry-points" | "traefik.ingress.kubernetes.io/router.entrypoints" => {
                    parsed.entry_points = Some(list(value));
                }
                "podgate.io/priority" | "traefik.ingress.kubernetes.io/router.priority" => {
                    parsed.priority = Some(
                        value
                            .trim()
                            .parse()
                            .map_err(|_| bad("must be a 32-bit integer"))?,
                    );
                }
                "podgate.io/chain" => parsed.chain = list(value),
                "podgate.io/tls" => {
                    parsed.tls = Some(match value.as_str() {
                        "acme" => TlsMode::Acme,
                        "on_demand" => TlsMode::OnDemand,
                        _ => return Err(bad("must be acme or on_demand")),
                    });
                }
                "traefik.ingress.kubernetes.io/router.tls.certresolver" => {
                    if value.is_empty() {
                        return Err(bad("is empty"));
                    }
                    parsed.tls = Some(TlsMode::Acme);
                }
                "traefik.ingress.kubernetes.io/router.tls" => {}
                "podgate.io/path-type" => match value.as_str() {
                    "regexp" => parsed.path_regexp = true,
                    "prefix" => {}
                    _ => return Err(bad("must be regexp or prefix")),
                },
                _ if key.starts_with(PODGATE_PREFIX) => {
                    return Err(bad("is not a podgate annotation"));
                }
                _ if key.starts_with(TRAEFIK_PREFIX) => {
                    return Err(bad(
                        "is a Traefik annotation podgate does not implement; ignoring it could publish the service without the protection it asks for",
                    ));
                }
                _ => {}
            }
        }
        Ok(parsed)
    }
}

fn middleware(name: &str, value: &str) -> Result<Declared, String> {
    let mut object = match serde_json::from_str::<Value>(value) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return Err("must be a JSON object".to_owned()),
        Err(err) => return Err(format!("is not valid JSON: {err}")),
    };
    if object.get("name").is_some_and(|inner| inner != name) {
        return Err("names a middleware other than the annotation's".to_owned());
    }
    object.insert("name".to_owned(), Value::from(name));
    serde_json::from_value(Value::Object(object))
        .map_err(|err| format!("is not a middleware (it needs a \"type\"): {err}"))
}

/// What an Ingress becomes.
#[derive(Debug)]
pub struct Mapped {
    /// The app.
    pub app: SourceApp,
    /// The certificates of its Secrets.
    pub certificates: Vec<SourceCertificate>,
    /// Routers left out, and why. The rest of the Ingress is served.
    pub notes: Vec<String>,
}

/// What the mapping reads besides the Ingress.
pub struct Cluster<'a> {
    /// The name of the source.
    pub source: &'a str,
    /// The tenant rules.
    pub tenancy: &'a Tenancy,
    /// Services and EndpointSlices.
    pub services: &'a ServiceIndex<'a>,
    /// Looks a `kubernetes.io/tls` Secret up by namespace and name.
    pub secret: &'a dyn Fn(&str, &str) -> Option<&'a Secret>,
}

/// Maps `ingress`.
///
/// # Errors
///
/// The reason the Ingress is refused as a whole.
pub fn map(ingress: &Ingress, cluster: &Cluster<'_>) -> Result<Mapped, String> {
    let meta = &ingress.metadata;
    let namespace = meta.namespace();
    let object = meta.key();
    let annotations = Annotations::parse(&meta.annotations)?;
    let first_seen = meta
        .creation_timestamp
        .as_deref()
        .and_then(unix_seconds)
        .unwrap_or(0);
    let origin = |object: String| Origin {
        source: cluster.source.into(),
        object: object.into(),
        first_seen,
    };

    let mut builder = Routes::new(&annotations, namespace, cluster.services);
    let mut rule_hosts: Vec<Box<str>> = Vec::new();
    for (rule_index, rule) in ingress.spec.rules.iter().enumerate() {
        let host = match rule.host.as_deref().filter(|host| !host.is_empty()) {
            Some(host) => {
                let pattern = HostPattern::parse(host)
                    .map_err(|err| format!("rules[{rule_index}].host: {err}"))?;
                let host: Box<str> = pattern.to_string().into();
                if !rule_hosts.contains(&host) {
                    rule_hosts.push(host.clone());
                }
                Some(host)
            }
            None => None,
        };
        let Some(http) = &rule.http else { continue };
        for (path_index, path) in http.paths.iter().enumerate() {
            builder
                .path(
                    &format!("r{rule_index}p{path_index}"),
                    host.as_deref(),
                    path,
                )
                .map_err(|why| format!("rules[{rule_index}].http.paths[{path_index}]: {why}"))?;
        }
    }
    if let Some(default) = &ingress.spec.default_backend {
        builder
            .default_backend(default)
            .map_err(|why| format!("defaultBackend: {why}"))?;
    }

    let claim: TenantClaim = cluster
        .tenancy
        .claim(namespace, annotations.tenant.as_deref());
    let vetted = cluster
        .tenancy
        .vet(&claim, &builder.routers)
        .map_err(|problem| format!("{}: {}", problem.code, problem.message))?;
    let mut notes = Vec::new();
    let mut kept = Vec::new();
    for (router, refused) in builder.routers.into_iter().zip(vetted.refused) {
        match refused {
            Some(problem) => notes.push(format!(
                "router {} left out: {}: {}",
                router.name, problem.code, problem.message
            )),
            None => kept.push(router),
        }
    }
    if kept.is_empty() {
        return Err(if notes.is_empty() {
            "it has no rule with a path and no defaultBackend, so there is nothing to route"
                .to_owned()
        } else {
            notes.join("; ")
        });
    }
    let used: BTreeSet<&str> = kept.iter().map(|router| &*router.service).collect();
    let services: Vec<Declared> = builder
        .services
        .into_values()
        .filter(|service| used.contains(&*service.name))
        .collect();

    let (mode, certificates) = tls(ingress, &annotations, &rule_hosts, cluster, &claim, &origin)?;
    let app = app_json(
        ingress,
        cluster.source,
        mode,
        &kept,
        &services,
        &annotations,
    )?;
    Ok(Mapped {
        app: SourceApp {
            origin: origin(object),
            tenant: claim,
            app,
        },
        certificates,
        notes,
    })
}

/// The routers and services of one Ingress, as they are built.
struct Routes<'a> {
    annotations: &'a Annotations,
    namespace: &'a str,
    index: &'a ServiceIndex<'a>,
    routers: Vec<Router>,
    services: BTreeMap<Box<str>, Declared>,
    matchers: BTreeSet<String>,
}

impl<'a> Routes<'a> {
    fn new(annotations: &'a Annotations, namespace: &'a str, index: &'a ServiceIndex<'a>) -> Self {
        Self {
            annotations,
            namespace,
            index,
            routers: Vec::new(),
            services: BTreeMap::new(),
            matchers: BTreeSet::new(),
        }
    }

    fn path(&mut self, name: &str, host: Option<&str>, path: &HttpPath) -> Result<(), String> {
        let leaf = self.leaf(path)?;
        let matcher = match host {
            Some(host) => json!({"all": [{"host": host}, leaf]}),
            None => leaf,
        };
        // Kubernetes allows the same host and path twice; the first wins there as here, and a
        // second identical router would be an ambiguity podgate refuses.
        if !self.matchers.insert(matcher.to_string()) {
            return Ok(());
        }
        let service = self.service(&path.backend)?;
        self.router(name, &matcher, &service, self.annotations.priority)
    }

    fn leaf(&self, path: &HttpPath) -> Result<Value, String> {
        let text = path.path.as_deref().unwrap_or("");
        let kind = path.path_type.as_deref().unwrap_or("");
        match kind {
            "Exact" | "Prefix" => {
                if !text.starts_with('/') {
                    return Err(format!("the {kind} path {text:?} must start with /"));
                }
            }
            "ImplementationSpecific" => {}
            other => {
                return Err(format!(
                    "pathType {other:?} is not Exact, Prefix or ImplementationSpecific"
                ));
            }
        }
        Ok(match kind {
            "Exact" => json!({ "path": text }),
            "ImplementationSpecific" if self.annotations.path_regexp && !text.is_empty() => {
                json!({ "path_regexp": text })
            }
            _ => {
                let prefix = if text.is_empty() { "/" } else { text };
                json!({ "path_prefix": prefix })
            }
        })
    }

    fn default_backend(&mut self, backend: &Backend) -> Result<(), String> {
        let service = self.service(backend)?;
        // Lowest priority: every rule of the tenant goes first.
        self.router(
            "default",
            &json!({ "path_prefix": "/" }),
            &service,
            Some(i32::MIN),
        )
    }

    fn router(
        &mut self,
        name: &str,
        matcher: &Value,
        service: &str,
        priority: Option<i32>,
    ) -> Result<(), String> {
        let mut router = json!({ "name": name, "match": matcher, "service": service });
        if let Some(entry_points) = &self.annotations.entry_points {
            router["entry_points"] = json!(entry_points);
        }
        if let Some(priority) = priority {
            router["priority"] = json!(priority);
        }
        if !self.annotations.chain.is_empty() {
            router["chain"] = json!(self.annotations.chain);
        }
        let router = serde_json::from_value(router).map_err(|err| err.to_string())?;
        self.routers.push(router);
        Ok(())
    }

    /// The name of the service for `backend`, declaring it on first use.
    fn service(&mut self, backend: &Backend) -> Result<String, String> {
        let Some(service) = &backend.service else {
            return Err(if backend.resource.is_some() {
                "resource backends are not supported; use a Service".to_owned()
            } else {
                "the backend names no Service".to_owned()
            });
        };
        let name = service.name.as_str();
        if name.is_empty() || name.contains(['/', '.']) {
            return Err(format!(
                "backend {name:?}: a backend names a plain Service of the Ingress's own namespace, never another namespace or a host"
            ));
        }
        let port = match (&service.port.number, &service.port.name) {
            (Some(number), None) => PortRef::Number(*number),
            (None, Some(port)) if !port.is_empty() => PortRef::Name(port.as_str().into()),
            _ => {
                return Err(format!(
                    "backend {name:?} needs exactly one of port number and port name"
                ));
            }
        };
        // Service names have no dots and port names have none either, so the key is unique.
        let key: Box<str> = format!("{name}.{port}").into();
        if !self.services.contains_key(&key) {
            let servers = self.index.servers(self.namespace, name, &port)?;
            let declared = serde_json::from_value(json!({
                "name": &*key,
                "type": "loadbalancer",
                "servers": servers.iter().map(|url| json!({ "url": &**url })).collect::<Vec<_>>(),
            }))
            .map_err(|err| err.to_string())?;
            self.services.insert(key.clone(), declared);
        }
        Ok(key.into())
    }
}

/// The certificate mode and the certificates of the Secrets of `spec.tls`.
fn tls(
    ingress: &Ingress,
    annotations: &Annotations,
    rule_hosts: &[Box<str>],
    cluster: &Cluster<'_>,
    claim: &TenantClaim,
    origin: &dyn Fn(String) -> Origin,
) -> Result<(TlsMode, Vec<SourceCertificate>), String> {
    let namespace = ingress.metadata.namespace();
    let mut certificates = Vec::new();
    for (index, entry) in ingress.spec.tls.iter().enumerate() {
        let Some(secret_name) = entry.secret_name.as_deref().filter(|name| !name.is_empty()) else {
            continue;
        };
        let hosts: Vec<Box<str>> = if entry.hosts.is_empty() {
            rule_hosts.to_vec()
        } else {
            entry
                .hosts
                .iter()
                .map(|host| {
                    HostPattern::parse(host)
                        .map(|pattern| pattern.to_string().into())
                        .map_err(|err| format!("tls[{index}].hosts: {err}"))
                })
                .collect::<Result<_, _>>()?
        };
        if hosts.is_empty() {
            return Err(format!(
                "tls[{index}] names no hosts and the Ingress has no host rule"
            ));
        }
        let secret = (cluster.secret)(namespace, secret_name).ok_or_else(|| {
            format!(
                "tls[{index}]: no Secret {namespace}/{secret_name} of type kubernetes.io/tls (it is missing, or has another type)"
            )
        })?;
        let pem = |key: &str| -> Result<String, String> {
            let value = secret.data.get(key).ok_or_else(|| {
                format!("tls[{index}]: Secret {namespace}/{secret_name} has no {key}")
            })?;
            let bytes = STANDARD.decode(value.trim()).map_err(|_| {
                format!(
                    "tls[{index}]: {key} of Secret {namespace}/{secret_name} is not valid base64"
                )
            })?;
            String::from_utf8(bytes).map_err(|_| {
                format!("tls[{index}]: {key} of Secret {namespace}/{secret_name} is not PEM text")
            })
        };
        certificates.push(SourceCertificate {
            origin: origin(format!("{}#tls-{index}", ingress.metadata.key())),
            tenant: claim.clone(),
            certificate: serde_json::from_value(json!({
                "hosts": hosts,
                "cert_pem": pem("tls.crt")?,
                "key_pem": pem("tls.key")?,
            }))
            .map_err(|err: serde_json::Error| err.to_string())?,
        });
    }
    // Without a Secret nothing orders a certificate until a handshake asks and the broker
    // approves it (`on_demand`), unless the Ingress says `acme`.
    Ok((annotations.tls.unwrap_or(TlsMode::OnDemand), certificates))
}

fn app_json(
    ingress: &Ingress,
    source: &str,
    mode: TlsMode,
    routers: &[Router],
    services: &[Declared],
    annotations: &Annotations,
) -> Result<App, String> {
    let meta = &ingress.metadata;
    let mode = match mode {
        TlsMode::Acme => "acme",
        TlsMode::OnDemand => "on_demand",
        TlsMode::Internal => "internal",
    };
    serde_json::from_value(json!({
        // The core replaces `tenant` and `declared_by`; they only have to exist.
        "id": format!("{}.{}", meta.namespace(), meta.name),
        "tenant": "default",
        "declared_by": format!("kubernetes/{source}:{}", meta.key()),
        "tls": { "mode": mode },
        "routers": routers,
        "middlewares": annotations.middlewares,
        "services": services,
        "revisions": [{ "id": REVISION, "state": "serving", "weight": 1 }],
    }))
    .map_err(|err: serde_json::Error| err.to_string())
}

/// Unix seconds of an RFC 3339 UTC timestamp such as `2026-11-20T12:30:00Z`.
pub(crate) fn unix_seconds(text: &str) -> Option<u64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let time = time.split('.').next()?;
    let mut time = time.split(':').map(str::parse::<i64>);
    let (hour, minute, second) = (time.next()?.ok()?, time.next()?.ok()?, time.next()?.ok()?);
    // Days since 1970-01-01 (Howard Hinnant's civil-from-days, inverted).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn timestamps_are_unix_seconds() {
        assert_eq!(unix_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_seconds("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(unix_seconds("2026-11-20T12:30:05Z"), Some(1_795_177_805));
        assert_eq!(unix_seconds("yesterday"), None);
    }

    #[test]
    fn annotations_refuse_what_they_do_not_know() {
        let parse = |key: &str, value: &str| {
            Annotations::parse(&BTreeMap::from([(key.to_owned(), value.to_owned())]))
        };
        assert!(parse("podgate.io/colour", "red").is_err());
        assert!(parse("traefik.ingress.kubernetes.io/router.middlewares", "a@b").is_err());
        assert!(parse("nginx.ingress.kubernetes.io/rewrite-target", "/").is_ok());
        assert!(parse("podgate.io/priority", "high").is_err());
        assert_eq!(
            parse("podgate.io/priority", "7").map(|parsed| parsed.priority),
            Ok(Some(7))
        );
    }
}
