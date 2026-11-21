//! The Gateway API objects the source reads, as plain serde structs.
//!
//! Only the fields the translation uses are declared (the same reason change 0072 did not take
//! `k8s-openapi`): unknown fields are tolerated on read. The ones podgate cannot honour but must
//! not ignore (`timeouts`, `sessionPersistence`, `retry` on a rule) are kept as raw values so the
//! translation can refuse the route and say why.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::super::client::{ObjectMeta, Resource};

/// The API group of the Gateway API.
pub const GROUP: &str = "gateway.networking.k8s.io";

/// The controller name a `GatewayClass` must carry for this source to serve its Gateways.
pub const CONTROLLER: &str = "podgate.io/gateway-controller";

macro_rules! resource {
    ($type:ty, $group:expr, $version:expr, $plural:expr, $kind:expr, $namespaced:expr) => {
        impl Resource for $type {
            const GROUP: &'static str = $group;
            const VERSION: &'static str = $version;
            const PLURAL: &'static str = $plural;
            const KIND: &'static str = $kind;
            const NAMESPACED: bool = $namespaced;

            fn meta(&self) -> &ObjectMeta {
                &self.metadata
            }
        }
    };
}

/// A `GatewayClass`: which controller serves the Gateways that name it.
#[derive(Debug, Deserialize)]
pub struct GatewayClass {
    /// Name.
    pub metadata: ObjectMeta,
    /// The class settings.
    #[serde(default)]
    pub spec: GatewayClassSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The part of a `GatewayClass` spec the source reads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// The controller that serves the class, `podgate.io/gateway-controller` for this one.
    #[serde(default)]
    pub controller_name: String,
}

resource!(
    GatewayClass,
    GROUP,
    "v1",
    "gatewayclasses",
    "GatewayClass",
    false
);

/// A `Gateway`: listeners that bound the routes that may attach.
#[derive(Debug, Deserialize)]
pub struct Gateway {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The listeners.
    #[serde(default)]
    pub spec: GatewaySpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The part of a Gateway spec the source reads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// The class that serves the Gateway.
    #[serde(default)]
    pub gateway_class_name: String,
    /// The listeners.
    #[serde(default)]
    pub listeners: Vec<Listener>,
}

/// One listener of a Gateway.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Listener {
    /// Unique within the Gateway; routes name it in `sectionName`.
    #[serde(default)]
    pub name: String,
    /// The port; the node binds it (the source maps it to an entry point).
    #[serde(default)]
    pub port: u16,
    /// `HTTP`, `HTTPS`, `TLS`, `TCP` or `UDP`. Only the first two carry HTTP routes.
    #[serde(default)]
    pub protocol: String,
    /// The host names the listener serves; absent means every name.
    #[serde(default)]
    pub hostname: Option<String>,
    /// TLS settings of an `HTTPS` listener.
    #[serde(default)]
    pub tls: Option<ListenerTls>,
    /// Which routes may attach.
    #[serde(default)]
    pub allowed_routes: Option<AllowedRoutes>,
}

/// The TLS settings of a listener.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerTls {
    /// `Terminate` (the default) or `Passthrough`.
    #[serde(default)]
    pub mode: Option<String>,
    /// The Secrets that hold the certificates.
    #[serde(default)]
    pub certificate_refs: Vec<ObjectReference>,
}

/// A reference to a Secret (or another kind, which the source refuses).
#[derive(Debug, Deserialize)]
pub struct ObjectReference {
    /// The API group; empty or absent is the core group.
    #[serde(default)]
    pub group: Option<String>,
    /// The kind; absent is `Secret`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The name.
    #[serde(default)]
    pub name: String,
    /// The namespace; absent is the referrer's own.
    #[serde(default)]
    pub namespace: Option<String>,
}

/// Which routes a listener accepts.
#[derive(Debug, Default, Deserialize)]
pub struct AllowedRoutes {
    /// From which namespaces. Absent: the Gateway's own (`Same`).
    #[serde(default)]
    pub namespaces: Option<RouteNamespaces>,
    /// Which route kinds. Absent: the kinds the protocol supports.
    #[serde(default)]
    pub kinds: Vec<RouteKindRef>,
}

/// The `allowedRoutes.namespaces` selector.
#[derive(Debug, Default, Deserialize)]
pub struct RouteNamespaces {
    /// `Same` (the default), `All` or `Selector`.
    #[serde(default)]
    pub from: Option<String>,
    /// The label selector of `Selector`.
    #[serde(default)]
    pub selector: Option<LabelSelector>,
}

/// A Kubernetes label selector.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    /// Labels that must have exactly these values.
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    /// Set-based requirements.
    #[serde(default)]
    pub match_expressions: Vec<SelectorRequirement>,
}

/// One `matchExpressions` entry.
#[derive(Debug, Deserialize)]
pub struct SelectorRequirement {
    /// The label key.
    #[serde(default)]
    pub key: String,
    /// `In`, `NotIn`, `Exists` or `DoesNotExist`.
    #[serde(default)]
    pub operator: String,
    /// The values of `In` and `NotIn`.
    #[serde(default)]
    pub values: Vec<String>,
}

/// A route kind in `allowedRoutes.kinds`.
#[derive(Debug, Deserialize)]
pub struct RouteKindRef {
    /// The group; absent is the Gateway API's.
    #[serde(default)]
    pub group: Option<String>,
    /// `HTTPRoute`, `GRPCRoute`, ...
    #[serde(default)]
    pub kind: String,
}

resource!(Gateway, GROUP, "v1", "gateways", "Gateway", true);

/// A core `Namespace`: its labels decide `allowedRoutes.namespaces.from: Selector`.
#[derive(Debug, Deserialize)]
pub struct Namespace {
    /// Name and labels.
    pub metadata: ObjectMeta,
}

resource!(Namespace, "", "v1", "namespaces", "Namespace", false);

/// A `ReferenceGrant`: the target namespace's permission for objects of other namespaces to
/// refer to its objects.
#[derive(Debug, Deserialize)]
pub struct ReferenceGrant {
    /// Name, namespace (the target's).
    pub metadata: ObjectMeta,
    /// Who may refer to what.
    #[serde(default)]
    pub spec: ReferenceGrantSpec,
}

/// The `from` and `to` lists of a grant.
#[derive(Debug, Default, Deserialize)]
pub struct ReferenceGrantSpec {
    /// The referrers.
    #[serde(default)]
    pub from: Vec<GrantFrom>,
    /// The objects they may refer to.
    #[serde(default)]
    pub to: Vec<GrantTo>,
}

/// A referrer a grant allows.
#[derive(Debug, Deserialize)]
pub struct GrantFrom {
    /// The referrer's API group.
    #[serde(default)]
    pub group: String,
    /// The referrer's kind.
    #[serde(default)]
    pub kind: String,
    /// The referrer's namespace.
    #[serde(default)]
    pub namespace: String,
}

/// An object a grant lets others refer to.
#[derive(Debug, Deserialize)]
pub struct GrantTo {
    /// The target's API group; empty is the core group.
    #[serde(default)]
    pub group: String,
    /// The target's kind.
    #[serde(default)]
    pub kind: String,
    /// The target's name; absent is every object of the kind in the namespace.
    #[serde(default)]
    pub name: Option<String>,
}

resource!(
    ReferenceGrant,
    GROUP,
    "v1beta1",
    "referencegrants",
    "ReferenceGrant",
    true
);

/// A `parentRefs` entry: the Gateway (and listener) a route wants to attach to.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentRef {
    /// The group; absent is the Gateway API's.
    #[serde(default)]
    pub group: Option<String>,
    /// The kind; absent is `Gateway`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The parent's namespace; absent is the route's.
    #[serde(default)]
    pub namespace: Option<String>,
    /// The parent's name.
    #[serde(default)]
    pub name: String,
    /// The listener, by name.
    #[serde(default)]
    pub section_name: Option<String>,
    /// The listener, by port.
    #[serde(default)]
    pub port: Option<u16>,
}

/// A `backendRefs` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendRef {
    /// The group; empty or absent is the core group.
    #[serde(default)]
    pub group: Option<String>,
    /// The kind; absent is `Service`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The Service's name.
    #[serde(default)]
    pub name: String,
    /// The Service's namespace; absent is the route's.
    #[serde(default)]
    pub namespace: Option<String>,
    /// The Service port. Required for a Service.
    #[serde(default)]
    pub port: Option<u16>,
    /// The share of traffic, `1` when absent; `0` sends nothing.
    #[serde(default)]
    pub weight: Option<u32>,
    /// Filters of this one backend, which podgate cannot express.
    #[serde(default)]
    pub filters: Vec<Value>,
}

/// A route filter of any type; only the field named by `type` is read.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    /// `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`, `URLRewrite`,
    /// `RequestMirror` or `ExtensionRef`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// The settings of `RequestHeaderModifier`.
    #[serde(default)]
    pub request_header_modifier: Option<HeaderModifier>,
    /// The settings of `ResponseHeaderModifier`.
    #[serde(default)]
    pub response_header_modifier: Option<HeaderModifier>,
    /// The settings of `RequestRedirect`.
    #[serde(default)]
    pub request_redirect: Option<Redirect>,
    /// The settings of `URLRewrite`.
    #[serde(default, rename = "urlRewrite")]
    pub url_rewrite: Option<UrlRewrite>,
    /// The settings of `RequestMirror`.
    #[serde(default)]
    pub request_mirror: Option<Mirror>,
    /// The reference of `ExtensionRef`.
    #[serde(default)]
    pub extension_ref: Option<Value>,
}

/// `set`, `add` and `remove` of a header modifier.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeaderModifier {
    /// Headers to overwrite.
    #[serde(default)]
    pub set: Vec<HeaderValue>,
    /// Headers to append to; podgate cannot, so a modifier that uses it is refused.
    #[serde(default)]
    pub add: Vec<HeaderValue>,
    /// Header names to remove.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// A header name and value.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderValue {
    /// The name.
    #[serde(default)]
    pub name: String,
    /// The value.
    #[serde(default)]
    pub value: String,
}

/// A `RequestRedirect`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirect {
    /// `http` or `https`.
    #[serde(default)]
    pub scheme: Option<String>,
    /// The host name of the target.
    #[serde(default)]
    pub hostname: Option<String>,
    /// The port of the target.
    #[serde(default)]
    pub port: Option<u16>,
    /// How the path changes.
    #[serde(default)]
    pub path: Option<PathModifier>,
    /// `301` or `302` (the default).
    #[serde(default)]
    pub status_code: Option<u16>,
}

/// A path change of a redirect or rewrite.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathModifier {
    /// `ReplaceFullPath` or `ReplacePrefixMatch`.
    #[serde(default, rename = "type")]
    pub kind: String,
    /// The new path of `ReplaceFullPath`.
    #[serde(default)]
    pub replace_full_path: Option<String>,
    /// The new prefix of `ReplacePrefixMatch`.
    #[serde(default)]
    pub replace_prefix_match: Option<String>,
}

/// A `URLRewrite`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UrlRewrite {
    /// The new `Host`; podgate cannot, so a rewrite that sets it is refused.
    #[serde(default)]
    pub hostname: Option<String>,
    /// How the path changes.
    #[serde(default)]
    pub path: Option<PathModifier>,
}

/// A `RequestMirror`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mirror {
    /// Where the copy goes.
    #[serde(default)]
    pub backend_ref: Option<BackendRef>,
    /// The share of requests copied, in percent.
    #[serde(default)]
    pub percent: Option<u32>,
    /// The share of requests copied, as a fraction.
    #[serde(default)]
    pub fraction: Option<Fraction>,
}

/// A fraction of requests.
#[derive(Debug, Clone, Deserialize)]
pub struct Fraction {
    /// The numerator.
    #[serde(default)]
    pub numerator: u32,
    /// The denominator; `100` when absent.
    #[serde(default)]
    pub denominator: Option<u32>,
}

/// An HTTP header or query parameter match.
#[derive(Debug, Clone, Deserialize)]
pub struct NameMatch {
    /// `Exact` (the default) or `RegularExpression`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// The header or parameter name.
    #[serde(default)]
    pub name: String,
    /// The value or expression.
    #[serde(default)]
    pub value: String,
}

/// An `HTTPRoute`.
#[derive(Debug, Deserialize)]
pub struct HttpRoute {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The route.
    #[serde(default)]
    pub spec: HttpRouteSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The spec of an HTTPRoute.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteSpec {
    /// The listeners it wants to attach to.
    #[serde(default)]
    pub parent_refs: Vec<ParentRef>,
    /// The host names it serves; absent inherits the listener's.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// The rules.
    #[serde(default)]
    pub rules: Vec<HttpRouteRule>,
}

/// One rule of an HTTPRoute.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRouteRule {
    /// The matches (any of); absent is one match of every path.
    #[serde(default)]
    pub matches: Vec<HttpMatch>,
    /// The filters, in order.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Where the requests go.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
    /// Not supported.
    #[serde(default)]
    pub timeouts: Option<Value>,
    /// Not supported.
    #[serde(default)]
    pub session_persistence: Option<Value>,
    /// Not supported.
    #[serde(default)]
    pub retry: Option<Value>,
}

/// One match of an HTTPRoute rule: all of its parts must hold.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpMatch {
    /// The path.
    #[serde(default)]
    pub path: Option<PathMatch>,
    /// Header matches.
    #[serde(default)]
    pub headers: Vec<NameMatch>,
    /// Query parameter matches.
    #[serde(default)]
    pub query_params: Vec<NameMatch>,
    /// The method.
    #[serde(default)]
    pub method: Option<String>,
}

/// A path match.
#[derive(Debug, Default, Deserialize)]
pub struct PathMatch {
    /// `Exact`, `PathPrefix` (the default) or `RegularExpression`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// The path or expression; `/` when absent.
    #[serde(default)]
    pub value: Option<String>,
}

resource!(HttpRoute, GROUP, "v1", "httproutes", "HTTPRoute", true);

/// A `GRPCRoute`.
#[derive(Debug, Deserialize)]
pub struct GrpcRoute {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The route.
    #[serde(default)]
    pub spec: GrpcRouteSpec,
    /// The status as the cluster holds it; only the status writer reads it.
    #[serde(default)]
    pub status: Option<Value>,
}

/// The spec of a GRPCRoute.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRouteSpec {
    /// The listeners it wants to attach to.
    #[serde(default)]
    pub parent_refs: Vec<ParentRef>,
    /// The host names it serves; absent inherits the listener's.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// The rules.
    #[serde(default)]
    pub rules: Vec<GrpcRouteRule>,
}

/// One rule of a GRPCRoute.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrpcRouteRule {
    /// The matches (any of); absent is every gRPC request.
    #[serde(default)]
    pub matches: Vec<GrpcMatch>,
    /// The filters, in order.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Where the requests go.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
    /// Not supported.
    #[serde(default)]
    pub session_persistence: Option<Value>,
}

/// One match of a GRPCRoute rule.
#[derive(Debug, Default, Deserialize)]
pub struct GrpcMatch {
    /// The service and method.
    #[serde(default)]
    pub method: Option<GrpcMethod>,
    /// Header matches.
    #[serde(default)]
    pub headers: Vec<NameMatch>,
}

/// A gRPC service and method match.
#[derive(Debug, Default, Deserialize)]
pub struct GrpcMethod {
    /// `Exact` (the default) or `RegularExpression`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// The service name, such as `helloworld.Greeter`; absent matches every service.
    #[serde(default)]
    pub service: Option<String>,
    /// The method name; absent matches every method.
    #[serde(default)]
    pub method: Option<String>,
}

resource!(GrpcRoute, GROUP, "v1", "grpcroutes", "GRPCRoute", true);
