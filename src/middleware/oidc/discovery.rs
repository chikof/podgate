//! What `oidc` asks the identity provider: its discovery document and its token endpoint.
//!
//! Both go through the bounded HTTP/1.1 client of `forward_auth` ([`Route`]): the connection is
//! made with the transport the middleware names, a host name is resolved once per call and every
//! answer is checked against the upstream address policy for the tenant, the first permitted
//! address is dialled, the body is read up to [`MAX_BODY`] bytes under a 5 second timeout, and a
//! redirect is a failure. The memory of a call is charged to the tenant's `max_buffer_bytes`
//! before the connection is made.
//!
//! # The discovery document
//!
//! `<issuer>/.well-known/openid-configuration`. It is used only when its `issuer` is the
//! configured one, byte for byte. An `https` issuer never sends the middleware to an `http`
//! endpoint (a downgrade): the authorization, token and JWKS endpoints must all be `https`.
//! When the document lists what it supports, the middleware needs the authorization code flow,
//! PKCE `S256` and the way it authenticates the client (`client_secret_basic`, or `none` for a
//! public client); a provider that cannot do that is refused, never worked around.
//!
//! # The token endpoint
//!
//! One `POST` per login, at most [`MAX_TOKEN_CALLS`] in flight on the node. The client secret
//! goes in the `Authorization` header (`client_secret_basic`, both parts form-encoded as RFC 6749
//! asks) and nowhere else; a public client sends its `client_id` in the body. Only the
//! `id_token` of the answer is read, the rest is dropped.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::budget::TenantBudget;
use crate::middleware::errors::fetch::Failure as CallFailure;
use crate::middleware::forward_auth::{Client, Parsed, Route, parse_url};
use crate::middleware::jwt_auth::jwks::{self, CHARGE, MAX_BODY, Target};
use crate::service::resolve::Resolver;
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Server, Transport};

/// How long a call may take.
pub(super) const TIMEOUT: Duration = Duration::from_secs(5);

/// How long a discovery document is fresh.
pub(super) const REFRESH_SECS: u64 = 3600;

/// The most token endpoint calls in flight on the node.
pub(super) const MAX_TOKEN_CALLS: usize = 32;

/// The permits of the token endpoint calls of every `oidc` middleware of the node.
static TOKEN_CALLS: Semaphore = Semaphore::const_new(MAX_TOKEN_CALLS);

/// The longest URL of the document.
const MAX_URL: usize = 2048;

/// The path of the document under the issuer.
const WELL_KNOWN: &str = "/.well-known/openid-configuration";

/// A server the middleware dials: where, and what to put in the request.
#[derive(Debug)]
pub(super) struct Endpoint {
    /// The server; a host name is resolved per call.
    pub(super) server: Server,
    /// The `Host` header: the authority as written.
    pub(super) host: Box<str>,
    /// The request target: the path and query.
    pub(super) target: Box<str>,
}

/// What the discovery document says the middleware needs of the provider.
#[derive(Debug)]
pub(super) struct Provider {
    /// Where the browser is sent to sign in.
    pub(super) authorization_endpoint: Box<str>,
    /// Where a code is redeemed.
    pub(super) token: Endpoint,
    /// Where the signing keys are.
    pub(super) jwks: Arc<Target>,
}

/// Why a discovery fetch gave no provider. Logged, never sent to a client.
#[derive(Debug, Error)]
pub(super) enum DiscoverError {
    #[error("the tenant has no room in its buffer budget for the fetch")]
    Budget,
    #[error("{0}")]
    Call(#[from] CallFailure),
    #[error("the issuer answered {0}")]
    Status(u16),
    #[error("the document is not a JSON object")]
    NotJson,
    #[error("the document names the issuer {0:?}, not the configured one")]
    IssuerMismatch(String),
    #[error("the document has no usable `{0}`")]
    Missing(&'static str),
    #[error("`{field}`: {reason}")]
    Unusable { field: &'static str, reason: String },
    #[error("an https issuer names an http `{0}`")]
    Downgrade(&'static str),
    #[error("the provider does not support {0}")]
    Unsupported(&'static str),
}

/// What a background discovery fetch needs, all owned.
pub(super) struct Discover {
    pub(super) issuer: Box<str>,
    pub(super) url: Arc<Parsed>,
    pub(super) transport: Arc<Transport>,
    pub(super) public_client: bool,
    pub(super) client: Client,
    pub(super) policy: UpstreamPolicy,
    pub(super) resolver: Resolver,
    pub(super) tenant: Box<str>,
    pub(super) budget: Arc<TenantBudget>,
}

/// The address of the discovery document of `issuer`.
///
/// # Errors
///
/// The reason the issuer cannot be used: not an absolute `http(s)` URL with an IP address or a
/// host name, or with a query or a fragment.
pub(super) fn document_url(issuer: &str) -> Result<Parsed, String> {
    if issuer.contains(['?', '#']) {
        return Err(format!(
            "issuer {issuer:?} has a query or a fragment; an issuer is a plain URL"
        ));
    }
    parse_url(
        &format!("{}{WELL_KNOWN}", issuer.trim_end_matches('/')),
        "issuer",
        MAX_URL,
    )
}

impl Discover {
    /// Fetches the document and reads it.
    pub(super) async fn run(&self) -> Result<Provider, DiscoverError> {
        let _charge = self.budget.charge(CHARGE).ok_or(DiscoverError::Budget)?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            self.url.target, self.url.host
        );
        let route = Route {
            server: &self.url.server,
            transport: &self.transport,
            resolver: &self.resolver,
            policy: &self.policy,
            tenant: &self.tenant,
        };
        let answer = self
            .client
            .call(&route, request.as_bytes(), MAX_BODY, TIMEOUT)
            .await?;
        if answer.status != 200 {
            return Err(DiscoverError::Status(answer.status));
        }
        let Ok(Value::Object(document)) = serde_json::from_slice(&answer.body) else {
            return Err(DiscoverError::NotJson);
        };
        provider_of(
            &document,
            &self.issuer,
            self.url.server.tls,
            &self.transport,
            self.public_client,
        )
    }
}

fn text<'a>(
    document: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, DiscoverError> {
    document
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(DiscoverError::Missing(field))
}

/// Whether the list `field` of the document, when it has one, holds `wanted`.
fn lacks(document: &Map<String, Value>, field: &str, wanted: &str) -> bool {
    document
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|list| !list.iter().any(|item| item.as_str() == Some(wanted)))
}

/// An endpoint of the document, read as the configuration reads a URL.
fn endpoint_of(
    document: &Map<String, Value>,
    field: &'static str,
    https: bool,
) -> Result<Parsed, DiscoverError> {
    let parsed = parse_url(text(document, field)?, field, MAX_URL)
        .map_err(|reason| DiscoverError::Unusable { field, reason })?;
    if https && !parsed.server.tls {
        return Err(DiscoverError::Downgrade(field));
    }
    Ok(parsed)
}

/// Reads a discovery document.
///
/// # Errors
///
/// [`DiscoverError`] for a document that names another issuer, lacks an endpoint the flow needs,
/// has one that is not a usable URL, downgrades an `https` issuer to `http`, or says the provider
/// cannot do the authorization code flow with PKCE `S256` and the client authentication in use.
pub(super) fn provider_of(
    document: &Map<String, Value>,
    issuer: &str,
    https: bool,
    transport: &Arc<Transport>,
    public_client: bool,
) -> Result<Provider, DiscoverError> {
    let named = text(document, "issuer")?;
    if named != issuer {
        return Err(DiscoverError::IssuerMismatch(named.to_owned()));
    }
    for (field, wanted, what) in [
        ("response_types_supported", "code", "response_type code"),
        (
            "grant_types_supported",
            "authorization_code",
            "the authorization_code grant",
        ),
        ("code_challenge_methods_supported", "S256", "PKCE S256"),
    ] {
        if lacks(document, field, wanted) {
            return Err(DiscoverError::Unsupported(what));
        }
    }
    let (method, what) = if public_client {
        ("none", "an unauthenticated (public) client")
    } else {
        ("client_secret_basic", "client_secret_basic")
    };
    if lacks(document, "token_endpoint_auth_methods_supported", method) {
        return Err(DiscoverError::Unsupported(what));
    }
    // Read for its checks; the browser is sent to the text as the document wrote it.
    endpoint_of(document, "authorization_endpoint", https)?;
    let token = endpoint_of(document, "token_endpoint", https)?;
    if !token.server.tls && transport.has_tls_settings() {
        return Err(DiscoverError::Unusable {
            field: "token_endpoint",
            reason: "the transport sets TLS options and the endpoint is plain http://".to_owned(),
        });
    }
    let jwks_text = text(document, "jwks_uri")?;
    let jwks = jwks::parse_uri(jwks_text, Arc::clone(transport)).map_err(|invalid| {
        DiscoverError::Unusable {
            field: "jwks_uri",
            reason: invalid.message,
        }
    })?;
    if https && !jwks.server.tls {
        return Err(DiscoverError::Downgrade("jwks_uri"));
    }
    Ok(Provider {
        authorization_endpoint: text(document, "authorization_endpoint")?.into(),
        token: Endpoint {
            server: token.server,
            host: token.host,
            target: token.target,
        },
        jwks: Arc::new(jwks),
    })
}

/// Why a code could not be redeemed.
#[derive(Debug, Error)]
pub(super) enum ExchangeError {
    #[error("the node is at its limit of token endpoint calls")]
    Busy,
    #[error("the tenant has no room in its buffer budget for the call")]
    Budget,
    #[error("{0}")]
    Call(#[from] CallFailure),
    #[error("the token endpoint answered {0}")]
    Rejected(u16),
    #[error("the token endpoint's answer has no `id_token`")]
    Malformed,
}

/// What redeeming a code needs. No `Debug`: it holds the client secret.
pub(super) struct Exchange<'a> {
    pub(super) client: &'a Client,
    pub(super) policy: &'a UpstreamPolicy,
    pub(super) resolver: &'a Resolver,
    pub(super) transport: &'a Transport,
    pub(super) tenant: &'a str,
    pub(super) budget: &'a Arc<TenantBudget>,
    pub(super) token: &'a Endpoint,
    pub(super) client_id: &'a str,
    pub(super) client_secret: Option<&'a str>,
    pub(super) code: &'a str,
    pub(super) verifier: &'a str,
    pub(super) redirect_uri: &'a str,
}

/// The request that redeems a code.
fn token_request(exchange: &Exchange<'_>) -> Vec<u8> {
    let mut form = form_urlencoded::Serializer::new(String::new());
    form.append_pair("grant_type", "authorization_code")
        .append_pair("code", exchange.code)
        .append_pair("redirect_uri", exchange.redirect_uri)
        .append_pair("code_verifier", exchange.verifier);
    let authorization = match exchange.client_secret {
        Some(secret) => {
            let encode =
                |part: &str| form_urlencoded::byte_serialize(part.as_bytes()).collect::<String>();
            let basic =
                STANDARD.encode(format!("{}:{}", encode(exchange.client_id), encode(secret)));
            format!("Authorization: Basic {basic}\r\n")
        }
        None => {
            form.append_pair("client_id", exchange.client_id);
            String::new()
        }
    };
    let body = form.finish();
    format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n{authorization}Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        exchange.token.target,
        exchange.token.host,
        body.len()
    )
    .into_bytes()
}

/// Redeems the code of `exchange` and returns the ID token of the answer.
///
/// # Errors
///
/// [`ExchangeError`]: the node is at its limit, the tenant's budget is full, the call failed, the
/// endpoint did not answer `200`, or its answer has no `id_token`.
pub(super) async fn redeem(exchange: &Exchange<'_>) -> Result<String, ExchangeError> {
    let _permit = TOKEN_CALLS.try_acquire().map_err(|_| ExchangeError::Busy)?;
    let _charge = exchange
        .budget
        .charge(CHARGE)
        .ok_or(ExchangeError::Budget)?;
    let route = Route {
        server: &exchange.token.server,
        transport: exchange.transport,
        resolver: exchange.resolver,
        policy: exchange.policy,
        tenant: exchange.tenant,
    };
    let answer = exchange
        .client
        .call(&route, &token_request(exchange), MAX_BODY, TIMEOUT)
        .await?;
    if answer.status != 200 {
        return Err(ExchangeError::Rejected(answer.status));
    }
    match serde_json::from_slice::<Value>(&answer.body) {
        Ok(Value::Object(mut answer)) => match answer.remove("id_token") {
            Some(Value::String(token)) if !token.is_empty() => Ok(token),
            _ => Err(ExchangeError::Malformed),
        },
        _ => Err(ExchangeError::Malformed),
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn document(extra: &Value) -> Map<String, Value> {
        let mut document = json!({
            "issuer": "https://idp.test",
            "authorization_endpoint": "https://idp.test/authorize",
            "token_endpoint": "https://idp.test/token",
            "jwks_uri": "https://idp.test/jwks",
        })
        .as_object()
        .expect("object")
        .clone();
        document.extend(extra.as_object().expect("object").clone());
        document
    }

    fn read(extra: &Value, public: bool) -> Result<Provider, DiscoverError> {
        provider_of(
            &document(extra),
            "https://idp.test",
            true,
            &Arc::new(Transport::default()),
            public,
        )
    }

    #[test]
    fn a_document_names_the_endpoints_the_flow_needs() {
        let provider = read(&json!({}), false).expect("provider");
        assert_eq!(
            &*provider.authorization_endpoint,
            "https://idp.test/authorize"
        );
        assert_eq!(&*provider.token.target, "/token");
        assert_eq!(provider.token.server.host(), Some("idp.test"));
        assert_eq!(provider.jwks.server.addr.port(), 443);
    }

    #[test]
    fn oidc_issuer_mismatch_refused() {
        let wrong = read(&json!({"issuer": "https://evil.test"}), false);
        assert!(
            matches!(wrong, Err(DiscoverError::IssuerMismatch(_))),
            "{wrong:?}"
        );
        // Byte for byte: a trailing slash is another issuer.
        let slash = read(&json!({"issuer": "https://idp.test/"}), false);
        assert!(
            matches!(slash, Err(DiscoverError::IssuerMismatch(_))),
            "{slash:?}"
        );
        let none = provider_of(
            &json!({"authorization_endpoint": "https://idp.test/a"})
                .as_object()
                .expect("object")
                .clone(),
            "https://idp.test",
            true,
            &Arc::new(Transport::default()),
            false,
        );
        assert!(
            matches!(none, Err(DiscoverError::Missing("issuer"))),
            "{none:?}"
        );
    }

    #[test]
    fn a_provider_that_cannot_do_the_flow_is_refused() {
        for (extra, public) in [
            (
                json!({"code_challenge_methods_supported": ["plain"]}),
                false,
            ),
            (json!({"response_types_supported": ["token"]}), false),
            (json!({"grant_types_supported": ["implicit"]}), false),
            (
                json!({"token_endpoint_auth_methods_supported": ["none"]}),
                false,
            ),
            (
                json!({"token_endpoint_auth_methods_supported": ["client_secret_post"]}),
                true,
            ),
        ] {
            let refused = read(&extra, public);
            assert!(
                matches!(refused, Err(DiscoverError::Unsupported(_))),
                "{extra}: {refused:?}"
            );
        }
        assert!(
            read(
                &json!({"code_challenge_methods_supported": ["plain", "S256"]}),
                false
            )
            .is_ok()
        );
        assert!(
            read(
                &json!({"token_endpoint_auth_methods_supported": ["none"]}),
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn an_https_issuer_never_names_an_http_endpoint() {
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let downgraded = read(&json!({ field: "http://idp.test/x" }), false);
            assert!(
                matches!(downgraded, Err(DiscoverError::Downgrade(_))),
                "{field}: {downgraded:?}"
            );
        }
        // An http issuer may name http endpoints.
        let plain = provider_of(
            &document(
                &json!({"issuer": "http://idp.test", "authorization_endpoint": "http://idp.test/a",
                "token_endpoint": "http://idp.test/t", "jwks_uri": "http://idp.test/k"}),
            ),
            "http://idp.test",
            false,
            &Arc::new(Transport::default()),
            false,
        );
        assert!(plain.is_ok(), "{plain:?}");
    }

    #[test]
    fn unusable_endpoints_are_refused() {
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            for bad in [
                json!("/relative"),
                json!(5),
                json!(""),
                json!("https://u:p@idp.test/x"),
                json!("ftp://idp.test/"),
            ] {
                let refused = read(&json!({ field: bad }), false);
                assert!(refused.is_err(), "{field}: {bad}");
            }
        }
    }

    #[test]
    fn the_document_url_follows_the_issuer() {
        assert_eq!(
            &*document_url("https://idp.test/realms/a")
                .expect("url")
                .target,
            "/realms/a/.well-known/openid-configuration"
        );
        assert_eq!(
            &*document_url("https://idp.test/").expect("url").target,
            "/.well-known/openid-configuration"
        );
        for bad in [
            "idp.test",
            "https://idp.test/?a=b",
            "https://idp.test/#x",
            "https://u@idp.test",
            "ftp://idp.test",
        ] {
            assert!(document_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_token_request_authenticates_the_client_once() {
        let token = Endpoint {
            server: document_url("http://10.0.0.5:8080").expect("url").server,
            host: "10.0.0.5:8080".into(),
            target: "/token".into(),
        };
        let budget = crate::budget::Budgets::new().tenant(
            "t",
            podgate_model::Budget {
                max_inflight: 1,
                max_buffer_bytes: 1,
            },
        );
        let (client, policy, resolver, transport) = (
            Client::new(Duration::from_secs(5)),
            UpstreamPolicy::allow_all(),
            Resolver::default(),
            Transport::default(),
        );
        let build = |secret: Option<&str>| {
            let exchange = Exchange {
                client: &client,
                policy: &policy,
                resolver: &resolver,
                transport: &transport,
                tenant: "t",
                budget: &budget,
                token: &token,
                client_id: "my app",
                client_secret: secret,
                code: "c&d",
                verifier: "v",
                redirect_uri: "https://a.test/cb",
            };
            String::from_utf8(token_request(&exchange)).expect("text")
        };
        let confidential = build(Some("s:3cret"));
        let basic = STANDARD.encode("my+app:s%3A3cret");
        assert!(
            confidential.contains(&format!("Authorization: Basic {basic}\r\n")),
            "{confidential}"
        );
        assert!(!confidential.contains("client_id"), "{confidential}");
        assert!(!confidential.contains("3cret&") && !confidential.contains("s:3cret"));
        let body = confidential.split("\r\n\r\n").nth(1).expect("body");
        assert_eq!(
            body,
            "grant_type=authorization_code&code=c%26d&redirect_uri=https%3A%2F%2Fa.test%2Fcb&code_verifier=v"
        );
        assert!(confidential.contains(&format!("Content-Length: {}\r\n", body.len())));
        let public = build(None);
        assert!(!public.contains("Authorization"), "{public}");
        assert!(public.ends_with("&client_id=my+app"), "{public}");
    }
}
