//! A client for the parts of the ECS, EC2 and credential APIs the source reads.
//!
//! Every ECS call is a `POST` (that is how the JSON 1.1 protocol works), so "only reads" cannot be
//! the HTTP method: it is the [`Operation`] enum. It lists the six `List*` and `Describe*` calls
//! the source needs and nothing else, and [`Client::call`] takes no other kind, so a source that
//! watches tasks has no way to start, stop or change one. The matching IAM policy is in
//! `docs/ref/provider-ecs.md`.
//!
//! Calls are spaced at least [`MIN_SPACING`] apart, whichever task sends them, and a throttled or
//! failed call is retried a few times with growing, jittered delays before the poll fails. Every
//! request is signed with AWS Signature Version 4 (`auth`).
//!
//! No secret reaches an error text: an error body is cut short and every credential the request
//! used is replaced in it by `[redacted]` (AWS quotes the canonical request, which holds the
//! session token, in its signature errors).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderValue;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as Hyper;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;

use super::auth::{AuthError, Chain, Credentials, Signing, sign, unix_now};
use super::model::{
    ClusterPage, DescribedDefinition, DescribedInstances, DescribedServices, DescribedTasks,
    TaskDefinition, TaskPage, leaf, leaves,
};
use crate::push::Backoff;

/// The longest a request, from connect to the last byte of its body, may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The smallest time between the starts of two calls: ten calls a second, well inside what ECS
/// allows an account for these calls.
pub(super) const MIN_SPACING: Duration = Duration::from_millis(100);

/// How often a throttled call is tried in all.
const ATTEMPTS: u32 = 4;

const MIN_RETRY: Duration = Duration::from_millis(200);
const MAX_RETRY: Duration = Duration::from_secs(3);

/// The largest response body the client reads.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// The most of an error answer that is quoted.
const MAX_QUOTED: usize = 200;

const TASK_BATCH: usize = 100;
const SERVICE_BATCH: usize = 10;
const INSTANCE_BATCH: usize = 100;

const JSON_CONTENT: &str = "application/x-amz-json-1.1";
const FORM_CONTENT: &str = "application/x-www-form-urlencoded; charset=utf-8";
const ECS_PREFIX: &str = "AmazonEC2ContainerServiceV20141113";

/// What went wrong with one HTTP exchange.
#[derive(Debug, Error)]
pub(super) enum HttpError {
    /// The request could not be made or the connection broke.
    #[error("{0}")]
    Transport(Box<str>),
    /// No answer in time.
    #[error("no answer in time")]
    Timeout,
    /// The body is larger than the client reads.
    #[error("the answer is larger than {MAX_BODY_BYTES} bytes")]
    TooLarge,
}

/// One HTTP answer.
pub(super) struct Response {
    pub(super) status: u16,
    pub(super) body: Bytes,
}

type Hyp = Hyper<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// One HTTP client for every service the source talks to: ECS, EC2, STS and the credential
/// endpoints. It never follows a redirect, and holds no connection open between requests.
#[derive(Clone)]
pub(super) struct Http {
    client: Hyp,
}

impl Http {
    /// A client that verifies `https://` servers against the platform's root certificates.
    ///
    /// # Errors
    ///
    /// The reason the root certificates cannot be loaded.
    pub(super) fn new() -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            // One connection per request: a poll every few seconds gains nothing from a pooled
            // connection, and one that the server closed in the meantime is a spurious error.
            client: Hyper::builder(TokioExecutor::new())
                .pool_max_idle_per_host(0)
                .build(connector),
        })
    }

    /// Sends `request` and reads the whole answer, whatever its status.
    pub(super) async fn send(
        &self,
        request: Request<Full<Bytes>>,
        patience: Duration,
    ) -> Result<Response, HttpError> {
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|err| HttpError::Transport(err.to_string().into()))?;
            let status = response.status().as_u16();
            let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
                .collect()
                .await
                .map_err(|err| {
                    if err
                        .downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        HttpError::TooLarge
                    } else {
                        HttpError::Transport(err.to_string().into())
                    }
                })?
                .to_bytes();
            Ok(Response { status, body })
        };
        tokio::time::timeout(patience, exchange)
            .await
            .map_err(|_| HttpError::Timeout)?
    }
}

/// An API endpoint: `scheme://authority`.
#[derive(Debug, Clone)]
pub(super) struct Endpoint {
    base: Box<str>,
    authority: Box<str>,
}

impl Endpoint {
    /// `scheme://authority`, without a trailing slash.
    pub(super) fn base(&self) -> &str {
        &self.base
    }

    /// The origin of `address`, which must be an `http` or `https` URL without a path, a query or
    /// credentials.
    ///
    /// # Errors
    ///
    /// What is wrong with the address.
    pub(super) fn parse(address: &str) -> Result<Self, &'static str> {
        let uri: Uri = address.parse().map_err(|_| "is not a URL")?;
        let scheme = uri.scheme_str().ok_or("needs http:// or https://")?;
        if scheme != "http" && scheme != "https" {
            return Err("must be an http:// or https:// URL");
        }
        let authority = uri.authority().ok_or("needs a host")?;
        if authority.as_str().contains('@') {
            return Err("must not carry credentials; they come from the AWS credential chain");
        }
        if uri.path() != "/" && !uri.path().is_empty() || uri.query().is_some() {
            return Err("must be the endpoint's origin, without a path or a query");
        }
        Ok(Self {
            base: format!("{scheme}://{authority}").into(),
            authority: authority.as_str().into(),
        })
    }
}

/// The ECS calls the source may make. Nothing else can be asked of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    ListClusters,
    ListTasks,
    DescribeTasks,
    DescribeTaskDefinition,
    DescribeServices,
    DescribeContainerInstances,
}

impl Operation {
    fn name(self) -> &'static str {
        match self {
            Self::ListClusters => "ListClusters",
            Self::ListTasks => "ListTasks",
            Self::DescribeTasks => "DescribeTasks",
            Self::DescribeTaskDefinition => "DescribeTaskDefinition",
            Self::DescribeServices => "DescribeServices",
            Self::DescribeContainerInstances => "DescribeContainerInstances",
        }
    }
}

/// What went wrong talking to AWS.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// No credentials could be found or fetched.
    #[error("{0}")]
    Credentials(#[from] AuthError),
    /// The request could not be made or the connection broke.
    #[error("cannot reach {service}: {why}")]
    Transport {
        service: &'static str,
        why: Box<str>,
    },
    /// No answer in time.
    #[error("{service} did not answer {operation} in time")]
    Timeout {
        service: &'static str,
        operation: &'static str,
    },
    /// An error status.
    #[error("{service} answered {status} to {operation}: {detail}")]
    Status {
        service: &'static str,
        status: u16,
        operation: &'static str,
        detail: Box<str>,
    },
    /// The body is not what was expected.
    #[error("{service} sent an answer that does not parse: {why}")]
    Parse {
        service: &'static str,
        why: Box<str>,
    },
    /// A body is larger than the client reads.
    #[error("{service} sent more than {MAX_BODY_BYTES} bytes")]
    TooLarge { service: &'static str },
}

impl ClientError {
    /// Whether a second try may succeed: throttling and server errors.
    fn transient(&self) -> bool {
        match self {
            Self::Status { status, detail, .. } => {
                matches!(status, 429 | 500 | 502 | 503 | 504)
                    || detail.contains("Throttl")
                    || detail.contains("RequestLimitExceeded")
            }
            _ => false,
        }
    }
}

/// Spaces calls out: each one starts at least [`MIN_SPACING`] after the one before.
struct Limiter {
    next: Mutex<Instant>,
}

impl Limiter {
    async fn wait(&self) {
        let mut next = self.next.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep_until(*next).await;
        }
        *next = Instant::now().max(*next) + MIN_SPACING;
    }
}

/// The AWS APIs.
pub(super) struct Client {
    ecs: Endpoint,
    ec2: Endpoint,
    region: Box<str>,
    http: Http,
    chain: Chain,
    limiter: Limiter,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("ecs", &self.ecs)
            .field("ec2", &self.ec2)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

/// Percent-encodes everything but unreserved characters, for a form value.
pub(super) fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `text` cut to [`MAX_QUOTED`] characters, with every credential of `credentials` replaced.
fn quoted(text: &str, credentials: &Credentials) -> Box<str> {
    let mut clean = text.trim().to_owned();
    for secret in credentials.secrets() {
        clean = clean.replace(secret, "[redacted]");
    }
    clean.chars().take(MAX_QUOTED).collect::<String>().into()
}

/// The error an AWS answer carries: its code and message, from JSON or XML.
fn detail(body: &[u8], credentials: &Credentials) -> Box<str> {
    let text = String::from_utf8_lossy(body);
    let described = if let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) {
        let code = object
            .get("__type")
            .and_then(Value::as_str)
            .map(|code| code.rsplit('#').next().unwrap_or(code));
        let message = ["message", "Message"]
            .iter()
            .find_map(|key| object.get(*key).and_then(Value::as_str));
        match (code, message) {
            (Some(code), Some(message)) => Some(format!("{code}: {message}")),
            (Some(only), None) | (None, Some(only)) => Some(only.to_owned()),
            (None, None) => None,
        }
    } else {
        let found = leaves(&text);
        leaf(&found, "Error/Code").map(|code| match leaf(&found, "Error/Message") {
            Some(message) => format!("{code}: {message}"),
            None => code.to_owned(),
        })
    };
    quoted(described.as_deref().unwrap_or(&text), credentials)
}

impl Client {
    /// A client of the ECS and EC2 endpoints that signs with credentials from `chain`.
    pub(super) fn new(
        ecs: Endpoint,
        ec2: Endpoint,
        region: &str,
        http: Http,
        chain: Chain,
    ) -> Self {
        Self {
            ecs,
            ec2,
            region: region.into(),
            http,
            chain,
            limiter: Limiter {
                next: Mutex::new(Instant::now()),
            },
        }
    }

    /// One signed `POST /`, retried while AWS throttles or fails, returning the answer's body.
    async fn post(
        &self,
        service: &'static str,
        endpoint: &Endpoint,
        operation: &'static str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Bytes, ClientError> {
        let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY).jittered();
        let mut attempt = 1;
        loop {
            match self
                .attempt(service, endpoint, operation, headers, body)
                .await
            {
                Err(err) if err.transient() && attempt < ATTEMPTS => {
                    attempt += 1;
                    tokio::time::sleep(backoff.next_delay()).await;
                }
                other => return other,
            }
        }
    }

    async fn attempt(
        &self,
        service: &'static str,
        endpoint: &Endpoint,
        operation: &'static str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Bytes, ClientError> {
        self.limiter.wait().await;
        let credentials = self.chain.get().await?;
        let signed = sign(
            &credentials,
            &Signing {
                region: &self.region,
                service: &service.to_ascii_lowercase(),
                method: "POST",
                host: &endpoint.authority,
                path: "/",
                query: "",
                headers,
                body,
                now: unix_now(),
            },
        );
        let uri: Uri =
            format!("{}/", endpoint.base)
                .parse()
                .map_err(|err: http::uri::InvalidUri| ClientError::Transport {
                    service,
                    why: err.to_string().into(),
                })?;
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", &*endpoint.authority);
        for (name, value) in headers.iter().copied().chain(
            signed
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        ) {
            let mut value = HeaderValue::from_str(value).map_err(|err| ClientError::Transport {
                service,
                why: err.to_string().into(),
            })?;
            // Signature and session token: never shown by a debug print of the request.
            value.set_sensitive(name == "authorization" || name == "x-amz-security-token");
            request = request.header(name, value);
        }
        let request = request
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|err| ClientError::Transport {
                service,
                why: err.to_string().into(),
            })?;
        let response = self
            .http
            .send(request, REQUEST_TIMEOUT)
            .await
            .map_err(|err| match err {
                HttpError::Timeout => ClientError::Timeout { service, operation },
                HttpError::TooLarge => ClientError::TooLarge { service },
                HttpError::Transport(why) => ClientError::Transport {
                    service,
                    why: quoted(&why, &credentials),
                },
            })?;
        if (200..300).contains(&response.status) {
            Ok(response.body)
        } else {
            Err(ClientError::Status {
                service,
                status: response.status,
                operation,
                detail: detail(&response.body, &credentials),
            })
        }
    }

    /// One ECS call.
    async fn call<T: DeserializeOwned>(
        &self,
        operation: Operation,
        request: &Value,
    ) -> Result<T, ClientError> {
        let target = format!("{ECS_PREFIX}.{}", operation.name());
        let body = request.to_string();
        let answer = self
            .post(
                "ECS",
                &self.ecs,
                operation.name(),
                &[("content-type", JSON_CONTENT), ("x-amz-target", &target)],
                body.as_bytes(),
            )
            .await?;
        serde_json::from_slice(&answer).map_err(|err| ClientError::Parse {
            service: "ECS",
            why: err.to_string().into(),
        })
    }

    /// The ARNs of the clusters of the account.
    pub(super) async fn clusters(&self) -> Result<Vec<String>, ClientError> {
        let mut arns = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page: ClusterPage = self
                .call(
                    Operation::ListClusters,
                    &json!({ "maxResults": 100, "nextToken": token }),
                )
                .await?;
            arns.extend(page.cluster_arns);
            match page.next_token {
                Some(next) if !next.is_empty() => token = Some(next),
                _ => return Ok(arns),
            }
        }
    }

    /// The ARNs of the tasks of `cluster` that should be running.
    pub(super) async fn running_tasks(&self, cluster: &str) -> Result<Vec<String>, ClientError> {
        let mut arns = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page: TaskPage = self
                .call(
                    Operation::ListTasks,
                    &json!({
                        "cluster": cluster,
                        "desiredStatus": "RUNNING",
                        "maxResults": 100,
                        "nextToken": token,
                    }),
                )
                .await?;
            arns.extend(page.task_arns);
            match page.next_token {
                Some(next) if !next.is_empty() => token = Some(next),
                _ => return Ok(arns),
            }
        }
    }

    /// The tasks `arns` of `cluster`, with their tags, in batches of 100.
    pub(super) async fn describe_tasks(
        &self,
        cluster: &str,
        arns: &[String],
    ) -> Result<DescribedTasks, ClientError> {
        let mut all = DescribedTasks {
            tasks: Vec::new(),
            failures: Vec::new(),
        };
        for batch in arns.chunks(TASK_BATCH) {
            let described: DescribedTasks = self
                .call(
                    Operation::DescribeTasks,
                    &json!({ "cluster": cluster, "tasks": batch, "include": ["TAGS"] }),
                )
                .await?;
            all.tasks.extend(described.tasks);
            all.failures.extend(described.failures);
        }
        Ok(all)
    }

    /// One task definition revision.
    pub(super) async fn task_definition(&self, arn: &str) -> Result<TaskDefinition, ClientError> {
        let described: DescribedDefinition = self
            .call(
                Operation::DescribeTaskDefinition,
                &json!({ "taskDefinition": arn }),
            )
            .await?;
        Ok(described.task_definition)
    }

    /// The services `names` of `cluster`, in batches of 10.
    pub(super) async fn services(
        &self,
        cluster: &str,
        names: &[String],
    ) -> Result<DescribedServices, ClientError> {
        let mut all = DescribedServices {
            services: Vec::new(),
            failures: Vec::new(),
        };
        for batch in names.chunks(SERVICE_BATCH) {
            let described: DescribedServices = self
                .call(
                    Operation::DescribeServices,
                    &json!({ "cluster": cluster, "services": batch }),
                )
                .await?;
            all.services.extend(described.services);
            all.failures.extend(described.failures);
        }
        Ok(all)
    }

    /// The container instances `arns` of `cluster`, in batches of 100.
    pub(super) async fn container_instances(
        &self,
        cluster: &str,
        arns: &[String],
    ) -> Result<DescribedInstances, ClientError> {
        let mut all = DescribedInstances {
            instances: Vec::new(),
            failures: Vec::new(),
        };
        for batch in arns.chunks(INSTANCE_BATCH) {
            let described: DescribedInstances = self
                .call(
                    Operation::DescribeContainerInstances,
                    &json!({ "cluster": cluster, "containerInstances": batch }),
                )
                .await?;
            all.instances.extend(described.instances);
            all.failures.extend(described.failures);
        }
        Ok(all)
    }

    /// The private IPv4 address of each EC2 instance in `ids` (EC2 `DescribeInstances`).
    pub(super) async fn instance_addresses(
        &self,
        ids: &[String],
    ) -> Result<BTreeMap<String, IpAddr>, ClientError> {
        let mut found = BTreeMap::new();
        for batch in ids.chunks(INSTANCE_BATCH) {
            let mut form = String::from("Action=DescribeInstances&Version=2016-11-15");
            for (n, id) in batch.iter().enumerate() {
                form.push_str(&format!("&InstanceId.{}={}", n + 1, encode(id)));
            }
            let answer = self
                .post(
                    "EC2",
                    &self.ec2,
                    "DescribeInstances",
                    &[("content-type", FORM_CONTENT)],
                    form.as_bytes(),
                )
                .await?;
            let text = String::from_utf8_lossy(&answer);
            let mut current: Option<String> = None;
            for (path, value) in leaves(&text) {
                if path.ends_with("/instancesSet/item/instanceId") {
                    current = Some(value);
                } else if path.ends_with("/instancesSet/item/privateIpAddress")
                    && let (Some(id), Ok(address)) = (current.as_ref(), value.parse::<IpAddr>())
                {
                    found.insert(id.clone(), address);
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_answers_are_cleaned_of_credentials() {
        let credentials = Credentials::new("AKIAEXAMPLE", "sekrit-key", Some("sekrit-token"), None);
        // AWS quotes the canonical request, which holds the session token.
        let body = br#"{"__type":"com.amazon#InvalidSignatureException","message":"canonical 'x-amz-security-token:sekrit-token' for AKIAEXAMPLE signed with sekrit-key"}"#;
        let shown = detail(body, &credentials);
        assert!(
            shown.starts_with("InvalidSignatureException: canonical"),
            "{shown}"
        );
        assert_eq!(
            &*shown,
            "InvalidSignatureException: canonical 'x-amz-security-token:[redacted]' for [redacted] signed with [redacted]"
        );
        let xml = b"<Response><Errors><Error><Code>AuthFailure</Code><Message>bad sekrit-token</Message></Error></Errors></Response>";
        assert_eq!(&*detail(xml, &credentials), "AuthFailure: bad [redacted]");
        let long = "x".repeat(1000);
        assert_eq!(quoted(&long, &credentials).len(), MAX_QUOTED);
    }

    #[test]
    fn form_values_are_encoded() {
        assert_eq!(encode("a b/c+d=~-._"), "a%20b%2Fc%2Bd%3D~-._");
    }

    #[test]
    fn endpoints_are_origins() {
        assert_eq!(
            Endpoint::parse("https://ecs.eu-west-1.amazonaws.com").map(|e| e.base().to_owned()),
            Ok("https://ecs.eu-west-1.amazonaws.com".to_owned())
        );
        assert!(Endpoint::parse("https://ecs.example.com/path").is_err());
        assert!(Endpoint::parse("https://user@ecs.example.com").is_err());
        assert!(Endpoint::parse("ecs.example.com").is_err());
    }
}
