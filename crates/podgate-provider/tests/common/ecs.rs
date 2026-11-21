//! A fake of the AWS APIs the ECS source uses, on a loopback TCP port. No test talks to AWS.
//!
//! One server answers everything the source may call, told apart by the request:
//!
//! - the ECS JSON 1.1 API (`POST /` with an `x-amz-target`): `ListClusters`, `ListTasks`,
//!   `DescribeTasks`, `DescribeTaskDefinition`, `DescribeServices`, `DescribeContainerInstances`;
//! - EC2 `DescribeInstances` (`POST /` with a form body);
//! - the credential endpoints: the ECS task role (`GET /creds`), IMDSv2 (`/latest/...`) and the
//!   STS `AssumeRoleWithWebIdentity` form.
//!
//! Every ECS and EC2 request must carry a valid AWS Signature Version 4 of the credentials the
//! fake was started with: the fake recomputes it from the request as received (with its own
//! implementation, not the source's) and answers `403` like AWS does, quoting the canonical
//! request, which holds the session token. Every request is logged with the result.
//!
//! [`FakeAws::stop`] drops the listener and every open connection, like a server that died, and
//! [`FakeAws::restart`] listens again on the same port.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ring::{digest, hmac};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub const REGION: &str = "eu-west-1";
pub const ACCESS_KEY: &str = "AKIAPODGATETEST0001";
pub const SECRET_KEY: &str = "s3cr3t/podgate+test/secret-access-key-7e41";
pub const SESSION_TOKEN: &str = "FwoGZXIvYXdzEPODGATE-session-token-c19b";
pub const CONTAINER_AUTH_TOKEN: &str = "container-auth-token-5d2a";
pub const WEB_IDENTITY_TOKEN: &str = "eyJ.web-identity-token.7b3e";
pub const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/podgate";
pub const IMDS_TOKEN: &str = "imds-session-token-91f0";

/// The credentials the fake accepts.
#[derive(Debug, Clone)]
pub struct Creds {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl Creds {
    pub fn standard() -> Self {
        Self {
            access_key: ACCESS_KEY.to_owned(),
            secret_key: SECRET_KEY.to_owned(),
            session_token: Some(SESSION_TOKEN.to_owned()),
        }
    }
}

/// A container of a fake task.
#[derive(Debug, Clone)]
pub struct Cont {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub status: String,
    /// The runtime health of the container.
    pub health: String,
    /// Whether the task definition defines a health check.
    pub health_check: bool,
    /// The container port of the task definition's one port mapping.
    pub port: Option<u16>,
    /// The instance port the container's port is published on (bridge mode).
    pub host_port: Option<u16>,
}

/// A task of the fake, with the task definition that goes with it.
#[derive(Debug, Clone)]
pub struct Task {
    pub cluster: String,
    pub id: String,
    pub family: String,
    pub service: Option<String>,
    /// `awsvpc`, `bridge`, `host`, or `none` for a definition that names no mode.
    pub mode: String,
    /// The private IPv4 address of the task's interface.
    pub ip: Option<String>,
    pub last_status: String,
    pub desired_status: String,
    /// The task-level health.
    pub health: String,
    pub launch_type: String,
    pub created: f64,
    pub container_instance: Option<String>,
    pub containers: Vec<Cont>,
    pub tags: Vec<(String, String)>,
}

impl Task {
    /// A running `awsvpc` task of `service` in `cluster` at `ip`, with one container `web` that
    /// listens on 8080 and carries no labels yet.
    pub fn new(cluster: &str, service: &str, ip: &str) -> Self {
        Self {
            cluster: cluster.to_owned(),
            id: format!(
                "{:032x}",
                ip.bytes().fold(7_u128, |n, b| n * 131 + u128::from(b))
            ),
            family: service.to_owned(),
            service: Some(service.to_owned()),
            mode: "awsvpc".to_owned(),
            ip: Some(ip.to_owned()),
            last_status: "RUNNING".to_owned(),
            desired_status: "RUNNING".to_owned(),
            health: "UNKNOWN".to_owned(),
            launch_type: "FARGATE".to_owned(),
            created: 1_700_000_000.25,
            container_instance: None,
            containers: vec![Cont {
                name: "web".to_owned(),
                labels: Vec::new(),
                status: "RUNNING".to_owned(),
                health: "UNKNOWN".to_owned(),
                health_check: false,
                port: Some(8080),
                host_port: None,
            }],
            tags: Vec::new(),
        }
    }

    /// A task that serves `host` through the `web` container on port 8080.
    pub fn web(cluster: &str, service: &str, ip: &str, host: &str) -> Self {
        Self::new(cluster, service, ip)
            .label("podgate.enable", "true")
            .label("podgate.host", host)
    }

    /// A label on the first container.
    pub fn label(mut self, key: &str, value: &str) -> Self {
        self.containers[0]
            .labels
            .push((key.to_owned(), value.to_owned()));
        self
    }

    pub fn tag(mut self, key: &str, value: &str) -> Self {
        self.tags.push((key.to_owned(), value.to_owned()));
        self
    }

    pub fn id(mut self, id: &str) -> Self {
        id.clone_into(&mut self.id);
        self
    }

    pub fn status(mut self, last: &str, desired: &str) -> Self {
        last.clone_into(&mut self.last_status);
        desired.clone_into(&mut self.desired_status);
        self
    }

    /// The task-level health.
    pub fn task_health(mut self, health: &str) -> Self {
        health.clone_into(&mut self.health);
        self
    }

    /// The first container defines a health check and its runtime health is `health`.
    pub fn health_check(mut self, health: &str) -> Self {
        self.containers[0].health_check = true;
        health.clone_into(&mut self.containers[0].health);
        self
    }

    pub fn created(mut self, created: f64) -> Self {
        self.created = created;
        self
    }

    pub fn family(mut self, family: &str) -> Self {
        family.clone_into(&mut self.family);
        self
    }

    /// No service: a task started on its own, grouped under its family.
    pub fn standalone(mut self) -> Self {
        self.service = None;
        self
    }

    /// The task has no network interface address.
    pub fn without_address(mut self) -> Self {
        self.ip = None;
        self
    }

    /// The first container declares no port mapping.
    pub fn without_port_mapping(mut self) -> Self {
        self.containers[0].port = None;
        self
    }

    /// A task of the EC2 launch type in `mode` (`bridge` or `host`) on `instance`, publishing
    /// container port 8080 on `host_port`.
    pub fn on_instance(mut self, mode: &str, instance: &str, host_port: u16) -> Self {
        mode.clone_into(&mut self.mode);
        self.ip = None;
        "EC2".clone_into(&mut self.launch_type);
        self.container_instance = Some(instance.to_owned());
        self.containers[0].host_port = Some(host_port);
        self
    }

    pub fn arn(&self) -> String {
        format!(
            "arn:aws:ecs:{REGION}:123456789012:task/{}/{}",
            self.cluster, self.id
        )
    }

    /// A revision number made from what the definition says: two tasks share a definition ARN
    /// exactly when their definitions are the same, as in ECS.
    pub fn revision(&self) -> u32 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.family.hash(&mut hasher);
        self.mode.hash(&mut hasher);
        for c in &self.containers {
            (&c.name, &c.labels, c.port, c.health_check).hash(&mut hasher);
        }
        u32::try_from(hasher.finish() % 100_000).unwrap_or(0) + 1
    }

    pub fn definition_arn(&self) -> String {
        format!(
            "arn:aws:ecs:{REGION}:123456789012:task-definition/{}:{}",
            self.family,
            self.revision()
        )
    }

    fn json(&self) -> Value {
        let mut task = json!({
            "taskArn": self.arn(),
            "clusterArn": cluster_arn(&self.cluster),
            "taskDefinitionArn": self.definition_arn(),
            "group": match &self.service {
                Some(service) => format!("service:{service}"),
                None => format!("family:{}", self.family),
            },
            "lastStatus": self.last_status,
            "desiredStatus": self.desired_status,
            "healthStatus": self.health,
            "launchType": self.launch_type,
            "createdAt": self.created,
            "containers": self.containers.iter().map(|c| {
                let mut container = json!({
                    "name": c.name,
                    "lastStatus": c.status,
                    "healthStatus": c.health,
                });
                if let Some(host) = c.host_port {
                    container["networkBindings"] = json!([{
                        "bindIP": "0.0.0.0",
                        "containerPort": c.port.unwrap_or(0),
                        "hostPort": host,
                        "protocol": "tcp",
                    }]);
                }
                if let Some(ip) = &self.ip {
                    container["networkInterfaces"] = json!([{ "privateIpv4Address": ip }]);
                }
                container
            }).collect::<Vec<_>>(),
            "tags": self.tags.iter().map(|(k, v)| json!({ "key": k, "value": v })).collect::<Vec<_>>(),
        });
        if let Some(ip) = &self.ip {
            task["attachments"] = json!([{
                "id": "eni-attach-0123",
                "type": "ElasticNetworkInterface",
                "status": "ATTACHED",
                "details": [
                    { "name": "subnetId", "value": "subnet-0abc" },
                    { "name": "networkInterfaceId", "value": "eni-0abc" },
                    { "name": "privateIPv4Address", "value": ip },
                ],
            }]);
        }
        if let Some(instance) = &self.container_instance {
            task["containerInstanceArn"] = json!(instance);
        }
        task
    }

    fn definition_json(&self) -> Value {
        let mut definition = json!({
            "taskDefinitionArn": self.definition_arn(),
            "family": self.family,
            "revision": self.revision(),
            "containerDefinitions": self.containers.iter().map(|c| {
                let mut container = json!({
                    "name": c.name,
                    "image": "registry.example/app:1",
                    "dockerLabels": c.labels.iter().cloned().collect::<BTreeMap<_, _>>(),
                });
                if let Some(port) = c.port {
                    container["portMappings"] = json!([{ "containerPort": port, "protocol": "tcp" }]);
                }
                if c.health_check {
                    container["healthCheck"] = json!({ "command": ["CMD-SHELL", "true"] });
                }
                container
            }).collect::<Vec<_>>(),
        });
        if self.mode != "none" {
            definition["networkMode"] = json!(self.mode);
        }
        definition
    }
}

fn cluster_arn(name: &str) -> String {
    format!("arn:aws:ecs:{REGION}:123456789012:cluster/{name}")
}

/// One request the fake got.
#[derive(Debug, Clone)]
pub struct Request {
    /// `ECS ListTasks`, `EC2 DescribeInstances`, `STS`, `CONTAINER`, `IMDS ...`.
    pub what: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Whether the signature was valid (`None` for the credential endpoints, which take none).
    pub signed: Option<bool>,
    pub at: Instant,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The JSON body.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

struct Inner {
    accepted: Creds,
    tasks: Vec<Task>,
    clusters: Vec<String>,
    /// `(cluster, service name, created)`.
    services: Vec<(String, String, f64)>,
    /// `(container instance ARN, EC2 instance id, private IP)`.
    instances: Vec<(String, String, String)>,
    requests: Vec<Request>,
    /// Every ECS and EC2 call is answered with this error.
    deny: bool,
    throttle: u32,
    page_size: usize,
    /// The credentials the credential endpoints hand out (the accepted ones by default).
    granted: Creds,
    expected_container_token: Option<String>,
}

/// The running fake.
pub struct FakeAws {
    addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl FakeAws {
    /// A fake with no clusters, accepting [`Creds::standard`].
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake AWS port");
        let addr = listener.local_addr().expect("the fake's address");
        let fake = Self {
            addr,
            inner: Arc::new(Mutex::new(Inner {
                accepted: Creds::standard(),
                tasks: Vec::new(),
                clusters: Vec::new(),
                services: Vec::new(),
                instances: Vec::new(),
                requests: Vec::new(),
                deny: false,
                throttle: 0,
                page_size: 100,
                granted: Creds::standard(),
                expected_container_token: None,
            })),
            server: Mutex::new(None),
        };
        fake.serve(listener);
        fake
    }

    /// `http://127.0.0.1:<port>`: the endpoint of every API.
    pub fn address(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn serve(&self, listener: TcpListener) {
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(handle(stream, Arc::clone(&inner)));
            }
        });
        *self.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// Drops the listener, like a server that died.
    pub fn stop(&self) {
        if let Some(task) = self
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }

    /// Listens again on the same port.
    pub async fn restart(&self) {
        self.stop();
        let wait = async {
            loop {
                if let Ok(listener) = TcpListener::bind(self.addr).await {
                    return listener;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let listener = tokio::time::timeout(super::DEADLINE, wait)
            .await
            .expect("the fake's port frees up");
        self.serve(listener);
    }

    /// Adds a cluster (a cluster with tasks is added by its first task).
    pub fn add_cluster(&self, name: &str) {
        let mut inner = self.inner();
        if !inner.clusters.iter().any(|c| c == name) {
            inner.clusters.push(name.to_owned());
        }
    }

    pub fn add(&self, task: Task) {
        self.add_cluster(&task.cluster);
        let mut inner = self.inner();
        inner
            .tasks
            .retain(|t| !(t.cluster == task.cluster && t.id == task.id));
        inner.tasks.push(task);
    }

    pub fn remove(&self, cluster: &str, id: &str) {
        self.inner()
            .tasks
            .retain(|task| !(task.cluster == cluster && task.id == id));
    }

    /// Changes the task `id` of `cluster`.
    pub fn change(&self, cluster: &str, id: &str, with: impl FnOnce(Task) -> Task) {
        let mut inner = self.inner();
        let position = inner
            .tasks
            .iter()
            .position(|task| task.cluster == cluster && task.id == id)
            .expect("the task exists");
        let task = inner.tasks.remove(position);
        inner.tasks.insert(position, with(task));
    }

    pub fn clear_tasks(&self) {
        self.inner().tasks.clear();
    }

    pub fn add_service(&self, cluster: &str, name: &str, created: f64) {
        self.inner()
            .services
            .push((cluster.to_owned(), name.to_owned(), created));
    }

    /// A container instance and the EC2 instance behind it.
    pub fn add_instance(&self, arn: &str, ec2_id: &str, ip: &str) {
        self.inner()
            .instances
            .push((arn.to_owned(), ec2_id.to_owned(), ip.to_owned()));
    }

    /// The credentials the fake accepts on ECS and EC2 calls, and hands out on the credential
    /// endpoints.
    pub fn accept(&self, creds: Creds) {
        let mut inner = self.inner();
        inner.granted = creds.clone();
        inner.accepted = creds;
    }

    /// The ECS and EC2 APIs answer every call with `AccessDeniedException`.
    pub fn deny(&self, deny: bool) {
        self.inner().deny = deny;
    }

    /// The next `n` ECS calls are answered `ThrottlingException`.
    pub fn throttle(&self, n: u32) {
        self.inner().throttle = n;
    }

    /// `ListTasks` answers at most this many ARNs a page.
    pub fn page_size(&self, n: usize) {
        self.inner().page_size = n;
    }

    /// The task role endpoint wants this `Authorization` header.
    pub fn require_container_token(&self, token: &str) {
        self.inner().expected_container_token = Some(token.to_owned());
    }

    pub fn requests(&self) -> Vec<Request> {
        self.inner().requests.clone()
    }

    /// The `what` of every request so far, oldest first.
    pub fn whats(&self) -> Vec<String> {
        self.requests().into_iter().map(|r| r.what).collect()
    }

    /// How many requests had this `what`.
    pub fn count(&self, what: &str) -> usize {
        self.requests().iter().filter(|r| r.what == what).count()
    }
}

impl Drop for FakeAws {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---- HTTP -------------------------------------------------------------------------------------

struct Raw {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Option<Raw> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 || buffer.len() > 256 * 1024 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some(Raw {
        method,
        path,
        headers,
        body,
    })
}

async fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Status",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(body.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn json_answer(stream: &mut TcpStream, status: u16, body: &Value) {
    respond(
        stream,
        status,
        "application/x-amz-json-1.1",
        &body.to_string(),
    )
    .await;
}

// ---- Signature Version 4, as the fake checks it -----------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn mac(key: &[u8], data: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
        .as_ref()
        .to_vec()
}

/// Checks the signature of `raw` for `service` against `accepted`. `Err` carries what AWS would
/// say: the canonical request it computed.
fn verify(raw: &Raw, service: &str, accepted: &Creds) -> Result<(), String> {
    let header = |name: &str| {
        raw.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let auth = header("authorization").ok_or("Authorization header is missing")?;
    let fields = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("the algorithm is not AWS4-HMAC-SHA256")?;
    let field = |name: &str| {
        fields
            .split(", ")
            .find_map(|part| part.strip_prefix(&format!("{name}=")))
    };
    let credential = field("Credential").ok_or("no Credential")?;
    let signed_headers = field("SignedHeaders").ok_or("no SignedHeaders")?;
    let signature = field("Signature").ok_or("no Signature")?;
    let scope: Vec<&str> = credential.split('/').collect();
    let [access, date, region, scope_service, "aws4_request"] = scope.as_slice() else {
        return Err("the credential scope is malformed".to_owned());
    };
    if *access != accepted.access_key {
        return Err("the security token included in the request is invalid".to_owned());
    }
    if *region != REGION || *scope_service != service {
        return Err(format!(
            "the scope {region}/{scope_service} is wrong, expected {REGION}/{service}"
        ));
    }
    let amz_date = header("x-amz-date").ok_or("x-amz-date is missing")?;
    if !amz_date.starts_with(date) || amz_date.len() != 16 {
        return Err("x-amz-date does not match the credential date".to_owned());
    }
    let names: Vec<&str> = signed_headers.split(';').collect();
    for required in ["host", "x-amz-date"] {
        if !names.contains(&required) {
            return Err(format!("{required} is not a signed header"));
        }
    }
    if service == "ecs" && !names.contains(&"x-amz-target") {
        return Err("x-amz-target is not a signed header".to_owned());
    }
    if let Some(token) = &accepted.session_token {
        if !names.contains(&"x-amz-security-token")
            || header("x-amz-security-token") != Some(token.as_str())
        {
            return Err("the security token is missing or wrong".to_owned());
        }
    } else if header("x-amz-security-token").is_some() {
        return Err("a session token was sent for long-term credentials".to_owned());
    }
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("signed headers must be sorted and unique".to_owned());
    }
    let mut canonical_headers = String::new();
    for name in &names {
        let value = header(name).ok_or_else(|| format!("signed header {name} is absent"))?;
        canonical_headers.push_str(&format!("{name}:{}\n", value.trim()));
    }
    let (path, query) = raw.path.split_once('?').unwrap_or((&raw.path, ""));
    let canonical = format!(
        "{}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        raw.method,
        sha(&raw.body)
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date}/{region}/{service}/aws4_request\n{}",
        sha(canonical.as_bytes())
    );
    let mut key = mac(format!("AWS4{}", accepted.secret_key).as_bytes(), date);
    for part in [region, service, "aws4_request"] {
        key = mac(&key, part);
    }
    let expected = hex(&mac(&key, &to_sign));
    if expected == signature {
        Ok(())
    } else {
        Err(format!(
            "The request signature we calculated does not match the signature you provided. The Canonical String for this request should have been '{canonical}'"
        ))
    }
}

// ---- handlers ---------------------------------------------------------------------------------

fn form_value(body: &str, name: &str) -> Option<String> {
    body.split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
        .map(percent_decode)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let digits = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|d| u8::from_str_radix(d, 16).ok());
        if let Some(byte) = digits {
            out.push(byte);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn credentials_document(creds: &Creds) -> Value {
    json!({
        "Code": "Success",
        "Type": "AWS-HMAC",
        "AccessKeyId": creds.access_key,
        "SecretAccessKey": creds.secret_key,
        "Token": creds.session_token,
        "Expiration": "2099-01-01T00:00:00Z",
    })
}

async fn handle(mut stream: TcpStream, inner: Arc<Mutex<Inner>>) {
    let Some(raw) = read_request(&mut stream).await else {
        return;
    };
    let target = raw
        .headers
        .iter()
        .find(|(name, _)| name == "x-amz-target")
        .map(|(_, value)| value.clone());
    let body_text = String::from_utf8_lossy(&raw.body).into_owned();
    let path = raw.path.split('?').next().unwrap_or("").to_owned();
    let (what, service) = match (raw.method.as_str(), path.as_str()) {
        ("POST", "/") => match &target {
            Some(target) => (
                format!("ECS {}", target.rsplit('.').next().unwrap_or(target)),
                Some("ecs"),
            ),
            None if body_text.starts_with("Action=DescribeInstances") => {
                ("EC2 DescribeInstances".to_owned(), Some("ec2"))
            }
            None if body_text.starts_with("Action=AssumeRoleWithWebIdentity") => {
                ("STS".to_owned(), None)
            }
            None => ("unknown".to_owned(), None),
        },
        ("GET", "/creds") => ("CONTAINER".to_owned(), None),
        ("PUT", "/latest/api/token") => ("IMDS token".to_owned(), None),
        ("GET", "/latest/meta-data/iam/security-credentials/") => ("IMDS role".to_owned(), None),
        ("GET", "/latest/meta-data/iam/security-credentials/podgate-role") => {
            ("IMDS credentials".to_owned(), None)
        }
        _ => ("unknown".to_owned(), None),
    };

    let (verdict, granted, container_token, deny, throttled) = {
        let mut guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
        let verdict = service.map(|service| verify(&raw, service, &guard.accepted));
        guard.requests.push(Request {
            what: what.clone(),
            method: raw.method.clone(),
            path: path.clone(),
            headers: raw.headers.clone(),
            body: body_text.clone(),
            signed: verdict.as_ref().map(Result::is_ok),
            at: Instant::now(),
        });
        let throttled = service == Some("ecs") && guard.throttle > 0;
        if throttled {
            guard.throttle -= 1;
        }
        (
            verdict,
            guard.granted.clone(),
            guard.expected_container_token.clone(),
            guard.deny,
            throttled,
        )
    };
    let header = |name: &str| {
        raw.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };

    match what.as_str() {
        "CONTAINER" => {
            if container_token.is_some() && header("authorization") != container_token {
                return respond(&mut stream, 403, "text/plain", "forbidden").await;
            }
            json_answer(&mut stream, 200, &credentials_document(&granted)).await;
        }
        "IMDS token" => {
            if header("x-aws-ec2-metadata-token-ttl-seconds").is_none() {
                return respond(&mut stream, 400, "text/plain", "no ttl").await;
            }
            respond(&mut stream, 200, "text/plain", IMDS_TOKEN).await;
        }
        "IMDS role" | "IMDS credentials" => {
            if header("x-aws-ec2-metadata-token").as_deref() != Some(IMDS_TOKEN) {
                return respond(&mut stream, 401, "text/plain", "no token").await;
            }
            if what == "IMDS role" {
                respond(&mut stream, 200, "text/plain", "podgate-role\n").await;
            } else {
                json_answer(&mut stream, 200, &credentials_document(&granted)).await;
            }
        }
        "STS" => {
            let ok = form_value(&body_text, "WebIdentityToken").as_deref()
                == Some(WEB_IDENTITY_TOKEN)
                && form_value(&body_text, "RoleArn").as_deref() == Some(ROLE_ARN);
            if !ok {
                return respond(&mut stream, 403, "text/xml", "<ErrorResponse><Error><Code>InvalidIdentityToken</Code></Error></ErrorResponse>").await;
            }
            let xml = format!(
                "<AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>{}</AccessKeyId><SecretAccessKey>{}</SecretAccessKey><SessionToken>{}</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>",
                granted.access_key,
                granted.secret_key,
                granted.session_token.clone().unwrap_or_default()
            );
            respond(&mut stream, 200, "text/xml", &xml).await;
        }
        "EC2 DescribeInstances" => {
            if let Some(Err(why)) = verdict {
                return respond(&mut stream, 403, "text/xml", &format!("<Response><Errors><Error><Code>AuthFailure</Code><Message>{why}</Message></Error></Errors></Response>")).await;
            }
            let ids: Vec<String> = raw_form_ids(&body_text);
            let items: String = {
                let guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
                guard
                    .instances
                    .iter()
                    .filter(|(_, id, _)| ids.contains(id))
                    .map(|(_, id, ip)| {
                        format!(
                            "<item><instanceId>{id}</instanceId><privateIpAddress>{ip}</privateIpAddress><networkInterfaceSet><item><privateIpAddress>10.255.255.255</privateIpAddress></item></networkInterfaceSet></item>"
                        )
                    })
                    .collect()
            };
            let xml = format!(
                "<DescribeInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><reservationSet><item><instancesSet>{items}</instancesSet></item></reservationSet></DescribeInstancesResponse>"
            );
            respond(&mut stream, 200, "text/xml", &xml).await;
        }
        w if w.starts_with("ECS ") => {
            if let Some(Err(why)) = verdict {
                // AWS quotes the canonical request, token included.
                return json_answer(
                    &mut stream,
                    403,
                    &json!({
                        "__type": "InvalidSignatureException",
                        "message": why,
                    }),
                )
                .await;
            }
            if deny {
                return json_answer(
                    &mut stream,
                    400,
                    &json!({
                        "__type": "AccessDeniedException",
                        "message": format!("User is not authorized to perform: ecs:{}", &w[4..]),
                    }),
                )
                .await;
            }
            if throttled {
                return json_answer(
                    &mut stream,
                    400,
                    &json!({
                        "__type": "ThrottlingException",
                        "message": "Rate exceeded",
                    }),
                )
                .await;
            }
            let request: Value = serde_json::from_slice(&raw.body).unwrap_or(Value::Null);
            let (status, answer) = ecs_answer(&inner, &w[4..], &request);
            json_answer(&mut stream, status, &answer).await;
        }
        _ => respond(&mut stream, 404, "text/plain", "no such endpoint").await,
    }
}

fn raw_form_ids(body: &str) -> Vec<String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, _)| key.starts_with("InstanceId."))
        .map(|(_, value)| percent_decode(value))
        .collect()
}

fn name_of(arn_or_name: &str) -> &str {
    arn_or_name.rsplit('/').next().unwrap_or(arn_or_name)
}

fn bad_request(message: &str) -> (u16, Value) {
    (
        400,
        json!({ "__type": "InvalidParameterException", "message": message }),
    )
}

fn ecs_answer(inner: &Arc<Mutex<Inner>>, operation: &str, request: &Value) -> (u16, Value) {
    let guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
    let cluster = request["cluster"]
        .as_str()
        .map(name_of)
        .unwrap_or("default");
    match operation {
        "ListClusters" => (
            200,
            json!({ "clusterArns": guard.clusters.iter().map(|c| cluster_arn(c)).collect::<Vec<_>>() }),
        ),
        "ListTasks" => {
            if !guard.clusters.iter().any(|c| c == cluster) {
                return (
                    400,
                    json!({ "__type": "ClusterNotFoundException", "message": "Cluster not found." }),
                );
            }
            let wanted: Vec<String> = guard
                .tasks
                .iter()
                .filter(|task| task.cluster == cluster)
                .filter(|task| {
                    request["desiredStatus"]
                        .as_str()
                        .is_none_or(|status| task.desired_status == status)
                })
                .map(Task::arn)
                .collect();
            let start: usize = request["nextToken"]
                .as_str()
                .and_then(|token| token.parse().ok())
                .unwrap_or(0);
            let size = guard.page_size.min(100);
            let page: Vec<String> = wanted.iter().skip(start).take(size).cloned().collect();
            let mut answer = json!({ "taskArns": page });
            if start + size < wanted.len() {
                answer["nextToken"] = json!((start + size).to_string());
            }
            (200, answer)
        }
        "DescribeTasks" => {
            let arns: Vec<&str> = request["tasks"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if arns.len() > 100 {
                return bad_request("too many tasks: at most 100");
            }
            if request["include"] != json!(["TAGS"]) {
                return bad_request("the source must ask for TAGS");
            }
            let mut tasks = Vec::new();
            let mut failures = Vec::new();
            for arn in arns {
                match guard
                    .tasks
                    .iter()
                    .find(|t| t.arn() == arn && t.cluster == cluster)
                {
                    Some(task) => tasks.push(task.json()),
                    None => failures.push(json!({ "arn": arn, "reason": "MISSING" })),
                }
            }
            (200, json!({ "tasks": tasks, "failures": failures }))
        }
        "DescribeTaskDefinition" => {
            let arn = request["taskDefinition"].as_str().unwrap_or_default();
            match guard.tasks.iter().find(|t| t.definition_arn() == arn) {
                Some(task) => (200, json!({ "taskDefinition": task.definition_json() })),
                None => (
                    400,
                    json!({ "__type": "ClientException", "message": "Unable to describe task definition." }),
                ),
            }
        }
        "DescribeServices" => {
            let names: Vec<&str> = request["services"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            if names.len() > 10 {
                return bad_request("too many services: at most 10");
            }
            let mut services = Vec::new();
            let mut failures = Vec::new();
            for name in names {
                match guard
                    .services
                    .iter()
                    .find(|(c, n, _)| c == cluster && n == name)
                {
                    Some((_, name, created)) => services.push(json!({
                        "serviceName": name,
                        "createdAt": created,
                        "status": "ACTIVE",
                    })),
                    None => failures.push(json!({ "arn": name, "reason": "MISSING" })),
                }
            }
            (200, json!({ "services": services, "failures": failures }))
        }
        "DescribeContainerInstances" => {
            let arns: Vec<&str> = request["containerInstances"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let mut instances = Vec::new();
            let mut failures = Vec::new();
            for arn in arns {
                match guard.instances.iter().find(|(a, _, _)| a == arn) {
                    Some((arn, id, _)) => instances.push(json!({
                        "containerInstanceArn": arn,
                        "ec2InstanceId": id,
                        "status": "ACTIVE",
                    })),
                    None => failures.push(json!({ "arn": arn, "reason": "MISSING" })),
                }
            }
            (
                200,
                json!({ "containerInstances": instances, "failures": failures }),
            )
        }
        other => (
            400,
            json!({ "__type": "UnknownOperationException", "message": format!("{other} is not a read the fake answers") }),
        ),
    }
}
