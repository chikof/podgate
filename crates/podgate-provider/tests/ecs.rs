//! Black-box tests of the ECS source against a fake AWS on a loopback port
//! (`tests/common/ecs.rs`): tasks to apps, servers from network interface addresses, request
//! signing and the credential chain, health, tenants and trust, the upstream policy, polling and
//! outages. Everything that waits has a deadline.
//!
//! No secret reaching a log is checked in `ecs_logs.rs`, a binary of its own.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use common::ecs::{
    ACCESS_KEY, CONTAINER_AUTH_TOKEN, FakeAws, ROLE_ARN, SECRET_KEY, SESSION_TOKEN, Task,
    WEB_IDENTITY_TOKEN,
};
use common::{DEADLINE, config};
use podgate_provider::ecs::EcsSource;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// A change must show within one refresh (5 seconds, the lowest the source takes) plus the
/// time a poll takes and scheduling slack.
const PROMPT: Duration = Duration::from_secs(12);

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// The environment of a source that signs with the fake's standard credentials.
fn env() -> Vec<(String, String)> {
    pairs(&[
        ("AWS_ACCESS_KEY_ID", ACCESS_KEY),
        ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
        ("AWS_SESSION_TOKEN", SESSION_TOKEN),
    ])
}

fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// The configuration with one ecs source named `ecs` after `tenants`, reading `clusters` (by
/// default `["prod"]`) from `endpoint`, and `settings` as more keys of the source.
fn ecs_config(endpoint: &str, tenants: &str, settings: &str) -> Config {
    let clusters = if settings.contains("clusters") || settings.contains("auto_discover") {
        ""
    } else {
        "clusters = [\"prod\"]\n"
    };
    config(
        std::path::Path::new("/nonexistent/admin.sock"),
        &format!(
            "{tenants}\n[[source]]\nkind = \"ecs\"\nname = \"ecs\"\nregion = \"eu-west-1\"\nendpoint = {endpoint:?}\nrefresh_secs = 5\n{clusters}{settings}\n"
        ),
    )
}

fn source_of(config: &Config, env: Vec<(String, String)>) -> EcsSource {
    EcsSource::from_config_with_env(&config.sources[0], env).expect("a valid ecs source")
}

/// A running ecs source and what it has said so far.
struct Watcher {
    rx: mpsc::Receiver<Update>,
    task: JoinHandle<()>,
    state: Option<State>,
    /// How many complete states arrived.
    states: usize,
    outage: Option<String>,
}

impl Watcher {
    fn start(config: &Config) -> Self {
        Self::start_with(config, env())
    }

    fn start_with(config: &Config, env: Vec<(String, String)>) -> Self {
        let (tx, rx) = mpsc::channel(64);
        let source = source_of(config, env);
        Self {
            rx,
            task: tokio::spawn(source.run(tx)),
            state: None,
            states: 0,
            outage: None,
        }
    }

    async fn until(&mut self, what: &str, done: impl Fn(Option<&State>, Option<&str>) -> bool) {
        let wait = async {
            while !done(self.state.as_ref(), self.outage.as_deref()) {
                let update = self.rx.recv().await.expect("the source keeps running");
                assert_eq!(&*update.source, "ecs");
                match update.body {
                    UpdateBody::State(state) => {
                        self.state = Some(state);
                        self.states += 1;
                        self.outage = None;
                    }
                    UpdateBody::Outage(why) => self.outage = Some(why.to_string()),
                }
            }
        };
        if tokio::time::timeout(DEADLINE, wait).await.is_err() {
            panic!(
                "timed out waiting for: {what}; apps: {:?}; outage: {:?}",
                self.state.as_ref().map(ids),
                self.outage
            );
        }
    }

    async fn wait_ids(&mut self, expected: &[&str]) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.until(&format!("apps {expected:?}"), |state, _| {
            state.is_some_and(|state| ids(state) == expected)
        })
        .await;
        self.state.clone().expect("a state")
    }

    async fn wait_outage(&mut self, needle: &str) {
        self.until(&format!("an outage naming {needle}"), |_, outage| {
            outage.is_some_and(|why| why.contains(needle))
        })
        .await;
    }

    /// Waits for the state `expected` and for the report that names `needle`.
    async fn wait_ids_and_report(&mut self, expected: &[&str], needle: &str) -> State {
        let expected: Vec<String> = expected.iter().map(|id| (*id).to_owned()).collect();
        self.until(
            &format!("apps {expected:?} and a report naming {needle}"),
            |state, outage| {
                state.is_some_and(|state| ids(state) == expected)
                    && outage.is_some_and(|why| why.contains(needle))
            },
        )
        .await;
        self.state.clone().expect("a state")
    }

    fn report(&self) -> &str {
        self.outage.as_deref().unwrap_or_default()
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn ids(state: &State) -> Vec<String> {
    let mut ids: Vec<String> = state
        .apps
        .iter()
        .map(|app| app.app.id.to_string())
        .collect();
    ids.sort();
    ids
}

fn app_of<'a>(state: &'a State, id: &str) -> &'a podgate_provider::source::SourceApp {
    state
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| panic!("no app {id}: {:?}", ids(state)))
}

fn app_json(state: &State, id: &str) -> Value {
    serde_json::to_value(&app_of(state, id).app).expect("an app serializes")
}

/// The urls of the servers of the first service of a revision of `id`.
fn servers_of(state: &State, id: &str, revision: &str) -> Vec<String> {
    let app = app_json(state, id);
    let revision = app["revisions"]
        .as_array()
        .expect("revisions")
        .iter()
        .find(|rev| rev["id"] == revision)
        .unwrap_or_else(|| panic!("no revision {revision} in {app}"));
    revision["services"][0]["servers"]
        .as_array()
        .expect("servers")
        .iter()
        .map(|server| server["url"].as_str().expect("a url").to_owned())
        .collect()
}

fn merge(config: &Config, policy: UpstreamPolicy, state: State) -> Merged {
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("ecs".into(), state)]);
    Merger::new(config, policy).merge(&states, &BTreeSet::new())
}

fn finding_codes(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn merged_apps(merged: &Merged) -> Vec<(String, String)> {
    merged
        .snapshot()
        .apps
        .iter()
        .map(|app| (app.id.to_string(), app.tenant.to_string()))
        .collect()
}

/// `check` is a function so the closure of a test reads as one line.
fn requests_of(fake: &FakeAws, what: &str) -> Vec<common::ecs::Request> {
    fake.requests()
        .into_iter()
        .filter(|request| request.what == what)
        .collect()
}

// ---- tasks to apps ----------------------------------------------------------------------------

#[tokio::test]
async fn ecs_tasks_to_apps() {
    let fake = FakeAws::start().await;
    fake.add_service("prod", "shop", 1_690_000_000.5);
    fake.add(
        Task::web(
            "prod",
            "shop",
            "10.4.0.5",
            "shop.acme.test, www.shop.acme.test",
        )
        .label("com.example.team", "storefront")
        .created(1_700_000_100.0),
    );
    fake.add(
        Task::web(
            "prod",
            "shop",
            "10.4.0.6",
            "shop.acme.test, www.shop.acme.test",
        )
        .label("com.example.team", "storefront")
        .created(1_700_000_200.0),
    );
    // A task started on its own is named after its task definition family, and the app is as old
    // as the task, since it has no service.
    fake.add(
        Task::web("prod", "ignored", "10.4.0.7", "batch.acme.test")
            .standalone()
            .family("batchy")
            .created(1_700_000_300.75),
    );
    // `podgate.app` names the app, whatever the service is called.
    fake.add(
        Task::web("prod", "legacy", "10.4.0.8", "old.acme.test").label("podgate.app", "custom"),
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    let state = watcher
        .wait_ids(&["prod.batchy", "prod.custom", "prod.shop"])
        .await;

    let shop = app_of(&state, "prod.shop");
    assert_eq!(&*shop.origin.object, "prod.shop");
    assert_eq!(&*shop.origin.source, "ecs");
    assert_eq!(
        shop.origin.first_seen, 1_690_000_000,
        "the app is as old as its service, not as old as the poll"
    );
    assert_eq!(shop.tenant.mapped.as_deref(), Some("default"));
    assert_eq!(shop.tenant.label, None);
    let json = app_json(&state, "prod.shop");
    assert_eq!(json["id"], "prod.shop");
    assert_eq!(json["tls"]["mode"], "acme");
    assert_eq!(
        json["routers"][0]["match"],
        json!({ "host": ["shop.acme.test", "www.shop.acme.test"] })
    );
    assert_eq!(json["routers"][0]["service"], "web");
    assert_eq!(
        servers_of(&state, "prod.shop", "default"),
        ["http://10.4.0.5:8080", "http://10.4.0.6:8080"],
        "both tasks of the service are its servers"
    );
    assert_eq!(
        app_of(&state, "prod.batchy").origin.first_seen,
        1_700_000_300,
        "no service: the task's own creation time, in whole seconds"
    );
    assert_eq!(
        servers_of(&state, "prod.custom", "default"),
        ["http://10.4.0.8:8080"]
    );
}

#[tokio::test]
async fn ecs_server_from_eni_address() {
    let fake = FakeAws::start().await;
    // The label names the container port; the address is the task's own interface.
    fake.add(
        Task::web("prod", "labelled", "10.4.1.1", "a.acme.test").label("podgate.port", "9090"),
    );
    // No label: the one port the task definition declares.
    fake.add(Task::web("prod", "declared", "10.4.1.2", "b.acme.test"));
    // No label and no declared port: nothing says where to connect.
    fake.add(
        Task::web("prod", "portless", "10.4.1.3", "c.acme.test")
            .without_port_mapping()
            .id("portless-task"),
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    let state = watcher
        .wait_ids_and_report(&["prod.declared", "prod.labelled"], "podgate.port")
        .await;
    assert_eq!(
        servers_of(&state, "prod.labelled", "default"),
        ["http://10.4.1.1:9090"]
    );
    assert_eq!(
        servers_of(&state, "prod.declared", "default"),
        ["http://10.4.1.2:8080"]
    );
    assert!(
        watcher.report().contains("portless-task"),
        "{}",
        watcher.report()
    );
}

// ---- requests and credentials -----------------------------------------------------------------

#[tokio::test]
async fn ecs_requests_sigv4_signed() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.5", "shop.acme.test"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.shop"]).await;

    let requests = fake.requests();
    assert!(requests.len() >= 4, "{:?}", fake.whats());
    for request in &requests {
        assert_eq!(request.signed, Some(true), "{request:?}");
        assert_eq!(request.method, "POST");
        let authorization = request.header("authorization").expect("an authorization");
        assert!(
            authorization.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/")),
            "{authorization}"
        );
        assert!(
            authorization.contains("/eu-west-1/ecs/aws4_request"),
            "{authorization}"
        );
        let signed = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .expect("signed headers");
        assert_eq!(
            signed,
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
        );
        assert_eq!(request.header("x-amz-security-token"), Some(SESSION_TOKEN));
        assert_eq!(
            request.header("content-type"),
            Some("application/x-amz-json-1.1")
        );
        assert!(
            request
                .header("x-amz-target")
                .is_some_and(|target| target.starts_with("AmazonEC2ContainerServiceV20141113."))
        );
    }

    // With another secret the signature does not match: AWS says so and the source reports it,
    // without the secrets that AWS quotes back (the canonical request holds the session token).
    let wrong = pairs(&[
        ("AWS_ACCESS_KEY_ID", ACCESS_KEY),
        ("AWS_SECRET_ACCESS_KEY", "another-secret-that-is-wrong"),
        ("AWS_SESSION_TOKEN", SESSION_TOKEN),
    ]);
    let mut denied = Watcher::start_with(&ecs_config(&fake.address(), "", ""), wrong);
    denied.wait_outage("InvalidSignatureException").await;
    let outage = denied.outage.clone().unwrap_or_default();
    assert!(outage.contains("403"), "{outage}");
    for secret in [SESSION_TOKEN, SECRET_KEY, "another-secret-that-is-wrong"] {
        assert!(!outage.contains(secret), "{outage}");
    }
    assert!(denied.state.is_none(), "no state without a valid signature");
}

#[tokio::test]
async fn ecs_credentials_from_chain() {
    let dir = std::env::temp_dir().join(format!("pgp-ecs-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let task = || Task::web("prod", "shop", "10.4.0.5", "shop.acme.test");

    // The shared credentials file: the profile named by AWS_PROFILE.
    let file = dir.join("credentials");
    std::fs::write(
        &file,
        format!(
            "[default]\naws_access_key_id = AKIAWRONGPROFILE\naws_secret_access_key = wrong\n\n[podgate]\n; the one that counts\naws_access_key_id = {ACCESS_KEY}\naws_secret_access_key={SECRET_KEY}\naws_session_token = {SESSION_TOKEN}\n"
        ),
    )
    .expect("credentials file");
    let fake = FakeAws::start().await;
    fake.add(task());
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[
            ("AWS_SHARED_CREDENTIALS_FILE", &file.display().to_string()),
            ("AWS_PROFILE", "podgate"),
        ]),
    );
    watcher.wait_ids(&["prod.shop"]).await;
    assert!(fake.requests().iter().all(|r| r.signed == Some(true)));

    // The ECS task role endpoint, with its authorization token.
    let fake = FakeAws::start().await;
    fake.add(task());
    fake.require_container_token(CONTAINER_AUTH_TOKEN);
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                &format!("{}/creds", fake.address()),
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", CONTAINER_AUTH_TOKEN),
        ]),
    );
    watcher.wait_ids(&["prod.shop"]).await;
    assert_eq!(fake.count("CONTAINER"), 1, "fetched once, then cached");
    assert!(fake.requests().iter().all(|r| r.signed != Some(false)));

    // Instance metadata, version 2: a token first, then the role, then its credentials.
    let fake = FakeAws::start().await;
    fake.add(task());
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &fake.address())]),
    );
    watcher.wait_ids(&["prod.shop"]).await;
    assert_eq!(
        fake.whats().into_iter().take(3).collect::<Vec<_>>(),
        ["IMDS token", "IMDS role", "IMDS credentials"]
    );

    // A web identity token, exchanged at STS.
    let token_file = dir.join("token");
    std::fs::write(&token_file, format!("{WEB_IDENTITY_TOKEN}\n")).expect("token file");
    let fake = FakeAws::start().await;
    fake.add(task());
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[
            (
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                &token_file.display().to_string(),
            ),
            ("AWS_ROLE_ARN", ROLE_ARN),
            ("AWS_ENDPOINT_URL_STS", &fake.address()),
        ]),
    );
    watcher.wait_ids(&["prod.shop"]).await;
    assert_eq!(fake.count("STS"), 1);

    // The environment comes first: the task role endpoint is not even asked.
    let fake = FakeAws::start().await;
    fake.add(task());
    let mut environment = env();
    environment.extend(pairs(&[(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        &format!("{}/creds", fake.address()),
    )]));
    let mut watcher = Watcher::start_with(&ecs_config(&fake.address(), "", ""), environment);
    watcher.wait_ids(&["prod.shop"]).await;
    assert_eq!(fake.count("CONTAINER"), 0);

    // A configured step that fails ends the chain with its own error: the wrong container token
    // is not hidden behind the instance profile that is also available.
    let fake = FakeAws::start().await;
    fake.add(task());
    fake.require_container_token("the-right-token");
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                &format!("{}/creds", fake.address()),
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "the-wrong-token"),
            ("AWS_EC2_METADATA_SERVICE_ENDPOINT", &fake.address()),
        ]),
    );
    watcher.wait_outage("ECS task role").await;
    assert!(watcher.report().contains("403"), "{}", watcher.report());
    assert_eq!(fake.count("IMDS token"), 0);
    assert!(watcher.state.is_none());

    // Nothing at all: the outage says where it looked, and no request reaches ECS.
    let fake = FakeAws::start().await;
    fake.add(task());
    let mut watcher = Watcher::start_with(
        &ecs_config(&fake.address(), "", ""),
        pairs(&[
            ("AWS_EC2_METADATA_DISABLED", "true"),
            ("HOME", "/nonexistent"),
        ]),
    );
    watcher.wait_outage("no AWS credentials").await;
    assert!(fake.requests().is_empty(), "{:?}", fake.whats());

    // Credentials are not a key of the configuration, whatever its value: the error names the
    // key, not what was in it.
    let leaked = "AKIA-leaked-in-the-config-file";
    let config = ecs_config(
        &fake.address(),
        "",
        &format!("access_key_id = {leaked:?}\nsecret_access_key = {leaked:?}"),
    );
    let err = EcsSource::from_config_with_env(&config.sources[0], env())
        .expect_err("credentials are not configuration")
        .to_string();
    assert!(err.contains("unknown field"), "{err}");
    assert!(!err.contains(leaked), "{err}");
    let _ = std::fs::remove_dir_all(dir);
}

// ---- which tasks serve ------------------------------------------------------------------------

#[tokio::test]
async fn ecs_only_running_healthy_tasks() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "plain", "10.4.0.1", "a.acme.test"));
    fake.add(Task::web("prod", "healthy", "10.4.0.2", "b.acme.test").health_check("HEALTHY"));
    fake.add(Task::web("prod", "pending", "10.4.0.3", "c.acme.test").status("PENDING", "RUNNING"));
    fake.add(Task::web("prod", "stopping", "10.4.0.4", "d.acme.test").status("RUNNING", "STOPPED"));
    fake.add(Task::web("prod", "unhealthy", "10.4.0.5", "e.acme.test").health_check("UNHEALTHY"));
    fake.add(Task::web("prod", "starting", "10.4.0.6", "f.acme.test").health_check("UNKNOWN"));
    fake.add(Task::web("prod", "sick", "10.4.0.7", "g.acme.test").task_health("UNHEALTHY"));
    fake.add(Task::web("prod", "stopped", "10.4.0.8", "h.acme.test").status("STOPPED", "STOPPED"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    let state = watcher.wait_ids(&["prod.healthy", "prod.plain"]).await;
    assert_eq!(
        servers_of(&state, "prod.healthy", "default"),
        ["http://10.4.0.2:8080"]
    );
    assert_eq!(
        watcher.report(),
        "",
        "tasks that are not serving yet are not a problem: {}",
        watcher.report()
    );
    let lists = requests_of(&fake, "ECS ListTasks");
    assert!(
        lists
            .iter()
            .all(|request| request.json()["desiredStatus"] == "RUNNING"),
        "only tasks that should be running are listed"
    );
}

#[tokio::test]
async fn ecs_bridge_mode_skipped_by_default() {
    let fake = FakeAws::start().await;
    fake.add_instance(
        "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/abc",
        "i-0123456789abcdef0",
        "10.9.0.7",
    );
    fake.add(
        Task::web("prod", "bridged", "10.4.0.1", "bridged.acme.test").on_instance(
            "bridge",
            "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/abc",
            32768,
        ),
    );
    fake.add(
        Task::web("prod", "hosted", "10.4.0.2", "hosted.acme.test").on_instance(
            "host",
            "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/abc",
            8080,
        ),
    );
    fake.add(Task::web("prod", "shop", "10.4.0.3", "shop.acme.test"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher
        .wait_ids_and_report(&["prod.shop"], "ec2 = true")
        .await;
    let report = watcher.report().to_owned();
    assert!(report.contains("bridge mode"), "{report}");
    assert!(report.contains("host mode"), "{report}");
    assert_eq!(
        fake.count("ECS DescribeContainerInstances") + fake.count("EC2 DescribeInstances"),
        0,
        "no instance is looked up unless ec2 is on"
    );
}

#[tokio::test]
async fn ecs_ec2_mode_uses_instance_address() {
    let fake = FakeAws::start().await;
    let instance = "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/abc";
    fake.add_instance(instance, "i-0123456789abcdef0", "10.9.0.7");
    fake.add(
        Task::web("prod", "bridged", "10.4.0.1", "bridged.acme.test")
            .on_instance("bridge", instance, 32768),
    );
    fake.add(
        Task::web("prod", "hosted", "10.4.0.2", "hosted.acme.test")
            .on_instance("host", instance, 8080),
    );
    // A bridge task on an instance the API does not know.
    fake.add(
        Task::web("prod", "lost", "10.4.0.4", "lost.acme.test").on_instance(
            "bridge",
            "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/gone",
            32769,
        ),
    );
    fake.add(Task::web("prod", "shop", "10.4.0.3", "shop.acme.test"));
    let settings = format!("ec2 = true\nec2_endpoint = {:?}", fake.address());
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", &settings));
    let state = watcher
        .wait_ids_and_report(
            &["prod.bridged", "prod.hosted", "prod.shop"],
            "container instance",
        )
        .await;
    assert_eq!(
        servers_of(&state, "prod.bridged", "default"),
        ["http://10.9.0.7:32768"],
        "the instance's private address and the published port"
    );
    assert_eq!(
        servers_of(&state, "prod.hosted", "default"),
        ["http://10.9.0.7:8080"]
    );
    assert_eq!(
        servers_of(&state, "prod.shop", "default"),
        ["http://10.4.0.3:8080"],
        "an awsvpc task keeps its own address"
    );
    let ec2 = requests_of(&fake, "EC2 DescribeInstances");
    assert!(!ec2.is_empty());
    assert!(ec2.iter().all(|r| r.signed == Some(true)), "{ec2:?}");
    assert!(
        ec2[0]
            .header("authorization")
            .is_some_and(|a| a.contains("/eu-west-1/ec2/aws4_request"))
    );
    assert!(ec2[0].body.contains("InstanceId.1=i-0123456789abcdef0"));
}

#[tokio::test]
async fn ecs_task_without_address_reported() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.1", "shop.acme.test"));
    fake.add(
        Task::web("prod", "ghost", "10.4.0.2", "ghost.acme.test")
            .without_address()
            .id("deadbeef"),
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher
        .wait_ids_and_report(&["prod.shop"], "no address")
        .await;
    let report = watcher.report();
    assert!(
        report.contains("deadbeef"),
        "the report names the task: {report}"
    );
    assert!(report.contains("cluster prod"), "{report}");
}

// ---- polling ----------------------------------------------------------------------------------

#[tokio::test]
async fn ecs_poll_updates() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "first", "10.4.0.1", "first.acme.test").id("t1"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.first"]).await;
    let described = || requests_of(&fake, "ECS DescribeTaskDefinition").len();
    assert_eq!(described(), 1);

    // A new task shows within one refresh, and the definition of the unchanged task is not
    // described again: a revision never changes.
    fake.add(Task::web("prod", "second", "10.4.0.2", "second.acme.test").id("t2"));
    let started = Instant::now();
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["prod.first", "prod.second"]))
        .await
        .expect("a new task shows within the refresh interval");
    assert!(started.elapsed() < PROMPT);
    assert_eq!(described(), 2);

    // A changed task (it becomes unhealthy) leaves its servers; a removed one leaves the state.
    fake.change("prod", "t1", |task| task.status("RUNNING", "STOPPED"));
    tokio::time::timeout(PROMPT, watcher.wait_ids(&["prod.second"]))
        .await
        .expect("a stopping task leaves within the refresh interval");
    fake.remove("prod", "t2");
    tokio::time::timeout(PROMPT, watcher.wait_ids(&[]))
        .await
        .expect("a removed task leaves within the refresh interval");
    assert_eq!(described(), 2);
}

#[tokio::test]
async fn ecs_api_outage_keeps_last_state() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.1", "shop.acme.test").id("t1"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.shop"]).await;
    let states = watcher.states;

    // ECS is gone: an outage, and no state that says the app is gone.
    fake.stop();
    watcher.wait_outage("cannot reach").await;
    assert_eq!(watcher.states, states, "an outage is not an empty list");
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state")),
        ["prod.shop"]
    );

    // It comes back with the task gone: the state follows.
    fake.remove("prod", "t1");
    fake.restart().await;
    watcher.wait_ids(&[]).await;
    assert!(watcher.states > states);
}

#[tokio::test]
async fn ecs_api_error_keeps_last_state() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.1", "shop.acme.test"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.shop"]).await;
    let states = watcher.states;

    // An IAM policy that lost a permission is an error answer, not an empty cluster.
    fake.deny(true);
    watcher.wait_outage("AccessDeniedException").await;
    assert!(watcher.report().contains("400"), "{}", watcher.report());
    assert_eq!(watcher.states, states);
    assert_eq!(
        ids(watcher.state.as_ref().expect("the last state")),
        ["prod.shop"]
    );
}

// ---- exposure and labels ----------------------------------------------------------------------

#[tokio::test]
async fn ecs_exposed_by_default_false() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "enabled", "10.4.0.1", "a.acme.test"));
    // Labels but no enable label: not exposed unless the source says so.
    fake.add(Task::new("prod", "quiet", "10.4.0.2").label("podgate.host", "b.acme.test"));
    // `false` hides in every mode.
    fake.add(
        Task::new("prod", "hidden", "10.4.0.3")
            .id("hidden-task")
            .label("podgate.enable", "false")
            .label("podgate.host", "c.acme.test"),
    );
    // Nothing at all: no labels, no router.
    fake.add(Task::new("prod", "bare", "10.4.0.4").id("bare-task"));
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.enabled"]).await;
    assert_eq!(watcher.report(), "", "{}", watcher.report());

    let mut watcher = Watcher::start(&ecs_config(
        &fake.address(),
        "",
        "exposed_by_default = true",
    ));
    watcher
        .wait_ids_and_report(&["prod.enabled", "prod.quiet"], "bare-task")
        .await;
    assert!(
        watcher.report().contains("no router"),
        "{}",
        watcher.report()
    );
    assert!(
        !watcher.report().contains("hidden-task"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn ecs_unknown_label_rejects_container() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "good", "10.4.0.1", "good.acme.test"));
    fake.add(
        Task::web("prod", "typo", "10.4.0.2", "typo.acme.test")
            .label("podgate.hosts", "x.acme.test"),
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher
        .wait_ids_and_report(&["prod.good"], "unknown label podgate.hosts")
        .await;
    assert!(
        watcher.report().contains("container web"),
        "{}",
        watcher.report()
    );
}

#[tokio::test]
async fn ecs_label_address_rejected() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "good", "10.4.0.1", "good.acme.test"));
    // A service that lists its own servers.
    fake.add(
        Task::web("prod", "listed", "10.4.0.2", "listed.acme.test").label(
            "podgate.service.web.config",
            r#"{"servers":[{"url":"http://10.0.0.99:80"}]}"#,
        ),
    );
    // A port label that is an address.
    fake.add(
        Task::web("prod", "ported", "10.4.0.3", "ported.acme.test")
            .label("podgate.port", "10.0.0.99:8080"),
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    let state = watcher.wait_ids_and_report(&["prod.good"], "address").await;
    assert_eq!(
        servers_of(&state, "prod.good", "default"),
        ["http://10.4.0.1:8080"]
    );
    let report = watcher.report().to_owned();
    assert!(report.contains("names an address"), "{report}");
    assert!(report.contains("podgate.port"), "{report}");
    let serialized = serde_json::to_string(&state.apps.iter().map(|a| &a.app).collect::<Vec<_>>())
        .expect("apps serialize");
    assert!(!serialized.contains("10.0.0.99"), "{serialized}");
}

// ---- tenants and trust ------------------------------------------------------------------------

const CLUSTERS: &str = r#"
clusters = ["prod-acme", "prod-globex", "scratch"]
tenant_from = "cluster"
cluster_tenants = { prod-acme = "acme", prod-globex = "globex" }
tenant = "default"
"#;

#[tokio::test]
async fn ecs_cluster_tenant() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod-acme", "web", "10.4.0.1", "web.acme.test"));
    fake.add(Task::web(
        "prod-globex",
        "web",
        "10.4.0.2",
        "web.globex.test",
    ));
    fake.add(Task::web("scratch", "web", "10.4.0.3", "web.example.test"));
    let config = ecs_config(&fake.address(), TENANTS, CLUSTERS);
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids(&["prod-acme.web", "prod-globex.web", "scratch.web"])
        .await;
    let tenants: Vec<(String, Option<&str>)> = state
        .apps
        .iter()
        .map(|app| (app.app.id.to_string(), app.tenant.mapped.as_deref()))
        .collect();
    assert_eq!(
        tenants,
        [
            ("prod-acme.web".to_owned(), Some("acme")),
            ("prod-globex.web".to_owned(), Some("globex")),
            ("scratch.web".to_owned(), Some("default")),
        ],
        "the same service name in three clusters is three apps, each in its cluster's tenant"
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("ecs-prod-acme.web".to_owned(), "acme".to_owned()),
            ("ecs-prod-globex.web".to_owned(), "globex".to_owned()),
            ("ecs-scratch.web".to_owned(), "default".to_owned()),
        ],
        "{:#?}",
        merged.findings()
    );

    // Discovery reads every cluster of the account, and maps a new one to the fallback.
    let discovered = ecs_config(
        &fake.address(),
        TENANTS,
        "auto_discover = true\ntenant_from = \"cluster\"\ncluster_tenants = { prod-acme = \"acme\" }",
    );
    let mut watcher = Watcher::start(&discovered);
    watcher
        .wait_ids(&["prod-acme.web", "prod-globex.web", "scratch.web"])
        .await;
    assert!(fake.count("ECS ListClusters") >= 1);
}

#[tokio::test]
async fn ecs_tenant_tag_requires_trust() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "mine", "10.4.0.1", "web.acme.test"));
    // A deployer names globex, by task tag and by container label, for globex's hosts.
    fake.add(
        Task::web("prod", "tagged", "10.4.0.2", "shop.globex.test").tag("podgate.tenant", "globex"),
    );
    fake.add(
        Task::web("prod", "labelled", "10.4.0.3", "www.globex.test")
            .label("podgate.tenant", "globex"),
    );
    let settings = "tenant_from = \"tag\"\ntenant = \"acme\"";
    let untrusted = ecs_config(&fake.address(), TENANTS, settings);
    let mut watcher = Watcher::start(&untrusted);
    let state = watcher
        .wait_ids(&["prod.labelled", "prod.mine", "prod.tagged"])
        .await;
    for id in ["prod.labelled", "prod.tagged"] {
        let claim = &app_of(&state, id).tenant;
        assert_eq!(claim.label.as_deref(), Some("globex"), "{id}");
        assert_eq!(claim.mapped.as_deref(), Some("acme"), "{id}");
    }
    assert_eq!(app_of(&state, "prod.mine").tenant.label, None);
    let merged = merge(&untrusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("ecs-prod.mine".to_owned(), "acme".to_owned())],
        "a tag is a claim: without the trust rule it moves nothing, and the host is not acme's"
    );
    let codes: BTreeSet<&str> = finding_codes(&merged)
        .iter()
        .map(|(code, _)| *code)
        .collect();
    assert_eq!(
        codes,
        BTreeSet::from(["foreign_host_claim", "label_ignored"]),
        "{:?}",
        finding_codes(&merged)
    );

    let trusted_tenants = TENANTS.replace(
        "hosts = [\"globex.test\", \"*.globex.test\"]",
        "hosts = [\"globex.test\", \"*.globex.test\"]\nlabel_sources = [\"ecs\"]",
    );
    let trusted = ecs_config(&fake.address(), &trusted_tenants, settings);
    let mut watcher = Watcher::start(&trusted);
    let state = watcher
        .wait_ids(&["prod.labelled", "prod.mine", "prod.tagged"])
        .await;
    let merged = merge(&trusted, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [
            ("ecs-prod.labelled".to_owned(), "globex".to_owned()),
            ("ecs-prod.mine".to_owned(), "acme".to_owned()),
            ("ecs-prod.tagged".to_owned(), "globex".to_owned()),
        ],
        "a tenant that lists the source in label_sources honours the claim"
    );
}

#[tokio::test]
async fn ecs_label_cannot_claim_foreign_host() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod-acme", "mine", "10.4.0.1", "web.acme.test"));
    // In acme's cluster, a task claims globex's host, with and without naming globex. Under
    // `tenant_from = "cluster"` the tenant label is not even read.
    fake.add(Task::web(
        "prod-acme",
        "grab",
        "10.4.0.2",
        "www.globex.test",
    ));
    fake.add(
        Task::web("prod-acme", "sneaky", "10.4.0.3", "shop.globex.test")
            .label("podgate.tenant", "globex")
            .tag("podgate.tenant", "globex"),
    );
    let config = ecs_config(
        &fake.address(),
        TENANTS,
        "clusters = [\"prod-acme\"]\ntenant_from = \"cluster\"\ncluster_tenants = { prod-acme = \"acme\" }",
    );
    let mut watcher = Watcher::start(&config);
    let state = watcher
        .wait_ids(&["prod-acme.grab", "prod-acme.mine", "prod-acme.sneaky"])
        .await;
    assert_eq!(
        app_of(&state, "prod-acme.sneaky").tenant.label,
        None,
        "the cluster decides the tenant; a label has no say"
    );
    let merged = merge(&config, UpstreamPolicy::builtin(), state);
    assert_eq!(
        merged_apps(&merged),
        [("ecs-prod-acme.mine".to_owned(), "acme".to_owned())]
    );
    let foreign: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "foreign_host_claim")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(foreign, ["prod-acme.grab", "prod-acme.sneaky"]);
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_ecs() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "inside", "10.4.0.1", "in.acme.test"));
    // The task's interface is wherever the VPC put it: the policy judges the address.
    fake.add(Task::web("prod", "outside", "10.5.0.1", "out.acme.test"));
    let config = ecs_config(&fake.address(), TENANTS, "tenant = \"acme\"");
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let mut watcher = Watcher::start(&config);
    let state = watcher.wait_ids(&["prod.inside", "prod.outside"]).await;
    let merged = merge(&config, policy, state);
    assert_eq!(
        merged_apps(&merged),
        [("ecs-prod.inside".to_owned(), "acme".to_owned())]
    );
    let forbidden: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["prod.outside"]);
}

// ---- what the client sends --------------------------------------------------------------------

#[tokio::test]
async fn ecs_client_only_reads() {
    let fake = FakeAws::start().await;
    let instance = "arn:aws:ecs:eu-west-1:123456789012:container-instance/prod/abc";
    fake.add_instance(instance, "i-0123456789abcdef0", "10.9.0.7");
    fake.add_service("prod", "shop", 1_690_000_000.0);
    fake.add(Task::web("prod", "shop", "10.4.0.1", "shop.acme.test"));
    fake.add(
        Task::web("prod", "bridged", "10.4.0.2", "bridged.acme.test")
            .on_instance("bridge", instance, 32768),
    );
    let settings = format!(
        "auto_discover = true\nec2 = true\nec2_endpoint = {:?}",
        fake.address()
    );
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", &settings));
    watcher.wait_ids(&["prod.bridged", "prod.shop"]).await;

    let allowed: BTreeSet<&str> = BTreeSet::from([
        "ECS ListClusters",
        "ECS ListTasks",
        "ECS DescribeTasks",
        "ECS DescribeTaskDefinition",
        "ECS DescribeServices",
        "ECS DescribeContainerInstances",
        "EC2 DescribeInstances",
    ]);
    let seen = fake.whats();
    for what in &seen {
        assert!(allowed.contains(what.as_str()), "unexpected call {what}");
    }
    for what in &allowed {
        assert!(
            seen.iter().any(|s| s == what),
            "{what} was never called: {seen:?}"
        );
    }
    // Every EC2 call is the read `DescribeInstances`, and every ECS call a `List*` or `Describe*`.
    for request in fake.requests() {
        if request.what.starts_with("EC2") {
            assert!(
                request.body.starts_with("Action=DescribeInstances&"),
                "{request:?}"
            );
        } else {
            let target = request.header("x-amz-target").expect("a target");
            let operation = target.rsplit('.').next().expect("an operation");
            assert!(
                operation.starts_with("List") || operation.starts_with("Describe"),
                "{target}"
            );
        }
    }
}

#[tokio::test]
async fn ecs_calls_are_batched_paged_and_rate_limited() {
    let fake = FakeAws::start().await;
    // 91 tasks of one service and ten services of one task each: 101 tasks to describe (the
    // fake refuses a batch of more than 100) in 11 services (it refuses more than 10 a call).
    for n in 0..91 {
        fake.add(Task::web(
            "prod",
            "big",
            &format!("10.7.{}.{}", n / 200, n % 200 + 1),
            "big.acme.test",
        ));
    }
    for n in 0..10 {
        fake.add_service("prod", &format!("small{n}"), 1_690_000_000.0);
        fake.add(Task::web(
            "prod",
            &format!("small{n}"),
            &format!("10.8.0.{}", n + 1),
            &format!("small{n}.acme.test"),
        ));
    }
    fake.add_service("prod", "big", 1_690_000_000.0);
    fake.page_size(40);
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    let mut expected: Vec<String> = (0..10).map(|n| format!("prod.small{n}")).collect();
    expected.push("prod.big".to_owned());
    expected.sort();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    let state = watcher.wait_ids(&expected).await;
    assert_eq!(servers_of(&state, "prod.big", "default").len(), 91);

    assert_eq!(fake.count("ECS ListTasks"), 3, "101 tasks in pages of 40");
    assert_eq!(fake.count("ECS DescribeTasks"), 2, "100, then 1");
    assert_eq!(fake.count("ECS DescribeServices"), 2, "ten, then one");
    assert_eq!(fake.count("ECS DescribeTaskDefinition"), 11);

    // Calls are spaced: ten a second at most.
    let times: Vec<Instant> = fake.requests().iter().map(|r| r.at).collect();
    for pair in times.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(gap >= Duration::from_millis(70), "calls {gap:?} apart");
    }
}

#[tokio::test]
async fn ecs_throttled_calls_back_off() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.1", "shop.acme.test"));
    fake.throttle(2);
    let mut watcher = Watcher::start(&ecs_config(&fake.address(), "", ""));
    watcher.wait_ids(&["prod.shop"]).await;
    let lists = requests_of(&fake, "ECS ListTasks");
    assert_eq!(lists.len(), 3, "two throttled answers, then the list");
    for pair in lists.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(gap >= Duration::from_millis(180), "retried after {gap:?}");
    }
    assert_eq!(watcher.report(), "");
}

// ---- configuration and the program ------------------------------------------------------------

#[tokio::test]
async fn ecs_config_rejects_bad_entries() {
    let cases: [(&str, &str); 15] = [
        ("region = \"eu-west-1\"\nfoo = 1", "unknown field"),
        ("region = \"EU\"", "region"),
        (
            "region = \"eu-west-1\"\nendpoint = \"ecs.example.com\"",
            "endpoint",
        ),
        (
            "region = \"eu-west-1\"\nendpoint = \"https://a@ecs.example.com\"",
            "credentials",
        ),
        (
            "region = \"eu-west-1\"\nendpoint = \"https://ecs.example.com/v1\"",
            "origin",
        ),
        ("region = \"eu-west-1\"\nrefresh_secs = 4", "refresh_secs"),
        ("region = \"eu-west-1\"\nnetwork = \"bridge\"", "network"),
        (
            "region = \"eu-west-1\"\nclusters = [\"a\"]\nauto_discover = true",
            "exclude each other",
        ),
        ("region = \"eu-west-1\"\nclusters = []", "clusters"),
        (
            "region = \"eu-west-1\"\ntenant_from = \"cluster\"",
            "cluster_tenants",
        ),
        (
            "region = \"eu-west-1\"\ncluster_tenants = { a = \"x\" }",
            "cluster_tenants",
        ),
        (
            "region = \"eu-west-1\"\nclusters = [\"a\"]\ntenant_from = \"cluster\"\ncluster_tenants = { b = \"x\" }",
            "not one of the source's clusters",
        ),
        (
            "region = \"eu-west-1\"\nclusters = [\"a\", \"b\"]\ntenant_from = \"cluster\"\ncluster_tenants = { a = \"x\" }",
            "no tenant for cluster",
        ),
        (
            "region = \"eu-west-1\"\nec2_endpoint = \"https://ec2.example.com\"",
            "ec2 = true",
        ),
        ("endpoint = \"https://ecs.example.com\"", "region"),
    ];
    for (settings, needle) in cases {
        let config = config(
            std::path::Path::new("/x.sock"),
            &format!("[[source]]\nkind = \"ecs\"\nname = \"ecs\"\n{settings}\n"),
        );
        let err = EcsSource::from_config_with_env(&config.sources[0], Vec::new())
            .expect_err(settings)
            .to_string();
        assert!(err.contains(needle), "{needle:?} missing from {err}");
        assert!(err.starts_with("source ecs: "), "{err}");
    }
    // The region may come from the environment.
    let config = config(
        std::path::Path::new("/x.sock"),
        "[[source]]\nkind = \"ecs\"\nname = \"ecs\"\n",
    );
    assert!(
        EcsSource::from_config_with_env(&config.sources[0], pairs(&[("AWS_REGION", "eu-west-1")]))
            .is_ok()
    );
}

#[tokio::test]
async fn ecs_runs_in_the_program() {
    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.5", "shop.acme.test"));
    let path = std::env::temp_dir().join(format!("pgp-ecs-print-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n[[source]]\nkind = \"ecs\"\nname = \"ecs\"\nregion = \"eu-west-1\"\nendpoint = {:?}\nclusters = [\"prod\"]\n",
            fake.address()
        ),
    )
    .expect("config");
    let output = tokio::task::spawn_blocking({
        let path = path.clone();
        move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
                .args(["print", "--config"])
                .arg(path)
                .env("AWS_ACCESS_KEY_ID", ACCESS_KEY)
                .env("AWS_SECRET_ACCESS_KEY", SECRET_KEY)
                .env("AWS_SESSION_TOKEN", SESSION_TOKEN)
                .output()
                .expect("run print")
        }
    })
    .await
    .expect("print ran");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("\"id\":\"ecs-prod.shop\""), "{stdout}");
    assert!(stdout.contains("http://10.4.0.5:8080"), "{stdout}");
    for secret in [SECRET_KEY, SESSION_TOKEN] {
        assert!(!stdout.contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    }
    let _ = std::fs::remove_file(path);
}
