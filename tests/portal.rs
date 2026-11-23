//! The developer portal through the real binary: who may declare it and behind which
//! login, what each viewer sees (only the published APIs of their own tenant), what the page and
//! the documents never carry, and that nothing about a viewer is kept.
//!
//! The portal is a `portal` stage after a `jwt_auth` stage of the operator's app `ops/portal`,
//! listed in `PORTAL_APPS` with a pin over the login's issuer and keys. A viewer is a signed
//! token whose `tenant` claim names the tenant.

mod common;

#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::path::Path;

use common::{Podgate, Response, Upstream, app, router, serving, with_middleware};
use podgate::dashboard::CONTENT_SECURITY_POLICY_VALUE;
use podgate::middleware::portal::pin::fingerprint;
use serde_json::{Value, json};
use signer::{Signer, now};

const ISSUER: &str = "https://idp.test";
const HOST: &str = "portal.test";

fn keys_of(signer: &Signer) -> Value {
    json!({"keys": [signer.jwk()]})
}

/// The `PORTAL_APPS` entry that lists `ops/portal` with a pin over `signer`'s inline keys.
fn pin(signer: &Signer) -> String {
    let print = fingerprint(&keys_of(signer)).expect("a fingerprint");
    format!("ops/portal={ISSUER}|keys:{print}")
}

fn jwt_config(signer: &Signer) -> Value {
    json!({"keys": keys_of(signer), "algorithms": ["ES256"], "issuer": ISSUER})
}

fn tenant(id: &str) -> Value {
    json!({"id": id, "weight": 1, "budget": {"max_inflight": 100, "max_buffer_bytes": 16_777_216}})
}

/// The operator's app: the login, then the portal.
fn operator_app(signer: &Signer, upstream: &Upstream) -> Value {
    let mut portal = app("portal", &[HOST], &[serving("r1", upstream.addr)]);
    portal["tenant"] = json!("ops");
    let portal = with_middleware(portal, "jwt", "jwt_auth", jwt_config(signer));
    with_middleware(portal, "portal", "portal", json!({}))
}

fn under(host: &str, name: &str, prefix: &str) -> Value {
    router(
        name,
        json!({"all": [{"host": host}, {"path_prefix": prefix}]}),
        "web",
    )
}

/// An OpenAPI document whose every field that must not reach a viewer holds `mark`.
fn document(mark: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": format!("{mark} Pets API"), "version": "1.0.0",
            "description": format!("{mark}-doc-description"),
        },
        "servers": [{"url": format!("https://{mark}-internal.example/v1")}],
        "x-owner": format!("{mark}-extension"),
        "paths": {"/pets": {"get": {
            "summary": format!("{mark} list pets"),
            "description": format!(
                "Authorization: Bearer {} and postgres://app:hunter2hunter2@db.internal/x",
                "q".repeat(30)
            ),
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "example": {"token": format!("{mark}-example-token")},
                "schema": {"type": "object"},
            }}}},
        }}},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
    })
}

fn api(id: &str, version: &str, lifecycle: &str, router: &str, extra: &Value) -> Value {
    let mut entry = json!({
        "id": id, "version": version, "lifecycle": lifecycle, "routers": [router],
    });
    if let (Some(entry), Some(extra)) = (entry.as_object_mut(), extra.as_object()) {
        entry.extend(extra.clone());
    }
    entry
}

/// Tenant `acme`: published and unpublished entries at every lifecycle, and a text that tries to
/// run script. Every field holds `ACMEMARK`.
fn acme(upstream: &Upstream) -> Value {
    let mut app = app(
        "pets-app",
        &["pets.acme.test"],
        &[serving("r1", upstream.addr)],
    );
    app["tenant"] = json!("acme");
    let host = "pets.acme.test";
    app["routers"] = json!([
        under(host, "p1", "/p1"),
        under(host, "p2", "/p2"),
        under(host, "d1", "/d1"),
        under(host, "g1", "/g1"),
        under(host, "h1", "/h1"),
        under(host, "p0", "/p0"),
        under(host, "l1", "/l1"),
    ]);
    app["middlewares"] = json!([
        {"name": "spec", "type": "openapi", "document": document("ACMEMARK")},
    ]);
    app["apis"] = json!([
        api(
            "pets",
            "1",
            "stable",
            "p1",
            &json!({
                "published": true, "openapi": "spec",
                "title": "ACMEMARK Pets <script>alert('acme')</script>",
                "description": "<img src=x onerror=alert(1)> ACMEMARK stable",
            })
        ),
        api(
            "pets",
            "2",
            "preview",
            "p2",
            &json!({
                "published": true, "title": "ACMEMARK Pets 2",
            })
        ),
        api(
            "drafty",
            "1",
            "draft",
            "d1",
            &json!({
                "published": true, "title": "ACMEMARK draft",
            })
        ),
        api(
            "gone",
            "1",
            "retired",
            "g1",
            &json!({
                "published": true, "title": "ACMEMARK retired",
            })
        ),
        api(
            "hidden",
            "1",
            "stable",
            "h1",
            &json!({
                "published": false, "openapi": "spec", "title": "ACMEMARK hidden",
            })
        ),
        api(
            "pets",
            "0",
            "deprecated",
            "p0",
            &json!({
                "published": true, "title": "ACMEMARK Pets 0", "sunset": "2027-03-01",
                "successor": {"id": "pets", "version": "1"},
            })
        ),
        api(
            "legacy",
            "1",
            "deprecated",
            "l1",
            &json!({
                "published": true, "title": "ACMEMARK legacy", "sunset": "2027-04-01",
                "successor": {"id": "hidden", "version": "1"},
            })
        ),
    ]);
    app
}

/// Tenant `globex`: one entry that shares its `(id, version)` with acme's, one that does not,
/// one unpublished. Every field holds `GLOBEXMARK`.
fn globex(upstream: &Upstream) -> Value {
    let mut app = app(
        "billing",
        &["billing.globex.test"],
        &[serving("r1", upstream.addr)],
    );
    app["tenant"] = json!("globex");
    let host = "billing.globex.test";
    app["routers"] = json!([
        under(host, "b1", "/b1"),
        under(host, "i1", "/i1"),
        under(host, "s1", "/s1"),
    ]);
    app["middlewares"] = json!([
        {"name": "spec", "type": "openapi", "document": document("GLOBEXMARK")},
    ]);
    app["apis"] = json!([
        api(
            "pets",
            "1",
            "stable",
            "b1",
            &json!({
                "published": true, "openapi": "spec", "title": "GLOBEXMARK Pets",
                "description": "GLOBEXMARK description",
            })
        ),
        api(
            "invoices",
            "1",
            "stable",
            "i1",
            &json!({
                "published": true, "title": "GLOBEXMARK Invoices",
            })
        ),
        api(
            "secret",
            "1",
            "stable",
            "s1",
            &json!({
                "published": false, "title": "GLOBEXMARK secret",
            })
        ),
    ]);
    app
}

fn fleet(version: u64, signer: &Signer, upstream: &Upstream) -> Value {
    json!({
        "version": version,
        "tenants": [tenant("ops"), tenant("acme"), tenant("globex")],
        "apps": [operator_app(signer, upstream), acme(upstream), globex(upstream)],
    })
}

struct Fleet {
    podgate: Podgate,
    signer: Signer,
    upstream: Upstream,
}

async fn start_with(extra: &[(&str, &str)]) -> Fleet {
    let signer = Signer::es256("idp-key");
    let pinned = pin(&signer);
    let mut env = vec![("PORTAL_APPS", pinned.as_str())];
    env.extend_from_slice(extra);
    let podgate = Podgate::start_with_env(&env).await;
    let upstream = Upstream::start("ok").await;
    let pushed = podgate.push_snapshot(&fleet(1, &signer, &upstream)).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    Fleet {
        podgate,
        signer,
        upstream,
    }
}

async fn start() -> Fleet {
    start_with(&[]).await
}

impl Fleet {
    fn token(&self, claims: &Value) -> String {
        let mut all = json!({"sub": "ann", "iss": ISSUER, "exp": now() + 600});
        if let (Some(all), Some(extra)) = (all.as_object_mut(), claims.as_object()) {
            all.extend(extra.clone());
        }
        self.signer.sign("ES256", &json!({}), &all)
    }

    /// `method path` as a person of `claims`.
    async fn send(
        &self,
        method: &str,
        claims: &Value,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Response {
        let bearer = format!("Bearer {}", self.token(claims));
        let mut headers = vec![("Authorization", bearer.as_str())];
        headers.extend_from_slice(extra);
        self.podgate.request(method, HOST, path, &headers).await
    }

    /// `GET path` as a person of `tenant`.
    async fn get_as(&self, tenant: &str, path: &str) -> Response {
        self.send("GET", &json!({"tenant": tenant}), path, &[])
            .await
    }

    async fn list_as(&self, tenant: &str, query: &str) -> Value {
        let answer = self.get_as(tenant, &format!("/api/catalog{query}")).await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.json()
    }
}

fn keys(list: &Value) -> Vec<String> {
    list["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            format!(
                "{}/{}",
                item["id"].as_str().expect("id"),
                item["version"].as_str().expect("version")
            )
        })
        .collect()
}

fn code_of(response: &Response) -> String {
    response.json()["conflicts"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

// ---------------------------------------------------------------------------------------------
// Who may declare it, and behind which login
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn portal_off_by_default() {
    let signer = Signer::es256("idp-key");
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("ok").await;
    let refused = podgate.push_snapshot(&fleet(1, &signer, &upstream)).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(code_of(&refused), "portal_not_allowed");
    assert!(!refused.body.contains("PORTAL_APPS"), "{}", refused.body);
}

#[tokio::test]
async fn portal_only_listed_apps_may_declare() {
    let fleet_up = start().await;
    let signer = &fleet_up.signer;
    let upstream = &fleet_up.upstream;
    let mut other = operator_app(signer, upstream);
    other["id"] = json!("other");
    other["declared_by"] = json!("tests/other");
    other["routers"][0]["match"] = json!({"host": ["other.test"]});
    let mut next = fleet(2, signer, upstream);
    next["apps"].as_array_mut().expect("apps").push(other);
    let refused = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(code_of(&refused), "portal_not_allowed");
    // The portal that was live still serves.
    let list = fleet_up.list_as("acme", "").await;
    assert_eq!(list["total"], 4);
}

#[tokio::test]
async fn portal_tenant_cannot_mint_viewer() {
    let fleet_up = start().await;
    // Tenant globex declares the portal behind a `jwt_auth` over a key of its own, the same
    // issuer string, and mints a viewer of tenant acme.
    let own = Signer::es256("evil-key");
    let mut evil = app(
        "evil",
        &["evil.globex.test"],
        &[serving("r1", fleet_up.upstream.addr)],
    );
    evil["tenant"] = json!("globex");
    let evil = with_middleware(evil, "jwt", "jwt_auth", jwt_config(&own));
    let evil = with_middleware(evil, "portal", "portal", json!({}));
    let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
    next["apps"].as_array_mut().expect("apps").push(evil);
    let refused = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(code_of(&refused), "portal_not_allowed");
    assert!(
        !refused.body.contains(&fleet_up.signer.jwk().to_string()),
        "{}",
        refused.body
    );
}

#[tokio::test]
async fn portal_needs_login_in_chain() {
    let fleet_up = start().await;
    let mut bare = app("portal", &[HOST], &[serving("r1", fleet_up.upstream.addr)]);
    bare["tenant"] = json!("ops");
    let bare = with_middleware(bare, "portal", "portal", json!({}));
    let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
    next["apps"][0] = bare.clone();
    let refused = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(code_of(&refused), "portal_needs_login");
    // A login after the portal is no login before it.
    let mut after = app("portal", &[HOST], &[serving("r1", fleet_up.upstream.addr)]);
    after["tenant"] = json!("ops");
    let after = with_middleware(after, "portal", "portal", json!({}));
    let after = with_middleware(after, "jwt", "jwt_auth", jwt_config(&fleet_up.signer));
    next["apps"][0] = after;
    let refused = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(code_of(&refused), "portal_needs_login");
}

/// Pushes the operator app with `login` as its `jwt_auth` configuration.
async fn push_login(fleet_up: &Fleet, login: &Value) -> Response {
    let mut portal = app("portal", &[HOST], &[serving("r1", fleet_up.upstream.addr)]);
    portal["tenant"] = json!("ops");
    let portal = with_middleware(portal, "jwt", "jwt_auth", login.clone());
    let portal = with_middleware(portal, "portal", "portal", json!({}));
    let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
    next["apps"][0] = portal;
    fleet_up.podgate.push_snapshot(&next).await
}

#[tokio::test]
async fn portal_listed_app_other_issuer_refused() {
    let fleet_up = start().await;
    let mut login = jwt_config(&fleet_up.signer);
    login["issuer"] = json!("https://evil.test");
    let refused = push_login(&fleet_up, &login).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(code_of(&refused), "portal_login_not_pinned");
    // No issuer at all is not a pinned issuer.
    let mut bare = jwt_config(&fleet_up.signer);
    bare.as_object_mut().expect("object").remove("issuer");
    assert_eq!(
        code_of(&push_login(&fleet_up, &bare).await),
        "portal_login_not_pinned"
    );
}

#[tokio::test]
async fn portal_listed_app_same_issuer_other_keys_refused() {
    let fleet_up = start().await;
    let own = Signer::es256("own-key");
    // The pinned issuer string, the app owner's own keys.
    let mut other_keys = jwt_config(&fleet_up.signer);
    other_keys["keys"] = keys_of(&own);
    let refused = push_login(&fleet_up, &other_keys).await;
    assert_eq!(code_of(&refused), "portal_login_not_pinned", "{refused:?}");
    // The pinned keys and one more.
    let mut added = jwt_config(&fleet_up.signer);
    added["keys"] = json!({"keys": [fleet_up.signer.jwk(), own.jwk()]});
    assert_eq!(
        code_of(&push_login(&fleet_up, &added).await),
        "portal_login_not_pinned"
    );
    // The pinned keys and a `jwks_uri` of its own.
    let mut both = jwt_config(&fleet_up.signer);
    both["jwks_uri"] = json!("http://127.0.0.1:9/jwks");
    assert_eq!(
        code_of(&push_login(&fleet_up, &both).await),
        "portal_login_not_pinned"
    );
    // A `jwks_uri` instead of the pinned keys.
    let mut remote = json!({"algorithms": ["ES256"], "issuer": ISSUER});
    remote["jwks_uri"] = json!("http://127.0.0.1:9/jwks");
    assert_eq!(
        code_of(&push_login(&fleet_up, &remote).await),
        "portal_login_not_pinned"
    );
}

#[tokio::test]
async fn portal_unpinnable_login_refused() {
    let fleet_up = start().await;
    let secret = Signer::hmac("shared", &[7_u8; 32]);
    let hmac = json!({"keys": keys_of(&secret), "algorithms": ["HS256"], "issuer": ISSUER});
    assert_eq!(
        code_of(&push_login(&fleet_up, &hmac).await),
        "portal_login_not_pinned"
    );
}

#[tokio::test]
async fn portal_pinned_login_accepted() {
    // A `keys:` pin over inline keys.
    let fleet_up = start().await;
    let list = fleet_up.list_as("acme", "").await;
    assert_eq!(list["total"], 4);
    // The same pin accepts a changed declaration of the same login (a leeway, an audience).
    let mut login = jwt_config(&fleet_up.signer);
    login["leeway_secs"] = json!(60);
    let accepted = push_login(&fleet_up, &login).await;
    assert_eq!(accepted.status, 200, "{accepted:?}");

    // A `jwks:` pin over a `jwks_uri`.
    let signer = Signer::es256("idp-key");
    let uri = "http://127.0.0.1:9/jwks";
    let podgate =
        Podgate::start_with_env(&[("PORTAL_APPS", &format!("ops/portal={ISSUER}|jwks:{uri}"))])
            .await;
    let upstream = Upstream::start("ok").await;
    let remote = json!({"algorithms": ["ES256"], "issuer": ISSUER, "jwks_uri": uri});
    let mut portal = app("portal", &[HOST], &[serving("r1", upstream.addr)]);
    portal["tenant"] = json!("ops");
    let portal = with_middleware(portal, "jwt", "jwt_auth", remote.clone());
    let portal = with_middleware(portal, "portal", "portal", json!({}));
    let mut pushed = fleet(1, &signer, &upstream);
    pushed["apps"][0] = portal.clone();
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
    // Another endpoint of the same issuer is not the pinned key source.
    let mut elsewhere = remote;
    elsewhere["jwks_uri"] = json!("http://127.0.0.1:9/other-jwks");
    let portal = with_middleware(
        with_middleware(
            {
                let mut bare = app("portal", &[HOST], &[serving("r1", upstream.addr)]);
                bare["tenant"] = json!("ops");
                bare
            },
            "jwt",
            "jwt_auth",
            elsewhere,
        ),
        "portal",
        "portal",
        json!({}),
    );
    pushed["version"] = json!(2);
    pushed["apps"][0] = portal;
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(code_of(&refused), "portal_login_not_pinned", "{refused:?}");
}

#[tokio::test]
async fn portal_pin_not_in_errors_or_logs() {
    let signer = Signer::es256("idp-key");
    let issuer = "https://pinned-issuer-zq81.test";
    let uri = "http://127.0.0.1:9/pinned-keys-zq81";
    let podgate =
        Podgate::start_logged(&[("PORTAL_APPS", &format!("ops/portal={issuer}|jwks:{uri}"))]).await;
    let upstream = Upstream::start("ok").await;
    let mut portal = app("portal", &[HOST], &[serving("r1", upstream.addr)]);
    portal["tenant"] = json!("ops");
    let wrong = json!({"algorithms": ["ES256"], "issuer": "https://other.test", "jwks_uri": uri});
    let portal = with_middleware(portal, "jwt", "jwt_auth", wrong);
    let portal = with_middleware(portal, "portal", "portal", json!({}));
    let mut pushed = fleet(1, &signer, &upstream);
    pushed["apps"][0] = portal;
    let refused = podgate.push_snapshot(&pushed).await;
    assert_eq!(code_of(&refused), "portal_login_not_pinned", "{refused:?}");
    let message = refused.json()["conflicts"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    for text in [
        issuer,
        "pinned-keys-zq81",
        "pinned-issuer-zq81",
        "other.test",
    ] {
        assert!(
            !refused.body.contains(text),
            "the rejection shows {text}: {}",
            refused.body
        );
        assert!(
            !podgate.log().contains(text),
            "the log shows {text}: {}",
            podgate.log()
        );
    }
    assert!(
        message.contains("not the one the operator pinned"),
        "{message}"
    );
}

// ---------------------------------------------------------------------------------------------
// The viewer
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn portal_identity_only_from_verified_claims() {
    let fleet_up = start().await;
    // The claim names acme; everything else the client controls says globex.
    let answer = fleet_up
        .send(
            "GET",
            &json!({"tenant": "acme"}),
            "/api/catalog?limit=100",
            &[
                ("X-Portal-Tenant", "globex"),
                ("X-Tenant", "globex"),
                ("X-Forwarded-For", "10.0.0.9"),
                ("Cookie", "tenant=globex"),
            ],
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(answer.body.contains("ACMEMARK"));
    assert!(!answer.body.contains("GLOBEXMARK"), "{}", answer.body);
}

#[tokio::test]
async fn portal_ignores_tenant_headers_and_query() {
    let fleet_up = start().await;
    // The query cannot choose a tenant: it is not a parameter of the list.
    let answer = fleet_up.get_as("acme", "/api/catalog?tenant=globex").await;
    assert_eq!(answer.status, 400, "{answer:?}");
    assert_eq!(answer.body, r#"{"error":"invalid query"}"#);
    // The path's tenant must be the viewer's.
    let doc = fleet_up
        .get_as("acme", "/api/catalog/globex/pets/1/openapi")
        .await;
    assert_eq!(doc.status, 404, "{doc:?}");
    assert!(!doc.body.contains("GLOBEXMARK"));
}

#[tokio::test]
async fn portal_claim_must_be_a_string() {
    let fleet_up = start().await;
    for claims in [
        json!({"tenant": ["acme"]}),
        json!({"tenant": 7}),
        json!({"tenant": true}),
        json!({"tenant": "acme globex"}),
        json!({"tenant": "acme, globex"}),
        json!({"tenant": ""}),
        json!({"tenant": {"id": "acme"}}),
        json!({"team": "acme"}),
        json!({}),
    ] {
        let list = fleet_up.send("GET", &claims, "/api/catalog", &[]).await;
        assert_eq!(list.status, 401, "{claims}: {list:?}");
        assert_eq!(list.body, r#"{"error":"unauthorized"}"#);
        // The page still loads, to say so.
        let page = fleet_up.send("GET", &claims, "/", &[]).await;
        assert_eq!(page.status, 200, "{claims}: {page:?}");
    }
}

#[tokio::test]
async fn portal_anonymous_gets_401() {
    let fleet_up = start().await;
    // A login that names no tenant: one `401` for every API path, whether or not it exists.
    let none = json!({});
    let mut bodies = Vec::new();
    for path in [
        "/api/catalog",
        "/api/catalog?limit=3",
        "/api/catalog/acme/pets/1/openapi",
        "/api/catalog/acme/nothing/9/openapi",
        "/api/catalog/x/y/z/openapi",
    ] {
        let answer = fleet_up.send("GET", &none, path, &[]).await;
        assert_eq!(answer.status, 401, "{path}: {answer:?}");
        bodies.push(answer.body);
    }
    assert!(bodies.iter().all(|body| *body == bodies[0]), "{bodies:?}");
    // No login at all is the login stage's own answer.
    let nobody = fleet_up.podgate.get(HOST, "/api/catalog").await;
    assert_eq!(nobody.status, 401, "{nobody:?}");
    assert!(nobody.header("www-authenticate").is_some());
}

// ---------------------------------------------------------------------------------------------
// What a viewer sees
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn portal_lists_only_published() {
    let fleet_up = start().await;
    let list = fleet_up.list_as("acme", "?limit=100").await;
    assert_eq!(list["total"], 4);
    assert_eq!(keys(&list), ["legacy/1", "pets/0", "pets/1", "pets/2"]);
    assert!(list.get("truncated").is_none(), "{list}");
    for hidden in [
        "drafty",
        "gone",
        "hidden",
        "ACMEMARK draft",
        "ACMEMARK retired",
        "ACMEMARK hidden",
    ] {
        assert!(
            !list.to_string().contains(hidden),
            "{hidden} is listed: {list}"
        );
    }
    let globex = fleet_up.list_as("globex", "?limit=100").await;
    assert_eq!(keys(&globex), ["invoices/1", "pets/1"]);
    // Nothing the portal does not show: no app, no declaring source, no router, no flag.
    let first = &list["items"][0];
    for hidden in [
        "app",
        "declared_by",
        "routers",
        "published",
        "version_of_snapshot",
    ] {
        assert!(first.get(hidden).is_none(), "{hidden}: {first}");
    }
}

#[tokio::test]
async fn portal_viewer_sees_only_own_tenant() {
    let fleet_up = start().await;
    let paths = [
        "/api/catalog?limit=100",
        "/api/catalog?q=mark",
        "/api/catalog?q=pets&limit=1",
        "/api/catalog/acme/pets/1/openapi",
        "/api/catalog/globex/pets/1/openapi",
        "/api/catalog/acme/hidden/1/openapi",
        "/api/catalog/globex/secret/1/openapi",
    ];
    for (viewer, other) in [("acme", "GLOBEX"), ("globex", "ACME")] {
        for path in paths {
            let answer = fleet_up.get_as(viewer, path).await;
            assert!(
                !answer.body.to_uppercase().contains(&format!("{other}MARK")),
                "{viewer} {path}: {answer:?}"
            );
            assert!(
                answer.status == 200 || answer.status == 404,
                "{viewer} {path}: {answer:?}"
            );
        }
    }
    let acme_list = fleet_up.list_as("acme", "?limit=100").await;
    for item in acme_list["items"].as_array().expect("items") {
        assert_eq!(item["tenant"], "acme");
    }
    assert!(
        fleet_up
            .list_as("acme", "?limit=100")
            .await
            .to_string()
            .contains("pets.acme.test")
    );
    assert!(
        !fleet_up
            .list_as("globex", "?limit=100")
            .await
            .to_string()
            .contains("acme")
    );
}

#[tokio::test]
async fn portal_same_id_in_two_tenants() {
    let fleet_up = start().await;
    let acme = fleet_up.list_as("acme", "?q=pets&limit=100").await;
    let globex = fleet_up.list_as("globex", "?q=pets&limit=100").await;
    let find = |list: &Value| {
        list["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|item| item["id"] == "pets" && item["version"] == "1")
            .cloned()
            .expect("pets 1")
    };
    assert!(
        find(&acme)["title"]
            .as_str()
            .expect("title")
            .contains("ACMEMARK")
    );
    assert!(
        find(&globex)["title"]
            .as_str()
            .expect("title")
            .contains("GLOBEXMARK")
    );
    let doc_acme = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/1/openapi")
        .await;
    let doc_globex = fleet_up
        .get_as("globex", "/api/catalog/globex/pets/1/openapi")
        .await;
    assert!(doc_acme.body.contains("ACMEMARK") && !doc_acme.body.contains("GLOBEXMARK"));
    assert!(doc_globex.body.contains("GLOBEXMARK") && !doc_globex.body.contains("ACMEMARK"));
}

#[tokio::test]
async fn portal_other_tenant_document_404() {
    let fleet_up = start().await;
    let foreign = fleet_up
        .get_as("globex", "/api/catalog/acme/pets/1/openapi")
        .await;
    let unknown = fleet_up
        .get_as("globex", "/api/catalog/globex/nothing/9/openapi")
        .await;
    assert_eq!(foreign.status, 404, "{foreign:?}");
    assert_eq!(foreign.body, unknown.body);
    assert_eq!(foreign.body, r#"{"error":"not found"}"#);
    assert_eq!(
        foreign.header("content-length"),
        unknown.header("content-length")
    );
    // Even a tenant named as globex in the path but asked for acme's id.
    let swapped = fleet_up
        .get_as("globex", "/api/catalog/globex/hidden/1/openapi")
        .await;
    assert_eq!(swapped.body, unknown.body);
}

#[tokio::test]
async fn portal_other_tenant_search_empty() {
    let fleet_up = start().await;
    for query in [
        "?q=ACMEMARK",
        "?q=acmemark",
        "?q=pets.acme.test",
        "?q=ACMEMARK%20Pets",
        "?q=legacy",
    ] {
        let answer = fleet_up.list_as("globex", query).await;
        assert_eq!(answer["total"], 0, "{query}: {answer}");
        assert_eq!(answer["items"], json!([]), "{query}");
    }
    // Their own text is found; acme's is found only by acme.
    assert_eq!(fleet_up.list_as("globex", "?q=invoices").await["total"], 1);
    assert_eq!(fleet_up.list_as("acme", "?q=ACMEMARK").await["total"], 4);
}

#[tokio::test]
async fn portal_other_tenant_cursor_leaks_nothing() {
    let fleet_up = start().await;
    // A cursor that names an entry only acme has, and one that names nothing.
    let a = fleet_up
        .list_as("globex", "?after=drafty%2F1&limit=100")
        .await;
    let b = fleet_up.list_as("globex", "?after=zzz%2F9&limit=100").await;
    assert_eq!(keys(&a), ["invoices/1", "pets/1"]);
    assert_eq!(b["items"], json!([]));
    assert!(!a.to_string().contains("ACMEMARK"));
    assert_eq!(
        a["total"], 2,
        "the total counts the viewer's own entries only"
    );
    // A page of the viewer's own entries ends with a cursor that names the viewer's own.
    let page = fleet_up.list_as("acme", "?limit=2").await;
    assert_eq!(page["total"], 4);
    assert_eq!(page["truncated"], true);
    assert_eq!(page["next"], "pets/0");
    let rest = fleet_up.list_as("acme", "?limit=100&after=pets%2F0").await;
    assert_eq!(keys(&rest), ["pets/1", "pets/2"]);
}

#[tokio::test]
async fn portal_errors_echo_nothing() {
    let fleet_up = start().await;
    let mut bodies = Vec::new();
    for path in [
        "/api/catalog/ECHO-tenant/ECHO-id/ECHO-ver/openapi",
        "/api/catalog/acme/ECHO-id/1/openapi",
        "/nothing-ECHO",
        "/api/ECHO",
        "/v1/ECHO",
    ] {
        let answer = fleet_up.get_as("acme", path).await;
        assert_eq!(answer.status, 404, "{path}: {answer:?}");
        assert!(!answer.body.contains("ECHO"), "{path}: {}", answer.body);
        bodies.push(answer.body);
    }
    assert!(bodies.iter().all(|body| *body == bodies[0]), "{bodies:?}");
    for query in [
        "?tenant=ECHO",
        "?q=ok&limit=ECHO",
        "?after=ECHO",
        "?ECHO=1",
        "?limit=0",
    ] {
        let answer = fleet_up
            .get_as("acme", &format!("/api/catalog{query}"))
            .await;
        assert_eq!(answer.status, 400, "{query}: {answer:?}");
        assert_eq!(answer.body, r#"{"error":"invalid query"}"#);
    }
    let doc_query = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/1/openapi?x=ECHO")
        .await;
    assert_eq!(doc_query.status, 400);
    assert!(!doc_query.body.contains("ECHO"));
}

#[tokio::test]
async fn portal_never_caches_across_viewers() {
    let fleet_up = start().await;
    for tenant in ["acme", "globex", "acme"] {
        for path in [
            "/api/catalog",
            "/api/catalog/acme/pets/1/openapi",
            "/api/catalog/zzz/y/1/openapi",
        ] {
            let answer = fleet_up.get_as(tenant, path).await;
            assert_eq!(
                answer.header("cache-control"),
                Some("no-store"),
                "{tenant} {path}"
            );
            for validator in ["etag", "last-modified", "age", "expires"] {
                assert!(answer.header(validator).is_none(), "{validator} on {path}");
            }
        }
    }
    // Two viewers one after the other each get their own answer.
    let first = fleet_up.get_as("acme", "/api/catalog").await;
    let second = fleet_up.get_as("globex", "/api/catalog").await;
    assert!(first.body.contains("ACMEMARK") && !first.body.contains("GLOBEXMARK"));
    assert!(second.body.contains("GLOBEXMARK") && !second.body.contains("ACMEMARK"));
}

#[tokio::test]
async fn portal_unpublished_equals_unknown() {
    let fleet_up = start().await;
    let unknown = fleet_up
        .get_as("acme", "/api/catalog/acme/nothing/9/openapi")
        .await;
    for missing in ["hidden/1", "drafty/1", "gone/1", "pets/9", "legacy/1"] {
        let answer = fleet_up
            .get_as("acme", &format!("/api/catalog/acme/{missing}/openapi"))
            .await;
        assert_eq!(answer.status, 404, "{missing}: {answer:?}");
        assert_eq!(answer.body, unknown.body, "{missing}");
        assert_eq!(
            answer.header("content-type"),
            unknown.header("content-type")
        );
        assert_eq!(
            answer.header("content-length"),
            unknown.header("content-length")
        );
    }
    // A published entry without a described API is the same `404`.
    let plain = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/2/openapi")
        .await;
    assert_eq!(plain.body, unknown.body);
    assert_eq!(fleet_up.list_as("acme", "?q=hidden").await["total"], 0);
}

#[tokio::test]
async fn portal_path_traversal_404() {
    let fleet_up = start().await;
    for path in [
        "/api/catalog/acme/../globex/pets/1/openapi",
        "/api/catalog/acme/%2e%2e/globex/pets/1/openapi",
        "/api/catalog/acme/pets/1/../../../globex/pets/1/openapi",
        "/api/catalog/acme%2Fx/../pets/1/openapi",
        "/api/catalog/acme/pets%2F1%2Fopenapi",
        "/api/catalog//globex/pets/1/openapi",
        "/api/catalog/acme/pets/1/openapi/",
        "/api/catalog/acme/pets/1/openapi/../../../v1/snapshot",
        "/../api/catalog/globex/pets/1/openapi",
        "/api/catalog/globex%00/pets/1/openapi",
    ] {
        let answer = fleet_up.get_as("acme", path).await;
        assert!(
            answer.status == 404 || answer.status == 400,
            "{path}: {answer:?}"
        );
        assert!(
            !answer.body.contains("GLOBEXMARK"),
            "{path}: {}",
            answer.body
        );
    }
}

#[tokio::test]
async fn portal_follows_live_table() {
    let fleet_up = start().await;
    assert_eq!(fleet_up.list_as("acme", "").await["total"], 4);
    // A swap that unpublishes pets/1 removes it from the list and its document.
    let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
    next["apps"][1]["apis"][0]["published"] = json!(false);
    let pushed = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
    let list = fleet_up.list_as("acme", "?limit=100").await;
    assert_eq!(keys(&list), ["legacy/1", "pets/0", "pets/2"]);
    assert_eq!(
        fleet_up
            .get_as("acme", "/api/catalog/acme/pets/1/openapi")
            .await
            .status,
        404
    );
    // A rejected snapshot changes nothing.
    let mut bad = fleet(3, &fleet_up.signer, &fleet_up.upstream);
    bad["apps"][1]["apis"][0]["routers"] = json!(["nowhere"]);
    let refused = fleet_up.podgate.push_snapshot(&bad).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(
        keys(&fleet_up.list_as("acme", "?limit=100").await),
        keys(&list)
    );
}

// ---------------------------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn portal_serves_openapi_document() {
    let fleet_up = start().await;
    let answer = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/1/openapi")
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    assert_eq!(answer.header("content-type"), Some("application/json"));
    assert!(answer.body.len() < 1024 * 1024);
    let view = answer.json();
    assert_eq!(view["openapi"], "3.1.0");
    assert_eq!(view["info"]["title"], "ACMEMARK Pets API");
    assert_eq!(
        view["paths"]["/pets"]["get"]["summary"],
        "ACMEMARK list pets"
    );
    assert_eq!(
        view["components"]["securitySchemes"]["bearer"]["scheme"],
        "bearer"
    );
    // HEAD has the headers and no body.
    let head = fleet_up
        .send(
            "HEAD",
            &json!({"tenant": "acme"}),
            "/api/catalog/acme/pets/1/openapi",
            &[],
        )
        .await;
    assert_eq!(head.status, 200);
    assert_eq!(head.body, "");
    assert_eq!(
        head.header("content-length"),
        answer.header("content-length")
    );
}

#[tokio::test]
async fn portal_document_withholds_servers_and_examples() {
    let fleet_up = start().await;
    let answer = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/1/openapi")
        .await;
    for withheld in [
        "ACMEMARK-internal",
        "ACMEMARK-example-token",
        "ACMEMARK-extension",
        "servers",
        "x-owner",
        "\"example\"",
    ] {
        assert!(
            !answer.body.contains(withheld),
            "{withheld} is shown: {}",
            answer.body
        );
    }
    assert!(answer.body.contains("ACMEMARK-doc-description"));
}

#[tokio::test]
async fn portal_scrubs_credential_shapes() {
    let fleet_up = start().await;
    let answer = fleet_up
        .get_as("acme", "/api/catalog/acme/pets/1/openapi")
        .await;
    assert!(!answer.body.contains(&"q".repeat(30)), "{}", answer.body);
    assert!(!answer.body.contains("hunter2hunter2"), "{}", answer.body);
    assert!(answer.body.contains("Bearer [redacted]"), "{}", answer.body);
    assert!(
        answer.body.contains("app:[redacted]@db.internal"),
        "{}",
        answer.body
    );
}

#[tokio::test]
async fn portal_shows_deprecation() {
    let fleet_up = start().await;
    let list = fleet_up.list_as("acme", "?limit=100").await;
    let old = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "pets" && item["version"] == "0")
        .expect("pets 0");
    assert_eq!(old["lifecycle"], "deprecated");
    assert_eq!(old["sunset"], "2027-03-01");
    assert_eq!(old["successor"], json!({"id": "pets", "version": "1"}));
    let stable = list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == "pets" && item["version"] == "1")
        .expect("pets 1");
    assert_eq!(stable["lifecycle"], "stable");
    assert!(stable.get("sunset").is_none());
    assert_eq!(stable["openapi"]["operations"], 1);
    assert_eq!(stable["openapi"]["dialect"], "3.1");
    assert_eq!(stable["hosts"], json!(["pets.acme.test"]));
}

#[tokio::test]
async fn portal_hides_unpublished_successor() {
    let fleet_up = start().await;
    let list = fleet_up.list_as("acme", "?q=legacy").await;
    let legacy = &list["items"][0];
    assert_eq!(legacy["id"], "legacy");
    assert_eq!(legacy["sunset"], "2027-04-01");
    assert!(legacy.get("successor").is_none(), "{legacy}");
    assert!(!list.to_string().contains("hidden"), "{list}");
}

// ---------------------------------------------------------------------------------------------
// The page and the browser
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn portal_serves_assets_with_headers() {
    let fleet_up = start().await;
    for (path, content_type) in [
        ("/", "text/html; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/style.css", "text/css; charset=utf-8"),
    ] {
        let answer = fleet_up.get_as("acme", path).await;
        assert_eq!(answer.status, 200, "{path}: {answer:?}");
        assert_eq!(answer.header("content-type"), Some(content_type));
        assert_eq!(answer.header("cache-control"), Some("no-cache"));
        assert!(!answer.body.is_empty());
    }
    // The page is the file of `portal/`, byte for byte.
    let page = fleet_up.get_as("acme", "/").await;
    let file =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("portal/index.html"))
            .expect("the page");
    assert_eq!(page.body, file);
    // A logged-in person whose login names no tenant still gets the page.
    assert_eq!(fleet_up.send("GET", &json!({}), "/", &[]).await.status, 200);
}

#[tokio::test]
async fn portal_csp_on_every_response() {
    let fleet_up = start().await;
    let acme = json!({"tenant": "acme"});
    let none = json!({});
    let cases: Vec<(&str, Value, &str)> = vec![
        ("GET", acme.clone(), "/"),
        ("GET", acme.clone(), "/app.js"),
        ("GET", acme.clone(), "/style.css"),
        ("HEAD", acme.clone(), "/"),
        ("GET", acme.clone(), "/api/catalog"),
        ("GET", acme.clone(), "/api/catalog?tenant=x"),
        ("GET", acme.clone(), "/api/catalog/acme/pets/1/openapi"),
        ("GET", acme.clone(), "/api/catalog/acme/none/1/openapi"),
        ("GET", acme.clone(), "/nothing"),
        ("GET", none.clone(), "/api/catalog"),
        ("POST", acme.clone(), "/"),
        ("DELETE", acme.clone(), "/api/catalog"),
    ];
    for (method, claims, path) in cases {
        let answer = fleet_up.send(method, &claims, path, &[]).await;
        assert_eq!(
            answer.header("content-security-policy"),
            Some(CONTENT_SECURITY_POLICY_VALUE),
            "{method} {path}: {answer:?}"
        );
        assert!(CONTENT_SECURITY_POLICY_VALUE.contains("default-src 'none'"));
        assert!(CONTENT_SECURITY_POLICY_VALUE.contains("script-src 'self'"));
        assert!(CONTENT_SECURITY_POLICY_VALUE.contains("style-src 'self'"));
        assert!(CONTENT_SECURITY_POLICY_VALUE.contains("connect-src 'self'"));
        assert_eq!(
            answer.header("x-content-type-options"),
            Some("nosniff"),
            "{method} {path}"
        );
        assert_eq!(
            answer.header("referrer-policy"),
            Some("no-referrer"),
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn portal_renders_tenant_text_as_text() {
    let fleet_up = start().await;
    let list = fleet_up.get_as("acme", "/api/catalog?q=stable").await;
    assert_eq!(list.header("content-type"), Some("application/json"));
    assert_eq!(list.header("x-content-type-options"), Some("nosniff"));
    let item = &list.json()["items"][0];
    // The markup arrives as the data the tenant wrote, in a JSON string the browser never parses
    // as HTML; the page puts it in the page with `textContent`.
    assert_eq!(
        item["title"],
        "ACMEMARK Pets <script>alert('acme')</script>"
    );
    assert_eq!(
        item["description"],
        "<img src=x onerror=alert(1)> ACMEMARK stable"
    );
}

async fn assets(fleet_up: &Fleet) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for path in ["/", "/app.js", "/style.css"] {
        found.push((path.to_owned(), fleet_up.get_as("acme", path).await.body));
    }
    found
}

#[tokio::test]
async fn portal_no_inline_script() {
    let fleet_up = start().await;
    let page = fleet_up.get_as("acme", "/").await.body;
    let mut rest = page.as_str();
    while let Some(start) = rest.find("<script") {
        let tag_end = rest[start..].find('>').expect("a closed tag") + start;
        let tag = &rest[start..tag_end];
        assert!(tag.contains("src="), "an inline script: {tag}");
        let close = rest[tag_end..].find("</script>").expect("a closing tag") + tag_end;
        assert_eq!(
            rest[tag_end + 1..close].trim(),
            "",
            "script text in the page"
        );
        rest = &rest[close..];
    }
    for (path, body) in assets(&fleet_up).await {
        if path != "/style.css" {
            for handler in [
                " onclick=",
                " onload=",
                " onerror=",
                " onsubmit=",
                " onchange=",
                " style=",
                "javascript:",
            ] {
                assert!(
                    !body.to_lowercase().contains(handler),
                    "{path} has {handler}"
                );
            }
        }
    }
}

#[tokio::test]
async fn portal_no_external_references() {
    let fleet_up = start().await;
    for (path, body) in assets(&fleet_up).await {
        for scheme in ["http://", "https://", "//cdn", "@import", "url("] {
            assert!(!body.contains(scheme), "{path} names {scheme}");
        }
    }
}

#[tokio::test]
async fn portal_script_never_parses_html() {
    let fleet_up = start().await;
    let script = fleet_up.get_as("acme", "/app.js").await.body;
    for api in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "DOMParser",
        "createContextualFragment",
        "srcdoc",
        "setAttribute(\"on",
        "importScripts",
    ] {
        assert!(!script.contains(api), "the page script uses {api}");
    }
    assert!(script.contains("textContent") || script.contains("createTextNode"));
}

#[tokio::test]
async fn portal_methods_405() {
    let fleet_up = start().await;
    let acme = json!({"tenant": "acme"});
    for path in [
        "/",
        "/app.js",
        "/api/catalog",
        "/api/catalog/acme/pets/1/openapi",
    ] {
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let answer = fleet_up.send(method, &acme, path, &[]).await;
            assert_eq!(answer.status, 405, "{method} {path}: {answer:?}");
            assert_eq!(answer.header("allow"), Some("GET, HEAD"));
            assert_eq!(answer.body, r#"{"error":"method not allowed"}"#);
        }
        let head = fleet_up.send("HEAD", &acme, path, &[]).await;
        assert!(head.status == 200 || head.status == 404, "{path}: {head:?}");
    }
    // Another path is `404` whatever the method.
    for method in ["GET", "POST", "DELETE"] {
        assert_eq!(
            fleet_up.send(method, &acme, "/nothing", &[]).await.status,
            404,
            "{method}"
        );
    }
}

#[tokio::test]
async fn portal_admin_routes_are_404() {
    let fleet_up = start().await;
    for path in [
        "/v1/snapshot",
        "/v1/snapshot/plan",
        "/v1/events",
        "/v1/catalog",
        "/v1/overview",
        "/v1/explain?url=http://portal.test/",
        "/v1/apps/pets-app/failures",
        "/healthz",
        "/readyz",
        "/metrics",
        "/api/overview",
        "/api/explain",
        "/api/audit",
    ] {
        let answer = fleet_up.get_as("acme", path).await;
        assert_eq!(answer.status, 404, "{path}: {answer:?}");
        assert_eq!(answer.body, r#"{"error":"not found"}"#);
    }
}

#[tokio::test]
async fn portal_bounds_page_and_document() {
    let fleet_up = start().await;
    // An app with many published entries.
    let host = "bulk.acme.test";
    let mut bulk = app("bulk", &[host], &[serving("r1", fleet_up.upstream.addr)]);
    bulk["tenant"] = json!("acme");
    let count = 130;
    bulk["routers"] = Value::Array(
        (0..count)
            .map(|n| under(host, &format!("r{n}"), &format!("/b{n}")))
            .collect(),
    );
    bulk["apis"] = Value::Array(
        (0..count)
            .map(|n| {
                api(
                    &format!("bulk{n:03}"),
                    "1",
                    "stable",
                    &format!("r{n}"),
                    &json!({"published": true, "description": "d".repeat(2000)}),
                )
            })
            .collect(),
    );
    let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
    next["apps"].as_array_mut().expect("apps").push(bulk);
    let pushed = fleet_up.podgate.push_snapshot(&next).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");

    let default = fleet_up.list_as("acme", "").await;
    assert_eq!(default["items"].as_array().expect("items").len(), 25);
    assert_eq!(default["total"], 134);
    assert_eq!(default["truncated"], true);
    let big = fleet_up.get_as("acme", "/api/catalog?limit=100000").await;
    assert!(big.body.len() < 1024 * 1024, "{} bytes", big.body.len());
    let page = big.json();
    assert_eq!(page["items"].as_array().expect("items").len(), 100);
    let next_key = page["next"].as_str().expect("next").to_owned();
    let rest = fleet_up
        .list_as(
            "acme",
            &format!("?limit=100&after={}", next_key.replace('/', "%2F")),
        )
        .await;
    assert_eq!(rest["items"].as_array().expect("items").len(), 34);
    assert!(rest.get("truncated").is_none());
    // Bounded inputs.
    for query in [
        format!("?q={}", "a".repeat(65)),
        format!("?after={}%2F1", "a".repeat(600)),
        format!("?q=a&{}", "x".repeat(3000)),
    ] {
        assert_eq!(
            fleet_up
                .get_as("acme", &format!("/api/catalog{query}"))
                .await
                .status,
            400
        );
    }
}

#[tokio::test]
async fn portal_reads_catalog_only_through_access() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/middleware");
    let mut files = vec![root.join("portal.rs")];
    for entry in std::fs::read_dir(root.join("portal")).expect("the portal directory") {
        files.push(entry.expect("an entry").path());
    }
    for file in files {
        if file.file_name().and_then(|name| name.to_str()) == Some("access.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("a source file");
        // Only the code, not the tests that build a table to look at.
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        for call in [
            ".apis()",
            ".apps()",
            "catalog::Api",
            "catalog::{",
            "RoutingTable::apps",
        ] {
            assert!(
                !code
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .any(|line| line.contains(call)),
                "{} reads the catalog itself ({call})",
                file.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Nothing about a viewer is kept
// ---------------------------------------------------------------------------------------------

/// An upstream that answers every request `500`.
async fn failing_upstream() -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut chunk = [0_u8; 4096];
                drop(stream.read(&mut chunk).await);
                drop(
                    stream
                        .write_all(
                            b"HTTP/1.1 500 X\r\nContent-Length: 4\r\nConnection: close\r\n\r\nboom",
                        )
                        .await,
                );
            });
        }
    });
    addr
}

/// `GET /api/overview` of the dashboard at `addr`.
async fn dashboard_overview(addr: std::net::SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "GET /api/overview?limit=500 HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    String::from_utf8_lossy(&raw).into_owned()
}

#[tokio::test]
async fn portal_claims_never_recorded_or_logged() {
    let dir = std::env::temp_dir().join(format!("podgate-portal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let log = dir.join("access.log");
    drop(std::fs::remove_file(&log));
    let dashboard = common::free_ports(1)[0];
    let dashboard_addr = format!("127.0.0.1:{dashboard}");
    let signer = Signer::es256("idp-key");
    let pinned = pin(&signer);
    let podgate = Podgate::start_with_env(&[
        ("PORTAL_APPS", pinned.as_str()),
        ("ACCESS_LOG_FILE", log.to_str().expect("utf-8")),
        ("DASHBOARD_ADDR", dashboard_addr.as_str()),
    ])
    .await;
    let upstream = Upstream::start("ok").await;
    let bad = failing_upstream().await;

    // The operator's app: the portal on `/`, and a route behind the same login whose upstream
    // fails, so the failure recorder sees a request that carried the token.
    let mut ops = app("portal", &[HOST], &[serving("r1", upstream.addr)]);
    ops["tenant"] = json!("ops");
    ops["middlewares"] = json!([
        {"name": "jwt", "type": "jwt_auth", "keys": keys_of(&signer),
         "algorithms": ["ES256"], "issuer": ISSUER},
        {"name": "portal", "type": "portal"},
    ]);
    ops["revisions"][0]["services"]
        .as_array_mut()
        .expect("services")
        .push(common::service("bad", &[bad]));
    ops["routers"] = json!([
        {"name": "default", "match": {"host": [HOST]}, "service": "web", "chain": ["jwt", "portal"]},
        {"name": "boom", "match": {"all": [{"host": HOST}, {"path_prefix": "/boom"}]},
         "service": "bad", "chain": ["jwt"]},
    ]);
    let mut pushed = fleet(1, &signer, &upstream);
    pushed["apps"][0] = ops;
    pushed["observability"] = json!({"access_log": {"headers": {"default": "keep"}}});
    let accepted = podgate.push_snapshot(&pushed).await;
    assert_eq!(accepted.status, 200, "{accepted:?}");

    let planted_email = "planted-email-claim-5c1";
    let planted_group = "planted-group-claim-9d2";
    let mut all = json!({"sub": "ann", "iss": ISSUER, "exp": now() + 600});
    all["tenant"] = json!("acme");
    all["email"] = json!(planted_email);
    all["groups"] = json!([planted_group]);
    let token = signer.sign("ES256", &json!({}), &all);
    let signature = token.rsplit('.').next().expect("a signature").to_owned();
    let bearer = format!("Bearer {token}");
    let headers = [("Authorization", bearer.as_str())];

    let viewed = podgate.request("GET", HOST, "/api/catalog", &headers).await;
    assert_eq!(viewed.status, 200, "{viewed:?}");
    let failed = podgate.request("GET", HOST, "/boom", &headers).await;
    assert_eq!(failed.status, 500, "{failed:?}");

    // Everything an operator or a control plane can read.
    let mut shown = vec![
        podgate.admin_get("/v1/overview?limit=500").await.body,
        podgate.admin_get("/v1/apps/portal/failures").await.body,
        podgate
            .admin_get(&format!("/v1/explain?url=http://{HOST}/api/catalog"))
            .await
            .body,
        podgate.admin_get("/v1/catalog").await.body,
        podgate.admin_get("/metrics").await.body,
        dashboard_overview(dashboard.into_addr()).await,
    ];
    let mut next = fleet(2, &signer, &upstream);
    next["apps"][0] = pushed["apps"][0].clone();
    shown.push(podgate.admin_post("/v1/snapshot/plan", &next).await.body);
    let mut text = String::new();
    for _ in 0..100 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.lines().count() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        text.lines().count() >= 2,
        "the access log has no lines: {text:?}"
    );
    shown.push(text);
    shown.push(podgate.log());
    let failures = shown[1].clone();
    assert!(
        failures.contains("/boom"),
        "the failure was recorded: {failures}"
    );
    for (at, body) in shown.iter().enumerate() {
        for secret in [
            planted_email,
            planted_group,
            token.as_str(),
            signature.as_str(),
        ] {
            assert!(!body.contains(secret), "source {at} shows {secret}: {body}");
        }
    }
    drop(std::fs::remove_dir_all(&dir));
}

trait IntoAddr {
    fn into_addr(self) -> std::net::SocketAddr;
}

impl IntoAddr for u16 {
    fn into_addr(self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self))
    }
}

#[tokio::test]
async fn portal_overview_and_schema_show_settings_only() {
    let fleet_up = start().await;
    let overview = fleet_up
        .podgate
        .admin_get("/v1/overview?limit=500")
        .await
        .body;
    assert!(overview.contains("tenant_claim"), "{overview}");
    let explain = fleet_up
        .podgate
        .admin_get(&format!("/v1/explain?url=http://{HOST}/api/catalog"))
        .await
        .body;
    assert!(explain.contains("tenant_claim"), "{explain}");
    // The pin is the environment's, and nothing here shows it.
    let print = fingerprint(&keys_of(&fleet_up.signer)).expect("a fingerprint");
    for body in [&overview, &explain] {
        assert!(!body.contains(&print), "the pin's key fingerprint is shown");
    }
    // The schema of the kind has its own setting and nothing else.
    let schema = fleet_up.podgate.admin_get("/v1/schema").await.json();
    let portal = &schema["$defs"]["middleware.portal"];
    assert!(portal.is_object(), "no schema for the portal kind");
    let properties = portal["properties"].as_object().expect("properties");
    let mut names: Vec<&str> = properties.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["name", "tenant_claim", "type"]);
}

#[tokio::test]
async fn portal_rule_names_only_the_asking_app() {
    let fleet_up = start().await;
    // Near misses of the listed `ops/portal`: each declares the portal behind the pinned login
    // itself, and each is refused, because only the listed pair may.
    for (tenant_id, app_id) in [
        ("ops", "portal2"),
        ("ops", "Portal"),
        ("ops", "portal "),
        ("ops2", "portal"),
        ("OPS", "portal"),
        ("ops/portal", "x"),
        ("ops", "portal/x"),
        ("ops=x", "portal"),
    ] {
        let mut lookalike = operator_app(&fleet_up.signer, &fleet_up.upstream);
        lookalike["id"] = json!(app_id);
        lookalike["tenant"] = json!(tenant_id);
        lookalike["routers"][0]["match"] = json!({"host": ["lookalike.test"]});
        let mut next = fleet(2, &fleet_up.signer, &fleet_up.upstream);
        if tenant_id != "ops" {
            next["tenants"]
                .as_array_mut()
                .expect("tenants")
                .push(tenant(tenant_id));
        }
        next["apps"].as_array_mut().expect("apps").push(lookalike);
        let answer = fleet_up.podgate.push_snapshot(&next).await;
        assert_eq!(answer.status, 422, "{tenant_id}/{app_id}: {answer:?}");
        let codes: Vec<String> = answer.json()["conflicts"]
            .as_array()
            .expect("conflicts")
            .iter()
            .map(|conflict| conflict["code"].as_str().unwrap_or_default().to_owned())
            .collect();
        assert!(
            codes.iter().any(|code| code == "portal_not_allowed")
                || codes.iter().any(|code| code.starts_with("invalid_")),
            "{tenant_id}/{app_id}: {codes:?}"
        );
        assert!(
            !codes.iter().any(|code| code == "portal_login_not_pinned"),
            "an unlisted app is refused as unlisted, before its login is judged"
        );
    }
}

/// Every kind that puts claims into the request state must say how it verifies (`Kind::login`),
/// or the portal would trust claims no pin covers.
#[tokio::test]
async fn portal_claims_writers_report_login() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/middleware");
    let mut writers = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("a directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source file");
                let code = text
                    .split("#[cfg(test)]\nmod test")
                    .next()
                    .unwrap_or_default();
                if code.contains("claims = Some(") {
                    assert!(
                        code.contains("fn login(") || path.ends_with("middleware.rs"),
                        "{} sets claims and does not implement `login`",
                        path.display()
                    );
                    writers.push(path);
                }
            }
        }
    }
    assert!(
        writers.iter().any(|path| path.ends_with("jwt_auth.rs"))
            && writers.iter().any(|path| path.ends_with("oidc.rs")),
        "the guard found no writer: {writers:?}"
    );
}
