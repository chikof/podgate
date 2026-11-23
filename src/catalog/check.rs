//! The rules for the `apis` of a snapshot, checked before any router compiles.
//!
//! `apis` is tenant-supplied, so everything is bounded and nothing is merged: an entry that
//! contradicts another or names something that is not there rejects the snapshot with a stable
//! code, and the `422` names the app, its `declared_by` and the entry.

use std::collections::HashMap;

use super::Sunset;
use crate::compile::{Invalid, Rejected};
use podgate_model::{Api, App, Lifecycle, Snapshot};

/// Most entries one app declares.
const MAX_PER_APP: usize = 256;
/// Longest `id`, in bytes.
const MAX_ID: usize = 128;
/// Longest `version`, in bytes.
const MAX_VERSION: usize = 64;
/// Longest `title`, in bytes.
const MAX_TITLE: usize = 256;
/// Longest `description`, in bytes.
const MAX_DESCRIPTION: usize = 2048;
/// Most routers one entry names.
const MAX_ROUTERS: usize = 64;

fn invalid_api(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_api", message)
}

fn invalid_sunset(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_sunset", message)
}

/// The identity of an entry: its tenant, id and version.
type Key<'a> = (&'a str, &'a str, &'a str);

fn key<'a>(app: &'a App, api: &'a Api) -> Key<'a> {
    (&*app.tenant, &*api.id, &*api.version)
}

/// Checks the `apis` of every app of `snapshot`; every problem is listed.
pub(crate) fn check(snapshot: &Snapshot) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    let mut owners: HashMap<Key<'_>, &App> = HashMap::new();
    for app in &snapshot.apps {
        if app.apis.len() > MAX_PER_APP {
            rejected.push(Rejected::new(
                app,
                "apis",
                invalid_api(format!("an app declares at most {MAX_PER_APP} apis")),
            ));
        }
        for api in &app.apis {
            if let Some(first) = owners.insert(key(app, api), app) {
                rejected.push(Rejected::new(
                    app,
                    at(api),
                    Invalid::new(
                        "duplicate_api_version",
                        format!(
                            "api {}@{} of tenant {} is also declared by app {} ({})",
                            api.id, api.version, app.tenant, first.id, first.declared_by
                        ),
                    ),
                ));
            }
        }
    }
    for app in &snapshot.apps {
        let mut named: HashMap<&str, &Api> = HashMap::new();
        for api in &app.apis {
            for problem in entry(app, api, &owners, &mut named) {
                rejected.push(Rejected::new(app, at(api), problem));
            }
        }
    }
    rejected
}

fn at(api: &Api) -> String {
    format!("api {}@{}", api.id, api.version)
}

/// Every problem of one entry. `named` maps the routers the app's earlier entries name to the
/// entry that names them.
fn entry<'a>(
    app: &'a App,
    api: &'a Api,
    owners: &HashMap<Key<'_>, &App>,
    named: &mut HashMap<&'a str, &'a Api>,
) -> Vec<Invalid> {
    let mut problems = Vec::new();
    if let Some(problem) = text(&api.id, "id", MAX_ID, b"._-") {
        problems.push(problem);
    }
    if let Some(problem) = text(&api.version, "version", MAX_VERSION, b"._+-") {
        problems.push(problem);
    }
    for (field, value, max) in [
        ("title", &api.title, MAX_TITLE),
        ("description", &api.description, MAX_DESCRIPTION),
    ] {
        if value.as_deref().is_some_and(|text| text.len() > max) {
            problems.push(invalid_api(format!("{field} is at most {max} bytes")));
        }
    }
    if api.routers.is_empty() || api.routers.len() > MAX_ROUTERS {
        problems.push(invalid_api(format!(
            "an api names 1 to {MAX_ROUTERS} routers, so the catalog never says more than the routers do"
        )));
    }
    for name in &api.routers {
        if !app.routers.iter().any(|router| router.name == *name) {
            problems.push(Invalid::new(
                "unknown_router",
                format!("router {name} is not a router of app {}", app.id),
            ));
        } else if let Some(first) = named.insert(&**name, api) {
            problems.push(Invalid::new(
                "router_in_two_apis",
                format!(
                    "router {name} is named by api {}@{} and by api {}@{}; a router has one lifecycle",
                    first.id, first.version, api.id, api.version
                ),
            ));
        }
    }
    if let Some(name) = &api.openapi
        && !app
            .middlewares
            .iter()
            .any(|declared| declared.name == *name && &*declared.kind == "openapi")
    {
        problems.push(Invalid::new(
            "unknown_openapi",
            format!("{name} is not an openapi middleware of app {}", app.id),
        ));
    }
    sunset(api, &mut problems);
    successor(app, api, owners, &mut problems);
    problems
}

/// 1 to `max` bytes of ASCII letters, digits and `extra`.
fn text(value: &str, field: &str, max: usize, extra: &[u8]) -> Option<Invalid> {
    let fits = (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b));
    (!fits).then(|| {
        let extra: String = extra
            .iter()
            .map(|b| format!(" {}", char::from(*b)))
            .collect();
        invalid_api(format!("{field} is 1 to {max} bytes of A-Z a-z 0-9{extra}"))
    })
}

fn sunset(api: &Api, problems: &mut Vec<Invalid>) {
    match (api.lifecycle, api.sunset.as_deref()) {
        (Lifecycle::Deprecated, None) => problems.push(invalid_sunset(
            "a deprecated api has a sunset day, YYYY-MM-DD, so clients know when it ends",
        )),
        (Lifecycle::Draft | Lifecycle::Preview | Lifecycle::Stable, Some(_)) => {
            problems.push(invalid_sunset(format!(
                "a {} api has no sunset: only deprecated and retired apis do",
                api.lifecycle.name()
            )));
        }
        (_, Some(day)) => {
            if let Err(message) = Sunset::parse(day) {
                problems.push(invalid_sunset(message));
            }
        }
        (_, None) => {}
    }
}

fn successor(app: &App, api: &Api, owners: &HashMap<Key<'_>, &App>, problems: &mut Vec<Invalid>) {
    let Some(successor) = &api.successor else {
        return;
    };
    if !matches!(api.lifecycle, Lifecycle::Deprecated | Lifecycle::Retired) {
        problems.push(invalid_api(format!(
            "a {} api has no successor: only deprecated and retired apis do",
            api.lifecycle.name()
        )));
    } else if successor.id == api.id && successor.version == api.version {
        problems.push(invalid_api("an api cannot be its own successor"));
    } else if !owners.contains_key(&(&*app.tenant, &*successor.id, &*successor.version)) {
        problems.push(Invalid::new(
            "unknown_successor",
            format!(
                "successor {}@{} is not an api of tenant {}",
                successor.id, successor.version, app.tenant
            ),
        ));
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::table::{CompileError, RoutingTable};

    fn app(id: &str, apis: Value, extra: Value) -> Value {
        let mut app = json!({
            "id": id, "tenant": "t", "declared_by": format!("source of {id}"),
            "tls": {"mode": "acme"},
            "routers": [
                {"name": "r1", "match": {"host": format!("{id}.test")}, "service": "web"},
                {"name": "r2", "match": {"host": format!("{id}-two.test")}, "service": "web"},
            ],
            "revisions": [{"id": "r1", "weight": 1, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9"}]}]}],
            "apis": apis,
        });
        if let (Some(object), Some(extra)) = (app.as_object_mut(), extra.as_object()) {
            object.extend(extra.clone());
        }
        app
    }

    fn snapshot(apps: &[Value]) -> Value {
        json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": apps,
        })
    }

    fn api(id: &str, version: &str, lifecycle: &str, extra: &Value) -> Value {
        let mut api =
            json!({"id": id, "version": version, "lifecycle": lifecycle, "routers": ["r1"]});
        if let (Some(object), Some(extra)) = (api.as_object_mut(), extra.as_object()) {
            object.extend(extra.clone());
        }
        api
    }

    /// The codes of every problem of `apps`, `Ok` when it compiles.
    fn codes(apps: &[Value]) -> Result<(), Vec<&'static str>> {
        let snapshot = serde_json::from_value(snapshot(apps)).expect("a snapshot");
        match RoutingTable::compile(&snapshot) {
            Ok(_) => Ok(()),
            Err(CompileError::Rejected(list)) => Err(list.iter().map(Rejected::code).collect()),
            Err(other) => panic!("not a rejection: {other}"),
        }
    }

    #[test]
    fn valid_entries_compile() {
        let apps = [app(
            "a",
            json!([
                api(
                    "pets",
                    "1",
                    "deprecated",
                    &json!({
                        "sunset": "2027-03-01", "successor": {"id": "pets", "version": "2"},
                    })
                ),
                api(
                    "pets",
                    "2",
                    "stable",
                    &json!({"routers": ["r2"], "published": true})
                ),
            ]),
            json!({}),
        )];
        assert_eq!(codes(&apps), Ok(()));
    }

    #[test]
    fn catalog_duplicate_version() {
        let twice = app(
            "a",
            json!([
                api("pets", "1", "stable", &json!({})),
                api("pets", "1", "preview", &json!({"routers": ["r2"]})),
            ]),
            json!({}),
        );
        assert_eq!(codes(&[twice]), Err(vec!["duplicate_api_version"]));
        let across = [
            app(
                "a",
                json!([api("pets", "1", "stable", &json!({}))]),
                json!({}),
            ),
            app(
                "b",
                json!([api("pets", "1", "stable", &json!({}))]),
                json!({}),
            ),
        ];
        assert_eq!(codes(&across), Err(vec!["duplicate_api_version"]));
    }

    #[test]
    fn catalog_unknown_router() {
        let apps = [app(
            "a",
            json!([api("pets", "1", "stable", &json!({"routers": ["nope"]}))]),
            json!({}),
        )];
        assert_eq!(codes(&apps), Err(vec!["unknown_router"]));
    }

    #[test]
    fn catalog_unknown_successor() {
        let apps = [app(
            "a",
            json!([api(
                "pets",
                "1",
                "retired",
                &json!({"successor": {"id": "pets", "version": "9"}})
            )]),
            json!({}),
        )];
        assert_eq!(codes(&apps), Err(vec!["unknown_successor"]));
        let own = [app(
            "a",
            json!([api(
                "pets",
                "1",
                "retired",
                &json!({"successor": {"id": "pets", "version": "1"}})
            )]),
            json!({}),
        )];
        assert_eq!(codes(&own), Err(vec!["invalid_api"]));
    }

    #[test]
    fn catalog_deprecated_needs_sunset() {
        let apps = [app(
            "a",
            json!([api("pets", "1", "deprecated", &json!({}))]),
            json!({}),
        )];
        assert_eq!(codes(&apps), Err(vec!["invalid_sunset"]));
        let early = [app(
            "a",
            json!([api("pets", "1", "stable", &json!({"sunset": "2027-03-01"}))]),
            json!({}),
        )];
        assert_eq!(codes(&early), Err(vec!["invalid_sunset"]));
        let retired = [app(
            "a",
            json!([api(
                "pets",
                "1",
                "retired",
                &json!({"sunset": "2027-03-01"})
            )]),
            json!({}),
        )];
        assert_eq!(codes(&retired), Ok(()));
    }

    #[test]
    fn catalog_bad_sunset_date() {
        for day in ["2027-02-30", "soon", "2027-3-1", "1960-01-01"] {
            let apps = [app(
                "a",
                json!([api("pets", "1", "deprecated", &json!({"sunset": day}))]),
                json!({}),
            )];
            assert_eq!(codes(&apps), Err(vec!["invalid_sunset"]), "{day}");
        }
    }

    #[test]
    fn catalog_unknown_openapi() {
        let named = |kind: &str| {
            app(
                "a",
                json!([api("pets", "1", "stable", &json!({"openapi": "spec"}))]),
                json!({"middlewares": [{"name": "spec", "type": kind, "status": 200}]}),
            )
        };
        assert_eq!(codes(&[named("respond")]), Err(vec!["unknown_openapi"]));
        let missing = app(
            "a",
            json!([api("pets", "1", "stable", &json!({"openapi": "spec"}))]),
            json!({}),
        );
        assert_eq!(codes(&[missing]), Err(vec!["unknown_openapi"]));
    }

    #[test]
    fn catalog_router_in_two_apis() {
        let apps = [app(
            "a",
            json!([
                api("pets", "1", "stable", &json!({})),
                api("pets", "2", "stable", &json!({})),
            ]),
            json!({}),
        )];
        assert_eq!(codes(&apps), Err(vec!["router_in_two_apis"]));
        let twice = [app(
            "a",
            json!([api(
                "pets",
                "1",
                "stable",
                &json!({"routers": ["r1", "r1"]})
            )]),
            json!({}),
        )];
        assert_eq!(codes(&twice), Err(vec!["router_in_two_apis"]));
    }

    #[test]
    fn catalog_entries_are_bounded() {
        let long = "x".repeat(MAX_ID + 1);
        for entry in [
            api(&long, "1", "stable", &json!({})),
            api("a/b", "1", "stable", &json!({})),
            api("pets", "", "stable", &json!({})),
            api("pets", "1", "stable", &json!({"routers": []})),
            api(
                "pets",
                "1",
                "stable",
                &json!({"title": "t".repeat(MAX_TITLE + 1)}),
            ),
            api(
                "pets",
                "1",
                "draft",
                &json!({"successor": {"id": "x", "version": "1"}}),
            ),
        ] {
            let apps = [app("a", json!([entry.clone()]), json!({}))];
            assert_eq!(codes(&apps), Err(vec!["invalid_api"]), "{entry}");
        }
    }

    #[test]
    fn a_misspelt_field_is_refused() {
        let snapshot = snapshot(&[app(
            "a",
            json!([{"id": "pets", "version": "1", "lifecycle": "retired", "state": "x", "routers": ["r1"]}]),
            json!({}),
        )]);
        assert!(serde_json::from_value::<Snapshot>(snapshot).is_err());
    }
}
