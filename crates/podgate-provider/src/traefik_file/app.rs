//! One Traefik file to one app: the sections in dependency order, then the routers, then the TLS
//! options the app can have.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::middleware::{self, Sinks};
use super::names::{Names, valid_name};
use super::obj::{Cx, Obj};
use super::router::{self, Built};
use super::tls::{self, Tls};
use super::{Converted, l4, service, transport};

/// The sections of one protocol.
#[derive(Default)]
struct Section<'a> {
    routers: Vec<(&'a str, &'a Value)>,
    services: Vec<(&'a str, &'a Value)>,
    middlewares: Vec<(&'a str, &'a Value)>,
    transports: Vec<(&'a str, &'a Value)>,
}

fn section<'a>(obj: &mut Obj<'a>, protocol: &str) -> Section<'a> {
    let Some(mut part) = obj.child(protocol) else {
        return Section::default();
    };
    let found = Section {
        routers: part.named("routers"),
        services: part.named("services"),
        middlewares: part.named("middlewares"),
        transports: part.named("serversTransports"),
    };
    part.finish();
    found
}

/// Builds the transports of one protocol, with names unique across protocols.
fn transports(
    cx: &Cx,
    protocol: &str,
    group: Vec<(&str, &Value)>,
    taken: &mut BTreeSet<String>,
    out: &mut Vec<Declared>,
) -> Names {
    let mut names = Names::default();
    for (name, value) in group {
        let at = format!("{protocol}.serversTransports.{name}");
        if !valid_name(cx, &at, name) {
            continue;
        }
        names.expect(name);
        let built = if taken.contains(name) {
            cx.invalid(
                &at,
                "has the name of another serversTransport, and podgate's transports share one namespace; rename one",
            );
            None
        } else if protocol == "http" {
            transport::http(cx, name, value)
        } else {
            transport::tcp(cx, name, value)
        };
        taken.insert(name.to_owned());
        names.settle(name, built.is_some());
        out.extend(built);
    }
    names
}

pub(super) fn convert(id: &str, root: &Value, dir: Option<&Path>) -> Converted {
    let cx = Cx::new(dir.map(Path::to_owned));
    let mut certificates = Vec::new();
    let mut app = Map::new();
    if let Some(mut top) = Obj::new(&cx, String::new(), root) {
        let tls = tls::build(&cx, top.value("tls"));
        let http = section(&mut top, "http");
        let tcp = section(&mut top, "tcp");
        let mut udp = top.child("udp");
        let udp_routers = udp
            .as_mut()
            .map(|udp| udp.named("routers"))
            .unwrap_or_default();
        let udp_services = udp
            .as_mut()
            .map(|udp| udp.named("services"))
            .unwrap_or_default();
        if let Some(udp) = udp {
            udp.finish();
        }
        top.finish();
        app = assemble(&cx, id, &tls, http, tcp, udp_routers, udp_services);
        certificates = tls.certificates;
    }
    let (problems, files) = cx.finish();
    Converted {
        app: Value::Object(app),
        certificates,
        problems,
        files,
    }
}

fn assemble(
    cx: &Cx,
    id: &str,
    tls: &Tls,
    http: Section<'_>,
    tcp: Section<'_>,
    udp_routers: Vec<(&str, &Value)>,
    udp_services: Vec<(&str, &Value)>,
) -> Map<String, Value> {
    let mut taken = BTreeSet::new();
    let mut transports_out = Vec::new();
    let http_transports = transports(cx, "http", http.transports, &mut taken, &mut transports_out);
    let tcp_transports = transports(cx, "tcp", tcp.transports, &mut taken, &mut transports_out);

    let mut services_out = Vec::new();
    let http_services = service::build(cx, http.services, &http_transports, &mut services_out);
    let mut middlewares_out = Vec::new();
    let http_middlewares = middleware::build_http(
        cx,
        http.middlewares,
        &http_services,
        &mut Sinks {
            middlewares: &mut middlewares_out,
            transports: &mut transports_out,
            taken: &mut taken,
        },
    );
    let mut tcp_services_out = Vec::new();
    let tcp_services = l4::build(
        cx,
        l4::Proto::Tcp,
        tcp.services,
        &tcp_transports,
        &mut tcp_services_out,
    );
    let mut tcp_middlewares_out = Vec::new();
    let tcp_middlewares = middleware::build_tcp(cx, tcp.middlewares, &mut tcp_middlewares_out);
    let mut udp_services_out = Vec::new();
    let udp_names = l4::build(
        cx,
        l4::Proto::Udp,
        udp_services,
        &Names::default(),
        &mut udp_services_out,
    );

    let mut http_routers: Vec<Built> = http
        .routers
        .into_iter()
        .filter_map(|(name, value)| {
            router::http(cx, name, value, &http_services, &http_middlewares)
        })
        .collect();
    let mut tcp_routers: Vec<Built> = tcp
        .routers
        .into_iter()
        .filter_map(|(name, value)| router::tcp(cx, name, value, &tcp_services, &tcp_middlewares))
        .collect();
    let udp_routers_out: Vec<Value> = udp_routers
        .into_iter()
        .filter_map(|(name, value)| router::udp(cx, name, value, &udp_names))
        .collect();

    let policy = choose_options(cx, tls, &mut http_routers, &mut tcp_routers);
    let mut tls_object = Map::new();
    tls_object.insert("mode".into(), json!("acme"));
    tls_object.extend(policy);

    let mut app = Map::new();
    app.insert("id".into(), json!(id));
    app.insert("tls".into(), Value::Object(tls_object));
    app.insert(
        "routers".into(),
        Value::Array(http_routers.into_iter().map(|built| built.json).collect()),
    );
    app.insert("middlewares".into(), json!(middlewares_out));
    app.insert("services".into(), json!(services_out));
    app.insert("transports".into(), json!(transports_out));
    app.insert(
        "revisions".into(),
        json!([{ "id": "file", "state": "serving", "weight": 1 }]),
    );
    if !(tcp_routers.is_empty() && tcp_services_out.is_empty() && tcp_middlewares_out.is_empty()) {
        app.insert(
            "tcp".into(),
            json!({
                "routers": tcp_routers.into_iter().map(|built| built.json).collect::<Vec<_>>(),
                "services": tcp_services_out,
                "middlewares": tcp_middlewares_out,
            }),
        );
    }
    if !(udp_routers_out.is_empty() && udp_services_out.is_empty()) {
        app.insert(
            "udp".into(),
            json!({ "routers": udp_routers_out, "services": udp_services_out }),
        );
    }
    app
}

/// The TLS options of the app. They are the app's, not the router's: the handshake runs before
/// any router is known (`docs/ref/tls-options.md`). The options that most routers use are
/// applied, and a router that asks for others is left out, never served under the wrong ones.
fn choose_options(
    cx: &Cx,
    tls: &Tls,
    http: &mut Vec<Built>,
    tcp: &mut Vec<Built>,
) -> Map<String, Value> {
    // The option every router gets: the one it names, else `default`, when there is one.
    let effective = |built: &Built| -> Option<Option<String>> {
        let used = built.tls.as_ref()?;
        Some(used.options.clone().or_else(|| {
            tls.options
                .contains_key("default")
                .then(|| "default".to_owned())
        }))
    };
    let mut votes: BTreeMap<Option<String>, usize> = BTreeMap::new();
    for built in http.iter().chain(tcp.iter()) {
        if let Some(option) = effective(built) {
            *votes.entry(option).or_default() += 1;
        }
    }
    // Most routers win; a tie goes to the one that sorts first, `None` before any name.
    let chosen: Option<String> = votes
        .iter()
        .max_by(|(left_name, left), (right_name, right)| {
            left.cmp(right).then_with(|| right_name.cmp(left_name))
        })
        .and_then(|(name, _)| name.clone());
    let policy = chosen
        .as_ref()
        .and_then(|name| tls.options.get(name))
        .cloned()
        .flatten()
        .unwrap_or_default();
    for (protocol, routers) in [("http", http), ("tcp", tcp)] {
        routers.retain(|built| {
            let Some(option) = effective(built) else {
                return true;
            };
            let at = format!("{protocol}.routers.{}.tls.options", built.name);
            if let Some(name) = &option {
                match tls.options.get(name) {
                    None => {
                        cx.invalid(&at, format!("names no TLS option of this file: {name:?}"));
                        return false;
                    }
                    Some(None) => {
                        cx.unsupported(
                            &at,
                            format!("the TLS option {name:?} was not translated, see its own problems"),
                        );
                        return false;
                    }
                    Some(Some(_)) => {}
                }
            }
            if option == chosen {
                return true;
            }
            cx.unsupported(
                &at,
                format!(
                    "podgate applies one TLS policy per app, and this app's is {}; put the routers with other TLS options in a file of their own",
                    chosen.as_deref().map_or("the listener's".to_owned(), |name| format!("{name:?}")),
                ),
            );
            false
        });
    }
    policy
}
