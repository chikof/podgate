//! `tcp.services` and `udp.services`: load balancers over `host:port` servers
//! (`docs/ref/l4-tcp.md`, `docs/ref/l4-udp.md`).

use podgate_model::Declared;
use serde_json::{Map, Value, json};

use super::files::{self, Unit};
use super::names::{Names, Resolved, valid_name};
use super::obj::{Cx, Obj};

/// The most a termination delay can be in podgate: a day.
const MAX_TERMINATION_MS: u64 = 86_400_000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Builds the services of `tcp.services` or `udp.services`. `transports` are the app's.
pub(super) fn build(
    cx: &Cx,
    proto: Proto,
    group: Vec<(&str, &Value)>,
    transports: &Names,
    out: &mut Vec<Declared>,
) -> Names {
    let mut names = Names::default();
    for (name, value) in group {
        let path = format!("{}.services.{name}", proto.name());
        if !valid_name(cx, &path, name) {
            continue;
        }
        names.expect(name);
        let built =
            Obj::new(cx, path, value).and_then(|obj| service(cx, name, obj, proto, transports));
        names.settle(name, built.is_some());
        out.extend(built);
    }
    names
}

fn service(
    cx: &Cx,
    name: &str,
    mut obj: Obj<'_>,
    proto: Proto,
    transports: &Names,
) -> Option<Declared> {
    let mark = cx.mark();
    if obj.has("weighted") {
        obj.refuse(
            "weighted",
            "podgate's TCP and UDP services are load balancers; weighted services choose among HTTP services",
        );
    }
    let mut config = Map::new();
    if let Some(mut lb) = obj.child("loadBalancer") {
        load_balancer(&mut lb, proto, transports, &mut config);
        lb.finish();
    } else if !obj.has("weighted") {
        obj.invalid("loadBalancer", "is required");
    }
    obj.finish();
    cx.clean_since(mark).then(|| Declared {
        name: name.into(),
        kind: "loadbalancer".into(),
        config,
    })
}

fn load_balancer(
    lb: &mut Obj<'_>,
    proto: Proto,
    transports: &Names,
    config: &mut Map<String, Value>,
) {
    let mut servers = Vec::new();
    if let Some(list) = lb.children("servers") {
        for mut server in list {
            let address = server.text("address").map(str::to_owned);
            if address.is_none() && !server.has("address") {
                server.invalid("address", "is required");
            }
            let secure = match proto {
                Proto::Tcp => server.boolean("tls"),
                Proto::Udp => None,
            };
            server.finish();
            if let Some(address) = address {
                let mut entry = Map::new();
                entry.insert("address".into(), json!(address));
                if let Some(secure) = secure {
                    entry.insert("tls".into(), json!(secure));
                }
                servers.push(Value::Object(entry));
            }
        }
    }
    config.insert("servers".into(), Value::Array(servers));
    if proto == Proto::Udp {
        return;
    }
    let at = lb.path_of("serversTransport");
    if let Some(raw) = lb.text("serversTransport")
        && let Resolved::Found(found) = transports.resolve(lb.cx(), &at, raw, "serversTransport")
    {
        config.insert("transport".into(), json!(found));
    }
    if let Some(mut proxy) = lb.child("proxyProtocol") {
        match proxy.number::<u8>("version") {
            Some(version @ (1 | 2)) => {
                config.insert("proxy_protocol".into(), json!({ "version": version }));
            }
            Some(_) => proxy.invalid("version", "must be 1 or 2"),
            None if !proxy.has("version") => proxy.invalid("version", "is required"),
            None => {}
        }
        proxy.finish();
    }
    if let Some(millis) = files::duration(lb, "terminationDelay", Unit::Millis) {
        if millis > MAX_TERMINATION_MS {
            lb.invalid("terminationDelay", "is longer than a day");
        } else {
            config.insert("termination_delay_ms".into(), json!(millis));
        }
    }
}
