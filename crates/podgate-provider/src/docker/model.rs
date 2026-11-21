//! The parts of the Docker Engine API that the source reads, and the shapes Podman's compatible
//! API changes.
//!
//! Every field is optional: Podman omits or nulls fields Docker always sends (a container
//! without a health check has no `Health`, `Labels` can be `null`, names carry no leading
//! slash), and a field the source does not read is never an error.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Deserialize;

/// One entry of `GET /containers/json`: only the id is used, everything else comes from the
/// inspect of that id.
#[derive(Debug, Deserialize)]
pub(super) struct Listed {
    #[serde(rename = "Id")]
    pub(super) id: String,
}

/// One entry of `GET /networks`.
#[derive(Debug, Deserialize)]
pub(super) struct NetworkName {
    #[serde(rename = "Name")]
    pub(super) name: String,
}

/// `GET /containers/<id>/json`.
#[derive(Debug, Deserialize)]
pub(super) struct Inspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Created", default)]
    created: String,
    #[serde(rename = "State", default)]
    state: State,
    #[serde(rename = "Config", default)]
    config: Config,
    #[serde(rename = "NetworkSettings", default)]
    network_settings: NetworkSettings,
}

#[derive(Debug, Default, Deserialize)]
struct State {
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Restarting", default)]
    restarting: bool,
    #[serde(rename = "Health", default)]
    health: Option<Health>,
}

#[derive(Debug, Default, Deserialize)]
struct Health {
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(rename = "Healthcheck", default)]
    healthcheck: Option<Healthcheck>,
}

#[derive(Debug, Default, Deserialize)]
struct Healthcheck {
    #[serde(rename = "Test", default)]
    test: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: Option<BTreeMap<String, Endpoint>>,
}

#[derive(Debug, Default, Deserialize)]
struct Endpoint {
    #[serde(rename = "IPAddress", default)]
    ip_address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    global_ipv6_address: String,
}

/// Whether a container may serve traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Readiness {
    /// Running, and healthy when it has a health check.
    Serving,
    /// Anything else: created, paused, restarting, exited, or not yet healthy.
    NotServing,
}

/// A container as the source needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Container {
    /// The full id.
    pub(super) id: Box<str>,
    /// The name without the leading slash Docker adds.
    pub(super) name: Box<str>,
    /// Creation time, unix seconds; `0` when the daemon sent none that parses.
    pub(super) created: u64,
    pub(super) labels: BTreeMap<String, String>,
    pub(super) readiness: Readiness,
    /// The address the daemon assigned on each network the container is attached to; `None` for
    /// a network where it has none.
    pub(super) networks: BTreeMap<String, Option<IpAddr>>,
}

impl Inspect {
    pub(super) fn into_container(self) -> Container {
        let state = &self.state;
        let has_check = self
            .config
            .healthcheck
            .as_ref()
            .is_some_and(|check| check.test.first().is_some_and(|kind| kind != "NONE"))
            || state
                .health
                .as_ref()
                .is_some_and(|health| !health.status.is_empty());
        let healthy = state
            .health
            .as_ref()
            .is_some_and(|health| health.status == "healthy");
        let running = state.status == "running" && !state.restarting;
        let readiness = if running && (!has_check || healthy) {
            Readiness::Serving
        } else {
            Readiness::NotServing
        };
        let networks = self
            .network_settings
            .networks
            .unwrap_or_default()
            .into_iter()
            .map(|(name, endpoint)| (name, endpoint.address()))
            .collect();
        Container {
            name: self.name.trim_start_matches('/').into(),
            created: parse_time(&self.created).unwrap_or(0),
            labels: self.config.labels.unwrap_or_default(),
            id: self.id.into(),
            readiness,
            networks,
        }
    }
}

impl Endpoint {
    /// The IPv4 address, else the global IPv6 one. Only literals count: a field that does not
    /// parse is no address.
    fn address(&self) -> Option<IpAddr> {
        [&self.ip_address, &self.global_ipv6_address]
            .into_iter()
            .find_map(|text| text.parse().ok())
    }
}

/// Parses `2026-11-20T12:00:00.123456789Z` (or a numeric offset) into unix seconds.
fn parse_time(text: &str) -> Option<u64> {
    let (date, rest) = text.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    let split = rest.find(['Z', '+', '-'])?;
    let (clock, zone) = rest.split_at(split);
    let mut clock = clock.split(':');
    let hour: i64 = clock.next()?.parse().ok()?;
    let minute: i64 = clock.next()?.parse().ok()?;
    let second: i64 = clock.next()?.split('.').next()?.parse().ok()?;
    let offset = match zone.as_bytes().first()? {
        b'Z' => 0,
        sign => {
            let (h, m) = zone.get(1..)?.split_once(':')?;
            let seconds = h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60;
            if *sign == b'-' { -seconds } else { seconds }
        }
    };
    // Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second - offset).ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_daemon_timestamps() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_time("2026-11-20T12:00:00.123456789Z"),
            Some(1_795_176_000)
        );
        assert_eq!(
            parse_time("2026-11-20T14:00:00+02:00"),
            Some(1_795_176_000),
            "a numeric offset"
        );
        assert_eq!(parse_time("yesterday"), None);
    }
}
