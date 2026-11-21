//! The parts of the ECS API (JSON 1.1), the EC2 API and the STS answers the source reads.
//!
//! Only the fields the source uses are named; everything else in an answer is ignored. A list
//! that ECS leaves out is an empty one.

use std::collections::BTreeMap;

use serde::Deserialize;

/// `ListClusters`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClusterPage {
    #[serde(default)]
    pub(super) cluster_arns: Vec<String>,
    pub(super) next_token: Option<String>,
}

/// `ListTasks`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskPage {
    #[serde(default)]
    pub(super) task_arns: Vec<String>,
    pub(super) next_token: Option<String>,
}

/// An entry of `failures`: something an ECS `Describe*` call could not describe.
#[derive(Debug, Deserialize)]
pub(super) struct Failure {
    #[serde(default)]
    pub(super) arn: Option<String>,
    #[serde(default)]
    pub(super) reason: Option<String>,
}

/// `DescribeTasks`.
#[derive(Debug, Deserialize)]
pub(super) struct DescribedTasks {
    #[serde(default)]
    pub(super) tasks: Vec<Task>,
    #[serde(default)]
    pub(super) failures: Vec<Failure>,
}

/// One task.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Task {
    pub(super) task_arn: String,
    pub(super) task_definition_arn: String,
    /// `service:<name>` for a task of a service, `family:<name>` otherwise.
    pub(super) group: Option<String>,
    pub(super) last_status: Option<String>,
    pub(super) desired_status: Option<String>,
    pub(super) health_status: Option<String>,
    pub(super) launch_type: Option<String>,
    /// Unix seconds, with a fraction.
    pub(super) created_at: Option<f64>,
    pub(super) container_instance_arn: Option<String>,
    #[serde(default)]
    pub(super) attachments: Vec<Attachment>,
    #[serde(default)]
    pub(super) containers: Vec<Container>,
    #[serde(default)]
    pub(super) tags: Vec<Tag>,
}

/// A network interface or another resource attached to a task.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct Attachment {
    #[serde(rename = "type")]
    pub(super) kind: Option<String>,
    #[serde(default)]
    pub(super) details: Vec<Detail>,
}

/// A `name` and `value`.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct Detail {
    pub(super) name: String,
    pub(super) value: Option<String>,
}

/// A resource tag of a task.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct Tag {
    pub(super) key: String,
    #[serde(default)]
    pub(super) value: String,
}

/// A container of a running task.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Container {
    pub(super) name: String,
    pub(super) last_status: Option<String>,
    pub(super) health_status: Option<String>,
    #[serde(default)]
    pub(super) network_bindings: Vec<NetworkBinding>,
    #[serde(default)]
    pub(super) network_interfaces: Vec<NetworkInterface>,
}

/// A container port published on the instance (bridge mode).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworkBinding {
    pub(super) container_port: Option<u16>,
    pub(super) host_port: Option<u16>,
    pub(super) protocol: Option<String>,
}

/// The network interface of a container in `awsvpc` mode.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetworkInterface {
    pub(super) private_ipv4_address: Option<String>,
}

/// `DescribeTaskDefinition`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DescribedDefinition {
    pub(super) task_definition: TaskDefinition,
}

/// A task definition revision: what the labels are written in.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TaskDefinition {
    pub(super) family: Option<String>,
    pub(super) network_mode: Option<String>,
    #[serde(default)]
    pub(super) container_definitions: Vec<ContainerDefinition>,
}

/// A container of a task definition.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContainerDefinition {
    pub(super) name: String,
    #[serde(default)]
    pub(super) docker_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) port_mappings: Vec<PortMapping>,
    /// Only whether one is defined matters.
    pub(super) health_check: Option<serde_json::Value>,
}

/// A port a container declares.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PortMapping {
    pub(super) container_port: Option<u16>,
    pub(super) protocol: Option<String>,
}

/// `DescribeServices`.
#[derive(Debug, Deserialize)]
pub(super) struct DescribedServices {
    #[serde(default)]
    pub(super) services: Vec<Service>,
    #[serde(default)]
    pub(super) failures: Vec<Failure>,
}

/// A service: its creation time is the app's age.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Service {
    pub(super) service_name: String,
    /// Unix seconds, with a fraction.
    pub(super) created_at: Option<f64>,
}

/// `DescribeContainerInstances`.
#[derive(Debug, Deserialize)]
pub(super) struct DescribedInstances {
    #[serde(default, rename = "containerInstances")]
    pub(super) instances: Vec<ContainerInstance>,
    #[serde(default)]
    pub(super) failures: Vec<Failure>,
}

/// An EC2 instance that runs tasks.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContainerInstance {
    pub(super) container_instance_arn: String,
    pub(super) ec2_instance_id: Option<String>,
}

/// The seconds of a timestamp ECS sends as a number, `0` when it sends none.
#[must_use]
pub(super) fn unix_secs(seconds: Option<f64>) -> u64 {
    seconds.map_or(0, |seconds| {
        // A finite, non-negative number of seconds fits; anything else is `0`.
        if seconds.is_finite() && seconds >= 0.0 {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "checked finite and non-negative; the fraction is dropped on purpose"
            )]
            let whole = seconds as u64;
            whole
        } else {
            0
        }
    })
}

/// The last path segment of an ARN (`.../cluster/prod` is `prod`).
#[must_use]
pub(super) fn arn_name(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

/// The text of every element that has no child elements, with the names of its ancestors:
/// `("Response/Credentials/AccessKeyId", "AKIA...")`. Enough for the few small XML answers of
/// EC2 and STS; it knows no namespaces, no CDATA and no attributes beyond skipping them.
#[must_use]
pub(super) fn leaves(xml: &str) -> Vec<(String, String)> {
    let mut path: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find('<') {
        let text = &rest[..open];
        let Some(length) = rest[open..].find('>') else {
            break;
        };
        let tag = &rest[open + 1..open + length];
        rest = &rest[open + length + 1..];
        if tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        if let Some(name) = tag.strip_prefix('/') {
            if !text.trim().is_empty() && path.last() == Some(&name.trim()) {
                out.push((path.join("/"), unescape(text.trim())));
            }
            path.pop();
        } else if !tag.ends_with('/') {
            path.push(tag.split_whitespace().next().unwrap_or(""));
        }
    }
    out
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The value of the first leaf whose path ends with `/<suffix>`.
#[must_use]
pub(super) fn leaf<'a>(leaves: &'a [(String, String)], suffix: &str) -> Option<&'a str> {
    leaves
        .iter()
        .find(|(path, _)| {
            path.strip_suffix(suffix)
                .is_some_and(|before| before.is_empty() || before.ends_with('/'))
        })
        .map(|(_, text)| text.as_str())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn arn_names_are_the_last_segment() {
        assert_eq!(arn_name("arn:aws:ecs:eu-west-1:1:cluster/prod"), "prod");
        assert_eq!(
            arn_name("arn:aws:ecs:eu-west-1:1:task/prod/abc123"),
            "abc123"
        );
        assert_eq!(arn_name("prod"), "prod");
    }

    #[test]
    fn timestamps_are_whole_seconds() {
        assert_eq!(unix_secs(Some(1_700_000_000.75)), 1_700_000_000);
        assert_eq!(unix_secs(Some(-1.0)), 0);
        assert_eq!(unix_secs(Some(f64::NAN)), 0);
        assert_eq!(unix_secs(None), 0);
    }

    #[test]
    fn xml_leaves_keep_their_path() {
        let xml = r#"<?xml version="1.0"?><R xmlns="x"><a><b>one &amp; two</b><c/><d><e>3</e></d></a></R>"#;
        let all = leaves(xml);
        assert_eq!(
            all,
            [
                ("R/a/b".to_owned(), "one & two".to_owned()),
                ("R/a/d/e".to_owned(), "3".to_owned())
            ]
        );
        assert_eq!(leaf(&all, "a/d/e"), Some("3"));
        assert_eq!(leaf(&all, "d/e"), Some("3"));
    }
}
