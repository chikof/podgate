//! The parsed tree of a rule, and its matcher JSON.

use serde_json::{Map, Value, json};

use crate::error::RuleError;

/// A rule as a tree. `Always` is a TCP `HostSNI(`*`)`: it matches every connection, which a
/// router says by having no matcher at all.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node {
    Always,
    Leaf(Value),
    All(Vec<Node>),
    Any(Vec<Node>),
    Not(Box<Node>),
}

impl Node {
    /// A leaf `{key: value}`.
    pub(crate) fn leaf(key: &str, value: Value) -> Self {
        let mut leaf = Map::new();
        leaf.insert(key.to_owned(), value);
        Self::Leaf(Value::Object(leaf))
    }

    /// Removes what `Always` makes redundant and merges `host` leaves of an `||`, then returns
    /// the matcher, or `None` when the whole rule matches everything.
    pub(crate) fn into_matcher(self, at: usize) -> Result<Option<Value>, RuleError> {
        Ok(match self.simplify(at)? {
            Self::Always => None,
            node => Some(node.json()),
        })
    }

    fn simplify(self, at: usize) -> Result<Self, RuleError> {
        Ok(match self {
            Self::Always | Self::Leaf(_) => self,
            Self::All(items) => {
                let mut kept = Vec::new();
                for item in items {
                    match item.simplify(at)? {
                        Self::Always => {}
                        other => kept.push(other),
                    }
                }
                match kept.len() {
                    0 => Self::Always,
                    1 => kept.remove(0),
                    _ => Self::All(kept),
                }
            }
            Self::Any(items) => {
                let mut kept = Vec::new();
                for item in items {
                    match item.simplify(at)? {
                        Self::Always => return Ok(Self::Always),
                        other => kept.push(other),
                    }
                }
                let mut kept = merge_hosts(kept);
                if kept.len() == 1 {
                    kept.remove(0)
                } else {
                    Self::Any(kept)
                }
            }
            Self::Not(inner) => match inner.simplify(at)? {
                Self::Always => {
                    return Err(RuleError::new(at, "a negated catch-all matches nothing"));
                }
                other => Self::Not(Box::new(other)),
            },
        })
    }

    fn json(self) -> Value {
        match self {
            Self::Always => Value::Null,
            Self::Leaf(value) => value,
            Self::All(items) => {
                json!({ "all": items.into_iter().map(Self::json).collect::<Vec<_>>() })
            }
            Self::Any(items) => {
                json!({ "any": items.into_iter().map(Self::json).collect::<Vec<_>>() })
            }
            Self::Not(inner) => json!({ "not": inner.json() }),
        }
    }
}

/// The names of the `{"host": ...}` leaf `node` is, as a list.
fn host_names(node: &Node) -> Option<Vec<Value>> {
    let Node::Leaf(Value::Object(map)) = node else {
        return None;
    };
    if map.len() != 1 {
        return None;
    }
    match map.get("host")? {
        Value::Array(names) => Some(names.clone()),
        name @ Value::String(_) => Some(vec![name.clone()]),
        _ => None,
    }
}

/// `Host(a) || Host(b)` is `{"host": [a, b]}`: the same set of requests, in the one shape the
/// daemon indexes by host. The merged leaf takes the place of the first one.
fn merge_hosts(items: Vec<Node>) -> Vec<Node> {
    if items
        .iter()
        .filter(|item| host_names(item).is_some())
        .count()
        < 2
    {
        return items;
    }
    let mut names: Vec<Value> = Vec::new();
    let mut merged: Vec<Node> = Vec::new();
    let mut slot = None;
    for item in items {
        match host_names(&item) {
            Some(list) => {
                names.extend(list);
                if slot.is_none() {
                    slot = Some(merged.len());
                    merged.push(Node::Always);
                }
            }
            None => merged.push(item),
        }
    }
    if let Some(index) = slot {
        let mut leaf = Map::new();
        leaf.insert("host".into(), Value::Array(names));
        merged[index] = Node::Leaf(Value::Object(leaf));
    }
    merged
}
