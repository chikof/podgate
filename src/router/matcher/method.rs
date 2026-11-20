//! `{"method": ["GET", "HEAD"]}`: the request method is any of the listed tokens
//! (case-sensitive, as HTTP methods are).

use serde_json::Value;

use super::{Error, Spec, View};

/// The methods of a `method` leaf.
#[derive(Debug)]
pub struct Method {
    methods: Vec<Box<str>>,
}

impl Method {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let list = match argument {
            Value::String(one) => vec![one.as_str()],
            Value::Array(list) => list
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .ok_or_else(|| Error::invalid("method: every entry is a string"))
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(Error::invalid("method: a string or a list of strings")),
        };
        if list.is_empty() {
            return Err(Error::invalid("method: the list is empty"));
        }
        let methods = list
            .into_iter()
            .map(|token| {
                http::Method::from_bytes(token.as_bytes())
                    .map(|method| Box::from(method.as_str()))
                    .map_err(|_| Error::invalid(format!("method: {token:?} is not a method")))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { methods })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        let method = view.request.method.as_str();
        self.methods.iter().any(|allowed| &**allowed == method)
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }
}

/// Two method lists are disjoint when they share no method.
pub(super) fn disjoint(a: &Method, b: &Method) -> bool {
    !a.methods.iter().any(|method| b.methods.contains(method))
}
