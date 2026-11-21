//! `{"alpn": "h2"}` and `{"alpn": ["h2", "postgresql"]}` (TCP routers): the client's
//! ClientHello offers at least one of the protocols (case-sensitive, as the registry names them).
//! A connection with no ClientHello, or one with no ALPN extension, matches no `alpn` leaf.
//!
//! It claims no host. In a terminating router the protocols it names are the ones the handshake
//! can negotiate (the first of them the client offers).

use serde_json::Value;

use super::{Error, Spec, View};

/// The longest protocol name TLS can carry: the length is one byte.
const MAX_PROTOCOL: usize = 255;

/// The protocols of an `alpn` leaf.
#[derive(Debug)]
pub struct Alpn {
    protocols: Vec<Box<[u8]>>,
}

impl Alpn {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let list = match argument {
            Value::String(one) => vec![one.as_str()],
            Value::Array(list) => list
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .ok_or_else(|| Error::invalid("alpn: every entry is a string"))
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(Error::invalid("alpn: a string or a list of strings")),
        };
        if list.is_empty() {
            return Err(Error::invalid("alpn: the list is empty"));
        }
        let protocols = list
            .into_iter()
            .map(|name| {
                if name.is_empty() || name.len() > MAX_PROTOCOL || !name.is_ascii() {
                    Err(Error::invalid(format!(
                        "alpn: {name:?} is not a protocol name (1 to {MAX_PROTOCOL} ASCII bytes)"
                    )))
                } else {
                    Ok(Box::from(name.as_bytes()))
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { protocols })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.hello.alpn.iter().any(|offered| {
            self.protocols
                .iter()
                .any(|protocol| **protocol == offered[..])
        })
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// The protocols, in the order the router wrote them.
    pub(super) fn protocols(&self) -> impl Iterator<Item = &[u8]> {
        self.protocols.iter().map(AsRef::as_ref)
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use crate::router::matcher::{Dialect, Hello, View, parse_in};

    #[test]
    fn matches_any_offered_protocol() {
        let matcher =
            parse_in(Dialect::Tcp, &json!({"alpn": ["h2", "postgresql"]})).expect("parses");
        let request = RequestHeader::build("GET", b"/", None).expect("request");
        let view = |alpn: &[Vec<u8>]| {
            matcher.matches(&View {
                host: "",
                path: "/",
                entry_point: "pg",
                tls: true,
                request: &request,
                client_ip: None,
                hello: Hello {
                    server_name: None,
                    alpn,
                    version: None,
                },
            })
        };
        assert!(view(&[b"http/1.1".to_vec(), b"postgresql".to_vec()]));
        assert!(!view(&[b"http/1.1".to_vec()]));
        assert!(!view(&[]));
    }

    #[test]
    fn bad_protocol_names_are_refused() {
        for bad in [json!(""), json!([]), json!(["h2", 1]), json!("é"), json!(7)] {
            let err = parse_in(Dialect::Tcp, &json!({ "alpn": bad })).expect_err("refused");
            assert_eq!(err.code, "invalid_matcher", "{bad}: {err}");
        }
    }
}
