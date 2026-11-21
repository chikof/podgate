//! What each rule function means: its arguments checked, its matcher built.

use std::net::IpAddr;

use serde_json::{Value, json};

use crate::error::RuleError;
use crate::node::Node;
use crate::regexp;
use crate::rule::Dialect;

/// Most arguments one function takes: a hostile label cannot cost more than this.
const MAX_ARGS: usize = 256;

/// Functions of Traefik v2's syntax, which podgate does not translate.
const V2_FUNCTIONS: [&str; 6] = [
    "headers",
    "headersregexp",
    "hostheader",
    "pathprefixstrip",
    "pathstrip",
    "pathprefixstripregex",
];

/// The matcher of `name(args)`, with every regular expression in it checked and recorded in
/// `regexes`.
pub(crate) fn call(
    dialect: Dialect,
    name: &str,
    args: Vec<String>,
    at: usize,
    regexes: &mut Vec<Box<str>>,
) -> Result<Node, RuleError> {
    let fail = |message: String| RuleError::new(at, message);
    let malformed = |message: String| RuleError::invalid(at, message);
    let function = name.to_ascii_lowercase();
    if args.len() > MAX_ARGS {
        return Err(malformed(format!(
            "{name} has more than {MAX_ARGS} arguments"
        )));
    }
    if V2_FUNCTIONS.contains(&function.as_str()) {
        return Err(fail(format!(
            "{name} is Traefik v2 syntax; podgate translates v3 rules only"
        )));
    }
    let http = dialect == Dialect::Http;
    let one_or_more = |what: &str| -> Result<(), RuleError> {
        if args.is_empty() {
            Err(malformed(format!("{what} needs at least one argument")))
        } else {
            Ok(())
        }
    };
    match function.as_str() {
        "host" if http => {
            one_or_more(name)?;
            let names = args
                .iter()
                .map(|arg| host_name(arg))
                .collect::<Result<Vec<_>, _>>()
                .map_err(fail)?;
            Ok(Node::leaf("host", one_or_list(names)))
        }
        "hostregexp" if http => {
            let [pattern] = exactly::<1>(name, &args, at)?;
            host_regexp(pattern, at, regexes)
        }
        "path" | "pathprefix" if http => {
            one_or_more(name)?;
            let key = if function == "path" {
                "path"
            } else {
                "path_prefix"
            };
            let leaves = args
                .iter()
                .map(|arg| {
                    if arg.starts_with('/') {
                        Ok(Node::leaf(key, Value::String(arg.clone())))
                    } else {
                        Err(fail(format!("{name}: {arg:?} must start with `/`")))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(any_of(leaves))
        }
        "pathregexp" if http => {
            one_or_more(name)?;
            let leaves = args
                .iter()
                .map(|arg| {
                    regexp::check(arg, at, regexes)?;
                    Ok(Node::leaf("path_regexp", Value::String(arg.clone())))
                })
                .collect::<Result<Vec<_>, RuleError>>()?;
            Ok(any_of(leaves))
        }
        "method" if http => {
            one_or_more(name)?;
            let methods = args
                .iter()
                .map(|arg| method(arg))
                .collect::<Result<Vec<_>, _>>()
                .map_err(fail)?;
            Ok(Node::leaf("method", one_or_list(methods)))
        }
        "header" if http => {
            let [header, value] = exactly::<2>(name, &args, at)?;
            let header = header_name(header).map_err(fail)?;
            Ok(Node::leaf(
                "header",
                json!({ "name": header, "value": value }),
            ))
        }
        "headerregexp" if http => {
            let [header, pattern] = exactly::<2>(name, &args, at)?;
            let header = header_name(header).map_err(fail)?;
            regexp::check(pattern, at, regexes)?;
            Ok(Node::leaf(
                "header_regexp",
                json!({ "name": header, "regex": pattern }),
            ))
        }
        "query" | "queryregexp" if http => {
            let regex = function == "queryregexp";
            let (key, value) = match args.as_slice() {
                [pair] => pair.split_once('=').ok_or_else(|| {
                    fail(format!(
                        "{name}: `{pair}` only tests that the parameter exists, podgate matches a value"
                    ))
                })?,
                [key, value] => (key.as_str(), value.as_str()),
                _ => {
                    return Err(malformed(format!(
                        "{name} takes `name=value` or a name and a value"
                    )));
                }
            };
            if key.is_empty() {
                return Err(malformed(format!("{name}: the parameter name is empty")));
            }
            if regex {
                regexp::check(value, at, regexes)?;
                Ok(Node::leaf(
                    "query_regexp",
                    json!({ "name": key, "regex": value }),
                ))
            } else {
                Ok(Node::leaf("query", json!({ "name": key, "value": value })))
            }
        }
        "clientip" => {
            one_or_more(name)?;
            for arg in &args {
                client_ip(arg).map_err(fail)?;
            }
            Ok(Node::leaf("client_ip", json!(args)))
        }
        "hostsni" if !http => {
            one_or_more(name)?;
            if args.iter().any(|arg| arg == "*") {
                return Ok(Node::Always);
            }
            let names = args
                .iter()
                .map(|arg| host_name(arg))
                .collect::<Result<Vec<_>, _>>()
                .map_err(fail)?;
            Ok(Node::leaf("sni", one_or_list(names)))
        }
        "hostsniregexp" if !http => {
            let [pattern] = exactly::<1>(name, &args, at)?;
            regexp::check(pattern, at, regexes)?;
            Ok(Node::leaf("sni_regexp", Value::String(pattern.clone())))
        }
        "alpn" if !http => {
            one_or_more(name)?;
            if args.iter().any(String::is_empty) {
                return Err(malformed("ALPN: a protocol name is empty".to_owned()));
            }
            Ok(Node::leaf("alpn", one_or_list(args)))
        }
        "host" | "hostregexp" | "path" | "pathprefix" | "pathregexp" | "method" | "header"
        | "headerregexp" | "query" | "queryregexp" => Err(malformed(format!(
            "{name} is an HTTP rule function and this is a TCP rule"
        ))),
        "hostsni" | "hostsniregexp" | "alpn" => Err(malformed(format!(
            "{name} is a TCP rule function and this is an HTTP rule"
        ))),
        _ => Err(fail(format!("unknown function {name}"))),
    }
}

/// `HostRegexp`. A pattern with a `{name:regex}` group is Traefik v2's.
fn host_regexp(pattern: &str, at: usize, regexes: &mut Vec<Box<str>>) -> Result<Node, RuleError> {
    if regexp::has_named_group(pattern) {
        return Err(RuleError::new(
            at,
            format!(
                "HostRegexp: {pattern:?} uses a `{{name:regex}}` group, which is Traefik v2 syntax; write a plain regular expression"
            ),
        ));
    }
    regexp::check(pattern, at, regexes)?;
    Ok(Node::leaf("host_regexp", Value::String(pattern.to_owned())))
}

fn exactly<'a, const N: usize>(
    name: &str,
    args: &'a [String],
    at: usize,
) -> Result<[&'a String; N], RuleError> {
    <[&String; N]>::try_from(args.iter().collect::<Vec<_>>()).map_err(|_| {
        RuleError::invalid(
            at,
            format!("{name} takes {N} argument(s), not {}", args.len()),
        )
    })
}

/// One name as a string, several as a list: the two shapes the daemon takes.
fn one_or_list(mut names: Vec<String>) -> Value {
    if names.len() == 1 {
        Value::String(names.remove(0))
    } else {
        json!(names)
    }
}

fn any_of(mut leaves: Vec<Node>) -> Node {
    if leaves.len() == 1 {
        leaves.remove(0)
    } else {
        Node::Any(leaves)
    }
}

/// A host name or one leading `*.` wildcard, lower case.
fn host_name(arg: &str) -> Result<String, String> {
    if !arg.is_ascii() {
        return Err(format!(
            "{arg:?} is not ASCII; write an internationalized name as punycode"
        ));
    }
    let name = arg.to_ascii_lowercase();
    let bare = name.strip_prefix("*.").unwrap_or(&name);
    let valid = !bare.is_empty()
        && bare
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(name)
    } else {
        Err(format!(
            "{arg:?} is not a host name or a `*.` wildcard; use HostRegexp for anything else"
        ))
    }
}

/// An upper case method token. Traefik compares methods without regard to case.
fn method(arg: &str) -> Result<String, String> {
    let token = arg.to_ascii_uppercase();
    if !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(token)
    } else {
        Err(format!("{arg:?} is not an HTTP method"))
    }
}

/// A header name, lower case: names are case-insensitive.
fn header_name(arg: &str) -> Result<String, String> {
    let valid = !arg.is_empty()
        && arg
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    if valid {
        Ok(arg.to_ascii_lowercase())
    } else {
        Err(format!("{arg:?} is not a header name"))
    }
}

/// An address or a CIDR range.
fn client_ip(arg: &str) -> Result<(), String> {
    let (address, prefix) = match arg.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (arg, None),
    };
    let ip: IpAddr = address
        .parse()
        .map_err(|_| format!("{arg:?} is not an IP address or a CIDR range"))?;
    if let Some(prefix) = prefix {
        let longest = if ip.is_ipv4() { 32 } else { 128 };
        match prefix.parse::<u8>() {
            Ok(bits) if bits <= longest => {}
            _ => return Err(format!("{arg:?} has a bad prefix length")),
        }
    }
    Ok(())
}
