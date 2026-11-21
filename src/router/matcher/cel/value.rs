//! Evaluation of a checked [`Expr`] over one request.
//!
//! Values borrow from the request: a string read from the request is never copied, a map is a
//! view of the request's headers or query and is looked up on demand, and an allocation happens
//! only for what the expression itself produces (a list literal, a string `+`, the text of the
//! client address). Every read is bounded:
//!
//! - a request string longer than [`INPUT_LIMIT`] makes the evaluation an error,
//! - `request.headers` is readable only when the request has at most [`MAX_HEADERS`] header
//!   lines, and a name with an upper-case letter is never in it (the names are lower-cased),
//! - `request.query` is readable only when the query is at most [`INPUT_LIMIT`] bytes,
//! - a string built by `+` is at most [`MAX_BUILT`] bytes.
//!
//! An error is not a failure of the request: the leaf treats it as a non-match and counts it.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::IpAddr;

use http::HeaderMap;
use thiserror::Error;

use super::env::{Expr, INPUT_LIMIT, MAX_HEADERS, Scan, Var};
use super::parse::Bin;
use crate::client_ip::Cidr;
use crate::router::matcher::View;

/// Longest string `+` may build, in bytes.
const MAX_BUILT: usize = 64 * 1024;

/// Why an evaluation has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum EvalError {
    #[error("no such key")]
    MissingKey,
    #[error("a list index is out of range")]
    OutOfRange,
    #[error("an input is longer than {INPUT_LIMIT} bytes")]
    InputTooLong,
    #[error("the request has more than {MAX_HEADERS} headers")]
    TooManyHeaders,
    #[error("the client address is not known")]
    UnknownClient,
    #[error("not an IP address")]
    BadIp,
    #[error("integer overflow or division by zero")]
    Arithmetic,
    #[error("a built string is longer than {MAX_BUILT} bytes")]
    TooLarge,
}

/// The request's headers or query, looked up by name.
#[derive(Debug, Clone, Copy)]
enum Lookup<'a> {
    Headers(&'a HeaderMap),
    Query(&'a str),
}

impl<'a> Lookup<'a> {
    fn get(self, key: &str) -> Result<Option<Cow<'a, str>>, EvalError> {
        match self {
            Self::Headers(headers) => {
                if headers.len() > MAX_HEADERS {
                    return Err(EvalError::TooManyHeaders);
                }
                if key.bytes().any(|byte| byte.is_ascii_uppercase()) {
                    return Ok(None);
                }
                let Some(value) = headers.get(key) else {
                    return Ok(None);
                };
                let Ok(text) = std::str::from_utf8(value.as_bytes()) else {
                    return Ok(None);
                };
                limited(text).map(|text| Some(Cow::Borrowed(text)))
            }
            Self::Query(query) => {
                limited(query)?;
                Ok(form_urlencoded::parse(query.as_bytes())
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value))
            }
        }
    }

    fn len(self) -> Result<usize, EvalError> {
        match self {
            Self::Headers(headers) => {
                if headers.len() > MAX_HEADERS {
                    return Err(EvalError::TooManyHeaders);
                }
                Ok(headers.keys_len())
            }
            Self::Query(query) => {
                limited(query)?;
                Ok(form_urlencoded::parse(query.as_bytes())
                    .map(|(name, _)| name)
                    .collect::<HashSet<_>>()
                    .len())
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Value<'a> {
    Bool(bool),
    Int(i64),
    Str(Cow<'a, str>),
    List(Vec<Value<'a>>),
    Map(Lookup<'a>),
    Ip(IpAddr),
    Cidr(&'a Cidr),
}

fn limited(text: &str) -> Result<&str, EvalError> {
    if text.len() > INPUT_LIMIT {
        Err(EvalError::InputTooLong)
    } else {
        Ok(text)
    }
}

fn str_of<'a>(value: Value<'a>) -> Cow<'a, str> {
    match value {
        Value::Str(text) => text,
        _ => Cow::Borrowed(""),
    }
}

fn bool_of(value: &Value<'_>) -> bool {
    matches!(value, Value::Bool(true))
}

fn int_of(value: &Value<'_>) -> i64 {
    match value {
        Value::Int(number) => *number,
        _ => 0,
    }
}

/// Evaluates the checked boolean `expr` over `view`.
///
/// # Errors
///
/// [`EvalError`] when a read fails or a bound is hit.
pub(super) fn run(expr: &Expr, view: &View<'_>) -> Result<bool, EvalError> {
    Ok(bool_of(&eval(expr, view)?))
}

fn read<'a>(var: Var, view: &View<'a>) -> Result<Value<'a>, EvalError> {
    let text = match var {
        Var::Method => view.request.method.as_str(),
        Var::Host => view.host,
        Var::Path => view.path,
        Var::Scheme => {
            if view.tls {
                "https"
            } else {
                "http"
            }
        }
        Var::EntryPoint => view.entry_point,
        Var::Sni => view.hello.server_name.unwrap_or_default(),
        Var::TlsVersion => view.hello.version.unwrap_or_default(),
        Var::ClientIp => {
            return Ok(Value::Str(Cow::Owned(
                view.client_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            )));
        }
        Var::Query => {
            return Ok(Value::Map(Lookup::Query(
                view.request.uri.query().unwrap_or_default(),
            )));
        }
        Var::Headers => return Ok(Value::Map(Lookup::Headers(&view.request.headers))),
    };
    Ok(Value::Str(Cow::Borrowed(limited(text)?)))
}

fn equal(left: &Value<'_>, right: &Value<'_>) -> bool {
    match (left, right) {
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Int(a), Value::Int(b)) => a == b,
        (Value::Str(a), Value::Str(b)) => a == b,
        (Value::Ip(a), Value::Ip(b)) => {
            crate::client_ip::normalize(*a) == crate::client_ip::normalize(*b)
        }
        (Value::List(a), Value::List(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| equal(x, y))
        }
        _ => false,
    }
}

fn order(left: &Value<'_>, right: &Value<'_>) -> Ordering {
    match (left, right) {
        (Value::Int(a), Value::Int(b)) => a.cmp(b),
        (Value::Str(a), Value::Str(b)) => a.cmp(b),
        _ => Ordering::Equal,
    }
}

/// `&&` and `||` are commutative about errors, as CEL defines them: a side that decides the
/// result wins over a side that failed.
fn logic<'a>(
    absorbing: bool,
    left: &'a Expr,
    right: &'a Expr,
    view: &View<'a>,
) -> Result<Value<'a>, EvalError> {
    let first = eval(left, view).map(|value| bool_of(&value));
    if first == Ok(absorbing) {
        return Ok(Value::Bool(absorbing));
    }
    let second = eval(right, view).map(|value| bool_of(&value));
    match (first, second) {
        (_, Ok(decided)) if decided == absorbing => Ok(Value::Bool(absorbing)),
        (Err(err), _) | (_, Err(err)) => Err(err),
        (Ok(_), Ok(other)) => Ok(Value::Bool(other)),
    }
}

fn eval<'a>(expr: &'a Expr, view: &View<'a>) -> Result<Value<'a>, EvalError> {
    Ok(match expr {
        Expr::Bool(value) => Value::Bool(*value),
        Expr::Int(value) => Value::Int(*value),
        Expr::Str(text) => Value::Str(Cow::Borrowed(text)),
        Expr::Cidr(block) => Value::Cidr(block),
        Expr::Var(var) => read(*var, view)?,
        Expr::ClientIp => Value::Ip(view.client_ip.ok_or(EvalError::UnknownClient)?),
        Expr::List(items) => Value::List(
            items
                .iter()
                .map(|item| eval(item, view))
                .collect::<Result<_, _>>()?,
        ),
        Expr::Index(container, key) => match (eval(container, view)?, eval(key, view)?) {
            (Value::Map(map), key) => {
                Value::Str(map.get(&str_of(key))?.ok_or(EvalError::MissingKey)?)
            }
            (Value::List(items), position) => usize::try_from(int_of(&position))
                .ok()
                .and_then(|at| items.into_iter().nth(at))
                .ok_or(EvalError::OutOfRange)?,
            _ => return Err(EvalError::MissingKey),
        },
        Expr::Has(container, key) => match (eval(container, view)?, eval(key, view)?) {
            (Value::Map(map), key) => Value::Bool(map.get(&str_of(key))?.is_some()),
            _ => Value::Bool(false),
        },
        Expr::Not(operand) => Value::Bool(!bool_of(&eval(operand, view)?)),
        Expr::Neg(operand) => Value::Int(
            int_of(&eval(operand, view)?)
                .checked_neg()
                .ok_or(EvalError::Arithmetic)?,
        ),
        Expr::And(left, right) => logic(false, left, right, view)?,
        Expr::Or(left, right) => logic(true, left, right, view)?,
        Expr::Compare(op, left, right) => {
            let (left, right) = (eval(left, view)?, eval(right, view)?);
            Value::Bool(match op {
                Bin::Eq => equal(&left, &right),
                Bin::Ne => !equal(&left, &right),
                Bin::Lt => order(&left, &right).is_lt(),
                Bin::Le => order(&left, &right).is_le(),
                Bin::Gt => order(&left, &right).is_gt(),
                _ => order(&left, &right).is_ge(),
            })
        }
        Expr::In(needle, haystack) => {
            let needle = eval(needle, view)?;
            Value::Bool(match eval(haystack, view)? {
                Value::List(items) => items.iter().any(|item| equal(item, &needle)),
                Value::Map(map) => map.get(&str_of(needle))?.is_some(),
                _ => false,
            })
        }
        Expr::Arith(op, left, right) => arithmetic(*op, &eval(left, view)?, &eval(right, view)?)?,
        Expr::Ternary(condition, then, otherwise) => {
            if bool_of(&eval(condition, view)?) {
                eval(then, view)?
            } else {
                eval(otherwise, view)?
            }
        }
        Expr::Size(operand) => {
            let size = match eval(operand, view)? {
                Value::Str(text) => text.chars().count(),
                Value::List(items) => items.len(),
                Value::Map(map) => map.len()?,
                _ => 0,
            };
            Value::Int(i64::try_from(size).unwrap_or(i64::MAX))
        }
        Expr::Scan(kind, subject, needle) => {
            let (subject, needle) = (str_of(eval(subject, view)?), str_of(eval(needle, view)?));
            Value::Bool(match kind {
                Scan::StartsWith => subject.starts_with(&*needle),
                Scan::EndsWith => subject.ends_with(&*needle),
                Scan::Contains => subject.contains(&*needle),
            })
        }
        Expr::Matches(subject, pattern) => {
            Value::Bool(pattern.is_match(&str_of(eval(subject, view)?)))
        }
        Expr::Ip(text) => Value::Ip(
            str_of(eval(text, view)?)
                .parse()
                .map_err(|_| EvalError::BadIp)?,
        ),
        Expr::InCidr(address, block) => match (eval(address, view)?, eval(block, view)?) {
            (Value::Ip(address), Value::Cidr(block)) => Value::Bool(block.contains(address)),
            _ => Value::Bool(false),
        },
    })
}

fn arithmetic<'a>(op: Bin, left: &Value<'_>, right: &Value<'_>) -> Result<Value<'a>, EvalError> {
    if let (Value::Str(a), Value::Str(b)) = (left, right) {
        if a.len() + b.len() > MAX_BUILT {
            return Err(EvalError::TooLarge);
        }
        return Ok(Value::Str(Cow::Owned(format!("{a}{b}"))));
    }
    let (a, b) = (int_of(left), int_of(right));
    let result = match op {
        Bin::Add => a.checked_add(b),
        Bin::Sub => a.checked_sub(b),
        Bin::Mul => a.checked_mul(b),
        Bin::Div => a.checked_div(b),
        _ => a.checked_rem(b),
    };
    result.map(Value::Int).ok_or(EvalError::Arithmetic)
}
