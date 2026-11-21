//! The static cost of a checked expression.
//!
//! An expression has no loops (comprehensions are refused when it is checked) and no recursion,
//! so evaluation visits each node at most once and the cost is a bound, not a guess. Every node
//! costs 1. A scan of a string (`contains`, `matches`, `size`, string `+`) also costs one unit
//! per [`UNIT`] bytes of the longest value it can read, which for anything from the request is
//! [`INPUT_LIMIT`]; `in` over a list costs one per element. Both branches of `&&`, `||` and `?:`
//! are charged: the estimate never assumes a short circuit.

use super::env::{Expr, INPUT_LIMIT, Scan, Var};

/// Bytes of string a scan reads for one unit of cost.
const UNIT: usize = 256;

/// Characters of a regular expression per unit of cost.
const PATTERN_UNIT: usize = 32;

fn scan(bytes: usize) -> u64 {
    bytes.div_ceil(UNIT) as u64
}

/// The most bytes `expr` can produce when it is a string, `None` when it is not one.
fn bound(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Str(text) => Some(text.len()),
        Expr::Var(
            Var::Method
            | Var::Host
            | Var::Path
            | Var::Scheme
            | Var::ClientIp
            | Var::EntryPoint
            | Var::Sni
            | Var::TlsVersion,
        )
        | Expr::Index(..) => Some(INPUT_LIMIT),
        Expr::Ternary(_, then, otherwise) => Some(bound(then)?.max(bound(otherwise)?)),
        Expr::Arith(_, left, right) => Some(bound(left)?.saturating_add(bound(right)?)),
        _ => None,
    }
}

/// The cost of `expr`, saturating.
pub(super) fn estimate(expr: &Expr) -> u64 {
    let own = match expr {
        Expr::Bool(_) | Expr::Int(_) | Expr::Str(_) | Expr::Cidr(_) | Expr::Var(_) => 0,
        Expr::ClientIp => 0,
        Expr::Scan(Scan::Contains, subject, _) => scan(bound(subject).unwrap_or(0)),
        Expr::Scan(..) | Expr::Not(_) | Expr::Neg(_) | Expr::Ip(_) => 0,
        Expr::Matches(subject, pattern) => {
            scan(bound(subject).unwrap_or(0)) + (pattern.as_str().len() / PATTERN_UNIT) as u64
        }
        Expr::Size(operand) => bound(operand).map_or(scan(INPUT_LIMIT), scan),
        Expr::Arith(..) => bound(expr).map_or(0, scan),
        Expr::In(_, haystack) => match &**haystack {
            Expr::List(items) => items.len() as u64,
            _ => 0,
        },
        Expr::List(_)
        | Expr::Index(..)
        | Expr::Has(..)
        | Expr::And(..)
        | Expr::Or(..)
        | Expr::Compare(..)
        | Expr::Ternary(..)
        | Expr::InCidr(..) => 0,
    };
    let children = match expr {
        Expr::Bool(_)
        | Expr::Int(_)
        | Expr::Str(_)
        | Expr::Cidr(_)
        | Expr::Var(_)
        | Expr::ClientIp => 0,
        Expr::List(items) => items.iter().map(estimate).fold(0, u64::saturating_add),
        Expr::Not(operand)
        | Expr::Neg(operand)
        | Expr::Size(operand)
        | Expr::Ip(operand)
        | Expr::Matches(operand, _) => estimate(operand),
        Expr::Index(left, right)
        | Expr::Has(left, right)
        | Expr::And(left, right)
        | Expr::Or(left, right)
        | Expr::Compare(_, left, right)
        | Expr::In(left, right)
        | Expr::Arith(_, left, right)
        | Expr::Scan(_, left, right)
        | Expr::InCidr(left, right) => estimate(left).saturating_add(estimate(right)),
        Expr::Ternary(condition, then, otherwise) => estimate(condition)
            .saturating_add(estimate(then))
            .saturating_add(estimate(otherwise)),
    };
    1_u64.saturating_add(own).saturating_add(children)
}
