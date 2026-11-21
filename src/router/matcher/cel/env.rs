//! The declared environment of a `cel` expression and its type check.
//!
//! [`check`] turns the syntax tree of [`super::parse`] into a typed [`Expr`], resolving every
//! name against the environment below and refusing everything else. The environment is a pure
//! function of one request: there is no clock, no randomness, no I/O and no way to name a
//! function that is not in this file (`now`, `timestamp`, `duration` and the like are
//! "undeclared references").
//!
//! | name | type |
//! |---|---|
//! | `request.method`, `request.host`, `request.path`, `request.scheme`, `request.client_ip` | string |
//! | `request.query`, `request.headers` | map of string to string |
//! | `entry_point`, `tls.sni`, `tls.version` | string |
//!
//! `request.client_ip` is `""` when the client address is not known, `tls.sni` and
//! `tls.version` are `""` on plain HTTP. Functions and methods: `size`, `has` (on a map key),
//! `startsWith`, `endsWith`, `contains`, `matches` (the pattern is a literal), `ip`, `cidr` (a
//! literal) and `in_cidr`.
//!
//! The checker is deliberately strict: there is no dynamic type, so `request.method == 1` is a
//! type error at compile time and not a surprise at request time.

use super::parse::{Bin, Error, Kind, Node, Un};
use crate::client_ip::Cidr;

/// Longest value of any request-derived string an expression can read, in bytes. A longer input
/// makes the evaluation an error (a non-match); it is also what the cost estimate charges.
pub(super) const INPUT_LIMIT: usize = 8192;

/// Most header lines a request may have for `request.headers` to be readable.
pub(super) const MAX_HEADERS: usize = 100;

/// The static type of an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Ty {
    Bool,
    Int,
    Str,
    List(Box<Ty>),
    /// A map of string to string: `request.query` and `request.headers`.
    Map,
    Ip,
    Cidr,
}

impl Ty {
    fn name(&self) -> String {
        match self {
            Self::Bool => "bool".to_owned(),
            Self::Int => "int".to_owned(),
            Self::Str => "string".to_owned(),
            Self::List(item) => format!("list({})", item.name()),
            Self::Map => "map(string, string)".to_owned(),
            Self::Ip => "ip".to_owned(),
            Self::Cidr => "cidr".to_owned(),
        }
    }
}

/// A request-derived value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Var {
    Method,
    Host,
    Path,
    Scheme,
    ClientIp,
    Query,
    Headers,
    EntryPoint,
    Sni,
    TlsVersion,
}

impl Var {
    fn ty(self) -> Ty {
        match self {
            Self::Query | Self::Headers => Ty::Map,
            _ => Ty::Str,
        }
    }
}

/// Which of the three string scans a call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scan {
    StartsWith,
    EndsWith,
    Contains,
}

/// A checked expression: every name resolved, every operand of a known type.
#[derive(Debug)]
pub(super) enum Expr {
    Bool(bool),
    Int(i64),
    Str(Box<str>),
    Cidr(Cidr),
    Var(Var),
    /// `ip(request.client_ip)`, without the round trip through text.
    ClientIp,
    List(Vec<Expr>),
    /// A map or list element.
    Index(Box<Expr>, Box<Expr>),
    /// `has(map.key)`: the map and the key.
    Has(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    /// `==`, `!=`, `<`, `<=`, `>`, `>=`.
    Compare(Bin, Box<Expr>, Box<Expr>),
    In(Box<Expr>, Box<Expr>),
    /// `+` (integers or strings), `-`, `*`, `/`, `%`.
    Arith(Bin, Box<Expr>, Box<Expr>),
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    Size(Box<Expr>),
    Scan(Scan, Box<Expr>, Box<Expr>),
    Matches(Box<Expr>, regex::Regex),
    Ip(Box<Expr>),
    InCidr(Box<Expr>, Box<Expr>),
}

/// Checks `root` and returns its typed form; the expression must be a boolean.
///
/// # Errors
///
/// [`Error`] for an undeclared name, a type mismatch, a comprehension, a non-literal regular
/// expression or CIDR block, and a result that is not a boolean.
pub(super) fn check(root: &Node) -> Result<Expr, Error> {
    let (expr, ty) = check_node(root)?;
    if ty == Ty::Bool {
        Ok(expr)
    } else {
        Err(Error::new(
            format!(
                "type error: the expression must be a bool, it is a {}",
                ty.name()
            ),
            root.column,
        ))
    }
}

type Checked = (Expr, Ty);

fn mismatch(what: &str, found: &Ty, column: usize) -> Error {
    Error::new(
        format!("type error: {what}, found {}", found.name()),
        column,
    )
}

fn expect(node: &Node, wanted: &Ty, what: &str) -> Result<Expr, Error> {
    let (expr, ty) = check_node(node)?;
    if &ty == wanted {
        Ok(expr)
    } else {
        Err(mismatch(what, &ty, node.column))
    }
}

fn boxed(expr: Expr) -> Box<Expr> {
    Box::new(expr)
}

fn check_node(node: &Node) -> Result<Checked, Error> {
    let column = node.column;
    match &node.kind {
        Kind::Bool(value) => Ok((Expr::Bool(*value), Ty::Bool)),
        Kind::Int(value) => Ok((Expr::Int(*value), Ty::Int)),
        Kind::Str(value) => Ok((Expr::Str(value.clone()), Ty::Str)),
        Kind::Ident(name) => match &**name {
            "entry_point" => Ok((Expr::Var(Var::EntryPoint), Ty::Str)),
            "request" | "tls" => Err(Error::new(
                format!("type error: '{name}' is a message, select a field like {name}.method"),
                column,
            )),
            _ => Err(Error::new(
                format!("undeclared reference to '{name}'"),
                column,
            )),
        },
        Kind::List(items) => list(items, column),
        Kind::Select(target, field) => select(target, field, column),
        Kind::Index(target, index) => element(target, index),
        Kind::Call { target, name, args } => call(target.as_deref(), name, args, column),
        Kind::Unary(Un::Not, arg) => Ok((
            Expr::Not(boxed(expect(arg, &Ty::Bool, "'!' takes a bool")?)),
            Ty::Bool,
        )),
        Kind::Unary(Un::Neg, arg) => Ok((
            Expr::Neg(boxed(expect(arg, &Ty::Int, "'-' takes an int")?)),
            Ty::Int,
        )),
        Kind::Binary(op, left, right) => binary(*op, left, right, column),
        Kind::Ternary(condition, then, otherwise) => {
            let condition = expect(condition, &Ty::Bool, "the condition of '?:' is a bool")?;
            let (then, then_ty) = check_node(then)?;
            let (otherwise, otherwise_ty) = check_node(otherwise)?;
            if then_ty != otherwise_ty {
                return Err(Error::new(
                    format!(
                        "type error: the branches of '?:' are a {} and a {}",
                        then_ty.name(),
                        otherwise_ty.name()
                    ),
                    column,
                ));
            }
            Ok((
                Expr::Ternary(boxed(condition), boxed(then), boxed(otherwise)),
                then_ty,
            ))
        }
    }
}

fn list(items: &[Node], column: usize) -> Result<Checked, Error> {
    let mut checked = Vec::with_capacity(items.len());
    let mut item_ty: Option<Ty> = None;
    for item in items {
        let (expr, ty) = check_node(item)?;
        match &item_ty {
            None => item_ty = Some(ty),
            Some(first) if *first == ty => {}
            Some(first) => {
                return Err(Error::new(
                    format!(
                        "type error: a list holds one type, found a {} and a {}",
                        first.name(),
                        ty.name()
                    ),
                    item.column,
                ));
            }
        }
        checked.push(expr);
    }
    let item_ty = item_ty.ok_or_else(|| {
        Error::new(
            "type error: an empty list has no type; write the test without it",
            column,
        )
    })?;
    Ok((Expr::List(checked), Ty::List(Box::new(item_ty))))
}

/// `request.field`, `tls.field` or `map.key`.
fn select(target: &Node, field: &str, column: usize) -> Result<Checked, Error> {
    if let Kind::Ident(name) = &target.kind {
        let var = match (&**name, field) {
            ("request", "method") => Some(Var::Method),
            ("request", "host") => Some(Var::Host),
            ("request", "path") => Some(Var::Path),
            ("request", "scheme") => Some(Var::Scheme),
            ("request", "client_ip") => Some(Var::ClientIp),
            ("request", "query") => Some(Var::Query),
            ("request", "headers") => Some(Var::Headers),
            ("tls", "sni") => Some(Var::Sni),
            ("tls", "version") => Some(Var::TlsVersion),
            ("request" | "tls", _) => {
                return Err(Error::new(
                    format!("undeclared reference to '{name}.{field}'"),
                    column,
                ));
            }
            _ => None,
        };
        if let Some(var) = var {
            return Ok((Expr::Var(var), var.ty()));
        }
    }
    let (expr, ty) = check_node(target)?;
    if ty == Ty::Map {
        Ok((
            Expr::Index(boxed(expr), boxed(Expr::Str(field.into()))),
            Ty::Str,
        ))
    } else {
        Err(mismatch(
            &format!("'.{field}' selects from a map"),
            &ty,
            column,
        ))
    }
}

fn element(target: &Node, index: &Node) -> Result<Checked, Error> {
    let (container, ty) = check_node(target)?;
    match ty {
        Ty::Map => {
            let key = expect(index, &Ty::Str, "a map key is a string")?;
            Ok((Expr::Index(boxed(container), boxed(key)), Ty::Str))
        }
        Ty::List(item) => {
            let position = expect(index, &Ty::Int, "a list index is an int")?;
            Ok((Expr::Index(boxed(container), boxed(position)), *item))
        }
        other => Err(mismatch(
            "only a map or a list can be indexed",
            &other,
            target.column,
        )),
    }
}

fn comprehension(name: &str, column: usize) -> Error {
    Error::new(
        format!(
            "cel_comprehension: '{name}' loops over its input and is not available; test the value directly"
        ),
        column,
    )
}

fn arity(name: &str, wanted: usize, args: &[Node], column: usize) -> Result<(), Error> {
    if args.len() == wanted {
        Ok(())
    } else {
        Err(Error::new(
            format!(
                "'{name}' takes {wanted} argument{}, found {}",
                if wanted == 1 { "" } else { "s" },
                args.len()
            ),
            column,
        ))
    }
}

fn literal<'a>(node: &'a Node, what: &str) -> Result<&'a str, Error> {
    match &node.kind {
        Kind::Str(text) => Ok(text),
        _ => Err(Error::new(
            format!("{what} must be a string literal: it is compiled when the snapshot is"),
            node.column,
        )),
    }
}

fn pattern(node: &Node) -> Result<regex::Regex, Error> {
    let text = literal(node, "the regular expression of 'matches'")?;
    super::super::regex("cel", text).map_err(|err| Error::new(err.message, node.column))
}

fn block(node: &Node) -> Result<Cidr, Error> {
    let text = literal(node, "the block of 'cidr'")?;
    text.parse()
        .map_err(|err| Error::new(format!("{err}"), node.column))
}

fn call(target: Option<&Node>, name: &str, args: &[Node], column: usize) -> Result<Checked, Error> {
    if target.is_some() && matches!(name, "all" | "exists" | "exists_one" | "map" | "filter") {
        return Err(comprehension(name, column));
    }
    match (target, name) {
        (None, "has") => {
            arity(name, 1, args, column)?;
            has(&args[0])
        }
        (None, "size") => {
            arity(name, 1, args, column)?;
            size(&args[0])
        }
        (Some(receiver), "size") => {
            arity(name, 0, args, column)?;
            size(receiver)
        }
        (None, "ip") => {
            arity(name, 1, args, column)?;
            ip(&args[0])
        }
        (None, "cidr") => {
            arity(name, 1, args, column)?;
            Ok((Expr::Cidr(block(&args[0])?), Ty::Cidr))
        }
        (None, "matches") => {
            arity(name, 2, args, column)?;
            let subject = expect(&args[0], &Ty::Str, "'matches' reads a string")?;
            Ok((Expr::Matches(boxed(subject), pattern(&args[1])?), Ty::Bool))
        }
        (Some(receiver), "matches") => {
            arity(name, 1, args, column)?;
            let subject = expect(receiver, &Ty::Str, "'matches' reads a string")?;
            Ok((Expr::Matches(boxed(subject), pattern(&args[0])?), Ty::Bool))
        }
        (Some(receiver), "startsWith" | "endsWith" | "contains") => {
            arity(name, 1, args, column)?;
            let scan = match name {
                "startsWith" => Scan::StartsWith,
                "endsWith" => Scan::EndsWith,
                _ => Scan::Contains,
            };
            let subject = expect(receiver, &Ty::Str, &format!("'{name}' reads a string"))?;
            let needle = expect(&args[0], &Ty::Str, &format!("'{name}' takes a string"))?;
            Ok((Expr::Scan(scan, boxed(subject), boxed(needle)), Ty::Bool))
        }
        (Some(receiver), "in_cidr") => {
            arity(name, 1, args, column)?;
            let address = expect(receiver, &Ty::Ip, "'in_cidr' is a method of ip")?;
            let block = match &args[0].kind {
                Kind::Str(_) => Expr::Cidr(block(&args[0])?),
                _ => expect(
                    &args[0],
                    &Ty::Cidr,
                    "'in_cidr' takes a cidr or a string literal",
                )?,
            };
            Ok((Expr::InCidr(boxed(address), boxed(block)), Ty::Bool))
        }
        (None, _) => Err(Error::new(
            format!("undeclared reference to function '{name}'"),
            column,
        )),
        (Some(_), _) => Err(Error::new(
            format!("undeclared reference to method '{name}'"),
            column,
        )),
    }
}

fn size(node: &Node) -> Result<Checked, Error> {
    let (expr, ty) = check_node(node)?;
    match ty {
        Ty::Str | Ty::List(_) | Ty::Map => Ok((Expr::Size(boxed(expr)), Ty::Int)),
        other => Err(mismatch(
            "'size' takes a string, a list or a map",
            &other,
            node.column,
        )),
    }
}

fn ip(node: &Node) -> Result<Checked, Error> {
    let (expr, ty) = check_node(node)?;
    if ty != Ty::Str {
        return Err(mismatch("'ip' takes a string", &ty, node.column));
    }
    Ok(match expr {
        Expr::Var(Var::ClientIp) => (Expr::ClientIp, Ty::Ip),
        other => (Expr::Ip(boxed(other)), Ty::Ip),
    })
}

/// `has(map.key)`: whether the map has the key.
fn has(node: &Node) -> Result<Checked, Error> {
    let Kind::Select(target, key) = &node.kind else {
        return Err(Error::new(
            "'has' takes a map key, like has(request.headers.etag)",
            node.column,
        ));
    };
    let (map, ty) = check_node(target)?;
    if ty != Ty::Map {
        return Err(mismatch(
            "'has' takes a key of request.headers or request.query",
            &ty,
            node.column,
        ));
    }
    Ok((
        Expr::Has(boxed(map), boxed(Expr::Str(key.clone()))),
        Ty::Bool,
    ))
}

fn binary(op: Bin, left: &Node, right: &Node, column: usize) -> Result<Checked, Error> {
    let (l, left_ty) = check_node(left)?;
    let (r, right_ty) = check_node(right)?;
    let both = |wanted: &Ty, what: &str| {
        if left_ty == *wanted && right_ty == *wanted {
            Ok(())
        } else {
            Err(Error::new(
                format!(
                    "type error: {what}, found {} and {}",
                    left_ty.name(),
                    right_ty.name()
                ),
                column,
            ))
        }
    };
    match op {
        Bin::Or | Bin::And => {
            both(&Ty::Bool, "'&&' and '||' take bools")?;
            let (l, r) = (boxed(l), boxed(r));
            Ok((
                if op == Bin::Or {
                    Expr::Or(l, r)
                } else {
                    Expr::And(l, r)
                },
                Ty::Bool,
            ))
        }
        Bin::Eq | Bin::Ne => {
            if left_ty != right_ty {
                return Err(Error::new(
                    format!(
                        "type error: no '==' or '!=' between a {} and a {}",
                        left_ty.name(),
                        right_ty.name()
                    ),
                    column,
                ));
            }
            if matches!(left_ty, Ty::Map | Ty::Cidr) {
                return Err(mismatch("this type cannot be compared", &left_ty, column));
            }
            Ok((Expr::Compare(op, boxed(l), boxed(r)), Ty::Bool))
        }
        Bin::Lt | Bin::Le | Bin::Gt | Bin::Ge => {
            if left_ty != right_ty || !matches!(left_ty, Ty::Int | Ty::Str) {
                return Err(Error::new(
                    format!(
                        "type error: '<', '<=', '>' and '>=' take two ints or two strings, found {} and {}",
                        left_ty.name(),
                        right_ty.name()
                    ),
                    column,
                ));
            }
            Ok((Expr::Compare(op, boxed(l), boxed(r)), Ty::Bool))
        }
        Bin::In => match &right_ty {
            Ty::List(item) if **item == left_ty => Ok((Expr::In(boxed(l), boxed(r)), Ty::Bool)),
            Ty::Map if left_ty == Ty::Str => Ok((Expr::In(boxed(l), boxed(r)), Ty::Bool)),
            _ => Err(Error::new(
                format!(
                    "type error: 'in' takes an element and a list of it, or a string and a map, found {} and {}",
                    left_ty.name(),
                    right_ty.name()
                ),
                column,
            )),
        },
        Bin::Add if left_ty == Ty::Str => {
            both(&Ty::Str, "'+' takes two strings or two ints")?;
            Ok((Expr::Arith(op, boxed(l), boxed(r)), Ty::Str))
        }
        Bin::Add | Bin::Sub | Bin::Mul | Bin::Div | Bin::Rem => {
            both(&Ty::Int, "arithmetic takes ints (and '+' two strings)")?;
            Ok((Expr::Arith(op, boxed(l), boxed(r)), Ty::Int))
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::parse::parse;
    use super::*;

    fn rejected(text: &str) -> String {
        let node = parse(text).expect("parses");
        check(&node).expect_err(text).message
    }

    #[test]
    fn names_outside_the_environment_are_undeclared() {
        for text in [
            "now > 1",
            "timestamp('2020-01-01T00:00:00Z') == 1",
            "request.headers.x == duration('1s')",
            "request.body == 'x'",
            "foo",
            "env('HOME') == 'x'",
            "request.path.getHours() == 1",
        ] {
            assert!(rejected(text).contains("undeclared reference"), "{text}");
        }
    }

    #[test]
    fn types_are_checked() {
        for text in [
            "request.method == 1",
            "request.method",
            "request",
            "request.headers == request.query",
            "1 < 'a'",
            "'a' + 1",
            "!'a'",
            "size(1) == 1",
            "has(request.method)",
            "[1, 'a'] == [1]",
            "[] == []",
            "request.method ? true : false",
            "request.headers[1] == 'x'",
            "ip(1).in_cidr('10.0.0.0/8')",
        ] {
            let message = rejected(text);
            assert!(
                message.contains("type error")
                    || message.contains("takes")
                    || message.contains("message"),
                "{text}: {message}"
            );
        }
    }

    #[test]
    fn regex_and_cidr_are_literals_that_compile() {
        assert!(rejected("request.path.matches(request.host)").contains("string literal"));
        assert!(rejected("request.path.matches('(')").contains("cel"));
        assert!(rejected("ip(request.client_ip).in_cidr(request.host)").contains("cidr"));
        assert!(rejected("ip('1.2.3.4').in_cidr('10.0.0.0/99')").contains("not an IP"));
    }

    #[test]
    fn comprehensions_are_refused() {
        for text in [
            "[1, 2].all(x, x > 0)",
            "[1].exists(x, x == 1)",
            "[1].exists_one(x, x == 1)",
            "[1].map(x, x)",
            "[1].filter(x, x > 0)",
        ] {
            assert!(rejected(text).contains("cel_comprehension"), "{text}");
        }
    }
}
