//! The CEL syntax of the subset podgate offers: a lexer and a recursive-descent parser that
//! build a [`Node`] tree. Nothing is evaluated here, and nothing is looked up: [`super::env`]
//! gives the names meaning.
//!
//! Supported: `true`, `false`, integer and string literals (single or double quoted, `r`-raw,
//! with the usual escapes), list literals, the operators `|| && ! - == != < <= > >= in + - * / %`,
//! the ternary `?:`, field selection, indexing, and calls (global and as a method). Not
//! supported, and refused with a position: floating point and unsigned numbers, `null`, bytes,
//! map and message literals, triple-quoted strings.

use std::fmt;

/// Deepest nesting the parser follows: bounds the recursion of a hostile expression.
const MAX_DEPTH: usize = 32;

/// Why an expression does not parse or check: a message and the 1-based column it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Error {
    pub(super) message: String,
    pub(super) column: usize,
}

impl Error {
    pub(super) fn new(message: impl Into<String>, column: usize) -> Self {
        Self {
            message: message.into(),
            column,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (column {})", self.message, self.column)
    }
}

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Bin {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

/// A prefix operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Un {
    Not,
    Neg,
}

/// One node of the syntax tree, with the column it starts at.
#[derive(Debug)]
pub(super) struct Node {
    pub(super) kind: Kind,
    pub(super) column: usize,
}

/// What a [`Node`] is.
#[derive(Debug)]
pub(super) enum Kind {
    Bool(bool),
    Int(i64),
    Str(Box<str>),
    Ident(Box<str>),
    List(Vec<Node>),
    Select(Box<Node>, Box<str>),
    Index(Box<Node>, Box<Node>),
    Call {
        target: Option<Box<Node>>,
        name: Box<str>,
        args: Vec<Node>,
    },
    Unary(Un, Box<Node>),
    Binary(Bin, Box<Node>, Box<Node>),
    Ternary(Box<Node>, Box<Node>, Box<Node>),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Int(i64),
    Str(Box<str>),
    Ident(Box<str>),
    /// `(`, `)`, `[`, `]`, `.`, `,`, `?`, `:`, `!`, `-`, `+`, `*`, `/`, `%`, `<`, `>`
    Punct(char),
    OrOr,
    AndAnd,
    EqEq,
    NotEq,
    LessEq,
    GreaterEq,
    End,
}

struct Lexer<'a> {
    text: &'a str,
    /// Byte offset of the next character.
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn column(&self, offset: usize) -> usize {
        self.text[..offset].chars().count() + 1
    }

    fn peek(&self) -> Option<char> {
        self.text[self.pos..].chars().next()
    }

    fn peek_second(&self) -> Option<char> {
        self.text[self.pos..].chars().nth(1)
    }

    fn bump(&mut self) -> Option<char> {
        let next = self.peek()?;
        self.pos += next.len_utf8();
        Some(next)
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Result<(Token, usize), Error> {
        while self.peek().is_some_and(char::is_whitespace) {
            self.bump();
        }
        let start = self.pos;
        let column = self.column(start);
        let Some(first) = self.bump() else {
            return Ok((Token::End, column));
        };
        let token = match first {
            '|' if self.eat('|') => Token::OrOr,
            '&' if self.eat('&') => Token::AndAnd,
            '=' if self.eat('=') => Token::EqEq,
            '!' if self.eat('=') => Token::NotEq,
            '<' if self.eat('=') => Token::LessEq,
            '>' if self.eat('=') => Token::GreaterEq,
            '(' | ')' | '[' | ']' | ',' | '?' | ':' | '!' | '-' | '+' | '*' | '/' | '%' | '<'
            | '>' => Token::Punct(first),
            '.' if !self.peek().is_some_and(|next| next.is_ascii_digit()) => Token::Punct('.'),
            '"' | '\'' => Token::Str(self.string(first, false, column)?.into()),
            digit if digit.is_ascii_digit() => self.number(start, column)?,
            'r' | 'R' if matches!(self.peek(), Some('"' | '\'')) => {
                let quote = self.bump().unwrap_or('"');
                Token::Str(self.string(quote, true, column)?.into())
            }
            letter if letter.is_ascii_alphabetic() || letter == '_' => {
                while self
                    .peek()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || next == '_')
                {
                    self.bump();
                }
                Token::Ident(self.text[start..self.pos].into())
            }
            other => {
                return Err(Error::new(
                    format!("syntax error: unexpected character {other:?}"),
                    column,
                ));
            }
        };
        Ok((token, column))
    }

    fn number(&mut self, start: usize, column: usize) -> Result<Token, Error> {
        let hex = self.text[start..].starts_with('0') && matches!(self.peek(), Some('x' | 'X'));
        let (radix, from) = if hex {
            self.bump();
            (16, self.pos)
        } else {
            (10, start)
        };
        while self
            .peek()
            .is_some_and(|next| next.is_ascii_hexdigit() && (hex || next.is_ascii_digit()))
        {
            self.bump();
        }
        if matches!(self.peek(), Some('.' | 'e' | 'E'))
            && self.peek_second().is_some_and(|next| next.is_ascii_digit())
        {
            return Err(Error::new(
                "floating point numbers are not available",
                column,
            ));
        }
        if matches!(self.peek(), Some('u' | 'U')) {
            return Err(Error::new("unsigned integers are not available", column));
        }
        i64::from_str_radix(&self.text[from..self.pos], radix)
            .map(Token::Int)
            .map_err(|_| Error::new("integer literal out of range or empty", column))
    }

    fn string(&mut self, quote: char, raw: bool, column: usize) -> Result<String, Error> {
        if self.peek() == Some(quote) && self.peek_second() == Some(quote) {
            return Err(Error::new(
                "triple-quoted strings are not available",
                column,
            ));
        }
        let mut out = String::new();
        loop {
            let at = self.column(self.pos);
            match self.bump() {
                None | Some('\n') => {
                    return Err(Error::new("syntax error: unterminated string", column));
                }
                Some(found) if found == quote => return Ok(out),
                Some('\\') if !raw => out.push(self.escape(at)?),
                Some(other) => out.push(other),
            }
        }
    }

    fn escape(&mut self, at: usize) -> Result<char, Error> {
        let bad = || Error::new("syntax error: invalid escape sequence", at);
        Ok(match self.bump().ok_or_else(bad)? {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'a' => '\u{7}',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'v' => '\u{b}',
            '\\' => '\\',
            '\'' => '\'',
            '"' => '"',
            '`' => '`',
            '?' => '?',
            'x' | 'X' => self.hex(2).ok_or_else(bad)?,
            'u' => self.hex(4).ok_or_else(bad)?,
            _ => return Err(bad()),
        })
    }

    fn hex(&mut self, digits: usize) -> Option<char> {
        let end = self.pos.checked_add(digits)?;
        let text = self.text.get(self.pos..end)?;
        let value = u32::from_str_radix(text, 16).ok()?;
        self.pos = end;
        char::from_u32(value)
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    token: Token,
    column: usize,
    depth: usize,
}

/// Parses `text` into a syntax tree.
///
/// # Errors
///
/// [`Error`] with the column of the first problem.
pub(super) fn parse(text: &str) -> Result<Node, Error> {
    let mut lexer = Lexer { text, pos: 0 };
    let (token, column) = lexer.next()?;
    let mut parser = Parser {
        lexer,
        token,
        column,
        depth: 0,
    };
    let root = parser.expression()?;
    if parser.token != Token::End {
        return Err(parser.unexpected());
    }
    Ok(root)
}

impl Parser<'_> {
    fn advance(&mut self) -> Result<Token, Error> {
        let (next, column) = self.lexer.next()?;
        self.column = column;
        Ok(std::mem::replace(&mut self.token, next))
    }

    fn unexpected(&self) -> Error {
        let found = match &self.token {
            Token::End => "the end of the expression".to_owned(),
            Token::Int(number) => number.to_string(),
            Token::Str(_) => "a string".to_owned(),
            Token::Ident(name) => format!("'{name}'"),
            Token::Punct(punct) => format!("'{punct}'"),
            Token::OrOr => "'||'".to_owned(),
            Token::AndAnd => "'&&'".to_owned(),
            Token::EqEq => "'=='".to_owned(),
            Token::NotEq => "'!='".to_owned(),
            Token::LessEq => "'<='".to_owned(),
            Token::GreaterEq => "'>='".to_owned(),
        };
        Error::new(format!("syntax error: unexpected {found}"), self.column)
    }

    fn is(&self, punct: char) -> bool {
        self.token == Token::Punct(punct)
    }

    fn expect(&mut self, punct: char) -> Result<(), Error> {
        if self.is(punct) {
            self.advance()?;
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::new(
                format!("the expression nests deeper than {MAX_DEPTH}"),
                self.column,
            ));
        }
        Ok(())
    }

    fn expression(&mut self) -> Result<Node, Error> {
        self.enter()?;
        let column = self.column;
        let condition = self.or()?;
        let node = if self.is('?') {
            self.advance()?;
            let then = self.or()?;
            self.expect(':')?;
            let otherwise = self.expression()?;
            Node {
                kind: Kind::Ternary(Box::new(condition), Box::new(then), Box::new(otherwise)),
                column,
            }
        } else {
            condition
        };
        self.depth -= 1;
        Ok(node)
    }

    fn binary(left: Node, op: Bin, right: Node) -> Node {
        Node {
            column: left.column,
            kind: Kind::Binary(op, Box::new(left), Box::new(right)),
        }
    }

    fn or(&mut self) -> Result<Node, Error> {
        let mut left = self.and()?;
        while self.token == Token::OrOr {
            self.advance()?;
            left = Self::binary(left, Bin::Or, self.and()?);
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Node, Error> {
        let mut left = self.relation()?;
        while self.token == Token::AndAnd {
            self.advance()?;
            left = Self::binary(left, Bin::And, self.relation()?);
        }
        Ok(left)
    }

    fn relation(&mut self) -> Result<Node, Error> {
        let mut left = self.addition()?;
        loop {
            let op = match &self.token {
                Token::EqEq => Bin::Eq,
                Token::NotEq => Bin::Ne,
                Token::LessEq => Bin::Le,
                Token::GreaterEq => Bin::Ge,
                Token::Punct('<') => Bin::Lt,
                Token::Punct('>') => Bin::Gt,
                Token::Ident(name) if &**name == "in" => Bin::In,
                _ => return Ok(left),
            };
            self.advance()?;
            left = Self::binary(left, op, self.addition()?);
        }
    }

    fn addition(&mut self) -> Result<Node, Error> {
        let mut left = self.multiplication()?;
        loop {
            let op = match self.token {
                Token::Punct('+') => Bin::Add,
                Token::Punct('-') => Bin::Sub,
                _ => return Ok(left),
            };
            self.advance()?;
            left = Self::binary(left, op, self.multiplication()?);
        }
    }

    fn multiplication(&mut self) -> Result<Node, Error> {
        let mut left = self.unary()?;
        loop {
            let op = match self.token {
                Token::Punct('*') => Bin::Mul,
                Token::Punct('/') => Bin::Div,
                Token::Punct('%') => Bin::Rem,
                _ => return Ok(left),
            };
            self.advance()?;
            left = Self::binary(left, op, self.unary()?);
        }
    }

    fn unary(&mut self) -> Result<Node, Error> {
        let column = self.column;
        let op = match self.token {
            Token::Punct('!') => Un::Not,
            Token::Punct('-') => Un::Neg,
            _ => return self.member(),
        };
        self.enter()?;
        self.advance()?;
        let arg = self.unary()?;
        self.depth -= 1;
        Ok(Node {
            kind: Kind::Unary(op, Box::new(arg)),
            column,
        })
    }

    fn member(&mut self) -> Result<Node, Error> {
        let mut node = self.primary()?;
        loop {
            let column = self.column;
            if self.is('.') {
                self.advance()?;
                let Token::Ident(name) = self.advance()? else {
                    return Err(Error::new(
                        "syntax error: a field or method name follows '.'",
                        column,
                    ));
                };
                node = if self.is('(') {
                    let args = self.arguments()?;
                    Node {
                        column: node.column,
                        kind: Kind::Call {
                            target: Some(Box::new(node)),
                            name,
                            args,
                        },
                    }
                } else {
                    Node {
                        column: node.column,
                        kind: Kind::Select(Box::new(node), name),
                    }
                };
            } else if self.is('[') {
                self.advance()?;
                let index = self.expression()?;
                self.expect(']')?;
                node = Node {
                    column: node.column,
                    kind: Kind::Index(Box::new(node), Box::new(index)),
                };
            } else {
                return Ok(node);
            }
        }
    }

    /// `(` arguments `)`; the current token is the `(`.
    fn arguments(&mut self) -> Result<Vec<Node>, Error> {
        self.expect('(')?;
        let mut args = Vec::new();
        if self.is(')') {
            self.advance()?;
            return Ok(args);
        }
        loop {
            args.push(self.expression()?);
            if self.is(',') {
                self.advance()?;
            } else {
                self.expect(')')?;
                return Ok(args);
            }
        }
    }

    fn primary(&mut self) -> Result<Node, Error> {
        let column = self.column;
        let kind = match self.token.clone() {
            Token::Int(number) => {
                self.advance()?;
                Kind::Int(number)
            }
            Token::Str(text) => {
                self.advance()?;
                Kind::Str(text)
            }
            Token::Ident(name) => match &*name {
                "true" | "false" => {
                    self.advance()?;
                    Kind::Bool(&*name == "true")
                }
                "null" => {
                    return Err(Error::new("null is not available", column));
                }
                "in" => return Err(self.unexpected()),
                _ => {
                    self.advance()?;
                    if self.is('(') {
                        Kind::Call {
                            target: None,
                            name,
                            args: self.arguments()?,
                        }
                    } else {
                        Kind::Ident(name)
                    }
                }
            },
            Token::Punct('(') => {
                self.advance()?;
                let inner = self.expression()?;
                self.expect(')')?;
                return Ok(inner);
            }
            Token::Punct('[') => {
                self.advance()?;
                let mut items = Vec::new();
                while !self.is(']') {
                    items.push(self.expression()?);
                    if self.is(',') {
                        self.advance()?;
                    } else if !self.is(']') {
                        return Err(self.unexpected());
                    }
                }
                self.advance()?;
                Kind::List(items)
            }
            Token::Punct('{') => return Err(self.unexpected()),
            _ => return Err(self.unexpected()),
        };
        Ok(Node { kind, column })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn fails(text: &str) -> Error {
        parse(text).expect_err(text)
    }

    #[test]
    fn parses_the_documented_forms() {
        for good in [
            "request.method == 'GET'",
            "request.headers['x-env'] == \"canary\" && !(1 + 2 * 3 > 4)",
            "request.path.startsWith('/a') ? true : false",
            "'a' in ['a', 'b']",
            "r'\\d+' == '\\\\d+'",
            "size(request.query) >= 0x10",
            "'\\u00e9\\x41\\n' == 'éA\\n'",
        ] {
            parse(good).unwrap_or_else(|err| panic!("{good}: {err}"));
        }
    }

    #[test]
    fn errors_carry_the_column() {
        assert_eq!(fails("request.method ==").column, 18);
        assert_eq!(fails("1 + * 2").column, 5);
        assert!(fails("a b").message.contains("unexpected 'b'"));
        assert!(fails("'abc").message.contains("unterminated"));
        assert!(fails("1.5").message.contains("floating point"));
        assert!(fails("3u").message.contains("unsigned"));
        assert!(fails("null").message.contains("null"));
        assert!(fails("a ~ b").message.contains("unexpected character"));
        assert!(fails("{}").message.contains("unexpected character"));
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = format!("{}1{}", "(".repeat(100), ")".repeat(100));
        assert!(fails(&deep).message.contains("nests deeper"));
        let nots = "!".repeat(100) + "true";
        assert!(fails(&nots).message.contains("nests deeper"));
    }
}
