//! The recursive-descent parser: `||` binds loosest, then `&&`, then `!`.

use crate::call::call;
use crate::error::RuleError;
use crate::lex::Token;
use crate::node::Node;
use crate::rule::Dialect;

/// How deep parentheses and `!` may nest. The daemon allows eight levels of matcher; this only
/// keeps the parser's own recursion bounded.
const MAX_DEPTH: usize = 64;

pub(crate) struct Parser {
    tokens: Vec<(Token, usize)>,
    next: usize,
    end: usize,
    dialect: Dialect,
    depth: usize,
    pub(crate) regexes: Vec<Box<str>>,
}

impl Parser {
    pub(crate) fn new(tokens: Vec<(Token, usize)>, end: usize, dialect: Dialect) -> Self {
        Self {
            tokens,
            next: 0,
            end,
            dialect,
            depth: 0,
            regexes: Vec::new(),
        }
    }

    /// The whole rule.
    pub(crate) fn rule(&mut self) -> Result<Node, RuleError> {
        let node = self.or()?;
        match self.tokens.get(self.next) {
            None => Ok(node),
            Some((token, at)) => Err(RuleError::new(
                *at,
                format!(
                    "expected `&&`, `||` or the end of the rule, found {}",
                    show(token)
                ),
            )),
        }
    }

    fn at(&self) -> usize {
        self.tokens.get(self.next).map_or(self.end, |(_, at)| *at)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.next).map(|(token, _)| token)
    }

    fn eat(&mut self, token: &Token) -> bool {
        let found = self.peek() == Some(token);
        if found {
            self.next += 1;
        }
        found
    }

    fn or(&mut self) -> Result<Node, RuleError> {
        let mut items = vec![self.and()?];
        while self.eat(&Token::Or) {
            items.push(self.and()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::Any(items)
        })
    }

    fn and(&mut self) -> Result<Node, RuleError> {
        let mut items = vec![self.unary()?];
        while self.eat(&Token::And) {
            items.push(self.unary()?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::All(items)
        })
    }

    fn unary(&mut self) -> Result<Node, RuleError> {
        if self.depth >= MAX_DEPTH {
            return Err(RuleError::new(self.at(), "the rule nests too deeply"));
        }
        self.depth += 1;
        let node = self.operand();
        self.depth -= 1;
        node
    }

    fn operand(&mut self) -> Result<Node, RuleError> {
        let at = self.at();
        match self.tokens.get(self.next).cloned() {
            Some((Token::Not, _)) => {
                self.next += 1;
                Ok(Node::Not(Box::new(self.unary()?)))
            }
            Some((Token::LParen, _)) => {
                self.next += 1;
                let node = self.or()?;
                if self.eat(&Token::RParen) {
                    Ok(node)
                } else {
                    Err(RuleError::new(self.at(), "expected `)`"))
                }
            }
            Some((Token::Ident(name), _)) => {
                self.next += 1;
                if !self.eat(&Token::LParen) {
                    return Err(RuleError::new(
                        self.at(),
                        format!("expected `(` after the function name {name}"),
                    ));
                }
                let args = self.arguments()?;
                call(self.dialect, &name, args, at, &mut self.regexes)
            }
            Some((token, at)) => Err(RuleError::new(
                at,
                format!("expected a function, `!` or `(`, found {}", show(&token)),
            )),
            None => Err(RuleError::new(
                at,
                "the rule ends where an operand is expected",
            )),
        }
    }

    fn arguments(&mut self) -> Result<Vec<String>, RuleError> {
        let mut args = Vec::new();
        if self.eat(&Token::RParen) {
            return Ok(args);
        }
        loop {
            match self.tokens.get(self.next).cloned() {
                Some((Token::Str(text), _)) => {
                    self.next += 1;
                    args.push(text);
                }
                Some((token, at)) => {
                    return Err(RuleError::new(
                        at,
                        format!("expected a quoted argument, found {}", show(&token)),
                    ));
                }
                None => {
                    return Err(RuleError::new(self.at(), "the arguments are never closed"));
                }
            }
            if self.eat(&Token::RParen) {
                return Ok(args);
            }
            if !self.eat(&Token::Comma) {
                return Err(RuleError::new(self.at(), "expected `,` or `)`"));
            }
        }
    }
}

fn show(token: &Token) -> String {
    match token {
        Token::Ident(name) => format!("`{name}`"),
        Token::Str(_) => "a string".to_owned(),
        Token::LParen => "`(`".to_owned(),
        Token::RParen => "`)`".to_owned(),
        Token::Comma => "`,`".to_owned(),
        Token::And => "`&&`".to_owned(),
        Token::Or => "`||`".to_owned(),
        Token::Not => "`!`".to_owned(),
    }
}
