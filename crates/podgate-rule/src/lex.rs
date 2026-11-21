//! The tokens of a rule.

use crate::error::RuleError;

/// Longest rule accepted, in bytes. A label is a few hundred bytes in practice; the cap keeps a
/// hostile one from costing more than a parse.
pub(crate) const MAX_RULE_BYTES: usize = 16 * 1024;

/// One token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
}

/// The tokens of `rule`, each with the byte offset where it starts.
pub(crate) fn lex(rule: &str) -> Result<Vec<(Token, usize)>, RuleError> {
    if rule.len() > MAX_RULE_BYTES {
        return Err(RuleError::new(
            0,
            format!("the rule is longer than {MAX_RULE_BYTES} bytes"),
        ));
    }
    let mut tokens = Vec::new();
    let mut chars = rule.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let token = match ch {
            _ if ch.is_whitespace() => continue,
            '(' => Token::LParen,
            ')' => Token::RParen,
            ',' => Token::Comma,
            '&' | '|' => {
                if chars.next_if(|&(_, next)| next == ch).is_none() {
                    return Err(RuleError::new(
                        at,
                        format!("`{ch}` is not an operator, write `{ch}{ch}`"),
                    ));
                }
                if ch == '&' { Token::And } else { Token::Or }
            }
            '!' => {
                if chars.peek().is_some_and(|&(_, next)| next == '=') {
                    return Err(RuleError::new(at, "`!=` is not an operator"));
                }
                Token::Not
            }
            '`' => {
                let rest = &rule[at + 1..];
                let Some(end) = rest.find('`') else {
                    return Err(RuleError::new(at, "this backtick string is never closed"));
                };
                let text = rest[..end].to_owned();
                for _ in 0..text.chars().count() + 1 {
                    chars.next();
                }
                Token::Str(text)
            }
            '"' => Token::Str(quoted(at, &mut chars)?),
            _ if ch.is_ascii_alphabetic() || ch == '_' => {
                let mut name = String::from(ch);
                while let Some((_, next)) =
                    chars.next_if(|&(_, next)| next.is_ascii_alphanumeric() || next == '_')
                {
                    name.push(next);
                }
                Token::Ident(name)
            }
            _ => {
                return Err(RuleError::new(
                    at,
                    format!("unexpected character {ch:?} in the rule"),
                ));
            }
        };
        tokens.push((token, at));
    }
    Ok(tokens)
}

/// A double-quoted string whose opening quote is at `start`. The escapes are the Go ones podgate
/// needs; anything else is refused rather than guessed.
fn quoted(
    start: usize,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<String, RuleError> {
    let mut text = String::new();
    while let Some((at, ch)) = chars.next() {
        match ch {
            '"' => return Ok(text),
            '\\' => match chars.next() {
                Some((_, '\\')) => text.push('\\'),
                Some((_, '"')) => text.push('"'),
                Some((_, 'n')) => text.push('\n'),
                Some((_, 't')) => text.push('\t'),
                Some((_, 'r')) => text.push('\r'),
                Some((_, other)) => {
                    return Err(RuleError::new(
                        at,
                        format!("the escape `\\{other}` is not supported, use a backtick string"),
                    ));
                }
                None => break,
            },
            '\n' => {
                return Err(RuleError::new(
                    at,
                    "a double-quoted string cannot contain a line break",
                ));
            }
            other => text.push(other),
        }
    }
    Err(RuleError::new(start, "this string is never closed"))
}

#[cfg(test)]
mod test {
    use super::*;

    fn kinds(rule: &str) -> Vec<Token> {
        lex(rule)
            .expect("lexes")
            .into_iter()
            .map(|(token, _)| token)
            .collect()
    }

    #[test]
    fn both_quote_styles() {
        assert_eq!(kinds("`a b`"), [Token::Str("a b".into())]);
        assert_eq!(kinds(r#""a\"b\\""#), [Token::Str("a\"b\\".into())]);
    }

    #[test]
    fn multibyte_backtick_strings_keep_the_offsets() {
        let tokens = lex("Path(`/é`) && Host(`a`)").expect("lexes");
        assert_eq!(tokens[2].0, Token::Str("/é".into()));
        assert_eq!(tokens[4], (Token::And, 12));
    }

    #[test]
    fn single_operators_are_refused() {
        assert!(lex("a & b").is_err());
        assert!(lex("a | b").is_err());
        assert!(lex("a != b").is_err());
    }
}
