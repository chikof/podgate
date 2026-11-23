//! A walk over the tokens of a JSON document that a rule can match, as byte spans of the
//! original text, so a rewrite replaces only those spans and copies everything else as it came.
//!
//! The walk assumes valid JSON: [`Rules::scan`](super::rules::Rules::scan) runs the document
//! through `serde_json` first, which checks the grammar, UTF-8 and the nesting depth. Nothing
//! here allocates per token.

/// The most containers that may be open at once: the nesting `serde_json` itself parses.
pub(super) const MAX_DEPTH: usize = 128;

/// What a token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// An object key.
    Key,
    /// A string value.
    Str,
    /// A number.
    Num,
}

/// One token: its kind and its byte span in the document (a string includes its quotes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Token {
    pub(super) kind: Kind,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// The tokens of a valid JSON document, in order. `true`, `false` and `null` are skipped.
#[derive(Debug)]
pub(super) struct Tokens<'a> {
    body: &'a [u8],
    at: usize,
    /// One entry per open container: `true` for an object.
    open: Vec<bool>,
    /// Whether the next string is an object key.
    key: bool,
    /// Whether the document nests deeper than [`MAX_DEPTH`]; the walk stops there.
    deep: bool,
}

impl<'a> Tokens<'a> {
    pub(super) fn new(body: &'a [u8]) -> Self {
        Self {
            body,
            at: 0,
            open: Vec::new(),
            key: false,
            deep: false,
        }
    }

    /// Whether the walk stopped because the document nests past [`MAX_DEPTH`].
    pub(super) fn too_deep(&self) -> bool {
        self.deep
    }

    /// The end (exclusive) of the string that starts at `start`, past its closing quote.
    fn string_end(&self, start: usize) -> usize {
        let mut at = start + 1;
        while let Some(byte) = self.body.get(at) {
            match byte {
                b'\\' => at += 2,
                b'"' => return at + 1,
                _ => at += 1,
            }
        }
        self.body.len()
    }

    /// The end (exclusive) of the scalar that starts at `start`.
    fn scalar_end(&self, start: usize) -> usize {
        let mut at = start;
        while let Some(byte) = self.body.get(at) {
            if matches!(
                byte,
                b',' | b':' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n'
            ) {
                break;
            }
            at += 1;
        }
        at
    }
}

impl Iterator for Tokens<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        while let Some(&byte) = self.body.get(self.at) {
            let start = self.at;
            match byte {
                b'{' => {
                    if self.open.len() >= MAX_DEPTH {
                        self.deep = true;
                        return None;
                    }
                    self.open.push(true);
                    self.key = true;
                    self.at += 1;
                }
                b'[' => {
                    if self.open.len() >= MAX_DEPTH {
                        self.deep = true;
                        return None;
                    }
                    self.open.push(false);
                    self.key = false;
                    self.at += 1;
                }
                b'}' | b']' => {
                    self.open.pop();
                    self.key = false;
                    self.at += 1;
                }
                b',' => {
                    self.key = self.open.last().copied().unwrap_or(false);
                    self.at += 1;
                }
                b':' => {
                    self.key = false;
                    self.at += 1;
                }
                b'"' => {
                    let end = self.string_end(start);
                    self.at = end;
                    let kind = if self.key { Kind::Key } else { Kind::Str };
                    return Some(Token { kind, start, end });
                }
                b' ' | b'\t' | b'\r' | b'\n' => self.at += 1,
                _ => {
                    let end = self.scalar_end(start);
                    self.at = end.max(start + 1);
                    if byte == b'-' || byte.is_ascii_digit() {
                        return Some(Token {
                            kind: Kind::Num,
                            start,
                            end,
                        });
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn spans(text: &str) -> Vec<(Kind, &str)> {
        Tokens::new(text.as_bytes())
            .map(|token| (token.kind, &text[token.start..token.end]))
            .collect()
    }

    #[test]
    fn tokens_tell_keys_from_values() {
        assert_eq!(
            spans(r#" {"a": "b", "c": [1, -2.5e3, "d", true, null], "e": {"f": 7}} "#),
            [
                (Kind::Key, r#""a""#),
                (Kind::Str, r#""b""#),
                (Kind::Key, r#""c""#),
                (Kind::Num, "1"),
                (Kind::Num, "-2.5e3"),
                (Kind::Str, r#""d""#),
                (Kind::Key, r#""e""#),
                (Kind::Key, r#""f""#),
                (Kind::Num, "7"),
            ]
        );
    }

    #[test]
    fn tokens_skip_escaped_quotes_and_read_scalars_at_the_top() {
        assert_eq!(
            spans(r#"["a\"b", "\\", "\u0022"]"#),
            [
                (Kind::Str, r#""a\"b""#),
                (Kind::Str, r#""\\""#),
                (Kind::Str, r#""\u0022""#),
            ]
        );
        assert_eq!(spans(r#""x""#), [(Kind::Str, r#""x""#)]);
        assert_eq!(spans("42"), [(Kind::Num, "42")]);
        assert!(spans("null").is_empty());
        assert_eq!(
            spans(r#"{"a":{"b":"c"},"d":"e"}"#),
            [
                (Kind::Key, r#""a""#),
                (Kind::Key, r#""b""#),
                (Kind::Str, r#""c""#),
                (Kind::Key, r#""d""#),
                (Kind::Str, r#""e""#),
            ]
        );
    }

    #[test]
    fn tokens_stop_at_the_depth_limit() {
        let nested = |depth: usize| format!("{}\"x\"{}", "[".repeat(depth), "]".repeat(depth));
        let ok = nested(MAX_DEPTH);
        let mut tokens = Tokens::new(ok.as_bytes());
        assert_eq!(tokens.by_ref().count(), 1);
        assert!(!tokens.too_deep());
        let deep = nested(MAX_DEPTH + 1);
        let mut tokens = Tokens::new(deep.as_bytes());
        assert_eq!(tokens.by_ref().count(), 0);
        assert!(tokens.too_deep());
    }
}
