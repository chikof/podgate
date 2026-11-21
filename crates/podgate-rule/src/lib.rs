//! `podgate-rule`: Traefik v3 router rules as podgate matcher JSON.
//!
//! ```
//! use podgate_rule::{Dialect, parse};
//!
//! let rule = parse("Host(`a.test`) && PathPrefix(`/api`)", Dialect::Http)?;
//! assert_eq!(
//!     rule.matcher.expect("a matcher").to_string(),
//!     r#"{"all":[{"host":"a.test"},{"path_prefix":"/api"}]}"#
//! );
//! # Ok::<(), podgate_rule::RuleError>(())
//! ```
//!
//! The crate does no I/O and depends only on `serde_json` and `regex`, so the provider can
//! translate `traefik.*` labels with it and the daemon can read a rule string in a snapshot with
//! the same parser. A rule that podgate cannot express exactly is a [`RuleError`], never a
//! guess: a matcher that differs from the rule is a different set of reachable hosts.
//!
//! Reference: `docs/ref/provider-traefik.md`.

mod call;
mod error;
mod lex;
mod node;
mod parse;
mod regexp;
mod rule;

pub use error::RuleError;
pub use regexp::check_pattern;
pub use rule::{Dialect, Rule, parse};
