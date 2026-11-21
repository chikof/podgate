//! Names of the objects of the file, and the references to them.
//!
//! A Traefik name may carry the provider that defines it: `auth@file`. In a file, `@file` is
//! this file and any other provider is somebody else's object, which podgate cannot see: it is
//! rejected, never guessed.

use std::collections::BTreeSet;

use super::obj::Cx;
use crate::traefik::Code;

const MAX_NAME: usize = 63;

/// The provider of the file itself.
const OWN_PROVIDER: &str = "file";

/// What is known about the objects of one kind: built, rejected, or not built yet.
#[derive(Default)]
pub(super) struct Names {
    good: BTreeSet<String>,
    bad: BTreeSet<String>,
    waiting: BTreeSet<String>,
}

/// What a reference came to.
pub(super) enum Resolved {
    /// An object that was built.
    Found(String),
    /// An object that was rejected, or no object: the problem is recorded.
    Missing,
    /// An object of the same kind that is not built yet.
    Waiting,
}

impl Names {
    /// Announces an object that will be built.
    pub(super) fn expect(&mut self, name: &str) {
        self.waiting.insert(name.to_owned());
    }

    /// Records the outcome for an announced object.
    pub(super) fn settle(&mut self, name: &str, built: bool) {
        self.waiting.remove(name);
        if built {
            self.good.insert(name.to_owned());
        } else {
            self.bad.insert(name.to_owned());
        }
    }

    /// Resolves the reference `raw` found at `at`. `what` names the kind for the message.
    pub(super) fn resolve(&self, cx: &Cx, at: &str, raw: &str, what: &str) -> Resolved {
        let (name, provider) = match raw.split_once('@') {
            Some((name, provider)) => (name, Some(provider)),
            None => (raw, None),
        };
        if provider.is_some_and(|provider| !provider.eq_ignore_ascii_case(OWN_PROVIDER)) {
            cx.report(
                Code::ForeignReference,
                at,
                format!(
                    "{raw:?} is defined by another provider; names resolve inside the file, and only `@file` is this file"
                ),
            );
            return Resolved::Missing;
        }
        if self.good.contains(name) {
            Resolved::Found(name.to_owned())
        } else if self.waiting.contains(name) {
            Resolved::Waiting
        } else if self.bad.contains(name) {
            cx.unsupported(
                at,
                format!("the {what} {name:?} was not translated, see its own problems"),
            );
            Resolved::Missing
        } else {
            cx.invalid(at, format!("names no {what} of this file: {name:?}"));
            Resolved::Missing
        }
    }
}

/// Whether `name` can be an object name in podgate, with the problem recorded when it cannot.
pub(super) fn valid_name(cx: &Cx, at: &str, name: &str) -> bool {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        cx.invalid(
            at,
            format!("the name {name:?} must be 1 to {MAX_NAME} letters, digits, `-` or `_`"),
        );
    }
    valid
}
