//! The options of one router, service or middleware, read one at a time.
//!
//! Every option that is read is marked. What nobody read is [`Reader::finish`]'s answer: an
//! unsupported label, named by its exact key. So a label that podgate does not understand can
//! never be dropped on the way, and a typo cannot turn a protection off.

use std::str::FromStr;

use super::problem::Problem;

struct Entry<'a> {
    /// The option's path below the object, lower case: `loadbalancer.server.port`.
    path: String,
    key: &'a str,
    value: &'a str,
    used: bool,
}

/// The options of one object.
pub(super) struct Reader<'a> {
    base: String,
    entries: Vec<Entry<'a>>,
    problems: Vec<Problem>,
}

impl<'a> Reader<'a> {
    /// `base` is the label prefix of the object, for the messages about options that are
    /// missing. `entries` are `(path, key, value)`.
    pub(super) fn new(base: String, entries: Vec<(String, &'a str, &'a str)>) -> Self {
        Self {
            base,
            entries: entries
                .into_iter()
                .map(|(path, key, value)| Entry {
                    path,
                    key,
                    value,
                    used: false,
                })
                .collect(),
            problems: Vec::new(),
        }
    }

    /// The key of the option `path`, or the one a missing option would have.
    pub(super) fn key_of(&self, path: &str) -> String {
        self.entries
            .iter()
            .find(|entry| entry.path == path)
            .map_or_else(
                || format!("{}.{path}", self.base),
                |entry| entry.key.to_owned(),
            )
    }

    /// Whether the option `path` was given, read or not.
    pub(super) fn has(&self, path: &str) -> bool {
        self.entries.iter().any(|entry| entry.path == path)
    }

    /// Records a problem with the object.
    pub(super) fn fail(&mut self, problem: Problem) {
        self.problems.push(problem);
    }

    /// Records that the option `path` is needed and absent.
    pub(super) fn missing(&mut self, path: &str, why: &str) {
        let key = self.key_of(path);
        self.problems.push(Problem::invalid(&key, why));
    }

    fn find(&mut self, path: &str) -> Option<(&'a str, &'a str)> {
        let entry = self.entries.iter_mut().find(|entry| entry.path == path)?;
        entry.used = true;
        Some((entry.key, entry.value))
    }

    /// The raw value of `path`.
    pub(super) fn text(&mut self, path: &str) -> Option<&'a str> {
        self.find(path).map(|(_, value)| value)
    }

    /// `true` or `false`, in any case.
    pub(super) fn boolean(&mut self, path: &str) -> Option<bool> {
        let (key, value) = self.find(path)?;
        match value.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                self.problems
                    .push(Problem::invalid(key, "must be true or false"));
                None
            }
        }
    }

    /// A whole number of type `T`.
    pub(super) fn number<T: FromStr>(&mut self, path: &str) -> Option<T> {
        let (key, value) = self.find(path)?;
        if let Ok(number) = value.trim().parse() {
            Some(number)
        } else {
            self.problems
                .push(Problem::invalid(key, "must be a whole number in range"));
            None
        }
    }

    /// A comma separated list, without blanks.
    pub(super) fn list(&mut self, path: &str) -> Option<Vec<&'a str>> {
        let (key, value) = self.find(path)?;
        let items: Vec<&str> = value.split(',').map(str::trim).collect();
        if items.iter().any(|item| item.is_empty()) {
            self.problems
                .push(Problem::invalid(key, "has an empty entry"));
            return None;
        }
        Some(items)
    }

    /// A duration in whole milliseconds.
    pub(super) fn millis(&mut self, path: &str) -> Option<u64> {
        let (key, value) = self.find(path)?;
        self.duration(key, value, 1_000_000)
    }

    /// A duration in whole seconds.
    pub(super) fn seconds(&mut self, path: &str) -> Option<u64> {
        let (key, value) = self.find(path)?;
        self.duration(key, value, 1_000_000_000)
    }

    fn duration(&mut self, key: &str, value: &str, unit_ns: u128) -> Option<u64> {
        match nanoseconds(value) {
            Ok(total) if total % unit_ns == 0 => {
                u64::try_from(total / unit_ns).ok().or_else(|| {
                    self.problems
                        .push(Problem::invalid(key, "is too long a duration"));
                    None
                })
            }
            Ok(_) => {
                let finest = if unit_ns == 1_000_000 {
                    "millisecond"
                } else {
                    "second"
                };
                self.problems.push(Problem::invalid(
                    key,
                    format!("podgate keeps durations in whole {finest}s here"),
                ));
                None
            }
            Err(why) => {
                self.problems.push(Problem::invalid(key, why));
                None
            }
        }
    }

    /// The options `<prefix>.<name>`, as `(name, value)`.
    pub(super) fn map(&mut self, prefix: &str) -> Vec<(String, &'a str)> {
        let start = format!("{prefix}.");
        let mut found = Vec::new();
        for entry in &mut self.entries {
            if let Some(name) = entry.path.strip_prefix(&start) {
                entry.used = true;
                found.push((name.to_owned(), entry.value));
            }
        }
        found
    }

    /// The key of the first option under `prefix`, if there is one; the options are marked read.
    pub(super) fn first_under(&mut self, prefix: &str) -> Option<&'a str> {
        let start = format!("{prefix}.");
        let mut first = None;
        for entry in &mut self.entries {
            if entry.path.starts_with(&start) || entry.path == prefix {
                entry.used = true;
                first.get_or_insert(entry.key);
            }
        }
        first
    }

    /// Refuses the option `path`, if given, as unsupported.
    pub(super) fn refuse(&mut self, path: &str, why: &str) {
        if let Some((key, _)) = self.find(path) {
            self.problems.push(Problem::unsupported_label(key, why));
        }
    }

    /// Refuses every option under `prefix` as unsupported.
    pub(super) fn refuse_under(&mut self, prefix: &str, why: &str) {
        if let Some(key) = self.first_under(prefix) {
            self.problems.push(Problem::unsupported_label(key, why));
        }
    }

    /// Whether any option is left that nobody read, or any problem was recorded.
    ///
    /// # Errors
    ///
    /// Every problem recorded, then one unsupported label for each option left unread.
    pub(super) fn finish(mut self) -> Result<(), Vec<Problem>> {
        for entry in &self.entries {
            if !entry.used {
                self.problems.push(Problem::unsupported_label(
                    entry.key,
                    "podgate has no equivalent of this label",
                ));
            }
        }
        if self.problems.is_empty() {
            Ok(())
        } else {
            Err(self.problems)
        }
    }
}

/// A Go duration (`10s`, `1m30s`, `250ms`), or a plain number of seconds, in nanoseconds.
fn nanoseconds(text: &str) -> Result<u128, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("is empty".to_owned());
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        return text
            .parse::<u128>()
            .map(|seconds| seconds.saturating_mul(1_000_000_000))
            .map_err(|_| "is not a duration".to_owned());
    }
    let mut total: u128 = 0;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(format!(
                "{text:?} is not a duration such as 10s, 250ms or 1m30s"
            ));
        }
        let amount: u128 = rest[..digits]
            .parse()
            .map_err(|_| format!("{text:?} is not a duration"))?;
        rest = &rest[digits..];
        let (unit, len): (u128, usize) = if rest.starts_with("ms") {
            (1_000_000, 2)
        } else if rest.starts_with("us") || rest.starts_with("µs") {
            (
                1_000,
                if rest.starts_with("us") {
                    2
                } else {
                    "µs".len()
                },
            )
        } else if rest.starts_with("ns") {
            (1, 2)
        } else if rest.starts_with('s') {
            (1_000_000_000, 1)
        } else if rest.starts_with('m') {
            (60_000_000_000, 1)
        } else if rest.starts_with('h') {
            (3_600_000_000_000, 1)
        } else {
            return Err(format!(
                "{text:?} is not a duration; use whole numbers with ns, us, ms, s, m or h"
            ));
        };
        total = total.saturating_add(amount.saturating_mul(unit));
        rest = &rest[len..];
    }
    Ok(total)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn go_durations() {
        assert_eq!(nanoseconds("10s"), Ok(10_000_000_000));
        assert_eq!(nanoseconds("1m30s"), Ok(90_000_000_000));
        assert_eq!(nanoseconds("250ms"), Ok(250_000_000));
        assert_eq!(nanoseconds("2"), Ok(2_000_000_000));
        assert_eq!(nanoseconds("1h"), Ok(3_600_000_000_000));
        assert!(nanoseconds("1.5s").is_err());
        assert!(nanoseconds("ten").is_err());
        assert!(nanoseconds("5x").is_err());
    }

    #[test]
    fn whole_unit_only() {
        let mut reader = Reader::new(
            "traefik.x".into(),
            vec![("a".into(), "traefik.x.a", "1500ms")],
        );
        assert_eq!(reader.seconds("a"), None);
        assert!(reader.finish().is_err());
    }

    #[test]
    fn unread_options_are_reported_with_their_key() {
        let reader = Reader::new(
            "traefik.x".into(),
            vec![("typo".into(), "traefik.x.TyPo", "1")],
        );
        let problems = reader.finish().expect_err("unread");
        assert_eq!(&*problems[0].key, "traefik.x.TyPo");
    }
}
