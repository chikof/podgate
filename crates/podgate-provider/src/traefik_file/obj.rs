//! The tree of a Traefik file, read one option at a time.
//!
//! Every option that is read is marked. What nobody read is [`Obj::finish`]'s answer: an
//! unsupported option, named by its path in the file (`http.middlewares.m.plugin`). So an option
//! that podgate does not understand can never be dropped on the way. Keys are case-insensitive,
//! as in Traefik's file provider, and the path keeps the spelling of the file.

use std::cell::RefCell;
use std::path::PathBuf;

use serde_json::{Map, Value};

use crate::traefik::{Code, Problem};

/// What one conversion collects: the problems, and the files it read.
pub(super) struct Cx {
    problems: RefCell<Vec<Problem>>,
    files: RefCell<Vec<PathBuf>>,
    /// Where a relative file path is looked up: the directory of the Traefik file. `None` is
    /// the no-disk mode: no file reference is followed and none touches the filesystem.
    pub(super) dir: Option<PathBuf>,
}

impl Cx {
    pub(super) fn new(dir: Option<PathBuf>) -> Self {
        Self {
            problems: RefCell::new(Vec::new()),
            files: RefCell::new(Vec::new()),
            dir,
        }
    }

    /// Records a problem at `path`.
    pub(super) fn report(&self, code: Code, path: &str, reason: impl Into<Box<str>>) {
        self.problems.borrow_mut().push(Problem {
            code,
            key: path.into(),
            reason: reason.into(),
            fatal: false,
        });
    }

    pub(super) fn unsupported(&self, path: &str, reason: impl Into<Box<str>>) {
        self.report(Code::UnsupportedLabel, path, reason);
    }

    pub(super) fn invalid(&self, path: &str, reason: impl Into<Box<str>>) {
        self.report(Code::InvalidLabel, path, reason);
    }

    /// Records problems found by the label translator, with their keys moved to the file's.
    pub(super) fn adopt(&self, problems: Vec<Problem>, label: &str, file: &str) {
        let mut own = self.problems.borrow_mut();
        for mut problem in problems {
            let key = problem.key.strip_prefix("traefik.").unwrap_or(&problem.key);
            problem.key = match key.get(..label.len()) {
                Some(head) if head.eq_ignore_ascii_case(label) => {
                    format!("{file}{}", &key[label.len()..]).into()
                }
                _ => key.into(),
            };
            problem.fatal = false;
            own.push(problem);
        }
    }

    /// How many problems there are now. An object is rejected when the count moved while it was
    /// read.
    pub(super) fn mark(&self) -> usize {
        self.problems.borrow().len()
    }

    pub(super) fn clean_since(&self, mark: usize) -> bool {
        self.mark() == mark
    }

    /// Remembers that the file at `path` was read, so a source can watch it.
    pub(super) fn read_file(&self, path: PathBuf) {
        self.files.borrow_mut().push(path);
    }

    pub(super) fn finish(self) -> (Vec<Problem>, Vec<PathBuf>) {
        (self.problems.into_inner(), self.files.into_inner())
    }
}

struct Entry<'a> {
    lower: String,
    spelled: &'a str,
    value: &'a Value,
    used: bool,
}

/// The options of one object of the file.
pub(super) struct Obj<'a> {
    cx: &'a Cx,
    path: String,
    entries: Vec<Entry<'a>>,
}

impl<'a> Obj<'a> {
    /// The object at `path`. `null` is an object with no options (an empty YAML key); anything
    /// but a map is a problem and `None`.
    pub(super) fn new(cx: &'a Cx, path: String, value: &'a Value) -> Option<Self> {
        let map = match value {
            Value::Object(map) => Some(map),
            Value::Null => None,
            _ => {
                cx.invalid(&path, "must be a map");
                return None;
            }
        };
        let mut entries: Vec<Entry<'a>> = Vec::with_capacity(map.map_or(0, Map::len));
        for (spelled, value) in map.into_iter().flatten() {
            let lower = spelled.to_ascii_lowercase();
            if entries.iter().any(|entry| entry.lower == lower) {
                cx.invalid(&join(&path, spelled), "is given twice with different case");
                return None;
            }
            entries.push(Entry {
                lower,
                spelled,
                value,
                used: false,
            });
        }
        Some(Self { cx, path, entries })
    }

    pub(super) fn path(&self) -> &str {
        &self.path
    }

    /// The path of the option `key`, as the file spells it when it is there.
    pub(super) fn path_of(&self, key: &str) -> String {
        if key.is_empty() {
            return self.path.clone();
        }
        let lower = key.to_ascii_lowercase();
        let spelled = self
            .entries
            .iter()
            .find(|entry| entry.lower == lower)
            .map_or(key, |entry| entry.spelled);
        join(&self.path, spelled)
    }

    /// Whether the option is there, read or not, `null` included.
    pub(super) fn has(&self, key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        self.entries.iter().any(|entry| entry.lower == lower)
    }

    /// The one option of an object that has exactly one, as `(key as spelled, value)`: a
    /// middleware is one type, so it has one option, its type. Anything else is a problem.
    pub(super) fn sole(&mut self, what: &str) -> Option<(&'a str, &'a Value)> {
        if self.entries.len() != 1 {
            self.cx.invalid(
                &self.path,
                format!(
                    "has {} {what}; it must have exactly one",
                    self.entries.len()
                ),
            );
            for entry in &mut self.entries {
                entry.used = true;
            }
            return None;
        }
        let entry = &mut self.entries[0];
        entry.used = true;
        Some((entry.spelled, entry.value))
    }

    pub(super) fn cx(&self) -> &'a Cx {
        self.cx
    }

    pub(super) fn invalid(&self, key: &str, reason: impl Into<Box<str>>) {
        self.cx.invalid(&self.path_of(key), reason);
    }

    pub(super) fn unsupported(&self, key: &str, reason: impl Into<Box<str>>) {
        self.cx.unsupported(&self.path_of(key), reason);
    }

    /// The value of `key`, marked read. `null` counts as absent.
    pub(super) fn value(&mut self, key: &str) -> Option<&'a Value> {
        let lower = key.to_ascii_lowercase();
        let entry = self.entries.iter_mut().find(|entry| entry.lower == lower)?;
        entry.used = true;
        (!entry.value.is_null()).then_some(entry.value)
    }

    pub(super) fn text(&mut self, key: &str) -> Option<&'a str> {
        match self.value(key)? {
            Value::String(text) => Some(text),
            _ => {
                self.invalid(key, "must be text");
                None
            }
        }
    }

    pub(super) fn boolean(&mut self, key: &str) -> Option<bool> {
        match self.value(key)? {
            Value::Bool(flag) => Some(*flag),
            _ => {
                self.invalid(key, "must be true or false");
                None
            }
        }
    }

    pub(super) fn number<T: TryFrom<i64>>(&mut self, key: &str) -> Option<T> {
        let found = self.value(key)?.as_i64().and_then(|n| T::try_from(n).ok());
        if found.is_none() {
            self.invalid(key, "must be a whole number in range");
        }
        found
    }

    /// A list of texts. Any other shape is a problem.
    pub(super) fn texts(&mut self, key: &str) -> Option<Vec<&'a str>> {
        let Value::Array(items) = self.value(key)? else {
            self.invalid(key, "must be a list");
            return None;
        };
        let mut texts = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            if let Value::String(text) = item {
                texts.push(text.as_str());
            } else {
                self.cx
                    .invalid(&format!("{}[{index}]", self.path_of(key)), "must be text");
                return None;
            }
        }
        Some(texts)
    }

    /// The object at `key`, as an `Obj` with its own path.
    pub(super) fn child(&mut self, key: &str) -> Option<Obj<'a>> {
        let path = self.path_of(key);
        let value = self.value(key)?;
        Obj::new(self.cx, path, value)
    }

    /// The list of objects at `key`.
    pub(super) fn children(&mut self, key: &str) -> Option<Vec<Obj<'a>>> {
        let path = self.path_of(key);
        let Value::Array(items) = self.value(key)? else {
            self.invalid(key, "must be a list");
            return None;
        };
        let mut children = Vec::with_capacity(items.len());
        let mut sound = true;
        for (index, item) in items.iter().enumerate() {
            match Obj::new(self.cx, format!("{path}[{index}]"), item) {
                Some(child) => children.push(child),
                None => sound = false,
            }
        }
        sound.then_some(children)
    }

    /// The options of a map of named objects (`http.routers`), as `(name, value)`.
    pub(super) fn named(&mut self, key: &str) -> Vec<(&'a str, &'a Value)> {
        let path = self.path_of(key);
        match self.value(key) {
            Some(Value::Object(map)) => map
                .iter()
                .map(|(name, value)| (name.as_str(), value))
                .collect(),
            Some(_) => {
                self.cx.invalid(&path, "must be a map of names");
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    /// Refuses the option `key`, when given, as unsupported.
    pub(super) fn refuse(&mut self, key: &str, why: &str) {
        if self.value(key).is_some() {
            self.unsupported(key, why);
        }
    }

    /// Refuses `key` when it says something. `false`, `0` and an empty list or map are what
    /// Traefik reads as "off", which podgate does as well.
    pub(super) fn refuse_if_set(&mut self, key: &str, why: &str) {
        let set = match self.value(key) {
            None | Some(Value::Bool(false)) => false,
            Some(Value::Array(items)) => !items.is_empty(),
            Some(Value::Object(map)) => !map.is_empty(),
            Some(Value::Number(n)) => n.as_i64() != Some(0),
            Some(Value::String(text)) => !text.is_empty(),
            Some(_) => true,
        };
        if set {
            self.unsupported(key, why);
        }
    }

    /// Reports every option nobody read.
    pub(super) fn finish(self) {
        for entry in self.entries.iter().filter(|entry| !entry.used) {
            self.cx.unsupported(
                &join(&self.path, entry.spelled),
                "podgate has no equivalent of this option",
            );
        }
    }
}

/// `base.key`, or `key` at the root of the file.
fn join(base: &str, key: &str) -> String {
    if base.is_empty() {
        key.to_owned()
    } else {
        format!("{base}.{key}")
    }
}
