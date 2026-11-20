//! The order in which matching routers win.

use std::cmp::Ordering;

use super::matcher::Spec;

/// The order of one matching router: larger wins. Compared field by field: explicit priority,
/// host rank (exact `3`, wildcard `2`, regexp `1`, none `0`), then the specificity of the rest of
/// the matcher. Ties are broken by `(app id, router name)` with [`Key::cmp_with`], smaller first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    priority: i32,
    host: u8,
    spec: Spec,
}

impl Key {
    pub(super) fn new(priority: i32, host: u8, spec: Spec) -> Self {
        Self {
            priority,
            host,
            spec,
        }
    }

    /// Orders two matches: [`Ordering::Greater`] when the first wins. Equal keys fall back to the
    /// names, so the answer never depends on declaration order.
    #[must_use]
    pub fn cmp_with(self, names: (&str, &str), other: Self, other_names: (&str, &str)) -> Ordering {
        self.cmp(&other).then_with(|| other_names.cmp(&names))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn spec(path: u32) -> Spec {
        Spec { path, others: 0 }
    }

    #[test]
    fn priority_beats_host_beats_specificity() {
        let high = Key::new(1, 0, spec(0));
        let exact = Key::new(0, 3, spec(0));
        assert_eq!(high.cmp(&exact), Ordering::Greater);
        let specific = Key::new(0, 2, spec(9));
        assert_eq!(exact.cmp(&specific), Ordering::Greater);
        assert_eq!(
            Key::new(0, 2, spec(9)).cmp(&Key::new(0, 2, spec(1))),
            Ordering::Greater
        );
    }

    #[test]
    fn equal_keys_prefer_the_smaller_names() {
        let key = Key::new(0, 3, spec(0));
        assert_eq!(key.cmp_with(("a", "x"), key, ("b", "x")), Ordering::Greater);
        assert_eq!(key.cmp_with(("a", "y"), key, ("a", "x")), Ordering::Less);
    }
}
