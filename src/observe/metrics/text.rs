//! Prometheus text exposition helpers: label escaping, family headers, and the counter and
//! histogram families of [`Series`].

use std::fmt::Write as _;

use super::series::{BOUNDS, CLASSES, Series};
use crate::budget::Escaped;

/// Appends `name="value"` with the value escaped as the text format requires.
pub(super) fn label(out: &mut String, name: &str, value: &str) {
    // Writing to a `String` cannot fail.
    let _ = write!(out, "{name}=\"{}\"", Escaped(value));
}

/// The label set `a="x",b="y"` of `pairs`.
pub(super) fn labels(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (name, value) in pairs {
        if !out.is_empty() {
            out.push(',');
        }
        label(&mut out, name, value);
    }
    out
}

/// The `# HELP` and `# TYPE` lines of a family.
pub(super) fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    // Writing to a `String` cannot fail.
    let _ = write!(out, "# HELP {name} {help}\n# TYPE {name} {kind}\n");
}

/// One sample line: `name{labels} value`.
pub(super) fn sample(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
    // Writing to a `String` cannot fail.
    let _ = if labels.is_empty() {
        writeln!(out, "{name} {value}")
    } else {
        writeln!(out, "{name}{{{labels}}} {value}")
    };
}

/// A latency in microseconds as seconds, exact to the microsecond.
fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

/// The counter family `name` with one sample per status class a series has seen. `rows` are the
/// label sets and series to report.
pub(super) fn requests(out: &mut String, name: &str, help: &str, rows: &[(String, &Series)]) {
    header(out, name, "counter", help);
    for (labels, series) in rows {
        for (class, text) in CLASSES.iter().enumerate() {
            let count = series.class(class);
            if count == 0 {
                continue;
            }
            let mut all = labels.clone();
            if !all.is_empty() {
                all.push(',');
            }
            label(&mut all, "code_class", text);
            sample(out, name, &all, count);
        }
    }
}

/// The histogram family `name` for every series that has seen a request.
pub(super) fn duration(out: &mut String, name: &str, help: &str, rows: &[(String, &Series)]) {
    header(out, name, "histogram", help);
    for (labels, series) in rows {
        let buckets = series.buckets();
        let total: u64 = buckets.iter().sum();
        if total == 0 {
            continue;
        }
        let with_le = |le: &str| {
            let mut all = labels.clone();
            if !all.is_empty() {
                all.push(',');
            }
            label(&mut all, "le", le);
            all
        };
        let mut cumulative = 0;
        for ((_, le), count) in BOUNDS.iter().zip(buckets) {
            cumulative += count;
            sample(out, &format!("{name}_bucket"), &with_le(le), cumulative);
        }
        sample(out, &format!("{name}_bucket"), &with_le("+Inf"), total);
        sample(
            out,
            &format!("{name}_sum"),
            labels,
            seconds(series.sum_micros()),
        );
        sample(out, &format!("{name}_count"), labels, total);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(labels(&[("app", "a\"b\\c\nd")]), "app=\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn seconds_are_exact() {
        assert_eq!(seconds(0), "0.000000");
        assert_eq!(seconds(1_234_567), "1.234567");
        assert_eq!(seconds(10_000_000), "10.000000");
    }
}
