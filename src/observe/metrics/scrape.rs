//! Reads the Prometheus text that [`super::render`] writes back into families, so the OTLP
//! exporter ships exactly what a scrape shows.
//!
//! This reads podgate's own output, not arbitrary Prometheus: `# HELP` and `# TYPE` lines, then
//! `name{label="value",...} value` samples with the escapes `\\`, `\"` and `\n`. A histogram is
//! its `_bucket`, `_sum` and `_count` samples grouped by the label set without `le`. A line that
//! is none of these is skipped and counted, never guessed at.

use std::collections::HashMap;

/// What a family is, from its `# TYPE` line. An untyped family reads as a gauge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Counter,
    Gauge,
    Histogram,
}

/// A sample value: an integer when the text is one, else the float.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) enum Number {
    Int(i64),
    Double(f64),
}

/// One histogram: the finite upper bounds, one count per bucket (not cumulative, the last is the
/// overflow bucket, so there is one more count than bounds), the sum and the total.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Histogram {
    pub(super) bounds: Vec<f64>,
    pub(super) counts: Vec<u64>,
    pub(super) sum: f64,
    pub(super) count: u64,
}

/// What one label set holds.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Value {
    Number(Number),
    Histogram(Histogram),
}

/// One label set and its value.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Point {
    pub(super) labels: Vec<(String, String)>,
    pub(super) value: Value,
}

/// One metric name with its type, help and every label set the scrape had for it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Family {
    pub(super) name: String,
    pub(super) help: String,
    pub(super) kind: Kind,
    pub(super) points: Vec<Point>,
}

/// The families of a scrape, in first-seen order, and the lines that could not be read.
#[derive(Debug, Default)]
pub(super) struct Parsed {
    pub(super) families: Vec<Family>,
    pub(super) skipped: usize,
}

/// The samples of one histogram label set while its lines are still arriving.
#[derive(Debug, Default)]
struct Draft {
    labels: Vec<(String, String)>,
    /// `(le, cumulative count)` in the order they came; `+Inf` is `f64::INFINITY`.
    buckets: Vec<(f64, u64)>,
    sum: Option<f64>,
    count: Option<u64>,
}

struct Building {
    family: Family,
    drafts: Vec<Draft>,
}

/// The index of the family `name`, added when it is new.
fn entry(index: &mut HashMap<String, usize>, building: &mut Vec<Building>, name: &str) -> usize {
    *index.entry(name.to_owned()).or_insert_with(|| {
        building.push(Building {
            family: Family {
                name: name.to_owned(),
                help: String::new(),
                kind: Kind::Gauge,
                points: Vec::new(),
            },
            drafts: Vec::new(),
        });
        building.len() - 1
    })
}

/// The value after the label set: the first token, which is a number. A timestamp after it is
/// ignored.
fn number(text: &str) -> Option<Number> {
    let token = text.split_whitespace().next()?;
    match token.parse::<i64>() {
        Ok(int) => Some(Number::Int(int)),
        Err(_) => token.parse::<f64>().ok().map(Number::Double),
    }
}

fn as_f64(number: Number) -> f64 {
    match number {
        Number::Int(int) => int as f64,
        Number::Double(double) => double,
    }
}

fn as_u64(number: Number) -> Option<u64> {
    match number {
        Number::Int(int) => u64::try_from(int).ok(),
        Number::Double(_) => None,
    }
}

/// The label set of a sample, in the order printed.
type Labels = Vec<(String, String)>;

/// `name`, its labels and the text after them, from one sample line.
fn sample(line: &str) -> Option<(&str, Labels, &str)> {
    let name_end = line.find(['{', ' '])?;
    let (name, rest) = line.split_at(name_end);
    if name.is_empty() {
        return None;
    }
    let Some(inner) = rest.strip_prefix('{') else {
        return Some((name, Vec::new(), rest));
    };
    let mut labels = Vec::new();
    let mut chars = inner.char_indices().peekable();
    loop {
        while chars.next_if(|(_, c)| *c == ',' || *c == ' ').is_some() {}
        let (start, first) = *chars.peek()?;
        if first == '}' {
            let (end, _) = chars.next()?;
            return Some((name, labels, &inner[end + 1..]));
        }
        let key_end = loop {
            let (at, c) = chars.next()?;
            if c == '=' {
                break at;
            }
        };
        let key = &inner[start..key_end];
        if key.is_empty() || chars.next()?.1 != '"' {
            return None;
        }
        let mut value = String::new();
        loop {
            match chars.next()?.1 {
                '"' => break,
                '\\' => match chars.next()?.1 {
                    '\\' => value.push('\\'),
                    '"' => value.push('"'),
                    'n' => value.push('\n'),
                    _ => return None,
                },
                c => value.push(c),
            }
        }
        labels.push((key.to_owned(), value));
    }
}

fn draft<'a>(drafts: &'a mut Vec<Draft>, labels: &[(String, String)]) -> &'a mut Draft {
    let at = drafts
        .iter()
        .position(|draft| draft.labels == labels)
        .unwrap_or_else(|| {
            drafts.push(Draft {
                labels: labels.to_vec(),
                ..Draft::default()
            });
            drafts.len() - 1
        });
    &mut drafts[at]
}

/// The histogram a draft describes, `None` when it has no buckets and no count.
fn histogram(draft: &Draft) -> Option<Histogram> {
    let finite: Vec<(f64, u64)> = draft
        .buckets
        .iter()
        .copied()
        .filter(|(le, _)| le.is_finite())
        .collect();
    let infinite = draft
        .buckets
        .iter()
        .find(|(le, _)| *le == f64::INFINITY)
        .map(|(_, count)| *count);
    let count = draft.count.or(infinite)?;
    let mut counts = Vec::with_capacity(finite.len() + 1);
    let mut before = 0;
    for (_, cumulative) in &finite {
        counts.push(cumulative.saturating_sub(before));
        before = *cumulative;
    }
    counts.push(count.saturating_sub(before));
    Some(Histogram {
        bounds: finite.iter().map(|(le, _)| *le).collect(),
        counts,
        sum: draft.sum.unwrap_or_default(),
        count,
    })
}

/// Reads `text`.
pub(super) fn parse(text: &str) -> Parsed {
    let mut building: Vec<Building> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut skipped = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(rest) = line.strip_prefix("# HELP ") {
            if let Some((name, help)) = rest.split_once(' ') {
                let at = entry(&mut index, &mut building, name);
                building[at].family.help = help.to_owned();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let Some((name, kind)) = rest.split_once(' ') else {
                skipped += 1;
                continue;
            };
            let kind = match kind.trim() {
                "counter" => Kind::Counter,
                "gauge" | "untyped" => Kind::Gauge,
                "histogram" => Kind::Histogram,
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            let at = entry(&mut index, &mut building, name);
            building[at].family.kind = kind;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((name, labels, rest)) = sample(line) else {
            skipped += 1;
            continue;
        };
        let Some(value) = number(rest) else {
            skipped += 1;
            continue;
        };
        let exact = index.get(name).copied();
        if let Some(at) = exact
            && building[at].family.kind != Kind::Histogram
        {
            building[at].family.points.push(Point {
                labels,
                value: Value::Number(value),
            });
            continue;
        }
        let part = ["_bucket", "_sum", "_count"]
            .into_iter()
            .find_map(|suffix| {
                let base = name.strip_suffix(suffix)?;
                let at = index.get(base).copied()?;
                (building[at].family.kind == Kind::Histogram).then_some((at, suffix))
            });
        let Some((at, suffix)) = part else {
            if exact.is_none() {
                let at = entry(&mut index, &mut building, name);
                building[at].family.points.push(Point {
                    labels,
                    value: Value::Number(value),
                });
            } else {
                skipped += 1;
            }
            continue;
        };
        let mut labels = labels;
        let le = labels
            .iter()
            .position(|(key, _)| key == "le")
            .map(|at| labels.remove(at).1);
        let draft = draft(&mut building[at].drafts, &labels);
        match suffix {
            "_bucket" => {
                let bound = le.as_deref().and_then(|le| le.parse::<f64>().ok());
                match (bound, as_u64(value)) {
                    (Some(bound), Some(count)) => draft.buckets.push((bound, count)),
                    _ => skipped += 1,
                }
            }
            "_sum" => draft.sum = Some(as_f64(value)),
            _ => match as_u64(value) {
                Some(count) => draft.count = Some(count),
                None => skipped += 1,
            },
        }
    }
    let families = building
        .into_iter()
        .filter_map(|mut done| {
            for draft in &done.drafts {
                match histogram(draft) {
                    Some(histogram) => done.family.points.push(Point {
                        labels: draft.labels.clone(),
                        value: Value::Histogram(histogram),
                    }),
                    None => skipped += 1,
                }
            }
            (!done.family.points.is_empty()).then_some(done.family)
        })
        .collect();
    Parsed { families, skipped }
}

#[cfg(test)]
mod test {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn prometheus_text_counters_and_gauges_keep_type_help_and_labels() {
        let parsed = parse(
            "# HELP podgate_a_total Things.\n# TYPE podgate_a_total counter\n\
             podgate_a_total{app=\"x\",code_class=\"2xx\"} 7\n\
             podgate_a_total{app=\"y\",code_class=\"5xx\"} 1\n\
             # HELP podgate_g A gauge.\n# TYPE podgate_g gauge\npodgate_g 1.5\n",
        );
        assert_eq!(parsed.skipped, 0);
        assert_eq!(parsed.families.len(), 2);
        let counter = &parsed.families[0];
        assert_eq!(
            (counter.name.as_str(), counter.kind),
            ("podgate_a_total", Kind::Counter)
        );
        assert_eq!(counter.help, "Things.");
        assert_eq!(counter.points.len(), 2);
        assert_eq!(
            counter.points[0].labels,
            labels(&[("app", "x"), ("code_class", "2xx")])
        );
        assert_eq!(counter.points[0].value, Value::Number(Number::Int(7)));
        assert_eq!(
            parsed.families[1].points[0].value,
            Value::Number(Number::Double(1.5))
        );
    }

    #[test]
    fn prometheus_text_label_escapes_are_undone() {
        let parsed = parse("# TYPE m gauge\nm{a=\"q\\\"b\\\\c\\nd\",e=\"\"} 1\n");
        assert_eq!(parsed.skipped, 0);
        assert_eq!(
            parsed.families[0].points[0].labels,
            labels(&[("a", "q\"b\\c\nd"), ("e", "")])
        );
    }

    #[test]
    fn prometheus_text_histograms_are_regrouped_by_label_set() {
        let parsed = parse(
            "# HELP d Latency.\n# TYPE d histogram\n\
             d_bucket{app=\"x\",le=\"0.005\"} 1\n\
             d_bucket{app=\"x\",le=\"0.01\"} 3\n\
             d_bucket{app=\"x\",le=\"+Inf\"} 4\n\
             d_sum{app=\"x\"} 0.250000\n\
             d_count{app=\"x\"} 4\n\
             d_bucket{app=\"y\",le=\"0.005\"} 0\n\
             d_bucket{app=\"y\",le=\"0.01\"} 0\n\
             d_bucket{app=\"y\",le=\"+Inf\"} 2\n\
             d_sum{app=\"y\"} 30.000000\n\
             d_count{app=\"y\"} 2\n",
        );
        assert_eq!(parsed.skipped, 0);
        let family = &parsed.families[0];
        assert_eq!(family.kind, Kind::Histogram);
        assert_eq!(family.points.len(), 2);
        assert_eq!(family.points[0].labels, labels(&[("app", "x")]));
        assert_eq!(
            family.points[0].value,
            Value::Histogram(Histogram {
                bounds: vec![0.005, 0.01],
                counts: vec![1, 2, 1],
                sum: 0.25,
                count: 4,
            })
        );
        assert_eq!(
            family.points[1].value,
            Value::Histogram(Histogram {
                bounds: vec![0.005, 0.01],
                counts: vec![0, 0, 2],
                sum: 30.0,
                count: 2,
            })
        );
    }

    #[test]
    fn prometheus_text_a_family_named_twice_is_merged_and_an_empty_one_dropped() {
        let parsed = parse(
            "# TYPE a counter\na{x=\"1\"} 1\n# TYPE empty counter\n# TYPE a counter\na{x=\"2\"} 2\n",
        );
        assert_eq!(parsed.families.len(), 1);
        assert_eq!(parsed.families[0].points.len(), 2);
    }

    #[test]
    fn prometheus_text_untyped_samples_read_as_gauges_and_bad_lines_are_counted() {
        let parsed = parse("bare 3\nbroken{a=\"b\n# TYPE x flavour\nm{a=b} 1\nok{a=\"b\"} nope\n");
        assert_eq!(parsed.families.len(), 1);
        assert_eq!(parsed.families[0].kind, Kind::Gauge);
        assert_eq!(parsed.skipped, 4);
    }
}
