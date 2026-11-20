//! `Range` requests: one satisfiable byte range is a `206`, an unsatisfiable one a `416`, and
//! anything else (several ranges, another unit, broken syntax) is the whole file.
//!
//! RFC 9110 lets a server ignore `Range`. Several ranges are ignored on purpose: a multipart
//! answer lets one small request ask for the same bytes many times over.

/// What a `Range` header asks for, against a representation of a known length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// The whole representation: no `Range`, or one that is ignored.
    Full,
    /// Bytes `start..=end`, both inside the representation.
    Partial {
        /// First byte.
        start: u64,
        /// Last byte, inclusive.
        end: u64,
    },
    /// No byte of the representation is in the range: `416`.
    Unsatisfiable,
}

/// Decides what `header` (the value of `Range`, if the request had one) asks of a body of `len`
/// bytes.
#[must_use]
pub(super) fn plan(header: Option<&str>, len: u64) -> Plan {
    let Some(header) = header else {
        return Plan::Full;
    };
    let Some((unit, specs)) = header.split_once('=') else {
        return Plan::Full;
    };
    if !unit.trim().eq_ignore_ascii_case("bytes") {
        return Plan::Full;
    }
    let mut specs = specs
        .split(',')
        .map(str::trim)
        .filter(|spec| !spec.is_empty());
    let (Some(spec), None) = (specs.next(), specs.next()) else {
        return Plan::Full;
    };
    let Some((first, last)) = spec.split_once('-') else {
        return Plan::Full;
    };
    let (first, last) = (first.trim(), last.trim());
    let digits = |text: &str| {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u64>().ok())
            .flatten()
    };
    let (start, end) = match (digits(first), digits(last)) {
        // `-n`: the last n bytes.
        (None, Some(suffix)) if first.is_empty() => {
            if suffix == 0 || len == 0 {
                return Plan::Unsatisfiable;
            }
            (len.saturating_sub(suffix), len - 1)
        }
        // `a-`: from a to the end.
        (Some(start), None) if last.is_empty() => {
            if start >= len {
                return Plan::Unsatisfiable;
            }
            (start, len - 1)
        }
        // `a-b`.
        (Some(start), Some(end)) => {
            if start > end {
                return Plan::Full;
            }
            if start >= len {
                return Plan::Unsatisfiable;
            }
            (start, end.min(len - 1))
        }
        _ => return Plan::Full,
    };
    Plan::Partial { start, end }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn one_range_is_partial_and_is_clamped_to_the_length() {
        assert_eq!(
            plan(Some("bytes=0-3"), 10),
            Plan::Partial { start: 0, end: 3 }
        );
        assert_eq!(
            plan(Some("bytes=4-"), 10),
            Plan::Partial { start: 4, end: 9 }
        );
        assert_eq!(
            plan(Some("bytes=-3"), 10),
            Plan::Partial { start: 7, end: 9 }
        );
        assert_eq!(
            plan(Some("bytes=-30"), 10),
            Plan::Partial { start: 0, end: 9 }
        );
        assert_eq!(
            plan(Some("bytes=8-99"), 10),
            Plan::Partial { start: 8, end: 9 }
        );
        assert_eq!(
            plan(Some("Bytes = 1-2"), 10),
            Plan::Partial { start: 1, end: 2 }
        );
    }

    #[test]
    fn a_range_past_the_end_is_unsatisfiable() {
        assert_eq!(plan(Some("bytes=10-"), 10), Plan::Unsatisfiable);
        assert_eq!(plan(Some("bytes=20-30"), 10), Plan::Unsatisfiable);
        assert_eq!(plan(Some("bytes=-0"), 10), Plan::Unsatisfiable);
        assert_eq!(plan(Some("bytes=0-0"), 0), Plan::Unsatisfiable);
        assert_eq!(plan(Some("bytes=-5"), 0), Plan::Unsatisfiable);
    }

    #[test]
    fn several_ranges_other_units_and_broken_syntax_are_the_whole_file() {
        for header in [
            "bytes=0-1,3-4",
            "bytes=0-1, 3-4, 6-",
            "items=0-1",
            "bytes",
            "bytes=",
            "bytes=a-b",
            "bytes=5-2",
            "bytes=--3",
            "bytes=1",
            "bytes=-",
        ] {
            assert_eq!(plan(Some(header), 10), Plan::Full, "{header}");
        }
        assert_eq!(plan(None, 10), Plan::Full);
    }
}
