//! RFC 3339 timestamps for the fields the source writes: condition times and Lease times.

use std::time::SystemTime;

/// The year, month and day of `days` since 1970-01-01 (Howard Hinnant's civil-from-days).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn date_time(secs: u64) -> String {
    let secs = i64::try_from(secs).unwrap_or(i64::MAX / 2);
    let (year, month, day) = civil(secs.div_euclid(86_400));
    let in_day = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        in_day / 3600,
        in_day % 3600 / 60,
        in_day % 60
    )
}

/// `now` as a `metav1.Time`: `2026-11-21T10:00:00Z`.
#[must_use]
pub fn time(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    format!("{}Z", date_time(secs))
}

/// `now` as a `metav1.MicroTime`, which a Lease's `renewTime` and `acquireTime` are:
/// `2026-11-21T10:00:00.123456Z`.
#[must_use]
pub fn micro_time(now: SystemTime) -> String {
    let since = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}.{:06}Z",
        date_time(since.as_secs()),
        since.subsec_micros()
    )
}

#[cfg(test)]
mod test {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::kubernetes::ingress::unix_seconds;

    #[test]
    fn formats_round_trip_through_the_parser() {
        for text in [
            "1970-01-01T00:00:00Z",
            "2024-02-29T23:59:59Z",
            "2026-11-21T10:00:00Z",
            "2100-03-01T00:00:01Z",
        ] {
            let secs = unix_seconds(text).expect("a valid time");
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
            assert_eq!(time(at), text);
        }
    }

    #[test]
    fn micro_time_keeps_microseconds() {
        let at = SystemTime::UNIX_EPOCH + Duration::new(1_795_255_200, 123_456_789);
        assert_eq!(micro_time(at), "2026-11-21T10:00:00.123456Z");
    }
}
