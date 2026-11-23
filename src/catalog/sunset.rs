//! The day a deprecated API is expected to stop answering.

use std::time::{Duration, UNIX_EPOCH};

use http::HeaderValue;

/// A sunset day, `YYYY-MM-DD` in UTC: the text it was declared with and the `Sunset` header value
/// (RFC 8594) for 00:00:00 UTC of that day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sunset {
    day: Box<str>,
    header: HeaderValue,
}

impl Sunset {
    /// Reads `YYYY-MM-DD`: a real calendar date, in the years 1970 to 9999.
    ///
    /// # Errors
    ///
    /// The reason the text is not a sunset day.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("{text:?} is not a date written YYYY-MM-DD");
        let bytes = text.as_bytes();
        if !text.is_ascii() || bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return Err(bad());
        }
        let number = |part: &str| -> Option<i64> {
            part.bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| part.parse().ok())
                .flatten()
        };
        let (Some(year), Some(month), Some(day)) =
            (number(&text[..4]), number(&text[5..7]), number(&text[8..]))
        else {
            return Err(bad());
        };
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
        {
            return Err(format!(
                "{text:?} is not a calendar date between 1970-01-01 and 9999-12-31"
            ));
        }
        let secs = u64::try_from(days_from_civil(year, month, day) * 86_400).map_err(|_| bad())?;
        let stamp = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(secs));
        let header = HeaderValue::from_str(&stamp).map_err(|_| bad())?;
        Ok(Self {
            day: text.into(),
            header,
        })
    }

    /// The day as declared, `YYYY-MM-DD`.
    #[must_use]
    pub fn day(&self) -> &str {
        &self.day
    }

    /// The `Sunset` header value, an HTTP-date.
    #[must_use]
    pub fn header(&self) -> &HeaderValue {
        &self.header
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod test {
    use super::*;

    fn header(text: &str) -> String {
        Sunset::parse(text)
            .expect("a date")
            .header()
            .to_str()
            .expect("ascii")
            .to_owned()
    }

    #[test]
    fn sunset_formats_http_dates() {
        assert_eq!(header("1970-01-01"), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(header("2000-02-29"), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(header("2027-03-01"), "Mon, 01 Mar 2027 00:00:00 GMT");
        assert_eq!(header("9999-12-31"), "Fri, 31 Dec 9999 00:00:00 GMT");
        assert_eq!(
            Sunset::parse("2027-03-01").expect("a date").day(),
            "2027-03-01"
        );
    }

    #[test]
    fn sunset_rejects_impossible_dates() {
        for text in [
            "",
            "2027-3-1",
            "2027/03/01",
            "2027-02-29",
            "2100-02-29",
            "2027-13-01",
            "2027-00-10",
            "2027-04-31",
            "1969-12-31",
            "+027-03-01",
            "2027-03-01 ",
            "next week",
        ] {
            assert!(Sunset::parse(text).is_err(), "{text:?}");
        }
    }
}
