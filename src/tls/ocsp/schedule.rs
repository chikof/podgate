//! When to ask a responder again. Pure functions of times and one random sample, so tests pin
//! them exactly.

use std::time::{Duration, SystemTime};

/// The wait after the first failure.
pub const BACKOFF_MIN: Duration = Duration::from_secs(60);
/// The longest wait between failed attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);

/// How long to wait after the `failures`th failure in a row (counting from 1): one minute,
/// doubling up to an hour, then shortened by up to 10% at random (`unit` is in `[0, 1)`) so the
/// certificates of one snapshot do not retry in step. It never exceeds [`BACKOFF_MAX`].
#[must_use]
pub fn backoff(failures: u32, unit: f64) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    let base = BACKOFF_MIN.saturating_mul(1 << doublings).min(BACKOFF_MAX);
    base.mul_f64(1.0 - 0.1 * unit.clamp(0.0, 1.0))
}

/// When to refresh a response valid from `this_update` to `next_update`, seen at `now`: the
/// midpoint of the window, moved by up to 5% of the window either way (`unit` in `[0, 1)`).
///
/// A response that is already past its midpoint is refreshed after `min(1 minute, half of what
/// is left)`, and the refresh is never later than nine tenths of the time left, so a staple is
/// replaced before it expires.
#[must_use]
pub fn next_refresh(
    this_update: SystemTime,
    next_update: SystemTime,
    now: SystemTime,
    unit: f64,
) -> SystemTime {
    let window = next_update
        .duration_since(this_update)
        .unwrap_or(Duration::ZERO);
    let midpoint = this_update + window / 2;
    let factor = (unit.clamp(0.0, 1.0) - 0.5) * 2.0;
    let swing = (window / 20).mul_f64(factor.abs());
    let target = if factor >= 0.0 {
        midpoint + swing
    } else {
        midpoint.checked_sub(swing).unwrap_or(midpoint)
    };
    let left = next_update.duration_since(now).unwrap_or(Duration::ZERO);
    let floor = BACKOFF_MIN.min(left / 2);
    let ceiling = left.mul_f64(0.9);
    let wait = target
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .clamp(floor, ceiling.max(floor));
    now + wait
}

#[cfg(test)]
mod test {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn backoff_doubles_from_a_minute_to_an_hour() {
        let waits: Vec<u64> = (1..=9).map(|n| backoff(n, 0.0).as_secs()).collect();
        assert_eq!(waits, [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
        assert_eq!(backoff(1, 1.0).as_secs(), 54);
        assert_eq!(backoff(u32::MAX, 0.0), BACKOFF_MAX);
    }

    #[test]
    fn refresh_is_the_midpoint_with_jitter() {
        let (this, next) = (at(0), at(7 * 24 * 3600));
        let midpoint = 3 * 24 * 3600 + 12 * 3600;
        assert_eq!(next_refresh(this, next, at(10), 0.5), at(midpoint));
        let window = 7 * 24 * 3600_u64;
        assert_eq!(
            next_refresh(this, next, at(10), 1.0),
            at(midpoint + window / 20)
        );
        assert_eq!(
            next_refresh(this, next, at(10), 0.0),
            at(midpoint - window / 20)
        );
    }

    #[test]
    fn refresh_of_a_late_response_is_soon_and_before_expiry() {
        let (this, next) = (at(0), at(1000));
        assert_eq!(next_refresh(this, next, at(900), 0.5), at(950));
        assert_eq!(next_refresh(this, next, at(100), 0.5), at(500));
        let tight = next_refresh(this, next, at(990), 0.5);
        assert!(tight <= at(999), "{tight:?}");
        assert!(tight > at(990));
    }
}
