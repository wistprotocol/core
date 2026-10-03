//! WIST-1 §3.4 and ADR-0026: Publisher timestamps compare exactly, without rounding, clamping
//! or leap-second tables.
use crate::timestamp::{days_from_civil, days_in_month};
use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Instant<'a> {
    second: i128,
    fraction: &'a str,
}

fn digits(bytes: &[u8]) -> Option<i64> {
    bytes.iter().try_fold(0i64, |n, b| {
        b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0'))
    })
}

fn parse(value: &str) -> Option<Instant<'_>> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (
        digits(&bytes[..4])?,
        digits(&bytes[5..7])?,
        digits(&bytes[8..10])?,
    );
    let (hour, minute, second) = (
        digits(&bytes[11..13])?,
        digits(&bytes[14..16])?,
        digits(&bytes[17..19])?,
    );
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut offset_start = 19;
    let fraction = if bytes[19] == b'.' {
        offset_start = 20;
        while bytes.get(offset_start).is_some_and(u8::is_ascii_digit) {
            offset_start += 1;
        }
        if offset_start == 20 {
            return None;
        }
        value[20..offset_start].trim_end_matches('0')
    } else {
        ""
    };
    let offset = match &bytes[offset_start..] {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let hours = digits(&[*h1, *h2])?;
            let minutes = digits(&[*m1, *m2])?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return None,
    };
    Some(Instant {
        second: i128::from(
            days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
                - offset,
        ),
        fraction,
    })
}

pub fn seconds(value: &str) -> Option<(i128, &str)> {
    parse(value).map(|instant| (instant.second, instant.fraction))
}

pub fn valid(value: &str) -> bool {
    parse(value).is_some()
}

pub fn compare(left: &str, right: &str) -> Option<Ordering> {
    Some(parse(left)?.cmp(&parse(right)?))
}

/// `bound_fraction` is the decimal digits after the point, without trailing zeros.
pub fn within_bound(value: &str, bound_s: i128, bound_fraction: &str) -> Option<bool> {
    let bound = Instant {
        second: bound_s,
        fraction: bound_fraction.trim_end_matches('0'),
    };
    Some(parse(value)? <= bound)
}

pub fn at_or_after(value: &str, bound_s: i128) -> Option<bool> {
    Some(
        parse(value)?
            >= Instant {
                second: bound_s,
                fraction: "",
            },
    )
}

/// WIST-1 §3.4: `value <= clock + allowance`, endpoint included, with a signed allowance and no
/// clamping to the spelling range; seconds.
pub fn within_clock_bound(value: &str, clock_s: i64, allowance_s: i64) -> Option<bool> {
    within_bound(value, i128::from(clock_s) + i128::from(allowance_s), "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_calendar_and_timestamp_syntax() {
        for invalid in [
            "",
            "2026-08-04",
            "2026-08-04T10:00:00",
            "2026-08-04 10:00:00Z",
            "2026-08-04T10:00:00.Z",
            "2026-08-04T10:00:00,5Z",
            "2026-08-04T10:00:00Z ",
            "2026-08-04T10:00:00+24:00",
            "2026-08-04T10:00:00+00:60",
            "2026-08-04T24:00:00Z",
            "2026-08-04T10:60:00Z",
            "2026-08-04T10:00:61Z",
            "2026-08-04T10:00:60Z",
            "2026-02-29T10:00:00Z",
            "1900-02-29T10:00:00Z",
            "2026-04-31T10:00:00Z",
            "2026-00-04T10:00:00Z",
            "２０２６-08-04T10:00:00Z",
            "2026-08-04T10:00:00.٥Z",
            "2026-08-04T10:00:00+01",
            "2026-08-04T10:00:00[UTC]",
        ] {
            assert_eq!(compare(invalid, "2026-08-04T10:00:00Z"), None, "{invalid}");
        }
    }

    #[test]
    fn compares_exact_fractions_offsets_and_range_edges() {
        assert_eq!(
            compare("2026-08-04T10:00:00.5Z", "2026-08-04T10:00:00.50Z"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare("2026-08-04T10:00:00.25Z", "2026-08-04T10:00:00.5Z"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare("2026-08-04T11:00:00+01:00", "2026-08-04T10:00:00Z"),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare("2000-02-29T00:00:00-00:00", "2000-02-29t00:00:00z"),
            Some(Ordering::Equal)
        );
        assert!(valid("0000-01-01T00:00:00+23:59"));
        assert!(valid("9999-12-31T23:59:59-23:59"));
        assert_eq!(
            within_clock_bound(
                "2026-08-11T00:01:00.00000000000000000001Z",
                1_786_406_400,
                60
            ),
            Some(false)
        );
        assert_eq!(
            within_clock_bound("2026-08-11T00:01:00Z", 1_786_406_400, 60),
            Some(true)
        );
        assert_eq!(
            within_clock_bound(
                "2026-08-11T02:58:59.99999999999999999999Z",
                1_786_417_200,
                -60
            ),
            Some(true)
        );
        assert_eq!(
            within_clock_bound("9999-12-31T23:59:59-23:59", 0, 9_007_199_254_740_991),
            Some(true)
        );
        assert_eq!(
            within_clock_bound("0000-01-01T00:00:00+23:59", 0, -9_007_199_254_740_991),
            Some(false)
        );
        assert_eq!(within_clock_bound("2026-08-11T00:00:60Z", 0, 0), None);
    }
}
