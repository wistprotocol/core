//! WIST-3 §3.1's whole-second, literal-`Z` Log timestamp profile: exact
//! Gregorian calendar validation across the four-digit-year range, and the
//! inverse spelling of an instant inside it.
use crate::error::Error;

/// `0000-01-01T00:00:00Z`, the first instant a Log timestamp denotes.
pub const LOG_TIMESTAMP_MIN_S: i64 = -62_167_219_200;
/// `9999-12-31T23:59:59Z`, the last instant a Log timestamp denotes.
pub const LOG_TIMESTAMP_MAX_S: i64 = 253_402_300_799;

fn leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub(crate) fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Parses a Log timestamp into seconds since the Unix epoch, rejecting
/// fractions, offsets, leap seconds and calendar dates that do not exist.
pub fn log_seconds(at: &str) -> Result<i64, Error> {
    let bytes = at.as_bytes();
    let shaped = bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            17 => (b'0'..=b'5').contains(byte),
            _ => byte.is_ascii_digit(),
        });
    if !shaped {
        return Err(Error::Timestamp(
            "timestamp must be whole-second UTC with trailing Z".into(),
        ));
    }
    let field = |from: usize, to: usize| -> i64 {
        at[from..to]
            .bytes()
            .fold(0i64, |acc, b| acc * 10 + i64::from(b - b'0'))
    };
    let (year, month, day) = (field(0, 4), field(5, 7), field(8, 10));
    let (hour, minute, second) = (field(11, 13), field(14, 16), field(17, 19));
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(Error::Timestamp(format!("{at} denotes no instant")));
    }
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The Log timestamp spelling of an instant inside the four-digit-year range.
pub fn instant(epoch_s: i64) -> Result<String, Error> {
    if !(LOG_TIMESTAMP_MIN_S..=LOG_TIMESTAMP_MAX_S).contains(&epoch_s) {
        return Err(Error::Timestamp(
            "instant is outside the Log timestamp range".into(),
        ));
    }
    let (year, month, day) = civil_from_days(epoch_s.div_euclid(86_400));
    let seconds = epoch_s.rem_euclid(86_400);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec_dir() -> PathBuf {
        std::env::var_os("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
    }

    #[test]
    fn timestamp_vectors_reject_leap_seconds_without_normalization() {
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist3/timestamps.json")).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let at = case["value"].as_str().unwrap();
            assert_eq!(
                log_seconds(at).ok(),
                case["epoch_seconds"].as_i64(),
                "{at:?}"
            );
            if let Some(seconds) = case["epoch_seconds"].as_i64() {
                assert_eq!(instant(seconds).unwrap(), at);
            }
        }
        for case in vector["distances"].as_array().unwrap() {
            assert_eq!(
                log_seconds(case["to"].as_str().unwrap()).unwrap()
                    - log_seconds(case["from"].as_str().unwrap()).unwrap(),
                case["seconds"].as_i64().unwrap()
            );
        }
    }

    #[test]
    fn instants_round_trip_across_the_whole_range() {
        for (seconds, spelled) in [
            (LOG_TIMESTAMP_MIN_S, "0000-01-01T00:00:00Z"),
            (-62_162_121_600, "0000-02-29T00:00:00Z"),
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (253_402_214_400, "9999-12-31T00:00:00Z"),
            (LOG_TIMESTAMP_MAX_S, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(instant(seconds).unwrap(), spelled);
            assert_eq!(log_seconds(spelled).unwrap(), seconds);
        }
        assert!(instant(LOG_TIMESTAMP_MIN_S - 1).is_err());
        assert!(instant(LOG_TIMESTAMP_MAX_S + 1).is_err());
        assert!(log_seconds("2026-02-29T00:00:00Z").is_err());
        assert!(log_seconds("2026-08-09T23:59:60Z").is_err());
    }
}
