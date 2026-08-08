//! Bluetooth SIG Current Time Service (0x1805) Current Time (0x2A2B) value
//! codec: 10 bytes, little-endian, per the CTS spec. Deliberately pure `std`
//! — netprov only ever needs UTC round-tripped through Unix time, which a
//! short proleptic-Gregorian conversion covers without a date-time crate.

use std::fmt;

pub const CTS_VALUE_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtsError {
    WrongLength(usize),
    OutOfRange(&'static str),
}

impl fmt::Display for CtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CtsError::WrongLength(len) => {
                write!(
                    f,
                    "current time value must be {CTS_VALUE_LEN} bytes, got {len}"
                )
            }
            CtsError::OutOfRange(field) => write!(f, "current time field out of range: {field}"),
        }
    }
}

impl std::error::Error for CtsError {}

/// Encodes `unix_secs` (UTC) as a 10-byte CTS Current Time value. Fractions256
/// (sub-second) and Adjust Reason are always 0: netprov has no sub-second
/// clock source and always sets the time manually.
pub fn encode_current_time(unix_secs: i64) -> [u8; CTS_VALUE_LEN] {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (secs_of_day / 3600) as u8;
    let minute = ((secs_of_day % 3600) / 60) as u8;
    let second = (secs_of_day % 60) as u8;
    let weekday = weekday_from_days(days);

    let mut out = [0u8; CTS_VALUE_LEN];
    out[0..2].copy_from_slice(&year.to_le_bytes());
    out[2] = month;
    out[3] = day;
    out[4] = hour;
    out[5] = minute;
    out[6] = second;
    out[7] = weekday;
    out[8] = 0; // fractions256: no sub-second clock source
    out[9] = 0; // adjust reason: netprov always sets the time manually
    out
}

/// Decodes a 10-byte CTS Current Time value into Unix seconds (UTC).
///
/// Rejects rather than coerces: wrong length or any out-of-range field is an
/// error, not a best-effort parse — this is untrusted input at a trust
/// boundary (an authenticated BLE peer, but still attacker-controlled bytes).
/// Day-of-week (offset 7), fractions256 (offset 8), and Adjust Reason (offset
/// 9) are accepted but not validated against the date: netprov only derives
/// year/month/day/hour/minute/second from the value.
pub fn decode_current_time(bytes: &[u8]) -> Result<i64, CtsError> {
    if bytes.len() != CTS_VALUE_LEN {
        return Err(CtsError::WrongLength(bytes.len()));
    }
    let year = u16::from_le_bytes([bytes[0], bytes[1]]);
    let month = bytes[2];
    let day = bytes[3];
    let hour = bytes[4];
    let minute = bytes[5];
    let second = bytes[6];

    if !(1582..=9999).contains(&year) {
        return Err(CtsError::OutOfRange("year"));
    }
    if !(1..=12).contains(&month) {
        return Err(CtsError::OutOfRange("month"));
    }
    if hour > 23 {
        return Err(CtsError::OutOfRange("hour"));
    }
    if minute > 59 {
        return Err(CtsError::OutOfRange("minute"));
    }
    if second > 59 {
        return Err(CtsError::OutOfRange("second"));
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(CtsError::OutOfRange("day"));
    }

    let days = days_from_civil(year as i64, month as i64, day as i64);
    Ok(days * 86_400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64)
}

fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days since the Unix epoch (1970-01-01) for a proleptic Gregorian date.
/// Howard Hinnant's `days_from_civil` algorithm (public domain):
/// <http://howardhinnant.github.io/date_algorithms.html#days_from_civil>.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (u16, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u16, m as u8, d as u8)
}

/// Weekday for a day count relative to the Unix epoch, CTS-numbered (1 =
/// Monday .. 7 = Sunday). 1970-01-01 (day 0) was a Thursday.
fn weekday_from_days(z: i64) -> u8 {
    let idx = z.rem_euclid(7); // 0 = Thursday .. 6 = Wednesday
    (((idx + 3) % 7) + 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH_BYTES: [u8; CTS_VALUE_LEN] =
        [0xB2, 0x07, 0x01, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00];

    fn time_bytes(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> [u8; CTS_VALUE_LEN] {
        let mut out = [0u8; CTS_VALUE_LEN];
        out[0..2].copy_from_slice(&year.to_le_bytes());
        out[2] = month;
        out[3] = day;
        out[4] = hour;
        out[5] = minute;
        out[6] = second;
        out
    }

    #[test]
    fn encodes_the_unix_epoch_to_the_spec_known_vector() {
        // 1970-01-01T00:00:00Z was a Thursday (CTS weekday 4) — a fact
        // independent of this module's own calendar math, so this is a real
        // cross-check and not just a round trip against itself.
        assert_eq!(encode_current_time(0), EPOCH_BYTES);
    }

    #[test]
    fn decodes_the_spec_known_vector_to_the_unix_epoch() {
        assert_eq!(decode_current_time(&EPOCH_BYTES).unwrap(), 0);
    }

    #[test]
    fn round_trips_arbitrary_unix_seconds_across_a_wide_span() {
        for unix_secs in [
            0i64,
            86_400,
            31_536_000,
            63_072_000,
            94_608_000,
            1_735_689_600,
            4_102_444_800,
        ] {
            let bytes = encode_current_time(unix_secs);
            assert_eq!(decode_current_time(&bytes).unwrap(), unix_secs);
        }
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            decode_current_time(&[0u8; 9]),
            Err(CtsError::WrongLength(9))
        );
        assert_eq!(
            decode_current_time(&[0u8; 11]),
            Err(CtsError::WrongLength(11))
        );
    }

    #[test]
    fn rejects_out_of_range_fields() {
        let mut bytes = EPOCH_BYTES;
        bytes[2] = 13; // month 13
        assert_eq!(
            decode_current_time(&bytes),
            Err(CtsError::OutOfRange("month"))
        );

        let mut bytes = EPOCH_BYTES;
        bytes[4] = 24; // hour 24
        assert_eq!(
            decode_current_time(&bytes),
            Err(CtsError::OutOfRange("hour"))
        );

        let mut bytes = EPOCH_BYTES;
        bytes[0..2].copy_from_slice(&0u16.to_le_bytes()); // year 0 ("unknown")
        assert_eq!(
            decode_current_time(&bytes),
            Err(CtsError::OutOfRange("year"))
        );
    }

    #[test]
    fn accepts_leap_day_only_in_leap_years() {
        assert!(decode_current_time(&time_bytes(2024, 2, 29, 0, 0, 0)).is_ok());
        assert_eq!(
            decode_current_time(&time_bytes(2023, 2, 29, 0, 0, 0)),
            Err(CtsError::OutOfRange("day"))
        );
    }
}
