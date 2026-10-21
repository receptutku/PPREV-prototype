//! Calendar days as phi_S compares them: Y * 10000 + M * 100 + D of a proleptic Gregorian date.

use anyhow::{Context, Result, ensure};

const SECS_PER_DAY: i64 = 86_400;

/// Y * 10000 + M * 100 + D of the civil date `days` days after 1970-01-01 (H. Hinnant's
/// civil_from_days).
pub fn ymd_of_days(days: i64) -> Result<u32> {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    ensure!((0..=9999).contains(&y), "year {y} is outside 0000..9999");
    u32::try_from(y * 10_000 + m * 100 + d).context("date out of range")
}

/// The engagement day of phi_S (Section V-G): the calendar day, in a time zone `utc_offset_secs`
/// ahead of UTC, of `expires_at - tau_lock`, as Y * 10000 + M * 100 + D.
pub fn engagement_day(expires_at: u64, tau_lock: u64, utc_offset_secs: i64) -> Result<u32> {
    let engaged = expires_at
        .checked_sub(tau_lock)
        .context("expiresAt precedes tau_lock")?;
    let local = i64::try_from(engaged)
        .ok()
        .and_then(|t| t.checked_add(utc_offset_secs))
        .context("engagement time out of range")?;
    ymd_of_days(local.div_euclid(SECS_PER_DAY))
}

#[cfg(test)]
// Dates are written Y_MM_DD, as phi_S encodes them.
#[allow(clippy::inconsistent_digit_grouping)]
mod tests {
    use super::*;

    #[test]
    fn days_map_to_civil_dates() {
        assert_eq!(ymd_of_days(0).unwrap(), 1970_01_01);
        assert_eq!(ymd_of_days(-1).unwrap(), 1969_12_31);
        assert_eq!(ymd_of_days(59).unwrap(), 1970_03_01);
        // 2026-09-25T00:00:00Z is Unix time 1790294400.
        assert_eq!(ymd_of_days(1_790_294_400 / 86_400).unwrap(), 2026_09_25);
        // Leap days: 2000 and 2024 have one, 2100 does not.
        assert_eq!(ymd_of_days(11_016).unwrap(), 2000_02_29);
        assert_eq!(ymd_of_days(19_782).unwrap(), 2024_02_29);
        assert_eq!(ymd_of_days(47_540).unwrap(), 2100_02_28);
        assert_eq!(ymd_of_days(47_541).unwrap(), 2100_03_01);
        assert!(ymd_of_days(3_000_000).is_err());
    }

    #[test]
    fn the_engagement_day_is_taken_in_the_registry_time_zone() {
        let tau = 14 * 86_400;
        // Engaged at 2026-09-24T21:30:00Z, which is 2026-09-25 00:30 in UTC+3.
        let engaged = 1_790_285_400;
        assert_eq!(engagement_day(engaged + tau, tau, 0).unwrap(), 2026_09_24);
        assert_eq!(
            engagement_day(engaged + tau, tau, 3 * 3600).unwrap(),
            2026_09_25
        );
        assert_eq!(
            engagement_day(engaged + tau, tau, -12 * 3600).unwrap(),
            2026_09_24
        );
        assert!(engagement_day(tau - 1, tau, 0).is_err());
    }
}
