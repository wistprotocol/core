use crate::coverage::within_days_ending_at;

pub const ESCALATION_L2_COUNT: u64 = 3;
pub const ESCALATION_L2_DAYS: u64 = 90;
pub const ESCALATION_L3_COUNT: u64 = 10;
pub const ESCALATION_L3_DAYS: u64 = 90;
pub const ESCALATION_L4_SEV3_COUNT: u64 = 3;
pub const ESCALATION_L4_DAYS: u64 = 180;
pub const APPEAL_WINDOW_DAYS: u64 = 14;
pub const APPEAL_SEAL_DAYS: u64 = 7;
pub const RULING_DEADLINE_DAYS: u64 = 30;

const DAY_S: i64 = 86_400;

#[derive(Debug, Clone, Copy)]
pub struct Finding {
    pub sealed_at_s: i64,
    pub severity: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Overturned,
    Upheld,
    Unappealed,
}

pub fn criterion_times(
    findings: &[Finding],
    count: u64,
    span_days: Option<u64>,
    min_severity: u8,
) -> Vec<i64> {
    let qualifying: Vec<i64> = findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .map(|f| f.sealed_at_s)
        .collect();
    qualifying
        .iter()
        .enumerate()
        .filter(|(k, &at)| {
            let in_span = qualifying[..=*k]
                .iter()
                .filter(|&&earlier| match span_days {
                    Some(days) => within_days_ending_at(earlier, at, days),
                    None => true,
                })
                .count() as u64;
            in_span >= count
        })
        .map(|(_, &at)| at)
        .collect()
}

fn in_force_strictly_before(met: &[i64], clear: &[i64], t_s: i64) -> bool {
    let last_met = met.iter().filter(|&&m| m < t_s).max();
    let last_clear = clear.iter().filter(|&&c| c < t_s).max();
    match (last_met, last_clear) {
        (Some(m), Some(c)) => c < m,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

pub fn l4_accrual_times(findings: &[Finding], l3_met: &[i64], l3_clear: &[i64]) -> Vec<i64> {
    findings
        .iter()
        .map(|f| f.sealed_at_s)
        .filter(|&at| in_force_strictly_before(l3_met, l3_clear, at))
        .collect()
}

pub fn state_void_at(
    notice_sealed_at_s: Option<i64>,
    appeal_sealed_at_s: Option<i64>,
    ruling: Option<(Outcome, i64)>,
) -> Option<i64> {
    let notice = notice_sealed_at_s?;
    let window_close = notice + (APPEAL_WINDOW_DAYS as i64) * DAY_S;
    let t = window_close + (APPEAL_SEAL_DAYS as i64) * DAY_S;
    let appeal_by_t = appeal_sealed_at_s.filter(|&a| a <= t);
    let valid_unappealed = matches!(
        ruling,
        Some((Outcome::Unappealed, rt)) if rt >= window_close && rt <= t
    );
    if appeal_by_t.is_none() && !valid_unappealed {
        return Some(t);
    }
    match appeal_by_t {
        None => None,
        Some(appeal) => {
            let due = appeal + (RULING_DEADLINE_DAYS as i64) * DAY_S;
            match ruling {
                Some((Outcome::Overturned, rt)) if rt <= due => Some(rt),
                Some((Outcome::Upheld, rt)) if rt <= due => None,
                _ => Some(due),
            }
        }
    }
}

pub fn in_force(met_times_s: &[i64], clear_times_s: &[i64], n_s: i64) -> bool {
    let last_met = met_times_s.iter().filter(|&&m| m <= n_s).max();
    let last_clear = clear_times_s.iter().filter(|&&c| c <= n_s).max();
    match (last_met, last_clear) {
        (Some(m), Some(c)) => c < m,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

pub fn ladder_level(levels: &[(&[i64], &[i64]); 4], n_s: i64) -> u8 {
    levels
        .iter()
        .enumerate()
        .rev()
        .find(|(_, (met, clear))| in_force(met, clear, n_s))
        .map(|(i, _)| i as u8 + 1)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(day: i64, severity: u8) -> Finding {
        Finding {
            sealed_at_s: day * DAY_S,
            severity,
        }
    }

    #[test]
    fn a_single_finding_meets_level_one_at_every_finding() {
        let findings = [f(10, 1), f(20, 2)];
        assert_eq!(
            criterion_times(&findings, 1, None, 0),
            vec![10 * DAY_S, 20 * DAY_S]
        );
    }

    #[test]
    fn three_findings_inside_ninety_days_meet_level_two() {
        let findings = [f(0, 1), f(30, 1), f(89, 1), f(200, 1)];
        assert_eq!(
            criterion_times(&findings, ESCALATION_L2_COUNT, Some(ESCALATION_L2_DAYS), 0),
            vec![89 * DAY_S]
        );
    }

    #[test]
    fn findings_spread_past_the_span_never_meet() {
        let findings = [f(0, 1), f(91, 1), f(182, 1)];
        assert!(
            criterion_times(&findings, ESCALATION_L2_COUNT, Some(ESCALATION_L2_DAYS), 0).is_empty()
        );
    }

    #[test]
    fn severity_filter_reads_only_qualifying_findings() {
        let findings = [f(0, 3), f(10, 1), f(20, 3), f(30, 3)];
        assert_eq!(
            criterion_times(
                &findings,
                ESCALATION_L4_SEV3_COUNT,
                Some(ESCALATION_L4_DAYS),
                3
            ),
            vec![30 * DAY_S]
        );
        assert_eq!(
            criterion_times(&findings, 1, None, 3),
            vec![0, 20 * DAY_S, 30 * DAY_S]
        );
    }

    #[test]
    fn accrual_counts_findings_while_level_three_is_in_force() {
        let findings = [f(10, 3), f(20, 1), f(30, 1)];
        let l3_met = [10 * DAY_S];
        assert_eq!(
            l4_accrual_times(&findings, &l3_met, &[]),
            vec![20 * DAY_S, 30 * DAY_S]
        );
    }

    #[test]
    fn the_finding_that_creates_level_three_is_not_an_accrual() {
        let findings = [f(10, 3)];
        assert_eq!(
            l4_accrual_times(&findings, &[10 * DAY_S], &[]),
            Vec::<i64>::new()
        );
    }

    #[test]
    fn accrual_stops_once_level_three_is_cleared() {
        let findings = [f(10, 3), f(20, 1), f(40, 1)];
        assert_eq!(
            l4_accrual_times(&findings, &[10 * DAY_S], &[30 * DAY_S]),
            vec![20 * DAY_S]
        );
    }

    #[test]
    fn no_notice_never_voids() {
        assert_eq!(state_void_at(None, None, None), None);
    }

    #[test]
    fn a_notice_answered_by_nothing_voids_at_t() {
        let t = (14 + 7) * DAY_S;
        assert_eq!(state_void_at(Some(0), None, None), Some(t));
    }

    #[test]
    fn a_valid_unappealed_ruling_discharges_t() {
        let ruling_at = 15 * DAY_S;
        assert_eq!(
            state_void_at(Some(0), None, Some((Outcome::Unappealed, ruling_at))),
            None
        );
    }

    #[test]
    fn an_unappealed_ruling_before_the_window_closes_is_absent() {
        let ruling_at = 13 * DAY_S;
        assert_eq!(
            state_void_at(Some(0), None, Some((Outcome::Unappealed, ruling_at))),
            Some((14 + 7) * DAY_S)
        );
    }

    #[test]
    fn a_sealed_appeal_with_no_ruling_voids_at_the_ruling_deadline() {
        let appeal_at = 10 * DAY_S;
        assert_eq!(
            state_void_at(Some(0), Some(appeal_at), None),
            Some(appeal_at + 30 * DAY_S)
        );
    }

    #[test]
    fn an_upheld_ruling_in_time_keeps_the_state() {
        let appeal_at = 10 * DAY_S;
        assert_eq!(
            state_void_at(
                Some(0),
                Some(appeal_at),
                Some((Outcome::Upheld, 20 * DAY_S))
            ),
            None
        );
    }

    #[test]
    fn a_late_ruling_does_not_cure_the_lapsed_deadline() {
        let appeal_at = 10 * DAY_S;
        assert_eq!(
            state_void_at(
                Some(0),
                Some(appeal_at),
                Some((Outcome::Upheld, 45 * DAY_S))
            ),
            Some(appeal_at + 30 * DAY_S)
        );
    }

    #[test]
    fn an_overturned_ruling_voids_when_sealed() {
        let appeal_at = 10 * DAY_S;
        assert_eq!(
            state_void_at(
                Some(0),
                Some(appeal_at),
                Some((Outcome::Overturned, 20 * DAY_S))
            ),
            Some(20 * DAY_S)
        );
    }

    #[test]
    fn an_appeal_sealed_after_t_does_not_discharge_it() {
        let t = (14 + 7) * DAY_S;
        assert_eq!(state_void_at(Some(0), Some(t + DAY_S), None), Some(t));
    }

    #[test]
    fn in_force_follows_the_latest_met_and_clear() {
        assert!(!in_force(&[], &[], 100));
        assert!(in_force(&[50], &[], 100));
        assert!(!in_force(&[50], &[60], 100));
        assert!(in_force(&[50, 70], &[60], 100));
        assert!(!in_force(&[150], &[], 100));
        assert!(!in_force(&[50], &[50], 100));
    }

    #[test]
    fn ladder_level_is_the_highest_rung_in_force() {
        let l1: (&[i64], &[i64]) = (&[10], &[]);
        let l2: (&[i64], &[i64]) = (&[20], &[]);
        let l3: (&[i64], &[i64]) = (&[30], &[40]);
        let l4: (&[i64], &[i64]) = (&[], &[]);
        assert_eq!(ladder_level(&[l1, l2, l3, l4], 100), 2);
        assert_eq!(ladder_level(&[l1, l2, l3, l4], 35), 3);
        assert_eq!(ladder_level(&[l1, l2, l3, l4], 5), 0);
    }
}
