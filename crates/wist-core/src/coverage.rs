pub const COVERAGE_DEADLINE_HOURS: u64 = 72;
pub const COVERAGE_FAILURES_MAX: u64 = 24;
pub const RECORD_SEAL_BLOCKS: u64 = 24;
pub const WINDOW_DAYS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairStatus {
    Discharged,
    Failed,
}

#[derive(Debug, Clone, Copy)]
pub enum Attestation {
    Unmet { chain_contradicts: bool },
    Missing,
}

pub fn within_days_ending_at(t_s: i64, end_s: i64, days: u64) -> bool {
    t_s <= end_s && end_s - t_s < (days as i64) * 86_400
}

pub fn pair_status(selected: &[&str], recorded: &[&str], attested: bool) -> PairStatus {
    if selected.is_empty() {
        return if attested {
            PairStatus::Discharged
        } else {
            PairStatus::Failed
        };
    }
    if selected.iter().all(|d| recorded.contains(d)) {
        PairStatus::Discharged
    } else {
        PairStatus::Failed
    }
}

pub fn pair_counts(attestation: Attestation, chain_proof_in_window: bool) -> bool {
    match attestation {
        Attestation::Unmet { chain_contradicts } => !chain_contradicts,
        Attestation::Missing => !chain_proof_in_window,
    }
}

pub fn in_coverage_failure(
    counting_failure_block_times_s: &[i64],
    n_sealed_at_s: i64,
    failures_max: u64,
) -> bool {
    let in_window = counting_failure_block_times_s
        .iter()
        .filter(|&&t| within_days_ending_at(t, n_sealed_at_s, WINDOW_DAYS))
        .count() as u64;
    in_window > failures_max
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn window_includes_the_endpoint_and_excludes_the_thirtieth_day_start() {
        assert!(within_days_ending_at(100 * DAY, 100 * DAY, 30));
        assert!(within_days_ending_at(
            100 * DAY - 30 * DAY + 1,
            100 * DAY,
            30
        ));
        assert!(!within_days_ending_at(70 * DAY, 100 * DAY, 30));
        assert!(!within_days_ending_at(101 * DAY, 100 * DAY, 30));
    }

    #[test]
    fn full_coverage_discharges() {
        assert_eq!(
            pair_status(&["sha256:a", "sha256:b"], &["sha256:b", "sha256:a"], false),
            PairStatus::Discharged
        );
    }

    #[test]
    fn partial_coverage_is_failure_not_partial_credit() {
        assert_eq!(
            pair_status(&["sha256:a", "sha256:b"], &["sha256:a"], false),
            PairStatus::Failed
        );
    }

    #[test]
    fn empty_selection_needs_an_attestation() {
        assert_eq!(pair_status(&[], &[], false), PairStatus::Failed);
        assert_eq!(pair_status(&[], &[], true), PairStatus::Discharged);
    }

    #[test]
    fn extra_records_do_not_hurt() {
        assert_eq!(
            pair_status(&["sha256:a"], &["sha256:a", "sha256:z"], false),
            PairStatus::Discharged
        );
    }

    #[test]
    fn attested_unmet_uncontradicted_counts() {
        assert!(pair_counts(
            Attestation::Unmet {
                chain_contradicts: false
            },
            false
        ));
    }

    #[test]
    fn chain_contradiction_stops_an_attested_failure_from_counting() {
        assert!(!pair_counts(
            Attestation::Unmet {
                chain_contradicts: true
            },
            false
        ));
    }

    #[test]
    fn unattested_pair_counts_like_an_attested_unmet_duty() {
        assert!(pair_counts(Attestation::Missing, false));
    }

    #[test]
    fn chain_proof_excludes_every_unattested_pair_in_the_window() {
        assert!(!pair_counts(Attestation::Missing, true));
    }

    #[test]
    fn chain_proof_does_not_shield_an_attested_unmet_duty() {
        assert!(pair_counts(
            Attestation::Unmet {
                chain_contradicts: false
            },
            true
        ));
    }

    #[test]
    fn failure_state_needs_strictly_more_than_the_maximum() {
        let at_max: Vec<i64> = (0..COVERAGE_FAILURES_MAX as i64)
            .map(|i| 90 * DAY + i)
            .collect();
        assert!(!in_coverage_failure(
            &at_max,
            100 * DAY,
            COVERAGE_FAILURES_MAX
        ));
        let past: Vec<i64> = (0..COVERAGE_FAILURES_MAX as i64 + 1)
            .map(|i| 90 * DAY + i)
            .collect();
        assert!(in_coverage_failure(&past, 100 * DAY, COVERAGE_FAILURES_MAX));
    }

    #[test]
    fn failures_age_out_of_the_window() {
        let old: Vec<i64> = (0..30).map(|i| 10 * DAY + i).collect();
        assert!(!in_coverage_failure(&old, 100 * DAY, COVERAGE_FAILURES_MAX));
    }
}
