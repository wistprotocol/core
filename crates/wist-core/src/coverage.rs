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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoidReason {
    RemovedAfterAnchorBlock,
    CoverageFailureAtSealing,
    MalformedEvidence,
    NeverAdmittedAtAnchorBlock,
    ProofWithoutStanding,
    OutsideSelectionDomain,
    SelfAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedBy {
    Draw,
    Extension,
}

pub fn void_record_discharges(void: &[VoidReason]) -> bool {
    void.iter().all(|reason| {
        matches!(
            reason,
            VoidReason::RemovedAfterAnchorBlock
                | VoidReason::CoverageFailureAtSealing
                | VoidReason::MalformedEvidence
        )
    })
}

pub fn duty_anchor_s(named_by: NamedBy, audited_sealed_at_s: i64, trigger_sealed_at_s: i64) -> i64 {
    match named_by {
        NamedBy::Draw => audited_sealed_at_s,
        NamedBy::Extension => trigger_sealed_at_s,
    }
}

pub fn removal_void(
    named_by: NamedBy,
    audited_sealed_at_s: i64,
    trigger_sealed_at_s: i64,
    removed_at_s: i64,
) -> VoidReason {
    if removed_at_s > duty_anchor_s(named_by, audited_sealed_at_s, trigger_sealed_at_s) {
        VoidReason::RemovedAfterAnchorBlock
    } else {
        VoidReason::NeverAdmittedAtAnchorBlock
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub sealed_at_s: i64,
}

pub fn establishing_height(
    blocks: &[Block],
    deadline_s: i64,
    attestation_height: Option<u64>,
    record_seal_blocks: u64,
) -> Option<u64> {
    if let Some(height) = attestation_height {
        return Some(height);
    }
    blocks
        .iter()
        .filter(|b| b.sealed_at_s > deadline_s)
        .nth(record_seal_blocks as usize - 1)
        .map(|b| b.height)
}

pub fn failure_counts_at(
    establishing_height: Option<u64>,
    audited_sealed_at_s: i64,
    n_height: u64,
    n_sealed_at_s: i64,
) -> bool {
    establishing_height.is_some_and(|h| h <= n_height)
        && within_days_ending_at(audited_sealed_at_s, n_sealed_at_s, WINDOW_DAYS)
}

pub fn chain_gap(sealed: &[(&str, Option<&str>)]) -> bool {
    let ids: Vec<&str> = sealed.iter().map(|(id, _)| *id).collect();
    sealed
        .iter()
        .any(|(_, prev)| prev.is_some_and(|p| !ids.contains(&p)))
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
    fn an_unattested_pair_establishes_at_the_nth_block_past_the_deadline() {
        let blocks: Vec<Block> = (170..185)
            .map(|h| Block {
                height: h,
                sealed_at_s: h as i64 * 3600,
            })
            .collect();
        assert_eq!(establishing_height(&blocks, 619_200, None, 4), Some(176));
        assert_eq!(
            establishing_height(&blocks[..3], 619_200, None, 4),
            None,
            "the deadline has not been passed by record_seal_blocks Blocks"
        );
        assert_eq!(
            establishing_height(&blocks, 619_200, Some(180), 4),
            Some(180),
            "an attestation establishes at its own Block"
        );
    }

    #[test]
    fn a_failure_counts_from_its_establishing_height_and_only_inside_the_window() {
        assert!(!failure_counts_at(Some(180), 360_000, 179, 644_400));
        assert!(failure_counts_at(Some(180), 360_000, 180, 648_000));
        assert!(!failure_counts_at(None, 360_000, 1_000, 3_600_000));
        assert!(
            !failure_counts_at(Some(820), 360_000, 820, 2_952_000),
            "evidence past the audited Block's 30-day window counts at no height"
        );
    }

    #[test]
    fn the_chain_gap_reads_one_logs_items() {
        let log_a = [
            ("sha256:p1", None),
            ("sha256:p3", Some("sha256:p1")),
            ("sha256:p5", Some("sha256:p3")),
        ];
        assert!(!chain_gap(&log_a));
        let suppressed = [("sha256:p1", None), ("sha256:p5", Some("sha256:p3"))];
        assert!(chain_gap(&suppressed));
        let global_order = [
            ("sha256:p1", None),
            ("sha256:p3", Some("sha256:p2")),
            ("sha256:p5", Some("sha256:p4")),
        ];
        assert!(
            chain_gap(&global_order),
            "a chain spanning two Logs shows a gap in each"
        );
    }

    #[test]
    fn a_standing_record_the_two_carve_outs_and_malformed_evidence_discharge() {
        assert!(void_record_discharges(&[]));
        assert!(void_record_discharges(&[
            VoidReason::RemovedAfterAnchorBlock
        ]));
        assert!(void_record_discharges(&[
            VoidReason::CoverageFailureAtSealing
        ]));
        assert!(void_record_discharges(&[VoidReason::MalformedEvidence]));
        assert!(void_record_discharges(&[
            VoidReason::RemovedAfterAnchorBlock,
            VoidReason::CoverageFailureAtSealing,
            VoidReason::MalformedEvidence
        ]));
    }

    #[test]
    fn a_record_with_no_duty_behind_it_discharges_nothing() {
        for void in [
            VoidReason::NeverAdmittedAtAnchorBlock,
            VoidReason::ProofWithoutStanding,
            VoidReason::OutsideSelectionDomain,
            VoidReason::SelfAudit,
        ] {
            assert!(!void_record_discharges(&[void]), "{void:?}");
            assert!(
                !void_record_discharges(&[VoidReason::RemovedAfterAnchorBlock, void]),
                "{void:?} beside a carve-out"
            );
            assert!(
                !void_record_discharges(&[VoidReason::MalformedEvidence, void]),
                "{void:?} beside malformed evidence"
            );
        }
    }

    #[test]
    fn a_removal_is_read_at_the_block_the_duty_is_anchored_to() {
        let (audited, trigger) = (100 * DAY, 101 * DAY);
        assert_eq!(
            removal_void(NamedBy::Draw, audited, trigger, audited + 1),
            VoidReason::RemovedAfterAnchorBlock
        );
        assert_eq!(
            removal_void(NamedBy::Draw, audited, trigger, audited),
            VoidReason::NeverAdmittedAtAnchorBlock
        );
        assert_eq!(
            removal_void(NamedBy::Extension, audited, trigger, trigger + 1),
            VoidReason::RemovedAfterAnchorBlock
        );
        assert_eq!(
            removal_void(NamedBy::Extension, audited, trigger, trigger - 1),
            VoidReason::NeverAdmittedAtAnchorBlock
        );
        assert_eq!(
            removal_void(NamedBy::Extension, audited, trigger, trigger),
            VoidReason::NeverAdmittedAtAnchorBlock
        );
    }

    #[test]
    fn failures_age_out_of_the_window() {
        let old: Vec<i64> = (0..30).map(|i| 10 * DAY + i).collect();
        assert!(!in_coverage_failure(&old, 100 * DAY, COVERAGE_FAILURES_MAX));
    }
}
