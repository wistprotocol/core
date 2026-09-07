use crate::confirmation::{
    confirming_index_including, confirming_index_with_quorum, independent, validate_log_order,
    CandidateRecord,
};
use crate::coverage::{within_days_ending_at, Block};
use crate::error::Error;
use crate::objects::audit::Verdict;
use crate::sampling::{draw, p_1e7, selected, SamplingConstants};
use crate::vrf::{self, PROOF_LEN};

pub const EXTENSION_TRIGGERS_MAX: u64 = 3;
pub const RATION_WINDOW_DAYS: u64 = 30;
pub const ESCALATION_WINDOW_DAYS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    Selected,
    Extension,
    Void,
}

/// A Block a proof may be over, with the key the Auditor held at its
/// `sealed_at`.
#[derive(Debug, Clone, Copy)]
pub struct ProofBlock<'a> {
    pub admitted_key: &'a [u8; 32],
    pub alpha: &'a [u8; 32],
}

/// `audited_block` is `None` when the Auditor held no key at the audited
/// Block; `trigger_block` is B₁ when the extension rule names
/// `audited_delta` for this Auditor, else `None`.
#[derive(Debug, Clone, Copy)]
pub struct StandingClaim<'a> {
    pub audited_block: Option<ProofBlock<'a>>,
    pub audited_delta: &'a str,
    pub reputation_u: u64,
    pub level1_sanction: bool,
    pub escalated_sampling: bool,
    pub sampling: SamplingConstants,
    pub trigger_block: Option<ProofBlock<'a>>,
    pub vrf_proof: &'a [u8; PROOF_LEN],
}

pub fn standing(claim: &StandingClaim<'_>) -> Standing {
    if let Some(block) = claim.audited_block {
        if let Ok(beta) = vrf::verify(block.admitted_key, block.alpha, claim.vrf_proof) {
            let d = draw(&beta, claim.audited_delta);
            if selected(
                d,
                p_1e7(
                    claim.reputation_u,
                    claim.level1_sanction,
                    claim.escalated_sampling,
                    &claim.sampling,
                ),
            ) {
                return Standing::Selected;
            }
        }
    }
    if let Some(block) = claim.trigger_block {
        if vrf::verify(block.admitted_key, block.alpha, claim.vrf_proof).is_ok() {
            return Standing::Extension;
        }
    }
    Standing::Void
}

pub fn trigger_indices(
    records: &[CandidateRecord],
    window_hours: u64,
) -> Result<Vec<usize>, Error> {
    validate_log_order(records)?;
    let window_s = i128::from(window_hours) * 3_600;
    Ok(records
        .iter()
        .enumerate()
        .filter(|(i, record)| {
            !records[..*i].iter().any(|earlier| {
                i128::from(record.block_sealed_at_s) - i128::from(earlier.block_sealed_at_s)
                    <= window_s
            })
        })
        .map(|(i, _)| i)
        .collect())
}

pub fn extension_deadline_s(b1_sealed_at_s: i64, confirm_window_hours: u64) -> i128 {
    i128::from(b1_sealed_at_s) + i128::from(confirm_window_hours / 2) * 3_600
}

pub fn rationed_summons(
    triggers: &[(&str, i64)],
    window_days: u64,
    triggers_max: u64,
) -> Vec<bool> {
    let mut summons: Vec<bool> = Vec::with_capacity(triggers.len());
    for (i, &(auditor, at_s)) in triggers.iter().enumerate() {
        let prior = triggers[..i]
            .iter()
            .zip(&summons)
            .filter(|(&(earlier_auditor, earlier_s), &summoned)| {
                summoned
                    && earlier_auditor == auditor
                    && within_days_ending_at(earlier_s, at_s, window_days)
            })
            .count() as u64;
        summons.push(prior < triggers_max);
    }
    summons
}

pub fn summoned(
    roster: &[&str],
    already_sealed_auditors: &[&str],
    publisher_domain: &str,
) -> Vec<usize> {
    roster
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            independent(candidate, publisher_domain)
                && already_sealed_auditors
                    .iter()
                    .all(|filer| independent(candidate, filer))
        })
        .map(|(i, _)| i)
        .collect()
}

#[derive(Debug, Clone)]
pub struct ExtensionRecord<'a> {
    pub position: CandidateRecord<'a>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtensionClaim {
    pub trigger_index: usize,
    pub summoned: bool,
    pub confirm_window_hours: u64,
    pub confirm_auditors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionOutcome {
    pub closing_block: Option<Block>,
    pub confirmed: bool,
    pub consistent_quorum: bool,
    pub establishing_block: Option<Block>,
}

pub fn evaluate(
    claim: &ExtensionClaim,
    records: &[ExtensionRecord<'_>],
    blocks: &[Block],
) -> Result<ExtensionOutcome, Error> {
    let positions: Vec<_> = records.iter().map(|r| r.position.clone()).collect();
    validate_log_order(&positions)?;
    if blocks
        .windows(2)
        .any(|pair| pair[0].height >= pair[1].height || pair[0].sealed_at_s >= pair[1].sealed_at_s)
    {
        return Err(Error::Confirmation("Blocks are not in Log order".into()));
    }
    for record in records {
        let position = &record.position;
        let block = blocks
            .binary_search_by_key(&position.block_height, |block| block.height)
            .ok()
            .map(|i| blocks[i]);
        if block.is_none_or(|block| block.sealed_at_s != position.block_sealed_at_s) {
            return Err(Error::Confirmation(
                "Record has no matching sealed Block".into(),
            ));
        }
    }
    let trigger = records
        .get(claim.trigger_index)
        .ok_or_else(|| Error::Confirmation("trigger Record is absent".into()))?;
    if !matches!(
        trigger.verdict,
        Verdict::Inconsistent | Verdict::LinkInconsistent
    ) {
        return Err(Error::Confirmation(
            "Record cannot trigger an extension".into(),
        ));
    }
    let start = i128::from(trigger.position.block_sealed_at_s);
    let end = start + i128::from(claim.confirm_window_hours) * 3_600;
    let closing_block = blocks
        .iter()
        .find(|block| i128::from(block.sealed_at_s) > end)
        .copied();
    let matching: Vec<_> = records
        .iter()
        .filter(|record| {
            record.verdict == trigger.verdict
                && i128::from(record.position.block_sealed_at_s) <= end
        })
        .map(|record| record.position.clone())
        .collect();
    let required_index = matching
        .iter()
        .position(|record| {
            (record.block_height, record.entry_index)
                == (trigger.position.block_height, trigger.position.entry_index)
        })
        .unwrap();
    let confirmed = confirming_index_including(
        &matching,
        claim.confirm_window_hours,
        claim.confirm_auditors,
        required_index,
    )?
    .is_some();
    let consistent: Vec<_> = records
        .iter()
        .filter(|record| {
            record.verdict == Verdict::Consistent
                && (start..=end).contains(&i128::from(record.position.block_sealed_at_s))
        })
        .map(|record| record.position.clone())
        .collect();
    let consistent_quorum = confirming_index_with_quorum(
        &consistent,
        claim.confirm_window_hours,
        claim.confirm_auditors,
    )?
    .is_some();
    Ok(ExtensionOutcome {
        closing_block,
        confirmed,
        consistent_quorum,
        establishing_block: closing_block
            .filter(|_| claim.summoned && !confirmed && consistent_quorum),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Escalation<'a> {
    pub publisher_domain: &'a str,
    pub establishing_block: Block,
}

pub fn escalated_sampling(
    escalations: &[Escalation<'_>],
    publisher_domain: &str,
    at: Block,
) -> bool {
    escalations.iter().any(|escalation| {
        let established = escalation.establishing_block;
        let age = i128::from(at.sealed_at_s) - i128::from(established.sealed_at_s);
        escalation.publisher_domain == publisher_domain
            && established.height <= at.height
            && (0..i128::from(ESCALATION_WINDOW_DAYS) * 86_400).contains(&age)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sampling::DEFAULT_SAMPLING;

    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;

    fn rec(height: u64, sealed_hours: i64, auditor_id: &str) -> CandidateRecord<'_> {
        CandidateRecord {
            block_height: height,
            entry_index: 0,
            block_sealed_at_s: sealed_hours * HOUR,
            auditor_id,
            effective_similarity: 0,
        }
    }

    #[test]
    fn a_lone_first_record_triggers() {
        let records = [rec(1, 0, "audit.example.net")];
        assert_eq!(trigger_indices(&records, 72).unwrap(), vec![0]);
    }

    #[test]
    fn a_record_inside_the_trailing_window_does_not_trigger() {
        let records = [
            rec(1, 0, "audit.example.net"),
            rec(2, 72, "checker.example.org"),
        ];
        assert_eq!(trigger_indices(&records, 72).unwrap(), vec![0]);
    }

    #[test]
    fn a_record_past_the_trailing_window_triggers_again() {
        let records = [
            rec(1, 0, "audit.example.net"),
            rec(2, 73, "checker.example.org"),
        ];
        assert_eq!(trigger_indices(&records, 72).unwrap(), vec![0, 1]);
    }

    #[test]
    fn the_trailing_check_reads_any_earlier_record_not_only_triggers() {
        let records = [
            rec(1, 0, "audit.example.net"),
            rec(2, 50, "checker.example.org"),
            rec(3, 100, "watch.sample.net"),
        ];
        assert_eq!(trigger_indices(&records, 72).unwrap(), vec![0]);
    }

    #[test]
    fn trigger_detection_rejects_out_of_order_input() {
        let records = [
            rec(2, 10, "audit.example.net"),
            rec(1, 0, "checker.example.org"),
        ];
        assert!(trigger_indices(&records, 72).is_err());
    }

    #[test]
    fn extension_deadline_is_half_the_window_integer_division() {
        assert_eq!(extension_deadline_s(1000, 72), i128::from(1000 + 36 * HOUR));
        assert_eq!(extension_deadline_s(0, 73), i128::from(36 * HOUR));
    }

    #[test]
    fn maximum_wire_window_preserves_deadlines_and_trigger_lookback() {
        let maximum = (1u64 << 53) - 1;
        assert_eq!(extension_deadline_s(0, maximum), 16_212_958_658_533_782_000);
        let records = [
            rec(0, 0, "audit.example.net"),
            rec(1, 100, "checker.example.org"),
        ];
        assert_eq!(trigger_indices(&records, maximum).unwrap(), vec![0]);
        let extension = [extension_record(
            0,
            "audit.example.net",
            Verdict::Inconsistent,
        )];
        let claim = ExtensionClaim {
            confirm_window_hours: maximum,
            ..CLAIM
        };
        assert_eq!(
            evaluate(&claim, &extension, &blocks_through(100))
                .unwrap()
                .closing_block,
            None
        );
    }

    #[test]
    fn first_three_triggers_summon_the_fourth_does_not() {
        let a = "audit.example.net";
        let triggers = [(a, 0), (a, DAY), (a, 2 * DAY), (a, 3 * DAY)];
        assert_eq!(
            rationed_summons(&triggers, RATION_WINDOW_DAYS, EXTENSION_TRIGGERS_MAX),
            vec![true, true, true, false]
        );
    }

    #[test]
    fn the_ration_resets_as_summons_age_out() {
        let a = "audit.example.net";
        let triggers = [(a, 0), (a, DAY), (a, 2 * DAY), (a, 32 * DAY)];
        assert_eq!(
            rationed_summons(&triggers, RATION_WINDOW_DAYS, EXTENSION_TRIGGERS_MAX),
            vec![true, true, true, true]
        );
    }

    #[test]
    fn a_rationed_out_trigger_does_not_consume_ration() {
        let a = "audit.example.net";
        let triggers = [
            (a, 0),
            (a, HOUR),
            (a, 2 * HOUR),
            (a, 3 * HOUR),
            (a, 30 * DAY + HOUR),
        ];
        assert_eq!(
            rationed_summons(&triggers, RATION_WINDOW_DAYS, EXTENSION_TRIGGERS_MAX),
            vec![true, true, true, false, true]
        );
    }

    #[test]
    fn rations_are_per_auditor() {
        let triggers = [
            ("audit.example.net", 0),
            ("audit.example.net", HOUR),
            ("audit.example.net", 2 * HOUR),
            ("checker.example.org", 3 * HOUR),
        ];
        assert_eq!(
            rationed_summons(&triggers, RATION_WINDOW_DAYS, EXTENSION_TRIGGERS_MAX),
            vec![true, true, true, true]
        );
    }

    #[test]
    fn summoned_filters_dependents_of_filers_and_publisher() {
        let roster = [
            "audit.example.net",
            "peer.example.net",
            "checker.example.org",
            "watch.publisher.example",
        ];
        let got = summoned(&roster, &["audit.example.net"], "www.publisher.example");
        assert_eq!(got, vec![2]);
    }

    #[test]
    fn summoned_requires_independence_from_every_filer() {
        let roster = ["watch.sample.net", "peer.example.net"];
        let got = summoned(
            &roster,
            &["audit.example.net", "eye.sample.net"],
            "www.publisher.example",
        );
        assert_eq!(got, Vec::<usize>::new());
    }

    fn extension_record(hours: i64, auditor: &str, verdict: Verdict) -> ExtensionRecord<'_> {
        ExtensionRecord {
            position: rec(hours as u64, hours, auditor),
            verdict,
        }
    }

    fn blocks_through(hours: u64) -> Vec<Block> {
        (0..=hours)
            .map(|height| Block {
                height,
                sealed_at_s: height as i64 * HOUR,
            })
            .collect()
    }

    const CLAIM: ExtensionClaim = ExtensionClaim {
        trigger_index: 0,
        summoned: true,
        confirm_window_hours: 72,
        confirm_auditors: 2,
    };

    #[test]
    fn closing_reads_actual_blocks_and_waits_past_the_fixed_endpoint() {
        let records = [
            extension_record(0, "audit.example.net", Verdict::Inconsistent),
            extension_record(10, "checker.example.org", Verdict::Consistent),
            extension_record(72, "watch.sample.net", Verdict::Consistent),
        ];
        let mut blocks = blocks_through(72);
        let open = evaluate(&CLAIM, &records, &blocks).unwrap();
        assert!(open.consistent_quorum);
        assert_eq!(open.closing_block, None);
        assert_eq!(open.establishing_block, None);
        let closing = Block {
            height: 73,
            sealed_at_s: 72 * HOUR + 1,
        };
        blocks.push(closing);
        let closed = evaluate(&CLAIM, &records, &blocks).unwrap();
        assert_eq!(closed.closing_block, Some(closing));
        assert_eq!(closed.establishing_block, Some(closing));
        blocks[73].sealed_at_s = 100 * HOUR;
        assert_eq!(
            evaluate(&CLAIM, &records, &blocks)
                .unwrap()
                .establishing_block,
            Some(blocks[73])
        );
    }

    #[test]
    fn closed_contradiction_ignores_later_confirming_records() {
        let mut records = vec![
            extension_record(0, "audit.example.net", Verdict::Inconsistent),
            extension_record(10, "checker.example.org", Verdict::Consistent),
            extension_record(20, "watch.sample.net", Verdict::Consistent),
        ];
        let closed = evaluate(&CLAIM, &records, &blocks_through(73)).unwrap();
        records.push(extension_record(
            74,
            "checker.example.org",
            Verdict::Inconsistent,
        ));
        records.push(extension_record(
            75,
            "watch.sample.net",
            Verdict::Inconsistent,
        ));
        assert_eq!(
            evaluate(&CLAIM, &records, &blocks_through(100)).unwrap(),
            closed
        );
    }

    #[test]
    fn trigger_containing_quorum_can_read_earlier_records_inside_its_width() {
        let mut records = [
            extension_record(0, "checker.example.org", Verdict::Inconsistent),
            extension_record(72, "audit.example.net", Verdict::Inconsistent),
            extension_record(73, "watch.sample.net", Verdict::Inconsistent),
        ];
        let claim = ExtensionClaim {
            trigger_index: 1,
            ..CLAIM
        };
        assert!(
            evaluate(&claim, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
        let quorum_three = ExtensionClaim {
            confirm_auditors: 3,
            ..claim
        };
        assert!(
            !evaluate(&quorum_three, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
        records[0] = extension_record(1, "checker.example.org", Verdict::Inconsistent);
        assert!(
            evaluate(&quorum_three, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
    }

    #[test]
    fn confirming_quorum_must_include_the_trigger_and_match_its_verdict() {
        let mut records = [
            extension_record(0, "old.example.org", Verdict::Inconsistent),
            extension_record(72, "audit.example.net", Verdict::Inconsistent),
            extension_record(73, "peer.example.net", Verdict::Inconsistent),
            extension_record(74, "watch.sample.net", Verdict::LinkInconsistent),
        ];
        let claim = ExtensionClaim {
            trigger_index: 1,
            confirm_auditors: 3,
            ..CLAIM
        };
        assert!(
            !evaluate(&claim, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
        records[3].verdict = Verdict::Inconsistent;
        assert!(
            !evaluate(&claim, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
        records[0] = extension_record(2, "old.example.org", Verdict::Inconsistent);
        assert!(
            evaluate(&claim, &records, &blocks_through(145))
                .unwrap()
                .confirmed
        );
    }

    #[test]
    fn consistent_records_before_the_trigger_count_only_in_its_block() {
        let mut records = [
            extension_record(9, "checker.example.org", Verdict::Consistent),
            extension_record(10, "audit.example.net", Verdict::Inconsistent),
            extension_record(11, "watch.sample.net", Verdict::Consistent),
        ];
        let claim = ExtensionClaim {
            trigger_index: 1,
            ..CLAIM
        };
        assert!(
            !evaluate(&claim, &records, &blocks_through(83))
                .unwrap()
                .consistent_quorum
        );
        records[0] = extension_record(10, "checker.example.org", Verdict::Consistent);
        records[1].position.entry_index = 1;
        assert!(evaluate(&claim, &records, &blocks_through(83))
            .unwrap()
            .establishing_block
            .is_some());
    }

    #[test]
    fn escalation_is_scoped_to_domain_height_and_thirty_days() {
        let first = Escalation {
            publisher_domain: "page.example.org",
            establishing_block: Block {
                height: 10,
                sealed_at_s: 0,
            },
        };
        for (height, time, expected) in [
            (9, 0, false),
            (10, -1, false),
            (10, 0, true),
            (11, 30 * DAY - 1, true),
            (12, 30 * DAY, false),
        ] {
            let at = Block {
                height,
                sealed_at_s: time,
            };
            assert_eq!(
                escalated_sampling(&[first], first.publisher_domain, at),
                expected
            );
            assert!(!escalated_sampling(&[first], "other.example.org", at));
        }
        let renewed = Escalation {
            establishing_block: Block {
                height: 11,
                sealed_at_s: DAY,
            },
            ..first
        };
        assert!(escalated_sampling(
            &[first, renewed],
            first.publisher_domain,
            Block {
                height: 12,
                sealed_at_s: 30 * DAY
            },
        ));
    }

    #[test]
    fn extension_rejects_invalid_inputs() {
        let mut records = [extension_record(
            0,
            "audit.example.net",
            Verdict::Inconsistent,
        )];
        let mut blocks = blocks_through(73);
        assert!(evaluate(
            &ExtensionClaim {
                trigger_index: 1,
                ..CLAIM
            },
            &records,
            &blocks
        )
        .is_err());
        assert!(evaluate(
            &ExtensionClaim {
                confirm_auditors: 1,
                ..CLAIM
            },
            &records,
            &blocks
        )
        .is_err());
        blocks.swap(0, 1);
        assert!(evaluate(&CLAIM, &records, &blocks).is_err());
        blocks.swap(0, 1);
        records[0].position.block_sealed_at_s = 1;
        assert!(evaluate(&CLAIM, &records, &blocks).is_err());
        records[0].position.block_sealed_at_s = 0;
        records[0].verdict = Verdict::Consistent;
        assert!(evaluate(&CLAIM, &records, &blocks).is_err());
    }

    const AUDITED_ALPHA: [u8; 32] = [1; 32];
    const TRIGGER_ALPHA: [u8; 32] = [2; 32];

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = [seed; 32];
        (sk, vrf::public_key(&sk))
    }

    fn delta_where(beta: &[u8; 64], wanted: impl Fn(u64) -> bool) -> String {
        (0u32..)
            .map(|i| format!("sha256:{i:064x}"))
            .find(|d| wanted(draw(beta, d)))
            .unwrap()
    }

    #[test]
    fn standing_reads_the_sampling_constants_in_force_at_the_audited_block() {
        let (sk, pk) = keypair(7);
        let pi = vrf::prove(&sk, &AUDITED_ALPHA).unwrap();
        let beta = vrf::verify(&pk, &AUDITED_ALPHA, &pi).unwrap();
        let narrowed = SamplingConstants {
            floor_1e7: 1,
            ceiling_1e7: 5_000_000,
            slope_per_micro: 3,
        };
        let marginal = delta_where(&beta, |d| {
            selected(d, p_1e7(1_000_000, false, false, &DEFAULT_SAMPLING))
                && !selected(d, p_1e7(1_000_000, false, false, &narrowed))
        });
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: &marginal,
            reputation_u: 1_000_000,
            level1_sanction: false,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            trigger_block: None,
            vrf_proof: &pi,
        };
        assert_eq!(standing(&claim), Standing::Selected);
        let amended = StandingClaim {
            sampling: narrowed,
            ..claim
        };
        assert_eq!(standing(&amended), Standing::Void);
    }

    #[test]
    fn a_selecting_proof_over_the_audited_block_stands_selected_even_when_summoned() {
        let (sk, pk) = keypair(7);
        let pi = vrf::prove(&sk, &AUDITED_ALPHA).unwrap();
        let beta = vrf::verify(&pk, &AUDITED_ALPHA, &pi).unwrap();
        let chosen = delta_where(&beta, |d| {
            selected(d, p_1e7(1_000_000, false, false, &DEFAULT_SAMPLING))
        });
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: &chosen,
            reputation_u: 1_000_000,
            level1_sanction: false,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            trigger_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &TRIGGER_ALPHA,
            }),
            vrf_proof: &pi,
        };
        assert_eq!(standing(&claim), Standing::Selected);
    }

    #[test]
    fn a_level1_sanction_widens_the_draw_that_gives_standing() {
        let (sk, pk) = keypair(7);
        let pi = vrf::prove(&sk, &AUDITED_ALPHA).unwrap();
        let beta = vrf::verify(&pk, &AUDITED_ALPHA, &pi).unwrap();
        let marginal = delta_where(&beta, |d| {
            !selected(d, p_1e7(1_000_000, false, false, &DEFAULT_SAMPLING))
                && selected(d, p_1e7(1_000_000, true, false, &DEFAULT_SAMPLING))
        });
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: &marginal,
            reputation_u: 1_000_000,
            level1_sanction: false,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            trigger_block: None,
            vrf_proof: &pi,
        };
        assert_eq!(standing(&claim), Standing::Void);
        let sanctioned = StandingClaim {
            level1_sanction: true,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            ..claim
        };
        assert_eq!(standing(&sanctioned), Standing::Selected);
        let escalated = StandingClaim {
            escalated_sampling: true,
            ..claim
        };
        assert_eq!(standing(&escalated), Standing::Selected);
    }

    #[test]
    fn no_key_at_the_audited_block_leaves_only_the_extension_path() {
        let (sk, pk) = keypair(9);
        let pi = vrf::prove(&sk, &TRIGGER_ALPHA).unwrap();
        let claim = StandingClaim {
            audited_block: None,
            audited_delta: "sha256:00",
            reputation_u: 0,
            level1_sanction: true,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            trigger_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &TRIGGER_ALPHA,
            }),
            vrf_proof: &pi,
        };
        assert_eq!(standing(&claim), Standing::Extension);
        let unsummoned = StandingClaim {
            trigger_block: None,
            ..claim
        };
        assert_eq!(standing(&unsummoned), Standing::Void);
    }

    #[test]
    fn an_extension_proof_reads_the_key_admitted_at_b1() {
        let (old_sk, old_pk) = keypair(3);
        let (new_sk, new_pk) = keypair(4);
        let pi_new = vrf::prove(&new_sk, &TRIGGER_ALPHA).unwrap();
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &old_pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: "sha256:00",
            reputation_u: 0,
            level1_sanction: true,
            escalated_sampling: false,
            sampling: DEFAULT_SAMPLING,
            trigger_block: Some(ProofBlock {
                admitted_key: &new_pk,
                alpha: &TRIGGER_ALPHA,
            }),
            vrf_proof: &pi_new,
        };
        assert_eq!(standing(&claim), Standing::Extension);
        let pi_old = vrf::prove(&old_sk, &TRIGGER_ALPHA).unwrap();
        let under_the_old_key = StandingClaim {
            vrf_proof: &pi_old,
            ..claim
        };
        assert_eq!(standing(&under_the_old_key), Standing::Void);
    }
}
