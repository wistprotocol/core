use crate::confirmation::{independent, validate_log_order, CandidateRecord};
use crate::coverage::within_days_ending_at;
use crate::error::Error;
use crate::sampling::{draw, p_1e7, selected};
use crate::vrf::{self, PROOF_LEN};

pub const EXTENSION_TRIGGERS_MAX: u64 = 3;
pub const CONTRADICTIONS_MAX: u64 = 2;
pub const RATION_WINDOW_DAYS: u64 = 30;

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
    pub trigger_block: Option<ProofBlock<'a>>,
    pub vrf_proof: &'a [u8; PROOF_LEN],
}

pub fn standing(claim: &StandingClaim<'_>) -> Standing {
    if let Some(block) = claim.audited_block {
        if let Ok(beta) = vrf::verify(block.admitted_key, block.alpha, claim.vrf_proof) {
            let d = draw(&beta, claim.audited_delta);
            if selected(d, p_1e7(claim.reputation_u, claim.level1_sanction)) {
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
    let window_s = (window_hours as i64) * 3_600;
    Ok(records
        .iter()
        .enumerate()
        .filter(|(i, record)| {
            !records[..*i]
                .iter()
                .any(|earlier| record.block_sealed_at_s - earlier.block_sealed_at_s <= window_s)
        })
        .map(|(i, _)| i)
        .collect())
}

pub fn extension_deadline_s(b1_sealed_at_s: i64, confirm_window_hours: u64) -> i64 {
    b1_sealed_at_s + ((confirm_window_hours / 2) as i64) * 3_600
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

pub fn has_independent_pair(auditor_ids: &[&str]) -> bool {
    auditor_ids
        .iter()
        .enumerate()
        .any(|(i, a)| auditor_ids[..i].iter().any(|b| independent(a, b)))
}

pub fn contradicted(summoning: bool, confirmed: bool, independent_consistent_pair: bool) -> bool {
    summoning && !confirmed && independent_consistent_pair
}

pub fn in_divergence(
    contradiction_times_s: &[i64],
    n_sealed_at_s: i64,
    contradictions_max: u64,
) -> bool {
    let in_window = contradiction_times_s
        .iter()
        .filter(|&&t| within_days_ending_at(t, n_sealed_at_s, RATION_WINDOW_DAYS))
        .count() as u64;
    in_window > contradictions_max
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(extension_deadline_s(1000, 72), 1000 + 36 * HOUR);
        assert_eq!(extension_deadline_s(0, 73), 36 * HOUR);
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

    #[test]
    fn independent_pair_detection() {
        assert!(!has_independent_pair(&[]));
        assert!(!has_independent_pair(&["a.example.org"]));
        assert!(!has_independent_pair(&["a.example.org", "b.example.org"]));
        assert!(has_independent_pair(&[
            "a.example.org",
            "b.example.org",
            "c.sample.net"
        ]));
    }

    #[test]
    fn contradiction_needs_summons_no_confirmation_and_an_independent_consistent_pair() {
        assert!(contradicted(true, false, true));
        assert!(!contradicted(false, false, true));
        assert!(!contradicted(true, true, true));
        assert!(!contradicted(true, false, false));
    }

    #[test]
    fn divergence_needs_strictly_more_than_the_maximum_inside_the_window() {
        let n = 100 * DAY;
        assert!(!in_divergence(&[99 * DAY, 98 * DAY], n, CONTRADICTIONS_MAX));
        assert!(in_divergence(
            &[99 * DAY, 98 * DAY, 97 * DAY],
            n,
            CONTRADICTIONS_MAX
        ));
        assert!(!in_divergence(
            &[60 * DAY, 98 * DAY, 97 * DAY],
            n,
            CONTRADICTIONS_MAX
        ));
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
    fn a_selecting_proof_over_the_audited_block_stands_selected_even_when_summoned() {
        let (sk, pk) = keypair(7);
        let pi = vrf::prove(&sk, &AUDITED_ALPHA).unwrap();
        let beta = vrf::verify(&pk, &AUDITED_ALPHA, &pi).unwrap();
        let chosen = delta_where(&beta, |d| selected(d, p_1e7(1_000_000, false)));
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: &chosen,
            reputation_u: 1_000_000,
            level1_sanction: false,
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
            !selected(d, p_1e7(1_000_000, false)) && selected(d, p_1e7(1_000_000, true))
        });
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &AUDITED_ALPHA,
            }),
            audited_delta: &marginal,
            reputation_u: 1_000_000,
            level1_sanction: false,
            trigger_block: None,
            vrf_proof: &pi,
        };
        assert_eq!(standing(&claim), Standing::Void);
        let sanctioned = StandingClaim {
            level1_sanction: true,
            ..claim
        };
        assert_eq!(standing(&sanctioned), Standing::Selected);
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
