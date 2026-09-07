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
        (Some(m), Some(c)) => c <= m,
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

#[derive(Debug, Clone, Copy)]
pub struct Notice<'a> {
    pub id: &'a str,
    pub subject: &'a str,
    pub sanction: bool,
    pub height: u64,
    pub sealed_at_s: i64,
    pub activation_height: u64,
    pub appeal_window_days: u64,
    pub appeal_seal_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessKind {
    Appeal,
    Ruling(Outcome),
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessAct<'a> {
    pub id: &'a str,
    pub notice: &'a str,
    pub subject: &'a str,
    pub height: u64,
    pub sealed_at_s: i64,
    pub kind: ProcessKind,
    pub ruling_deadline_days: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProcessState {
    pub appeal_index: Option<usize>,
    pub merits_index: Option<usize>,
    pub unappealed_index: Option<usize>,
    pub void_at_s: Option<i128>,
    pub rejected: Vec<usize>,
}

impl ProcessState {
    pub fn error_at(&self, index: usize) -> Option<&'static str> {
        self.rejected.contains(&index).then_some("WIST4-E05")
    }
}

pub fn process_at(
    notice: Notice<'_>,
    acts: &[ProcessAct<'_>],
    height: u64,
    sealed_at_s: i64,
) -> ProcessState {
    use std::collections::{BTreeMap, HashSet};

    let mut state = ProcessState::default();
    let mut blocks = BTreeMap::<u64, Vec<usize>>::new();
    for (i, act) in acts
        .iter()
        .enumerate()
        .filter(|(_, act)| act.height <= height)
    {
        blocks.entry(act.height).or_default().push(i);
    }
    let window_close =
        i128::from(notice.sealed_at_s) + i128::from(notice.appeal_window_days) * i128::from(DAY_S);
    let seal_due = window_close + i128::from(notice.appeal_seal_days) * i128::from(DAY_S);
    let mut seen = HashSet::new();
    for indices in blocks.values() {
        let mut eligible = Vec::new();
        for &i in indices {
            let act = &acts[i];
            if !seen.insert(act.id) {
                continue;
            }
            if !notice.sanction
                || act.notice != notice.id
                || act.subject != notice.subject
                || act.height < notice.height
            {
                state.rejected.push(i);
            } else {
                eligible.push(i);
            }
        }
        let appeals: Vec<usize> = eligible
            .iter()
            .copied()
            .filter(|&i| acts[i].kind == ProcessKind::Appeal)
            .collect();
        if state.appeal_index.is_none() && appeals.len() == 1 {
            state.appeal_index = Some(appeals[0]);
        } else {
            state.rejected.extend(appeals);
        }
        let timely_appeal = state
            .appeal_index
            .filter(|&i| i128::from(acts[i].sealed_at_s) <= seal_due);
        let mut merits = Vec::new();
        let mut unappealed = Vec::new();
        for i in eligible {
            let act = &acts[i];
            let ProcessKind::Ruling(outcome) = act.kind else {
                continue;
            };
            let at = i128::from(act.sealed_at_s);
            let valid = match outcome {
                Outcome::Unappealed => {
                    let valid = timely_appeal.is_none()
                        && state.unappealed_index.is_none()
                        && window_close <= at
                        && at <= seal_due;
                    if valid {
                        unappealed.push(i);
                    }
                    valid
                }
                Outcome::Upheld | Outcome::Overturned => {
                    let valid = state.merits_index.is_none()
                        && act.height > notice.activation_height
                        && timely_appeal.is_some_and(|a| {
                            at <= i128::from(acts[a].sealed_at_s)
                                + i128::from(acts[a].ruling_deadline_days) * i128::from(DAY_S)
                        });
                    if valid {
                        merits.push(i);
                    }
                    valid
                }
            };
            if !valid {
                state.rejected.push(i);
            }
        }
        if merits.len() == 1 {
            state.merits_index = Some(merits[0]);
        } else {
            state.rejected.extend(merits);
        }
        if unappealed.len() == 1 {
            state.unappealed_index = Some(unappealed[0]);
        } else {
            state.rejected.extend(unappealed);
        }
    }
    if notice.sanction && notice.height <= height {
        let timely_appeal = state
            .appeal_index
            .filter(|&i| i128::from(acts[i].sealed_at_s) <= seal_due);
        state.void_at_s = match timely_appeal {
            Some(a) => match state.merits_index {
                Some(r) if acts[r].kind == ProcessKind::Ruling(Outcome::Overturned) => {
                    Some(i128::from(acts[r].sealed_at_s))
                }
                Some(_) => None,
                None => Some(
                    i128::from(acts[a].sealed_at_s)
                        + i128::from(acts[a].ruling_deadline_days) * i128::from(DAY_S),
                ),
            },
            None if state.unappealed_index.is_none() => Some(seal_due),
            None => None,
        }
        .filter(|&at| at <= i128::from(sealed_at_s));
    }
    state.rejected.sort_unstable();
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    pub record_id: [u8; 32],
    pub height: u64,
    pub entry_index: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct OrderedFinding {
    pub record_id: [u8; 32],
    pub entry_index: u64,
    pub severity: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct NoticeVoid {
    pub level: u8,
    pub activation: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct SanctionBlock<'a> {
    pub height: u64,
    pub sealed_at_s: i64,
    pub reset: bool,
    pub lift: bool,
    pub voids: &'a [NoticeVoid],
    pub findings: &'a [OrderedFinding],
}

#[derive(Debug, Default)]
pub struct Ladder {
    active: [Option<Activation>; 4],
    findings: Vec<Finding>,
}

impl Ladder {
    pub fn active(&self) -> &[Option<Activation>; 4] {
        &self.active
    }

    pub fn level(&self) -> u8 {
        self.active
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |i| i as u8 + 1)
    }

    pub fn apply_block(&mut self, block: SanctionBlock<'_>) {
        let SanctionBlock {
            height,
            sealed_at_s,
            reset,
            lift,
            voids,
            findings,
        } = block;
        if reset {
            self.findings.clear();
        }
        if reset || lift {
            self.active.fill(None);
        }
        for void in voids {
            if let 3..=4 = void.level {
                let rung = &mut self.active[usize::from(void.level - 1)];
                if rung.is_some_and(|a| a.record_id == void.activation) {
                    *rung = None;
                }
            }
        }
        let mut ordered: Vec<_> = findings.iter().collect();
        ordered.sort_unstable_by_key(|f| f.entry_index);
        for finding in ordered {
            let further = self.active[2].is_some();
            self.findings.push(Finding {
                sealed_at_s,
                severity: finding.severity,
            });
            let count = |days, severity| {
                self.findings
                    .iter()
                    .filter(|f| {
                        f.severity >= severity
                            && within_days_ending_at(f.sealed_at_s, sealed_at_s, days)
                    })
                    .count() as u64
            };
            let all_90 = count(ESCALATION_L2_DAYS, 0);
            let severity_three = finding.severity == 3;
            let met = [
                true,
                all_90 >= ESCALATION_L2_COUNT,
                all_90 >= ESCALATION_L3_COUNT || severity_three,
                further
                    || (severity_three && count(ESCALATION_L4_DAYS, 3) >= ESCALATION_L4_SEV3_COUNT),
            ];
            for (rung, met) in self.active.iter_mut().zip(met) {
                if met && rung.is_none() {
                    *rung = Some(Activation {
                        record_id: finding.record_id,
                        height,
                        entry_index: finding.entry_index,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_rungs_keep_their_activation_and_ignore_stale_voids() {
        let mut ladder = Ladder::default();
        let apply = |ladder: &mut Ladder,
                     height: u64,
                     severity: Option<u8>,
                     lift,
                     reset,
                     voids: &[NoticeVoid]| {
            let findings = severity.map(|severity| OrderedFinding {
                record_id: [height as u8; 32],
                entry_index: 0,
                severity,
            });
            ladder.apply_block(SanctionBlock {
                height,
                sealed_at_s: height as i64 * DAY_S,
                lift,
                reset,
                voids,
                findings: findings.as_slice(),
            });
        };
        apply(&mut ladder, 0, Some(3), false, false, &[]);
        apply(&mut ladder, 1, Some(3), false, false, &[]);
        assert_eq!(ladder.active()[2].unwrap().record_id, [0; 32]);
        assert_eq!(ladder.active()[3].unwrap().record_id, [1; 32]);
        apply(&mut ladder, 2, Some(3), true, false, &[]);
        assert_eq!(ladder.active()[2].unwrap().record_id, [2; 32]);
        assert_eq!(ladder.level(), 4);
        apply(
            &mut ladder,
            3,
            None,
            false,
            false,
            &[NoticeVoid {
                level: 3,
                activation: [0; 32],
            }],
        );
        assert_eq!(ladder.active()[2].unwrap().record_id, [2; 32]);
        apply(
            &mut ladder,
            4,
            None,
            false,
            false,
            &[NoticeVoid {
                level: 4,
                activation: [2; 32],
            }],
        );
        assert_eq!(ladder.level(), 3);
        apply(&mut ladder, 5, Some(1), false, true, &[]);
        assert_eq!(ladder.level(), 1);
    }

    #[test]
    fn process_clocks_keep_their_anchors_and_exact_wire_arithmetic() {
        let notice = Notice {
            id: "n",
            subject: "s",
            sanction: true,
            height: 0,
            sealed_at_s: 0,
            activation_height: 0,
            appeal_window_days: 1,
            appeal_seal_days: 1,
        };
        let appeal = ProcessAct {
            id: "a",
            notice: "n",
            subject: "s",
            height: 1,
            sealed_at_s: DAY_S,
            kind: ProcessKind::Appeal,
            ruling_deadline_days: 2,
        };
        assert_eq!(
            process_at(notice, &[appeal], 2, 3 * DAY_S - 1).void_at_s,
            None
        );
        assert_eq!(
            process_at(notice, &[appeal], 2, 3 * DAY_S).void_at_s,
            Some(i128::from(3 * DAY_S))
        );
        let huge = ProcessAct {
            ruling_deadline_days: crate::parameters::WIRE_INTEGER_MAX as u64,
            ..appeal
        };
        assert_eq!(process_at(notice, &[huge], 2, i64::MAX).void_at_s, None);
        let huge_notice = Notice {
            appeal_window_days: crate::parameters::WIRE_INTEGER_MAX as u64,
            ..notice
        };
        assert_eq!(process_at(huge_notice, &[], 2, i64::MAX).void_at_s, None);
    }

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
        assert!(in_force(&[50], &[50], 100));
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
