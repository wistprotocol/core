use super::*;
use crate::confirmation::{ci_severity, independent, validate_log_order, CandidateRecord};
use crate::objects::{RegistryAction, RegistryUpdate};
use crate::Error;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct EvidenceRecord<'a> {
    pub id: [u8; 32],
    pub record: CandidateRecord<'a>,
    pub confirm_window_hours: u64,
    pub confirm_auditors: u64,
}

#[derive(Debug, Clone)]
pub struct ConfirmedFinding<'a> {
    records: &'a [EvidenceRecord<'a>],
    severity: u8,
}

impl<'a> ConfirmedFinding<'a> {
    pub fn new(records: &'a [EvidenceRecord<'a>], link: bool) -> Result<Self, Error> {
        let candidates: Vec<_> = records.iter().map(|r| r.record.clone()).collect();
        validate_log_order(&candidates)?;
        let ids: BTreeSet<_> = records.iter().map(|r| r.id).collect();
        let first = records
            .iter()
            .enumerate()
            .position(|(i, r)| quorum_at(records[..=i].iter(), r));
        if records.is_empty()
            || ids.len() != records.len()
            || records.iter().any(|r| r.confirm_auditors < 2)
            || first != Some(records.len() - 1)
        {
            return Err(Error::Sanction(
                "finding must end at its first confirmation".into(),
            ));
        }
        let severity = if link {
            1
        } else {
            ci_severity(&candidates, records.len() - 1)?
        };
        Ok(Self { records, severity })
    }

    fn confirming(&self) -> &EvidenceRecord<'a> {
        self.records.last().unwrap()
    }

    fn established_by(&self, evidence: &BTreeSet<[u8; 32]>) -> bool {
        if !evidence.contains(&self.confirming().id) {
            return false;
        }
        quorum_at(
            self.records.iter().filter(|r| evidence.contains(&r.id)),
            self.confirming(),
        )
    }
}

fn quorum_at<'a, 'b>(
    records: impl Iterator<Item = &'b EvidenceRecord<'a>>,
    anchor: &EvidenceRecord<'_>,
) -> bool
where
    'a: 'b,
{
    let mut members: Vec<&str> = Vec::new();
    for record in records {
        if i128::from(anchor.record.block_sealed_at_s) - i128::from(record.record.block_sealed_at_s)
            <= i128::from(anchor.confirm_window_hours) * 3600
            && members
                .iter()
                .all(|member| independent(member, record.record.auditor_id))
        {
            members.push(record.record.auditor_id);
        }
    }
    members.len() as u64 >= anchor.confirm_auditors
}

#[derive(Debug)]
enum Criterion {
    Count {
        findings: Vec<usize>,
        minimum: usize,
    },
    Any(Vec<Arc<Criterion>>),
    All(Vec<Arc<Criterion>>),
}

impl Criterion {
    fn established_by(
        &self,
        findings: &[ConfirmedFinding<'_>],
        evidence: &BTreeSet<[u8; 32]>,
    ) -> bool {
        match self {
            Self::Count {
                findings: indices,
                minimum,
            } => {
                indices
                    .iter()
                    .filter(|&&i| findings[i].established_by(evidence))
                    .count()
                    >= *minimum
            }
            Self::Any(branches) => branches
                .iter()
                .any(|b| b.established_by(findings, evidence)),
            Self::All(branches) => branches
                .iter()
                .all(|b| b.established_by(findings, evidence)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NoticeCandidate<'a> {
    pub id: &'a str,
    pub update: &'a RegistryUpdate,
}

#[derive(Debug, Clone, Copy)]
pub struct ReplayBlock<'a, 'b> {
    pub height: u64,
    pub sealed_at_s: i64,
    pub reset: bool,
    pub lift: bool,
    pub findings: &'b [ConfirmedFinding<'a>],
    pub available_records: &'b [[u8; 32]],
    pub notices: &'b [NoticeCandidate<'a>],
    pub acts: &'b [ProcessAct<'a>],
    pub appeal_window_days: u64,
    pub appeal_seal_days: u64,
}

#[derive(Debug)]
pub struct AcceptedNotice<'a> {
    pub notice: Notice<'a>,
    pub level: u8,
    pub activation: [u8; 32],
    pub evidence: Vec<[u8; 32]>,
    pub state: ProcessState,
    acts: Vec<ProcessAct<'a>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BlockAdmission {
    pub accepted_notices: Vec<usize>,
    pub rejected_notices: BTreeMap<usize, &'static str>,
    pub rejected_acts: Vec<usize>,
}

#[derive(Debug)]
pub struct Replay<'a> {
    subject: &'a str,
    ladder: Ladder,
    findings: Vec<ConfirmedFinding<'a>>,
    identity_start: usize,
    criteria: [Option<Arc<Criterion>>; 4],
    notices: Vec<AcceptedNotice<'a>>,
    seen_notices: BTreeSet<&'a str>,
    seen_acts: BTreeSet<&'a str>,
    available_records: BTreeSet<[u8; 32]>,
    last_block: Option<(u64, i64)>,
}

impl<'a> Replay<'a> {
    pub fn new(subject: &'a str) -> Self {
        Self {
            subject,
            ladder: Ladder::default(),
            findings: Vec::new(),
            identity_start: 0,
            criteria: Default::default(),
            notices: Vec::new(),
            seen_notices: BTreeSet::new(),
            seen_acts: BTreeSet::new(),
            available_records: BTreeSet::new(),
            last_block: None,
        }
    }

    pub fn ladder(&self) -> &Ladder {
        &self.ladder
    }

    pub fn notices(&self) -> &[AcceptedNotice<'a>] {
        &self.notices
    }

    pub fn apply_block(&mut self, block: ReplayBlock<'a, '_>) -> Result<BlockAdmission, Error> {
        if self
            .last_block
            .is_some_and(|(h, t)| block.height <= h || block.sealed_at_s <= t)
            || block
                .acts
                .iter()
                .any(|a| a.height != block.height || a.sealed_at_s != block.sealed_at_s)
            || block.findings.iter().any(|f| {
                f.confirming().record.block_height != block.height
                    || f.confirming().record.block_sealed_at_s != block.sealed_at_s
            })
        {
            return Err(Error::Sanction(
                "inputs must follow authenticated Block chronology".into(),
            ));
        }
        let positions: BTreeSet<_> = block
            .findings
            .iter()
            .map(|f| f.confirming().record.entry_index)
            .collect();
        if positions.len() != block.findings.len() {
            return Err(Error::Sanction(
                "findings must have distinct confirming positions".into(),
            ));
        }
        self.last_block = Some((block.height, block.sealed_at_s));
        self.available_records.extend(block.available_records);
        let mut result = BlockAdmission::default();
        let unseen: Vec<_> = block
            .acts
            .iter()
            .enumerate()
            .filter(|(_, a)| self.seen_acts.insert(a.id))
            .collect();
        let mut routed = BTreeSet::new();
        let mut voids = Vec::new();
        for process in &mut self.notices {
            update_process(
                process,
                &unseen,
                &mut routed,
                &mut result,
                block.height,
                block.sealed_at_s,
            );
            if process.state.void_at_s.is_some() {
                voids.push(NoticeVoid {
                    level: process.level,
                    activation: process.activation,
                });
            }
        }
        self.ladder.apply_block(SanctionBlock {
            height: block.height,
            sealed_at_s: block.sealed_at_s,
            reset: block.reset,
            lift: block.lift,
            voids: &voids,
            findings: &[],
        });
        if block.reset {
            self.identity_start = self.findings.len();
        }
        for (active, criterion) in self.ladder.active().iter().zip(&mut self.criteria) {
            if active.is_none() {
                *criterion = None;
            }
        }
        let mut ordered: Vec<_> = block.findings.iter().collect();
        ordered.sort_by_key(|f| f.confirming().record.entry_index);
        for finding in ordered {
            let before = *self.ladder.active();
            let prior_l3 = self.criteria[2].clone();
            self.findings.push(finding.clone());
            let current = self.findings.len() - 1;
            self.available_records
                .extend(finding.records.iter().map(|r| r.id));
            let record = finding.confirming();
            self.ladder.apply_block(SanctionBlock {
                height: block.height,
                sealed_at_s: block.sealed_at_s,
                reset: false,
                lift: false,
                voids: &[],
                findings: &[OrderedFinding {
                    record_id: record.id,
                    entry_index: record.record.entry_index,
                    severity: finding.severity,
                }],
            });
            let count = |days, severity, minimum| {
                Arc::new(Criterion::Count {
                    findings: (self.identity_start..self.findings.len())
                        .filter(|&i| {
                            let f = &self.findings[i];
                            f.severity >= severity
                                && within_days_ending_at(
                                    f.confirming().record.block_sealed_at_s,
                                    block.sealed_at_s,
                                    days,
                                )
                        })
                        .collect(),
                    minimum,
                })
            };
            let single = Arc::new(Criterion::Count {
                findings: vec![current],
                minimum: 1,
            });
            if before[2].is_none() && self.ladder.active()[2].is_some() {
                let mut branches = vec![count(ESCALATION_L3_DAYS, 0, ESCALATION_L3_COUNT as usize)];
                if finding.severity == 3 {
                    branches.push(single.clone());
                }
                self.criteria[2] = Some(Arc::new(Criterion::All(vec![
                    single.clone(),
                    Arc::new(Criterion::Any(branches)),
                ])));
            }
            if before[3].is_none() && self.ladder.active()[3].is_some() {
                let mut branches = Vec::new();
                if finding.severity == 3 {
                    branches.push(count(
                        ESCALATION_L4_DAYS,
                        3,
                        ESCALATION_L4_SEV3_COUNT as usize,
                    ));
                }
                if let Some(prior) = prior_l3 {
                    branches.push(Arc::new(Criterion::All(vec![prior, single.clone()])));
                }
                self.criteria[3] = Some(Arc::new(Criterion::All(vec![
                    single.clone(),
                    Arc::new(Criterion::Any(branches)),
                ])));
            }
        }
        let old_len = self.notices.len();
        let mut eligible = BTreeMap::<(u8, [u8; 32]), Vec<(usize, Vec<[u8; 32]>)>>::new();
        for (i, candidate) in block.notices.iter().enumerate() {
            if !self.seen_notices.insert(candidate.id) {
                continue;
            }
            let target = notice_target(candidate.update);
            let (level, activation, evidence) = match target {
                Ok(None) => continue,
                Ok(Some(target)) => target,
                Err(error) => {
                    result.rejected_notices.insert(i, error);
                    continue;
                }
            };
            let active = self.ladder.active()[usize::from(level - 1)];
            let cited: BTreeSet<_> = evidence.iter().copied().collect();
            let valid = candidate.update.subject == self.subject
                && active.is_some_and(|a| a.record_id == activation)
                && cited.contains(&activation)
                && cited.iter().all(|id| self.available_records.contains(id))
                && self.criteria[usize::from(level - 1)]
                    .as_ref()
                    .is_some_and(|c| c.established_by(&self.findings, &cited))
                && !self
                    .notices
                    .iter()
                    .any(|p| p.level == level && p.activation == activation);
            if valid {
                eligible
                    .entry((level, activation))
                    .or_default()
                    .push((i, evidence));
            } else {
                result.rejected_notices.insert(i, "WIST4-E05");
            }
        }
        for ((level, activation), candidates) in eligible {
            if candidates.len() != 1 {
                for (i, _) in candidates {
                    result.rejected_notices.insert(i, "WIST4-E05");
                }
                continue;
            }
            let (i, evidence) = candidates.into_iter().next().unwrap();
            let candidate = block.notices[i];
            self.notices.push(AcceptedNotice {
                notice: Notice {
                    id: candidate.id,
                    subject: self.subject,
                    sanction: true,
                    height: block.height,
                    sealed_at_s: block.sealed_at_s,
                    activation_height: self.ladder.active()[usize::from(level - 1)].unwrap().height,
                    appeal_window_days: block.appeal_window_days,
                    appeal_seal_days: block.appeal_seal_days,
                },
                level,
                activation,
                evidence,
                state: ProcessState::default(),
                acts: Vec::new(),
            });
            result.accepted_notices.push(i);
        }
        for process in &mut self.notices[old_len..] {
            update_process(
                process,
                &unseen,
                &mut routed,
                &mut result,
                block.height,
                block.sealed_at_s,
            );
        }
        result.rejected_acts.extend(
            unseen
                .iter()
                .filter(|(i, _)| !routed.contains(i))
                .map(|(i, _)| i),
        );
        result.accepted_notices.sort_unstable();
        result.rejected_acts.sort_unstable();
        Ok(result)
    }
}

fn update_process<'a>(
    process: &mut AcceptedNotice<'a>,
    acts: &[(usize, &ProcessAct<'a>)],
    routed: &mut BTreeSet<usize>,
    result: &mut BlockAdmission,
    height: u64,
    sealed_at_s: i64,
) {
    let mut indices = Vec::new();
    for &(i, act) in acts {
        if act.notice == process.notice.id {
            routed.insert(i);
            indices.push((i, process.acts.len()));
            process.acts.push(*act);
        }
    }
    process.state = process_at(process.notice, &process.acts, height, sealed_at_s);
    result.rejected_acts.extend(
        indices
            .into_iter()
            .filter(|(_, index)| process.state.error_at(*index).is_some())
            .map(|(i, _)| i),
    );
}

type NoticeTarget = (u8, [u8; 32], Vec<[u8; 32]>);

fn notice_target(update: &RegistryUpdate) -> Result<Option<NoticeTarget>, &'static str> {
    if !matches!(update.action, RegistryAction::Notice) {
        return Err("WIST4-E04");
    }
    let details = update.details.as_ref().ok_or("WIST4-E04")?;
    match details.get("kind").and_then(serde_json::Value::as_str) {
        Some("recovery") => return Ok(None),
        Some("sanction") => {}
        _ => return Err("WIST4-E04"),
    }
    let level = details
        .get("level")
        .and_then(serde_json::Value::as_u64)
        .filter(|l| matches!(l, 3 | 4))
        .ok_or("WIST4-E04")? as u8;
    let activation = parse_id(
        details
            .get("activation")
            .and_then(serde_json::Value::as_str)
            .ok_or("WIST4-E04")?,
    )?;
    let evidence = update
        .evidence
        .as_ref()
        .ok_or("WIST4-E04")?
        .iter()
        .map(|id| parse_id(id))
        .collect::<Result<_, _>>()?;
    Ok(Some((level, activation, evidence)))
}

fn parse_id(id: &str) -> Result<[u8; 32], &'static str> {
    let hex = id.strip_prefix("sha256:").ok_or("WIST4-E04")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("WIST4-E04");
    }
    crate::crypto::hex_decode(hex)
        .map_err(|_| "WIST4-E04")?
        .try_into()
        .map_err(|_| "WIST4-E04")
}
