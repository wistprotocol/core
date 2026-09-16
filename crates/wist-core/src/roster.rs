use crate::confirmation::independent;
use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterAction {
    Admit,
    Register,
    Remove { for_cause: bool },
}

impl RosterAction {
    /// WIST-4 §4: a removal is for cause exactly when its `evidence`
    /// names at least one ID.
    pub fn try_remove_with(evidence: Option<&[String]>) -> Result<Self, Error> {
        if evidence.is_some_and(|ids| ids.is_empty()) {
            return Err(Error::Roster(
                "WIST4-E04: removal evidence must be absent or nonempty".into(),
            ));
        }
        Ok(Self::remove_with(evidence))
    }

    pub fn remove_with(evidence: Option<&[String]>) -> Self {
        RosterAction::Remove {
            for_cause: evidence.is_some_and(|ids| !ids.is_empty()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterAct<'a> {
    pub action: RosterAction,
    pub auditor_id: &'a str,
    pub key_id: &'a str,
    pub public_key: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Tenure {
    auditor_id: String,
    key_id: String,
    public_key: String,
    from_s: i64,
    until_s: Option<i64>,
}

impl Tenure {
    fn holds_at(&self, t_s: i64) -> bool {
        self.from_s <= t_s && self.until_s.is_none_or(|until| t_s < until)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Roster {
    log_id: String,
    tenures: Vec<Tenure>,
    held: BTreeMap<String, usize>,
    observer_tenures: Vec<Tenure>,
    observers: BTreeMap<String, usize>,
    retired_key_ids: BTreeSet<String>,
    retired_public_keys: BTreeSet<String>,
    barred: BTreeSet<String>,
    last_sealed_at_s: Option<i64>,
}

impl Roster {
    pub fn new(log_id: &str) -> Self {
        Roster {
            log_id: log_id.to_owned(),
            tenures: Vec::new(),
            held: BTreeMap::new(),
            observer_tenures: Vec::new(),
            observers: BTreeMap::new(),
            retired_key_ids: BTreeSet::new(),
            retired_public_keys: BTreeSet::new(),
            barred: BTreeSet::new(),
            last_sealed_at_s: None,
        }
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Seeds an admission or registration holding since `from_s`, as a
    /// Snapshot's `auditor` or `observer` tuple states it (WIST-3 §7).
    pub fn adopt(
        &mut self,
        action: RosterAction,
        subject: &str,
        key_id: &str,
        public_key: &str,
        from_s: i64,
    ) {
        let tenure = Tenure {
            auditor_id: subject.to_owned(),
            key_id: key_id.to_owned(),
            public_key: public_key.to_owned(),
            from_s,
            until_s: None,
        };
        match action {
            RosterAction::Admit => {
                self.held.insert(subject.to_owned(), self.tenures.len());
                self.tenures.push(tenure);
            }
            RosterAction::Register => {
                self.observers
                    .insert(subject.to_owned(), self.observer_tenures.len());
                self.observer_tenures.push(tenure);
            }
            RosterAction::Remove { .. } => {}
        }
    }

    /// Seeds a retired key binding from a Snapshot's removed `auditor`
    /// tuple: neither the identifier nor the public bytes may be held again.
    pub fn retire(&mut self, key_id: &str, public_key: &str) {
        self.retired_key_ids.insert(key_id.to_owned());
        self.retired_public_keys.insert(public_key.to_owned());
    }

    /// Every public key an admitted or registered tenure carries.
    pub fn public_keys(&self) -> impl Iterator<Item = &str> {
        self.tenures
            .iter()
            .chain(&self.observer_tenures)
            .map(|tenure| tenure.public_key.as_str())
    }

    pub fn apply_block(
        &mut self,
        sealed_at_s: i64,
        acts: &[RosterAct<'_>],
    ) -> Result<Vec<(usize, Error)>, Error> {
        self.apply_block_checked(sealed_at_s, acts, |_| Ok(()))
    }

    pub fn apply_block_checked(
        &mut self,
        sealed_at_s: i64,
        acts: &[RosterAct<'_>],
        mut validate_evidence: impl FnMut(usize) -> Result<(), Error>,
    ) -> Result<Vec<(usize, Error)>, Error> {
        if self
            .last_sealed_at_s
            .is_some_and(|last| sealed_at_s <= last)
        {
            return Err(Error::Roster(
                "blocks are not in Log order: sealed_at must strictly increase".into(),
            ));
        }
        self.last_sealed_at_s = Some(sealed_at_s);
        let mut rejected = BTreeMap::new();
        let mut removals = Vec::new();
        for (i, act) in acts.iter().enumerate() {
            if let RosterAction::Remove { for_cause } = act.action {
                if let Err(error) = validate_evidence(i) {
                    rejected.insert(i, error);
                    continue;
                }
                match self.held.get(act.auditor_id).copied() {
                    Some(idx) if self.tenures[idx].key_id == act.key_id => {
                        removals.push((idx, for_cause));
                    }
                    _ => {
                        rejected.insert(
                            i,
                            roster_error("removal does not name the subject's pre-Block key"),
                        );
                    }
                }
            }
        }
        for (idx, for_cause) in removals {
            let tenure = &mut self.tenures[idx];
            tenure.until_s = Some(sealed_at_s);
            self.held.remove(&tenure.auditor_id);
            self.retired_key_ids.insert(tenure.key_id.clone());
            self.retired_public_keys.insert(tenure.public_key.clone());
            if for_cause {
                self.barred.insert(tenure.auditor_id.clone());
            }
        }
        let candidates: Vec<usize> = acts
            .iter()
            .enumerate()
            .filter(|(_, act)| matches!(act.action, RosterAction::Admit | RosterAction::Register))
            .map(|(i, _)| i)
            .collect();
        for &i in &candidates {
            let act = &acts[i];
            if candidates
                .iter()
                .filter(|&&j| acts[j].action == act.action && acts[j].auditor_id == act.auditor_id)
                .count()
                > 1
            {
                rejected.insert(i, roster_error("multiple same-subject claims of one kind"));
            }
        }
        for &i in &candidates {
            if rejected.contains_key(&i) {
                continue;
            }
            if let Err(error) = self
                .check_incumbents(&acts[i])
                .and_then(|()| validate_evidence(i))
            {
                rejected.insert(i, error);
            }
        }
        for &i in &candidates {
            let act = &acts[i];
            if act.action == RosterAction::Register
                && !rejected.contains_key(&i)
                && candidates.iter().any(|&j| {
                    !rejected.contains_key(&j)
                        && acts[j].action == RosterAction::Admit
                        && acts[j].auditor_id == act.auditor_id
                })
            {
                rejected.insert(
                    i,
                    roster_error("same-subject admission supersedes registration"),
                );
            }
        }
        let remaining: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|i| !rejected.contains_key(i))
            .collect();
        let conflicts: Vec<usize> = remaining
            .iter()
            .copied()
            .filter(|&i| {
                remaining.iter().any(|&j| {
                    acts[i].auditor_id != acts[j].auditor_id
                        && (acts[i].key_id == acts[j].key_id
                            || acts[i].public_key == acts[j].public_key)
                })
            })
            .collect();
        for i in conflicts {
            rejected.insert(
                i,
                roster_error("simultaneous claims share a key across subjects"),
            );
        }
        for i in candidates {
            if rejected.contains_key(&i) {
                continue;
            }
            let act = &acts[i];
            if let Some(idx) = self.observers.remove(act.auditor_id) {
                self.observer_tenures[idx].until_s = Some(sealed_at_s);
            }
            let tenure = Tenure {
                auditor_id: act.auditor_id.to_owned(),
                key_id: act.key_id.to_owned(),
                public_key: act.public_key.to_owned(),
                from_s: sealed_at_s,
                until_s: None,
            };
            match act.action {
                RosterAction::Admit => {
                    self.held
                        .insert(act.auditor_id.to_owned(), self.tenures.len());
                    self.tenures.push(tenure);
                }
                RosterAction::Register => {
                    self.observers
                        .insert(act.auditor_id.to_owned(), self.observer_tenures.len());
                    self.observer_tenures.push(tenure);
                }
                RosterAction::Remove { .. } => unreachable!(),
            }
        }
        Ok(rejected.into_iter().collect())
    }

    fn check_incumbents(&self, act: &RosterAct<'_>) -> Result<(), Error> {
        if !independent(act.auditor_id, &self.log_id) {
            return Err(roster_error("subject is not independent of log_id"));
        }
        if self.retired_key_ids.contains(act.key_id)
            || self.retired_public_keys.contains(act.public_key)
        {
            return Err(roster_error("key is retired"));
        }
        if self.held.contains_key(act.auditor_id) {
            return Err(roster_error("subject already holds an admitted key"));
        }
        if act.action == RosterAction::Admit && self.barred.contains(act.auditor_id) {
            return Err(roster_error("subject is barred by a removal for cause"));
        }
        if self.held.values().any(|&idx| {
            let t = &self.tenures[idx];
            t.key_id == act.key_id || t.public_key == act.public_key
        }) || self.observers.values().any(|&idx| {
            let t = &self.observer_tenures[idx];
            t.auditor_id != act.auditor_id
                && (t.key_id == act.key_id || t.public_key == act.public_key)
        }) {
            return Err(roster_error("key is held by an incumbent"));
        }
        Ok(())
    }

    pub fn observer_key_at(&self, observer_id: &str, t_s: i64) -> Option<&str> {
        self.observer_tenures
            .iter()
            .find(|t| t.auditor_id == observer_id && t.holds_at(t_s))
            .map(|t| t.key_id.as_str())
    }

    pub fn registered_at(&self, t_s: i64) -> Vec<(&str, &str)> {
        let mut registered: Vec<_> = self
            .observer_tenures
            .iter()
            .filter(|t| t.holds_at(t_s))
            .map(|t| (t.auditor_id.as_str(), t.key_id.as_str()))
            .collect();
        registered.sort_unstable();
        registered
    }

    pub fn key_at(&self, auditor_id: &str, t_s: i64) -> Option<&str> {
        self.tenures
            .iter()
            .find(|t| t.auditor_id == auditor_id && t.holds_at(t_s))
            .map(|t| t.key_id.as_str())
    }

    pub fn public_key_at(&self, auditor_id: &str, t_s: i64) -> Option<&str> {
        self.tenures
            .iter()
            .find(|t| t.auditor_id == auditor_id && t.holds_at(t_s))
            .map(|t| t.public_key.as_str())
    }

    pub fn observer_public_key_at(&self, observer_id: &str, t_s: i64) -> Option<&str> {
        self.observer_tenures
            .iter()
            .find(|t| t.auditor_id == observer_id && t.holds_at(t_s))
            .map(|t| t.public_key.as_str())
    }

    pub fn tenure(&self, auditor_id: &str, key_id: &str) -> Option<(i64, Option<i64>)> {
        self.tenures
            .iter()
            .find(|t| t.auditor_id == auditor_id && t.key_id == key_id)
            .map(|t| (t.from_s, t.until_s))
    }

    pub fn admitted_at(&self, t_s: i64) -> Vec<(&str, &str)> {
        let mut admitted: Vec<(&str, &str)> = self
            .tenures
            .iter()
            .filter(|t| t.holds_at(t_s))
            .map(|t| (t.auditor_id.as_str(), t.key_id.as_str()))
            .collect();
        admitted.sort_unstable();
        admitted
    }
}

fn roster_error(reason: &str) -> Error {
    Error::Roster(format!("WIST4-E07: {reason}"))
}

#[derive(Debug, Clone, Copy)]
pub struct ObserverRegistration<'a> {
    pub observer_id: &'a str,
    pub height: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ObserverCheckpoint<'a> {
    pub observer_id: &'a str,
    pub height: u64,
    pub update_id: &'a str,
}

pub fn validate_admission_evidence(
    subject: &str,
    height: u64,
    registrations: &[ObserverRegistration<'_>],
    checkpoints: &[ObserverCheckpoint<'_>],
    track_record: Option<&crate::objects::audit::TrackRecord>,
) -> Result<(), Error> {
    let was_observer = registrations
        .iter()
        .any(|r| r.observer_id == subject && r.height <= height);
    match (was_observer, track_record) {
        (false, None) => Ok(()),
        (true, Some(record)) => {
            let newest = checkpoints
                .iter()
                .filter(|c| c.observer_id == subject && c.height <= height)
                .max_by_key(|c| (c.height, c.update_id.as_bytes()));
            if newest.is_some_and(|c| c.update_id == record.checkpoint) {
                Ok(())
            } else {
                Err(Error::Roster(
                    "WIST4-E04: track_record must cite the newest valid Observer checkpoint".into(),
                ))
            }
        }
        _ => Err(Error::Roster(
            "WIST4-E04: track_record must accompany exactly an Observer history".into(),
        )),
    }
}

pub fn replay<'a>(
    log_id: &str,
    entries: &[(i64, RosterAct<'a>)],
) -> Result<(Roster, Vec<(usize, Error)>), Error> {
    let mut roster = Roster::new(log_id);
    let mut rejected = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let sealed_at_s = entries[start].0;
        let len = entries[start..]
            .iter()
            .take_while(|(t, _)| *t == sealed_at_s)
            .count();
        let acts: Vec<RosterAct<'a>> = entries[start..start + len]
            .iter()
            .map(|(_, act)| *act)
            .collect();
        for (i, e) in roster.apply_block(sealed_at_s, &acts)? {
            rejected.push((start + i, e));
        }
        start += len;
    }
    Ok((roster, rejected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "log.example.org";
    const A: &str = "audit.example.net";
    const B: &str = "checker.sample.org";

    fn admit(auditor_id: &'static str, key_id: &'static str) -> RosterAct<'static> {
        admit_key(auditor_id, key_id, public_key_of(key_id))
    }

    fn public_key_of(key_id: &'static str) -> &'static str {
        match key_id {
            "k1" => "pk-k1",
            "k2" => "pk-k2",
            "k3" => "pk-k3",
            "k4" => "pk-k4",
            "k9" => "pk-k9",
            "ka" => "pk-ka",
            "kb" => "pk-kb",
            other => panic!("no test public key for {other}"),
        }
    }

    fn admit_key(
        auditor_id: &'static str,
        key_id: &'static str,
        public_key: &'static str,
    ) -> RosterAct<'static> {
        RosterAct {
            action: RosterAction::Admit,
            auditor_id,
            key_id,
            public_key,
        }
    }

    fn remove(
        auditor_id: &'static str,
        key_id: &'static str,
        for_cause: bool,
    ) -> RosterAct<'static> {
        RosterAct {
            action: RosterAction::Remove { for_cause },
            auditor_id,
            key_id,
            public_key: "",
        }
    }

    fn indices(rejected: &[(usize, Error)]) -> Vec<usize> {
        rejected.iter().map(|(i, _)| *i).collect()
    }

    #[test]
    fn a_removal_is_for_cause_exactly_when_its_evidence_names_something() {
        let none: Option<&[String]> = None;
        assert_eq!(
            RosterAction::remove_with(none),
            RosterAction::Remove { for_cause: false }
        );
        assert_eq!(
            RosterAction::remove_with(Some(&[])),
            RosterAction::Remove { for_cause: false }
        );
        assert_eq!(
            RosterAction::remove_with(Some(&["sha256:void".to_owned()])),
            RosterAction::Remove { for_cause: true }
        );
    }

    #[test]
    fn removes_are_read_before_admits_in_one_block() {
        let mut roster = Roster::new(LOG);
        let rejected = roster
            .apply_block(0, &[admit(A, "k1"), remove(A, "k1", false)])
            .unwrap();
        assert_eq!(indices(&rejected), vec![1]);
        assert_eq!(roster.key_at(A, 0), Some("k1"));
    }

    #[test]
    fn two_admits_for_one_subject_in_one_block_are_both_rejected() {
        let mut roster = Roster::new(LOG);
        let rejected = roster
            .apply_block(0, &[admit(A, "k1"), admit(A, "k2"), admit(B, "k3")])
            .unwrap();
        assert_eq!(indices(&rejected), vec![0, 1]);
        assert_eq!(roster.key_at(A, 0), None);
        assert_eq!(roster.key_at(B, 0), Some("k3"));
        assert!(roster.apply_block(1, &[admit(A, "k1")]).unwrap().is_empty());
    }

    #[test]
    fn tenures_run_from_admission_to_removal_exclusive() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        assert_eq!(roster.tenure(A, "k1"), Some((0, None)));
        roster
            .apply_block(10, &[remove(A, "k1", false), admit(A, "k2")])
            .unwrap();
        assert_eq!(roster.tenure(A, "k1"), Some((0, Some(10))));
        assert_eq!(roster.tenure(A, "k2"), Some((10, None)));
        assert_eq!(roster.tenure(B, "k1"), None);
        assert_eq!(roster.tenure(A, "k9"), None);
    }

    #[test]
    fn a_retired_key_id_is_retired_for_every_auditor() {
        let mut roster = Roster::new(LOG);
        assert!(roster.apply_block(0, &[admit(A, "k1")]).unwrap().is_empty());
        assert!(roster
            .apply_block(10, &[remove(A, "k1", false)])
            .unwrap()
            .is_empty());
        let rejected = roster.apply_block(20, &[admit(B, "k1")]).unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert_eq!(roster.key_at(B, 20), None);
    }

    #[test]
    fn a_removed_public_key_is_retired_under_any_label() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        roster.apply_block(10, &[remove(A, "k1", false)]).unwrap();
        let rejected = roster
            .apply_block(20, &[admit_key(A, "k2", "pk-k1")])
            .unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        let rejected = roster
            .apply_block(30, &[admit_key(B, "k3", "pk-k1")])
            .unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert!(roster
            .apply_block(40, &[admit(A, "k2")])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn no_two_live_admissions_share_a_key_id_or_a_public_key() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        let rejected = roster
            .apply_block(
                10,
                &[
                    admit_key(B, "k1", "pk-other"),
                    admit_key("peer.example.net", "k2", "pk-k1"),
                ],
            )
            .unwrap();
        assert_eq!(indices(&rejected), vec![0, 1]);
        assert_eq!(roster.key_at(B, 10), None);
        roster.apply_block(20, &[remove(A, "k1", false)]).unwrap();
        assert!(roster
            .apply_block(30, &[admit(B, "k2")])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_bar_for_cause_names_one_auditor_id_exactly() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        roster.apply_block(10, &[remove(A, "k1", true)]).unwrap();
        let rejected = roster
            .apply_block(20, &[admit(A, "k2"), admit("peer.example.net", "k3")])
            .unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert_eq!(roster.key_at("peer.example.net", 20), Some("k3"));
    }

    #[test]
    fn a_rejected_remove_retires_and_bars_nothing() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        let rejected = roster.apply_block(10, &[remove(A, "k9", true)]).unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert!(roster
            .apply_block(20, &[remove(A, "k1", false)])
            .unwrap()
            .is_empty());
        assert!(roster
            .apply_block(30, &[admit(A, "k9")])
            .unwrap()
            .is_empty());
        assert_eq!(roster.key_at(A, 30), Some("k9"));
    }

    #[test]
    fn history_answers_instants_before_a_rotation() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        roster
            .apply_block(100, &[remove(A, "k1", false), admit(A, "k2")])
            .unwrap();
        roster.apply_block(200, &[remove(A, "k2", false)]).unwrap();
        assert_eq!(roster.key_at(A, -1), None);
        assert_eq!(roster.key_at(A, 0), Some("k1"));
        assert_eq!(roster.key_at(A, 99), Some("k1"));
        assert_eq!(roster.key_at(A, 100), Some("k2"));
        assert_eq!(roster.key_at(A, 199), Some("k2"));
        assert_eq!(roster.key_at(A, 200), None);
        assert_eq!(roster.key_at("nobody.example.com", 100), None);
    }

    #[test]
    fn admitted_at_lists_live_tenures_sorted_by_auditor_id() {
        let mut roster = Roster::new(LOG);
        roster
            .apply_block(0, &[admit(B, "kb"), admit(A, "ka")])
            .unwrap();
        roster.apply_block(10, &[remove(B, "kb", false)]).unwrap();
        assert_eq!(roster.admitted_at(0), vec![(A, "ka"), (B, "kb")]);
        assert_eq!(roster.admitted_at(10), vec![(A, "ka")]);
        assert_eq!(roster.admitted_at(-1), Vec::<(&str, &str)>::new());
    }

    #[test]
    fn blocks_must_arrive_with_strictly_increasing_sealed_at() {
        let mut roster = Roster::new(LOG);
        roster.apply_block(10, &[admit(A, "k1")]).unwrap();
        assert!(roster.apply_block(10, &[]).is_err());
        assert!(roster.apply_block(9, &[]).is_err());
        assert!(roster.apply_block(11, &[]).is_ok());
    }

    #[test]
    fn replay_groups_consecutive_entries_sharing_an_instant_into_one_block() {
        let entries = [
            (0, admit(A, "k1")),
            (5, remove(A, "k1", false)),
            (5, admit(A, "k2")),
            (5, admit(B, "k3")),
        ];
        let (roster, rejected) = replay(LOG, &entries).unwrap();
        assert!(rejected.is_empty());
        assert_eq!(roster.admitted_at(5), vec![(A, "k2"), (B, "k3")]);
        assert_eq!(roster.key_at(A, 4), Some("k1"));
    }

    #[test]
    fn replay_reports_global_indices() {
        let entries = [
            (0, admit(A, "k1")),
            (5, admit(B, "k2")),
            (5, admit(A, "k3")),
            (9, remove(B, "k9", false)),
        ];
        let (_, rejected) = replay(LOG, &entries).unwrap();
        assert_eq!(indices(&rejected), vec![2, 3]);
        assert!(rejected
            .iter()
            .all(|(_, e)| e.to_string().starts_with("roster: WIST4-E07: ")));
    }
    #[test]
    fn invalid_removal_evidence_neither_retires_nor_bars() {
        assert!(RosterAction::try_remove_with(Some(&[])).is_err());
        assert_eq!(
            RosterAction::try_remove_with(None).unwrap(),
            RosterAction::Remove { for_cause: false }
        );
        let mut roster = Roster::new(LOG);
        roster.apply_block(0, &[admit(A, "k1")]).unwrap();
        let rejected = roster
            .apply_block_checked(1, &[remove(A, "k1", true)], |_| {
                Err(Error::Roster("WIST4-E04: malformed evidence".into()))
            })
            .unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert_eq!(roster.key_at(A, 1), Some("k1"));
        assert!(roster
            .apply_block(2, &[remove(A, "k1", false), admit(A, "k2")])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn invalid_admission_evidence_does_not_veto_a_registration() {
        let mut roster = Roster::new(LOG);
        let mut registration = admit(B, "k1");
        registration.action = RosterAction::Register;
        let rejected = roster
            .apply_block_checked(0, &[admit(A, "k1"), registration], |i| {
                if i == 0 {
                    Err(Error::Roster("WIST4-E04: missing checkpoint".into()))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert_eq!(indices(&rejected), vec![0]);
        assert_eq!(roster.observer_key_at(B, 0), Some("k1"));
    }

    #[test]
    fn observer_rotation_releases_keys_only_for_later_blocks() {
        let mut roster = Roster::new(LOG);
        let mut registration = admit(A, "k1");
        registration.action = RosterAction::Register;
        roster.apply_block(0, &[registration]).unwrap();
        registration.key_id = "k2";
        registration.public_key = "pk-k2";
        assert_eq!(
            indices(
                &roster
                    .apply_block(1, &[registration, admit(B, "k1")])
                    .unwrap()
            ),
            vec![1]
        );
        assert!(roster.apply_block(2, &[admit(B, "k1")]).unwrap().is_empty());
        assert_eq!(roster.observer_key_at(A, 0), Some("k1"));
        assert_eq!(roster.observer_key_at(A, 1), Some("k2"));
        assert_eq!(roster.key_at(B, 2), Some("k1"));
    }

    #[test]
    fn checkpoint_citation_reads_only_the_subjects_history_through_admission() {
        use crate::objects::audit::{Scoreboard, TrackRecord};
        let registrations = [ObserverRegistration {
            observer_id: A,
            height: 2,
        }];
        let checkpoints = [
            ObserverCheckpoint {
                observer_id: A,
                height: 2,
                update_id: "sha256:a",
            },
            ObserverCheckpoint {
                observer_id: A,
                height: 3,
                update_id: "sha256:0",
            },
            ObserverCheckpoint {
                observer_id: A,
                height: 4,
                update_id: "sha256:z",
            },
            ObserverCheckpoint {
                observer_id: B,
                height: 3,
                update_id: "sha256:z",
            },
        ];
        let record = TrackRecord {
            checkpoint: "sha256:0".into(),
            scoreboard: Scoreboard {
                provisional: [0; 3],
                standing: [0; 3],
                mature: [0; 3],
            },
        };
        assert!(validate_admission_evidence(A, 1, &registrations, &checkpoints, None).is_ok());
        assert!(
            validate_admission_evidence(A, 1, &registrations, &checkpoints, Some(&record)).is_err()
        );
        assert!(validate_admission_evidence(A, 2, &registrations, &checkpoints, None).is_err());
        assert!(
            validate_admission_evidence(A, 3, &registrations, &checkpoints, Some(&record)).is_ok()
        );
        assert!(
            validate_admission_evidence(A, 4, &registrations, &checkpoints, Some(&record)).is_err()
        );
    }
}
