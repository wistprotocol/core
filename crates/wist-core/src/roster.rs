use crate::confirmation::independent;
use crate::error::Error;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterAction {
    Admit,
    Remove { for_cause: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterAct<'a> {
    pub action: RosterAction,
    pub auditor_id: &'a str,
    pub key_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tenure {
    auditor_id: String,
    key_id: String,
    from_s: i64,
    until_s: Option<i64>,
}

impl Tenure {
    fn holds_at(&self, t_s: i64) -> bool {
        self.from_s <= t_s && self.until_s.is_none_or(|until| t_s < until)
    }
}

#[derive(Debug, Clone)]
pub struct Roster {
    log_id: String,
    tenures: Vec<Tenure>,
    held: BTreeMap<String, usize>,
    retired: BTreeSet<String>,
    barred: BTreeSet<String>,
    last_sealed_at_s: Option<i64>,
}

impl Roster {
    pub fn new(log_id: &str) -> Self {
        Roster {
            log_id: log_id.to_owned(),
            tenures: Vec::new(),
            held: BTreeMap::new(),
            retired: BTreeSet::new(),
            barred: BTreeSet::new(),
            last_sealed_at_s: None,
        }
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Removes are read before admits within the Block; rejected acts leave
    /// the roster unchanged and later acts see the accepted earlier ones.
    pub fn apply_block(
        &mut self,
        sealed_at_s: i64,
        acts: &[RosterAct<'_>],
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
        let mut rejected = Vec::new();
        for (i, act) in acts.iter().enumerate() {
            if let RosterAction::Remove { for_cause } = act.action {
                if let Err(e) = self.remove(sealed_at_s, act, for_cause) {
                    rejected.push((i, e));
                }
            }
        }
        for (i, act) in acts.iter().enumerate() {
            if act.action == RosterAction::Admit {
                if let Err(e) = self.admit(sealed_at_s, act) {
                    rejected.push((i, e));
                }
            }
        }
        rejected.sort_by_key(|(i, _)| *i);
        Ok(rejected)
    }

    fn remove(
        &mut self,
        sealed_at_s: i64,
        act: &RosterAct<'_>,
        for_cause: bool,
    ) -> Result<(), Error> {
        let idx = match self.held.get(act.auditor_id) {
            Some(&idx) if self.tenures[idx].key_id == act.key_id => idx,
            _ => {
                return Err(Error::Roster(format!(
                    "WIST4-E07: {} does not hold key {}",
                    act.auditor_id, act.key_id
                )))
            }
        };
        self.tenures[idx].until_s = Some(sealed_at_s);
        self.held.remove(act.auditor_id);
        self.retired.insert(act.key_id.to_owned());
        if for_cause {
            self.barred.insert(act.auditor_id.to_owned());
        }
        Ok(())
    }

    fn admit(&mut self, sealed_at_s: i64, act: &RosterAct<'_>) -> Result<(), Error> {
        if self.retired.contains(act.key_id) {
            return Err(Error::Roster(format!(
                "WIST4-E07: key {} is retired",
                act.key_id
            )));
        }
        if self.barred.contains(act.auditor_id) {
            return Err(Error::Roster(format!(
                "WIST4-E07: {} is barred by a removal for cause",
                act.auditor_id
            )));
        }
        if let Some(&idx) = self.held.get(act.auditor_id) {
            return Err(Error::Roster(format!(
                "WIST4-E07: {} holds key {} not removed at or before this Block",
                act.auditor_id, self.tenures[idx].key_id
            )));
        }
        if !independent(act.auditor_id, &self.log_id) {
            return Err(Error::Roster(format!(
                "WIST4-E07: {} is not independent of log_id {}",
                act.auditor_id, self.log_id
            )));
        }
        self.held
            .insert(act.auditor_id.to_owned(), self.tenures.len());
        self.tenures.push(Tenure {
            auditor_id: act.auditor_id.to_owned(),
            key_id: act.key_id.to_owned(),
            from_s: sealed_at_s,
            until_s: None,
        });
        Ok(())
    }

    pub fn key_at(&self, auditor_id: &str, t_s: i64) -> Option<&str> {
        self.tenures
            .iter()
            .find(|t| t.auditor_id == auditor_id && t.holds_at(t_s))
            .map(|t| t.key_id.as_str())
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
        RosterAct {
            action: RosterAction::Admit,
            auditor_id,
            key_id,
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
        }
    }

    fn indices(rejected: &[(usize, Error)]) -> Vec<usize> {
        rejected.iter().map(|(i, _)| *i).collect()
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
    fn a_second_admit_in_the_same_block_is_rejected() {
        let mut roster = Roster::new(LOG);
        let rejected = roster
            .apply_block(0, &[admit(A, "k1"), admit(A, "k2")])
            .unwrap();
        assert_eq!(indices(&rejected), vec![1]);
        assert_eq!(roster.key_at(A, 0), Some("k1"));
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
}
