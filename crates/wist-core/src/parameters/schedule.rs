use super::{spec, validate_combinations, validate_value, PARAMS};
use crate::Error;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amendment {
    pub parameter: String,
    pub value: i64,
    pub block_number: u64,
    pub entry_index: u64,
    pub sealed_at_s: i64,
    pub effective_at_s: i64,
}

#[derive(Debug, Clone)]
pub struct Schedule {
    first_block_s: i64,
    accepted: Vec<Amendment>,
    last_position: Option<(u64, u64)>,
}

#[derive(Debug)]
pub struct ScheduleReplay {
    pub schedule: Schedule,
    pub rejected: Vec<usize>,
}

impl ScheduleReplay {
    pub fn error_at(&self, index: usize) -> Option<&'static str> {
        self.rejected.contains(&index).then_some("WIST4-E03")
    }
}

impl Schedule {
    pub fn new(first_block_s: i64) -> Self {
        Self {
            first_block_s,
            accepted: Vec::new(),
            last_position: None,
        }
    }

    pub fn replay(first_block_s: i64, amendments: &[Amendment]) -> ScheduleReplay {
        let mut order: Vec<usize> = (0..amendments.len()).collect();
        order.sort_by_key(|&i| (amendments[i].block_number, amendments[i].entry_index));
        let mut schedule = Self::new(first_block_s);
        let mut rejected = Vec::new();
        for i in order {
            if schedule.try_accept(amendments[i].clone()).is_err() {
                rejected.push(i);
            }
        }
        rejected.sort_unstable();
        ScheduleReplay { schedule, rejected }
    }

    pub fn accepted(&self) -> &[Amendment] {
        &self.accepted
    }

    pub fn value_at(&self, parameter: &str, at_s: i64) -> Option<i64> {
        let default = spec(parameter)?.default?;
        Some(
            self.accepted
                .iter()
                .filter(|a| a.parameter == parameter && a.effective_at_s <= at_s)
                .max_by_key(|a| (a.effective_at_s, a.block_number, a.entry_index))
                .map_or(default, |a| a.value),
        )
    }

    pub fn try_accept(&mut self, amendment: Amendment) -> Result<(), Error> {
        let position = (amendment.block_number, amendment.entry_index);
        if self.last_position.is_some_and(|last| position <= last) {
            return Err(Error::Parameter(
                "amendments must arrive once in canonical Log order".into(),
            ));
        }
        self.last_position = Some(position);
        validate_value(&amendment.parameter, amendment.value)?;
        let grace = self
            .value_at("param_grace_days", amendment.sealed_at_s)
            .unwrap();
        if i128::from(amendment.effective_at_s) - i128::from(amendment.sealed_at_s)
            < i128::from(grace) * 86_400
        {
            return Err(Error::Parameter(
                "amendment does not satisfy the grace period".into(),
            ));
        }
        let sealed_at_s = amendment.sealed_at_s;
        self.accepted.push(amendment);
        let result = self.validate_from(sealed_at_s);
        if result.is_err() {
            self.accepted.pop();
        }
        result
    }

    fn validate_from(&self, sealed_at_s: i64) -> Result<(), Error> {
        let instants: BTreeSet<i64> = std::iter::once(sealed_at_s)
            .chain(
                self.accepted
                    .iter()
                    .map(|a| a.effective_at_s)
                    .filter(|&t| t >= sealed_at_s),
            )
            .collect();
        for at_s in instants {
            validate_combinations(|name| self.value_at(name, at_s).unwrap())?;
        }
        let boundaries: BTreeSet<i64> = std::iter::once(self.first_block_s)
            .chain(self.accepted.iter().map(|a| a.effective_at_s))
            .collect();
        let mut previous = None;
        let mut profiles = Vec::new();
        for from_s in boundaries {
            let values: Vec<i64> = PARAMS
                .iter()
                .map(|p| self.value_at(p.name, from_s).unwrap())
                .collect();
            if previous.as_ref() == Some(&values) {
                continue;
            }
            profiles.push(CadenceProfile {
                from_s,
                confirm_window_hours: self.value_at("confirm_window_hours", from_s).unwrap(),
                record_seal_blocks: self.value_at("record_seal_blocks", from_s).unwrap(),
                block_cadence_seconds: self.value_at("block_cadence_seconds", from_s).unwrap(),
            });
            previous = Some(values);
        }
        validate_cadence_transitions(&profiles)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CadenceProfile {
    pub from_s: i64,
    pub confirm_window_hours: i64,
    pub record_seal_blocks: i64,
    pub block_cadence_seconds: i64,
}

pub fn validate_cadence_transitions(profiles: &[CadenceProfile]) -> Result<(), Error> {
    for (i, profile) in profiles.iter().enumerate() {
        let window = i128::from(profile.confirm_window_hours) * 3600;
        let publication = i128::from(profile.confirm_window_hours / 2) * 3600;
        let end = profiles.get(i + 1).map(|p| i128::from(p.from_s) + window);
        let cadence = profiles[i..]
            .iter()
            .take_while(|p| end.is_none_or(|end| i128::from(p.from_s) < end))
            .map(|p| i128::from(p.block_cadence_seconds))
            .max()
            .unwrap();
        if publication + i128::from(profile.record_seal_blocks) * cadence > window {
            return Err(Error::Parameter(
                "cadence transition outlives an extension window".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn change(parameter: &str, value: i64, height: u64, sealed: i64, effective: i64) -> Amendment {
        Amendment {
            parameter: parameter.into(),
            value,
            block_number: height,
            entry_index: 0,
            sealed_at_s: sealed,
            effective_at_s: effective,
        }
    }

    #[test]
    fn grace_uses_the_sealing_prefix_and_includes_its_activation_endpoint() {
        let changes = [
            change("param_grace_days", 1, 0, 0, 7 * DAY),
            change("quota_base", 101, 1, DAY, 2 * DAY),
            change("quota_base", 102, 2, 7 * DAY, 8 * DAY),
            change("quota_base", 103, 3, 7 * DAY + 1, 8 * DAY),
            change("quota_base", 104, 4, 7 * DAY + 2, 8 * DAY + 2),
        ];
        let replay = Schedule::replay(0, &changes);
        assert_eq!(replay.rejected, [1, 3]);
        assert_eq!(replay.schedule.value_at("quota_base", 8 * DAY), Some(102));
        assert_eq!(
            replay.schedule.value_at("quota_base", 8 * DAY + 2),
            Some(104)
        );
        let raised = Schedule::replay(
            0,
            &[
                change("param_grace_days", 14, 0, 0, 7 * DAY),
                change("param_grace_days", 1, 1, 7 * DAY, 14 * DAY),
                change("quota_base", 101, 2, 7 * DAY + 1, 21 * DAY + 1),
            ],
        );
        assert_eq!(raised.rejected, [1]);
    }

    #[test]
    fn rejected_replacements_preserve_the_accepted_value() {
        let replay = Schedule::replay(
            0,
            &[
                change("sampling_floor", 4_000_000, 0, 0, 10 * DAY),
                change("sampling_floor", 6_000_000, 1, DAY, 10 * DAY),
            ],
        );
        assert_eq!(replay.rejected, [1]);
        assert_eq!(replay.schedule.accepted().len(), 1);
        assert_eq!(
            replay.schedule.value_at("sampling_floor", 10 * DAY),
            Some(4_000_000)
        );
    }

    #[test]
    fn intermediate_future_map_cannot_hide_behind_a_valid_final_map() {
        let replay = Schedule::replay(
            0,
            &[
                change("sampling_floor", 4_000_000, 0, 0, 10 * DAY),
                change("sampling_floor", 200_000, 1, DAY, 12 * DAY),
                change("sampling_ceiling", 3_000_000, 2, 2 * DAY, 11 * DAY),
            ],
        );
        assert_eq!(replay.rejected, [2]);
        assert_eq!(
            replay.schedule.value_at("sampling_ceiling", 12 * DAY),
            Some(5_000_000)
        );
    }

    #[test]
    fn cadence_rejection_keeps_old_profiles_and_pending_changes() {
        let replay = Schedule::replay(
            0,
            &[
                change("confirm_window_hours", 96, 0, 0, 10 * DAY),
                change("block_cadence_seconds", 7200, 1, DAY, 13 * DAY - 1),
                change("block_cadence_seconds", 7200, 2, 2 * DAY, 13 * DAY),
            ],
        );
        assert_eq!(replay.rejected, [1]);
        assert_eq!(
            replay
                .schedule
                .value_at("block_cadence_seconds", 13 * DAY - 1),
            Some(3600)
        );
        assert_eq!(
            replay.schedule.value_at("block_cadence_seconds", 13 * DAY),
            Some(7200)
        );
    }

    #[test]
    fn rejected_candidates_cannot_be_resubmitted_out_of_order() {
        let mut schedule = Schedule::new(0);
        let floor = change("sampling_floor", 6_000_000, 0, 0, 10 * DAY);
        assert!(schedule.try_accept(floor.clone()).is_err());
        schedule
            .try_accept(change("sampling_ceiling", 7_000_000, 1, DAY, 10 * DAY))
            .unwrap();
        assert!(schedule.try_accept(floor).is_err());
        assert_eq!(schedule.value_at("sampling_floor", 10 * DAY), Some(200_000));
    }

    #[test]
    fn long_grace_and_windows_do_not_overflow() {
        let max = super::super::WIRE_INTEGER_MAX;
        let replay = Schedule::replay(
            0,
            &[
                change("param_grace_days", max, 0, 0, 7 * DAY),
                change("quota_base", 101, 1, 7 * DAY, i64::MAX),
                change("confirm_window_hours", max, 2, 7 * DAY + 1, i64::MAX),
            ],
        );
        assert_eq!(replay.rejected, [1, 2]);
        validate_cadence_transitions(&[CadenceProfile {
            from_s: i64::MAX,
            confirm_window_hours: max,
            record_seal_blocks: max,
            block_cadence_seconds: 1,
        }])
        .unwrap();
    }
}
