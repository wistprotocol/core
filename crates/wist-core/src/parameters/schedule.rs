use super::{spec, validate_combinations, validate_value};
use crate::Error;
use std::collections::BTreeSet;

pub use crate::timestamp::LOG_TIMESTAMP_MAX_S;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amendment {
    pub parameter: String,
    pub value: i64,
    pub epoch_number: u64,
    pub entry_index: u64,
    pub sealed_at_s: i64,
    pub effective_at_s: i64,
}

#[derive(Debug, Clone)]
pub struct Schedule {
    first_epoch_s: i64,
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
    pub fn new(first_epoch_s: i64) -> Self {
        Self {
            first_epoch_s,
            accepted: Vec::new(),
            last_position: None,
        }
    }

    pub fn replay(first_epoch_s: i64, amendments: &[Amendment]) -> ScheduleReplay {
        let mut order: Vec<usize> = (0..amendments.len()).collect();
        order.sort_by_key(|&i| (amendments[i].epoch_number, amendments[i].entry_index));
        let mut schedule = Self::new(first_epoch_s);
        let mut rejected = Vec::new();
        for i in order {
            if schedule.try_accept(amendments[i].clone()).is_err() {
                rejected.push(i);
            }
        }
        rejected.sort_unstable();
        ScheduleReplay { schedule, rejected }
    }

    /// WIST-3 §7: an amendment from a Snapshot's `parameter` tuple is already accepted, so no
    /// admission check applies.
    pub fn adopt(&mut self, amendment: Amendment) {
        self.accepted.push(amendment);
    }

    pub fn first_epoch_s(&self) -> i64 {
        self.first_epoch_s
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
                .max_by_key(|a| (a.effective_at_s, a.epoch_number, a.entry_index))
                .map_or(default, |a| a.value),
        )
    }

    pub fn epoch_size_bounds(&self, at_s: i64) -> (u64, u64) {
        let mut bounds = (u64::MAX, 0);
        for instant in std::iter::once(at_s).chain(
            self.accepted
                .iter()
                .map(|a| a.effective_at_s)
                .filter(|&t| t >= at_s),
        ) {
            let cap = self.value_at("epoch_cap_bytes", instant).unwrap() as u64;
            bounds.0 = bounds.0.min(cap);
            bounds.1 = bounds.1.max(cap);
        }
        bounds
    }

    pub fn try_accept(&mut self, amendment: Amendment) -> Result<(), Error> {
        self.try_accept_with_epoch_size(amendment, 0)
    }

    pub fn try_accept_with_epoch_size(
        &mut self,
        amendment: Amendment,
        largest_epoch_bytes: u64,
    ) -> Result<(), Error> {
        let position = (amendment.epoch_number, amendment.entry_index);
        if self.last_position.is_some_and(|last| position <= last) {
            return Err(Error::Parameter(
                "amendments must arrive once in canonical Log order".into(),
            ));
        }
        self.last_position = Some(position);
        validate_value(&amendment.parameter, amendment.value)?;
        if amendment.parameter == "recovery_window_days"
            && i128::from(amendment.effective_at_s) + i128::from(amendment.value) * 86_400
                > i128::from(LOG_TIMESTAMP_MAX_S)
        {
            return Err(Error::Parameter(
                "recovery_window_days would end a window past the Log timestamp range".into(),
            ));
        }
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
        let result = self.validate_from(sealed_at_s).and_then(|()| {
            if self.epoch_size_bounds(sealed_at_s).0 < largest_epoch_bytes {
                Err(Error::Parameter(
                    "Epoch cap is below a sealed Epoch's size".into(),
                ))
            } else {
                Ok(())
            }
        });
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn change(parameter: &str, value: i64, height: u64, sealed: i64, effective: i64) -> Amendment {
        Amendment {
            parameter: parameter.into(),
            value,
            epoch_number: height,
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
                change("links_cap_bytes", 6000, 0, 0, 10 * DAY),
                change("link_url_cap_bytes", 5000, 1, DAY, 10 * DAY),
                change("links_cap_bytes", 5000, 2, 2 * DAY, 10 * DAY),
            ],
        );
        assert_eq!(replay.rejected, [2]);
        assert_eq!(replay.schedule.accepted().len(), 2);
        assert_eq!(
            replay.schedule.value_at("links_cap_bytes", 10 * DAY),
            Some(6000)
        );
    }

    #[test]
    fn intermediate_future_map_cannot_hide_behind_a_valid_final_map() {
        let replay = Schedule::replay(
            0,
            &[
                change("links_cap_bytes", 6000, 0, 0, 9 * DAY),
                change("link_url_cap_bytes", 5000, 1, DAY, 10 * DAY),
                change("link_url_cap_bytes", 2048, 2, 2 * DAY, 12 * DAY),
                change("links_cap_bytes", 5000, 3, 3 * DAY, 11 * DAY),
            ],
        );
        assert_eq!(replay.rejected, [3]);
        assert_eq!(
            replay.schedule.value_at("links_cap_bytes", 12 * DAY),
            Some(6000)
        );
    }

    #[test]
    fn rejected_candidates_cannot_be_resubmitted_out_of_order() {
        let mut schedule = Schedule::new(0);
        let window = change("payload_window_days", 541, 0, 0, 10 * DAY);
        assert!(schedule.try_accept(window.clone()).is_err());
        schedule
            .try_accept(change("mirror_retention_days", 120, 1, DAY, 10 * DAY))
            .unwrap();
        assert!(schedule.try_accept(window).is_err());
        assert_eq!(
            schedule.value_at("payload_window_days", 10 * DAY),
            Some(180)
        );
    }

    #[test]
    fn recovery_window_days_stay_inside_the_log_timestamp_range() {
        let effective = 10 * DAY;
        let largest = (LOG_TIMESTAMP_MAX_S - effective) / DAY;
        let replay = Schedule::replay(
            0,
            &[
                change("recovery_window_days", largest, 0, 0, effective),
                change("recovery_window_days", largest + 1, 1, 0, effective),
                change("recovery_window_days", 7, 2, 0, effective),
            ],
        );
        assert_eq!(replay.rejected, [1]);
        assert_eq!(
            replay.schedule.value_at("recovery_window_days", effective),
            Some(7)
        );
        assert!(effective + largest * DAY <= LOG_TIMESTAMP_MAX_S);
        assert!(effective + (largest + 1) * DAY > LOG_TIMESTAMP_MAX_S);
    }

    #[test]
    fn long_grace_and_windows_do_not_overflow() {
        let max = super::super::WIRE_INTEGER_MAX;
        let replay = Schedule::replay(
            0,
            &[
                change("param_grace_days", max, 0, 0, 7 * DAY),
                change("quota_base", 101, 1, 7 * DAY, i64::MAX),
                change("payload_window_days", max, 2, 7 * DAY + 1, i64::MAX),
            ],
        );
        assert_eq!(replay.rejected, [1, 2]);
    }
}
