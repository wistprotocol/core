use super::{spec, validate_combinations, validate_value};
use crate::crypto::PublicKey;
use crate::objects::{RegistryAction, RegistryDetails, RegistryUpdateEnvelope};
use crate::registry_updates::AcceptedUpdates;
use crate::Error;
use serde_json::Value;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActPosition {
    pub epoch_number: u64,
    pub entry_index: u64,
    pub sealed_at_s: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Accepted(Amendment),
    Repeated {
        update_id: String,
        accepted_height: u64,
    },
    Rejected {
        code: &'static str,
        reason: String,
    },
    NotParameterChange,
}

#[derive(Debug, Clone)]
pub struct Schedule {
    first_epoch_s: i64,
    accepted: Vec<Amendment>,
    last_position: Option<(u64, u64)>,
    updates: AcceptedUpdates,
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
            updates: AcceptedUpdates::new(),
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

    /// WIST-4 §5.1: a Consumer resumed from a Snapshot holds the IDs of its `registry_update`
    /// tuples as accepted.
    pub fn hold_accepted_updates(&mut self, updates: AcceptedUpdates) {
        self.updates = updates;
    }

    pub fn accepted_updates(&self) -> &AcceptedUpdates {
        &self.updates
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

    /// WIST-4 §5.1: eligibility and field validation, then the ID, so an occurrence of an
    /// accepted ID is idempotent whatever its signature, then authentication under `log_key`,
    /// then §5.
    pub fn apply_act(
        &mut self,
        doc: &Value,
        at: ActPosition,
        largest_epoch_bytes: u64,
        log_key: impl Fn(&str) -> Option<PublicKey>,
    ) -> Disposition {
        let rejected = |code: &'static str, reason: &str| Disposition::Rejected {
            code,
            reason: reason.to_owned(),
        };
        if crate::jcs::canonicalize(doc).is_err() {
            return rejected("WIST1-E05", "the act is not JSON a Log Entry carries");
        }
        let Ok(envelope) = serde_json::from_value::<RegistryUpdateEnvelope>(doc.clone()) else {
            return rejected("WIST4-E11", "the act is not a Registry Update Envelope");
        };
        if let Err(code) = crate::withdrawal::envelope_fields(&envelope) {
            return rejected(
                code,
                "the act's envelope fields are outside the §5.1 contract",
            );
        }
        if envelope.update.action != RegistryAction::ParameterChange {
            return Disposition::NotParameterChange;
        }
        let details = match envelope.update.typed_details() {
            Ok(RegistryDetails::ParameterChange(details)) => details,
            _ => {
                return rejected(
                    "WIST4-E04",
                    "the act's details or subject violate the parameter_change contract",
                )
            }
        };
        let Ok(effective_at_s) = crate::timestamp::log_seconds(&envelope.update.effective_at)
        else {
            return rejected("WIST4-E11", "the act's effective_at denotes no instant");
        };
        let Ok(update_id) = crate::registry_updates::update_id(doc) else {
            return rejected("WIST1-E05", "the act carries no update");
        };
        if let Some(accepted_height) = self.updates.accepted_height(&update_id) {
            return Disposition::Repeated {
                update_id,
                accepted_height,
            };
        }
        let authentic = log_key(&envelope.sig.key_id)
            .is_some_and(|key| crate::envelope::verify_envelope(doc, "update", &key).is_ok());
        if !authentic {
            return rejected(
                "WIST4-E11",
                "no key valid at the act's Epoch signed the act",
            );
        }
        let amendment = Amendment {
            parameter: details.parameter,
            value: details.value,
            epoch_number: at.epoch_number,
            entry_index: at.entry_index,
            sealed_at_s: at.sealed_at_s,
            effective_at_s,
        };
        match self.try_accept_with_epoch_size(amendment.clone(), largest_epoch_bytes) {
            Ok(()) => {
                self.updates.accept(&update_id, at.epoch_number);
                Disposition::Accepted(amendment)
            }
            Err(error) => rejected("WIST4-E03", &error.to_string()),
        }
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

    fn log_key() -> crate::crypto::SigningKey {
        crate::crypto::SigningKey::from_seed(&[7; 32])
    }

    fn act(parameter: &str, value: i64, effective_at: &str) -> Value {
        let update = serde_json::json!({
            "wist_version": "1.0.0",
            "action": "parameter_change",
            "subject": parameter,
            "effective_at": effective_at,
            "details": {"parameter": parameter, "value": value}
        });
        crate::envelope::sign_envelope(&update, "update", "log", &log_key()).unwrap()
    }

    fn apply(schedule: &mut Schedule, epoch_number: u64, doc: &Value) -> Disposition {
        let key = log_key().public();
        schedule.apply_act(
            doc,
            ActPosition {
                epoch_number,
                entry_index: 0,
                sealed_at_s: epoch_number as i64 * 3600,
            },
            0,
            |key_id| (key_id == "log").then(|| key.clone()),
        )
    }

    const EFFECTIVE: &str = "1970-01-11T00:00:00Z";

    #[test]
    fn an_amendment_sealed_again_after_a_later_one_applies_nothing() {
        let mut schedule = Schedule::new(0);
        let first = act("catalog_refresh_seconds", 3600, EFFECTIVE);
        assert!(matches!(
            apply(&mut schedule, 1, &first),
            Disposition::Accepted(_)
        ));
        assert!(matches!(
            apply(
                &mut schedule,
                2,
                &act("catalog_refresh_seconds", 7200, EFFECTIVE)
            ),
            Disposition::Accepted(_)
        ));
        assert_eq!(
            apply(&mut schedule, 3, &first),
            Disposition::Repeated {
                update_id: crate::registry_updates::update_id(&first).unwrap(),
                accepted_height: 1,
            }
        );
        assert_eq!(
            schedule.value_at("catalog_refresh_seconds", 10 * DAY),
            Some(7200)
        );
        assert_eq!(schedule.accepted().len(), 2);
        assert_eq!(schedule.accepted_updates().entries().len(), 2);
    }

    #[test]
    fn an_amendment_sealed_again_in_its_own_epoch_is_idempotent() {
        let mut schedule = Schedule::new(0);
        let doc = act("quota_base", 101, EFFECTIVE);
        apply(&mut schedule, 0, &doc);
        let key = log_key().public();
        let again = schedule.apply_act(
            &doc,
            ActPosition {
                epoch_number: 0,
                entry_index: 1,
                sealed_at_s: 0,
            },
            0,
            |key_id| (key_id == "log").then(|| key.clone()),
        );
        assert!(matches!(
            again,
            Disposition::Repeated {
                accepted_height: 0,
                ..
            }
        ));
        assert_eq!(schedule.accepted().len(), 1);
    }

    #[test]
    fn an_amendment_sealed_again_rejects_nothing_whatever_its_signature() {
        let mut schedule = Schedule::new(0);
        let doc = act("quota_base", 101, EFFECTIVE);
        apply(&mut schedule, 0, &doc);
        let mut unverified = doc.clone();
        unverified["sig"]["value"] =
            serde_json::json!(crate::crypto::SigningKey::from_seed(&[8; 32]).sign(b"other"));
        assert!(matches!(
            apply(&mut schedule, 1, &unverified),
            Disposition::Repeated { .. }
        ));
        assert!(matches!(
            apply(&mut Schedule::new(0), 1, &unverified),
            Disposition::Rejected {
                code: "WIST4-E11",
                ..
            }
        ));
    }

    #[test]
    fn an_amendment_sealed_again_that_fails_field_validation_keeps_its_code() {
        let mut schedule = Schedule::new(0);
        let doc = act("quota_base", 101, EFFECTIVE);
        apply(&mut schedule, 0, &doc);
        let mut malformed = doc.clone();
        malformed["sig"]["alg"] = serde_json::json!("Ed448");
        assert!(matches!(
            apply(&mut schedule, 1, &malformed),
            Disposition::Rejected {
                code: "WIST4-E11",
                ..
            }
        ));
    }

    #[test]
    fn an_amendment_failing_its_contract_or_section_5_is_rejected_with_its_code() {
        let mut schedule = Schedule::new(0);
        let mut other_subject = act("quota_base", 101, EFFECTIVE);
        other_subject["update"]["subject"] = serde_json::json!("feed_window");
        let other_subject =
            crate::envelope::sign_envelope(&other_subject["update"], "update", "log", &log_key())
                .unwrap();
        assert!(matches!(
            apply(&mut schedule, 0, &other_subject),
            Disposition::Rejected {
                code: "WIST4-E04",
                ..
            }
        ));
        assert!(matches!(
            apply(
                &mut schedule,
                0,
                &act("quota_base", 101, "1970-01-02T00:00:00Z")
            ),
            Disposition::Rejected {
                code: "WIST4-E03",
                ..
            }
        ));
        assert!(schedule.accepted_updates().entries().is_empty());
    }

    #[test]
    fn a_schedule_holding_registry_update_tuples_reads_a_sealing_again_as_repeated() {
        let doc = act("catalog_refresh_seconds", 3600, EFFECTIVE);
        let tuples = [crate::objects::StateEntry::RegistryUpdate(
            crate::objects::RegistryUpdateEntry {
                update_id: crate::registry_updates::update_id(&doc).unwrap(),
                sealing_height: 1,
            },
        )];
        let mut schedule = Schedule::new(0);
        schedule.hold_accepted_updates(AcceptedUpdates::from_state(&tuples).unwrap());
        assert!(matches!(
            apply(&mut schedule, 3, &doc),
            Disposition::Repeated {
                accepted_height: 1,
                ..
            }
        ));
        assert!(schedule.accepted().is_empty());
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
