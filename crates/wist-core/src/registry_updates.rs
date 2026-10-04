use crate::error::Error;
use crate::objects::{RegistryUpdateEntry, StateEntry};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn update_id(act: &Value) -> Result<String, Error> {
    let update = act
        .get("update")
        .ok_or_else(|| Error::Envelope("a Registry Update carries an update member".into()))?;
    crate::item::sha256_hex("sha256:", update)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedUpdates {
    accepted: BTreeMap<String, u64>,
}

impl AcceptedUpdates {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_state(entries: &[StateEntry]) -> Result<Self, Error> {
        let mut updates = Self::new();
        for entry in entries {
            if let StateEntry::RegistryUpdate(entry) = entry {
                if !updates.accept(&entry.update_id, entry.sealing_height) {
                    return Err(Error::Snapshot(format!(
                        "two registry_update tuples of {}",
                        entry.update_id
                    )));
                }
            }
        }
        Ok(updates)
    }

    pub fn accept(&mut self, update_id: &str, height: u64) -> bool {
        match self.accepted.get_mut(update_id) {
            Some(held) => {
                *held = (*held).min(height);
                false
            }
            None => {
                self.accepted.insert(update_id.to_owned(), height);
                true
            }
        }
    }

    pub fn is_accepted(&self, update_id: &str) -> bool {
        self.accepted.contains_key(update_id)
    }

    pub fn accepted_height(&self, update_id: &str) -> Option<u64> {
        self.accepted.get(update_id).copied()
    }

    pub fn entries(&self) -> Vec<RegistryUpdateEntry> {
        self.accepted
            .iter()
            .map(|(update_id, height)| RegistryUpdateEntry {
                update_id: update_id.clone(),
                sealing_height: *height,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tuple(update_id: &str, height: u64) -> StateEntry {
        StateEntry::RegistryUpdate(RegistryUpdateEntry {
            update_id: update_id.into(),
            sealing_height: height,
        })
    }

    #[test]
    fn an_update_id_is_the_digest_of_the_update_member_alone() {
        let act = json!({"update": {"action": "parameter_change"}, "sig": {"key_id": "a"}});
        let mut resigned = act.clone();
        resigned["sig"]["key_id"] = json!("b");
        assert_eq!(update_id(&act).unwrap(), update_id(&resigned).unwrap());
        assert!(update_id(&json!({"sig": {}})).is_err());
    }

    #[test]
    fn an_id_accepted_again_keeps_its_earliest_height() {
        let mut updates = AcceptedUpdates::new();
        assert!(updates.accept("sha256:a", 4));
        assert!(!updates.accept("sha256:a", 6));
        assert!(!updates.accept("sha256:a", 2));
        assert_eq!(updates.accepted_height("sha256:a"), Some(2));
        assert!(!updates.is_accepted("sha256:b"));
    }

    #[test]
    fn registry_update_tuples_round_trip_and_a_repeated_id_is_refused() {
        let tuples = [tuple("sha256:a", 1), tuple("sha256:b", 3)];
        let updates = AcceptedUpdates::from_state(&tuples).unwrap();
        assert_eq!(
            serde_json::to_value(
                updates
                    .entries()
                    .into_iter()
                    .map(StateEntry::RegistryUpdate)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            serde_json::to_value(tuples).unwrap()
        );
        assert!(
            AcceptedUpdates::from_state(&[tuple("sha256:a", 1), tuple("sha256:a", 2)]).is_err()
        );
    }
}
