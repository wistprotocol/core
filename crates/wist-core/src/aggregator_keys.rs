use crate::checkpoint::{self, AggregatorKey};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::objects::{
    AggregatorKeyEntry, GenesisKey, KeyAddDetails, RegistryAction, RegistryDetails,
    RegistryUpdateEnvelope,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const KEY_ACT_CONFLICT_CODE: &str = "WIST4-E04";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accepted {
        action: KeyAction,
        key_id: String,
    },
    Ignored {
        code: &'static str,
        reason: &'static str,
    },
    Conflict {
        reason: &'static str,
    },
    NotKeyAct,
}

impl Outcome {
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Outcome::Ignored { code, .. } => Some(code),
            Outcome::Conflict { .. } => Some(KEY_ACT_CONFLICT_CODE),
            Outcome::Accepted { .. } | Outcome::NotKeyAct => None,
        }
    }

    pub fn is_accepted(&self) -> bool {
        matches!(self, Outcome::Accepted { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub key_id: String,
    pub public_key: PublicKey,
    pub added_height: u64,
    pub removed_height: Option<u64>,
}

impl KeyRecord {
    pub fn valid_at(&self, height: u64) -> bool {
        self.added_height <= height && self.removed_height.is_none_or(|removed| removed > height)
    }
}

#[derive(Debug, Clone)]
pub struct Registry {
    log_id: String,
    genesis_key_id: Option<String>,
    keys: BTreeMap<String, KeyRecord>,
}

impl Registry {
    pub fn from_genesis(log_id: &str, genesis: &GenesisKey) -> Result<Self, Error> {
        if genesis.alg != "Ed25519" {
            return Err(Error::Envelope(
                "the genesis key does not name the Ed25519 algorithm".into(),
            ));
        }
        let public_key = PublicKey::from_b64u(&genesis.public_key)?;
        let record = KeyRecord {
            key_id: genesis.key_id.clone(),
            public_key,
            added_height: 0,
            removed_height: None,
        };
        Ok(Registry {
            log_id: log_id.to_owned(),
            genesis_key_id: Some(genesis.key_id.clone()),
            keys: [(genesis.key_id.clone(), record)].into_iter().collect(),
        })
    }

    pub fn from_entries(log_id: &str, entries: &[AggregatorKeyEntry]) -> Result<Self, Error> {
        let mut keys = BTreeMap::new();
        for entry in entries {
            if entry
                .removed_height
                .is_some_and(|removed| removed < entry.added_height)
            {
                return Err(Error::Envelope(
                    "a key is retired below the height that admitted it".into(),
                ));
            }
            let record = KeyRecord {
                key_id: entry.key_id.clone(),
                public_key: PublicKey::from_b64u(&entry.public_key)?,
                added_height: entry.added_height,
                removed_height: entry.removed_height,
            };
            if keys.insert(entry.key_id.clone(), record).is_some() {
                return Err(Error::Envelope(
                    "the state carries one key_id more than once".into(),
                ));
            }
        }
        Ok(Registry {
            log_id: log_id.to_owned(),
            genesis_key_id: None,
            keys,
        })
    }

    pub fn genesis_key_id(&self) -> Option<&str> {
        self.genesis_key_id.as_deref()
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    pub fn records(&self) -> impl Iterator<Item = &KeyRecord> {
        self.keys.values()
    }

    pub fn record(&self, key_id: &str) -> Option<&KeyRecord> {
        self.keys.get(key_id)
    }

    pub fn valid_at(&self, height: u64) -> Vec<AggregatorKey> {
        self.keys
            .values()
            .filter(|record| record.valid_at(height))
            .map(|record| AggregatorKey {
                key_id: record.key_id.clone(),
                public_key: record.public_key.clone(),
            })
            .collect()
    }

    pub fn key_act_authenticators(&self, epoch_number: u64) -> Vec<AggregatorKey> {
        match epoch_number.checked_sub(1) {
            Some(height) => self.valid_at(height),
            None => self
                .genesis_key_id
                .as_ref()
                .and_then(|key_id| self.keys.get(key_id))
                .map(|record| AggregatorKey {
                    key_id: record.key_id.clone(),
                    public_key: record.public_key.clone(),
                })
                .into_iter()
                .collect(),
        }
    }

    pub fn public_key_at(&self, key_id: &str, height: u64) -> Option<PublicKey> {
        self.keys
            .get(key_id)
            .filter(|record| record.valid_at(height))
            .map(|record| record.public_key.clone())
    }

    pub fn entries(&self) -> Vec<AggregatorKeyEntry> {
        self.keys
            .values()
            .map(|record| AggregatorKeyEntry {
                key_id: record.key_id.clone(),
                public_key: record.public_key.to_b64u(),
                added_height: record.added_height,
                removed_height: record.removed_height,
            })
            .collect()
    }

    pub fn apply_epoch<'a>(
        &mut self,
        height: u64,
        acts: impl IntoIterator<Item = &'a Value>,
    ) -> Vec<Outcome> {
        let authenticators = self.key_act_authenticators(height);
        acts.into_iter()
            .map(|act| self.apply(height, act, &authenticators))
            .collect()
    }

    fn apply(&mut self, height: u64, act: &Value, authenticators: &[AggregatorKey]) -> Outcome {
        if crate::jcs::canonicalize(act).is_err() {
            return Outcome::Ignored {
                code: "WIST1-E05",
                reason: "the act is not JSON a Log Entry carries",
            };
        }
        let Ok(envelope) = serde_json::from_value::<RegistryUpdateEnvelope>(act.clone()) else {
            return Outcome::Ignored {
                code: "WIST4-E11",
                reason: "the act is not a Registry Update Envelope",
            };
        };
        if let Err(code) = crate::withdrawal::envelope_fields(&envelope) {
            return Outcome::Ignored {
                code,
                reason: "the act's envelope fields are outside the §5.1 contract",
            };
        }
        if !matches!(
            envelope.update.action,
            RegistryAction::AggregatorKeyAdd | RegistryAction::AggregatorKeyRemove
        ) {
            return Outcome::NotKeyAct;
        }
        let details = match envelope.update.typed_details() {
            Ok(details) => details,
            Err(_) => {
                return Outcome::Ignored {
                    code: "WIST4-E04",
                    reason: "the act's details violate its action's contract",
                }
            }
        };
        if authenticate(act, authenticators).is_err() {
            return Outcome::Ignored {
                code: "WIST4-E11",
                reason: "no key valid at the Epoch before this one signed the act",
            };
        }
        match details {
            RegistryDetails::KeyAdd(details) => self.admit(height, &details),
            RegistryDetails::KeyRemove(details) => {
                self.retire(height, &details.key_id, authenticators)
            }
            _ => Outcome::NotKeyAct,
        }
    }

    fn admit(&mut self, height: u64, details: &KeyAddDetails) -> Outcome {
        let Ok(public_key) = PublicKey::from_b64u(&details.public_key) else {
            return Outcome::Ignored {
                code: "WIST4-E04",
                reason: "the act names octets that are not an Ed25519 public key",
            };
        };
        if self.keys.contains_key(&details.key_id) {
            return Outcome::Conflict {
                reason: "the key_id is one the Log has already admitted",
            };
        }
        let note_key_id = checkpoint::aggregator_key_id(&self.log_id, &public_key);
        if self.keys.values().any(|record| {
            checkpoint::aggregator_key_id(&self.log_id, &record.public_key) == note_key_id
        }) {
            return Outcome::Conflict {
                reason: "the note key ID is one an admitted key already derives",
            };
        }
        self.keys.insert(
            details.key_id.clone(),
            KeyRecord {
                key_id: details.key_id.clone(),
                public_key,
                added_height: height,
                removed_height: None,
            },
        );
        Outcome::Accepted {
            action: KeyAction::Add,
            key_id: details.key_id.clone(),
        }
    }

    fn retire(&mut self, height: u64, key_id: &str, authenticators: &[AggregatorKey]) -> Outcome {
        if !authenticators.iter().any(|key| key.key_id == key_id) {
            return Outcome::Conflict {
                reason: "the key_id is not valid at the Epoch before this one",
            };
        }
        if let Some(record) = self.keys.get_mut(key_id) {
            record.removed_height = Some(height);
        }
        Outcome::Accepted {
            action: KeyAction::Remove,
            key_id: key_id.to_owned(),
        }
    }
}

pub fn authenticate(act: &Value, keys: &[AggregatorKey]) -> Result<(), Error> {
    let named = act
        .pointer("/sig/key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Envelope("WIST4-E11 the act carries no sig.key_id".into()))?;
    let key = keys.iter().find(|key| key.key_id == named).ok_or_else(|| {
        Error::Envelope("WIST4-E11 no supplied key bears the act's key_id".into())
    })?;
    crate::envelope::verify_envelope(act, "update", &key.public_key).map_err(|_| {
        Error::Envelope(
            "WIST4-E11 the act's signature does not verify under the key it names".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::objects::StateEntry;
    use serde_json::json;

    const LOG_ID: &str = "log.example.org";
    const SEALED_AT: &str = "2026-08-02T13:00:00Z";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_seed(&[seed; 32])
    }

    fn genesis_registry() -> (Registry, SigningKey) {
        let key = signing_key(1);
        let genesis = GenesisKey {
            key_id: "genesis".into(),
            alg: "Ed25519".into(),
            public_key: key.public().to_b64u(),
        };
        (Registry::from_genesis(LOG_ID, &genesis).unwrap(), key)
    }

    fn add_act(signer_id: &str, signer: &SigningKey, key_id: &str, added: &SigningKey) -> Value {
        let update = json!({
            "wist_version": "1.0.0",
            "action": "aggregator_key_add",
            "subject": key_id,
            "details": {
                "key_id": key_id,
                "alg": "Ed25519",
                "public_key": added.public().to_b64u(),
            },
            "effective_at": SEALED_AT,
        });
        crate::envelope::sign_envelope(&update, "update", signer_id, signer).unwrap()
    }

    fn remove_act(signer_id: &str, signer: &SigningKey, key_id: &str) -> Value {
        let update = json!({
            "wist_version": "1.0.0",
            "action": "aggregator_key_remove",
            "subject": key_id,
            "details": {"key_id": key_id},
            "effective_at": SEALED_AT,
        });
        crate::envelope::sign_envelope(&update, "update", signer_id, signer).unwrap()
    }

    fn checkpoint_signed_by(epoch_number: u64, key: &SigningKey) -> checkpoint::Checkpoint {
        let mut note =
            checkpoint::Checkpoint::new(LOG_ID, 4, [7u8; 32], epoch_number, SEALED_AT).unwrap();
        note.sign(key);
        note
    }

    fn signs_checkpoint(registry: &Registry, height: u64, key: &SigningKey) -> bool {
        let note = checkpoint_signed_by(height, key);
        checkpoint::verify(&note, LOG_ID, &registry.valid_at(height), &[]).is_ok()
    }

    fn tuples(registry: &Registry) -> Vec<Value> {
        registry
            .entries()
            .into_iter()
            .map(|entry| serde_json::to_value(StateEntry::AggregatorKey(entry)).unwrap())
            .collect()
    }

    #[test]
    fn a_key_added_at_a_height_signs_that_checkpoint_but_not_a_key_act_in_its_epoch() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let third = signing_key(3);
        let outcomes = registry.apply_epoch(
            1,
            &[
                add_act("genesis", &genesis, "k2", &second),
                add_act("k2", &second, "k3", &third),
            ],
        );
        assert!(outcomes[0].is_accepted());
        assert_eq!(outcomes[1].code(), Some("WIST4-E11"));
        assert!(registry.record("k3").is_none());
        assert!(signs_checkpoint(&registry, 1, &second));
        assert!(!signs_checkpoint(&registry, 0, &second));
    }

    #[test]
    fn a_key_removed_at_a_height_does_not_sign_the_checkpoint_of_that_height() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let outcomes = registry.apply_epoch(2, &[remove_act("genesis", &genesis, "k2")]);
        assert!(outcomes[0].is_accepted());
        assert!(signs_checkpoint(&registry, 1, &second));
        assert!(!signs_checkpoint(&registry, 2, &second));
        assert_eq!(registry.record("k2").unwrap().removed_height, Some(2));
    }

    #[test]
    fn a_key_signs_its_own_removal() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let outcomes = registry.apply_epoch(2, &[remove_act("k2", &second, "k2")]);
        assert_eq!(
            outcomes[0],
            Outcome::Accepted {
                action: KeyAction::Remove,
                key_id: "k2".into()
            }
        );
        assert!(!signs_checkpoint(&registry, 2, &second));
        assert!(signs_checkpoint(&registry, 1, &second));
    }

    #[test]
    fn a_removed_genesis_key_stays_removed_across_a_state_round_trip() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let outcomes = registry.apply_epoch(2, &[remove_act("genesis", &genesis, "genesis")]);
        assert!(outcomes[0].is_accepted());

        let restored_entries: Vec<AggregatorKeyEntry> = tuples(&registry)
            .into_iter()
            .map(|tuple| match serde_json::from_value(tuple).unwrap() {
                StateEntry::AggregatorKey(entry) => entry,
                other => panic!("{other:?} is not an aggregator_key tuple"),
            })
            .collect();
        let mut restored = Registry::from_entries(LOG_ID, &restored_entries).unwrap();
        assert_eq!(tuples(&restored), tuples(&registry));
        assert!(!signs_checkpoint(&restored, 5, &genesis));
        assert_eq!(
            restored
                .valid_at(5)
                .iter()
                .map(|key| key.key_id.clone())
                .collect::<Vec<_>>(),
            vec!["k2".to_string()]
        );
        let readmission = restored.apply_epoch(5, &[add_act("k2", &second, "genesis", &genesis)]);
        assert_eq!(readmission[0].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert!(!signs_checkpoint(&restored, 5, &genesis));
    }

    #[test]
    fn an_add_and_a_remove_in_one_epoch_give_the_same_registry_in_either_entry_order() {
        let (mut first, genesis) = genesis_registry();
        let second = signing_key(2);
        let third = signing_key(3);
        first.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let mut reversed = first.clone();

        let add = add_act("genesis", &genesis, "k3", &third);
        let remove = remove_act("k2", &second, "k2");
        let forward = first.apply_epoch(2, &[add.clone(), remove.clone()]);
        let backward = reversed.apply_epoch(2, &[remove, add]);
        assert!(forward.iter().all(Outcome::is_accepted));
        assert!(backward.iter().all(Outcome::is_accepted));
        assert_eq!(tuples(&first), tuples(&reversed));
        assert!(signs_checkpoint(&first, 2, &third));
        assert!(!signs_checkpoint(&first, 2, &second));
    }

    #[test]
    fn a_re_add_of_a_removed_key_id_is_ignored() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(2, &[remove_act("genesis", &genesis, "k2")]);
        let fresh = signing_key(4);
        let outcomes = registry.apply_epoch(3, &[add_act("genesis", &genesis, "k2", &fresh)]);
        assert_eq!(outcomes[0].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert_eq!(registry.record("k2").unwrap().public_key, second.public());
        assert!(!signs_checkpoint(&registry, 3, &fresh));
    }

    #[test]
    fn an_add_whose_note_key_id_collides_with_a_removed_key_is_ignored() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(2, &[remove_act("genesis", &genesis, "k2")]);
        let outcomes = registry.apply_epoch(3, &[add_act("genesis", &genesis, "k9", &second)]);
        assert_eq!(outcomes[0].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert!(registry.record("k9").is_none());
    }

    #[test]
    fn a_duplicate_add_in_one_epoch_keeps_the_act_at_the_lower_entry_index() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let third = signing_key(3);
        let outcomes = registry.apply_epoch(
            1,
            &[
                add_act("genesis", &genesis, "k2", &second),
                add_act("genesis", &genesis, "k2", &third),
                add_act("genesis", &genesis, "k3", &second),
            ],
        );
        assert!(outcomes[0].is_accepted());
        assert_eq!(outcomes[1].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert_eq!(outcomes[2].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert_eq!(registry.record("k2").unwrap().public_key, second.public());
        assert!(registry.record("k3").is_none());
        assert!(signs_checkpoint(&registry, 1, &second));
        assert!(!signs_checkpoint(&registry, 1, &third));
    }

    #[test]
    fn a_remove_of_an_unknown_or_already_removed_key_id_is_ignored() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let unknown = registry.apply_epoch(2, &[remove_act("genesis", &genesis, "k7")]);
        assert_eq!(unknown[0].code(), Some(KEY_ACT_CONFLICT_CODE));
        registry.apply_epoch(3, &[remove_act("genesis", &genesis, "k2")]);
        let again = registry.apply_epoch(4, &[remove_act("genesis", &genesis, "k2")]);
        assert_eq!(again[0].code(), Some(KEY_ACT_CONFLICT_CODE));
        assert_eq!(registry.record("k2").unwrap().removed_height, Some(3));
    }

    #[test]
    fn an_unauthenticated_act_is_ignored_as_wist4_e11() {
        let (mut registry, genesis) = genesis_registry();
        let stranger = signing_key(8);
        let second = signing_key(2);
        let unknown_signer = add_act("stranger", &stranger, "k2", &second);
        let forged = {
            let mut act = add_act("stranger", &stranger, "k2", &second);
            act["sig"]["key_id"] = json!("genesis");
            act
        };
        let outcomes = registry.apply_epoch(1, &[unknown_signer, forged]);
        assert_eq!(outcomes[0].code(), Some("WIST4-E11"));
        assert_eq!(outcomes[1].code(), Some("WIST4-E11"));
        assert!(registry.record("k2").is_none());
        assert!(
            registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)])[0]
                .is_accepted()
        );
    }

    #[test]
    fn the_set_an_epoch_0_key_act_authenticates_under_is_the_genesis_key_alone() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(2, &[remove_act("k2", &second, "genesis")]);
        assert_eq!(registry.record("genesis").unwrap().removed_height, Some(2));
        assert_eq!(registry.genesis_key_id(), Some("genesis"));
        let authenticators = registry.key_act_authenticators(0);
        assert_eq!(
            authenticators
                .iter()
                .map(|key| key.key_id.clone())
                .collect::<Vec<_>>(),
            vec!["genesis".to_string()]
        );
        assert_eq!(
            registry
                .key_act_authenticators(2)
                .iter()
                .map(|key| key.key_id.clone())
                .collect::<Vec<_>>(),
            vec!["genesis".to_string(), "k2".to_string()]
        );

        let resumed = Registry::from_entries(LOG_ID, &registry.entries()).unwrap();
        assert_eq!(resumed.genesis_key_id(), None);
        assert!(resumed.key_act_authenticators(0).is_empty());
    }

    #[test]
    fn valid_at_reports_a_key_before_at_and_after_its_add_and_remove() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(3, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(5, &[remove_act("genesis", &genesis, "k2")]);
        let valid = |height: u64| {
            registry
                .valid_at(height)
                .iter()
                .any(|key| key.key_id == "k2")
        };
        assert!(!valid(2));
        assert!(valid(3));
        assert!(valid(4));
        assert!(!valid(5));
        assert!(!valid(6));
        assert!(registry.public_key_at("k2", 4).is_some());
        assert!(registry.public_key_at("k2", 5).is_none());
        assert!(registry.public_key_at("k7", 4).is_none());
    }

    #[test]
    fn a_registry_update_of_another_action_changes_no_key() {
        let (mut registry, genesis) = genesis_registry();
        let update = json!({
            "wist_version": "1.0.0",
            "action": "parameter_change",
            "subject": "quota_base",
            "details": {"parameter": "quota_base", "value": 64},
            "effective_at": SEALED_AT,
        });
        let act = crate::envelope::sign_envelope(&update, "update", "genesis", &genesis).unwrap();
        let outcomes = registry.apply_epoch(1, &[act]);
        assert_eq!(outcomes[0], Outcome::NotKeyAct);
        assert_eq!(registry.entries().len(), 1);
    }

    #[test]
    fn a_genesis_key_outside_the_anchor_contract_is_rejected() {
        let key = signing_key(1);
        let wrong_algorithm = GenesisKey {
            key_id: "genesis".into(),
            alg: "Ed448".into(),
            public_key: key.public().to_b64u(),
        };
        assert!(Registry::from_genesis(LOG_ID, &wrong_algorithm).is_err());
        let wrong_key = GenesisKey {
            key_id: "genesis".into(),
            alg: "Ed25519".into(),
            public_key: "not-a-key".into(),
        };
        assert!(Registry::from_genesis(LOG_ID, &wrong_key).is_err());
    }

    #[test]
    fn a_state_that_repeats_a_key_id_or_retires_before_admission_is_rejected() {
        let key = signing_key(1);
        let entry = |key_id: &str, added: u64, removed: Option<u64>| AggregatorKeyEntry {
            key_id: key_id.into(),
            public_key: key.public().to_b64u(),
            added_height: added,
            removed_height: removed,
        };
        assert!(
            Registry::from_entries(LOG_ID, &[entry("k1", 0, None), entry("k1", 1, None)]).is_err()
        );
        assert!(Registry::from_entries(LOG_ID, &[entry("k1", 4, Some(3))]).is_err());
        assert!(Registry::from_entries(LOG_ID, &[entry("k1", 4, Some(4))]).is_ok());
    }
}
