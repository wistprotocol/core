use crate::checkpoint::{self, AggregatorKey};
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::objects::{
    AggregatorKeyEntry, Anchor, GenesisKey, KeyAddDetails, RegistryAction, RegistryDetails,
    RegistryUpdateEnvelope,
};
use crate::registry_updates::AcceptedUpdates;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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
    Repeated {
        update_id: String,
        accepted_height: u64,
    },
    NotKeyAct,
}

impl Outcome {
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Outcome::Ignored { code, .. } => Some(code),
            Outcome::Conflict { .. } => Some(KEY_ACT_CONFLICT_CODE),
            Outcome::Accepted { .. } | Outcome::Repeated { .. } | Outcome::NotKeyAct => None,
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
    pub adding_act: Option<Value>,
    pub removing_act: Option<Value>,
}

impl KeyRecord {
    pub fn valid_at(&self, height: u64) -> bool {
        self.added_height <= height && self.removed_height.is_none_or(|removed| removed > height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTupleRule {
    DistinctKeys,
    GenesisTuple,
    AddingAct,
    RemovingAct,
    ActSignature,
}

impl KeyTupleRule {
    pub fn number(self) -> u8 {
        match self {
            KeyTupleRule::DistinctKeys => 1,
            KeyTupleRule::GenesisTuple => 2,
            KeyTupleRule::AddingAct => 3,
            KeyTupleRule::RemovingAct => 4,
            KeyTupleRule::ActSignature => 5,
        }
    }
}

impl fmt::Display for KeyTupleRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let requirement = match self {
            KeyTupleRule::DistinctKeys => {
                "two tuples carry one key_id or keys with one note key ID"
            }
            KeyTupleRule::GenesisTuple => {
                "the tuple with no adding act is not the Anchor's genesis key at height 0"
            }
            KeyTupleRule::AddingAct => {
                "an adding act is not an aggregator_key_add for its tuple at a height through the Snapshot's Epoch"
            }
            KeyTupleRule::RemovingAct => {
                "a removing act and a removed height do not pair as an aggregator_key_remove for the tuple above its added height"
            }
            KeyTupleRule::ActSignature => {
                "an act does not verify under a key the tuples hold valid at the height below its own"
            }
        };
        write!(f, "rule {} — {requirement}", self.number())
    }
}

#[derive(Debug, Clone)]
pub struct Registry {
    log_id: String,
    genesis_key_id: Option<String>,
    keys: BTreeMap<String, KeyRecord>,
    updates: AcceptedUpdates,
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
            adding_act: None,
            removing_act: None,
        };
        Ok(Registry {
            log_id: log_id.to_owned(),
            genesis_key_id: Some(genesis.key_id.clone()),
            keys: [(genesis.key_id.clone(), record)].into_iter().collect(),
            updates: AcceptedUpdates::new(),
        })
    }

    pub fn from_state_tuples(
        anchor: &Anchor,
        epoch_number: u64,
        entries: &[AggregatorKeyEntry],
    ) -> Result<Self, Error> {
        let genesis = &anchor.genesis_key;
        let log_id = anchor.log_id.as_str();
        let broken = |rule: KeyTupleRule| Err(Error::KeyTuples(rule));

        let mut public_keys = Vec::with_capacity(entries.len());
        for entry in entries {
            match PublicKey::from_b64u(&entry.public_key) {
                Ok(key) => public_keys.push(key),
                Err(_) => return broken(KeyTupleRule::DistinctKeys),
            }
        }
        let mut key_ids = BTreeSet::new();
        let mut note_key_ids = BTreeSet::new();
        for (entry, public_key) in entries.iter().zip(&public_keys) {
            if !key_ids.insert(entry.key_id.as_str())
                || !note_key_ids.insert(checkpoint::aggregator_key_id(log_id, public_key))
            {
                return broken(KeyTupleRule::DistinctKeys);
            }
        }

        let mut rootless = entries.iter().filter(|entry| entry.adding_act.is_none());
        let Some(root) = rootless.next() else {
            return broken(KeyTupleRule::GenesisTuple);
        };
        if rootless.next().is_some()
            || root.key_id != genesis.key_id
            || root.public_key != genesis.public_key
            || root.added_height != 0
        {
            return broken(KeyTupleRule::GenesisTuple);
        }

        for entry in entries {
            if let Some(act) = &entry.adding_act {
                if !carries_act(
                    act,
                    RegistryAction::AggregatorKeyAdd,
                    &entry.key_id,
                    Some(&entry.public_key),
                ) || entry.added_height > epoch_number
                {
                    return broken(KeyTupleRule::AddingAct);
                }
            }
            match (entry.removed_height, &entry.removing_act) {
                (None, None) => {}
                (Some(removed), Some(act)) => {
                    let floor = match entry.adding_act {
                        None => 0,
                        Some(_) => entry.added_height + 1,
                    };
                    if !carries_act(
                        act,
                        RegistryAction::AggregatorKeyRemove,
                        &entry.key_id,
                        None,
                    ) || removed < floor
                        || removed > epoch_number
                    {
                        return broken(KeyTupleRule::RemovingAct);
                    }
                }
                _ => return broken(KeyTupleRule::RemovingAct),
            }
        }

        for entry in entries {
            for (act, height) in [
                (&entry.adding_act, Some(entry.added_height)),
                (&entry.removing_act, entry.removed_height),
            ] {
                let (Some(act), Some(height)) = (act, height) else {
                    continue;
                };
                let signer = act.pointer("/sig/key_id").and_then(Value::as_str);
                let named = signer.and_then(|signer| {
                    entries
                        .iter()
                        .zip(&public_keys)
                        .find(|(entry, _)| entry.key_id == signer)
                });
                let Some((tuple, public_key)) = named else {
                    return broken(KeyTupleRule::ActSignature);
                };
                let valid = match height.checked_sub(1) {
                    None => tuple.key_id == genesis.key_id,
                    Some(below) => {
                        tuple.added_height <= below
                            && tuple.removed_height.is_none_or(|removed| removed > below)
                    }
                };
                if !valid || crate::envelope::verify_envelope(act, "update", public_key).is_err() {
                    return broken(KeyTupleRule::ActSignature);
                }
            }
        }

        let keys = entries
            .iter()
            .zip(public_keys)
            .map(|(entry, public_key)| {
                (
                    entry.key_id.clone(),
                    KeyRecord {
                        key_id: entry.key_id.clone(),
                        public_key,
                        added_height: entry.added_height,
                        removed_height: entry.removed_height,
                        adding_act: entry.adding_act.clone(),
                        removing_act: entry.removing_act.clone(),
                    },
                )
            })
            .collect();
        Ok(Registry {
            log_id: log_id.to_owned(),
            genesis_key_id: Some(genesis.key_id.clone()),
            keys,
            updates: AcceptedUpdates::new(),
        })
    }

    /// WIST-4 §5.1: a Consumer resumed from a Snapshot holds the IDs of its `registry_update`
    /// tuples as accepted.
    pub fn hold_accepted_updates(&mut self, updates: AcceptedUpdates) {
        self.updates = updates;
    }

    pub fn accepted_updates(&self) -> &AcceptedUpdates {
        &self.updates
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
                adding_act: record.adding_act.clone(),
                removing_act: record.removing_act.clone(),
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
        let Ok(update_id) = crate::registry_updates::update_id(act) else {
            return Outcome::Ignored {
                code: "WIST1-E05",
                reason: "the act carries no update",
            };
        };
        if let Some(accepted_height) = self.updates.accepted_height(&update_id) {
            return Outcome::Repeated {
                update_id,
                accepted_height,
            };
        }
        if authenticate(act, authenticators).is_err() {
            return Outcome::Ignored {
                code: "WIST4-E11",
                reason: "no key valid at the Epoch before this one signed the act",
            };
        }
        let outcome = match details {
            RegistryDetails::KeyAdd(details) => self.admit(height, act, &details),
            RegistryDetails::KeyRemove(details) => {
                self.retire(height, act, &details.key_id, authenticators)
            }
            _ => Outcome::NotKeyAct,
        };
        if outcome.is_accepted() {
            self.updates.accept(&update_id, height);
        }
        outcome
    }

    fn admit(&mut self, height: u64, act: &Value, details: &KeyAddDetails) -> Outcome {
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
                adding_act: Some(act.clone()),
                removing_act: None,
            },
        );
        Outcome::Accepted {
            action: KeyAction::Add,
            key_id: details.key_id.clone(),
        }
    }

    fn retire(
        &mut self,
        height: u64,
        act: &Value,
        key_id: &str,
        authenticators: &[AggregatorKey],
    ) -> Outcome {
        if !authenticators.iter().any(|key| key.key_id == key_id) {
            return Outcome::Conflict {
                reason: "the key_id is not valid at the Epoch before this one",
            };
        }
        if let Some(record) = self.keys.get_mut(key_id) {
            record.removed_height = Some(height);
            if record.removing_act.is_none() {
                record.removing_act = Some(act.clone());
            }
        }
        Outcome::Accepted {
            action: KeyAction::Remove,
            key_id: key_id.to_owned(),
        }
    }
}

fn carries_act(
    act: &Value,
    action: RegistryAction,
    key_id: &str,
    public_key: Option<&str>,
) -> bool {
    if crate::jcs::canonicalize(act).is_err() {
        return false;
    }
    let Ok(envelope) = serde_json::from_value::<RegistryUpdateEnvelope>(act.clone()) else {
        return false;
    };
    if crate::withdrawal::envelope_fields(&envelope).is_err() || envelope.update.action != action {
        return false;
    }
    match envelope.update.typed_details() {
        Ok(RegistryDetails::KeyAdd(details)) => {
            details.key_id == key_id && public_key == Some(details.public_key.as_str())
        }
        Ok(RegistryDetails::KeyRemove(details)) => details.key_id == key_id,
        _ => false,
    }
}

pub fn check_catch_up(
    held: &Registry,
    verified_head: u64,
    offered: &Registry,
) -> Result<(), Error> {
    let disagreement = |key_id: &str| {
        Err(Error::KeyTupleCatchUp {
            key_id: key_id.to_owned(),
        })
    };
    let key_ids: BTreeSet<&str> = held
        .keys
        .keys()
        .chain(offered.keys.keys())
        .map(String::as_str)
        .collect();
    for key_id in key_ids {
        match (held.keys.get(key_id), offered.keys.get(key_id)) {
            (Some(_), None) => return disagreement(key_id),
            (Some(held), Some(offered)) => {
                let agrees = offered.public_key == held.public_key
                    && offered.added_height == held.added_height
                    && same_act(&offered.adding_act, &held.adding_act)
                    && match held.removed_height {
                        None => offered.removed_height.is_none_or(|h| h > verified_head),
                        Some(removed) => {
                            offered.removed_height == Some(removed)
                                && same_act(&offered.removing_act, &held.removing_act)
                        }
                    };
                if !agrees {
                    return disagreement(key_id);
                }
            }
            (None, Some(offered)) => {
                if offered.added_height <= verified_head {
                    return disagreement(key_id);
                }
            }
            (None, None) => {}
        }
    }
    Ok(())
}

fn same_act(left: &Option<Value>, right: &Option<Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => match (
            crate::jcs::canonicalize(left),
            crate::jcs::canonicalize(right),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        },
        _ => false,
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

    fn anchor(genesis: &SigningKey) -> Anchor {
        Anchor {
            wist_version: crate::WIST_VERSION.into(),
            log_id: LOG_ID.into(),
            genesis_key: GenesisKey {
                key_id: "genesis".into(),
                alg: "Ed25519".into(),
                public_key: genesis.public().to_b64u(),
            },
            created_at: SEALED_AT.into(),
            predecessor: None,
        }
    }

    fn genesis_registry() -> (Registry, SigningKey) {
        let key = signing_key(1);
        let anchor = anchor(&key);
        (
            Registry::from_genesis(LOG_ID, &anchor.genesis_key).unwrap(),
            key,
        )
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
        let mut restored =
            Registry::from_state_tuples(&anchor(&genesis), 5, &restored_entries).unwrap();
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
        let mut later = remove_act("genesis", &genesis, "k2")["update"].clone();
        later["effective_at"] = json!("2026-08-02T13:00:01Z");
        let later = crate::envelope::sign_envelope(&later, "update", "genesis", &genesis).unwrap();
        let again = registry.apply_epoch(4, &[later]);
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

        let resumed = Registry::from_state_tuples(&anchor(&genesis), 4, &registry.entries())
            .expect("the tuples the replay leaves authenticate from the Anchor");
        assert_eq!(resumed.genesis_key_id(), Some("genesis"));
        assert_eq!(
            resumed
                .key_act_authenticators(0)
                .iter()
                .map(|key| key.key_id.clone())
                .collect::<Vec<_>>(),
            vec!["genesis".to_string()]
        );
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

    fn state_tuples(registry: &Registry) -> Vec<AggregatorKeyEntry> {
        registry.entries()
    }

    fn rule(error: &Error) -> KeyTupleRule {
        match error {
            Error::KeyTuples(rule) => *rule,
            other => panic!("{other} is not a key-tuple authentication failure"),
        }
    }

    #[test]
    fn a_state_that_repeats_a_key_id_or_a_note_key_id_does_not_authenticate() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let anchor = anchor(&genesis);
        let entries = state_tuples(&registry);
        Registry::from_state_tuples(&anchor, 1, &entries).unwrap();

        let mut repeated = entries.clone();
        repeated.push(entries[0].clone());
        let error = Registry::from_state_tuples(&anchor, 1, &repeated).unwrap_err();
        assert_eq!(rule(&error), KeyTupleRule::DistinctKeys);
        assert_eq!(error.code(), Some("WIST3-E04"));

        let mut shared_note_key = entries.clone();
        shared_note_key.push(AggregatorKeyEntry {
            key_id: "k3".into(),
            public_key: second.public().to_b64u(),
            added_height: 1,
            removed_height: None,
            adding_act: Some(add_act("genesis", &genesis, "k3", &second)),
            removing_act: None,
        });
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 1, &shared_note_key).unwrap_err()),
            KeyTupleRule::DistinctKeys,
            "two key_ids naming one public key derive one note key ID"
        );
    }

    #[test]
    fn only_the_anchors_genesis_key_may_carry_no_adding_act() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let anchor = anchor(&genesis);

        let mut rootless = state_tuples(&registry);
        rootless[1].adding_act = None;
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 1, &rootless).unwrap_err()),
            KeyTupleRule::GenesisTuple
        );

        let mut restated = state_tuples(&registry);
        restated[0].public_key = signing_key(3).public().to_b64u();
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 1, &restated).unwrap_err()),
            KeyTupleRule::GenesisTuple
        );

        let mut raised = state_tuples(&registry);
        raised[0].added_height = 1;
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 1, &raised).unwrap_err()),
            KeyTupleRule::GenesisTuple
        );
    }

    #[test]
    fn a_height_outside_its_acts_contract_does_not_authenticate() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(2, &[remove_act("genesis", &genesis, "k2")]);
        let anchor = anchor(&genesis);
        let entries = state_tuples(&registry);

        let mut above_the_epoch = entries.clone();
        above_the_epoch[1].added_height = 3;
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &above_the_epoch).unwrap_err()),
            KeyTupleRule::AddingAct
        );

        let mut removed_where_added = entries.clone();
        removed_where_added[1].removed_height = Some(entries[1].added_height);
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &removed_where_added).unwrap_err()),
            KeyTupleRule::RemovingAct
        );

        let mut act_without_height = entries.clone();
        act_without_height[1].removed_height = None;
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &act_without_height).unwrap_err()),
            KeyTupleRule::RemovingAct
        );

        let mut height_without_act = entries.clone();
        height_without_act[1].removing_act = None;
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &height_without_act).unwrap_err()),
            KeyTupleRule::RemovingAct
        );
    }

    #[test]
    fn the_genesis_key_alone_may_be_removed_at_the_height_that_admitted_it() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(
            0,
            &[
                add_act("genesis", &genesis, "k2", &second),
                remove_act("genesis", &genesis, "genesis"),
            ],
        );
        assert_eq!(registry.record("genesis").unwrap().removed_height, Some(0));
        let entries = state_tuples(&registry);
        let restored = Registry::from_state_tuples(&anchor(&genesis), 0, &entries).unwrap();
        assert_eq!(tuples(&restored), tuples(&registry));
    }

    #[test]
    fn an_act_no_key_the_tuples_hold_valid_below_its_height_signed_does_not_authenticate() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let third = signing_key(3);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        registry.apply_epoch(2, &[add_act("genesis", &genesis, "k3", &third)]);
        let anchor = anchor(&genesis);
        Registry::from_state_tuples(&anchor, 2, &state_tuples(&registry)).unwrap();

        let mut self_admitted = state_tuples(&registry);
        self_admitted[2].adding_act = Some(add_act("k3", &third, "k3", &third));
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &self_admitted).unwrap_err()),
            KeyTupleRule::ActSignature
        );

        let mut signed_by_a_stranger = state_tuples(&registry);
        let stranger = signing_key(8);
        signed_by_a_stranger[2].adding_act = Some(add_act("k8", &stranger, "k3", &third));
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &signed_by_a_stranger).unwrap_err()),
            KeyTupleRule::ActSignature
        );

        let mut damaged = state_tuples(&registry);
        let mut act = damaged[2].adding_act.clone().unwrap();
        act["update"]["effective_at"] = json!("2026-08-02T14:00:00Z");
        damaged[2].adding_act = Some(act);
        assert_eq!(
            rule(&Registry::from_state_tuples(&anchor, 2, &damaged).unwrap_err()),
            KeyTupleRule::ActSignature
        );
    }

    #[test]
    fn a_second_removal_of_one_key_in_one_epoch_leaves_the_act_at_the_lower_entry_index() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let first_removal = remove_act("genesis", &genesis, "k2");
        let mut later = first_removal["update"].clone();
        later["effective_at"] = json!("2026-08-02T13:00:01Z");
        let second_removal =
            crate::envelope::sign_envelope(&later, "update", "k2", &second).unwrap();
        assert_ne!(
            crate::registry_updates::update_id(&first_removal).unwrap(),
            crate::registry_updates::update_id(&second_removal).unwrap()
        );
        let outcomes = registry.apply_epoch(2, &[first_removal.clone(), second_removal]);
        assert!(outcomes.iter().all(Outcome::is_accepted));
        let record = registry.record("k2").unwrap();
        assert_eq!(record.removed_height, Some(2));
        assert_eq!(record.removing_act.as_ref(), Some(&first_removal));
    }

    #[test]
    fn a_removal_sealed_again_under_its_id_in_one_epoch_is_repeated() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        registry.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let removal = remove_act("genesis", &genesis, "k2");
        let resigned = remove_act("k2", &second, "k2");
        let outcomes = registry.apply_epoch(2, &[removal.clone(), resigned]);
        assert!(outcomes[0].is_accepted());
        assert_eq!(
            outcomes[1],
            Outcome::Repeated {
                update_id: crate::registry_updates::update_id(&removal).unwrap(),
                accepted_height: 2,
            }
        );
        assert_eq!(outcomes[1].code(), None);
        assert_eq!(
            registry.record("k2").unwrap().removing_act.as_ref(),
            Some(&removal)
        );
    }

    #[test]
    fn a_key_act_sealed_again_at_a_later_height_is_repeated_not_evaluated() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let addition = add_act("genesis", &genesis, "k2", &second);
        let removal = remove_act("genesis", &genesis, "k2");
        registry.apply_epoch(1, std::slice::from_ref(&addition));
        registry.apply_epoch(2, std::slice::from_ref(&removal));
        let again = registry.apply_epoch(3, &[addition.clone(), removal.clone()]);
        assert_eq!(
            again,
            [
                Outcome::Repeated {
                    update_id: crate::registry_updates::update_id(&addition).unwrap(),
                    accepted_height: 1,
                },
                Outcome::Repeated {
                    update_id: crate::registry_updates::update_id(&removal).unwrap(),
                    accepted_height: 2,
                },
            ]
        );
        let record = registry.record("k2").unwrap();
        assert_eq!((record.added_height, record.removed_height), (1, Some(2)));
    }

    #[test]
    fn a_key_act_sealed_again_rejects_nothing_whatever_its_signature() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let addition = add_act("genesis", &genesis, "k2", &second);
        registry.apply_epoch(1, std::slice::from_ref(&addition));
        let mut unverified = addition.clone();
        unverified["sig"]["value"] = json!(signing_key(9).sign(b"other"));
        assert!(matches!(
            registry.apply_epoch(2, &[unverified])[0],
            Outcome::Repeated {
                accepted_height: 1,
                ..
            }
        ));
    }

    #[test]
    fn a_key_act_sealed_again_that_fails_field_validation_keeps_its_code() {
        let (mut registry, genesis) = genesis_registry();
        let second = signing_key(2);
        let addition = add_act("genesis", &genesis, "k2", &second);
        registry.apply_epoch(1, std::slice::from_ref(&addition));
        let mut malformed = addition.clone();
        malformed["sig"]["alg"] = json!("Ed448");
        assert_eq!(
            registry.apply_epoch(2, &[malformed])[0].code(),
            Some("WIST4-E11")
        );
    }

    #[test]
    fn a_registry_holding_registry_update_tuples_reads_a_key_act_sealed_again_as_repeated() {
        let (mut sealed, genesis) = genesis_registry();
        let second = signing_key(2);
        let addition = add_act("genesis", &genesis, "k2", &second);
        sealed.apply_epoch(1, std::slice::from_ref(&addition));
        let anchor = anchor(&genesis);
        let mut resumed = Registry::from_state_tuples(&anchor, 1, &sealed.entries()).unwrap();
        assert_eq!(
            resumed
                .clone()
                .apply_epoch(2, std::slice::from_ref(&addition))[0]
                .code(),
            Some(KEY_ACT_CONFLICT_CODE),
            "without the registry_update tuples the act is evaluated"
        );
        let tuples: Vec<StateEntry> = sealed
            .accepted_updates()
            .entries()
            .into_iter()
            .map(StateEntry::RegistryUpdate)
            .collect();
        resumed.hold_accepted_updates(AcceptedUpdates::from_state(&tuples).unwrap());
        assert!(matches!(
            resumed.apply_epoch(2, &[addition])[0],
            Outcome::Repeated {
                accepted_height: 1,
                ..
            }
        ));
    }

    #[test]
    fn tuples_agree_with_a_consumers_registry_up_to_its_verified_head() {
        let (mut held, genesis) = genesis_registry();
        let second = signing_key(2);
        let third = signing_key(3);
        held.apply_epoch(1, &[add_act("genesis", &genesis, "k2", &second)]);
        let mut offered = held.clone();
        offered.apply_epoch(2, &[add_act("genesis", &genesis, "k3", &third)]);
        let anchor = anchor(&genesis);
        let offered = Registry::from_state_tuples(&anchor, 2, &offered.entries()).unwrap();
        check_catch_up(&held, 1, &offered).unwrap();

        let key_id = |error: Error| match error {
            Error::KeyTupleCatchUp { key_id } => key_id,
            other => panic!("{other} is not a catch-up disagreement"),
        };
        assert_eq!(
            key_id(check_catch_up(&held, 2, &offered).unwrap_err()),
            "k3",
            "a key the registry does not hold is admitted at or below its verified head"
        );

        let mut omitted = offered.entries();
        omitted.retain(|entry| entry.key_id != "k2");
        let omitted = Registry::from_state_tuples(&anchor, 2, &omitted)
            .expect("§7's rules do not require a tuple for every key the Log admitted");
        assert_eq!(
            key_id(check_catch_up(&held, 1, &omitted).unwrap_err()),
            "k2",
            "a key the registry holds has no tuple"
        );

        let mut removed_below_the_head = held.clone();
        removed_below_the_head.apply_epoch(2, &[remove_act("genesis", &genesis, "k2")]);
        let removed_below_the_head =
            Registry::from_state_tuples(&anchor, 2, &removed_below_the_head.entries()).unwrap();
        check_catch_up(&held, 1, &removed_below_the_head).unwrap();
        assert_eq!(
            key_id(check_catch_up(&held, 2, &removed_below_the_head).unwrap_err()),
            "k2",
            "a key the registry holds as valid at its head is removed at or below it"
        );
    }
}
