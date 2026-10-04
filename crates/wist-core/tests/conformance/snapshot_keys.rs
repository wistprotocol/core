use super::read_json;
use serde_json::Value;
use std::collections::BTreeSet;
use wist_core::aggregator_keys::{check_catch_up, Registry};
use wist_core::checkpoint::{self, AggregatorKey, Checkpoint};
use wist_core::crypto::PublicKey;
use wist_core::objects::{AggregatorKeyEntry, Anchor, StateEntry};
use wist_core::registry_updates::{update_id, AcceptedUpdates};
use wist_core::unsealed::{self, Document};
use wist_core::Error;

const DOCUMENTS: [Document; 3] = [Document::Index, Document::Manifest, Document::StateFile];

fn vector() -> Value {
    read_json("vectors/wist3/snapshot-keys.json")
}

fn anchor(history: &Value) -> Anchor {
    let envelope = &history["anchor"];
    let anchor: Anchor = serde_json::from_value(envelope["anchor"].clone()).unwrap();
    let public_key = PublicKey::from_b64u(&anchor.genesis_key.public_key).unwrap();
    wist_core::envelope::verify_envelope(envelope, "anchor", &public_key)
        .expect("the Anchor is self-signed under its own genesis_key");
    assert_eq!(anchor.log_id, history["log_id"].as_str().unwrap());
    anchor
}

fn key_tuples(entries: &Value) -> Vec<AggregatorKeyEntry> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .filter(|tuple| tuple[0] == "aggregator_key")
        .map(
            |tuple| match serde_json::from_value(tuple.clone()).unwrap() {
                StateEntry::AggregatorKey(entry) => entry,
                other => panic!("{other:?} is not an aggregator_key tuple"),
            },
        )
        .collect()
}

fn tuple_set(registry: &Registry) -> BTreeSet<String> {
    registry
        .entries()
        .into_iter()
        .map(|entry| serde_json::to_string(&StateEntry::AggregatorKey(entry)).unwrap())
        .collect()
}

fn stated_tuples(entries: &Value) -> BTreeSet<String> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .map(|tuple| serde_json::to_string(tuple).unwrap())
        .collect()
}

fn key_ids(keys: &[AggregatorKey]) -> BTreeSet<String> {
    keys.iter().map(|key| key.key_id.clone()).collect()
}

fn stated_strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

fn state_digest(entries: &Value) -> String {
    let entries: Vec<Value> = entries.as_array().unwrap().clone();
    wist_core::snapshot::state_digest(&entries).unwrap()
}

fn walk(registry: &Registry, history: &Value, from: u64, to: u64) -> Registry {
    let mut walked = registry.clone();
    for epoch in history["epochs"].as_array().unwrap() {
        let height = epoch["epoch_number"].as_u64().unwrap();
        if height > from && height <= to {
            walked.apply_epoch(
                height,
                epoch["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|entry| &entry["body"]),
            );
        }
    }
    walked
}

fn replay_history(history: &Value, anchor: &Anchor) -> Vec<Registry> {
    let mut registry = Registry::from_genesis(&anchor.log_id, &anchor.genesis_key).unwrap();
    let mut states = Vec::new();
    for epoch in history["epochs"].as_array().unwrap() {
        let height = epoch["epoch_number"].as_u64().unwrap();
        registry.apply_epoch(
            height,
            epoch["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["body"]),
        );
        let note = Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
        checkpoint::verify(&note, &anchor.log_id, &registry.valid_at(height), &[])
            .unwrap_or_else(|e| panic!("epoch {height}: the published Checkpoint verifies: {e}"));
        states.push(registry.clone());
    }
    states
}

fn accepted_updates(history: &Value, anchor: &Anchor) -> Vec<AcceptedUpdates> {
    let mut registry = Registry::from_genesis(&anchor.log_id, &anchor.genesis_key).unwrap();
    let mut updates = AcceptedUpdates::new();
    let mut states = Vec::new();
    for epoch in history["epochs"].as_array().unwrap() {
        let height = epoch["epoch_number"].as_u64().unwrap();
        let acts: Vec<&Value> = epoch["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["body"])
            .collect();
        let outcomes = registry.apply_epoch(height, acts.iter().copied());
        for (act, outcome) in acts.iter().zip(outcomes) {
            if outcome.is_accepted() {
                updates.accept(&update_id(act).unwrap(), height);
            }
        }
        states.push(updates.clone());
    }
    states
}

struct CaseReplay {
    verdict: Result<(), Error>,
    authenticated: bool,
    key_ids: BTreeSet<String>,
    failed_documents: BTreeSet<String>,
}

fn replay_case(case: &Value, history: &Value, anchor: &Anchor) -> CaseReplay {
    let epoch_number = case["epoch_number"].as_u64().unwrap();
    let head = case["adopted_head"].as_u64().unwrap();
    let entries = key_tuples(&case["state"]["state"]["entries"]);

    let offered = match Registry::from_state_tuples(anchor, epoch_number, &entries) {
        Ok(registry) => registry,
        Err(error) => {
            return CaseReplay {
                verdict: Err(error),
                authenticated: false,
                key_ids: BTreeSet::new(),
                failed_documents: BTreeSet::new(),
            }
        }
    };

    let mut verdict = Ok(());
    if let Some(consumer) = case.get("consumer_registry") {
        let verified_head = consumer["verified_head"].as_u64().unwrap();
        let held =
            Registry::from_state_tuples(anchor, verified_head, &key_tuples(&consumer["entries"]))
                .expect("the Consumer's own registry authenticates from the Anchor");
        verdict = check_catch_up(&held, verified_head, &offered);
    }

    let at_head = walk(&offered, history, epoch_number, head);
    let mut failed_documents = BTreeSet::new();
    for document in DOCUMENTS {
        if let Err(error) = unsealed::verify(document, &case[document.inner_key()], &at_head, head)
        {
            failed_documents.insert(document.inner_key().to_string());
            if verdict.is_ok() {
                verdict = Err(error);
            }
        }
    }

    CaseReplay {
        verdict,
        authenticated: true,
        key_ids: key_ids(&at_head.valid_at(head)),
        failed_documents,
    }
}

#[test]
fn each_epoch_of_the_log_leaves_the_aggregator_key_tuples_the_vector_records() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let states = replay_history(history, &anchor);
    for (epoch, registry) in history["epochs"].as_array().unwrap().iter().zip(&states) {
        let height = epoch["epoch_number"].as_u64().unwrap();
        assert!(epoch["applied"].as_bool().unwrap(), "epoch {height}");
        assert_eq!(
            tuple_set(registry),
            stated_tuples(&epoch["expected_state"]),
            "epoch {height}: {}",
            epoch["why"]
        );
    }
    for stated in history["valid_at"].as_array().unwrap() {
        let height = stated["height"].as_i64().unwrap();
        let expected = stated_strings(&stated["key_ids"]);
        let valid = match u64::try_from(height) {
            Ok(height) => key_ids(&states[height as usize].valid_at(height)),
            Err(_) => key_ids(&states[0].key_act_authenticators(0)),
        };
        assert_eq!(valid, expected, "the set valid at height {height}");
    }
    assert_eq!(
        states.len() as u64 - 1,
        history["verified_head"].as_u64().unwrap()
    );
}

#[test]
fn every_snapshot_is_accepted_or_rejected_as_wist3_e04_with_the_key_set_the_vector_records() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let mut outcomes = BTreeSet::new();
    let mut authenticated_rejections = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let replayed = replay_case(case, history, &anchor);
        let outcome = match &replayed.verdict {
            Ok(()) => "accept".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(
            case["expected"].as_str().unwrap(),
            outcome,
            "{name}: {}",
            case["why"]
        );
        outcomes.insert(outcome);
        if replayed.verdict.is_ok() {
            assert_eq!(
                replayed.key_ids,
                stated_strings(&case["key_ids_at_adopted_head"]),
                "{name}: the key set at the adopted head"
            );
        } else if replayed.authenticated {
            authenticated_rejections += 1;
        }
        assert_eq!(
            state_digest(&case["state"]["state"]["entries"]),
            case["state_digest"].as_str().unwrap(),
            "{name}: the state_digest over this state file's own tuples"
        );
    }
    assert_eq!(
        outcomes,
        ["accept".to_string(), "WIST3-E04".to_string()]
            .into_iter()
            .collect()
    );
    assert!(
        authenticated_rejections >= 1,
        "no Snapshot whose tuples authenticate was rejected by a later step"
    );
}

#[test]
fn the_documents_that_fail_are_the_ones_the_vector_records_as_unverifiable_at_the_adopted_head() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let mut failed = BTreeSet::new();
    let mut above_their_epoch = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let replayed = replay_case(case, history, &anchor);
        if !replayed.authenticated {
            continue;
        }
        let stated = stated_strings(&case["violations"]["unsealed_documents"]);
        assert_eq!(
            replayed.failed_documents, stated,
            "{name}: the documents that do not verify at the adopted head"
        );
        failed.extend(replayed.failed_documents);
        if case["expected"] == "accept"
            && case["adopted_head"].as_u64() > case["epoch_number"].as_u64()
        {
            above_their_epoch += 1;
        }
    }
    assert_eq!(
        failed,
        [
            "index".to_string(),
            "manifest".to_string(),
            "state".to_string()
        ]
        .into_iter()
        .collect(),
        "no case rejects each document in turn"
    );
    assert!(
        above_their_epoch >= 1,
        "no accepted Snapshot is read at a head above its own Epoch"
    );
}

#[test]
fn a_signature_failing_under_the_key_its_tuple_names_verifies_at_no_height() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let mut early = 0;
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let entries = key_tuples(&case["state"]["state"]["entries"]);
        let epoch_number = case["epoch_number"].as_u64().unwrap();
        let Ok(offered) = Registry::from_state_tuples(&anchor, epoch_number, &entries) else {
            continue;
        };
        for document in DOCUMENTS {
            let envelope = &case[document.inner_key()];
            if unsealed::verifies_at_no_height(document, envelope, &offered) {
                early += 1;
                assert_eq!(
                    case["expected"].as_str().unwrap(),
                    "WIST3-E04",
                    "{name}: a signature verifying at no height did not reject the Snapshot"
                );
                assert!(stated_strings(&case["violations"]["unsealed_documents"])
                    .contains(document.inner_key()));
            }
        }
    }
    assert!(
        early >= 3,
        "no document whose signature fails under the key its tuple names was exercised"
    );
}

#[test]
fn a_snapshot_that_verifies_against_its_own_tuples_is_rejected_by_the_chain_to_the_anchor() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let mut self_consistent = 0;
    for case in vector["cases"].as_array().unwrap() {
        if !case["self_consistent"].as_bool().unwrap_or(false) {
            continue;
        }
        self_consistent += 1;
        let name = case["name"].as_str().unwrap();
        let entries = key_tuples(&case["state"]["state"]["entries"]);
        let epoch_number = case["epoch_number"].as_u64().unwrap();

        let valid: Vec<AggregatorKey> = entries
            .iter()
            .filter(|entry| {
                entry.added_height <= epoch_number
                    && entry
                        .removed_height
                        .is_none_or(|removed| removed > epoch_number)
            })
            .map(|entry| AggregatorKey {
                key_id: entry.key_id.clone(),
                public_key: PublicKey::from_b64u(&entry.public_key).unwrap(),
            })
            .collect();
        let note = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
        checkpoint::verify(&note, &anchor.log_id, &valid, &[])
            .unwrap_or_else(|e| panic!("{name}: the Checkpoint verifies under the tuples: {e}"));
        for document in DOCUMENTS {
            let envelope = &case[document.inner_key()];
            let signer = envelope["sig"]["key_id"].as_str().unwrap();
            let key = valid
                .iter()
                .find(|key| key.key_id == signer)
                .unwrap_or_else(|| panic!("{name}: {document} names no key the tuples hold valid"));
            wist_core::envelope::verify_envelope(envelope, document.inner_key(), &key.public_key)
                .unwrap_or_else(|e| panic!("{name}: {document} verifies under the tuples: {e}"));
        }

        let error = Registry::from_state_tuples(&anchor, epoch_number, &entries)
            .err()
            .unwrap_or_else(|| panic!("{name}: the forged tuples authenticated from the Anchor"));
        assert_eq!(error.code(), Some("WIST3-E04"), "{name}");
    }
    assert!(
        self_consistent >= 3,
        "the forgeries that verify against themselves were not exercised"
    );
}

#[test]
fn the_catch_up_clauses_reject_tuples_that_disagree_with_the_registry_the_consumer_holds() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let mut held_cases = 0;
    for case in vector["cases"].as_array().unwrap() {
        let Some(consumer) = case.get("consumer_registry") else {
            continue;
        };
        held_cases += 1;
        let name = case["name"].as_str().unwrap();
        let verified_head = consumer["verified_head"].as_u64().unwrap();
        let held =
            Registry::from_state_tuples(&anchor, verified_head, &key_tuples(&consumer["entries"]))
                .expect("the Consumer's own registry authenticates from the Anchor");
        let offered = Registry::from_state_tuples(
            &anchor,
            case["epoch_number"].as_u64().unwrap(),
            &key_tuples(&case["state"]["state"]["entries"]),
        )
        .expect("the catch-up cases carry tuples that authenticate");
        let stated: BTreeSet<String> = case["violations"]["catch_up"]
            .as_array()
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .map(|conflict| conflict["key_id"].as_str().unwrap().to_string())
            .collect();
        match check_catch_up(&held, verified_head, &offered) {
            Ok(()) => assert!(stated.is_empty(), "{name}: {stated:?} went unreported"),
            Err(error) => {
                assert_eq!(error.code(), Some("WIST3-E04"), "{name}");
                let key_id = match &error {
                    Error::KeyTupleCatchUp { key_id } => key_id.clone(),
                    other => panic!("{name}: {other} is not a catch-up disagreement"),
                };
                assert!(
                    stated.contains(&key_id),
                    "{name}: {key_id} is not a key the vector records as disagreeing"
                );
            }
        }
    }
    assert!(
        held_cases >= 4,
        "the catch-up clauses were not exercised against a Consumer's own registry"
    );
}

#[test]
fn a_mirror_list_that_does_not_verify_at_the_adopted_head_is_no_error() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let states = replay_history(history, &anchor);
    let mut verdicts = BTreeSet::new();
    let mut without_a_head = 0;
    for case in vector["mirror_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(case["error"].is_null(), "{name}: §5 gives it no error code");
        let authenticated = match case["adopted_head"].as_u64() {
            None => {
                without_a_head += 1;
                false
            }
            Some(head) => unsealed::verify(
                Document::MirrorList,
                &case["mirrors"],
                &states[head as usize],
                head,
            )
            .is_ok(),
        };
        assert_eq!(
            authenticated,
            case["authenticated"].as_bool().unwrap(),
            "{name}: {}",
            case["why"]
        );
        verdicts.insert(authenticated);
    }
    assert_eq!(verdicts, [false, true].into_iter().collect());
    assert_eq!(without_a_head, 1);
}

#[test]
fn the_removal_a_replaying_consumer_rebuilds_is_the_one_at_the_lower_entry_index() {
    let vector = vector();
    let history = &vector["history"];
    let anchor = anchor(history);
    let tie = &vector["removal_tie_break"];
    let height = tie["epoch_number"].as_u64().unwrap();
    let key_id = tie["key_id"].as_str().unwrap();
    let states = replay_history(history, &anchor);

    let epoch = &history["epochs"].as_array().unwrap()[height as usize];
    let removals: Vec<usize> = epoch["entries"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            entry["body"]["update"]["action"] == "aggregator_key_remove"
                && entry["body"]["update"]["details"]["key_id"] == key_id
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        removals.len(),
        2,
        "the Epoch accepts two removals of the key"
    );
    let accepted = tie["accepted_entry_index"].as_u64().unwrap() as usize;
    assert_eq!(accepted, removals[0]);

    let record = states[height as usize].record(key_id).unwrap();
    assert_eq!(record.removed_height, Some(height));
    assert_eq!(
        record.removing_act.as_ref(),
        Some(&epoch["entries"][accepted]["body"]),
        "the tuple carries the removal at the lower Entry index"
    );

    let updates = &accepted_updates(history, &anchor)[height as usize];
    assert_eq!(
        updates.entries().len(),
        6,
        "every key act through the Epoch is accepted"
    );
    let rebuilt: Vec<Value> = states[height as usize]
        .entries()
        .into_iter()
        .map(StateEntry::AggregatorKey)
        .chain(
            updates
                .entries()
                .into_iter()
                .map(StateEntry::RegistryUpdate),
        )
        .map(|entry| serde_json::to_value(entry).unwrap())
        .collect();
    assert_eq!(
        wist_core::snapshot::state_digest(&rebuilt).unwrap(),
        tie["accepted_state_digest"].as_str().unwrap()
    );
    assert_ne!(
        tie["accepted_state_digest"], tie["alternate_state_digest"],
        "the two removals leave one digest, so the rebuild decides nothing"
    );

    let case = |name: &Value| {
        vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == *name)
            .unwrap()
            .clone()
    };
    let accepted_case = case(&tie["accepted_case"]);
    let alternate_case = case(&tie["alternate_case"]);
    for case in [&accepted_case, &alternate_case] {
        assert_eq!(
            case["expected"], "accept",
            "§7's rules read both tuples alike"
        );
        assert!(replay_case(case, history, &anchor).verdict.is_ok());
    }
    assert_eq!(
        accepted_case["state_digest"].as_str().unwrap(),
        tie["accepted_state_digest"].as_str().unwrap()
    );
    assert_eq!(
        alternate_case["state_digest"].as_str().unwrap(),
        tie["alternate_state_digest"].as_str().unwrap()
    );
}
