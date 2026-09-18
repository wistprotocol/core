use super::{entry_leaf_hashes, hash_list, read_json};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use wist_core::aggregator_keys::{self, Outcome, Registry};
use wist_core::checkpoint::{self, Checkpoint};
use wist_core::crypto::PublicKey;
use wist_core::merkle::{self, LeafHashes};
use wist_core::objects::{AggregatorKeyEntry, GenesisKey, StateEntry};

const BLOCK_CAP_BYTES: u64 = 268_435_456;
const CADENCE_SECONDS: i64 = 3600;

fn vector() -> Value {
    read_json("vectors/wist3/aggregator-keys.json")
}

fn histories() -> Vec<Value> {
    vector()["histories"].as_array().unwrap().clone()
}

fn history_named(name: &str) -> Value {
    histories()
        .into_iter()
        .find(|history| history["name"] == name)
        .unwrap_or_else(|| panic!("the vector carries no history named {name:?}"))
}

fn genesis_registry(history: &Value) -> Registry {
    let log_id = history["log_id"].as_str().unwrap();
    let anchor = &history["anchor"];
    assert_eq!(anchor["anchor"]["log_id"], history["log_id"]);
    let genesis: GenesisKey =
        serde_json::from_value(anchor["anchor"]["genesis_key"].clone()).unwrap();
    let public_key = PublicKey::from_b64u(&genesis.public_key).unwrap();
    wist_core::envelope::verify_envelope(anchor, "anchor", &public_key)
        .expect("the Anchor is self-signed under its own genesis_key");
    Registry::from_genesis(log_id, &genesis).unwrap()
}

fn tuple_set(registry: &Registry) -> BTreeSet<String> {
    registry
        .entries()
        .into_iter()
        .map(|entry| serde_json::to_string(&StateEntry::AggregatorKey(entry)).unwrap())
        .collect()
}

fn stated_tuples(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|tuple| serde_json::to_string(tuple).unwrap())
        .collect()
}

fn key_ids(keys: &[checkpoint::AggregatorKey]) -> BTreeSet<String> {
    keys.iter().map(|key| key.key_id.clone()).collect()
}

fn stated_key_ids(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|key_id| key_id.as_str().unwrap().to_string())
        .collect()
}

struct BlockReplay {
    block_number: u64,
    codes: Vec<Option<String>>,
    valid_at: BTreeSet<String>,
    tuples: BTreeSet<String>,
    applied: bool,
    checkpoint: Option<Checkpoint>,
    sealed: Registry,
}

struct Replay {
    log_id: String,
    blocks: Vec<BlockReplay>,
    adopted: Registry,
    head: Option<u64>,
}

fn replay(history: &Value) -> Replay {
    let log_id = history["log_id"].as_str().unwrap().to_string();
    let mut adopted = genesis_registry(history);
    let mut blocks = Vec::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut head: Option<u64> = None;
    let mut verified: Option<Checkpoint> = None;

    for block in history["blocks"].as_array().unwrap() {
        let where_ = format!("{} block {}", history["name"], block["block_number"]);
        let height = block["block_number"].as_u64().unwrap();
        let entries = block["entries"].as_array().unwrap();
        let verified_size = verified.as_ref().map_or(0, Checkpoint::tree_size);
        let prior = leaves.clone();
        leaves.extend(entry_leaf_hashes(&block["entries"]));
        assert_eq!(leaves, hash_list(&block["leaf_hashes"]), "{where_}");
        assert_eq!(
            block["tree_size"].as_u64().unwrap(),
            leaves.len() as u64,
            "{where_}"
        );

        let mut sealed = adopted.clone();
        let outcomes = sealed.apply_block(height, entries.iter().map(|entry| &entry["body"]));
        let authenticators = sealed.valid_at(height);
        let codes: Vec<Option<String>> = outcomes
            .iter()
            .zip(entries)
            .map(|(outcome, entry)| match outcome {
                Outcome::NotKeyAct => {
                    aggregator_keys::authenticate(&entry["body"], &authenticators)
                        .err()
                        .map(|_| "WIST4-E11".to_string())
                }
                other => other.code().map(str::to_string),
            })
            .collect();

        let checkpoint = block["checkpoint"]
            .as_str()
            .map(|note| Checkpoint::parse(note).unwrap());
        if let Some(checkpoint) = &checkpoint {
            checkpoint::verify(checkpoint, &log_id, &sealed.valid_at(height), &[])
                .unwrap_or_else(|e| panic!("{where_}: the published Checkpoint verifies: {e}"));
            assert_eq!(checkpoint.block_number(), height, "{where_}");
            assert_eq!(checkpoint.sealed_at(), block["sealed_at"], "{where_}");
            let summary = wist_core::block::verify_block(
                verified_size,
                checkpoint,
                entries,
                &LeafHashes(&prior),
                BLOCK_CAP_BYTES,
            )
            .unwrap_or_else(|e| panic!("{where_}: the Block fills the tree it states: {e}"));
            assert_eq!(summary.leaf_hashes, leaves[prior.len()..], "{where_}");
            assert_eq!(*checkpoint.root(), merkle::merkle_root(&leaves), "{where_}");
            checkpoint::check_sequence(verified.as_ref(), checkpoint, CADENCE_SECONDS)
                .unwrap_or_else(|e| panic!("{where_}: {e}"));
            if let Some(previous) = &verified {
                let path = merkle::consistency_proof(
                    previous.tree_size(),
                    checkpoint.tree_size(),
                    &leaves,
                )
                .unwrap();
                checkpoint::check_consistency(previous, checkpoint, &path)
                    .unwrap_or_else(|e| panic!("{where_}: {e}"));
            }
            adopted = sealed.clone();
            head = Some(height);
            verified = Some(checkpoint.clone());
        }

        blocks.push(BlockReplay {
            block_number: height,
            codes,
            valid_at: key_ids(&sealed.valid_at(height)),
            tuples: tuple_set(&adopted),
            applied: checkpoint.is_some(),
            checkpoint,
            sealed,
        });
    }

    Replay {
        log_id,
        blocks,
        adopted,
        head,
    }
}

#[test]
fn every_key_act_is_dispositioned_as_its_authentication_height_and_the_admitted_set_require() {
    let mut seen: BTreeSet<Option<String>> = BTreeSet::new();
    let mut ties = 0;
    for history in histories() {
        let replayed = replay(&history);
        for (block, replayed) in history["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&replayed.blocks)
        {
            let where_ = format!("{} block {}", history["name"], replayed.block_number);
            let acts = block["acts"].as_array().unwrap();
            assert_eq!(acts.len(), replayed.codes.len(), "{where_}");
            for (index, (act, code)) in acts.iter().zip(&replayed.codes).enumerate() {
                let update = &block["entries"][index]["body"]["update"];
                assert_eq!(
                    act["entry_index"].as_u64().unwrap() as usize,
                    index,
                    "{where_}"
                );
                assert_eq!(act["action"], update["action"], "{where_}");
                assert_eq!(act["subject"], update["subject"], "{where_}");
                assert_eq!(
                    act["signer_key_id"], block["entries"][index]["body"]["sig"]["key_id"],
                    "{where_}"
                );
                assert_eq!(
                    code.as_deref(),
                    act["code"].as_str(),
                    "{where_} act {index}: {}",
                    act["why"]
                );
                seen.insert(code.clone());
            }
            for tie in block["tie_breaks"].as_array().unwrap_or(&Vec::new()) {
                ties += 1;
                let accepted = tie["accepted_entry_index"].as_u64().unwrap() as usize;
                let failed = tie["failed_entry_index"].as_u64().unwrap() as usize;
                assert!(accepted < failed, "{where_}");
                assert_eq!(
                    replayed.codes[accepted], None,
                    "{where_}: {}",
                    tie["reason"]
                );
                assert_eq!(
                    replayed.codes[failed].as_deref(),
                    Some(aggregator_keys::KEY_ACT_CONFLICT_CODE),
                    "{where_}: {}",
                    tie["reason"]
                );
            }
        }
    }
    assert_eq!(
        seen,
        [None, Some("WIST4-E04".into()), Some("WIST4-E11".into())]
            .into_iter()
            .collect()
    );
    assert!(ties >= 2, "the tie-break cases were not exercised");
}

#[test]
fn each_block_leaves_the_aggregator_key_tuples_the_vector_records() {
    let mut unapplied = 0;
    for history in histories() {
        let replayed = replay(&history);
        for (block, replayed) in history["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&replayed.blocks)
        {
            let where_ = format!("{} block {}", history["name"], replayed.block_number);
            assert_eq!(
                replayed.applied,
                block["applied"].as_bool().unwrap(),
                "{where_}"
            );
            assert_eq!(
                replayed.tuples,
                stated_tuples(&block["expected_state"]),
                "{where_}: {}",
                block["why"]
            );
            if !replayed.applied {
                unapplied += 1;
            }
        }
        assert_eq!(
            replayed.head,
            history["verified_head"].as_u64(),
            "{}: the verified head the replay leaves",
            history["name"]
        );
    }
    assert!(
        unapplied >= 1,
        "no Block the Consumer refuses to apply was exercised"
    );
}

#[test]
fn a_block_no_checkpoint_verifies_leaves_the_head_and_the_key_registry_where_they_were() {
    let history = history_named("keys exhausted");
    let replayed = replay(&history);
    let refused = replayed
        .blocks
        .iter()
        .find(|block| !block.applied)
        .expect("the history carries a Block no Checkpoint verifies");
    let kept = replayed
        .blocks
        .iter()
        .find(|block| block.block_number + 1 == refused.block_number)
        .unwrap();
    assert!(refused.checkpoint.is_none());
    assert!(
        refused.sealed.valid_at(refused.block_number).is_empty(),
        "the Block's accepted removals leave no key valid at its height"
    );
    assert_eq!(refused.tuples, kept.tuples);
    assert_eq!(replayed.head, Some(kept.block_number));
    assert_eq!(tuple_set(&replayed.adopted), kept.tuples);
}

#[test]
fn the_key_set_at_every_height_is_the_one_the_vector_records() {
    for history in histories() {
        let replayed = replay(&history);
        let mut expected: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
        for entry in history["valid_at"].as_array().unwrap() {
            expected.insert(
                entry["height"].as_i64().unwrap(),
                stated_key_ids(&entry["key_ids"]),
            );
        }
        let genesis = history["anchor"]["anchor"]["genesis_key"]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            key_ids(&replayed.adopted.key_act_authenticators(0)),
            expected[&-1],
            "{}: the set valid at height -1",
            history["name"]
        );
        assert_eq!(
            expected[&-1],
            [genesis].into_iter().collect(),
            "{}",
            history["name"]
        );
        for block in &replayed.blocks {
            assert_eq!(
                block.valid_at,
                expected[&(block.block_number as i64)],
                "{} block {}",
                history["name"],
                block.block_number
            );
            if block.block_number > 0 {
                assert_eq!(
                    key_ids(&block.sealed.key_act_authenticators(block.block_number)),
                    expected[&(block.block_number as i64 - 1)],
                    "{} block {}: the set its key acts authenticate under",
                    history["name"],
                    block.block_number
                );
            }
        }
    }
}

#[test]
fn a_checkpoint_candidate_is_judged_under_the_keys_valid_at_its_own_block() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rotations = 0;
    let mut ignored_lines = 0;
    for history in histories() {
        let replayed = replay(&history);
        for (block, sealed) in history["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .zip(&replayed.blocks)
        {
            let where_ = format!("{} block {}", history["name"], sealed.block_number);
            let valid = sealed.sealed.valid_at(sealed.block_number);
            if let Some(checkpoint) = &sealed.checkpoint {
                let verification =
                    checkpoint::verify(checkpoint, &replayed.log_id, &valid, &[]).unwrap();
                if verification.signers.len() > 1 {
                    rotations += 1;
                }
            }
            for case in block["checkpoint_cases"].as_array().unwrap() {
                let name = case["name"].as_str().unwrap();
                let candidate = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
                assert_eq!(candidate.block_number(), sealed.block_number, "{where_}");
                let outcome = match checkpoint::verify(&candidate, &replayed.log_id, &valid, &[]) {
                    Ok(verification) => {
                        assert_eq!(
                            key_ids(&valid)
                                .intersection(&stated_key_ids(&case["signer_key_ids"]))
                                .cloned()
                                .collect::<BTreeSet<_>>(),
                            verification.signers,
                            "{where_}: {name}"
                        );
                        if candidate.signatures().len() > verification.signers.len() {
                            ignored_lines += 1;
                        }
                        "valid".to_string()
                    }
                    Err(error) => error.code().unwrap().to_string(),
                };
                assert_eq!(case["expected"], outcome, "{where_}: {name}");
                seen.insert(outcome);
            }
        }
    }
    assert_eq!(
        seen,
        ["valid".into(), "WIST3-E03".into()].into_iter().collect()
    );
    assert!(
        rotations >= 1,
        "no rotation Checkpoint with two verifying lines was exercised"
    );
    assert!(
        ignored_lines >= 1,
        "no Checkpoint carrying a line from a key not valid at its height was exercised"
    );
}

#[test]
fn a_checkpoint_at_or_below_the_head_is_evidence_only_under_the_keys_valid_at_its_own_height() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for history in histories() {
        let replayed = replay(&history);
        let head = replayed.head.expect("the history has a verified head");
        for case in history["equivocation_cases"]
            .as_array()
            .unwrap_or(&Vec::new())
        {
            let name = case["name"].as_str().unwrap();
            let height = case["block_number"].as_u64().unwrap();
            assert!(height <= head, "{name}");
            let block = replayed
                .blocks
                .iter()
                .find(|block| block.block_number == height)
                .unwrap();
            let offered = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
            let valid = block.sealed.valid_at(height);
            let outcome = match checkpoint::verify(&offered, &replayed.log_id, &valid, &[]) {
                Err(error) => error.code().unwrap().to_string(),
                Ok(_) => match checkpoint::progression(&offered, head, block.checkpoint.as_ref()) {
                    Ok(_) => "valid".to_string(),
                    Err(error) => error.code().unwrap().to_string(),
                },
            };
            assert_eq!(case["expected"], outcome, "{name}: {}", case["why"]);
            seen.insert(outcome);
        }
    }
    assert_eq!(
        seen,
        ["WIST3-E02".into(), "WIST3-E03".into()]
            .into_iter()
            .collect()
    );
}

#[test]
fn a_snapshot_state_that_omits_a_removed_keys_tuple_does_not_restore_the_registry() {
    let mut checked = 0;
    for history in histories() {
        let Some(snapshot) = history.get("snapshot_state") else {
            continue;
        };
        let replayed = replay(&history);
        let head = replayed.head.unwrap();
        assert_eq!(snapshot["block_number"].as_u64(), Some(head));
        let block = replayed
            .blocks
            .iter()
            .find(|block| block.block_number == head)
            .unwrap();
        assert_eq!(
            snapshot["log_position"].as_u64(),
            block.checkpoint.as_ref().map(Checkpoint::tree_size)
        );
        for case in snapshot["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let carried: BTreeSet<String> = case["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|tuple| tuple[0] == "aggregator_key")
                .map(|tuple| serde_json::to_string(tuple).unwrap())
                .collect();
            let complete = carried == block.tuples;
            assert_eq!(
                complete,
                case["verifies"].as_bool().unwrap(),
                "{name}: {}",
                case["why"]
            );
            let entries: Vec<AggregatorKeyEntry> = case["entries"]
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
                .collect();
            let restored = Registry::from_entries(&replayed.log_id, &entries).unwrap();
            assert_eq!(
                tuple_set(&restored) == block.tuples,
                complete,
                "{name}: the resumed registry"
            );
            if !complete {
                let missing: BTreeSet<&String> = block.tuples.difference(&carried).collect();
                assert!(
                    !missing.is_empty() && missing.iter().all(|tuple| !tuple.ends_with(",null]")),
                    "{name}: what the file omits is a removed key's tuple"
                );
            }
            checked += 1;
        }
    }
    assert!(checked >= 3, "the snapshot state cases were not exercised");
}

#[test]
fn the_two_entry_orders_of_one_blocks_add_and_remove_leave_one_registry() {
    let names = vector()["same_registry_histories"].clone();
    let names = names.as_array().unwrap();
    assert_eq!(names.len(), 2);
    let registries: Vec<BTreeSet<String>> = names
        .iter()
        .map(|name| {
            let history = history_named(name.as_str().unwrap());
            tuple_set(&replay(&history).adopted)
        })
        .collect();
    assert_eq!(registries[0], registries[1]);

    let action_order = |name: &str| {
        let history = history_named(name);
        let block = history["blocks"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let actions: Vec<String> = block["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                entry["body"]["update"]["action"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        actions
    };
    let first = action_order(names[0].as_str().unwrap());
    let second = action_order(names[1].as_str().unwrap());
    assert_ne!(
        first.iter().position(|a| a == "aggregator_key_add")
            < first.iter().position(|a| a == "aggregator_key_remove"),
        second.iter().position(|a| a == "aggregator_key_add")
            < second.iter().position(|a| a == "aggregator_key_remove"),
        "both histories place the addition on the same side of the removal"
    );
}
