//! WIST-1 §5.1/§5.2: the key directory, its windows, the rotation
//! commitment and the activation delay, replayed from
//! `vectors/wist1/key-directory.json`.
use super::read_json;
use serde_json::{json, Value};
use wist_core::declaration::{evaluate, evaluate_initial, verify_signed, Decision};
use wist_core::declarations::{Declarations, Position};
use wist_core::objects::publisher::{key_set_fingerprint, thumbprint};
use wist_core::objects::PublisherKey;

fn vector() -> Value {
    read_json("vectors/wist1/key-directory.json")
}

fn keys_of(envelope: &Value) -> Vec<PublisherKey> {
    serde_json::from_value(envelope["publisher"]["keys"].clone()).unwrap()
}

fn timestamp(at: i128) -> String {
    wist_core::timestamp::instant(i64::try_from(at).unwrap()).unwrap()
}

fn summary(domain: &wist_core::declarations::Domain) -> Value {
    json!({
        "current_declaration": domain.current().hash(),
        "pending_head": domain.pending().map(|pending| pending.head().hash()),
        "activation_height": domain.pending().map(|pending| pending.activation_height()),
        "highest_accepted_seq": domain.highest_accepted_seq(),
        "reset_height": domain.reset().map(|position| position.block_number),
        "window_end": domain.window().map(|window| timestamp(window.end_s())),
    })
}

fn declaration_outcome(stored: Option<&Value>, fetched: &Value) -> String {
    let result = match stored {
        None => evaluate_initial(fetched).map(|_| "initial"),
        Some(stored) => evaluate(stored, fetched).map(|decision| match decision {
            Decision::Ordinary => "ordinary_rotation",
            Decision::Recovery => "recovery_rotation",
            Decision::FreshIdentity => "fresh_identity",
            Decision::Unchanged => "idempotent",
        }),
    };
    result.unwrap_or_else(|(code, _)| code).to_string()
}

fn delta_check(declaration: &Value, envelope: &Value) -> String {
    let keys = keys_of(declaration);
    let observed_at = envelope["delta"]["observed_at"].as_str().unwrap();
    match verify_signed(
        &keys.iter().collect::<Vec<_>>(),
        envelope,
        "delta",
        Some(observed_at),
    ) {
        Ok(()) => "accepted".to_string(),
        Err(code) => code.to_string(),
    }
}

/// Replays one history and returns the state after each of its Blocks.
fn replay(vector: &Value, history: &Value) -> Vec<Declarations> {
    let days = vector["recovery_window_days"].as_i64().unwrap();
    let activation = history["declaration_activation_blocks"]
        .as_i64()
        .unwrap_or_else(|| vector["declaration_activation_blocks"].as_i64().unwrap());
    let mut state = Declarations::default();
    let mut prefix = Vec::new();
    for block in history["blocks"].as_array().unwrap() {
        let header = &block["header"];
        state
            .apply_block(
                header["block_number"].as_u64().unwrap(),
                header["prev_block_hash"].as_str().unwrap(),
                &wist_core::block::block_hash(header).unwrap(),
                header["sealed_at"].as_str().unwrap(),
                days,
                activation,
                block["entries"].as_array().unwrap(),
            )
            .unwrap();
        prefix.push(state.clone());
    }
    prefix
}

#[test]
fn thumbprints_and_fingerprints_match_their_known_answers() {
    let vector = vector();
    for row in vector["thumbprints"].as_array().unwrap() {
        assert_eq!(
            thumbprint(row["x"].as_str().unwrap()),
            row["kid"].as_str().unwrap(),
            "{}",
            row["name"]
        );
    }
    for row in vector["fingerprints"].as_array().unwrap() {
        let keys: Vec<PublisherKey> = row["kids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kid| PublisherKey {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: String::new(),
                kid: kid.as_str().unwrap().to_string(),
                nbf: 0,
                exp: None,
            })
            .collect();
        assert_eq!(
            key_set_fingerprint(&keys),
            row["fingerprint"].as_str().unwrap(),
            "{}",
            row["name"]
        );
    }
    let record = &vector["dns_record"];
    let example = read_json("examples/publisher.json");
    assert_eq!(
        record["txt"].as_str().unwrap(),
        format!("v=wist1; keys={}", key_set_fingerprint(&keys_of(&example)))
    );
}

#[test]
fn entry_field_rules_and_key_windows_hold() {
    let vector = vector();
    for case in vector["entry_cases"].as_array().unwrap() {
        assert_eq!(
            declaration_outcome(None, &case["envelope"]),
            case["expected"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
    for case in vector["window_cases"].as_array().unwrap() {
        assert_eq!(
            delta_check(&case["declaration"], &case["envelope"]),
            case["expected"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_rotation_commitment_binds_an_ordinary_rotation() {
    let vector = vector();
    for case in vector["commitment_cases"].as_array().unwrap() {
        assert_eq!(
            declaration_outcome(Some(&case["stored"]), &case["fetched"]),
            case["expected"].as_str().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn histories_activate_reverse_and_resume_as_the_vector_records() {
    let vector = vector();
    let days = vector["recovery_window_days"].as_i64().unwrap();
    for (name, history) in vector["histories"].as_object().unwrap() {
        let prefix = replay(&vector, history);
        for row in history["expected_states"].as_array().unwrap() {
            let height = row["height"].as_u64().unwrap() as usize;
            assert_eq!(
                summary(&prefix[height].domains()["example.com"]),
                row["state"],
                "{name} at height {height}"
            );
        }
        let activation = history["declaration_activation_blocks"]
            .as_i64()
            .unwrap_or_else(|| vector["declaration_activation_blocks"].as_i64().unwrap());
        for case in vector["rejections"].as_array().unwrap() {
            if case["history"] != *name {
                continue;
            }
            let height = case["prefix_height"].as_u64().unwrap() as usize;
            let state = &prefix[height];
            let entries = vec![json!({"type": "publisher_declaration", "body": case["candidate"]})];
            let projection = state.project(
                case["candidate_sealed_at"].as_str().unwrap(),
                days,
                activation,
                &entries,
            );
            match projection {
                Ok(projection) => {
                    let pending = projection.domains()["example.com"].pending();
                    match case["expected"].as_str().unwrap() {
                        "fresh_identity" => assert_eq!(
                            pending.map(|pending| pending.head().envelope()),
                            Some(&case["candidate"]),
                            "{}",
                            case["name"]
                        ),
                        // A re-serve of the pending head installs nothing.
                        "idempotent" => assert_eq!(
                            summary(&projection.domains()["example.com"]),
                            summary(&state.domains()["example.com"]),
                            "{}",
                            case["name"]
                        ),
                        other => panic!("{}: unexpected {other}", case["name"]),
                    }
                }
                Err(error) => assert!(
                    error
                        .to_string()
                        .contains(case["expected"].as_str().unwrap()),
                    "{}: {error}",
                    case["name"]
                ),
            }
        }
        for case in vector["delta_probes"].as_array().unwrap() {
            if case["history"] != *name {
                continue;
            }
            let height = case["prefix_height"].as_u64().unwrap() as usize;
            let current = prefix[height].domains()["example.com"].current().envelope();
            assert_eq!(
                delta_check(current, &case["envelope"]),
                case["expected"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn a_pending_declaration_tuple_restores_the_state_it_records() {
    let vector = vector();
    for row in vector["snapshot_tuples"].as_array().unwrap() {
        let history = &vector["histories"][row["history"].as_str().unwrap()];
        let prefix = replay(&vector, history);
        let height = row["height"].as_u64().unwrap() as usize;
        let declaration = row["declaration"].as_array().unwrap();
        let pending = row["pending_declaration"].as_array();
        let mut adopted = Declarations::default();
        adopted
            .adopt(
                declaration[1].as_str().unwrap(),
                declaration[2].clone(),
                Position {
                    block_number: declaration[3].as_u64().unwrap(),
                    entry_index: 0,
                },
                0,
                declaration[4].as_u64().unwrap(),
                None,
                pending.map(|pending| {
                    (
                        pending[2].clone(),
                        Position {
                            block_number: pending[3].as_u64().unwrap(),
                            entry_index: 0,
                        },
                        0,
                        pending[4].as_u64().unwrap(),
                    )
                }),
            )
            .unwrap();
        let (mut restored, mut replayed) = (
            summary(&adopted.domains()["example.com"]),
            summary(&prefix[height].domains()["example.com"]),
        );
        // A Snapshot records no reset height (WIST-3 §7).
        restored["reset_height"] = Value::Null;
        replayed["reset_height"] = Value::Null;
        assert_eq!(restored, replayed, "{} at height {height}", row["history"]);
    }
}
