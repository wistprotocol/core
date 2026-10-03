use super::read_json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use wist_core::collection::{
    authority_reductions, covers, judge_publication, judge_scope, last_seal_height,
    reduces_authority, Limits,
};
use wist_core::crypto::PublicKey;
use wist_core::declaration::{evaluate, evaluate_initial, publisher_of, validate_fields, Decision};
use wist_core::declarations::Declarations;
use wist_core::envelope::verify_envelope;
use wist_core::narrowing::{Record, Records};
use wist_core::objects::publisher::key_set_fingerprint;
use wist_core::objects::Publisher;

pub fn limits(parameters: &Value) -> Limits {
    let suite = Limits::suite();
    let value = |name: &str, default: u64| {
        parameters
            .get(name)
            .map_or(default as i64, |value| value.as_i64().unwrap())
    };
    Limits::new(
        value("collections_max", suite.collections_max()),
        value("scope_entries_max", suite.scope_entries_max()),
        value("url_cap_bytes", suite.url_cap_bytes()),
    )
    .unwrap()
}

fn validation(envelope: &Value, parameters: &Value) -> String {
    match validate_fields(envelope, Some(&limits(parameters))) {
        Ok(_) => "accepted".into(),
        Err((code, _)) => code.into(),
    }
}

fn assert_validation_cases(file: &str, array: &str) -> usize {
    let vector = read_json(file);
    let cases = vector[array].as_array().unwrap();
    for case in cases {
        assert_eq!(
            validation(&case["envelope"], &case["parameters"]),
            case["expected"],
            "{file} {array}: {}",
            case["name"]
        );
    }
    cases.len()
}

#[test]
fn collection_forms_counts_and_sizes_select_the_documented_outcome() {
    assert_eq!(
        assert_validation_cases("vectors/wist1/collection-fields.json", "cases"),
        65
    );
}

#[test]
fn collection_entries_of_two_collections_never_cover_each_other() {
    assert_eq!(
        assert_validation_cases("vectors/wist1/collection-scope.json", "disjointness_cases"),
        21
    );
}

#[test]
fn a_public_key_appears_once_across_keys_recovery_keys_and_collections() {
    assert_eq!(
        assert_validation_cases("vectors/wist1/collection-keys.json", "uniqueness_cases"),
        6
    );
}

#[test]
fn a_collections_scope_covers_normalized_urls_by_octets_and_port() {
    let vector = read_json("vectors/wist1/collection-scope.json");
    for case in vector["coverage_cases"].as_array().unwrap() {
        let declaration = publisher_of(&case["declaration"]).unwrap();
        assert_eq!(
            covers(
                &declaration,
                case["collection"].as_str().unwrap(),
                case["url"].as_str().unwrap()
            ),
            case["covered"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

fn publication(case: &Value) -> &'static str {
    let declaration = publisher_of(&case["declaration"]).unwrap();
    let envelope = &case["probe"];
    let probe = &envelope["probe"];
    assert_eq!(probe["publisher"], declaration.domain.as_str());
    assert_eq!(envelope["sig"]["alg"], "Ed25519");
    let verifies = |key: &wist_core::objects::PublisherKey| {
        PublicKey::from_b64u(&key.x)
            .is_ok_and(|public| verify_envelope(envelope, "probe", &public).is_ok())
    };
    match judge_publication(
        &declaration,
        probe["collection"].as_str().unwrap(),
        probe["url"].as_str().unwrap(),
        envelope["sig"]["key_id"].as_str().unwrap(),
        probe["instant"].as_str().unwrap(),
        verifies,
    ) {
        Ok(()) => "accepted",
        Err(code) => code,
    }
}

#[test]
fn a_publication_is_bound_to_its_collections_keys_then_judged_by_its_scope() {
    for file in [
        "vectors/wist1/collection-scope.json",
        "vectors/wist1/collection-keys.json",
    ] {
        let vector = read_json(file);
        for case in vector["publication_cases"].as_array().unwrap() {
            assert_eq!(
                publication(case),
                case["expected"],
                "{file}: {}",
                case["name"]
            );
        }
    }
}

fn classification(stored: &Value, fetched: &Value) -> String {
    let result = if stored.is_null() {
        evaluate_initial(fetched, &Limits::suite()).map(|_| "initial")
    } else {
        evaluate(stored, fetched, &Limits::suite()).map(|decision| match decision {
            Decision::Ordinary => "ordinary_rotation",
            Decision::Recovery => "recovery_rotation",
            Decision::FreshIdentity => "fresh_identity",
            Decision::Unchanged => "idempotent",
        })
    };
    result.unwrap_or_else(|(code, _)| code).to_string()
}

#[test]
fn signer_resolution_and_the_rotation_commitment_read_owner_keys_alone() {
    let vector = read_json("vectors/wist1/collection-keys.json");
    for array in ["signer_cases", "commitment_cases"] {
        for case in vector[array].as_array().unwrap() {
            assert_eq!(
                classification(&case["stored"], &case["fetched"]),
                case["expected"],
                "{array}: {}",
                case["name"]
            );
        }
    }
    for case in vector["fingerprint_cases"].as_array().unwrap() {
        let publisher: Publisher = serde_json::from_value(case["publisher"].clone()).unwrap();
        assert_eq!(
            key_set_fingerprint(&publisher.keys),
            case["fingerprint"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn a_declaration_reduces_authority_by_the_five_tests_of_its_predecessor() {
    let vector = read_json("vectors/wist2/declaration-pull.json");
    for case in vector["reduction_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let predecessor = publisher_of(&case["predecessor"]).unwrap();
        let declaration = publisher_of(&case["declaration"]).unwrap();
        assert_eq!(
            case["declaration"]["publisher"]["prev_declaration"],
            wist_core::declaration::inner_hash(&case["predecessor"]).unwrap(),
            "{name}"
        );
        let reductions: Vec<&str> = authority_reductions(&predecessor, &declaration)
            .into_iter()
            .map(|reduction| reduction.as_str())
            .collect();
        assert_eq!(json!(reductions), case["reductions"], "{name}");
        let reduces = reduces_authority(&predecessor, &declaration);
        assert_eq!(reduces, case["reduces_authority"], "{name}");
        let deadline = reduces.then(|| {
            last_seal_height(
                case["last_sealed_at_discovery"].as_u64().unwrap(),
                case["record_seal_epochs"].as_u64().unwrap(),
            )
            .unwrap()
        });
        assert_eq!(json!(deadline), case["last_seal_height"], "{name}");
    }
}

fn record_value(record: &Record) -> Value {
    json!({"url": record.url, "collection": record.collection, "sealed_height": record.sealed_height})
}

fn ordered(mut records: Vec<Value>) -> Vec<Value> {
    records.sort_by(|a, b| {
        (a["url"].as_str(), a["collection"].as_str())
            .cmp(&(b["url"].as_str(), b["collection"].as_str()))
    });
    records
}

fn replay_history(history: &Value, per_epoch: bool) -> Value {
    let name = history["name"].as_str().unwrap();
    let envelopes = history["declarations"].as_object().unwrap();
    let labels: BTreeMap<String, &str> = envelopes
        .iter()
        .map(|(label, envelope)| {
            (
                wist_core::declaration::inner_hash(envelope).unwrap(),
                label.as_str(),
            )
        })
        .collect();
    let label = |hash: &str| labels[hash];
    let mut state = Declarations::default();
    let mut records = Records::default();
    let mut epochs = Vec::new();
    let mut rejected = Value::Null;
    let mut domain = None;
    for epoch in history["epochs"].as_array().unwrap() {
        let parameters = if per_epoch {
            &epoch["parameters"]
        } else {
            &history["parameters"]
        };
        let height = epoch["height"].as_u64().unwrap();
        let mut entries: Vec<Value> = epoch["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|label| {
                let envelope = &envelopes[label.as_str().unwrap()];
                domain.get_or_insert_with(|| {
                    envelope["publisher"]["domain"]
                        .as_str()
                        .unwrap()
                        .to_string()
                });
                json!({"type": "publisher_declaration", "body": envelope})
            })
            .collect();
        wist_core::epoch::sort_entries(&mut entries).unwrap();
        let effects = match state.apply_epoch(
            height,
            &format!("height {height}"),
            epoch["sealed_at"].as_str().unwrap(),
            parameters["recovery_window_days"].as_i64().unwrap_or(7),
            parameters["declaration_activation_epochs"]
                .as_i64()
                .unwrap_or(24),
            &limits(parameters),
            &entries,
        ) {
            Ok(effects) => effects,
            Err(error) => {
                rejected = json!({"height": height, "code": error.code()});
                break;
            }
        };
        let mut transitions = Vec::new();
        for transition in &effects.transitions {
            let removed = if transition.kind.narrows() {
                let publisher = publisher_of(transition.declaration.envelope()).unwrap();
                records
                    .narrow(&transition.domain, &publisher, transition.height)
                    .iter()
                    .map(record_value)
                    .collect()
            } else {
                Vec::new()
            };
            transitions.push(json!({
                "kind": transition.kind.as_str(),
                "declaration": label(transition.declaration.hash()),
                "narrows": transition.kind.narrows(),
                "removed": ordered(removed),
            }));
        }
        let domain = domain.as_deref().unwrap();
        let state_of = &state.domains()[domain];
        let current = publisher_of(state_of.current().envelope()).unwrap();
        let mut sealed = Vec::new();
        let mut refused = Vec::new();
        for record in epoch["records"].as_array().unwrap() {
            assert!(
                state_of.window().is_none(),
                "{name}: records inside a window"
            );
            let url = record["url"].as_str().unwrap();
            let collection = record["collection"].as_str().unwrap();
            match judge_scope(&current, collection, url) {
                Ok(()) => {
                    records.seal(domain, url, collection, height);
                    sealed.push(json!({"url": url, "collection": collection}));
                }
                Err(code) => {
                    refused.push(json!({"url": url, "collection": collection, "code": code}))
                }
            }
        }
        epochs.push(json!({
            "height": height,
            "current_declaration": label(state_of.current().hash()),
            "pending_head": state_of.pending().map(|pending| label(pending.head().hash())),
            "activation_height": state_of.pending().map(|pending| pending.activation_height()),
            "window_end": state_of.window().map(|window| {
                wist_core::timestamp::instant(i64::try_from(window.end_s()).unwrap()).unwrap()
            }),
            "transitions": transitions,
            "records_sealed": ordered(sealed),
            "records_rejected": ordered(refused),
        }));
    }
    let live: Vec<Value> = records.live().map(|record| record_value(&record)).collect();
    let mut result = json!({"epochs": epochs, "live_records": ordered(live)});
    if per_epoch {
        result["rejected"] = rejected;
    } else {
        assert!(rejected.is_null(), "{name}: {rejected}");
    }
    result
}

#[test]
fn narrowing_removes_the_records_a_declaration_taking_effect_does_not_keep() {
    let vector = read_json("vectors/wist1/collection-narrowing.json");
    for (array, per_epoch) in [("histories", false), ("parameter_histories", true)] {
        for history in vector[array].as_array().unwrap() {
            let mut replayed = replay_history(history, per_epoch);
            if history["expected"].get("live_records").is_none() {
                replayed.as_object_mut().unwrap().remove("live_records");
            }
            assert_eq!(
                replayed, history["expected"],
                "{array}: {}",
                history["name"]
            );
        }
    }
}
