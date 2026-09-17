use serde_json::Value;
use wist_core::crypto::PublicKey;
use wist_core::envelope::verify_envelope;
use wist_core::objects::PublisherKey;
use wist_core::recovery::{admits_to_queue, settle, WindowDeclaration};

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().into())
        .collect()
}

fn verifies_fixture_delta(delta: &Value, keys: &[PublisherKey]) -> bool {
    keys.iter()
        .find(|key| delta["sig"]["key_id"] == key.kid)
        .filter(|key| key.admits(delta["delta"]["observed_at"].as_str().unwrap()) == Some(true))
        .is_some_and(|key| {
            verify_envelope(delta, "delta", &PublicKey::from_b64u(&key.x).unwrap()).is_ok()
        })
}

fn declaration(value: &Value, previous: Option<&Value>) -> WindowDeclaration {
    let envelope = &value["envelope"];
    let inner = &envelope["publisher"];
    let mut candidates = inner["keys"].as_array().unwrap().clone();
    if let Some(previous) = previous {
        for field in ["keys", "recovery_keys"] {
            candidates.extend(
                previous["envelope"]["publisher"][field]
                    .as_array()
                    .unwrap()
                    .clone(),
            );
        }
    }
    let signer = candidates
        .iter()
        .filter(|key| key["kid"] == envelope["sig"]["key_id"])
        .find(|key| {
            verify_envelope(
                envelope,
                "publisher",
                &PublicKey::from_b64u(key["x"].as_str().unwrap()).unwrap(),
            )
            .is_ok()
        })
        .expect("authenticated Declaration signer")["x"]
        .as_str()
        .unwrap()
        .to_string();
    WindowDeclaration {
        label: value["label"].as_str().unwrap().into(),
        predecessor: inner["prev_declaration"].as_str().map(String::from),
        signer,
        keys: serde_json::from_value(inner["keys"].clone()).unwrap(),
        recovery_keys: serde_json::from_value(inner["recovery_keys"].clone()).unwrap(),
    }
}

#[test]
fn signed_recovery_settlement() {
    let vector = super::read_json("vectors/wist1/recovery-settlement.json");
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let initial = &case["initial_declaration"];
        let recovery = &case["recovery_declaration"];
        let mut projections = vec![initial, recovery];
        projections.extend(case["window_declarations"].as_array().unwrap());
        let declarations: Vec<_> = projections
            .iter()
            .map(|projection| {
                let previous = projections
                    .iter()
                    .find(|p| p["label"] == projection["predecessor"]);
                declaration(projection, previous.copied())
            })
            .collect();
        let mut queued = Vec::new();
        let mut not_queued = Vec::new();
        for served in case["served"].as_array().unwrap() {
            let id = served["delta_id"].as_str().unwrap().to_string();
            let delta = served["envelope"].clone();
            if admits_to_queue(
                &declarations[0].keys,
                &declarations[1].keys,
                &delta,
                verifies_fixture_delta,
            ) {
                queued.push((id, delta));
            } else {
                not_queued.push(id);
            }
        }
        let expected = &case["expected"];
        assert_eq!(
            queued.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>(),
            strings(&expected["queued"]),
            "{name}"
        );
        assert_eq!(not_queued, strings(&expected["not_queued"]), "{name}");
        let result = settle(
            &declarations[1],
            &declarations[2..],
            &queued,
            verifies_fixture_delta,
        );
        assert_eq!(
            result.effective_declaration, expected["effective_declaration"],
            "{name}"
        );
        assert_eq!(
            result.effective_keys,
            strings(&expected["effective_keys"]),
            "{name}"
        );
        assert_eq!(
            result.superseded,
            strings(&expected["superseded"]),
            "{name}"
        );
        assert_eq!(result.eligible, strings(&expected["eligible"]), "{name}");
        assert_eq!(result.rejected, strings(&expected["rejected"]), "{name}");
    }
}

#[test]
fn delta_bindings_control_queue_admission_and_settlement() {
    let vector = super::read_json("vectors/wist1/recovery-settlement.json");
    for case in vector["binding_cases"].as_array().unwrap() {
        let before: Vec<PublisherKey> =
            serde_json::from_value(case["pre_recovery_keys"].clone()).unwrap();
        let opening: Vec<PublisherKey> =
            serde_json::from_value(case["recovery_keys"].clone()).unwrap();
        let final_keys: Vec<PublisherKey> =
            serde_json::from_value(case["settlement_keys"].clone()).unwrap();
        let delta = &case["envelope"];
        if let Some(index) = case["re_serve_of"].as_u64() {
            let earlier = &vector["binding_cases"][index as usize];
            assert_eq!(earlier["envelope"], *delta);
            assert_eq!(earlier["delta_id"], case["delta_id"]);
            assert_eq!(earlier["expected_queued"], true);
            assert_eq!(earlier["expected_eligible"], false);
            assert_eq!(case["expected_eligible"], true);
        }
        let queued = admits_to_queue(&before, &opening, delta, verifies_fixture_delta);
        assert_eq!(queued, case["expected_queued"], "{}", case["name"]);
        let declaration = WindowDeclaration {
            label: "settled".into(),
            predecessor: None,
            signer: String::new(),
            keys: final_keys,
            recovery_keys: Vec::new(),
        };
        let id = case["delta_id"].as_str().unwrap().to_string();
        let queue = if queued {
            vec![(id.clone(), delta.clone())]
        } else {
            Vec::new()
        };
        let result = settle(&declaration, &[], &queue, verifies_fixture_delta);
        assert_eq!(
            result.eligible.contains(&id),
            case["expected_eligible"],
            "{}",
            case["name"]
        );
        assert_eq!(
            result.rejected.contains(&id),
            queued && !case["expected_eligible"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
