use serde_json::{json, Value};
use wist_core::collection::Limits;
use wist_core::declaration::{evaluate, inner_hash, publisher_of, resolve_signer, Decision};
use wist_core::declarations::Declarations;

fn kids(keys: &[wist_core::objects::PublisherKey]) -> Value {
    json!(keys.iter().map(|key| key.kid.as_str()).collect::<Vec<_>>())
}

#[test]
fn signed_recovery_settlement() {
    let vector = super::read_json("vectors/wist1/recovery-settlement.json");
    let days = vector["recovery_window_days"].as_i64().unwrap();
    let activation = vector["declaration_activation_epochs"].as_i64().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let epochs = case["epochs"].as_array().unwrap();
        let mut projections = vec![&case["initial_declaration"], &case["recovery_declaration"]];
        projections.extend(case["window_declarations"].as_array().unwrap());
        for (index, projection) in projections.iter().enumerate() {
            let envelope = &projection["envelope"];
            let publisher = publisher_of(envelope).unwrap();
            assert_eq!(inner_hash(envelope).unwrap(), projection["label"], "{name}");
            assert_eq!(
                envelope["publisher"]["prev_declaration"], projection["predecessor"],
                "{name}"
            );
            assert_eq!(kids(&publisher.keys), projection["keys"], "{name}");
            assert_eq!(
                kids(publisher.recovery_keys.as_deref().unwrap_or(&[])),
                projection["recovery_keys"],
                "{name}"
            );
            let previous = projections
                .iter()
                .find(|other| other["label"] == projection["predecessor"])
                .map(|other| publisher_of(&other["envelope"]).unwrap());
            let signer = resolve_signer(envelope, &publisher, previous.as_ref()).unwrap();
            assert_eq!(signer.kid, projection["signer"], "{name}");
            assert_eq!(
                epochs[index]["entries"],
                json!([{"type": "publisher_declaration", "body": envelope}]),
                "{name}"
            );
        }
        assert_eq!(
            case["pre_recovery_keys"], case["initial_declaration"]["keys"],
            "{name}"
        );
        assert_eq!(
            evaluate(
                &case["initial_declaration"]["envelope"],
                &case["recovery_declaration"]["envelope"],
                &Limits::suite(),
            ),
            Ok(Decision::Recovery),
            "{name}"
        );
        let mut state = Declarations::default();
        for epoch in epochs {
            let checkpoint =
                wist_core::checkpoint::Checkpoint::parse(epoch["checkpoint"].as_str().unwrap())
                    .unwrap();
            state
                .apply_epoch(
                    checkpoint.epoch_number(),
                    &checkpoint.root_token(),
                    checkpoint.sealed_at(),
                    days,
                    activation,
                    &Limits::suite(),
                    epoch["entries"].as_array().unwrap(),
                )
                .unwrap();
        }
        let current = state.domains()["example.com"].current();
        assert_eq!(
            current.hash(),
            case["expected"]["effective_declaration"],
            "{name}"
        );
        assert_eq!(
            kids(&publisher_of(current.envelope()).unwrap().keys),
            case["expected"]["effective_keys"],
            "{name}"
        );
        assert_eq!(state.head().unwrap().1, case["pinned_head"], "{name}");
    }
}

struct Admission {
    current: Value,
    floor: u64,
    head: Option<Value>,
    end_s: i128,
    retained: Vec<String>,
    removed: Vec<(String, Decision)>,
}

impl Admission {
    fn settle_at(&mut self, instant_s: i128) {
        if instant_s >= self.end_s {
            if let Some(head) = self.head.take() {
                self.current = head;
            }
        }
    }

    fn admit(&mut self, label: &str, envelope: &Value) -> Result<Decision, &'static str> {
        let decision = wist_core::declaration::evaluate_with_heads(
            &self.current,
            self.head.as_ref(),
            None,
            self.floor,
            envelope,
            &Limits::suite(),
        )
        .map_err(|(code, _)| code)?;
        if decision == Decision::Unchanged {
            return Ok(decision);
        }
        if let Some(head) = &self.head {
            let names_head = envelope["publisher"]["prev_declaration"] == inner_hash(head).unwrap();
            if names_head && matches!(decision, Decision::Ordinary | Decision::Recovery) {
                self.head = Some(envelope.clone());
                self.retained.push(label.to_string());
            } else {
                self.removed.push((label.to_string(), decision));
            }
        } else {
            assert_ne!(decision, Decision::Recovery, "{label}");
        }
        self.current = envelope.clone();
        self.floor = envelope["publisher"]["seq"].as_u64().unwrap();
        Ok(decision)
    }
}

fn outcome(decision: Decision) -> &'static str {
    match decision {
        Decision::Ordinary => "ordinary_rotation",
        Decision::Recovery => "recovery_rotation",
        Decision::FreshIdentity => "fresh_identity",
        Decision::Unchanged => "idempotent",
    }
}

fn apply_epoch(state: &mut Declarations, epoch: &Value) -> (u64, String) {
    let checkpoint =
        wist_core::checkpoint::Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
    state
        .apply_epoch(
            checkpoint.epoch_number(),
            &checkpoint.root_token(),
            checkpoint.sealed_at(),
            7,
            0,
            &Limits::suite(),
            epoch["entries"].as_array().unwrap(),
        )
        .unwrap();
    (
        checkpoint.epoch_number(),
        checkpoint.sealed_at().to_string(),
    )
}

#[test]
fn admission_settlement_removes_unsealed_competitors_and_keeps_chain_followers() {
    let vector = super::read_json("vectors/wist1/recovery-admission.json");
    assert_eq!(vector["recovery_window_days"], 7);
    assert_eq!(vector["declaration_activation_epochs"], 0);
    let record_seal_epochs = wist_core::parameters::spec("record_seal_epochs")
        .and_then(|parameter| parameter.default)
        .unwrap() as u64;
    let declarations = vector["declarations"].as_object().unwrap();
    let labels: std::collections::BTreeMap<String, &str> = declarations
        .iter()
        .map(|(label, envelope)| (inner_hash(envelope).unwrap(), label.as_str()))
        .collect();
    let label = |envelope: &Value| labels[&inner_hash(envelope).unwrap()].to_string();
    let entry_labels = |epoch: &Value| -> Vec<String> {
        epoch["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| label(&entry["body"]))
            .collect()
    };
    let deadline_s = i128::from(
        wist_core::timestamp::log_seconds(vector["deadline"].as_str().unwrap()).unwrap(),
    );
    let mut prefix = Declarations::default();
    let mut sealed_at = Vec::new();
    for epoch in vector["epochs"].as_array().unwrap() {
        sealed_at.push(apply_epoch(&mut prefix, epoch));
    }
    assert_eq!(prefix.head().unwrap().1, vector["pinned_head"]);
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut log = prefix.clone();
        let mut sealed_at = sealed_at.clone();
        sealed_at.push(apply_epoch(&mut log, &case["last_inside_epoch"]));
        assert_eq!(log.head().unwrap().1, case["last_inside_pin"], "{name}");
        let domain = &log.domains()["example.com"];
        let window = domain.window().unwrap();
        assert_eq!(window.end_s(), deadline_s, "{name}");
        let queue_source = label(window.head().envelope());
        let mut admission = Admission {
            current: domain.current().envelope().clone(),
            floor: domain.highest_accepted_seq(),
            head: Some(window.head().envelope().clone()),
            end_s: window.end_s(),
            retained: Vec::new(),
            removed: Vec::new(),
        };
        let admitted_at = case["admitted_at"].as_str().unwrap();
        let admitted_s = i128::from(wist_core::timestamp::log_seconds(admitted_at).unwrap());
        for admitted in case["admitted"].as_array().unwrap() {
            let admitted = admitted.as_str().unwrap();
            admission.settle_at(admitted_s);
            admission
                .admit(admitted, &declarations[admitted])
                .unwrap_or_else(|code| panic!("{name}: {admitted} {code}"));
        }
        admission.settle_at(deadline_s);
        assert_eq!(
            json!({
                "current": label(&admission.current),
                "floor": admission.floor,
                "queue_source": queue_source,
                "retained": admission.retained,
                "removed": admission.removed.iter().map(|(label, _)| label).collect::<Vec<_>>(),
            }),
            case["expected_settlement"],
            "{name}"
        );
        let deadline_epoch = &case["deadline_epoch"];
        let deadline_checkpoint = wist_core::checkpoint::Checkpoint::parse(
            deadline_epoch["checkpoint"].as_str().unwrap(),
        )
        .unwrap();
        let deadline_height = deadline_checkpoint.epoch_number();
        sealed_at.push((deadline_height, deadline_checkpoint.sealed_at().to_string()));
        let first_after_discovery = sealed_at
            .iter()
            .find(|(_, at)| wist_core::timestamp::log_seconds(at).unwrap() > admitted_s as i64)
            .map(|(height, _)| *height)
            .unwrap();
        let violation = admission.removed.iter().any(|(_, decision)| {
            *decision == Decision::Recovery
                && first_after_discovery + record_seal_epochs < deadline_height
        });
        assert_eq!(
            violation, case["removed_recovery_sealing_violation"],
            "{name}"
        );
        let mut accepted = admission.retained.clone();
        for candidate in case["at_deadline"].as_array().unwrap() {
            let candidate_label = candidate["declaration"].as_str().unwrap();
            let result = admission.admit(candidate_label, &declarations[candidate_label]);
            assert_eq!(
                result.map_or_else(|code| code, outcome),
                candidate["expected"],
                "{name}: {candidate_label}"
            );
            if result.is_ok() {
                accepted.push(candidate_label.to_string());
            }
        }
        admission.settle_at(deadline_s);
        assert_eq!(
            json!({"current": label(&admission.current), "floor": admission.floor}),
            case["expected_after_repeat"],
            "{name}"
        );
        let mut revival = log.clone();
        apply_epoch(&mut log, deadline_epoch);
        assert_eq!(log.head().unwrap().1, case["deadline_pin"], "{name}");
        assert!(
            entry_labels(deadline_epoch)
                .iter()
                .all(|sealed| accepted.contains(sealed)),
            "{name}"
        );
        let domain = &log.domains()["example.com"];
        assert_eq!(
            json!({
                "current": label(domain.current().envelope()),
                "floor": domain.highest_accepted_seq(),
                "window_end": domain.window().map(|window| {
                    wist_core::timestamp::instant(i64::try_from(window.end_s()).unwrap()).unwrap()
                }),
                "reset_height": domain.reset().map(|position| position.epoch_number),
            }),
            case["expected_log"],
            "{name}"
        );
        if let Some(forbidden) = case.get("forbidden_revival") {
            apply_epoch(&mut revival, &forbidden["epoch"]);
            assert_eq!(revival.head().unwrap().1, forbidden["pin"], "{name}");
            let domain = &revival.domains()["example.com"];
            assert_eq!(
                label(domain.current().envelope()),
                forbidden["log_current"],
                "{name}"
            );
            assert_eq!(
                json!(domain.reset().map(|position| position.epoch_number)),
                forbidden["log_reset_height"],
                "{name}"
            );
            let removed: Vec<&String> = admission.removed.iter().map(|(label, _)| label).collect();
            assert!(
                entry_labels(&forbidden["epoch"])
                    .iter()
                    .all(|revived| removed.contains(&revived)),
                "{name}"
            );
        }
    }
}
