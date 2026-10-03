use super::{entry_leaf_hashes, read_json};
use serde_json::{json, Value};
use wist_core::checkpoint::Checkpoint;
use wist_core::collection::Limits;
use wist_core::declaration::Decision;
use wist_core::declarations::{Declarations, Domain, Effects};
use wist_core::merkle;
use wist_core::Error;

#[derive(Clone, Copy)]
struct Params {
    days: i64,
    activation_epochs: i64,
}

fn params(vector: &Value) -> Params {
    Params {
        days: vector["recovery_window_days"].as_i64().unwrap(),
        activation_epochs: vector["declaration_activation_epochs"]
            .as_i64()
            .unwrap_or(24),
    }
}

struct Sealed {
    epoch_number: u64,
    root_token: String,
    sealed_at: String,
    entries: Vec<Value>,
}

fn sealed(epoch: &Value) -> Sealed {
    let checkpoint = Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
    Sealed {
        epoch_number: checkpoint.epoch_number(),
        root_token: checkpoint.root_token(),
        sealed_at: checkpoint.sealed_at().to_string(),
        entries: epoch["entries"].as_array().map_or(Vec::new(), Vec::clone),
    }
}

fn apply(state: &mut Declarations, epoch: &Sealed, params: Params) -> Result<Effects, Error> {
    state.apply_epoch(
        epoch.epoch_number,
        &epoch.root_token,
        &epoch.sealed_at,
        params.days,
        params.activation_epochs,
        &Limits::suite(),
        &epoch.entries,
    )
}

fn windows_opened(effects: &Effects) -> u64 {
    effects
        .installations
        .iter()
        .filter(|i| i.opens_window)
        .count() as u64
}

fn timestamp(at: i128) -> String {
    wist_core::timestamp::instant(i64::try_from(at).unwrap()).unwrap()
}

fn digest(value: &Value) -> String {
    wist_core::delta::delta_id(value).unwrap()
}

fn summary(domain: &Domain, windows: u64) -> Value {
    json!({
        "current_declaration": domain.current().hash(),
        "recovery_head": domain.window().map(|w| w.head().hash()),
        "highest_accepted_seq": domain.highest_accepted_seq(),
        "window_end": domain.window().map(|w| timestamp(w.end_s())),
        "windows_opened": windows,
    })
}

fn outcome(effects: &Effects) -> &'static str {
    effects
        .installations
        .last()
        .map_or("idempotent", |i| match i.decision {
            None => "initial",
            Some(Decision::Ordinary) => "ordinary_rotation",
            Some(Decision::Recovery) => "recovery_rotation",
            Some(Decision::FreshIdentity) => "fresh_identity",
            Some(Decision::Unchanged) => unreachable!(),
        })
}

fn candidate_epoch(prefix: &[Value], sealed_at: &str, entries: Vec<Value>) -> Sealed {
    let mut leaves: Vec<[u8; 32]> = prefix
        .iter()
        .flat_map(|epoch| entry_leaf_hashes(&epoch["entries"]))
        .collect();
    leaves.extend(entry_leaf_hashes(&json!(entries)));
    Sealed {
        epoch_number: prefix.len() as u64,
        root_token: format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&merkle::merkle_root(&leaves))
        ),
        sealed_at: sealed_at.to_string(),
        entries,
    }
}

fn probe(
    epochs: &[Value],
    days: Params,
    probe: &Value,
) -> (Declarations, Result<Effects, String>, u64) {
    let height = probe["prefix_height"].as_u64().unwrap() as usize;
    let mut entries: Vec<Value> = if let Some(candidates) = probe["candidates"].as_array() {
        candidates
            .iter()
            .map(|c| json!({"type": "publisher_declaration", "body": c}))
            .collect()
    } else {
        vec![json!({"type": "publisher_declaration", "body": probe["candidate"]})]
    };
    if !probe["successor"].is_null() {
        entries.push(json!({"type": "publisher_declaration", "body": probe["successor"]}));
    }
    entries.sort_by_key(|entry| {
        wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(entry).unwrap())
    });
    let mut state = Declarations::default();
    let mut windows = 0;
    for epoch in &epochs[..=height] {
        windows += windows_opened(&apply(&mut state, &sealed(epoch), days).unwrap());
    }
    let candidate = candidate_epoch(
        &epochs[..=height],
        probe["candidate_sealed_at"].as_str().unwrap(),
        entries,
    );
    let before = format!("{state:?}");
    let projection = state.project(
        &candidate.sealed_at,
        days.days,
        days.activation_epochs,
        &Limits::suite(),
        &candidate.entries,
    );
    assert_eq!(format!("{state:?}"), before);
    let result = apply(&mut state, &candidate, days).map_err(|e| e.to_string());
    match (&projection, &result) {
        (Ok(projected), Ok(effects)) => {
            assert_eq!(
                format!("{:?}", projected.domains()),
                format!("{:?}", state.domains())
            );
            assert_eq!(format!("{:?}", projected.effects()), format!("{effects:?}"));
        }
        (Err(projected), Err(applied)) => assert_eq!(projected.to_string(), *applied),
        _ => panic!("projection disagrees with application: {}", probe["name"]),
    }
    match &result {
        Ok(effects) => {
            windows += windows_opened(effects);
            assert_eq!(
                outcome(effects),
                probe
                    .get("expected_successor_result")
                    .unwrap_or(&probe["expected_result"]),
                "{}",
                probe["name"]
            );
        }
        Err(error) => {
            assert!(
                error.contains(probe["expected_result"].as_str().unwrap()),
                "{}: {error}",
                probe["name"]
            );
            assert_eq!(format!("{state:?}"), before);
        }
    }
    (state, result, windows)
}

#[test]
fn recovery_heads_sequence_floors_and_named_predecessors() {
    let vector = read_json("vectors/wist1/recovery-heads.json");
    let days = params(&vector);
    for branch in std::iter::once(&vector).chain(vector["branches"].as_array().unwrap()) {
        let epochs = branch["epochs"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut windows = 0;
        for epoch in epochs {
            let epoch = sealed(epoch);
            windows += windows_opened(&apply(&mut state, &epoch, days).unwrap());
            for expected in branch["expected_prefix_states"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if expected["height"].as_u64() == Some(epoch.epoch_number) {
                    assert_eq!(
                        summary(&state.domains()["example.com"], windows),
                        expected["state"]
                    );
                }
            }
        }
        for candidate in branch["probes"].as_array().into_iter().flatten() {
            let selected = candidate["branch"].as_u64().map_or(epochs, |index| {
                vector["branches"][index as usize]["epochs"]
                    .as_array()
                    .unwrap()
            });
            let (state, result, windows) = probe(selected, days, candidate);
            if result.is_ok() {
                assert_eq!(
                    summary(&state.domains()["example.com"], windows),
                    candidate["expected_state"],
                    "{}",
                    candidate["name"]
                );
            }
        }
        if !branch["expected_state"].is_null() {
            assert_eq!(
                summary(&state.domains()["example.com"], windows),
                branch["expected_state"]
            );
        }
        assert_eq!(state.head().unwrap().1, branch["pinned_head"]);
    }
}

#[test]
fn recovery_ownership_uses_sequence_with_original_canonical_positions() {
    let vector = read_json("vectors/wist1/recovery-order.json");
    let days = params(&vector);
    for case in vector["cases"].as_array().unwrap() {
        let epochs = case["epochs"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut sequences = Vec::new();
        let mut windows = 0;
        for epoch in epochs {
            for installation in apply(&mut state, &sealed(epoch), days)
                .unwrap()
                .installations
            {
                let position = installation.declaration.position();
                assert_eq!(
                    &epochs[position.epoch_number as usize]["entries"][position.entry_index]
                        ["body"],
                    installation.declaration.envelope()
                );
                sequences.push(installation.declaration.envelope()["publisher"]["seq"].clone());
                windows += u64::from(installation.opens_window);
            }
        }
        assert_eq!(json!(sequences), case["expected"]["application_sequences"]);
        assert_eq!(windows, case["expected"]["windows_opened"]);
        let window = state.domains()["example.com"].window().unwrap();
        assert_eq!(window.owner().hash(), case["expected"]["owner_declaration"]);
        assert_eq!(
            window.owner().position().epoch_number,
            case["expected"]["owner_height"]
        );
        assert_eq!(
            window.owner().envelope()["publisher"]["seq"],
            case["expected"]["owner_sequence"]
        );
        assert_eq!(
            timestamp(i128::from(window.owner().sealed_at_s())),
            case["expected"]["opened_at"]
        );
        assert_eq!(state.head().unwrap().1, case["pinned_head"]);
    }
}

#[test]
fn conflicting_groups_and_failed_authors_reject_epochs_atomically() {
    let vector = read_json("vectors/wist1/declaration-conflicts.json");
    let days = params(&vector);
    for case in vector["cases"].as_array().unwrap() {
        let mut epochs = vector["prefixes"][case["prefix"].as_str().unwrap()]
            .as_array()
            .unwrap()
            .clone();
        epochs.push(case["epoch"].clone());
        let name = case["name"].as_str().unwrap();
        let candidate = sealed(&case["epoch"]);
        assert_eq!(candidate.root_token, case["pinned_head"], "{name}");
        let bindings: Vec<wist_core::objects::PublisherKey> = epochs
            .iter()
            .flat_map(|epoch| epoch["entries"].as_array().unwrap())
            .filter(|entry| entry["type"] == "publisher_declaration")
            .flat_map(|entry| {
                let publisher = &entry["body"]["publisher"];
                let mut keys = publisher["keys"].as_array().unwrap().clone();
                keys.extend(
                    publisher["recovery_keys"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default(),
                );
                keys
            })
            .map(|key| serde_json::from_value(key).unwrap())
            .collect();
        let authorship: Vec<bool> = candidate
            .entries
            .iter()
            .map(|entry| {
                bindings
                    .iter()
                    .filter(|key| entry["body"]["sig"]["key_id"] == key.kid.as_str())
                    .any(|key| {
                        wist_core::envelope::verify_envelope(
                            &entry["body"],
                            "publisher",
                            &wist_core::crypto::PublicKey::from_b64u(&key.x).unwrap(),
                        )
                        .is_ok()
                    })
            })
            .collect();
        assert_eq!(json!(authorship), case["signature_valid"], "{name}");
        for isolated in case["isolated_candidates"].as_array().into_iter().flatten() {
            assert_eq!(
                classification(&isolated["previous"], &isolated["incoming"]),
                isolated["expected_result"],
                "{name}"
            );
        }
        if !case["first_candidate"].is_null() {
            let first = usize::from(case["sibling_leaves_reversed"] == true);
            assert_eq!(
                digest(&candidate.entries[first]["body"]),
                case["first_candidate"],
                "{name}"
            );
        }
        let mut state = Declarations::default();
        let mut windows = std::collections::BTreeMap::<String, u64>::new();
        let last = epochs.len() - 1;
        for (index, epoch) in epochs.iter().enumerate() {
            let before = format!("{state:?}");
            match apply(&mut state, &sealed(epoch), days) {
                Ok(effects) => {
                    for installation in effects.installations {
                        let domain = installation.declaration.envelope()["publisher"]["domain"]
                            .as_str()
                            .unwrap()
                            .to_string();
                        *windows.entry(domain).or_default() += u64::from(installation.opens_window);
                    }
                    if index == last {
                        assert!(case["expected_results"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("accepted")));
                    }
                }
                Err(error) => {
                    assert_eq!(index, last, "{}", case["name"]);
                    assert!(
                        case["expected_results"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| error.to_string().contains(c.as_str().unwrap())),
                        "{}: {error}",
                        case["name"]
                    );
                    assert_eq!(format!("{state:?}"), before);
                }
            }
        }
        let actual: serde_json::Map<_, _> = state
            .domains()
            .iter()
            .map(|(name, domain)| {
                (
                    name.clone(),
                    json!({
                        "current_envelope": digest(domain.current().envelope()),
                        "recovery_envelope": domain.window().map(|w| digest(w.head().envelope())),
                        "highest_accepted_seq": domain.highest_accepted_seq(),
                        "window_end": domain.window().map(|w| timestamp(w.end_s())),
                        "windows_opened": windows[name],
                        "reset_height": domain.reset().map(|p| p.epoch_number),
                    }),
                )
            })
            .collect();
        assert_eq!(
            Value::Object(actual),
            case["expected_state"],
            "{}",
            case["name"]
        );
        let before_any_epoch = format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&merkle::EMPTY_ROOT)
        );
        assert_eq!(
            state.head().map_or(before_any_epoch.as_str(), |h| h.1),
            case["expected_accepted_head"]
        );
    }
}

#[test]
fn settlement_restores_authenticated_chain_and_reports_competitors() {
    let vector = read_json("vectors/wist1/recovery-settlement.json");
    let days = params(&vector);
    for case in vector["cases"].as_array().unwrap() {
        let epochs = case["epochs"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut superseded = Vec::new();
        for epoch in epochs {
            for settlement in apply(&mut state, &sealed(epoch), days).unwrap().settlements {
                superseded.extend(settlement.superseded.iter().map(|d| d.hash().to_string()));
            }
        }
        assert_eq!(
            state.domains()["example.com"].current().hash(),
            case["expected"]["effective_declaration"]
        );
        assert_eq!(json!(superseded), case["expected"]["superseded"]);
        for candidate in case["probes"].as_array().unwrap() {
            let mut candidate = candidate.clone();
            let height = candidate["prefix_height"].as_u64().unwrap() as usize;
            let previous =
                wist_core::timestamp::log_seconds(&sealed(&epochs[height]).sealed_at).unwrap();
            candidate["candidate_sealed_at"] = timestamp(i128::from(previous) + 3600).into();
            assert!(probe(epochs, days, &candidate).1.is_err());
        }
    }
}

fn classification(stored: &Value, fetched: &Value) -> String {
    let result = if stored.is_null() {
        wist_core::declaration::evaluate_initial(fetched, &Limits::suite()).map(|_| "initial")
    } else {
        wist_core::declaration::evaluate(stored, fetched, &Limits::suite()).map(|decision| {
            match decision {
                Decision::Ordinary => "ordinary_rotation",
                Decision::Recovery => "recovery_rotation",
                Decision::FreshIdentity => "fresh_identity",
                Decision::Unchanged => "idempotent",
            }
        })
    };
    result.unwrap_or_else(|(code, _)| code).to_string()
}

fn authored(envelope: &Value, author: &str) -> bool {
    let author = wist_core::crypto::PublicKey::from_b64u(author).unwrap();
    wist_core::envelope::verify_envelope(envelope, "publisher", &author).is_ok()
}

fn epoch_case(file: &str, vector: &Value, case: &Value) {
    let name = case["name"].as_str().unwrap();
    let params = params(vector);
    let mut state = Declarations::default();
    for epoch in vector["prefixes"][case["prefix"].as_str().unwrap()]
        .as_array()
        .unwrap()
    {
        apply(&mut state, &sealed(epoch), params).unwrap();
    }
    let candidate = sealed(&case["epoch"]);
    assert_eq!(candidate.root_token, case["pinned_head"], "{file}: {name}");
    let before = format!("{state:?}");
    match apply(&mut state, &candidate, params) {
        Ok(_) => {
            assert_eq!(case["expected"], "accepted", "{file}: {name}");
            assert_eq!(
                state.head().unwrap().1,
                case["pinned_head"],
                "{file}: {name}"
            );
            if let Some(domains) = case.get("expected_domains") {
                assert_eq!(
                    json!(state.domains().keys().collect::<Vec<_>>()),
                    *domains,
                    "{file}: {name}"
                );
            }
        }
        Err(error) => {
            assert_eq!(
                error.code(),
                case["expected"].as_str(),
                "{file}: {name}: {error}"
            );
            assert_eq!(format!("{state:?}"), before, "{file}: {name}");
        }
    }
}

#[test]
fn declaration_field_failures_reject_the_declaration_and_preserve_the_prefix() {
    let file = "vectors/wist1/declaration-fields.json";
    let vector = read_json(file);
    let author = vector["author_key"].as_str().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        assert_eq!(
            authored(&case["envelope"], author),
            case["author_signature_valid"],
            "{}",
            case["name"]
        );
        assert_eq!(
            classification(&vector["stored"], &case["envelope"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
    for case in vector["epoch_cases"].as_array().unwrap() {
        epoch_case(file, &vector, case);
    }
}

#[test]
fn a_catalog_instant_is_bound_by_the_whole_second_key_window() {
    let vector = read_json("vectors/wist1/declaration-fields.json");
    for case in vector["key_time_cases"].as_array().unwrap() {
        let declaration = wist_core::declaration::publisher_of(&case["declaration"]).unwrap();
        let envelope = &case["envelope"];
        let catalog = &envelope["catalog"];
        let generated_at = catalog["generated_at"].as_str().unwrap();
        let verifies = |key: &wist_core::objects::PublisherKey| {
            wist_core::crypto::PublicKey::from_b64u(&key.x).is_ok_and(|public| {
                wist_core::envelope::verify_envelope(envelope, "catalog", &public).is_ok()
            })
        };
        let outcome = if wist_core::timestamp::log_seconds(generated_at).is_err() {
            "WIST1-E14"
        } else {
            match wist_core::collection::check_binding(
                &declaration,
                catalog["collection"].as_str().unwrap(),
                envelope["sig"]["key_id"].as_str().unwrap(),
                generated_at,
                verifies,
            ) {
                Ok(()) => "key_bound_satisfied",
                Err(code) => code,
            }
        };
        assert_eq!(outcome, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn publisher_instants_relate_as_exact_civil_clock_seconds() {
    let vector = read_json("vectors/wist1/declaration-fields.json");
    for case in vector["elapsed_cases"].as_array().unwrap() {
        let (start, start_fraction) =
            wist_core::publisher_time::seconds(case["start"].as_str().unwrap()).unwrap();
        let (end, end_fraction) =
            wist_core::publisher_time::seconds(case["end"].as_str().unwrap()).unwrap();
        assert_eq!(start_fraction, "", "{case}");
        let mut elapsed = (end - start).to_string();
        if !end_fraction.is_empty() {
            elapsed = format!("{elapsed}.{end_fraction}");
        }
        assert_eq!(elapsed, case["seconds"], "{case}");
    }
    let allowance = wist_core::parameters::spec("clock_skew_seconds")
        .and_then(|parameter| parameter.default)
        .unwrap();
    for case in vector["relation_cases"].as_array().unwrap() {
        let generated_at = case["envelope"]["catalog"]["generated_at"]
            .as_str()
            .unwrap();
        let satisfied = match case["kind"].as_str().unwrap() {
            "clock" => {
                let generated_s = wist_core::timestamp::log_seconds(generated_at).unwrap();
                wist_core::publisher_time::at_or_after(
                    case["reference"].as_str().unwrap(),
                    i128::from(generated_s - allowance),
                )
                .unwrap()
            }
            "item" => {
                assert_eq!(case["reference"], generated_at, "{}", case["name"]);
                wist_core::publisher_time::compare(
                    case["item"]["observed_at"].as_str().unwrap(),
                    generated_at,
                )
                .unwrap()
                    != std::cmp::Ordering::Greater
            }
            kind => panic!("{kind}"),
        };
        let outcome = if satisfied {
            "relation_satisfied"
        } else {
            "WIST1-E06"
        };
        assert_eq!(outcome, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn declaration_sequence_classifies_each_replacement_or_names_its_rejection() {
    let vector = read_json("vectors/wist1/declaration-sequence.json");
    for case in vector["cases"].as_array().unwrap() {
        assert_eq!(
            classification(&case["stored"], &case["fetched"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn declaration_hosts_accept_only_their_signed_canonical_spelling() {
    let file = "vectors/wist1/declaration-hosts.json";
    let vector = read_json(file);
    let author = vector["author_key"].as_str().unwrap();
    for case in vector["cases"].as_array().unwrap() {
        assert!(authored(&case["envelope"], author), "{}", case["name"]);
        assert_eq!(
            classification(&Value::Null, &case["envelope"]),
            case["expected"],
            "{}",
            case["name"]
        );
    }
    for case in vector["epoch_cases"].as_array().unwrap() {
        epoch_case(file, &vector, case);
    }
}

fn snapshot_tuples(domain_name: &str, domain: &Domain) -> (Value, Value) {
    (
        json!([
            "declaration",
            domain_name,
            domain.current().envelope(),
            domain.current().position().epoch_number,
            domain.highest_accepted_seq(),
        ]),
        domain.window().map_or(Value::Null, |window| {
            json!([
                "recovery_window",
                domain_name,
                window.owner().position().epoch_number,
                timestamp(window.end_s()),
                window.head().envelope(),
                window.head().position().epoch_number,
            ])
        }),
    )
}

fn resumed(case: &Value, without: Option<&str>) -> String {
    let declaration = &case["declaration"];
    let domain = declaration[1].as_str().unwrap();
    let current = declaration[2].clone();
    let floor = if without == Some("floor") {
        current["publisher"]["seq"].as_u64().unwrap()
    } else {
        declaration[4].as_u64().unwrap()
    };
    let position = |height: &Value| wist_core::declarations::Position {
        epoch_number: height.as_u64().unwrap(),
        entry_index: 0,
    };
    let window = (without != Some("head") && !case["recovery_window"].is_null()).then(|| {
        let tuple = &case["recovery_window"];
        (
            tuple[4].clone(),
            position(&tuple[5]),
            0,
            i128::from(wist_core::timestamp::log_seconds(tuple[3].as_str().unwrap()).unwrap()),
        )
    });
    let height = case["height"].as_u64().unwrap();
    let mut state = Declarations::default();
    state
        .adopt(
            domain,
            current,
            position(&declaration[3]),
            0,
            floor,
            window,
            None,
        )
        .unwrap();
    state.seed_head(height - 1, "resumed", None);
    let entries = vec![json!({"type": "publisher_declaration", "body": case["candidate"]})];
    match state.project(
        case["candidate_sealed_at"].as_str().unwrap(),
        7,
        0,
        &Limits::suite(),
        &entries,
    ) {
        Ok(projection) => outcome(projection.effects()).to_string(),
        Err(error) => error.code().unwrap().to_string(),
    }
}

#[test]
fn snapshot_tuples_restate_and_resume_the_replayed_declaration_heads() {
    let vector = read_json("vectors/wist1/recovery-heads.json");
    let days = params(&vector);
    let mut state = Declarations::default();
    let mut tuples = std::collections::BTreeMap::new();
    for epoch in vector["epochs"].as_array().unwrap() {
        let epoch = sealed(epoch);
        apply(&mut state, &epoch, days).unwrap();
        tuples.insert(
            epoch.epoch_number,
            snapshot_tuples("example.com", &state.domains()["example.com"]),
        );
    }
    for expected in vector["snapshot_tuples"].as_array().unwrap() {
        let (declaration, window) = &tuples[&expected["height"].as_u64().unwrap()];
        assert_eq!(
            *declaration, expected["declaration"],
            "{}",
            expected["height"]
        );
        assert_eq!(
            *window, expected["recovery_window"],
            "{}",
            expected["height"]
        );
    }
    assert_eq!(days.days, 7);
    assert_eq!(days.activation_epochs, 0);
    for case in vector["resume_cases"].as_array().unwrap() {
        assert_eq!(
            resumed(case, None),
            case["expected_result"],
            "{}",
            case["label"]
        );
        assert_eq!(
            resumed(case, case["without"].as_str()),
            case["degraded_result"],
            "{}",
            case["label"]
        );
    }
}
