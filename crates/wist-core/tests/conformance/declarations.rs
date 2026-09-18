use super::{entry_leaf_hashes, read_json};
use serde_json::{json, Value};
use wist_core::checkpoint::Checkpoint;
use wist_core::declaration::Decision;
use wist_core::declarations::{Declarations, Domain, Effects};
use wist_core::merkle;
use wist_core::Error;

/// The recovery window length and the fresh-identity activation delay a
/// vector's parameter map fixes; an absent delay is the registry default.
#[derive(Clone, Copy)]
struct Params {
    days: i64,
    activation_blocks: i64,
}

fn params(vector: &Value) -> Params {
    Params {
        days: vector["recovery_window_days"].as_i64().unwrap(),
        activation_blocks: vector["declaration_activation_blocks"]
            .as_i64()
            .unwrap_or(24),
    }
}

struct Sealed {
    block_number: u64,
    root_token: String,
    sealed_at: String,
    entries: Vec<Value>,
}

fn sealed(block: &Value) -> Sealed {
    let checkpoint = Checkpoint::parse(block["checkpoint"].as_str().unwrap()).unwrap();
    Sealed {
        block_number: checkpoint.block_number(),
        root_token: checkpoint.root_token(),
        sealed_at: checkpoint.sealed_at().to_string(),
        entries: block["entries"].as_array().map_or(Vec::new(), Vec::clone),
    }
}

fn apply(state: &mut Declarations, block: &Sealed, params: Params) -> Result<Effects, Error> {
    state.apply_block(
        block.block_number,
        &block.root_token,
        &block.sealed_at,
        params.days,
        params.activation_blocks,
        &block.entries,
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

fn candidate_block(prefix: &[Value], sealed_at: &str, entries: Vec<Value>) -> Sealed {
    let mut leaves: Vec<[u8; 32]> = prefix
        .iter()
        .flat_map(|block| entry_leaf_hashes(&block["entries"]))
        .collect();
    leaves.extend(entry_leaf_hashes(&json!(entries)));
    Sealed {
        block_number: prefix.len() as u64,
        root_token: format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&merkle::merkle_root(&leaves))
        ),
        sealed_at: sealed_at.to_string(),
        entries,
    }
}

/// Replays the prefix, then applies the probe's candidate Block, checking
/// that the projection agrees with the application and that a rejected
/// candidate leaves the state untouched.
fn probe(
    blocks: &[Value],
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
    for block in &blocks[..=height] {
        windows += windows_opened(&apply(&mut state, &sealed(block), days).unwrap());
    }
    let candidate = candidate_block(
        &blocks[..=height],
        probe["candidate_sealed_at"].as_str().unwrap(),
        entries,
    );
    let before = format!("{state:?}");
    let projection = state.project(
        &candidate.sealed_at,
        days.days,
        days.activation_blocks,
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
        let blocks = branch["blocks"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut windows = 0;
        for block in blocks {
            let block = sealed(block);
            windows += windows_opened(&apply(&mut state, &block, days).unwrap());
            for expected in branch["expected_prefix_states"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if expected["height"].as_u64() == Some(block.block_number) {
                    assert_eq!(
                        summary(&state.domains()["example.com"], windows),
                        expected["state"]
                    );
                }
            }
        }
        for candidate in branch["probes"].as_array().into_iter().flatten() {
            let selected = candidate["branch"].as_u64().map_or(blocks, |index| {
                vector["branches"][index as usize]["blocks"]
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
        let blocks = case["blocks"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut sequences = Vec::new();
        let mut windows = 0;
        for block in blocks {
            for installation in apply(&mut state, &sealed(block), days)
                .unwrap()
                .installations
            {
                let position = installation.declaration.position();
                assert_eq!(
                    &blocks[position.block_number as usize]["entries"][position.entry_index]
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
            window.owner().position().block_number,
            case["expected"]["owner_height"]
        );
        assert_eq!(state.head().unwrap().1, case["pinned_head"]);
    }
}

#[test]
fn conflicting_groups_and_failed_authors_reject_blocks_atomically() {
    let vector = read_json("vectors/wist1/declaration-conflicts.json");
    let days = params(&vector);
    for case in vector["cases"].as_array().unwrap() {
        let mut blocks = vector["prefixes"][case["prefix"].as_str().unwrap()]
            .as_array()
            .unwrap()
            .clone();
        blocks.push(case["block"].clone());
        let mut state = Declarations::default();
        let mut windows = std::collections::BTreeMap::<String, u64>::new();
        let last = blocks.len() - 1;
        for (index, block) in blocks.iter().enumerate() {
            let before = format!("{state:?}");
            match apply(&mut state, &sealed(block), days) {
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
                        "reset_height": domain.reset().map(|p| p.block_number),
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
        let before_any_block = format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&merkle::EMPTY_ROOT)
        );
        assert_eq!(
            state.head().map_or(before_any_block.as_str(), |h| h.1),
            case["expected_accepted_head"]
        );
    }
}

#[test]
fn settlement_restores_authenticated_chain_and_reports_competitors() {
    let vector = read_json("vectors/wist1/recovery-settlement.json");
    let days = params(&vector);
    for case in vector["cases"].as_array().unwrap() {
        let blocks = case["blocks"].as_array().unwrap();
        let mut state = Declarations::default();
        let mut superseded = Vec::new();
        for block in blocks {
            for settlement in apply(&mut state, &sealed(block), days).unwrap().settlements {
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
                wist_core::timestamp::log_seconds(&sealed(&blocks[height]).sealed_at).unwrap();
            candidate["candidate_sealed_at"] = timestamp(i128::from(previous) + 3600).into();
            assert!(probe(blocks, days, &candidate).1.is_err());
        }
    }
}
