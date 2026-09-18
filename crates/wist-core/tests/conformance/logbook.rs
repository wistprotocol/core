use super::{entry_leaf_hashes, example_log, hash_list, read_json, read_text};
use serde_json::Value;
use wist_core::checkpoint::{self, Adoption, Checkpoint, Equivocation, Progression, WitnessKey};
use wist_core::merkle::{self, LeafHashes};
use wist_core::tiles::{self, Bundle, Tile, TileSet};

fn vector() -> Value {
    read_json("vectors/wist3/checkpoints.json")
}

fn roster(vector: &Value) -> Vec<WitnessKey> {
    vector["witness_roster"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, key)| WitnessKey {
            name: name.clone(),
            public_key: wist_core::crypto::PublicKey::from_b64u(key.as_str().unwrap()).unwrap(),
        })
        .collect()
}

fn verified(note: &str, witnesses: &[WitnessKey]) -> Result<Checkpoint, String> {
    let (log_id, key) = example_log();
    let checkpoint = Checkpoint::parse(note).map_err(|e| e.code().unwrap_or("none").to_string())?;
    checkpoint::verify(&checkpoint, &log_id, std::slice::from_ref(&key), witnesses)
        .map_err(|e| e.code().unwrap_or("none").to_string())?;
    Ok(checkpoint)
}

#[test]
fn note_form_and_signature_rules_select_the_documented_outcome() {
    let vector = vector();
    let witnesses = roster(&vector);
    for case in vector["note_form_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        match verified(case["checkpoint"].as_str().unwrap(), &witnesses) {
            Ok(checkpoint) => {
                assert_eq!(case["expected"], "valid", "{name}");
                let verification = checkpoint::verify(
                    &checkpoint,
                    &example_log().0,
                    std::slice::from_ref(&example_log().1),
                    &witnesses,
                )
                .unwrap();
                assert!(
                    verification.cosigners.is_empty(),
                    "{name}: a line from an untrusted signer counted as a Cosignature"
                );
                assert_eq!(
                    checkpoint.encode(),
                    case["checkpoint"].as_str().unwrap(),
                    "{name}: the note does not re-encode octet for octet"
                );
            }
            Err(code) => assert_eq!(case["expected"], code, "{name}"),
        }
    }
}

#[test]
fn each_block_of_the_vector_log_states_its_cumulative_tree() {
    let vector = vector();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut previous: Option<Checkpoint> = None;
    for block in vector["blocks"].as_array().unwrap() {
        let checkpoint = verified(block["checkpoint"].as_str().unwrap(), &[]).unwrap();
        assert_eq!(
            checkpoint.block_number(),
            block["block_number"].as_u64().unwrap()
        );
        let previous_size = leaves.len() as u64;
        let entries: Vec<Value> = block["entries"].as_array().unwrap().clone();
        let prior = leaves.clone();
        let summary = wist_core::block::verify_block(
            previous_size,
            &checkpoint,
            &entries,
            &LeafHashes(&prior),
            268_435_456,
        )
        .unwrap();
        leaves.extend(summary.leaf_hashes);
        assert_eq!(checkpoint.tree_size(), leaves.len() as u64);
        assert_eq!(leaves, hash_list(&block["leaf_hashes"]));
        assert_eq!(*checkpoint.root(), merkle::merkle_root(&leaves));
        if let Some(previous) = &previous {
            checkpoint::check_sequence(Some(previous), &checkpoint, 3600).unwrap();
            let path =
                merkle::consistency_proof(previous.tree_size(), checkpoint.tree_size(), &leaves)
                    .unwrap();
            checkpoint::check_consistency(previous, &checkpoint, &path).unwrap();
        } else {
            checkpoint::check_sequence(None, &checkpoint, 3600).unwrap();
        }
        previous = Some(checkpoint);
    }
    assert_eq!(leaves.len(), 7);
}

#[test]
fn consistency_proofs_verify_or_report_chain_divergence() {
    let mut compared_the_size_zero_root = false;
    for case in vector()["consistency_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let m = case["m"].as_u64().unwrap();
        let m_root = hash_list(&serde_json::json!([case["m_root"]]))[0];
        let n_root = hash_list(&serde_json::json!([case["n_root"]]))[0];
        let path = hash_list(&case["path"]);
        let result =
            merkle::verify_consistency(m, case["n"].as_u64().unwrap(), &m_root, &n_root, &path);
        let outcome = if result.is_ok() { "valid" } else { "WIST3-E02" };
        assert_eq!(case["expected"], outcome, "{name}");
        if m == 0 && m_root != merkle::EMPTY_ROOT {
            assert_eq!(case["expected"], "WIST3-E02", "{name}");
            compared_the_size_zero_root = true;
        }
    }
    assert!(
        compared_the_size_zero_root,
        "no case offers size 0 with a root other than SHA-256(\"\")"
    );
}

#[test]
fn a_checkpoint_stating_tree_size_zero_states_the_empty_trees_root() {
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector()["size_zero_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let checkpoint = verified(case["checkpoint"].as_str().unwrap(), &[])
            .unwrap_or_else(|code| panic!("{name}: the note is validly signed, got {code}"));
        assert_eq!(checkpoint.tree_size(), 0, "{name}");
        let outcome = match checkpoint::check_size_zero_root(&checkpoint) {
            Ok(()) => {
                assert_eq!(*checkpoint.root(), merkle::EMPTY_ROOT, "{name}");
                "valid".to_string()
            }
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        outcomes.insert(outcome);
    }
    assert_eq!(
        outcomes,
        ["valid".to_string(), "WIST3-E02".to_string()]
            .into_iter()
            .collect()
    );
}

#[test]
fn a_lower_checkpoint_is_stale_unless_its_note_text_differs_from_the_retained_one() {
    for case in vector()["rollback_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let offered = verified(case["offered_checkpoint"].as_str().unwrap(), &[]).unwrap();
        let head = case["verified_head_block_number"].as_u64().unwrap();
        assert!(offered.block_number() < head, "{name}");
        let retained = case["verified_checkpoint"]
            .as_str()
            .map(|note| verified(note, &[]).unwrap());
        match checkpoint::progression(&offered, head, retained.as_ref()) {
            Ok(progression) => {
                assert_eq!(progression, Progression::NotAdopted, "{name}");
                assert_eq!(case["expected"], "not_adopted", "{name}");
            }
            Err(error) => assert_eq!(case["expected"], error.code().unwrap(), "{name}"),
        }
    }
}

#[test]
fn the_three_equivocation_forms_are_detected_from_their_evidence() {
    let mut forms = std::collections::BTreeSet::new();
    for case in vector()["equivocation_cases"].as_array().unwrap() {
        let form = case["form"].as_str().unwrap();
        let first = verified(case["checkpoint_1"].as_str().unwrap(), &[]).unwrap();
        let second = verified(case["checkpoint_2"].as_str().unwrap(), &[]).unwrap();
        let detected = match case["leaf_hashes_2"].as_array() {
            None => checkpoint::equivocation(&first, &second),
            Some(_) => {
                assert_eq!(checkpoint::equivocation(&first, &second), None, "{form}");
                let leaves = hash_list(&case["leaf_hashes_2"]);
                checkpoint::prefix_equivocation(&first, &second, &LeafHashes(&leaves)).unwrap()
            }
        };
        let detected = detected.unwrap_or_else(|| panic!("{form}: no equivocation detected"));
        assert_eq!(case["expected"], detected.code(), "{form}");
        forms.insert(detected);
    }
    assert_eq!(
        forms,
        [
            Equivocation::SameSizeDifferentRoot,
            Equivocation::SameBlockDifferentStatement,
            Equivocation::NoConsistentPrefix
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn an_archived_checkpoint_must_sit_at_its_own_block_path() {
    for case in vector()["archive_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let checkpoint = verified(case["checkpoint"].as_str().unwrap(), &[]).unwrap();
        let path = case["path"].as_str().unwrap();
        match checkpoint::check_archive_path(&checkpoint, path) {
            Ok(()) => assert_eq!(case["expected"], "valid", "{name}"),
            Err(error) => assert_eq!(case["expected"], error.code().unwrap(), "{name}"),
        }
    }
}

#[test]
fn the_witness_quorum_counts_distinct_trusted_names() {
    let vector = vector();
    let witnesses = roster(&vector);
    let (log_id, key) = example_log();
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector["quorum_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let quorum = case["quorum"].as_u64().unwrap();
        let checkpoint = Checkpoint::parse(case["checkpoint"].as_str().unwrap()).unwrap();
        let verification = match checkpoint::verify(
            &checkpoint,
            &log_id,
            std::slice::from_ref(&key),
            &witnesses,
        ) {
            Ok(verification) => verification,
            Err(error) => {
                assert_eq!(case["expected"], error.code().unwrap(), "{name}");
                outcomes.insert("WIST3-E03");
                continue;
            }
        };
        match checkpoint::adoption(&verification, quorum) {
            Adoption::Adopted { unwitnessed } => {
                assert_eq!(case["expected"], "valid", "{name}");
                if let Some(expected) = case["unwitnessed"].as_bool() {
                    assert_eq!(unwitnessed, expected, "{name}");
                }
                outcomes.insert("valid");
            }
            Adoption::NotAdopted => {
                assert_eq!(case["expected"], "not_adopted", "{name}");
                outcomes.insert("not_adopted");
            }
        }
    }
    assert_eq!(
        outcomes,
        ["valid", "not_adopted", "WIST3-E03"].into_iter().collect()
    );
}

#[test]
fn a_snapshot_manifest_must_match_the_checkpoint_at_its_block() {
    let manifest_template: Value = read_json("examples/snapshot-manifest.json")["manifest"].clone();
    for case in vector()["cold_start_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let checkpoint = verified(case["checkpoint"].as_str().unwrap(), &[]).unwrap();
        let mut value = manifest_template.clone();
        for field in ["block_number", "log_position", "anchor_block_hash"] {
            value[field] = case["manifest"][field].clone();
        }
        let manifest: wist_core::objects::SnapshotManifest = serde_json::from_value(value).unwrap();
        match wist_core::snapshot::check_manifest_anchor(&manifest, &checkpoint) {
            Ok(()) => assert_eq!(case["expected"], "valid", "{name}"),
            Err(error) => assert_eq!(case["expected"], error.code().unwrap(), "{name}"),
        }
    }
}

#[test]
fn the_static_surface_of_the_example_tree_is_the_octets_the_vector_fixes() {
    let block = read_json("vectors/wist3/block.json");
    let checkpoint = Checkpoint::parse(block["checkpoint"].as_str().unwrap()).unwrap();
    let leaves = entry_leaf_hashes(&block["entries"]);
    let tree_size = block["tree_size"].as_u64().unwrap();

    let tile = Tile {
        level: 0,
        index: 0,
        width: leaves.len() as u32,
    };
    assert_eq!(tile.path(), block["tile_0_000_p_4_path"].as_str().unwrap());
    assert_eq!(tiles::required_tiles(tree_size), vec![tile]);
    let tile_bytes =
        wist_core::crypto::hex_decode(block["tile_0_000_p_4"].as_str().unwrap()).unwrap();
    assert_eq!(tiles::encode_tile(&leaves), tile_bytes);
    assert_eq!(tiles::decode_tile(&tile_bytes).unwrap(), leaves);

    let bundle = Bundle {
        index: 0,
        width: leaves.len() as u32,
    };
    assert_eq!(
        bundle.path(),
        block["entry_bundle_000_p_4_path"].as_str().unwrap()
    );
    assert_eq!(tiles::required_bundles(tree_size), vec![bundle]);
    let bundle_bytes =
        wist_core::crypto::hex_decode(block["entry_bundle_000_p_4"].as_str().unwrap()).unwrap();
    let leaf_data: Vec<Vec<u8>> = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| wist_core::jcs::canonicalize(entry).unwrap())
        .collect();
    assert_eq!(
        tiles::encode_entry_bundle(&leaf_data).unwrap(),
        bundle_bytes
    );
    assert_eq!(
        tiles::decode_entry_bundle(&bundle_bytes).unwrap(),
        leaf_data
    );
    assert_eq!(
        wist_core::block::parse_entries(&leaf_data).unwrap(),
        *block["entries"].as_array().unwrap()
    );

    let mut served = TileSet::new();
    served.insert_bytes(0, 0, &tile_bytes).unwrap();
    tiles::check_tree(&served, tree_size, checkpoint.root()).unwrap();
    tiles::check_bundle(&leaf_data, 0, &served).unwrap();
    assert_eq!(
        TileSet::build(&leaves).serve(tree_size),
        [(tile.path(), tile_bytes.clone())].into_iter().collect()
    );

    assert!(block["consistency_proof_0_to_4"]
        .as_array()
        .unwrap()
        .is_empty());
    checkpoint::check_consistency(
        &Checkpoint::parse(&read_text("examples/checkpoint.txt")).unwrap(),
        &checkpoint,
        &[],
    )
    .unwrap();

    let mut tampered = tile_bytes.clone();
    tampered[0] ^= 1;
    let mut altered = TileSet::new();
    altered.insert_bytes(0, 0, &tampered).unwrap();
    assert_eq!(
        tiles::check_tree(&altered, tree_size, checkpoint.root())
            .unwrap_err()
            .code(),
        Some("WIST3-E03")
    );
}

#[test]
fn the_static_file_octet_bounds_admit_equality_and_reject_excess() {
    let vector = read_json("vectors/wist3/tile-bounds.json");

    let tile = &vector["tile"];
    assert_eq!(tile["bound_bytes"].as_u64().unwrap(), tiles::TILE_MAX_BYTES);
    for (field, expected) in [
        ("at_bound_hex", tile["at_bound_expected"].as_str().unwrap()),
        (
            "over_bound_hex",
            tile["over_bound_expected"].as_str().unwrap(),
        ),
    ] {
        let bytes = wist_core::crypto::hex_decode(tile[field].as_str().unwrap()).unwrap();
        let outcome = match tiles::decode_tile(&bytes) {
            Ok(hashes) => {
                assert_eq!(hashes.len() * 32, bytes.len());
                "valid".to_string()
            }
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(outcome, expected, "{field}");
    }

    let bundle = &vector["entry_bundle"];
    assert_eq!(
        bundle["bound_bytes"].as_u64().unwrap(),
        tiles::ENTRY_BUNDLE_MAX_BYTES
    );
    assert_eq!(
        tiles::ENTRY_BUNDLE_MAX_BYTES,
        u64::from(tiles::TILE_WIDTH) * (tiles::ENTRY_MAX_BYTES + 2)
    );
    for (field, expected) in [
        (
            "at_bound_declared_bytes",
            bundle["at_bound_expected"].as_str().unwrap(),
        ),
        (
            "over_bound_declared_bytes",
            bundle["over_bound_expected"].as_str().unwrap(),
        ),
    ] {
        let declared = bundle[field].as_u64().unwrap();
        let outcome = match tiles::check_entry_bundle_bytes(declared) {
            Ok(()) => "valid".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(outcome, expected, "{field}");
    }

    let entry = &vector["entry_jcs"];
    assert_eq!(
        entry["bound_bytes"].as_u64().unwrap(),
        tiles::ENTRY_MAX_BYTES
    );
    for (field, expected) in [
        (
            "at_bound_entry",
            entry["at_bound_expected"].as_str().unwrap(),
        ),
        (
            "over_bound_entry",
            entry["over_bound_expected"].as_str().unwrap(),
        ),
    ] {
        let octets = wist_core::jcs::canonicalize(&entry[field]).unwrap().len() as u64;
        let outcome = match wist_core::block::entry_leaf(&entry[field]) {
            Ok(_) => "valid".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(outcome, expected, "{field}: {octets} octets");
    }
}

#[test]
fn the_sealed_at_line_is_read_under_the_log_timestamp_profile() {
    let vector = read_json("vectors/wist3/timestamps.json");
    let case = &vector["checkpoint_field_case"];
    let index = case["sealed_at_line_index"].as_u64().unwrap() as usize;
    let lines: Vec<String> = case["note_lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap().to_string())
        .collect();
    for (field, accepted) in [
        ("field_accept", true),
        ("field_reject", false),
        ("field_reject_non_ascii", false),
    ] {
        let mut lines = lines.clone();
        lines[index] = format!("sealed_at {}", vector[field].as_str().unwrap());
        let note = format!(
            "{}\n\n{}",
            lines.join("\n"),
            case["sig_block"].as_str().unwrap()
        );
        let parsed = Checkpoint::parse(&note);
        assert_eq!(parsed.is_ok(), accepted, "{field}");
        match parsed {
            Ok(checkpoint) => assert_eq!(checkpoint.sealed_at(), vector[field].as_str().unwrap()),
            Err(error) => assert_eq!(error.code(), Some("WIST3-E03"), "{field}"),
        }
    }
}

fn aggregator_key(key_id: &str, public_key: &str) -> wist_core::checkpoint::AggregatorKey {
    wist_core::checkpoint::AggregatorKey {
        key_id: key_id.to_string(),
        public_key: wist_core::crypto::PublicKey::from_b64u(public_key).unwrap(),
    }
}

fn walk_history(label: &str, blocks: &[Value], key: &wist_core::checkpoint::AggregatorKey) {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut previous: Option<Checkpoint> = None;
    for block in blocks {
        let checkpoint = Checkpoint::parse(block["checkpoint"].as_str().unwrap()).unwrap();
        let verification = checkpoint::verify(
            &checkpoint,
            checkpoint.origin(),
            std::slice::from_ref(key),
            &[],
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(verification.signers, [key.key_id.clone()].into());
        leaves.extend(entry_leaf_hashes(&block["entries"]));
        assert_eq!(checkpoint.tree_size(), leaves.len() as u64, "{label}");
        assert_eq!(*checkpoint.root(), merkle::merkle_root(&leaves), "{label}");
        if let Some(previous) = &previous {
            assert_eq!(checkpoint.block_number(), previous.block_number() + 1);
            let proof =
                merkle::consistency_proof(previous.tree_size(), checkpoint.tree_size(), &leaves)
                    .unwrap();
            checkpoint::check_consistency(previous, &checkpoint, &proof).unwrap();
        }
        previous = Some(checkpoint);
    }
}

#[test]
fn histories_that_carry_checkpoints_bind_their_cumulative_trees() {
    for path in [
        "vectors/wist1/recovery-heads.json",
        "vectors/wist1/recovery-order.json",
        "vectors/wist1/recovery-settlement.json",
        "vectors/wist1/key-directory.json",
        "vectors/wist1/declaration-conflicts.json",
    ] {
        let vector = read_json(path);
        let key = aggregator_key(
            vector["log_key"]["key_id"].as_str().unwrap(),
            vector["log_key"]["public_key"].as_str().unwrap(),
        );
        let mut histories = Vec::new();
        collect_histories(&vector, &mut histories);
        assert!(!histories.is_empty(), "{path}: no history of Blocks");
        for blocks in histories {
            walk_history(path, &blocks, &key);
        }
    }
}

#[test]
fn each_log_of_the_deduplication_vector_seals_the_shared_delta_under_its_own_key() {
    let vector = read_json("vectors/multilog/dedup.json");
    let delta_id = vector["delta_id"].as_str().unwrap();
    for log in vector["logs"].as_array().unwrap() {
        let anchor = &log["anchor"]["anchor"];
        let key = aggregator_key(
            anchor["genesis_key"]["key_id"].as_str().unwrap(),
            anchor["genesis_key"]["public_key"].as_str().unwrap(),
        );
        let blocks = log["blocks"].as_array().unwrap();
        walk_history(log["log_id"].as_str().unwrap(), blocks, &key);
        let sealed = blocks.iter().any(|block| {
            block["entries"].as_array().unwrap().iter().any(|entry| {
                entry["type"] == "publisher_delta"
                    && wist_core::delta::delta_id(&entry["body"]["delta"]).unwrap() == delta_id
            })
        });
        assert!(sealed, "{}: the shared Delta is not sealed", log["log_id"]);
    }
    let sources: Vec<&str> = vector["expected"]["merged_records"][0]["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| source.as_str().unwrap())
        .collect();
    assert_eq!(sources.len(), vector["logs"].as_array().unwrap().len());
}

fn collect_histories(value: &Value, found: &mut Vec<Vec<Value>>) {
    match value {
        Value::Array(items) => {
            if items
                .iter()
                .all(|item| item.get("checkpoint").is_some() && item.get("entries").is_some())
                && !items.is_empty()
            {
                found.push(items.clone());
                return;
            }
            for item in items {
                collect_histories(item, found);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                collect_histories(member, found);
            }
        }
        _ => {}
    }
}
