use super::{entry_leaf_hashes, example_log, hash_list, read_json, read_text};
use serde_json::Value;
use wist_core::checkpoint::{self, Adoption, Checkpoint, Equivocation, Progression, WitnessKey};
use wist_core::merkle::{self, LeafHashes};
use wist_core::tiles::{self, EntryBundle, Tile, TileSet};

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
fn the_sequence_rules_at_a_verified_head_select_the_documented_code() {
    let vector = vector();
    let (log_id, key) = example_log();
    let cadence = vector["epoch_cadence_seconds"].as_i64().unwrap();
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector["sequence_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let head = verified(case["verified_checkpoint"].as_str().unwrap(), &[])
            .unwrap_or_else(|code| panic!("{name}: the head Checkpoint verifies, got {code}"));
        assert_eq!(
            head.epoch_number(),
            case["verified_head_epoch_number"].as_u64().unwrap(),
            "{name}"
        );
        let offered = Checkpoint::parse(case["offered_checkpoint"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: the offered note parses, got {e}"));
        let signature_verifies =
            checkpoint::verify(&offered, &log_id, std::slice::from_ref(&key), &[]).is_ok();
        assert_eq!(
            signature_verifies,
            case["signature_verifies"].as_bool().unwrap(),
            "{name}"
        );

        let larger = case["larger_tree_leaf_hashes"]
            .as_array()
            .map(|_| hash_list(&case["larger_tree_leaf_hashes"]));
        assert_eq!(
            larger.is_some(),
            offered.tree_size() < head.tree_size(),
            "{name}: the larger tree's leaf hashes are the evidence of the size rule"
        );
        if let Some(leaves) = &larger {
            assert_eq!(
                merkle::merkle_root(leaves),
                *head.root(),
                "{name}: the stated hashes do not reproduce the head's root"
            );
        }
        let reader = larger.as_deref().map(LeafHashes);

        let outcome = match checkpoint::check_sequence_at_head(
            &head,
            &offered,
            cadence,
            signature_verifies,
            reader.as_ref().map(|tree| tree as &dyn merkle::HashReader),
        ) {
            Ok(()) if signature_verifies => "valid".to_string(),
            Ok(()) => "WIST3-E03".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        let head_after = if outcome == "valid" {
            offered.epoch_number()
        } else {
            head.epoch_number()
        };
        assert_eq!(
            case["expected_head_epoch_number"].as_u64().unwrap(),
            head_after,
            "{name}"
        );
        if let Some(unobtainable) = case["unobtainable_epoch_number"].as_u64() {
            assert_eq!(outcome, "WIST3-E01", "{name}");
            assert_eq!(unobtainable, head.epoch_number() + 1, "{name}");
            assert!(unobtainable < offered.epoch_number(), "{name}");
        }
        assert_eq!(
            case["evidence"].is_array(),
            outcome == "WIST3-E02",
            "{name}: Equivocation is the case that carries an evidence bundle"
        );
        if let Some(evidence) = case["evidence"].as_array() {
            let named: Vec<&str> = evidence.iter().map(|e| e.as_str().unwrap()).collect();
            assert_eq!(
                named,
                [
                    "verified_checkpoint",
                    "offered_checkpoint",
                    "larger_tree_leaf_hashes"
                ],
                "{name}"
            );
        }
        outcomes.insert(outcome);
    }
    assert_eq!(
        outcomes,
        ["valid", "WIST3-E01", "WIST3-E02", "WIST3-E03"]
            .map(str::to_string)
            .into_iter()
            .collect()
    );
}

#[test]
fn each_epoch_of_the_vector_log_states_its_cumulative_tree() {
    let vector = vector();
    let cadence = vector["epoch_cadence_seconds"].as_i64().unwrap();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut previous: Option<Checkpoint> = None;
    for epoch in vector["epochs"].as_array().unwrap() {
        let checkpoint = verified(epoch["checkpoint"].as_str().unwrap(), &[]).unwrap();
        assert_eq!(
            checkpoint.epoch_number(),
            epoch["epoch_number"].as_u64().unwrap()
        );
        let previous_size = leaves.len() as u64;
        let entries: Vec<Value> = epoch["entries"].as_array().unwrap().clone();
        let prior = leaves.clone();
        let summary = wist_core::epoch::verify_epoch(
            previous_size,
            &checkpoint,
            &entries,
            &LeafHashes(&prior),
            268_435_456,
        )
        .unwrap();
        leaves.extend(summary.leaf_hashes);
        assert_eq!(checkpoint.tree_size(), leaves.len() as u64);
        assert_eq!(leaves, hash_list(&epoch["leaf_hashes"]));
        assert_eq!(*checkpoint.root(), merkle::merkle_root(&leaves));
        if let Some(previous) = &previous {
            checkpoint::check_sequence(Some(previous), &checkpoint, cadence).unwrap();
            let path =
                merkle::consistency_proof(previous.tree_size(), checkpoint.tree_size(), &leaves)
                    .unwrap();
            checkpoint::check_consistency(previous, &checkpoint, &path).unwrap();
        } else {
            checkpoint::check_sequence(None, &checkpoint, cadence).unwrap();
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
        let head = case["verified_head_epoch_number"].as_u64().unwrap();
        assert!(offered.epoch_number() < head, "{name}");
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
            Equivocation::SameEpochDifferentStatement,
            Equivocation::NoConsistentPrefix
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn an_archived_checkpoint_must_sit_at_its_own_epoch_path() {
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
fn a_snapshot_position_is_read_from_the_state_file_and_the_checkpoint_the_manifest_selects() {
    let manifest_template: Value = read_json("examples/snapshot-manifest.json")["manifest"].clone();
    let mut outcomes = std::collections::BTreeSet::new();
    for case in vector()["cold_start_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let checkpoint = verified(case["checkpoint"].as_str().unwrap(), &[]).unwrap();
        let mut value = manifest_template.clone();
        for field in ["epoch_number", "tree_size", "root_hash"] {
            value[field] = case["manifest"][field].clone();
        }
        let manifest: wist_core::objects::SnapshotManifest = serde_json::from_value(value).unwrap();
        let state_tree_size = case["state_tree_size"].as_u64().unwrap();
        let outcome = wist_core::snapshot::check_state_tree_size(&manifest, state_tree_size)
            .and_then(|()| wist_core::snapshot::check_manifest_anchor(&manifest, &checkpoint));
        let outcome = match outcome {
            Ok(()) => "valid".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        let head = (outcome == "valid").then_some(manifest.epoch_number);
        assert_eq!(case["expected_head_epoch_number"].as_u64(), head, "{name}");
        outcomes.insert(outcome);
    }
    assert_eq!(
        outcomes,
        ["valid", "WIST3-E02", "WIST3-E03", "WIST3-E04"]
            .map(str::to_string)
            .into_iter()
            .collect()
    );
}

#[test]
fn the_static_surface_of_the_example_tree_is_the_octets_the_vector_fixes() {
    let epoch = read_json("vectors/wist3/epoch.json");
    let checkpoint = Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
    let leaves = entry_leaf_hashes(&epoch["entries"]);
    let tree_size = epoch["tree_size"].as_u64().unwrap();

    let tile = Tile {
        level: 0,
        index: 0,
        width: leaves.len() as u32,
    };
    assert_eq!(tile.path(), epoch["tile_0_000_p_4_path"].as_str().unwrap());
    assert_eq!(tiles::required_tiles(tree_size), vec![tile]);
    let tile_bytes =
        wist_core::crypto::hex_decode(epoch["tile_0_000_p_4"].as_str().unwrap()).unwrap();
    assert_eq!(tiles::encode_tile(&leaves), tile_bytes);
    assert_eq!(tiles::decode_tile(&tile_bytes).unwrap(), leaves);

    let bundle = EntryBundle {
        index: 0,
        width: leaves.len() as u32,
    };
    assert_eq!(
        bundle.path(),
        epoch["entry_bundle_000_p_4_path"].as_str().unwrap()
    );
    assert_eq!(tiles::required_entry_bundles(tree_size), vec![bundle]);
    let bundle_bytes =
        wist_core::crypto::hex_decode(epoch["entry_bundle_000_p_4"].as_str().unwrap()).unwrap();
    let leaf_data: Vec<Vec<u8>> = epoch["entries"]
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
        wist_core::epoch::parse_entries(&leaf_data).unwrap(),
        *epoch["entries"].as_array().unwrap()
    );

    let mut served = TileSet::new();
    served.insert_bytes(0, 0, &tile_bytes).unwrap();
    tiles::check_tree(&served, tree_size, checkpoint.root()).unwrap();
    tiles::check_entry_bundle(&leaf_data, 0, &served).unwrap();
    assert_eq!(
        TileSet::build(&leaves).serve(tree_size),
        [(tile.path(), tile_bytes.clone())].into_iter().collect()
    );

    assert!(epoch["consistency_proof_0_to_4"]
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
fn the_tile_and_bundle_forms_the_spec_excludes_are_rejected_at_the_paths_width() {
    let vector = read_json("vectors/wist3/tile-bounds.json");
    assert_eq!(vector["tile_hash_octets"].as_u64().unwrap(), 32);
    assert_eq!(
        vector["full_tile_hashes"].as_u64().unwrap(),
        u64::from(tiles::TILE_WIDTH)
    );

    let mut tile_outcomes = std::collections::BTreeSet::new();
    for case in vector["tile_form_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let octets = wist_core::crypto::hex_decode(case["octets_hex"].as_str().unwrap()).unwrap();
        let outcome = match tiles::decode_tile_at(path, &octets) {
            Ok(hashes) => {
                assert_eq!(hashes.len(), octets.len() / 32, "{name}");
                assert_eq!(
                    hashes.len() as u32,
                    tiles::path_width(path).unwrap(),
                    "{name}"
                );
                "valid".to_string()
            }
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        tile_outcomes.insert(outcome);
    }

    let mut bundle_outcomes = std::collections::BTreeSet::new();
    for case in vector["bundle_form_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let path = case["path"].as_str().unwrap();
        let octets = wist_core::crypto::hex_decode(case["octets_hex"].as_str().unwrap()).unwrap();
        let outcome = match tiles::decode_entry_bundle_at(path, &octets) {
            Ok(entries) => {
                assert_eq!(
                    entries.len() as u32,
                    tiles::path_width(path).unwrap(),
                    "{name}"
                );
                assert_eq!(
                    tiles::encode_entry_bundle(&entries).unwrap(),
                    octets,
                    "{name}: the accepted form does not re-encode to its octets"
                );
                "valid".to_string()
            }
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        bundle_outcomes.insert(outcome);
    }

    let mut range_outcomes = std::collections::BTreeSet::new();
    for case in vector["epoch_range_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let indexes: Vec<u64> = case["entry_leaf_indexes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|index| index.as_u64().unwrap())
            .collect();
        let outcome = match wist_core::epoch::check_leaf_range(
            case["size_previous"].as_u64().unwrap(),
            case["size"].as_u64().unwrap(),
            &indexes,
        ) {
            Ok(()) => "valid".to_string(),
            Err(error) => error.code().unwrap().to_string(),
        };
        assert_eq!(case["expected"], outcome, "{name}");
        range_outcomes.insert(outcome);
    }

    let both: std::collections::BTreeSet<String> = ["valid", "WIST3-E03"]
        .map(str::to_string)
        .into_iter()
        .collect();
    assert_eq!(tile_outcomes, both);
    assert_eq!(bundle_outcomes, both);
    assert_eq!(range_outcomes, both);
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
        let outcome = match wist_core::epoch::entry_leaf(&entry[field]) {
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

fn walk_history(label: &str, epochs: &[Value], key: &wist_core::checkpoint::AggregatorKey) {
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut previous: Option<Checkpoint> = None;
    for epoch in epochs {
        let checkpoint = Checkpoint::parse(epoch["checkpoint"].as_str().unwrap()).unwrap();
        let verification = checkpoint::verify(
            &checkpoint,
            checkpoint.origin(),
            std::slice::from_ref(key),
            &[],
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(verification.signers, [key.key_id.clone()].into());
        leaves.extend(entry_leaf_hashes(&epoch["entries"]));
        assert_eq!(checkpoint.tree_size(), leaves.len() as u64, "{label}");
        assert_eq!(*checkpoint.root(), merkle::merkle_root(&leaves), "{label}");
        if let Some(previous) = &previous {
            assert_eq!(checkpoint.epoch_number(), previous.epoch_number() + 1);
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
        "vectors/wist1/declaration-fields.json",
        "vectors/wist1/declaration-hosts.json",
        "vectors/wist1/recovery-admission.json",
    ] {
        let vector = read_json(path);
        let key = aggregator_key(
            vector["log_key"]["key_id"].as_str().unwrap(),
            vector["log_key"]["public_key"].as_str().unwrap(),
        );
        let mut histories = Vec::new();
        collect_histories(&vector, &mut histories);
        assert!(!histories.is_empty(), "{path}: no history of Epochs");
        for epochs in histories {
            walk_history(path, &epochs, &key);
        }
    }
}

#[test]
#[ignore = "vectors/multilog/dedup.json"]
fn each_log_of_the_deduplication_vector_seals_the_shared_delta_under_its_own_key() {
    let vector = read_json("vectors/multilog/dedup.json");
    let delta_id = vector["delta_id"].as_str().unwrap();
    for log in vector["logs"].as_array().unwrap() {
        let anchor = &log["anchor"]["anchor"];
        let key = aggregator_key(
            anchor["genesis_key"]["key_id"].as_str().unwrap(),
            anchor["genesis_key"]["public_key"].as_str().unwrap(),
        );
        let epochs = log["epochs"].as_array().unwrap();
        walk_history(log["log_id"].as_str().unwrap(), epochs, &key);
        let sealed = epochs.iter().any(|epoch| {
            epoch["entries"].as_array().unwrap().iter().any(|entry| {
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
