use std::path::PathBuf;

#[path = "conformance/declarations.rs"]
mod declarations;
#[path = "conformance/parameters.rs"]
mod parameters;
#[path = "conformance/recovery.rs"]
mod recovery;

pub fn spec_dir() -> PathBuf {
    std::env::var_os("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
}

pub fn read_json(rel: &str) -> serde_json::Value {
    let path = spec_dir().join(rel);
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).expect("invalid JSON in spec repo")
}

#[test]
fn spec_checkout_present() {
    let keys = read_json("vectors/wist1/keypair.json");
    assert_eq!(
        keys["public_key"],
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
    );
}

#[test]
fn wist1_canonical_bytes() {
    let env = read_json("vectors/wist1/envelope.json");
    let expected = std::fs::read(spec_dir().join("vectors/wist1/delta.canonical")).unwrap();
    let got = wist_core::jcs::canonicalize(&env["delta"]).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn wist1_signature_and_deterministic_resign() {
    let env = read_json("vectors/wist1/envelope.json");
    let keys = read_json("vectors/wist1/keypair.json");
    let canonical = wist_core::jcs::canonicalize(&env["delta"]).unwrap();

    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    wist_core::crypto::verify(&pk, &canonical, env["sig"]["value"].as_str().unwrap()).unwrap();

    let seed: [u8; 32] = wist_core::crypto::hex_decode(keys["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sk = wist_core::crypto::SigningKey::from_seed(&seed);
    assert_eq!(sk.sign(&canonical), env["sig"]["value"].as_str().unwrap());
}

#[test]
fn wist1_delta_id() {
    let env = read_json("vectors/wist1/envelope.json");
    let expected = std::fs::read_to_string(spec_dir().join("vectors/wist1/id.txt")).unwrap();
    assert_eq!(
        wist_core::delta::delta_id(&env["delta"]).unwrap(),
        expected.trim()
    );
}

#[test]
fn example_envelopes_verify() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    for (file, inner) in [
        ("delta.json", "delta"),
        ("publisher.json", "publisher"),
        ("feed.json", "feed"),
        ("checkpoint.json", "checkpoint"),
        ("snapshot-manifest.json", "manifest"),
        ("snapshot-index.json", "index"),
        ("snapshot-state.json", "state"),
        ("registry-update.json", "update"),
        ("log-anchor.json", "anchor"),
    ] {
        let doc = read_json(&format!("examples/{file}"));
        wist_core::envelope::verify_envelope(&doc, inner, &pk)
            .unwrap_or_else(|e| panic!("{file}: {e}"));
    }
}

#[test]
fn verify_envelope_rejects_missing_and_tampered() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    let doc = read_json("examples/delta.json");

    assert!(wist_core::envelope::verify_envelope(&doc, "nope", &pk).is_err());

    let mut no_sig_value = doc.clone();
    no_sig_value["sig"].as_object_mut().unwrap().remove("value");
    assert!(wist_core::envelope::verify_envelope(&no_sig_value, "delta", &pk).is_err());

    let mut bad_sig = doc.clone();
    let mut sig = bad_sig["sig"]["value"].as_str().unwrap().to_owned();
    let flipped = if sig.ends_with('A') { 'B' } else { 'A' };
    sig.replace_range(sig.len() - 1.., &flipped.to_string());
    bad_sig["sig"]["value"] = sig.into();
    assert!(wist_core::envelope::verify_envelope(&bad_sig, "delta", &pk).is_err());

    let mut tampered_field = doc.clone();
    tampered_field["delta"]["url"] = "https://example.com/blog/post-2".into();
    assert!(wist_core::envelope::verify_envelope(&tampered_field, "delta", &pk).is_err());
}

#[test]
fn payload_commitment_recomputes_and_tamper_fails() {
    let payload = read_json("examples/payload.json");
    let delta = read_json("examples/delta.json");
    let salt = payload["salt"].as_str().unwrap();
    let declared = delta["delta"]["payload"]["commitment"].as_str().unwrap();
    wist_core::delta::verify_commitment(salt, &payload["content"], declared).unwrap();
    assert_eq!(
        wist_core::delta::content_bytes(&payload["content"]).unwrap(),
        delta["delta"]["payload"]["bytes"].as_u64().unwrap()
    );

    let mut tampered = payload["content"].clone();
    let ex = tampered["extract"].as_str().unwrap().to_owned() + "x";
    tampered["extract"] = ex.into();
    assert!(wist_core::delta::verify_commitment(salt, &tampered, declared).is_err());
    assert!(wist_core::delta::verify_commitment("AAAA", &payload["content"], declared).is_err());
}

#[test]
fn wist3_merkle_vectors() {
    let block = read_json("vectors/wist3/block.json");
    let leaves: Vec<[u8; 32]> = block["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| wist_core::merkle::leaf_hash(&wist_core::jcs::canonicalize(e).unwrap()))
        .collect();
    let root = wist_core::merkle::merkle_root(&leaves).unwrap();
    assert_eq!(
        format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
        block["header"]["merkle_root"].as_str().unwrap()
    );

    let proof = read_json("vectors/wist3/inclusion-proof.json");
    let idx = proof["index"].as_u64().unwrap() as usize;
    let n = proof["entry_count"].as_u64().unwrap() as usize;
    assert_eq!(n, block["header"]["entry_count"].as_u64().unwrap() as usize);
    let path: Vec<[u8; 32]> = proof["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            wist_core::crypto::hex_decode(h.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let leaf = wist_core::merkle::leaf_hash(
        &wist_core::jcs::canonicalize(&block["entries"][idx]).unwrap(),
    );
    wist_core::merkle::verify_inclusion(&leaf, idx, n, &path, &root).unwrap();
    assert_eq!(wist_core::merkle::audit_path(idx, &leaves).unwrap(), path);
}

#[test]
fn example_block_and_checkpoint() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    let block = read_json("examples/block.json");
    let cp = read_json("examples/checkpoint.json");

    wist_core::block::verify_block(&block, &pk).unwrap();
    wist_core::block::verify_checkpoint_binding(&cp, &block).unwrap();

    let mut bad = block.clone();
    bad["header"]["entry_count"] = 99.into();
    assert!(wist_core::block::verify_block(&bad, &pk).is_err());

    let mut swapped = block.clone();
    let e0 = swapped["entries"][0].clone();
    swapped["entries"][0] = swapped["entries"][1].clone();
    swapped["entries"][1] = e0;
    assert!(wist_core::block::verify_block(&swapped, &pk).is_err());
}

#[test]
fn entry_count_mismatch_survives_resign() {
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();
    let seed: [u8; 32] = wist_core::crypto::hex_decode(keys["seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sk = wist_core::crypto::SigningKey::from_seed(&seed);
    let block = read_json("examples/block.json");

    let mut control = block.clone();
    let control_sig = sk.sign(&wist_core::jcs::canonicalize(&control["header"]).unwrap());
    control["sig"]["value"] = control_sig.into();
    wist_core::block::verify_block(&control, &pk).unwrap();

    let mut mutated = block.clone();
    let real_count = mutated["header"]["entry_count"].as_u64().unwrap();
    mutated["header"]["entry_count"] = (real_count + 1).into();
    let mutated_sig = sk.sign(&wist_core::jcs::canonicalize(&mutated["header"]).unwrap());
    mutated["sig"]["value"] = mutated_sig.into();

    let err = wist_core::block::verify_block(&mutated, &pk).unwrap_err();
    assert!(
        err.to_string().contains("entry_count"),
        "expected entry_count mismatch past a passing signature check, got: {err}"
    );
}

#[test]
fn genesis_chain_link() {
    let block = read_json("vectors/wist3/block.json");
    assert_eq!(block["header"]["block_number"], 0);
    wist_core::block::verify_chain_link(&block["header"], "sha256:genesis").unwrap();
    assert!(wist_core::block::verify_chain_link(&block["header"], "sha256:0000").is_err());
}

#[test]
fn chain_link_rejects_non_genesis_block_zero_even_when_prev_matches() {
    let block = read_json("vectors/wist3/block.json");
    let mut header = block["header"].clone();
    assert_eq!(header["block_number"], 0);
    header["prev_block_hash"] = "sha256:notgenesis".into();
    let err = wist_core::block::verify_chain_link(&header, "sha256:notgenesis").unwrap_err();
    assert!(
        err.to_string().contains("genesis"),
        "expected the block-0-must-carry-genesis branch, got: {err}"
    );
}

#[test]
fn wist3_snapshot_records_digest() {
    let v = read_json("vectors/wist3/snapshot-records.json");
    let records: Vec<_> = v["records"].as_array().unwrap().clone();
    for r in &records {
        wist_core::snapshot::check_record_shape(r).unwrap();
    }
    let digest = wist_core::snapshot::content_digest(&records).unwrap();
    assert_eq!(digest, v["content_digest"].as_str().unwrap());

    let mut reversed = records.clone();
    reversed.reverse();
    assert_eq!(
        wist_core::snapshot::content_digest(&reversed).unwrap(),
        digest
    );

    let manifest = read_json("examples/snapshot-manifest.json");
    assert_eq!(
        manifest["manifest"]["content_digest"].as_str().unwrap(),
        digest
    );
}

#[test]
fn state_digest_matches_manifest() {
    let state = read_json("examples/snapshot-state.json");
    let manifest = read_json("examples/snapshot-manifest.json");
    let entries: Vec<_> = state["state"]["entries"].as_array().unwrap().clone();
    assert_eq!(
        wist_core::snapshot::state_digest(&entries).unwrap(),
        manifest["manifest"]["state"]["state_digest"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn every_example_parses_typed() {
    use wist_core::objects as o;
    fn p<T: serde::de::DeserializeOwned>(file: &str) -> T {
        let bytes = std::fs::read(spec_dir().join("examples").join(file)).unwrap();
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"))
    }
    let _: o::DeltaEnvelope = p("delta.json");
    let _: o::PublisherEnvelope = p("publisher.json");
    let _: o::FeedEnvelope = p("feed.json");
    let _: o::Block = p("block.json");
    let _: o::CheckpointEnvelope = p("checkpoint.json");
    let _: o::LogAnchorEnvelope = p("log-anchor.json");
    let _: o::SnapshotIndexEnvelope = p("snapshot-index.json");
    let _: o::SnapshotManifestEnvelope = p("snapshot-manifest.json");
    let _: o::SnapshotStateEnvelope = p("snapshot-state.json");
    let _: o::Status = p("status.json");
    let _: o::Payload = p("payload.json");
    let _: o::RegistryUpdateEnvelope = p("registry-update.json");
}

#[test]
fn unknown_field_rejected() {
    let mut doc = read_json("examples/delta.json");
    doc["delta"]["surprise"] = 1.into();
    let res: Result<wist_core::objects::DeltaEnvelope, _> = serde_json::from_value(doc);
    assert!(res.is_err());
}

#[test]
fn state_tuple_over_arity_rejected() {
    let mut doc = read_json("examples/snapshot-state.json");
    doc["state"]["entries"][1]
        .as_array_mut()
        .unwrap()
        .push("extra".into());
    let res: Result<wist_core::objects::SnapshotStateEnvelope, _> = serde_json::from_value(doc);
    assert!(res.is_err());
}

#[test]
fn required_nullable_field_must_be_present() {
    let mut omitted = read_json("examples/feed.json");
    omitted["feed"].as_object_mut().unwrap().remove("next");
    let res: Result<wist_core::objects::FeedEnvelope, _> = serde_json::from_value(omitted);
    assert!(res.is_err());

    let mut present_null = read_json("examples/feed.json");
    present_null["feed"]["next"] = serde_json::Value::Null;
    let res: Result<wist_core::objects::FeedEnvelope, _> = serde_json::from_value(present_null);
    assert!(res.is_ok());
}

#[test]
fn wist2_link_extraction_vector() {
    let vec = read_json("vectors/wist2/link-extraction.json");
    let cap = vec["links_cap_bytes"].as_u64().unwrap() as usize;
    for case in vec["cases"].as_array().unwrap() {
        let html = wist_core::crypto::hex_decode(case["html_hex"].as_str().unwrap()).unwrap();
        let (urls, total) = wist_core::extract::extract_links(
            &html,
            case["base_url"].as_str().unwrap(),
            case["publisher_domain"].as_str().unwrap(),
        );
        let member = wist_core::extract::links_member(&urls, total, cap);
        assert_eq!(member, case["expected"], "{}", case["label"]);
    }
}

#[test]
fn wist2_text_extraction_vector() {
    let vec = read_json("vectors/wist2/text-extraction.json");
    for case in vec["extraction"].as_array().unwrap() {
        let html = wist_core::crypto::hex_decode(case["html_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            wist_core::extract::extract_text(&html),
            case["expected"].as_str().unwrap(),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn manifest_anchored_to_block() {
    let manifest = read_json("examples/snapshot-manifest.json");
    let block = read_json("examples/block.json");
    assert_eq!(
        manifest["manifest"]["anchor_block_hash"].as_str().unwrap(),
        wist_core::block::block_hash(&block["header"]).unwrap()
    );
}

#[test]
fn wist1_host_canonicalization() {
    let v = read_json("vectors/wist1/host-canonicalization.json");
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let got = wist_core::host::canonical_host(input);
        match case["expected"].as_str() {
            Some(expected) => assert_eq!(got.as_deref().ok(), Some(expected), "{name}"),
            None => assert!(
                got.is_err(),
                "{name}: expected no canonicalization, got {got:?}"
            ),
        }
    }
}

#[test]
fn wist1_declaration_host_spelling() {
    let vector = read_json("vectors/wist1/declaration-hosts.json");
    for case in vector["hosts"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let canonical = wist_core::host::canonical_host(input);
        assert_eq!(
            canonical.as_deref().ok(),
            case["canonical"].as_str(),
            "{}",
            case["name"]
        );
        assert_eq!(
            canonical.as_deref().ok() == Some(input),
            case["expected"] == "well_formed",
            "{}",
            case["name"]
        );
    }
    let author =
        wist_core::crypto::PublicKey::from_b64u(vector["author_key"].as_str().unwrap()).unwrap();
    for case in vector["cases"].as_array().unwrap() {
        let envelope = &case["envelope"];
        let publisher = &envelope["publisher"];
        let bytes = wist_core::jcs::canonicalize(publisher).unwrap();
        wist_core::crypto::verify(&author, &bytes, envelope["sig"]["value"].as_str().unwrap())
            .unwrap();
        let valid = std::iter::once(publisher["domain"].as_str().unwrap())
            .chain(
                publisher["subdomain_scope"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap()),
            )
            .all(|host| wist_core::host::canonical_host(host).as_deref().ok() == Some(host));
        assert_eq!(valid, case["expected"] == "initial", "{}", case["name"]);
    }
}

#[test]
fn wist1_ed25519_verification_profile() {
    let v = read_json("vectors/wist1/ed25519-strictness.json");
    let msg = wist_core::crypto::hex_decode(v["message_hex"].as_str().unwrap()).unwrap();
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let key_raw =
            wist_core::crypto::hex_decode(case["public_key_hex"].as_str().unwrap()).unwrap();
        let sig_raw =
            wist_core::crypto::hex_decode(case["signature_hex"].as_str().unwrap()).unwrap();
        let sig_b64u = wist_core::crypto::b64u_encode(&sig_raw);
        let accepted = match wist_core::crypto::PublicKey::from_b64u(
            &wist_core::crypto::b64u_encode(&key_raw),
        ) {
            Ok(pk) => wist_core::crypto::verify(&pk, &msg, &sig_b64u).is_ok(),
            Err(_) => false,
        };
        let expected = case["expected"].as_str().unwrap() == "accept";
        assert_eq!(accepted, expected, "{name}");
    }
}

#[test]
fn wist3_empty_block_verifies() {
    let v = read_json("vectors/wist3/empty-block.json");
    let block = &v["block"];
    let keys = read_json("vectors/wist1/keypair.json");
    let pk = wist_core::crypto::PublicKey::from_b64u(keys["public_key"].as_str().unwrap()).unwrap();

    assert_eq!(
        wist_core::block::block_hash(&block["header"]).unwrap(),
        v["block_hash"].as_str().unwrap()
    );
    wist_core::block::verify_block(block, &pk).unwrap();
    let entries: Vec<serde_json::Value> = block["entries"].as_array().unwrap().clone();
    assert!(entries.is_empty());
    let root = wist_core::merkle::leaf_hash(&[]);
    assert_eq!(
        format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
        block["header"]["merkle_root"].as_str().unwrap(),
        "the empty tree is SHA-256(0x00), not RFC 6962's SHA-256(\"\")"
    );
    assert_ne!(
        block["header"]["merkle_root"].as_str().unwrap(),
        v["rfc6962_empty_root"].as_str().unwrap()
    );
}

fn string_list(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn wist1_keyset_at_height_vectors() {
    use wist_core::keyset::{key_set_at, verifies_at, SealedDeclaration};

    let vector = read_json("vectors/wist1/keyset-at-height.json");
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let declarations: Vec<SealedDeclaration> = case["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| SealedDeclaration {
                seq: d["seq"].as_u64().unwrap(),
                height: d["height"].as_u64().unwrap(),
                keys: string_list(&d["keys"]),
            })
            .collect();
        let expected = &case["expected"];

        for row in expected["key_set_at"].as_array().unwrap() {
            let height = row["height"].as_u64().unwrap();
            assert_eq!(
                key_set_at(&declarations, height),
                string_list(&row["keys"]),
                "{name}: key set at height {height}"
            );
        }

        let mut verifies = Vec::new();
        let mut rejected = Vec::new();
        for delta in case["deltas"].as_array().unwrap() {
            let delta_id = delta["delta_id"].as_str().unwrap().to_string();
            let height = delta["height"].as_u64().unwrap();
            let signer = delta["signer"].as_str().unwrap();
            if verifies_at(&declarations, height, signer) {
                verifies.push(delta_id);
            } else {
                rejected.push(delta_id);
            }
        }
        assert_eq!(
            verifies,
            string_list(&expected["verifies"]),
            "{name}: verifies"
        );
        assert_eq!(
            rejected,
            string_list(&expected["rejected"]),
            "{name}: rejected"
        );
    }
}

#[test]
fn wist2_page_keyset_vectors() {
    use wist_core::keyset::{
        page_key_set_current, page_key_set_next, page_resolution, DeclarationAtInstant,
        PageResolution,
    };

    let vector = read_json("vectors/wist2/page-keyset.json");
    for case in vector["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let declarations: Vec<DeclarationAtInstant> = case["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| DeclarationAtInstant {
                seq: d["seq"].as_u64().unwrap(),
                sealed_at_s: d["sealed_at_s"].as_i64().unwrap(),
                keys: string_list(&d["keys"]),
            })
            .collect();
        let pages = case["pages"].as_array().unwrap();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(pages.len(), expected.len(), "{name}: one row per page");

        for (page, row) in pages.iter().zip(expected) {
            let number = page["page"].as_u64().unwrap();
            assert_eq!(row["page"].as_u64().unwrap(), number, "{name}: row order");
            let generated_at_s = page["generated_at_s"].as_i64().unwrap();
            let signer = page["signer"].as_str().unwrap();

            assert_eq!(
                page_key_set_current(&declarations, generated_at_s),
                string_list(&row["current_keys"]),
                "{name}: page {number} current key set"
            );
            assert_eq!(
                page_key_set_next(&declarations, generated_at_s),
                string_list(&row["next_keys"]),
                "{name}: page {number} next key set"
            );

            let resolution = page_resolution(&declarations, generated_at_s, signer);
            let expected_under = match row["verifies_under"].as_str() {
                Some("current") => Some(PageResolution::Current),
                Some("next") => Some(PageResolution::Next),
                Some(other) => panic!("{name}: unknown resolution {other}"),
                None => None,
            };
            assert_eq!(
                resolution, expected_under,
                "{name}: page {number} verifies under"
            );
            assert_eq!(
                resolution.is_some(),
                row["verifies"].as_bool().unwrap(),
                "{name}: page {number} verifies"
            );
        }
    }
}

#[test]
fn wist4_withdrawal_vectors() {
    use wist_core::withdrawal::{Disposition, SealedDelta, WithdrawalReplay};
    let vector = read_json("vectors/wist4/withdrawal.json");
    let log_key =
        wist_core::crypto::PublicKey::from_b64u(vector["log_key"]["public_key"].as_str().unwrap())
            .unwrap();
    let log_key_id = vector["log_key"]["key_id"].as_str().unwrap();
    let sealed: Vec<(String, String, u64)> = vector["sealed_deltas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d["delta_id"].as_str().unwrap().into(),
                d["publisher"].as_str().unwrap().into(),
                d["height"].as_u64().unwrap(),
            )
        })
        .collect();
    let mut replay = WithdrawalReplay::new();
    let mut codes = std::collections::BTreeSet::new();
    for case in vector["act_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let disposition = replay.apply_raw(
            case["height"].as_u64().unwrap(),
            case["envelope_json"].as_str().unwrap().as_bytes(),
            |key_id| (key_id == log_key_id).then(|| log_key.clone()),
            |delta_id| {
                sealed.iter().find(|(id, _, _)| id == delta_id).map_or(
                    SealedDelta::Absent,
                    |(_, publisher, height)| SealedDelta::Known {
                        publisher: publisher.clone(),
                        height: *height,
                    },
                )
            },
        );
        match disposition {
            Disposition::Accepted {
                withdrawn_height, ..
            } => {
                assert!(case["code"].is_null(), "{label}");
                assert_eq!(
                    Some(withdrawn_height),
                    case["withdrawn_height"].as_u64(),
                    "{label}"
                );
                codes.insert(None);
            }
            Disposition::Rejected(code) => {
                assert_eq!(Some(code), case["code"].as_str(), "{label}");
                assert!(case["withdrawn_height"].is_null(), "{label}");
                codes.insert(Some(code));
            }
            Disposition::NotWithdrawal => panic!("{label}: not a withdrawal"),
        }
    }
    assert_eq!(
        codes,
        [None, Some("WIST4-E11"), Some("WIST4-E04")]
            .into_iter()
            .collect()
    );
    let tuples: Vec<serde_json::Value> = replay
        .entries()
        .into_iter()
        .map(|entry| {
            serde_json::to_value(wist_core::objects::StateEntry::Withdrawal(entry)).unwrap()
        })
        .collect();
    let mut expected = vector["state_tuples"].as_array().unwrap().clone();
    expected.sort_by_key(|t| t.to_string());
    let mut got = tuples;
    got.sort_by_key(|t| t.to_string());
    assert_eq!(got, expected);
    let mut resumed = WithdrawalReplay::new();
    for entry in replay.entries() {
        resumed.adopt(&entry.delta_id, &entry.publisher, entry.sealing_height);
    }
    assert_eq!(resumed.entries().len(), replay.entries().len());
    assert_eq!(
        replay.apply_raw(
            9,
            br#"{"update": {"wist_version": "1.0.0", "action": "parameter_change", "subject": "quota_base", "effective_at": "2026-08-05T12:00:00Z", "details": {"parameter": "quota_base", "value": 2}}, "sig": {"key_id": "x", "alg": "Ed25519", "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#,
            |_| None,
            |_| SealedDelta::Absent
        ),
        Disposition::NotWithdrawal
    );
    let duplicate = br#"{"update": {"a": 1, "a": 2}, "sig": {}}"#;
    assert_eq!(
        replay.apply_raw(9, duplicate, |_| None, |_| SealedDelta::Absent),
        Disposition::Rejected("WIST1-E05")
    );
}

#[test]
fn wist4_parameter_in_force_vectors() {
    use wist_core::parameters::{value_in_force, ParameterChange};

    let vector = read_json("vectors/wist4/parameter-in-force.json");
    for case in vector["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let default = case["default"].as_i64().unwrap();
        let changes: Vec<ParameterChange> = case["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| ParameterChange {
                block_number: c["block_number"].as_u64().unwrap(),
                entry_index: c["entry_index"].as_u64().unwrap(),
                effective_at_s: c["effective_at_s"].as_i64().unwrap(),
                value: c["value"].as_i64().unwrap(),
            })
            .collect();

        for query in case["queries"].as_array().unwrap() {
            let t_s = query["t_s"].as_i64().unwrap();
            let expected_value = query["value"].as_i64().unwrap();
            let expected_from = query["from_index"].as_u64().map(|i| i as usize);
            assert_eq!(
                value_in_force(default, &changes, t_s),
                (expected_value, expected_from),
                "{label}: value in force at {t_s}"
            );
        }
    }
}

#[test]
fn wist3_chain_materialization_vectors() {
    use wist_core::chain::ChainTips;

    let vector = read_json("vectors/wist3/chain-materialization.json");
    for case in vector["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let mut tips = ChainTips::new();
        let mut ignored = Vec::new();
        for (index, delta) in case["deltas"].as_array().unwrap().iter().enumerate() {
            let applied = delta["eligible"] != false
                && tips.apply(
                    delta["publisher"].as_str().unwrap(),
                    delta["url"].as_str().unwrap(),
                    delta["id"].as_str().unwrap(),
                    delta["prev"].as_str(),
                );
            if !applied {
                ignored.push(index as u64);
            }
        }
        let expected_ignored: Vec<u64> = case["ignored_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap())
            .collect();
        assert_eq!(ignored, expected_ignored, "{label}: ignored indices");

        let expected_tips: Vec<(String, String, String)> = case["tips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["publisher"].as_str().unwrap().to_string(),
                    t["url"].as_str().unwrap().to_string(),
                    t["delta"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let got: Vec<(String, String, String)> = tips
            .tips()
            .map(|(p, u, d)| (p.to_string(), u.to_string(), d.to_string()))
            .collect();
        assert_eq!(got, expected_tips, "{label}: tips");
        for (publisher, url, delta) in &expected_tips {
            assert_eq!(
                tips.tip(publisher, url),
                Some(delta.as_str()),
                "{label}: tip of {publisher} {url}"
            );
        }
    }
}

fn parameter_default(name: &str) -> i64 {
    wist_core::parameters::spec(name).unwrap().default.unwrap()
}

#[test]
fn wist4_parameter_catalog() {
    use wist_core::parameters::{spec, validate_value, PARAMS, WIRE_INTEGER_MAX};
    let schema = read_json("schemas/registry-update.schema.json");
    let clause = schema["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            c["if"]["properties"]["update"]["properties"]["action"]["const"] == "parameter_change"
        })
        .unwrap();
    let details = &clause["then"]["properties"]["update"]["properties"]["details"];
    let identifiers = details["properties"]["parameter"]["enum"]
        .as_array()
        .unwrap();
    assert_eq!(PARAMS.len(), identifiers.len());
    for ident in identifiers {
        assert!(spec(ident.as_str().unwrap()).is_some(), "{ident}");
    }
    for clause in details["allOf"].as_array().unwrap() {
        let name = clause["if"]["properties"]["parameter"]["const"]
            .as_str()
            .unwrap();
        let bounds = &clause["then"]["properties"]["value"];
        let p = spec(name).unwrap();
        assert_eq!(p.min, bounds["minimum"].as_i64(), "{name}");
        assert_eq!(p.max, bounds["maximum"].as_i64(), "{name}");
    }
    for p in PARAMS {
        validate_value(p.name, p.default.unwrap()).unwrap();
        validate_value(p.name, p.min.unwrap_or(-WIRE_INTEGER_MAX)).unwrap();
        validate_value(p.name, p.max.unwrap_or(WIRE_INTEGER_MAX)).unwrap();
        assert!(validate_value(p.name, p.min.unwrap_or(-WIRE_INTEGER_MAX) - 1).is_err());
        assert!(validate_value(p.name, p.max.unwrap_or(WIRE_INTEGER_MAX) + 1).is_err());
    }
    for name in [
        "sampling_floor",
        "similarity_consistent",
        "shingle_size",
        "c_cap",
        "unknown",
    ] {
        assert!(validate_value(name, 1).is_err());
    }
    wist_core::parameters::validate_combinations(parameter_default).unwrap();
}

#[test]
fn signed_delta_publisher_fields_and_ids() {
    let vector = read_json("vectors/wist1/delta-attribution.json");
    for case in vector["cases"].as_array().unwrap() {
        let original = case.clone();
        for (index, envelope) in case["envelopes"].as_array().unwrap().iter().enumerate() {
            let valid_field = case["expected"][index] != "WIST1-E14";
            assert_eq!(
                wist_core::delta::publisher(&envelope["delta"]).is_ok(),
                valid_field,
                "{}",
                case["name"]
            );
            assert_eq!(
                serde_json::from_value::<wist_core::objects::DeltaEnvelope>(envelope.clone())
                    .is_ok(),
                valid_field,
                "{}",
                case["name"]
            );
            assert_eq!(
                wist_core::delta::delta_id(&envelope["delta"]).unwrap(),
                case["delta_ids"][index]
            );
        }
        assert_eq!(*case, original);
    }
    for case in vector["cases"].as_array().unwrap().iter().take(2) {
        assert_ne!(case["delta_ids"][0], case["delta_ids"][1]);
        assert_ne!(
            case["envelopes"][0]["sig"]["value"],
            case["envelopes"][1]["sig"]["value"]
        );
    }
}
