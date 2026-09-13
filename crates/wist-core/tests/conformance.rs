use std::path::PathBuf;

#[path = "conformance/canary.rs"]
mod canary;
#[path = "conformance/observer.rs"]
mod observer;
#[path = "conformance/parameters.rs"]
mod parameters;
#[path = "conformance/recovery.rs"]
mod recovery;
#[path = "conformance/sanctions.rs"]
mod sanctions;

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
        ("audit-record.json", "record"),
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
    let _: o::AuditRecordEnvelope = p("audit-record.json");
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
    let guard = vec["min_observed_words"].as_u64().unwrap();
    for case in vec["extraction"].as_array().unwrap() {
        let html = wist_core::crypto::hex_decode(case["html_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            wist_core::extract::extract_text(&html),
            case["expected"].as_str().unwrap(),
            "{}",
            case["label"]
        );
    }
    for case in vec["similarity"].as_array().unwrap() {
        let got = wist_core::extract::similarity(
            case["reference"].as_str().unwrap(),
            case["observed"].as_str().unwrap(),
            guard,
            case["shingle_size"].as_u64().unwrap() as usize,
        );
        let expected = case["similarity"].as_u64();
        assert_eq!(got, expected, "{}", case["label"]);
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
fn wist4_link_agreement_vector() {
    let v = read_json("vectors/wist4/link-agreement.json");
    for case in v["cases"].as_array().unwrap() {
        let declared: Vec<String> = case["declared_urls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u.as_str().unwrap().to_string())
            .collect();
        let observed: Vec<String> = case["observed_urls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u.as_str().unwrap().to_string())
            .collect();
        let got = wist_core::agreement::link_agreement(
            &declared,
            &observed,
            case["declared_total"].as_u64().unwrap(),
            case["observed_total"].as_u64().unwrap(),
        );
        assert_eq!(
            got,
            case["link_agreement"].as_u64().unwrap(),
            "case {}",
            case["label"]
        );
    }
}

#[test]
fn wist4_record_scores_follow_link_profile_vectors() {
    use wist_core::verdict::{record_scores_valid, ChangeType, Thresholds, Verdict};

    let vector = read_json("vectors/wist4/link-agreement.json");
    let verdicts = [
        ("consistent", Verdict::Consistent),
        ("dynamic_variance", Verdict::DynamicVariance),
        ("inconsistent", Verdict::Inconsistent),
        ("link_variance", Verdict::LinkVariance),
        ("link_inconsistent", Verdict::LinkInconsistent),
        ("unreachable", Verdict::Unreachable),
        ("not_auditable", Verdict::NotAuditable),
    ];
    for case in vector["verdict_profiles"]["cases"].as_array().unwrap() {
        let profile = &case["expected_profile"];
        let thresholds = Thresholds {
            similarity_consistent: profile["similarity_consistent"].as_u64().unwrap(),
            similarity_variance_floor: profile["similarity_variance_floor"].as_u64().unwrap(),
            link_agreement_consistent: profile["link_agreement_consistent"].as_u64().unwrap(),
            link_variance_floor: profile["link_variance_floor"].as_u64().unwrap(),
            min_observed_words: profile["min_observed_words"].as_u64().unwrap(),
        };
        for reading in case["readings"].as_array().unwrap() {
            let change = change_type(reading["reference_change"].as_str().unwrap());
            for (name, verdict) in verdicts {
                let valid = record_scores_valid(
                    change,
                    verdict,
                    reading["similarity"].as_u64(),
                    reading["link_agreement"].as_u64(),
                    &thresholds,
                );
                assert_eq!(
                    valid,
                    change != ChangeType::Delete && reading["verdict"] == name,
                    "{}: {reading}, {name}",
                    case["label"]
                );
                if change == ChangeType::Delete {
                    assert_eq!(
                        record_scores_valid(
                            change,
                            verdict,
                            reading["similarity"].as_u64(),
                            None,
                            &thresholds,
                        ),
                        reading["verdict"] == name
                    );
                }
            }
        }
    }
}

#[test]
fn wist4_audit_commitments_vector() {
    let v = read_json("vectors/wist4/audit-commitments.json");
    let payload = read_json("examples/payload.json");
    let salt = payload["salt"].as_str().unwrap();
    for (name, c) in v["commitments"].as_object().unwrap() {
        let msg = wist_core::crypto::hex_decode(c["message_hex"].as_str().unwrap()).unwrap();
        let expected = c["value"].as_str().unwrap();
        let got = wist_core::delta::make_commitment_bytes(salt, &msg).unwrap();
        assert_eq!(got, expected, "commitment {name}");
        wist_core::delta::verify_commitment_bytes(salt, &msg, expected).unwrap();
        assert!(wist_core::delta::verify_commitment_bytes(salt, b"tampered", expected).is_err());
    }
}

#[test]
fn wist4_decay_table_vendored_and_normative() {
    let spec_bytes = std::fs::read(spec_dir().join("vectors/wist4/decay-table.json")).unwrap();
    assert_eq!(spec_bytes, wist_core::reputation::DECAY_TABLE_BYTES);
    let t = wist_core::reputation::DecayTable::from_bytes(&spec_bytes).unwrap();
    assert_eq!(t.decay(0), 1_000_000_000);
    assert_eq!(t.decay(30), 846_481_724);
    assert_eq!(t.decay(1825), 39_512);
    assert_eq!(t.decay(1826), 0);
    assert_eq!(t.decay(u64::MAX), 0);
    for day in 1..=1825u64 {
        assert!(
            t.decay(day) < t.decay(day - 1),
            "not strictly decreasing at {day}"
        );
    }
    let b = wist_core::reputation::DecayTable::builtin();
    assert_eq!(b.decay(30), 846_481_724);
    let mut tampered = spec_bytes.clone();
    let n = tampered.len();
    tampered[n / 2] ^= 1;
    assert!(wist_core::reputation::DecayTable::from_bytes(&tampered).is_err());
}

#[test]
fn wist4_reputation_vectors() {
    let v = read_json("vectors/wist4/reputation.json");
    let table = wist_core::reputation::DecayTable::builtin();
    let mut cases: Vec<&serde_json::Value> = vec![&v["worked_example"]];
    cases.extend(v["boundary"].as_array().unwrap().iter());
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let a = case["A"].as_u64().unwrap();
        let c = case["C"].as_u64().unwrap();
        let base = wist_core::reputation::base_u(a);
        assert_eq!(base, case["base_u"].as_u64().unwrap(), "{label} base_u");
        let confirmed: Vec<(u8, u64)> = case["inconsistencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                assert_eq!(
                    table.decay(i["t_days"].as_u64().unwrap()),
                    i["decay"].as_u64().unwrap(),
                    "{label} decay"
                );
                (
                    i["severity"].as_u64().unwrap() as u8,
                    i["t_days"].as_u64().unwrap(),
                )
            })
            .collect();
        let pen = wist_core::reputation::penalty_n(&confirmed, table);
        assert_eq!(
            pen,
            case["penalty_n"].as_u64().unwrap() as u128,
            "{label} penalty_n"
        );
        let c1 = (c.min(500) + 1) as u128;
        assert_eq!(
            base as u128 * c1 * 1_000_000_000,
            case["numerator"].as_u64().unwrap() as u128,
            "{label} numerator"
        );
        assert_eq!(
            c1 * 1_000_000_000 + 5 * pen,
            case["denominator"].as_u64().unwrap() as u128,
            "{label} denominator"
        );
        let f = wist_core::reputation::reputation_formula_u(base, c, pen);
        assert_eq!(f, case["formula_u"].as_u64().unwrap(), "{label} formula_u");
        assert_eq!(
            wist_core::reputation::is_provisional(a, c),
            case["provisional"].as_bool().unwrap(),
            "{label} provisional"
        );
        let rep = wist_core::reputation::apply_provisional_cap(f, a, c);
        assert_eq!(
            rep,
            case["reputation_u"].as_u64().unwrap(),
            "{label} reputation_u"
        );
        assert_eq!(
            wist_core::reputation::quota_q(rep),
            case["Q"].as_u64().unwrap(),
            "{label} Q"
        );
        assert_eq!(
            wist_core::sampling::p_1e7(rep, false, false, &wist_core::sampling::DEFAULT_SAMPLING),
            case["p_1e7"].as_u64().unwrap(),
            "{label} p_1e7"
        );
    }
}

#[test]
fn wist4_reputation_worked_example_day_counts() {
    let v = read_json("vectors/wist4/reputation.json");
    let s = &v["worked_example"]["sealed_at"];
    assert_eq!(
        s["first_delta_block"].as_str().unwrap(),
        "2026-08-02T13:00:00Z"
    );
    assert_eq!(
        s["confirming_block"].as_str().unwrap(),
        "2027-08-07T17:00:00Z"
    );
    assert_eq!(s["block_n"].as_str().unwrap(), "2027-09-06T18:00:00Z");
    const FIRST_DELTA: i64 = 1_785_675_600;
    const CONFIRMING: i64 = 1_817_658_000;
    const BLOCK_N: i64 = 1_820_253_600;
    assert_eq!(
        wist_core::reputation::whole_days(FIRST_DELTA, BLOCK_N).unwrap(),
        400
    );
    assert_eq!(
        wist_core::reputation::whole_days(CONFIRMING, BLOCK_N).unwrap(),
        30
    );
    assert!(wist_core::reputation::whole_days(BLOCK_N, CONFIRMING).is_err());
}

#[test]
fn wist4_sampling_vector() {
    let v = read_json("vectors/wist4/sampling.json");
    let raw = std::fs::read_to_string(spec_dir().join("vectors/wist4/sampling.json")).unwrap();
    let pk: [u8; 32] = wist_core::crypto::b64u_decode(v["auditor_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let alpha =
        wist_core::sampling::alpha_from_block_hash(v["block_hash"].as_str().unwrap()).unwrap();
    assert_eq!(
        wist_core::crypto::hex_encode(&alpha),
        v["alpha_hex"].as_str().unwrap()
    );
    let pi: [u8; 80] = wist_core::crypto::hex_decode(v["vrf_proof_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let beta = wist_core::vrf::verify(&pk, &alpha, &pi).unwrap();
    assert_eq!(
        wist_core::crypto::hex_encode(&beta),
        v["beta_hex"].as_str().unwrap()
    );
    for row in v["selection"].as_array().unwrap() {
        let label = row["label"].as_str().unwrap();
        let d = wist_core::sampling::draw(&beta, row["delta_id"].as_str().unwrap());
        assert_eq!(
            format!("{d:016x}"),
            row["draw_first8_hex"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(d, row["D"].as_u64().unwrap(), "{label}");
        let p = wist_core::sampling::p_1e7(
            row["reputation_u"].as_u64().unwrap(),
            false,
            false,
            &wist_core::sampling::DEFAULT_SAMPLING,
        );
        assert_eq!(p, row["p_1e7"].as_u64().unwrap(), "{label}");
        let lhs = d as u128 * 10_000_000;
        let rhs = (p as u128) << 64;
        assert!(
            raw.contains(&format!("\"lhs\": {lhs}")),
            "{label} lhs {lhs} not in vector"
        );
        assert!(
            raw.contains(&format!("\"rhs\": {rhs}")),
            "{label} rhs {rhs} not in vector"
        );
        assert_eq!(
            wist_core::sampling::selected(d, p),
            row["selected"].as_bool().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn wist4_sampling_signed_parameter_rates() {
    use wist_core::sampling::{p_1e7, SamplingConstants};

    let vector = read_json("vectors/wist4/sampling.json");
    let cases = vector["parameter_rate_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    for case in cases {
        let params = &case["parameters"];
        let constants = SamplingConstants {
            floor_1e7: params["floor_1e7"].as_u64().unwrap(),
            ceiling_1e7: params["ceiling_1e7"].as_u64().unwrap(),
            slope_per_micro: params["slope_per_micro"].as_i64().unwrap(),
        };
        let displaced = case["level1_or_escalation"].as_bool().unwrap();
        for (sanction, escalation) in [(displaced, false), (false, displaced)] {
            assert_eq!(
                p_1e7(
                    case["reputation_u"].as_u64().unwrap(),
                    sanction,
                    escalation,
                    &constants
                ),
                case["p_1e7"].as_u64().unwrap(),
                "{case}"
            );
        }
    }
}

fn confirmation_records(case: &serde_json::Value) -> Vec<serde_json::Value> {
    case["records"].as_array().unwrap().to_vec()
}

fn candidate_records(
    raw: &[serde_json::Value],
) -> Vec<wist_core::confirmation::CandidateRecord<'_>> {
    raw.iter()
        .map(|r| wist_core::confirmation::CandidateRecord {
            block_height: r["block_height"].as_u64().unwrap(),
            entry_index: r["entry_index"].as_u64().unwrap(),
            block_sealed_at_s: r["sealed_at_s"].as_i64().unwrap(),
            auditor_id: r["auditor"].as_str().unwrap(),
            effective_similarity: r["effective_similarity"].as_u64().unwrap(),
        })
        .collect()
}

fn i64_list(v: &serde_json::Value) -> Vec<i64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_i64().unwrap())
        .collect()
}

#[test]
fn wist4_confirmation_vectors() {
    let v = read_json("vectors/wist4/confirmation.json");
    let window = v["confirm_window_hours"].as_u64().unwrap();
    for row in v["independence"].as_array().unwrap() {
        assert_eq!(
            wist_core::confirmation::independent(
                row["a"].as_str().unwrap(),
                row["b"].as_str().unwrap()
            ),
            row["independent"].as_bool().unwrap(),
            "{} vs {}",
            row["a"],
            row["b"]
        );
    }
    for case in v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(v["quorum_cases"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let raw = confirmation_records(case);
        let records = candidate_records(&raw);
        let idx = wist_core::confirmation::confirming_index_with_quorum(
            &records,
            window,
            case["confirm_auditors"].as_u64().unwrap_or(2),
        )
        .unwrap();
        assert_eq!(
            idx.map(|i| i as u64),
            case["confirming_index"].as_u64(),
            "{label}"
        );
        if let Some(i) = idx {
            assert_eq!(
                if case["verdict"].as_str() == Some("link_inconsistent") {
                    1
                } else {
                    wist_core::confirmation::ci_severity(&records, i).unwrap() as u64
                },
                case["severity"].as_u64().unwrap(),
                "{label}"
            );
        } else {
            assert!(case["severity"].is_null(), "{label}");
        }
    }
}

#[test]
fn wist4_derivation_vectors() {
    let v = read_json("vectors/wist4/derivation.json");
    assert_eq!(v["c_cap"].as_u64().unwrap(), wist_core::reputation::C_CAP);
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let resets: Vec<u64> = case["resets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_u64().unwrap())
            .collect();
        let n_height = case["n"]["height"].as_u64().unwrap();
        let n_sealed = case["n"]["sealed_at_s"].as_i64().unwrap();
        let expected = &case["expected"];
        let reset = wist_core::derivation::most_recent_reset(&resets, n_height);
        assert_eq!(reset, expected["reset"].as_u64(), "{label}");
        let accepted: Vec<wist_core::derivation::DeltaEvent> = case["accepted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| wist_core::derivation::DeltaEvent {
                height: d["height"].as_u64().unwrap(),
                sealed_at_s: d["sealed_at_s"].as_i64().unwrap(),
            })
            .collect();
        assert_eq!(
            wist_core::derivation::age_days(&accepted, reset, n_height, n_sealed).unwrap(),
            expected["a_days"].as_u64().unwrap(),
            "{label}"
        );
        let audits: Vec<wist_core::derivation::ConsistentAudit> = case["consistent_audits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| wist_core::derivation::ConsistentAudit {
                height: a["height"].as_u64().unwrap(),
                audited_height: a["audited_height"].as_u64().unwrap(),
                url: a["url"].as_str().unwrap(),
                change: match a["change"].as_str().unwrap() {
                    "new" => wist_core::verdict::ChangeType::New,
                    "update" => wist_core::verdict::ChangeType::Update,
                    "attest" => wist_core::verdict::ChangeType::Attest,
                    "delete" => wist_core::verdict::ChangeType::Delete,
                    other => panic!("unknown change type {other}"),
                },
            })
            .collect();
        assert_eq!(
            wist_core::derivation::c_count(&audits, reset, n_height),
            expected["c"].as_u64().unwrap(),
            "{label}"
        );
        let findings: Vec<wist_core::derivation::ConfirmedFinding> = case["confirmed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| wist_core::derivation::ConfirmedFinding {
                confirming_height: f["height"].as_u64().unwrap(),
                audited_height: f["audited_height"].as_u64().unwrap(),
                confirming_sealed_at_s: f["sealed_at_s"].as_i64().unwrap(),
                delta_id: f["delta_id"].as_str().unwrap(),
                severity: f["severity"].as_u64().unwrap() as u8,
            })
            .collect();
        let penalty =
            wist_core::derivation::penalty_inputs(&findings, reset, n_height, n_sealed).unwrap();
        let expected_penalty: Vec<(u8, u64)> = expected["penalty_inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                let row = row.as_array().unwrap();
                (row[0].as_u64().unwrap() as u8, row[1].as_u64().unwrap())
            })
            .collect();
        assert_eq!(penalty, expected_penalty, "{label}");
    }
}

#[test]
fn wist4_coverage_vectors() {
    let v = read_json("vectors/wist4/coverage.json");
    let failures_max = v["coverage_failures_max"].as_u64().unwrap();
    assert_eq!(failures_max, wist_core::coverage::COVERAGE_FAILURES_MAX);
    for case in v["pair_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let selected: Vec<&str> = case["selected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        let recorded: Vec<&str> = case["recorded"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d.as_str().unwrap())
            .collect();
        let status = wist_core::coverage::pair_status(
            &selected,
            &recorded,
            case["attested"].as_bool().unwrap(),
        );
        let expected = match case["status"].as_str().unwrap() {
            "discharged" => wist_core::coverage::PairStatus::Discharged,
            "failed" => wist_core::coverage::PairStatus::Failed,
            other => panic!("unknown status {other}"),
        };
        assert_eq!(status, expected, "{label}");
    }
    for case in v["counting_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let attestation = match case["attestation"].as_str().unwrap() {
            "unmet" => wist_core::coverage::Attestation::Unmet {
                chain_contradicts: false,
            },
            "unmet-chain-contradicted" => wist_core::coverage::Attestation::Unmet {
                chain_contradicts: true,
            },
            "missing" => wist_core::coverage::Attestation::Missing,
            other => panic!("unknown attestation {other}"),
        };
        assert_eq!(
            wist_core::coverage::pair_counts(
                attestation,
                case["chain_gap_in_window"].as_bool().unwrap()
            ),
            case["counts"].as_bool().unwrap(),
            "{label}"
        );
    }
    for case in v["state_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            wist_core::coverage::in_coverage_failure(
                &i64_list(&case["counting_failure_times_s"]),
                case["n_sealed_at_s"].as_i64().unwrap(),
                failures_max
            ),
            case["in_coverage_failure"].as_bool().unwrap(),
            "{label}"
        );
    }
    fn void_reason(name: &str) -> wist_core::coverage::VoidReason {
        use wist_core::coverage::VoidReason::*;
        match name {
            "removed after anchor block" => RemovedAfterAnchorBlock,
            "coverage failure at sealing" => CoverageFailureAtSealing,
            "malformed as evidence" => MalformedEvidence,
            "never admitted at anchor block" => NeverAdmittedAtAnchorBlock,
            "proof without standing" => ProofWithoutStanding,
            "outside selection domain" => OutsideSelectionDomain,
            "self audit" => SelfAudit,
            other => panic!("unknown void reason {other}"),
        }
    }
    for case in v["discharge_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let void: Vec<_> = case["void"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| void_reason(r.as_str().unwrap()))
            .collect();
        assert_eq!(
            wist_core::coverage::void_record_discharges(&void),
            case["discharges"].as_bool().unwrap(),
            "{label}"
        );
    }
    for case in v["establishing_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let blocks: Vec<wist_core::coverage::Block> = case["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| wist_core::coverage::Block {
                height: b["height"].as_u64().unwrap(),
                sealed_at_s: b["sealed_at_s"].as_i64().unwrap(),
            })
            .collect();
        let establishing = wist_core::coverage::establishing_height(
            &blocks,
            case["coverage_deadline_s"].as_i64().unwrap(),
            case["attestation_height"].as_u64(),
            case["record_seal_blocks"].as_u64().unwrap(),
        );
        assert_eq!(
            establishing,
            case["establishing_height"].as_u64(),
            "{label}"
        );
        let audited_sealed_at_s = case["audited_block"]["sealed_at_s"].as_i64().unwrap();
        for probe in case["counts_at"].as_array().unwrap() {
            assert_eq!(
                wist_core::coverage::failure_counts_at(
                    establishing,
                    audited_sealed_at_s,
                    probe["height"].as_u64().unwrap(),
                    probe["sealed_at_s"].as_i64().unwrap()
                ),
                probe["counts"].as_bool().unwrap(),
                "{label} at height {}",
                probe["height"]
            );
        }
    }
    for case in v["chain_scope_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        for log in case["logs"].as_array().unwrap() {
            for (field, prev_map) in [
                ("chain_gap", &case["prev_record"]),
                (
                    "chain_gap_under_global_publication_order",
                    &case["prev_record_under_global_publication_order"],
                ),
            ] {
                let sealed: Vec<(&str, Option<&str>)> = log["sealed"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        let id = id.as_str().unwrap();
                        (id, prev_map[id].as_str())
                    })
                    .collect();
                assert_eq!(
                    wist_core::coverage::chain_gap(&sealed),
                    log[field].as_bool().unwrap(),
                    "{label} {} {field}",
                    log["log"]
                );
            }
        }
    }
    for case in v["anchor_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let named_by = match case["named_by"].as_str().unwrap() {
            "draw" => wist_core::coverage::NamedBy::Draw,
            "extension" => wist_core::coverage::NamedBy::Extension,
            other => panic!("unknown named_by {other}"),
        };
        let void = wist_core::coverage::removal_void(
            named_by,
            case["audited_sealed_at_s"].as_i64().unwrap(),
            case["trigger_sealed_at_s"].as_i64().unwrap(),
            case["removed_at_s"].as_i64().unwrap(),
        );
        assert_eq!(void, void_reason(case["void"].as_str().unwrap()), "{label}");
        assert_eq!(
            wist_core::coverage::void_record_discharges(&[void]),
            case["discharges"].as_bool().unwrap(),
            "{label}"
        );
    }
    for case in v["signature_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let void = wist_core::coverage::signature_void(
            case["signed_under"].as_str().unwrap(),
            case["record_block_key"].as_str(),
            case["duty_block_key"].as_str().unwrap(),
        );
        assert_eq!(void, case["void"].as_str().map(void_reason), "{label}");
        assert_eq!(void.is_none(), case["counts"].as_bool().unwrap(), "{label}");
        let voids: Vec<_> = void.into_iter().collect();
        assert_eq!(
            wist_core::coverage::void_record_discharges(&voids),
            case["discharges"].as_bool().unwrap(),
            "{label}"
        );
    }
}

fn hourly_blocks(end_height: u64) -> Vec<wist_core::coverage::Block> {
    (0..=end_height)
        .map(|height| wist_core::coverage::Block {
            height,
            sealed_at_s: height as i64 * 3_600,
        })
        .collect()
}

fn extension_records(case: &serde_json::Value) -> Vec<wist_core::extension::ExtensionRecord<'_>> {
    std::iter::once(&case["trigger"])
        .chain(case["records"].as_array().unwrap())
        .enumerate()
        .map(|(i, record)| {
            let sealed_at_s = record["sealed_at_s"].as_i64().unwrap();
            wist_core::extension::ExtensionRecord {
                position: wist_core::confirmation::CandidateRecord {
                    block_height: record["height"]
                        .as_u64()
                        .unwrap_or((sealed_at_s / 3_600) as u64),
                    entry_index: i as u64,
                    block_sealed_at_s: sealed_at_s,
                    auditor_id: record["auditor"].as_str().unwrap(),
                    effective_similarity: 0,
                },
                verdict: serde_json::from_value(record["verdict"].clone()).unwrap(),
            }
        })
        .collect()
}

#[test]
fn wist4_contradiction_quorum_vectors() {
    use wist_core::extension::{evaluate, ExtensionClaim};
    let v = read_json("vectors/wist4/confirmation.json");
    for case in v["quorum_contradiction_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let records = extension_records(case);
        let closing_s = case["closing_sealed_at_s"].as_i64().unwrap();
        let result = evaluate(
            &ExtensionClaim {
                trigger_index: 0,
                summoned: true,
                confirm_window_hours: v["confirm_window_hours"].as_u64().unwrap(),
                confirm_auditors: case["confirm_auditors"].as_u64().unwrap(),
            },
            &records,
            &hourly_blocks((closing_s / 3_600) as u64),
        )
        .unwrap();
        assert_eq!(
            result.closing_block.unwrap().sealed_at_s,
            closing_s,
            "{label}"
        );
        assert_eq!(
            result.confirmed,
            case["confirmed"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            result.establishing_block.is_some(),
            case["contradicted"].as_bool().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn wist4_extension_order_vectors() {
    use wist_core::extension::{rationed_summons, summoned, trigger_indices};
    let v = read_json("vectors/wist4/extension.json");
    for case in v["order_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let raw = case["records"].as_array().unwrap();
        let positions: Vec<_> = raw
            .iter()
            .map(|record| wist_core::confirmation::CandidateRecord {
                block_height: record["block_height"].as_u64().unwrap(),
                entry_index: record["entry_index"].as_u64().unwrap(),
                block_sealed_at_s: record["sealed_at_s"].as_i64().unwrap(),
                auditor_id: record["auditor"].as_str().unwrap(),
                effective_similarity: 0,
            })
            .collect();
        let roster: Vec<_> = case["roster"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let mut triggers: Vec<_> = case["prior_triggers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row[0].as_str().unwrap(), row[1].as_i64().unwrap()))
            .collect();
        for (i, record) in raw.iter().enumerate() {
            let same_delta: Vec<_> = raw[..=i]
                .iter()
                .zip(&positions)
                .filter(|(earlier, _)| earlier["delta"] == record["delta"])
                .map(|(_, position)| position.clone())
                .collect();
            let eligible =
                trigger_indices(&same_delta, v["confirm_window_hours"].as_u64().unwrap())
                    .unwrap()
                    .contains(&(same_delta.len() - 1));
            assert_eq!(eligible, case["eligible"][i].as_bool().unwrap(), "{label}");
            let summons = if eligible {
                triggers.push((positions[i].auditor_id, positions[i].block_sealed_at_s));
                *rationed_summons(
                    &triggers,
                    v["ration_window_days"].as_u64().unwrap(),
                    v["extension_triggers_max"].as_u64().unwrap(),
                )
                .last()
                .unwrap()
            } else {
                false
            };
            assert_eq!(summons, case["summons"][i].as_bool().unwrap(), "{label}");
            let filers: Vec<_> = same_delta.iter().map(|record| record.auditor_id).collect();
            let peers: Vec<_> = if summons {
                summoned(&roster, &filers, case["publisher_domain"].as_str().unwrap())
                    .into_iter()
                    .map(|index| roster[index])
                    .collect()
            } else {
                Vec::new()
            };
            let expected: Vec<_> = case["summoned_auditors"][i]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect();
            assert_eq!(peers, expected, "{label}");
        }
    }
}

#[test]
fn wist4_extension_vectors() {
    let v = read_json("vectors/wist4/extension.json");
    let window = v["confirm_window_hours"].as_u64().unwrap();
    let triggers_max = v["extension_triggers_max"].as_u64().unwrap();
    let ration_days = v["ration_window_days"].as_u64().unwrap();
    assert_eq!(triggers_max, wist_core::extension::EXTENSION_TRIGGERS_MAX);
    for case in v["deadline_cases"].as_array().unwrap() {
        assert_eq!(
            wist_core::extension::extension_deadline_s(
                case["b1_sealed_at_s"].as_i64().unwrap(),
                case["confirm_window_hours"].as_u64().unwrap()
            ),
            i128::from(case["deadline_s"].as_i64().unwrap())
        );
    }
    for case in v["trigger_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let raw = confirmation_records(case);
        let records = candidate_records(&raw);
        let expected: Vec<usize> = case["trigger_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(
            wist_core::extension::trigger_indices(&records, window).unwrap(),
            expected,
            "{label}"
        );
    }
    for case in v["ration_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let triggers: Vec<(&str, i64)> = case["triggers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                let t = t.as_array().unwrap();
                (t[0].as_str().unwrap(), t[1].as_i64().unwrap())
            })
            .collect();
        let expected: Vec<bool> = case["summons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_bool().unwrap())
            .collect();
        assert_eq!(
            wist_core::extension::rationed_summons(&triggers, ration_days, triggers_max),
            expected,
            "{label}"
        );
    }
    for case in v["summons_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let roster: Vec<&str> = case["roster"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let filers: Vec<&str> = case["already_sealed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        let expected: Vec<usize> = case["summoned_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(
            wist_core::extension::summoned(
                &roster,
                &filers,
                case["publisher_domain"].as_str().unwrap()
            ),
            expected,
            "{label}"
        );
    }
    assert_eq!(
        v["escalation_window_days"].as_u64().unwrap(),
        wist_core::extension::ESCALATION_WINDOW_DAYS
    );
    for case in v["contradiction_cases"].as_array().unwrap() {
        use wist_core::extension::{escalated_sampling, evaluate, Escalation, ExtensionClaim};
        let label = case["label"].as_str().unwrap();
        let records = extension_records(case);
        let end_height = case["escalation_at"]
            .as_array()
            .unwrap()
            .iter()
            .map(|point| point["height"].as_u64().unwrap())
            .max()
            .unwrap();
        let blocks = hourly_blocks(end_height);
        let result = evaluate(
            &ExtensionClaim {
                trigger_index: 0,
                summoned: case["summoned"].as_bool().unwrap(),
                confirm_window_hours: window,
                confirm_auditors: 2,
            },
            &records,
            &blocks,
        )
        .unwrap();
        assert_eq!(
            result.closing_block.map(|block| block.height),
            case["closes_at_height"].as_u64(),
            "{label}"
        );
        assert_eq!(
            result.confirmed,
            case["confirmed"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            result.consistent_quorum,
            case["independent_consistent_pair"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            result.establishing_block.is_some(),
            case["contradicted"].as_bool().unwrap(),
            "{label}"
        );
        assert_eq!(
            result.establishing_block.map(|block| block.height),
            case["establishing_height"].as_u64(),
            "{label}"
        );
        let escalations: Vec<_> = result
            .establishing_block
            .into_iter()
            .map(|block| Escalation {
                publisher_domain: "page.example.com",
                establishing_block: block,
            })
            .collect();
        for point in case["escalation_at"].as_array().unwrap() {
            let at = wist_core::coverage::Block {
                height: point["height"].as_u64().unwrap(),
                sealed_at_s: point["sealed_at_s"].as_i64().unwrap(),
            };
            let active = escalated_sampling(&escalations, "page.example.com", at);
            assert_eq!(active, point["in_force"].as_bool().unwrap(), "{label}");
            assert_eq!(
                wist_core::sampling::p_1e7(
                    1_000_000,
                    false,
                    active,
                    &wist_core::sampling::DEFAULT_SAMPLING,
                ),
                if active { 5_000_000 } else { 200_000 },
                "{label}"
            );
        }
    }
}

#[test]
fn wist4_sanctions_vectors() {
    let v = read_json("vectors/wist4/sanctions.json");
    for case in v["criterion_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let findings: Vec<wist_core::sanctions::Finding> = case["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| wist_core::sanctions::Finding {
                sealed_at_s: f["sealed_at_s"].as_i64().unwrap(),
                severity: f["severity"].as_u64().unwrap() as u8,
            })
            .collect();
        assert_eq!(
            wist_core::sanctions::criterion_times(
                &findings,
                case["count"].as_u64().unwrap(),
                case["span_days"].as_u64(),
                case["min_severity"].as_u64().unwrap() as u8
            ),
            i64_list(&case["met_times_s"]),
            "{label}"
        );
    }
    for case in v["accrual_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let findings: Vec<wist_core::sanctions::Finding> = case["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| wist_core::sanctions::Finding {
                sealed_at_s: f["sealed_at_s"].as_i64().unwrap(),
                severity: f["severity"].as_u64().unwrap() as u8,
            })
            .collect();
        assert_eq!(
            wist_core::sanctions::l4_accrual_times(
                &findings,
                &i64_list(&case["l3_met_times_s"]),
                &i64_list(&case["l3_clear_times_s"])
            ),
            i64_list(&case["accrual_times_s"]),
            "{label}"
        );
    }
    for case in v["void_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let ruling = case["ruling"].as_array().map(|r| {
            let outcome = match r[0].as_str().unwrap() {
                "overturned" => wist_core::sanctions::Outcome::Overturned,
                "upheld" => wist_core::sanctions::Outcome::Upheld,
                "unappealed" => wist_core::sanctions::Outcome::Unappealed,
                other => panic!("unknown outcome {other}"),
            };
            (outcome, r[1].as_i64().unwrap())
        });
        assert_eq!(
            wist_core::sanctions::state_void_at(
                case["notice_sealed_at_s"].as_i64(),
                case["appeal_sealed_at_s"].as_i64(),
                ruling
            ),
            case["void_at_s"].as_i64(),
            "{label}"
        );
    }
    for case in v["in_force_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            wist_core::sanctions::in_force(
                &i64_list(&case["met_times_s"]),
                &i64_list(&case["clear_times_s"]),
                case["n_s"].as_i64().unwrap()
            ),
            case["in_force"].as_bool().unwrap(),
            "{label}"
        );
    }
    for case in v["ladder_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let met: Vec<Vec<i64>> = case["met_times_s"]
            .as_array()
            .unwrap()
            .iter()
            .map(i64_list)
            .collect();
        let clear: Vec<Vec<i64>> = case["clear_times_s"]
            .as_array()
            .unwrap()
            .iter()
            .map(i64_list)
            .collect();
        let levels: [(&[i64], &[i64]); 4] = [
            (&met[0], &clear[0]),
            (&met[1], &clear[1]),
            (&met[2], &clear[2]),
            (&met[3], &clear[3]),
        ];
        assert_eq!(
            wist_core::sanctions::ladder_level(&levels, case["n_s"].as_i64().unwrap()),
            case["level"].as_u64().unwrap() as u8,
            "{label}"
        );
    }
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

fn change_type(s: &str) -> wist_core::verdict::ChangeType {
    use wist_core::verdict::ChangeType::*;
    match s {
        "new" => New,
        "update" => Update,
        "attest" => Attest,
        "delete" => Delete,
        other => panic!("unknown change type {other}"),
    }
}

fn chain_deltas(v: &serde_json::Value) -> Vec<wist_core::reference::ChainDelta<'_>> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|d| wist_core::reference::ChainDelta {
            id: d["id"].as_str().unwrap(),
            height: d["height"].as_u64().unwrap(),
            sealed_at_s: d["sealed_at_s"].as_i64().unwrap(),
            change: change_type(d["change"].as_str().unwrap()),
            payload: d["payload"].as_str(),
        })
        .collect()
}

#[test]
fn wist4_superseded_audit_vectors() {
    let v = read_json("vectors/wist4/superseded-audit.json");
    let chain = chain_deltas(&v["chain"]);
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let audited = case["audited"].as_str().unwrap();
        let reference = case["reference"].as_str().unwrap();
        let fetched = case["fetched_at_s"].as_i64().unwrap();
        assert_eq!(
            wist_core::reference::newest_at_or_before(&chain, fetched),
            case["expected_reference"].as_str(),
            "{label}: expected_reference"
        );
        let valid = wist_core::reference::reference_valid(&chain, audited, reference, fetched);
        match case["valid"].as_bool() {
            Some(true) => {
                valid.unwrap_or_else(|e| panic!("{label}: rejected: {e}"));
                assert_eq!(
                    wist_core::reference::resolve_anchor(&chain, reference).unwrap(),
                    case["resolved_payload"].as_str(),
                    "{label}: resolved_payload"
                );
                let change = change_type(case["reading_change"].as_str().unwrap());
                if let Some(sim) = case["similarity"].as_u64() {
                    assert_eq!(
                        wist_core::verdict::effective_similarity(sim, change),
                        case["effective_similarity"].as_u64().unwrap(),
                        "{label}: effective_similarity"
                    );
                }
            }
            _ => {
                assert_eq!(case["valid"].as_str(), Some("WIST4-E02"), "{label}");
                assert!(valid.is_err(), "{label}: should be WIST4-E02");
            }
        }
    }
}

#[test]
fn wist4_example_record_carries_reference_delta() {
    let v = read_json("examples/audit-record.json");
    let env: wist_core::objects::AuditRecordEnvelope = serde_json::from_value(v).unwrap();
    assert_eq!(env.record.reference_delta, env.record.audited_delta);
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
            let applied = tips.apply(
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

#[test]
fn wist4_roster_vectors() {
    use wist_core::roster::{RosterAct, RosterAction};
    let v = read_json("vectors/wist4/roster.json");
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let entries: Vec<(i64, RosterAct<'_>)> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let action = match e["action"].as_str().unwrap() {
                    "auditor_admit" => RosterAction::Admit,
                    "auditor_remove" => {
                        let evidence: Option<Vec<String>> = e
                            .get("evidence")
                            .map(|ids| serde_json::from_value(ids.clone()).unwrap());
                        RosterAction::try_remove_with(evidence.as_deref()).unwrap()
                    }
                    other => panic!("unknown action {other}"),
                };
                (
                    e["sealed_at_s"].as_i64().unwrap(),
                    RosterAct {
                        action,
                        auditor_id: e["auditor_id"].as_str().unwrap(),
                        key_id: e["key_id"].as_str().unwrap(),
                        public_key: e["public_key"].as_str().unwrap_or(""),
                    },
                )
            })
            .collect();
        let (roster, rejected) =
            wist_core::roster::replay(case["log_id"].as_str().unwrap(), &entries).unwrap();
        let rejected_indices: Vec<usize> = rejected.iter().map(|(i, _)| *i).collect();
        let expected: Vec<usize> = case["rejected_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(rejected_indices, expected, "{label}");
        for (_, reason) in &rejected {
            assert!(
                reason.to_string().contains("WIST4-E07: "),
                "{label}: {reason}"
            );
        }
        for row in case["admitted_key_at"].as_array().unwrap() {
            let at = row["sealed_at_s"].as_i64().unwrap();
            assert_eq!(
                roster.key_at(row["auditor_id"].as_str().unwrap(), at),
                row["key_id"].as_str(),
                "{label} at {at}"
            );
        }
    }
}

#[test]
fn wist4_selection_domain_vectors() {
    let v = read_json("vectors/wist4/selection-domain.json");
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let declarations: Vec<(&str, u64)> = case["declarations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["domain"].as_str().unwrap(),
                    d["seq0_height"].as_u64().unwrap(),
                )
            })
            .collect();
        let deltas: Vec<wist_core::sampling::DomainDelta<'_>> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| wist_core::sampling::DomainDelta {
                publisher: e["publisher"].as_str().unwrap(),
                url_host: e["url_host"].as_str().unwrap(),
            })
            .collect();
        let expected: Vec<usize> = case["excluded_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(
            wist_core::sampling::selection_domain_excluded(
                case["block_height"].as_u64().unwrap(),
                &declarations,
                &deltas
            ),
            expected,
            "{label}"
        );
    }
    for case in v["self_audit_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            wist_core::sampling::self_audit_barred(
                case["auditor_id"].as_str().unwrap(),
                case["publisher"].as_str().unwrap()
            ),
            case["barred"].as_bool().unwrap(),
            "{label}"
        );
    }
}

fn proof80(hex: &str) -> [u8; 80] {
    wist_core::crypto::hex_decode(hex)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn wist4_extension_proof_vectors() {
    use wist_core::extension::{standing, ProofBlock, Standing, StandingClaim};
    let v = read_json("vectors/wist4/extension-proof.json");
    let pk: [u8; 32] = wist_core::crypto::b64u_decode(v["auditor_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let alpha_of = |block: &serde_json::Value| -> [u8; 32] {
        let alpha =
            wist_core::sampling::alpha_from_block_hash(block["block_hash"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            wist_core::crypto::hex_encode(&alpha),
            block["alpha_hex"].as_str().unwrap()
        );
        alpha
    };
    let audited_alpha = alpha_of(&v["audited_block"]);
    let trigger_alpha = alpha_of(&v["trigger_block"]);
    let audited_delta = v["audited_delta"].as_str().unwrap();
    let reputation_u = v["reputation_u"].as_u64().unwrap();
    let key_of = |b64: &serde_json::Value| -> [u8; 32] {
        wist_core::crypto::b64u_decode(b64.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let mut rotated_cases = 0;
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let pi = proof80(case["vrf_proof_hex"].as_str().unwrap());
        let pk_audited = key_of(&case["admitted_at"]["audited_block"]);
        let pk_trigger = key_of(&case["admitted_at"]["trigger_block"]);
        if pk_audited != pk_trigger {
            rotated_cases += 1;
        }
        let over_audited = wist_core::vrf::verify(&pk_audited, &audited_alpha, &pi).is_ok();
        let over_trigger = wist_core::vrf::verify(&pk_trigger, &trigger_alpha, &pi).is_ok();
        let expected_block = match case["proof_block"].as_str() {
            Some("audited") => (true, false),
            Some("trigger") => (false, true),
            None => (false, false),
            Some(other) => panic!("unknown proof_block {other}"),
        };
        assert_eq!((over_audited, over_trigger), expected_block, "{label}");
        let named = case["named_by_extension"].as_bool().unwrap();
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk_audited,
                alpha: &audited_alpha,
            }),
            audited_delta,
            reputation_u,
            level1_sanction: false,
            escalated_sampling: false,
            sampling: wist_core::sampling::DEFAULT_SAMPLING,
            trigger_block: named.then_some(ProofBlock {
                admitted_key: &pk_trigger,
                alpha: &trigger_alpha,
            }),
            vrf_proof: &pi,
        };
        let expected = match case["standing"].as_str().unwrap() {
            "selected" => Standing::Selected,
            "extension" => Standing::Extension,
            "WIST4-E01" => Standing::Void,
            other => panic!("unknown standing {other}"),
        };
        assert_eq!(standing(&claim), expected, "{label}");
    }
    assert!(
        rotated_cases > 0,
        "no case rotates between the audited Block and B₁"
    );

    let s = read_json("vectors/wist4/sampling.json");
    assert_eq!(s["auditor_public_key"], v["auditor_public_key"]);
    assert_eq!(s["block_hash"], v["audited_block"]["block_hash"]);
    let pi = proof80(s["vrf_proof_hex"].as_str().unwrap());
    let mut selected_rows = 0;
    for row in s["selection"].as_array().unwrap() {
        let label = row["label"].as_str().unwrap();
        let claim = StandingClaim {
            audited_block: Some(ProofBlock {
                admitted_key: &pk,
                alpha: &audited_alpha,
            }),
            audited_delta: row["delta_id"].as_str().unwrap(),
            reputation_u: row["reputation_u"].as_u64().unwrap(),
            level1_sanction: false,
            escalated_sampling: false,
            sampling: wist_core::sampling::DEFAULT_SAMPLING,
            trigger_block: None,
            vrf_proof: &pi,
        };
        let expected = if row["selected"].as_bool().unwrap() {
            selected_rows += 1;
            Standing::Selected
        } else {
            Standing::Void
        };
        assert_eq!(standing(&claim), expected, "{label}");
    }
    assert!(selected_rows > 0, "sampling.json must hold a selected row");
}

#[test]
fn wist4_unauditable_vectors() {
    use wist_core::objects::audit::Verdict;
    use wist_core::unauditable::{
        blocks, clears, unauditable_at, SealedBy, VerdictRecord, UNAUDITABLE_HORIZON_DAYS,
    };
    let v = read_json("vectors/wist4/unauditable.json");
    let horizon = v["unauditable_horizon_days"].as_u64().unwrap();
    assert_eq!(horizon, UNAUDITABLE_HORIZON_DAYS);
    let every_verdict = [
        Verdict::Consistent,
        Verdict::Inconsistent,
        Verdict::Unreachable,
        Verdict::DynamicVariance,
        Verdict::NotAuditable,
        Verdict::LinkVariance,
        Verdict::LinkInconsistent,
    ];
    let mut clearing: Vec<String> = every_verdict
        .iter()
        .filter(|verdict| clears(verdict))
        .map(|verdict| {
            serde_json::to_value(verdict)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    clearing.sort();
    let mut expected_clearing: Vec<String> = v["clearing_verdicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect();
    expected_clearing.sort();
    assert_eq!(clearing, expected_clearing);
    for case in v["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let blocking: Vec<SealedBy<'_>> = case["blocking"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| {
                let verdict: Verdict = serde_json::from_value(r["verdict"].clone()).unwrap();
                let unmeasured = r["unmeasured"].as_str().map(|s| {
                    serde_json::from_value(serde_json::Value::String(s.to_owned())).unwrap()
                });
                let does = blocks(
                    &verdict,
                    r["robots_excluded"].as_bool().unwrap_or(false),
                    unmeasured,
                );
                assert_eq!(does, r["blocks"].as_bool().unwrap(), "{label}: blocks");
                does
            })
            .map(|r| SealedBy {
                auditor_id: r["auditor"].as_str().unwrap(),
                sealed_at_s: r["sealed_at_s"].as_i64().unwrap(),
            })
            .collect();
        let others: Vec<VerdictRecord<'_>> = case["other_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| VerdictRecord {
                sealed_by: SealedBy {
                    auditor_id: r["auditor"].as_str().unwrap(),
                    sealed_at_s: r["sealed_at_s"].as_i64().unwrap(),
                },
                verdict: serde_json::from_value(r["verdict"].clone()).unwrap(),
            })
            .collect();
        assert_eq!(
            unauditable_at(
                &blocking,
                &others,
                case["n_sealed_at_s"].as_i64().unwrap(),
                horizon
            ),
            case["unauditable"].as_bool().unwrap(),
            "{label}"
        );
    }
}

#[test]
fn wist4_roster_batch_vectors() {
    use wist_core::roster::{Roster, RosterAct, RosterAction};
    fn permutations(indices: &mut [usize], start: usize, out: &mut Vec<Vec<usize>>) {
        if start == indices.len() {
            out.push(indices.to_vec());
            return;
        }
        for i in start..indices.len() {
            indices.swap(start, i);
            permutations(indices, start + 1, out);
            indices.swap(start, i);
        }
    }
    let v = read_json("vectors/wist4/roster.json");
    for case in v["batch_cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let initial = &case["initial_after_removals"];
        for field in ["barred", "retired_key_ids", "retired_public_keys"] {
            assert!(
                initial[field].as_array().unwrap().is_empty(),
                "{label}: {field} needs replay history"
            );
        }
        let seed: Vec<_> = [
            ("auditors", RosterAction::Admit),
            ("observers", RosterAction::Register),
        ]
        .into_iter()
        .flat_map(|(kind, action)| {
            initial[kind]
                .as_object()
                .unwrap()
                .iter()
                .map(move |(subject, key)| RosterAct {
                    action,
                    auditor_id: subject,
                    key_id: key["key_id"].as_str().unwrap(),
                    public_key: key["public_key"].as_str().unwrap(),
                })
        })
        .collect();
        let acts: Vec<_> = case["acts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|act| RosterAct {
                action: match act["action"].as_str().unwrap() {
                    "auditor_admit" => RosterAction::Admit,
                    "observer_register" => RosterAction::Register,
                    other => panic!("unknown roster action {other}"),
                },
                auditor_id: act["subject"].as_str().unwrap(),
                key_id: act["key_id"].as_str().unwrap(),
                public_key: act["public_key"].as_str().unwrap(),
            })
            .collect();
        let expected_rejections: Vec<usize> =
            serde_json::from_value(case["expected"]["rejected_indices"].clone()).unwrap();
        let mut orders = Vec::new();
        permutations(&mut (0..acts.len()).collect::<Vec<_>>(), 0, &mut orders);
        for order in orders {
            let mut roster = Roster::new("log.example.org");
            assert!(roster.apply_block(0, &seed).unwrap().is_empty(), "{label}");
            let reordered: Vec<_> = order.iter().map(|&i| acts[i]).collect();
            let rejected = roster.apply_block(1, &reordered).unwrap();
            let mut actual: Vec<_> = rejected
                .iter()
                .map(|(i, error)| {
                    assert!(error.to_string().contains("WIST4-E07"), "{label}: {error}");
                    order[*i]
                })
                .collect();
            actual.sort_unstable();
            assert_eq!(actual, expected_rejections, "{label}: {order:?}");
            for (kind, active) in [
                ("auditors", roster.admitted_at(1)),
                ("observers", roster.registered_at(1)),
            ] {
                let actual: serde_json::Map<String, serde_json::Value> = active
                    .into_iter()
                    .map(|(subject, key)| {
                        let public_key = if kind == "auditors" {
                            roster.public_key_at(subject, 1)
                        } else {
                            roster.observer_public_key_at(subject, 1)
                        }
                        .unwrap();
                        (
                            subject.to_owned(),
                            serde_json::json!({"key_id": key, "public_key": public_key}),
                        )
                    })
                    .collect();
                assert_eq!(
                    serde_json::Value::Object(actual),
                    case["expected"][kind],
                    "{label}: {kind}, {order:?}"
                );
            }
            for act in &seed {
                let key = match act.action {
                    RosterAction::Admit => roster.key_at(act.auditor_id, 0),
                    RosterAction::Register => roster.observer_key_at(act.auditor_id, 0),
                    _ => unreachable!(),
                };
                assert_eq!(key, Some(act.key_id), "{label}: historical tenure");
            }
        }
    }
}

#[test]
fn wist4_signed_admission_evidence_vectors() {
    use wist_core::objects::audit::{RegistryDetails, RegistryUpdateEnvelope};
    use wist_core::roster::{
        validate_admission_evidence, ObserverCheckpoint, ObserverRegistration, Roster, RosterAct,
        RosterAction,
    };
    let v = read_json("vectors/wist4/roster.json");
    let admission = &v["admission"];
    let keys: std::collections::BTreeMap<&str, wist_core::crypto::PublicKey> = admission["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            (
                k["key_id"].as_str().unwrap(),
                wist_core::crypto::PublicKey::from_b64u(k["public_key"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let record_doc = &admission["record_envelope"];
    let record: wist_core::objects::AuditRecordEnvelope =
        serde_json::from_value(record_doc.clone()).unwrap();
    wist_core::envelope::verify_envelope(record_doc, "record", &keys[record.sig.key_id.as_str()])
        .unwrap();
    let head = wist_core::delta::delta_id(&record_doc["record"]).unwrap();
    for case in admission["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let mut roster = Roster::new("log.example.org");
        let mut registrations = Vec::new();
        let mut checkpoints = Vec::new();
        let history: Vec<(u64, RegistryUpdateEnvelope, String)> = case["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let doc = &entry["envelope"];
                let envelope: RegistryUpdateEnvelope = serde_json::from_value(doc.clone()).unwrap();
                wist_core::envelope::verify_envelope(
                    doc,
                    "update",
                    &keys[envelope.sig.key_id.as_str()],
                )
                .unwrap();
                (
                    entry["height"].as_u64().unwrap(),
                    envelope,
                    wist_core::delta::delta_id(&doc["update"]).unwrap(),
                )
            })
            .collect();
        for (height, envelope, id) in &history {
            let update = &envelope.update;
            match update.typed_details().unwrap() {
                RegistryDetails::Registration(details) => {
                    assert_eq!(envelope.sig.key_id, details.key_id, "{label}");
                    assert!(
                        roster
                            .apply_block(
                                *height as i64,
                                &[RosterAct {
                                    action: RosterAction::Register,
                                    auditor_id: &update.subject,
                                    key_id: &details.key_id,
                                    public_key: &details.public_key,
                                }]
                            )
                            .unwrap()
                            .is_empty(),
                        "{label}"
                    );
                    registrations.push(ObserverRegistration {
                        observer_id: &update.subject,
                        height: *height,
                    });
                }
                RegistryDetails::ObserverCheckpoint(details) => {
                    assert_eq!(details.head, head, "{label}");
                    assert_eq!(update.subject, record.record.auditor_id, "{label}");
                    assert_eq!(
                        roster.observer_key_at(&update.subject, *height as i64),
                        Some(envelope.sig.key_id.as_str()),
                        "{label}"
                    );
                    checkpoints.push(ObserverCheckpoint {
                        observer_id: &update.subject,
                        height: *height,
                        update_id: id,
                    });
                }
                other => panic!("unexpected history details {other:?}"),
            }
        }
        let doc = &case["envelope"];
        let envelope: RegistryUpdateEnvelope = serde_json::from_value(doc.clone()).unwrap();
        wist_core::envelope::verify_envelope(doc, "update", &keys[envelope.sig.key_id.as_str()])
            .unwrap();
        let RegistryDetails::Admission(details) = envelope.update.typed_details().unwrap() else {
            panic!("{label}")
        };
        let height = case["admission_height"].as_u64().unwrap();
        let subject = &envelope.update.subject;
        let rejected = roster
            .apply_block_checked(
                height as i64,
                &[RosterAct {
                    action: RosterAction::Admit,
                    auditor_id: subject,
                    key_id: &details.key_id,
                    public_key: &details.public_key,
                }],
                |_| {
                    validate_admission_evidence(
                        subject,
                        height,
                        &registrations,
                        &checkpoints,
                        details.track_record.as_ref(),
                    )
                },
            )
            .unwrap();
        match case["error"].as_str() {
            None => assert!(rejected.is_empty(), "{label}: {rejected:?}"),
            Some(code) => {
                assert_eq!(rejected.len(), 1, "{label}");
                assert!(
                    rejected[0].1.to_string().contains(code),
                    "{label}: {rejected:?}"
                );
            }
        }
        assert_eq!(
            roster.key_at(subject, height as i64),
            case["admitted_key"].as_str(),
            "{label}"
        );
        if rejected.is_empty() {
            assert_eq!(
                roster.observer_key_at(subject, height as i64),
                None,
                "{label}"
            );
        }
    }
}

#[test]
fn measured_audit_fields_follow_the_verdict() {
    use wist_core::objects::AuditRecordEnvelope;
    let original = read_json("examples/audit-record.json");
    let fields = [
        "response_commitment",
        "credit_commitment",
        "ref_extract_commitment",
        "evidence_commitment",
        "similarity",
    ];
    for verdict in [
        "consistent",
        "inconsistent",
        "dynamic_variance",
        "link_variance",
        "link_inconsistent",
    ] {
        let mut measured = original.clone();
        measured["record"]["verdict"] = verdict.into();
        assert!(
            serde_json::from_value::<AuditRecordEnvelope>(measured.clone()).is_ok(),
            "{verdict}"
        );
        for field in fields {
            let mut missing = measured.clone();
            missing["record"].as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<AuditRecordEnvelope>(missing.clone()).is_err(),
                "{verdict}: missing {field}"
            );
            missing["record"][field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<AuditRecordEnvelope>(missing).is_err(),
                "{verdict}: null {field}"
            );
        }
        measured["record"]["unmeasured"] = "reference".into();
        assert!(
            serde_json::from_value::<AuditRecordEnvelope>(measured).is_err(),
            "{verdict}: unmeasured"
        );
    }
    for verdict in ["unreachable", "not_auditable"] {
        let mut unmeasured = original.clone();
        unmeasured["record"]["verdict"] = verdict.into();
        for field in fields.into_iter().chain(["link_agreement"]) {
            unmeasured["record"].as_object_mut().unwrap().remove(field);
        }
        if verdict == "not_auditable" {
            assert!(serde_json::from_value::<AuditRecordEnvelope>(unmeasured.clone()).is_err());
            unmeasured["record"]["unmeasured"] = "reference".into();
        }
        let parsed: AuditRecordEnvelope = serde_json::from_value(unmeasured.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), unmeasured);
        for field in fields {
            let mut extra = unmeasured.clone();
            extra["record"][field] = original["record"][field].clone();
            assert!(
                serde_json::from_value::<AuditRecordEnvelope>(extra.clone()).is_err(),
                "{verdict}: {field}"
            );
            extra["record"][field] = serde_json::Value::Null;
            assert!(
                serde_json::from_value::<AuditRecordEnvelope>(extra).is_err(),
                "{verdict}: null {field}"
            );
        }
    }
}

#[test]
fn wist4_registry_details_types_preserve_signed_objects() {
    use wist_core::objects::audit::{RegistryDetails, RegistryUpdateEnvelope};
    let roster = read_json("vectors/wist4/roster.json");
    let canary = read_json("vectors/wist4/canary.json");
    let mut docs = vec![
        canary["membership"]["commitment_envelope"].clone(),
        canary["membership"]["cases"][0]["envelope"].clone(),
    ];
    for case in roster["admission"]["cases"].as_array().unwrap() {
        docs.push(case["envelope"].clone());
        docs.extend(
            case["history"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["envelope"].clone()),
        );
    }
    for doc in docs {
        let envelope: RegistryUpdateEnvelope = serde_json::from_value(doc.clone()).unwrap();
        assert_eq!(serde_json::to_value(&envelope).unwrap(), doc);
        let details = envelope.update.typed_details().unwrap();
        let actual = match details {
            RegistryDetails::Admission(d) => serde_json::to_value(d),
            RegistryDetails::Registration(d) => serde_json::to_value(d),
            RegistryDetails::ObserverCheckpoint(d) => serde_json::to_value(d),
            RegistryDetails::CanaryCommitment(d) => serde_json::to_value(d),
            RegistryDetails::CanaryReveal(d) => serde_json::to_value(d),
            other => panic!("unexpected details {other:?}"),
        }
        .unwrap();
        assert_eq!(actual, doc["update"]["details"]);
        for field in doc["update"]["details"].as_object().unwrap().keys() {
            if field == "track_record" {
                continue;
            }
            let mut missing = envelope.update.clone();
            missing
                .details
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(missing.typed_details().is_err(), "missing {field}: {doc}");
        }
        let mut extended = envelope.update.clone();
        extended.details.as_mut().unwrap()["extension"] = serde_json::json!({"number": 1.5});
        assert!(extended.typed_details().is_ok());
    }
    let pk = wist_core::crypto::PublicKey::from_b64u(
        canary["membership"]["public_key"].as_str().unwrap(),
    )
    .unwrap();
    wist_core::envelope::verify_envelope(
        &canary["membership"]["commitment_envelope"],
        "update",
        &pk,
    )
    .unwrap();
    wist_core::envelope::verify_envelope(
        &canary["membership"]["cases"][0]["envelope"],
        "update",
        &pk,
    )
    .unwrap();
    let commitment: RegistryUpdateEnvelope =
        serde_json::from_value(canary["membership"]["commitment_envelope"].clone()).unwrap();
    let reveal: RegistryUpdateEnvelope =
        serde_json::from_value(canary["membership"]["cases"][0]["envelope"].clone()).unwrap();
    for (envelope, pointer, bad_value, code) in [
        (
            &commitment,
            "/root",
            serde_json::json!("sha256:ABC"),
            "WIST4-E04",
        ),
        (&commitment, "/leaves", serde_json::json!(0), "WIST4-E08"),
        (&reveal, "/leaves", serde_json::json!([]), "WIST4-E04"),
        (
            &reveal,
            "/leaves/0/path/0",
            serde_json::json!("0".repeat(64)),
            "WIST4-E04",
        ),
        (
            &reveal,
            "/leaves/0/index",
            serde_json::json!(-1),
            "WIST4-E04",
        ),
    ] {
        let mut update = envelope.update.clone();
        *update
            .details
            .as_mut()
            .unwrap()
            .pointer_mut(pointer)
            .unwrap() = bad_value;
        assert!(
            update
                .typed_details()
                .unwrap_err()
                .to_string()
                .contains(code),
            "{pointer}"
        );
    }
    let mut extra_leaf_field = reveal.update.clone();
    extra_leaf_field.details.as_mut().unwrap()["leaves"][0]["extension"] = true.into();
    assert!(extra_leaf_field.typed_details().is_err());
    let mut admission: RegistryUpdateEnvelope =
        serde_json::from_value(roster["admission"]["cases"][3]["envelope"].clone()).unwrap();
    admission.update.details.as_mut().unwrap()["track_record"]["scoreboard"]["mature"] =
        serde_json::json!([0, 0]);
    assert!(admission.update.typed_details().is_err());
    admission.update.details.as_mut().unwrap()["track_record"] = serde_json::Value::Null;
    assert!(admission.update.typed_details().is_err());
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
        "contradictions_max",
        "escalation_l2",
        "escalation_l3",
        "escalation_l4",
        "unknown",
    ] {
        assert!(validate_value(name, 1).is_err());
    }
    wist_core::parameters::validate_combinations(parameter_default).unwrap();
}

#[test]
fn wist4_extension_parameter_combinations() {
    use wist_core::parameters::validate;
    let vectors = read_json("vectors/wist4/parameter-combinations.json");
    for case in vectors["extension_window_cases"].as_array().unwrap() {
        let lookup = |name: &str| {
            case[name]
                .as_i64()
                .unwrap_or_else(|| parameter_default(name))
        };
        let changed = case["changed"].as_str().unwrap();
        assert_eq!(
            validate(changed, lookup(changed), lookup).is_ok(),
            case["rule_holds"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn wist4_sanction_reversals() {
    use wist_core::sanctions::*;
    let v = read_json("vectors/wist4/sanctions.json");
    for case in v["reversal_cases"].as_array().unwrap() {
        let findings: Vec<Finding> = case["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| Finding {
                sealed_at_s: f["sealed_at_s"].as_i64().unwrap(),
                severity: f["severity"].as_u64().unwrap() as u8,
            })
            .collect();
        let lifts = i64_list(&case["lift_times_s"]);
        let l3 = criterion_times(&findings, 1, None, 3);
        let count = criterion_times(
            &findings,
            ESCALATION_L4_SEV3_COUNT,
            Some(ESCALATION_L4_DAYS),
            3,
        );
        let accrual = l4_accrual_times(&findings, &l3, &lifts);
        assert_eq!(count, i64_list(&case["l4_count_branch_times_s"]));
        assert_eq!(accrual, i64_list(&case["l4_accrual_branch_times_s"]));
        let mut l4 = count;
        l4.extend(accrual);
        l4.sort_unstable();
        l4.dedup();
        let met = [
            criterion_times(&findings, 1, None, 0),
            criterion_times(&findings, ESCALATION_L2_COUNT, Some(ESCALATION_L2_DAYS), 0),
            l3,
            l4,
        ];
        for (actual, expected) in met.iter().zip(case["met_times_s"].as_array().unwrap()) {
            assert_eq!(*actual, i64_list(expected));
        }
        for probe in case["probes"].as_array().unwrap() {
            let n = probe["n_s"].as_i64().unwrap();
            let mut times: Vec<_> = findings
                .iter()
                .map(|f| f.sealed_at_s)
                .chain(lifts.iter().copied())
                .filter(|&t| t <= n)
                .collect();
            times.sort_unstable();
            times.dedup();
            let mut ladder = Ladder::default();
            for (height, at) in times.into_iter().enumerate() {
                let fs: Vec<_> = findings
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| f.sealed_at_s == at)
                    .map(|(i, f)| OrderedFinding {
                        record_id: [i as u8; 32],
                        entry_index: i as u64,
                        severity: f.severity,
                    })
                    .collect();
                ladder.apply_block(SanctionBlock {
                    height: height as u64,
                    sealed_at_s: at,
                    reset: false,
                    lift: lifts.contains(&at),
                    voids: &[],
                    findings: &fs,
                });
            }
            assert_eq!(
                u64::from(ladder.level()),
                probe["level"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
        }
    }
}

#[test]
fn wist4_sanction_transitions() {
    use wist_core::sanctions::*;
    let v = read_json("vectors/wist4/sanctions.json");
    for case in v["transition_cases"].as_array().unwrap() {
        for reversed in [false, true] {
            let mut ladder = Ladder::default();
            for (i, b) in case["blocks"].as_array().unwrap().iter().enumerate() {
                let voids: Vec<_> = b["void_levels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| {
                        let level = l.as_u64().unwrap() as u8;
                        NoticeVoid {
                            level,
                            activation: ladder.active()[usize::from(level - 1)].unwrap().record_id,
                        }
                    })
                    .collect();
                let mut findings: Vec<_> = b["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| OrderedFinding {
                        record_id: [i as u8 * 8 + f["entry_index"].as_u64().unwrap() as u8; 32],
                        entry_index: f["entry_index"].as_u64().unwrap(),
                        severity: f["severity"].as_u64().unwrap() as u8,
                    })
                    .collect();
                if reversed {
                    findings.reverse();
                }
                ladder.apply_block(SanctionBlock {
                    height: b["height"].as_u64().unwrap(),
                    sealed_at_s: b["sealed_at_s"].as_i64().unwrap(),
                    reset: false,
                    lift: b["lift"].as_bool().unwrap(),
                    voids: &voids,
                    findings: &findings,
                });
                let active: Vec<_> = ladder
                    .active()
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.is_some())
                    .map(|(i, _)| i as i64 + 1)
                    .collect();
                assert_eq!(
                    active,
                    i64_list(&case["active_rungs"][i]),
                    "{}",
                    case["label"]
                );
                assert_eq!(
                    u64::from(ladder.level()),
                    case["levels"][i].as_u64().unwrap()
                );
            }
        }
    }
}

#[test]
fn wist4_sanction_process() {
    use wist_core::sanctions::*;
    let v = read_json("vectors/wist4/sanctions.json");
    let p = &v["process"];
    let key = wist_core::crypto::PublicKey::from_b64u(p["public_key"].as_str().unwrap()).unwrap();
    for case in p["cases"].as_array().unwrap() {
        let notice_doc = case.get("notice").unwrap_or(&p["notice"]);
        wist_core::envelope::verify_envelope(notice_doc, "update", &key).unwrap();
        let notice_id = wist_core::delta::delta_id(&notice_doc["update"]).unwrap();
        let docs = case["acts"].as_array().unwrap();
        let ids: Vec<_> = docs
            .iter()
            .map(|a| {
                wist_core::envelope::verify_envelope(&a["envelope"], "update", &key).unwrap();
                wist_core::delta::delta_id(&a["envelope"]["update"]).unwrap()
            })
            .collect();
        let mut times: Vec<_> = docs
            .iter()
            .map(|a| a["sealed_at_s"].as_i64().unwrap())
            .chain(
                case["probes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a["n_s"].as_i64().unwrap()),
            )
            .chain([0])
            .collect();
        times.sort_unstable();
        times.dedup();
        let height_at = |t: i64| times.binary_search(&t).unwrap() as u64 + 1;
        let acts: Vec<_> = docs
            .iter()
            .zip(&ids)
            .map(|(a, id)| {
                let update = &a["envelope"]["update"];
                let details = &update["details"];
                let kind = match update["action"].as_str().unwrap() {
                    "appeal" => ProcessKind::Appeal,
                    "appeal_ruling" => {
                        ProcessKind::Ruling(match details["outcome"].as_str().unwrap() {
                            "upheld" => Outcome::Upheld,
                            "overturned" => Outcome::Overturned,
                            "unappealed" => Outcome::Unappealed,
                            other => panic!("{other}"),
                        })
                    }
                    other => panic!("{other}"),
                };
                let at = a["sealed_at_s"].as_i64().unwrap();
                ProcessAct {
                    id,
                    notice: details["notice"].as_str().unwrap(),
                    subject: update["subject"].as_str().unwrap(),
                    height: height_at(at),
                    sealed_at_s: at,
                    kind,
                    ruling_deadline_days: 30,
                }
            })
            .collect();
        let notice = Notice {
            id: &notice_id,
            subject: notice_doc["update"]["subject"].as_str().unwrap(),
            sanction: notice_doc["update"]["details"]["kind"] == "sanction",
            height: height_at(0),
            sealed_at_s: 0,
            activation_height: case["activation_sealed_at_s"].as_i64().map_or(0, height_at),
            appeal_window_days: 14,
            appeal_seal_days: 7,
        };
        for (i, probe) in case["probes"].as_array().unwrap().iter().enumerate() {
            let at = probe["n_s"].as_i64().unwrap();
            let state = process_at(notice, &acts, height_at(at), at);
            let expected = &probe["expected"];
            assert_eq!(
                state.appeal_index.map(|i| i as u64),
                expected["appeal_index"].as_u64(),
                "{}",
                case["label"]
            );
            assert_eq!(
                state.merits_index.map(|i| i as u64),
                expected["merits_index"].as_u64(),
                "{}",
                case["label"]
            );
            assert_eq!(
                state.unappealed_index.map(|i| i as u64),
                expected["unappealed_index"].as_u64(),
                "{}",
                case["label"]
            );
            assert_eq!(
                state.void_at_s,
                expected["void_at_s"].as_i64().map(i128::from),
                "{}",
                case["label"]
            );
            if let Some(severity) = case["activation_severity"].as_u64() {
                let mut ladder = Ladder::default();
                let finding = OrderedFinding {
                    record_id: [1; 32],
                    entry_index: 0,
                    severity: severity as u8,
                };
                ladder.apply_block(SanctionBlock {
                    height: height_at(0),
                    sealed_at_s: 0,
                    reset: false,
                    lift: false,
                    voids: &[],
                    findings: &[finding],
                });
                if state.void_at_s.is_some() {
                    ladder.apply_block(SanctionBlock {
                        height: height_at(at),
                        sealed_at_s: at,
                        reset: false,
                        lift: false,
                        voids: &[NoticeVoid {
                            level: 3,
                            activation: [1; 32],
                        }],
                        findings: &[],
                    });
                }
                assert_eq!(
                    u64::from(ladder.level()),
                    case["levels"][i].as_u64().unwrap(),
                    "{}",
                    case["label"]
                );
                assert_eq!(state.error_at(1), case["same_block_ruling_error"].as_str());
            }
        }
    }
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
