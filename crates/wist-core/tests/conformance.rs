use std::path::PathBuf;

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
            .as_array().unwrap().iter()
            .map(|u| u.as_str().unwrap().to_string()).collect();
        let observed: Vec<String> = case["observed_urls"]
            .as_array().unwrap().iter()
            .map(|u| u.as_str().unwrap().to_string()).collect();
        let got = wist_core::agreement::link_agreement(
            &declared,
            &observed,
            case["declared_total"].as_u64().unwrap(),
            case["observed_total"].as_u64().unwrap(),
        );
        assert_eq!(got, case["link_agreement"].as_u64().unwrap(), "case {}", case["label"]);
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
        assert!(t.decay(day) < t.decay(day - 1), "not strictly decreasing at {day}");
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
        let confirmed: Vec<(u8, u64)> = case["inconsistencies"].as_array().unwrap().iter()
            .map(|i| {
                assert_eq!(
                    table.decay(i["t_days"].as_u64().unwrap()),
                    i["decay"].as_u64().unwrap(),
                    "{label} decay"
                );
                (i["severity"].as_u64().unwrap() as u8, i["t_days"].as_u64().unwrap())
            })
            .collect();
        let pen = wist_core::reputation::penalty_n(&confirmed, table);
        assert_eq!(pen, case["penalty_n"].as_u64().unwrap() as u128, "{label} penalty_n");
        let c1 = (c.min(500) + 1) as u128;
        assert_eq!(base as u128 * c1 * 1_000_000_000, case["numerator"].as_u64().unwrap() as u128, "{label} numerator");
        assert_eq!(c1 * 1_000_000_000 + 5 * pen, case["denominator"].as_u64().unwrap() as u128, "{label} denominator");
        let f = wist_core::reputation::reputation_formula_u(base, c, pen);
        assert_eq!(f, case["formula_u"].as_u64().unwrap(), "{label} formula_u");
        assert_eq!(
            wist_core::reputation::is_provisional(a, c),
            case["provisional"].as_bool().unwrap(),
            "{label} provisional"
        );
        let rep = wist_core::reputation::apply_provisional_cap(f, a, c);
        assert_eq!(rep, case["reputation_u"].as_u64().unwrap(), "{label} reputation_u");
        assert_eq!(wist_core::reputation::quota_q(rep), case["Q"].as_u64().unwrap(), "{label} Q");
    }
}

#[test]
fn wist4_reputation_worked_example_day_counts() {
    let v = read_json("vectors/wist4/reputation.json");
    let s = &v["worked_example"]["sealed_at"];
    assert_eq!(s["first_delta_block"].as_str().unwrap(), "2026-08-02T13:00:00Z");
    assert_eq!(s["confirming_block"].as_str().unwrap(), "2027-08-07T17:00:00Z");
    assert_eq!(s["block_n"].as_str().unwrap(), "2027-09-06T18:00:00Z");
    const FIRST_DELTA: i64 = 1_785_675_600;
    const CONFIRMING: i64 = 1_817_658_000;
    const BLOCK_N: i64 = 1_820_253_600;
    assert_eq!(wist_core::reputation::whole_days(FIRST_DELTA, BLOCK_N).unwrap(), 400);
    assert_eq!(wist_core::reputation::whole_days(CONFIRMING, BLOCK_N).unwrap(), 30);
    assert!(wist_core::reputation::whole_days(BLOCK_N, CONFIRMING).is_err());
}

#[test]
fn wist4_sampling_vector() {
    let v = read_json("vectors/wist4/sampling.json");
    let raw = std::fs::read_to_string(spec_dir().join("vectors/wist4/sampling.json")).unwrap();
    let pk: [u8; 32] = wist_core::crypto::b64u_decode(v["auditor_public_key"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let alpha =
        wist_core::sampling::alpha_from_block_hash(v["block_hash"].as_str().unwrap()).unwrap();
    assert_eq!(wist_core::crypto::hex_encode(&alpha), v["alpha_hex"].as_str().unwrap());
    let pi: [u8; 80] = wist_core::crypto::hex_decode(v["vrf_proof_hex"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let beta = wist_core::vrf::verify(&pk, &alpha, &pi).unwrap();
    assert_eq!(wist_core::crypto::hex_encode(&beta), v["beta_hex"].as_str().unwrap());
    for row in v["selection"].as_array().unwrap() {
        let label = row["label"].as_str().unwrap();
        let d = wist_core::sampling::draw(&beta, row["delta_id"].as_str().unwrap());
        assert_eq!(format!("{d:016x}"), row["draw_first8_hex"].as_str().unwrap(), "{label}");
        assert_eq!(d, row["D"].as_u64().unwrap(), "{label}");
        let p = wist_core::sampling::p_1e7(row["reputation_u"].as_u64().unwrap(), false);
        assert_eq!(p, row["p_1e7"].as_u64().unwrap(), "{label}");
        let lhs = d as u128 * 10_000_000;
        let rhs = (p as u128) << 64;
        assert!(raw.contains(&format!("\"lhs\": {lhs}")), "{label} lhs {lhs} not in vector");
        assert!(raw.contains(&format!("\"rhs\": {rhs}")), "{label} rhs {rhs} not in vector");
        assert_eq!(
            wist_core::sampling::selected(d, p),
            row["selected"].as_bool().unwrap(),
            "{label}"
        );
    }
}
