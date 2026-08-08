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
fn genesis_chain_link() {
    let block = read_json("vectors/wist3/block.json");
    assert_eq!(block["header"]["block_number"], 0);
    wist_core::block::verify_chain_link(&block["header"], "sha256:genesis").unwrap();
    assert!(wist_core::block::verify_chain_link(&block["header"], "sha256:0000").is_err());
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
fn manifest_anchored_to_block() {
    let manifest = read_json("examples/snapshot-manifest.json");
    let block = read_json("examples/block.json");
    assert_eq!(
        manifest["manifest"]["anchor_block_hash"].as_str().unwrap(),
        wist_core::block::block_hash(&block["header"]).unwrap()
    );
}
