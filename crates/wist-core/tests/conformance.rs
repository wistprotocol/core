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
