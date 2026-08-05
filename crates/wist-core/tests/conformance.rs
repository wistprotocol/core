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
