use crate::crypto::{b64u_decode, b64u_encode, verify, PublicKey, SigningKey};
use crate::error::Error;
use crate::jcs;
use serde_json::Value;

pub fn canonical_b64u(value: &str, length: usize) -> bool {
    b64u_decode(value).is_ok_and(|bytes| bytes.len() == length && b64u_encode(&bytes) == value)
}

/// WIST-1 §3.1: no leading zeros, prerelease or build suffix.
pub fn version_spelled(version: &str) -> bool {
    version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && !(part.len() > 1 && part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
        })
}

/// WIST-1 §3.1: wire major `1` alone is implemented.
pub fn validate_version(version: &str) -> Result<(), &'static str> {
    if !version_spelled(version) {
        return Err("WIST1-E14");
    }
    if version.split('.').next() != Some("1") {
        return Err("WIST1-E15");
    }
    Ok(())
}

pub fn verify_envelope(doc: &Value, inner_key: &str, key: &PublicKey) -> Result<(), Error> {
    let inner = doc
        .get(inner_key)
        .ok_or_else(|| Error::Envelope(format!("missing inner object {inner_key:?}")))?;
    let sig = doc
        .pointer("/sig/value")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Envelope("missing sig.value".into()))?;
    let canonical = jcs::canonicalize(inner)?;
    verify(key, &canonical, sig)
}

pub fn sign_envelope(
    inner: &Value,
    inner_key: &str,
    key_id: &str,
    sk: &SigningKey,
) -> Result<Value, Error> {
    let canonical = jcs::canonicalize(inner)?;
    let value = sk.sign(&canonical);
    Ok(serde_json::json!({
        inner_key: inner,
        "sig": {"key_id": key_id, "alg": "Ed25519", "value": value}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec_dir() -> PathBuf {
        std::env::var_os("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
    }

    #[test]
    fn sign_envelope_roundtrips_with_verify() {
        let sk = crate::crypto::SigningKey::from_seed(&[7u8; 32]);
        let inner = serde_json::json!({"b": 1, "a": "x"});
        let env = sign_envelope(&inner, "catalog", "k1", &sk).unwrap();
        assert_eq!(env["sig"]["alg"], "Ed25519");
        assert_eq!(env["sig"]["key_id"], "k1");
        verify_envelope(&env, "catalog", &sk.public()).unwrap();
    }

    #[test]
    fn a_version_is_refused_misspelled_before_outside_major_one() {
        assert_eq!(validate_version("1.0.0"), Ok(()));
        assert_eq!(validate_version("1.12.3"), Ok(()));
        for misspelled in [
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.00.0",
            "1.0.0-rc1",
            "1.0.0+b",
            "",
        ] {
            assert_eq!(
                validate_version(misspelled),
                Err("WIST1-E14"),
                "{misspelled}"
            );
        }
        assert_eq!(validate_version("2.0.0"), Err("WIST1-E15"));
        assert_eq!(validate_version("0.9.0"), Err("WIST1-E15"));
    }

    #[test]
    fn sign_envelope_reproduces_wist1_vector() {
        let dir = spec_dir().join("vectors/wist1");
        let kp: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("keypair.json")).unwrap()).unwrap();
        let env: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("envelope.json")).unwrap()).unwrap();
        let seed_bytes = crate::crypto::hex_decode(kp["seed_hex"].as_str().unwrap()).unwrap();
        let sk = crate::crypto::SigningKey::from_seed(&seed_bytes.try_into().unwrap());
        let signed = sign_envelope(
            &env["catalog"],
            "catalog",
            env["sig"]["key_id"].as_str().unwrap(),
            &sk,
        )
        .unwrap();
        assert_eq!(signed["sig"]["value"], env["sig"]["value"]);
    }
}
