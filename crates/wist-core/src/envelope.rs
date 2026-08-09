use crate::crypto::{verify, PublicKey, SigningKey};
use crate::error::Error;
use crate::jcs;
use serde_json::Value;

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
        "sig": {"key_id": key_id, "alg": "ed25519", "value": value}
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
        let env = sign_envelope(&inner, "delta", "k1", &sk).unwrap();
        assert_eq!(env["sig"]["alg"], "ed25519");
        assert_eq!(env["sig"]["key_id"], "k1");
        verify_envelope(&env, "delta", &sk.public()).unwrap();
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
            &env["delta"],
            "delta",
            env["sig"]["key_id"].as_str().unwrap(),
            &sk,
        )
        .unwrap();
        assert_eq!(signed["sig"]["value"], env["sig"]["value"]);
    }
}
