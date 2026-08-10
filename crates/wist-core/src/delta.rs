use crate::crypto::{b64u_decode, hex_encode};
use crate::error::Error;
use crate::jcs;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn delta_id(delta: &Value) -> Result<String, Error> {
    let canonical = jcs::canonicalize(delta)?;
    Ok(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(&canonical))
    ))
}

pub fn content_bytes(content: &Value) -> Result<u64, Error> {
    Ok(jcs::canonicalize(content)?.len() as u64)
}

fn commitment_mac(salt_b64u: &str) -> Result<Hmac<Sha256>, Error> {
    let salt = b64u_decode(salt_b64u)?;
    if salt.len() < 16 {
        return Err(Error::Commitment("salt shorter than 128 bits".into()));
    }
    Hmac::<Sha256>::new_from_slice(&salt).map_err(|e| Error::Commitment(e.to_string()))
}

pub fn verify_commitment(salt_b64u: &str, content: &Value, declared: &str) -> Result<(), Error> {
    let mut mac = commitment_mac(salt_b64u)?;
    let canonical = jcs::canonicalize(content)?;
    mac.update(&canonical);
    let got = format!("hmac-sha256:{}", hex_encode(&mac.finalize().into_bytes()));
    if got != declared {
        return Err(Error::Commitment("commitment mismatch".into()));
    }
    Ok(())
}

pub fn make_commitment(salt_b64u: &str, content: &Value) -> Result<String, Error> {
    let mut mac = commitment_mac(salt_b64u)?;
    let canonical = jcs::canonicalize(content)?;
    mac.update(&canonical);
    Ok(format!(
        "hmac-sha256:{}",
        hex_encode(&mac.finalize().into_bytes())
    ))
}

pub fn make_commitment_bytes(salt_b64u: &str, octets: &[u8]) -> Result<String, Error> {
    let mut mac = commitment_mac(salt_b64u)?;
    mac.update(octets);
    Ok(format!("hmac-sha256:{}", hex_encode(&mac.finalize().into_bytes())))
}

pub fn verify_commitment_bytes(salt_b64u: &str, octets: &[u8], declared: &str) -> Result<(), Error> {
    let got = make_commitment_bytes(salt_b64u, octets)?;
    if got != declared {
        return Err(Error::Commitment("commitment mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_commitment_matches_verify() {
        let salt = crate::crypto::b64u_encode(&[9u8; 16]);
        let content = serde_json::json!({"extract": "hi", "links": {"total": 0, "urls": []}, "summary": {"title": "t"}});
        let c = make_commitment(&salt, &content).unwrap();
        assert!(c.starts_with("hmac-sha256:"));
        verify_commitment(&salt, &content, &c).unwrap();
    }

    #[test]
    fn make_commitment_rejects_short_salt() {
        let salt = crate::crypto::b64u_encode(&[9u8; 8]);
        assert!(make_commitment(&salt, &serde_json::json!({})).is_err());
    }

    #[test]
    fn bytes_commitment_roundtrip_and_salt_sensitivity() {
        let salt = crate::crypto::b64u_encode(&[7u8; 16]);
        let other = crate::crypto::b64u_encode(&[8u8; 16]);
        let c = make_commitment_bytes(&salt, b"octets").unwrap();
        verify_commitment_bytes(&salt, b"octets", &c).unwrap();
        assert!(verify_commitment_bytes(&other, b"octets", &c).is_err());
    }

    #[test]
    fn short_salt_error_precedes_jcs_error() {
        let short_salt = crate::crypto::b64u_encode(&[9u8; 8]);
        let bad_content = serde_json::json!({"f": 1.5});
        let err = make_commitment(&short_salt, &bad_content).unwrap_err();
        assert!(
            err.to_string().contains("salt"),
            "expected salt error before JCS error, got: {err}"
        );
    }
}
