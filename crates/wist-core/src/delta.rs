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

pub fn verify_commitment(salt_b64u: &str, content: &Value, declared: &str) -> Result<(), Error> {
    let salt = b64u_decode(salt_b64u)?;
    if salt.len() < 16 {
        return Err(Error::Commitment("salt shorter than 128 bits".into()));
    }
    let canonical = jcs::canonicalize(content)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&salt).map_err(|e| Error::Commitment(e.to_string()))?;
    mac.update(&canonical);
    let got = format!("hmac-sha256:{}", hex_encode(&mac.finalize().into_bytes()));
    if got != declared {
        return Err(Error::Commitment("commitment mismatch".into()));
    }
    Ok(())
}
