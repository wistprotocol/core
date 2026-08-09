use crate::crypto::{hex_encode, verify, PublicKey};
use crate::error::Error;
use crate::{jcs, merkle};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn field<'a>(v: &'a Value, path: &str) -> Result<&'a Value, Error> {
    v.pointer(path)
        .ok_or_else(|| Error::Block(format!("missing {path}")))
}

pub fn block_hash(header: &Value) -> Result<String, Error> {
    let canonical = jcs::canonicalize(header)?;
    Ok(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(&canonical))
    ))
}

pub fn verify_block(doc: &Value, key: &PublicKey) -> Result<(), Error> {
    let header = field(doc, "/header")?;
    let entries = field(doc, "/entries")?
        .as_array()
        .ok_or_else(|| Error::Block("entries is not an array".into()))?;
    let sig = field(doc, "/sig/value")?
        .as_str()
        .ok_or_else(|| Error::Block("sig.value is not a string".into()))?;
    verify(key, &jcs::canonicalize(header)?, sig)?;

    let declared = field(header, "/entry_count")?
        .as_u64()
        .ok_or_else(|| Error::Block("entry_count is not an integer".into()))?;
    if declared != entries.len() as u64 {
        return Err(Error::Block("entry_count mismatch".into()));
    }

    // WIST-3 §4: empty Blocks pin merkle_root to the leaf hash of zero
    // bytes, not RFC 6962's MTH({}) = SHA-256(""); merkle_root() errors on
    // an empty leaf set, so this case is handled separately.
    let root = if entries.is_empty() {
        merkle::leaf_hash(&[])
    } else {
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|e| Ok(merkle::leaf_hash(&jcs::canonicalize(e)?)))
            .collect::<Result<_, Error>>()?;
        merkle::merkle_root(&leaves)?
    };
    let declared_root = field(header, "/merkle_root")?
        .as_str()
        .ok_or_else(|| Error::Block("merkle_root is not a string".into()))?;
    if format!("sha256:{}", hex_encode(&root)) != declared_root {
        return Err(Error::Block("merkle root mismatch".into()));
    }
    Ok(())
}

pub fn verify_chain_link(header: &Value, prev_hash: &str) -> Result<(), Error> {
    let prev = field(header, "/prev_block_hash")?
        .as_str()
        .ok_or_else(|| Error::Block("prev_block_hash is not a string".into()))?;
    let number = field(header, "/block_number")?
        .as_u64()
        .ok_or_else(|| Error::Block("block_number is not an integer".into()))?;
    if number == 0 && prev != "sha256:genesis" {
        return Err(Error::Block("block 0 must carry sha256:genesis".into()));
    }
    if prev != prev_hash {
        return Err(Error::Block("chain link mismatch".into()));
    }
    Ok(())
}

pub fn verify_checkpoint_binding(checkpoint: &Value, block: &Value) -> Result<(), Error> {
    let header = field(block, "/header")?;
    let declared_hash = field(checkpoint, "/checkpoint/block_hash")?;
    let declared_number = field(checkpoint, "/checkpoint/block_number")?;
    if declared_hash != &Value::from(block_hash(header)?) {
        return Err(Error::Block("checkpoint does not bind block".into()));
    }
    if declared_number != field(header, "/block_number")? {
        return Err(Error::Block("block_number mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;

    const EMPTY_MERKLE_ROOT: &str =
        "sha256:6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

    fn empty_block(sk: &SigningKey, merkle_root: &str) -> Value {
        let header = serde_json::json!({
            "wist_version": "1.0.0",
            "block_number": 0,
            "prev_block_hash": "sha256:genesis",
            "sealed_at": "2026-08-02T13:00:00Z",
            "merkle_root": merkle_root,
            "entry_count": 0
        });
        let sig = sk.sign(&jcs::canonicalize(&header).unwrap());
        serde_json::json!({
            "header": header,
            "entries": [],
            "sig": {"key_id": "test-agg-k1", "alg": "Ed25519", "value": sig}
        })
    }

    #[test]
    fn verify_block_accepts_spec_conformant_empty_block() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let block = empty_block(&sk, EMPTY_MERKLE_ROOT);
        verify_block(&block, &sk.public()).unwrap();
    }

    #[test]
    fn verify_block_rejects_empty_block_with_wrong_root() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let wrong_root = format!("sha256:{}", "0".repeat(64));
        let block = empty_block(&sk, &wrong_root);
        assert!(verify_block(&block, &sk.public()).is_err());
    }
}
