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

    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| Ok(merkle::leaf_hash(&jcs::canonicalize(e)?)))
        .collect::<Result<_, Error>>()?;
    let root = merkle::merkle_root(&leaves)?;
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
