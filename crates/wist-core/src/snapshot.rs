use crate::checkpoint::Checkpoint;
use crate::crypto::hex_encode;
use crate::error::Error;
use crate::jcs;
use crate::objects::SnapshotManifest;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const RECORD_FIELDS: [&str; 4] = ["url", "publisher", "delta_id", "observed_at"];

pub fn check_record_shape(r: &Value) -> Result<(), Error> {
    let obj = r
        .as_object()
        .ok_or_else(|| Error::Snapshot("record is not an object".into()))?;

    let mut actual_keys: Vec<&String> = obj.keys().collect();
    actual_keys.sort();

    let mut expected_keys: Vec<&str> = RECORD_FIELDS.to_vec();
    expected_keys.sort();

    let actual_strs: Vec<&str> = actual_keys.iter().map(|s| s.as_str()).collect();

    if actual_strs == expected_keys {
        Ok(())
    } else {
        Err(Error::Snapshot(format!(
            "record keys mismatch: expected {:?}, got {:?}",
            expected_keys, actual_strs
        )))
    }
}

pub fn content_digest(records: &[Value]) -> Result<String, Error> {
    let mut sers: Vec<Vec<u8>> = records
        .iter()
        .map(jcs::canonicalize)
        .collect::<Result<_, _>>()?;
    sers.sort();

    let concatenated = sers
        .iter()
        .flat_map(|s| s.iter())
        .copied()
        .collect::<Vec<u8>>();
    let hash = Sha256::digest(&concatenated);

    Ok(format!("sha256:{}", hex_encode(&hash)))
}

pub fn check_manifest_anchor(
    manifest: &SnapshotManifest,
    checkpoint: &Checkpoint,
) -> Result<(), Error> {
    let divergence = |message: &str| Error::Snapshot(format!("WIST3-E02 {message}"));
    if manifest.epoch_number != checkpoint.epoch_number() {
        return Err(divergence("the Checkpoint is not the Snapshot's Epoch"));
    }
    if manifest.tree_size != checkpoint.tree_size() {
        return Err(divergence(
            "the Checkpoint's tree size is not the Snapshot's tree_size",
        ));
    }
    if manifest.root_hash != checkpoint.root_token() {
        return Err(divergence(
            "the Checkpoint states another root than root_hash",
        ));
    }
    Ok(())
}

pub fn state_digest(entries: &[Value]) -> Result<String, Error> {
    let mut sers: Vec<Vec<u8>> = entries
        .iter()
        .map(jcs::canonicalize)
        .collect::<Result<_, _>>()?;
    sers.sort();

    let concatenated = sers
        .iter()
        .flat_map(|s| s.iter())
        .copied()
        .collect::<Vec<u8>>();
    let hash = Sha256::digest(&concatenated);

    Ok(format!("sha256:{}", hex_encode(&hash)))
}
