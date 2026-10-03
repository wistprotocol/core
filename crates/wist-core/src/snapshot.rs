use crate::checkpoint::Checkpoint;
use crate::crypto::hex_encode;
use crate::error::Error;
use crate::jcs;
use crate::materialization::ContentTuple;
use crate::objects::SnapshotManifest;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::num::NonZeroU64;

pub const TIER_FILES: [(&str, u8); 6] = [
    ("tier0/index.sqlite", 0),
    ("tier1/extracts.parquet", 1),
    ("tier1/links.parquet", 1),
    ("tier1/labels.parquet", 1),
    ("tier1/disputes.parquet", 1),
    ("tier1/labelers.parquet", 1),
];

fn digest_of<T: Serialize>(tuples: &[T]) -> Result<String, Error> {
    let mut sers: Vec<Vec<u8>> = tuples
        .iter()
        .map(|tuple| {
            serde_json::to_value(tuple)
                .map_err(|e| Error::Jcs(e.to_string()))
                .and_then(|value| jcs::canonicalize(&value))
        })
        .collect::<Result<_, _>>()?;
    sers.sort();
    let hash = Sha256::digest(sers.concat());
    Ok(format!("sha256:{}", hex_encode(&hash)))
}

pub fn content_digest(tuples: &[ContentTuple]) -> Result<String, Error> {
    digest_of(tuples)
}

pub fn shard_of(domain: &str, count: NonZeroU64) -> u64 {
    let hash = Sha256::digest(domain.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&hash[..8]);
    u64::from_be_bytes(first) % count.get()
}

pub fn shard_path(shard: u64, tier_file: &str) -> String {
    format!("shard-{shard}/{tier_file}")
}

pub fn check_state_tree_size(
    manifest: &SnapshotManifest,
    state_tree_size: u64,
) -> Result<(), Error> {
    if state_tree_size != manifest.tree_size {
        return Err(Error::Snapshot(
            "WIST3-E04 the state file states another tree_size than the manifest".into(),
        ));
    }
    Ok(())
}

pub fn check_manifest_anchor(
    manifest: &SnapshotManifest,
    checkpoint: &Checkpoint,
) -> Result<(), Error> {
    let divergence = |message: &str| Error::Snapshot(format!("WIST3-E02 {message}"));
    if manifest.epoch_number != checkpoint.epoch_number() {
        return Err(Error::Snapshot(
            "WIST3-E03 the Checkpoint at the manifest's epoch_number states another Epoch".into(),
        ));
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
    digest_of(entries)
}
