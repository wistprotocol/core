use crate::checkpoint::Checkpoint;
use crate::error::Error;
use crate::merkle::{self, HashReader};
use crate::tiles;
use crate::{jcs, json};
use serde_json::Value;

pub const ENTRY_TYPES: [&str; 5] = [
    "publisher_declaration",
    "registry_update",
    "publisher_delta",
    "label",
    "dispute",
];

fn invalid(message: &str) -> Error {
    Error::Block(format!("WIST3-E03 {message}"))
}

pub fn entry_group(entry: &Value) -> Result<usize, Error> {
    let kind = entry["type"]
        .as_str()
        .and_then(|kind| ENTRY_TYPES.iter().position(|known| *known == kind))
        .ok_or_else(|| invalid("unknown Block Entry type"))?;
    if entry.as_object().is_none_or(|object| object.len() != 2) || !entry["body"].is_object() {
        return Err(invalid("malformed Block Entry envelope"));
    }
    Ok(kind)
}

pub fn entry_leaf(entry: &Value) -> Result<(Vec<u8>, [u8; 32]), Error> {
    let bytes = jcs::canonicalize(entry)?;
    tiles::check_entry_bytes(bytes.len() as u64)?;
    let hash = merkle::leaf_hash(&bytes);
    Ok((bytes, hash))
}

/// WIST-3 §3.3: Entries are grouped by type in the fixed order and, within
/// a group, in ascending octet order of their Merkle leaf hashes; a Block
/// ordered otherwise is rejected by every replaying party.
pub fn validate_entry_order(entries: &[Value]) -> Result<(), Error> {
    leaf_hashes(entries).map(|_| ())
}

pub fn leaf_hashes(entries: &[Value]) -> Result<Vec<[u8; 32]>, Error> {
    let mut hashes = Vec::with_capacity(entries.len());
    let mut previous: Option<(usize, [u8; 32])> = None;
    for entry in entries {
        let group = entry_group(entry)?;
        let (_, hash) = entry_leaf(entry)?;
        let order = (group, hash);
        if previous.is_some_and(|previous| previous > order) {
            return Err(invalid("Block Entries are not in canonical order"));
        }
        previous = Some(order);
        hashes.push(hash);
    }
    Ok(hashes)
}

pub fn sort_entries(entries: &mut [Value]) -> Result<(), Error> {
    let mut keyed: Vec<((usize, [u8; 32]), Value)> = entries
        .iter()
        .map(|entry| {
            let group = entry_group(entry)?;
            let (_, hash) = entry_leaf(entry)?;
            Ok(((group, hash), entry.clone()))
        })
        .collect::<Result<_, Error>>()?;
    keyed.sort_by_key(|entry| entry.0);
    for (slot, (_, entry)) in entries.iter_mut().zip(keyed) {
        *slot = entry;
    }
    Ok(())
}

pub fn block_octets(entries: &[Value]) -> Result<u64, Error> {
    let mut octets: u64 = 0;
    for entry in entries {
        let (bytes, _) = entry_leaf(entry)?;
        octets += bytes.len() as u64 + 2;
    }
    Ok(octets)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    pub leaf_hashes: Vec<[u8; 32]>,
    pub octets: u64,
}

pub fn verify_block(
    previous_size: u64,
    checkpoint: &Checkpoint,
    entries: &[Value],
    prior_tree: &dyn HashReader,
    block_cap_bytes: u64,
) -> Result<BlockSummary, Error> {
    if checkpoint.tree_size() < previous_size {
        return Err(Error::Block(
            "WIST3-E02 a Block's tree size is not below the Block before it".into(),
        ));
    }
    if checkpoint.tree_size() - previous_size != entries.len() as u64 {
        return Err(invalid("the Block's Entries do not fill its leaf range"));
    }
    let mut octets: u64 = 0;
    let mut hashes = Vec::with_capacity(entries.len());
    let mut previous: Option<(usize, [u8; 32])> = None;
    for entry in entries {
        let group = entry_group(entry)?;
        let (bytes, hash) = entry_leaf(entry)?;
        let order = (group, hash);
        if previous.is_some_and(|previous| previous > order) {
            return Err(invalid("Block Entries are not in canonical order"));
        }
        previous = Some(order);
        octets += bytes.len() as u64 + 2;
        hashes.push(hash);
    }
    if octets > block_cap_bytes {
        return Err(invalid("a Block over the size cap in force"));
    }
    if merkle::root_after_appending(prior_tree, previous_size, &hashes)? != *checkpoint.root() {
        return Err(invalid(
            "the Block's Entries do not reproduce the root the Checkpoint states",
        ));
    }
    Ok(BlockSummary {
        leaf_hashes: hashes,
        octets,
    })
}

pub fn parse_entries(leaf_data: &[Vec<u8>]) -> Result<Vec<Value>, Error> {
    leaf_data
        .iter()
        .map(|bytes| {
            let entry = json::parse(bytes)
                .map_err(|e| invalid(&format!("an Entry does not parse: {e}")))?;
            if jcs::canonicalize(&entry)? != *bytes {
                return Err(invalid("an Entry's leaf data is not its JCS serialization"));
            }
            Ok(entry)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::merkle::LeafHashes;
    use serde_json::json;

    fn entry(kind: &str, value: u64) -> Value {
        json!({"type": kind, "body": {"n": value}})
    }

    fn sealed(previous: &[[u8; 32]], entries: &[Value], block_number: u64) -> Checkpoint {
        let mut leaves = previous.to_vec();
        leaves.extend(leaf_hashes(entries).unwrap());
        let mut checkpoint = Checkpoint::new(
            "log.example.org",
            leaves.len() as u64,
            merkle::merkle_root(&leaves),
            block_number,
            "2026-08-02T13:00:00Z",
        )
        .unwrap();
        checkpoint.sign(&SigningKey::from_seed(&[5u8; 32]));
        checkpoint
    }

    fn canonical(mut entries: Vec<Value>) -> Vec<Value> {
        sort_entries(&mut entries).unwrap();
        entries
    }

    #[test]
    fn a_blocks_entries_reproduce_the_root_the_checkpoint_states() {
        let entries = canonical(vec![
            entry("publisher_delta", 1),
            entry("publisher_delta", 2),
            entry("label", 3),
        ]);
        let checkpoint = sealed(&[], &entries, 0);
        let summary = verify_block(0, &checkpoint, &entries, &LeafHashes(&[]), 1 << 20).unwrap();
        assert_eq!(summary.leaf_hashes.len(), 3);
        assert_eq!(summary.octets, block_octets(&entries).unwrap());
    }

    #[test]
    fn a_later_block_extends_the_tree_of_the_block_before_it() {
        let first = canonical(vec![entry("publisher_delta", 1), entry("label", 2)]);
        let first_hashes = leaf_hashes(&first).unwrap();
        let second = canonical(vec![entry("dispute", 3)]);
        let checkpoint = sealed(&first_hashes, &second, 1);
        verify_block(
            first_hashes.len() as u64,
            &checkpoint,
            &second,
            &LeafHashes(&first_hashes),
            1 << 20,
        )
        .unwrap();
    }

    #[test]
    fn an_empty_block_restates_the_previous_tree() {
        let first = canonical(vec![entry("publisher_delta", 1)]);
        let hashes = leaf_hashes(&first).unwrap();
        let checkpoint = sealed(&hashes, &[], 1);
        assert_eq!(checkpoint.tree_size(), 1);
        let summary = verify_block(1, &checkpoint, &[], &LeafHashes(&hashes), 1 << 20).unwrap();
        assert_eq!(summary.octets, 0);
        assert!(summary.leaf_hashes.is_empty());
    }

    #[test]
    fn sorting_puts_entries_in_the_order_a_block_seals_them() {
        let mut entries = vec![
            entry("dispute", 1),
            entry("publisher_delta", 2),
            entry("publisher_declaration", 3),
            entry("registry_update", 4),
            entry("label", 5),
        ];
        sort_entries(&mut entries).unwrap();
        let groups: Vec<&str> = entries
            .iter()
            .map(|entry| entry["type"].as_str().unwrap())
            .collect();
        assert_eq!(groups, ENTRY_TYPES);
        validate_entry_order(&entries).unwrap();
    }

    #[test]
    fn entries_outside_the_canonical_order_or_type_are_rejected() {
        let mut entries = canonical(vec![entry("publisher_delta", 1), entry("label", 2)]);
        entries.reverse();
        assert_eq!(
            validate_entry_order(&entries).unwrap_err().code(),
            Some("WIST3-E03")
        );
        assert_eq!(
            validate_entry_order(&[entry("surprise", 1)])
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
    }

    #[test]
    fn a_block_whose_checkpoint_shrinks_the_tree_is_reported_as_divergence() {
        let entries = canonical(vec![entry("publisher_delta", 1), entry("label", 2)]);
        let hashes = leaf_hashes(&entries).unwrap();
        let checkpoint = sealed(&hashes, &[], 1);
        let err = verify_block(
            hashes.len() as u64 + 1,
            &checkpoint,
            &[],
            &LeafHashes(&hashes),
            1 << 20,
        )
        .unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E02"));
    }

    #[test]
    fn a_block_over_the_cap_in_force_is_rejected() {
        let entries = canonical(vec![entry("publisher_delta", 1)]);
        let checkpoint = sealed(&[], &entries, 0);
        let octets = block_octets(&entries).unwrap();
        verify_block(0, &checkpoint, &entries, &LeafHashes(&[]), octets).unwrap();
        let err = verify_block(0, &checkpoint, &entries, &LeafHashes(&[]), octets - 1).unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E03"));
    }

    #[test]
    fn leaf_data_that_is_not_its_entrys_jcs_is_rejected() {
        let entries = canonical(vec![entry("publisher_delta", 1)]);
        let leaf_data: Vec<Vec<u8>> = entries
            .iter()
            .map(|e| jcs::canonicalize(e).unwrap())
            .collect();
        assert_eq!(parse_entries(&leaf_data).unwrap(), entries);
        assert!(parse_entries(&[b" {\"type\":\"label\",\"body\":{}}".to_vec()]).is_err());
    }
}
