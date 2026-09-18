use crate::error::Error;
use sha2::{Digest, Sha256};

pub const EMPTY_ROOT: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn failure(message: &str) -> Error {
    Error::Merkle(message.to_owned())
}

fn split(size: u64) -> u64 {
    1u64 << (u64::BITS - 1 - (size - 1).leading_zeros())
}

fn index(value: u64) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| failure("tree position is not addressable"))
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return EMPTY_ROOT;
    }
    let mut complete: Vec<[u8; 32]> = Vec::with_capacity(u64::BITS as usize);
    for (position, leaf) in leaves.iter().enumerate() {
        let mut hash = *leaf;
        let mut absorbed = position + 1;
        while absorbed.is_multiple_of(2) {
            let left = complete.pop().expect("a completed subtree to the left");
            hash = node_hash(&left, &hash);
            absorbed /= 2;
        }
        complete.push(hash);
    }
    let mut root = complete.pop().expect("at least one subtree");
    while let Some(left) = complete.pop() {
        root = node_hash(&left, &root);
    }
    root
}

pub fn inclusion_proof(index_of_leaf: u64, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, Error> {
    let position = index(index_of_leaf)?;
    if position >= leaves.len() {
        return Err(failure("leaf index is outside the tree"));
    }
    fn walk(m: usize, d: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if d.len() <= 1 {
            return Vec::new();
        }
        let k = split(d.len() as u64) as usize;
        let mut path;
        if m < k {
            path = walk(m, &d[..k]);
            path.push(merkle_root(&d[k..]));
        } else {
            path = walk(m - k, &d[k..]);
            path.push(merkle_root(&d[..k]));
        }
        path
    }
    Ok(walk(position, leaves))
}

pub fn verify_inclusion(
    leaf: &[u8; 32],
    index_of_leaf: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<(), Error> {
    if tree_size == 0 || index_of_leaf >= tree_size {
        return Err(failure("leaf index is outside the tree"));
    }
    let (mut fnode, mut snode, mut consumed) = (index_of_leaf, tree_size - 1, 0usize);
    let mut hash = *leaf;
    let short = || failure("the audit path ends before the root");
    while snode > 0 {
        if fnode % 2 == 1 {
            let sibling = path.get(consumed).ok_or_else(short)?;
            hash = node_hash(sibling, &hash);
            consumed += 1;
        } else if fnode < snode {
            let sibling = path.get(consumed).ok_or_else(short)?;
            hash = node_hash(&hash, sibling);
            consumed += 1;
        }
        fnode /= 2;
        snode /= 2;
    }
    if consumed != path.len() {
        return Err(failure("the audit path carries unconsumed siblings"));
    }
    if hash != *root {
        return Err(failure("the audit path does not reproduce the root"));
    }
    Ok(())
}

pub fn consistency_proof(m: u64, n: u64, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, Error> {
    if m > n || n > leaves.len() as u64 {
        return Err(failure(
            "a Consistency Proof requires 0 <= m <= n <= tree size",
        ));
    }
    if m == 0 || m == n {
        return Ok(Vec::new());
    }
    fn walk(m: usize, d: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
        if m == d.len() {
            return if complete {
                Vec::new()
            } else {
                vec![merkle_root(d)]
            };
        }
        let k = split(d.len() as u64) as usize;
        let mut path;
        if m <= k {
            path = walk(m, &d[..k], complete);
            path.push(merkle_root(&d[k..]));
        } else {
            path = walk(m - k, &d[k..], false);
            path.push(merkle_root(&d[..k]));
        }
        path
    }
    Ok(walk(index(m)?, &leaves[..index(n)?], true))
}

pub fn verify_consistency(
    m: u64,
    n: u64,
    m_root: &[u8; 32],
    n_root: &[u8; 32],
    path: &[[u8; 32]],
) -> Result<(), Error> {
    if m > n {
        return Err(failure(
            "no Consistency Proof runs from a larger tree to a smaller one",
        ));
    }
    if m == 0 || m == n {
        if !path.is_empty() {
            return Err(failure(
                "a Consistency Proof at m = 0 or m = n carries no nodes",
            ));
        }
        if m == n && m_root != n_root {
            return Err(failure("equal tree sizes state different roots"));
        }
        return Ok(());
    }
    let (mut node, mut last) = (m - 1, n - 1);
    while node % 2 == 1 {
        node /= 2;
        last /= 2;
    }
    let mut consumed = 0usize;
    let short = || failure("the Consistency Proof ends before the root");
    let (mut old_hash, mut new_hash) = if node > 0 {
        let seed = *path.first().ok_or_else(short)?;
        consumed = 1;
        (seed, seed)
    } else {
        (*m_root, *m_root)
    };
    while last > 0 {
        if node % 2 == 1 {
            let sibling = *path.get(consumed).ok_or_else(short)?;
            consumed += 1;
            old_hash = node_hash(&sibling, &old_hash);
            new_hash = node_hash(&sibling, &new_hash);
        } else if node < last {
            let sibling = *path.get(consumed).ok_or_else(short)?;
            consumed += 1;
            new_hash = node_hash(&new_hash, &sibling);
        }
        node /= 2;
        last /= 2;
    }
    if old_hash != *m_root {
        return Err(failure(
            "the Consistency Proof does not reproduce the earlier root",
        ));
    }
    if new_hash != *n_root {
        return Err(failure(
            "the Consistency Proof does not reproduce the later root",
        ));
    }
    if consumed != path.len() {
        return Err(failure("the Consistency Proof carries unconsumed nodes"));
    }
    Ok(())
}

pub trait HashReader {
    fn node(&self, level: u32, index: u64) -> Result<[u8; 32], Error>;
}

pub struct LeafHashes<'a>(pub &'a [[u8; 32]]);

impl HashReader for LeafHashes<'_> {
    fn node(&self, level: u32, node_index: u64) -> Result<[u8; 32], Error> {
        let width = 1u64
            .checked_shl(level)
            .ok_or_else(|| failure("tree level is outside the tree"))?;
        let start = node_index
            .checked_mul(width)
            .ok_or_else(|| failure("tree position is outside the tree"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| failure("tree position is outside the tree"))?;
        let (start, end) = (index(start)?, index(end)?);
        if end > self.0.len() {
            return Err(failure("tree position is outside the tree"));
        }
        Ok(merkle_root(&self.0[start..end]))
    }
}

pub struct Extended<'a> {
    prior: &'a dyn HashReader,
    previous_size: u64,
    appended: &'a [[u8; 32]],
}

impl<'a> Extended<'a> {
    pub fn new(prior: &'a dyn HashReader, previous_size: u64, appended: &'a [[u8; 32]]) -> Self {
        Extended {
            prior,
            previous_size,
            appended,
        }
    }
}

impl HashReader for Extended<'_> {
    fn node(&self, level: u32, node_index: u64) -> Result<[u8; 32], Error> {
        let width = 1u64
            .checked_shl(level)
            .ok_or_else(|| failure("tree level is outside the tree"))?;
        let start = node_index
            .checked_mul(width)
            .ok_or_else(|| failure("tree position is outside the tree"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| failure("tree position is outside the tree"))?;
        if end <= self.previous_size {
            return self.prior.node(level, node_index);
        }
        if start >= self.previous_size {
            let (from, to) = (
                index(start - self.previous_size)?,
                index(end - self.previous_size)?,
            );
            if to > self.appended.len() {
                return Err(failure("tree position is outside the tree"));
            }
            return Ok(merkle_root(&self.appended[from..to]));
        }
        if level == 0 {
            return Err(failure("tree position is outside the tree"));
        }
        let left = self.node(level - 1, node_index * 2)?;
        let right = self.node(level - 1, node_index * 2 + 1)?;
        Ok(node_hash(&left, &right))
    }
}

fn subtree_root(reader: &dyn HashReader, start: u64, size: u64) -> Result<[u8; 32], Error> {
    if size == 0 {
        return Err(failure("an empty range has no subtree root"));
    }
    if size.is_power_of_two() && start.is_multiple_of(size) {
        return reader.node(size.trailing_zeros(), start / size);
    }
    let k = split(size);
    let left = subtree_root(reader, start, k)?;
    let right = subtree_root(reader, start + k, size - k)?;
    Ok(node_hash(&left, &right))
}

pub fn root_from(reader: &dyn HashReader, tree_size: u64) -> Result<[u8; 32], Error> {
    if tree_size == 0 {
        return Ok(EMPTY_ROOT);
    }
    subtree_root(reader, 0, tree_size)
}

pub fn inclusion_proof_from(
    reader: &dyn HashReader,
    index_of_leaf: u64,
    tree_size: u64,
) -> Result<Vec<[u8; 32]>, Error> {
    if index_of_leaf >= tree_size {
        return Err(failure("leaf index is outside the tree"));
    }
    fn walk(
        reader: &dyn HashReader,
        m: u64,
        start: u64,
        size: u64,
    ) -> Result<Vec<[u8; 32]>, Error> {
        if size <= 1 {
            return Ok(Vec::new());
        }
        let k = split(size);
        let mut path;
        if m < k {
            path = walk(reader, m, start, k)?;
            path.push(subtree_root(reader, start + k, size - k)?);
        } else {
            path = walk(reader, m - k, start + k, size - k)?;
            path.push(subtree_root(reader, start, k)?);
        }
        Ok(path)
    }
    walk(reader, index_of_leaf, 0, tree_size)
}

pub fn consistency_proof_from(
    reader: &dyn HashReader,
    m: u64,
    n: u64,
) -> Result<Vec<[u8; 32]>, Error> {
    if m > n {
        return Err(failure("a Consistency Proof requires 0 <= m <= n"));
    }
    if m == 0 || m == n {
        return Ok(Vec::new());
    }
    fn walk(
        reader: &dyn HashReader,
        m: u64,
        start: u64,
        size: u64,
        complete: bool,
    ) -> Result<Vec<[u8; 32]>, Error> {
        if m == size {
            return if complete {
                Ok(Vec::new())
            } else {
                Ok(vec![subtree_root(reader, start, size)?])
            };
        }
        let k = split(size);
        let mut path;
        if m <= k {
            path = walk(reader, m, start, k, complete)?;
            path.push(subtree_root(reader, start + k, size - k)?);
        } else {
            path = walk(reader, m - k, start + k, size - k, false)?;
            path.push(subtree_root(reader, start, k)?);
        }
        Ok(path)
    }
    walk(reader, m, 0, n, true)
}

pub fn root_after_appending(
    prior: &dyn HashReader,
    previous_size: u64,
    appended: &[[u8; 32]],
) -> Result<[u8; 32], Error> {
    let size = previous_size
        .checked_add(appended.len() as u64)
        .ok_or_else(|| failure("tree size is not addressable"))?;
    root_from(&Extended::new(prior, previous_size, appended), size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(format!("{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_tree_root_is_the_hash_of_no_octets() {
        assert_eq!(merkle_root(&[]), EMPTY_ROOT);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(b"")), EMPTY_ROOT);
        assert_eq!(root_from(&LeafHashes(&[]), 0).unwrap(), EMPTY_ROOT);
    }

    #[test]
    fn single_leaf_root_is_that_leaf() {
        let l = leaf_hash(b"a");
        assert_eq!(merkle_root(&[l]), l);
        assert_eq!(inclusion_proof(0, &[l]).unwrap(), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn an_unpaired_trailing_node_is_promoted_unchanged() {
        let ls: Vec<[u8; 32]> = [b"a", b"b", b"c"].iter().map(|d| leaf_hash(*d)).collect();
        let expected = node_hash(&node_hash(&ls[0], &ls[1]), &ls[2]);
        assert_eq!(merkle_root(&ls), expected);
    }

    #[test]
    fn stored_hashes_reproduce_the_slice_computations() {
        for n in 0u64..40 {
            let ls = leaves(n as usize);
            let reader = LeafHashes(&ls);
            assert_eq!(root_from(&reader, n).unwrap(), merkle_root(&ls));
            for i in 0..n {
                assert_eq!(
                    inclusion_proof_from(&reader, i, n).unwrap(),
                    inclusion_proof(i, &ls).unwrap()
                );
            }
            for m in 0..=n {
                assert_eq!(
                    consistency_proof_from(&reader, m, n).unwrap(),
                    consistency_proof(m, n, &ls).unwrap()
                );
            }
        }
    }

    #[test]
    fn appended_leaves_extend_the_prior_tree() {
        let ls = leaves(37);
        for previous in 0..=37usize {
            let prior = LeafHashes(&ls[..previous]);
            assert_eq!(
                root_after_appending(&prior, previous as u64, &ls[previous..]).unwrap(),
                merkle_root(&ls)
            );
        }
    }

    #[test]
    fn a_proof_that_runs_short_or_long_is_rejected() {
        let ls = leaves(5);
        let root = merkle_root(&ls);
        let path = inclusion_proof(1, &ls).unwrap();
        verify_inclusion(&ls[1], 1, 5, &path, &root).unwrap();
        assert!(verify_inclusion(&ls[1], 1, 5, &path[..1], &root).is_err());
        let mut long = path.clone();
        long.push([0u8; 32]);
        assert!(verify_inclusion(&ls[1], 1, 5, &long, &root).is_err());
        assert!(verify_inclusion(&ls[1], 5, 5, &path, &root).is_err());
        assert!(verify_inclusion(&ls[1], 1, 4, &path, &root).is_err());
    }

    #[test]
    fn a_consistency_proof_to_a_smaller_tree_does_not_exist() {
        let ls = leaves(6);
        let root = merkle_root(&ls);
        assert!(consistency_proof(6, 4, &ls).is_err());
        assert!(verify_consistency(6, 4, &root, &merkle_root(&ls[..4]), &[]).is_err());
        assert!(verify_consistency(4, 4, &root, &root, &[[0u8; 32]]).is_err());
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn generated_paths_verify(n in 1usize..64, seed in any::<u64>()) {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| leaf_hash(format!("{seed}-{i}").as_bytes()))
                .collect();
            let root = merkle_root(&leaves);
            for idx in 0..n {
                let path = inclusion_proof(idx as u64, &leaves).unwrap();
                verify_inclusion(&leaves[idx], idx as u64, n as u64, &path, &root).unwrap();
                if n > 1 {
                    let wrong = ((idx + 1) % n) as u64;
                    prop_assert!(verify_inclusion(
                        &leaves[idx], wrong, n as u64, &path, &root).is_err());
                }
            }
        }

        #[test]
        fn generated_consistency_proofs_verify(n in 1usize..64, seed in any::<u64>()) {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| leaf_hash(format!("{seed}-{i}").as_bytes()))
                .collect();
            let n_root = merkle_root(&leaves);
            for m in 0..=n {
                let m_root = merkle_root(&leaves[..m]);
                let path = consistency_proof(m as u64, n as u64, &leaves).unwrap();
                verify_consistency(m as u64, n as u64, &m_root, &n_root, &path).unwrap();
                if m > 0 && m < n {
                    let mut altered = path.clone();
                    altered[0][0] ^= 1;
                    prop_assert!(verify_consistency(
                        m as u64, n as u64, &m_root, &n_root, &altered).is_err());
                }
            }
        }
    }
}
