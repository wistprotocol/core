use crate::error::Error;
use sha2::{Digest, Sha256};

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

pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    if leaves.is_empty() {
        return Err(Error::Merkle("empty leaf set".into()));
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node_hash(l, r),
                [lone] => *lone,
                _ => unreachable!(),
            })
            .collect();
    }
    Ok(level[0])
}

pub fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, Error> {
    if index >= leaves.len() {
        return Err(Error::Merkle("index out of range".into()));
    }
    fn rec(m: usize, d: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let n = d.len();
        if n <= 1 {
            return Vec::new();
        }
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        let mut path;
        if m < k {
            path = rec(m, &d[..k]);
            path.push(merkle_root(&d[k..]).expect("non-empty by construction"));
        } else {
            path = rec(m - k, &d[k..]);
            path.push(merkle_root(&d[..k]).expect("non-empty by construction"));
        }
        path
    }
    Ok(rec(index, leaves))
}

pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: usize,
    entry_count: usize,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<(), Error> {
    if index >= entry_count || entry_count == 0 {
        return Err(Error::Merkle("index out of range".into()));
    }
    let (mut fnode, mut snode, mut p) = (index, entry_count - 1, 0usize);
    let mut h = *leaf;
    while snode > 0 {
        if fnode % 2 == 1 {
            let sib = path
                .get(p)
                .ok_or_else(|| Error::Merkle("path too short".into()))?;
            h = node_hash(sib, &h);
            p += 1;
        } else if fnode < snode {
            let sib = path
                .get(p)
                .ok_or_else(|| Error::Merkle("path too short".into()))?;
            h = node_hash(&h, sib);
            p += 1;
        }
        fnode /= 2;
        snode /= 2;
    }
    if p != path.len() {
        return Err(Error::Merkle("unused path elements".into()));
    }
    if h != *root {
        return Err(Error::Merkle("root mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_leaf() {
        let l = leaf_hash(b"a");
        assert_eq!(merkle_root(&[l]).unwrap(), l);
        assert!(merkle_root(&[]).is_err());
        assert_eq!(audit_path(0, &[l]).unwrap(), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn three_leaves_odd_promotion() {
        let ls: Vec<[u8; 32]> = [b"a", b"b", b"c"].iter().map(|d| leaf_hash(*d)).collect();
        let expected = node_hash(&node_hash(&ls[0], &ls[1]), &ls[2]);
        assert_eq!(merkle_root(&ls).unwrap(), expected);
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
            let root = merkle_root(&leaves).unwrap();
            for idx in 0..n {
                let path = audit_path(idx, &leaves).unwrap();
                verify_inclusion(&leaves[idx], idx, n, &path, &root).unwrap();
                if n > 1 {
                    let wrong = (idx + 1) % n;
                    prop_assert!(verify_inclusion(
                        &leaves[idx], wrong, n, &path, &root).is_err());
                }
            }
        }
    }
}
