use crate::error::Error;
use crate::merkle::{self, HashReader};
use std::collections::BTreeMap;

pub const TILE_HEIGHT: u32 = 8;
pub const TILE_WIDTH: u32 = 256;
pub const TILE_MAX_BYTES: u64 = 8_192;
pub const ENTRY_BUNDLE_MAX_BYTES: u64 = 16_777_472;
pub const ENTRY_MAX_BYTES: u64 = 65_535;

fn invalid(message: &str) -> Error {
    Error::Tile(format!("WIST3-E03 {message}"))
}

pub fn path_index(index: u64) -> String {
    let mut groups = Vec::new();
    let mut rest = index;
    loop {
        groups.push(format!("{:03}", rest % 1000));
        rest /= 1000;
        if rest == 0 {
            break;
        }
    }
    groups.reverse();
    let last = groups.pop().expect("at least one group");
    let mut path = String::new();
    for group in groups {
        path.push('x');
        path.push_str(&group);
        path.push('/');
    }
    path.push_str(&last);
    path
}

fn width_suffix(width: u32) -> String {
    if width < TILE_WIDTH {
        format!(".p/{width}")
    } else {
        String::new()
    }
}

pub fn path_width(path: &str) -> Result<u32, Error> {
    let Some((_, stated)) = path.rsplit_once(".p/") else {
        return Ok(TILE_WIDTH);
    };
    let canonical = stated == "0" || (!stated.starts_with('0') && !stated.is_empty());
    let width = (canonical && stated.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| stated.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| Error::Tile("a partial path states no decimal width".into()))?;
    if !(1..u64::from(TILE_WIDTH)).contains(&width) {
        return Err(invalid(
            "a partial path states a width outside 1 through 255",
        ));
    }
    Ok(width as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tile {
    pub level: u8,
    pub index: u64,
    pub width: u32,
}

impl Tile {
    pub fn path(&self) -> String {
        format!(
            "/tile/{}/{}{}",
            self.level,
            path_index(self.index),
            width_suffix(self.width)
        )
    }

    pub fn leaf_range(&self) -> (u64, u64) {
        let span = 1u64 << (TILE_HEIGHT * u32::from(self.level));
        let start = self.index * u64::from(TILE_WIDTH) * span;
        (start, start + u64::from(self.width) * span)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryBundle {
    pub index: u64,
    pub width: u32,
}

impl EntryBundle {
    pub fn path(&self) -> String {
        format!(
            "/tile/entries/{}{}",
            path_index(self.index),
            width_suffix(self.width)
        )
    }

    pub fn leaf_range(&self) -> (u64, u64) {
        let start = self.index * u64::from(TILE_WIDTH);
        (start, start + u64::from(self.width))
    }
}

pub fn required_tiles(tree_size: u64) -> Vec<Tile> {
    let mut tiles = Vec::new();
    let mut level = 0u8;
    loop {
        let hashes = tree_size >> (TILE_HEIGHT * u32::from(level));
        if hashes == 0 {
            break;
        }
        let full = hashes / u64::from(TILE_WIDTH);
        let remainder = (hashes % u64::from(TILE_WIDTH)) as u32;
        for index in 0..full {
            tiles.push(Tile {
                level,
                index,
                width: TILE_WIDTH,
            });
        }
        if remainder > 0 {
            tiles.push(Tile {
                level,
                index: full,
                width: remainder,
            });
        }
        level += 1;
    }
    tiles
}

pub fn required_entry_bundles(tree_size: u64) -> Vec<EntryBundle> {
    let full = tree_size / u64::from(TILE_WIDTH);
    let remainder = (tree_size % u64::from(TILE_WIDTH)) as u32;
    let mut bundles: Vec<EntryBundle> = (0..full)
        .map(|index| EntryBundle {
            index,
            width: TILE_WIDTH,
        })
        .collect();
    if remainder > 0 {
        bundles.push(EntryBundle {
            index: full,
            width: remainder,
        });
    }
    bundles
}

fn meets(range: (u64, u64), from: u64, to: u64) -> bool {
    range.0 < to && from < range.1
}

pub fn tiles_for_range(from: u64, to: u64, tree_size: u64) -> Vec<Tile> {
    required_tiles(tree_size)
        .into_iter()
        .filter(|tile| meets(tile.leaf_range(), from, to))
        .collect()
}

pub fn entry_bundles_for_range(from: u64, to: u64, tree_size: u64) -> Vec<EntryBundle> {
    required_entry_bundles(tree_size)
        .into_iter()
        .filter(|bundle| meets(bundle.leaf_range(), from, to))
        .collect()
}

pub fn encode_tile(hashes: &[[u8; 32]]) -> Vec<u8> {
    hashes
        .iter()
        .flat_map(|hash| hash.iter().copied())
        .collect()
}

pub fn decode_tile(bytes: &[u8]) -> Result<Vec<[u8; 32]>, Error> {
    if bytes.len() as u64 > TILE_MAX_BYTES {
        return Err(invalid("a tile over its format size"));
    }
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return Err(invalid("a tile is a whole number of 32-octet hashes"));
    }
    Ok(bytes
        .chunks(32)
        .map(|chunk| chunk.try_into().expect("32 octets"))
        .collect())
}

pub fn decode_tile_at(path: &str, bytes: &[u8]) -> Result<Vec<[u8; 32]>, Error> {
    let width = path_width(path)?;
    let hashes = decode_tile(bytes)?;
    if hashes.len() as u64 != u64::from(width) {
        return Err(invalid(
            "a tile holds a number of hashes other than the one its path states",
        ));
    }
    Ok(hashes)
}

pub fn decode_entry_bundle_at(path: &str, bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let width = path_width(path)?;
    let entries = decode_entry_bundle(bytes)?;
    if entries.len() as u64 != u64::from(width) {
        return Err(invalid(
            "an entry bundle holds a number of Entries other than the one its path states",
        ));
    }
    Ok(entries)
}

pub fn encode_entry_bundle(entries: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    if entries.len() as u32 > TILE_WIDTH {
        return Err(invalid("an entry bundle carries at most 256 Entries"));
    }
    let mut bytes = Vec::new();
    for entry in entries {
        check_entry_bytes(entry.len() as u64)?;
        bytes.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        bytes.extend_from_slice(entry);
    }
    Ok(bytes)
}

pub fn decode_entry_bundle(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    check_entry_bundle_bytes(bytes.len() as u64)?;
    let mut entries = Vec::new();
    let mut position = 0usize;
    while position < bytes.len() {
        let prefix = bytes
            .get(position..position + 2)
            .ok_or_else(|| invalid("an entry bundle ends inside a length prefix"))?;
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        let entry = bytes
            .get(position + 2..position + 2 + length)
            .ok_or_else(|| invalid("an entry bundle ends inside an Entry"))?;
        entries.push(entry.to_vec());
        position += 2 + length;
        if entries.len() as u32 > TILE_WIDTH {
            return Err(invalid("an entry bundle carries at most 256 Entries"));
        }
    }
    Ok(entries)
}

pub fn check_tile_bytes(octets: u64) -> Result<(), Error> {
    if octets > TILE_MAX_BYTES {
        return Err(invalid("a tile over its format size"));
    }
    Ok(())
}

pub fn check_entry_bundle_bytes(octets: u64) -> Result<(), Error> {
    if octets > ENTRY_BUNDLE_MAX_BYTES {
        return Err(invalid("an entry bundle over its format size"));
    }
    Ok(())
}

pub fn check_entry_bytes(octets: u64) -> Result<(), Error> {
    if octets > ENTRY_MAX_BYTES {
        return Err(invalid("an Entry over 65 535 octets"));
    }
    Ok(())
}

pub fn check_transport_bound(octets: u64, bound: u64) -> Result<(), Error> {
    if octets > bound {
        return Err(invalid("an Epoch over its transport bound"));
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct TileSet {
    tiles: BTreeMap<(u8, u64), Vec<[u8; 32]>>,
}

impl TileSet {
    pub fn new() -> Self {
        TileSet::default()
    }

    pub fn insert(&mut self, level: u8, index: u64, hashes: Vec<[u8; 32]>) {
        self.tiles.insert((level, index), hashes);
    }

    pub fn insert_bytes(&mut self, level: u8, index: u64, bytes: &[u8]) -> Result<(), Error> {
        self.insert(level, index, decode_tile(bytes)?);
        Ok(())
    }

    pub fn tile(&self, level: u8, index: u64) -> Option<&[[u8; 32]]> {
        self.tiles.get(&(level, index)).map(Vec::as_slice)
    }

    pub fn build(leaves: &[[u8; 32]]) -> Self {
        let mut set = TileSet::new();
        let reader = merkle::LeafHashes(leaves);
        let mut hashes: BTreeMap<(u8, u64), Vec<[u8; 32]>> = BTreeMap::new();
        for tile in required_tiles(leaves.len() as u64) {
            let level = TILE_HEIGHT * u32::from(tile.level);
            let first = tile.index * u64::from(TILE_WIDTH);
            let entries = (0..u64::from(tile.width))
                .map(|offset| reader.node(level, first + offset))
                .collect::<Result<Vec<_>, Error>>()
                .expect("complete subtrees of the tree the leaves define");
            hashes.insert((tile.level, tile.index), entries);
        }
        set.tiles = hashes;
        set
    }

    pub fn serve(&self, tree_size: u64) -> BTreeMap<String, Vec<u8>> {
        required_tiles(tree_size)
            .into_iter()
            .filter_map(|tile| {
                self.tile(tile.level, tile.index)
                    .map(|hashes| (tile.path(), encode_tile(hashes)))
            })
            .collect()
    }
}

impl HashReader for TileSet {
    fn node(&self, level: u32, index: u64) -> Result<[u8; 32], Error> {
        if level.is_multiple_of(TILE_HEIGHT) {
            let tile_level = u8::try_from(level / TILE_HEIGHT)
                .map_err(|_| invalid("a tree level beyond the tiled levels"))?;
            let hashes = self
                .tile(tile_level, index / u64::from(TILE_WIDTH))
                .ok_or_else(|| Error::Tile("WIST3-E01 a tile the tree needs is absent".into()))?;
            let offset = usize::try_from(index % u64::from(TILE_WIDTH)).expect("below 256");
            return hashes
                .get(offset)
                .copied()
                .ok_or_else(|| Error::Tile("WIST3-E01 a tile the tree needs is absent".into()));
        }
        let left = self.node(level - 1, index * 2)?;
        let right = self.node(level - 1, index * 2 + 1)?;
        Ok(merkle::node_hash(&left, &right))
    }
}

pub fn check_tree(tiles: &TileSet, tree_size: u64, root: &[u8; 32]) -> Result<(), Error> {
    if merkle::root_from(tiles, tree_size)? != *root {
        return Err(invalid("the tiles do not reproduce the Checkpoint's tree"));
    }
    Ok(())
}

pub fn check_entry_bundle(
    entries: &[Vec<u8>],
    first_leaf: u64,
    tiles: &TileSet,
) -> Result<(), Error> {
    for (offset, entry) in entries.iter().enumerate() {
        let index = first_leaf + offset as u64;
        let stored = tiles
            .node(0, index)
            .map_err(|_| invalid("the entry bundle's leaves are not in the tree's tiles"))?;
        if stored != merkle::leaf_hash(entry) {
            return Err(invalid("an Entry does not hash to its leaf in the tree"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| merkle::leaf_hash(format!("{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn a_tile_index_is_encoded_in_x_prefixed_three_digit_groups() {
        assert_eq!(path_index(0), "000");
        assert_eq!(path_index(44), "044");
        assert_eq!(path_index(999), "999");
        assert_eq!(path_index(1000), "x001/000");
        assert_eq!(path_index(1234), "x001/234");
        assert_eq!(path_index(1_000_000), "x001/x000/000");
        assert_eq!(
            Tile {
                level: 1,
                index: 1000,
                width: 3
            }
            .path(),
            "/tile/1/x001/000.p/3"
        );
        assert_eq!(
            EntryBundle {
                index: 1000,
                width: 256
            }
            .path(),
            "/tile/entries/x001/000"
        );
    }

    #[test]
    fn a_tree_size_requires_its_partial_tiles() {
        assert_eq!(
            required_tiles(300)
                .iter()
                .map(Tile::path)
                .collect::<Vec<_>>(),
            ["/tile/0/000", "/tile/0/001.p/44", "/tile/1/000.p/1"]
        );
        assert_eq!(
            required_entry_bundles(300)
                .iter()
                .map(EntryBundle::path)
                .collect::<Vec<_>>(),
            ["/tile/entries/000", "/tile/entries/001.p/44"]
        );
        assert!(required_tiles(0).is_empty());
    }

    #[test]
    fn a_leaf_range_needs_the_tiles_its_leaves_meet() {
        let paths: Vec<String> = tiles_for_range(256, 300, 300)
            .iter()
            .map(Tile::path)
            .collect();
        assert_eq!(paths, ["/tile/0/001.p/44"]);
        let early: Vec<String> = tiles_for_range(0, 4, 300).iter().map(Tile::path).collect();
        assert_eq!(early, ["/tile/0/000", "/tile/1/000.p/1"]);
        let bundles: Vec<String> = entry_bundles_for_range(255, 257, 300)
            .iter()
            .map(EntryBundle::path)
            .collect();
        assert_eq!(bundles, ["/tile/entries/000", "/tile/entries/001.p/44"]);
    }

    #[test]
    fn tiles_reproduce_the_root_the_leaves_define() {
        for n in [1usize, 5, 255, 256, 257, 300, 700] {
            let ls = leaves(n);
            let tiles = TileSet::build(&ls);
            check_tree(&tiles, n as u64, &merkle::merkle_root(&ls)).unwrap();
            assert_eq!(
                merkle::root_from(&tiles, n as u64).unwrap(),
                merkle::merkle_root(&ls)
            );
            for index in [0u64, (n as u64) - 1] {
                assert_eq!(
                    merkle::inclusion_proof_from(&tiles, index, n as u64).unwrap(),
                    merkle::inclusion_proof(index, &ls).unwrap()
                );
            }
        }
    }

    #[test]
    fn a_tile_that_does_not_reproduce_the_root_is_rejected() {
        let ls = leaves(300);
        let mut tiles = TileSet::build(&ls);
        check_tree(&tiles, 300, &merkle::merkle_root(&ls)).unwrap();
        let mut altered = tiles.tile(1, 0).unwrap().to_vec();
        altered[0][0] ^= 1;
        tiles.insert(1, 0, altered);
        let err = check_tree(&tiles, 300, &merkle::merkle_root(&ls)).unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E03"));
    }

    #[test]
    fn a_bundle_whose_entries_do_not_hash_to_their_leaves_is_rejected() {
        let entries: Vec<Vec<u8>> = (0..4u8).map(|i| vec![b'{', b'}', i]).collect();
        let hashes: Vec<[u8; 32]> = entries.iter().map(|e| merkle::leaf_hash(e)).collect();
        let tiles = TileSet::build(&hashes);
        check_entry_bundle(&entries, 0, &tiles).unwrap();
        let mut tampered = entries.clone();
        tampered[2].push(b' ');
        let err = check_entry_bundle(&tampered, 0, &tiles).unwrap_err();
        assert_eq!(err.code(), Some("WIST3-E03"));
    }

    #[test]
    fn entry_bundles_round_trip_and_reject_truncation_and_trailing_octets() {
        let entries: Vec<Vec<u8>> = vec![b"{}".to_vec(), b"[1,2,3]".to_vec()];
        let bytes = encode_entry_bundle(&entries).unwrap();
        assert_eq!(decode_entry_bundle(&bytes).unwrap(), entries);
        assert_eq!(
            decode_entry_bundle(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .code(),
            Some("WIST3-E03")
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_entry_bundle(&trailing).unwrap_err().code(),
            Some("WIST3-E03")
        );
    }

    #[test]
    fn tile_based_and_leaf_based_computations_agree_for_every_size_to_300() {
        let all = leaves(300);
        for n in 0..=300u64 {
            let ls = &all[..n as usize];
            let tiles = TileSet::build(ls);
            let root = merkle::merkle_root(ls);
            assert_eq!(merkle::root_from(&tiles, n).unwrap(), root, "size {n}");
            for index in 0..n {
                assert_eq!(
                    merkle::inclusion_proof_from(&tiles, index, n).unwrap(),
                    merkle::inclusion_proof(index, ls).unwrap(),
                    "leaf {index} of {n}"
                );
            }
            for m in 0..=n {
                let proof = merkle::consistency_proof_from(&tiles, m, n).unwrap();
                assert_eq!(
                    proof,
                    merkle::consistency_proof(m, n, ls).unwrap(),
                    "{m} to {n}"
                );
                merkle::verify_consistency(
                    m,
                    n,
                    &merkle::merkle_root(&ls[..m as usize]),
                    &root,
                    &proof,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn a_path_states_the_width_a_file_served_at_it_must_hold() {
        assert_eq!(path_width("/tile/0/000").unwrap(), TILE_WIDTH);
        assert_eq!(path_width("/tile/entries/x001/000").unwrap(), TILE_WIDTH);
        assert_eq!(path_width("/tile/0/001.p/1").unwrap(), 1);
        assert_eq!(path_width("/tile/0/001.p/255").unwrap(), 255);
        for path in ["/tile/0/001.p/0", "/tile/0/001.p/256", "/tile/0/001.p/4096"] {
            assert_eq!(
                path_width(path).unwrap_err().code(),
                Some("WIST3-E03"),
                "{path}"
            );
        }
        for path in ["/tile/0/001.p/", "/tile/0/001.p/04", "/tile/0/001.p/4x"] {
            assert_eq!(path_width(path).unwrap_err().code(), None, "{path}");
        }
    }

    #[test]
    fn a_tile_or_bundle_holding_another_count_than_its_path_states_is_rejected() {
        let hashes = leaves(44);
        let octets = encode_tile(&hashes);
        assert_eq!(decode_tile_at("/tile/0/001.p/44", &octets).unwrap(), hashes);
        for (path, bytes) in [
            ("/tile/0/000", octets.clone()),
            ("/tile/0/001.p/44", octets[..octets.len() - 32].to_vec()),
            ("/tile/0/001.p/44", octets[..octets.len() - 1].to_vec()),
            ("/tile/0/001.p/44", Vec::new()),
        ] {
            assert_eq!(
                decode_tile_at(path, &bytes).unwrap_err().code(),
                Some("WIST3-E03"),
                "{path} with {} octets",
                bytes.len()
            );
        }

        let entries: Vec<Vec<u8>> = (0..3u8).map(|i| vec![b'{', b'}', i]).collect();
        let bundle = encode_entry_bundle(&entries).unwrap();
        assert_eq!(
            decode_entry_bundle_at("/tile/entries/000.p/3", &bundle).unwrap(),
            entries
        );
        let mut trailing = bundle.clone();
        trailing.extend_from_slice(&[0, 0]);
        for (path, bytes) in [
            ("/tile/entries/000.p/2", bundle.clone()),
            ("/tile/entries/000.p/4", bundle.clone()),
            ("/tile/entries/000", bundle.clone()),
            ("/tile/entries/000.p/3", trailing),
        ] {
            assert_eq!(
                decode_entry_bundle_at(path, &bytes).unwrap_err().code(),
                Some("WIST3-E03"),
                "{path} with {} octets",
                bytes.len()
            );
        }
    }

    #[test]
    fn the_octet_bounds_admit_equality_and_reject_one_octet_more() {
        check_tile_bytes(TILE_MAX_BYTES).unwrap();
        assert!(check_tile_bytes(TILE_MAX_BYTES + 1).is_err());
        check_entry_bundle_bytes(ENTRY_BUNDLE_MAX_BYTES).unwrap();
        assert!(check_entry_bundle_bytes(ENTRY_BUNDLE_MAX_BYTES + 1).is_err());
        check_entry_bytes(ENTRY_MAX_BYTES).unwrap();
        assert!(check_entry_bytes(ENTRY_MAX_BYTES + 1).is_err());
        assert!(decode_tile(&vec![0u8; TILE_MAX_BYTES as usize]).is_ok());
        assert!(decode_tile(&vec![0u8; TILE_MAX_BYTES as usize + 1]).is_err());
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    fn read_path_index(encoded: &str) -> Option<u64> {
        let groups: Vec<&str> = encoded.split('/').collect();
        let mut value: u64 = 0;
        for (position, group) in groups.iter().enumerate() {
            let last = position + 1 == groups.len();
            let digits = if last {
                *group
            } else {
                group.strip_prefix('x')?
            };
            if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            value = value.checked_mul(1000)?.checked_add(digits.parse().ok()?)?;
        }
        Some(value)
    }

    proptest! {
        #[test]
        fn path_indexes_round_trip_beyond_the_first_thousand(index in 1000u64..u64::MAX) {
            let encoded = path_index(index);
            prop_assert!(encoded.starts_with('x'));
            prop_assert_eq!(read_path_index(&encoded), Some(index));
            prop_assert_eq!(
                Tile { level: 0, index, width: TILE_WIDTH }.path(),
                format!("/tile/0/{encoded}")
            );
            prop_assert_eq!(
                EntryBundle { index, width: 3 }.path(),
                format!("/tile/entries/{encoded}.p/3")
            );
        }

        #[test]
        fn the_tiles_a_tree_requires_cover_its_leaves(tree_size in 0u64..5000) {
            for tile in required_tiles(tree_size) {
                let (start, end) = tile.leaf_range();
                prop_assert!(start < end && end <= tree_size);
                prop_assert!(tiles_for_range(start, end, tree_size).contains(&tile));
            }
            for bundle in required_entry_bundles(tree_size) {
                let (start, end) = bundle.leaf_range();
                prop_assert!(start < end && end <= tree_size);
            }
            prop_assert_eq!(
                required_entry_bundles(tree_size).iter().map(|b| u64::from(b.width)).sum::<u64>(),
                tree_size
            );
        }
    }
}
