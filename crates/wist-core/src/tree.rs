use crate::crypto::hex_encode;
use crate::error::Error;
use crate::item::{hash_formed, key, members, root, safe_integer};
use crate::objects::{Catalog, TreeEntry, TreeFile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const REFUSED: &str = "WIST2-E07";

pub const CHILDREN_MAX: usize = 16;

pub const BUCKET_ITEMS_MAX: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeBounds {
    tree_file_cap_bytes: u64,
    tree_depth_max: u64,
}

impl TreeBounds {
    pub fn new(tree_file_cap_bytes: i64, tree_depth_max: i64) -> Result<Self, Error> {
        crate::parameters::validate_value("tree_file_cap_bytes", tree_file_cap_bytes)?;
        crate::parameters::validate_value("tree_depth_max", tree_depth_max)?;
        Ok(TreeBounds {
            tree_file_cap_bytes: tree_file_cap_bytes as u64,
            tree_depth_max: tree_depth_max as u64,
        })
    }

    pub fn suite() -> Self {
        let default = |name| {
            crate::parameters::spec(name)
                .and_then(|parameter| parameter.default)
                .expect("a suite default") as u64
        };
        TreeBounds {
            tree_file_cap_bytes: default("tree_file_cap_bytes"),
            tree_depth_max: default("tree_depth_max"),
        }
    }

    pub fn tree_file_cap_bytes(&self) -> u64 {
        self.tree_file_cap_bytes
    }

    pub fn tree_depth_max(&self) -> u64 {
        self.tree_depth_max
    }
}

impl Default for TreeBounds {
    fn default() -> Self {
        TreeBounds::suite()
    }
}

fn lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_file_form(file: &Value) -> Result<(), &'static str> {
    let map = file
        .as_object()
        .filter(|map| map.len() == 1)
        .ok_or(REFUSED)?;
    if let Some(items) = map.get("items") {
        let items = items.as_array().ok_or(REFUSED)?;
        if !items
            .iter()
            .all(|element| element.get("url").is_some_and(Value::is_string))
        {
            return Err(REFUSED);
        }
        return Ok(());
    }
    let children = map
        .get("children")
        .and_then(Value::as_array)
        .filter(|children| (1..=CHILDREN_MAX).contains(&children.len()))
        .ok_or(REFUSED)?;
    for entry in children {
        members(entry, &["prefix", "count", "file"], &[]).map_err(|_| REFUSED)?;
        if !entry["prefix"]
            .as_str()
            .is_some_and(|prefix| !prefix.is_empty() && lowercase_hex(prefix))
            || !safe_integer(&entry["count"]).is_some_and(|count| count >= 1)
            || !hash_formed(&entry["file"], "sha256:")
        {
            return Err(REFUSED);
        }
    }
    Ok(())
}

pub fn read_file(hex: &str, octets: &[u8], bounds: &TreeBounds) -> Result<TreeFile, &'static str> {
    if octets.len() as u64 > bounds.tree_file_cap_bytes
        || hex_encode(&Sha256::digest(octets)) != hex
    {
        return Err(REFUSED);
    }
    let file = crate::json::parse(octets).map_err(|_| REFUSED)?;
    if crate::jcs::canonicalize(&file).map_err(|_| REFUSED)? != octets {
        return Err(REFUSED);
    }
    check_file_form(&file)?;
    Ok(serde_json::from_value(file).expect("a checked tree file"))
}

fn check_bucket(items: &[Value], prefix: &str, count: u64) -> Result<(), &'static str> {
    let mut previous: Option<[u8; 32]> = None;
    for element in items {
        let key = key(element["url"].as_str().expect("a checked url"));
        if previous.is_some_and(|previous| key <= previous) || !hex_encode(&key).starts_with(prefix)
        {
            return Err(REFUSED);
        }
        previous = Some(key);
    }
    if items.len() as u64 != count {
        return Err(REFUSED);
    }
    Ok(())
}

fn check_children(children: &[TreeEntry], prefix: &str, count: u64) -> Result<(), &'static str> {
    let mut previous: Option<&str> = None;
    let mut total: u64 = 0;
    for entry in children {
        if entry.prefix.len() != prefix.len() + 1
            || !entry.prefix.starts_with(prefix)
            || previous.is_some_and(|previous| entry.prefix.as_str() <= previous)
        {
            return Err(REFUSED);
        }
        previous = Some(&entry.prefix);
        total = total.saturating_add(entry.count);
    }
    if total != count {
        return Err(REFUSED);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeFetch {
    Octets(Vec<u8>),
    Failed,
    Suspended,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Walk {
    Listed(Vec<Value>),
    Refused(&'static str),
    Suspended,
}

struct Pending {
    hex: String,
    prefix: String,
    level: u64,
    count: u64,
}

/// WIST-2 §5.3: depth-first, children in their order; the walk fetches no file after the first
/// condition it meets.
pub fn walk(
    catalog: &Catalog,
    bounds: &TreeBounds,
    mut fetch: impl FnMut(&str) -> TreeFetch,
) -> Walk {
    let tree = Value::String(catalog.tree.clone());
    if !hash_formed(&tree, "sha256:") {
        return Walk::Refused(REFUSED);
    }
    let mut pending = vec![Pending {
        hex: catalog.tree["sha256:".len()..].to_owned(),
        prefix: String::new(),
        level: 1,
        count: catalog.size,
    }];
    let mut listed = Vec::new();
    while let Some(file) = pending.pop() {
        let octets = match fetch(&file.hex) {
            TreeFetch::Octets(octets) => octets,
            TreeFetch::Failed => return Walk::Refused(REFUSED),
            TreeFetch::Suspended => return Walk::Suspended,
        };
        let checked = read_file(&file.hex, &octets, bounds).and_then(|read| match read {
            TreeFile::Bucket(bucket) => {
                check_bucket(&bucket.items, &file.prefix, file.count)?;
                listed.extend(bucket.items);
                Ok(())
            }
            TreeFile::Inner(inner) => {
                if file.level >= bounds.tree_depth_max {
                    return Err(REFUSED);
                }
                check_children(&inner.children, &file.prefix, file.count)?;
                pending.extend(inner.children.into_iter().rev().map(|entry| Pending {
                    hex: entry.file["sha256:".len()..].to_owned(),
                    prefix: entry.prefix,
                    level: file.level + 1,
                    count: entry.count,
                }));
                Ok(())
            }
        });
        if let Err(code) = checked {
            return Walk::Refused(code);
        }
    }
    let rooted =
        root(&listed).is_ok_and(|root| format!("sha256:{}", hex_encode(&root)) == catalog.root);
    if listed.len() as u64 != catalog.size || !rooted {
        return Walk::Refused(REFUSED);
    }
    Walk::Listed(listed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub tree: String,
    pub files: BTreeMap<String, Vec<u8>>,
}

fn digit(key: &[u8; 32], position: usize) -> u8 {
    let byte = key[position / 2];
    if position.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn store(
    octets: Vec<u8>,
    bounds: &TreeBounds,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<String, Error> {
    if octets.len() as u64 > bounds.tree_file_cap_bytes {
        return Err(Error::Envelope(format!(
            "a tree file of {} octets exceeds tree_file_cap_bytes at tree_depth_max",
            octets.len()
        )));
    }
    let hex = hex_encode(&Sha256::digest(&octets));
    files.insert(hex.clone(), octets);
    Ok(hex)
}

fn bucket(keyed: &[([u8; 32], &Value)]) -> Result<Vec<u8>, Error> {
    let items: Vec<&Value> = keyed.iter().map(|(_, item)| *item).collect();
    crate::jcs::canonicalize(&json!({ "items": items }))
}

fn emit(
    keyed: &[([u8; 32], &Value)],
    prefix: &str,
    level: u64,
    bounds: &TreeBounds,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<String, Error> {
    if keyed.len() <= BUCKET_ITEMS_MAX || level >= bounds.tree_depth_max {
        let octets = bucket(keyed)?;
        if octets.len() as u64 <= bounds.tree_file_cap_bytes || level >= bounds.tree_depth_max {
            return store(octets, bounds, files);
        }
    }
    let position = prefix.len();
    let mut children = Vec::new();
    for group in
        keyed.chunk_by(|(left, _), (right, _)| digit(left, position) == digit(right, position))
    {
        let child = format!("{prefix}{:x}", digit(&group[0].0, position));
        let file = emit(group, &child, level + 1, bounds, files)?;
        children.push(json!({
            "prefix": child,
            "count": group.len(),
            "file": format!("sha256:{file}"),
        }));
    }
    store(
        crate::jcs::canonicalize(&json!({ "children": children }))?,
        bounds,
        files,
    )
}

pub fn build(items: &[Value], bounds: &TreeBounds) -> Result<Built, Error> {
    let mut keyed = items
        .iter()
        .map(|item| {
            let url = item
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Envelope("an Item's url is a string".into()))?;
            Ok((key(url), item))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    keyed.sort_by_key(|(key, _)| *key);
    if keyed.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::Envelope("a list holds two Items of one key".into()));
    }
    let mut files = BTreeMap::new();
    let root = emit(&keyed, "", 1, bounds, &mut files)?;
    Ok(Built {
        tree: format!("sha256:{root}"),
        files,
    })
}
