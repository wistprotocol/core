use crate::crypto::hex_decode;
use crate::item::{hash_formed, leaf, members, safe_integer};
use crate::objects::Catalog;
use serde_json::Value;

fn digest(hex: &str) -> Option<[u8; 32]> {
    hex_decode(hex).ok()?.try_into().ok()
}

pub fn check_form(proof: &Value) -> Result<(), &'static str> {
    members(proof, &["index", "tree_size", "path"], &[])?;
    if safe_integer(&proof["index"]).is_none()
        || safe_integer(&proof["tree_size"]).is_none()
        || !proof["path"]
            .as_array()
            .is_some_and(|path| path.iter().all(|hash| hash_formed(hash, "")))
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

pub fn verify(item: &Value, proof: &Value, catalog: &Catalog) -> Result<(), &'static str> {
    check_form(proof)?;
    let leaf = leaf(item).map_err(|_| "WIST1-E14")?;
    let index = safe_integer(&proof["index"]).expect("a checked index");
    let tree_size = safe_integer(&proof["tree_size"]).expect("a checked tree_size");
    let path: Vec<[u8; 32]> = proof["path"]
        .as_array()
        .expect("a checked path")
        .iter()
        .map(|hash| digest(hash.as_str().expect("a checked hash")).expect("a checked hash"))
        .collect();
    let root = catalog
        .root
        .strip_prefix("sha256:")
        .and_then(digest)
        .ok_or("WIST1-E17")?;
    if tree_size != catalog.size {
        return Err("WIST1-E17");
    }
    crate::merkle::verify_inclusion(&leaf, index, tree_size, &path, &root).map_err(|_| "WIST1-E17")
}
