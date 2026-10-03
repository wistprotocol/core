use crate::catalog::catalog_id;
use crate::constants::CHANGE_LIST_CAP_BYTES;
use crate::crypto::hex_encode;
use crate::error::Error;
use crate::item::{hash_formed, item_id, key, members};
use crate::objects::{Catalog, ChangeList};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const FORM: &str = "form";

fn element_key(element: &Value) -> Option<[u8; 32]> {
    element.get("url").and_then(Value::as_str).map(key)
}

fn check_form(file: &Value) -> Result<(), &'static str> {
    let map = members(file, &["previous", "catalog", "dropped", "items"], &[]).map_err(|_| FORM)?;
    if !hash_formed(&map["previous"], "sha256:") || !hash_formed(&map["catalog"], "sha256:") {
        return Err(FORM);
    }
    let dropped: Vec<&str> = map["dropped"]
        .as_array()
        .filter(|dropped| dropped.iter().all(|key| hash_formed(key, "")))
        .ok_or(FORM)?
        .iter()
        .map(|key| key.as_str().expect("a checked key"))
        .collect();
    let keys: Vec<String> = map["items"]
        .as_array()
        .ok_or(FORM)?
        .iter()
        .map(|element| element_key(element).map(|key| hex_encode(&key)))
        .collect::<Option<_>>()
        .ok_or(FORM)?;
    let ascending = |keys: &[&str]| keys.windows(2).all(|pair| pair[0] < pair[1]);
    let listed: Vec<&str> = keys.iter().map(String::as_str).collect();
    let dropped_set: BTreeSet<&str> = dropped.iter().copied().collect();
    if !ascending(&dropped)
        || !ascending(&listed)
        || listed.iter().any(|key| dropped_set.contains(key))
    {
        return Err(FORM);
    }
    Ok(())
}

pub fn read(hex: &str, octets: &[u8]) -> Result<ChangeList, &'static str> {
    let file = crate::json::parse(octets).map_err(|_| FORM)?;
    if crate::jcs::canonicalize(&file).map_err(|_| FORM)? != octets {
        return Err(FORM);
    }
    check_form(&file)?;
    if file["catalog"]
        .as_str()
        .and_then(|id| id.strip_prefix("sha256:"))
        != Some(hex)
    {
        return Err(FORM);
    }
    Ok(serde_json::from_value(file).expect("a checked change list"))
}

fn keyed(list: &[Value]) -> Result<BTreeMap<[u8; 32], &Value>, Error> {
    let mut by_key = BTreeMap::new();
    for item in list {
        let key = element_key(item)
            .ok_or_else(|| Error::ChangeList("an Item's url is a string".into()))?;
        if by_key.insert(key, item).is_some() {
            return Err(Error::ChangeList(
                "an Item list holds two Items under one key".into(),
            ));
        }
    }
    Ok(by_key)
}

pub fn apply(list: &[Value], change: &ChangeList) -> Result<Vec<Value>, Error> {
    let file = serde_json::to_value(change).expect("a change list serializes");
    check_form(&file).map_err(|_| Error::ChangeList("not of the form of WIST-2 §3.1".into()))?;
    let mut by_key = keyed(list)?;
    for dropped in &change.dropped {
        let key: [u8; 32] = crate::crypto::hex_decode(dropped)?
            .try_into()
            .expect("a checked key");
        by_key.remove(&key);
    }
    for element in &change.items {
        by_key.insert(element_key(element).expect("a checked url"), element);
    }
    Ok(by_key.into_values().cloned().collect())
}

#[derive(Debug, Clone, Copy)]
pub struct Listed<'a> {
    pub catalog: &'a Catalog,
    pub list: &'a [Value],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub name: String,
    pub octets: Vec<u8>,
}

fn listed_catalog_id(catalog: &Catalog) -> Result<String, Error> {
    catalog_id(&serde_json::to_value(catalog).expect("a Catalog serializes"))
}

pub fn difference(served: Listed, new: Listed) -> Result<ChangeList, Error> {
    let served_by_key = keyed(served.list)?;
    let new_by_key = keyed(new.list)?;
    let mut items = Vec::new();
    for (key, item) in &new_by_key {
        let unchanged = match served_by_key.get(key) {
            Some(held) => item_id(held)? == item_id(item)?,
            None => false,
        };
        if !unchanged {
            items.push((*item).clone());
        }
    }
    let dropped = served_by_key
        .keys()
        .filter(|key| !new_by_key.contains_key(*key))
        .map(|key| hex_encode(key))
        .collect();
    Ok(ChangeList {
        previous: listed_catalog_id(served.catalog)?,
        catalog: listed_catalog_id(new.catalog)?,
        dropped,
        items,
    })
}

pub fn write(served: Option<Listed>, new: Listed) -> Result<Option<Written>, Error> {
    let Some(served) = served else {
        return Ok(None);
    };
    let change = difference(served, new)?;
    // WIST-2 §3.1: a Catalog with the served Catalog's ID is the served Catalog.
    if change.previous == change.catalog {
        return Ok(None);
    }
    let octets = crate::jcs::canonicalize(
        &serde_json::to_value(&change).expect("a change list serializes"),
    )?;
    if octets.len() as u64 > CHANGE_LIST_CAP_BYTES {
        return Ok(None);
    }
    Ok(Some(Written {
        name: change.catalog["sha256:".len()..].to_owned(),
        octets,
    }))
}
