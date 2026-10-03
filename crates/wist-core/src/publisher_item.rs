use crate::collection::name_formed;
use crate::crypto::hex_encode;
use crate::error::Error;
use crate::item::{hash_formed, leaf, members};
use crate::objects::Catalog;
use serde_json::{json, Value};

pub fn check_form(body: &Value) -> Result<(), &'static str> {
    members(body, &["item", "collection", "catalog", "proof"], &[])?;
    crate::item::check_form(&body["item"])?;
    if !body["collection"].as_str().is_some_and(name_formed)
        || !hash_formed(&body["catalog"], "sha256:")
    {
        return Err("WIST1-E14");
    }
    crate::proof::check_form(&body["proof"])
}

/// WIST-3 §3.3: the form (I1) comes first; among the other codes WIST-1 §7 leaves the choice.
pub fn verify(body: &Value, catalog: &Catalog) -> Result<(), &'static str> {
    check_form(body)?;
    let named = serde_json::to_value(catalog)
        .ok()
        .and_then(|inner| crate::catalog::catalog_id(&inner).ok());
    if named.as_deref() != body["catalog"].as_str() {
        return Err("WIST3-E06");
    }
    if body["collection"] != catalog.collection.as_str() {
        return Err("WIST1-E17");
    }
    if body["item"]["publisher"] != catalog.publisher.as_str() {
        return Err("WIST2-E03");
    }
    crate::proof::verify(&body["item"], &body["proof"], catalog)
}

pub fn build(items: &[Value], index: u64, catalog: &Catalog) -> Result<Value, Error> {
    let leaves = items.iter().map(leaf).collect::<Result<Vec<_>, Error>>()?;
    let path = crate::merkle::inclusion_proof(index, &leaves)?;
    let inner =
        serde_json::to_value(catalog).map_err(|error| Error::Envelope(error.to_string()))?;
    let body = json!({
        "item": items[usize::try_from(index).expect("an index inside the list")],
        "collection": catalog.collection,
        "catalog": crate::catalog::catalog_id(&inner)?,
        "proof": {
            "index": index,
            "tree_size": items.len(),
            "path": path.iter().map(|hash| hex_encode(hash)).collect::<Vec<_>>(),
        },
    });
    verify(&body, catalog).map_err(|code| {
        Error::Envelope(format!(
            "{code} the publisher_item Entry built from the list does not verify against its Catalog"
        ))
    })?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn removed(n: usize) -> Value {
        json!({
            "publisher": "example.com",
            "url": format!("https://example.com/journal/{n}"),
            "observed_at": "2026-09-01T00:00:00Z",
            "removed": true,
        })
    }

    fn catalog_of(items: &[Value]) -> Catalog {
        Catalog {
            wist_version: "1.0.0".into(),
            publisher: "example.com".into(),
            collection: "journal".into(),
            generated_at: "2026-10-01T12:00:00Z".into(),
            size: items.len() as u64,
            root: format!("sha256:{}", hex_encode(&crate::item::root(items).unwrap())),
            tree: format!("sha256:{}", "0".repeat(64)),
        }
    }

    fn ordered(size: usize) -> Vec<Value> {
        let mut items: Vec<Value> = (0..size).map(removed).collect();
        items.sort_by_key(|item| crate::item::key(item["url"].as_str().unwrap()));
        items
    }

    #[test]
    fn verify_accepts_the_entry_built_for_every_index_of_lists_of_1_2_3_and_8_items() {
        for size in [1, 2, 3, 8] {
            let items = ordered(size);
            let catalog = catalog_of(&items);
            for index in 0..size as u64 {
                let body = build(&items, index, &catalog).unwrap();
                assert_eq!(verify(&body, &catalog), Ok(()), "{size} {index}");
                assert_eq!(body["proof"]["index"], index);
                assert_eq!(body["item"], items[index as usize]);
            }
        }
    }

    #[test]
    fn no_entry_is_built_for_an_index_outside_the_list_or_a_list_its_catalog_does_not_state() {
        let items = ordered(3);
        let catalog = catalog_of(&items);
        assert!(build(&items, 3, &catalog).is_err());
        let mut reversed = items.clone();
        reversed.reverse();
        assert!(build(&reversed, 0, &catalog).is_err());
        assert_eq!(
            build(&items[..2], 0, &catalog).unwrap_err().code(),
            Some("WIST1-E17")
        );
    }
}
