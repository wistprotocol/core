use crate::collection::name_formed;
use crate::item::{hash_formed, members};
use crate::objects::Catalog;
use serde_json::Value;

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
