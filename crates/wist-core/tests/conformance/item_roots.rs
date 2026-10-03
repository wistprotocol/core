use super::read_json;
use serde_json::Value;
use std::collections::BTreeMap;
use wist_core::crypto::hex_encode;
use wist_core::item::{item_id, judge_payload, key, kind, leaf, root, Kind, SizeCaps};
use wist_core::objects::{Catalog, PageItem, PublisherItem};
use wist_core::{proof, publisher_item};

fn outcome(result: Result<(), &'static str>) -> &'static str {
    result.map_or_else(|code| code, |()| "accepted")
}

fn catalog(case: &Value) -> Catalog {
    serde_json::from_value(case["catalog"].clone()).unwrap()
}

#[test]
fn a_root_is_the_merkle_tree_hash_of_the_leaves_in_key_order() {
    let vector = read_json("vectors/wist1/item-roots.json");
    let cases = vector["root_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 11);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let items = case["items"].as_array().unwrap();
        let keys: Vec<String> = items
            .iter()
            .map(|item| hex_encode(&key(item["url"].as_str().unwrap())))
            .collect();
        let leaves: Vec<String> = items
            .iter()
            .map(|item| hex_encode(&leaf(item).unwrap()))
            .collect();
        assert_eq!(serde_json::json!(keys), case["keys"], "{name}");
        assert_eq!(serde_json::json!(leaves), case["leaves"], "{name}");
        let expected = case["root"].as_str().unwrap();
        assert_eq!(
            format!("sha256:{}", hex_encode(&root(items).unwrap())),
            expected,
            "{name}"
        );
        let reversed: Vec<Value> = items.iter().rev().cloned().collect();
        assert_eq!(
            format!("sha256:{}", hex_encode(&root(&reversed).unwrap())),
            expected,
            "{name}"
        );
    }
}

#[test]
fn an_inclusion_proof_is_checked_for_form_then_verified_against_its_catalog() {
    let vector = read_json("vectors/wist1/item-roots.json");
    let cases = vector["proof_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 27);
    let mut spelled = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let proof = match case.get("proof_json") {
            Some(raw) => {
                spelled += 1;
                wist_core::json::parse(raw.as_str().unwrap().as_bytes()).unwrap()
            }
            None => case["proof"].clone(),
        };
        assert_eq!(
            outcome(proof::verify(&case["item"], &proof, &catalog(case))),
            case["expected"],
            "{name}"
        );
        assert_eq!(
            proof::check_form(&proof).is_ok(),
            case["expected"] != "WIST1-E14",
            "{name}"
        );
    }
    assert_eq!(spelled, 3);
}

#[test]
fn a_publisher_item_body_is_checked_for_form_collection_publisher_and_proof() {
    let vector = read_json("vectors/wist1/item-roots.json");
    let cases = vector["body_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let body = &case["body"];
        assert_eq!(
            outcome(publisher_item::verify(body, &catalog(case))),
            case["expected"],
            "{name}"
        );
        let formed = publisher_item::check_form(body).is_ok();
        assert_eq!(formed, case["expected"] != "WIST1-E14", "{name}");
        if formed {
            serde_json::from_value::<PublisherItem>(body.clone()).unwrap();
        }
    }
}

#[test]
fn a_body_naming_another_catalog_than_the_one_supplied_is_not_verified_against_it() {
    let vector = read_json("vectors/wist1/item-roots.json");
    let case = &vector["body_cases"][0];
    assert_eq!(case["expected"], "accepted");
    let mut other = catalog(case);
    other.generated_at = "2026-10-01T12:00:01Z".to_owned();
    assert_eq!(
        publisher_item::verify(&case["body"], &other),
        Err("WIST3-E06")
    );
}

#[test]
fn each_page_item_of_the_file_has_its_payload_under_its_item_id() {
    let vector = read_json("vectors/wist1/item-roots.json");
    let mut pages: BTreeMap<String, Value> = BTreeMap::new();
    let listed = vector["root_cases"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|case| case["items"].as_array().unwrap().iter())
        .chain(
            vector["proof_cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| &case["item"]),
        )
        .chain(
            vector["body_cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| &case["body"]["item"]),
        );
    for item in listed {
        if wist_core::item::check_form(item).is_ok() && kind(item) == Kind::Page {
            pages.insert(item_id(item).unwrap(), item.clone());
        }
    }
    let payloads = vector["payloads"].as_object().unwrap();
    assert_eq!(payloads.len(), 13);
    assert_eq!(
        pages.keys().collect::<Vec<_>>(),
        payloads.keys().collect::<Vec<_>>()
    );
    for (id, payload) in payloads {
        let page: PageItem = serde_json::from_value(pages[id].clone()).unwrap();
        assert_eq!(
            judge_payload(&page, payload, &SizeCaps::suite()),
            Ok(()),
            "{id}"
        );
    }
}

#[test]
fn the_publisher_item_example_is_formed_and_parses_typed() {
    let example = read_json("examples/publisher-item.json");
    assert_eq!(publisher_item::check_form(&example), Ok(()));
    let body: PublisherItem = serde_json::from_value(example).unwrap();
    assert_eq!(body.proof.tree_size, 1);
}
