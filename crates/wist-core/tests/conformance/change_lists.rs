use super::read_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wist_core::change_list::{apply, difference, read, write, Listed, FORM};
use wist_core::constants::CHANGE_LIST_CAP_BYTES;
use wist_core::crypto::hex_encode;
use wist_core::item::{item_id, root};
use wist_core::objects::{Catalog, ChangeList};

fn outcome(result: Result<ChangeList, &'static str>) -> &'static str {
    result.map_or_else(|code| code, |_| "accepted")
}

fn named(text: &str) -> String {
    let file = wist_core::json::parse(text.as_bytes()).unwrap();
    file["catalog"].as_str().unwrap()["sha256:".len()..].to_owned()
}

fn ids(list: &[Value]) -> Vec<String> {
    list.iter().map(|item| item_id(item).unwrap()).collect()
}

#[test]
fn a_change_list_is_of_the_form_only_as_the_jcs_serialization_named_by_its_catalog() {
    let vector = read_json("vectors/wist2/change-lists.json");
    let cases = vector["form_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 41);
    let mut accepted = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();
        let read = read(case["file"].as_str().unwrap(), text.as_bytes());
        if let Ok(change) = &read {
            accepted += 1;
            let canonical =
                wist_core::jcs::canonicalize(&serde_json::to_value(change).unwrap()).unwrap();
            assert_eq!(canonical, text.as_bytes(), "{name}");
        }
        assert_eq!(outcome(read), case["expected"], "{name}");
    }
    assert_eq!(accepted, 6);
}

#[test]
fn an_applied_change_list_drops_and_places_items_in_ascending_key_order() {
    let vector = read_json("vectors/wist2/change-lists.json");
    let cases = vector["application_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let text = case["change_list"].as_str().unwrap();
        let change = read(&named(text), text.as_bytes()).unwrap();
        let result = apply(case["list"].as_array().unwrap(), &change).unwrap();
        let expected = &case["expected"];
        assert_eq!(json!(ids(&result)), expected["list"], "{name}");
        assert_eq!(json!(result.len()), expected["size"], "{name}");
        assert_eq!(
            format!("sha256:{}", hex_encode(&root(&result).unwrap())),
            expected["root"].as_str().unwrap(),
            "{name}"
        );
    }
}

fn expand(list: &Value, sets: &Value) -> Vec<Value> {
    let mut expanded = Vec::new();
    for element in list.as_array().unwrap() {
        let Some(set) = element.as_str() else {
            expanded.push(element.clone());
            continue;
        };
        let set = &sets[set];
        for url in set["urls"].as_array().unwrap() {
            let fill = usize::try_from(url[1].as_u64().unwrap()).unwrap();
            expanded.push(json!({
                "publisher": set["publisher"],
                "observed_at": set["observed_at"],
                "url": format!("{}{}", url[0].as_str().unwrap(), "x".repeat(fill)),
                "removed": true,
            }));
        }
    }
    expanded
}

struct Side {
    catalog: Catalog,
    list: Vec<Value>,
}

impl Side {
    fn of(side: &Value, sets: &Value) -> Option<Side> {
        (!side.is_null()).then(|| Side {
            catalog: serde_json::from_value(side["catalog"].clone()).unwrap(),
            list: expand(&side["list"], sets),
        })
    }

    fn listed(&self) -> Listed<'_> {
        Listed {
            catalog: &self.catalog,
            list: &self.list,
        }
    }
}

#[test]
fn a_publisher_writes_the_difference_of_the_new_list_from_the_served_one_up_to_the_cap() {
    let vector = read_json("vectors/wist2/change-list-serving.json");
    let sets = &vector["large_item_sets"];
    let cases = vector["write_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    let mut at_cap = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let served = Side::of(&case["served"], sets);
        let new = Side::of(&case["new"], sets).unwrap();
        let written = write(served.as_ref().map(Side::listed), new.listed()).unwrap();
        let expected = &case["expected"];
        let Some(written) = written else {
            assert_eq!(*expected, json!({"written": false}), "{name}");
            continue;
        };
        assert_eq!(expected["written"], true, "{name}");
        assert_eq!(written.name, expected["name"].as_str().unwrap(), "{name}");
        assert_eq!(
            written.octets.len() as u64,
            expected["octets"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex_encode(&Sha256::digest(&written.octets)),
            expected["sha256"].as_str().unwrap(),
            "{name}"
        );
        match expected["text"].as_str() {
            Some(text) => assert_eq!(written.octets, text.as_bytes(), "{name}"),
            None => assert!(written.octets.len() > 65_536, "{name}"),
        }
        at_cap += usize::from(written.octets.len() as u64 == CHANGE_LIST_CAP_BYTES);
    }
    assert_eq!(at_cap, 1);
}

#[test]
fn a_written_change_list_is_of_the_form_and_leads_from_the_served_list_to_the_new_one() {
    let vector = read_json("vectors/wist2/change-list-serving.json");
    let sets = &vector["large_item_sets"];
    let mut checked = 0;
    for case in vector["write_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let (Some(served), Some(new)) = (
            Side::of(&case["served"], sets),
            Side::of(&case["new"], sets),
        ) else {
            continue;
        };
        let change = difference(served.listed(), new.listed()).unwrap();
        let applied = apply(&served.list, &change).unwrap();
        let mut expected = new.list.clone();
        expected.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
        assert_eq!(ids(&applied), ids(&expected), "{name}");
        if let Some(written) = write(Some(served.listed()), new.listed()).unwrap() {
            assert_eq!(read(&written.name, &written.octets), Ok(change), "{name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 8);
}

fn first_written_case() -> (Side, Side) {
    let vector = read_json("vectors/wist2/change-list-serving.json");
    let case = &vector["write_cases"][0];
    let sets = &vector["large_item_sets"];
    (
        Side::of(&case["served"], sets).unwrap(),
        Side::of(&case["new"], sets).unwrap(),
    )
}

#[test]
fn the_difference_does_not_depend_on_the_order_of_the_lists_given() {
    let (served, new) = first_written_case();
    let expected = write(Some(served.listed()), new.listed()).unwrap();
    let reversed_served: Vec<Value> = served.list.iter().rev().cloned().collect();
    let reversed_new: Vec<Value> = new.list.iter().rev().cloned().collect();
    let reversed = write(
        Some(Listed {
            catalog: &served.catalog,
            list: &reversed_served,
        }),
        Listed {
            catalog: &new.catalog,
            list: &reversed_new,
        },
    )
    .unwrap();
    assert_eq!(reversed, expected);
}

#[test]
fn a_list_holding_two_items_under_one_key_is_neither_differenced_nor_applied() {
    let (served, new) = first_written_case();
    let mut doubled = new.list.clone();
    let mut twin = doubled[0].clone();
    twin["observed_at"] = json!("2026-09-21T08:00:00Z");
    doubled.push(twin);
    let doubled = Listed {
        catalog: &new.catalog,
        list: &doubled,
    };
    assert!(write(Some(served.listed()), doubled).is_err());
    assert!(write(Some(doubled), new.listed()).is_err());
    let change = difference(served.listed(), new.listed()).unwrap();
    assert!(apply(doubled.list, &change).is_err());
}

#[test]
fn a_change_list_not_of_the_form_is_not_applied() {
    let (served, new) = first_written_case();
    let change = difference(served.listed(), new.listed()).unwrap();
    let mut reordered = change.clone();
    reordered.items.reverse();
    assert!(reordered.items.len() > 1);
    assert!(apply(&served.list, &reordered).is_err());
    let mut overlapping = change;
    let listed = overlapping.items[0]["url"].as_str().unwrap();
    overlapping
        .dropped
        .push(hex_encode(&wist_core::item::key(listed)));
    overlapping.dropped.sort();
    assert!(apply(&served.list, &overlapping).is_err());
}

#[test]
fn a_change_list_read_from_octets_of_the_form_names_the_form_condition_otherwise() {
    let (served, new) = first_written_case();
    let written = write(Some(served.listed()), new.listed()).unwrap().unwrap();
    assert!(read(&written.name, &written.octets).is_ok());
    assert_eq!(
        read(&written.name.to_uppercase(), &written.octets),
        Err(FORM)
    );
    let mut invalid = written.octets.clone();
    invalid.insert(1, 0xff);
    assert_eq!(read(&written.name, &invalid), Err(FORM));
}
