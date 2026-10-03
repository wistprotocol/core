use super::read_json;
use serde_json::Value;
use std::collections::BTreeMap;
use wist_core::crypto::{hex_decode, hex_encode, SigningKey};
use wist_core::declaration::publisher_of;
use wist_core::item::{
    check_form, commitment, item_id, judge, judge_payload, judge_payload_octets, key, kind, leaf,
    payload_name, Kind, SizeCaps,
};
use wist_core::objects::publisher::thumbprint;
use wist_core::objects::{Catalog, PageItem, Publisher};

pub fn declarations(vector: &Value) -> BTreeMap<String, Publisher> {
    vector["declarations"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(label, envelope)| (label.clone(), publisher_of(envelope).unwrap()))
        .collect()
}

pub fn assert_fixture_keys(vector: &Value) {
    for (label, key) in vector["keys"].as_object().unwrap() {
        let seed: [u8; 32] = hex_decode(key["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let public = SigningKey::from_seed(&seed).public().to_b64u();
        assert_eq!(public, key["x"], "{label}");
        assert_eq!(thumbprint(&public), key["kid"], "{label}");
    }
}

fn caps(parameters: &Value) -> Result<SizeCaps, wist_core::Error> {
    let suite = SizeCaps::suite();
    let value = |name: &str, default: u64| {
        parameters
            .get(name)
            .map_or(default as i64, |value| value.as_i64().unwrap())
    };
    SizeCaps::new(
        value("url_cap_bytes", suite.url_cap_bytes()),
        value("extract_cap_bytes", suite.extract_cap_bytes()),
        value("links_cap_bytes", suite.links_cap_bytes()),
        value("link_url_cap_bytes", suite.link_url_cap_bytes()),
        value("summary_cap_bytes", suite.summary_cap_bytes()),
    )
}

fn outcome(result: Result<(), &'static str>) -> &'static str {
    result.map_or_else(|code| code, |()| "accepted")
}

fn page(item: &Value) -> PageItem {
    serde_json::from_value(item.clone()).unwrap()
}

#[test]
fn each_item_is_judged_by_its_form_url_caps_instant_and_publisher() {
    let vector = read_json("vectors/wist1/item-fields.json");
    assert_fixture_keys(&vector);
    let declarations = declarations(&vector);
    let cases = vector["item_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 112);
    for case in cases {
        let catalog: Catalog = serde_json::from_value(case["catalog"].clone()).unwrap();
        let declaration = &declarations[case["declaration"].as_str().unwrap()];
        let caps = caps(&case["parameters"]).unwrap();
        assert_eq!(
            outcome(judge(&case["item"], &catalog, declaration, &caps)),
            case["expected"],
            "{}",
            case["name"]
        );
        assert_eq!(
            check_form(&case["item"]).is_ok(),
            case["expected"] != "WIST1-E14",
            "{}",
            case["name"]
        );
    }
}

#[test]
fn item_ids_keys_and_leaves_match_their_known_answers() {
    let vector = read_json("vectors/wist1/item-fields.json");
    let cases = vector["known_answers"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let item = &case["item"];
        assert_eq!(item_id(item).unwrap(), case["item_id"], "{name}");
        assert_eq!(
            format!("sha256:{}", payload_name(item).unwrap()),
            case["item_id"],
            "{name}"
        );
        assert_eq!(
            hex_encode(&key(item["url"].as_str().unwrap())),
            case["key"],
            "{name}"
        );
        assert_eq!(hex_encode(&leaf(item).unwrap()), case["leaf"], "{name}");
        match kind(item) {
            Kind::Page => assert_eq!(
                judge_payload(&page(item), &case["payload"], &SizeCaps::suite()),
                Ok(()),
                "{name}"
            ),
            Kind::Removed => assert!(case.get("payload").is_none(), "{name}"),
        }
    }
}

#[test]
fn a_payload_named_by_its_item_id_reproduces_the_commitment_and_length() {
    let vector = read_json("vectors/wist1/item-fields.json");
    let cases = vector["payload_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let path = case["payload_path"].as_str().unwrap();
        let collection = path
            .strip_prefix("/.well-known/wist/collections/")
            .and_then(|rest| rest.split_once("/payloads/"))
            .unwrap();
        assert_eq!(
            collection.1,
            format!("{}.json", payload_name(&case["item"]).unwrap()),
            "{name}"
        );
        assert_eq!(
            outcome(judge_payload(
                &page(&case["item"]),
                &case["payload"],
                &caps(&case["parameters"]).unwrap()
            )),
            case["expected"],
            "{name}"
        );
    }
}

#[test]
fn size_cap_maps_are_read_only_within_their_bounds() {
    let vector = read_json("vectors/wist1/item-fields.json");
    let cases = vector["parameter_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for case in cases {
        let read = if caps(&case["parameters"]).is_ok() {
            "read"
        } else {
            "refused"
        };
        assert_eq!(read, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn payload_fields_are_checked_before_any_semantic_rejection() {
    let vector = read_json("vectors/wist1/payload-fields.json");
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 129);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let item = page(&case["item"]);
        let preimage = &case["preimage"];
        assert_eq!(
            commitment(preimage["salt"].as_str().unwrap(), &preimage["content"]).unwrap(),
            item.payload.commitment,
            "{name}"
        );
        let caps = caps(case.get("caps").unwrap_or(&Value::Null)).unwrap();
        let result = match case["payload_json"].as_str() {
            Some(raw) => judge_payload_octets(&item, raw.as_bytes(), &caps),
            None => judge_payload(&item, &case["payload"], &caps),
        };
        let allowed: Vec<&str> = case["allowed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        match result {
            Ok(()) => assert!(allowed.is_empty(), "{name}: accepted, allowed {allowed:?}"),
            Err(code) => assert!(
                allowed.contains(&code),
                "{name}: {code}, allowed {allowed:?}"
            ),
        }
    }
}

#[test]
fn declared_links_are_normalized_external_distinct_and_within_their_total() {
    let vector = read_json("vectors/wist1/payload-links.json");
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for case in cases {
        let expected = case["expected"].as_str().unwrap_or("accepted");
        assert_eq!(
            outcome(judge_payload(
                &page(&case["item"]),
                &case["payload"],
                &SizeCaps::suite()
            )),
            expected,
            "{}",
            case["name"]
        );
    }
}
