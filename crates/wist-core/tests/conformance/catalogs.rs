use super::items::{assert_fixture_keys, declarations};
use super::read_json;
use serde_json::Value;
use wist_core::catalog::{
    catalog_id, judge, judge_octets, order, pull, read, Attempt, Fetch, Pull,
};
use wist_core::objects::Publisher;

fn attempt<'a>(declaration: &'a Publisher, case: &Value) -> Attempt<'a> {
    let parameters = &case["parameters"];
    Attempt::new(
        declaration,
        case["clock"].as_str().unwrap(),
        parameters["clock_skew_seconds"].as_i64().unwrap(),
        parameters["catalog_items_max"].as_i64().unwrap(),
    )
    .unwrap()
}

fn outcome<T>(result: Result<T, &'static str>) -> &'static str {
    result.map_or_else(|code| code, |_| "accepted")
}

#[test]
fn each_catalog_is_judged_by_its_form_version_size_collection_binding_and_clock() {
    let vector = read_json("vectors/wist1/catalog-fields.json");
    assert_fixture_keys(&vector);
    let declarations = declarations(&vector);
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 81);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let declaration = &declarations[case["declaration"].as_str().unwrap()];
        let attempt = attempt(declaration, case);
        let result = match case["catalog_json"].as_str() {
            Some(raw) => judge_octets(raw.as_bytes(), &attempt),
            None => judge(&case["catalog"], &attempt),
        };
        assert_eq!(outcome(result), case["expected"], "{name}");
        if let Some(expected) = case.get("catalog_id") {
            let envelope =
                wist_core::json::parse(case["catalog_json"].as_str().unwrap().as_bytes()).unwrap();
            assert_eq!(
                catalog_id(&envelope["catalog"]).unwrap(),
                *expected,
                "{name}"
            );
        }
    }
}

#[test]
fn a_catalog_id_is_the_sha256_of_its_inner_objects_jcs() {
    let vector = read_json("vectors/wist1/catalog-fields.json");
    let cases = vector["id_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        assert_eq!(
            catalog_id(&case["catalog"]).unwrap(),
            case["catalog_id"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn a_catalog_json_above_16_384_octets_is_a_failed_fetch() {
    let vector = read_json("vectors/wist1/catalog-fields.json");
    let declarations = declarations(&vector);
    let cases = vector["read_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let octets = case["catalog_json"].as_str().unwrap().as_bytes();
        assert_eq!(
            octets.len() as u64,
            case["octets"].as_u64().unwrap(),
            "{name}"
        );
        let declaration = &declarations[case["declaration"].as_str().unwrap()];
        assert_eq!(
            read(octets, &attempt(declaration, case)).as_str(),
            case["expected"],
            "{name}"
        );
    }
}

#[test]
fn a_pulled_catalog_replaces_only_with_a_later_instant_unless_reserved() {
    let vector = read_json("vectors/wist2/catalog-order.json");
    let cases = vector["pull_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let fetch = Fetch {
            publisher: case["fetched_for"]["publisher"].as_str().unwrap(),
            collection: case["fetched_for"]["collection"].as_str().unwrap(),
            last_accepted: Some(&case["last_accepted"]).filter(|catalog| !catalog.is_null()),
            latest: Some(&case["latest"]).filter(|catalog| !catalog.is_null()),
            recovery: None,
        };
        assert_eq!(
            order(&fetch, &case["fetched"], None).as_str(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

fn accepted_journal_catalog(vector: &Value) -> &Value {
    vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "journal Catalog signed by an owner key")
        .unwrap()
}

#[test]
fn a_pull_reads_the_bound_then_the_catalog_conditions_then_the_order() {
    let vector = read_json("vectors/wist1/catalog-fields.json");
    let declarations = declarations(&vector);
    let case = accepted_journal_catalog(&vector);
    let declaration = &declarations[case["declaration"].as_str().unwrap()];
    let attempt = attempt(declaration, case);
    let envelope = &case["catalog"];
    let octets = serde_json::to_vec(envelope).unwrap();
    let mut fetch = Fetch {
        publisher: "example.com",
        collection: "journal",
        last_accepted: None,
        latest: None,
        recovery: None,
    };
    let signer = judge(envelope, &attempt).unwrap();
    assert_eq!(
        pull(&fetch, &octets, &attempt),
        Pull::Accepted(Some(signer.clone()))
    );

    fetch.last_accepted = Some(&envelope["catalog"]);
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Idempotent);

    let mut padded = octets.clone();
    padded.resize(16_385, b' ');
    assert_eq!(pull(&fetch, &padded, &attempt), Pull::Failed);
    padded.truncate(16_384);
    assert_eq!(pull(&fetch, &padded, &attempt), Pull::Idempotent);

    fetch.collection = "store";
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Refused("WIST2-E04"));
    fetch.collection = "journal";

    let mut tampered = envelope.clone();
    tampered["catalog"]["size"] = 3.into();
    let tampered = serde_json::to_vec(&tampered).unwrap();
    assert_eq!(
        pull(&fetch, &tampered, &attempt),
        Pull::Refused("WIST1-E01")
    );
    assert_eq!(pull(&fetch, b"{", &attempt), Pull::Refused("WIST1-E05"));

    let id = catalog_id(&envelope["catalog"]).unwrap();
    let other = wist_core::crypto::SigningKey::from_seed(&[9u8; 32]).public();
    let queued_by_other = [(id.clone(), other)];
    fetch.recovery = Some(&queued_by_other);
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Refused("WIST2-E05"));
    let queued = [(id, signer)];
    fetch.recovery = Some(&queued);
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Idempotent);
    fetch.recovery = Some(&[]);
    fetch.latest = Some(&envelope["catalog"]);
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Idempotent);
}
