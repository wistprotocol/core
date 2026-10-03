use super::items::{assert_fixture_keys, declarations};
use super::read_json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use wist_core::catalog::{
    catalog_id, judge, judge_octets, order, order_in_window, pull, pull_in_window, read, Attempt,
    Fetch, Pull, Window,
};
use wist_core::crypto::{PublicKey, SigningKey};
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

fn labelled_key(label: &Value) -> PublicKey {
    let seed: [u8; 32] = Sha256::digest(label.as_str().unwrap().as_bytes()).into();
    SigningKey::from_seed(&seed).public()
}

fn held(entry: &Value) -> (Value, PublicKey) {
    (entry["catalog"].clone(), labelled_key(&entry["key"]))
}

#[test]
fn a_pulled_catalog_replaces_only_with_a_later_instant_unless_reserved() {
    let vector = read_json("vectors/wist2/catalog-order.json");
    let cases = vector["pull_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24);
    let mut windowed = 0;
    for case in cases {
        let fetch = Fetch {
            publisher: case["fetched_for"]["publisher"].as_str().unwrap(),
            collection: case["fetched_for"]["collection"].as_str().unwrap(),
            last_accepted: Some(&case["last_accepted"]).filter(|catalog| !catalog.is_null()),
            latest: Some(&case["latest"]).filter(|catalog| !catalog.is_null()),
        };
        let window = &case["window"];
        let pulled = if window.is_null() {
            assert!(case["signed_by"].is_null(), "{}", case["name"]);
            order(&fetch, &case["fetched"], None)
        } else {
            windowed += 1;
            let queued: Vec<(Value, PublicKey)> = window["queued"]
                .as_array()
                .unwrap()
                .iter()
                .map(held)
                .collect();
            let waiting = Some(&window["waiting"])
                .filter(|waiting| !waiting.is_null())
                .map(held);
            let window = Window {
                opened: window["opened"].as_bool().unwrap(),
                queued: &queued,
                waiting: waiting.as_ref(),
            };
            order_in_window(
                &fetch,
                &window,
                &case["fetched"],
                &labelled_key(&case["signed_by"]),
            )
        };
        assert_eq!(pulled.as_str(), case["expected"], "{}", case["name"]);
    }
    assert_eq!(windowed, 11);
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

    fetch.last_accepted = None;
    fetch.latest = Some(&envelope["catalog"]);
    assert_eq!(pull(&fetch, &octets, &attempt), Pull::Idempotent);
}

#[test]
fn a_pull_inside_a_window_judges_the_catalog_then_reads_the_order_by_key() {
    let vector = read_json("vectors/wist1/catalog-fields.json");
    let declarations = declarations(&vector);
    let case = accepted_journal_catalog(&vector);
    let declaration = &declarations[case["declaration"].as_str().unwrap()];
    let attempt = attempt(declaration, case);
    let envelope = &case["catalog"];
    let inner = &envelope["catalog"];
    let octets = serde_json::to_vec(envelope).unwrap();
    let signer = judge(envelope, &attempt).unwrap();
    let other = SigningKey::from_seed(&[9u8; 32]).public();
    let fetch = Fetch {
        publisher: "example.com",
        collection: "journal",
        last_accepted: Some(inner),
        latest: None,
    };
    let window = |queued: &[(Value, PublicKey)], waiting: Option<&(Value, PublicKey)>, opened| {
        let window = Window {
            opened,
            queued,
            waiting,
        };
        pull_in_window(&fetch, &window, &octets, &attempt)
    };
    assert_eq!(
        window(&[], None, true),
        Pull::Accepted(Some(signer.clone()))
    );
    let mine = [(inner.clone(), signer.clone())];
    let theirs = [(inner.clone(), other.clone())];
    assert_eq!(window(&mine, None, true), Pull::Idempotent);
    assert_eq!(
        window(&theirs, None, true),
        Pull::Accepted(Some(signer.clone()))
    );
    assert_eq!(window(&[], Some(&mine[0]), false), Pull::Idempotent);
    assert_eq!(
        window(&[], Some(&mine[0]), true),
        Pull::Accepted(Some(signer.clone()))
    );
    let mut later = inner.clone();
    later["generated_at"] = "2026-12-31T00:00:00Z".into();
    assert_eq!(
        window(&[(later, signer.clone())], None, true),
        Pull::Refused("WIST2-E05")
    );
    let mut tampered = envelope.clone();
    tampered["catalog"]["size"] = 3.into();
    let tampered = serde_json::to_vec(&tampered).unwrap();
    let empty = Window {
        opened: true,
        queued: &[],
        waiting: None,
    };
    assert_eq!(
        pull_in_window(&fetch, &empty, &tampered, &attempt),
        Pull::Refused("WIST1-E01")
    );
    let mut padded = octets.clone();
    padded.resize(16_385, b' ');
    assert_eq!(
        pull_in_window(&fetch, &empty, &padded, &attempt),
        Pull::Failed
    );
}
