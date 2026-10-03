use super::items::{assert_fixture_keys, declarations};
use super::read_json;
use serde_json::{json, Value};
use std::cell::RefCell;
use wist_core::catalog::{judge, Attempt};
use wist_core::item::{item_id, SizeCaps};
use wist_core::objects::Catalog;
use wist_core::tree::{read_file, walk, TreeBounds, TreeFetch, Walk};

fn bounds(parameters: &Value) -> TreeBounds {
    TreeBounds::new(
        parameters["tree_file_cap_bytes"].as_i64().unwrap(),
        parameters["tree_depth_max"].as_i64().unwrap(),
    )
    .unwrap()
}

fn served(files: &Value) -> impl Fn(&str) -> TreeFetch + '_ {
    move |hex| match files.get(hex).and_then(Value::as_str) {
        Some(text) => TreeFetch::Octets(text.as_bytes().to_vec()),
        None => TreeFetch::Failed,
    }
}

fn disposition(walked: Walk) -> Value {
    match walked {
        Walk::Listed(items) => {
            json!({"list": items.iter().map(|item| item_id(item).unwrap()).collect::<Vec<_>>()})
        }
        Walk::Refused(code) => json!({ "refused": code }),
        Walk::Suspended => json!("suspended"),
    }
}

#[test]
fn a_catalog_tree_is_walked_depth_first_and_refused_whole_at_its_first_broken_rule() {
    let vector = read_json("vectors/wist2/catalog-tree.json");
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 54);
    for case in cases {
        let catalog: Catalog = serde_json::from_value(case["catalog"].clone()).unwrap();
        let mut fetched = Vec::new();
        let walked = walk(&catalog, &bounds(&case["parameters"]), |hex| {
            fetched.push(hex.to_owned());
            served(&case["tree_files"])(hex)
        });
        let distinct: std::collections::BTreeSet<&String> = fetched.iter().collect();
        assert_eq!(distinct.len(), fetched.len(), "{}", case["name"]);
        let mut outcome = disposition(walked);
        outcome["fetched"] = json!(fetched);
        assert_eq!(outcome, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn a_walk_fetches_no_file_after_a_failed_fetch() {
    let vector = read_json("vectors/wist2/catalog-tree.json");
    let mut refusals = 0;
    for case in vector["cases"].as_array().unwrap() {
        let catalog: Catalog = serde_json::from_value(case["catalog"].clone()).unwrap();
        let files = &case["tree_files"];
        let failed = RefCell::new(false);
        let walked = walk(&catalog, &bounds(&case["parameters"]), |hex| {
            assert!(!*failed.borrow(), "{}", case["name"]);
            let answer = served(files)(hex);
            *failed.borrow_mut() = answer == TreeFetch::Failed;
            answer
        });
        if failed.into_inner() {
            assert_eq!(walked, Walk::Refused("WIST2-E07"), "{}", case["name"]);
            refusals += 1;
        }
    }
    assert!(refusals > 0);
}

#[test]
fn a_suspended_fetch_suspends_the_walk_without_refusing_it() {
    let vector = read_json("vectors/wist2/catalog-tree.json");
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "three levels")
        .unwrap();
    let catalog: Catalog = serde_json::from_value(case["catalog"].clone()).unwrap();
    let bounds = bounds(&case["parameters"]);
    let files = &case["tree_files"];
    let mut calls = 0;
    let walked = walk(&catalog, &bounds, |hex| {
        calls += 1;
        if calls == 2 {
            TreeFetch::Suspended
        } else {
            served(files)(hex)
        }
    });
    assert_eq!(walked, Walk::Suspended);
    assert_eq!(calls, 2);
    assert_eq!(
        disposition(walk(&catalog, &bounds, served(files)))["list"],
        case["expected"]["list"]
    );
}

#[test]
fn tree_bounds_are_not_read_below_their_floors() {
    assert_eq!(TreeBounds::new(65_536, 16).unwrap(), TreeBounds::suite());
    assert!(TreeBounds::new(65_535, 16).is_err());
    assert!(TreeBounds::new(65_536, 15).is_err());
    assert!(TreeBounds::new(65_537, 17).is_ok());
}

#[test]
fn the_tree_file_example_reads_as_a_bucket() {
    let octets = super::read_text("examples/tree-file.json");
    let octets = octets.trim_end_matches('\n').as_bytes();
    let hex = wist_core::crypto::hex_encode(&<sha2::Sha256 as sha2::Digest>::digest(octets));
    assert!(matches!(
        read_file(&hex, octets, &TreeBounds::suite()),
        Ok(wist_core::objects::TreeFile::Bucket(_))
    ));
}

fn caps(parameters: &Value) -> SizeCaps {
    let value = |name: &str| parameters[name].as_i64().unwrap();
    SizeCaps::new(
        value("url_cap_bytes"),
        value("extract_cap_bytes"),
        value("links_cap_bytes"),
        value("link_url_cap_bytes"),
        value("summary_cap_bytes"),
    )
    .unwrap()
}

#[test]
fn the_items_of_an_accepted_catalog_are_judged_one_by_one_in_list_order() {
    let vector = read_json("vectors/wist2/catalog-items.json");
    assert_fixture_keys(&vector);
    let declarations = declarations(&vector);
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let declaration = &declarations[case["declaration"].as_str().unwrap()];
        let parameters = &case["parameters"];
        let attempt = Attempt::new(
            declaration,
            case["clock"].as_str().unwrap(),
            parameters["clock_skew_seconds"].as_i64().unwrap(),
            parameters["catalog_items_max"].as_i64().unwrap(),
        )
        .unwrap();
        let expected = &case["expected"];
        if let Err(code) = judge(&case["catalog"], &attempt) {
            assert_eq!(code, expected["catalog"], "{name}");
            assert!(expected.get("items").is_none(), "{name}");
            continue;
        }
        assert_eq!(expected["catalog"], "accepted", "{name}");
        let catalog: Catalog = serde_json::from_value(case["catalog"]["catalog"].clone()).unwrap();
        let Walk::Listed(listed) = walk(&catalog, &bounds(parameters), served(&case["tree_files"]))
        else {
            panic!("{name}: the walk does not list the Items");
        };
        let wanted = expected["items"].as_array().unwrap();
        assert_eq!(listed.len(), wanted.len(), "{name}");
        let caps = caps(parameters);
        for (item, want) in listed.iter().zip(wanted) {
            assert_eq!(item["url"], want["url"], "{name}");
            assert_eq!(item_id(item).unwrap(), want["item_id"], "{name}");
            let judged = wist_core::item::judge(item, &catalog, declaration, &caps);
            assert_eq!(
                judged.map_or_else(|code| code, |()| "accepted"),
                want["expected"],
                "{name} {}",
                want["url"]
            );
        }
    }
}

fn built_walk(listed: &[Value], bounds: &TreeBounds) -> (wist_core::tree::Built, Walk) {
    let built = wist_core::tree::build(listed, bounds).unwrap();
    let catalog = Catalog {
        wist_version: "1.0.0".into(),
        publisher: "example.com".into(),
        collection: "journal".into(),
        generated_at: "2026-10-01T12:00:00Z".into(),
        size: listed.len() as u64,
        root: format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&wist_core::item::root(listed).unwrap())
        ),
        tree: built.tree.clone(),
    };
    let walked = walk(&catalog, bounds, |hex| match built.files.get(hex) {
        Some(octets) => TreeFetch::Octets(octets.clone()),
        None => TreeFetch::Failed,
    });
    (built, walked)
}

#[test]
fn a_built_tree_walks_to_the_list_of_every_accepted_tree_vector() {
    let vector = read_json("vectors/wist2/catalog-tree.json");
    let mut rebuilt = 0;
    for case in vector["cases"].as_array().unwrap() {
        let catalog: Catalog = serde_json::from_value(case["catalog"].clone()).unwrap();
        let bounds = bounds(&case["parameters"]);
        let Walk::Listed(listed) = walk(&catalog, &bounds, served(&case["tree_files"])) else {
            continue;
        };
        let (built, walked) = built_walk(&listed, &bounds);
        assert_eq!(walked, Walk::Listed(listed), "{}", case["name"]);
        let written_by_the_reference_writer = [
            "empty Collection: one bucket with no Items",
            "root bucket",
            "sixteen Items whose one bucket would exceed tree_file_cap_bytes, divided by the reference writer",
        ];
        if written_by_the_reference_writer.contains(&case["name"].as_str().unwrap()) {
            assert_eq!(built.tree, catalog.tree, "{}", case["name"]);
        }
        rebuilt += 1;
    }
    assert_eq!(rebuilt, 17);
}

#[test]
fn a_built_tree_divides_a_bucket_above_sixteen_items_into_files_within_the_bounds() {
    let listed: Vec<Value> = (0..300)
        .map(|n| {
            json!({
                "publisher": "example.com",
                "url": format!("https://example.com/journal/{n}"),
                "observed_at": "2026-09-01T00:00:00Z",
                "removed": true,
            })
        })
        .collect();
    let bounds = TreeBounds::suite();
    let (built, walked) = built_walk(&listed, &bounds);
    let Walk::Listed(walked) = walked else {
        panic!("the built tree is refused");
    };
    let mut ordered = listed.clone();
    ordered.sort_by_key(|item| wist_core::item::key(item["url"].as_str().unwrap()));
    assert_eq!(walked, ordered);
    assert!(built.files.len() > 17);
    for (hex, octets) in &built.files {
        match read_file(hex, octets, &bounds).unwrap() {
            wist_core::objects::TreeFile::Bucket(bucket) => {
                assert!(bucket.items.len() <= wist_core::tree::BUCKET_ITEMS_MAX)
            }
            wist_core::objects::TreeFile::Inner(inner) => {
                assert!(inner.children.len() <= wist_core::tree::CHILDREN_MAX)
            }
        }
    }
}

#[test]
fn a_tree_is_not_built_for_a_list_holding_two_items_of_one_url() {
    let item = json!({
        "publisher": "example.com",
        "url": "https://example.com/journal/a",
        "observed_at": "2026-09-01T00:00:00Z",
        "removed": true,
    });
    assert!(wist_core::tree::build(&[item.clone(), item], &TreeBounds::suite()).is_err());
}
