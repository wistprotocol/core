use super::read_json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::PublicKey;
use wist_core::declaration::inner_hash;
use wist_core::item::{item_id, judge_payload, SizeCaps};
use wist_core::objects::PageItem;
use wist_core::sealing::{Epoch, Judgment, Outcome, Parameters, Replay};

fn parameters(map: &Value) -> Result<Parameters, wist_core::Error> {
    let map = map.as_object().unwrap();
    let mut amended: Vec<(&str, i64)> = map
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_i64().unwrap()))
        .collect();
    let domain = map["domain_epoch_entries_max"].as_i64().unwrap();
    let labeler = wist_core::parameters::spec("labeler_epoch_entries_max")
        .unwrap()
        .default
        .unwrap();
    amended.push(("labeler_epoch_entries_max", labeler.min(domain)));
    Parameters::new(amended)
}

fn declaration_names(histories: &[Value]) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for history in histories {
        for epoch in history["epochs"].as_array().unwrap() {
            for named in epoch["entries"].as_array().unwrap() {
                if named["entry"]["type"] == "publisher_declaration" {
                    names.insert(
                        inner_hash(&named["entry"]["body"]).unwrap(),
                        named["name"].as_str().unwrap().to_owned(),
                    );
                }
            }
        }
    }
    names
}

fn state(replay: &Replay, names: &BTreeMap<String, String>) -> Value {
    let declarations: Vec<Value> = replay
        .declarations()
        .domains()
        .iter()
        .map(|(domain, state)| {
            json!({
                "publisher": domain,
                "current": names[state.current().hash()],
                "pending_head": state.pending().map(|pending| &names[pending.head().hash()]),
                "window_end": state.window().map(|window| {
                    wist_core::timestamp::instant(i64::try_from(window.end_s()).unwrap()).unwrap()
                }),
            })
        })
        .collect();
    let catalogs: Vec<Value> = replay
        .latest_catalogs()
        .map(|(publisher, collection, latest)| {
            json!({
                "publisher": publisher,
                "collection": collection,
                "catalog": latest.catalog_id,
                "floor": latest.floor(),
                "sealing_height": latest.sealing_height,
                "base": latest.base,
            })
        })
        .collect();
    let records: Vec<Value> = replay
        .records()
        .records()
        .map(|(publisher, url, record)| {
            json!({
                "publisher": publisher,
                "url": url,
                "item": record.item,
                "collection": record.collection,
                "catalog": record.catalog,
                "generated_at": record.generated_at,
            })
        })
        .collect();
    let removals: Vec<Value> = replay
        .records()
        .removals()
        .map(|(publisher, url, removal)| {
            json!({
                "publisher": publisher,
                "url": url,
                "item": removal.item_id,
                "catalog": removal.catalog,
                "generated_at": removal.generated_at,
            })
        })
        .collect();
    json!({"declarations": declarations, "catalogs": catalogs, "records": records, "removals": removals})
}

fn assert_judgments(label: &str, named: &[Value], judged: &[Option<Judgment>], expected: &Value) {
    let expected = expected.as_array().unwrap();
    let produced: Vec<(&str, &Judgment)> = named
        .iter()
        .zip(judged)
        .filter_map(|(named, judgment)| Some((named["name"].as_str().unwrap(), judgment.as_ref()?)))
        .collect();
    assert_eq!(produced.len(), expected.len(), "{label}: judged Entries");
    for ((name, judgment), want) in produced.into_iter().zip(expected) {
        assert_eq!(name, want["name"], "{label}");
        match judgment {
            Judgment::Valid => assert_eq!(want["disposition"], "valid", "{label}: {name}"),
            Judgment::Ignored(failures) => {
                assert_eq!(want["disposition"], "ignored", "{label}: {name}");
                let conditions: Vec<&str> = failures.iter().map(|f| f.condition.as_str()).collect();
                assert_eq!(json!(conditions), want["failed"], "{label}: {name}");
                let allowed: BTreeSet<&str> = want["codes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|code| code.as_str().unwrap())
                    .collect();
                for failure in failures {
                    assert!(
                        allowed.contains(failure.code),
                        "{label}: {name} {} reported {}, not among {allowed:?}",
                        failure.condition.as_str(),
                        failure.code
                    );
                }
            }
        }
    }
}

#[test]
fn catalog_sealing_histories_replay_every_epoch_judgment_and_state() {
    let vector = read_json("vectors/wist3/catalog-sealing.json");
    let histories = vector["histories"].as_array().unwrap();
    let names = declaration_names(histories);
    let log = &vector["keys"]["log"];
    let log_key_id = log["kid"].as_str().unwrap();
    let log_public = PublicKey::from_b64u(log["x"].as_str().unwrap()).unwrap();
    let log_key = |key_id: &str| (key_id == log_key_id).then(|| log_public.clone());
    let mut epochs_replayed = 0;
    for history in histories {
        let label = history["name"].as_str().unwrap();
        let mut replay = Replay::new();
        let epochs = history["epochs"].as_array().unwrap();
        let expected = history["expected"].as_array().unwrap();
        assert_eq!(epochs.len(), expected.len(), "{label}");
        for (epoch, want) in epochs.iter().zip(expected) {
            let height = epoch["height"].as_u64().unwrap();
            let label = format!("{label} at {height}");
            let named = epoch["entries"].as_array().unwrap();
            let entries: Vec<Value> = named.iter().map(|named| named["entry"].clone()).collect();
            let parameters = parameters(&epoch["parameters"]).unwrap();
            let root = format!("height {height}");
            let sealed_at = epoch["sealed_at"].as_str().unwrap();
            let outcome = replay
                .epoch(&Epoch {
                    height,
                    root: &root,
                    sealed_at,
                    parameters: &parameters,
                    suffix_list: None,
                    log_key: &log_key,
                    entries: &entries,
                })
                .unwrap();
            assert_eq!(want["height"], height, "{label}");
            match outcome {
                Outcome::Rejected { codes } => {
                    assert_eq!(want["status"], "rejected", "{label}");
                    assert_eq!(json!(codes), want["codes"], "{label}");
                }
                Outcome::Accepted {
                    entries: judged,
                    records_removed,
                } => {
                    assert_eq!(want["status"], "accepted", "{label}");
                    assert_judgments(&label, named, &judged, &want["entries"]);
                    let removed: Vec<Value> = records_removed
                        .iter()
                        .map(|removed| {
                            json!({
                                "publisher": removed.publisher,
                                "url": removed.url,
                                "cause": removed.cause.as_str(),
                            })
                        })
                        .collect();
                    assert_eq!(json!(removed), want["records_removed"], "{label}");
                }
            }
            assert_eq!(state(&replay, &names), want["state"], "{label}");
            if let Some(duties) = want.get("payload_duties") {
                let produced: Vec<Value> = replay
                    .payload_duties(sealed_at)
                    .unwrap()
                    .into_iter()
                    .map(|duty| {
                        json!({
                            "publisher": duty.publisher,
                            "url": duty.url,
                            "item": duty.item_id,
                            "until": duty.until,
                        })
                    })
                    .collect();
                assert_eq!(&json!(produced), duties, "{label}: payload_duties");
            }
            epochs_replayed += 1;
        }
    }
    assert_eq!(
        epochs_replayed,
        histories
            .iter()
            .map(|h| h["epochs"].as_array().unwrap().len())
            .sum::<usize>()
    );
}

#[test]
fn a_replay_refuses_a_parameter_map_out_of_bound_or_carrying_a_constant() {
    let vector = read_json("vectors/wist3/catalog-sealing.json");
    for case in vector["parameter_cases"].as_array().unwrap() {
        let outcome = if parameters(&case["parameters"]).is_ok() {
            "accepted"
        } else {
            "refused"
        };
        assert_eq!(outcome, case["expected"], "{}", case["name"]);
    }
}

fn page_items(histories: &[Value]) -> BTreeMap<String, PageItem> {
    let mut found = BTreeMap::new();
    for history in histories {
        for epoch in history["epochs"].as_array().unwrap() {
            for named in epoch["entries"].as_array().unwrap() {
                let item = &named["entry"]["body"]["item"];
                if named["entry"]["type"] != "publisher_item" || item.get("removed").is_some() {
                    continue;
                }
                if let Ok(page) = serde_json::from_value::<PageItem>(item.clone()) {
                    found.insert(item_id(item).unwrap(), page);
                }
            }
        }
    }
    found
}

#[test]
fn every_page_item_of_the_sealing_histories_commits_to_its_payload() {
    let vector = read_json("vectors/wist3/catalog-sealing.json");
    let items = page_items(vector["histories"].as_array().unwrap());
    let payloads = vector["payloads"].as_object().unwrap();
    assert_eq!(
        payloads.keys().collect::<BTreeSet<_>>(),
        items.keys().collect::<BTreeSet<_>>()
    );
    for (identifier, payload) in payloads {
        assert_eq!(
            judge_payload(&items[identifier], payload, &SizeCaps::suite()),
            Ok(()),
            "{identifier}"
        );
    }
}

#[test]
fn the_example_epoch_seals_a_declaration_a_catalog_and_two_valid_items() {
    let vector = read_json("vectors/wist3/epoch.json");
    let entries = vector["entries"].as_array().unwrap();
    let sealed_at = vector["checkpoint"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("sealed_at "))
        .unwrap();
    let mut replay = Replay::new();
    let outcome = replay
        .epoch(&Epoch {
            height: 0,
            root: vector["root"].as_str().unwrap(),
            sealed_at,
            parameters: &Parameters::suite(),
            suffix_list: None,
            log_key: &|_| None,
            entries,
        })
        .unwrap();
    let Outcome::Accepted {
        entries: judged,
        records_removed,
    } = outcome
    else {
        panic!("the example Epoch is rejected: {outcome:?}");
    };
    assert_eq!(
        judged,
        vec![
            None,
            Some(Judgment::Valid),
            Some(Judgment::Valid),
            Some(Judgment::Valid)
        ]
    );
    assert!(records_removed.is_empty());
    let urls: Vec<&str> = replay.records().records().map(|(_, url, _)| url).collect();
    assert_eq!(
        urls,
        [
            "https://example.com/blog/post-2",
            "https://example.com/blog/post-3"
        ]
    );
    let items = page_items(&[json!({"epochs": [{"entries": entries
        .iter()
        .map(|entry| json!({"entry": entry}))
        .collect::<Vec<_>>()}]})]);
    let payloads = vector["payloads"].as_object().unwrap();
    assert_eq!(payloads.len(), items.len());
    for (identifier, payload) in payloads {
        assert_eq!(
            judge_payload(&items[identifier], payload, &SizeCaps::suite()),
            Ok(())
        );
    }
}
