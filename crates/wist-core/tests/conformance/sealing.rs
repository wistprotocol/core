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

fn replay_history(
    label: &str,
    epochs: &[Value],
    results: &[Value],
    log_key: &dyn Fn(&str) -> Option<PublicKey>,
) -> Replay {
    assert_eq!(epochs.len(), results.len(), "{label}");
    let mut replay = Replay::new();
    for (epoch, want) in epochs.iter().zip(results) {
        let height = epoch["height"].as_u64().unwrap();
        assert_eq!(want["height"], height, "{label}");
        let label = format!("{label} at {height}");
        let named = epoch["entries"].as_array().unwrap();
        let entries: Vec<Value> = named.iter().map(|named| named["entry"].clone()).collect();
        let parameters = parameters(&epoch["parameters"]).unwrap();
        let root = format!("height {height}");
        let outcome = replay
            .epoch(&Epoch {
                height,
                root: &root,
                sealed_at: epoch["sealed_at"].as_str().unwrap(),
                parameters: &parameters,
                suffix_list: None,
                log_key,
                entries: &entries,
            })
            .unwrap();
        match outcome {
            Outcome::Rejected { codes } => {
                assert_eq!(want["status"], "rejected", "{label}");
                assert_eq!(json!(codes), want["codes"], "{label}");
            }
            Outcome::Accepted {
                entries: judged, ..
            } => {
                assert_eq!(want["status"], "accepted", "{label}");
                assert_judgments(&label, named, &judged, &want["entries"]);
            }
        }
    }
    replay
}

#[test]
fn several_logs_order_catalogs_and_take_the_state_proved_against_the_latest() {
    let vector = read_json("vectors/multilog/catalog-order.json");
    for case in vector["order_cases"].as_array().unwrap() {
        let catalogs = case["catalogs"].as_array().unwrap();
        assert_eq!(
            json!(wist_core::several_logs::in_catalog_order(catalogs).unwrap()),
            case["expected"],
            "{}",
            case["name"]
        );
    }
    let log = &vector["keys"]["log"];
    let log_key_id = log["kid"].as_str().unwrap();
    let log_public = PublicKey::from_b64u(log["x"].as_str().unwrap()).unwrap();
    let log_key = |key_id: &str| (key_id == log_key_id).then(|| log_public.clone());
    let mut found = BTreeMap::new();
    let cases = vector["combined_cases"].as_array().unwrap();
    for case in cases {
        let label = case["name"].as_str().unwrap();
        let publisher = case["publisher"].as_str().unwrap();
        let url = case["url"].as_str().unwrap();
        let expected = &case["expected"];
        let mut replays = Vec::new();
        for log in case["logs"].as_array().unwrap() {
            let name = log["name"].as_str().unwrap().to_owned();
            let replay = replay_history(
                &format!("{label}: {name}"),
                log["epochs"].as_array().unwrap(),
                log["results"].as_array().unwrap(),
                &log_key,
            );
            assert_eq!(
                super::logbook::url_state(&replay, publisher, url),
                expected["log_states"][&name],
                "{label}: {name}"
            );
            found.extend(page_items(std::slice::from_ref(log)));
            replays.push((name, replay));
        }
        assert_eq!(
            expected["log_states"].as_object().unwrap().len(),
            replays.len(),
            "{label}"
        );
        let combined = wist_core::several_logs::combine(
            replays
                .iter()
                .map(|(name, replay)| (name.clone(), replay.records().state(publisher, url))),
        )
        .unwrap();
        assert_eq!(
            super::logbook::combined_state(combined),
            expected["combined"],
            "{label}"
        );
        if let Some(snapshot) = expected.get("snapshot") {
            let (_, replay) = replays
                .iter()
                .find(|(name, _)| *name == snapshot["log"])
                .unwrap();
            let removals: Vec<Value> = replay
                .state_entries()
                .into_iter()
                .filter_map(|tuple| match tuple {
                    wist_core::objects::StateEntry::Removal(removal) => Some(json!({
                        "publisher": removal.publisher,
                        "url": removal.url,
                        "item": removal.item_id,
                        "catalog": removal.catalog_id,
                        "generated_at": removal.generated_at,
                    })),
                    _ => None,
                })
                .collect();
            assert_eq!(json!(removals), snapshot["removals"], "{label}: snapshot");
        }
    }
    let payloads = vector["payloads"].as_object().unwrap();
    assert_eq!(
        payloads.keys().collect::<BTreeSet<_>>(),
        found.keys().collect::<BTreeSet<_>>()
    );
    for (identifier, payload) in payloads {
        assert_eq!(
            judge_payload(&found[identifier], payload, &SizeCaps::suite()),
            Ok(()),
            "{identifier}"
        );
    }
}

#[test]
fn a_replay_resumed_from_its_state_tuples_at_every_height_judges_and_holds_what_the_full_replay_does(
) {
    let vector = read_json("vectors/wist3/catalog-sealing.json");
    let log = &vector["keys"]["log"];
    let log_key_id = log["kid"].as_str().unwrap();
    let log_public = PublicKey::from_b64u(log["x"].as_str().unwrap()).unwrap();
    let log_key = |key_id: &str| (key_id == log_key_id).then(|| log_public.clone());
    let mut resumes = 0;
    let mut breaches = 0;
    for history in vector["histories"].as_array().unwrap() {
        let label = history["name"].as_str().unwrap();
        let epochs = history["epochs"].as_array().unwrap();
        for resume_at in 0..epochs.len() {
            let mut full = Replay::new();
            let mut resumed: Option<Replay> = None;
            for epoch in epochs {
                let height = epoch["height"].as_u64().unwrap();
                let entries: Vec<Value> = epoch["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|named| named["entry"].clone())
                    .collect();
                let parameters = parameters(&epoch["parameters"]).unwrap();
                let root = format!("height {height}");
                let sealed_at = epoch["sealed_at"].as_str().unwrap();
                let at = Epoch {
                    height,
                    root: &root,
                    sealed_at,
                    parameters: &parameters,
                    suffix_list: None,
                    log_key: &log_key,
                    entries: &entries,
                };
                let outcome = full.epoch(&at).unwrap();
                if let Some(replay) = resumed.as_mut() {
                    let label = format!("{label}: resumed at {resume_at}, Epoch {height}");
                    let judged = replay.epoch(&at).unwrap();
                    if judged != outcome {
                        assert_breach_accepted_after_resume(&label, &entries, &judged, &outcome);
                        resumed = None;
                        breaches += 1;
                        continue;
                    }
                    let resumed = replay;
                    assert_eq!(
                        resumed.state_entries().len(),
                        full.state_entries().len(),
                        "{label}"
                    );
                    assert_eq!(
                        serde_json::to_value(resumed.state_entries()).unwrap(),
                        serde_json::to_value(full.state_entries()).unwrap(),
                        "{label}"
                    );
                    assert_eq!(
                        resumed.materialized().unwrap(),
                        full.materialized().unwrap()
                    );
                    assert!(resumed.payload_duties(sealed_at).is_err());
                }
                if height == resume_at as u64 {
                    let tuples = full.state_entries();
                    let replay =
                        Replay::resumed(height, sealed_at, full.declarations().clone(), &tuples)
                            .unwrap();
                    assert_eq!(
                        serde_json::to_value(replay.state_entries()).unwrap(),
                        serde_json::to_value(&tuples).unwrap()
                    );
                    resumed = Some(replay);
                    resumes += 1;
                }
            }
        }
    }
    assert!(resumes > breaches && breaches > 0);
}

fn assert_breach_accepted_after_resume(
    label: &str,
    entries: &[Value],
    resumed: &Outcome,
    full: &Outcome,
) {
    let (
        Outcome::Accepted {
            entries: resumed,
            records_removed: resumed_removed,
        },
        Outcome::Accepted {
            entries: full,
            records_removed: full_removed,
        },
    ) = (resumed, full)
    else {
        panic!("{label}: {resumed:?} against {full:?}");
    };
    assert_eq!(resumed_removed, full_removed, "{label}");
    for ((entry, resumed), full) in entries.iter().zip(resumed).zip(full) {
        if resumed != full {
            assert_eq!(entry["type"], "registry_update", "{label}");
            assert_eq!(*resumed, Some(Judgment::Valid), "{label}");
            let Some(Judgment::Ignored(failures)) = full else {
                panic!("{label}: {full:?}");
            };
            assert!(
                failures
                    .iter()
                    .all(|f| f.condition.as_str() == "contract" && f.code == "WIST4-E04"),
                "{label}"
            );
        }
    }
}
