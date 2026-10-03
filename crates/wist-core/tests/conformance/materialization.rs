use super::read_json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::crypto::{hex_decode, SigningKey};
use wist_core::item::{item_id, judge_payload, SizeCaps};
use wist_core::materialization::{self, ContentTuple};
use wist_core::objects::publisher::thumbprint;
use wist_core::objects::{PageItem, PublisherEnvelope, StateEntry};
use wist_core::sealing::{Records, Removal};
use wist_core::snapshot::content_digest;
use wist_core::withdrawal::WithdrawalReplay;

#[derive(Default)]
struct EventReplay {
    records: Records,
    withdrawals: WithdrawalReplay,
    declared: BTreeSet<String>,
}

impl EventReplay {
    fn resumed(tuples: &[StateEntry]) -> Self {
        EventReplay {
            records: Records::from_state(tuples).unwrap(),
            withdrawals: WithdrawalReplay::from_state(tuples).unwrap(),
            declared: tuples
                .iter()
                .filter_map(|tuple| match tuple {
                    StateEntry::Declaration(entry) => Some(entry.domain.clone()),
                    _ => None,
                })
                .collect(),
        }
    }

    fn apply(&mut self, height: u64, event: &Value, publishers: &BTreeMap<String, String>) {
        let text = |member: &str| event[member].as_str().unwrap();
        match text("event") {
            "declaration" => {
                self.declared.insert(text("domain").to_owned());
            }
            "narrowing" => {
                for url in event["urls"].as_array().unwrap() {
                    assert!(self
                        .records
                        .remove(text("publisher"), url.as_str().unwrap())
                        .is_some());
                }
            }
            "withdrawal" => {
                let item = text("item");
                self.withdrawals.adopt(item, &publishers[item], height);
            }
            "base" => {
                self.records
                    .remove_collection(text("publisher"), text("collection"));
            }
            "record" => {
                self.records
                    .apply(
                        text("publisher"),
                        &event["item"],
                        text("collection"),
                        text("catalog"),
                        text("generated_at"),
                    )
                    .unwrap();
            }
            "removal" => {
                assert!(self
                    .records
                    .remove_with(
                        text("publisher"),
                        text("url"),
                        Removal {
                            item_id: text("item").to_owned(),
                            catalog: text("catalog").to_owned(),
                            generated_at: text("generated_at").to_owned(),
                        },
                    )
                    .is_some());
            }
            other => panic!("an event {other}"),
        }
    }

    fn materialized(&self) -> Vec<ContentTuple> {
        materialization::materialized(
            self.records.records(),
            |host| self.declared.contains(host),
            |item| self.withdrawals.is_withdrawn(item),
        )
        .unwrap()
    }

    fn assert_reaches(&self, label: &str, want: &Value) {
        let records: Vec<Value> = self
            .records
            .records()
            .map(|(publisher, url, record)| {
                json!({
                    "publisher": publisher,
                    "url": url,
                    "item": record.item_id,
                    "collection": record.collection,
                    "catalog": record.catalog,
                    "generated_at": record.generated_at,
                })
            })
            .collect();
        assert_eq!(json!(records), want["records"], "{label}: records");
        let removals: Vec<Value> = self
            .records
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
        assert_eq!(json!(removals), want["removals"], "{label}: removals");
        let materialized = self.materialized();
        assert_eq!(
            serde_json::to_value(&materialized).unwrap(),
            want["materialized"],
            "{label}: materialized"
        );
        assert_eq!(
            content_digest(&materialized).unwrap(),
            want["content_digest"].as_str().unwrap(),
            "{label}: content_digest"
        );
    }
}

fn tuples_of(tuples: &[StateEntry], kinds: &[&str]) -> Vec<Value> {
    let mut found: Vec<Value> = tuples
        .iter()
        .map(|tuple| serde_json::to_value(tuple).unwrap())
        .filter(|tuple| kinds.contains(&tuple[0].as_str().unwrap()))
        .collect();
    found.sort_by_key(Value::to_string);
    found
}

#[test]
fn record_materialization_cases_replay_every_epoch_and_resume_from_the_snapshot_tuples() {
    let vector = read_json("vectors/wist3/record-materialization.json");
    for (name, key) in vector["keys"].as_object().unwrap() {
        let seed: [u8; 32] = hex_decode(key["seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let public = SigningKey::from_seed(&seed).public().to_b64u();
        assert_eq!(public, key["x"].as_str().unwrap(), "{name}");
        assert_eq!(thumbprint(&public), key["kid"].as_str().unwrap(), "{name}");
    }
    let mut pages = BTreeMap::new();
    let mut epochs_replayed = 0;
    for case in vector["cases"].as_array().unwrap() {
        let label = case["name"].as_str().unwrap();
        let epochs = case["epochs"].as_array().unwrap();
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(epochs.len(), expected.len(), "{label}");
        let mut publishers = BTreeMap::new();
        for epoch in epochs {
            for event in epoch["events"].as_array().unwrap() {
                if event["event"] == "record" {
                    let id = item_id(&event["item"]).unwrap();
                    publishers.insert(id.clone(), event["publisher"].as_str().unwrap().to_owned());
                    pages.insert(id, event["item"].clone());
                }
            }
        }
        let snapshot = &case["snapshot"];
        let snapshot_height = snapshot["height"].as_u64().unwrap();
        let tuples: Vec<StateEntry> = serde_json::from_value(snapshot["tuples"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&tuples).unwrap(),
            snapshot["tuples"],
            "{label}: the tuples round-trip"
        );
        let mut replay = EventReplay::default();
        let mut resumed: Option<EventReplay> = None;
        let mut sealed_at = None;
        for (epoch, want) in epochs.iter().zip(expected) {
            let height = epoch["height"].as_u64().unwrap();
            assert_eq!(want["height"], height, "{label}");
            let at = epoch["sealed_at"].as_str().unwrap();
            let at_s = wist_core::timestamp::log_seconds(at).unwrap();
            assert!(sealed_at.is_none_or(|previous| previous < at_s), "{label}");
            sealed_at = Some(at_s);
            let label = format!("{label} at {height}");
            for event in epoch["events"].as_array().unwrap() {
                replay.apply(height, event, &publishers);
                if let Some(resumed) = resumed.as_mut() {
                    resumed.apply(height, event, &publishers);
                }
            }
            replay.assert_reaches(&label, want);
            if let Some(resumed) = &resumed {
                resumed.assert_reaches(&format!("{label}, resumed"), want);
            }
            if height == snapshot_height {
                let replayed: Vec<StateEntry> = replay
                    .records
                    .state_entries()
                    .into_iter()
                    .chain(
                        replay
                            .withdrawals
                            .entries()
                            .into_iter()
                            .map(StateEntry::Withdrawal),
                    )
                    .collect();
                assert_eq!(
                    tuples_of(&replayed, &["record", "removal", "withdrawal"]),
                    tuples_of(&tuples, &["record", "removal", "withdrawal"]),
                    "{label}: record, removal and withdrawal tuples"
                );
                let declared: BTreeSet<String> = tuples
                    .iter()
                    .filter_map(|tuple| match tuple {
                        StateEntry::Declaration(entry) => Some(entry.domain.clone()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(declared, replay.declared, "{label}: declaration tuples");
                for tuple in &tuples {
                    match tuple {
                        StateEntry::Collection(entry) => {
                            let declaration = tuples
                                .iter()
                                .find_map(|tuple| match tuple {
                                    StateEntry::Declaration(d) if d.domain == entry.publisher => {
                                        Some(d)
                                    }
                                    _ => None,
                                })
                                .unwrap();
                            let declaration: PublisherEnvelope =
                                serde_json::from_value(declaration.declaration.clone()).unwrap();
                            wist_core::catalog::authenticate(
                                &entry.envelope,
                                &declaration.publisher,
                            )
                            .unwrap_or_else(|code| panic!("{label}: {}: {code}", entry.publisher));
                        }
                        StateEntry::Declaration(_)
                        | StateEntry::Record(_)
                        | StateEntry::Removal(_)
                        | StateEntry::Withdrawal(_) => {}
                        other => panic!("{label}: a tuple {other:?}"),
                    }
                }
                let consumer = EventReplay::resumed(&tuples);
                consumer.assert_reaches(&format!("{label}, resumed"), want);
                resumed = Some(consumer);
            }
            epochs_replayed += 1;
        }
        assert!(
            resumed.is_some(),
            "{label}: the Snapshot height is replayed"
        );
    }
    assert_eq!(
        epochs_replayed,
        vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| case["epochs"].as_array().unwrap().len())
            .sum::<usize>()
    );
    let payloads = vector["payloads"].as_object().unwrap();
    assert_eq!(
        payloads.keys().collect::<BTreeSet<_>>(),
        pages.keys().collect::<BTreeSet<_>>()
    );
    for (identifier, payload) in payloads {
        let page: PageItem = serde_json::from_value(pages[identifier].clone()).unwrap();
        assert_eq!(
            judge_payload(&page, payload, &SizeCaps::suite()),
            Ok(()),
            "{identifier}"
        );
    }
}
