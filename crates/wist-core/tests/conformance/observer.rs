use super::read_json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use wist_core::canary::{sealing_opportunities, BudgetingEpoch, CoverageDeadline};
use wist_core::crypto::hex_decode;
use wist_core::observer::*;

fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}
fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}
fn assert_budget(got: Budget<'_>, expected: &Value) {
    assert_eq!(json!(got.suffix_order), expected["suffix_order"]);
    assert_eq!(json!(got.positions), expected["positions"]);
    assert_eq!(json!(got.budgeted), expected["budgeted"]);
}

#[test]
fn epoch_budget_rotates_across_suffixes() {
    let v = read_json("vectors/wist4/observer-checkpoints.json");
    for case in v["budget_cases"].as_array().unwrap() {
        let registered = names(&case["registered"]);
        let budget = number(&case["budget"]).try_into().unwrap();
        for epoch in case["epochs"].as_array().unwrap() {
            assert_budget(
                epoch_budget(&registered, number(&epoch["epoch"]), budget),
                epoch,
            );
        }
        let size = registered
            .iter()
            .map(|name| suffix(name))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        assert_eq!(size, number(&case["suffixes"]));
        let bound = size.div_ceil(budget.get());
        assert_eq!(bound, number(&case["bound_epochs"]));
        for start in 0..bound {
            let mut seen = BTreeSet::new();
            for epoch in start..start + bound {
                seen.extend(
                    epoch_budget(&registered, epoch, budget)
                        .budgeted
                        .into_iter()
                        .map(suffix),
                );
            }
            assert_eq!(seen.len() as u64, size);
        }
    }
}

#[test]
fn canonical_names_break_equal_budget_hashes() {
    let v = read_json("vectors/wist4/observer-checkpoints.json");
    for case in v["ordering_boundary"]["cases"].as_array().unwrap() {
        let registered = names(&case["registered"]);
        let key = |kind: &str, name: &str| -> [u8; 32] {
            let row = case["sort_keys"][kind]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["name"] == name)
                .unwrap();
            hex_decode(row["sort_key_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        for i in 0..3 {
            for j in 0..3 {
                if i == j {
                    continue;
                }
                let k = 3 - i - j;
                let permutation = [registered[i], registered[j], registered[k]];
                for epoch in case["epochs"].as_array().unwrap() {
                    assert_budget(
                        budget_with_sort_keys(
                            &permutation,
                            number(&epoch["epoch"]),
                            number(&case["budget"]).try_into().unwrap(),
                            |name| key("suffixes", name),
                            |name| key("observers", name),
                        ),
                        epoch,
                    );
                }
            }
        }
    }
}

#[test]
fn epoch_length_is_pinned_at_its_first_block() {
    let v = read_json("vectors/wist4/observer-checkpoints.json");
    for case in v["epoch_cases"].as_array().unwrap() {
        let got = epoch_of_block(number(&case["block"]), |first| {
            let value = v["epoch_changes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|change| number(&change["effective_at_s"]) <= first * 3600)
                .max_by_key(|change| number(&change["effective_at_s"]))
                .map_or(number(&v["epoch_blocks_default"]), |change| {
                    number(&change["value"])
                });
            value.try_into().ok()
        })
        .unwrap();
        assert_eq!(got.number, number(&case["epoch"]));
        assert_eq!(got.first, number(&case["epoch_first_block"]));
        assert_eq!(got.length.get(), number(&case["epoch_length"]));
    }
}

#[test]
fn checkpoints_fix_only_ancestors_strictly_before_reveal() {
    let v = read_json("vectors/wist4/observer-checkpoints.json");
    let prev: BTreeMap<_, _> = v["prev_record"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(id, prev)| (id.as_str(), prev.as_str()))
        .collect();
    let checkpoints: Vec<_> = v["checkpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cp| Checkpoint {
            head: cp["head"].as_str().unwrap(),
            height: number(&cp["height"]),
        })
        .collect();
    for case in v["coverage_cases"].as_array().unwrap() {
        for (id, fixed) in case["fixed_before_reveal"].as_object().unwrap() {
            assert_eq!(
                covered_before(id, number(&case["reveal_height"]), &checkpoints, &prev),
                fixed.as_bool().unwrap()
            );
        }
    }
    let cycle = BTreeMap::from([("a", Some("b")), ("b", Some("a"))]);
    assert!(!covered_before(
        "missing",
        2,
        &[Checkpoint {
            head: "a",
            height: 1
        }],
        &cycle
    ));
    assert!(!covered_before(
        "missing",
        2,
        &[Checkpoint {
            head: "absent",
            height: 1
        }],
        &prev
    ));
}

#[test]
fn reveals_leave_actual_record_and_checkpoint_sealing_opportunities() {
    let v = read_json("vectors/wist4/observer-checkpoints.json");
    for case in v["opportunity_cases"].as_array().unwrap() {
        let times: Vec<_> = case["block_times_s"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        let changes = case["changes"].as_array().unwrap();
        let roster_at = |height| {
            changes
                .iter()
                .filter(|change| {
                    number(&change["height"]) <= height && change.get("registered").is_some()
                })
                .max_by_key(|change| number(&change["height"]))
                .map_or_else(
                    || names(&case["initial_registered"]),
                    |change| names(&change["registered"]),
                )
        };
        let parameter_at = |height, name: &str, default| {
            changes
                .iter()
                .filter(|change| number(&change["height"]) <= height && change.get(name).is_some())
                .max_by_key(|change| number(&change["height"]))
                .map_or(default, |change| number(&change[name]))
        };
        let mut epochs = Vec::new();
        for expected in case["epochs"].as_array().unwrap() {
            let first = number(&expected["first"]);
            let epoch = epoch_of_block(first, |h| {
                parameter_at(h, "epoch_blocks", 24).try_into().ok()
            })
            .unwrap();
            assert_eq!(epoch.number, number(&expected["number"]));
            assert_eq!(epoch.first, first);
            assert_eq!(epoch.last(), u128::from(number(&expected["last"])));
            let roster = roster_at(first);
            assert_eq!(json!(roster), expected["registered"]);
            let budget = parameter_at(
                first,
                "observer_checkpoint_budget",
                number(&case["initial_budget"]),
            );
            assert_eq!(budget, number(&expected["budget"]));
            let budgeted_suffixes: BTreeSet<_> =
                epoch_budget(&roster, epoch.number, budget.try_into().unwrap())
                    .budgeted
                    .into_iter()
                    .map(suffix)
                    .collect();
            assert_eq!(json!(budgeted_suffixes), expected["budgeted_suffixes"]);
            epochs.push(BudgetingEpoch {
                epoch,
                budgeted_suffixes: budgeted_suffixes.into_iter().collect(),
                record_seal_blocks: number(&expected["seal_blocks"]).try_into().unwrap(),
            });
        }
        let deadlines = [CoverageDeadline {
            deadline_s: i128::from(case["coverage_deadline_s"].as_i64().unwrap()),
            record_seal_blocks: number(&case["record_seal_blocks"]).try_into().unwrap(),
        }];
        for probe in case["probes"].as_array().unwrap() {
            let height = number(&probe["height"]);
            let prefix = &times[..=height as usize];
            let opportunities = sealing_opportunities(
                height,
                prefix,
                &deadlines,
                &roster_at(number(&case["newest_delta_height"])),
                &roster_at(height),
                &epochs,
            );
            assert_eq!(
                height >= number(&case["numeric_minimum"]) && opportunities,
                probe["valid"].as_bool().unwrap(),
                "{} at {height}",
                case["label"]
            );
        }
    }
}
