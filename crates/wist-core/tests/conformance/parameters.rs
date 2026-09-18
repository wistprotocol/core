use super::{parameter_default, read_json};
use serde_json::Value;
use wist_core::parameters::{self, Amendment, Schedule};

fn vector() -> Value {
    read_json("vectors/wist4/parameter-combinations.json")
}

#[test]
fn prospective_schedule() {
    let vectors = vector();
    for case in vectors["prospective_cases"].as_array().unwrap() {
        let changes: Vec<_> = case["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Amendment {
                parameter: c["parameter"].as_str().unwrap().into(),
                value: c["value"].as_i64().unwrap(),
                block_number: c["block_height"].as_u64().unwrap(),
                entry_index: c["entry_index"].as_u64().unwrap(),
                sealed_at_s: c["sealed_at_s"].as_i64().unwrap(),
                effective_at_s: c["effective_at_s"].as_i64().unwrap(),
            })
            .collect();
        let replay = Schedule::replay(0, &changes);
        let rejected: Vec<_> = case["rejected_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as usize)
            .collect();
        assert_eq!(replay.rejected, rejected, "{}", case["label"]);
        for i in 0..changes.len() {
            assert_eq!(
                replay.error_at(i),
                rejected.contains(&i).then_some("WIST4-E03")
            );
        }
        for probe in case["maps"].as_array().unwrap() {
            for (name, value) in probe["values"].as_object().unwrap() {
                assert_eq!(
                    replay
                        .schedule
                        .value_at(name, probe["at_s"].as_i64().unwrap()),
                    value.as_i64(),
                    "{}: {name}",
                    case["label"]
                );
            }
        }
    }
}

#[test]
fn signed_parameter_wire_bounds() {
    let vectors = vector();
    let key = wist_core::crypto::PublicKey::from_b64u(vectors["wire_public_key"].as_str().unwrap())
        .unwrap();
    for case in vectors["wire_cases"].as_array().unwrap() {
        let envelope = &case["envelope"];
        if case["canonical_integer"].as_bool().unwrap() {
            let bytes = wist_core::jcs::canonicalize(&envelope["update"]).unwrap();
            wist_core::crypto::verify(&key, &bytes, envelope["sig"]["value"].as_str().unwrap())
                .unwrap();
        }
        let details = &envelope["update"]["details"];
        let name = details["parameter"].as_str().unwrap();
        let integral = details["value"].as_i64().or_else(|| {
            details["value"]
                .as_f64()
                .filter(|f| f.fract() == 0.0)
                .map(|f| f as i64)
        });
        let timestamp_ok =
            wist_core::timestamp::log_seconds(envelope["update"]["effective_at"].as_str().unwrap())
                .is_ok();
        let (Some(value), true) = (integral, timestamp_ok) else {
            assert!(
                !case["schema_valid"].as_bool().unwrap(),
                "{}",
                case["label"]
            );
            assert_eq!(case["sealed_disposition"], "ignored", "{}", case["label"]);
            continue;
        };
        let bounds = parameters::validate_value(name, value).is_ok();
        let combinations = parameters::validate_combinations(|p| {
            if p == name {
                value
            } else {
                parameter_default(p)
            }
        })
        .is_ok();
        assert_eq!(
            bounds,
            case["schema_valid"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
        assert_eq!(
            combinations,
            case["combinations_hold_at_defaults"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
        let mut schedule = Schedule::new(0);
        assert_eq!(
            schedule
                .try_accept(Amendment {
                    parameter: name.into(),
                    value,
                    block_number: 0,
                    entry_index: 0,
                    sealed_at_s: 0,
                    effective_at_s: 7 * 86400,
                })
                .is_ok(),
            bounds && combinations,
            "{}",
            case["label"]
        );
    }
}

#[test]
fn block_size_schedules() {
    let v = vector();
    let floor = parameters::spec("block_decompressed_cap_bytes")
        .unwrap()
        .min
        .unwrap();
    let grace = parameter_default("param_grace_days") * 86_400;
    for case in v["block_size_cases"].as_array().unwrap() {
        let mut schedule = Schedule::new(0);
        let mut registry = Schedule::new(0);
        let mut largest = 0;
        let mut previous = None;
        for (height, block) in case["blocks"].as_array().unwrap().iter().enumerate() {
            let expected = &case["expected"][height];
            let transport = previous.map_or(v["block_cap_default"].as_u64().unwrap(), |at| {
                schedule.block_size_bounds(at).1
            });
            assert_eq!(
                transport,
                expected["transport_bound_before"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
            let at = block["sealed_at_s"].as_i64().unwrap();
            let proposed_max = largest.max(block["jcs_bytes"].as_u64().unwrap());
            let mut tentative = schedule.clone();
            let mut under_registry = registry.clone();
            let mut rejected = Vec::new();
            let mut rejected_under_registry = std::collections::BTreeSet::new();
            let mut below_floor = std::collections::BTreeSet::new();
            for (index, change) in block["amendments"].as_array().unwrap().iter().enumerate() {
                let Some(value) = change["value"].as_i64() else {
                    rejected.push(index);
                    rejected_under_registry.insert(index);
                    continue;
                };
                let amendment = Amendment {
                    parameter: "block_decompressed_cap_bytes".into(),
                    value,
                    block_number: height as u64,
                    entry_index: index as u64,
                    sealed_at_s: at,
                    effective_at_s: change["effective_at_s"].as_i64().unwrap(),
                };
                assert_eq!(
                    parameters::validate_value(&amendment.parameter, value).is_ok(),
                    value >= floor,
                    "{}",
                    case["label"]
                );
                if value < floor {
                    below_floor.insert(index);
                }
                if under_registry
                    .try_accept_with_block_size(amendment.clone(), proposed_max)
                    .is_err()
                {
                    rejected_under_registry.insert(index);
                }
                let within_grace = amendment.effective_at_s - amendment.sealed_at_s >= grace;
                let mut candidate = tentative.clone();
                candidate.adopt(amendment);
                if within_grace && candidate.block_size_bounds(at).0 >= proposed_max {
                    tentative = candidate;
                } else {
                    rejected.push(index);
                }
            }
            assert_eq!(
                serde_json::json!(rejected),
                expected["rejected_indices"],
                "{}",
                case["label"]
            );
            let expected_under_registry: std::collections::BTreeSet<usize> =
                rejected.iter().copied().chain(below_floor).collect();
            assert_eq!(
                rejected_under_registry, expected_under_registry,
                "{}",
                case["label"]
            );
            let cap = tentative.block_size_bounds(at).0;
            assert_eq!(
                cap,
                expected["sealing_cap"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
            let valid = proposed_max <= cap;
            assert_eq!(
                valid,
                expected["block_valid"].as_bool().unwrap(),
                "{}",
                case["label"]
            );
            if valid {
                schedule = tentative;
                registry = under_registry;
                largest = proposed_max;
                previous = Some(at);
            }
            assert_eq!(
                largest,
                expected["largest_bytes"].as_u64().unwrap(),
                "{}",
                case["label"]
            );
        }
    }
}
