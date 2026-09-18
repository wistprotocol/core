use super::{parameter_default, read_json};
use serde_json::Value;
use wist_core::parameters::{self, Amendment, Schedule};
use wist_core::tiles;

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
    for case in v["block_size_cases"].as_array().unwrap() {
        let mut schedule = Schedule::new(0);
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
            let mut rejected = Vec::new();
            for (index, change) in block["amendments"].as_array().unwrap().iter().enumerate() {
                let Some(value) = change["value"].as_i64() else {
                    rejected.push(index);
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
                if tentative
                    .try_accept_with_block_size(amendment, proposed_max)
                    .is_err()
                {
                    rejected.push(index);
                }
            }
            assert_eq!(
                serde_json::json!(rejected),
                expected["rejected_indices"],
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

#[test]
fn block_size_candidate_at_the_registry_floor_is_accepted_below_it_rejected() {
    let floor = parameters::spec("block_decompressed_cap_bytes")
        .unwrap()
        .min
        .unwrap();
    assert_eq!(floor, 65_537);
    let below = Amendment {
        parameter: "block_decompressed_cap_bytes".into(),
        value: floor - 1,
        block_number: 0,
        entry_index: 0,
        sealed_at_s: 0,
        effective_at_s: 604_800,
    };
    let at_floor = Amendment {
        parameter: "block_decompressed_cap_bytes".into(),
        value: floor,
        block_number: 0,
        entry_index: 1,
        sealed_at_s: 0,
        effective_at_s: 604_800,
    };
    let mut rejecting = Schedule::new(0);
    assert!(rejecting.try_accept_with_block_size(below, 0).is_err());
    let mut accepting = Schedule::new(0);
    assert!(accepting.try_accept_with_block_size(at_floor, 0).is_ok());
}

#[test]
fn block_transport_bound_from_verified_prefix() {
    let v = vector();
    let default = v["block_cap_default"].as_u64().unwrap();
    for case in v["block_transport_cases"].as_array().unwrap() {
        let snapshot_bootstrap = case["snapshot_bootstrap"].as_bool().unwrap_or(false);
        let bound = if snapshot_bootstrap {
            case["accepted_caps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cap| cap["value"].as_u64().unwrap())
                .fold(default, u64::max)
        } else if let Some(prefix_sealed_at_s) = case["prefix_sealed_at_s"].as_i64() {
            let mut schedule = Schedule::new(0);
            for cap in case["accepted_caps"].as_array().unwrap() {
                schedule.adopt(Amendment {
                    parameter: "block_decompressed_cap_bytes".into(),
                    value: cap["value"].as_i64().unwrap(),
                    block_number: cap["block_height"].as_u64().unwrap(),
                    entry_index: cap["entry_index"].as_u64().unwrap(),
                    sealed_at_s: 0,
                    effective_at_s: cap["effective_at_s"].as_i64().unwrap(),
                });
            }
            schedule.block_size_bounds(prefix_sealed_at_s).1
        } else {
            default
        };
        assert_eq!(
            bound,
            case["transport_bound"].as_u64().unwrap(),
            "{}",
            case["label"]
        );
        let entries_bytes = case["entries_bytes"].as_u64().unwrap();
        let result = tiles::check_transport_bound(entries_bytes, bound);
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
        match (result, case["error"].as_str()) {
            (Ok(()), None) => {}
            (Err(err), Some(code)) => assert_eq!(err.code(), Some(code), "{}", case["label"]),
            other => panic!("{}: {other:?}", case["label"]),
        }
    }
}
