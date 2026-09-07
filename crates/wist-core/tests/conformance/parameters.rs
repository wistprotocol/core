use super::{parameter_default, read_json};
use serde_json::Value;
use wist_core::parameters::{self, Amendment, CadenceProfile, Schedule};
use wist_core::sanctions::{self, Notice, Outcome, ProcessAct, ProcessKind};

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
fn cadence_transitions() {
    for case in vector()["cadence_transition_cases"].as_array().unwrap() {
        let profiles: Vec<_> = case["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| CadenceProfile {
                from_s: p["from_s"].as_i64().unwrap(),
                confirm_window_hours: p["confirm_window_hours"].as_i64().unwrap(),
                record_seal_blocks: p["record_seal_blocks"].as_i64().unwrap(),
                block_cadence_seconds: p["block_cadence_seconds"].as_i64().unwrap(),
            })
            .collect();
        assert_eq!(
            parameters::validate_cadence_transitions(&profiles).is_ok(),
            case["transition_valid"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
        let mut schedule = Schedule::new(0);
        let mut index = 0;
        let mut rejected = false;
        for pair in profiles.windows(2) {
            for (name, old, value) in [
                (
                    "confirm_window_hours",
                    pair[0].confirm_window_hours,
                    pair[1].confirm_window_hours,
                ),
                (
                    "block_cadence_seconds",
                    pair[0].block_cadence_seconds,
                    pair[1].block_cadence_seconds,
                ),
            ] {
                if old == value {
                    continue;
                }
                rejected |= schedule
                    .try_accept(Amendment {
                        parameter: name.into(),
                        value,
                        block_number: 0,
                        entry_index: index,
                        sealed_at_s: 0,
                        effective_at_s: pair[1].from_s,
                    })
                    .is_err();
                index += 1;
            }
        }
        assert_eq!(
            !rejected,
            case["transition_valid"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
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
        let value = details["value"].as_i64().unwrap();
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
fn live_evidence_retention() {
    let vectors = vector();
    let param = |name: &str, at: i64| {
        vectors["retention_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|p| p["from_s"].as_i64().unwrap() <= at)
            .unwrap()[name]
            .as_i64()
            .unwrap()
    };
    for case in vectors["retention_cases"].as_array().unwrap() {
        let first_served = case["evidence_first_served_s"].as_i64().unwrap();
        for probe in case["probes"].as_array().unwrap() {
            let now = probe["n_s"].as_i64().unwrap();
            let mut processes = Vec::new();
            for notice in case["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["accepted"].as_bool().unwrap())
            {
                let opened = notice["sealed_at_s"].as_i64().unwrap();
                let notice = (
                    notice,
                    Notice {
                        id: "notice",
                        subject: "sample.net",
                        sanction: true,
                        height: opened as u64,
                        sealed_at_s: opened,
                        activation_height: opened as u64,
                        appeal_window_days: param("appeal_window_days", opened) as u64,
                        appeal_seal_days: param("appeal_seal_days", opened) as u64,
                    },
                );
                let acts: Vec<_> = [
                    ("appeal_s", ProcessKind::Appeal),
                    ("merits_ruling_s", ProcessKind::Ruling(Outcome::Upheld)),
                    ("unappealed_s", ProcessKind::Ruling(Outcome::Unappealed)),
                ]
                .into_iter()
                .filter_map(|(id, kind)| {
                    notice.0[id].as_i64().map(|at| ProcessAct {
                        id,
                        notice: "notice",
                        subject: "sample.net",
                        height: at as u64,
                        sealed_at_s: at,
                        kind,
                        ruling_deadline_days: param("ruling_deadline_days", at) as u64,
                    })
                })
                .collect();
                processes.push(sanctions::process_at(notice.1, &acts, now as u64, now));
            }
            let ends: Vec<_> = processes
                .iter()
                .filter_map(|p| p.retention_end_at_s)
                .collect();
            let expected: Vec<_> = probe["process_ends_s"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| i128::from(v.as_i64().unwrap()))
                .collect();
            assert_eq!(ends, expected, "{} at {now}", case["label"]);
            assert_eq!(
                sanctions::must_retain_evidence(
                    first_served,
                    param("mirror_retention_days", first_served),
                    &processes,
                    now
                ),
                probe["must_serve"].as_bool().unwrap(),
                "{} at {now}",
                case["label"]
            );
        }
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
                let amendment = Amendment {
                    parameter: "block_decompressed_cap_bytes".into(),
                    value: change["value"].as_i64().unwrap(),
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
