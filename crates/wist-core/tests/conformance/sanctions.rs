use super::read_json;
use serde_json::{json, Value};
use wist_core::confirmation::CandidateRecord;
use wist_core::objects::RegistryUpdate;
use wist_core::sanctions::*;

const DAY: i64 = 86_400;
const SUBJECT: &str = "site.sample.net";

fn id(value: &str) -> [u8; 32] {
    wist_core::crypto::hex_decode(value.strip_prefix("sha256:").unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn name(value: [u8; 32]) -> String {
    format!("sha256:{}", wist_core::crypto::hex_encode(&value))
}

fn records(activation: [u8; 32], height: u64, severity: u8) -> Vec<EvidenceRecord<'static>> {
    [([2; 32], "a.example.org"), (activation, "b.sample.net")]
        .into_iter()
        .enumerate()
        .map(|(i, (id, auditor))| EvidenceRecord {
            id,
            record: CandidateRecord {
                block_height: height,
                entry_index: i as u64,
                block_sealed_at_s: height as i64 * DAY,
                auditor_id: auditor,
                effective_similarity: if severity == 3 { 0 } else { 200_000 },
            },
            confirm_auditors: 2,
            confirm_window_hours: 72,
        })
        .collect()
}

fn block<'a, 'b>(height: u64) -> ReplayBlock<'a, 'b> {
    ReplayBlock {
        height,
        sealed_at_s: height as i64 * DAY,
        reset: false,
        lift: false,
        findings: &[],
        available_records: &[],
        notices: &[],
        acts: &[],
        appeal_window_days: 14,
        appeal_seal_days: 7,
    }
}

fn update(level: u8, activation: [u8; 32], evidence: Vec<String>) -> RegistryUpdate {
    serde_json::from_value(json!({"wist_version":"1.0.0", "action":"notice", "subject": SUBJECT,
        "effective_at":"2026-08-02T00:00:00Z", "details":{"kind":"sanction", "level":level,
        "activation":name(activation), "reason":"confirmed evidence", "appeal_deadline":"2026-08-16T00:00:00Z"},
        "evidence":evidence})).unwrap()
}

#[test]
fn wist4_notice_targets() {
    let v = read_json("vectors/wist4/sanctions.json");
    let key = wist_core::crypto::PublicKey::from_b64u(v["process"]["public_key"].as_str().unwrap())
        .unwrap();
    for case in v["notice_target_cases"].as_array().unwrap() {
        let target = &case["activation"];
        let activation = id(target["record_id"].as_str().unwrap());
        let current = id(case["current_activation_at_reversal"].as_str().unwrap());
        let mut evidence = records(activation, 0, 3);
        evidence[0].id = [0x22; 32];
        let mut replacement = records(current, 2, 3);
        replacement[0].id = [0x22; 32];
        let docs = case["notices"].as_array().unwrap();
        let updates: Vec<RegistryUpdate> = docs
            .iter()
            .map(|doc| {
                wist_core::envelope::verify_envelope(&doc["envelope"], "update", &key).unwrap();
                serde_json::from_value(doc["envelope"]["update"].clone()).unwrap()
            })
            .collect();
        let ids: Vec<_> = docs
            .iter()
            .map(|doc| wist_core::delta::delta_id(&doc["envelope"]["update"]).unwrap())
            .collect();
        let mut replay = Replay::new(SUBJECT);
        let mut accepted = Vec::new();
        for height in 0..=3 {
            let findings = if height == 0 {
                vec![ConfirmedFinding::new(&evidence, false).unwrap()]
            } else if height == 2 && current != activation {
                vec![ConfirmedFinding::new(&replacement, false).unwrap()]
            } else {
                vec![]
            };
            let selected: Vec<_> = docs
                .iter()
                .enumerate()
                .filter(|(_, d)| d["height"] == height)
                .map(|(i, _)| i)
                .collect();
            let candidates: Vec<_> = selected
                .iter()
                .map(|&i| NoticeCandidate {
                    id: &ids[i],
                    update: &updates[i],
                })
                .collect();
            let result = replay
                .apply_block(ReplayBlock {
                    findings: &findings,
                    notices: &candidates,
                    lift: height == 2 && current != activation,
                    ..block(height)
                })
                .unwrap();
            accepted.extend(result.accepted_notices.iter().map(|&i| selected[i] as u64));
            if case["label"] == "missing activation" && height == 1 {
                assert_eq!(result.rejected_notices.get(&0), Some(&"WIST4-E04"));
            }
        }
        assert_eq!(
            accepted,
            case["accepted_indices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap())
                .collect::<Vec<_>>(),
            "{}",
            case["label"]
        );
        replay.apply_block(block(30)).unwrap();
        assert_eq!(
            replay.ladder().active()[2].map(|a| name(a.record_id)),
            case["activation_after_reversal"]
                .as_str()
                .map(str::to_owned),
            "{}",
            case["label"]
        );
    }
}

fn evidence_record(value: &Value, finding: &Value) -> EvidenceRecord<'static> {
    EvidenceRecord {
        id: id(value["id"].as_str().unwrap()),
        record: CandidateRecord {
            block_height: value["block_height"].as_u64().unwrap(),
            entry_index: value["entry_index"].as_u64().unwrap(),
            block_sealed_at_s: value["sealed_at_s"].as_i64().unwrap(),
            auditor_id: match value["auditor_id"].as_str().unwrap() {
                "a.example.org" => "a.example.org",
                "b.example.org" => "b.example.org",
                "c.sample.net" => "c.sample.net",
                "d.other.io" => "d.other.io",
                other => panic!("{other}"),
            },
            effective_similarity: value["effective_similarity"].as_u64().unwrap(),
        },
        confirm_auditors: value["confirm_auditors"]
            .as_u64()
            .unwrap_or(finding["quorum"].as_u64().unwrap()),
        confirm_window_hours: value["confirm_window_hours"]
            .as_u64()
            .unwrap_or(finding["window_hours"].as_u64().unwrap()),
    }
}

#[test]
fn wist4_notice_evidence() {
    let v = read_json("vectors/wist4/sanctions.json");
    for case in v["notice_evidence_cases"].as_array().unwrap() {
        let blocks = case["blocks"].as_array().unwrap();
        let all_records: Vec<Vec<Vec<_>>> = blocks
            .iter()
            .map(|b| {
                b["findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        f["records"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| evidence_record(r, f))
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let n = &case["notice"];
        let notice = update(
            n["level"].as_u64().unwrap() as u8,
            id(n["activation"].as_str().unwrap()),
            n["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect(),
        );
        let mut replay = Replay::new(SUBJECT);
        for (b, records) in blocks.iter().zip(&all_records) {
            let height = b["height"].as_u64().unwrap();
            if height > n["height"].as_u64().unwrap() {
                break;
            }
            let findings: Vec<_> = records
                .iter()
                .zip(b["findings"].as_array().unwrap())
                .map(|(rs, f)| ConfirmedFinding::new(rs, f["link"].as_bool().unwrap()).unwrap())
                .collect();
            let candidates = if height == n["height"].as_u64().unwrap() {
                vec![NoticeCandidate {
                    id: "notice",
                    update: &notice,
                }]
            } else {
                vec![]
            };
            let result = replay
                .apply_block(ReplayBlock {
                    sealed_at_s: b["sealed_at_s"].as_i64().unwrap(),
                    lift: b["lift"].as_bool().unwrap(),
                    reset: b["reset"].as_bool().unwrap(),
                    findings: &findings,
                    notices: &candidates,
                    ..block(height)
                })
                .unwrap();
            if !candidates.is_empty() {
                assert_eq!(
                    result.rejected_notices.get(&0).copied(),
                    case["error"].as_str(),
                    "{}",
                    case["label"]
                );
                assert_eq!(
                    result.accepted_notices,
                    if case["error"].is_null() {
                        vec![0]
                    } else {
                        vec![]
                    },
                    "{}",
                    case["label"]
                );
            }
        }
    }
}

fn act(
    id: &'static str,
    notice: &'static str,
    height: u64,
    kind: ProcessKind,
) -> ProcessAct<'static> {
    ProcessAct {
        id,
        notice,
        subject: SUBJECT,
        height,
        sealed_at_s: height as i64 * DAY,
        kind,
        ruling_deadline_days: 30,
    }
}

#[test]
fn accepted_processes_apply_at_actual_blocks_before_new_findings() {
    let initial = records([1; 32], 0, 3);
    let rearming = records([3; 32], 22, 1);
    let first_notice = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let mut replay = Replay::new(SUBJECT);
    let findings = [ConfirmedFinding::new(&initial, false).unwrap()];
    replay
        .apply_block(ReplayBlock {
            findings: &findings,
            notices: &[NoticeCandidate {
                id: "n",
                update: &first_notice,
            }],
            ..block(0)
        })
        .unwrap();
    assert_eq!(replay.ladder().level(), 3);
    replay.apply_block(block(20)).unwrap();
    assert_eq!(replay.ladder().level(), 3);
    let findings = [ConfirmedFinding::new(&rearming, false).unwrap()];
    replay
        .apply_block(ReplayBlock {
            findings: &findings,
            ..block(22)
        })
        .unwrap();
    assert_eq!(
        replay.notices()[0].state.void_at_s,
        Some(i128::from(21 * DAY))
    );
    assert_eq!(replay.ladder().level(), 1);
    assert!(replay.ladder().active()[3].is_none());
}

#[test]
fn same_block_admission_and_appeal_reject_activation_block_ruling() {
    let initial = records([1; 32], 0, 3);
    let first_notice = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let findings = [ConfirmedFinding::new(&initial, false).unwrap()];
    let mut replay = Replay::new(SUBJECT);
    let result = replay
        .apply_block(ReplayBlock {
            findings: &findings,
            notices: &[NoticeCandidate {
                id: "n",
                update: &first_notice,
            }],
            acts: &[
                act("r0", "n", 0, ProcessKind::Ruling(Outcome::Overturned)),
                act("a", "n", 0, ProcessKind::Appeal),
            ],
            ..block(0)
        })
        .unwrap();
    assert_eq!(result.rejected_acts, vec![0]);
    assert_eq!(replay.ladder().level(), 3);
    assert_eq!(
        replay.notices()[0].state.retention_end_at_s,
        Some(i128::from(30 * DAY))
    );
    let result = replay
        .apply_block(ReplayBlock {
            acts: &[act("r1", "n", 1, ProcessKind::Ruling(Outcome::Overturned))],
            ..block(1)
        })
        .unwrap();
    assert!(result.rejected_acts.is_empty());
    assert_eq!(replay.ladder().level(), 1);
    assert_eq!(
        replay.notices()[0].state.retention_end_at_s,
        Some(i128::from(DAY))
    );
}

#[test]
fn invalid_notice_evidence_cannot_veto_an_eligible_candidate() {
    let initial = records([1; 32], 0, 3);
    let valid = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let invalid = update(3, [1; 32], vec![name([1; 32])]);
    let findings = [ConfirmedFinding::new(&initial, false).unwrap()];
    for reversed in [false, true] {
        let mut replay = Replay::new(SUBJECT);
        let mut notices = [
            NoticeCandidate {
                id: "bad",
                update: &invalid,
            },
            NoticeCandidate {
                id: "good",
                update: &valid,
            },
        ];
        if reversed {
            notices.reverse();
        }
        let result = replay
            .apply_block(ReplayBlock {
                findings: &findings,
                notices: &notices,
                ..block(0)
            })
            .unwrap();
        assert_eq!(result.accepted_notices, vec![usize::from(!reversed)]);
        assert_eq!(
            result.rejected_notices.get(&usize::from(reversed)),
            Some(&"WIST4-E05")
        );
        assert_eq!(replay.notices()[0].notice.id, "good");
    }
}

#[test]
fn rejected_pre_notice_acts_do_not_participate_when_resealed() {
    let initial = records([1; 32], 0, 3);
    let notice = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let findings = [ConfirmedFinding::new(&initial, false).unwrap()];
    let mut replay = Replay::new(SUBJECT);
    let result = replay
        .apply_block(ReplayBlock {
            findings: &findings,
            acts: &[act("a", "n", 0, ProcessKind::Appeal)],
            ..block(0)
        })
        .unwrap();
    assert_eq!(result.rejected_acts, vec![0]);
    replay
        .apply_block(ReplayBlock {
            notices: &[NoticeCandidate {
                id: "n",
                update: &notice,
            }],
            acts: &[act("a", "n", 1, ProcessKind::Appeal)],
            ..block(1)
        })
        .unwrap();
    assert_eq!(replay.notices()[0].state.appeal_index, None);
}

#[test]
fn timely_appeal_and_ruling_at_deadlines_preserve_the_rung() {
    let initial = records([1; 32], 0, 3);
    let notice = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let mut replay = Replay::new(SUBJECT);
    replay
        .apply_block(ReplayBlock {
            findings: &[ConfirmedFinding::new(&initial, false).unwrap()],
            notices: &[NoticeCandidate {
                id: "n",
                update: &notice,
            }],
            ..block(0)
        })
        .unwrap();
    replay
        .apply_block(ReplayBlock {
            acts: &[act("u", "n", 14, ProcessKind::Ruling(Outcome::Unappealed))],
            ..block(14)
        })
        .unwrap();
    assert_eq!(
        replay.notices()[0].state.retention_end_at_s,
        Some(i128::from(21 * DAY))
    );
    replay
        .apply_block(ReplayBlock {
            acts: &[act("a", "n", 21, ProcessKind::Appeal)],
            ..block(21)
        })
        .unwrap();
    assert_eq!(replay.ladder().level(), 3);
    assert_eq!(
        replay.notices()[0].state.retention_end_at_s,
        Some(i128::from(51 * DAY))
    );
    replay
        .apply_block(ReplayBlock {
            acts: &[act("r", "n", 51, ProcessKind::Ruling(Outcome::Upheld))],
            ..block(51)
        })
        .unwrap();
    assert_eq!(replay.ladder().level(), 3);
    let result = replay
        .apply_block(ReplayBlock {
            acts: &[act("r2", "n", 52, ProcessKind::Ruling(Outcome::Overturned))],
            ..block(52)
        })
        .unwrap();
    assert_eq!(result.rejected_acts, vec![0]);
    assert_eq!(replay.ladder().level(), 3);
}

#[test]
fn deadline_rearming_opens_a_distinct_process_and_ignores_old_voids() {
    let initial = records([1; 32], 0, 3);
    let rearming = records([3; 32], 22, 3);
    let first = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let second = update(3, [3; 32], vec![name([3; 32]), name([2; 32])]);
    let mut replay = Replay::new(SUBJECT);
    replay
        .apply_block(ReplayBlock {
            findings: &[ConfirmedFinding::new(&initial, false).unwrap()],
            notices: &[NoticeCandidate {
                id: "n0",
                update: &first,
            }],
            ..block(0)
        })
        .unwrap();
    replay
        .apply_block(ReplayBlock {
            findings: &[ConfirmedFinding::new(&rearming, false).unwrap()],
            notices: &[NoticeCandidate {
                id: "n1",
                update: &second,
            }],
            ..block(22)
        })
        .unwrap();
    assert_eq!(replay.notices().len(), 2);
    assert_eq!(replay.ladder().active()[2].unwrap().record_id, [3; 32]);
    assert!(replay.ladder().active()[3].is_none());
    replay.apply_block(block(23)).unwrap();
    assert_eq!(replay.ladder().active()[2].unwrap().record_id, [3; 32]);
    replay.apply_block(block(43)).unwrap();
    assert_eq!(replay.ladder().level(), 1);
}

#[test]
fn reset_clears_rungs_but_preserves_the_old_identity_process() {
    let initial = records([1; 32], 0, 3);
    let notice = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let mut replay = Replay::new(SUBJECT);
    replay
        .apply_block(ReplayBlock {
            findings: &[ConfirmedFinding::new(&initial, false).unwrap()],
            notices: &[NoticeCandidate {
                id: "n",
                update: &notice,
            }],
            ..block(0)
        })
        .unwrap();
    replay
        .apply_block(ReplayBlock {
            reset: true,
            acts: &[act("a", "n", 1, ProcessKind::Appeal)],
            ..block(1)
        })
        .unwrap();
    assert_eq!(replay.ladder().level(), 0);
    assert_eq!(replay.notices()[0].state.appeal_index, Some(0));
    assert_eq!(
        replay.notices()[0].state.retention_end_at_s,
        Some(i128::from(31 * DAY))
    );
    replay.apply_block(block(31)).unwrap();
    assert_eq!(
        replay.notices()[0].state.void_at_s,
        Some(i128::from(31 * DAY))
    );
    assert_eq!(replay.ladder().level(), 0);
}

#[test]
fn recovery_and_rejected_notices_open_no_process_for_same_block_acts() {
    let initial = records([1; 32], 0, 3);
    let mut recovery = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    recovery.details = Some(json!({"kind":"recovery"}));
    let valid = update(3, [1; 32], vec![name([1; 32]), name([2; 32])]);
    let mut competing = valid.clone();
    competing.details.as_mut().unwrap()["reason"] = json!("additional confirmed evidence");
    let mut replay = Replay::new(SUBJECT);
    let result = replay
        .apply_block(ReplayBlock {
            findings: &[ConfirmedFinding::new(&initial, false).unwrap()],
            notices: &[
                NoticeCandidate {
                    id: "r",
                    update: &recovery,
                },
                NoticeCandidate {
                    id: "n1",
                    update: &valid,
                },
                NoticeCandidate {
                    id: "n2",
                    update: &competing,
                },
            ],
            acts: &[
                act("a0", "r", 0, ProcessKind::Appeal),
                act("a1", "n1", 0, ProcessKind::Appeal),
            ],
            ..block(0)
        })
        .unwrap();
    assert_eq!(result.rejected_acts, vec![0, 1]);
    assert_eq!(
        result
            .rejected_notices
            .values()
            .copied()
            .collect::<Vec<_>>(),
        vec!["WIST4-E05", "WIST4-E05"]
    );
    assert!(replay.notices().is_empty());
    replay.apply_block(block(30)).unwrap();
    assert_eq!(replay.ladder().level(), 3);
}
