use super::read_json;
use serde_json::{json, Value};
use wist_core::canary::*;
use wist_core::crypto::{b64u_encode, hex_decode, hex_encode};
use wist_core::delta::{make_commitment_bytes, make_credit_commitment};
use wist_core::merkle;
use wist_core::verdict::{ChangeType, Verdict};

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}
fn number(value: &Value) -> u64 {
    value.as_u64().unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    hex_decode(text(value)).unwrap()
}
fn hash(value: &Value) -> [u8; 32] {
    hex_decode(text(value).strip_prefix("sha256:").unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn verdict(value: &Value) -> Verdict {
    match text(value) {
        "consistent" => Verdict::Consistent,
        "inconsistent" => Verdict::Inconsistent,
        "dynamic_variance" => Verdict::DynamicVariance,
        "not_auditable" => Verdict::NotAuditable,
        "unreachable" => Verdict::Unreachable,
        "link_variance" => Verdict::LinkVariance,
        "link_inconsistent" => Verdict::LinkInconsistent,
        other => panic!("unknown verdict {other}"),
    }
}
fn lookup(parameters: &Value, name: &str) -> u64 {
    parameters[name].as_u64().unwrap_or_else(|| {
        wist_core::parameters::spec(name)
            .unwrap()
            .default
            .unwrap()
            .try_into()
            .unwrap()
    })
}
fn row(counts: Counts) -> Value {
    json!([counts.encountered, counts.credited, counts.hard_hits])
}
fn board(value: Scoreboard) -> Value {
    json!({"provisional": row(value.provisional), "standing": row(value.standing), "mature": row(value.mature)})
}

#[test]
fn credit_leaf_proofs_and_derived_bands() {
    let v = read_json("vectors/wist4/canary.json");
    let payload = read_json("examples/payload.json");
    let salt = text(&payload["salt"]);
    let profile = ScoringProfile::at_audited_delta(0, |name, _| lookup(&v["parameters"], name));
    let leaves = v["leaves"].as_array().unwrap();
    let bodies: Vec<_> = leaves
        .iter()
        .map(|leaf| bytes(&leaf["served_bytes_hex"]))
        .collect();
    let root = hash(&v["commitment"]["root"]);
    for leaf in leaves {
        let index = number(&leaf["index"]) as usize;
        let body = &bodies[index];
        let digest = merkle::leaf_hash(body);
        assert_eq!(format!("sha256:{}", hex_encode(&digest)), leaf["leaf_hash"]);
        if !leaf["revealed"].as_bool().unwrap() {
            continue;
        }
        let path: Vec<_> = leaf["path"].as_array().unwrap().iter().map(hash).collect();
        merkle::verify_inclusion(
            &digest,
            index,
            number(&v["commitment"]["leaves"]) as usize,
            &path,
            &root,
        )
        .unwrap();
        let derived =
            profile.derived_similarity(body, text(&v["reference_extract"]), ChangeType::New);
        assert_eq!(json!(derived), leaf["derived_similarity"]);
        assert_eq!(profile.band(derived), verdict(&leaf["derived_verdict"]));
        let mirrored =
            profile.derived_similarity(body, text(&v["reference_extract"]), ChangeType::Delete);
        assert_eq!(mirrored, derived.map(|n| 1_000_000 - n));
        let mut surplus = path.clone();
        surplus.push([0; 32]);
        assert!(merkle::verify_inclusion(&digest, index, leaves.len(), &surplus, &root).is_err());
        assert!(merkle::verify_inclusion(
            &digest,
            index,
            leaves.len(),
            &path[..path.len() - 1],
            &root
        )
        .is_err());
        assert!(merkle::verify_inclusion(
            &merkle::leaf_hash(b"changed body"),
            index,
            leaves.len(),
            &path,
            &root
        )
        .is_err());
    }
    for case in v["credit_cases"].as_array().unwrap() {
        let index = number(&case["leaf_index"]) as usize;
        let other_salt = b64u_encode(&bytes(&v["alternate_inputs"]["other_salt_hex"]));
        let key = if case["salt"] == "reference" {
            salt
        } else {
            &other_salt
        };
        let held = match case["held"].as_str() {
            Some("leaf") => Some(bodies[index].clone()),
            Some("payload_page") => Some(bytes(&v["payload_page_hex"])),
            Some("other_nonce") => Some(bytes(&v["alternate_inputs"]["other_nonce_body_hex"])),
            None => None,
            other => panic!("unknown held bytes {other:?}"),
        };
        let credit = held.as_ref().map(|body| {
            make_credit_commitment(
                key,
                body,
                case["copied_from"]
                    .as_str()
                    .unwrap_or(text(&case["auditor_id"])),
            )
            .unwrap()
        });
        assert_eq!(
            json!(credit),
            case["credit_commitment"],
            "{}",
            case["label"]
        );
        assert_eq!(
            json!(held
                .as_ref()
                .map(|body| make_commitment_bytes(key, body).unwrap())),
            case["response_commitment"]
        );
        let reproduces = credit.as_deref()
            == Some(
                make_credit_commitment(salt, &bodies[index], text(&case["auditor_id"]))
                    .unwrap()
                    .as_str(),
            );
        assert_eq!(reproduces, case["reproduces"].as_bool().unwrap());
        let derived = profile.derived_similarity(
            &bodies[index],
            text(&v["reference_extract"]),
            ChangeType::New,
        );
        assert_eq!(
            profile.hard_hit(reproduces, verdict(&case["verdict"]), derived),
            case["hard_hit"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn numeric_reveal_delay_and_scoring_window() {
    let v = read_json("vectors/wist4/canary.json");
    let p = &v["parameters"];
    for case in v["timing_cases"].as_array().unwrap() {
        let result = numeric_timing(
            CommitmentTiming {
                height: number(&case["commitment_height"]),
                lead_blocks: number(&p["canary_lead_blocks"]),
                lifetime_blocks: number(&p["canary_lifetime_blocks"]),
            },
            &case["delta_heights"]
                .as_array()
                .unwrap()
                .iter()
                .map(number)
                .collect::<Vec<_>>(),
            RevealDelay {
                minimum_blocks: number(&p["canary_reveal_min_blocks"]),
                suffixes_registered: number(&case["suffixes_registered"]),
                checkpoint_budget: number(&p["observer_checkpoint_budget"]).try_into().unwrap(),
                epoch_blocks: number(&p["epoch_blocks"]).try_into().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            result.earliest,
            u128::from(number(&case["earliest_reveal_height"]))
        );
        assert_eq!(
            result.latest,
            u128::from(number(&case["latest_reveal_height"]))
        );
        assert_eq!(
            result.lead_respected,
            case["lead_respected"].as_bool().unwrap()
        );
        assert_eq!(
            result.allows(number(&case["reveal_height"])),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["label"]
        );
    }
    for case in v["scoring_window_cases"].as_array().unwrap() {
        assert_eq!(
            scoring_window_open(
                case["reveal_sealed_at_s"].as_i64().unwrap(),
                case["n_sealed_at_s"].as_i64().unwrap(),
                number(&case["payload_window_days"])
            ),
            case["open"].as_bool().unwrap()
        );
    }
}

#[test]
fn scoring_profile_anchors_all_four_parameters_at_the_audited_delta() {
    let v = read_json("vectors/wist4/canary.json")["scoring_profile"].clone();
    for case in v["cases"].as_array().unwrap() {
        let change = &case["change"];
        let lookup = |name: &str, time: i64| {
            if name == text(&change["parameter"])
                && time >= change["effective_at_s"].as_i64().unwrap()
            {
                number(&change["value"])
            } else {
                number(&v["defaults"][name])
            }
        };
        let body = bytes(&case["served_bytes_hex"]);
        let salt = b64u_encode(&[7; 16]);
        let credit = make_credit_commitment(&salt, &body, "audit.example.net").unwrap();
        let leaf = RevealedLeaf {
            delta_id: "reference",
            body: &body,
            leaf_hash: merkle::leaf_hash(&body),
            reference_extract: text(&case["reference_extract"]),
            salt_b64u: &salt,
            tier: Tier::Standing,
            reveal_height: 1000,
            reveal_sealed_at_s: case["reveal_sealed_at_s"].as_i64().unwrap(),
            payload_window_days: 180,
        };
        let record = ScoringRecord {
            id: "record",
            auditor_id: "audit.example.net",
            reference_delta: "reference",
            fixed_height: Some(999),
            audited_sealed_at_s: case["audited_delta_sealed_at_s"].as_i64().unwrap(),
            change: ChangeType::New,
            verdict: verdict(&case["verdict"]),
            credit_commitment: case["credit_reproduces"]
                .as_bool()
                .unwrap()
                .then_some(credit.as_str()),
        };
        for query in case["queries_s"].as_array().unwrap() {
            let profile = ScoringProfile::at_audited_delta(
                case["audited_delta_sealed_at_s"].as_i64().unwrap(),
                lookup,
            );
            assert_eq!(
                json!({"shingle_size":profile.shingle_size, "min_observed_words":profile.min_observed_words,
                "similarity_consistent":profile.similarity_consistent, "similarity_variance_floor":profile.similarity_variance_floor}),
                case["expected"]["profile"]
            );
            let derived = profile.derived_similarity(
                &bytes(&case["served_bytes_hex"]),
                text(&case["reference_extract"]),
                ChangeType::New,
            );
            assert_eq!(
                json!(derived),
                case["expected"]["derived_similarity"],
                "{}",
                case["label"]
            );
            assert_eq!(
                profile.hard_hit(
                    case["credit_reproduces"].as_bool().unwrap(),
                    verdict(&case["verdict"]),
                    derived
                ),
                case["expected"]["hard_hit"].as_bool().unwrap()
            );
            let result = scoreboard(
                "audit.example.net",
                1001,
                query.as_i64().unwrap(),
                std::slice::from_ref(&leaf),
                std::slice::from_ref(&record),
                lookup,
            )
            .unwrap();
            assert_eq!(result.standing.encountered, 1);
            assert_eq!(
                result.standing.credited,
                u64::from(case["credit_reproduces"].as_bool().unwrap())
            );
            assert_eq!(
                result.standing.hard_hits,
                u64::from(case["expected"]["hard_hit"].as_bool().unwrap())
            );
        }
    }
}

#[test]
fn scoreboards_count_unique_records_per_tier() {
    let v = read_json("vectors/wist4/canary.json");
    let payload = read_json("examples/payload.json");
    let raw_leaves = v["leaves"].as_array().unwrap();
    let bodies: Vec<_> = raw_leaves
        .iter()
        .map(|leaf| bytes(&leaf["served_bytes_hex"]))
        .collect();
    let leaves: Vec<_> = raw_leaves
        .iter()
        .filter(|leaf| leaf["revealed"] == true)
        .map(|leaf| {
            let leaf_tier = tier(
                leaf["domain_provisional"].as_bool().unwrap(),
                number(&leaf["domain_reputation_u"]),
                number(&v["parameters"]["latency_threshold_u"]),
            );
            assert_eq!(
                match leaf_tier {
                    Tier::Provisional => "provisional",
                    Tier::Standing => "standing",
                    Tier::Mature => "mature",
                },
                leaf["tier"]
            );
            RevealedLeaf {
                delta_id: text(&leaf["delta_id"]),
                body: &bodies[number(&leaf["index"]) as usize],
                leaf_hash: hash(&leaf["leaf_hash"]),
                reference_extract: text(&v["reference_extract"]),
                salt_b64u: text(&payload["salt"]),
                tier: leaf_tier,
                reveal_height: 1000,
                reveal_sealed_at_s: 3600000,
                payload_window_days: number(&v["parameters"]["payload_window_days"]),
            }
        })
        .collect();
    let raw_records = v["scoreboard_records"].as_array().unwrap();
    let ids: Vec<_> = (0..raw_records.len())
        .map(|i| format!("record-{i}"))
        .collect();
    let records: Vec<_> = v["binding"]["record_occurrences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|index| {
            let i = number(index) as usize;
            let record = &raw_records[i];
            ScoringRecord {
                id: &ids[i],
                auditor_id: text(&record["auditor_id"]),
                reference_delta: text(
                    &raw_leaves[number(&record["leaf_index"]) as usize]["delta_id"],
                ),
                fixed_height: Some(if record["fixed_before_reveal"] == true {
                    999
                } else {
                    1000
                }),
                audited_sealed_at_s: 0,
                change: ChangeType::New,
                verdict: verdict(&record["verdict"]),
                credit_commitment: record["credit_commitment"].as_str(),
            }
        })
        .collect();
    let lookup = |name: &str, _: i64| lookup(&v["parameters"], name);
    for (id, expected) in v["scoreboards"].as_object().unwrap() {
        assert_eq!(
            board(scoreboard(id, 1000, 3600000, &leaves, &records, lookup).unwrap()),
            *expected
        );
        assert_eq!(*expected, v["binding"]["scoreboards"][id]);
        let mut reversed = records.clone();
        reversed.reverse();
        assert_eq!(
            board(scoreboard(id, 1000, 3600000, &leaves, &reversed, lookup).unwrap()),
            *expected
        );
        assert_eq!(
            scoreboard(id, 999, 3600000, &leaves, &records, lookup).unwrap(),
            Scoreboard::default()
        );
        assert_eq!(
            scoreboard(id, 1000, 3600000 + 180 * 86400, &leaves, &records, lookup).unwrap(),
            Scoreboard::default()
        );
    }
    let mut altered = leaves.clone();
    altered[0].body = b"altered";
    assert!(scoreboard(
        "audit.example.net",
        1000,
        3600000,
        &altered,
        &records,
        lookup
    )
    .is_err());
}
