//! WIST-1 §7's Delta diagnostics: complete field validation under
//! `delta.schema.json` before any semantic rejection, version eligibility
//! (§3.1, ADR-0030), the stage-independent static checks, and the §3.4
//! clock check. Each function returns the WIST-1 §7 error code it selects.
use crate::crypto::{b64u_decode, b64u_encode};
use crate::publisher_time;
use serde_json::Value;

fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, &'static str> {
    let map = value.as_object().ok_or("WIST1-E14")?;
    if required.iter().any(|key| !map.contains_key(*key))
        || map
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("WIST1-E14");
    }
    Ok(map)
}

fn string(value: &Value) -> Result<&str, &'static str> {
    value.as_str().ok_or("WIST1-E14")
}

fn hash(value: &Value, prefix: &str) -> bool {
    value
        .as_str()
        .and_then(|s| s.strip_prefix(prefix))
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Whether `value` is the canonical base64url spelling of `length` octets.
pub fn canonical_b64u(value: &str, length: usize) -> bool {
    b64u_decode(value).is_ok_and(|bytes| bytes.len() == length && b64u_encode(&bytes) == value)
}

/// Whether `version` is three dot-separated decimal components without
/// leading zeros, prerelease or build suffix (§3.1).
pub fn version_spelled(version: &str) -> bool {
    version.split('.').count() == 3
        && version.split('.').all(|part| {
            !part.is_empty()
                && !(part.len() > 1 && part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Complete field validation of a Delta Envelope: `WIST1-E05` for
/// non-canonicalizable input, `WIST1-E14` for any structural failure.
pub fn validate_fields(doc: &Value) -> Result<(), &'static str> {
    crate::jcs::canonicalize(doc).map_err(|_| "WIST1-E05")?;
    object(doc, &["delta", "sig"], &[])?;
    let body = &doc["delta"];
    object(
        body,
        &[
            "wist_version",
            "publisher",
            "url",
            "change_type",
            "observed_at",
            "meta",
        ],
        &["prev", "payload"],
    )?;
    if !version_spelled(string(&body["wist_version"])?) {
        return Err("WIST1-E14");
    }
    crate::delta::publisher(body).map_err(|_| "WIST1-E14")?;
    string(&body["url"])?;
    if !publisher_time::valid(string(&body["observed_at"])?) {
        return Err("WIST1-E14");
    }
    let kind = string(&body["change_type"])?;
    if !["new", "update", "delete", "attest"].contains(&kind)
        || body.get("prev").is_some_and(|v| !hash(v, "sha256:"))
    {
        return Err("WIST1-E14");
    }
    if let Some(payload) = body.get("payload") {
        object(payload, &["commitment", "alg", "bytes"], &[])?;
        if !["new", "update"].contains(&kind)
            || !hash(&payload["commitment"], "hmac-sha256:")
            || payload["alg"] != "HMAC-SHA256"
            || !payload["bytes"].as_f64().is_some_and(|n| {
                n.is_finite() && (0.0..=9_007_199_254_740_991.0).contains(&n) && n.fract() == 0.0
            })
        {
            return Err("WIST1-E14");
        }
    }
    let meta = &body["meta"];
    object(meta, &["lang"], &["topics", "license"])?;
    let mut parts = string(&meta["lang"])?.split('-');
    let primary = parts.next().unwrap_or_default();
    if !(2..=3).contains(&primary.len())
        || !primary.bytes().all(|b| b.is_ascii_lowercase())
        || parts.any(|part| {
            !(1..=8).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
    {
        return Err("WIST1-E14");
    }
    if let Some(topics) = meta.get("topics") {
        let topics = topics.as_array().ok_or("WIST1-E14")?;
        if topics.len() > 10
            || topics
                .iter()
                .any(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 64))
        {
            return Err("WIST1-E14");
        }
    }
    if meta
        .get("license")
        .is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 64))
    {
        return Err("WIST1-E14");
    }
    let sig = &doc["sig"];
    object(sig, &["key_id", "alg", "value"], &[])?;
    if string(&sig["key_id"])?.chars().count() > 64 || sig["alg"] != "Ed25519" {
        return Err("WIST1-E14");
    }
    if !canonical_b64u(string(&sig["value"])?, 64) {
        return Err("WIST1-E14");
    }
    Ok(())
}

/// Field validation followed by §3.1 major support: a validator of this
/// revision implements wire major `1` only (`WIST1-E15` otherwise).
pub fn validate_version(doc: &Value) -> Result<(), &'static str> {
    validate_fields(doc)?;
    if doc["delta"]["wist_version"]
        .as_str()
        .unwrap()
        .split('.')
        .next()
        != Some("1")
    {
        return Err("WIST1-E15");
    }
    Ok(())
}

/// Version validation plus the presence rules: `payload` on `new` and
/// `update` (`WIST1-E09`), `prev` on everything but `new` (`WIST1-E07`).
pub fn validate_content_and_prev(doc: &Value) -> Result<(), &'static str> {
    validate_version(doc)?;
    let body = &doc["delta"];
    if body.get("payload").is_none()
        && matches!(body["change_type"].as_str(), Some("new" | "update"))
    {
        return Err("WIST1-E09");
    }
    if body["change_type"] != "new" && body.get("prev").is_none() {
        return Err("WIST1-E07");
    }
    Ok(())
}

/// The stage-independent checks under a parameter profile: the §3.6
/// derived commitment cap (`WIST1-E04`) and the §3.2 JCS-octet URL cap
/// (`WIST1-E11`), after `validate_content_and_prev`.
pub fn validate_static(
    doc: &Value,
    url_cap: i64,
    commitment_cap: i128,
) -> Result<(), &'static str> {
    validate_content_and_prev(doc)?;
    let body = &doc["delta"];
    if let Some(payload) = body.get("payload") {
        if payload["bytes"].as_f64().unwrap() as i128 > commitment_cap {
            return Err("WIST1-E04");
        }
    }
    if crate::jcs::canonicalize(&body["url"])
        .map_err(|_| "WIST1-E05")?
        .len() as i128
        > i128::from(url_cap)
    {
        return Err("WIST1-E11");
    }
    Ok(())
}

/// §3.6's derived commitment cap: 32 salt octets plus the extract, links
/// and summary caps in force.
pub fn commitment_cap(extract_cap: i64, links_cap: i64, summary_cap: i64) -> i128 {
    32 + i128::from(extract_cap) + i128::from(links_cap) + i128::from(summary_cap)
}

/// §3.4's clock check against a whole-second clock: a sealed Delta uses its
/// committing Epoch's `sealed_at` and the `clock_skew_seconds` accepted at
/// that instant (`WIST1-E06`; a malformed `observed_at` is `WIST1-E14`).
pub fn verify_clock(doc: &Value, clock_s: i64, allowance_s: i64) -> Result<(), &'static str> {
    let observed_at = doc["delta"]["observed_at"].as_str().ok_or("WIST1-E14")?;
    match publisher_time::within_clock_bound(observed_at, clock_s, allowance_s) {
        Some(true) => Ok(()),
        Some(false) => Err("WIST1-E06"),
        None => Err("WIST1-E14"),
    }
}

/// §3.4's predecessor order: `observed_at` strictly after the predecessor's.
pub fn verify_observation_order(
    observed_at: &str,
    predecessor_observed_at: &str,
) -> Result<(), &'static str> {
    match publisher_time::compare(observed_at, predecessor_observed_at) {
        Some(std::cmp::Ordering::Greater) => Ok(()),
        _ => Err("WIST1-E07"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn spec_dir() -> PathBuf {
        std::env::var_os("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
    }

    #[test]
    fn signed_field_vectors_select_the_documented_diagnostics() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist1/delta-fields.json")).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let doc = &case["envelope"];
            let before = doc.clone();
            let allowed: BTreeSet<&str> = case["allowed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            let field = validate_fields(doc);
            assert_eq!(
                field.is_err(),
                allowed.contains("WIST1-E14"),
                "{}: {field:?}",
                case["name"]
            );
            let version = validate_version(doc);
            assert_eq!(
                version,
                if allowed.contains("WIST1-E14") {
                    Err("WIST1-E14")
                } else if allowed.contains("WIST1-E15") {
                    Err("WIST1-E15")
                } else {
                    Ok(())
                },
                "{}",
                case["name"]
            );
            let static_check = validate_static(
                doc,
                case["url_cap_bytes"].as_i64().unwrap_or(2048),
                i128::from(case["commitment_cap_bytes"].as_i64().unwrap_or(38944)),
            );
            if let Err(code) = static_check {
                assert!(allowed.contains(code), "{}: {code}", case["name"]);
            }
            assert_eq!(*doc, before);
        }
        for case in vector["version_cases"].as_array().into_iter().flatten() {
            assert_eq!(
                validate_version(&case["envelope"])
                    .err()
                    .unwrap_or("accepted"),
                case["expected"],
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn version_cases_reject_unsupported_majors_after_field_checks() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist1/delta-attribution.json")).unwrap(),
        )
        .unwrap();
        for case in vector["version_cases"].as_array().unwrap() {
            assert_eq!(
                validate_version(&case["envelope"])
                    .err()
                    .unwrap_or("accepted"),
                case["expected"],
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn historical_clock_probes_use_the_sealing_instant_and_its_allowance() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist1/delta-clock-time.json")).unwrap(),
        )
        .unwrap();
        for probe in vector["probes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["stage"] == "historical")
        {
            let clock_s =
                crate::timestamp::log_seconds(probe["sealed_at"].as_str().unwrap()).unwrap();
            assert_eq!(probe["sealed_at"], probe["expected_clock"]);
            let allowance = probe["expected_allowance"].as_i64().unwrap();
            assert_eq!(
                serde_json::json!(verify_clock(&probe["envelope"], clock_s, allowance).err()),
                probe["expected"],
                "{}",
                probe["name"]
            );
        }
    }
}
