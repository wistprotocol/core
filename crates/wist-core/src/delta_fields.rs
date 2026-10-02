//! WIST-1 §7: complete field validation under `delta.schema.json` precedes any semantic
//! rejection.
use crate::envelope::{canonical_b64u, validate_version, version_spelled};
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

pub fn validate_delta_version(doc: &Value) -> Result<(), &'static str> {
    validate_fields(doc)?;
    validate_version(doc["delta"]["wist_version"].as_str().unwrap())
}

pub fn validate_content_and_prev(doc: &Value) -> Result<(), &'static str> {
    validate_delta_version(doc)?;
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

/// WIST-1 §3.6 commitment cap and §3.2 URL cap, the latter in JCS octets.
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

/// WIST-1 §3.6, in octets.
pub fn commitment_cap(extract_cap: i64, links_cap: i64, summary_cap: i64) -> i128 {
    32 + i128::from(extract_cap) + i128::from(links_cap) + i128::from(summary_cap)
}

/// WIST-1 §3.4: for a sealed Delta, `clock_s` is its committing Epoch's `sealed_at` and
/// `allowance_s` the `clock_skew_seconds` in force then, both in seconds.
pub fn verify_clock(doc: &Value, clock_s: i64, allowance_s: i64) -> Result<(), &'static str> {
    let observed_at = doc["delta"]["observed_at"].as_str().ok_or("WIST1-E14")?;
    match publisher_time::within_clock_bound(observed_at, clock_s, allowance_s) {
        Some(true) => Ok(()),
        Some(false) => Err("WIST1-E06"),
        None => Err("WIST1-E14"),
    }
}

/// WIST-1 §3.4: `observed_at` strictly after the predecessor's.
pub fn verify_observation_order(
    observed_at: &str,
    predecessor_observed_at: &str,
) -> Result<(), &'static str> {
    match publisher_time::compare(observed_at, predecessor_observed_at) {
        Some(std::cmp::Ordering::Greater) => Ok(()),
        _ => Err("WIST1-E07"),
    }
}
