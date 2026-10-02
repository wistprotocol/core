use crate::crypto::PublicKey;
use crate::delta_fields;
use crate::envelope::{canonical_b64u, verify_envelope, version_spelled};
use crate::objects::publisher::{key_set_fingerprint, thumbprint, NUMERIC_DATE_MAX};
use crate::objects::{Publisher, PublisherEnvelope, PublisherKey};
use crate::publisher_time;
use serde_json::Value;
use sha2::Digest;

pub type Rejection = (&'static str, String);

/// WIST-1 §3.5 and §3.4: a Delta's predecessor is the Delta its `prev`
/// names, by the same Publisher for the same URL, observed strictly earlier.
pub fn verify_delta_predecessor(doc: &Value, predecessor: &Value) -> Result<(), &'static str> {
    let publisher = delta_publisher(doc)?;
    let prior = &predecessor["delta"];
    let prior_id = crate::delta::delta_id(prior).map_err(|_| "WIST1-E07")?;
    if delta_publisher(predecessor) != Ok(publisher)
        || doc["delta"]["url"].as_str().is_none()
        || doc["delta"]["url"] != prior["url"]
        || Some(prior_id.as_str()) != doc["delta"]["prev"].as_str()
    {
        return Err("WIST1-E07");
    }
    delta_fields::verify_observation_order(
        doc["delta"]["observed_at"].as_str().unwrap(),
        prior["observed_at"].as_str().unwrap(),
    )
}

/// WIST-1 §3.1: major `1` alone is implemented; a differing minor or patch never rejects
/// (`WIST1-E15`).
pub fn validate_fields(doc: &Value) -> Result<PublisherEnvelope, Rejection> {
    let canonical = crate::jcs::canonicalize(doc).map_err(|e| ("WIST1-E05", e.to_string()))?;
    let envelope: PublisherEnvelope =
        serde_json::from_slice(&canonical).map_err(|e| ("WIST1-E14", e.to_string()))?;
    validate_structure(doc, &envelope).map_err(|e| ("WIST1-E14", e))?;
    if envelope.publisher.wist_version.split('.').next() != Some("1") {
        return Err((
            "WIST1-E15",
            format!(
                "wist_version {} is a major version this revision does not implement",
                envelope.publisher.wist_version
            ),
        ));
    }
    for key in envelope
        .publisher
        .keys
        .iter()
        .chain(envelope.publisher.recovery_keys.iter().flatten())
    {
        if !canonical_b64u(&key.x, 32) {
            return Err((
                "WIST1-E14",
                "x: expected canonical base64url encoding of 32 octets".into(),
            ));
        }
        if key.kid != thumbprint(&key.x) {
            return Err(("WIST1-E14", "kid is not the entry's JWK thumbprint".into()));
        }
    }
    if !canonical_b64u(&envelope.sig.value, 64) {
        return Err((
            "WIST1-E14",
            "sig.value: expected canonical base64url encoding of 64 octets".into(),
        ));
    }
    Ok(envelope)
}

fn validate_structure(doc: &Value, envelope: &PublisherEnvelope) -> Result<(), String> {
    let publisher = &envelope.publisher;
    for field in [
        "prev_declaration",
        "subdomain_scope",
        "recovery_keys",
        "next_keys",
        "contact",
    ] {
        if doc["publisher"].get(field).is_some_and(Value::is_null) {
            return Err(format!("{field} must not be null"));
        }
    }
    if publisher.seq > 9_007_199_254_740_991 {
        return Err("seq exceeds the safe integer range".into());
    }
    if !version_spelled(&publisher.wist_version) {
        return Err("wist_version must contain three decimal components".into());
    }
    let sha256_shaped = |hash: &String| {
        hash.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    if publisher
        .prev_declaration
        .as_ref()
        .is_some_and(|hash| !sha256_shaped(hash))
    {
        return Err("prev_declaration must be a lowercase SHA-256 hash".into());
    }
    if publisher
        .next_keys
        .as_ref()
        .is_some_and(|hash| !sha256_shaped(hash))
    {
        return Err("next_keys must be a lowercase SHA-256 fingerprint".into());
    }
    for host in std::iter::once(&publisher.domain).chain(publisher.subdomain_scope.iter().flatten())
    {
        if !crate::host::canonical_host(host).is_ok_and(|canonical| canonical == *host) {
            return Err("Declaration hosts must equal their Canonical Host".into());
        }
    }
    if publisher
        .contact
        .as_ref()
        .is_some_and(|value| value.chars().count() > 256)
    {
        return Err("contact exceeds 256 characters".into());
    }
    if publisher.keys.is_empty() {
        return Err("keys must not be empty".into());
    }
    for (index, key) in publisher
        .keys
        .iter()
        .chain(publisher.recovery_keys.iter().flatten())
        .enumerate()
    {
        let signed = if index < publisher.keys.len() {
            &doc["publisher"]["keys"][index]
        } else {
            &doc["publisher"]["recovery_keys"][index - publisher.keys.len()]
        };
        if key.kty != "OKP" || key.crv != "Ed25519" {
            return Err("key entries must be Ed25519 OKP JSON Web Keys".into());
        }
        if signed.get("exp").is_some_and(Value::is_null) {
            return Err("exp must not be null".into());
        }
        if key.nbf > NUMERIC_DATE_MAX || key.exp.is_some_and(|exp| exp > NUMERIC_DATE_MAX) {
            return Err("nbf and exp must not exceed 253402300799".into());
        }
        if key.exp.is_some_and(|exp| exp <= key.nbf) {
            return Err("exp must be greater than nbf".into());
        }
    }
    if envelope.sig.key_id.chars().count() > 64 || envelope.sig.alg != "Ed25519" {
        return Err("signature key_id exceeds 64 characters or alg is not Ed25519".into());
    }
    Ok(())
}

/// ADR-0023: only a canonical, non-small-order Ed25519 point is a signer candidate; other signed
/// entries are retained.
pub fn usable_keys(keys: &[PublisherKey]) -> impl Iterator<Item = &PublisherKey> {
    keys.iter()
        .filter(|key| PublicKey::from_b64u(&key.x).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Unchanged,
    Ordinary,
    Recovery,
    FreshIdentity,
}

pub fn inner_hash(doc: &Value) -> Result<String, String> {
    let canonical = crate::jcs::canonicalize(&doc["publisher"]).map_err(|e| e.to_string())?;
    Ok(format!(
        "sha256:{}",
        crate::crypto::hex_encode(&sha2::Sha256::digest(&canonical))
    ))
}

pub fn publisher_of(doc: &Value) -> Result<Publisher, String> {
    validate_fields(doc)
        .map(|envelope| envelope.publisher)
        .map_err(|(code, detail)| format!("{code}: {detail}"))
}

fn recovery_keys_bytes(p: &Publisher) -> Result<Vec<u8>, String> {
    match &p.recovery_keys {
        Some(keys) if !keys.is_empty() => {
            let v = serde_json::to_value(keys).map_err(|e| e.to_string())?;
            crate::jcs::canonicalize(&v).map_err(|e| e.to_string())
        }
        _ => Ok(Vec::new()),
    }
}

/// WIST-1 §5.2 and ADR-0023: every public key occurs once across `keys`
/// and `recovery_keys`, identical duplicates included.
pub fn disjoint_key_sets(p: &Publisher) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for key in p.keys.iter().chain(p.recovery_keys.iter().flatten()) {
        if !seen.insert(&key.x) {
            return Err(format!("key {} listed twice in Declaration", key.kid));
        }
    }
    Ok(())
}

fn verify_with(doc: &Value, key: &PublisherKey) -> bool {
    (doc["sig"]["alg"] == "Ed25519")
        .then(|| PublicKey::from_b64u(&key.x).ok())
        .flatten()
        .is_some_and(|public| verify_envelope(doc, "publisher", &public).is_ok())
}

pub fn evaluate_initial(doc: &Value) -> Result<Publisher, Rejection> {
    let envelope = validate_fields(doc)?;
    let publisher = envelope.publisher;
    disjoint_key_sets(&publisher).map_err(|e| ("WIST1-E08", e))?;
    if publisher.seq != 0 || publisher.prev_declaration.is_some() {
        return Err((
            "WIST1-E08",
            "first Declaration must start at seq 0 without a predecessor".into(),
        ));
    }
    resolve_signer(doc, &publisher, None)?;
    Ok(publisher)
}

/// ADR-0023: candidates are the usable previous signing and recovery bindings and the usable
/// incoming signing bindings.
pub fn resolve_signer<'a>(
    doc: &Value,
    incoming: &'a Publisher,
    previous: Option<&'a Publisher>,
) -> Result<&'a PublisherKey, Rejection> {
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let candidates: Vec<_> = previous
        .into_iter()
        .flat_map(|p| {
            usable_keys(&p.keys).chain(usable_keys(p.recovery_keys.as_deref().unwrap_or(&[])))
        })
        .chain(usable_keys(&incoming.keys))
        .filter(|key| key.kid == key_id)
        .collect();
    if candidates.is_empty() {
        return Err((
            "WIST1-E02",
            format!("sig.key_id {key_id} matches no known key"),
        ));
    }
    candidates
        .into_iter()
        .find(|key| verify_with(doc, key))
        .ok_or((
            "WIST1-E01",
            "declaration signature verification failed".into(),
        ))
}

pub fn delta_publisher(doc: &Value) -> Result<&str, &'static str> {
    delta_fields::validate_fields(doc)?;
    Ok(doc["delta"]["publisher"].as_str().unwrap())
}

/// WIST-1 §§3.2/5.2 and ADR-0023: a usable signing binding valid at `observed_at` verifies the
/// Delta, and its source's authority covers the URL.
pub fn verify_delta_authority(sources: &[&Publisher], doc: &Value) -> Result<(), &'static str> {
    let domain = delta_publisher(doc)?;
    let sources: Vec<_> = sources
        .iter()
        .filter(|source| source.domain == domain)
        .collect();
    let keys: Vec<_> = sources.iter().flat_map(|source| &source.keys).collect();
    let observed_at = doc["delta"]["observed_at"].as_str();
    verify_signed(&keys, doc, "delta", observed_at)?;
    let url = doc["delta"]["url"].as_str().ok_or("WIST1-E03")?;
    for source in sources {
        if url_in_scope(
            url,
            &source.domain,
            source.subdomain_scope.as_deref().unwrap_or(&[]),
        ) && verify_signed(
            &source.keys.iter().collect::<Vec<_>>(),
            doc,
            "delta",
            observed_at,
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    Err("WIST1-E03")
}

pub fn url_in_scope(url: &str, domain: &str, scope: &[String]) -> bool {
    if crate::extract::normalize_url(url, url).as_deref() != Some(url) {
        return false;
    }
    let host = url_host(url);
    host == domain || scope.iter().any(|declared| declared == host)
}

pub fn url_host(url: &str) -> &str {
    url.strip_prefix("https://")
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or_default()
}

/// WIST-1 §5.1/§5.2: `observed_at` is `None` for Feeds, which no `nbf`/`exp` window bounds.
pub fn verify_signed(
    keys: &[&PublisherKey],
    doc: &Value,
    kind: &str,
    observed_at: Option<&str>,
) -> Result<(), &'static str> {
    if kind == "delta" {
        delta_fields::validate_delta_version(doc)?;
    }
    if observed_at.is_some_and(|value| !publisher_time::valid(value)) {
        return Err("WIST1-E14");
    }
    if !canonical_b64u(doc["sig"]["value"].as_str().ok_or("WIST1-E14")?, 64) {
        return Err("WIST1-E14");
    }
    for key in keys {
        if !canonical_b64u(&key.x, 32) || key.kid != thumbprint(&key.x) {
            return Err("WIST1-E14");
        }
    }
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let mut eligible = false;
    for key in keys.iter().filter(|key| key.kid == key_id) {
        let Ok(public) = PublicKey::from_b64u(&key.x) else {
            continue;
        };
        if observed_at.is_some_and(|at| key.admits(at) != Some(true)) {
            continue;
        }
        eligible = true;
        if verify_envelope(doc, kind, &public).is_ok() {
            return Ok(());
        }
    }
    if eligible {
        Err("WIST1-E01")
    } else {
        Err("WIST1-E02")
    }
}

/// WIST-1 §5.2: an open recovery window's chain head or a pending head is an alternative
/// predecessor; every replacement must exceed the accepted sequence floor.
pub fn evaluate_with_heads(
    current: &Value,
    recovery_head: Option<&Value>,
    pending_head: Option<&Value>,
    highest_accepted_seq: u64,
    fetched: &Value,
) -> Result<Decision, Rejection> {
    let incoming = validate_fields(fetched)?.publisher;
    if incoming.domain != current["publisher"]["domain"] {
        return Err(("WIST2-E04", "declaration domain changed".into()));
    }
    let fetched_hash = inner_hash(fetched).map_err(|e| ("WIST2-E04", e))?;
    if inner_hash(current).map_err(|e| ("WIST2-E04", e))? == fetched_hash {
        return Ok(Decision::Unchanged);
    }
    // WIST-1 §5.2: the pending head is re-fetched throughout the activation delay, so its
    // re-serve installs nothing rather than reading as a superseded replay.
    if pending_head.is_some_and(|head| inner_hash(head).ok().as_deref() == Some(&fetched_hash)) {
        return Ok(Decision::Unchanged);
    }
    if incoming.seq <= highest_accepted_seq {
        return Err((
            "WIST1-E08",
            "Declaration sequence does not exceed the accepted floor".into(),
        ));
    }
    let previous = std::iter::once(current)
        .chain(recovery_head)
        .chain(pending_head)
        .find(|head| inner_hash(head).ok().as_deref() == incoming.prev_declaration.as_deref())
        .ok_or(("WIST1-E08", "ineligible Declaration predecessor".into()))?;
    evaluate(previous, fetched)
}

/// WIST-1 §5.2 and ADR-0023: a nonempty recovery set is protected against every non-recovery
/// signer.
pub fn evaluate(stored: &Value, fetched: &Value) -> Result<Decision, Rejection> {
    let stored_p = publisher_of(stored).map_err(|e| ("WIST2-E04", e))?;
    let fetched_p = validate_fields(fetched)?.publisher;
    disjoint_key_sets(&fetched_p).map_err(|e| ("WIST1-E08", e))?;

    if fetched_p.domain != stored_p.domain {
        return Err(("WIST2-E04", "declaration domain changed".into()));
    }

    if fetched_p.seq < stored_p.seq {
        return Err((
            "WIST1-E08",
            format!(
                "stale declaration: seq {} below accepted {}",
                fetched_p.seq, stored_p.seq
            ),
        ));
    }
    if fetched_p.seq == stored_p.seq {
        if inner_hash(fetched).map_err(|e| ("WIST2-E04", e))?
            == inner_hash(stored).map_err(|e| ("WIST2-E04", e))?
        {
            return Ok(Decision::Unchanged);
        }
        return Err((
            "WIST1-E08",
            format!(
                "declaration replayed seq {} with different content",
                fetched_p.seq
            ),
        ));
    }

    if fetched_p.prev_declaration.as_deref()
        != Some(inner_hash(stored).map_err(|e| ("WIST2-E04", e))?.as_str())
    {
        return Err((
            "WIST1-E08",
            "prev_declaration does not equal the hash of the previously accepted declaration"
                .into(),
        ));
    }

    let signer = resolve_signer(fetched, &fetched_p, Some(&stored_p))?;
    let decision = if stored_p.keys.iter().any(|key| key.x == signer.x) {
        Decision::Ordinary
    } else if stored_p
        .recovery_keys
        .iter()
        .flatten()
        .any(|key| key.x == signer.x)
    {
        Decision::Recovery
    } else {
        Decision::FreshIdentity
    };

    if decision == Decision::Ordinary {
        if let Some(commitment) = &stored_p.next_keys {
            let kids = |keys: &[PublisherKey]| {
                keys.iter()
                    .map(|key| key.kid.clone())
                    .collect::<std::collections::BTreeSet<_>>()
            };
            let kept = kids(&stored_p.keys) == kids(&fetched_p.keys)
                && fetched_p.next_keys.as_deref() == Some(commitment.as_str());
            if !kept && key_set_fingerprint(&fetched_p.keys) != *commitment {
                return Err((
                    "WIST1-E08",
                    "ordinary rotation neither keeps nor installs the next_keys commitment".into(),
                ));
            }
        }
    }

    if decision != Decision::Recovery {
        let stored_recovery = recovery_keys_bytes(&stored_p).map_err(|e| ("WIST2-E04", e))?;
        if !stored_recovery.is_empty()
            && recovery_keys_bytes(&fetched_p).map_err(|e| ("WIST2-E04", e))? != stored_recovery
        {
            return Err((
                "WIST1-E08",
                "recovery_keys altered by a declaration not signed by a recovery key".into(),
            ));
        }
    }

    Ok(decision)
}

/// WIST-1 §5.2: the signer must be named in the chain head's `keys` or `recovery_keys`.
pub fn follows_chain_head(head: &Value, candidate: &Value) -> bool {
    matches!(
        evaluate(head, candidate),
        Ok(Decision::Ordinary | Decision::Recovery)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec_dir() -> PathBuf {
        std::env::var_os("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
    }

    fn outcome(case: &Value) -> String {
        let result = if case["stored"].is_null() {
            evaluate_initial(&case["fetched"]).map(|_| "initial")
        } else {
            evaluate(&case["stored"], &case["fetched"]).map(|decision| match decision {
                Decision::Ordinary => "ordinary_rotation",
                Decision::Recovery => "recovery_rotation",
                Decision::FreshIdentity => "fresh_identity",
                Decision::Unchanged => "idempotent",
            })
        };
        result.unwrap_or_else(|(code, _)| code).to_string()
    }

    #[test]
    fn binding_and_key_eligibility_vectors_select_the_documented_outcome() {
        for name in [
            "declaration-binding",
            "declaration-key-eligibility",
            "base64url",
        ] {
            let vector: Value = serde_json::from_slice(
                &std::fs::read(spec_dir().join(format!("vectors/wist1/{name}.json"))).unwrap(),
            )
            .unwrap();
            for case in vector["cases"].as_array().unwrap() {
                let fetched = case.get("fetched").unwrap_or(&case["envelope"]);
                let case = serde_json::json!({"stored": case["stored"], "fetched": fetched,
                    "expected": case["expected"], "name": case["name"]});
                assert_eq!(outcome(&case), case["expected"], "{name}: {}", case["name"]);
            }
        }
    }

    #[test]
    fn recovery_chain_membership_uses_authenticated_public_key() {
        let vector: Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist1/declaration-binding.json")).unwrap(),
        )
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            if matches!(
                case["expected"].as_str(),
                Some(
                    "ordinary_rotation"
                        | "recovery_rotation"
                        | "fresh_identity"
                        | "WIST1-E01"
                        | "WIST1-E02"
                )
            ) {
                assert_eq!(
                    follows_chain_head(&case["stored"], &case["fetched"]),
                    matches!(
                        case["expected"].as_str(),
                        Some("ordinary_rotation" | "recovery_rotation")
                    ),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}
