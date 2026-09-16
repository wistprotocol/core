//! WIST-1 §§5.1/5.2 and ADR-0023: Declaration field validation, key-set
//! well-formedness, signer resolution, replacement classification, and the
//! Delta authority, predecessor and clock rules every role applies.
//! Rejections carry the WIST-1 §7 code and a detail.
use crate::crypto::PublicKey;
use crate::delta_fields::{self, canonical_b64u};
use crate::envelope::verify_envelope;
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

/// Complete Declaration field validation (`WIST1-E05` for
/// non-canonicalizable input, `WIST1-E14` otherwise).
pub fn validate_fields(doc: &Value) -> Result<PublisherEnvelope, Rejection> {
    let canonical = crate::jcs::canonicalize(doc).map_err(|e| ("WIST1-E05", e.to_string()))?;
    let envelope: PublisherEnvelope =
        serde_json::from_slice(&canonical).map_err(|e| ("WIST1-E14", e.to_string()))?;
    validate_structure(doc, &envelope).map_err(|e| ("WIST1-E14", e))?;
    for key in envelope
        .publisher
        .keys
        .iter()
        .chain(envelope.publisher.recovery_keys.iter().flatten())
    {
        if !canonical_b64u(&key.public_key, 32) {
            return Err((
                "WIST1-E14",
                "public_key: expected canonical base64url encoding of 32 octets".into(),
            ));
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
        "contact",
    ] {
        if doc["publisher"].get(field).is_some_and(Value::is_null) {
            return Err(format!("{field} must not be null"));
        }
    }
    if publisher.seq > 9_007_199_254_740_991 {
        return Err("seq exceeds the safe integer range".into());
    }
    if !delta_fields::version_spelled(&publisher.wist_version) {
        return Err("wist_version must contain three decimal components".into());
    }
    if publisher.prev_declaration.as_ref().is_some_and(|hash| {
        !hash.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    }) {
        return Err("prev_declaration must be a lowercase SHA-256 hash".into());
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
    for key in publisher
        .keys
        .iter()
        .chain(publisher.recovery_keys.iter().flatten())
    {
        if key.key_id.chars().count() > 64 || key.alg != "Ed25519" {
            return Err("key_id exceeds 64 characters or alg is not Ed25519".into());
        }
        if !publisher_time::valid(&key.valid_from) {
            return Err("valid_from must satisfy the Publisher timestamp profile".into());
        }
    }
    if envelope.sig.key_id.chars().count() > 64 || envelope.sig.alg != "Ed25519" {
        return Err("signature key_id exceeds 64 characters or alg is not Ed25519".into());
    }
    Ok(())
}

/// ADR-0023: the keys whose public bytes decode to a canonical,
/// non-small-order Ed25519 point; every other signed entry is retained
/// but never a signer candidate.
pub fn usable_keys(keys: &[PublisherKey]) -> impl Iterator<Item = &PublisherKey> {
    keys.iter()
        .filter(|key| key.alg == "Ed25519" && PublicKey::from_b64u(&key.public_key).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Unchanged,
    Ordinary,
    Recovery,
    FreshIdentity,
}

/// The Declaration hash: SHA-256 of the canonical `publisher` object.
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

/// WIST-1 §5.2 and ADR-0023: every identifier occurs once across `keys`
/// and `recovery_keys`, identical duplicates included, and the two sets
/// share neither identifiers nor public bytes.
pub fn disjoint_key_sets(p: &Publisher) -> Result<(), String> {
    let mut identifiers = std::collections::BTreeSet::new();
    for key in p.keys.iter().chain(p.recovery_keys.iter().flatten()) {
        if !identifiers.insert(&key.key_id) {
            return Err(format!("duplicate key_id {} in Declaration", key.key_id));
        }
    }
    let Some(recovery) = p.recovery_keys.as_deref() else {
        return Ok(());
    };
    for r in recovery {
        if let Some(clash) = p
            .keys
            .iter()
            .find(|k| k.key_id == r.key_id || k.public_key == r.public_key)
        {
            return Err(format!(
                "key {} is named in both keys and recovery_keys",
                clash.key_id
            ));
        }
    }
    Ok(())
}

fn verify_with(doc: &Value, key: &PublisherKey) -> bool {
    (key.alg == "Ed25519" && doc["sig"]["alg"] == "Ed25519")
        .then(|| PublicKey::from_b64u(&key.public_key).ok())
        .flatten()
        .is_some_and(|public| verify_envelope(doc, "publisher", &public).is_ok())
}

/// An initial Declaration: seq 0, no predecessor, self-signed by one of
/// its own usable signing keys.
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

/// ADR-0023: the signer is the entry named by `sig.key_id` among the usable
/// previous signing and recovery bindings and the usable incoming signing
/// bindings whose key verifies the Envelope; `WIST1-E02` names none,
/// `WIST1-E01` verifies under none.
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
        .filter(|key| key.key_id == key_id)
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

/// The canonical Publisher of a field-valid Delta.
pub fn delta_publisher(doc: &Value) -> Result<&str, &'static str> {
    delta_fields::validate_fields(doc)?;
    Ok(doc["delta"]["publisher"].as_str().unwrap())
}

/// WIST-1 §§3.2/5.2 and ADR-0023: a Delta is authorized when a named,
/// usable signing binding of a source Declaration for its Publisher, valid
/// at its `observed_at`, verifies it, and its URL lies inside that
/// source's authority.
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

/// Whether `url` is its own Normalized URL under `domain` or one of the
/// declared scope hosts.
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

/// WIST-1 §5.1/§5.2 Key Set checks for a signed object. `observed_at`
/// activates the `valid_from` bound (Deltas); pass None for Feeds.
pub fn verify_signed(
    keys: &[&PublisherKey],
    doc: &Value,
    kind: &str,
    observed_at: Option<&str>,
) -> Result<(), &'static str> {
    if kind == "delta" {
        delta_fields::validate_version(doc)?;
    }
    if observed_at.is_some_and(|value| !publisher_time::valid(value))
        || keys
            .iter()
            .any(|key| !publisher_time::valid(&key.valid_from))
    {
        return Err("WIST1-E14");
    }
    if !canonical_b64u(doc["sig"]["value"].as_str().ok_or("WIST1-E14")?, 64) {
        return Err("WIST1-E14");
    }
    for key in keys {
        if !canonical_b64u(&key.public_key, 32) {
            return Err("WIST1-E14");
        }
    }
    let key_id = doc["sig"]["key_id"].as_str().unwrap_or_default();
    let mut eligible = false;
    for key in keys.iter().filter(|key| key.key_id == key_id) {
        if key.alg != "Ed25519" {
            continue;
        }
        let Ok(public) = PublicKey::from_b64u(&key.public_key) else {
            continue;
        };
        if observed_at.is_some_and(|at| {
            !publisher_time::compare(at, &key.valid_from).is_some_and(|order| !order.is_lt())
        }) {
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

/// WIST-1 §5.2: evaluate a fetched Declaration against the accepted one,
/// with an open recovery window's chain head as an alternative
/// predecessor and the accepted sequence floor every replacement must
/// exceed.
pub fn evaluate_with_heads(
    current: &Value,
    recovery_head: Option<&Value>,
    highest_accepted_seq: u64,
    fetched: &Value,
) -> Result<Decision, Rejection> {
    let incoming = validate_fields(fetched)?.publisher;
    if incoming.domain != current["publisher"]["domain"] {
        return Err(("WIST2-E04", "declaration domain changed".into()));
    }
    if inner_hash(current).map_err(|e| ("WIST2-E04", e))?
        == inner_hash(fetched).map_err(|e| ("WIST2-E04", e))?
    {
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
        .find(|head| inner_hash(head).ok().as_deref() == incoming.prev_declaration.as_deref())
        .ok_or(("WIST1-E08", "ineligible Declaration predecessor".into()))?;
    evaluate(previous, fetched)
}

/// WIST-1 §5.2 and ADR-0023: classify a replacement of `stored` by the
/// authenticated public bytes of its signer, protecting a nonempty
/// recovery set against every non-recovery signer.
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
    let decision = if stored_p
        .keys
        .iter()
        .any(|key| key.public_key == signer.public_key)
    {
        Decision::Ordinary
    } else if stored_p
        .recovery_keys
        .iter()
        .flatten()
        .any(|key| key.public_key == signer.public_key)
    {
        Decision::Recovery
    } else {
        Decision::FreshIdentity
    };

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

/// WIST-1 §5.2: a Declaration legitimately follows the recovery chain when
/// its signer is named in the chain head's `keys` or `recovery_keys`.
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
