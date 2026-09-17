//! WIST-2 §3.3 and WIST-4 §6: Labels, disputes and label definitions —
//! their IDs, validation under the signer's Declaration, the current-Label
//! and current-dispute rules with the WIST-3 §7 tuples they leave, the
//! Delta binding, the labeler statistics and the recommended default
//! profile.
use crate::crypto::{hex_encode, PublicKey};
use crate::objects::{
    DisputeEntry, DisputeEnvelope, Label, LabelDefinitionEnvelope, LabelEntry, LabelEnvelope,
    Publisher, PublisherEnvelope,
};
use crate::publisher_time;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// The names WIST-4 §6 defines under the `wist` prefix.
pub const WIST_TERMS: &[&str] = &[
    "wist:trust-seed",
    "wist:distrust-seed",
    "wist:spam",
    "wist:copied",
    "wist:mismatch",
    "wist:unavailable",
    "wist:adult",
];

/// Why a Label, dispute or definition is not accepted, with the code an
/// Aggregator reports (WIST-2 §3.3, WIST-1 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// A field, form or version failure, `WIST2-E06`.
    Fields,
    /// A Label about the Labeler itself, `WIST2-E06`.
    SelfLabel,
    /// A dispute of a Label the Log has not sealed, `WIST2-E06`.
    Unsealed,
    /// A dispute of a Label whose subject is outside the disputant's
    /// authority, `WIST2-E06`.
    Authority,
    /// `sig.key_id` names no usable signing entry, `WIST1-E02`.
    Binding,
    /// The signature does not verify under the named entry, `WIST1-E01`.
    Signature,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Rejection::Fields
            | Rejection::SelfLabel
            | Rejection::Unsealed
            | Rejection::Authority => "WIST2-E06",
            Rejection::Binding => "WIST1-E02",
            Rejection::Signature => "WIST1-E01",
        }
    }
}

fn digest_of(inner: &Value) -> Result<String, Rejection> {
    let canonical = crate::jcs::canonicalize(inner).map_err(|_| Rejection::Fields)?;
    Ok(format!(
        "sha256:{}",
        hex_encode(&Sha256::digest(&canonical))
    ))
}

/// The Label ID: `"sha256:" + hex(SHA-256(JCS(label)))`.
pub fn label_id(label: &Value) -> Result<String, Rejection> {
    digest_of(label)
}

/// The Dispute ID, the Label ID construction over `dispute`.
pub fn dispute_id(dispute: &Value) -> Result<String, Rejection> {
    digest_of(dispute)
}

fn is_delta_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_canonical_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && crate::host::canonical_host(value).is_ok_and(|host| host == value)
}

fn is_normalized_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value.contains('#')
        && crate::extract::normalize_url(value, value).as_deref() == Some(value)
}

fn supported_major(version: &str) -> bool {
    crate::delta_fields::version_spelled(version) && version.split('.').next() == Some("1")
}

fn signature_canonical(value: &str) -> bool {
    crate::delta_fields::canonical_b64u(value, 64)
}

/// WIST-4 §6: the `<prefix>:<term>` form, a registry term under `wist`
/// and a Canonical Host under any other prefix.
pub fn valid_name(name: &str) -> bool {
    if name.len() > 64 {
        return false;
    }
    let Some((prefix, term)) = name.rsplit_once(':') else {
        return false;
    };
    if term.is_empty()
        || !term
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    if prefix == "wist" {
        WIST_TERMS.contains(&name)
    } else {
        is_canonical_host(prefix)
    }
}

/// The host a subject names: a Normalized URL's host or the Canonical
/// Host itself.
pub fn subject_host(subject: &str) -> &str {
    match subject.strip_prefix("https://") {
        Some(rest) => rest.split('/').next().unwrap_or(rest),
        None => subject,
    }
}

fn under_authority(host: &str, publisher: &Publisher) -> bool {
    host == publisher.domain
        || publisher
            .subdomain_scope
            .as_ref()
            .is_some_and(|scope| scope.iter().any(|scoped| scoped == host))
}

fn signer(
    doc: &Value,
    inner: &str,
    publisher: &Publisher,
    asserted_at: &str,
) -> Result<(), Rejection> {
    let key_id = doc["sig"]["key_id"].as_str().ok_or(Rejection::Fields)?;
    let entry = publisher
        .keys
        .iter()
        .find(|key| key.kid == key_id)
        .ok_or(Rejection::Binding)?;
    if entry.admits(asserted_at) != Some(true) {
        return Err(Rejection::Binding);
    }
    let key = PublicKey::from_b64u(&entry.x).map_err(|_| Rejection::Binding)?;
    crate::envelope::verify_envelope(doc, inner, &key).map_err(|_| Rejection::Signature)
}

fn sig_fields(doc: &Value) -> Result<(), Rejection> {
    let sig = doc.get("sig").ok_or(Rejection::Fields)?;
    let key_id = sig["key_id"].as_str().ok_or(Rejection::Fields)?;
    if key_id.chars().count() > 64
        || sig["alg"] != "Ed25519"
        || !sig["value"].as_str().is_some_and(signature_canonical)
    {
        return Err(Rejection::Fields);
    }
    Ok(())
}

/// WIST-2 §3.3: validates one Label Envelope under the Labeler's
/// Declaration and the `url_cap_bytes` in force, in the order the section
/// and WIST-1 §7 apply the checks.
pub fn validate_label(
    doc: &Value,
    declaration: &PublisherEnvelope,
    url_cap_bytes: i64,
) -> Result<LabelEnvelope, Rejection> {
    let envelope: LabelEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| Rejection::Fields)?;
    sig_fields(doc)?;
    let label = &envelope.label;
    let publisher = &declaration.publisher;
    if !supported_major(&label.wist_version) || label.labeler != publisher.domain {
        return Err(Rejection::Fields);
    }
    let url_subject = label.subject.starts_with("https://");
    if url_subject {
        if !is_normalized_url(&label.subject) {
            return Err(Rejection::Fields);
        }
    } else if !is_canonical_host(&label.subject) {
        return Err(Rejection::Fields);
    }
    let subject_octets = crate::jcs::canonicalize(&Value::String(label.subject.clone()))
        .map_err(|_| Rejection::Fields)?
        .len();
    if i64::try_from(subject_octets).map_or(true, |octets| octets > url_cap_bytes) {
        return Err(Rejection::Fields);
    }
    if !valid_name(&label.name)
        || label
            .value
            .is_some_and(|value| !(0..=1_000_000).contains(&value))
        || !publisher_time::valid(&label.asserted_at)
        || label.retracted.is_some_and(|retracted| !retracted)
    {
        return Err(Rejection::Fields);
    }
    if let Some(expires_at) = &label.expires_at {
        if publisher_time::compare(expires_at, &label.asserted_at) != Some(Ordering::Greater) {
            return Err(Rejection::Fields);
        }
    }
    if let Some(delta) = &label.delta {
        if !url_subject || !is_delta_id(delta) {
            return Err(Rejection::Fields);
        }
    }
    if under_authority(subject_host(&label.subject), publisher) {
        return Err(Rejection::SelfLabel);
    }
    signer(doc, "label", publisher, &label.asserted_at)?;
    Ok(envelope)
}

/// A Label the Log sealed, at its Block and Entry index.
#[derive(Debug, Clone)]
pub struct SealedLabel {
    pub label: Label,
    pub label_id: String,
    pub height: u64,
    pub entry_index: u64,
}

fn rank(
    asserted_at: &str,
    height: u64,
    entry_index: u64,
) -> impl Fn(&str, u64, u64) -> Ordering + '_ {
    move |other_at, other_height, other_index| {
        publisher_time::compare(asserted_at, other_at)
            .unwrap_or(Ordering::Equal)
            .then(height.cmp(&other_height))
            .then(entry_index.cmp(&other_index))
    }
}

/// WIST-2 §3.3: the current Label of one (labeler, subject, name) — the
/// greatest `asserted_at`, then the later in Log order.
pub fn current_label<'a>(
    sealed: impl IntoIterator<Item = &'a SealedLabel>,
) -> Option<&'a SealedLabel> {
    sealed
        .into_iter()
        .fold(None, |best: Option<&SealedLabel>, candidate| match best {
            Some(best)
                if rank(&best.label.asserted_at, best.height, best.entry_index)(
                    &candidate.label.asserted_at,
                    candidate.height,
                    candidate.entry_index,
                ) != Ordering::Less =>
            {
                Some(best)
            }
            _ => Some(candidate),
        })
}

/// Whether a Label applies nothing at a Block sealed at `sealed_at`
/// because its `expires_at` is at or before that instant.
pub fn expired_at(label: &Label, sealed_at: &str) -> bool {
    label.expires_at.as_deref().is_some_and(|expires_at| {
        publisher_time::compare(expires_at, sealed_at) != Some(Ordering::Greater)
    })
}

/// WIST-3 §7: the `label` tuple the current Label leaves at a Snapshot
/// whose Block is sealed at `sealed_at`; none when retracted or expired.
pub fn label_tuple(current: &SealedLabel, sealed_at: &str) -> Option<LabelEntry> {
    let label = &current.label;
    if label.retracted == Some(true) || expired_at(label, sealed_at) {
        return None;
    }
    Some(LabelEntry {
        labeler: label.labeler.clone(),
        subject: label.subject.clone(),
        name: label.name.clone(),
        value: label.value.map(|value| value as u64),
        asserted_at: label.asserted_at.clone(),
        expires_at: label.expires_at.clone(),
        delta: label.delta.clone(),
        label_id: current.label_id.clone(),
        sealing_height: current.height,
    })
}

/// WIST-2 §3.3: whether a Label bound to `delta` applies to a URL whose
/// record stands on `record_anchor`, none where no record is live.
pub fn binding_applies(delta: Option<&str>, record_anchor: Option<&str>) -> bool {
    match (delta, record_anchor) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(delta), Some(anchor)) => delta == anchor,
    }
}

/// What the validating party knows about the Label a dispute names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelLookup {
    /// Sealed in this Log, with its subject.
    Known { subject: String },
    /// Not sealed anywhere the party can see.
    Absent,
    /// Sealed below what the party holds — a Consumer resumed from a
    /// Snapshot holds no Label IDs (WIST-3 §7) — so the sealing and
    /// authority checks cannot be made and the dispute is read as
    /// consistent, as a withdrawal of an unwalked Delta is.
    Unverifiable,
}

/// WIST-2 §3.3: validates one Dispute Envelope under the disputant's
/// Declaration against the Labels this Log sealed.
pub fn validate_dispute(
    doc: &Value,
    declaration: &PublisherEnvelope,
    sealed: impl Fn(&str) -> LabelLookup,
) -> Result<DisputeEnvelope, Rejection> {
    let envelope: DisputeEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| Rejection::Fields)?;
    sig_fields(doc)?;
    let dispute = &envelope.dispute;
    let publisher = &declaration.publisher;
    if !supported_major(&dispute.wist_version)
        || dispute.disputant != publisher.domain
        || !is_delta_id(&dispute.label)
        || !is_canonical_host(&dispute.log)
        || dispute
            .reason
            .as_deref()
            .is_some_and(|reason| reason.len() > 2048 || !is_normalized_url(reason))
        || !publisher_time::valid(&dispute.asserted_at)
    {
        return Err(Rejection::Fields);
    }
    match sealed(&dispute.label) {
        LabelLookup::Absent => return Err(Rejection::Unsealed),
        LabelLookup::Known { subject } if !under_authority(subject_host(&subject), publisher) => {
            return Err(Rejection::Authority)
        }
        LabelLookup::Known { .. } | LabelLookup::Unverifiable => {}
    }
    signer(doc, "dispute", publisher, &dispute.asserted_at)?;
    Ok(envelope)
}

/// A dispute the Log sealed, at its Block and Entry index.
#[derive(Debug, Clone)]
pub struct SealedDispute {
    pub dispute: crate::objects::Dispute,
    pub dispute_id: String,
    pub height: u64,
    pub entry_index: u64,
}

/// WIST-2 §3.3: the current dispute of one (label, disputant).
pub fn current_dispute<'a>(
    sealed: impl IntoIterator<Item = &'a SealedDispute>,
) -> Option<&'a SealedDispute> {
    sealed
        .into_iter()
        .fold(None, |best: Option<&SealedDispute>, candidate| match best {
            Some(best)
                if rank(&best.dispute.asserted_at, best.height, best.entry_index)(
                    &candidate.dispute.asserted_at,
                    candidate.height,
                    candidate.entry_index,
                ) != Ordering::Less =>
            {
                Some(best)
            }
            _ => Some(candidate),
        })
}

/// WIST-3 §7: the `dispute` tuple the current dispute leaves.
pub fn dispute_tuple(current: &SealedDispute) -> DisputeEntry {
    DisputeEntry {
        label_id: current.dispute.label.clone(),
        disputant: current.dispute.disputant.clone(),
        reason: current.dispute.reason.clone(),
        asserted_at: current.dispute.asserted_at.clone(),
        sealing_height: current.height,
    }
}

/// WIST-2 §3.3: validates one label definition under the Labeler's
/// Declaration; a definition that fails supplies no treatment.
pub fn validate_definition(
    doc: &Value,
    declaration: &PublisherEnvelope,
) -> Result<LabelDefinitionEnvelope, Rejection> {
    let envelope: LabelDefinitionEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| Rejection::Fields)?;
    sig_fields(doc)?;
    let definition = &envelope.definition;
    let publisher = &declaration.publisher;
    if !supported_major(&definition.wist_version)
        || definition.labeler != publisher.domain
        || !valid_name(&definition.name)
        || definition.description.len() > 2048
        || !is_normalized_url(&definition.description)
        || !publisher_time::valid(&definition.asserted_at)
    {
        return Err(Rejection::Fields);
    }
    signer(doc, "definition", publisher, &definition.asserted_at)?;
    Ok(envelope)
}

/// WIST-2 §3.3: the path under the Labeler's well-known prefix where the
/// definition of `name` is served.
pub fn definition_path(name: &str) -> String {
    format!(
        "labels/definitions/{}.json",
        hex_encode(&Sha256::digest(name.as_bytes()))
    )
}

/// One sealed `label` Entry as the labeler table counts it.
#[derive(Debug, Clone)]
pub struct SealedLabelCount<'a> {
    pub height: u64,
    pub labeler: &'a str,
    pub subject: &'a str,
    pub retracted: bool,
}

/// WIST-3 §7: one row of `tier1/labelers.parquet`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelerRow {
    pub labeler: String,
    pub label_count: u64,
    pub retraction_count: u64,
    pub distinct_subjects: u64,
    pub first_seen_height: u64,
}

/// WIST-3 §7: the labeler table over every sealed `label` Entry, in
/// ascending labeler order.
pub fn labeler_rows<'a>(sealed: impl IntoIterator<Item = SealedLabelCount<'a>>) -> Vec<LabelerRow> {
    let mut rows: BTreeMap<&str, (u64, u64, BTreeSet<&str>, u64)> = BTreeMap::new();
    for entry in sealed {
        let row = rows
            .entry(entry.labeler)
            .or_insert((0, 0, BTreeSet::new(), entry.height));
        row.0 += 1;
        row.1 += u64::from(entry.retracted);
        row.2.insert(entry.subject);
        row.3 = row.3.min(entry.height);
    }
    rows.into_iter()
        .map(
            |(labeler, (count, retractions, subjects, first))| LabelerRow {
                labeler: labeler.to_string(),
                label_count: count,
                retraction_count: retractions,
                distinct_subjects: subjects.len() as u64,
                first_seen_height: first,
            },
        )
        .collect()
}

/// One Label event of a (labeler, subject, name) as the default profile
/// reads it.
#[derive(Debug, Clone)]
pub struct LabelEvent<'a> {
    pub height: u64,
    pub asserted_at: &'a str,
    pub retracted: bool,
}

/// WIST-4 §6's recommended default profile: whether the triple's Label is
/// live at `height` — current, unretracted and not yet at
/// `expires_at_height`, the first height whose Block instant reaches the
/// expiry.
pub fn live_at(events: &[LabelEvent<'_>], expires_at_height: Option<u64>, height: u64) -> bool {
    let current = events.iter().filter(|event| event.height <= height).fold(
        None,
        |best: Option<&LabelEvent>, event| match best {
            Some(best)
                if publisher_time::compare(best.asserted_at, event.asserted_at)
                    != Some(Ordering::Less) =>
            {
                Some(best)
            }
            _ => Some(event),
        },
    );
    match current {
        None => false,
        Some(current) if current.retracted => false,
        Some(_) => expires_at_height.is_none_or(|expiry| height < expiry),
    }
}

/// WIST-4 §6: a `wist:mismatch` or `wist:unavailable` Label counts at
/// `height` only once live there and at the height before.
pub fn counted_at(events: &[LabelEvent<'_>], expires_at_height: Option<u64>, height: u64) -> bool {
    height > 0
        && live_at(events, expires_at_height, height)
        && live_at(events, expires_at_height, height - 1)
}

/// WIST-4 §6: a Labeler with no sealed Entry within `inactivity_blocks`
/// of `height` is ignored.
pub fn labeler_active(last_sealed_height: u64, inactivity_blocks: u64, height: u64) -> bool {
    height.saturating_sub(last_sealed_height) <= inactivity_blocks
}
