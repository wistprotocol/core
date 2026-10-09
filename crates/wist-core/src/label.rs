use crate::crypto::{hex_encode, PublicKey};
use crate::objects::{
    Dispute, DisputeEntry, DisputeEnvelope, Label, LabelDefinitionEnvelope, LabelEntry,
    LabelEnvelope, Publisher, PublisherEnvelope,
};
use crate::publisher_time;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// WIST-4 §6.
pub const WIST_TERMS: &[&str] = &[
    "wist:trust-seed",
    "wist:distrust-seed",
    "wist:spam",
    "wist:copied",
    "wist:mismatch",
    "wist:unavailable",
    "wist:adult",
];

/// WIST-2 §3.3 and WIST-1 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Fields,
    Clock,
    SelfLabel,
    Unsealed,
    Authority,
    Binding,
    Signature,
}

impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Rejection::Fields
            | Rejection::Clock
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

pub fn label_id(label: &Value) -> Result<String, Rejection> {
    digest_of(label)
}

pub fn dispute_id(dispute: &Value) -> Result<String, Rejection> {
    digest_of(dispute)
}

fn is_sha256_id(value: &str) -> bool {
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
    crate::envelope::validate_version(version).is_ok()
}

fn signature_canonical(value: &str) -> bool {
    crate::envelope::canonical_b64u(value, 64)
}

/// WIST-4 §6: a registry term under `wist`, a Canonical Host under any other prefix.
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

pub fn subject_host(subject: &str) -> &str {
    match subject.strip_prefix("https://") {
        Some(rest) => rest.split(['/', ':']).next().unwrap_or(rest),
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

fn label_fields(label: &Label, url_cap_bytes: i64) -> Result<(), Rejection> {
    if !supported_major(&label.wist_version) {
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
        if !url_subject || !is_sha256_id(delta) {
            return Err(Rejection::Fields);
        }
    }
    Ok(())
}

fn dispute_fields(dispute: &Dispute) -> Result<(), Rejection> {
    if !supported_major(&dispute.wist_version)
        || !is_sha256_id(&dispute.label)
        || !is_canonical_host(&dispute.log)
        || dispute
            .reason
            .as_deref()
            .is_some_and(|reason| reason.len() > 2048 || !is_normalized_url(reason))
        || !publisher_time::valid(&dispute.asserted_at)
    {
        return Err(Rejection::Fields);
    }
    Ok(())
}

/// WIST-2 §3.3 and WIST-1 §7 check order; `asserted_at` is checked as a Catalog's `generated_at`
/// against `clock_s` (WIST-1 §3.4).
pub fn validate_label(
    doc: &Value,
    declaration: &PublisherEnvelope,
    url_cap_bytes: i64,
    clock_s: i64,
    clock_skew_seconds: i64,
) -> Result<LabelEnvelope, Rejection> {
    let envelope: LabelEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| Rejection::Fields)?;
    sig_fields(doc)?;
    let label = &envelope.label;
    let publisher = &declaration.publisher;
    label_fields(label, url_cap_bytes)?;
    if label.labeler != publisher.domain {
        return Err(Rejection::Fields);
    }
    within_allowance(&label.asserted_at, clock_s, clock_skew_seconds)?;
    if under_authority(subject_host(&label.subject), publisher) {
        return Err(Rejection::SelfLabel);
    }
    signer(doc, "label", publisher, &label.asserted_at)?;
    Ok(envelope)
}

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

/// WIST-2 §3.3: the greatest `asserted_at`, then the later in Log order.
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

pub fn expired_at(label: &Label, sealed_at: &str) -> bool {
    expired(label.expires_at.as_deref(), sealed_at)
}

fn expired(expires_at: Option<&str>, sealed_at: &str) -> bool {
    expires_at.is_some_and(|expires_at| {
        publisher_time::compare(expires_at, sealed_at) != Some(Ordering::Greater)
    })
}

pub fn applies_at(entry: &LabelEntry, sealed_at: &str) -> bool {
    !entry.retracted && !expired(entry.expires_at.as_deref(), sealed_at)
}

/// WIST-3 §7: the current Label's tuple, retracted and expired included.
pub fn label_tuple(current: &SealedLabel) -> LabelEntry {
    let label = &current.label;
    LabelEntry {
        labeler: label.labeler.clone(),
        subject: label.subject.clone(),
        name: label.name.clone(),
        value: label.value.map(|value| value as u64),
        asserted_at: label.asserted_at.clone(),
        retracted: label.retracted == Some(true),
        expires_at: label.expires_at.clone(),
        delta: label.delta.clone(),
        label_id: current.label_id.clone(),
        sealing_height: current.height,
    }
}

/// WIST-2 §3.3.
pub fn binding_applies(delta: Option<&str>, record_item_id: Option<&str>) -> bool {
    match (delta, record_item_id) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(delta), Some(item_id)) => delta == item_id,
    }
}

/// WIST-2 §3.3: `records` holds `(publisher, item_id, withdrawn)` for each record of `subject`.
pub fn materialized_binding_applies<'a>(
    delta: Option<&str>,
    subject: &str,
    self_declared: bool,
    records: impl IntoIterator<Item = (&'a str, &'a str, bool)>,
) -> bool {
    let records: Vec<(&str, &str, bool)> = records.into_iter().collect();
    let chosen = crate::materialization::preferred(
        crate::declaration::url_host(subject),
        self_declared,
        records
            .iter()
            .map(|(publisher, _, withdrawn)| (*publisher, *withdrawn)),
    );
    let item_id = chosen.and_then(|chosen| {
        records
            .iter()
            .find(|(publisher, _, _)| *publisher == chosen)
            .map(|(_, item_id, _)| *item_id)
    });
    binding_applies(delta, item_id)
}

/// WIST-3 §7: a Consumer resumed from a Snapshot holds no Label IDs, so an `Unverifiable`
/// dispute is read as consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelLookup {
    Known { subject: String },
    Absent,
    Unverifiable,
}

fn within_allowance(
    asserted_at: &str,
    clock_s: i64,
    clock_skew_seconds: i64,
) -> Result<(), Rejection> {
    match publisher_time::within_clock_bound(asserted_at, clock_s, clock_skew_seconds) {
        Some(true) => Ok(()),
        Some(false) => Err(Rejection::Clock),
        None => Err(Rejection::Fields),
    }
}

/// WIST-2 §3.3: `asserted_at` is checked against `clock_s` as a Label's is.
pub fn validate_dispute(
    doc: &Value,
    declaration: &PublisherEnvelope,
    sealed: impl Fn(&str) -> LabelLookup,
    clock_s: i64,
    clock_skew_seconds: i64,
) -> Result<DisputeEnvelope, Rejection> {
    let envelope: DisputeEnvelope =
        serde_json::from_value(doc.clone()).map_err(|_| Rejection::Fields)?;
    sig_fields(doc)?;
    let dispute = &envelope.dispute;
    let publisher = &declaration.publisher;
    dispute_fields(dispute)?;
    if dispute.disputant != publisher.domain {
        return Err(Rejection::Fields);
    }
    within_allowance(&dispute.asserted_at, clock_s, clock_skew_seconds)?;
    disputed(dispute, publisher, sealed)?;
    signer(doc, "dispute", publisher, &dispute.asserted_at)?;
    Ok(envelope)
}

fn disputed(
    dispute: &Dispute,
    publisher: &Publisher,
    sealed: impl Fn(&str) -> LabelLookup,
) -> Result<(), Rejection> {
    match sealed(&dispute.label) {
        LabelLookup::Absent => Err(Rejection::Unsealed),
        LabelLookup::Known { subject } if !under_authority(subject_host(&subject), publisher) => {
            Err(Rejection::Authority)
        }
        LabelLookup::Known { .. } | LabelLookup::Unverifiable => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Label,
    Dispute,
}

impl EntryKind {
    pub fn of(entry_type: &str) -> Option<Self> {
        match entry_type {
            "label" => Some(EntryKind::Label),
            "dispute" => Some(EntryKind::Dispute),
            _ => None,
        }
    }

    pub fn member(self) -> &'static str {
        match self {
            EntryKind::Label => "label",
            EntryKind::Dispute => "dispute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Judging {
    pub clock_s: i64,
    pub clock_skew_seconds: i64,
    pub url_cap_bytes: i64,
}

/// WIST-3 §3.3: a labeler or disputant with no Declaration in force fails the binding check.
pub fn judge_entry<'p>(
    kind: EntryKind,
    body: &Value,
    judging: &Judging,
    in_force: impl Fn(&str) -> Option<&'p Publisher>,
    sealed: impl Fn(&str) -> LabelLookup,
) -> Result<(), Rejection> {
    let members = body.as_object().ok_or(Rejection::Fields)?;
    if crate::jcs::canonicalize(body).is_err()
        || members.len() != 2
        || !members.contains_key(kind.member())
    {
        return Err(Rejection::Fields);
    }
    sig_fields(body)?;
    let (author, asserted_at, label, dispute) = match kind {
        EntryKind::Label => {
            let envelope: LabelEnvelope =
                serde_json::from_value(body.clone()).map_err(|_| Rejection::Fields)?;
            label_fields(&envelope.label, judging.url_cap_bytes)?;
            let label = envelope.label;
            (
                label.labeler.clone(),
                label.asserted_at.clone(),
                Some(label),
                None,
            )
        }
        EntryKind::Dispute => {
            let envelope: DisputeEnvelope =
                serde_json::from_value(body.clone()).map_err(|_| Rejection::Fields)?;
            dispute_fields(&envelope.dispute)?;
            let dispute = envelope.dispute;
            (
                dispute.disputant.clone(),
                dispute.asserted_at.clone(),
                None,
                Some(dispute),
            )
        }
    };
    if !is_canonical_host(&author) {
        return Err(Rejection::Fields);
    }
    within_allowance(&asserted_at, judging.clock_s, judging.clock_skew_seconds)?;
    let publisher = in_force(&author).ok_or(Rejection::Binding)?;
    if let Some(label) = &label {
        if under_authority(subject_host(&label.subject), publisher) {
            return Err(Rejection::SelfLabel);
        }
    }
    if let Some(dispute) = &dispute {
        disputed(dispute, publisher, sealed)?;
    }
    signer(body, kind.member(), publisher, &asserted_at)
}

#[derive(Debug, Clone)]
pub struct SealedDispute {
    pub dispute: crate::objects::Dispute,
    pub dispute_id: String,
    pub height: u64,
    pub entry_index: u64,
}

/// WIST-2 §3.3: one current dispute per (label, disputant).
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

/// WIST-3 §7.
pub fn dispute_tuple(current: &SealedDispute) -> DisputeEntry {
    DisputeEntry {
        label_id: current.dispute.label.clone(),
        disputant: current.dispute.disputant.clone(),
        reason: current.dispute.reason.clone(),
        asserted_at: current.dispute.asserted_at.clone(),
        sealing_height: current.height,
    }
}

/// WIST-2 §3.3: a failing definition supplies no treatment.
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

/// WIST-2 §3.3.
pub fn definition_path(name: &str) -> String {
    format!(
        "labels/definitions/{}.json",
        hex_encode(&Sha256::digest(name.as_bytes()))
    )
}

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

/// WIST-3 §7: ascending labeler order.
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

#[derive(Debug, Clone)]
pub struct LabelEvent<'a> {
    pub height: u64,
    pub asserted_at: &'a str,
    pub retracted: bool,
}

/// WIST-4 §6 default profile. `expires_at_height` is the first height whose Epoch instant
/// reaches the expiry; `events` are in ascending Log order, the WIST-2 §3.3 tie-break.
pub fn live_at(events: &[LabelEvent<'_>], expires_at_height: Option<u64>, height: u64) -> bool {
    let current = events.iter().filter(|event| event.height <= height).fold(
        None,
        |best: Option<&LabelEvent>, event| match best {
            Some(best)
                if publisher_time::compare(best.asserted_at, event.asserted_at)
                    == Some(Ordering::Greater) =>
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

/// WIST-4 §6: a Labeler with no sealed Entry within `inactivity_epochs`
/// of `height` is ignored.
pub fn labeler_active(last_sealed_height: u64, inactivity_epochs: u64, height: u64) -> bool {
    height.saturating_sub(last_sealed_height) <= inactivity_epochs
}
