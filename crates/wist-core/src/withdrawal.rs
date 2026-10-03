//! WIST-4 §5.1 `payload_withdrawal` replay.
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::item::Kind;
use crate::objects::{RegistryAction, RegistryDetails, RegistryUpdateEnvelope, WithdrawalEntry};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
struct Sightings {
    pages: BTreeMap<String, u64>,
    removed: Option<u64>,
}

/// WIST-4 §5.1: a resumed Consumer accepts an act whose Item nothing it holds shows.
#[derive(Debug, Clone, Default)]
pub struct SealedItems {
    resumed: bool,
    items: BTreeMap<String, Sightings>,
}

impl SealedItems {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resumed() -> Self {
        Self {
            resumed: true,
            items: BTreeMap::new(),
        }
    }

    pub fn seal(&mut self, item_id: &str, publisher: &str, kind: Kind, height: u64) {
        let sightings = self.items.entry(item_id.to_owned()).or_default();
        match kind {
            Kind::Page => {
                let earliest = sightings
                    .pages
                    .entry(publisher.to_owned())
                    .or_insert(height);
                *earliest = (*earliest).min(height);
            }
            Kind::Removed => {
                sightings.removed = Some(sightings.removed.map_or(height, |at| at.min(height)));
            }
        }
    }

    pub fn meets_contract(&self, item_id: &str, subject: &str, height: u64) -> Option<bool> {
        let sightings = self.items.get(item_id);
        if sightings
            .and_then(|sightings| sightings.pages.get(subject))
            .is_some_and(|sealed| *sealed <= height)
        {
            return Some(true);
        }
        let shown = sightings.is_some_and(|sightings| {
            sightings.removed.is_some_and(|sealed| sealed <= height)
                || sightings.pages.values().any(|sealed| *sealed <= height)
        });
        (shown || !self.resumed).then_some(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Accepted {
        item_id: String,
        publisher: String,
        withdrawn_height: u64,
        changed: bool,
    },
    Rejected(&'static str),
    NotWithdrawal,
}

#[derive(Debug, Clone, Default)]
pub struct WithdrawalReplay {
    withdrawn: BTreeMap<String, (u64, String)>,
}

impl WithdrawalReplay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn adopt(&mut self, item_id: &str, publisher: &str, height: u64) {
        self.withdrawn
            .entry(item_id.to_string())
            .or_insert((height, publisher.to_string()));
    }

    pub fn is_withdrawn(&self, item_id: &str) -> bool {
        self.withdrawn.contains_key(item_id)
    }

    pub fn withdrawn_height(&self, item_id: &str) -> Option<u64> {
        self.withdrawn.get(item_id).map(|(height, _)| *height)
    }

    /// WIST-3 §7.
    pub fn entries(&self) -> Vec<WithdrawalEntry> {
        self.withdrawn
            .iter()
            .map(|(item_id, (height, publisher))| WithdrawalEntry {
                delta_id: item_id.clone(),
                publisher: publisher.clone(),
                sealing_height: *height,
            })
            .collect()
    }

    pub fn apply_raw(
        &mut self,
        height: u64,
        raw: &[u8],
        log_key: impl Fn(&str) -> Option<PublicKey>,
        sealed: &SealedItems,
    ) -> Disposition {
        let Ok(doc) = crate::json::parse(raw) else {
            return Disposition::Rejected("WIST1-E05");
        };
        self.apply(height, &doc, log_key, sealed)
    }

    /// The body must come from `json::parse`, which rejects repeated members.
    pub fn apply(
        &mut self,
        height: u64,
        doc: &Value,
        log_key: impl Fn(&str) -> Option<PublicKey>,
        sealed: &SealedItems,
    ) -> Disposition {
        if crate::jcs::canonicalize(doc).is_err() {
            return Disposition::Rejected("WIST1-E05");
        }
        let envelope: RegistryUpdateEnvelope = match serde_json::from_value(doc.clone()) {
            Ok(envelope) => envelope,
            Err(_) => return Disposition::Rejected("WIST4-E11"),
        };
        if let Err(code) = envelope_fields(&envelope) {
            return Disposition::Rejected(code);
        }
        if !matches!(envelope.update.action, RegistryAction::PayloadWithdrawal) {
            return Disposition::NotWithdrawal;
        }
        let details = match envelope.update.typed_details() {
            Ok(RegistryDetails::PayloadWithdrawal(details)) => details,
            _ => return Disposition::Rejected("WIST4-E04"),
        };
        let Some(key) = log_key(&envelope.sig.key_id) else {
            return Disposition::Rejected("WIST4-E11");
        };
        if crate::envelope::verify_envelope(doc, "update", &key).is_err() {
            return Disposition::Rejected("WIST4-E11");
        }
        let publisher = envelope.update.subject;
        if sealed.meets_contract(&details.delta_id, &publisher, height) == Some(false) {
            return Disposition::Rejected("WIST4-E04");
        }
        let changed = !self.withdrawn.contains_key(&details.delta_id);
        let (withdrawn_height, _) = self
            .withdrawn
            .entry(details.delta_id.clone())
            .or_insert((height, publisher.clone()));
        Disposition::Accepted {
            item_id: details.delta_id,
            publisher,
            withdrawn_height: *withdrawn_height,
            changed,
        }
    }
}

/// WIST-4 §5.1 checks outside any action's contract.
pub(crate) fn envelope_fields(envelope: &RegistryUpdateEnvelope) -> Result<(), &'static str> {
    let update = &envelope.update;
    if !release_version(&update.wist_version)
        || update.wist_version.split('.').next() != Some("1")
        || update.subject.is_empty()
        || update.subject.chars().count() > 256
        || crate::timestamp::log_seconds(&update.effective_at).is_err()
        || envelope.sig.alg != "Ed25519"
        || envelope.sig.key_id.chars().count() > 64
        || !canonical_signature(&envelope.sig.value)
    {
        return Err("WIST4-E11");
    }
    Ok(())
}

fn release_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}

fn canonical_signature(value: &str) -> bool {
    crate::crypto::b64u_decode(value)
        .is_ok_and(|bytes| bytes.len() == 64 && crate::crypto::b64u_encode(&bytes) == value)
}

impl From<Disposition> for Result<(), Error> {
    fn from(disposition: Disposition) -> Self {
        match disposition {
            Disposition::Rejected(code) => Err(Error::Envelope(code.into())),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_history_breaks_the_contract_of_an_item_it_never_sealed() {
        let sealed = SealedItems::new();
        assert_eq!(
            sealed.meets_contract("sha256:a", "a.example", 3),
            Some(false)
        );
        assert_eq!(
            SealedItems::resumed().meets_contract("sha256:a", "a.example", 3),
            None
        );
    }

    #[test]
    fn a_page_of_the_subject_at_or_below_the_act_meets_the_contract() {
        for mut sealed in [SealedItems::new(), SealedItems::resumed()] {
            sealed.seal("sha256:a", "a.example", Kind::Page, 4);
            assert_eq!(
                sealed.meets_contract("sha256:a", "a.example", 4),
                Some(true)
            );
            assert_eq!(
                sealed.meets_contract("sha256:a", "b.example", 4),
                Some(false)
            );
            sealed.seal("sha256:r", "a.example", Kind::Removed, 2);
            assert_eq!(
                sealed.meets_contract("sha256:r", "a.example", 4),
                Some(false)
            );
        }
    }

    #[test]
    fn an_item_sealed_above_the_act_shows_nothing_to_a_resumed_consumer() {
        let mut complete = SealedItems::new();
        let mut resumed = SealedItems::resumed();
        complete.seal("sha256:a", "a.example", Kind::Page, 5);
        resumed.seal("sha256:a", "a.example", Kind::Page, 5);
        assert_eq!(
            complete.meets_contract("sha256:a", "a.example", 4),
            Some(false)
        );
        assert_eq!(resumed.meets_contract("sha256:a", "a.example", 4), None);
    }
}
