//! WIST-4 §5.1 `payload_withdrawal` replay.
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::objects::{RegistryAction, RegistryDetails, RegistryUpdateEnvelope, WithdrawalEntry};
use serde_json::Value;
use std::collections::BTreeMap;

/// WIST-3 §7 carries no per-Delta tuple a resuming Consumer could check, so an act naming an
/// `Unverifiable` Delta is read as consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedDelta {
    Known { publisher: String, height: u64 },
    Absent,
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Accepted {
        delta_id: String,
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

    pub fn adopt(&mut self, delta_id: &str, publisher: &str, height: u64) {
        self.withdrawn
            .entry(delta_id.to_string())
            .or_insert((height, publisher.to_string()));
    }

    pub fn is_withdrawn(&self, delta_id: &str) -> bool {
        self.withdrawn.contains_key(delta_id)
    }

    pub fn withdrawn_height(&self, delta_id: &str) -> Option<u64> {
        self.withdrawn.get(delta_id).map(|(height, _)| *height)
    }

    /// WIST-3 §7.
    pub fn entries(&self) -> Vec<WithdrawalEntry> {
        self.withdrawn
            .iter()
            .map(|(delta_id, (height, publisher))| WithdrawalEntry {
                delta_id: delta_id.clone(),
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
        sealed: impl Fn(&str) -> SealedDelta,
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
        sealed: impl Fn(&str) -> SealedDelta,
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
        match sealed(&details.delta_id) {
            SealedDelta::Known {
                publisher,
                height: sealed_height,
            } => {
                if sealed_height > height || publisher != envelope.update.subject {
                    return Disposition::Rejected("WIST4-E04");
                }
            }
            SealedDelta::Absent => return Disposition::Rejected("WIST4-E04"),
            SealedDelta::Unverifiable => {}
        }
        let publisher = envelope.update.subject;
        let changed = !self.withdrawn.contains_key(&details.delta_id);
        let (withdrawn_height, _) = self
            .withdrawn
            .entry(details.delta_id.clone())
            .or_insert((height, publisher.clone()));
        Disposition::Accepted {
            delta_id: details.delta_id,
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
