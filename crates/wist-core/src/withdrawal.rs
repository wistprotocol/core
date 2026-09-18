//! WIST-4 §5.1 replay of `payload_withdrawal` acts: JSON eligibility, the
//! field partition between `WIST4-E11` and `WIST4-E04`, authentication
//! under a Log key valid at the act's Epoch, the sealed-Delta contract and
//! the earliest-Epoch rule every withdrawn Delta reads.
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::objects::{RegistryAction, RegistryDetails, RegistryUpdateEnvelope, WithdrawalEntry};
use serde_json::Value;
use std::collections::BTreeMap;

/// What a replaying party knows about the Delta a withdrawal names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealedDelta {
    /// Sealed at `height` under the signed `publisher`.
    Known { publisher: String, height: u64 },
    /// Not sealed anywhere the party can see, at or below the act.
    Absent,
    /// Sealed below what the party holds, so the contract cannot be
    /// checked; the act is read as consistent (WIST-3 §7 carries no
    /// per-Delta tuple a resuming Consumer could check it against).
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// The act is a valid withdrawal; `withdrawn_height` is the earliest
    /// accepted withdrawal's Epoch, this act's own when `changed`.
    Accepted {
        delta_id: String,
        publisher: String,
        withdrawn_height: u64,
        changed: bool,
    },
    /// The act is ignored: `WIST1-E05`, `WIST4-E11` or `WIST4-E04`.
    Rejected(&'static str),
    /// The act is a governance act of another kind.
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

    /// Adopts a withdrawal a Snapshot tuple or a store already holds.
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

    /// The WIST-3 §7 `withdrawal` tuples, one per withdrawn Delta.
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

    /// Replays one `registry_update` body from its raw octets at `height`.
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

    /// Replays one parsed `registry_update` body at `height`. The caller
    /// has parsed it through `json::parse` so repeated members are gone.
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

/// WIST-4 §5.1's field checks outside any action's contract: release
/// version spelling under major 1, the general `subject` bound, a Log
/// timestamp `effective_at` and a well-formed signature block.
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
