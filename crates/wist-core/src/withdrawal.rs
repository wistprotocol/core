//! WIST-4 §5.1 `payload_withdrawal` replay.
use crate::crypto::PublicKey;
use crate::error::Error;
use crate::item::Kind;
use crate::objects::{
    RegistryAction, RegistryDetails, RegistryUpdateEnvelope, StateEntry, WithdrawalEntry,
};
use crate::registry_updates::AcceptedUpdates;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
struct Sightings {
    pages: BTreeMap<String, u64>,
    removed: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedItem<'a> {
    pub item_id: &'a str,
    pub publisher: &'a str,
    pub kind: Kind,
    pub height: u64,
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

    /// WIST-4 §5.1: the `record`, `removal` and `withdrawal` tuples show their Items sealed at
    /// or below the Snapshot's Epoch.
    pub fn from_state(epoch_number: u64, entries: &[StateEntry]) -> Result<Self, Error> {
        let mut sealed = Self::resumed();
        for entry in entries {
            match entry {
                StateEntry::Record(entry) => {
                    let item_id = crate::item::item_id(&entry.item)?;
                    sealed.seal(&item_id, &entry.publisher, Kind::Page, epoch_number);
                }
                StateEntry::Removal(entry) => {
                    sealed.seal(
                        &entry.item_id,
                        &entry.publisher,
                        Kind::Removed,
                        epoch_number,
                    );
                }
                StateEntry::Withdrawal(entry) => {
                    sealed.seal(&entry.item_id, &entry.publisher, Kind::Page, epoch_number);
                }
                _ => {}
            }
        }
        Ok(sealed)
    }

    pub fn seal(&mut self, item_id: &str, publisher: &str, kind: Kind, height: u64) {
        let sightings = self.items.entry(item_id.to_owned()).or_default();
        let by_publisher = match kind {
            Kind::Page => &mut sightings.pages,
            Kind::Removed => &mut sightings.removed,
        };
        let earliest = by_publisher.entry(publisher.to_owned()).or_insert(height);
        *earliest = (*earliest).min(height);
    }

    pub fn sealed(&self) -> impl Iterator<Item = SealedItem<'_>> {
        self.items.iter().flat_map(|(item_id, sightings)| {
            let pages = sightings
                .pages
                .iter()
                .map(|(publisher, height)| (publisher, Kind::Page, height));
            let removed = sightings
                .removed
                .iter()
                .map(|(publisher, height)| (publisher, Kind::Removed, height));
            pages
                .chain(removed)
                .map(|(publisher, kind, height)| SealedItem {
                    item_id,
                    publisher,
                    kind,
                    height: *height,
                })
        })
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
            sightings
                .removed
                .values()
                .chain(sightings.pages.values())
                .any(|sealed| *sealed <= height)
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
    Repeated {
        item_id: String,
        withdrawn_height: u64,
    },
    Rejected(&'static str),
    NotWithdrawal,
}

pub(crate) enum Act {
    Judged(Disposition),
    Unauthenticated,
}

#[derive(Debug, Clone, Default)]
pub struct WithdrawalReplay {
    withdrawn: BTreeMap<String, (u64, String)>,
    accepted: AcceptedUpdates,
}

impl WithdrawalReplay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_state(entries: &[StateEntry]) -> Result<Self, Error> {
        let mut replay = Self::new();
        for entry in entries {
            if let StateEntry::Withdrawal(entry) = entry {
                if replay.withdrawn.contains_key(&entry.item_id) {
                    return Err(Error::Snapshot(format!(
                        "two withdrawal tuples of {}",
                        entry.item_id
                    )));
                }
                replay.adopt(&entry.item_id, &entry.publisher, entry.sealing_height);
            }
        }
        replay.accepted = AcceptedUpdates::from_state(entries)?;
        Ok(replay)
    }

    pub fn adopt(&mut self, item_id: &str, publisher: &str, height: u64) {
        self.withdrawn
            .entry(item_id.to_string())
            .or_insert((height, publisher.to_string()));
    }

    pub fn accepted_updates(&self) -> &AcceptedUpdates {
        &self.accepted
    }

    pub fn accept_update(&mut self, update_id: &str, height: u64) -> bool {
        self.accepted.accept(update_id, height)
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
                item_id: item_id.clone(),
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
        match self.act(height, doc, log_key, sealed) {
            Act::Judged(disposition) => disposition,
            Act::Unauthenticated => Disposition::Rejected("WIST4-E11"),
        }
    }

    pub(crate) fn act(
        &mut self,
        height: u64,
        doc: &Value,
        log_key: impl Fn(&str) -> Option<PublicKey>,
        sealed: &SealedItems,
    ) -> Act {
        let rejected = |code| Act::Judged(Disposition::Rejected(code));
        if crate::jcs::canonicalize(doc).is_err() {
            return rejected("WIST1-E05");
        }
        let envelope: RegistryUpdateEnvelope = match serde_json::from_value(doc.clone()) {
            Ok(envelope) => envelope,
            Err(_) => return rejected("WIST4-E11"),
        };
        if let Err(code) = envelope_fields(&envelope) {
            return rejected(code);
        }
        if !matches!(envelope.update.action, RegistryAction::PayloadWithdrawal) {
            return Act::Judged(Disposition::NotWithdrawal);
        }
        let details = match envelope.update.typed_details() {
            Ok(RegistryDetails::PayloadWithdrawal(details)) => details,
            _ => return rejected("WIST4-E04"),
        };
        let Ok(update_id) = crate::item::sha256_hex("sha256:", &doc["update"]) else {
            return rejected("WIST1-E05");
        };
        if self.accepted.is_accepted(&update_id) {
            if let Some(withdrawn_height) = self.withdrawn_height(&details.delta_id) {
                return Act::Judged(Disposition::Repeated {
                    item_id: details.delta_id,
                    withdrawn_height,
                });
            }
        }
        let Some(key) = log_key(&envelope.sig.key_id) else {
            return Act::Unauthenticated;
        };
        if crate::envelope::verify_envelope(doc, "update", &key).is_err() {
            return Act::Unauthenticated;
        }
        let publisher = envelope.update.subject;
        if sealed.meets_contract(&details.delta_id, &publisher, height) == Some(false) {
            return rejected("WIST4-E04");
        }
        self.accepted.accept(&update_id, height);
        let changed = !self.withdrawn.contains_key(&details.delta_id);
        let (withdrawn_height, _) = self
            .withdrawn
            .entry(details.delta_id.clone())
            .or_insert((height, publisher.clone()));
        Act::Judged(Disposition::Accepted {
            item_id: details.delta_id,
            publisher,
            withdrawn_height: *withdrawn_height,
            changed,
        })
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
    use crate::crypto::SigningKey;
    use serde_json::json;

    const ITEM: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn log_key() -> SigningKey {
        SigningKey::from_seed(&[7; 32])
    }

    fn act(legal_basis: &str) -> Value {
        let update = json!({
            "wist_version": "1.0.0",
            "action": "payload_withdrawal",
            "subject": "a.example",
            "effective_at": "2026-08-05T12:00:00Z",
            "details": {"delta_id": ITEM, "legal_basis": legal_basis, "jurisdiction": "BR"}
        });
        crate::envelope::sign_envelope(&update, "update", "log", &log_key()).unwrap()
    }

    fn unverified(mut act: Value) -> Value {
        act["sig"]["value"] = json!(SigningKey::from_seed(&[8; 32]).sign(b"other"));
        act
    }

    fn sealed() -> SealedItems {
        let mut sealed = SealedItems::new();
        sealed.seal(ITEM, "a.example", Kind::Page, 1);
        sealed
    }

    fn apply(replay: &mut WithdrawalReplay, height: u64, act: &Value) -> Disposition {
        let key = log_key().public();
        replay.apply(
            height,
            act,
            |key_id| (key_id == "log").then(|| key.clone()),
            &sealed(),
        )
    }

    #[test]
    fn an_accepted_update_under_a_signature_that_does_not_verify_repeats_at_the_earliest_height() {
        let mut replay = WithdrawalReplay::new();
        assert!(matches!(
            apply(&mut replay, 3, &act("order")),
            Disposition::Accepted {
                withdrawn_height: 3,
                ..
            }
        ));
        assert_eq!(
            apply(&mut replay, 5, &unverified(act("order"))),
            Disposition::Repeated {
                item_id: ITEM.into(),
                withdrawn_height: 3
            }
        );
        assert_eq!(
            apply(&mut replay, 3, &unverified(act("order"))),
            Disposition::Repeated {
                item_id: ITEM.into(),
                withdrawn_height: 3
            }
        );
        assert_eq!(replay.withdrawn_height(ITEM), Some(3));
    }

    #[test]
    fn another_update_withdrawing_a_withdrawn_item_is_judged() {
        let mut replay = WithdrawalReplay::new();
        apply(&mut replay, 3, &act("order"));
        assert_eq!(
            apply(&mut replay, 5, &unverified(act("second order"))),
            Disposition::Rejected("WIST4-E11")
        );
        assert!(matches!(
            apply(&mut replay, 5, &act("second order")),
            Disposition::Accepted {
                withdrawn_height: 3,
                changed: false,
                ..
            }
        ));
    }

    #[test]
    fn a_field_failure_keeps_its_diagnostic_when_the_update_was_accepted() {
        let mut replay = WithdrawalReplay::new();
        apply(&mut replay, 3, &act("order"));
        let mut malformed = act("order");
        malformed["sig"]["alg"] = json!("Ed448");
        assert_eq!(
            apply(&mut replay, 5, &malformed),
            Disposition::Rejected("WIST4-E11")
        );
    }

    #[test]
    fn an_update_only_ignored_before_is_judged_again() {
        let mut replay = WithdrawalReplay::new();
        assert_eq!(
            apply(&mut replay, 3, &unverified(act("order"))),
            Disposition::Rejected("WIST4-E11")
        );
        assert!(matches!(
            apply(&mut replay, 4, &act("order")),
            Disposition::Accepted {
                withdrawn_height: 4,
                ..
            }
        ));
    }

    #[test]
    fn a_replay_resumed_from_withdrawal_tuples_holds_no_accepted_update() {
        let tuples = [StateEntry::Withdrawal(WithdrawalEntry {
            item_id: ITEM.into(),
            publisher: "a.example".into(),
            sealing_height: 3,
        })];
        let mut replay = WithdrawalReplay::from_state(&tuples).unwrap();
        assert_eq!(
            apply(&mut replay, 5, &unverified(act("order"))),
            Disposition::Rejected("WIST4-E11")
        );
    }

    #[test]
    fn a_replay_resumed_from_registry_update_tuples_reads_a_sealing_again_as_repeated() {
        let tuples = [
            StateEntry::Withdrawal(WithdrawalEntry {
                item_id: ITEM.into(),
                publisher: "a.example".into(),
                sealing_height: 3,
            }),
            StateEntry::RegistryUpdate(crate::objects::RegistryUpdateEntry {
                update_id: crate::registry_updates::update_id(&act("order")).unwrap(),
                sealing_height: 3,
            }),
        ];
        let mut replay = WithdrawalReplay::from_state(&tuples).unwrap();
        assert_eq!(
            apply(&mut replay, 5, &unverified(act("order"))),
            Disposition::Repeated {
                item_id: ITEM.into(),
                withdrawn_height: 3
            }
        );
        assert_eq!(replay.accepted_updates().entries().len(), 1);
    }

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
    fn sealed_items_are_enumerated_per_publisher_and_kind_at_their_earliest_height() {
        let mut sealed = SealedItems::new();
        sealed.seal("sha256:a", "a.example", Kind::Page, 4);
        sealed.seal("sha256:a", "a.example", Kind::Page, 2);
        sealed.seal("sha256:a", "b.example", Kind::Page, 5);
        sealed.seal("sha256:r", "a.example", Kind::Removed, 3);
        let found: Vec<(&str, &str, Kind, u64)> = sealed
            .sealed()
            .map(|item| (item.item_id, item.publisher, item.kind, item.height))
            .collect();
        assert_eq!(
            found,
            [
                ("sha256:a", "a.example", Kind::Page, 2),
                ("sha256:a", "b.example", Kind::Page, 5),
                ("sha256:r", "a.example", Kind::Removed, 3),
            ]
        );
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
