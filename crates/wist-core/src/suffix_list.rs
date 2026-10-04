//! WIST-4 §3.1: Registrable Domains under the Public Suffix List snapshot in force.
use crate::crypto::{hex_encode, PublicKey};
use crate::error::Error;
use crate::objects::{
    RegistryAction, RegistryDetails, RegistryUpdateEnvelope, StateEntry, SuffixListEntry,
};
use crate::registry_updates::AcceptedUpdates;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn identifier(octets: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(octets)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrableDomain {
    pub domain: String,
    pub public_suffix: bool,
}

#[derive(Debug, Clone)]
struct Rule {
    labels: Vec<String>,
    exception: bool,
}

#[derive(Debug, Clone)]
pub struct SuffixList {
    identifier: String,
    bytes: u64,
    rules: Vec<Rule>,
}

impl SuffixList {
    /// WIST-4 §3.1: every rule line of both sections applies; a rule with a label Canonical Host
    /// processing rejects is ignored.
    pub fn parse(octets: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(octets)
            .map_err(|e| Error::Host(format!("suffix list is not UTF-8: {e}")))?;
        let mut rules = Vec::new();
        for line in text.split('\n') {
            let rule = line
                .split(['\t', '\x0b', '\x0c', '\r', ' '])
                .next()
                .unwrap_or_default();
            if rule.is_empty() || rule.starts_with("//") {
                continue;
            }
            let (exception, spelled) = match rule.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, rule),
            };
            let labels: Option<Vec<String>> = spelled
                .split('.')
                .map(|label| {
                    if label == "*" {
                        Some(label.to_string())
                    } else {
                        crate::host::canonical_host(label).ok()
                    }
                })
                .collect();
            if let Some(labels) = labels {
                rules.push(Rule { labels, exception });
            }
        }
        Ok(Self {
            identifier: identifier(octets),
            bytes: octets.len() as u64,
            rules,
        })
    }

    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn registrable_domain(&self, host: &str) -> RegistrableDomain {
        let labels: Vec<&str> = host.split('.').collect();
        let mut prevailing: Option<&Rule> = None;
        for rule in &self.rules {
            if rule.labels.len() > labels.len() {
                continue;
            }
            let matches = rule
                .labels
                .iter()
                .rev()
                .zip(labels.iter().rev())
                .all(|(r, h)| r == "*" || r == h);
            if !matches {
                continue;
            }
            prevailing = Some(match prevailing {
                Some(current) if !prevails(rule, current) => current,
                _ => rule,
            });
        }
        let suffix = match prevailing {
            None => 1,
            Some(rule) => rule.labels.len() - usize::from(rule.exception),
        };
        if suffix >= labels.len() {
            return RegistrableDomain {
                domain: host.to_string(),
                public_suffix: true,
            };
        }
        RegistrableDomain {
            domain: labels[labels.len() - suffix - 1..].join("."),
            public_suffix: false,
        }
    }
}

fn prevails(candidate: &Rule, current: &Rule) -> bool {
    if candidate.exception != current.exception {
        return candidate.exception;
    }
    candidate.labels.len() > current.labels.len()
}

pub fn registrable_domain(host: &str, list: Option<&SuffixList>) -> RegistrableDomain {
    match list {
        Some(list) => list.registrable_domain(host),
        None => RegistrableDomain {
            domain: host.to_string(),
            public_suffix: false,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldFile {
    Bytes(u64),
    Absent,
    Unobtainable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Accepted {
        identifier: String,
        in_force_height: u64,
        changed: bool,
    },
    Repeated {
        identifier: String,
        accepted_height: u64,
    },
    Rejected(&'static str),
    NotSuffixList,
}

#[derive(Debug, Clone, Default)]
pub struct SuffixListReplay {
    accepted: Vec<(u64, String)>,
    updates: AcceptedUpdates,
}

impl SuffixListReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// WIST-3 §7 `suffix_list` tuple.
    pub fn adopt(&mut self, identifier: &str, height: u64) {
        self.accepted.push((height, identifier.to_string()));
    }

    /// WIST-4 §5.1: the `registry_update` tuples hold the IDs accepted up to the Snapshot.
    pub fn from_state(entries: &[StateEntry]) -> Result<Self, Error> {
        let mut replay = Self::new();
        for entry in entries {
            if let StateEntry::SuffixList(entry) = entry {
                if !replay.accepted.is_empty() {
                    return Err(Error::Snapshot("two suffix_list tuples".into()));
                }
                replay.adopt(&entry.identifier, entry.sealing_height);
            }
        }
        replay.updates = AcceptedUpdates::from_state(entries)?;
        Ok(replay)
    }

    pub fn accepted_updates(&self) -> &AcceptedUpdates {
        &self.updates
    }

    pub fn hold_accepted_updates(&mut self, updates: AcceptedUpdates) {
        self.updates = updates;
    }

    pub fn apply(
        &mut self,
        height: u64,
        doc: &Value,
        log_key: impl Fn(&str) -> Option<PublicKey>,
        held: impl Fn(&str) -> HeldFile,
    ) -> Disposition {
        if crate::jcs::canonicalize(doc).is_err() {
            return Disposition::Rejected("WIST1-E05");
        }
        let envelope: RegistryUpdateEnvelope = match serde_json::from_value(doc.clone()) {
            Ok(envelope) => envelope,
            Err(_) => return Disposition::Rejected("WIST4-E11"),
        };
        if let Err(code) = crate::withdrawal::envelope_fields(&envelope) {
            return Disposition::Rejected(code);
        }
        if !matches!(envelope.update.action, RegistryAction::SuffixListUpdate) {
            return Disposition::NotSuffixList;
        }
        let details = match envelope.update.typed_details() {
            Ok(RegistryDetails::SuffixListUpdate(details)) => details,
            _ => return Disposition::Rejected("WIST4-E04"),
        };
        let Ok(update_id) = crate::registry_updates::update_id(doc) else {
            return Disposition::Rejected("WIST1-E05");
        };
        if let Some(accepted_height) = self.updates.accepted_height(&update_id) {
            return Disposition::Repeated {
                identifier: details.sha256,
                accepted_height,
            };
        }
        let Some(key) = log_key(&envelope.sig.key_id) else {
            return Disposition::Rejected("WIST4-E11");
        };
        if crate::envelope::verify_envelope(doc, "update", &key).is_err() {
            return Disposition::Rejected("WIST4-E11");
        }
        match held(&details.sha256) {
            HeldFile::Unobtainable => return Disposition::Rejected("WIST3-E01"),
            HeldFile::Absent => return Disposition::Rejected("WIST4-E04"),
            HeldFile::Bytes(bytes) if bytes != details.bytes => {
                return Disposition::Rejected("WIST4-E04")
            }
            HeldFile::Bytes(_) => {}
        }
        self.updates.accept(&update_id, height);
        if let Some((current, in_force_height)) = self.in_force_after(height) {
            if current == details.sha256 {
                return Disposition::Accepted {
                    identifier: details.sha256,
                    in_force_height,
                    changed: false,
                };
            }
        }
        self.accepted.push((height, details.sha256.clone()));
        Disposition::Accepted {
            identifier: details.sha256,
            in_force_height: height,
            changed: true,
        }
    }

    /// WIST-4 §3.1: named by the most recent accepted act sealed below `height`.
    pub fn in_force_at_epoch(&self, height: u64) -> Option<(&str, u64)> {
        self.accepted
            .iter()
            .rev()
            .find(|(sealed, _)| *sealed < height)
            .map(|(sealed, id)| (id.as_str(), *sealed))
    }

    /// WIST-4 §3.1: in force from Epoch `height`'s `sealed_at` to the next Epoch's, and at Epoch
    /// `height + 1`.
    pub fn in_force_after(&self, height: u64) -> Option<(&str, u64)> {
        self.accepted
            .iter()
            .rev()
            .find(|(sealed, _)| *sealed <= height)
            .map(|(sealed, id)| (id.as_str(), *sealed))
    }

    /// WIST-3 §7.
    pub fn entry_at(&self, tree_size: u64) -> Option<SuffixListEntry> {
        self.in_force_after(tree_size)
            .map(|(identifier, sealing_height)| SuffixListEntry {
                identifier: identifier.to_string(),
                sealing_height,
            })
    }

    pub fn accepted(&self) -> &[(u64, String)] {
        &self.accepted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochCaps {
    pub domain_epoch_entries_max: u64,
    pub labeler_epoch_entries_max: u64,
}

/// WIST-3 §3.2: `entries` pairs each Entry type with its `catalog.publisher`, `item.publisher`,
/// `label.labeler` or `dispute.disputant`; one that is not a Canonical Host counts toward no
/// domain.
pub fn check_epoch_capacity<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    list: Option<&SuffixList>,
    caps: EpochCaps,
) -> Result<(), Error> {
    let mut per_domain: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_labeler: BTreeMap<String, u64> = BTreeMap::new();
    for (kind, host) in entries {
        let labeled = matches!(kind, "label" | "dispute");
        if !labeled && !matches!(kind, "publisher_catalog" | "publisher_item") {
            continue;
        }
        if crate::host::canonical_host(host).ok().as_deref() != Some(host) {
            continue;
        }
        let unit = registrable_domain(host, list).domain;
        let count = per_domain.entry(unit.clone()).or_default();
        *count += 1;
        if *count > caps.domain_epoch_entries_max {
            return Err(Error::Epoch(format!(
                "WIST3-E03 {unit} carries more than {} Entries in one Epoch",
                caps.domain_epoch_entries_max
            )));
        }
        if labeled {
            let count = per_labeler.entry(unit.clone()).or_default();
            *count += 1;
            if *count > caps.labeler_epoch_entries_max {
                return Err(Error::Epoch(format!(
                    "WIST3-E03 {unit} carries more than {} label and dispute Entries in one Epoch",
                    caps.labeler_epoch_entries_max
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "// comment\ncom\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n公司.cn\nbad..rule\n";

    #[test]
    fn derives_registrable_domains() {
        let list = SuffixList::parse(LIST.as_bytes()).unwrap();
        assert_eq!(list.bytes(), LIST.len() as u64);
        let rd = |host: &str| list.registrable_domain(host);
        assert_eq!(rd("a.b.example.com").domain, "example.com");
        assert_eq!(rd("example.com").domain, "example.com");
        assert!(rd("com").public_suffix);
        assert_eq!(rd("alice.github.io").domain, "alice.github.io");
        assert!(rd("github.io").public_suffix);
        assert_eq!(rd("www.ck").domain, "www.ck");
        assert!(rd("test.ck").public_suffix);
        assert_eq!(rd("b.test.ck").domain, "b.test.ck");
        assert_eq!(rd("a.b.unlisted").domain, "b.unlisted");
        assert!(rd("localhost").public_suffix);
        assert_eq!(rd("x.xn--55qx5d.cn").domain, "x.xn--55qx5d.cn");
        assert_eq!(
            registrable_domain("a.example.com", None).domain,
            "a.example.com"
        );
    }

    #[test]
    fn in_force_follows_the_epoch_after_sealing() {
        let mut replay = SuffixListReplay::new();
        replay.adopt("sha256:a", 0);
        replay.adopt("sha256:b", 3);
        assert_eq!(replay.in_force_at_epoch(0), None);
        assert_eq!(replay.in_force_at_epoch(1), Some(("sha256:a", 0)));
        assert_eq!(replay.in_force_at_epoch(3), Some(("sha256:a", 0)));
        assert_eq!(replay.in_force_at_epoch(4), Some(("sha256:b", 3)));
        assert_eq!(replay.entry_at(3).unwrap().sealing_height, 3);
    }

    fn log_key() -> crate::crypto::SigningKey {
        crate::crypto::SigningKey::from_seed(&[7; 32])
    }

    fn snapshot(octets: &str) -> String {
        identifier(octets.as_bytes())
    }

    fn pin(octets: &str) -> Value {
        let update = serde_json::json!({
            "wist_version": "1.0.0",
            "action": "suffix_list_update",
            "subject": snapshot(octets),
            "effective_at": "2026-08-05T12:00:00Z",
            "details": {"sha256": snapshot(octets), "bytes": octets.len()}
        });
        crate::envelope::sign_envelope(&update, "update", "log", &log_key()).unwrap()
    }

    fn unverified(mut act: Value) -> Value {
        act["sig"]["value"] =
            serde_json::json!(crate::crypto::SigningKey::from_seed(&[8; 32]).sign(b"other"));
        act
    }

    fn apply(replay: &mut SuffixListReplay, height: u64, act: &Value) -> Disposition {
        let key = log_key().public();
        replay.apply(
            height,
            act,
            |key_id| (key_id == "log").then(|| key.clone()),
            |id| {
                ["com\n", "org\n"]
                    .into_iter()
                    .find(|octets| snapshot(octets) == id)
                    .map_or(HeldFile::Absent, |octets| {
                        HeldFile::Bytes(octets.len() as u64)
                    })
            },
        )
    }

    #[test]
    fn an_act_sealed_again_after_another_snapshot_applies_nothing() {
        let mut replay = SuffixListReplay::new();
        assert!(matches!(
            apply(&mut replay, 0, &pin("com\n")),
            Disposition::Accepted { changed: true, .. }
        ));
        assert!(matches!(
            apply(&mut replay, 1, &pin("org\n")),
            Disposition::Accepted { changed: true, .. }
        ));
        assert_eq!(
            apply(&mut replay, 2, &pin("com\n")),
            Disposition::Repeated {
                identifier: snapshot("com\n"),
                accepted_height: 0,
            }
        );
        assert_eq!(
            replay.in_force_after(2),
            Some((snapshot("org\n").as_str(), 1))
        );
        assert_eq!(replay.accepted_updates().entries().len(), 2);
    }

    #[test]
    fn an_act_sealed_again_in_its_own_epoch_is_idempotent() {
        let mut replay = SuffixListReplay::new();
        apply(&mut replay, 4, &pin("com\n"));
        assert_eq!(
            apply(&mut replay, 4, &pin("com\n")),
            Disposition::Repeated {
                identifier: snapshot("com\n"),
                accepted_height: 4,
            }
        );
        assert_eq!(replay.accepted().len(), 1);
    }

    #[test]
    fn an_act_sealed_again_rejects_nothing_whatever_its_signature() {
        let mut replay = SuffixListReplay::new();
        apply(&mut replay, 0, &pin("com\n"));
        assert_eq!(
            apply(&mut replay, 3, &unverified(pin("com\n"))),
            Disposition::Repeated {
                identifier: snapshot("com\n"),
                accepted_height: 0,
            }
        );
    }

    #[test]
    fn an_act_sealed_again_that_fails_field_validation_keeps_its_diagnostic() {
        let mut replay = SuffixListReplay::new();
        apply(&mut replay, 0, &pin("com\n"));
        let mut malformed = pin("com\n");
        malformed["sig"]["alg"] = serde_json::json!("Ed448");
        assert_eq!(
            apply(&mut replay, 1, &malformed),
            Disposition::Rejected("WIST4-E11")
        );
    }

    #[test]
    fn a_replay_resumed_from_registry_update_tuples_reads_a_sealing_again_as_repeated() {
        let tuples = [
            StateEntry::SuffixList(SuffixListEntry {
                identifier: snapshot("org\n"),
                sealing_height: 1,
            }),
            StateEntry::RegistryUpdate(crate::objects::RegistryUpdateEntry {
                update_id: crate::registry_updates::update_id(&pin("com\n")).unwrap(),
                sealing_height: 0,
            }),
        ];
        let mut replay = SuffixListReplay::from_state(&tuples).unwrap();
        assert_eq!(
            apply(&mut replay, 5, &pin("com\n")),
            Disposition::Repeated {
                identifier: snapshot("com\n"),
                accepted_height: 0,
            }
        );
        assert_eq!(
            replay.in_force_after(5),
            Some((snapshot("org\n").as_str(), 1))
        );
    }

    #[test]
    fn capacity_counts_per_registrable_domain() {
        let list = SuffixList::parse(LIST.as_bytes()).unwrap();
        let caps = EpochCaps {
            domain_epoch_entries_max: 2,
            labeler_epoch_entries_max: 1,
        };
        let shared = [
            ("publisher_catalog", "a.example.com"),
            ("publisher_item", "b.example.com"),
            ("publisher_item", "c.example.com"),
        ];
        assert!(check_epoch_capacity(shared, Some(&list), caps).is_err());
        assert!(check_epoch_capacity(shared, None, caps).is_ok());
        let labels = [("label", "a.github.io"), ("dispute", "a.github.io")];
        assert!(check_epoch_capacity(labels, Some(&list), caps).is_err());
        let separate = [("label", "a.github.io"), ("label", "b.github.io")];
        assert!(check_epoch_capacity(separate, Some(&list), caps).is_ok());
    }

    #[test]
    fn a_member_that_is_not_a_canonical_host_and_other_entry_types_count_toward_no_domain() {
        let caps = EpochCaps {
            domain_epoch_entries_max: 1,
            labeler_epoch_entries_max: 1,
        };
        let uncounted = [
            ("publisher_item", "a.example.com"),
            ("label", "A.example.com"),
            ("dispute", "a.example.com."),
            ("publisher_catalog", "not a host"),
            ("publisher_declaration", "a.example.com"),
            ("registry_update", "a.example.com"),
        ];
        assert!(check_epoch_capacity(uncounted, None, caps).is_ok());
    }
}
