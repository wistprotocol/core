//! WIST-4 §3.1: Public Suffix List snapshots, the Registrable Domain of a
//! Canonical Host under one, the replay of `suffix_list_update` acts with
//! the snapshot in force at each Epoch, and WIST-3 §3.2's per-domain Epoch
//! capacity counted per Registrable Domain.
use crate::crypto::{hex_encode, PublicKey};
use crate::error::Error;
use crate::objects::{RegistryAction, RegistryDetails, RegistryUpdateEnvelope, SuffixListEntry};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The snapshot identifier of a file: `"sha256:" + hex(SHA-256(octets))`.
pub fn identifier(octets: &[u8]) -> String {
    format!("sha256:{}", hex_encode(&Sha256::digest(octets)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrableDomain {
    pub domain: String,
    /// The host is a listed suffix, a single label or a host a wildcard
    /// rule swallows whole, so the unit is the host itself.
    pub public_suffix: bool,
}

#[derive(Debug, Clone)]
struct Rule {
    labels: Vec<String>,
    exception: bool,
}

/// One Public Suffix List snapshot, its rules in Canonical Host form.
#[derive(Debug, Clone)]
pub struct SuffixList {
    identifier: String,
    bytes: u64,
    rules: Vec<Rule>,
}

impl SuffixList {
    /// Parses the exact octets of a snapshot: every rule line of both
    /// sections, a rule with a label Canonical Host processing rejects
    /// ignored.
    pub fn parse(octets: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(octets)
            .map_err(|e| Error::Host(format!("suffix list is not UTF-8: {e}")))?;
        let mut rules = Vec::new();
        for line in text.split('\n') {
            let Some(rule) = line.split_whitespace().next() else {
                continue;
            };
            if rule.starts_with("//") {
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

    /// The Registrable Domain of a Canonical Host under this snapshot.
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

/// The Registrable Domain of a Canonical Host under the snapshot in force,
/// the host itself while none is.
pub fn registrable_domain(host: &str, list: Option<&SuffixList>) -> RegistrableDomain {
    match list {
        Some(list) => list.registrable_domain(host),
        None => RegistrableDomain {
            domain: host.to_string(),
            public_suffix: false,
        },
    }
}

/// What the replaying party holds under the identifier an act names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldFile {
    /// The file, verified to hash to the identifier, with its octet count.
    Bytes(u64),
    /// No such file: the party that must hold every file it seals under
    /// knows the act fails its contract.
    Absent,
    /// A file the party could not obtain, so the act cannot be checked.
    Unobtainable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// The act is accepted; `in_force_height` is the sealing height of the
    /// act that put the named snapshot in force, this one's when `changed`.
    Accepted {
        identifier: String,
        in_force_height: u64,
        changed: bool,
    },
    /// The act is ignored: `WIST1-E05`, `WIST4-E11` or `WIST4-E04`; or
    /// the named file could not be obtained, `WIST3-E01`, which stops a
    /// Consumer at the act's Epoch.
    Rejected(&'static str),
    /// The act is a governance act of another kind.
    NotSuffixList,
}

/// The accepted `suffix_list_update` acts in Log order.
#[derive(Debug, Clone, Default)]
pub struct SuffixListReplay {
    accepted: Vec<(u64, String)>,
}

impl SuffixListReplay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adopts the WIST-3 §7 `suffix_list` tuple: the snapshot in force
    /// and the height of the act that put it there.
    pub fn adopt(&mut self, identifier: &str, height: u64) {
        self.accepted.push((height, identifier.to_string()));
    }

    /// Replays one `registry_update` body at `height`. `held` answers
    /// what the caller holds under the named identifier.
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

    /// The snapshot in force at Epoch `height`, named by the most recent
    /// accepted act sealed below it, with that act's height.
    pub fn in_force_at_epoch(&self, height: u64) -> Option<(&str, u64)> {
        self.accepted
            .iter()
            .rev()
            .find(|(sealed, _)| *sealed < height)
            .map(|(sealed, id)| (id.as_str(), *sealed))
    }

    /// The snapshot in force once Epoch `height` is sealed: at every
    /// instant from its `sealed_at` to the next Epoch's, and at Epoch
    /// `height + 1`.
    pub fn in_force_after(&self, height: u64) -> Option<(&str, u64)> {
        self.accepted
            .iter()
            .rev()
            .find(|(sealed, _)| *sealed <= height)
            .map(|(sealed, id)| (id.as_str(), *sealed))
    }

    /// The WIST-3 §7 `suffix_list` tuple of a Snapshot at `tree_size`.
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

/// WIST-3 §3.2: an Epoch carries at most `domain_epoch_entries_max`
/// `publisher_delta`, `label` and `dispute` Entries of one Registrable
/// Domain under the snapshot in force at it, and inside that at most
/// `labeler_epoch_entries_max` `label` and `dispute` Entries. `entries`
/// pairs each Entry type with the Canonical Host of its Publisher,
/// Labeler or disputant; a breach is `WIST3-E03`.
pub fn check_epoch_capacity<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    list: Option<&SuffixList>,
    caps: EpochCaps,
) -> Result<(), Error> {
    let mut per_domain: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_labeler: BTreeMap<String, u64> = BTreeMap::new();
    for (kind, host) in entries {
        if !matches!(kind, "publisher_delta" | "label" | "dispute") {
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
        if kind != "publisher_delta" {
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

    #[test]
    fn capacity_counts_per_registrable_domain() {
        let list = SuffixList::parse(LIST.as_bytes()).unwrap();
        let caps = EpochCaps {
            domain_epoch_entries_max: 2,
            labeler_epoch_entries_max: 1,
        };
        let shared = [
            ("publisher_delta", "a.example.com"),
            ("publisher_delta", "b.example.com"),
            ("publisher_delta", "c.example.com"),
        ];
        assert!(check_epoch_capacity(shared, Some(&list), caps).is_err());
        assert!(check_epoch_capacity(shared, None, caps).is_ok());
        let labels = [("label", "a.github.io"), ("dispute", "a.github.io")];
        assert!(check_epoch_capacity(labels, Some(&list), caps).is_err());
        let separate = [("label", "a.github.io"), ("label", "b.github.io")];
        assert!(check_epoch_capacity(separate, Some(&list), caps).is_ok());
    }
}
