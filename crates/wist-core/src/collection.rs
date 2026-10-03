use crate::declaration::{check_key_entry, url_host};
use crate::error::Error;
use crate::extract::normalize_url;
use crate::objects::publisher::{Collection, Match, Publisher, PublisherKey, ScopeEntry};
use crate::publisher_time;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const IMPLICIT_COLLECTION: &str = "default";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    collections_max: u64,
    scope_entries_max: u64,
    url_cap_bytes: u64,
}

impl Limits {
    pub fn new(
        collections_max: i64,
        scope_entries_max: i64,
        url_cap_bytes: i64,
    ) -> Result<Self, Error> {
        for (name, value) in [
            ("collections_max", collections_max),
            ("scope_entries_max", scope_entries_max),
            ("url_cap_bytes", url_cap_bytes),
        ] {
            crate::parameters::validate_value(name, value)?;
        }
        Ok(Limits {
            collections_max: collections_max as u64,
            scope_entries_max: scope_entries_max as u64,
            url_cap_bytes: url_cap_bytes as u64,
        })
    }

    pub fn suite() -> Self {
        let default = |name| {
            crate::parameters::spec(name)
                .and_then(|parameter| parameter.default)
                .expect("a suite default") as u64
        };
        Limits {
            collections_max: default("collections_max"),
            scope_entries_max: default("scope_entries_max"),
            url_cap_bytes: default("url_cap_bytes"),
        }
    }

    pub fn collections_max(&self) -> u64 {
        self.collections_max
    }

    pub fn scope_entries_max(&self) -> u64 {
        self.scope_entries_max
    }

    pub fn url_cap_bytes(&self) -> u64 {
        self.url_cap_bytes
    }
}

impl Default for Limits {
    fn default() -> Self {
        Limits::suite()
    }
}

pub fn name_formed(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

pub(crate) fn check_forms(
    signed: &Value,
    publisher: &Publisher,
    limits: Option<&Limits>,
) -> Result<(), String> {
    let Some(collections) = &publisher.collections else {
        return Ok(());
    };
    if collections.is_empty() {
        return Err("collections must hold one or more Collections".into());
    }
    for (index, collection) in collections.iter().enumerate() {
        let signed = &signed["collections"][index];
        if !name_formed(&collection.name) {
            return Err(format!(
                "Collection name {:?} is malformed",
                collection.name
            ));
        }
        if signed.get("keys").is_some_and(Value::is_null) {
            return Err("a Collection's keys must not be null".into());
        }
        for (position, key) in collection.keys.iter().flatten().enumerate() {
            check_key_entry(key, &signed["keys"][position])?;
        }
        if collection.scope.is_empty() {
            return Err(format!(
                "the Scope of Collection {} must hold one or more entries",
                collection.name
            ));
        }
        for entry in &collection.scope {
            if normalize_url(&entry.url, &entry.url).as_deref() != Some(entry.url.as_str()) {
                return Err(format!(
                    "Scope entry {:?} is not a Normalized URL",
                    entry.url
                ));
            }
            if let Some(limits) = limits {
                let octets = crate::jcs::canonicalize(&Value::String(entry.url.clone()))
                    .map_err(|e| e.to_string())?
                    .len() as u64;
                if octets > limits.url_cap_bytes {
                    return Err(format!(
                        "JCS of Scope entry {:?} exceeds url_cap_bytes",
                        entry.url
                    ));
                }
            }
        }
    }
    Ok(())
}

fn authority(publisher: &Publisher) -> impl Iterator<Item = &str> {
    std::iter::once(publisher.domain.as_str()).chain(
        publisher
            .subdomain_scope
            .iter()
            .flatten()
            .map(String::as_str),
    )
}

fn in_authority(publisher: &Publisher, url: &str) -> bool {
    let host = url_host(url);
    authority(publisher).any(|member| member == host)
}

pub fn entry_covers(entry: &ScopeEntry, url: &str) -> bool {
    match entry.r#match {
        Match::Exact => url == entry.url,
        Match::Prefix => url.as_bytes().starts_with(entry.url.as_bytes()),
    }
}

pub(crate) fn check_rules(publisher: &Publisher, limits: Option<&Limits>) -> Result<(), String> {
    let Some(collections) = &publisher.collections else {
        return Ok(());
    };
    if limits.is_some_and(|limits| collections.len() as u64 > limits.collections_max) {
        return Err("more Collections than collections_max".into());
    }
    let mut names = BTreeSet::new();
    if !collections
        .iter()
        .all(|collection| names.insert(collection.name.as_str()))
    {
        return Err("a Collection name repeats".into());
    }
    for collection in collections {
        if limits.is_some_and(|limits| collection.scope.len() as u64 > limits.scope_entries_max) {
            return Err(format!(
                "the Scope of Collection {} holds more entries than scope_entries_max",
                collection.name
            ));
        }
        if let Some(entry) = collection
            .scope
            .iter()
            .find(|entry| !in_authority(publisher, &entry.url))
        {
            return Err(format!(
                "Scope entry {:?} lies outside the Publisher's authority",
                entry.url
            ));
        }
    }
    for (index, collection) in collections.iter().enumerate() {
        for (other_index, other) in collections.iter().enumerate() {
            if index == other_index {
                continue;
            }
            for entry in &collection.scope {
                if other
                    .scope
                    .iter()
                    .any(|covered| entry_covers(entry, &covered.url))
                {
                    return Err(format!(
                        "a Scope entry of Collection {} covers one of Collection {}",
                        collection.name, other.name
                    ));
                }
            }
        }
    }
    Ok(())
}

struct View<'a> {
    name: &'a str,
    scope: Option<&'a [ScopeEntry]>,
    keys: &'a [PublisherKey],
}

fn views(publisher: &Publisher) -> Vec<View<'_>> {
    match &publisher.collections {
        None => vec![View {
            name: IMPLICIT_COLLECTION,
            scope: None,
            keys: &[],
        }],
        Some(collections) => collections
            .iter()
            .map(|collection: &Collection| View {
                name: &collection.name,
                scope: Some(&collection.scope),
                keys: collection.keys.as_deref().unwrap_or(&[]),
            })
            .collect(),
    }
}

fn view<'a>(publisher: &'a Publisher, name: &str) -> Option<View<'a>> {
    views(publisher).into_iter().find(|view| view.name == name)
}

pub fn names(publisher: &Publisher) -> Vec<&str> {
    views(publisher).into_iter().map(|view| view.name).collect()
}

pub fn covers(publisher: &Publisher, collection: &str, url: &str) -> bool {
    let Some(url) = normalize_url(url, url) else {
        return false;
    };
    match view(publisher, collection) {
        None => false,
        Some(View { scope: None, .. }) => in_authority(publisher, &url),
        Some(View {
            scope: Some(scope), ..
        }) => scope.iter().any(|entry| entry_covers(entry, &url)),
    }
}

pub fn judge_publication(
    declaration: &Publisher,
    collection: &str,
    url: &str,
    key_id: &str,
    instant: &str,
    verifies: impl Fn(&PublisherKey) -> bool,
) -> Result<(), &'static str> {
    check_binding(declaration, collection, key_id, instant, verifies)?;
    judge_scope(declaration, collection, url)
}

pub fn check_binding(
    declaration: &Publisher,
    collection: &str,
    key_id: &str,
    instant: &str,
    verifies: impl Fn(&PublisherKey) -> bool,
) -> Result<(), &'static str> {
    if !publisher_time::valid(instant) {
        return Err("WIST1-E14");
    }
    let named = view(declaration, collection);
    let candidates: Vec<&PublisherKey> = declaration
        .keys
        .iter()
        .chain(named.iter().flat_map(|view| view.keys))
        .filter(|key| key.kid == key_id)
        .filter(|key| crate::crypto::PublicKey::from_b64u(&key.x).is_ok())
        .filter(|key| key.admits(instant) == Some(true))
        .collect();
    if candidates.is_empty() {
        return Err("WIST1-E02");
    }
    if !candidates.into_iter().any(verifies) {
        return Err("WIST1-E01");
    }
    Ok(())
}

pub fn judge_scope(
    declaration: &Publisher,
    collection: &str,
    url: &str,
) -> Result<(), &'static str> {
    if normalize_url(url, url).as_deref() != Some(url) || !covers(declaration, collection, url) {
        return Err("WIST1-E03");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reduction {
    Key,
    KeyWindow,
    Collection,
    ScopeEntry,
    SubdomainScope,
}

impl Reduction {
    pub fn as_str(self) -> &'static str {
        match self {
            Reduction::Key => "key",
            Reduction::KeyWindow => "key_window",
            Reduction::Collection => "collection",
            Reduction::ScopeEntry => "scope_entry",
            Reduction::SubdomainScope => "subdomain_scope",
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Member<'a> {
    Keys,
    RecoveryKeys,
    Collection(&'a str),
}

fn keys_by_member(publisher: &Publisher) -> BTreeMap<Member<'_>, BTreeMap<&str, &PublisherKey>> {
    let mut sources = vec![
        (Member::Keys, publisher.keys.as_slice()),
        (
            Member::RecoveryKeys,
            publisher.recovery_keys.as_deref().unwrap_or(&[]),
        ),
    ];
    sources.extend(
        views(publisher)
            .into_iter()
            .map(|view| (Member::Collection(view.name), view.keys)),
    );
    let mut members: BTreeMap<Member<'_>, BTreeMap<&str, &PublisherKey>> = BTreeMap::new();
    for (member, keys) in sources {
        let held = members.entry(member).or_default();
        for key in keys {
            held.insert(key.x.as_str(), key);
        }
    }
    members
}

fn window_shortened(before: &PublisherKey, after: &PublisherKey) -> bool {
    after.nbf > before.nbf
        || after
            .exp
            .is_some_and(|exp| before.exp.is_none_or(|previous| exp < previous))
}

pub fn authority_reductions(predecessor: &Publisher, declaration: &Publisher) -> Vec<Reduction> {
    let mut found = Vec::new();
    let before = keys_by_member(predecessor);
    let after = keys_by_member(declaration);
    let empty = BTreeMap::new();
    let listed = |member| after.get(member).unwrap_or(&empty);
    if before
        .iter()
        .any(|(member, keys)| keys.keys().any(|x| !listed(member).contains_key(x)))
    {
        found.push(Reduction::Key);
    }
    if before.iter().any(|(member, keys)| {
        keys.iter().any(|(x, key)| {
            listed(member)
                .get(x)
                .is_some_and(|kept| window_shortened(key, kept))
        })
    }) {
        found.push(Reduction::KeyWindow);
    }
    let kept = views(declaration);
    let kept_view = |name: &str| kept.iter().find(|view| view.name == name);
    if views(predecessor)
        .iter()
        .any(|view| kept_view(view.name).is_none())
    {
        found.push(Reduction::Collection);
    }
    let entries = |view: &View<'_>| -> Vec<Option<(String, Match)>> {
        match view.scope {
            None => vec![None],
            Some(scope) => scope
                .iter()
                .map(|entry| Some((entry.url.clone(), entry.r#match)))
                .collect(),
        }
    };
    if views(predecessor).iter().any(|view| {
        let carried = kept_view(view.name).map(entries).unwrap_or_default();
        entries(view).iter().any(|entry| !carried.contains(entry))
    }) {
        found.push(Reduction::ScopeEntry);
    }
    let hosts = |publisher: &Publisher| -> BTreeSet<String> {
        publisher
            .subdomain_scope
            .iter()
            .flatten()
            .cloned()
            .collect()
    };
    if !hosts(predecessor).is_subset(&hosts(declaration)) {
        found.push(Reduction::SubdomainScope);
    }
    found
}

pub fn reduces_authority(predecessor: &Publisher, declaration: &Publisher) -> bool {
    !authority_reductions(predecessor, declaration).is_empty()
}

pub fn last_seal_height(last_sealed_at_discovery: u64, record_seal_epochs: u64) -> Option<u64> {
    last_sealed_at_discovery
        .checked_add(1)?
        .checked_add(record_seal_epochs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_are_not_amended_below_the_suite_floor() {
        assert!(Limits::new(15, 32, 2048).is_err());
        assert!(Limits::new(16, 31, 2048).is_err());
        assert!(Limits::new(16, 32, 32_769).is_err());
        assert_eq!(Limits::new(16, 32, 2048).unwrap(), Limits::suite());
    }

    #[test]
    fn last_seal_height_counts_from_the_first_epoch_after_discovery() {
        assert_eq!(last_seal_height(99, 24), Some(124));
        assert_eq!(last_seal_height(u64::MAX, 0), None);
    }
}
