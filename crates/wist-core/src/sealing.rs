use crate::catalog::{self, Attempt};
use crate::collection::{names, Limits};
use crate::constants::REMOVAL_RETENTION_DAYS;
use crate::crypto::PublicKey;
use crate::declaration::publisher_of;
use crate::declaration::url_host;
use crate::declarations::Declarations;
use crate::error::Error;
use crate::item::{self, Kind, SizeCaps};
use crate::label::{self, EntryKind, Judging, LabelLookup, Rejection, SealedDispute, SealedLabel};
use crate::materialization::{self, ContentTuple};
use crate::narrowing::stays;
use crate::objects::{
    Catalog, CollectionEntry, DisputeEnvelope, LabelEnvelope, Publisher, RecordEntry, RemovalEntry,
    StateEntry,
};
use crate::registry_updates::AcceptedUpdates;
use crate::suffix_list::{check_epoch_capacity, EpochCaps, SuffixList};
use crate::timestamp::{instant, log_seconds};
use crate::withdrawal::{self, SealedItems, WithdrawalReplay};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const DAY_SECONDS: i64 = 86_400;
const OUT_OF_PLACE: &str = "WIST3-E06";
const EPOCH_REJECTED: &str = "WIST3-E03";
const NOT_JCS: &str = "WIST1-E05";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    values: BTreeMap<&'static str, i64>,
}

impl Parameters {
    pub fn suite() -> Self {
        Parameters {
            values: crate::parameters::PARAMS
                .iter()
                .filter_map(|spec| spec.default.map(|value| (spec.name, value)))
                .collect(),
        }
    }

    pub fn new<'a>(amended: impl IntoIterator<Item = (&'a str, i64)>) -> Result<Self, Error> {
        let mut parameters = Self::suite();
        for (name, value) in amended {
            let spec = crate::parameters::spec(name).ok_or_else(|| {
                Error::Parameter(format!("{name:?} is not a parameter a Log amends"))
            })?;
            crate::parameters::validate_value(name, value)?;
            parameters.values.insert(spec.name, value);
        }
        crate::parameters::validate_combinations(|name| parameters.get(name))?;
        Ok(parameters)
    }

    pub fn from_schedule(schedule: &crate::parameters::Schedule, at_s: i64) -> Result<Self, Error> {
        Self::new(crate::parameters::PARAMS.iter().filter_map(|spec| {
            schedule
                .value_at(spec.name, at_s)
                .map(|value| (spec.name, value))
        }))
    }

    pub fn get(&self, name: &str) -> i64 {
        self.values[name]
    }

    fn limits(&self) -> Result<Limits, Error> {
        Limits::new(
            self.get("collections_max"),
            self.get("scope_entries_max"),
            self.get("url_cap_bytes"),
        )
    }

    fn size_caps(&self) -> Result<SizeCaps, Error> {
        SizeCaps::new(
            self.get("url_cap_bytes"),
            self.get("extract_cap_bytes"),
            self.get("links_cap_bytes"),
            self.get("link_url_cap_bytes"),
            self.get("summary_cap_bytes"),
        )
    }

    fn caps(&self) -> EpochCaps {
        EpochCaps {
            domain_epoch_entries_max: self.get("domain_epoch_entries_max") as u64,
            labeler_epoch_entries_max: self.get("labeler_epoch_entries_max") as u64,
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self::suite()
    }
}

pub struct Epoch<'a> {
    pub height: u64,
    pub root: &'a str,
    pub sealed_at: &'a str,
    pub parameters: &'a Parameters,
    pub suffix_list: Option<&'a SuffixList>,
    pub log_key: &'a dyn Fn(&str) -> Option<PublicKey>,
    pub entries: &'a [Value],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    C1,
    C2,
    C3,
    C4,
    I1,
    I2,
    I3,
    I4,
    I5,
    I6,
    I7,
    Envelope,
    Authentication,
    Contract,
    Eligibility,
    Fields,
    Clock,
    SelfLabel,
    Unsealed,
    Authority,
    Binding,
    Signature,
}

impl Condition {
    pub fn as_str(self) -> &'static str {
        match self {
            Condition::C1 => "C1",
            Condition::C2 => "C2",
            Condition::C3 => "C3",
            Condition::C4 => "C4",
            Condition::I1 => "I1",
            Condition::I2 => "I2",
            Condition::I3 => "I3",
            Condition::I4 => "I4",
            Condition::I5 => "I5",
            Condition::I6 => "I6",
            Condition::I7 => "I7",
            Condition::Envelope => "envelope",
            Condition::Authentication => "authentication",
            Condition::Contract => "contract",
            Condition::Eligibility => "eligibility",
            Condition::Fields => "fields",
            Condition::Clock => "clock",
            Condition::SelfLabel => "self",
            Condition::Unsealed => "unsealed",
            Condition::Authority => "authority",
            Condition::Binding => "binding",
            Condition::Signature => "signature",
        }
    }
}

impl From<Rejection> for Condition {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::Fields => Condition::Fields,
            Rejection::Clock => Condition::Clock,
            Rejection::SelfLabel => Condition::SelfLabel,
            Rejection::Unsealed => Condition::Unsealed,
            Rejection::Authority => Condition::Authority,
            Rejection::Binding => Condition::Binding,
            Rejection::Signature => Condition::Signature,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub condition: Condition,
    pub code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Judgment {
    Valid,
    Ignored(Vec<Failure>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    Narrowing,
    Base,
    RemovedItem,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Cause::Narrowing => "narrowing",
            Cause::Base => "base",
            Cause::RemovedItem => "removed_item",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub publisher: String,
    pub url: String,
    pub cause: Cause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Rejected {
        codes: Vec<String>,
    },
    Accepted {
        entries: Vec<Option<Judgment>>,
        records_removed: Vec<Removed>,
    },
}

/// WIST-3 §7, A base.
pub fn base_against_floor(generated_at: &str, floor: Option<&str>) -> Result<bool, Error> {
    let Some(floor) = floor else {
        return Ok(false);
    };
    let interval = i128::from(REMOVAL_RETENTION_DAYS) * i128::from(DAY_SECONDS);
    Ok(i128::from(log_seconds(generated_at)?) > i128::from(log_seconds(floor)?) + interval)
}

#[derive(Debug, Clone, PartialEq)]
pub struct LatestCatalog {
    pub envelope: Value,
    pub catalog_id: String,
    pub sealing_height: u64,
    pub base: Option<bool>,
}

impl LatestCatalog {
    pub fn floor(&self) -> &str {
        self.envelope["catalog"]["generated_at"]
            .as_str()
            .expect("a valid Catalog's generated_at")
    }

    fn floor_s(&self) -> i64 {
        log_seconds(self.floor()).expect("a valid Catalog's generated_at")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub item: Value,
    pub item_id: String,
    pub collection: String,
    pub catalog: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    pub item_id: String,
    pub catalog: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UrlState<'a> {
    Record(&'a Record),
    Removed(&'a Removal),
}

impl<'a> UrlState<'a> {
    pub fn item_id(&self) -> &'a str {
        match self {
            UrlState::Record(record) => &record.item_id,
            UrlState::Removed(removal) => &removal.item_id,
        }
    }

    pub fn catalog(&self) -> &'a str {
        match self {
            UrlState::Record(record) => &record.catalog,
            UrlState::Removed(removal) => &removal.catalog,
        }
    }

    pub fn generated_at(&self) -> &'a str {
        match self {
            UrlState::Record(record) => &record.generated_at,
            UrlState::Removed(removal) => &removal.generated_at,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Records {
    records: BTreeMap<(String, String), Record>,
    removals: BTreeMap<(String, String), Removal>,
}

fn state_error(message: String) -> Error {
    Error::Snapshot(message)
}

impl Records {
    pub fn from_state(entries: &[StateEntry]) -> Result<Self, Error> {
        let mut records = Records::default();
        for entry in entries {
            match entry {
                StateEntry::Record(entry) => {
                    if entry.item["url"] != entry.url.as_str()
                        || item::kind(&entry.item) != Kind::Page
                    {
                        return Err(state_error(format!(
                            "the record tuple of {} {} does not carry an Item of kind page of its URL",
                            entry.publisher, entry.url
                        )));
                    }
                    let record = Record {
                        item: entry.item.clone(),
                        item_id: item::item_id(&entry.item)?,
                        collection: entry.collection.clone(),
                        catalog: entry.catalog_id.clone(),
                        generated_at: entry.generated_at.clone(),
                    };
                    let slot = (entry.publisher.clone(), entry.url.clone());
                    if records.records.insert(slot, record).is_some() {
                        return Err(state_error(format!(
                            "two record tuples of {} {}",
                            entry.publisher, entry.url
                        )));
                    }
                }
                StateEntry::Removal(entry) => {
                    let removal = Removal {
                        item_id: entry.item_id.clone(),
                        catalog: entry.catalog_id.clone(),
                        generated_at: entry.generated_at.clone(),
                    };
                    let slot = (entry.publisher.clone(), entry.url.clone());
                    if records.removals.insert(slot, removal).is_some() {
                        return Err(state_error(format!(
                            "two removal tuples of {} {}",
                            entry.publisher, entry.url
                        )));
                    }
                }
                _ => {}
            }
        }
        if let Some((publisher, url)) = records
            .removals
            .keys()
            .find(|slot| records.records.contains_key(*slot))
        {
            return Err(state_error(format!(
                "a record tuple and a removal tuple of {publisher} {url}"
            )));
        }
        Ok(records)
    }

    pub fn state_entries(&self) -> Vec<StateEntry> {
        let records = self.records().map(|(publisher, url, record)| {
            StateEntry::Record(RecordEntry {
                publisher: publisher.to_owned(),
                url: url.to_owned(),
                item: record.item.clone(),
                collection: record.collection.clone(),
                catalog_id: record.catalog.clone(),
                generated_at: record.generated_at.clone(),
            })
        });
        let removals = self.removals().map(|(publisher, url, removal)| {
            StateEntry::Removal(RemovalEntry {
                publisher: publisher.to_owned(),
                url: url.to_owned(),
                item_id: removal.item_id.clone(),
                catalog_id: removal.catalog.clone(),
                generated_at: removal.generated_at.clone(),
            })
        });
        records.chain(removals).collect()
    }

    pub fn apply(
        &mut self,
        publisher: &str,
        item: &Value,
        collection: &str,
        catalog: &str,
        generated_at: &str,
    ) -> Result<Option<Record>, Error> {
        let url = item["url"]
            .as_str()
            .ok_or_else(|| Error::Envelope("an Item's url is a string".into()))?;
        let item_id = item::item_id(item)?;
        match item::kind(item) {
            Kind::Page => Ok(self.insert(
                publisher,
                url,
                Record {
                    item: item.clone(),
                    item_id,
                    collection: collection.to_owned(),
                    catalog: catalog.to_owned(),
                    generated_at: generated_at.to_owned(),
                },
            )),
            Kind::Removed => Ok(self.remove_with(
                publisher,
                url,
                Removal {
                    item_id,
                    catalog: catalog.to_owned(),
                    generated_at: generated_at.to_owned(),
                },
            )),
        }
    }

    pub fn insert(&mut self, publisher: &str, url: &str, record: Record) -> Option<Record> {
        let slot = (publisher.to_owned(), url.to_owned());
        self.removals.remove(&slot);
        self.records.insert(slot, record)
    }

    pub fn remove_with(&mut self, publisher: &str, url: &str, removal: Removal) -> Option<Record> {
        let slot = (publisher.to_owned(), url.to_owned());
        let previous = self.records.remove(&slot);
        self.removals.insert(slot, removal);
        previous
    }

    pub fn remove(&mut self, publisher: &str, url: &str) -> Option<Record> {
        self.records.remove(&(publisher.to_owned(), url.to_owned()))
    }

    pub fn remove_collection(&mut self, publisher: &str, collection: &str) -> Vec<String> {
        let gone = self.leaving(publisher, |_, record| record.collection == collection);
        for url in &gone {
            self.remove(publisher, url);
        }
        gone
    }

    pub fn record(&self, publisher: &str, url: &str) -> Option<&Record> {
        self.records.get(&(publisher.to_owned(), url.to_owned()))
    }

    pub fn removal(&self, publisher: &str, url: &str) -> Option<&Removal> {
        self.removals.get(&(publisher.to_owned(), url.to_owned()))
    }

    pub fn state(&self, publisher: &str, url: &str) -> Option<UrlState<'_>> {
        self.record(publisher, url)
            .map(UrlState::Record)
            .or_else(|| self.removal(publisher, url).map(UrlState::Removed))
    }

    pub fn records(&self) -> impl Iterator<Item = (&str, &str, &Record)> {
        self.records
            .iter()
            .map(|((publisher, url), record)| (publisher.as_str(), url.as_str(), record))
    }

    pub fn removals(&self) -> impl Iterator<Item = (&str, &str, &Removal)> {
        self.removals
            .iter()
            .map(|((publisher, url), removal)| (publisher.as_str(), url.as_str(), removal))
    }

    fn leaving(&self, publisher: &str, leaves: impl Fn(&str, &Record) -> bool) -> Vec<String> {
        self.records()
            .filter(|(owner, url, record)| *owner == publisher && leaves(url, record))
            .map(|(_, url, _)| url.to_owned())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDuty {
    pub publisher: String,
    pub url: String,
    pub item_id: String,
    pub until: Option<String>,
}

#[derive(Debug, Clone)]
struct Duty {
    publisher: String,
    url: String,
    record: bool,
    until_s: i64,
}

#[derive(Debug, Clone, Default)]
pub struct Replay {
    declarations: Declarations,
    next_height: u64,
    sealed_at_s: Option<i64>,
    latest: BTreeMap<(String, String), LatestCatalog>,
    records: Records,
    sealed: SealedItems,
    withdrawals: WithdrawalReplay,
    duties: BTreeMap<String, Duty>,
    labels: BTreeMap<String, SealedLabel>,
    disputes: BTreeMap<String, SealedDispute>,
    sealed_labels: BTreeSet<String>,
    resumed_labels: BTreeMap<String, String>,
    resumed: bool,
    walked: Walked,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Walked {
    #[default]
    Unstated,
    FromFirstEpoch,
    Above(u64),
}

struct Leaf {
    octets: Option<Vec<u8>>,
    body_eligible: bool,
    label_eligible: bool,
}

fn leaves(entries: &[Value], stored: &[(usize, &[u8])]) -> Result<Vec<Leaf>, Error> {
    let mut leaves: Vec<Leaf> = entries
        .iter()
        .map(|entry| {
            let octets = crate::jcs::canonicalize(entry).ok();
            let label_eligible = entry["body"]
                .get("label")
                .is_some_and(|label| crate::jcs::canonicalize(label).is_ok());
            Leaf {
                body_eligible: octets.is_some(),
                octets,
                label_eligible,
            }
        })
        .collect();
    for (index, octets) in stored {
        let parsed: Value = serde_json::from_slice(octets)
            .map_err(|e| Error::History(format!("stored Entry {index} is not JSON text: {e}")))?;
        if entries.get(*index) != Some(&parsed) {
            return Err(Error::History(format!(
                "stored Entry {index} does not read as the Entry at its index"
            )));
        }
        leaves[*index] = Leaf {
            octets: Some(octets.to_vec()),
            body_eligible: crate::json::member_eligible(octets, &["body"]) == Some(true),
            label_eligible: crate::json::member_eligible(octets, &["body", "label"]) == Some(true),
        };
    }
    Ok(leaves)
}

/// WIST-3 §3.2, A Label is sealed once.
fn carried_label_id(entry: &Value, leaf: &Leaf) -> Option<String> {
    if entry["type"] != "label" || !leaf.label_eligible {
        return None;
    }
    label::label_id(entry["body"].get("label")?).ok()
}

/// WIST-3 §3.2: the Label IDs an Epoch's `label` Entries carry, valid or ignored.
pub fn carried_label_ids(
    entries: &[Value],
    stored: &[(usize, &[u8])],
) -> Result<Vec<String>, Error> {
    Ok(entries
        .iter()
        .zip(&leaves(entries, stored)?)
        .filter_map(|(entry, leaf)| carried_label_id(entry, leaf))
        .collect())
}

struct Context<'a> {
    epoch: &'a Epoch<'a>,
    sealed_at_s: i64,
    in_force: BTreeMap<String, Publisher>,
    windows: BTreeSet<String>,
    caps: SizeCaps,
}

impl Context<'_> {
    fn in_force(&self, publisher: &str) -> Option<&Publisher> {
        self.in_force.get(publisher)
    }

    fn window_open(&self, publisher: &str) -> bool {
        self.windows.contains(publisher)
    }
}

fn body_text<'v>(entry: &'v Value, outer: &str, member: &str) -> Option<&'v str> {
    entry["body"].get(outer)?.get(member)?.as_str()
}

fn counted_host(entry: &Value) -> Option<(&str, &str)> {
    let kind = entry["type"].as_str()?;
    let (outer, member) = match kind {
        "publisher_catalog" => ("catalog", "publisher"),
        "publisher_item" => ("item", "publisher"),
        "label" => ("label", "labeler"),
        "dispute" => ("dispute", "disputant"),
        _ => return None,
    };
    Some((kind, body_text(entry, outer, member)?))
}

fn text<'v>(value: &'v Value, member: &str) -> &'v str {
    value[member].as_str().expect("a checked member")
}

impl Replay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resumed(
        epoch_number: u64,
        sealed_at: &str,
        declarations: Declarations,
        entries: &[StateEntry],
    ) -> Result<Self, Error> {
        if declarations.head().map(|(height, _)| height) != Some(epoch_number) {
            return Err(Error::History(format!(
                "a Replay resumed at Epoch {epoch_number} needs Declarations headed there"
            )));
        }
        let mut latest = BTreeMap::new();
        let mut resumed_labels = BTreeMap::new();
        for entry in entries {
            if let StateEntry::Label(entry) = entry {
                resumed_labels.insert(entry.label_id.clone(), entry.subject.clone());
            }
            if let StateEntry::Collection(entry) = entry {
                let inner = &entry.envelope["catalog"];
                if inner["publisher"] != entry.publisher.as_str()
                    || inner["collection"] != entry.collection.as_str()
                    || log_seconds(inner["generated_at"].as_str().unwrap_or_default()).is_err()
                {
                    return Err(state_error(format!(
                        "the collection tuple of {} {} does not carry a Catalog of that name",
                        entry.publisher, entry.collection
                    )));
                }
                let slot = (entry.publisher.clone(), entry.collection.clone());
                let adopted = LatestCatalog {
                    envelope: entry.envelope.clone(),
                    catalog_id: catalog::catalog_id(inner)?,
                    sealing_height: entry.sealing_height,
                    base: None,
                };
                if latest.insert(slot, adopted).is_some() {
                    return Err(state_error(format!(
                        "two collection tuples of {} {}",
                        entry.publisher, entry.collection
                    )));
                }
            }
        }
        Ok(Replay {
            declarations,
            next_height: epoch_number + 1,
            sealed_at_s: Some(log_seconds(sealed_at)?),
            latest,
            records: Records::from_state(entries)?,
            sealed: SealedItems::from_state(epoch_number, entries)?,
            withdrawals: WithdrawalReplay::from_state(entries)?,
            duties: BTreeMap::new(),
            labels: BTreeMap::new(),
            disputes: BTreeMap::new(),
            sealed_labels: resumed_labels.keys().cloned().collect(),
            resumed_labels,
            resumed: true,
            walked: Walked::Unstated,
        })
    }

    pub fn state_entries(&self) -> Vec<StateEntry> {
        let collections = self
            .latest_catalogs()
            .map(|(publisher, collection, latest)| {
                StateEntry::Collection(CollectionEntry {
                    publisher: publisher.to_owned(),
                    collection: collection.to_owned(),
                    envelope: latest.envelope.clone(),
                    sealing_height: latest.sealing_height,
                })
            });
        let updates = self
            .registry_updates()
            .entries()
            .into_iter()
            .map(StateEntry::RegistryUpdate);
        updates
            .chain(collections)
            .chain(self.records.state_entries())
            .chain(
                self.withdrawals
                    .entries()
                    .into_iter()
                    .map(StateEntry::Withdrawal),
            )
            .collect()
    }

    pub fn materialized(&self) -> Result<Vec<ContentTuple>, Error> {
        let domains = self.declarations.domains();
        materialization::materialized(
            self.records.records(),
            |host| domains.contains_key(host),
            |item_id| self.withdrawals.is_withdrawn(item_id),
        )
    }

    pub fn materialized_record(&self, url: &str) -> Option<(&str, &Record)> {
        let host = url_host(url);
        let held: Vec<(&str, &Record)> = self
            .records
            .records()
            .filter(|(_, held_url, _)| *held_url == url)
            .map(|(publisher, _, record)| (publisher, record))
            .collect();
        let chosen = materialization::preferred(
            host,
            self.declarations.domains().contains_key(host),
            held.iter().map(|(publisher, record)| {
                (*publisher, self.withdrawals.is_withdrawn(&record.item_id))
            }),
        )?;
        held.into_iter().find(|(publisher, _)| *publisher == chosen)
    }

    pub fn labels(&self) -> impl Iterator<Item = &SealedLabel> {
        self.labels.values()
    }

    pub fn disputes(&self) -> impl Iterator<Item = &SealedDispute> {
        self.disputes.values()
    }

    /// WIST-3 §3.2: every Label ID sealed in an applied Epoch, with its `subject` where the Label
    /// was valid.
    pub fn sealed_label_subjects(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.sealed_labels.iter().map(|label_id| {
            let subject = self
                .labels
                .get(label_id)
                .map(|sealed| sealed.label.subject.as_str())
                .or_else(|| self.resumed_labels.get(label_id).map(String::as_str));
            (label_id.as_str(), subject)
        })
    }

    pub fn sealed_items(&self) -> &SealedItems {
        &self.sealed
    }

    pub fn registry_updates(&self) -> &AcceptedUpdates {
        self.withdrawals.accepted_updates()
    }

    pub fn accept_registry_update(&mut self, update_id: &str, height: u64) -> bool {
        self.withdrawals.accept_update(update_id, height)
    }

    pub fn hold_sealed_label(&mut self, label_id: &str, subject: Option<&str>) {
        if let Some(subject) = subject {
            self.resumed_labels
                .insert(label_id.to_owned(), subject.to_owned());
        }
        self.sealed_labels.insert(label_id.to_owned());
    }

    pub fn hold_sealed_item(&mut self, item_id: &str, publisher: &str, kind: Kind, height: u64) {
        self.sealed.seal(item_id, publisher, kind, height);
    }

    /// WIST-3 §7: the holder has handed this Replay every Label ID and Item sealed above `floor`,
    /// or, with `None`, every one the Log has sealed; WIST-4 §5.1: the Item sightings are then the
    /// holder's alone, none derived from the state tuples.
    pub fn hold_walk_floor(&mut self, floor: Option<u64>) {
        self.walked = match floor {
            None => Walked::FromFirstEpoch,
            Some(floor) => Walked::Above(floor),
        };
        self.sealed.clear();
        self.sealed.set_resumed(floor.is_some());
    }

    fn label_lookup(&self, label_id: &str, stated_height: Option<u64>) -> LabelLookup {
        if let Some(sealed) = self.labels.get(label_id) {
            return LabelLookup::Known {
                subject: sealed.label.subject.clone(),
            };
        }
        if let Some(subject) = self.resumed_labels.get(label_id) {
            return LabelLookup::Known {
                subject: subject.clone(),
            };
        }
        if self.sealed_labels.contains(label_id) {
            return LabelLookup::Absent;
        }
        let below_walk = match self.walked {
            Walked::Unstated => self.resumed,
            Walked::FromFirstEpoch => false,
            Walked::Above(floor) => stated_height.is_some_and(|height| height <= floor),
        };
        if below_walk {
            LabelLookup::Unverifiable
        } else {
            LabelLookup::Absent
        }
    }

    pub fn declarations(&self) -> &Declarations {
        &self.declarations
    }

    pub fn latest(&self, publisher: &str, collection: &str) -> Option<&LatestCatalog> {
        self.latest
            .get(&(publisher.to_owned(), collection.to_owned()))
    }

    pub fn latest_catalogs(&self) -> impl Iterator<Item = (&str, &str, &LatestCatalog)> {
        self.latest.iter().map(|((publisher, collection), latest)| {
            (publisher.as_str(), collection.as_str(), latest)
        })
    }

    pub fn records(&self) -> &Records {
        &self.records
    }

    pub fn withdrawals(&self) -> &WithdrawalReplay {
        &self.withdrawals
    }

    pub fn payload_duties(&self, at: &str) -> Result<Vec<PayloadDuty>, Error> {
        if self.resumed {
            return Err(Error::History(
                "the state tuples carry no Epoch that sealed an Item, so a resumed Replay holds no Payload window".into(),
            ));
        }
        let at_s = log_seconds(at)?;
        let mut duties = Vec::new();
        for (item_id, duty) in &self.duties {
            if !duty.record && at_s >= duty.until_s {
                continue;
            }
            duties.push(PayloadDuty {
                publisher: duty.publisher.clone(),
                url: duty.url.clone(),
                item_id: item_id.clone(),
                until: if duty.record {
                    None
                } else {
                    Some(instant(duty.until_s)?)
                },
            });
        }
        duties.sort_by(|a, b| {
            (&a.publisher, &a.url, &a.item_id).cmp(&(&b.publisher, &b.url, &b.item_id))
        });
        Ok(duties)
    }

    pub fn epoch(&mut self, epoch: &Epoch<'_>) -> Result<Outcome, Error> {
        self.epoch_stored(epoch, &[])
    }

    /// WIST-3 §3.3, Rejected Epochs: nothing of a rejected Epoch applies here; its key acts and
    /// their Registry Update IDs are the holder's. `stored` holds the leaf data of each Entry, by
    /// index, whose body is not valid JCS input (WIST-1 §4).
    pub fn epoch_stored(
        &mut self,
        epoch: &Epoch<'_>,
        stored: &[(usize, &[u8])],
    ) -> Result<Outcome, Error> {
        let sealed_at_s = log_seconds(epoch.sealed_at)?;
        self.check_next(epoch.height, sealed_at_s)?;
        let limits = epoch.parameters.limits()?;
        let caps = epoch.parameters.size_caps()?;
        let leaves = leaves(epoch.entries, stored)?;
        let mut declarations: Vec<Value> = epoch
            .entries
            .iter()
            .zip(&leaves)
            .filter(|(entry, leaf)| entry["type"] == "publisher_declaration" && leaf.body_eligible)
            .map(|(entry, _)| entry.clone())
            .collect();
        let (codes, label_ids) = self.rejections(epoch, &leaves, &limits, &mut declarations)?;
        if !codes.is_empty() {
            return Ok(self.rejected(epoch, sealed_at_s, codes.into_iter().collect()));
        }
        let effects = self.declarations.apply_epoch(
            epoch.height,
            epoch.root,
            epoch.sealed_at,
            epoch.parameters.get("recovery_window_days"),
            epoch.parameters.get("declaration_activation_epochs"),
            &limits,
            &declarations,
        )?;
        self.next_height = epoch.height + 1;
        self.sealed_at_s = Some(sealed_at_s);
        self.sealed_labels.extend(label_ids);
        let mut records_removed = Vec::new();
        let mut narrowings: Vec<_> = effects.narrowings().collect();
        narrowings.sort_by(|a, b| a.domain.cmp(&b.domain));
        for transition in narrowings {
            let declaration =
                publisher_of(transition.declaration.envelope()).map_err(Error::History)?;
            let gone = self.records.leaving(&transition.domain, |url, record| {
                !stays(&declaration, url, &record.collection)
            });
            for url in gone {
                self.drop_record(
                    &transition.domain,
                    &url,
                    Cause::Narrowing,
                    &mut records_removed,
                );
            }
        }
        let mut in_force = BTreeMap::new();
        let mut windows = BTreeSet::new();
        for (domain, state) in self.declarations.domains() {
            in_force.insert(
                domain.clone(),
                publisher_of(state.current().envelope()).map_err(Error::History)?,
            );
            if state.window().is_some() {
                windows.insert(domain.clone());
            }
        }
        let context = Context {
            epoch,
            sealed_at_s,
            in_force,
            windows,
            caps,
        };
        let ineligible =
            |condition, code| Some(Judgment::Ignored(vec![Failure { condition, code }]));
        let mut entries = vec![None; epoch.entries.len()];
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "publisher_catalog" {
                if !leaves[index].body_eligible {
                    entries[index] = ineligible(Condition::C1, NOT_JCS);
                    continue;
                }
                let failed = self.judge_catalog(&entry["body"], &context)?;
                if failed.is_empty() {
                    self.apply_catalog(&entry["body"], &context, &mut records_removed)?;
                }
                entries[index] = Some(judgment(failed));
            }
        }
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "publisher_item" {
                if !leaves[index].body_eligible {
                    entries[index] = ineligible(Condition::I1, NOT_JCS);
                    continue;
                }
                let (failed, named) = self.judge_item(&entry["body"], &context)?;
                if let (true, Some(named)) = (failed.is_empty(), named) {
                    self.apply_item(&entry["body"], &named, &context, &mut records_removed)?;
                }
                entries[index] = Some(judgment(failed));
            }
        }
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "registry_update" {
                entries[index] = if leaves[index].body_eligible {
                    self.apply_withdrawal(&entry["body"], &context)
                } else {
                    ineligible(Condition::Eligibility, NOT_JCS)
                };
            }
        }
        let judging = Judging {
            clock_s: sealed_at_s,
            clock_skew_seconds: epoch.parameters.get("clock_skew_seconds"),
            url_cap_bytes: epoch.parameters.get("url_cap_bytes"),
        };
        for kind in [EntryKind::Label, EntryKind::Dispute] {
            for (index, entry) in epoch.entries.iter().enumerate() {
                if entry["type"] != kind.member() {
                    continue;
                }
                let judged = if leaves[index].body_eligible {
                    label::judge_entry(
                        kind,
                        &entry["body"],
                        &judging,
                        |domain| context.in_force(domain),
                        |label_id| {
                            self.label_lookup(label_id, entry["body"]["dispute"]["height"].as_u64())
                        },
                    )
                } else {
                    Err(Rejection::Fields)
                };
                entries[index] = Some(match judged {
                    Ok(()) => {
                        self.apply_label(kind, &entry["body"], epoch.height, index)?;
                        Judgment::Valid
                    }
                    Err(rejection) => Judgment::Ignored(vec![Failure {
                        condition: rejection.into(),
                        code: rejection.code(),
                    }]),
                });
            }
        }
        Ok(Outcome::Accepted {
            entries,
            records_removed,
        })
    }

    /// WIST-3 §3.3, Rejected Epochs: for a whole-Epoch rejection the holder establishes itself,
    /// such as the Epoch-size bound of WIST-4 §5.
    pub fn reject_epoch(
        &mut self,
        epoch: &Epoch<'_>,
        codes: Vec<String>,
    ) -> Result<Outcome, Error> {
        let sealed_at_s = log_seconds(epoch.sealed_at)?;
        self.check_next(epoch.height, sealed_at_s)?;
        Ok(self.rejected(epoch, sealed_at_s, codes))
    }

    fn rejected(&mut self, epoch: &Epoch<'_>, sealed_at_s: i64, codes: Vec<String>) -> Outcome {
        self.declarations
            .seed_head(epoch.height, epoch.root, Some(sealed_at_s));
        self.next_height = epoch.height + 1;
        self.sealed_at_s = Some(sealed_at_s);
        Outcome::Rejected { codes }
    }

    fn check_next(&self, height: u64, sealed_at_s: i64) -> Result<(), Error> {
        if height != self.next_height {
            return Err(Error::History(format!(
                "replay expects Epoch {}, not {}",
                self.next_height, height
            )));
        }
        if self
            .sealed_at_s
            .is_some_and(|previous| sealed_at_s <= previous)
        {
            return Err(Error::History(
                "an Epoch's sealed_at must follow the Epoch before it".into(),
            ));
        }
        Ok(())
    }

    fn rejections(
        &self,
        epoch: &Epoch<'_>,
        leaves: &[Leaf],
        limits: &Limits,
        declarations: &mut [Value],
    ) -> Result<(BTreeSet<String>, Vec<String>), Error> {
        let mut codes = BTreeSet::new();
        let mut order = Vec::with_capacity(leaves.len());
        for (entry, leaf) in epoch.entries.iter().zip(leaves) {
            let group = crate::epoch::entry_group(entry).ok();
            let octets = leaf
                .octets
                .as_deref()
                .filter(|octets| crate::tiles::check_entry_bytes(octets.len() as u64).is_ok());
            match (group, octets) {
                (Some(group), Some(octets)) => {
                    order.push((group, crate::merkle::leaf_hash(octets)));
                }
                _ => {
                    codes.insert(EPOCH_REJECTED.to_owned());
                }
            }
        }
        if order.windows(2).any(|pair| pair[0] > pair[1]) {
            codes.insert(EPOCH_REJECTED.to_owned());
        }
        if epoch
            .entries
            .iter()
            .zip(leaves)
            .any(|(entry, leaf)| entry["type"] == "publisher_declaration" && !leaf.body_eligible)
        {
            codes.insert(NOT_JCS.to_owned());
        }
        let label_ids: Vec<String> = epoch
            .entries
            .iter()
            .zip(leaves)
            .filter_map(|(entry, leaf)| carried_label_id(entry, leaf))
            .collect();
        let distinct: BTreeSet<&String> = label_ids.iter().collect();
        if distinct.len() != label_ids.len()
            || distinct.iter().any(|id| self.sealed_labels.contains(*id))
        {
            codes.insert(EPOCH_REJECTED.to_owned());
        }
        let mut named = BTreeSet::new();
        for entry in epoch.entries {
            if entry["type"] != "publisher_catalog" {
                continue;
            }
            if let (Some(publisher), Some(collection)) = (
                body_text(entry, "catalog", "publisher"),
                body_text(entry, "catalog", "collection"),
            ) {
                if !named.insert((publisher, collection)) {
                    codes.insert(EPOCH_REJECTED.to_owned());
                }
            }
        }
        if check_epoch_capacity(
            epoch.entries.iter().filter_map(counted_host),
            epoch.suffix_list,
            epoch.parameters.caps(),
        )
        .is_err()
        {
            codes.insert(EPOCH_REJECTED.to_owned());
        }
        if crate::epoch::sort_entries(declarations).is_err() {
            codes.insert(EPOCH_REJECTED.to_owned());
            return Ok((codes, label_ids));
        }
        if let Err(error) = self.declarations.project(
            epoch.sealed_at,
            epoch.parameters.get("recovery_window_days"),
            epoch.parameters.get("declaration_activation_epochs"),
            limits,
            declarations,
        ) {
            match error.code() {
                Some(code) => {
                    codes.insert(code.to_owned());
                }
                None => return Err(error),
            }
        }
        Ok((codes, label_ids))
    }

    fn judge_catalog(&self, body: &Value, context: &Context<'_>) -> Result<Vec<Failure>, Error> {
        let failure = |condition, code| Failure { condition, code };
        if let Err(code) = catalog::check_form(body) {
            return Ok(vec![failure(Condition::C1, code)]);
        }
        let inner = &body["catalog"];
        let publisher = text(inner, "publisher");
        let parameters = context.epoch.parameters;
        let mut failed = Vec::new();
        match context.in_force(publisher) {
            None => failed.push(failure(Condition::C1, "WIST1-E02")),
            Some(declaration) => {
                let attempt = Attempt::new(
                    declaration,
                    context.epoch.sealed_at,
                    parameters.get("clock_skew_seconds"),
                    parameters.get("catalog_items_max"),
                )?;
                if let Err(code) = catalog::judge(body, &attempt) {
                    failed.push(failure(Condition::C1, code));
                    if matches!(code, "WIST1-E05" | "WIST1-E14") {
                        return Ok(failed);
                    }
                }
            }
        }
        if context.window_open(publisher) {
            failed.push(failure(Condition::C2, OUT_OF_PLACE));
        }
        if let Some(latest) = self.latest(publisher, text(inner, "collection")) {
            let generated_s = log_seconds(text(inner, "generated_at"))?;
            let floor_s = latest.floor_s();
            if generated_s <= floor_s {
                failed.push(failure(Condition::C3, OUT_OF_PLACE));
            }
            let unchanged = inner["root"] == latest.envelope["catalog"]["root"]
                && i128::from(generated_s)
                    < i128::from(floor_s) + i128::from(parameters.get("catalog_refresh_seconds"));
            let binds = context.in_force(publisher).is_some_and(|declaration| {
                catalog::authenticate(&latest.envelope, declaration).is_ok()
            });
            if unchanged && binds {
                failed.push(failure(Condition::C4, OUT_OF_PLACE));
            }
        }
        Ok(failed)
    }

    fn apply_catalog(
        &mut self,
        body: &Value,
        context: &Context<'_>,
        records_removed: &mut Vec<Removed>,
    ) -> Result<(), Error> {
        let inner = &body["catalog"];
        let publisher = text(inner, "publisher");
        let collection = text(inner, "collection");
        let base = base_against_floor(
            text(inner, "generated_at"),
            self.latest(publisher, collection).map(LatestCatalog::floor),
        )?;
        self.latest.insert(
            (publisher.to_owned(), collection.to_owned()),
            LatestCatalog {
                envelope: body.clone(),
                catalog_id: catalog::catalog_id(inner)?,
                sealing_height: context.epoch.height,
                base: Some(base),
            },
        );
        if base {
            let gone = self
                .records
                .leaving(publisher, |_, record| record.collection == collection);
            for url in gone {
                self.drop_record(publisher, &url, Cause::Base, records_removed);
            }
        }
        Ok(())
    }

    fn judge_item(
        &self,
        body: &Value,
        context: &Context<'_>,
    ) -> Result<(Vec<Failure>, Option<LatestCatalog>), Error> {
        let failure = |condition, code| Failure { condition, code };
        if let Err(code) = crate::publisher_item::check_form(body) {
            return Ok((vec![failure(Condition::I1, code)], None));
        }
        let Some(named) = self
            .latest
            .values()
            .find(|latest| body["catalog"] == latest.catalog_id.as_str())
        else {
            return Ok((vec![failure(Condition::I3, OUT_OF_PLACE)], None));
        };
        let catalog: Catalog = serde_json::from_value(named.envelope["catalog"].clone())
            .map_err(|e| Error::Envelope(format!("a latest Catalog does not read typed: {e}")))?;
        let item = &body["item"];
        let declaration = context.in_force(&catalog.publisher);
        let mut failed = Vec::new();
        if context.window_open(&catalog.publisher) {
            failed.push(failure(Condition::I2, OUT_OF_PLACE));
        }
        let binding = match declaration {
            None => Err("WIST1-E02"),
            Some(declaration) if !names(declaration).contains(&catalog.collection.as_str()) => {
                Err("WIST1-E03")
            }
            Some(declaration) => catalog::authenticate(&named.envelope, declaration).map(|_| ()),
        };
        if let Err(code) = binding {
            failed.push(failure(Condition::I4, code));
        }
        let conditions = if body["collection"] != catalog.collection.as_str() {
            Err("WIST1-E17")
        } else {
            match declaration {
                None => Err("WIST1-E03"),
                Some(declaration) => item::judge(item, &catalog, declaration, &context.caps),
            }
        };
        if let Err(code) = conditions {
            failed.push(failure(Condition::I5, code));
        }
        if let Err(code) = crate::proof::verify(item, &body["proof"], &catalog) {
            failed.push(failure(Condition::I6, code));
        }
        let item_id = item::item_id(item)?;
        let record = self.records.record(&catalog.publisher, text(item, "url"));
        let out_of_place = match item::kind(item) {
            Kind::Page => {
                record.is_some_and(|record| record.item_id == item_id)
                    || self
                        .withdrawals
                        .withdrawn_height(&item_id)
                        .is_some_and(|withdrawn| withdrawn < context.epoch.height)
            }
            Kind::Removed => record.is_none(),
        };
        if out_of_place {
            failed.push(failure(Condition::I7, OUT_OF_PLACE));
        }
        Ok((failed, Some(named.clone())))
    }

    fn apply_item(
        &mut self,
        body: &Value,
        named: &LatestCatalog,
        context: &Context<'_>,
        records_removed: &mut Vec<Removed>,
    ) -> Result<(), Error> {
        let item = &body["item"];
        let publisher = text(&named.envelope["catalog"], "publisher");
        let url = text(item, "url");
        let kind = item::kind(item);
        let item_id = item::item_id(item)?;
        self.sealed
            .seal(&item_id, publisher, kind, context.epoch.height);
        let previous = self.records.apply(
            publisher,
            item,
            text(body, "collection"),
            &named.catalog_id,
            named.floor(),
        )?;
        if let Some(previous) = previous {
            self.end_duty(&previous.item_id);
        }
        match kind {
            Kind::Page => {
                let until_s = context.sealed_at_s
                    + context.epoch.parameters.get("payload_window_days") * DAY_SECONDS;
                let duty = self.duties.entry(item_id).or_insert_with(|| Duty {
                    publisher: publisher.to_owned(),
                    url: url.to_owned(),
                    record: true,
                    until_s,
                });
                duty.record = true;
                duty.until_s = duty.until_s.max(until_s);
            }
            Kind::Removed => records_removed.push(Removed {
                publisher: publisher.to_owned(),
                url: url.to_owned(),
                cause: Cause::RemovedItem,
            }),
        }
        Ok(())
    }

    fn apply_withdrawal(&mut self, body: &Value, context: &Context<'_>) -> Option<Judgment> {
        let ignored = |condition, code| Some(Judgment::Ignored(vec![Failure { condition, code }]));
        match self.withdrawals.act(
            context.epoch.height,
            body,
            context.epoch.log_key,
            &self.sealed,
        ) {
            withdrawal::Act::Judged(withdrawal::Disposition::Accepted { item_id, .. }) => {
                self.duties.remove(&item_id);
                Some(Judgment::Valid)
            }
            withdrawal::Act::Judged(withdrawal::Disposition::Rejected(code)) => {
                let condition = if code == "WIST4-E04" {
                    Condition::Contract
                } else {
                    Condition::Envelope
                };
                ignored(condition, code)
            }
            withdrawal::Act::Unauthenticated => ignored(Condition::Authentication, "WIST4-E11"),
            withdrawal::Act::Judged(
                withdrawal::Disposition::Repeated { .. } | withdrawal::Disposition::NotWithdrawal,
            ) => None,
        }
    }

    fn apply_label(
        &mut self,
        kind: EntryKind,
        body: &Value,
        height: u64,
        index: usize,
    ) -> Result<(), Error> {
        let malformed = |e: serde_json::Error| Error::Envelope(format!("a valid {kind:?}: {e}"));
        let entry_index = index as u64;
        match kind {
            EntryKind::Label => {
                let envelope: LabelEnvelope =
                    serde_json::from_value(body.clone()).map_err(malformed)?;
                let label_id = label::label_id(&body["label"])
                    .map_err(|_| Error::Envelope("a valid Label has an ID".into()))?;
                self.labels.insert(
                    label_id.clone(),
                    SealedLabel {
                        label: envelope.label,
                        label_id,
                        height,
                        entry_index,
                    },
                );
            }
            EntryKind::Dispute => {
                let envelope: DisputeEnvelope =
                    serde_json::from_value(body.clone()).map_err(malformed)?;
                let dispute_id = label::dispute_id(&body["dispute"])
                    .map_err(|_| Error::Envelope("a valid dispute has an ID".into()))?;
                self.disputes.insert(
                    dispute_id.clone(),
                    SealedDispute {
                        dispute: envelope.dispute,
                        dispute_id,
                        height,
                        entry_index,
                    },
                );
            }
        }
        Ok(())
    }

    fn drop_record(
        &mut self,
        publisher: &str,
        url: &str,
        cause: Cause,
        records_removed: &mut Vec<Removed>,
    ) {
        if let Some(record) = self.records.remove(publisher, url) {
            self.end_duty(&record.item_id);
            records_removed.push(Removed {
                publisher: publisher.to_owned(),
                url: url.to_owned(),
                cause,
            });
        }
    }

    fn end_duty(&mut self, item_id: &str) {
        if let Some(duty) = self.duties.get_mut(item_id) {
            duty.record = false;
        }
    }
}

fn judgment(failed: Vec<Failure>) -> Judgment {
    if failed.is_empty() {
        Judgment::Valid
    } else {
        Judgment::Ignored(failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::RemovalEntry;

    #[test]
    fn a_catalog_is_a_base_only_more_than_180_days_after_a_floor() {
        let floor = Some("2026-01-01T00:00:00Z");
        let base = |generated_at| base_against_floor(generated_at, floor).unwrap();
        assert!(!base("2026-06-30T00:00:00Z"));
        assert!(base("2026-06-30T00:00:01Z"));
        assert!(!base("2026-01-01T00:00:00Z"));
        assert!(!base_against_floor("2027-01-01T00:00:00Z", None).unwrap());
        assert!(base_against_floor("not an instant", floor).is_err());
        assert!(base_against_floor("2026-06-30T00:00:01Z", Some("not an instant")).is_err());
    }

    fn removal_tuple(url: &str) -> StateEntry {
        StateEntry::Removal(RemovalEntry {
            publisher: "example.com".into(),
            url: url.into(),
            item_id: format!("sha256:{}", "a".repeat(64)),
            catalog_id: format!("sha256:{}", "b".repeat(64)),
            generated_at: "2026-10-01T00:00:00Z".into(),
        })
    }

    fn record_tuple(url: &str, item_url: &str) -> StateEntry {
        StateEntry::Record(RecordEntry {
            publisher: "example.com".into(),
            url: url.into(),
            item: serde_json::json!({
                "publisher": "example.com",
                "url": item_url,
                "observed_at": "2026-10-01T00:00:00Z",
                "payload": {"commitment": "hmac-sha256:00", "alg": "HMAC-SHA256", "bytes": 1}
            }),
            collection: "default".into(),
            catalog_id: format!("sha256:{}", "b".repeat(64)),
            generated_at: "2026-10-01T00:00:00Z".into(),
        })
    }

    #[test]
    fn records_from_state_round_trip_their_tuples() {
        let tuples = vec![
            record_tuple("https://example.com/a", "https://example.com/a"),
            removal_tuple("https://example.com/b"),
        ];
        let records = Records::from_state(&tuples).unwrap();
        assert_eq!(
            serde_json::to_value(records.state_entries()).unwrap(),
            serde_json::to_value(&tuples).unwrap()
        );
        assert!(matches!(
            records.state("example.com", "https://example.com/b"),
            Some(UrlState::Removed(_))
        ));
    }

    #[test]
    fn tuples_no_replay_produces_are_refused() {
        let url = "https://example.com/a";
        for tuples in [
            vec![record_tuple(url, url), removal_tuple(url)],
            vec![removal_tuple(url), removal_tuple(url)],
            vec![record_tuple(url, url), record_tuple(url, url)],
            vec![record_tuple(url, "https://example.com/other")],
        ] {
            assert!(Records::from_state(&tuples).is_err(), "{tuples:?}");
        }
    }

    fn empty_epoch<'a>(height: u64, sealed_at: &'a str, entries: &'a [Value]) -> Epoch<'a> {
        static SUITE: std::sync::OnceLock<Parameters> = std::sync::OnceLock::new();
        Epoch {
            height,
            root: "root",
            sealed_at,
            parameters: SUITE.get_or_init(Parameters::suite),
            suffix_list: None,
            log_key: &|_| None,
            entries,
        }
    }

    #[test]
    fn an_entry_over_one_leaf_rejects_its_epoch_and_the_replay_goes_on() {
        let pad = "x".repeat(65_536);
        for kind in ["publisher_declaration", "publisher_catalog", "label"] {
            let mut replay = Replay::new();
            let entries = [serde_json::json!({"type": kind, "body": {"pad": pad}})];
            let outcome = replay
                .epoch(&empty_epoch(0, "2026-10-01T00:00:00Z", &entries))
                .unwrap();
            assert_eq!(
                outcome,
                Outcome::Rejected {
                    codes: vec![EPOCH_REJECTED.to_owned()]
                },
                "{kind}"
            );
            let next = replay
                .epoch(&empty_epoch(1, "2026-10-01T01:00:00Z", &[]))
                .unwrap();
            assert!(matches!(next, Outcome::Accepted { .. }), "{kind}");
        }
    }

    #[test]
    fn an_epoch_its_holder_rejects_applies_nothing_and_the_replay_goes_on() {
        let mut replay = Replay::new();
        let entries = [serde_json::json!({"type": "label", "body": {}})];
        let outcome = replay
            .reject_epoch(
                &empty_epoch(0, "2026-10-01T00:00:00Z", &entries),
                vec![EPOCH_REJECTED.to_owned()],
            )
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Rejected {
                codes: vec![EPOCH_REJECTED.to_owned()]
            }
        );
        assert!(replay.sealed_label_subjects().next().is_none());
        assert!(replay
            .reject_epoch(&empty_epoch(0, "2026-10-01T00:30:00Z", &[]), Vec::new())
            .is_err());
        assert!(replay
            .reject_epoch(&empty_epoch(1, "2026-10-01T00:00:00Z", &[]), Vec::new())
            .is_err());
        let next = replay
            .epoch(&empty_epoch(1, "2026-10-01T01:00:00Z", &[]))
            .unwrap();
        assert!(matches!(next, Outcome::Accepted { .. }));
    }

    #[test]
    fn stored_text_that_does_not_read_as_its_entry_is_refused() {
        let entries = [serde_json::json!({"type": "label", "body": {"a": 2}})];
        let epoch = empty_epoch(0, "2026-10-01T00:00:00Z", &entries);
        let other = br#"{"type": "label", "body": {"a": 1}}"#;
        assert!(Replay::new().epoch_stored(&epoch, &[(0, other)]).is_err());
        let repeated = br#"{"type": "label", "body": {"a": 1, "a": 2}}"#;
        let outcome = Replay::new()
            .epoch_stored(&epoch, &[(0, repeated)])
            .unwrap();
        let Outcome::Accepted { entries, .. } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            entries,
            [Some(Judgment::Ignored(vec![Failure {
                condition: Condition::Fields,
                code: "WIST2-E06"
            }]))]
        );
    }

    #[test]
    fn a_label_id_carried_twice_in_one_epoch_rejects_it() {
        let label = serde_json::json!({"label": {"labeler": "a.example"}, "sig": {}});
        let entries = [
            serde_json::json!({"type": "label", "body": label}),
            serde_json::json!({"type": "label", "body": {"label": label["label"], "sig": 1}}),
        ];
        let mut entries = entries.to_vec();
        crate::epoch::sort_entries(&mut entries).unwrap();
        let outcome = Replay::new()
            .epoch(&empty_epoch(0, "2026-10-01T00:00:00Z", &entries))
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Rejected {
                codes: vec![EPOCH_REJECTED.to_owned()]
            }
        );
    }

    #[test]
    fn accepted_registry_update_ids_resume_from_their_tuples() {
        let mut declarations = Declarations::default();
        declarations.seed_head(3, "root", None);
        let mut replay = Replay::new();
        assert!(replay.accept_registry_update("sha256:a", 2));
        assert!(!replay.accept_registry_update("sha256:a", 3));
        let tuples = replay.state_entries();
        assert_eq!(
            serde_json::to_value(&tuples).unwrap(),
            serde_json::json!([["registry_update", "sha256:a", 2]])
        );
        let resumed = Replay::resumed(3, "2026-10-01T00:00:00Z", declarations, &tuples).unwrap();
        assert_eq!(
            resumed.registry_updates().accepted_height("sha256:a"),
            Some(2)
        );
    }

    #[test]
    fn a_resumed_replay_knows_the_labels_of_its_tuples_and_reads_no_other_as_absent() {
        let mut declarations = Declarations::default();
        declarations.seed_head(3, "root", None);
        let id = format!("sha256:{}", "c".repeat(64));
        let tuples = [StateEntry::Label(crate::objects::LabelEntry {
            labeler: "labeler.example".into(),
            subject: "https://example.com/a".into(),
            name: "wist:spam".into(),
            value: None,
            asserted_at: "2026-10-01T00:00:00Z".into(),
            retracted: false,
            expires_at: None,
            delta: None,
            label_id: id.clone(),
            sealing_height: 2,
        })];
        let resumed = Replay::resumed(3, "2026-10-01T00:00:00Z", declarations, &tuples).unwrap();
        assert_eq!(
            resumed.label_lookup(&id, None),
            LabelLookup::Known {
                subject: "https://example.com/a".into()
            }
        );
        assert!(resumed.sealed_labels.contains(&id));
        assert_eq!(
            resumed.label_lookup("sha256:other", None),
            LabelLookup::Unverifiable
        );
        assert_eq!(Replay::new().label_lookup(&id, None), LabelLookup::Absent);
    }

    #[test]
    fn sealed_label_subjects_hand_another_replay_the_lookups_of_this_one() {
        let mut declarations = Declarations::default();
        declarations.seed_head(3, "root", None);
        let valid = format!("sha256:{}", "a".repeat(64));
        let ignored = format!("sha256:{}", "b".repeat(64));
        let mut held =
            Replay::resumed(3, "2026-10-01T00:00:00Z", declarations.clone(), &[]).unwrap();
        held.hold_sealed_label(&valid, Some("https://example.com/a"));
        held.hold_sealed_label(&ignored, None);
        assert_eq!(
            held.sealed_label_subjects().collect::<Vec<_>>(),
            [
                (valid.as_str(), Some("https://example.com/a")),
                (ignored.as_str(), None)
            ]
        );
        let mut handed = Replay::resumed(3, "2026-10-01T00:00:00Z", declarations, &[]).unwrap();
        for (label_id, subject) in held.sealed_label_subjects() {
            handed.hold_sealed_label(label_id, subject);
        }
        handed.hold_walk_floor(None);
        assert_eq!(
            handed.label_lookup(&valid, None),
            LabelLookup::Known {
                subject: "https://example.com/a".into()
            }
        );
        assert_eq!(handed.label_lookup(&ignored, None), LabelLookup::Absent);
        assert_eq!(
            handed.label_lookup("sha256:other", None),
            LabelLookup::Absent
        );
    }

    #[test]
    fn a_held_label_is_known_to_disputes_and_cannot_be_sealed_again() {
        let mut declarations = Declarations::default();
        declarations.seed_head(3, "root", None);
        let label = serde_json::json!({"label": {"labeler": "a.example"}, "sig": {}});
        let id = label::label_id(&label["label"]).unwrap();
        let mut replay = Replay::resumed(3, "2026-10-01T00:00:00Z", declarations, &[]).unwrap();
        assert_eq!(replay.label_lookup(&id, None), LabelLookup::Unverifiable);
        replay.hold_sealed_label(&id, Some("https://example.com/a"));
        assert_eq!(
            replay.label_lookup(&id, None),
            LabelLookup::Known {
                subject: "https://example.com/a".into()
            }
        );
        assert_eq!(replay.labels().count(), 0);
        let entries = [serde_json::json!({"type": "label", "body": label})];
        let outcome = replay
            .epoch(&empty_epoch(4, "2026-10-01T01:00:00Z", &entries))
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Rejected {
                codes: vec![EPOCH_REJECTED.to_owned()]
            }
        );
    }

    fn resumed_at(height: u64) -> Replay {
        let mut declarations = Declarations::default();
        declarations.seed_head(height, "root", None);
        Replay::resumed(height, "2026-10-01T00:00:00Z", declarations, &[]).unwrap()
    }

    #[test]
    fn a_replay_walked_from_the_first_epoch_reads_unknown_labels_and_items_as_absent() {
        let mut replay = resumed_at(8);
        let unknown = format!("sha256:{}", "d".repeat(64));
        assert_eq!(
            replay
                .sealed_items()
                .meets_contract(&unknown, "example.com", 8),
            None
        );
        replay.hold_walk_floor(None);
        for stated in [None, Some(0), Some(8), Some(9)] {
            assert_eq!(replay.label_lookup(&unknown, stated), LabelLookup::Absent);
        }
        assert_eq!(
            replay
                .sealed_items()
                .meets_contract(&unknown, "example.com", 8),
            Some(false)
        );
        replay.hold_sealed_item(&unknown, "example.com", Kind::Page, 3);
        assert_eq!(
            replay
                .sealed_items()
                .meets_contract(&unknown, "example.com", 8),
            Some(true)
        );
    }

    fn resumed_with_withdrawal_of(item_id: &str, publisher: &str, height: u64) -> Replay {
        let mut declarations = Declarations::default();
        declarations.seed_head(height, "root", None);
        let tuples = [StateEntry::Withdrawal(crate::objects::WithdrawalEntry {
            item_id: item_id.to_owned(),
            publisher: publisher.to_owned(),
            sealing_height: height,
        })];
        Replay::resumed(height, "2026-10-01T00:00:00Z", declarations, &tuples).unwrap()
    }

    #[test]
    fn a_walk_floor_leaves_the_replay_only_the_sightings_its_holder_hands_it() {
        let item = format!("sha256:{}", "e".repeat(64));
        let key = crate::crypto::SigningKey::from_seed(&[7u8; 32]);
        let update = serde_json::json!({
            "wist_version": "1.0.0",
            "action": "payload_withdrawal",
            "subject": "q.example",
            "effective_at": "2026-10-01T00:00:00Z",
            "details": {"delta_id": item, "legal_basis": "court order", "jurisdiction": "EU"},
        });
        let act = crate::envelope::sign_envelope(&update, "update", "log1", &key).unwrap();
        let log_key = |_: &str| Some(key.public());
        let judge = |replay: &Replay| {
            crate::withdrawal::WithdrawalReplay::new().apply(
                9,
                &act,
                log_key,
                replay.sealed_items(),
            )
        };
        let seeded = resumed_with_withdrawal_of(&item, "p.example", 8);
        assert_eq!(
            judge(&seeded),
            crate::withdrawal::Disposition::Rejected("WIST4-E04")
        );
        let mut held = resumed_with_withdrawal_of(&item, "p.example", 8);
        held.hold_walk_floor(Some(8));
        assert!(matches!(
            judge(&held),
            crate::withdrawal::Disposition::Accepted { .. }
        ));
        held.hold_sealed_item(&item, "p.example", Kind::Page, 8);
        assert_eq!(
            judge(&held),
            crate::withdrawal::Disposition::Rejected("WIST4-E04")
        );
    }

    #[test]
    fn a_walk_floor_leaves_unverifiable_only_a_label_stated_at_or_below_it() {
        let mut replay = resumed_at(8);
        replay.hold_walk_floor(Some(5));
        let unknown = format!("sha256:{}", "d".repeat(64));
        assert_eq!(
            replay.label_lookup(&unknown, Some(4)),
            LabelLookup::Unverifiable
        );
        assert_eq!(
            replay.label_lookup(&unknown, Some(5)),
            LabelLookup::Unverifiable
        );
        assert_eq!(replay.label_lookup(&unknown, Some(6)), LabelLookup::Absent);
        assert_eq!(replay.label_lookup(&unknown, None), LabelLookup::Absent);
        assert_eq!(
            replay
                .sealed_items()
                .meets_contract(&unknown, "example.com", 8),
            None
        );
    }

    #[test]
    fn an_ignored_label_held_without_a_subject_is_absent_and_cannot_be_sealed_again() {
        let mut replay = resumed_at(3);
        let label = serde_json::json!({"label": {"labeler": "a.example"}, "sig": {}});
        let id = label::label_id(&label["label"]).unwrap();
        replay.hold_sealed_label(&id, None);
        assert_eq!(replay.label_lookup(&id, Some(1)), LabelLookup::Absent);
        let entries = [serde_json::json!({"type": "label", "body": label})];
        assert_eq!(carried_label_ids(&entries, &[]).unwrap(), [id]);
        let outcome = replay
            .epoch(&empty_epoch(4, "2026-10-01T01:00:00Z", &entries))
            .unwrap();
        assert_eq!(
            outcome,
            Outcome::Rejected {
                codes: vec![EPOCH_REJECTED.to_owned()]
            }
        );
    }

    #[test]
    fn parameters_from_a_schedule_read_each_value_in_force_at_the_instant() {
        let first = log_seconds("2026-10-01T00:00:00Z").unwrap();
        let mut schedule = crate::parameters::Schedule::new(first);
        assert_eq!(
            Parameters::from_schedule(&schedule, first).unwrap(),
            Parameters::suite()
        );
        let amendment = |parameter: &str, value, effective_at_s| crate::parameters::Amendment {
            parameter: parameter.into(),
            value,
            epoch_number: 1,
            entry_index: 0,
            sealed_at_s: first,
            effective_at_s,
        };
        schedule.adopt(amendment("catalog_refresh_seconds", 3600, first + 100));
        let before = Parameters::from_schedule(&schedule, first + 99).unwrap();
        assert_eq!(before.get("catalog_refresh_seconds"), 604_800);
        let at = Parameters::from_schedule(&schedule, first + 100).unwrap();
        assert_eq!(at.get("catalog_refresh_seconds"), 3600);
        assert_eq!(
            at.get("url_cap_bytes"),
            Parameters::suite().get("url_cap_bytes")
        );
        schedule.adopt(amendment("catalog_refresh_seconds", 0, first + 200));
        assert!(Parameters::from_schedule(&schedule, first + 200).is_err());
        assert!(Parameters::from_schedule(&schedule, first + 199).is_ok());
    }

    #[test]
    fn a_resumed_replay_needs_declarations_headed_at_its_epoch() {
        let mut declarations = Declarations::default();
        assert!(Replay::resumed(3, "2026-10-01T00:00:00Z", declarations.clone(), &[]).is_err());
        declarations.seed_head(3, "root", None);
        let replay = Replay::resumed(3, "2026-10-01T00:00:00Z", declarations, &[]).unwrap();
        assert!(replay.payload_duties("2026-10-01T00:00:00Z").is_err());
    }
}
