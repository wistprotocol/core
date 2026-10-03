use crate::catalog::{self, Attempt};
use crate::collection::{names, Limits};
use crate::constants::REMOVAL_RETENTION_DAYS;
use crate::crypto::PublicKey;
use crate::declaration::publisher_of;
use crate::declarations::Declarations;
use crate::error::Error;
use crate::item::{self, Kind, SizeCaps};
use crate::narrowing::stays;
use crate::objects::{Catalog, Publisher};
use crate::suffix_list::{check_epoch_capacity, EpochCaps, SuffixList};
use crate::timestamp::{instant, log_seconds};
use crate::withdrawal::{self, SealedItems, WithdrawalReplay};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const DAY_SECONDS: i64 = 86_400;
const OUT_OF_PLACE: &str = "WIST3-E06";
const EPOCH_REJECTED: &str = "WIST3-E03";

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
    Contract,
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
            Condition::Contract => "contract",
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

#[derive(Debug, Clone, PartialEq)]
pub struct LatestCatalog {
    pub envelope: Value,
    pub catalog_id: String,
    pub sealing_height: u64,
    pub base: bool,
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

#[derive(Debug, Clone, Default)]
pub struct Records {
    records: BTreeMap<(String, String), Record>,
    removals: BTreeMap<(String, String), Removal>,
}

impl Records {
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
        let slot = (publisher.to_owned(), url.to_owned());
        let previous = self.records.remove(&slot);
        match item::kind(item) {
            Kind::Page => {
                self.removals.remove(&slot);
                self.records.insert(
                    slot,
                    Record {
                        item: item.clone(),
                        item_id,
                        collection: collection.to_owned(),
                        catalog: catalog.to_owned(),
                        generated_at: generated_at.to_owned(),
                    },
                );
            }
            Kind::Removed => {
                self.removals.insert(
                    slot,
                    Removal {
                        item_id,
                        catalog: catalog.to_owned(),
                        generated_at: generated_at.to_owned(),
                    },
                );
            }
        }
        Ok(previous)
    }

    pub fn remove(&mut self, publisher: &str, url: &str) -> Option<Record> {
        self.records.remove(&(publisher.to_owned(), url.to_owned()))
    }

    pub fn record(&self, publisher: &str, url: &str) -> Option<&Record> {
        self.records.get(&(publisher.to_owned(), url.to_owned()))
    }

    pub fn removal(&self, publisher: &str, url: &str) -> Option<&Removal> {
        self.removals.get(&(publisher.to_owned(), url.to_owned()))
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

    /// WIST-3 §3.3: a rejected Epoch preserves the accepted prefix and its state.
    pub fn epoch(&mut self, epoch: &Epoch<'_>) -> Result<Outcome, Error> {
        let sealed_at_s = log_seconds(epoch.sealed_at)?;
        if epoch.height != self.next_height {
            return Err(Error::History(format!(
                "replay expects Epoch {}, not {}",
                self.next_height, epoch.height
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
        let limits = epoch.parameters.limits()?;
        let caps = epoch.parameters.size_caps()?;
        let mut declarations: Vec<Value> = epoch
            .entries
            .iter()
            .filter(|entry| entry["type"] == "publisher_declaration")
            .cloned()
            .collect();
        let codes = self.rejections(epoch, &limits, &mut declarations)?;
        if !codes.is_empty() {
            self.declarations
                .seed_head(epoch.height, epoch.root, Some(sealed_at_s));
            self.next_height = epoch.height + 1;
            self.sealed_at_s = Some(sealed_at_s);
            return Ok(Outcome::Rejected {
                codes: codes.into_iter().collect(),
            });
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
        let mut entries = vec![None; epoch.entries.len()];
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "publisher_catalog" {
                let failed = self.judge_catalog(&entry["body"], &context)?;
                if failed.is_empty() {
                    self.apply_catalog(&entry["body"], &context, &mut records_removed)?;
                }
                entries[index] = Some(judgment(failed));
            }
        }
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "publisher_item" {
                let (failed, named) = self.judge_item(&entry["body"], &context)?;
                if let (true, Some(named)) = (failed.is_empty(), named) {
                    self.apply_item(&entry["body"], &named, &context, &mut records_removed)?;
                }
                entries[index] = Some(judgment(failed));
            }
        }
        for (index, entry) in epoch.entries.iter().enumerate() {
            if entry["type"] == "registry_update" {
                entries[index] = self.apply_withdrawal(&entry["body"], &context);
            }
        }
        Ok(Outcome::Accepted {
            entries,
            records_removed,
        })
    }

    fn rejections(
        &self,
        epoch: &Epoch<'_>,
        limits: &Limits,
        declarations: &mut [Value],
    ) -> Result<BTreeSet<String>, Error> {
        let mut codes = BTreeSet::new();
        let formed = epoch.entries.iter().all(|entry| {
            crate::epoch::entry_group(entry).is_ok() && crate::epoch::entry_leaf(entry).is_ok()
        });
        if !formed || crate::epoch::validate_entry_order(epoch.entries).is_err() {
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
            return Ok(codes);
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
        Ok(codes)
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
        let generated_s = log_seconds(text(inner, "generated_at"))?;
        let base = self.latest(publisher, collection).is_some_and(|latest| {
            i128::from(generated_s)
                > i128::from(latest.floor_s())
                    + i128::from(REMOVAL_RETENTION_DAYS) * i128::from(DAY_SECONDS)
        });
        self.latest.insert(
            (publisher.to_owned(), collection.to_owned()),
            LatestCatalog {
                envelope: body.clone(),
                catalog_id: catalog::catalog_id(inner)?,
                sealing_height: context.epoch.height,
                base,
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
        match self.withdrawals.apply(
            context.epoch.height,
            body,
            context.epoch.log_key,
            &self.sealed,
        ) {
            withdrawal::Disposition::Accepted { item_id, .. } => {
                self.duties.remove(&item_id);
                Some(Judgment::Valid)
            }
            withdrawal::Disposition::Rejected(code) => {
                let condition = if code == "WIST4-E04" {
                    Condition::Contract
                } else {
                    Condition::Envelope
                };
                Some(Judgment::Ignored(vec![Failure { condition, code }]))
            }
            withdrawal::Disposition::NotWithdrawal => None,
        }
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
