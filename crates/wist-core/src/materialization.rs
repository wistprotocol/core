//! WIST-3 §7, one URL, one Publisher.
use crate::declaration::url_host;
use crate::error::Error;
use crate::objects::Payload;
use crate::sealing::Record;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn preferred<'a, I>(host: &str, self_declared: bool, records: I) -> Option<&'a str>
where
    I: IntoIterator<Item = (&'a str, bool)>,
{
    let candidates: Vec<&str> = records
        .into_iter()
        .filter(|(_, withdrawn)| !withdrawn)
        .map(|(publisher, _)| publisher)
        .collect();
    if self_declared {
        return candidates.into_iter().find(|domain| *domain == host);
    }
    candidates
        .iter()
        .filter(|domain| is_ancestor(domain, host))
        .max_by_key(|domain| domain.len())
        .or_else(|| candidates.iter().min())
        .copied()
}

pub fn is_ancestor(domain: &str, host: &str) -> bool {
    host.len() > domain.len() + 1
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentTuple {
    pub url: String,
    pub publisher: String,
    pub item_id: String,
    pub observed_at: String,
    pub attested_at: String,
}

impl ContentTuple {
    pub fn of(publisher: &str, url: &str, record: &Record) -> Result<Self, Error> {
        let observed_at = record.item["observed_at"]
            .as_str()
            .ok_or_else(|| Error::Envelope("a page Item's observed_at is a string".into()))?;
        Ok(ContentTuple {
            url: url.to_owned(),
            publisher: publisher.to_owned(),
            item_id: record.item_id.clone(),
            observed_at: observed_at.to_owned(),
            attested_at: record.generated_at.clone(),
        })
    }
}

pub fn materialized<'a, I>(
    records: I,
    self_declared: impl Fn(&str) -> bool,
    withdrawn: impl Fn(&str) -> bool,
) -> Result<Vec<ContentTuple>, Error>
where
    I: IntoIterator<Item = (&'a str, &'a str, &'a Record)>,
{
    let mut by_url: BTreeMap<&str, Vec<(&str, &Record)>> = BTreeMap::new();
    for (publisher, url, record) in records {
        by_url.entry(url).or_default().push((publisher, record));
    }
    let mut tuples = Vec::new();
    for (url, held) in by_url {
        let host = url_host(url);
        let chosen = preferred(
            host,
            self_declared(host),
            held.iter()
                .map(|(publisher, record)| (*publisher, withdrawn(&record.item_id))),
        );
        if let Some((publisher, record)) = held.iter().find(|(p, _)| Some(*p) == chosen) {
            tuples.push(ContentTuple::of(publisher, url, record)?);
        }
    }
    tuples.sort_by(|a, b| (&a.publisher, &a.url).cmp(&(&b.publisher, &b.url)));
    Ok(tuples)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRow {
    pub source_url: String,
    pub target_url: String,
    pub position: u64,
}

pub fn links(source_url: &str, payload: &Payload) -> Vec<LinkRow> {
    payload
        .content
        .links
        .urls
        .iter()
        .enumerate()
        .map(|(position, target_url)| LinkRow {
            source_url: source_url.to_owned(),
            target_url: target_url.clone(),
            position: position as u64,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_candidate_materializes_nothing() {
        assert_eq!(preferred("a.example.com", false, []), None);
        assert_eq!(preferred("a.example.com", true, []), None);
        assert_eq!(
            preferred("a.example.com", false, [("example.com", true)]),
            None
        );
    }

    #[test]
    fn a_host_is_no_ancestor_of_itself() {
        assert!(!is_ancestor("example.com", "example.com"));
        assert!(is_ancestor("example.com", "a.example.com"));
        assert!(!is_ancestor("example.com", "notexample.com"));
    }
}
