use crate::collection::{covers, IMPLICIT_COLLECTION};
use crate::objects::Publisher;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    pub publisher: String,
    pub url: String,
    pub collection: String,
    pub sealed_height: u64,
}

pub fn stays(declaration: &Publisher, url: &str, collection: &str) -> bool {
    match declaration.collections {
        None => collection == IMPLICIT_COLLECTION,
        Some(_) => covers(declaration, collection, url),
    }
}

#[derive(Debug, Clone, Default)]
pub struct Records {
    live: BTreeMap<(String, String), (String, u64)>,
}

impl Records {
    pub fn seal(&mut self, publisher: &str, url: &str, collection: &str, height: u64) {
        self.live.insert(
            (publisher.to_owned(), url.to_owned()),
            (collection.to_owned(), height),
        );
    }

    pub fn narrow(&mut self, publisher: &str, declaration: &Publisher, height: u64) -> Vec<Record> {
        let removed: Vec<Record> = self
            .live()
            .filter(|record| {
                record.publisher == publisher
                    && record.sealed_height < height
                    && !stays(declaration, &record.url, &record.collection)
            })
            .collect();
        for record in &removed {
            self.live
                .remove(&(record.publisher.clone(), record.url.clone()));
        }
        removed
    }

    pub fn live(&self) -> impl Iterator<Item = Record> + '_ {
        self.live
            .iter()
            .map(|((publisher, url), (collection, sealed_height))| Record {
                publisher: publisher.clone(),
                url: url.clone(),
                collection: collection.clone(),
                sealed_height: *sealed_height,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(collections: serde_json::Value) -> Publisher {
        let mut publisher = serde_json::json!({
            "wist_version": "1.0.0",
            "domain": "example.com",
            "seq": 0,
            "keys": [],
        });
        if !collections.is_null() {
            publisher["collections"] = collections;
        }
        serde_json::from_value(publisher).unwrap()
    }

    #[test]
    fn narrowing_at_a_height_keeps_records_sealed_at_that_height() {
        let mut records = Records::default();
        records.seal("example.com", "https://example.com/a", "journal", 1);
        records.seal("example.com", "https://example.com/b", "journal", 2);
        let removed = records.narrow("example.com", &declaration(serde_json::Value::Null), 2);
        assert_eq!(
            removed.iter().map(|r| r.url.as_str()).collect::<Vec<_>>(),
            ["https://example.com/a"]
        );
        assert_eq!(records.live().count(), 1);
    }

    #[test]
    fn a_declaration_without_collections_keeps_default_records_whatever_their_host() {
        let without = declaration(serde_json::Value::Null);
        assert!(stays(&without, "https://elsewhere.example/x", "default"));
        assert!(!stays(&without, "https://example.com/x", "journal"));
        let with = declaration(serde_json::json!([
            {"name": "journal", "scope": [{"url": "https://example.com/j/", "match": "prefix"}]}
        ]));
        assert!(stays(&with, "https://example.com/j/x", "journal"));
        assert!(!stays(&with, "https://example.com/x", "journal"));
        assert!(!stays(&with, "https://example.com/j/x", "default"));
    }

    #[test]
    fn sealing_a_url_again_replaces_its_record_and_collection() {
        let mut records = Records::default();
        records.seal("example.com", "https://example.com/a", "journal", 1);
        records.seal("example.com", "https://example.com/a", "store", 3);
        let live: Vec<Record> = records.live().collect();
        assert_eq!(live.len(), 1);
        assert_eq!(
            (live[0].collection.as_str(), live[0].sealed_height),
            ("store", 3)
        );
    }
}
