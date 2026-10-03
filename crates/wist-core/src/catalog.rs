use crate::collection::{check_binding, name_formed, names};
use crate::constants::CATALOG_FILE_READ_MAX_BYTES;
use crate::crypto::PublicKey;
use crate::envelope::{canonical_b64u, verify_envelope, version_spelled};
use crate::error::Error;
use crate::item::{canonical_host_formed, hash_formed, members, safe_integer, sha256_hex};
use crate::objects::Publisher;
use crate::publisher_time;
use crate::timestamp::log_seconds;
use serde_json::Value;
use std::cell::RefCell;

const INNER_MEMBERS: [&str; 7] = [
    "wist_version",
    "publisher",
    "collection",
    "generated_at",
    "size",
    "root",
    "tree",
];

pub struct Attempt<'a> {
    declaration: &'a Publisher,
    clock: String,
    clock_skew_seconds: i64,
    catalog_items_max: u64,
}

impl<'a> Attempt<'a> {
    pub fn new(
        declaration: &'a Publisher,
        clock: &str,
        clock_skew_seconds: i64,
        catalog_items_max: i64,
    ) -> Result<Self, Error> {
        if !publisher_time::valid(clock) {
            return Err(Error::Timestamp(format!(
                "clock {clock:?} is not a Publisher timestamp"
            )));
        }
        crate::parameters::validate_value("clock_skew_seconds", clock_skew_seconds)?;
        crate::parameters::validate_value("catalog_items_max", catalog_items_max)?;
        Ok(Attempt {
            declaration,
            clock: clock.to_owned(),
            clock_skew_seconds,
            catalog_items_max: catalog_items_max as u64,
        })
    }

    pub fn declaration(&self) -> &Publisher {
        self.declaration
    }

    pub fn clock(&self) -> &str {
        &self.clock
    }

    pub fn clock_skew_seconds(&self) -> i64 {
        self.clock_skew_seconds
    }

    pub fn catalog_items_max(&self) -> u64 {
        self.catalog_items_max
    }
}

pub fn catalog_id(catalog: &Value) -> Result<String, Error> {
    sha256_hex("sha256:", catalog)
}

pub fn check_form(envelope: &Value) -> Result<(), &'static str> {
    members(envelope, &["catalog", "sig"], &[])?;
    let sig = &envelope["sig"];
    members(sig, &["key_id", "alg", "value"], &[])?;
    if !sig["key_id"]
        .as_str()
        .is_some_and(|key_id| key_id.chars().count() <= 64)
        || sig["alg"] != "Ed25519"
        || !sig["value"]
            .as_str()
            .is_some_and(|value| canonical_b64u(value, 64))
    {
        return Err("WIST1-E14");
    }
    let catalog = &envelope["catalog"];
    members(catalog, &INNER_MEMBERS, &[])?;
    if !catalog["wist_version"]
        .as_str()
        .is_some_and(version_spelled)
        || !canonical_host_formed(&catalog["publisher"])
        || !catalog["collection"].as_str().is_some_and(name_formed)
        || !catalog["generated_at"]
            .as_str()
            .is_some_and(|at| log_seconds(at).is_ok())
        || safe_integer(&catalog["size"]).is_none()
        || !hash_formed(&catalog["root"], "sha256:")
        || !hash_formed(&catalog["tree"], "sha256:")
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

fn text<'v>(catalog: &'v Value, member: &str) -> &'v str {
    catalog[member].as_str().expect("a checked member")
}

fn binding(envelope: &Value, declaration: &Publisher) -> Result<PublicKey, &'static str> {
    let catalog = &envelope["catalog"];
    if text(catalog, "publisher") != declaration.domain {
        return Err("WIST1-E02");
    }
    let signer = RefCell::new(None);
    check_binding(
        declaration,
        text(catalog, "collection"),
        text(&envelope["sig"], "key_id"),
        text(catalog, "generated_at"),
        |key| {
            let verified = PublicKey::from_b64u(&key.x)
                .ok()
                .filter(|public| verify_envelope(envelope, "catalog", public).is_ok());
            let found = verified.is_some();
            if found {
                *signer.borrow_mut() = verified;
            }
            found
        },
    )?;
    Ok(signer.into_inner().expect("a verifying binding"))
}

pub fn authenticate(envelope: &Value, declaration: &Publisher) -> Result<PublicKey, &'static str> {
    check_form(envelope)?;
    binding(envelope, declaration)
}

pub fn check_clock(
    generated_at: &str,
    clock: &str,
    clock_skew_seconds: i64,
) -> Result<(), &'static str> {
    let generated_s = log_seconds(generated_at).map_err(|_| "WIST1-E14")?;
    match publisher_time::at_or_after(
        clock,
        i128::from(generated_s) - i128::from(clock_skew_seconds),
    ) {
        Some(true) => Ok(()),
        Some(false) => Err("WIST1-E06"),
        None => Err("WIST1-E14"),
    }
}

fn judge_checked(
    envelope: &Value,
    attempt: &Attempt<'_>,
    fetched_for: Option<(&str, &str)>,
) -> Result<PublicKey, &'static str> {
    let catalog = &envelope["catalog"];
    if fetched_for.is_some_and(|(publisher, collection)| {
        text(catalog, "publisher") != publisher || text(catalog, "collection") != collection
    }) {
        return Err("WIST2-E04");
    }
    if text(catalog, "wist_version").split('.').next() != Some("1") {
        return Err("WIST1-E15");
    }
    if safe_integer(&catalog["size"]).expect("a checked size") > attempt.catalog_items_max {
        return Err("WIST1-E04");
    }
    if !names(attempt.declaration).contains(&text(catalog, "collection")) {
        return Err("WIST1-E03");
    }
    let signer = binding(envelope, attempt.declaration)?;
    check_clock(
        text(catalog, "generated_at"),
        &attempt.clock,
        attempt.clock_skew_seconds,
    )?;
    Ok(signer)
}

/// WIST-1 §7: `WIST1-E05` and then the `WIST1-E14` conditions come first; the order of the
/// others is a choice §7 leaves open.
pub fn judge(envelope: &Value, attempt: &Attempt<'_>) -> Result<PublicKey, &'static str> {
    check_form(envelope)?;
    judge_checked(envelope, attempt, None)
}

pub fn judge_octets(octets: &[u8], attempt: &Attempt<'_>) -> Result<PublicKey, &'static str> {
    judge(&parse(octets)?, attempt)
}

fn parse(octets: &[u8]) -> Result<Value, &'static str> {
    let envelope = crate::json::parse(octets).map_err(|_| "WIST1-E05")?;
    crate::jcs::canonicalize(&envelope).map_err(|_| "WIST1-E05")?;
    Ok(envelope)
}

pub struct Fetch<'a> {
    pub publisher: &'a str,
    pub collection: &'a str,
    pub last_accepted: Option<&'a Value>,
    pub latest: Option<&'a Value>,
    /// WIST-1 §7: from the discovery of a recovery rotation until its settlement, the Catalog ID
    /// and signing key of every Catalog queued under its name or waiting for its Collection.
    pub recovery: Option<&'a [(String, PublicKey)]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pull {
    Failed,
    Refused(&'static str),
    Idempotent,
    Accepted(Option<PublicKey>),
}

impl Pull {
    pub fn as_str(&self) -> &'static str {
        match self {
            Pull::Failed => "failed",
            Pull::Refused(code) => code,
            Pull::Idempotent => "idempotent",
            Pull::Accepted(_) => "accepted",
        }
    }
}

fn same_id(catalog: &Value, other: Option<&Value>) -> bool {
    other.is_some_and(|other| catalog_id(catalog).ok() == catalog_id(other).ok())
}

pub fn order(fetch: &Fetch<'_>, fetched: &Value, signer: Option<&PublicKey>) -> Pull {
    if fetched["publisher"] != fetch.publisher || fetched["collection"] != fetch.collection {
        return Pull::Refused("WIST2-E04");
    }
    let reserved = same_id(fetched, fetch.latest)
        || match fetch.recovery {
            None => same_id(fetched, fetch.last_accepted),
            Some(signed) => catalog_id(fetched).is_ok_and(|id| {
                signed
                    .iter()
                    .any(|(queued, key)| *queued == id && Some(key) == signer)
            }),
        };
    if reserved {
        return Pull::Idempotent;
    }
    let instant = |catalog: &Value| {
        catalog["generated_at"]
            .as_str()
            .and_then(|at| log_seconds(at).ok())
    };
    if let Some(last) = fetch.last_accepted {
        if instant(fetched) <= instant(last) {
            return Pull::Refused("WIST2-E05");
        }
    }
    Pull::Accepted(signer.cloned())
}

/// WIST-2 §8: an answer above the read bound is a failed fetch, neither refused nor accepted.
pub fn read(octets: &[u8], attempt: &Attempt<'_>) -> Pull {
    if octets.len() as u64 > CATALOG_FILE_READ_MAX_BYTES {
        return Pull::Failed;
    }
    match judge_octets(octets, attempt) {
        Ok(signer) => Pull::Accepted(Some(signer)),
        Err(code) => Pull::Refused(code),
    }
}

pub fn pull(fetch: &Fetch<'_>, octets: &[u8], attempt: &Attempt<'_>) -> Pull {
    if octets.len() as u64 > CATALOG_FILE_READ_MAX_BYTES {
        return Pull::Failed;
    }
    let judged = parse(octets).and_then(|envelope| {
        check_form(&envelope)?;
        let signer = judge_checked(
            &envelope,
            attempt,
            Some((fetch.publisher, fetch.collection)),
        )?;
        Ok((envelope, signer))
    });
    match judged {
        Ok((envelope, signer)) => order(fetch, &envelope["catalog"], Some(&signer)),
        Err(code) => Pull::Refused(code),
    }
}
