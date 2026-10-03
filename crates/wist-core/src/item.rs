use crate::collection::judge_scope;
use crate::constants::ITEM_BOUND_BYTES;
use crate::crypto::{b64u_decode, b64u_encode, hex_encode};
use crate::declaration::url_in_scope;
use crate::envelope::version_spelled;
use crate::error::Error;
use crate::jcs;
use crate::objects::{Catalog, PageItem, Publisher};
use crate::publisher_time;
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CONTENT_STRUCTURE_OCTETS: u64 = 32;

pub const SALT_MIN_OCTETS: usize = 16;

const SAFE_INTEGER_MAX: f64 = 9_007_199_254_740_991.0;

const PAGE_MEMBERS: [&str; 5] = ["publisher", "url", "observed_at", "payload", "meta"];
const REMOVED_MEMBERS: [&str; 4] = ["publisher", "url", "observed_at", "removed"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeCaps {
    url_cap_bytes: u64,
    extract_cap_bytes: u64,
    links_cap_bytes: u64,
    link_url_cap_bytes: u64,
    summary_cap_bytes: u64,
}

impl SizeCaps {
    pub fn new(
        url_cap_bytes: i64,
        extract_cap_bytes: i64,
        links_cap_bytes: i64,
        link_url_cap_bytes: i64,
        summary_cap_bytes: i64,
    ) -> Result<Self, Error> {
        let values = [
            ("url_cap_bytes", url_cap_bytes),
            ("extract_cap_bytes", extract_cap_bytes),
            ("links_cap_bytes", links_cap_bytes),
            ("link_url_cap_bytes", link_url_cap_bytes),
            ("summary_cap_bytes", summary_cap_bytes),
        ];
        for (name, value) in values {
            crate::parameters::validate_value(name, value)?;
        }
        crate::parameters::validate_combinations(|name| {
            values
                .iter()
                .find(|(named, _)| *named == name)
                .map_or_else(|| suite_default(name), |(_, value)| *value)
        })?;
        Ok(SizeCaps {
            url_cap_bytes: url_cap_bytes as u64,
            extract_cap_bytes: extract_cap_bytes as u64,
            links_cap_bytes: links_cap_bytes as u64,
            link_url_cap_bytes: link_url_cap_bytes as u64,
            summary_cap_bytes: summary_cap_bytes as u64,
        })
    }

    pub fn suite() -> Self {
        let default = |name| suite_default(name) as u64;
        SizeCaps {
            url_cap_bytes: default("url_cap_bytes"),
            extract_cap_bytes: default("extract_cap_bytes"),
            links_cap_bytes: default("links_cap_bytes"),
            link_url_cap_bytes: default("link_url_cap_bytes"),
            summary_cap_bytes: default("summary_cap_bytes"),
        }
    }

    pub fn url_cap_bytes(&self) -> u64 {
        self.url_cap_bytes
    }

    pub fn extract_cap_bytes(&self) -> u64 {
        self.extract_cap_bytes
    }

    pub fn links_cap_bytes(&self) -> u64 {
        self.links_cap_bytes
    }

    pub fn link_url_cap_bytes(&self) -> u64 {
        self.link_url_cap_bytes
    }

    pub fn summary_cap_bytes(&self) -> u64 {
        self.summary_cap_bytes
    }

    pub fn derived_payload_cap(&self) -> u64 {
        self.extract_cap_bytes
            + self.links_cap_bytes
            + self.summary_cap_bytes
            + CONTENT_STRUCTURE_OCTETS
    }

    pub fn item_bound(&self) -> u64 {
        ITEM_BOUND_BYTES + self.url_cap_bytes
    }
}

impl Default for SizeCaps {
    fn default() -> Self {
        SizeCaps::suite()
    }
}

fn suite_default(name: &str) -> i64 {
    crate::parameters::spec(name)
        .and_then(|parameter| parameter.default)
        .expect("a suite default")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Page,
    Removed,
}

pub fn kind(item: &Value) -> Kind {
    if item.get("removed").is_some() {
        Kind::Removed
    } else {
        Kind::Page
    }
}

pub(crate) fn safe_integer_value(value: f64) -> bool {
    value.is_finite() && value.fract() == 0.0 && (0.0..=SAFE_INTEGER_MAX).contains(&value)
}

pub(crate) fn safe_integer(value: &Value) -> Option<u64> {
    let number = value.as_f64()?;
    safe_integer_value(number).then_some(number as u64)
}

pub(crate) fn jcs_octets(value: &Value) -> Result<u64, Error> {
    Ok(jcs::canonicalize(value)?.len() as u64)
}

fn string_octets(value: &str) -> u64 {
    jcs_octets(&Value::String(value.to_owned())).expect("a string is canonicalizable")
}

pub(crate) fn sha256_hex(prefix: &str, value: &Value) -> Result<String, Error> {
    Ok(format!(
        "{prefix}{}",
        hex_encode(&Sha256::digest(jcs::canonicalize(value)?))
    ))
}

pub fn item_id(item: &Value) -> Result<String, Error> {
    sha256_hex("sha256:", item)
}

pub fn payload_name(item: &Value) -> Result<String, Error> {
    sha256_hex("", item)
}

pub fn key(url: &str) -> [u8; 32] {
    let canonical = jcs::canonicalize(&serde_json::json!(["page", url]))
        .expect("a string array is canonicalizable");
    Sha256::digest(canonical).into()
}

pub fn leaf(item: &Value) -> Result<[u8; 32], Error> {
    let url = item
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Envelope("an Item's url is a string".into()))?;
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(key(url));
    hasher.update(Sha256::digest(jcs::canonicalize(item)?));
    Ok(hasher.finalize().into())
}

pub fn root(items: &[Value]) -> Result<[u8; 32], Error> {
    let mut keyed = items
        .iter()
        .map(|item| {
            let leaf = leaf(item)?;
            Ok((key(item["url"].as_str().expect("a url leaf() read")), leaf))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    keyed.sort_by_key(|(key, _)| *key);
    let leaves: Vec<[u8; 32]> = keyed.into_iter().map(|(_, leaf)| leaf).collect();
    Ok(crate::merkle::merkle_root(&leaves))
}

pub(crate) fn hash_formed(value: &Value, prefix: &str) -> bool {
    value
        .as_str()
        .and_then(|s| s.strip_prefix(prefix))
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

pub(crate) fn canonical_host_formed(value: &Value) -> bool {
    value.as_str().is_some_and(|host| {
        crate::host::canonical_host(host).is_ok_and(|canonical| canonical == host)
    })
}

pub(crate) fn members<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, &'static str> {
    let map = value.as_object().ok_or("WIST1-E14")?;
    if required.iter().any(|name| !map.contains_key(*name))
        || map
            .keys()
            .any(|name| !required.contains(&name.as_str()) && !optional.contains(&name.as_str()))
    {
        return Err("WIST1-E14");
    }
    Ok(map)
}

fn scalar_values_at_most(value: &Value, bound: usize) -> bool {
    value.as_str().is_some_and(|s| s.chars().count() <= bound)
}

fn language_tag(value: &Value) -> bool {
    let Some(tag) = value.as_str() else {
        return false;
    };
    let mut parts = tag.split('-');
    let primary = parts.next().unwrap_or_default();
    (2..=3).contains(&primary.len())
        && primary.bytes().all(|b| b.is_ascii_lowercase())
        && parts.all(|part| {
            (1..=8).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

fn check_commitment_form(payload: &Value) -> Result<(), &'static str> {
    members(payload, &["commitment", "alg", "bytes"], &[])?;
    if !hash_formed(&payload["commitment"], "hmac-sha256:")
        || payload["alg"] != "HMAC-SHA256"
        || safe_integer(&payload["bytes"]).is_none()
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

fn check_meta_form(meta: &Value) -> Result<(), &'static str> {
    let map = members(meta, &["lang"], &["topics", "license"])?;
    if !language_tag(&meta["lang"]) {
        return Err("WIST1-E14");
    }
    if let Some(topics) = map.get("topics") {
        let topics = topics.as_array().ok_or("WIST1-E14")?;
        if topics.len() > 10 || !topics.iter().all(|topic| scalar_values_at_most(topic, 64)) {
            return Err("WIST1-E14");
        }
    }
    if map
        .get("license")
        .is_some_and(|license| !scalar_values_at_most(license, 64))
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

pub fn check_form(item: &Value) -> Result<(), &'static str> {
    let removed = kind(item) == Kind::Removed;
    let required: &[&str] = if removed {
        &REMOVED_MEMBERS
    } else {
        &PAGE_MEMBERS
    };
    members(item, required, &[])?;
    if removed && item["removed"] != Value::Bool(true) {
        return Err("WIST1-E14");
    }
    if !canonical_host_formed(&item["publisher"])
        || !item["url"].is_string()
        || !item["observed_at"]
            .as_str()
            .is_some_and(publisher_time::valid)
    {
        return Err("WIST1-E14");
    }
    if !removed {
        check_commitment_form(&item["payload"])?;
        check_meta_form(&item["meta"])?;
    }
    Ok(())
}

pub fn check_observed_at(observed_at: &str, generated_at: &str) -> Result<(), &'static str> {
    match publisher_time::compare(observed_at, generated_at) {
        Some(std::cmp::Ordering::Greater) => Err("WIST1-E06"),
        Some(_) => Ok(()),
        None => Err("WIST1-E14"),
    }
}

/// WIST-1 §7: the `WIST1-E14` conditions come first; the order of the others is a choice §7 leaves
/// open.
pub fn judge(
    item: &Value,
    catalog: &Catalog,
    declaration: &Publisher,
    caps: &SizeCaps,
) -> Result<(), &'static str> {
    check_form(item)?;
    let url = item["url"].as_str().expect("a checked url");
    if !url_in_scope(
        url,
        &declaration.domain,
        declaration.subdomain_scope.as_deref().unwrap_or(&[]),
    ) {
        return Err("WIST1-E03");
    }
    judge_scope(declaration, &catalog.collection, url)?;
    let page = kind(item) == Kind::Page;
    if page && string_octets(url) > caps.url_cap_bytes {
        return Err("WIST1-E11");
    }
    if page
        && safe_integer(&item["payload"]["bytes"]).expect("checked bytes")
            > caps.derived_payload_cap()
    {
        return Err("WIST1-E04");
    }
    if jcs_octets(item).map_err(|_| "WIST1-E05")? > caps.item_bound() {
        return Err("WIST1-E04");
    }
    check_observed_at(
        item["observed_at"].as_str().expect("a checked observed_at"),
        &catalog.generated_at,
    )?;
    if item["publisher"] != catalog.publisher.as_str() {
        return Err("WIST2-E03");
    }
    Ok(())
}

pub fn decode_salt(salt: &str) -> Option<Vec<u8>> {
    b64u_decode(salt)
        .ok()
        .filter(|octets| octets.len() >= SALT_MIN_OCTETS && b64u_encode(octets) == salt)
}

pub fn commitment(salt: &str, content: &Value) -> Result<String, Error> {
    let salt = decode_salt(salt).ok_or_else(|| {
        Error::Commitment("a salt is canonical base64url of at least 16 octets".into())
    })?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&salt).map_err(|e| Error::Commitment(e.to_string()))?;
    mac.update(&jcs::canonicalize(content)?);
    Ok(format!(
        "hmac-sha256:{}",
        hex_encode(&mac.finalize().into_bytes())
    ))
}

fn check_payload_form(payload: &Value) -> Result<(), &'static str> {
    members(payload, &["wist_version", "salt", "content"], &[])?;
    if !payload["wist_version"]
        .as_str()
        .is_some_and(version_spelled)
        || !payload["salt"]
            .as_str()
            .is_some_and(|salt| decode_salt(salt).is_some())
    {
        return Err("WIST1-E14");
    }
    let content = &payload["content"];
    members(content, &["extract", "links", "summary"], &[])?;
    if !content["extract"].is_string() {
        return Err("WIST1-E14");
    }
    let links = &content["links"];
    members(links, &["total", "urls"], &[])?;
    if safe_integer(&links["total"]).is_none()
        || !links["urls"]
            .as_array()
            .is_some_and(|urls| urls.iter().all(Value::is_string))
    {
        return Err("WIST1-E14");
    }
    let summary = &content["summary"];
    let map = members(summary, &["title"], &["abstract"])?;
    if !scalar_values_at_most(&summary["title"], 256)
        || map
            .get("abstract")
            .is_some_and(|text| !scalar_values_at_most(text, 1500))
    {
        return Err("WIST1-E14");
    }
    Ok(())
}

fn links_hold(links: &Value, publisher: &str) -> bool {
    let urls: Vec<&str> = links["urls"]
        .as_array()
        .expect("checked urls")
        .iter()
        .map(|url| url.as_str().expect("checked url"))
        .collect();
    let distinct: BTreeSet<&str> = urls.iter().copied().collect();
    distinct.len() == urls.len()
        && urls.len() as u64 <= safe_integer(&links["total"]).expect("checked total")
        && urls.iter().all(|url| {
            crate::extract::normalize_url(url, url).as_deref() == Some(*url)
                && crate::extract::external(url, publisher)
        })
}

/// WIST-1 §7: the `WIST1-E14` conditions come first; the order of the others is a choice §7 leaves
/// open.
pub fn judge_payload(
    item: &PageItem,
    payload: &Value,
    caps: &SizeCaps,
) -> Result<(), &'static str> {
    check_payload_form(payload)?;
    if payload["wist_version"]
        .as_str()
        .and_then(|v| v.split('.').next())
        != Some("1")
    {
        return Err("WIST1-E15");
    }
    let content = &payload["content"];
    let octets = |value: &Value| jcs_octets(value).map_err(|_| "WIST1-E05");
    let urls = content["links"]["urls"].as_array().expect("checked urls");
    if octets(&content["extract"])? > caps.extract_cap_bytes
        || octets(&content["links"])? > caps.links_cap_bytes
        || urls
            .iter()
            .any(|url| string_octets(url.as_str().expect("checked url")) > caps.link_url_cap_bytes)
        || octets(&content["summary"])? > caps.summary_cap_bytes
    {
        return Err("WIST1-E04");
    }
    if octets(content)? != item.payload.bytes
        || commitment(payload["salt"].as_str().expect("checked salt"), content)
            .map_err(|_| "WIST1-E14")?
            != item.payload.commitment
    {
        return Err("WIST1-E10");
    }
    if !links_hold(&content["links"], &item.publisher) {
        return Err("WIST1-E12");
    }
    Ok(())
}

pub fn judge_payload_octets(
    item: &PageItem,
    octets: &[u8],
    caps: &SizeCaps,
) -> Result<(), &'static str> {
    let payload = crate::json::parse(octets).map_err(|_| "WIST1-E05")?;
    jcs::canonicalize(&payload).map_err(|_| "WIST1-E05")?;
    judge_payload(item, &payload, caps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_derived_payload_cap_is_38944_octets_under_the_suite_caps() {
        assert_eq!(SizeCaps::suite().derived_payload_cap(), 38_944);
        assert_eq!(SizeCaps::suite().item_bound(), 16_384 + 2048);
        assert_eq!(
            SizeCaps::new(2048, 32_768, 4096, 2048, 2048).unwrap(),
            SizeCaps::suite()
        );
    }

    #[test]
    fn a_salt_is_canonical_base64url_of_at_least_16_octets() {
        assert!(decode_salt(&b64u_encode(&[1; 16])).is_some());
        assert!(decode_salt(&b64u_encode(&[1; 15])).is_none());
        assert!(decode_salt("").is_none());
        let padded = format!("{}=", b64u_encode(&[1; 16]));
        assert!(decode_salt(&padded).is_none());
    }
}
