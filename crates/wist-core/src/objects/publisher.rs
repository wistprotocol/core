use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// WIST-1 §5.1: `kid` is the RFC 7638 thumbprint; `nbf`/`exp` are NumericDates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    pub nbf: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

/// The last instant a NumericDate denotes, `9999-12-31T23:59:59Z`.
pub const NUMERIC_DATE_MAX: u64 = 253_402_300_799;

impl PublisherKey {
    pub fn new(public_key_b64u: &str, nbf: u64, exp: Option<u64>) -> Self {
        PublisherKey {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x: public_key_b64u.into(),
            kid: thumbprint(public_key_b64u),
            nbf,
            exp,
        }
    }

    pub fn admits(&self, observed_at: &str) -> Option<bool> {
        let after_nbf = crate::publisher_time::at_or_after(observed_at, i128::from(self.nbf))?;
        let before_exp = match self.exp {
            Some(exp) => !crate::publisher_time::at_or_after(observed_at, i128::from(exp))?,
            None => true,
        };
        Some(after_nbf && before_exp)
    }
}

/// RFC 7638 thumbprint.
pub fn thumbprint(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    crate::crypto::b64u_encode(&sha2::Sha256::digest(canonical.as_bytes()))
}

/// WIST-1 §5.1 Key Set fingerprint.
pub fn key_set_fingerprint(keys: &[PublisherKey]) -> String {
    let mut kids: Vec<&str> = keys.iter().map(|key| key.kid.as_str()).collect();
    kids.sort_unstable();
    let canonical = crate::jcs::canonicalize(&serde_json::json!(kids)).unwrap_or_default();
    format!(
        "sha256:{}",
        crate::crypto::hex_encode(&sha2::Sha256::digest(&canonical))
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publisher {
    pub wist_version: String,
    pub domain: String,
    pub keys: Vec<PublisherKey>,
    pub seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_declaration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain_scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_keys: Option<Vec<PublisherKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collections: Option<Vec<Collection>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub name: String,
    pub scope: Vec<ScopeEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<PublisherKey>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEntry {
    pub url: String,
    pub r#match: Match,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Match {
    Prefix,
    Exact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherEnvelope {
    pub publisher: Publisher,
    pub sig: Sig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_matches_rfc_8037_known_answer() {
        assert_eq!(
            thumbprint("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn window_is_inclusive_at_nbf_and_exclusive_at_exp() {
        let key = PublisherKey::new(
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            100,
            Some(200),
        );
        assert_eq!(key.admits("1970-01-01T00:01:39.999999999999Z"), Some(false));
        assert_eq!(key.admits("1970-01-01T00:01:40Z"), Some(true));
        assert_eq!(key.admits("1970-01-01T00:03:19.5Z"), Some(true));
        assert_eq!(key.admits("1970-01-01T00:03:20Z"), Some(false));
        assert_eq!(key.admits("1970-01-01T01:03:20+01:00"), Some(false));
        assert_eq!(key.admits("not a time"), None);
        let open = PublisherKey::new("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", 0, None);
        assert_eq!(open.admits("9999-12-31T23:59:59Z"), Some(true));
        assert_eq!(open.admits("1969-12-31T23:59:59.5Z"), Some(false));
    }
}
