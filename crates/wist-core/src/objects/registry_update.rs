use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    AggregatorKeyAdd,
    AggregatorKeyRemove,
    ParameterChange,
    PayloadWithdrawal,
    SuffixListUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdate {
    pub wist_version: String,
    pub action: RegistryAction,
    pub subject: String,
    pub details: Value,
    pub effective_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdateEnvelope {
    pub update: RegistryUpdate,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAddDetails {
    pub key_id: String,
    pub alg: KeyAlgorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRemoveDetails {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterChangeDetails {
    pub parameter: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadWithdrawalDetails {
    pub delta_id: String,
    pub legal_basis: String,
    pub jurisdiction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixListDetails {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub enum RegistryDetails {
    KeyAdd(KeyAddDetails),
    KeyRemove(KeyRemoveDetails),
    ParameterChange(ParameterChangeDetails),
    PayloadWithdrawal(PayloadWithdrawalDetails),
    SuffixListUpdate(SuffixListDetails),
}

impl RegistryUpdate {
    /// WIST-4 §5.1: a violation of the action's `details` and `subject` contract is `WIST4-E04`.
    pub fn typed_details(&self) -> Result<RegistryDetails, crate::error::Error> {
        use RegistryAction::*;
        let value = self.details.clone();
        let parsed = match self.action {
            AggregatorKeyAdd => serde_json::from_value(value).map(RegistryDetails::KeyAdd),
            AggregatorKeyRemove => serde_json::from_value(value).map(RegistryDetails::KeyRemove),
            ParameterChange => serde_json::from_value(value).map(RegistryDetails::ParameterChange),
            PayloadWithdrawal => {
                serde_json::from_value(value).map(RegistryDetails::PayloadWithdrawal)
            }
            SuffixListUpdate => {
                serde_json::from_value(value).map(RegistryDetails::SuffixListUpdate)
            }
        };
        let details =
            parsed.map_err(|e| crate::error::Error::Envelope(format!("WIST4-E04: {e}")))?;
        let valid = match &details {
            RegistryDetails::KeyAdd(d) => {
                key_id(&d.key_id) && public_key(&d.public_key) && self.subject == d.key_id
            }
            RegistryDetails::KeyRemove(d) => key_id(&d.key_id) && self.subject == d.key_id,
            RegistryDetails::ParameterChange(d) => {
                crate::parameters::spec(&d.parameter).is_some()
                    && crate::parameters::validate_value(&d.parameter, d.value).is_ok()
                    && self.subject == d.parameter
            }
            RegistryDetails::PayloadWithdrawal(d) => {
                digest(&d.delta_id)
                    && (1..=1024).contains(&d.legal_basis.chars().count())
                    && (1..=128).contains(&d.jurisdiction.chars().count())
                    && crate::host::canonical_host(&self.subject)
                        .is_ok_and(|host| host == self.subject)
            }
            RegistryDetails::SuffixListUpdate(d) => {
                digest(&d.sha256)
                    && (1..=9_007_199_254_740_991).contains(&d.bytes)
                    && self.subject == d.sha256
            }
        };
        if !valid {
            return Err(crate::error::Error::Envelope(
                "WIST4-E04: Registry Update details violate the action's contract".into(),
            ));
        }
        Ok(details)
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn key_id(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 64
}

fn public_key(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
