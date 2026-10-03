use crate::objects::Sig;
use serde::{Deserialize, Deserializer, Serialize};

// WIST-1 §4: a number is the double it denotes, so `5.0` and `5e0` are the integer 5.
fn integer_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    crate::objects::safe_integer(deserializer).map(|value| Some(value as i64))
}

/// WIST-2 §3.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub wist_version: String,
    pub labeler: String,
    pub subject: String,
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "integer_value"
    )]
    pub value: Option<i64>,
    pub asserted_at: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub retracted: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub expires_at: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub delta: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelEnvelope {
    pub label: Label,
    pub sig: Sig,
}

/// WIST-2 §3.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispute {
    pub wist_version: String,
    pub disputant: String,
    pub label: String,
    pub log: String,
    pub height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub asserted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeEnvelope {
    pub dispute: Dispute,
    pub sig: Sig,
}

/// WIST-4 §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Treatment {
    Hide,
    Warn,
    Inform,
}

/// WIST-2 §3.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelDefinition {
    pub wist_version: String,
    pub labeler: String,
    pub name: String,
    pub description: String,
    pub treatment: Treatment,
    pub asserted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelDefinitionEnvelope {
    pub definition: LabelDefinition,
    pub sig: Sig,
}
