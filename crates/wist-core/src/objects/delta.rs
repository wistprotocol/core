use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    New,
    Update,
    Delete,
    Attest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaPayloadCommitment {
    pub commitment: String,
    pub alg: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaMeta {
    pub lang: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    pub wist_version: String,
    #[serde(deserialize_with = "deserialize_publisher")]
    pub publisher: String,
    pub url: String,
    pub change_type: ChangeType,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<DeltaPayloadCommitment>,
    pub meta: DeltaMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaEnvelope {
    pub delta: Delta,
    pub sig: Sig,
}

fn deserialize_publisher<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    crate::delta::validate_publisher(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}
