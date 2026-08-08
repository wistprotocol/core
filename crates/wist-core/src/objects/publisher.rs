use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherKey {
    pub key_id: String,
    pub alg: String,
    pub public_key: String,
    pub valid_from: String,
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
    pub contact: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherEnvelope {
    pub publisher: Publisher,
    pub sig: Sig,
}
