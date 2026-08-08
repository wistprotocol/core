use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisKey {
    pub key_id: String,
    pub alg: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Predecessor {
    pub log_id: String,
    pub final_block_number: u64,
    pub final_block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub wist_version: String,
    pub log_id: String,
    pub genesis_key: GenesisKey,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<Predecessor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogAnchorEnvelope {
    pub anchor: Anchor,
    pub sig: Sig,
}
