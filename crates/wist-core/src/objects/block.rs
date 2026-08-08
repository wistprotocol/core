use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    pub wist_version: String,
    pub block_number: u64,
    pub prev_block_hash: String,
    pub sealed_at: String,
    pub merkle_root: String,
    pub entry_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: BlockHeader,
    pub entries: Vec<Value>,
    pub sig: Sig,
}
