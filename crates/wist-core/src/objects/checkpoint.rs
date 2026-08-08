use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub wist_version: String,
    pub block_number: u64,
    pub block_hash: String,
    pub sealed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEnvelope {
    pub checkpoint: Checkpoint,
    pub sig: Sig,
}
