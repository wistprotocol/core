use crate::objects::Item;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProof {
    #[serde(deserialize_with = "crate::objects::safe_integer")]
    pub index: u64,
    #[serde(deserialize_with = "crate::objects::safe_integer")]
    pub tree_size: u64,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherItem {
    pub item: Item,
    pub collection: String,
    pub catalog: String,
    pub proof: InclusionProof,
}
