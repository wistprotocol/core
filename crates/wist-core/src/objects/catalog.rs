use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub wist_version: String,
    pub publisher: String,
    pub collection: String,
    pub generated_at: String,
    #[serde(deserialize_with = "crate::objects::safe_integer")]
    pub size: u64,
    pub root: String,
    pub tree: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEnvelope {
    pub catalog: Catalog,
    pub sig: Sig,
}
