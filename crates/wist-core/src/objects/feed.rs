use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub wist_version: String,
    pub domain: String,
    pub generated_at: String,
    pub deltas: Vec<String>,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEnvelope {
    pub feed: Feed,
    pub sig: Sig,
}
