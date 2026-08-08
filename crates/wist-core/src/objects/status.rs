use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherState {
    New,
    Active,
    SanctionedQuarantine,
    Delisted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRejection {
    pub code: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub wist_version: String,
    pub domain: String,
    #[serde(deserialize_with = "crate::objects::required_nullable")]
    pub last_pull_at: Option<String>,
    pub quota_remaining: u64,
    pub state: PublisherState,
    pub rejections: Vec<StatusRejection>,
}
