use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherState {
    New,
    Active,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Deferral {
    RecoveryWindow,
    Capacity,
    CatalogWaiting,
    LatestFailsI4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitingStatus {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub deferrals: Vec<Deferral>,
    pub held: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionStatus {
    pub name: String,
    #[serde(deserialize_with = "crate::objects::required_nullable")]
    pub latest: Option<String>,
    #[serde(deserialize_with = "crate::objects::required_nullable")]
    pub accepted: Option<String>,
    pub waiting: Vec<WaitingStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCondition {
    Fetch,
    Size,
    Form,
    Chain,
    Result,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRejection {
    pub code: String,
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<RejectionCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_list: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub collections: Vec<CollectionStatus>,
    pub rejections: Vec<StatusRejection>,
}
