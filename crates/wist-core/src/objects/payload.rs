use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadLinks {
    #[serde(deserialize_with = "crate::objects::safe_integer")]
    pub total: u64,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSummary {
    pub title: String,
    #[serde(
        rename = "abstract",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub r#abstract: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadContent {
    pub extract: String,
    pub links: PayloadLinks,
    pub summary: PayloadSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub wist_version: String,
    pub salt: String,
    pub content: PayloadContent,
}
