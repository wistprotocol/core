use crate::objects::Sig;
use serde::{Deserialize, Serialize};

/// WIST-2 §3.3: a Labeler's signed statement about a subject outside its
/// own authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub wist_version: String,
    pub labeler: String,
    pub subject: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    pub asserted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retracted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelEnvelope {
    pub label: Label,
    pub sig: Sig,
}

/// WIST-2 §3.3: a labeled domain's signed dispute of one sealed Label.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dispute {
    pub wist_version: String,
    pub disputant: String,
    pub label: String,
    pub log: String,
    pub height: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub asserted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisputeEnvelope {
    pub dispute: Dispute,
    pub sig: Sig,
}

/// WIST-4 §6: what a Consumer does with a labeled subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Treatment {
    Hide,
    Warn,
    Inform,
}

/// WIST-2 §3.3: a Labeler's signed definition of one name it uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelDefinition {
    pub wist_version: String,
    pub labeler: String,
    pub name: String,
    pub description: String,
    pub treatment: Treatment,
    pub asserted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelDefinitionEnvelope {
    pub definition: LabelDefinition,
    pub sig: Sig,
}
