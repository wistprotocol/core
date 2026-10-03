use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeList {
    pub previous: String,
    pub catalog: String,
    pub dropped: Vec<String>,
    pub items: Vec<Value>,
}
