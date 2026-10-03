use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadCommitment {
    pub commitment: String,
    pub alg: String,
    #[serde(deserialize_with = "crate::objects::safe_integer")]
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemMeta {
    pub lang: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub topics: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageItem {
    pub publisher: String,
    pub url: String,
    pub observed_at: String,
    pub payload: PayloadCommitment,
    pub meta: ItemMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedItem {
    pub publisher: String,
    pub url: String,
    pub observed_at: String,
    #[serde(deserialize_with = "removed_true")]
    pub removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Item {
    Removed(RemovedItem),
    Page(PageItem),
}

impl Item {
    pub fn publisher(&self) -> &str {
        match self {
            Item::Removed(item) => &item.publisher,
            Item::Page(item) => &item.publisher,
        }
    }

    pub fn url(&self) -> &str {
        match self {
            Item::Removed(item) => &item.url,
            Item::Page(item) => &item.url,
        }
    }

    pub fn observed_at(&self) -> &str {
        match self {
            Item::Removed(item) => &item.observed_at,
            Item::Page(item) => &item.observed_at,
        }
    }
}

fn removed_true<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(true)
    } else {
        Err(serde::de::Error::custom("removed must be true"))
    }
}
