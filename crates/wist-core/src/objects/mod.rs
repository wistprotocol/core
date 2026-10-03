pub mod catalog;
pub mod change_list;
pub mod feed;
pub mod item;
pub mod label;
pub mod log_anchor;
pub mod payload;
pub mod publisher;
pub mod publisher_item;
pub mod registry_update;
pub mod snapshot;
pub mod status;
pub mod tree_file;

pub use catalog::{Catalog, CatalogEnvelope};
pub use change_list::ChangeList;
pub use feed::{Feed, FeedEnvelope};
pub use item::{Item, ItemMeta, PageItem, PayloadCommitment, RemovedItem};
pub use label::{
    Dispute, DisputeEnvelope, Label, LabelDefinition, LabelDefinitionEnvelope, LabelEnvelope,
    Treatment,
};
pub use log_anchor::{Anchor, GenesisKey, LogAnchorEnvelope, Predecessor};
pub use payload::{Payload, PayloadContent, PayloadLinks, PayloadSummary};
pub use publisher::{Collection, Match, Publisher, PublisherEnvelope, PublisherKey, ScopeEntry};
pub use publisher_item::{InclusionProof, PublisherItem};
pub use registry_update::{
    KeyAddDetails, KeyAlgorithm, KeyRemoveDetails, ParameterChangeDetails,
    PayloadWithdrawalDetails, RegistryAction, RegistryDetails, RegistryUpdate,
    RegistryUpdateEnvelope, SuffixListDetails,
};
pub use snapshot::{
    AggregatorKeyEntry, DeclarationEntry, DisputeEntry, LabelEntry, ParameterEntry,
    PendingDeclarationEntry, RecordEntry, RecoveryWindowEntry, SnapshotFile, SnapshotIndex,
    SnapshotIndexEntry, SnapshotIndexEnvelope, SnapshotManifest, SnapshotManifestEnvelope,
    SnapshotShards, SnapshotState, SnapshotStateEnvelope, SnapshotStateFile, StateEntry,
    SuffixListEntry, WithdrawalEntry,
};
pub use status::{PublisherState, Status, StatusRejection};
pub use tree_file::{Bucket, InnerFile, TreeEntry, TreeFile};

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sig {
    pub key_id: String,
    pub alg: String,
    pub value: String,
}

pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(crate) fn safe_integer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = f64::deserialize(deserializer)?;
    if crate::item::safe_integer_value(value) {
        Ok(value as u64)
    } else {
        Err(serde::de::Error::custom(
            "expected a nonnegative integer of the safe range",
        ))
    }
}
