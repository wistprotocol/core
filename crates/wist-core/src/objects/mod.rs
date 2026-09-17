pub mod block;
pub mod checkpoint;
pub mod delta;
pub mod feed;
pub mod label;
pub mod log_anchor;
pub mod payload;
pub mod publisher;
pub mod registry_update;
pub mod snapshot;
pub mod status;

pub use block::{Block, BlockHeader};
pub use checkpoint::{Checkpoint, CheckpointEnvelope};
pub use delta::{ChangeType, Delta, DeltaEnvelope, DeltaMeta, DeltaPayloadCommitment};
pub use feed::{Feed, FeedEnvelope};
pub use label::{
    Dispute, DisputeEnvelope, Label, LabelDefinition, LabelDefinitionEnvelope, LabelEnvelope,
    Treatment,
};
pub use log_anchor::{Anchor, GenesisKey, LogAnchorEnvelope, Predecessor};
pub use payload::{Payload, PayloadContent, PayloadLinks, PayloadSummary};
pub use publisher::{Publisher, PublisherEnvelope, PublisherKey};
pub use registry_update::{
    KeyAddDetails, KeyAlgorithm, KeyRemoveDetails, ParameterChangeDetails,
    PayloadWithdrawalDetails, RegistryAction, RegistryDetails, RegistryUpdate,
    RegistryUpdateEnvelope, SuffixListDetails,
};
pub use snapshot::{
    AggregatorKeyEntry, DeclarationEntry, DisputeEntry, LabelEntry, ParameterEntry, RecordEntry,
    RecoveryWindowEntry, SnapshotFile, SnapshotIndex, SnapshotIndexEntry, SnapshotIndexEnvelope,
    SnapshotManifest, SnapshotManifestEnvelope, SnapshotShards, SnapshotState,
    SnapshotStateEnvelope, SnapshotStateFile, StateEntry, SuffixListEntry, WithdrawalEntry,
};
pub use status::{PublisherState, Status, StatusRejection};

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
