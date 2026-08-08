pub mod audit;
pub mod block;
pub mod checkpoint;
pub mod delta;
pub mod feed;
pub mod log_anchor;
pub mod payload;
pub mod publisher;
pub mod snapshot;
pub mod status;

pub use audit::{
    AuditRecord, AuditRecordEnvelope, RegistryAction, RegistryUpdate, RegistryUpdateEnvelope,
    Verdict,
};
pub use block::{Block, BlockHeader};
pub use checkpoint::{Checkpoint, CheckpointEnvelope};
pub use delta::{ChangeType, Delta, DeltaEnvelope, DeltaMeta, DeltaPayloadCommitment};
pub use feed::{Feed, FeedEnvelope};
pub use log_anchor::{Anchor, GenesisKey, LogAnchorEnvelope, Predecessor};
pub use payload::{Payload, PayloadContent, PayloadLinks, PayloadSummary};
pub use publisher::{Publisher, PublisherEnvelope, PublisherKey};
pub use snapshot::{
    AggregatorKeyEntry, AuditorEntry, CoverageFailureEntry, DeclarationEntry, ExclusionEntry,
    ParameterEntry, RecordEntry, RecoveryWindowEntry, ReputationInputsEntry, SanctionDeadlineLabel,
    SanctionStateEntry, SnapshotFile, SnapshotIndex, SnapshotIndexEntry, SnapshotIndexEnvelope,
    SnapshotManifest, SnapshotManifestEnvelope, SnapshotShards, SnapshotState,
    SnapshotStateEnvelope, SnapshotStateFile, StateEntry,
};
pub use status::{PublisherState, Status, StatusRejection};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sig {
    pub key_id: String,
    pub alg: String,
    pub value: String,
}
