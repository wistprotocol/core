use crate::objects::Sig;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIndexEntry {
    pub snapshot_date: String,
    pub log_position: u64,
    pub manifest_url: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIndex {
    pub wist_version: String,
    pub updated_at: String,
    pub snapshots: Vec<SnapshotIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIndexEnvelope {
    pub index: SnapshotIndex,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStateFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub state_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotShards {
    pub count: u64,
    pub digests: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub tier: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub wist_version: String,
    pub snapshot_date: String,
    pub log_position: u64,
    pub anchor_block_hash: String,
    pub content_digest: String,
    pub state: SnapshotStateFile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shards: Option<SnapshotShards>,
    pub files: Vec<SnapshotFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifestEnvelope {
    pub manifest: SnapshotManifest,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SanctionDeadlineLabel {
    Appeal,
    AppealSealing,
    Ruling,
}

#[derive(Debug, Clone)]
pub struct AggregatorKeyEntry {
    pub key_id: String,
    pub public_key: String,
    pub added_height: u64,
    pub removed_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct AuditorEntry {
    pub auditor_id: String,
    pub key_id: String,
    pub public_key: String,
    pub admitted_height: u64,
    pub removed_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DeclarationEntry {
    pub domain: String,
    pub declaration: Value,
    pub sealing_height: u64,
}

#[derive(Debug, Clone)]
pub struct ParameterEntry {
    pub name: String,
    pub effective_at: String,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct SanctionStateEntry {
    pub domain: String,
    pub level: u64,
    pub evidence: Vec<String>,
    pub deadlines: Vec<(SanctionDeadlineLabel, String)>,
}

#[derive(Debug, Clone)]
pub struct RecoveryWindowEntry {
    pub domain: String,
    pub declaration_height: u64,
    pub window_end: String,
}

#[derive(Debug, Clone)]
pub struct ExclusionEntry {
    pub publisher: String,
    pub url: String,
    pub excluded_since_height: u64,
}

#[derive(Debug, Clone)]
pub struct CoverageFailureEntry {
    pub auditor_id: String,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct ReputationInputsEntry {
    pub domain: String,
    pub first_accepted_sealed_at: String,
    pub reset_height: Option<u64>,
    pub counted_total: u64,
    pub counted_url_digests: Vec<String>,
    pub penalties: Vec<(String, u64)>,
}

#[derive(Debug, Clone)]
pub struct RecordEntry {
    pub publisher: String,
    pub url: String,
    pub delta_id: String,
}

#[derive(Debug, Clone)]
pub enum StateEntry {
    AggregatorKey(AggregatorKeyEntry),
    Auditor(AuditorEntry),
    Declaration(DeclarationEntry),
    Parameter(ParameterEntry),
    SanctionState(SanctionStateEntry),
    RecoveryWindow(RecoveryWindowEntry),
    Exclusion(ExclusionEntry),
    CoverageFailure(CoverageFailureEntry),
    ReputationInputs(ReputationInputsEntry),
    Record(RecordEntry),
}

fn field<T: serde::de::DeserializeOwned, E: de::Error>(tail: &[Value], i: usize) -> Result<T, E> {
    serde_json::from_value(tail[i].clone()).map_err(|e| de::Error::custom(e.to_string()))
}

fn check_arity<E: de::Error>(kind: &str, tail: &[Value], expected: usize) -> Result<(), E> {
    if tail.len() != expected {
        Err(de::Error::custom(format!(
            "state entry {kind:?}: expected {expected} fields after the kind tag, got {}",
            tail.len()
        )))
    } else {
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StateEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let items = Vec::<Value>::deserialize(deserializer)?;
        let kind = items
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::custom("state entry missing kind tag"))?
            .to_string();
        let tail = &items[1..];
        match kind.as_str() {
            "aggregator_key" => {
                check_arity::<D::Error>(&kind, tail, 4)?;
                Ok(StateEntry::AggregatorKey(AggregatorKeyEntry {
                    key_id: field(tail, 0)?,
                    public_key: field(tail, 1)?,
                    added_height: field(tail, 2)?,
                    removed_height: field(tail, 3)?,
                }))
            }
            "auditor" => {
                check_arity::<D::Error>(&kind, tail, 5)?;
                Ok(StateEntry::Auditor(AuditorEntry {
                    auditor_id: field(tail, 0)?,
                    key_id: field(tail, 1)?,
                    public_key: field(tail, 2)?,
                    admitted_height: field(tail, 3)?,
                    removed_height: field(tail, 4)?,
                }))
            }
            "declaration" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Declaration(DeclarationEntry {
                    domain: field(tail, 0)?,
                    declaration: field(tail, 1)?,
                    sealing_height: field(tail, 2)?,
                }))
            }
            "parameter" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Parameter(ParameterEntry {
                    name: field(tail, 0)?,
                    effective_at: field(tail, 1)?,
                    value: field(tail, 2)?,
                }))
            }
            "sanction_state" => {
                check_arity::<D::Error>(&kind, tail, 4)?;
                Ok(StateEntry::SanctionState(SanctionStateEntry {
                    domain: field(tail, 0)?,
                    level: field(tail, 1)?,
                    evidence: field(tail, 2)?,
                    deadlines: field(tail, 3)?,
                }))
            }
            "recovery_window" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::RecoveryWindow(RecoveryWindowEntry {
                    domain: field(tail, 0)?,
                    declaration_height: field(tail, 1)?,
                    window_end: field(tail, 2)?,
                }))
            }
            "exclusion" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Exclusion(ExclusionEntry {
                    publisher: field(tail, 0)?,
                    url: field(tail, 1)?,
                    excluded_since_height: field(tail, 2)?,
                }))
            }
            "coverage_failure" => {
                check_arity::<D::Error>(&kind, tail, 2)?;
                Ok(StateEntry::CoverageFailure(CoverageFailureEntry {
                    auditor_id: field(tail, 0)?,
                    block_number: field(tail, 1)?,
                }))
            }
            "reputation_inputs" => {
                check_arity::<D::Error>(&kind, tail, 6)?;
                Ok(StateEntry::ReputationInputs(ReputationInputsEntry {
                    domain: field(tail, 0)?,
                    first_accepted_sealed_at: field(tail, 1)?,
                    reset_height: field(tail, 2)?,
                    counted_total: field(tail, 3)?,
                    counted_url_digests: field(tail, 4)?,
                    penalties: field(tail, 5)?,
                }))
            }
            "record" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Record(RecordEntry {
                    publisher: field(tail, 0)?,
                    url: field(tail, 1)?,
                    delta_id: field(tail, 2)?,
                }))
            }
            other => Err(de::Error::custom(format!(
                "unknown state entry kind {other:?}"
            ))),
        }
    }
}

impl Serialize for StateEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = match self {
            StateEntry::AggregatorKey(e) => serde_json::json!([
                "aggregator_key",
                e.key_id,
                e.public_key,
                e.added_height,
                e.removed_height
            ]),
            StateEntry::Auditor(e) => serde_json::json!([
                "auditor",
                e.auditor_id,
                e.key_id,
                e.public_key,
                e.admitted_height,
                e.removed_height
            ]),
            StateEntry::Declaration(e) => {
                serde_json::json!(["declaration", e.domain, e.declaration, e.sealing_height])
            }
            StateEntry::Parameter(e) => {
                serde_json::json!(["parameter", e.name, e.effective_at, e.value])
            }
            StateEntry::SanctionState(e) => {
                serde_json::json!(["sanction_state", e.domain, e.level, e.evidence, e.deadlines])
            }
            StateEntry::RecoveryWindow(e) => serde_json::json!([
                "recovery_window",
                e.domain,
                e.declaration_height,
                e.window_end
            ]),
            StateEntry::Exclusion(e) => {
                serde_json::json!(["exclusion", e.publisher, e.url, e.excluded_since_height])
            }
            StateEntry::CoverageFailure(e) => {
                serde_json::json!(["coverage_failure", e.auditor_id, e.block_number])
            }
            StateEntry::ReputationInputs(e) => serde_json::json!([
                "reputation_inputs",
                e.domain,
                e.first_accepted_sealed_at,
                e.reset_height,
                e.counted_total,
                e.counted_url_digests,
                e.penalties
            ]),
            StateEntry::Record(e) => {
                serde_json::json!(["record", e.publisher, e.url, e.delta_id])
            }
        };
        value.serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotState {
    pub wist_version: String,
    pub log_position: u64,
    pub entries: Vec<StateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStateEnvelope {
    pub state: SnapshotState,
    pub sig: Sig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_entry_round_trips_every_kind() {
        let pk = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
        let evidence_digest = format!("sha256:{}", "a".repeat(64));
        let url_digest = "b".repeat(32);
        let delta_id = format!("sha256:{}", "c".repeat(64));
        let cases = [
            serde_json::json!(["aggregator_key", "key-1", pk, 10, Value::Null]),
            serde_json::json!(["auditor", "auditor.example.com", "key-2", pk, 5, 20]),
            serde_json::json!(["declaration", "example.com", {"policy": "strict"}, 42]),
            serde_json::json!(["parameter", "max_shard_bytes", "2026-08-09T13:00:00Z", -5]),
            serde_json::json!([
                "sanction_state",
                "example.com",
                2,
                [evidence_digest],
                [["appeal", "2026-08-02T12:00:00Z"]]
            ]),
            serde_json::json!(["recovery_window", "example.com", 7, "2026-08-02T12:00:00Z"]),
            serde_json::json!(["exclusion", "example.com", "/blog/post-1", 3]),
            serde_json::json!(["coverage_failure", "auditor.example.com", 12]),
            serde_json::json!([
                "reputation_inputs",
                "example.com",
                "2026-08-02T12:00:00Z",
                Value::Null,
                9,
                [url_digest],
                [["2026-08-02T12:00:00Z", 1]]
            ]),
            serde_json::json!([
                "record",
                "example.com",
                "https://example.com/blog/post-1",
                delta_id
            ]),
        ];
        assert_eq!(cases.len(), 10);
        for tuple in cases {
            let entry: StateEntry =
                serde_json::from_value(tuple.clone()).unwrap_or_else(|e| panic!("{tuple}: {e}"));
            assert_eq!(serde_json::to_value(&entry).unwrap(), tuple);
        }
    }
}
