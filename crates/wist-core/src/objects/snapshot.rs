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

#[derive(Debug, Clone)]
pub struct AggregatorKeyEntry {
    pub key_id: String,
    pub public_key: String,
    pub added_height: u64,
    pub removed_height: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DeclarationEntry {
    pub domain: String,
    pub declaration: Value,
    pub sealing_height: u64,
    pub highest_accepted_seq: u64,
}

#[derive(Debug, Clone)]
pub struct ParameterEntry {
    pub name: String,
    pub effective_at: String,
    pub value: i64,
}

#[derive(Debug, Clone)]
pub struct RecoveryWindowEntry {
    pub domain: String,
    pub declaration_height: u64,
    pub window_end: String,
    pub head: Value,
    pub head_height: u64,
}

#[derive(Debug, Clone)]
pub struct SuffixListEntry {
    pub identifier: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone)]
pub struct WithdrawalEntry {
    pub delta_id: String,
    pub publisher: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone)]
pub struct LabelEntry {
    pub labeler: String,
    pub subject: String,
    pub name: String,
    pub value: Option<u64>,
    pub asserted_at: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone)]
pub struct RecordEntry {
    pub publisher: String,
    pub url: String,
    pub delta_id: String,
}

/// One live-state tuple of WIST-3 §7's inventory, in the table's order.
#[derive(Debug, Clone)]
pub enum StateEntry {
    AggregatorKey(AggregatorKeyEntry),
    Declaration(DeclarationEntry),
    Parameter(ParameterEntry),
    RecoveryWindow(RecoveryWindowEntry),
    SuffixList(SuffixListEntry),
    Withdrawal(WithdrawalEntry),
    Label(LabelEntry),
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
            "declaration" => {
                check_arity::<D::Error>(&kind, tail, 4)?;
                Ok(StateEntry::Declaration(DeclarationEntry {
                    domain: field(tail, 0)?,
                    declaration: field(tail, 1)?,
                    sealing_height: field(tail, 2)?,
                    highest_accepted_seq: field(tail, 3)?,
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
            "recovery_window" => {
                check_arity::<D::Error>(&kind, tail, 5)?;
                Ok(StateEntry::RecoveryWindow(RecoveryWindowEntry {
                    domain: field(tail, 0)?,
                    declaration_height: field(tail, 1)?,
                    window_end: field(tail, 2)?,
                    head: field(tail, 3)?,
                    head_height: field(tail, 4)?,
                }))
            }
            "suffix_list" => {
                check_arity::<D::Error>(&kind, tail, 2)?;
                Ok(StateEntry::SuffixList(SuffixListEntry {
                    identifier: field(tail, 0)?,
                    sealing_height: field(tail, 1)?,
                }))
            }
            "withdrawal" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Withdrawal(WithdrawalEntry {
                    delta_id: field(tail, 0)?,
                    publisher: field(tail, 1)?,
                    sealing_height: field(tail, 2)?,
                }))
            }
            "label" => {
                check_arity::<D::Error>(&kind, tail, 6)?;
                Ok(StateEntry::Label(LabelEntry {
                    labeler: field(tail, 0)?,
                    subject: field(tail, 1)?,
                    name: field(tail, 2)?,
                    value: field(tail, 3)?,
                    asserted_at: field(tail, 4)?,
                    sealing_height: field(tail, 5)?,
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
            StateEntry::Declaration(e) => serde_json::json!([
                "declaration",
                e.domain,
                e.declaration,
                e.sealing_height,
                e.highest_accepted_seq
            ]),
            StateEntry::Parameter(e) => {
                serde_json::json!(["parameter", e.name, e.effective_at, e.value])
            }
            StateEntry::RecoveryWindow(e) => serde_json::json!([
                "recovery_window",
                e.domain,
                e.declaration_height,
                e.window_end,
                e.head,
                e.head_height
            ]),
            StateEntry::SuffixList(e) => {
                serde_json::json!(["suffix_list", e.identifier, e.sealing_height])
            }
            StateEntry::Withdrawal(e) => {
                serde_json::json!(["withdrawal", e.delta_id, e.publisher, e.sealing_height])
            }
            StateEntry::Label(e) => serde_json::json!([
                "label",
                e.labeler,
                e.subject,
                e.name,
                e.value,
                e.asserted_at,
                e.sealing_height
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
        let delta_id = format!("sha256:{}", "c".repeat(64));
        let cases = [
            serde_json::json!(["aggregator_key", "key-1", pk, 10, Value::Null]),
            serde_json::json!(["declaration", "example.com", {"policy": "strict"}, 42, 43]),
            serde_json::json!(["parameter", "quota_base", "2026-08-09T13:00:00Z", -5]),
            serde_json::json!([
                "recovery_window",
                "example.com",
                7,
                "2026-08-02T12:00:00Z",
                {"policy": "head"},
                9
            ]),
            serde_json::json!(["withdrawal", delta_id, "example.com", 3]),
            serde_json::json!([
                "label",
                "labeler.example.net",
                "https://example.com/blog/post-1",
                "wist:spam",
                Value::Null,
                "2026-08-02T12:00:00Z",
                12
            ]),
            serde_json::json!([
                "record",
                "example.com",
                "https://example.com/blog/post-1",
                delta_id
            ]),
        ];
        assert_eq!(cases.len(), 7);
        for tuple in cases {
            let entry: StateEntry =
                serde_json::from_value(tuple.clone()).unwrap_or_else(|e| panic!("{tuple}: {e}"));
            assert_eq!(serde_json::to_value(&entry).unwrap(), tuple);
        }
    }

    #[test]
    fn unknown_and_short_tuples_are_rejected() {
        for tuple in [
            serde_json::json!(["exclusion", "example.com", "/blog/post-1", 3]),
            serde_json::json!(["withdrawal", "sha256:00", "example.com"]),
            serde_json::json!([]),
        ] {
            assert!(serde_json::from_value::<StateEntry>(tuple).is_err());
        }
    }
}
