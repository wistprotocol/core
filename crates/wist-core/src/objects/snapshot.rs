use crate::objects::Sig;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIndexEntry {
    pub snapshot_date: String,
    pub tree_size: u64,
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
    pub shard: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub wist_version: String,
    pub snapshot_date: String,
    pub epoch_number: u64,
    pub tree_size: u64,
    pub root_hash: String,
    pub content_digest: String,
    pub state: SnapshotStateFile,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::objects::present"
    )]
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
    pub adding_act: Option<Value>,
    pub removing_act: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct DeclarationEntry {
    pub domain: String,
    pub declaration: Value,
    pub sealing_height: u64,
    pub highest_accepted_seq: u64,
}

#[derive(Debug, Clone)]
pub struct PendingDeclarationEntry {
    pub domain: String,
    pub head: Value,
    pub sealing_height: u64,
    pub activation_height: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryUpdateEntry {
    pub update_id: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CollectionEntry {
    pub publisher: String,
    pub collection: String,
    pub envelope: Value,
    pub sealing_height: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecordEntry {
    pub publisher: String,
    pub url: String,
    pub item: Value,
    pub collection: String,
    pub catalog_id: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalEntry {
    pub publisher: String,
    pub url: String,
    pub item_id: String,
    pub catalog_id: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalEntry {
    pub item_id: String,
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
    pub expires_at: Option<String>,
    pub delta: Option<String>,
    pub label_id: String,
    pub sealing_height: u64,
}

#[derive(Debug, Clone)]
pub struct DisputeEntry {
    pub label_id: String,
    pub disputant: String,
    pub reason: Option<String>,
    pub asserted_at: String,
    pub sealing_height: u64,
}

/// WIST-3 §7 inventory; variants follow the table's order.
#[derive(Debug, Clone)]
pub enum StateEntry {
    AggregatorKey(AggregatorKeyEntry),
    Declaration(DeclarationEntry),
    PendingDeclaration(PendingDeclarationEntry),
    Parameter(ParameterEntry),
    RecoveryWindow(RecoveryWindowEntry),
    SuffixList(SuffixListEntry),
    RegistryUpdate(RegistryUpdateEntry),
    Collection(CollectionEntry),
    Record(RecordEntry),
    Removal(RemovalEntry),
    Withdrawal(WithdrawalEntry),
    Label(LabelEntry),
    Dispute(DisputeEntry),
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
                check_arity::<D::Error>(&kind, tail, 6)?;
                Ok(StateEntry::AggregatorKey(AggregatorKeyEntry {
                    key_id: field(tail, 0)?,
                    public_key: field(tail, 1)?,
                    added_height: field(tail, 2)?,
                    removed_height: field(tail, 3)?,
                    adding_act: field(tail, 4)?,
                    removing_act: field(tail, 5)?,
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
            "pending_declaration" => {
                check_arity::<D::Error>(&kind, tail, 4)?;
                Ok(StateEntry::PendingDeclaration(PendingDeclarationEntry {
                    domain: field(tail, 0)?,
                    head: field(tail, 1)?,
                    sealing_height: field(tail, 2)?,
                    activation_height: field(tail, 3)?,
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
            "registry_update" => {
                check_arity::<D::Error>(&kind, tail, 2)?;
                Ok(StateEntry::RegistryUpdate(RegistryUpdateEntry {
                    update_id: field(tail, 0)?,
                    sealing_height: field(tail, 1)?,
                }))
            }
            "collection" => {
                check_arity::<D::Error>(&kind, tail, 4)?;
                Ok(StateEntry::Collection(CollectionEntry {
                    publisher: field(tail, 0)?,
                    collection: field(tail, 1)?,
                    envelope: field(tail, 2)?,
                    sealing_height: field(tail, 3)?,
                }))
            }
            "record" => {
                check_arity::<D::Error>(&kind, tail, 6)?;
                Ok(StateEntry::Record(RecordEntry {
                    publisher: field(tail, 0)?,
                    url: field(tail, 1)?,
                    item: field(tail, 2)?,
                    collection: field(tail, 3)?,
                    catalog_id: field(tail, 4)?,
                    generated_at: field(tail, 5)?,
                }))
            }
            "removal" => {
                check_arity::<D::Error>(&kind, tail, 5)?;
                Ok(StateEntry::Removal(RemovalEntry {
                    publisher: field(tail, 0)?,
                    url: field(tail, 1)?,
                    item_id: field(tail, 2)?,
                    catalog_id: field(tail, 3)?,
                    generated_at: field(tail, 4)?,
                }))
            }
            "withdrawal" => {
                check_arity::<D::Error>(&kind, tail, 3)?;
                Ok(StateEntry::Withdrawal(WithdrawalEntry {
                    item_id: field(tail, 0)?,
                    publisher: field(tail, 1)?,
                    sealing_height: field(tail, 2)?,
                }))
            }
            "label" => {
                check_arity::<D::Error>(&kind, tail, 9)?;
                Ok(StateEntry::Label(LabelEntry {
                    labeler: field(tail, 0)?,
                    subject: field(tail, 1)?,
                    name: field(tail, 2)?,
                    value: field(tail, 3)?,
                    asserted_at: field(tail, 4)?,
                    expires_at: field(tail, 5)?,
                    delta: field(tail, 6)?,
                    label_id: field(tail, 7)?,
                    sealing_height: field(tail, 8)?,
                }))
            }
            "dispute" => {
                check_arity::<D::Error>(&kind, tail, 5)?;
                Ok(StateEntry::Dispute(DisputeEntry {
                    label_id: field(tail, 0)?,
                    disputant: field(tail, 1)?,
                    reason: field(tail, 2)?,
                    asserted_at: field(tail, 3)?,
                    sealing_height: field(tail, 4)?,
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
                e.removed_height,
                e.adding_act,
                e.removing_act
            ]),
            StateEntry::Declaration(e) => serde_json::json!([
                "declaration",
                e.domain,
                e.declaration,
                e.sealing_height,
                e.highest_accepted_seq
            ]),
            StateEntry::PendingDeclaration(e) => serde_json::json!([
                "pending_declaration",
                e.domain,
                e.head,
                e.sealing_height,
                e.activation_height
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
            StateEntry::RegistryUpdate(e) => {
                serde_json::json!(["registry_update", e.update_id, e.sealing_height])
            }
            StateEntry::Collection(e) => serde_json::json!([
                "collection",
                e.publisher,
                e.collection,
                e.envelope,
                e.sealing_height
            ]),
            StateEntry::Record(e) => serde_json::json!([
                "record",
                e.publisher,
                e.url,
                e.item,
                e.collection,
                e.catalog_id,
                e.generated_at
            ]),
            StateEntry::Removal(e) => serde_json::json!([
                "removal",
                e.publisher,
                e.url,
                e.item_id,
                e.catalog_id,
                e.generated_at
            ]),
            StateEntry::Withdrawal(e) => {
                serde_json::json!(["withdrawal", e.item_id, e.publisher, e.sealing_height])
            }
            StateEntry::Label(e) => serde_json::json!([
                "label",
                e.labeler,
                e.subject,
                e.name,
                e.value,
                e.asserted_at,
                e.expires_at,
                e.delta,
                e.label_id,
                e.sealing_height
            ]),
            StateEntry::Dispute(e) => serde_json::json!([
                "dispute",
                e.label_id,
                e.disputant,
                e.reason,
                e.asserted_at,
                e.sealing_height
            ]),
        };
        value.serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotState {
    pub wist_version: String,
    pub tree_size: u64,
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
        let id = format!("sha256:{}", "c".repeat(64));
        let cases = [
            serde_json::json!([
                "aggregator_key",
                "key-1",
                pk,
                10,
                Value::Null,
                {"update": {"action": "aggregator_key_add"}, "sig": {"key_id": "key-0"}},
                Value::Null
            ]),
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
            serde_json::json!(["withdrawal", id, "example.com", 3]),
            serde_json::json!(["suffix_list", id, 4]),
            serde_json::json!(["registry_update", id, 5]),
            serde_json::json!([
                "label",
                "labeler.example.net",
                "https://example.com/blog/post-1",
                "wist:spam",
                Value::Null,
                "2026-08-02T12:00:00Z",
                "2026-09-02T12:00:00Z",
                id,
                id,
                12
            ]),
            serde_json::json!([
                "dispute",
                id,
                "example.com",
                Value::Null,
                "2026-08-02T13:00:00Z",
                13
            ]),
            serde_json::json!([
                "collection",
                "example.com",
                "default",
                {"catalog": {"publisher": "example.com"}, "sig": {"key_id": "k"}},
                5
            ]),
            serde_json::json!([
                "record",
                "example.com",
                "https://example.com/blog/post-1",
                {"publisher": "example.com", "url": "https://example.com/blog/post-1"},
                "default",
                id,
                "2026-08-02T12:00:00Z"
            ]),
            serde_json::json!([
                "removal",
                "example.com",
                "https://example.com/blog/post-2",
                id,
                id,
                "2026-08-02T12:00:00Z"
            ]),
        ];
        assert_eq!(cases.len(), 12);
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
            serde_json::json!(["registry_update", "sha256:00"]),
            serde_json::json!([
                "record",
                "example.com",
                "https://example.com/a",
                "sha256:00"
            ]),
            serde_json::json!([
                "removal",
                "example.com",
                "https://example.com/a",
                "sha256:00"
            ]),
            serde_json::json!([]),
            serde_json::json!(["aggregator_key", "key-1", "pk", 10, Value::Null]),
        ] {
            assert!(serde_json::from_value::<StateEntry>(tuple).is_err());
        }
    }
}
