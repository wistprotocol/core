use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Consistent,
    Inconsistent,
    Unreachable,
    DynamicVariance,
    NotAuditable,
    LinkVariance,
    LinkInconsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unmeasured {
    Observed,
    Reference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "AuditRecordWire")]
pub struct AuditRecord {
    pub wist_version: String,
    pub audited_delta: String,
    pub reference_delta: String,
    pub auditor_id: String,
    pub fetched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_extract_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<u64>,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_agreement: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub robots_excluded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmeasured: Option<Unmeasured>,
    pub vrf_proof: String,
    #[serde(deserialize_with = "crate::objects::required_nullable")]
    pub prev_record: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecordWire {
    wist_version: String,
    audited_delta: String,
    reference_delta: String,
    auditor_id: String,
    fetched_at: String,
    #[serde(default, deserialize_with = "present")]
    response_commitment: Option<String>,
    #[serde(default, deserialize_with = "present")]
    ref_extract_commitment: Option<String>,
    #[serde(default, deserialize_with = "present")]
    credit_commitment: Option<String>,
    #[serde(default, deserialize_with = "present")]
    similarity: Option<u64>,
    verdict: Verdict,
    #[serde(default, deserialize_with = "present")]
    evidence_commitment: Option<String>,
    #[serde(default, deserialize_with = "present")]
    link_agreement: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    robots_excluded: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    unmeasured: Option<Unmeasured>,
    vrf_proof: String,
    #[serde(deserialize_with = "crate::objects::required_nullable")]
    prev_record: Option<String>,
}

impl TryFrom<AuditRecordWire> for AuditRecord {
    type Error = String;

    fn try_from(record: AuditRecordWire) -> Result<Self, Self::Error> {
        let measured = !matches!(record.verdict, Verdict::Unreachable | Verdict::NotAuditable);
        let fields = [
            record.response_commitment.is_some(),
            record.credit_commitment.is_some(),
            record.ref_extract_commitment.is_some(),
            record.evidence_commitment.is_some(),
            record.similarity.is_some(),
        ];
        if fields.iter().any(|present| *present != measured) {
            return Err(
                "WIST4-E02: measured fields must accompany exactly the measured verdicts".into(),
            );
        }
        if (record.verdict == Verdict::NotAuditable) != record.unmeasured.is_some() {
            return Err("WIST4-E02: unmeasured must accompany exactly not_auditable".into());
        }
        Ok(Self {
            wist_version: record.wist_version,
            audited_delta: record.audited_delta,
            reference_delta: record.reference_delta,
            auditor_id: record.auditor_id,
            fetched_at: record.fetched_at,
            response_commitment: record.response_commitment,
            ref_extract_commitment: record.ref_extract_commitment,
            credit_commitment: record.credit_commitment,
            similarity: record.similarity,
            verdict: record.verdict,
            evidence_commitment: record.evidence_commitment,
            link_agreement: record.link_agreement,
            robots_excluded: record.robots_excluded,
            unmeasured: record.unmeasured,
            vrf_proof: record.vrf_proof,
            prev_record: record.prev_record,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecordEnvelope {
    pub record: AuditRecord,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    AggregatorKeyAdd,
    AggregatorKeyRemove,
    AuditorAdmit,
    AuditorRemove,
    ObserverRegister,
    ObserverCheckpoint,
    CanaryCommitment,
    CanaryReveal,
    Sanction,
    SanctionLift,
    Notice,
    Appeal,
    AppealRuling,
    ParameterChange,
    CoverageAttestation,
    PayloadWithdrawal,
    PullAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdate {
    pub wist_version: String,
    pub action: RegistryAction,
    pub subject: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub details: Option<Value>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence: Option<Vec<String>>,
    pub effective_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdateEnvelope {
    pub update: RegistryUpdate,
    pub sig: Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scoreboard {
    pub provisional: [u64; 3],
    pub standing: [u64; 3],
    pub mature: [u64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackRecord {
    pub checkpoint: String,
    pub scoreboard: Scoreboard,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationDetails {
    pub key_id: String,
    pub alg: KeyAlgorithm,
    pub public_key: String,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionDetails {
    pub key_id: String,
    pub alg: KeyAlgorithm,
    pub public_key: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub track_record: Option<TrackRecord>,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverCheckpointDetails {
    pub head: String,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryCommitmentDetails {
    pub root: String,
    pub leaves: u64,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryLeaf {
    pub index: u64,
    pub delta_id: String,
    pub leaf_hash: String,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryRevealDetails {
    pub commitment: String,
    pub leaves: Vec<CanaryLeaf>,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalDetails {
    pub key_id: String,
    #[serde(flatten)]
    pub extensions: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub enum RegistryDetails {
    Removal(RemovalDetails),
    Admission(AdmissionDetails),
    Registration(RegistrationDetails),
    ObserverCheckpoint(ObserverCheckpointDetails),
    CanaryCommitment(CanaryCommitmentDetails),
    CanaryReveal(CanaryRevealDetails),
    Other(Option<Value>),
}

impl RegistryUpdate {
    pub fn typed_details(&self) -> Result<RegistryDetails, crate::error::Error> {
        use RegistryAction::*;
        let value = self.details.clone().unwrap_or(Value::Null);
        let parsed = match self.action {
            AuditorAdmit => serde_json::from_value(value).map(RegistryDetails::Admission),
            AuditorRemove => serde_json::from_value(value).map(RegistryDetails::Removal),
            ObserverRegister => serde_json::from_value(value).map(RegistryDetails::Registration),
            ObserverCheckpoint => {
                serde_json::from_value(value).map(RegistryDetails::ObserverCheckpoint)
            }
            CanaryCommitment => {
                serde_json::from_value(value).map(RegistryDetails::CanaryCommitment)
            }
            CanaryReveal => serde_json::from_value(value).map(RegistryDetails::CanaryReveal),
            _ => return Ok(RegistryDetails::Other(self.details.clone())),
        };
        let details = parsed.map_err(|e| crate::error::Error::Roster(format!("WIST4-E04: {e}")))?;
        let valid = match &details {
            RegistryDetails::Admission(d) => {
                key_fields(&d.key_id, &d.public_key)
                    && d.track_record
                        .as_ref()
                        .is_none_or(|t| digest(&t.checkpoint))
            }
            RegistryDetails::Registration(d) => key_fields(&d.key_id, &d.public_key),
            RegistryDetails::Removal(d) => {
                d.key_id.chars().count() <= 64
                    && self.evidence.as_ref().is_none_or(|ids| !ids.is_empty())
            }
            RegistryDetails::ObserverCheckpoint(d) => digest(&d.head),
            RegistryDetails::CanaryCommitment(d) => digest(&d.root),
            RegistryDetails::CanaryReveal(d) => {
                digest(&d.commitment)
                    && !d.leaves.is_empty()
                    && d.leaves.iter().all(|leaf| {
                        digest(&leaf.delta_id)
                            && digest(&leaf.leaf_hash)
                            && leaf.path.iter().all(|hash| digest(hash))
                    })
            }
            RegistryDetails::Other(_) => true,
        };
        if !valid {
            return Err(crate::error::Error::Roster(
                "WIST4-E04: malformed Registry details or evidence".into(),
            ));
        }
        if matches!(&details, RegistryDetails::CanaryCommitment(d) if d.leaves == 0) {
            return Err(crate::error::Error::Roster(
                "WIST4-E08: a canary commitment must name at least one leaf".into(),
            ));
        }
        Ok(details)
    }
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn key_fields(key_id: &str, public_key: &str) -> bool {
    key_id.chars().count() <= 64
        && public_key.len() == 43
        && public_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
