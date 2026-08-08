use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub wist_version: String,
    pub audited_delta: String,
    pub auditor_id: String,
    pub fetched_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_extract_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<u64>,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_agreement: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub robots_excluded: Option<bool>,
    pub vrf_proof: String,
    pub prev_record: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<String>>,
    pub effective_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdateEnvelope {
    pub update: RegistryUpdate,
    pub sig: Sig,
}
