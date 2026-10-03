use crate::objects::Sig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    AggregatorKeyAdd,
    AggregatorKeyRemove,
    ParameterChange,
    PayloadWithdrawal,
    SuffixListUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdate {
    pub wist_version: String,
    pub action: RegistryAction,
    pub subject: String,
    pub details: Value,
    pub effective_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryUpdateEnvelope {
    pub update: RegistryUpdate,
    pub sig: Sig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAddDetails {
    pub key_id: String,
    pub alg: KeyAlgorithm,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRemoveDetails {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterChangeDetails {
    pub parameter: String,
    pub value: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadWithdrawalDetails {
    pub delta_id: String,
    pub legal_basis: String,
    pub jurisdiction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuffixListDetails {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub enum RegistryDetails {
    KeyAdd(KeyAddDetails),
    KeyRemove(KeyRemoveDetails),
    ParameterChange(ParameterChangeDetails),
    PayloadWithdrawal(PayloadWithdrawalDetails),
    SuffixListUpdate(SuffixListDetails),
}

impl RegistryUpdate {
    /// WIST-4 §5.1: a violation of the action's `details` and `subject` contract is `WIST4-E04`,
    /// except a `parameter_change` naming no §5 identifier or a value outside its §5 bound, which
    /// §5 rejects with `WIST4-E03`.
    pub fn typed_details(&self) -> Result<RegistryDetails, crate::error::Error> {
        use RegistryAction::*;
        let value = self.details.clone();
        let parsed = match self.action {
            AggregatorKeyAdd => serde_json::from_value(value).map(RegistryDetails::KeyAdd),
            AggregatorKeyRemove => serde_json::from_value(value).map(RegistryDetails::KeyRemove),
            ParameterChange => serde_json::from_value(value).map(RegistryDetails::ParameterChange),
            PayloadWithdrawal => {
                serde_json::from_value(value).map(RegistryDetails::PayloadWithdrawal)
            }
            SuffixListUpdate => {
                serde_json::from_value(value).map(RegistryDetails::SuffixListUpdate)
            }
        };
        let details =
            parsed.map_err(|e| crate::error::Error::Envelope(format!("WIST4-E04: {e}")))?;
        let valid = match &details {
            RegistryDetails::KeyAdd(d) => {
                key_id(&d.key_id) && public_key(&d.public_key) && self.subject == d.key_id
            }
            RegistryDetails::KeyRemove(d) => key_id(&d.key_id) && self.subject == d.key_id,
            RegistryDetails::ParameterChange(d) => {
                (-crate::parameters::WIRE_INTEGER_MAX..=crate::parameters::WIRE_INTEGER_MAX)
                    .contains(&d.value)
                    && self.subject == d.parameter
            }
            RegistryDetails::PayloadWithdrawal(d) => {
                digest(&d.delta_id)
                    && (1..=1024).contains(&d.legal_basis.chars().count())
                    && (1..=128).contains(&d.jurisdiction.chars().count())
                    && crate::host::canonical_host(&self.subject)
                        .is_ok_and(|host| host == self.subject)
            }
            RegistryDetails::SuffixListUpdate(d) => {
                digest(&d.sha256)
                    && (1..=9_007_199_254_740_991).contains(&d.bytes)
                    && self.subject == d.sha256
            }
        };
        if !valid {
            return Err(crate::error::Error::Envelope(
                "WIST4-E04: Registry Update details violate the action's contract".into(),
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

fn key_id(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 64
}

fn public_key(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameter_change(subject: &str, details: Value) -> RegistryUpdate {
        RegistryUpdate {
            wist_version: "1.0.0".into(),
            action: RegistryAction::ParameterChange,
            subject: subject.into(),
            details,
            effective_at: "2026-08-09T00:00:00Z".into(),
        }
    }

    fn outcome(update: &RegistryUpdate) -> Option<(String, i64)> {
        match update.typed_details() {
            Ok(RegistryDetails::ParameterChange(details)) => {
                Some((details.parameter, details.value))
            }
            Ok(_) => panic!("a parameter_change reads as another action"),
            Err(_) => None,
        }
    }

    #[test]
    fn an_unknown_identifier_or_an_out_of_bound_value_passes_the_field_check() {
        let unknown = parameter_change(
            "sampling_floor",
            serde_json::json!({"parameter": "sampling_floor", "value": 1}),
        );
        assert_eq!(outcome(&unknown), Some(("sampling_floor".into(), 1)));
        let out_of_bound = parameter_change(
            "quota_base",
            serde_json::json!({"parameter": "quota_base", "value": 0}),
        );
        assert_eq!(outcome(&out_of_bound), Some(("quota_base".into(), 0)));
    }

    #[test]
    fn a_parameter_change_fails_its_fields_for_another_subject_type_or_wire_range() {
        let other_subject = parameter_change(
            "quota_base",
            serde_json::json!({"parameter": "sampling_floor", "value": 1}),
        );
        assert_eq!(outcome(&other_subject), None);
        let non_string = parameter_change(
            "quota_base",
            serde_json::json!({"parameter": 7, "value": 1}),
        );
        assert_eq!(outcome(&non_string), None);
        let beyond_wire = parameter_change(
            "quota_base",
            serde_json::json!({"parameter": "quota_base", "value": 9_007_199_254_740_992_i64}),
        );
        assert_eq!(outcome(&beyond_wire), None);
    }
}
