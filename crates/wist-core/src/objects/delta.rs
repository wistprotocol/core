use crate::objects::Sig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    New,
    Update,
    Delete,
    Attest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaPayloadCommitment {
    pub commitment: String,
    pub alg: String,
    #[serde(deserialize_with = "deserialize_integral")]
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaMeta {
    pub lang: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delta {
    pub wist_version: String,
    #[serde(deserialize_with = "deserialize_publisher")]
    pub publisher: String,
    pub url: String,
    pub change_type: ChangeType,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<DeltaPayloadCommitment>,
    pub meta: DeltaMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeltaEnvelope {
    pub delta: Delta,
    pub sig: Sig,
}

fn deserialize_publisher<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    crate::delta::validate_publisher(&value).map_err(serde::de::Error::custom)?;
    Ok(value)
}

/// WIST-1 §7: `payload.bytes` eligibility reads the JSON number's value,
/// so `1`, `1.0` and `1e0` are the same nonnegative safe integer.
fn deserialize_integral<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let value = f64::deserialize(deserializer)?;
    if value.is_finite() && value.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&value)
    {
        Ok(value as u64)
    } else {
        Err(serde::de::Error::custom(
            "payload.bytes must be a nonnegative safe integer",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_bytes_read_by_numeric_value() {
        for spelling in ["263", "263.0", "2.63e2"] {
            let commitment: DeltaPayloadCommitment = serde_json::from_str(&format!(
                "{{\"commitment\":\"hmac-sha256:{}\",\"alg\":\"HMAC-SHA256\",\"bytes\":{spelling}}}",
                "0".repeat(64)
            ))
            .unwrap();
            assert_eq!(commitment.bytes, 263);
        }
        for spelling in ["-1", "1.5", "9007199254740992", "1e400"] {
            assert!(serde_json::from_str::<DeltaPayloadCommitment>(&format!(
                "{{\"commitment\":\"hmac-sha256:{}\",\"alg\":\"HMAC-SHA256\",\"bytes\":{spelling}}}",
                "0".repeat(64)
            ))
            .is_err());
        }
    }
}
