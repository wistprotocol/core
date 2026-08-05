use crate::crypto::{verify, PublicKey};
use crate::error::Error;
use crate::jcs;
use serde_json::Value;

pub fn verify_envelope(doc: &Value, inner_key: &str, key: &PublicKey) -> Result<(), Error> {
    let inner = doc
        .get(inner_key)
        .ok_or_else(|| Error::Envelope(format!("missing inner object {inner_key:?}")))?;
    let sig = doc
        .pointer("/sig/value")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Envelope("missing sig.value".into()))?;
    let canonical = jcs::canonicalize(inner)?;
    verify(key, &canonical, sig)
}
