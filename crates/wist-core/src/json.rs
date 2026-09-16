//! WIST-1 §4 and RFC 8785 §3.1: protocol JSON is rejected when any object,
//! at any depth, repeats a decoded member name, before a parsed value that
//! would silently keep the last occurrence can reach field, signature or
//! replay checks.
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

struct Unique;

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Unique)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = Self;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object member names")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_unit<E: Error>(self) -> Result<Self, E> {
        Ok(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self, A::Error> {
        while seq.next_element::<Unique>()?.is_some() {}
        Ok(self)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self, A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(A::Error::custom("duplicate JSON member name"));
            }
            map.next_value::<Unique>()?;
        }
        Ok(self)
    }
}

/// Rejects malformed JSON and any repeated decoded member name.
pub fn validate(raw: &[u8]) -> serde_json::Result<()> {
    serde_json::from_slice::<Unique>(raw)?;
    Ok(())
}

/// `validate` followed by the ordinary parse.
pub fn parse(raw: &[u8]) -> serde_json::Result<serde_json::Value> {
    validate(raw)?;
    serde_json::from_slice(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn spec_dir() -> PathBuf {
        std::env::var_os("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../spec"))
    }

    #[test]
    fn repeated_decoded_names_are_rejected_at_every_depth() {
        for raw in [
            r#"{"a":1,"a":1}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"x":{"a":1,"a":2}}"#,
            r#"{"x":[{"a":1},{"b":1,"b":2}]}"#,
            r#"{"a":null,"a":{"b":1}}"#,
        ] {
            assert!(validate(raw.as_bytes()).is_err(), "{raw}");
        }
        for raw in [
            r#"{"a":1,"b":1}"#,
            r#"{"a":{"a":1},"b":[{"a":1},{"a":2}]}"#,
            r#"[1,"a",null,true,1.5]"#,
            r#""a""#,
        ] {
            validate(raw.as_bytes()).unwrap_or_else(|e| panic!("{raw}: {e}"));
        }
        assert!(validate(b"{\"a\":1,}").is_err());
    }

    #[test]
    fn raw_payload_probes_fail_before_field_checks() {
        let vector: serde_json::Value = serde_json::from_slice(
            &std::fs::read(spec_dir().join("vectors/wist1/payload-fields.json")).unwrap(),
        )
        .unwrap();
        let mut probes = 0;
        for case in vector["cases"].as_array().unwrap() {
            let Some(raw) = case["payload_json"].as_str() else {
                continue;
            };
            probes += 1;
            let allowed: Vec<&str> = case["allowed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(
                validate(raw.as_bytes()).is_err(),
                allowed == ["WIST1-E05"],
                "{}",
                case["name"]
            );
        }
        assert!(probes > 0);
    }
}
