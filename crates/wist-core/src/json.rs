//! WIST-1 §4 and RFC 8785 §3.1: a repeated decoded member name at any depth is rejected, and so
//! are arrays and objects nested deeper than 64 levels, the top-level value being level 1.
use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use std::collections::HashSet;
use std::fmt;

pub const NESTING_LEVELS_MAX: usize = 64;

#[derive(Clone, Copy)]
struct Unique {
    enclosing: usize,
}

impl Unique {
    fn inner<E: Error>(self) -> Result<Self, E> {
        if self.enclosing >= NESTING_LEVELS_MAX {
            return Err(E::custom("JSON nested deeper than 64 levels"));
        }
        Ok(Self {
            enclosing: self.enclosing + 1,
        })
    }
}

impl<'de> DeserializeSeed<'de> for Unique {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Unique {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object member names")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let inner = self.inner()?;
        while seq.next_element_seed(inner)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let inner = self.inner()?;
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(A::Error::custom("duplicate JSON member name"));
            }
            map.next_value_seed(inner)?;
        }
        Ok(())
    }
}

pub fn validate(raw: &[u8]) -> serde_json::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    Unique { enclosing: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()
}

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

    fn nested(levels: usize, open: &str, close: &str) -> String {
        format!("{}{}", open.repeat(levels), close.repeat(levels))
    }

    #[test]
    fn nesting_is_accepted_at_64_levels_and_refused_at_65() {
        for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
            let at_bound = nested(NESTING_LEVELS_MAX, open, close).replace(":}", ":1}");
            validate(at_bound.as_bytes()).unwrap_or_else(|e| panic!("{open}: {e}"));
            parse(at_bound.as_bytes()).unwrap();
            let past = nested(NESTING_LEVELS_MAX + 1, open, close).replace(":}", ":1}");
            assert!(validate(past.as_bytes()).is_err(), "{open}");
            assert!(parse(past.as_bytes()).is_err(), "{open}");
        }
        let scalar_inside = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        validate(scalar_inside.as_bytes()).unwrap();
        let mixed = format!("{}[{{}}]{}", "[{\"a\":".repeat(31), "}]".repeat(31));
        validate(mixed.as_bytes()).unwrap();
        let mixed_past = format!("{}[[{{}}]]{}", "[{\"a\":".repeat(31), "}]".repeat(31));
        assert!(validate(mixed_past.as_bytes()).is_err());
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
