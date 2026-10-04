//! WIST-1 §4 and RFC 8785 §3.1: a repeated decoded member name at any depth is rejected, and so
//! are arrays and objects nested deeper than 64 levels, the top-level value being level 1.
use serde::de::{DeserializeSeed, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
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

#[derive(Clone, Copy)]
struct Eligible {
    enclosing: usize,
}

impl<'de> DeserializeSeed<'de> for Eligible {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Eligible {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_unit<E: Error>(self) -> Result<bool, E> {
        Ok(true)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<bool, A::Error> {
        let inner = Eligible {
            enclosing: self.enclosing + 1,
        };
        let mut eligible = self.enclosing < NESTING_LEVELS_MAX;
        while let Some(element) = seq.next_element_seed(inner)? {
            eligible &= element;
        }
        Ok(eligible)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let inner = Eligible {
            enclosing: self.enclosing + 1,
        };
        let mut eligible = self.enclosing < NESTING_LEVELS_MAX;
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            eligible &= names.insert(name);
            eligible &= map.next_value_seed(inner)?;
        }
        Ok(eligible)
    }
}

#[derive(Clone, Copy)]
struct Member<'p> {
    path: &'p [&'p str],
    enclosing: usize,
}

impl<'de> DeserializeSeed<'de> for Member<'_> {
    type Value = Option<bool>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Option<bool>, D::Error> {
        if self.path.is_empty() {
            return Eligible {
                enclosing: self.enclosing,
            }
            .deserialize(deserializer)
            .map(Some);
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Member<'_> {
    type Value = Option<bool>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON")
    }

    fn visit_bool<E: Error>(self, _: bool) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_i64<E: Error>(self, _: i64) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_u64<E: Error>(self, _: u64) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_f64<E: Error>(self, _: f64) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_str<E: Error>(self, _: &str) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_unit<E: Error>(self) -> Result<Option<bool>, E> {
        Ok(None)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Option<bool>, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<bool>, A::Error> {
        let inner = Member {
            path: &self.path[1..],
            enclosing: self.enclosing + 1,
        };
        let mut found = None;
        while let Some(name) = map.next_key::<String>()? {
            if name == self.path[0] {
                found = map.next_value_seed(inner)?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

/// WIST-1 §4: of a member repeated along `path`, the last is read, as `serde_json` reads it.
pub fn member_eligible(raw: &[u8], path: &[&str]) -> Option<bool> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let found = Member { path, enclosing: 0 }
        .deserialize(&mut deserializer)
        .ok()?;
    deserializer.end().ok()?;
    found
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
    fn a_member_is_judged_eligible_apart_from_its_siblings() {
        let raw = br#"{"type":"label","body":{"label":{"a":1},"sig":{},"note":1,"note":2}}"#;
        assert_eq!(member_eligible(raw, &[]), Some(false));
        assert_eq!(member_eligible(raw, &["body"]), Some(false));
        assert_eq!(member_eligible(raw, &["body", "label"]), Some(true));
        assert_eq!(member_eligible(raw, &["body", "missing"]), None);
        assert_eq!(member_eligible(raw, &["type", "label"]), None);
        let inner = br#"{"body":{"label":{"a":1,"a":2}}}"#;
        assert_eq!(member_eligible(inner, &["body", "label"]), Some(false));
        assert_eq!(member_eligible(b"{\"a\":1,}", &["a"]), None);
        let deep = format!("{}1{}", "[".repeat(64), "]".repeat(64));
        assert_eq!(member_eligible(deep.as_bytes(), &[]), Some(true));
        let past = format!("{{\"a\":{}1{}}}", "[".repeat(64), "]".repeat(64));
        assert_eq!(member_eligible(past.as_bytes(), &[]), Some(false));
        assert_eq!(member_eligible(past.as_bytes(), &["a"]), Some(false));
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
