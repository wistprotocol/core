use crate::error::Error;
use serde_json::Value;

const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// RFC 8785 JSON Canonicalization Scheme, restricted to the value shapes
/// WIST objects use: no floats, no integers outside ±2^53-1 (all registry
/// parameters are micro-units, so this restriction is deliberate).
pub fn canonicalize(v: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write_value(v, &mut out)?;
    Ok(out)
}

fn write_value(v: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            let i = n
                .as_i64()
                .filter(|i| i.abs() <= MAX_SAFE)
                .ok_or_else(|| Error::Jcs(format!("unsupported number {n}")))?;
            out.extend_from_slice(i.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| {
                a.encode_utf16()
                    .collect::<Vec<u16>>()
                    .cmp(&b.encode_utf16().collect::<Vec<u16>>())
            });
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&m[*k], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::canonicalize;
    use serde_json::json;

    fn c(v: serde_json::Value) -> String {
        String::from_utf8(canonicalize(&v).unwrap()).unwrap()
    }

    #[test]
    fn sorts_keys_by_utf16_code_units() {
        assert_eq!(c(json!({"b":1,"a":2})), r#"{"a":2,"b":1}"#);
        // '€' (U+20AC, one UTF-16 unit 0x20AC) sorts before '𝄞' (U+1D11E,
        // surrogate pair starting 0xD834), which sorts before 'ﬁ' (U+FB01):
        // surrogate code units (0xD800-0xDFFF) are numerically below the
        // Alphabetic Presentation Forms block, even though UTF-8 byte order
        // would rank 'ﬁ' before '𝄞'.
        assert_eq!(
            c(json!({"𝄞": 1, "€": 2, "ﬁ": 3})),
            "{\"€\":2,\"𝄞\":1,\"ﬁ\":3}"
        );
    }

    #[test]
    fn escapes_strings_like_ecma262() {
        assert_eq!(
            c(json!("a\"b\\c\u{8}\u{c}\n\r\t\u{1f}")),
            r#""a\"b\\c\b\f\n\r\t\u001f""#
        );
        assert_eq!(c(json!("é€𝄞")), "\"é€𝄞\"");
    }

    #[test]
    fn integers_only() {
        assert_eq!(
            c(json!([0, -1, 9007199254740991i64])),
            "[0,-1,9007199254740991]"
        );
        assert!(canonicalize(&json!(1.5)).is_err());
        assert!(canonicalize(&json!(9007199254740992i64)).is_err());
    }

    #[test]
    fn literals_and_nesting() {
        assert_eq!(
            c(json!({"x":[true,false,null,{}]})),
            r#"{"x":[true,false,null,{}]}"#
        );
    }
}

#[cfg(test)]
mod props {
    use proptest::prelude::*;

    fn arb_json() -> impl Strategy<Value = serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::from),
            (-9_007_199_254_740_991i64..=9_007_199_254_740_991).prop_map(serde_json::Value::from),
            ".*".prop_map(serde_json::Value::from),
        ];
        leaf.prop_recursive(4, 32, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::from),
                prop::collection::hash_map(".*", inner, 0..8)
                    .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        #[test]
        fn canonical_roundtrip_is_fixpoint(v in arb_json()) {
            let c1 = super::canonicalize(&v).unwrap();
            let reparsed: serde_json::Value =
                serde_json::from_slice(&c1).unwrap();
            let c2 = super::canonicalize(&reparsed).unwrap();
            prop_assert_eq!(c1, c2);
        }
    }
}
