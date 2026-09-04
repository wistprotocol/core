use crate::error::Error;
use serde_json::Value;

const MAX_SAFE: i64 = 9_007_199_254_740_991;

/// RFC 8785 JSON Canonicalization Scheme. A number outside the IEEE-754
/// double range has no canonical form and is rejected (`WIST1-E05`).
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
        Value::Number(n) => write_number(n, out)?,
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

/// RFC 8785 §3.2.2.3: a JSON number is an IEEE-754 double serialized by
/// the ECMA-262 `Number::toString` algorithm. Integers inside the
/// ±(2^53−1) safe range take the plain path, which that algorithm agrees
/// with exactly.
fn write_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), Error> {
    if let Some(i) = n.as_i64() {
        if (-MAX_SAFE..=MAX_SAFE).contains(&i) {
            out.extend_from_slice(i.to_string().as_bytes());
            return Ok(());
        }
    }
    let x = n
        .as_f64()
        .filter(|x| x.is_finite())
        .ok_or_else(|| Error::Jcs(format!("number {n} is outside the IEEE-754 double range")))?;
    out.extend_from_slice(number_to_string(x).as_bytes());
    Ok(())
}

fn number_to_string(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string();
    }
    if x < 0.0 {
        return format!("-{}", number_to_string(-x));
    }
    let shortest = format!("{x:e}");
    let (mantissa, exponent) = shortest
        .split_once('e')
        .expect("LowerExp emits an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exponent.parse::<i32>().expect("LowerExp emits an integer") + 1;
    if k <= n && n <= 21 {
        let mut s = digits;
        s.push_str(&"0".repeat((n - k) as usize));
        s
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat(-n as usize), digits)
    } else {
        let sign = if n > 1 { '+' } else { '-' };
        let magnitude = (n - 1).abs();
        if k == 1 {
            format!("{digits}e{sign}{magnitude}")
        } else {
            format!("{}.{}e{sign}{magnitude}", &digits[..1], &digits[1..])
        }
    }
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
    use serde_json::{json, Value};

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
    fn integers_keep_their_plain_form() {
        assert_eq!(
            c(json!([0, -1, 9007199254740991i64])),
            "[0,-1,9007199254740991]"
        );
        assert_eq!(c(json!(9007199254740992i64)), "9007199254740992");
        assert_eq!(c(json!(-9007199254740992i64)), "-9007199254740992");
    }

    #[test]
    #[allow(clippy::excessive_precision)]
    fn non_integers_serialize_by_the_ecma262_number_to_string() {
        let cases: &[(f64, &str)] = &[
            (1.5, "1.5"),
            (0.1, "0.1"),
            (-0.0, "0"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (333333333.33333329, "333333333.3333333"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (-1.5, "-1.5"),
            (1e30, "1e+30"),
        ];
        for (value, expected) in cases {
            assert_eq!(c(json!(value)), *expected, "value {value}");
        }
    }

    #[test]
    fn an_integer_past_the_safe_range_is_serialized_as_the_double_it_is() {
        assert_eq!(c(json!(i64::MIN)), "-9223372036854776000");
    }

    #[test]
    fn parsing_a_canonical_number_recovers_the_double_it_came_from() {
        let text = "5.3467826177869005e+177";
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.as_f64().unwrap(), text.parse::<f64>().unwrap());
    }

    #[test]
    fn a_number_outside_the_double_range_never_parses() {
        let parsed = serde_json::from_str::<Value>("1e400");
        assert!(parsed.is_err(), "{parsed:?}");
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
            any::<f64>()
                .prop_filter("JSON has no NaN or infinity", |x| x.is_finite())
                .prop_map(serde_json::Value::from),
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
