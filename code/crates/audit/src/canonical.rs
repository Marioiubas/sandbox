//! Canonical JSON for hashing (format version 1).
//!
//! Object keys are sorted bytewise **by this encoder** (never by relying on
//! `serde_json::Map`, whose order changes when any crate in the build turns
//! on serde_json's `preserve_order` feature, as cedar-policy does), no
//! insignificant whitespace, strings escaped by serde_json, and only integer
//! numbers: a float anywhere is an error, because float formatting is the
//! classic source of non-deterministic hashes.

use serde::Serialize;
use serde_json::Value;

pub fn canonical_json<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(v)?;
    reject_floats(&value)?;
    let mut out = Vec::new();
    write_canonical(&value, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) -> anyhow::Result<()> {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(k)?);
                out.push(b':');
                write_canonical(&o[k.as_str()], out)?;
            }
            out.push(b'}');
        }
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(x, out)?;
            }
            out.push(b']');
        }
        scalar => out.extend(serde_json::to_vec(scalar)?),
    }
    Ok(())
}

fn reject_floats(v: &Value) -> anyhow::Result<()> {
    match v {
        Value::Number(n) if n.is_f64() => anyhow::bail!("floats are not allowed in audit events"),
        Value::Array(a) => a.iter().try_for_each(reject_floats),
        Value::Object(o) => o.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted_no_whitespace() {
        let v = json!({"b": 1, "a": {"d": [1, 2], "c": "x"}});
        assert_eq!(canonical_json(&v).unwrap(), br#"{"a":{"c":"x","d":[1,2]},"b":1}"#);
    }

    #[test]
    fn order_independent_of_insertion() {
        // Built in reverse insertion order: the encoding must not change.
        let mut m = serde_json::Map::new();
        m.insert("zeta".into(), json!(1));
        m.insert("alpha".into(), json!({"y": 2, "b": 3}));
        let a = canonical_json(&Value::Object(m)).unwrap();
        assert_eq!(a, br#"{"alpha":{"b":3,"y":2},"zeta":1}"#);
    }

    #[test]
    fn floats_rejected() {
        assert!(canonical_json(&json!({"x": 1.5})).is_err());
    }
}
