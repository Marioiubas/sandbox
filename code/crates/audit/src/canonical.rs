//! Canonical JSON for hashing (format version 1).
//!
//! Object keys are sorted bytewise (serde_json's default `Map` is a
//! `BTreeMap`), no insignificant whitespace, strings escaped by serde_json,
//! and only integer numbers: a float anywhere is an error, because float
//! formatting is the classic source of non-deterministic hashes.

use serde::Serialize;
use serde_json::Value;

pub fn canonical_json<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(v)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
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
    fn floats_rejected() {
        assert!(canonical_json(&json!({"x": 1.5})).is_err());
    }
}
