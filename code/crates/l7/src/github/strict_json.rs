//! JSON with duplicate object keys rejected at any depth: another parser
//! (the server's) could keep the other copy of a key.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A JSON value parsed with duplicate object keys rejected (another parser
/// could keep the other copy).
pub struct Strict(pub serde_json::Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("JSON without duplicate keys")
    }
    fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E> {
        Ok(b.into())
    }
    fn visit_i64<E>(self, n: i64) -> Result<Self::Value, E> {
        Ok(n.into())
    }
    fn visit_u64<E>(self, n: u64) -> Result<Self::Value, E> {
        Ok(n.into())
    }
    fn visit_f64<E>(self, n: f64) -> Result<Self::Value, E> {
        Ok(n.into())
    }
    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
        Ok(s.into())
    }
    fn visit_string<E>(self, s: String) -> Result<Self::Value, E> {
        Ok(s.into())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut v = Vec::new();
        while let Some(Strict(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(v.into())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            let Strict(v) = a.next_value()?;
            if m.insert(k, v).is_some() {
                return Err(serde::de::Error::custom("duplicate key"));
            }
        }
        Ok(m.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        assert!(serde_json::from_str::<Strict>(r#"{"a": 1, "a": 2}"#).is_err());
        assert!(serde_json::from_str::<Strict>(r#"{"a": [{"b": 1, "b": 1}]}"#).is_err());
        let Strict(v) = serde_json::from_str(r#"{"a": [1, 2.5, "x", null, true, {"b": {}}]}"#).unwrap();
        assert_eq!(v, serde_json::json!({"a": [1, 2.5, "x", null, true, {"b": {}}]}));
    }
}
