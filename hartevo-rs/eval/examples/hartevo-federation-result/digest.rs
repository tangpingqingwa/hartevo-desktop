use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn domain_canonical_json_bytes(domain: &str, value: &Value) -> serde_json::Result<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let mut message = Vec::with_capacity(16 + domain.len() + canonical.len());
    message.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    message.extend_from_slice(&canonical);
    Ok(message)
}

#[cfg(test)]
pub fn sha256_json(value: &Value) -> serde_json::Result<String> {
    canonical_json_bytes(value).map(|bytes| sha256_hex(&bytes))
}

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn parse_strict_json<T: serde::de::DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn canonical_json_bytes(value: &Value) -> serde_json::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => serde_json::to_writer(output, value)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{domain_canonical_json_bytes, is_lower_hex, sha256_hex, sha256_json};

    #[test]
    fn canonical_json_is_order_independent() {
        let first = json!({"b": 2, "a": 1});
        let second = json!({"a": 1, "b": 2});
        assert_eq!(
            sha256_json(&first).expect("digest"),
            sha256_json(&second).expect("digest")
        );
    }

    #[test]
    fn domains_are_length_delimited() {
        let value = json!({"root": "a"});
        assert_ne!(
            domain_canonical_json_bytes("result/v1", &value).expect("message"),
            domain_canonical_json_bytes("result/v10", &value).expect("message")
        );
    }

    #[test]
    fn sha256_is_lower_hex() {
        assert!(is_lower_hex(&sha256_hex(b"federation"), 32));
    }
}
