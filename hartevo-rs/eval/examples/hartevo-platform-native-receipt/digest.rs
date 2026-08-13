use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_json(value: &impl Serialize) -> serde_json::Result<String> {
    serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes))
}

#[cfg(test)]
pub fn sha256_canonical_json(value: &Value) -> serde_json::Result<String> {
    canonical_json_bytes(value).map(|bytes| sha256_hex(&bytes))
}

pub fn sha256_domain_canonical_json(domain: &str, value: &Value) -> serde_json::Result<String> {
    domain_canonical_json_bytes(domain, value).map(|bytes| sha256_hex(&bytes))
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

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        domain_canonical_json_bytes, is_lower_hex, sha256_canonical_json,
        sha256_domain_canonical_json, sha256_hex,
    };

    #[test]
    fn digest_is_lowercase_sha256() {
        let digest = sha256_hex(b"hartevo-platform-native-receipt");
        assert!(is_lower_hex(&digest, 32));
        assert!(!is_lower_hex(&digest.to_uppercase(), 32));
    }

    #[test]
    fn canonical_json_digest_ignores_object_insertion_order() {
        let first = json!({"a": 1, "b": [true, "x"]});
        let second = serde_json::from_str(r#"{"b":[true,"x"],"a":1}"#).expect("valid JSON");
        assert_eq!(
            sha256_canonical_json(&first).expect("digest"),
            sha256_canonical_json(&second).expect("digest")
        );
    }

    #[test]
    fn signed_payload_digest_is_domain_separated() {
        let payload = json!({"receiptId": "receipt_01"});
        assert_ne!(
            sha256_domain_canonical_json("domain-a", &payload).expect("digest"),
            sha256_domain_canonical_json("domain-b", &payload).expect("digest")
        );
    }

    #[test]
    fn signed_payload_bytes_are_canonical_and_length_delimited() {
        let first = json!({"b": 2, "a": 1});
        let second = json!({"a": 1, "b": 2});
        assert_eq!(
            domain_canonical_json_bytes("receipt/v2", &first).expect("message"),
            domain_canonical_json_bytes("receipt/v2", &second).expect("message")
        );
        assert_ne!(
            domain_canonical_json_bytes("receipt/v2", &first).expect("message"),
            domain_canonical_json_bytes("receipt/v20", &first).expect("message")
        );
    }
}
