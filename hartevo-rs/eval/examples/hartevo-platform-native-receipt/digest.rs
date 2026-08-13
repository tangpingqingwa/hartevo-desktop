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
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    Ok(sha256_hex(&bytes))
}

pub fn sha256_domain_canonical_json(domain: &str, value: &Value) -> serde_json::Result<String> {
    let mut canonical = Vec::new();
    write_canonical_json(value, &mut canonical)?;
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
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

    use super::{is_lower_hex, sha256_canonical_json, sha256_domain_canonical_json, sha256_hex};

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
}
