use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn digest_json<T: Serialize>(domain: &str, value: &T) -> serde_json::Result<String> {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + 256);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&serde_json::to_vec(value)?);
    Ok(sha256_hex(&bytes))
}

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{digest_json, is_lower_hex};

    #[test]
    fn digests_are_domain_separated_lowercase_sha256() {
        let first = digest_json("plugin-journey", &serde_json::json!({"value": 1})).unwrap();
        let second = digest_json("plugin-journey-other", &serde_json::json!({"value": 1})).unwrap();
        assert_ne!(first, second);
        assert!(is_lower_hex(&first, 32));
        assert!(!is_lower_hex(&first.to_uppercase(), 32));
    }
}
