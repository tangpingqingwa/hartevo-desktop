use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_json(value: &impl Serialize) -> serde_json::Result<String> {
    serde_json::to_vec(value).map(|bytes| sha256_hex(&bytes))
}

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_lower_hex, sha256_hex};

    #[test]
    fn digest_is_lowercase_sha256() {
        let digest = sha256_hex(b"hartevo-platform-contract");
        assert!(is_lower_hex(&digest, 32));
        assert!(!is_lower_hex(&digest.to_uppercase(), 32));
    }
}
