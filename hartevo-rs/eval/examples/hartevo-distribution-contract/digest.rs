use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
        assert!(is_lower_hex(&sha256_hex(b"hartevo-distribution"), 32));
        assert!(!is_lower_hex("ABC", 32));
    }
}
