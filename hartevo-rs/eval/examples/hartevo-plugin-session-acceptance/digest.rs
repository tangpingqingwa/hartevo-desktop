use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn digest_json(domain: &str, value: &impl Serialize) -> serde_json::Result<String> {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(serde_json::to_vec(value)?);
    Ok(hex::encode(digest.finalize()))
}

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{digest_json, is_lower_hex, sha256_hex};

    #[test]
    fn digests_are_domain_separated_lowercase_sha256() {
        let raw = sha256_hex(b"plugin-session-acceptance");
        let typed = digest_json("hartevo-plugin-session-acceptance/v1", &42).expect("typed digest");
        assert!(is_lower_hex(&raw, 32));
        assert!(is_lower_hex(&typed, 32));
        assert_ne!(raw, typed);
    }
}
