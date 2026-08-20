use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn domain_digest(domain: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    hex::encode(digest.finalize())
}

pub fn is_lower_hex(value: &str, byte_count: usize) -> bool {
    value.len() == byte_count * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

#[cfg(test)]
mod tests {
    use super::{bool_text, domain_digest, is_lower_hex, sha256_hex};

    #[test]
    fn domain_digest_is_stable_and_separated() {
        let first = domain_digest("hartevo-plugin-test/v1", &["a", "b"]);
        let second = domain_digest("hartevo-plugin-test/v1", &["a", "b"]);
        let different_domain = domain_digest("other/v1", &["a", "b"]);
        let different_order = domain_digest("hartevo-plugin-test/v1", &["b", "a"]);
        assert_eq!(first, second);
        assert_ne!(first, different_domain);
        assert_ne!(first, different_order);
        assert!(is_lower_hex(&first, 32));
        assert!(is_lower_hex(&sha256_hex(b"fixture"), 32));
        assert_eq!(bool_text(true), "true");
        assert_eq!(bool_text(false), "false");
    }
}
