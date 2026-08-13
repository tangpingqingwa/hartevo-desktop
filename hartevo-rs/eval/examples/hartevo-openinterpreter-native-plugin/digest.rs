use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

pub fn sha256_text(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

pub fn sha256_json<T: Serialize>(value: &T) -> serde_json::Result<String> {
    serde_json::to_vec(value).map(sha256_hex)
}

pub fn oracle_digest_json<T: Serialize>(domain: &str, value: &T) -> serde_json::Result<String> {
    let mut bytes = Vec::with_capacity(domain.len() + 1 + 256);
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&serde_json::to_vec(value)?);
    Ok(sha256_hex(bytes))
}

pub fn domain_digest(domain: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_lower_sha256(value: &str) -> bool {
    is_sha256(value)
        && value
            .chars()
            .all(|character| !character.is_ascii_uppercase())
}
