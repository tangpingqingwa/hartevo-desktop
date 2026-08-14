use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::SupabaseIdentityError;

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn serialized_digest<T: Serialize>(value: &T) -> Result<String, SupabaseIdentityError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SupabaseIdentityError::Canonicalization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn digest_parts(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_digest(value: &str, field: &'static str) -> Result<(), SupabaseIdentityError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(SupabaseIdentityError::InvalidModel(format!(
            "{field} must be a lowercase or uppercase SHA-256 digest"
        )))
    }
}
