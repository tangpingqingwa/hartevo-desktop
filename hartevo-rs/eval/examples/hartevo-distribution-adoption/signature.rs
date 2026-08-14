use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::digest::{is_lower_hex, sha256_hex};

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub fn decode_lower_hex_exact(value: &str, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    ensure!(
        is_lower_hex(value, expected_bytes),
        "{label} is not canonical lowercase hex with the required length"
    );
    hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))
}

pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let public_key = decode_lower_hex_exact(
        public_key_hex,
        ED25519_PUBLIC_KEY_BYTES,
        "Ed25519 verification key",
    )?;
    let signature = decode_lower_hex_exact(
        signature_hex,
        ED25519_SIGNATURE_BYTES,
        "Ed25519 detached signature",
    )?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 detached signature verification failed"))
}

pub fn signature_digest(signature_hex: &str) -> Result<String> {
    let signature = decode_lower_hex_exact(
        signature_hex,
        ED25519_SIGNATURE_BYTES,
        "Ed25519 detached signature",
    )?;
    Ok(sha256_hex(&signature))
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::verify_ed25519;

    #[test]
    fn tampered_detached_signature_fails() {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).expect("fixed signer");
        let public_key = hex::encode(signer.public_key().as_ref());
        let signature = hex::encode(signer.sign(b"payload").as_ref());
        verify_ed25519(&public_key, b"payload", &signature).expect("valid signature");
        verify_ed25519(&public_key, b"tampered", &signature).expect_err("tampered payload");
    }
}
