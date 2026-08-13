use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::digest::{is_lower_hex, sha256_hex};

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub fn signature_digest(signature_hex: &str) -> Result<String> {
    let signature = hex::decode(signature_hex).context("signature is not hexadecimal")?;
    ensure!(
        signature.len() == ED25519_SIGNATURE_BYTES
            && is_lower_hex(signature_hex, ED25519_SIGNATURE_BYTES),
        "signature is not canonical Ed25519 hexadecimal"
    );
    Ok(sha256_hex(&signature))
}

pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    ensure!(
        is_lower_hex(public_key_hex, ED25519_PUBLIC_KEY_BYTES),
        "public key is not canonical Ed25519 hexadecimal"
    );
    let public_key = hex::decode(public_key_hex).context("public key is not hexadecimal")?;
    let signature = hex::decode(signature_hex).context("signature is not hexadecimal")?;
    ensure!(
        signature.len() == ED25519_SIGNATURE_BYTES,
        "signature has the wrong length"
    );
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 signature verification failed"))
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::verify_ed25519;

    #[test]
    fn verifies_and_rejects_tampered_messages() {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[19; 32]).expect("fixed signer");
        let message = b"federation result";
        let signature = hex::encode(signer.sign(message).as_ref());
        let public_key = hex::encode(signer.public_key().as_ref());
        verify_ed25519(&public_key, message, &signature).expect("signature");
        verify_ed25519(&public_key, b"tampered", &signature).expect_err("tamper");
    }
}
