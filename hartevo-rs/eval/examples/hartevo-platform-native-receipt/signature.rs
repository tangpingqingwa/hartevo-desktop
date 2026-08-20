use anyhow::{Context, Result, ensure};
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::digest::sha256_hex;

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ED25519_SIGNATURE_BYTES: usize = 64;

pub fn decode_lower_hex_exact(value: &str, expected_bytes: usize, label: &str) -> Result<Vec<u8>> {
    let decoded = hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))?;
    ensure!(
        decoded.len() == expected_bytes && value == hex::encode(&decoded),
        "{label} is not canonical lowercase hex with the required length"
    );
    Ok(decoded)
}

pub fn verification_key_digest(public_key_hex: &str) -> Result<String> {
    decode_lower_hex_exact(
        public_key_hex,
        ED25519_PUBLIC_KEY_BYTES,
        "Ed25519 verification key",
    )
    .map(|key| sha256_hex(&key))
}

pub fn signature_digest(signature_hex: &str) -> Result<String> {
    decode_lower_hex_exact(signature_hex, ED25519_SIGNATURE_BYTES, "Ed25519 signature")
        .map(|signature| sha256_hex(&signature))
}

pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature_hex: &str) -> Result<()> {
    let public_key = decode_lower_hex_exact(
        public_key_hex,
        ED25519_PUBLIC_KEY_BYTES,
        "Ed25519 verification key",
    )?;
    let signature =
        decode_lower_hex_exact(signature_hex, ED25519_SIGNATURE_BYTES, "Ed25519 signature")?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| anyhow::anyhow!("Ed25519 receipt signature verification failed"))
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;

    use super::{signature_digest, verification_key_digest, verify_ed25519};
    use crate::digest::domain_canonical_json_bytes;

    fn signer() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[37; 32]).expect("fixed test signer")
    }

    #[test]
    fn verifies_domain_separated_canonical_payload() {
        let signer = signer();
        let message = domain_canonical_json_bytes(
            "hartevo-platform-native-receipt-signature/v2",
            &json!({"nonceHex": "11".repeat(32), "receiptId": "receipt_01"}),
        )
        .expect("canonical message");
        let signature = signer.sign(&message);
        let public_key_hex = hex::encode(signer.public_key().as_ref());
        let signature_hex = hex::encode(signature.as_ref());

        verify_ed25519(&public_key_hex, &message, &signature_hex).expect("valid signature");
        assert_eq!(
            verification_key_digest(&public_key_hex)
                .expect("key digest")
                .len(),
            64
        );
        assert_eq!(
            signature_digest(&signature_hex)
                .expect("signature digest")
                .len(),
            64
        );
    }

    #[test]
    fn rejects_tampering_and_noncanonical_hex() {
        let signer = signer();
        let message = b"authenticated receipt";
        let signature = signer.sign(message);
        let public_key_hex = hex::encode(signer.public_key().as_ref());
        let signature_hex = hex::encode(signature.as_ref());

        verify_ed25519(&public_key_hex, b"tampered receipt", &signature_hex)
            .expect_err("payload tampering must fail");
        verify_ed25519(&public_key_hex.to_uppercase(), message, &signature_hex)
            .expect_err("uppercase key encoding must fail");
        verify_ed25519(&public_key_hex, message, &signature_hex[..126])
            .expect_err("truncated signature must fail");
    }
}
