use anyhow::{Context, Result, ensure};

use crate::digest::{domain_canonical_json_bytes, sha256_domain_canonical_json, sha256_hex};
use crate::model::{HostAttestationEnvelope, SignatureAlgorithm};
use crate::signature::{signature_digest, verification_key_digest, verify_ed25519};

pub const HOST_ATTESTATION_PAYLOAD_SCHEMA_VERSION: &str =
    "hartevo-platform-host-attestation-payload/v1";
pub const HOST_ATTESTATION_ENVELOPE_SCHEMA_VERSION: &str =
    "hartevo-platform-host-attestation-envelope/v1";

pub fn host_attestation_signature_message(
    domain: &str,
    envelope: &HostAttestationEnvelope,
) -> Result<Vec<u8>> {
    let value = serde_json::json!({
        "schemaVersion": envelope.schema_version,
        "attestorIdentityDigest": envelope.attestor_identity_digest,
        "registryDigest": envelope.registry_digest,
        "registryEpoch": envelope.registry_epoch,
        "algorithm": envelope.algorithm,
        "keyDigest": envelope.key_digest,
        "payload": envelope.payload,
    });
    domain_canonical_json_bytes(domain, &value)
        .context("encoding canonical host-attestation signed envelope")
}

pub fn host_attestation_envelope_digest(
    domain: &str,
    envelope: &HostAttestationEnvelope,
) -> Result<String> {
    let value =
        serde_json::to_value(envelope).context("serializing signed host-attestation envelope")?;
    sha256_domain_canonical_json(domain, &value)
        .context("digesting signed host-attestation envelope")
}

pub fn verify_host_attestation_crypto(
    envelope: &HostAttestationEnvelope,
    verification_key_hex: &str,
    payload_domain: &str,
) -> Result<()> {
    ensure!(
        envelope.schema_version == HOST_ATTESTATION_ENVELOPE_SCHEMA_VERSION
            && envelope.payload.schema_version == HOST_ATTESTATION_PAYLOAD_SCHEMA_VERSION,
        "host-attestation schema version changed"
    );
    ensure!(
        envelope.algorithm == SignatureAlgorithm::Ed25519,
        "host-attestation signature algorithm is unsupported"
    );
    ensure!(
        envelope.key_digest == verification_key_digest(verification_key_hex)?,
        "host-attestation key digest does not match the verification key"
    );
    ensure!(
        envelope.signature_digest == signature_digest(&envelope.signature_hex)?,
        "host-attestation signature digest does not match its bytes"
    );
    let message = host_attestation_signature_message(payload_domain, envelope)?;
    ensure!(
        envelope.signed_payload_digest == sha256_hex(&message),
        "host-attestation signed payload digest mismatch"
    );
    verify_ed25519(verification_key_hex, &message, &envelope.signature_hex)
        .context("host-attestation signature verification failed")
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::{
        HOST_ATTESTATION_ENVELOPE_SCHEMA_VERSION, HOST_ATTESTATION_PAYLOAD_SCHEMA_VERSION,
        host_attestation_envelope_digest, host_attestation_signature_message,
        verify_host_attestation_crypto,
    };
    use crate::digest::sha256_hex;
    use crate::model::{
        Architecture, ChallengeBinding, HostAttestationEnvelope, HostAttestationPayload,
        HostObservation, HostReceiptIdentity, OperatingSystem, PlatformStatus, ReceiptKind,
        RunnerBinding, SignatureAlgorithm, VirtualizationKind,
    };
    use crate::signature::{signature_digest, verification_key_digest};

    const PAYLOAD_DOMAIN: &str = "hartevo-platform-host-attestation-signature/v1";
    const ENVELOPE_DOMAIN: &str = "hartevo-platform-host-attestation-envelope-digest/v1";

    fn payload() -> HostAttestationPayload {
        HostAttestationPayload {
            schema_version: HOST_ATTESTATION_PAYLOAD_SCHEMA_VERSION.to_owned(),
            attestation_id: "attestation_01".to_owned(),
            receipt: HostReceiptIdentity {
                source_commit: "11".repeat(20),
                matrix_digest: "22".repeat(32),
                case_definition_digest: "33".repeat(32),
                receipt_id: "receipt_01".to_owned(),
                run_id: "run_01".to_owned(),
                attempt_ordinal: 1,
                case_id: "I-01.macos-aarch64.browser.pipe_platform_default".to_owned(),
                target_id: "macos-aarch64".to_owned(),
                status: PlatformStatus::BlockedEnv,
                receipt_kind: ReceiptKind::NativePreflight,
            },
            challenge: ChallengeBinding {
                challenge_id: "challenge_01".to_owned(),
                nonce_hex: "44".repeat(32),
                nonce_digest: "55".repeat(32),
                issuer_digest: "66".repeat(32),
                issued_at: "2026-08-13T00:00:00Z".to_owned(),
                expires_at: "2026-08-13T00:05:00Z".to_owned(),
            },
            runner: RunnerBinding {
                runner_id: "runner_01".to_owned(),
                runner_identity_digest: "77".repeat(32),
                registry_digest: "88".repeat(32),
                registry_epoch: 1,
                signing_key_digest: "99".repeat(32),
                signature_algorithm: SignatureAlgorithm::Ed25519,
                producer_binary_digest: "aa".repeat(32),
            },
            host: HostObservation {
                host_identity_digest: "bb".repeat(32),
                os: OperatingSystem::Macos,
                arch: Architecture::Aarch64,
                os_build_digest: "cc".repeat(32),
                virtualization: VirtualizationKind::Physical,
                virtualization_observation_digest: "dd".repeat(32),
                observed_at: "2026-08-13T00:01:00Z".to_owned(),
            },
        }
    }

    fn signed_envelope() -> (HostAttestationEnvelope, String) {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[71; 32]).expect("fixed signer");
        let verification_key_hex = hex::encode(signer.public_key().as_ref());
        let mut envelope = HostAttestationEnvelope {
            schema_version: HOST_ATTESTATION_ENVELOPE_SCHEMA_VERSION.to_owned(),
            attestor_identity_digest: "ee".repeat(32),
            registry_digest: "ff".repeat(32),
            registry_epoch: 1,
            algorithm: SignatureAlgorithm::Ed25519,
            key_digest: verification_key_digest(&verification_key_hex).expect("key digest"),
            signed_payload_digest: "00".repeat(32),
            signature_digest: "00".repeat(32),
            signature_hex: "00".repeat(64),
            payload: payload(),
        };
        let message = host_attestation_signature_message(PAYLOAD_DOMAIN, &envelope)
            .expect("signed envelope message");
        let signature_hex = hex::encode(signer.sign(&message).as_ref());
        envelope.signed_payload_digest = sha256_hex(&message);
        envelope.signature_digest = signature_digest(&signature_hex).expect("signature digest");
        envelope.signature_hex = signature_hex;
        (envelope, verification_key_hex)
    }

    #[test]
    fn verifies_domain_separated_privacy_safe_host_envelope() {
        let (envelope, key) = signed_envelope();
        verify_host_attestation_crypto(&envelope, &key, PAYLOAD_DOMAIN)
            .expect("signed host attestation");
        let digest =
            host_attestation_envelope_digest(ENVELOPE_DOMAIN, &envelope).expect("envelope digest");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn rejects_unsigned_and_partially_signed_host_fields() {
        let (envelope, key) = signed_envelope();
        for mutation in [
            "host",
            "build",
            "virtualization",
            "receipt",
            "challenge",
            "runner",
            "attestor",
            "registry",
            "registry_epoch",
            "key",
        ] {
            let mut tampered = envelope.clone();
            match mutation {
                "host" => tampered.payload.host.host_identity_digest = "01".repeat(32),
                "build" => tampered.payload.host.os_build_digest = "02".repeat(32),
                "virtualization" => {
                    tampered.payload.host.virtualization = VirtualizationKind::VirtualMachine;
                }
                "receipt" => tampered.payload.receipt.receipt_id = "receipt_02".to_owned(),
                "challenge" => {
                    tampered.payload.challenge.challenge_id = "challenge_02".to_owned();
                }
                "runner" => tampered.payload.runner.runner_id = "runner_02".to_owned(),
                "attestor" => tampered.attestor_identity_digest = "03".repeat(32),
                "registry" => tampered.registry_digest = "04".repeat(32),
                "registry_epoch" => tampered.registry_epoch = 2,
                "key" => tampered.key_digest = "05".repeat(32),
                _ => unreachable!(),
            }
            verify_host_attestation_crypto(&tampered, &key, PAYLOAD_DOMAIN)
                .expect_err("mutating a signed host field must invalidate the signature");
        }
    }

    #[test]
    fn typed_envelope_rejects_missing_unknown_and_null_signature_fields() {
        let (envelope, _) = signed_envelope();
        let baseline = serde_json::to_value(envelope).expect("typed envelope JSON");

        let mut missing = baseline.clone();
        missing
            .as_object_mut()
            .expect("envelope object")
            .remove("signatureHex");
        serde_json::from_value::<HostAttestationEnvelope>(missing)
            .expect_err("missing signatureHex must fail");

        let mut unknown = baseline.clone();
        unknown["hostName"] = serde_json::json!("private-host");
        serde_json::from_value::<HostAttestationEnvelope>(unknown)
            .expect_err("unknown raw host identity must fail");

        let mut present_null = baseline;
        present_null["signatureDigest"] = serde_json::Value::Null;
        serde_json::from_value::<HostAttestationEnvelope>(present_null)
            .expect_err("present-null signature field must fail");
    }
}
