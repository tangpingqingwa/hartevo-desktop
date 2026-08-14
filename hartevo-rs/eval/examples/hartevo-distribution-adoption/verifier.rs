use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::digest::{domain_canonical_json_bytes, is_lower_hex, sha256_hex, sha256_json};
use crate::model::{
    ArtifactBinding, AttestationEvidence, DependencyEvidenceBinding, DetachedSignature,
    EvidenceOrigin, EvidenceStatus, KeyRegistry, ProvenanceBinding, ReleaseContract,
    ReleaseEvidence, ReleasePromotionGate, RevocationStatus, SbomEvidence, SbomFormat,
    TargetBinding, ValidityWindow, VerificationKey, VerificationReceipt, VerificationReport,
    parse_strict_json,
};
use crate::signature::{signature_digest, verify_ed25519};

pub const CONTRACT_PATH: &str = "contracts/distribution/release-evidence-plugin.v1.json";
pub const CONTRACT_SCHEMA_PATH: &str =
    "contracts/distribution/release-evidence-plugin.schema.v1.json";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-distribution-release-evidence/v1";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const PROVIDER: &str = "hartevo-distribution-verifier-provider";
pub const CONSUMER: &str = "release-promotion-eval-gate";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const SIGNATURE_DOMAIN: &str = "hartevo-distribution-release-evidence/v1";

const EXPECTED_CONTRACT_SCHEMA: &str = "hartevo-distribution-release-evidence-plugin/v1";
const EXPECTED_PLUGIN_ID: &str = "DIST-SBOM-TARGET-02";
const EXPECTED_SBOM_SCHEMA: &str = "hartevo-distribution-sbom/v1";
const EXPECTED_ATTESTATION_SCHEMA: &str = "hartevo-distribution-attestation/v1";
const EXPECTED_ATTESTATION_PREDICATE: &str = "https://slsa.dev/provenance/v1";
const SHA256_BYTES: usize = 32;
const SOURCE_COMMIT_MIN_BYTES: usize = 20;
const SOURCE_COMMIT_MAX_BYTES: usize = 32;

const CONTRACT: &[u8] =
    include_bytes!("../../../../contracts/distribution/release-evidence-plugin.v1.json");
const CONTRACT_SCHEMA: &[u8] =
    include_bytes!("../../../../contracts/distribution/release-evidence-plugin.schema.v1.json");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationInput {
    pub version: String,
    pub platform: String,
    pub target_triple: String,
    pub source_commit: String,
    pub artifact_bytes: Vec<u8>,
    pub sbom_bytes: Vec<u8>,
    pub attestation_bytes: Vec<u8>,
    pub advisory_report_bytes: Vec<u8>,
    pub toolchain_version: String,
    pub toolchain_digest: String,
    pub build_manifest_digest: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationInput {
    pub evidence_bytes: Vec<u8>,
    pub artifact_bytes: Vec<u8>,
    pub sbom_bytes: Option<Vec<u8>>,
    pub attestation_bytes: Option<Vec<u8>>,
    pub signature_hex: Option<String>,
    pub key_registry_bytes: Option<Vec<u8>>,
    pub as_of: String,
    pub expected_version: Option<String>,
    pub expected_platform: Option<String>,
    pub expected_target_triple: Option<String>,
    pub expected_source_commit: Option<String>,
}

pub trait ReleaseEvidencePlugin {
    fn generate(&self, input: &GenerationInput) -> Result<ReleaseEvidence>;

    fn verify(&self, input: &VerificationInput) -> Result<VerificationReport>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DistributionVerifierProvider;

impl ReleaseEvidencePlugin for DistributionVerifierProvider {
    fn generate(&self, input: &GenerationInput) -> Result<ReleaseEvidence> {
        generate_evidence(input)
    }

    fn verify(&self, input: &VerificationInput) -> Result<VerificationReport> {
        verify_evidence(input)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ReleasePromotionEvalGate;

impl ReleasePromotionEvalGate {
    pub fn consume(
        status: EvidenceStatus,
        origin: EvidenceOrigin,
        failure_codes: &[String],
    ) -> ReleasePromotionGate {
        let mut reason_codes = failure_codes.to_vec();
        reason_codes.push("RELEASE_FALSE_FAIL_CLOSED".to_owned());
        reason_codes.sort();
        reason_codes.dedup();
        let decision = match status {
            EvidenceStatus::Verified => {
                ensure_external_origin(origin, &mut reason_codes);
                "BLOCKED_RELEASE_FALSE"
            }
            EvidenceStatus::CodeFailure => "CODE_FAILURE",
            EvidenceStatus::BlockedEnv => "BLOCKED_ENV",
            EvidenceStatus::NotImplemented => "NOT_IMPLEMENTED",
        };
        ReleasePromotionGate {
            consumer: CONSUMER.to_owned(),
            decision: decision.to_owned(),
            promotion_eligible: false,
            release: false,
            deployment: false,
            reason_codes,
        }
    }
}

fn ensure_external_origin(origin: EvidenceOrigin, reason_codes: &mut Vec<String>) {
    if origin != EvidenceOrigin::ExternalSigned {
        reason_codes.push("PRODUCTION_SIGNATURE_NOT_PRESENT".to_owned());
    }
}

pub fn validate_contracts() -> Result<()> {
    let contract = parse_strict_json::<Value>(CONTRACT)
        .context("release evidence plugin contract is not strict JSON")?;
    let schema = parse_strict_json::<Value>(CONTRACT_SCHEMA)
        .context("release evidence plugin schema is not strict JSON")?;
    validate_contract(&contract, &schema)
}

pub fn contract_digests() -> (String, String) {
    (sha256_hex(CONTRACT), sha256_hex(CONTRACT_SCHEMA))
}

fn validate_contract(contract: &Value, schema: &Value) -> Result<()> {
    ensure!(
        contract.pointer("/schemaVersion").and_then(Value::as_str)
            == Some(EXPECTED_CONTRACT_SCHEMA),
        "release evidence plugin contract schemaVersion drift"
    );
    ensure!(
        contract.pointer("/pluginId").and_then(Value::as_str) == Some(EXPECTED_PLUGIN_ID),
        "release evidence plugin id drift"
    );
    ensure!(
        contract.pointer("/provider").and_then(Value::as_str) == Some(PROVIDER),
        "release evidence plugin provider drift"
    );
    ensure!(
        contract.pointer("/consumer").and_then(Value::as_str) == Some(CONSUMER),
        "release evidence plugin consumer drift"
    );
    ensure!(
        contract.pointer("/releaseDecision").and_then(Value::as_str) == Some(RELEASE_DECISION),
        "release evidence plugin release decision drift"
    );
    ensure!(
        contract.pointer("/release/passed").and_then(Value::as_bool) == Some(false)
            && contract
                .pointer("/release/deployment")
                .and_then(Value::as_bool)
                == Some(false),
        "release evidence plugin must remain release=false"
    );
    ensure!(
        contract
            .pointer("/signature/detached")
            .and_then(Value::as_bool)
            == Some(true)
            && contract
                .pointer("/signature/keyReferenceRequired")
                .and_then(Value::as_bool)
                == Some(true),
        "release evidence plugin must require detached signatures and key references"
    );
    ensure!(
        contract
            .pointer("/signature/privateKeyInEvidence")
            .and_then(Value::as_bool)
            == Some(false)
            && contract
                .pointer("/productionEvidence/privateSigningMaterialAllowed")
                .and_then(Value::as_bool)
                == Some(false),
        "release evidence plugin must not carry private signing material"
    );
    ensure!(
        contract
            .pointer("/validity/failClosed")
            .and_then(Value::as_bool)
            == Some(true),
        "release evidence plugin validity must fail closed"
    );
    ensure!(
        contract
            .pointer("/verificationReceipt/contentFree")
            .and_then(Value::as_bool)
            == Some(true),
        "verification receipt must be content-free"
    );
    ensure!(
        schema.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
            && schema.get("type").and_then(Value::as_str) == Some("object")
            && schema.get("additionalProperties").and_then(Value::as_bool) == Some(false),
        "release evidence plugin schema must be a closed draft-2020-12 object"
    );
    ensure!(
        schema.get("$defs").and_then(Value::as_object).is_some(),
        "release evidence plugin schema is missing definitions"
    );
    Ok(())
}

fn generate_evidence(input: &GenerationInput) -> Result<ReleaseEvidence> {
    validate_contracts()?;
    validate_common_bindings(
        &input.version,
        &input.platform,
        &input.target_triple,
        &input.source_commit,
        &input.toolchain_digest,
        &input.build_manifest_digest,
    )?;
    validate_time_window(&input.issued_at, &input.expires_at)?;

    let artifact_digest = sha256_hex(&input.artifact_bytes);
    let sbom = parse_strict_json::<SbomInput>(&input.sbom_bytes)
        .context("SBOM is not strict typed JSON")?;
    validate_sbom(
        &sbom,
        &input.version,
        &input.platform,
        &input.target_triple,
        &input.source_commit,
        &artifact_digest,
    )?;
    let sbom_digest = sha256_hex(&input.sbom_bytes);

    let attestation = parse_strict_json::<AttestationInput>(&input.attestation_bytes)
        .context("attestation is not strict typed JSON")?;
    validate_attestation(
        &attestation,
        &AttestationExpectations {
            input,
            artifact_digest: &artifact_digest,
            sbom_digest: &sbom_digest,
        },
    )?;
    let attestation_digest = sha256_hex(&input.attestation_bytes);
    let dependency_evidence = dependency_evidence_from_report(&input.advisory_report_bytes)?;
    ensure!(
        dependency_evidence.source_commit == input.source_commit,
        "dependency evidence source commit does not match generation source commit"
    );
    let build_context = EvidenceBuildContext {
        input,
        sbom: &sbom,
        attestation: &attestation,
        dependency_evidence: &dependency_evidence,
        artifact_digest: &artifact_digest,
        sbom_digest: &sbom_digest,
        attestation_digest: &attestation_digest,
    };
    let evidence = build_unsigned_evidence(&build_context)?;
    let payload_digest = sha256_json(&evidence.signed_payload())?;
    Ok(ReleaseEvidence {
        payload_digest,
        ..evidence
    })
}

struct EvidenceBuildContext<'a> {
    input: &'a GenerationInput,
    sbom: &'a SbomInput,
    attestation: &'a AttestationInput,
    dependency_evidence: &'a DependencyEvidenceBinding,
    artifact_digest: &'a str,
    sbom_digest: &'a str,
    attestation_digest: &'a str,
}

fn build_unsigned_evidence(context: &EvidenceBuildContext<'_>) -> Result<ReleaseEvidence> {
    let input = context.input;
    let sbom = context.sbom.clone();
    let attestation = context.attestation.clone();
    let dependency_evidence = context.dependency_evidence;

    let evidence = ReleaseEvidence {
        schema_version: VALIDATION_SCHEMA_VERSION.to_owned(),
        plugin_id: EXPECTED_PLUGIN_ID.to_owned(),
        provider: PROVIDER.to_owned(),
        provider_version: PROVIDER_VERSION.to_owned(),
        consumer: CONSUMER.to_owned(),
        release_decision: RELEASE_DECISION.to_owned(),
        release: ReleaseContract {
            passed: false,
            deployment: false,
        },
        evidence_origin: EvidenceOrigin::UnsignedGenerated,
        version: input.version.clone(),
        platform: input.platform.clone(),
        target_triple: input.target_triple.clone(),
        artifact: ArtifactBinding {
            version: input.version.clone(),
            sha256: context.artifact_digest.to_owned(),
            platform: input.platform.clone(),
            target_triple: input.target_triple.clone(),
        },
        sbom: SbomEvidence {
            format: sbom.format,
            spec_version: sbom.spec_version,
            document_version: sbom.document_version,
            digest: context.sbom_digest.to_owned(),
            platform: sbom.platform,
            target_triple: sbom.target_triple,
            artifact_digest: sbom.artifact_digest,
            source_commit: sbom.source_commit,
            lockfile_digest: sbom.lockfile_digest,
        },
        attestation: AttestationEvidence {
            predicate_type: attestation.predicate_type,
            version: attestation.version,
            digest: context.attestation_digest.to_owned(),
            platform: attestation.platform,
            target_triple: attestation.target_triple,
            artifact_digest: attestation.artifact_digest,
            sbom_digest: attestation.sbom_digest,
            source_commit: attestation.source_commit,
            lockfile_digest: attestation.lockfile_digest,
            toolchain_version: attestation.toolchain_version,
            toolchain_digest: attestation.toolchain_digest,
            build_manifest_digest: attestation.build_manifest_digest,
        },
        provenance: ProvenanceBinding {
            source_commit: input.source_commit.clone(),
            cargo_lock_digest: dependency_evidence.lockfile_digest.clone(),
            toolchain_version: input.toolchain_version.clone(),
            toolchain_digest: input.toolchain_digest.clone(),
            build_manifest_digest: input.build_manifest_digest.clone(),
            artifact_digest: context.artifact_digest.to_owned(),
            sbom_digest: context.sbom_digest.to_owned(),
            attestation_digest: context.attestation_digest.to_owned(),
            dependency_evidence_digest: sha256_json(dependency_evidence)?,
        },
        dependency_evidence: dependency_evidence.clone(),
        validity: ValidityWindow {
            issued_at: input.issued_at.clone(),
            expires_at: input.expires_at.clone(),
        },
        signature: DetachedSignature {
            algorithm: "ed25519".to_owned(),
            detached: true,
            key_reference: None,
            signature_digest: None,
        },
        payload_digest: String::new(),
    };
    Ok(evidence)
}

fn verify_evidence(input: &VerificationInput) -> Result<VerificationReport> {
    validate_contracts()?;
    let evidence = parse_strict_json::<ReleaseEvidence>(&input.evidence_bytes)
        .context("release evidence is not strict typed JSON")?;
    let as_of = parse_timestamp(&input.as_of, "verification asOf")?;
    let (contract_digest, contract_schema_digest) = contract_digests();
    let evidence_digest = sha256_hex(&input.evidence_bytes);
    let recomputed_payload_digest = sha256_json(&evidence.signed_payload())?;
    let mut code_failures = BTreeSet::new();
    let mut blocked_env = BTreeSet::new();
    let mut evidence_expiry_status = "UNKNOWN".to_owned();

    collect_evidence_failures(
        &evidence,
        &recomputed_payload_digest,
        input,
        &as_of,
        &mut code_failures,
        &mut blocked_env,
        &mut evidence_expiry_status,
    );

    let SignatureCheck {
        is_valid: signature_is_valid,
        code_failures: signature_code_failures,
        blocked_env: signature_blocked_env,
        key_revocation_status,
        key_validity,
    } = verify_signature(&evidence, input, &as_of)?;
    code_failures.extend(signature_code_failures);
    blocked_env.extend(signature_blocked_env);

    if evidence.dependency_evidence.code_failure_count > 0 {
        code_failures.insert("DEPENDENCY_EVIDENCE_CODE_FAILURE".to_owned());
    }

    let status = if !code_failures.is_empty() {
        EvidenceStatus::CodeFailure
    } else if !blocked_env.is_empty() {
        EvidenceStatus::BlockedEnv
    } else if !signature_is_valid {
        blocked_env.insert("SIGNATURE_NOT_VERIFIED".to_owned());
        EvidenceStatus::BlockedEnv
    } else {
        EvidenceStatus::Verified
    };
    let mut failure_codes = code_failures.into_iter().collect::<Vec<_>>();
    failure_codes.extend(blocked_env);
    failure_codes.sort();
    failure_codes.dedup();
    let receipt_context = ReceiptContext {
        status,
        verified_at: &input.as_of,
        evidence: &evidence,
        evidence_digest: &evidence_digest,
        signed_payload_digest: &recomputed_payload_digest,
        key_revocation_status,
        key_validity: &key_validity,
        evidence_expiry_status: &evidence_expiry_status,
        failure_codes: &failure_codes,
    };
    let receipt = verification_receipt(&receipt_context)?;
    let gate = ReleasePromotionEvalGate::consume(status, evidence.evidence_origin, &failure_codes);
    Ok(VerificationReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        provider: PROVIDER,
        consumer: CONSUMER,
        status,
        release_decision: RELEASE_DECISION,
        release: false,
        deployment: false,
        evidence_accepted: status == EvidenceStatus::Verified,
        promotion_eligible: false,
        contract_digest,
        contract_schema_digest,
        evidence_digest,
        verification_receipt: receipt,
        gate,
    })
}

struct SignatureCheck {
    is_valid: bool,
    code_failures: BTreeSet<String>,
    blocked_env: BTreeSet<String>,
    key_revocation_status: RevocationStatus,
    key_validity: String,
}

fn verify_signature(
    evidence: &ReleaseEvidence,
    input: &VerificationInput,
    as_of: &DateTime<Utc>,
) -> Result<SignatureCheck> {
    let mut code_failures = BTreeSet::new();
    let mut blocked_env = BTreeSet::new();
    let mut key_revocation_status = RevocationStatus::Unknown;
    let mut key_validity = "UNKNOWN".to_owned();
    if evidence.signature.key_reference.is_none() {
        blocked_env.insert("KEY_REFERENCE_MISSING".to_owned());
    }
    if input.signature_hex.is_none() {
        blocked_env.insert("DETACHED_SIGNATURE_UNAVAILABLE".to_owned());
    }
    if input.key_registry_bytes.is_none() {
        blocked_env.insert("KEY_REGISTRY_UNAVAILABLE".to_owned());
    }
    let parsed_registry = input
        .key_registry_bytes
        .as_deref()
        .map(parse_key_registry)
        .transpose()?;
    let selected_key = match (
        &parsed_registry,
        evidence.signature.key_reference.as_deref(),
    ) {
        (Some(registry), Some(key_reference)) => {
            let key = registry
                .keys
                .iter()
                .find(|entry| entry.key_reference == key_reference);
            if key.is_none() {
                blocked_env.insert("KEY_REFERENCE_NOT_FOUND".to_owned());
            }
            key
        }
        _ => None,
    };
    if let Some(key) = selected_key {
        evaluate_key_validity(
            key,
            as_of,
            &mut code_failures,
            &mut key_revocation_status,
            &mut key_validity,
        )?;
    }
    let mut is_valid = false;
    if let (Some(key), Some(signature_hex)) = (selected_key, input.signature_hex.as_deref()) {
        if let Some(expected_digest) = evidence.signature.signature_digest.as_deref() {
            match signature_digest(signature_hex) {
                Ok(actual_digest) if actual_digest == expected_digest => {}
                Ok(_) => {
                    code_failures.insert("DETACHED_SIGNATURE_DIGEST_DRIFT".to_owned());
                }
                Err(_) => {
                    code_failures.insert("DETACHED_SIGNATURE_ENCODING_INVALID".to_owned());
                }
            }
        }
        match domain_canonical_json_bytes(SIGNATURE_DOMAIN, &evidence.signed_payload()) {
            Ok(message) => match verify_ed25519(&key.public_key_hex, &message, signature_hex) {
                Ok(()) => is_valid = true,
                Err(_) => {
                    code_failures.insert("DETACHED_SIGNATURE_INVALID".to_owned());
                }
            },
            Err(_) => {
                code_failures.insert("SIGNED_PAYLOAD_CANONICALIZATION_FAILED".to_owned());
            }
        }
    }
    if is_valid && evidence.evidence_origin != EvidenceOrigin::ExternalSigned {
        blocked_env.insert("PRODUCTION_SIGNATURE_NOT_PRESENT".to_owned());
    }
    Ok(SignatureCheck {
        is_valid,
        code_failures,
        blocked_env,
        key_revocation_status,
        key_validity,
    })
}

fn collect_evidence_failures(
    evidence: &ReleaseEvidence,
    recomputed_payload_digest: &str,
    input: &VerificationInput,
    as_of: &DateTime<Utc>,
    code_failures: &mut BTreeSet<String>,
    blocked_env: &mut BTreeSet<String>,
    evidence_expiry_status: &mut String,
) {
    if evidence.schema_version != VALIDATION_SCHEMA_VERSION {
        code_failures.insert("EVIDENCE_SCHEMA_VERSION_DRIFT".to_owned());
    }
    if evidence.plugin_id != EXPECTED_PLUGIN_ID
        || evidence.provider != PROVIDER
        || evidence.provider_version != PROVIDER_VERSION
        || evidence.consumer != CONSUMER
    {
        code_failures.insert("EVIDENCE_PROVIDER_BINDING_DRIFT".to_owned());
    }
    if evidence.release_decision != RELEASE_DECISION
        || evidence.release.passed
        || evidence.release.deployment
    {
        code_failures.insert("RELEASE_FALSE_CONTRACT_DRIFT".to_owned());
    }
    match evidence.evidence_origin {
        EvidenceOrigin::ExternalSigned => {}
        EvidenceOrigin::UnsignedGenerated => {
            blocked_env.insert("PRODUCTION_SIGNATURE_NOT_PRESENT".to_owned());
        }
        EvidenceOrigin::TestFixtureOnly => {
            code_failures.insert("TEST_FIXTURE_NOT_PRODUCTION_EVIDENCE".to_owned());
        }
    }
    validate_target(&evidence.platform, &evidence.target_triple, code_failures);
    if evidence.version.is_empty() || evidence.artifact.version != evidence.version {
        code_failures.insert("VERSION_BINDING_DRIFT".to_owned());
    }
    if evidence.artifact.platform != evidence.platform
        || evidence.artifact.target_triple != evidence.target_triple
    {
        code_failures.insert("ARTIFACT_PLATFORM_BINDING_DRIFT".to_owned());
    }
    if !is_lower_hex(&evidence.artifact.sha256, SHA256_BYTES)
        || sha256_hex(&input.artifact_bytes) != evidence.artifact.sha256
    {
        code_failures.insert("ARTIFACT_DIGEST_DRIFT".to_owned());
    }
    if !is_lower_hex(&evidence.payload_digest, SHA256_BYTES)
        || evidence.payload_digest != recomputed_payload_digest
    {
        code_failures.insert("SIGNED_PAYLOAD_DIGEST_DRIFT".to_owned());
    }
    validate_sbom_binding(evidence, code_failures);
    validate_attestation_binding(evidence, code_failures);
    validate_provenance_binding(evidence, code_failures);
    validate_dependency_binding(evidence, code_failures);
    validate_raw_documents(evidence, input, code_failures, blocked_env);
    if evidence.signature.algorithm != "ed25519" || !evidence.signature.detached {
        code_failures.insert("DETACHED_ED25519_SIGNATURE_REQUIRED".to_owned());
    }
    if evidence
        .signature
        .signature_digest
        .as_deref()
        .is_none_or(|digest| !is_lower_hex(digest, SHA256_BYTES))
    {
        blocked_env.insert("SIGNATURE_DIGEST_MISSING_OR_INVALID".to_owned());
    }

    let Ok(issued_at) = parse_timestamp(&evidence.validity.issued_at, "evidence issuedAt") else {
        code_failures.insert("EVIDENCE_ISSUED_AT_INVALID".to_owned());
        "INVALID".clone_into(evidence_expiry_status);
        return;
    };
    let Ok(expires_at) = parse_timestamp(&evidence.validity.expires_at, "evidence expiresAt")
    else {
        code_failures.insert("EVIDENCE_EXPIRES_AT_INVALID".to_owned());
        "INVALID".clone_into(evidence_expiry_status);
        return;
    };
    if expires_at <= issued_at {
        code_failures.insert("EVIDENCE_VALIDITY_WINDOW_INVALID".to_owned());
    }
    if *as_of < issued_at {
        code_failures.insert("EVIDENCE_NOT_YET_VALID".to_owned());
        "NOT_YET_VALID".clone_into(evidence_expiry_status);
    } else if *as_of >= expires_at {
        code_failures.insert("EVIDENCE_EXPIRED".to_owned());
        "EXPIRED".clone_into(evidence_expiry_status);
    } else {
        "ACTIVE".clone_into(evidence_expiry_status);
    }
    validate_expected_bindings(input, evidence, code_failures);
}

fn validate_expected_bindings(
    input: &VerificationInput,
    evidence: &ReleaseEvidence,
    code_failures: &mut BTreeSet<String>,
) {
    if let Some(expected) = input.expected_version.as_deref()
        && expected != evidence.version
    {
        code_failures.insert("EXPECTED_VERSION_MISMATCH".to_owned());
    }
    if let Some(expected) = input.expected_platform.as_deref()
        && expected != evidence.platform
    {
        code_failures.insert("EXPECTED_PLATFORM_MISMATCH".to_owned());
    }
    if let Some(expected) = input.expected_target_triple.as_deref()
        && expected != evidence.target_triple
    {
        code_failures.insert("EXPECTED_TARGET_TRIPLE_MISMATCH".to_owned());
    }
    if let Some(expected) = input.expected_source_commit.as_deref()
        && expected != evidence.provenance.source_commit
    {
        code_failures.insert("EXPECTED_SOURCE_COMMIT_MISMATCH".to_owned());
    }
}

fn validate_raw_documents(
    evidence: &ReleaseEvidence,
    input: &VerificationInput,
    code_failures: &mut BTreeSet<String>,
    blocked_env: &mut BTreeSet<String>,
) {
    match input.sbom_bytes.as_deref() {
        Some(bytes) => match parse_strict_json::<SbomInput>(bytes) {
            Ok(sbom) => {
                let valid_projection = validate_sbom(
                    &sbom,
                    &evidence.version,
                    &evidence.platform,
                    &evidence.target_triple,
                    &evidence.provenance.source_commit,
                    &evidence.artifact.sha256,
                )
                .is_ok();
                if !valid_projection
                    || sha256_hex(bytes) != evidence.sbom.digest
                    || sbom.lockfile_digest != evidence.provenance.cargo_lock_digest
                {
                    code_failures.insert("SBOM_CONTENT_DIGEST_OR_BINDING_DRIFT".to_owned());
                }
            }
            Err(_) => {
                code_failures.insert("SBOM_CONTENT_INVALID".to_owned());
            }
        },
        None => {
            blocked_env.insert("SBOM_UNAVAILABLE".to_owned());
        }
    }
    match input.attestation_bytes.as_deref() {
        Some(bytes) => match parse_strict_json::<AttestationInput>(bytes) {
            Ok(attestation) => {
                if !validate_raw_attestation(&attestation, evidence)
                    || sha256_hex(bytes) != evidence.attestation.digest
                {
                    code_failures.insert("ATTESTATION_CONTENT_DIGEST_OR_BINDING_DRIFT".to_owned());
                }
            }
            Err(_) => {
                code_failures.insert("ATTESTATION_CONTENT_INVALID".to_owned());
            }
        },
        None => {
            blocked_env.insert("ATTESTATION_UNAVAILABLE".to_owned());
        }
    }
}

fn validate_raw_attestation(attestation: &AttestationInput, evidence: &ReleaseEvidence) -> bool {
    attestation.schema_version == EXPECTED_ATTESTATION_SCHEMA
        && attestation.predicate_type == EXPECTED_ATTESTATION_PREDICATE
        && attestation.version == evidence.version
        && attestation.platform == evidence.platform
        && attestation.target_triple == evidence.target_triple
        && attestation.source_commit == evidence.provenance.source_commit
        && attestation.artifact_digest == evidence.artifact.sha256
        && attestation.sbom_digest == evidence.sbom.digest
        && attestation.lockfile_digest == evidence.provenance.cargo_lock_digest
        && attestation.toolchain_version == evidence.provenance.toolchain_version
        && attestation.toolchain_digest == evidence.provenance.toolchain_digest
        && attestation.build_manifest_digest == evidence.provenance.build_manifest_digest
        && is_lower_hex(&attestation.lockfile_digest, SHA256_BYTES)
        && is_lower_hex(&attestation.toolchain_digest, SHA256_BYTES)
        && is_lower_hex(&attestation.build_manifest_digest, SHA256_BYTES)
}

fn validate_target(platform: &str, target_triple: &str, failures: &mut BTreeSet<String>) {
    let supported = matches!(
        (platform, target_triple),
        ("macos-aarch64", "aarch64-apple-darwin") | ("macos-x86_64", "x86_64-apple-darwin")
    );
    if !supported {
        failures.insert("UNSUPPORTED_RELEASE_TARGET".to_owned());
    }
}

fn validate_sbom_binding(evidence: &ReleaseEvidence, failures: &mut BTreeSet<String>) {
    if !is_lower_hex(&evidence.sbom.digest, SHA256_BYTES)
        || evidence.sbom.platform != evidence.platform
        || evidence.sbom.target_triple != evidence.target_triple
        || evidence.sbom.artifact_digest != evidence.artifact.sha256
        || evidence.sbom.source_commit != evidence.provenance.source_commit
        || evidence.sbom.lockfile_digest != evidence.provenance.cargo_lock_digest
        || evidence.sbom.spec_version.is_empty()
        || evidence.sbom.document_version.is_empty()
    {
        failures.insert("SBOM_BINDING_INVALID".to_owned());
    }
}

fn validate_attestation_binding(evidence: &ReleaseEvidence, failures: &mut BTreeSet<String>) {
    if evidence.attestation.predicate_type != EXPECTED_ATTESTATION_PREDICATE
        || evidence.attestation.version.is_empty()
        || !is_lower_hex(&evidence.attestation.digest, SHA256_BYTES)
        || evidence.attestation.platform != evidence.platform
        || evidence.attestation.target_triple != evidence.target_triple
        || evidence.attestation.artifact_digest != evidence.artifact.sha256
        || evidence.attestation.sbom_digest != evidence.sbom.digest
        || evidence.attestation.source_commit != evidence.provenance.source_commit
        || evidence.attestation.lockfile_digest != evidence.provenance.cargo_lock_digest
        || evidence.attestation.toolchain_digest != evidence.provenance.toolchain_digest
        || evidence.attestation.build_manifest_digest != evidence.provenance.build_manifest_digest
    {
        failures.insert("ATTESTATION_BINDING_INVALID".to_owned());
    }
}

fn validate_provenance_binding(evidence: &ReleaseEvidence, failures: &mut BTreeSet<String>) {
    let provenance = &evidence.provenance;
    let digests_are_valid = [
        &provenance.cargo_lock_digest,
        &provenance.toolchain_digest,
        &provenance.build_manifest_digest,
        &provenance.artifact_digest,
        &provenance.sbom_digest,
        &provenance.attestation_digest,
        &provenance.dependency_evidence_digest,
    ]
    .into_iter()
    .all(|digest| is_lower_hex(digest, SHA256_BYTES));
    if !is_source_commit(provenance.source_commit.as_str())
        || !digests_are_valid
        || provenance.artifact_digest != evidence.artifact.sha256
        || provenance.sbom_digest != evidence.sbom.digest
        || provenance.attestation_digest != evidence.attestation.digest
        || provenance.dependency_evidence_digest
            != sha256_json(&evidence.dependency_evidence).unwrap_or_default()
    {
        failures.insert("SOURCE_TOOLCHAIN_PROVENANCE_INVALID".to_owned());
    }
}

fn validate_dependency_binding(evidence: &ReleaseEvidence, failures: &mut BTreeSet<String>) {
    let dependency = &evidence.dependency_evidence;
    let digests_are_valid = [
        &dependency.report_digest,
        &dependency.lockfile_digest,
        &dependency.audit_receipt_digest,
        &dependency.finding_digest,
    ]
    .into_iter()
    .all(|digest| is_lower_hex(digest, SHA256_BYTES));
    if dependency.report_schema_version != "hartevo-distribution-dependency-advisory/v1"
        || dependency.policy_id != "DIST-SBOM-TARGET-01"
        || !digests_are_valid
        || dependency.release
        || dependency.source_commit != evidence.provenance.source_commit
        || dependency.lockfile_digest != evidence.provenance.cargo_lock_digest
        || dependency.target_bindings.is_empty()
    {
        failures.insert("TARGET_AWARE_DEPENDENCY_EVIDENCE_INVALID".to_owned());
    }
}

fn evaluate_key_validity(
    key: &VerificationKey,
    as_of: &DateTime<Utc>,
    failures: &mut BTreeSet<String>,
    revocation_status: &mut RevocationStatus,
    key_validity: &mut String,
) -> Result<()> {
    ensure!(
        key.algorithm == "ed25519",
        "verification key algorithm must be ed25519"
    );
    let valid_from = parse_timestamp(&key.valid_from, "verification key validFrom")?;
    let valid_until = parse_timestamp(&key.valid_until, "verification key validUntil")?;
    if valid_until <= valid_from {
        failures.insert("VERIFICATION_KEY_VALIDITY_WINDOW_INVALID".to_owned());
    }
    if *as_of < valid_from || *as_of >= valid_until {
        failures.insert("VERIFICATION_KEY_EXPIRED_OR_NOT_YET_VALID".to_owned());
        "EXPIRED_OR_NOT_YET_VALID".clone_into(key_validity);
    } else {
        "ACTIVE".clone_into(key_validity);
    }
    if let Some(revoked_at) = key.revoked_at.as_deref() {
        let revoked_at = parse_timestamp(revoked_at, "verification key revokedAt")?;
        if *as_of >= revoked_at {
            *revocation_status = RevocationStatus::Revoked;
            failures.insert("VERIFICATION_KEY_REVOKED".to_owned());
        } else {
            *revocation_status = RevocationStatus::Active;
        }
    } else {
        *revocation_status = RevocationStatus::Active;
    }
    Ok(())
}

fn parse_key_registry(bytes: &[u8]) -> Result<KeyRegistry> {
    let registry = parse_strict_json::<KeyRegistry>(bytes)
        .context("verification key registry is not strict typed JSON")?;
    ensure!(
        registry.schema_version == "hartevo-distribution-key-registry/v1",
        "verification key registry schema drift"
    );
    ensure!(
        !registry.keys.is_empty(),
        "verification key registry is empty"
    );
    let projection = json!({
        "schemaVersion": registry.schema_version,
        "registryVersion": registry.registry_version,
        "keys": registry.keys.clone(),
    });
    ensure!(
        registry.registry_digest == sha256_json(&projection)?,
        "verification key registry digest drift"
    );
    Ok(registry)
}

struct ReceiptContext<'a> {
    status: EvidenceStatus,
    verified_at: &'a str,
    evidence: &'a ReleaseEvidence,
    evidence_digest: &'a str,
    signed_payload_digest: &'a str,
    key_revocation_status: RevocationStatus,
    key_validity: &'a str,
    evidence_expiry_status: &'a str,
    failure_codes: &'a [String],
}

fn verification_receipt(context: &ReceiptContext<'_>) -> Result<VerificationReceipt> {
    let mut receipt = VerificationReceipt {
        receipt_version: "hartevo-distribution-verification-receipt/v1".to_owned(),
        status: context.status,
        verified_at: context.verified_at.to_owned(),
        verifier_version: PROVIDER_VERSION.to_owned(),
        evidence_digest: context.evidence_digest.to_owned(),
        signed_payload_digest: context.signed_payload_digest.to_owned(),
        artifact_digest: context.evidence.artifact.sha256.clone(),
        sbom_digest: context.evidence.sbom.digest.clone(),
        attestation_digest: context.evidence.attestation.digest.clone(),
        source_commit: context.evidence.provenance.source_commit.clone(),
        key_reference: context.evidence.signature.key_reference.clone(),
        key_revocation_status: context.key_revocation_status,
        key_validity: context.key_validity.to_owned(),
        evidence_expiry_status: context.evidence_expiry_status.to_owned(),
        failure_codes: context.failure_codes.to_vec(),
        content_free: true,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = sha256_json(&receipt)?;
    Ok(receipt)
}

fn dependency_evidence_from_report(bytes: &[u8]) -> Result<DependencyEvidenceBinding> {
    let report = parse_strict_json::<Value>(bytes)
        .context("target-aware dependency report is not strict JSON")?;
    let report_schema_version = string_at(&report, "/schemaVersion")?;
    ensure!(
        report_schema_version == "hartevo-distribution-dependency-advisory/v1",
        "target-aware dependency report schema drift"
    );
    let policy_id = string_at(&report, "/policyId")?;
    ensure!(
        policy_id == "DIST-SBOM-TARGET-01",
        "target-aware dependency report policy drift"
    );
    let source_commit = string_at(&report, "/sourceCommit")?;
    ensure!(
        is_source_commit(&source_commit),
        "target-aware dependency report source commit is invalid"
    );
    let lockfile_digest = string_at(&report, "/lockfileSha256")?;
    let audit_receipt_digest = string_at(&report, "/auditReceiptSha256")?;
    ensure!(
        is_lower_hex(&lockfile_digest, SHA256_BYTES)
            && is_lower_hex(&audit_receipt_digest, SHA256_BYTES),
        "target-aware dependency report digest is invalid"
    );
    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .context("target-aware dependency report findings are missing")?;
    let target_metadata = report
        .get("targetMetadata")
        .and_then(Value::as_array)
        .context("target-aware dependency report target metadata is missing")?;
    let mut target_bindings = target_metadata
        .iter()
        .map(|target| {
            let target_triple = string_at(target, "/targetTriple")?;
            let platform = platform_for_target(&target_triple);
            Ok(TargetBinding {
                platform,
                target_triple,
                metadata_digest: string_at(target, "/metadataSha256")?,
                role: string_at(target, "/role")?,
                release: bool_at(target, "/release")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    target_bindings.sort_by(|left, right| {
        (left.platform.as_str(), left.target_triple.as_str())
            .cmp(&(right.platform.as_str(), right.target_triple.as_str()))
    });
    ensure!(
        !target_bindings.is_empty()
            && target_bindings
                .iter()
                .all(|binding| is_lower_hex(&binding.metadata_digest, SHA256_BYTES)),
        "target-aware dependency report has invalid target metadata bindings"
    );
    let code_failure_count = usize_at(&report, "/codeFailureCount")?;
    let informational_warning_count = usize_at(&report, "/informationalWarningCount")?;
    let status = string_at(&report, "/status")?;
    let release = bool_at(&report, "/release")?;
    ensure!(
        !release,
        "target-aware dependency report cannot assert release=true"
    );
    ensure!(
        matches!(status.as_str(), "PASS" | "CODE_FAILURE"),
        "target-aware dependency report status is unknown"
    );
    Ok(DependencyEvidenceBinding {
        report_digest: sha256_hex(bytes),
        report_schema_version,
        policy_id,
        status,
        release,
        source_commit,
        lockfile_digest,
        audit_receipt_digest,
        finding_digest: sha256_json(findings)?,
        code_failure_count,
        informational_warning_count,
        target_bindings,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SbomInput {
    schema_version: String,
    format: SbomFormat,
    spec_version: String,
    document_version: String,
    version: String,
    platform: String,
    target_triple: String,
    source_commit: String,
    artifact_digest: String,
    lockfile_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttestationInput {
    schema_version: String,
    predicate_type: String,
    version: String,
    platform: String,
    target_triple: String,
    source_commit: String,
    artifact_digest: String,
    sbom_digest: String,
    lockfile_digest: String,
    toolchain_version: String,
    toolchain_digest: String,
    build_manifest_digest: String,
}

fn validate_sbom(
    sbom: &SbomInput,
    version: &str,
    platform: &str,
    target_triple: &str,
    source_commit: &str,
    artifact_digest: &str,
) -> Result<()> {
    ensure!(
        sbom.schema_version == EXPECTED_SBOM_SCHEMA,
        "SBOM schema version is not the distribution projection v1"
    );
    ensure!(
        !sbom.spec_version.is_empty(),
        "SBOM spec version is required"
    );
    ensure!(
        !sbom.document_version.is_empty() && sbom.version == version,
        "SBOM version binding drift"
    );
    ensure!(
        sbom.platform == platform && sbom.target_triple == target_triple,
        "SBOM platform binding drift"
    );
    ensure!(
        sbom.source_commit == source_commit && is_source_commit(&sbom.source_commit),
        "SBOM source commit binding drift"
    );
    ensure!(
        sbom.artifact_digest == artifact_digest
            && is_lower_hex(&sbom.artifact_digest, SHA256_BYTES),
        "SBOM artifact digest binding drift"
    );
    ensure!(
        is_lower_hex(&sbom.lockfile_digest, SHA256_BYTES),
        "SBOM lockfile digest is invalid"
    );
    Ok(())
}

struct AttestationExpectations<'a> {
    input: &'a GenerationInput,
    artifact_digest: &'a str,
    sbom_digest: &'a str,
}

fn validate_attestation(
    attestation: &AttestationInput,
    expected: &AttestationExpectations<'_>,
) -> Result<()> {
    let input = expected.input;
    ensure!(
        attestation.schema_version == EXPECTED_ATTESTATION_SCHEMA,
        "attestation schema version is not the distribution projection v1"
    );
    ensure!(
        attestation.predicate_type == EXPECTED_ATTESTATION_PREDICATE,
        "attestation predicate type drift"
    );
    ensure!(
        !attestation.version.is_empty() && attestation.version == input.version,
        "attestation version binding drift"
    );
    ensure!(
        attestation.platform == input.platform && attestation.target_triple == input.target_triple,
        "attestation platform binding drift"
    );
    ensure!(
        attestation.source_commit == input.source_commit && is_source_commit(&input.source_commit),
        "attestation source commit binding drift"
    );
    ensure!(
        attestation.artifact_digest == expected.artifact_digest,
        "attestation artifact digest binding drift"
    );
    ensure!(
        attestation.sbom_digest == expected.sbom_digest,
        "attestation SBOM digest binding drift"
    );
    ensure!(
        attestation.toolchain_version == input.toolchain_version
            && attestation.toolchain_digest == input.toolchain_digest
            && attestation.build_manifest_digest == input.build_manifest_digest,
        "attestation toolchain/build manifest provenance drift"
    );
    ensure!(
        is_lower_hex(&attestation.lockfile_digest, SHA256_BYTES)
            && is_lower_hex(&attestation.toolchain_digest, SHA256_BYTES)
            && is_lower_hex(&attestation.build_manifest_digest, SHA256_BYTES),
        "attestation provenance digest is invalid"
    );
    Ok(())
}

fn validate_common_bindings(
    version: &str,
    platform: &str,
    target_triple: &str,
    source_commit: &str,
    toolchain_digest: &str,
    build_manifest_digest: &str,
) -> Result<()> {
    ensure!(!version.is_empty(), "distribution version is required");
    ensure!(
        matches!(
            (platform, target_triple),
            ("macos-aarch64", "aarch64-apple-darwin") | ("macos-x86_64", "x86_64-apple-darwin")
        ),
        "unsupported macOS release target"
    );
    ensure!(is_source_commit(source_commit), "source commit is invalid");
    ensure!(
        is_lower_hex(toolchain_digest, SHA256_BYTES)
            && is_lower_hex(build_manifest_digest, SHA256_BYTES),
        "toolchain and build manifest digests must be lowercase SHA-256"
    );
    Ok(())
}

fn validate_time_window(issued_at: &str, expires_at: &str) -> Result<()> {
    let issued_at = parse_timestamp(issued_at, "issuedAt")?;
    let expires_at = parse_timestamp(expires_at, "expiresAt")?;
    ensure!(
        expires_at > issued_at,
        "evidence expiresAt must be after issuedAt"
    );
    Ok(())
}

fn parse_timestamp(value: &str, label: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{label} must be RFC3339"))
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn is_source_commit(value: &str) -> bool {
    (is_lower_hex(value, SOURCE_COMMIT_MIN_BYTES) || is_lower_hex(value, SOURCE_COMMIT_MAX_BYTES))
        && !value.is_empty()
}

fn platform_for_target(target_triple: &str) -> String {
    match target_triple {
        "aarch64-apple-darwin" => "macos-aarch64".to_owned(),
        "x86_64-apple-darwin" => "macos-x86_64".to_owned(),
        _ => "ci-unclassified".to_owned(),
    }
}

fn string_at(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("JSON pointer {pointer} is not a string"))
}

fn bool_at(value: &Value, pointer: &str) -> Result<bool> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .with_context(|| format!("JSON pointer {pointer} is not a boolean"))
}

fn usize_at(value: &Value, pointer: &str) -> Result<usize> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .with_context(|| format!("JSON pointer {pointer} is not a usize"))
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::{Value, json};

    use super::{
        CONTRACT, CONTRACT_SCHEMA, DistributionVerifierProvider, GenerationInput,
        ReleaseEvidencePlugin, VerificationInput, contract_digests,
        dependency_evidence_from_report, validate_contracts,
    };
    use crate::digest::{domain_canonical_json_bytes, sha256_hex, sha256_json};
    use crate::model::{
        ArtifactBinding, AttestationEvidence, DependencyEvidenceBinding, DetachedSignature,
        EvidenceOrigin, EvidenceStatus, ProvenanceBinding, ReleaseContract, ReleaseEvidence,
        SbomEvidence, SbomFormat, TargetBinding, ValidityWindow,
    };

    const SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
    const LOCK_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TOOLCHAIN_DIGEST: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const MANIFEST_DIGEST: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";

    fn sample_dependency() -> DependencyEvidenceBinding {
        DependencyEvidenceBinding {
            report_digest: "55".repeat(32),
            report_schema_version: "hartevo-distribution-dependency-advisory/v1".to_owned(),
            policy_id: "DIST-SBOM-TARGET-01".to_owned(),
            status: "PASS".to_owned(),
            release: false,
            source_commit: SOURCE_COMMIT.to_owned(),
            lockfile_digest: LOCK_DIGEST.to_owned(),
            audit_receipt_digest: "66".repeat(32),
            finding_digest: "77".repeat(32),
            code_failure_count: 0,
            informational_warning_count: 1,
            target_bindings: vec![TargetBinding {
                platform: "macos-aarch64".to_owned(),
                target_triple: "aarch64-apple-darwin".to_owned(),
                metadata_digest: "88".repeat(32),
                role: "release".to_owned(),
                release: true,
            }],
        }
    }

    fn sample_evidence() -> ReleaseEvidence {
        let dependency_evidence = sample_dependency();
        let artifact_digest = sha256_hex(b"artifact-v1");
        let sbom_digest = "aa".repeat(32);
        let attestation_digest = "bb".repeat(32);
        let evidence = ReleaseEvidence {
            schema_version: "hartevo-distribution-release-evidence/v1".to_owned(),
            plugin_id: "DIST-SBOM-TARGET-02".to_owned(),
            provider: "hartevo-distribution-verifier-provider".to_owned(),
            provider_version: "1.0.0".to_owned(),
            consumer: "release-promotion-eval-gate".to_owned(),
            release_decision: "NOT_EVALUATED".to_owned(),
            release: ReleaseContract {
                passed: false,
                deployment: false,
            },
            evidence_origin: EvidenceOrigin::ExternalSigned,
            version: "0.1.0".to_owned(),
            platform: "macos-aarch64".to_owned(),
            target_triple: "aarch64-apple-darwin".to_owned(),
            artifact: ArtifactBinding {
                version: "0.1.0".to_owned(),
                sha256: artifact_digest.clone(),
                platform: "macos-aarch64".to_owned(),
                target_triple: "aarch64-apple-darwin".to_owned(),
            },
            sbom: SbomEvidence {
                format: SbomFormat::Cyclonedx,
                spec_version: "1.6".to_owned(),
                document_version: "1".to_owned(),
                digest: sbom_digest.clone(),
                platform: "macos-aarch64".to_owned(),
                target_triple: "aarch64-apple-darwin".to_owned(),
                artifact_digest: artifact_digest.clone(),
                source_commit: SOURCE_COMMIT.to_owned(),
                lockfile_digest: LOCK_DIGEST.to_owned(),
            },
            attestation: AttestationEvidence {
                predicate_type: "https://slsa.dev/provenance/v1".to_owned(),
                version: "0.1.0".to_owned(),
                digest: attestation_digest.clone(),
                platform: "macos-aarch64".to_owned(),
                target_triple: "aarch64-apple-darwin".to_owned(),
                artifact_digest: artifact_digest.clone(),
                sbom_digest: sbom_digest.clone(),
                source_commit: SOURCE_COMMIT.to_owned(),
                lockfile_digest: LOCK_DIGEST.to_owned(),
                toolchain_version: "rustc 1.88.0".to_owned(),
                toolchain_digest: TOOLCHAIN_DIGEST.to_owned(),
                build_manifest_digest: MANIFEST_DIGEST.to_owned(),
            },
            provenance: ProvenanceBinding {
                source_commit: SOURCE_COMMIT.to_owned(),
                cargo_lock_digest: LOCK_DIGEST.to_owned(),
                toolchain_version: "rustc 1.88.0".to_owned(),
                toolchain_digest: TOOLCHAIN_DIGEST.to_owned(),
                build_manifest_digest: MANIFEST_DIGEST.to_owned(),
                artifact_digest,
                sbom_digest,
                attestation_digest,
                dependency_evidence_digest: sha256_json(&dependency_evidence).expect("dependency"),
            },
            dependency_evidence,
            validity: ValidityWindow {
                issued_at: "2026-08-14T00:00:00Z".to_owned(),
                expires_at: "2026-08-15T00:00:00Z".to_owned(),
            },
            signature: DetachedSignature {
                algorithm: "ed25519".to_owned(),
                detached: true,
                key_reference: Some("release-key-01".to_owned()),
                signature_digest: None,
            },
            payload_digest: String::new(),
        };
        ReleaseEvidence {
            payload_digest: sha256_json(&evidence.signed_payload()).expect("payload"),
            ..evidence
        }
    }

    fn signed_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let signer = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).expect("fixed signer");
        let mut evidence = sample_evidence();
        let artifact_digest = sha256_hex(b"artifact-v1");
        let sbom = json!({
            "schemaVersion": "hartevo-distribution-sbom/v1",
            "format": "cyclonedx",
            "specVersion": "1.6",
            "documentVersion": "1",
            "version": "0.1.0",
            "platform": "macos-aarch64",
            "targetTriple": "aarch64-apple-darwin",
            "sourceCommit": SOURCE_COMMIT,
            "artifactDigest": artifact_digest,
            "lockfileDigest": LOCK_DIGEST
        });
        let sbom_bytes = serde_json::to_vec(&sbom).expect("sbom");
        evidence.sbom.digest = sha256_hex(&sbom_bytes);
        evidence.provenance.sbom_digest = evidence.sbom.digest.clone();
        evidence.attestation.sbom_digest = evidence.sbom.digest.clone();
        let attestation = json!({
            "schemaVersion": "hartevo-distribution-attestation/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "version": "0.1.0",
            "platform": "macos-aarch64",
            "targetTriple": "aarch64-apple-darwin",
            "sourceCommit": SOURCE_COMMIT,
            "artifactDigest": artifact_digest,
            "sbomDigest": evidence.sbom.digest.clone(),
            "lockfileDigest": LOCK_DIGEST,
            "toolchainVersion": "rustc 1.88.0",
            "toolchainDigest": TOOLCHAIN_DIGEST,
            "buildManifestDigest": MANIFEST_DIGEST
        });
        let attestation_bytes = serde_json::to_vec(&attestation).expect("attestation");
        evidence.attestation.digest = sha256_hex(&attestation_bytes);
        evidence.provenance.attestation_digest = evidence.attestation.digest.clone();
        evidence.payload_digest = sha256_json(&evidence.signed_payload()).expect("payload");
        let payload =
            domain_canonical_json_bytes(super::SIGNATURE_DOMAIN, &evidence.signed_payload())
                .expect("payload bytes");
        let signature_hex = hex::encode(signer.sign(&payload).as_ref());
        evidence.signature.signature_digest = Some(sha256_hex(
            &hex::decode(&signature_hex).expect("signature hex"),
        ));
        let evidence_bytes = serde_json::to_vec(&evidence).expect("evidence");
        let public_key_hex = hex::encode(signer.public_key().as_ref());
        let registry_projection = json!({
            "schemaVersion": "hartevo-distribution-key-registry/v1",
            "registryVersion": "2026-08-14.1",
            "keys": [{
                "keyReference": "release-key-01",
                "algorithm": "ed25519",
                "publicKeyHex": public_key_hex,
                "validFrom": "2026-08-13T00:00:00Z",
                "validUntil": "2026-08-20T00:00:00Z",
                "revokedAt": null
            }]
        });
        let registry = json!({
            "schemaVersion": "hartevo-distribution-key-registry/v1",
            "registryVersion": "2026-08-14.1",
            "registryDigest": sha256_json(&registry_projection).expect("registry digest"),
            "keys": registry_projection["keys"].clone()
        });
        (
            evidence_bytes,
            signature_hex.into_bytes(),
            serde_json::to_vec(&registry).expect("registry"),
            sbom_bytes,
            attestation_bytes,
        )
    }

    #[test]
    fn committed_contract_is_closed_and_release_false() {
        validate_contracts().expect("contract validation");
        assert_eq!(contract_digests().0.len(), 64);
        assert!(!CONTRACT.is_empty() && !CONTRACT_SCHEMA.is_empty());
    }

    #[test]
    fn generation_is_explicitly_unsigned_and_not_production_evidence() {
        let artifact = b"artifact-v1".to_vec();
        let artifact_digest = sha256_hex(&artifact);
        let sbom = json!({
            "schemaVersion": "hartevo-distribution-sbom/v1",
            "format": "cyclonedx",
            "specVersion": "1.6",
            "documentVersion": "1",
            "version": "0.1.0",
            "platform": "macos-aarch64",
            "targetTriple": "aarch64-apple-darwin",
            "sourceCommit": SOURCE_COMMIT,
            "artifactDigest": artifact_digest,
            "lockfileDigest": LOCK_DIGEST
        });
        let sbom_bytes = serde_json::to_vec(&sbom).expect("sbom");
        let attestation = json!({
            "schemaVersion": "hartevo-distribution-attestation/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "version": "0.1.0",
            "platform": "macos-aarch64",
            "targetTriple": "aarch64-apple-darwin",
            "sourceCommit": SOURCE_COMMIT,
            "artifactDigest": artifact_digest,
            "sbomDigest": sha256_hex(&sbom_bytes),
            "lockfileDigest": LOCK_DIGEST,
            "toolchainVersion": "rustc 1.88.0",
            "toolchainDigest": TOOLCHAIN_DIGEST,
            "buildManifestDigest": MANIFEST_DIGEST
        });
        let report = json!({
            "schemaVersion": "hartevo-distribution-dependency-advisory/v1",
            "policyId": "DIST-SBOM-TARGET-01",
            "status": "PASS",
            "release": false,
            "sourceCommit": SOURCE_COMMIT,
            "lockfileSha256": LOCK_DIGEST,
            "auditReceiptSha256": "66".repeat(32),
            "findings": [],
            "targetMetadata": [{
                "target": "macos-aarch64",
                "targetTriple": "aarch64-apple-darwin",
                "role": "release",
                "release": true,
                "metadataSha256": "88".repeat(32)
            }],
            "codeFailureCount": 0,
            "informationalWarningCount": 0
        });
        let evidence = DistributionVerifierProvider
            .generate(&GenerationInput {
                version: "0.1.0".to_owned(),
                platform: "macos-aarch64".to_owned(),
                target_triple: "aarch64-apple-darwin".to_owned(),
                source_commit: SOURCE_COMMIT.to_owned(),
                artifact_bytes: artifact,
                sbom_bytes,
                attestation_bytes: serde_json::to_vec(&attestation).expect("attestation"),
                advisory_report_bytes: serde_json::to_vec(&report).expect("report"),
                toolchain_version: "rustc 1.88.0".to_owned(),
                toolchain_digest: TOOLCHAIN_DIGEST.to_owned(),
                build_manifest_digest: MANIFEST_DIGEST.to_owned(),
                issued_at: "2026-08-14T00:00:00Z".to_owned(),
                expires_at: "2026-08-15T00:00:00Z".to_owned(),
            })
            .expect("generated evidence");
        assert_eq!(evidence.evidence_origin, EvidenceOrigin::UnsignedGenerated);
        assert!(evidence.signature.key_reference.is_none());
        assert!(!evidence.release.passed);
    }

    #[test]
    fn signed_evidence_verifies_but_consumer_remains_release_false() {
        let (evidence_bytes, signature_hex, registry_bytes, sbom_bytes, attestation_bytes) =
            signed_inputs();
        let artifact_bytes = b"artifact-v1".to_vec();
        let provider = DistributionVerifierProvider;
        let report = provider
            .verify(&VerificationInput {
                evidence_bytes,
                artifact_bytes,
                sbom_bytes: Some(sbom_bytes),
                attestation_bytes: Some(attestation_bytes),
                signature_hex: Some(String::from_utf8(signature_hex).expect("signature")),
                key_registry_bytes: Some(registry_bytes),
                as_of: "2026-08-14T12:00:00Z".to_owned(),
                expected_version: Some("0.1.0".to_owned()),
                expected_platform: Some("macos-aarch64".to_owned()),
                expected_target_triple: Some("aarch64-apple-darwin".to_owned()),
                expected_source_commit: Some(SOURCE_COMMIT.to_owned()),
            })
            .expect("verification report");
        assert_eq!(
            report.status,
            EvidenceStatus::Verified,
            "verification failures: {:?}",
            report.verification_receipt.failure_codes
        );
        assert!(!report.release);
        assert!(!report.promotion_eligible);
        assert_eq!(report.gate.decision, "BLOCKED_RELEASE_FALSE");
    }

    #[test]
    fn tampered_signed_payload_and_expired_key_fail_closed() {
        let (evidence_bytes, signature_hex, mut registry_bytes, sbom_bytes, attestation_bytes) =
            signed_inputs();
        let mut registry: Value = serde_json::from_slice(&registry_bytes).expect("registry");
        registry["keys"][0]["revokedAt"] = json!("2026-08-14T01:00:00Z");
        registry["registryDigest"] = Value::String(
            sha256_json(&json!({
                "schemaVersion": registry["schemaVersion"],
                "registryVersion": registry["registryVersion"],
                "keys": registry["keys"]
            }))
            .expect("registry digest"),
        );
        registry_bytes = serde_json::to_vec(&registry).expect("registry");
        let mut tampered: Value = serde_json::from_slice(&evidence_bytes).expect("evidence");
        tampered["version"] = json!("9.9.9");
        let report = DistributionVerifierProvider
            .verify(&VerificationInput {
                evidence_bytes: serde_json::to_vec(&tampered).expect("tampered evidence"),
                artifact_bytes: b"artifact-v1".to_vec(),
                sbom_bytes: Some(sbom_bytes),
                attestation_bytes: Some(attestation_bytes),
                signature_hex: Some(String::from_utf8(signature_hex).expect("signature")),
                key_registry_bytes: Some(registry_bytes),
                as_of: "2026-08-14T12:00:00Z".to_owned(),
                expected_version: None,
                expected_platform: None,
                expected_target_triple: None,
                expected_source_commit: None,
            })
            .expect("fail-closed report");
        assert_eq!(report.status, EvidenceStatus::CodeFailure);
        assert!(!report.release);
        assert!(
            report
                .verification_receipt
                .failure_codes
                .iter()
                .any(|code| code == "SIGNED_PAYLOAD_DIGEST_DRIFT"
                    || code == "DETACHED_SIGNATURE_INVALID")
        );
    }

    #[test]
    fn missing_credentials_are_blocked_environment_not_pass() {
        let (evidence_bytes, _, _, sbom_bytes, attestation_bytes) = signed_inputs();
        let report = DistributionVerifierProvider
            .verify(&VerificationInput {
                evidence_bytes,
                artifact_bytes: b"artifact-v1".to_vec(),
                sbom_bytes: Some(sbom_bytes),
                attestation_bytes: Some(attestation_bytes),
                signature_hex: None,
                key_registry_bytes: None,
                as_of: "2026-08-14T12:00:00Z".to_owned(),
                expected_version: None,
                expected_platform: None,
                expected_target_triple: None,
                expected_source_commit: None,
            })
            .expect("blocked report");
        assert_eq!(
            report.status,
            EvidenceStatus::BlockedEnv,
            "verification failures: {:?}",
            report.verification_receipt.failure_codes
        );
        assert!(!report.release);
        assert!(!report.promotion_eligible);
    }

    #[test]
    fn raw_sbom_or_attestation_tampering_is_code_failure() {
        let (evidence_bytes, signature_hex, registry_bytes, sbom_bytes, attestation_bytes) =
            signed_inputs();
        let mut tampered_sbom: Value = serde_json::from_slice(&sbom_bytes).expect("SBOM");
        tampered_sbom["documentVersion"] = json!("2");
        let report = DistributionVerifierProvider
            .verify(&VerificationInput {
                evidence_bytes: evidence_bytes.clone(),
                artifact_bytes: b"artifact-v1".to_vec(),
                sbom_bytes: Some(serde_json::to_vec(&tampered_sbom).expect("tampered SBOM")),
                attestation_bytes: Some(attestation_bytes.clone()),
                signature_hex: Some(String::from_utf8(signature_hex.clone()).expect("signature")),
                key_registry_bytes: Some(registry_bytes.clone()),
                as_of: "2026-08-14T12:00:00Z".to_owned(),
                expected_version: None,
                expected_platform: None,
                expected_target_triple: None,
                expected_source_commit: None,
            })
            .expect("SBOM tamper report");
        assert_eq!(report.status, EvidenceStatus::CodeFailure);
        assert!(
            report
                .verification_receipt
                .failure_codes
                .iter()
                .any(|code| { code == "SBOM_CONTENT_DIGEST_OR_BINDING_DRIFT" })
        );

        let mut tampered_attestation: Value =
            serde_json::from_slice(&attestation_bytes).expect("attestation");
        tampered_attestation["toolchainDigest"] = json!("00".repeat(32));
        let report = DistributionVerifierProvider
            .verify(&VerificationInput {
                evidence_bytes,
                artifact_bytes: b"artifact-v1".to_vec(),
                sbom_bytes: Some(sbom_bytes),
                attestation_bytes: Some(
                    serde_json::to_vec(&tampered_attestation).expect("tampered attestation"),
                ),
                signature_hex: Some(String::from_utf8(signature_hex).expect("signature")),
                key_registry_bytes: Some(registry_bytes),
                as_of: "2026-08-14T12:00:00Z".to_owned(),
                expected_version: None,
                expected_platform: None,
                expected_target_triple: None,
                expected_source_commit: None,
            })
            .expect("attestation tamper report");
        assert_eq!(report.status, EvidenceStatus::CodeFailure);
        assert!(
            report
                .verification_receipt
                .failure_codes
                .iter()
                .any(|code| { code == "ATTESTATION_CONTENT_DIGEST_OR_BINDING_DRIFT" })
        );
    }

    #[test]
    fn expired_evidence_window_is_code_failure() {
        let (evidence_bytes, signature_hex, registry_bytes, sbom_bytes, attestation_bytes) =
            signed_inputs();
        let report = DistributionVerifierProvider
            .verify(&VerificationInput {
                evidence_bytes,
                artifact_bytes: b"artifact-v1".to_vec(),
                sbom_bytes: Some(sbom_bytes),
                attestation_bytes: Some(attestation_bytes),
                signature_hex: Some(String::from_utf8(signature_hex).expect("signature")),
                key_registry_bytes: Some(registry_bytes),
                as_of: "2026-08-16T00:00:00Z".to_owned(),
                expected_version: None,
                expected_platform: None,
                expected_target_triple: None,
                expected_source_commit: None,
            })
            .expect("expiry report");
        assert_eq!(report.status, EvidenceStatus::CodeFailure);
        assert!(
            report
                .verification_receipt
                .failure_codes
                .contains(&"EVIDENCE_EXPIRED".to_owned())
        );
    }

    #[test]
    fn dependency_report_preserves_target_bindings() {
        let report = json!({
            "schemaVersion": "hartevo-distribution-dependency-advisory/v1",
            "policyId": "DIST-SBOM-TARGET-01",
            "status": "PASS",
            "release": false,
            "sourceCommit": SOURCE_COMMIT,
            "lockfileSha256": LOCK_DIGEST,
            "auditReceiptSha256": "66".repeat(32),
            "findings": [],
            "targetMetadata": [{
                "target": "linux-x86_64-ci",
                "targetTriple": "x86_64-unknown-linux-gnu",
                "role": "ci",
                "release": false,
                "metadataSha256": "88".repeat(32)
            }],
            "codeFailureCount": 0,
            "informationalWarningCount": 1
        });
        let binding =
            dependency_evidence_from_report(&serde_json::to_vec(&report).expect("report"))
                .expect("binding");
        assert_eq!(binding.target_bindings[0].platform, "ci-unclassified");
        assert!(!binding.target_bindings[0].release);
    }
}
