use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use chrono::Duration;
use serde::Serialize;
use serde_json::Value;

use crate::digest::{digest_json, is_lower_hex, sha256_hex};
use crate::model::{
    ConsumerEvidence, EnvironmentStatus, LifecycleHook, LifecycleProof, ProviderMode,
    ProviderProvenance, ReceiptStatus, RedactionEvidence, RedactionSurface, SecretBrokerAcceptance,
    VerificationStatus,
};

pub const CONTRACT_PATH: &str = "contracts/secrets/secret-broker-native-acceptance.v1.json";
pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-secret-broker-native-acceptance/v1";
pub const DOCUMENT_TYPE: &str = "secret_broker_native_acceptance";
pub const AUTHORITY: &str = "secret_broker_native_acceptance_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const REPORT_SCHEMA_VERSION: &str = "hartevo-secret-broker-native-acceptance-report/v1";

const CONTRACT_BYTES: &[u8] =
    include_bytes!("../../../../contracts/secrets/secret-broker-native-acceptance.v1.json");
const REQUIRED_LIFECYCLE_HOOKS: [LifecycleHook; 5] = [
    LifecycleHook::Rotation,
    LifecycleHook::Revoke,
    LifecycleHook::Unmount,
    LifecycleHook::Crash,
    LifecycleHook::Replay,
];
const REQUIRED_REDACTION_SURFACES: [RedactionSurface; 5] = [
    RedactionSurface::Mission,
    RedactionSurface::Event,
    RedactionSurface::Debug,
    RedactionSurface::Error,
    RedactionSurface::Receipt,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidatorStatus {
    NativePass,
    BlockedEnv,
    NotEvaluated,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ValidationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub release_decision: &'static str,
    pub validator_status: ValidatorStatus,
    pub native_pass: bool,
    pub source_commit: String,
    pub contract_digest: String,
    pub scope_digest: String,
    pub provider_mode: ProviderMode,
    pub lease_reclaimed: bool,
    pub lifecycle_verified: bool,
    pub redaction_verified: bool,
    pub missing_reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct ScopeDigestMaterial<'a> {
    tenant_id: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultDigestMaterial<'a> {
    scope_digest: &'a str,
    provider_output_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestMaterial<'a> {
    source_commit: &'a str,
    scope_digest: &'a str,
    reference_digest: &'a str,
    lease_digest: &'a str,
    result_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationDigestMaterial<'a> {
    source_commit: &'a str,
    scope_digest: &'a str,
    receipt_digest: &'a str,
    result_digest: &'a str,
    provider_output_digest: &'a str,
    verified: bool,
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_BYTES)
}

pub fn current_source_commit() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("invoke Git for the current source commit")?;
    ensure!(
        output.status.success(),
        "Git cannot resolve the current source commit"
    );
    let commit = String::from_utf8(output.stdout)
        .context("Git returned a non-UTF-8 source commit")?
        .trim()
        .to_owned();
    validate_commit(&commit)?;
    Ok(commit)
}

pub fn read_acceptance(path: impl AsRef<Path>) -> Result<SecretBrokerAcceptance> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("read acceptance input {}", path.display()))?;
    crate::model::parse_strict_json(&bytes)
        .with_context(|| format!("parse strict acceptance input {}", path.display()))
}

pub fn validate_contract() -> Result<()> {
    let contract: Value = crate::model::parse_strict_json(CONTRACT_BYTES)
        .context("Secret Broker acceptance contract is not strict JSON")?;
    validate_contract_root(&contract)?;
    validate_contract_definitions(&contract)
}

fn validate_contract_root(contract: &Value) -> Result<()> {
    ensure!(
        contract.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema"),
        "acceptance contract must declare JSON Schema 2020-12"
    );
    ensure!(
        contract.get("type").and_then(Value::as_str) == Some("object")
            && contract
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false),
        "acceptance contract root must be a closed object"
    );
    ensure!(
        contract.get("$id").and_then(Value::as_str) == Some(CONTRACT_SCHEMA_VERSION),
        "acceptance contract id drifted"
    );
    let expected = [
        "schemaVersion",
        "documentType",
        "authority",
        "releaseDecision",
        "sourceCommit",
        "scope",
        "secretReference",
        "dispatch",
        "lease",
        "provider",
        "consumer",
        "receipt",
        "verification",
        "redaction",
        "lifecycleProofs",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let required = exact_string_set(contract.get("required").context("contract required list")?)?;
    ensure!(
        required == expected,
        "acceptance contract required set drifted"
    );
    let properties = contract
        .get("properties")
        .and_then(Value::as_object)
        .context("acceptance contract root properties")?;
    ensure!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "acceptance contract root property set drifted"
    );
    for (property, expected_const) in [
        ("schemaVersion", CONTRACT_SCHEMA_VERSION),
        ("documentType", DOCUMENT_TYPE),
        ("authority", AUTHORITY),
        ("releaseDecision", RELEASE_DECISION),
    ] {
        ensure!(
            properties
                .get(property)
                .and_then(|value| value.get("const"))
                .and_then(Value::as_str)
                == Some(expected_const),
            "acceptance contract {property} constant drifted"
        );
    }
    Ok(())
}

fn validate_contract_definitions(contract: &Value) -> Result<()> {
    let defs = contract
        .get("$defs")
        .and_then(Value::as_object)
        .context("acceptance contract definitions")?;
    let expected = [
        "consumer",
        "dispatch",
        "lease",
        "lifecycleProof",
        "provider",
        "receipt",
        "redaction",
        "redactionSurface",
        "scope",
        "secretReference",
        "verification",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    ensure!(
        defs.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected,
        "acceptance contract definition set drifted"
    );
    for definition in defs.values() {
        ensure!(
            definition.get("type").and_then(Value::as_str) == Some("object")
                && definition
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    == Some(false),
            "acceptance contract nested definition must be a closed object"
        );
    }
    Ok(())
}

pub fn validate_acceptance(
    acceptance: &SecretBrokerAcceptance,
    expected_source_commit: &str,
) -> Result<ValidationReport> {
    validate_commit(expected_source_commit)?;
    ensure!(
        acceptance.schema_version == CONTRACT_SCHEMA_VERSION
            && acceptance.document_type == DOCUMENT_TYPE
            && acceptance.authority == AUTHORITY
            && acceptance.release_decision == RELEASE_DECISION,
        "acceptance envelope schema, document type, authority or Release decision drifted"
    );
    ensure_source(
        &acceptance.source_commit,
        expected_source_commit,
        "envelope",
    )?;
    validate_scope(&acceptance.scope)?;
    validate_reference(acceptance)?;
    validate_dispatch(acceptance)?;
    validate_lease(acceptance)?;
    validate_provider(acceptance)?;
    validate_consumer(acceptance)?;
    validate_receipt(acceptance)?;
    validate_verification(acceptance)?;
    validate_redaction(&acceptance.redaction, expected_source_commit)?;
    validate_lifecycle(&acceptance.lifecycle_proofs, acceptance)?;
    let (native_candidate, missing_reasons) = assess_native_candidate(acceptance)?;

    let environment_blocked = matches!(
        acceptance.provider.mode,
        ProviderMode::BlockedEnv | ProviderMode::Missing
    ) || (acceptance.provider.mode == ProviderMode::Native
        && (acceptance.provider.os_keyring_status != EnvironmentStatus::Available
            || acceptance.provider.real_output_status != EnvironmentStatus::Available
            || !acceptance.provider.output_present
            || acceptance.provider.provenance != ProviderProvenance::NativeProvider));
    let validator_status = if native_candidate {
        ValidatorStatus::NativePass
    } else if environment_blocked {
        ValidatorStatus::BlockedEnv
    } else {
        ValidatorStatus::NotEvaluated
    };
    Ok(ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status,
        native_pass: native_candidate,
        source_commit: expected_source_commit.into(),
        contract_digest: contract_digest(),
        scope_digest: acceptance.scope.scope_digest.clone(),
        provider_mode: acceptance.provider.mode,
        lease_reclaimed: acceptance.lease.reclaimed && !acceptance.lease.active_after_reclaim,
        lifecycle_verified: true,
        redaction_verified: acceptance.redaction.all_content_free,
        missing_reasons,
    })
}

fn validate_scope(scope: &crate::model::Scope) -> Result<()> {
    validate_identifier(&scope.tenant_id, "tenant id")?;
    validate_identifier(&scope.project_id, "project id")?;
    validate_identifier(&scope.mission_id, "mission id")?;
    validate_digest(&scope.scope_digest, "scope digest")?;
    ensure!(
        scope.scope_digest == expected_scope_digest(scope)?,
        "scope digest is not derived from tenant/project/mission"
    );
    Ok(())
}

fn validate_reference(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let reference = &acceptance.secret_reference;
    validate_digest(&reference.reference_digest, "SecretReference digest")?;
    validate_digest(&reference.service_digest, "service digest")?;
    validate_digest(&reference.account_digest, "account digest")?;
    validate_identifier(&reference.provider_id, "provider id")?;
    validate_identifier(&reference.capability, "capability")?;
    ensure!(
        reference.credential_revision > 0,
        "credential revision must be positive"
    );
    ensure!(
        reference.generation > 0,
        "reference generation must be positive"
    );
    ensure!(
        reference.scope_digest == acceptance.scope.scope_digest,
        "SecretReference scope drifted"
    );
    ensure!(
        reference.reference_only,
        "SecretReference must remain opaque and reference-only"
    );
    ensure!(
        !reference.plaintext_present,
        "SecretReference contains plaintext"
    );
    Ok(())
}

fn validate_dispatch(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let dispatch = &acceptance.dispatch;
    ensure!(
        dispatch.mode == "reference_only",
        "provider dispatch is not reference-only"
    );
    ensure!(
        dispatch.reference_digest == acceptance.secret_reference.reference_digest
            && dispatch.scope_digest == acceptance.scope.scope_digest,
        "provider dispatch reference/scope drifted"
    );
    ensure!(
        !dispatch.contains_handle && !dispatch.contains_lease && !dispatch.contains_plaintext,
        "provider dispatch carried handle, lease or plaintext"
    );
    ensure!(
        dispatch.reauthorization_required,
        "reference replay does not require reauthorization"
    );
    Ok(())
}

fn validate_lease(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let lease = &acceptance.lease;
    validate_digest(&lease.lease_digest, "lease digest")?;
    ensure!(
        lease.scope_digest == acceptance.scope.scope_digest
            && lease.generation == acceptance.secret_reference.generation
            && lease.credential_revision == acceptance.secret_reference.credential_revision,
        "lease scope, generation or credential revision drifted"
    );
    ensure!(
        (1..=60).contains(&lease.ttl_seconds),
        "lease TTL must be within the short-lease bound"
    );
    ensure!(
        lease.issued_at < lease.expires_at,
        "lease validity window is empty"
    );
    let lifetime = lease.expires_at.signed_duration_since(lease.issued_at);
    ensure!(
        lifetime > Duration::zero()
            && lifetime <= Duration::seconds(lease.ttl_seconds.cast_signed()),
        "lease expiry exceeds its declared short TTL"
    );
    ensure!(
        lease.reclaimed_at >= lease.issued_at,
        "lease reclaim precedes lease issuance"
    );
    ensure!(
        lease.reclaimed && !lease.active_after_reclaim && lease.provider_boundary,
        "lease was not reclaimed at the provider boundary"
    );
    ensure!(
        !lease.plaintext_present,
        "lease evidence contains plaintext"
    );
    Ok(())
}

fn validate_provider(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let provider = &acceptance.provider;
    validate_identifier(&provider.id, "provider id")?;
    ensure_source(
        &provider.source_commit,
        &acceptance.source_commit,
        "provider",
    )?;
    ensure!(
        provider.scope_digest == acceptance.scope.scope_digest,
        "provider scope drifted"
    );
    if provider.output_present {
        validate_digest(&provider.output_digest, "provider output digest")?;
    } else {
        ensure!(
            provider.output_digest.is_empty(),
            "missing provider output cannot carry an output digest"
        );
    }
    if provider.provenance == ProviderProvenance::NativeProvider {
        ensure!(
            provider.mode == ProviderMode::Native,
            "native provider provenance requires native provider mode"
        );
    }
    ensure!(
        provider.consumer_used_service,
        "provider did not use the broker service"
    );
    ensure!(
        !provider.plaintext_present,
        "provider evidence contains plaintext"
    );
    Ok(())
}

fn validate_consumer(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    validate_consumer_fields(&acceptance.consumer, acceptance)?;
    Ok(())
}

fn validate_consumer_fields(
    consumer: &ConsumerEvidence,
    acceptance: &SecretBrokerAcceptance,
) -> Result<()> {
    validate_identifier(&consumer.id, "consumer id")?;
    ensure_source(
        &consumer.source_commit,
        &acceptance.source_commit,
        "consumer",
    )?;
    ensure!(
        consumer.scope_digest == acceptance.scope.scope_digest
            && consumer.reference_digest == acceptance.secret_reference.reference_digest
            && consumer.generation == acceptance.secret_reference.generation
            && consumer.credential_revision == acceptance.secret_reference.credential_revision,
        "consumer scope/reference lineage drifted"
    );
    ensure!(
        consumer.service_used
            && consumer.provider_dispatch_reference_only
            && !consumer.effect_authority_attached,
        "consumer did not prove service-only reference dispatch"
    );
    ensure!(
        !consumer.plaintext_present,
        "consumer evidence contains plaintext"
    );
    Ok(())
}

fn validate_receipt(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let receipt = &acceptance.receipt;
    ensure_source(&receipt.source_commit, &acceptance.source_commit, "receipt")?;
    ensure!(
        receipt.scope_digest == acceptance.scope.scope_digest
            && receipt.reference_digest == acceptance.secret_reference.reference_digest
            && receipt.lease_digest == acceptance.lease.lease_digest,
        "receipt scope/reference/lease lineage drifted"
    );
    ensure!(
        receipt.lease_reclaimed,
        "receipt does not prove lease reclamation"
    );
    ensure!(
        !receipt.contains_handle,
        "receipt contains a provider handle"
    );
    ensure!(
        !receipt.plaintext_present && receipt.error_redacted,
        "receipt redaction failed"
    );
    if receipt.status == ReceiptStatus::NotEvaluated {
        ensure!(
            receipt.result_digest.is_empty() && receipt.verification_digest.is_empty(),
            "NOT_EVALUATED receipt cannot carry native result digests"
        );
    } else {
        validate_digest(&receipt.result_digest, "receipt result digest")?;
        validate_digest(&receipt.verification_digest, "receipt verification digest")?;
    }
    Ok(())
}

fn validate_verification(acceptance: &SecretBrokerAcceptance) -> Result<()> {
    let verification = &acceptance.verification;
    ensure_source(
        &verification.source_commit,
        &acceptance.source_commit,
        "verification",
    )?;
    ensure!(
        verification.scope_digest == acceptance.scope.scope_digest,
        "verification scope drifted"
    );
    if verification.verified {
        ensure!(
            verification.status == VerificationStatus::Verified,
            "verified evidence has a non-verified status"
        );
        validate_digest(&verification.receipt_digest, "verification receipt digest")?;
        validate_digest(&verification.result_digest, "verification result digest")?;
        validate_digest(
            &verification.provider_output_digest,
            "verification provider output digest",
        )?;
    } else {
        ensure!(
            verification.status != VerificationStatus::Verified,
            "unverified evidence has a verified status"
        );
        ensure!(
            verification.receipt_digest.is_empty()
                && verification.result_digest.is_empty()
                && verification.provider_output_digest.is_empty(),
            "non-native verification cannot carry native digests"
        );
    }
    ensure!(
        !verification.plaintext_present,
        "verification evidence contains plaintext"
    );
    Ok(())
}

fn validate_redaction(redaction: &RedactionEvidence, expected_source_commit: &str) -> Result<()> {
    ensure_source(
        &redaction.source_commit,
        expected_source_commit,
        "redaction",
    )?;
    validate_digest(&redaction.scan_digest, "redaction scan digest")?;
    ensure!(redaction.all_content_free, "content-free scan did not pass");
    ensure!(
        redaction.surfaces.len() == REQUIRED_REDACTION_SURFACES.len(),
        "redaction scan must cover mission, event, debug, error and receipt"
    );
    let mut surfaces = BTreeSet::new();
    for surface in &redaction.surfaces {
        ensure!(
            surfaces.insert(surface.surface),
            "duplicate redaction surface proof"
        );
        ensure!(
            REQUIRED_REDACTION_SURFACES.contains(&surface.surface),
            "unknown redaction surface proof"
        );
        ensure!(
            !surface.plaintext_found,
            "plaintext found in a redaction surface"
        );
        validate_digest(&surface.scan_digest, "redaction surface digest")?;
    }
    ensure!(
        surfaces == REQUIRED_REDACTION_SURFACES.into_iter().collect(),
        "redaction surface set is incomplete"
    );
    Ok(())
}

fn validate_lifecycle(
    proofs: &[LifecycleProof],
    acceptance: &SecretBrokerAcceptance,
) -> Result<()> {
    ensure!(
        proofs.len() == REQUIRED_LIFECYCLE_HOOKS.len(),
        "rotation, revoke, unmount, crash and replay proofs are required"
    );
    let mut hooks = BTreeSet::new();
    for proof in proofs {
        ensure!(hooks.insert(proof.hook), "duplicate lifecycle proof");
        ensure!(
            REQUIRED_LIFECYCLE_HOOKS.contains(&proof.hook),
            "unknown lifecycle proof"
        );
        ensure_source(&proof.source_commit, &acceptance.source_commit, "lifecycle")?;
        ensure!(
            proof.scope_digest == acceptance.scope.scope_digest
                && proof.old_reference_digest == acceptance.secret_reference.reference_digest
                && proof.old_generation == acceptance.secret_reference.generation
                && proof.old_lease_digest == acceptance.lease.lease_digest,
            "lifecycle proof is not bound to the old reference and lease"
        );
        ensure!(
            proof.new_generation > proof.old_generation,
            "lifecycle hook did not advance the generation fence"
        );
        ensure!(
            !proof.old_generation_accepted && !proof.old_lease_accepted,
            "old generation or lease remains accepted after lifecycle hook"
        );
        validate_digest(&proof.proof_digest, "lifecycle proof digest")?;
        match proof.hook {
            LifecycleHook::Replay => ensure!(
                proof.replay_reference_only
                    && proof.reauthorization_required
                    && proof.new_lease_issued,
                "replay must carry only a reference and require fresh authorization"
            ),
            _ => ensure!(
                !proof.replay_reference_only
                    && !proof.reauthorization_required
                    && !proof.new_lease_issued,
                "non-replay lifecycle proof has replay-only fields"
            ),
        }
        ensure!(
            !proof.failure_code.trim().is_empty(),
            "lifecycle proof must record a fail-closed rejection code"
        );
    }
    ensure!(
        hooks == REQUIRED_LIFECYCLE_HOOKS.into_iter().collect(),
        "lifecycle proof set is incomplete"
    );
    Ok(())
}

fn assess_native_candidate(acceptance: &SecretBrokerAcceptance) -> Result<(bool, Vec<String>)> {
    let mut missing_reasons = Vec::new();
    if acceptance.provider.mode != ProviderMode::Native {
        missing_reasons.push("provider_mode_is_not_native".into());
    }
    if acceptance.provider.provenance != ProviderProvenance::NativeProvider {
        missing_reasons.push("provider_provenance_is_not_native_provider".into());
    }
    if acceptance.provider.os_keyring_status != EnvironmentStatus::Available {
        missing_reasons.push("os_keyring_unavailable_or_not_evaluated".into());
    }
    if acceptance.provider.real_output_status != EnvironmentStatus::Available
        || !acceptance.provider.output_present
    {
        missing_reasons.push("real_provider_output_missing_or_unavailable".into());
    }
    if acceptance.receipt.status != ReceiptStatus::Completed {
        missing_reasons.push("provider_receipt_not_completed".into());
    }
    if acceptance.verification.status != VerificationStatus::Verified
        || !acceptance.verification.verified
    {
        missing_reasons.push("receipt_verification_not_native_verified".into());
    }
    let native_candidate = missing_reasons.is_empty();
    if acceptance.provider.mode == ProviderMode::Fixture {
        missing_reasons.push("fixture_evidence_is_not_native".into());
    }
    if acceptance.provider.mode == ProviderMode::BlockedEnv {
        missing_reasons.push("native_environment_blocked".into());
    }
    if native_candidate {
        ensure!(
            acceptance.receipt.result_digest
                == expected_result_digest(
                    &acceptance.scope.scope_digest,
                    &acceptance.provider.output_digest,
                )?,
            "native receipt result digest is not bound to provider output"
        );
        let expected_receipt = expected_receipt_digest(acceptance)?;
        ensure!(
            acceptance.verification.receipt_digest == expected_receipt,
            "native verification is not bound to the exact receipt"
        );
        ensure!(
            acceptance.verification.result_digest == acceptance.receipt.result_digest
                && acceptance.verification.provider_output_digest
                    == acceptance.provider.output_digest,
            "native verification result/provider digest drifted"
        );
        let expected_verification = expected_verification_digest(acceptance)?;
        ensure!(
            acceptance.receipt.verification_digest == expected_verification,
            "receipt verification digest is not derived from typed verification fields"
        );
    } else {
        ensure!(
            acceptance.receipt.status == ReceiptStatus::NotEvaluated,
            "non-native evidence cannot claim a completed receipt"
        );
        ensure!(
            !acceptance.verification.verified
                && acceptance.verification.status != VerificationStatus::Verified,
            "non-native evidence cannot claim verified output"
        );
    }
    Ok((native_candidate, missing_reasons))
}

fn expected_scope_digest(scope: &crate::model::Scope) -> Result<String> {
    digest_json(
        "hartevo-secret-broker-scope/v1",
        &ScopeDigestMaterial {
            tenant_id: &scope.tenant_id,
            project_id: &scope.project_id,
            mission_id: &scope.mission_id,
        },
    )
    .context("derive typed scope digest")
}

fn expected_result_digest(scope_digest: &str, provider_output_digest: &str) -> Result<String> {
    digest_json(
        "hartevo-secret-broker-native-result/v1",
        &ResultDigestMaterial {
            scope_digest,
            provider_output_digest,
        },
    )
    .context("derive typed provider result digest")
}

fn expected_receipt_digest(acceptance: &SecretBrokerAcceptance) -> Result<String> {
    digest_json(
        "hartevo-secret-broker-native-receipt/v1",
        &ReceiptDigestMaterial {
            source_commit: &acceptance.receipt.source_commit,
            scope_digest: &acceptance.receipt.scope_digest,
            reference_digest: &acceptance.receipt.reference_digest,
            lease_digest: &acceptance.receipt.lease_digest,
            result_digest: &acceptance.receipt.result_digest,
        },
    )
    .context("derive typed receipt digest")
}

fn expected_verification_digest(acceptance: &SecretBrokerAcceptance) -> Result<String> {
    let receipt_digest = expected_receipt_digest(acceptance)?;
    digest_json(
        "hartevo-secret-broker-native-verification/v1",
        &VerificationDigestMaterial {
            source_commit: &acceptance.verification.source_commit,
            scope_digest: &acceptance.verification.scope_digest,
            receipt_digest: &receipt_digest,
            result_digest: &acceptance.verification.result_digest,
            provider_output_digest: &acceptance.verification.provider_output_digest,
            verified: acceptance.verification.verified,
        },
    )
    .context("derive typed verification digest")
}

fn ensure_source(value: &str, expected: &str, label: &str) -> Result<()> {
    ensure!(value == expected, "{label} source commit drifted");
    Ok(())
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} is required");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)),
        "{label} contains an unsafe character"
    );
    Ok(())
}

fn validate_commit(value: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "source commit must be a lowercase 40-hex Git commit"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(is_lower_hex(value, 32), "{label} must be lowercase SHA-256");
    Ok(())
}

fn exact_string_set(value: &Value) -> Result<BTreeSet<&str>> {
    let values = value
        .as_array()
        .context("expected a JSON string array")?
        .iter()
        .map(|item| item.as_str().context("expected a JSON string"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "JSON string array contains duplicates"
    );
    Ok(values.into_iter().collect())
}

pub fn blocked_environment_report(source_commit: String) -> ValidationReport {
    ValidationReport {
        schema_version: REPORT_SCHEMA_VERSION,
        authority: AUTHORITY,
        release_decision: RELEASE_DECISION,
        validator_status: ValidatorStatus::BlockedEnv,
        native_pass: false,
        source_commit,
        contract_digest: contract_digest(),
        scope_digest: String::new(),
        provider_mode: ProviderMode::Missing,
        lease_reclaimed: false,
        lifecycle_verified: false,
        redaction_verified: false,
        missing_reasons: vec![
            "os_keyring_unavailable_or_not_evaluated".into(),
            "real_provider_output_missing_or_unavailable".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DispatchEvidence, LeaseEvidence, ProviderEvidence, ReceiptEvidence,
        RedactionSurfaceEvidence, Scope, SecretReferenceEvidence, VerificationEvidence,
    };
    use chrono::{TimeZone, Utc};

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn scope() -> Scope {
        let mut value = Scope {
            tenant_id: "tenant-native".into(),
            project_id: "project-market".into(),
            mission_id: "mission-germany".into(),
            scope_digest: String::new(),
        };
        value.scope_digest = expected_scope_digest(&value).expect("scope digest");
        value
    }

    fn base_acceptance(source_commit: &str, mode: ProviderMode) -> SecretBrokerAcceptance {
        let scope = scope();
        let reference_digest = digest('a');
        let lease_digest = digest('b');
        let output_digest = if mode == ProviderMode::Native {
            digest('c')
        } else {
            String::new()
        };
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 14, 0, 0, 0).unwrap();
        let expires_at = issued_at + Duration::seconds(30);
        let reclaimed_at = issued_at + Duration::seconds(2);
        let surfaces = REQUIRED_REDACTION_SURFACES
            .into_iter()
            .map(|surface| RedactionSurfaceEvidence {
                surface,
                plaintext_found: false,
                scan_digest: digest('d'),
            })
            .collect();
        let lifecycle_proofs = REQUIRED_LIFECYCLE_HOOKS
            .into_iter()
            .map(|hook| LifecycleProof {
                hook,
                source_commit: source_commit.into(),
                scope_digest: scope.scope_digest.clone(),
                old_reference_digest: reference_digest.clone(),
                old_generation: 1,
                new_generation: 2,
                old_lease_digest: lease_digest.clone(),
                old_generation_accepted: false,
                old_lease_accepted: false,
                replay_reference_only: hook == LifecycleHook::Replay,
                reauthorization_required: hook == LifecycleHook::Replay,
                new_lease_issued: hook == LifecycleHook::Replay,
                failure_code: "generation_fence".into(),
                proof_digest: digest('e'),
            })
            .collect();
        let mut acceptance = SecretBrokerAcceptance {
            schema_version: CONTRACT_SCHEMA_VERSION.into(),
            document_type: DOCUMENT_TYPE.into(),
            authority: AUTHORITY.into(),
            release_decision: RELEASE_DECISION.into(),
            source_commit: source_commit.into(),
            secret_reference: SecretReferenceEvidence {
                reference_digest: reference_digest.clone(),
                service_digest: digest('f'),
                provider_id: "native-provider".into(),
                account_digest: digest('1'),
                capability: "read_secret".into(),
                credential_revision: 7,
                generation: 1,
                scope_digest: scope.scope_digest.clone(),
                reference_only: true,
                plaintext_present: false,
            },
            dispatch: DispatchEvidence {
                mode: "reference_only".into(),
                reference_digest: reference_digest.clone(),
                scope_digest: scope.scope_digest.clone(),
                contains_handle: false,
                contains_lease: false,
                contains_plaintext: false,
                reauthorization_required: true,
            },
            lease: LeaseEvidence {
                lease_digest: lease_digest.clone(),
                scope_digest: scope.scope_digest.clone(),
                generation: 1,
                credential_revision: 7,
                ttl_seconds: 30,
                issued_at,
                expires_at,
                reclaimed_at,
                reclaimed: true,
                active_after_reclaim: false,
                provider_boundary: true,
                plaintext_present: false,
            },
            provider: ProviderEvidence {
                id: "native-provider".into(),
                source_commit: source_commit.into(),
                scope_digest: scope.scope_digest.clone(),
                mode,
                provenance: if mode == ProviderMode::Native {
                    ProviderProvenance::NativeProvider
                } else {
                    ProviderProvenance::Fixture
                },
                output_present: mode == ProviderMode::Native,
                output_digest,
                os_keyring_status: if mode == ProviderMode::Native {
                    EnvironmentStatus::Available
                } else {
                    EnvironmentStatus::NotEvaluated
                },
                real_output_status: if mode == ProviderMode::Native {
                    EnvironmentStatus::Available
                } else {
                    EnvironmentStatus::NotEvaluated
                },
                consumer_used_service: true,
                plaintext_present: false,
            },
            consumer: ConsumerEvidence {
                id: "consumer".into(),
                source_commit: source_commit.into(),
                scope_digest: scope.scope_digest.clone(),
                reference_digest: reference_digest.clone(),
                generation: 1,
                credential_revision: 7,
                service_used: true,
                provider_dispatch_reference_only: true,
                effect_authority_attached: false,
                plaintext_present: false,
            },
            receipt: ReceiptEvidence {
                status: ReceiptStatus::NotEvaluated,
                source_commit: source_commit.into(),
                scope_digest: scope.scope_digest.clone(),
                reference_digest,
                lease_digest,
                result_digest: String::new(),
                verification_digest: String::new(),
                lease_reclaimed: true,
                contains_handle: false,
                plaintext_present: false,
                error_redacted: true,
            },
            verification: VerificationEvidence {
                status: VerificationStatus::NotEvaluated,
                source_commit: source_commit.into(),
                scope_digest: scope.scope_digest.clone(),
                receipt_digest: String::new(),
                result_digest: String::new(),
                provider_output_digest: String::new(),
                verified: false,
                plaintext_present: false,
            },
            redaction: RedactionEvidence {
                source_commit: source_commit.into(),
                surfaces,
                all_content_free: true,
                scan_digest: digest('6'),
            },
            lifecycle_proofs,
            scope,
        };
        if mode == ProviderMode::Native {
            let output = acceptance.provider.output_digest.clone();
            acceptance.receipt.status = ReceiptStatus::Completed;
            acceptance.receipt.result_digest =
                expected_result_digest(&acceptance.scope.scope_digest, &output).unwrap();
            acceptance.verification.status = VerificationStatus::Verified;
            acceptance.verification.verified = true;
            acceptance.verification.result_digest = acceptance.receipt.result_digest.clone();
            acceptance.verification.provider_output_digest = output;
            acceptance.verification.receipt_digest = expected_receipt_digest(&acceptance).unwrap();
            acceptance.receipt.verification_digest =
                expected_verification_digest(&acceptance).unwrap();
        }
        acceptance
    }

    #[test]
    fn contract_is_strict_and_complete() {
        validate_contract().expect("contract validation");
    }

    #[test]
    fn fixture_can_never_be_native_pass() {
        let source = current_source_commit().expect("source commit");
        let report = validate_acceptance(&base_acceptance(&source, ProviderMode::Fixture), &source)
            .expect("fixture evidence should be typed not evaluated");
        assert_eq!(report.validator_status, ValidatorStatus::NotEvaluated);
        assert!(!report.native_pass);
        assert!(
            report
                .missing_reasons
                .iter()
                .any(|reason| reason == "fixture_evidence_is_not_native")
        );
    }

    #[test]
    fn complete_native_evidence_can_pass_only_with_available_environment() {
        let source = current_source_commit().expect("source commit");
        let report = validate_acceptance(&base_acceptance(&source, ProviderMode::Native), &source)
            .expect("complete native evidence should validate");
        assert_eq!(report.validator_status, ValidatorStatus::NativePass);
        assert!(report.native_pass);
        assert!(report.lease_reclaimed);
        assert!(report.lifecycle_verified);
        assert!(report.redaction_verified);
    }

    #[test]
    fn missing_keyring_is_blocked_and_not_a_native_pass() {
        let source = current_source_commit().expect("source commit");
        let mut acceptance = base_acceptance(&source, ProviderMode::Native);
        acceptance.provider.os_keyring_status = EnvironmentStatus::BlockedEnv;
        acceptance.receipt.status = ReceiptStatus::NotEvaluated;
        acceptance.receipt.result_digest.clear();
        acceptance.receipt.verification_digest.clear();
        acceptance.verification.status = VerificationStatus::BlockedEnv;
        acceptance.verification.receipt_digest.clear();
        acceptance.verification.result_digest.clear();
        acceptance.verification.provider_output_digest.clear();
        acceptance.verification.verified = false;
        let report = validate_acceptance(&acceptance, &source)
            .expect("missing keyring should be a typed blocked environment");
        assert_eq!(report.validator_status, ValidatorStatus::BlockedEnv);
        assert!(!report.native_pass);
    }

    #[test]
    fn native_evidence_requires_all_digest_links() {
        let source = current_source_commit().expect("source commit");
        let mut acceptance = base_acceptance(&source, ProviderMode::Native);
        acceptance.receipt.result_digest = digest('7');
        let error = validate_acceptance(&acceptance, &source).expect_err("digest drift must fail");
        assert!(error.to_string().contains("result digest"));
    }

    #[test]
    fn lifecycle_requires_exact_five_unique_hooks() {
        let source = current_source_commit().expect("source commit");
        let mut acceptance = base_acceptance(&source, ProviderMode::Fixture);
        acceptance.lifecycle_proofs.pop();
        let error = validate_acceptance(&acceptance, &source).expect_err("missing hook must fail");
        assert!(
            error
                .to_string()
                .contains("rotation, revoke, unmount, crash and replay")
        );
    }

    #[test]
    fn strict_parser_rejects_duplicate_keys_and_nulls() {
        assert!(crate::model::parse_strict_json::<Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(crate::model::parse_strict_json::<Value>(br#"{"a":null}"#).is_err());
    }
}
