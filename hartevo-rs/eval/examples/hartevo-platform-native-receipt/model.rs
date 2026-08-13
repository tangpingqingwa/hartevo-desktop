use std::fmt;

use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PlatformStatus {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
}

impl PlatformStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::NotImplemented => "NOT_IMPLEMENTED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ImplementationState {
    #[serde(rename = "IMPLEMENTED")]
    Implemented,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReceiptKind {
    #[serde(rename = "source_audit")]
    SourceAudit,
    #[serde(rename = "native_preflight")]
    NativePreflight,
    #[serde(rename = "native_execution")]
    NativeExecution,
}

impl ReceiptKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceAudit => "source_audit",
            Self::NativePreflight => "native_preflight",
            Self::NativeExecution => "native_execution",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceRequirement {
    #[serde(rename = "source_audit")]
    SourceAudit,
    #[serde(rename = "native_execution")]
    NativeExecution,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OperatingSystem {
    #[serde(rename = "macos")]
    Macos,
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "linux")]
    Linux,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Architecture {
    #[serde(rename = "aarch64")]
    Aarch64,
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SupportClass {
    #[serde(rename = "release")]
    Release,
    #[serde(rename = "compatibility")]
    Compatibility,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceMode {
    #[serde(rename = "source_audit_baseline")]
    SourceAuditBaseline,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum InventoryAuthority {
    #[serde(rename = "platform_inventory_only")]
    PlatformInventoryOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReleaseDecision {
    #[serde(rename = "NOT_EVALUATED")]
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MissingReceiptDisposition {
    #[serde(rename = "aggregate_failure")]
    AggregateFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NativeProducerMode {
    #[serde(rename = "contract_only_fail_closed")]
    ContractOnlyFailClosed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RegistryEmptyPolicy {
    #[serde(rename = "deny_all")]
    DenyAll,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CanonicalPayloadEncoding {
    #[serde(rename = "hartevo_sorted_json/v1")]
    HartevoSortedJsonV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SignaturePayloadProjection {
    #[serde(rename = "receipt_without_signature_and_runner_signature_evidence/v1")]
    ReceiptWithoutSignatureAndRunnerSignatureEvidenceV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReadinessClassification {
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum VirtualizationKind {
    #[serde(rename = "physical")]
    Physical,
    #[serde(rename = "virtual_machine")]
    VirtualMachine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformTarget {
    pub id: String,
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub support_class: SupportClass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBinding {
    pub path: String,
    pub mode: String,
    pub blob_sha256: String,
    pub byte_count: u64,
    pub locator: String,
    pub fact: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentBlocker {
    pub code: String,
    pub observation_source: String,
    pub exit_condition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatrixCase {
    pub case_id: String,
    pub target_id: String,
    pub capability_id: String,
    pub source_audit_disposition: PlatformStatus,
    pub implementation_state: ImplementationState,
    pub evidence_requirement: EvidenceRequirement,
    #[serde(default)]
    pub production_component: Option<String>,
    pub required_assertions: Vec<String>,
    pub allowed_blocker_codes: Vec<String>,
    #[serde(default)]
    pub current_blocker: Option<CurrentBlocker>,
    pub missing_gates: Vec<String>,
    pub source_bindings: Vec<SourceBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DispositionCounts {
    pub pass: usize,
    pub fail: usize,
    pub blocked_env: usize,
    pub not_implemented: usize,
}

impl DispositionCounts {
    pub const fn zero() -> Self {
        Self {
            pass: 0,
            fail: 0,
            blocked_env: 0,
            not_implemented: 0,
        }
    }

    pub fn increment(&mut self, status: PlatformStatus) {
        match status {
            PlatformStatus::Pass => self.pass += 1,
            PlatformStatus::Fail => self.fail += 1,
            PlatformStatus::BlockedEnv => self.blocked_env += 1,
            PlatformStatus::NotImplemented => self.not_implemented += 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptPolicy {
    pub pass_receipt_kind: ReceiptKind,
    pub fail_receipt_kind: ReceiptKind,
    pub blocked_env_receipt_kind: ReceiptKind,
    pub not_implemented_receipt_kind: ReceiptKind,
    pub native_target_must_match: bool,
    pub cleanup_required_for_native_execution: bool,
    pub missing_receipt_disposition: MissingReceiptDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NativeProducerPolicy {
    pub mode: NativeProducerMode,
    pub native_receipt_emission_allowed: bool,
    pub registry_empty_policy: RegistryEmptyPolicy,
    pub trusted_registry_required: bool,
    pub runner_signature_required: bool,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature_verifier_available: bool,
    pub host_attestation_verifier_available: bool,
    pub real_host_required: bool,
    pub content_free: bool,
    pub canonical_payload_encoding: CanonicalPayloadEncoding,
    pub signature_payload_projection: SignaturePayloadProjection,
    pub challenge_nonce_digest_required: bool,
    pub persistent_nonce_replay_guard_available: bool,
    pub max_challenge_age_seconds: u64,
    pub max_receipt_age_seconds: u64,
    pub max_run_duration_seconds: u64,
    pub signature_payload_domain: String,
    pub preflight_evidence_kinds: Vec<EvidenceReferenceKind>,
    pub execution_evidence_kinds: Vec<EvidenceReferenceKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessBlocker {
    pub code: String,
    pub classification: ReadinessClassification,
    pub observation_source: String,
    pub exit_condition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunnerRevocation {
    pub revoked_at: String,
    pub reason_code: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunnerRegistration {
    pub runner_id: String,
    pub runner_identity_digest: String,
    pub registry_epoch: u64,
    pub signing_key_digest: String,
    pub verification_key_hex: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub producer_binary_digest: String,
    pub valid_from: String,
    pub valid_until: String,
    pub allowed_receipt_kinds: Vec<ReceiptKind>,
    pub allowed_targets: Vec<String>,
    pub allowed_host_identity_digests: Vec<String>,
    pub allowed_challenge_issuer_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<RunnerRevocation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformMatrix {
    pub schema_version: String,
    pub matrix_version: String,
    pub repository_id: String,
    pub source_commit: String,
    pub receipt_schema_uri: String,
    pub receipt_schema_sha256: String,
    pub evidence_mode: EvidenceMode,
    pub release_eligible: bool,
    pub native_receipt_count: usize,
    pub native_producer_policy: NativeProducerPolicy,
    pub readiness_blockers: Vec<ReadinessBlocker>,
    pub source_audit_disposition_counts: DispositionCounts,
    pub receipt_policy: ReceiptPolicy,
    pub runner_registry_epoch: u64,
    pub runner_registry_digest: String,
    pub allowed_runners: Vec<RunnerRegistration>,
    pub prohibited_upgrade_evidence: Vec<String>,
    pub allowed_blocker_codes: Vec<String>,
    pub targets: Vec<PlatformTarget>,
    pub cases: Vec<MatrixCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetTuple {
    pub os: OperatingSystem,
    pub arch: Architecture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActualHost {
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub os_build_digest: String,
    pub host_identity_digest: String,
    pub virtualization: VirtualizationKind,
    pub observed_at: String,
    pub attestation_reference_id: String,
    pub attestation_digest: String,
}

impl From<&PlatformTarget> for TargetTuple {
    fn from(target: &PlatformTarget) -> Self {
        Self {
            os: target.os,
            arch: target.arch,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunnerBinding {
    pub runner_id: String,
    pub runner_identity_digest: String,
    pub registry_digest: String,
    pub registry_epoch: u64,
    pub signing_key_digest: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub producer_binary_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductionBinding {
    pub component: String,
    pub implementation_digest: String,
    pub executable_digest: String,
    pub build_manifest_digest: String,
    pub binary_attestation_reference_id: String,
    pub binary_attestation_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChallengeBinding {
    pub challenge_id: String,
    pub nonce_hex: String,
    pub nonce_digest: String,
    pub issuer_digest: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptSignature {
    pub algorithm: SignatureAlgorithm,
    pub key_digest: String,
    pub signed_payload_digest: String,
    pub signature_reference_id: String,
    pub signature_digest: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct EvidenceQualifiers {
    pub compile_only: bool,
    pub cross_compiled: bool,
    pub fake_host: bool,
    pub ignored_test: bool,
    pub mock_credential_store: bool,
    pub source_audit_only: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EvidenceReferenceKind {
    #[serde(rename = "source_binding_digest")]
    SourceBinding,
    #[serde(rename = "native_preflight_digest")]
    NativePreflight,
    #[serde(rename = "native_execution_digest")]
    NativeExecution,
    #[serde(rename = "host_attestation_digest")]
    HostAttestation,
    #[serde(rename = "codesign_attestation_digest")]
    CodesignAttestation,
    #[serde(rename = "cleanup_digest")]
    Cleanup,
    #[serde(rename = "producer_binary_digest")]
    ProducerBinary,
    #[serde(rename = "production_binary_digest")]
    ProductionBinary,
    #[serde(rename = "runner_signature_digest")]
    RunnerSignature,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReference {
    pub reference_id: String,
    pub kind: EvidenceReferenceKind,
    pub artifact_id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub artifact_id: String,
    pub kind: EvidenceReferenceKind,
    pub media_type: String,
    pub digest: String,
    pub byte_count: u64,
    pub produced_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AssertionOutcome {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "TIMEOUT")]
    Timeout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssertionEvidence {
    pub id: String,
    pub outcome: AssertionOutcome,
    pub evidence_reference_id: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CleanupEvidence {
    pub required: bool,
    pub attempted: bool,
    pub succeeded: bool,
    pub residue_count: u64,
    pub deadline_exceeded: bool,
    pub resource_kind: String,
    pub before_state_digest: String,
    pub after_state_digest: String,
    pub evidence_reference_id: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockerEvidence {
    pub code: String,
    pub observation_digest: String,
    pub evidence_reference_id: String,
    pub evidence_digest: String,
    pub exit_condition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PlatformReceipt {
    pub schema_version: String,
    pub matrix_version: String,
    pub source_commit: String,
    pub matrix_digest: String,
    pub case_definition_digest: String,
    pub receipt_id: String,
    pub run_id: String,
    pub attempt_ordinal: u64,
    pub case_id: String,
    pub target_id: String,
    pub target: TargetTuple,
    pub actual_host: ActualHost,
    pub status: PlatformStatus,
    pub receipt_kind: ReceiptKind,
    pub implementation_state: ImplementationState,
    pub authority: InventoryAuthority,
    pub native_calls: u64,
    pub release_decision: ReleaseDecision,
    pub test_mode: bool,
    pub mock: bool,
    pub started_at: String,
    pub completed_at: String,
    pub execution_started: bool,
    pub platform_touched: bool,
    pub runner_binding: RunnerBinding,
    pub challenge_binding: ChallengeBinding,
    pub production_binding: ProductionBinding,
    pub evidence_qualifiers: EvidenceQualifiers,
    pub artifacts: Vec<EvidenceArtifact>,
    pub evidence_references: Vec<EvidenceReference>,
    pub assertions: Vec<AssertionEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker: Option<BlockerEvidence>,
    pub signature: ReceiptSignature,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseDefinitionDigestMaterial<'a> {
    pub target: &'a PlatformTarget,
    pub case: &'a MatrixCase,
}

pub fn parse_strict_json<T: DeserializeOwned>(input: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)?;
    deserializer.end()?;
    serde_json::from_value(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys or null values")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("JSON null is forbidden"))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, StrictValue(value))) = map.next_entry::<String, StrictValue>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(de::Error::custom(format_args!(
                    "duplicate JSON object key: {key}"
                )));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_json;
    use serde_json::Value;

    #[test]
    fn strict_json_rejects_duplicate_keys() {
        let error = parse_strict_json::<Value>(br#"{"value":1,"value":2}"#)
            .expect_err("duplicate key must fail");
        assert!(error.to_string().contains("duplicate JSON object key"));
    }

    #[test]
    fn strict_json_rejects_null_at_any_depth() {
        let error = parse_strict_json::<Value>(br#"{"value":[null]}"#).expect_err("null must fail");
        assert!(error.to_string().contains("JSON null is forbidden"));
    }
}
