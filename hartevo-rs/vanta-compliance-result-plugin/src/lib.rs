//! Standalone Layer-1 Vanta compliance-audit result plugin.
//!
//! This crate exposes a bounded, read/proposal/recording-only seam for
//! Mission-scoped audit readiness. It deliberately has no native credential
//! authority, no Connected claim, no evidence upload or acceptance, no control
//! or policy mutation, no audit approval, and no compliance certification
//! authority.

#![forbid(unsafe_code)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionVantaComplianceConsumer, MissionVantaComplianceResult, MissionVantaDecisionState,
    VantaConsumerError,
};
pub use model::*;
pub use provider::{
    NativeProbe, NativeProbeStatus, VantaProvider, VantaProviderIdentity, VantaRateLimit,
    native_probe_from_environment,
};
pub use service::{
    VantaCapability, VantaComplianceResultService, VantaComplianceResultServiceOperation,
    VantaProposalRequest,
};
pub use transport::{
    BlockedEnvVantaTransport, FakeVantaTransport, FixtureVantaTransport, LoopbackVantaTransport,
    RecordingVantaTransport, VantaHttpRequest, VantaHttpResponse, VantaTransport,
    VantaTransportError,
};

pub const VANTA_SCHEMA_VERSION: &str = "hartevo.vanta-compliance-result.contract/v1";
pub const VANTA_CONTRACT_VERSION: &str = "vanta-compliance-result/v1";
pub const VANTA_PLUGIN_ID: &str = "vanta-compliance-result";
pub const VANTA_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const VANTA_SERVICE_ID: &str = "hartevo.vanta.compliance-result";
pub const VANTA_SERVICE_NAME: &str = "VantaComplianceResultService";
pub const VANTA_PROVIDER_ID: &str = "vanta.compliance-audit";
pub const VANTA_PROVIDER_NAME: &str = "VantaProvider";
pub const MISSION_VANTA_CONSUMER_ID: &str = "mission.vanta-compliance-result";
pub const MISSION_VANTA_CONSUMER_NAME: &str = "MissionVantaComplianceConsumer";
pub const VANTA_SERVICE_SCHEMA: &str = "hartevo.vanta-compliance-result-service/v1";
pub const VANTA_PROVIDER_SCHEMA: &str = "hartevo.vanta-provider/v1";
pub const MISSION_VANTA_CONSUMER_SCHEMA: &str = "hartevo.mission-vanta-compliance-result/v1";
pub const VANTA_PROVIDER_REVISION_TEXT: &str = "vanta-api-manage-audit-r1";
pub const VANTA_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const VANTA_MAX_PAGES: u16 = 4;
pub const VANTA_PAGE_SIZE: u16 = 50;
pub const VANTA_MAX_REQUESTS_PER_MINUTE: u8 = 5;
pub const VANTA_NATIVE_PROBE_ENV: &str = "HARTEVO_VANTA_NATIVE_PROBE";
pub const VANTA_NATIVE_PROBE_GATE: &str = "HARTEVO_VANTA_NATIVE_PROBE=1";

pub const VANTA_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/vanta-compliance-result/vanta-compliance-result.v1.json"
);

/// Errors shared by the service, provider, and Mission consumer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VantaComplianceResultError {
    #[error("Vanta compliance result input is invalid: {0}")]
    InvalidInput(String),
    #[error("Vanta compliance result contract is invalid: {0}")]
    Contract(String),
    #[error("Vanta compliance result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Vanta compliance result registration is revoked")]
    RegistrationRevoked,
    #[error("Vanta compliance result registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("Vanta compliance result secret reference is revoked")]
    SecretRevoked,
    #[error("Vanta compliance result proposal is stale or tampered")]
    StaleProposal,
    #[error("Vanta compliance result evidence is stale or tampered")]
    StaleEvidence,
    #[error("Vanta compliance result provider is not compatible")]
    ProviderMismatch,
    #[error(
        "Vanta compliance result provider rate limit exceeded: retry after {retry_after_seconds} seconds"
    )]
    RateLimited { retry_after_seconds: u64 },
    #[error("Vanta compliance result provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Vanta compliance result transport error: {0}")]
    Transport(#[from] transport::VantaTransportError),
    #[error("Vanta compliance result model error: {0}")]
    Model(#[from] model::VantaModelError),
    #[error("Vanta plugin runtime error: {0}")]
    Plugin(#[from] PluginError),
}

pub fn contract_digest() -> Digest {
    model::sha256_digest(VANTA_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build the runtime contribution descriptors for one exact Project/Mission
/// generation. Mounting remains a host-owned action outside this Layer-1
/// crate.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, VantaComplianceResultError> {
    let plugin_id = PluginId::new(VANTA_PLUGIN_ID)?;
    let service_id = ServiceId::new(VANTA_SERVICE_ID)?;
    let provider_id = ProviderId::new(VANTA_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_VANTA_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(VANTA_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(VANTA_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_VANTA_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

/// The checked-in JSON contract is intentionally validated by the crate so a
/// contract edit cannot silently drift from the typed Layer-1 implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VantaComplianceResultContract {
    value: Value,
}

impl VantaComplianceResultContract {
    pub fn baseline() -> Result<Self, VantaComplianceResultError> {
        let value = serde_json::from_str::<Value>(VANTA_CONTRACT_JSON)
            .map_err(|error| VantaComplianceResultError::Contract(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), VantaComplianceResultError> {
        let object = self.value.as_object().ok_or_else(|| {
            VantaComplianceResultError::Contract("contract is not an object".to_owned())
        })?;
        let required = [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "projections",
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ];
        if required.iter().any(|key| !object.contains_key(*key))
            || object.get("schemaVersion").and_then(Value::as_str) != Some(VANTA_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str) != Some(VANTA_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(VANTA_PLUGIN_VERSION_TEXT)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract top-level identity drifted".to_owned(),
            ));
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or_else(|| VantaComplianceResultError::Contract("service is missing".to_owned()))?;
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("provider is missing".to_owned())
            })?;
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("consumer is missing".to_owned())
            })?;
        if service.get("id").and_then(Value::as_str) != Some(VANTA_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str) != Some(VANTA_SERVICE_NAME)
            || provider.get("id").and_then(Value::as_str) != Some(VANTA_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str) != Some(VANTA_PROVIDER_NAME)
            || consumer.get("id").and_then(Value::as_str) != Some(MISSION_VANTA_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some(MISSION_VANTA_CONSUMER_NAME)
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract typed identities drifted".to_owned(),
            ));
        }
        let service_operations = service
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("service operations are missing".to_owned())
            })?;
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded_status",
            "compile_readiness_proposal",
            "record_proposal",
        ];
        if service.get("version").and_then(Value::as_str) != Some(VANTA_PLUGIN_VERSION_TEXT)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || service_operations.len() != expected_operations.len()
            || service_operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract service seam drifted".to_owned(),
            ));
        }
        let provider_methods = provider
            .get("allowlistedMethods")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("provider methods are missing".to_owned())
            })?;
        let provider_reads = provider
            .get("allowlistedReads")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("provider reads are missing".to_owned())
            })?;
        let expected_reads = [
            "list_audits",
            "list_controls",
            "list_tests",
            "list_issues",
            "list_information_requests",
        ];
        if provider.get("version").and_then(Value::as_str) != Some(VANTA_PLUGIN_VERSION_TEXT)
            || provider_methods.len() != 1
            || provider_methods[0].as_str() != Some("GET")
            || provider_reads.len() != expected_reads.len()
            || provider_reads
                .iter()
                .zip(expected_reads)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract provider seam drifted".to_owned(),
            ));
        }
        if consumer.get("version").and_then(Value::as_str) != Some(VANTA_PLUGIN_VERSION_TEXT)
            || consumer.get("missionBound") != Some(&Value::Bool(true))
            || consumer.get("projectBound") != Some(&Value::Bool(true))
            || consumer.get("consentBound") != Some(&Value::Bool(true))
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&Value::Bool(false))
            || consumer.get("certificationAuthority") != Some(&Value::Bool(false))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract consumer seam drifted".to_owned(),
            ));
        }
        let scope = object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or_else(|| VantaComplianceResultError::Contract("scope is missing".to_owned()))?;
        let required_scope_fields = [
            "tenant",
            "region",
            "api_family",
            "audit_id_and_revision",
            "framework_id",
            "allowlisted_control_ids",
            "control_revision_fences",
            "allowlisted_test_ids",
            "test_revision_fences",
            "allowlisted_issue_ids",
            "issue_revision_fences",
            "allowlisted_information_request_ids",
            "information_request_revision_fences",
            "compliance_objective_id_and_revision",
            "mission_id_and_revision",
            "project_id_and_revision",
            "consent_id_and_revision",
            "permission_digest",
            "scope_digest",
        ];
        let scope_required = scope
            .get("required")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("scope requirements are missing".to_owned())
            })?;
        if scope.get("secret").and_then(Value::as_str) != Some("opaque_secret_reference_only")
            || required_scope_fields.iter().any(|field| {
                !scope_required
                    .iter()
                    .any(|value| value.as_str() == Some(field))
            })
            || [
                "tenantBound",
                "auditBound",
                "frameworkBound",
                "missionBound",
                "projectBound",
                "consentBound",
            ]
            .iter()
            .any(|key| scope.get(*key) != Some(&Value::Bool(true)))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract scope seam drifted".to_owned(),
            ));
        }
        let registration = object
            .get("registration")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("registration is missing".to_owned())
            })?;
        if [
            "versionBound",
            "contractDigestBound",
            "providerDigestBound",
            "auditDigestBound",
            "scopeDigestBound",
            "permissionDigestBound",
            "consentDigestBound",
            "secretReferenceDigestBound",
            "reversible",
            "revocable",
        ]
        .iter()
        .any(|key| registration.get(*key) != Some(&Value::Bool(true)))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract registration fences drifted".to_owned(),
            ));
        }
        let bounds = object
            .get("bounds")
            .and_then(Value::as_object)
            .ok_or_else(|| VantaComplianceResultError::Contract("bounds are missing".to_owned()))?;
        if bounds.get("maxResponseBytes").and_then(Value::as_u64)
            != Some(VANTA_MAX_RESPONSE_BYTES as u64)
            || bounds.get("maxPages").and_then(Value::as_u64) != Some(u64::from(VANTA_MAX_PAGES))
            || bounds.get("pageSize").and_then(Value::as_u64) != Some(u64::from(VANTA_PAGE_SIZE))
            || bounds.get("maxRequestsPerMinute").and_then(Value::as_u64)
                != Some(u64::from(VANTA_MAX_REQUESTS_PER_MINUTE))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract bounds drifted".to_owned(),
            ));
        }
        let authority = object
            .get("authority")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("authority is missing".to_owned())
            })?;
        let redaction = object
            .get("redaction")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                VantaComplianceResultError::Contract("redaction is missing".to_owned())
            })?;
        let honesty = object
            .get("honesty")
            .and_then(Value::as_object)
            .ok_or_else(|| VantaComplianceResultError::Contract("honesty is missing".to_owned()))?;
        let all_false = [
            "externalWrites",
            "evidenceUpload",
            "informationRequestAcceptance",
            "controlOrPolicyMutation",
            "auditApproval",
            "mcp",
            "certification",
            "dashboard",
            "connected",
            "native",
            "durableReceipt",
            "verification",
            "kernelOutcomeAdoption",
        ];
        if authority.get("readOnly") != Some(&Value::Bool(true))
            || authority.get("proposalOnly") != Some(&Value::Bool(true))
            || all_false
                .iter()
                .any(|key| authority.get(*key) != Some(&Value::Bool(false)))
            || [
                "owners",
                "evidenceUrls",
                "comments",
                "documentBodies",
                "rawProviderPayload",
                "credentialMaterial",
            ]
            .iter()
            .any(|key| redaction.get(*key) != Some(&Value::Bool(false)))
            || honesty.get("nativeStatus").and_then(Value::as_str) != Some("BLOCKED_ENV")
            || honesty.get("blockedEnvironmentIsNative") != Some(&Value::Bool(false))
            || honesty.get("absenceOfIssuesIsCertification") != Some(&Value::Bool(false))
        {
            return Err(VantaComplianceResultError::Contract(
                "Vanta contract authority/redaction/honesty boundary drifted".to_owned(),
            ));
        }
        Ok(())
    }
}
