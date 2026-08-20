//! Standalone Layer-1 SailPoint Identity Security Cloud certification result
//! plugin.
//!
//! This crate is a bounded read/proposal/record/verify seam. It never resolves
//! PAT/OAuth material, sends a decision write, submits an access request,
//! mutates an identity or entitlement, exposes reviewer PII or raw access
//! descriptions, claims Connected/native evidence, or adopts kernel Consent
//! and Outcome authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
#![allow(clippy::large_enum_variant)]

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
    MissionSailPointCertificationConsumer, SailPointCertificationAdoptionProposal,
    SailPointConsumerError,
};
pub use model::*;
pub use provider::{
    NativeProbe, NativeProbeStatus, SailPointProvider, SailPointProviderDefinition,
    SailPointProviderError, native_probe_from_environment,
};
pub use service::{
    SailPointCapability, SailPointCertificationService, SailPointEvidenceProposalRequest,
    SailPointServiceOperation,
};
pub use transport::{
    BlockedEnvSailPointTransport, FixtureSailPointTransport, LoopbackSailPointTransport,
    RecordingSailPointTransport, SailPointTransport, SailPointTransportError, response_from_json,
};

pub const SAILPOINT_SCHEMA_VERSION: &str = "hartevo.sailpoint-certification-result.contract/v1";
pub const SAILPOINT_CONTRACT_VERSION: &str = "sailpoint-certification-result/v1";
pub const SAILPOINT_PLUGIN_ID: &str = "sailpoint-certification-result";
pub const SAILPOINT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const SAILPOINT_SERVICE_ID: &str = "hartevo.sailpoint.certification";
pub const SAILPOINT_SERVICE_IMPLEMENTATION: &str = "SailPointCertificationService";
pub const SAILPOINT_PROVIDER_ID: &str = "sailpoint.identity-security-cloud";
pub const SAILPOINT_PROVIDER_IMPLEMENTATION: &str = "SailPointProvider";
pub const MISSION_SAILPOINT_CONSUMER_ID: &str = "mission.sailpoint-certification-result";
pub const MISSION_SAILPOINT_CONSUMER_IMPLEMENTATION: &str = "MissionSailPointCertificationConsumer";
pub const SAILPOINT_API_VERSION: &str = "v3";
pub const SAILPOINT_PROVIDER_REVISION_TEXT: &str = "sailpoint-isc-v3-r1";
pub const SAILPOINT_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const SAILPOINT_MAX_IDENTIFIER_BYTES: usize = 128;
pub const SAILPOINT_MAX_LIMIT: u32 = 250;
pub const SAILPOINT_MAX_OFFSET: u32 = 10_000;
pub const SAILPOINT_MAX_PAGES: u16 = 4;
pub const SAILPOINT_MAX_REQUESTS_PER_MINUTE: u8 = 5;
pub const SAILPOINT_NATIVE_PROBE_ENV: &str = "HARTEVO_SAILPOINT_NATIVE_PROBE";
pub const SAILPOINT_NATIVE_PROBE_GATE: &str = "HARTEVO_SAILPOINT_NATIVE_PROBE=1";

pub const SAILPOINT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/sailpoint-certification-result/sailpoint-certification-result.v1.json"
);

/// Errors shared by the service, provider, and Mission consumer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SailPointCertificationResultError {
    #[error("SailPoint certification result input is invalid: {0}")]
    InvalidInput(String),
    #[error("SailPoint certification result contract is invalid: {0}")]
    Contract(String),
    #[error("SailPoint certification result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("SailPoint certification result registration is revoked")]
    RegistrationRevoked,
    #[error("SailPoint certification result registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("SailPoint certification result secret reference is revoked")]
    SecretRevoked,
    #[error("SailPoint certification result proposal is stale or tampered")]
    StaleProposal,
    #[error("SailPoint certification result evidence is stale or tampered")]
    StaleEvidence,
    #[error("SailPoint certification result provider is not compatible")]
    ProviderMismatch,
    #[error(
        "SailPoint certification result provider rate limit exceeded: retry after {retry_after_seconds} seconds"
    )]
    RateLimited { retry_after_seconds: u64 },
    #[error("SailPoint certification result provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("SailPoint certification result provider access was lost")]
    AccessLost,
    #[error("SailPoint certification result campaign revision is stale")]
    StaleCampaignRevision,
    #[error("SailPoint certification result entitlement revision is stale")]
    StaleEntitlementRevision,
    #[error("SailPoint certification result contains a duplicate immutable identifier")]
    DuplicateIdentifier,
    #[error("SailPoint certification result response was tampered")]
    ResponseTampered,
    #[error("SailPoint certification result pagination drifted")]
    PaginationDrift,
    #[error("SailPoint certification result provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("SailPoint certification result provider error: {0}")]
    Provider(String),
    #[error("SailPoint certification result transport error: {0}")]
    Transport(#[from] SailPointTransportError),
    #[error("SailPoint certification result model error: {0}")]
    Model(#[from] SailPointModelError),
    #[error("Hartevo plugin runtime error: {0}")]
    Plugin(#[from] PluginError),
}

pub fn contract_digest() -> Digest {
    sha256_digest(SAILPOINT_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build runtime contribution descriptors for one exact Project/Mission
/// generation. Mounting remains host-owned and outside Layer 1.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, SailPointCertificationResultError> {
    let plugin_id = PluginId::new(SAILPOINT_PLUGIN_ID)?;
    let service_id = ServiceId::new(SAILPOINT_SERVICE_ID)?;
    let provider_id = ProviderId::new(SAILPOINT_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_SAILPOINT_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text("hartevo.sailpoint-certification-service/v1"),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text("hartevo.sailpoint-provider/v1"),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text("hartevo.mission-sailpoint-certification-result/v1"),
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

/// Checked-in contract parsed and checked against the typed implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SailPointCertificationContract {
    value: Value,
}

impl SailPointCertificationContract {
    pub fn baseline() -> Result<Self, SailPointCertificationResultError> {
        let value = serde_json::from_str::<Value>(SAILPOINT_CONTRACT_JSON)
            .map_err(|error| SailPointCertificationResultError::Contract(error.to_string()))?;
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
    pub fn validate(&self) -> Result<(), SailPointCertificationResultError> {
        let object = self.value.as_object().ok_or_else(|| {
            SailPointCertificationResultError::Contract("contract is not an object".to_owned())
        })?;
        for key in [
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
            "evidence",
            "projections",
            "authority",
            "redaction",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(SailPointCertificationResultError::Contract(format!(
                    "missing top-level field {key}"
                )));
            }
        }
        if object.get("schemaVersion").and_then(Value::as_str) != Some(SAILPOINT_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(SAILPOINT_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(SAILPOINT_PLUGIN_VERSION_TEXT)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(SailPointCertificationResultError::Contract(
                "top-level identity drifted".to_owned(),
            ));
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("service missing".to_owned())
            })?;
        if service.get("id").and_then(Value::as_str) != Some(SAILPOINT_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str)
                != Some(SAILPOINT_SERVICE_IMPLEMENTATION)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
        {
            return Err(SailPointCertificationResultError::Contract(
                "service authority drifted".to_owned(),
            ));
        }
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("provider missing".to_owned())
            })?;
        if provider.get("id").and_then(Value::as_str) != Some(SAILPOINT_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some(SAILPOINT_PROVIDER_IMPLEMENTATION)
            || provider.get("apiVersion").and_then(Value::as_str) != Some(SAILPOINT_API_VERSION)
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
            || provider.get("decisionWrites") != Some(&Value::Bool(false))
        {
            return Err(SailPointCertificationResultError::Contract(
                "provider authority drifted".to_owned(),
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("consumer missing".to_owned())
            })?;
        if consumer.get("id").and_then(Value::as_str) != Some(MISSION_SAILPOINT_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some(MISSION_SAILPOINT_CONSUMER_IMPLEMENTATION)
            || consumer.get("adoptsOutcome") != Some(&Value::Bool(false))
            || consumer.get("consentAuthority") != Some(&Value::Bool(false))
        {
            return Err(SailPointCertificationResultError::Contract(
                "consumer authority drifted".to_owned(),
            ));
        }
        let access_types = provider
            .get("accessTypes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("accessTypes missing".to_owned())
            })?;
        let expected_access_types = ["ROLE", "ACCESS_PROFILE", "ENTITLEMENT"]
            .into_iter()
            .map(Value::from)
            .collect::<Vec<_>>();
        if *access_types != expected_access_types {
            return Err(SailPointCertificationResultError::Contract(
                "access type set drifted".to_owned(),
            ));
        }
        let bounds = object
            .get("bounds")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("bounds missing".to_owned())
            })?;
        if bounds.get("maxResponseBytes").and_then(Value::as_u64)
            != Some(SAILPOINT_MAX_RESPONSE_BYTES as u64)
            || bounds.get("maxLimit").and_then(Value::as_u64)
                != Some(u64::from(SAILPOINT_MAX_LIMIT))
            || bounds.get("maxOffset").and_then(Value::as_u64)
                != Some(u64::from(SAILPOINT_MAX_OFFSET))
            || bounds.get("maxPages").and_then(Value::as_u64)
                != Some(u64::from(SAILPOINT_MAX_PAGES))
            || bounds.get("maxRequestsPerMinute").and_then(Value::as_u64)
                != Some(u64::from(SAILPOINT_MAX_REQUESTS_PER_MINUTE))
        {
            return Err(SailPointCertificationResultError::Contract(
                "pagination or response bounds drifted".to_owned(),
            ));
        }
        let authority = object
            .get("authority")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                SailPointCertificationResultError::Contract("authority missing".to_owned())
            })?;
        for key in [
            "certificationApproval",
            "certificationRevocation",
            "certificationFinalization",
            "accessRequestSubmission",
            "identityMutation",
            "entitlementMutation",
            "externalWrites",
            "accessSafety",
            "consentAuthority",
            "connected",
            "native",
        ] {
            if authority.get(key) != Some(&Value::Bool(false)) {
                return Err(SailPointCertificationResultError::Contract(format!(
                    "authority field {key} is not fail-closed"
                )));
            }
        }
        if object
            .get("honesty")
            .and_then(Value::as_object)
            .and_then(|value| value.get("nativeStatus"))
            .and_then(Value::as_str)
            != Some("BLOCKED_ENV")
        {
            return Err(SailPointCertificationResultError::Contract(
                "native honesty status drifted".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn contract_bounds_tripwire() -> bool {
    SailPointCertificationContract::baseline().is_ok()
}
