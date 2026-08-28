//! Standalone Layer-1 OneTrust consent-evidence result plugin.
//!
//! The crate exposes a typed, bounded read/proposal/record/verify seam. It
//! never creates or changes consent, never stores raw subject identifiers or
//! JWTs, and never claims native, Connected, first-party, or kernel authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

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
    MissionConsentDecision, MissionOneTrustConsentConsumer, OneTrustConsentAdoptionProposal,
    OneTrustConsumerError,
};
pub use model::*;
pub use provider::{
    NativeProbe, NativeProbeStatus, OneTrustConsentProvider, OneTrustProviderDefinition,
    OneTrustProviderError, native_probe_from_environment,
};
pub use service::{
    OneTrustCapability, OneTrustConsentEvidenceService, OneTrustEvidenceProposalRequest,
    OneTrustServiceOperation,
};
pub use transport::{
    BlockedEnvOneTrustTransport, FixtureOneTrustTransport, LoopbackOneTrustTransport,
    OneTrustTransport, OneTrustTransportError, RecordingOneTrustTransport,
};

pub const ONETRUST_SCHEMA_VERSION: &str = "hartevo.onetrust-consent-result.contract/v1";
pub const ONETRUST_CONTRACT_VERSION: &str = "onetrust-consent-result/v1";
pub const ONETRUST_PLUGIN_ID: &str = "onetrust-consent-result";
pub const ONETRUST_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const ONETRUST_SERVICE_ID: &str = "hartevo.onetrust.consent-evidence";
pub const ONETRUST_SERVICE_NAME: &str = "OneTrustConsentEvidenceService";
pub const ONETRUST_PROVIDER_ID: &str = "onetrust.consent";
pub const ONETRUST_PROVIDER_NAME: &str = "OneTrustConsentProvider";
pub const MISSION_ONETRUST_CONSUMER_ID: &str = "mission.onetrust-consent-result";
pub const MISSION_ONETRUST_CONSUMER_NAME: &str = "MissionOneTrustConsentConsumer";
pub const ONETRUST_SERVICE_SCHEMA: &str = "hartevo.onetrust-consent-evidence-service/v1";
pub const ONETRUST_PROVIDER_SCHEMA: &str = "hartevo.onetrust-consent-provider/v1";
pub const MISSION_ONETRUST_CONSUMER_SCHEMA: &str = "hartevo.mission-onetrust-consent-result/v1";
pub const ONETRUST_PROVIDER_REVISION_TEXT: &str = "onetrust-consent-v4-r1";
pub const ONETRUST_MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const ONETRUST_MAX_PAGES: u16 = 4;
pub const ONETRUST_PAGE_SIZE: u16 = 50;
pub const ONETRUST_MAX_REQUESTS_PER_MINUTE: u8 = 5;
pub const ONETRUST_MAX_RECORDING_REPLAY_KEYS: usize = 256;
pub const ONETRUST_MAX_CONSENT_WINDOW_HOURS: i64 = 24;
pub const ONETRUST_CONSENT_WINDOW_HOURS: i64 = ONETRUST_MAX_CONSENT_WINDOW_HOURS;
pub const ONETRUST_MAX_OBSERVATIONS: usize = 256;
pub const ONETRUST_NATIVE_PROBE_ENV: &str = "HARTEVO_ONETRUST_NATIVE_PROBE";
pub const ONETRUST_NATIVE_PROBE_GATE: &str = "HARTEVO_ONETRUST_NATIVE_PROBE=1";

pub const ONETRUST_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/onetrust-consent-result/onetrust-consent-result.v1.json"
);

/// Errors shared by the service, provider, and Mission consumer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OneTrustConsentResultError {
    #[error("OneTrust consent result input is invalid: {0}")]
    InvalidInput(String),
    #[error("OneTrust consent result contract is invalid: {0}")]
    Contract(String),
    #[error("OneTrust consent result scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("OneTrust consent result registration is revoked")]
    RegistrationRevoked,
    #[error("OneTrust consent result registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("OneTrust consent result secret reference is revoked")]
    SecretRevoked,
    #[error("OneTrust consent result proposal is stale or tampered")]
    StaleProposal,
    #[error("OneTrust consent result evidence is stale or tampered")]
    StaleEvidence,
    #[error("OneTrust consent result recording replay or resealing was rejected")]
    RecordingReplay,
    #[error("OneTrust consent result provider is not compatible")]
    ProviderMismatch,
    #[error(
        "OneTrust consent result provider rate limit exceeded: retry after {retry_after_seconds} seconds"
    )]
    RateLimited { retry_after_seconds: u64 },
    #[error("OneTrust consent result provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("OneTrust consent result provider error: {0}")]
    Provider(String),
    #[error("OneTrust consent result transport error: {0}")]
    Transport(#[from] transport::OneTrustTransportError),
    #[error("OneTrust consent result model error: {0}")]
    Model(#[from] model::OneTrustModelError),
    #[error("Hartevo plugin runtime error: {0}")]
    Plugin(#[from] PluginError),
}

pub fn contract_digest() -> Digest {
    model::sha256_digest(ONETRUST_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

/// Build runtime contribution descriptors for one exact Project/Mission
/// generation. Mounting remains a host-owned action outside Layer 1.
pub fn plugin_definition(
    scope: PluginScope,
) -> Result<PluginDefinition, OneTrustConsentResultError> {
    let plugin_id = PluginId::new(ONETRUST_PLUGIN_ID)?;
    let service_id = ServiceId::new(ONETRUST_SERVICE_ID)?;
    let provider_id = ProviderId::new(ONETRUST_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_ONETRUST_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(ONETRUST_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(ONETRUST_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(MISSION_ONETRUST_CONSUMER_SCHEMA),
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

/// The checked-in JSON contract is parsed and checked against the typed
/// implementation so a contract edit cannot silently change the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneTrustConsentResultContract {
    value: Value,
}

impl OneTrustConsentResultContract {
    pub fn baseline() -> Result<Self, OneTrustConsentResultError> {
        let value = serde_json::from_str::<Value>(ONETRUST_CONTRACT_JSON)
            .map_err(|error| OneTrustConsentResultError::Contract(error.to_string()))?;
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
    pub fn validate(&self) -> Result<(), OneTrustConsentResultError> {
        let object = self.value.as_object().ok_or_else(|| {
            OneTrustConsentResultError::Contract("contract is not an object".to_owned())
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
            "recording",
            "bounds",
            "evidence",
            "projections",
            "authority",
            "redaction",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ];
        if required.iter().any(|key| !object.contains_key(*key))
            || object.get("schemaVersion").and_then(Value::as_str) != Some(ONETRUST_SCHEMA_VERSION)
            || object.get("contractVersion").and_then(Value::as_str)
                != Some(ONETRUST_CONTRACT_VERSION)
            || object.get("pluginVersion").and_then(Value::as_str)
                != Some(ONETRUST_PLUGIN_VERSION_TEXT)
            || object.get("layer").and_then(Value::as_str) != Some("Layer-1")
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust contract top-level identity drifted".to_owned(),
            ));
        }
        let service = object
            .get("service")
            .and_then(Value::as_object)
            .ok_or_else(|| OneTrustConsentResultError::Contract("service is missing".to_owned()))?;
        let provider = object
            .get("provider")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("provider is missing".to_owned())
            })?;
        let consumer = object
            .get("consumer")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("consumer is missing".to_owned())
            })?;
        if service.get("id").and_then(Value::as_str) != Some(ONETRUST_SERVICE_ID)
            || service.get("implementation").and_then(Value::as_str) != Some(ONETRUST_SERVICE_NAME)
            || service.get("version").and_then(Value::as_str) != Some(ONETRUST_PLUGIN_VERSION_TEXT)
            || service.get("readOnly") != Some(&Value::Bool(true))
            || service.get("proposalOnly") != Some(&Value::Bool(true))
            || service.get("liveExecution") != Some(&Value::Bool(false))
            || provider.get("id").and_then(Value::as_str) != Some(ONETRUST_PROVIDER_ID)
            || provider.get("implementation").and_then(Value::as_str)
                != Some(ONETRUST_PROVIDER_NAME)
            || provider.get("version").and_then(Value::as_str) != Some(ONETRUST_PLUGIN_VERSION_TEXT)
            || consumer.get("id").and_then(Value::as_str) != Some(MISSION_ONETRUST_CONSUMER_ID)
            || consumer.get("implementation").and_then(Value::as_str)
                != Some(MISSION_ONETRUST_CONSUMER_NAME)
            || consumer.get("version").and_then(Value::as_str) != Some(ONETRUST_PLUGIN_VERSION_TEXT)
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust contract typed identities drifted".to_owned(),
            ));
        }
        let operations = service
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("service operations are missing".to_owned())
            })?;
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "read_bounded_consent_evidence",
            "compile_evidence_proposal",
            "record_proposal",
            "verify_proposal",
        ];
        if operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust service operations drifted".to_owned(),
            ));
        }
        let reads = provider
            .get("allowlistedReads")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("provider reads are missing".to_owned())
            })?;
        let expected_reads = [
            "get_datasubject_details_v4",
            "get_realtime_preferences_v2",
            "get_transactions_v2",
        ];
        if reads.len() != expected_reads.len()
            || reads
                .iter()
                .zip(expected_reads)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
            || provider.get("native") != Some(&Value::Bool(false))
            || provider.get("connected") != Some(&Value::Bool(false))
            || provider.get("externalWrites") != Some(&Value::Bool(false))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust provider read boundary drifted".to_owned(),
            ));
        }
        for (key, value) in [
            ("missionBound", true),
            ("projectBound", true),
            ("consentBound", true),
            ("workProductBound", true),
            ("adoptsOutcome", false),
            ("truthAuthority", false),
            ("consentAuthority", false),
            ("effectAuthority", false),
        ] {
            if consumer.get(key) != Some(&Value::Bool(value)) {
                return Err(OneTrustConsentResultError::Contract(format!(
                    "consumer field {key} drifted"
                )));
            }
        }
        let scope = object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or_else(|| OneTrustConsentResultError::Contract("scope is missing".to_owned()))?;
        let scope_required = scope
            .get("required")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("scope requirements are missing".to_owned())
            })?;
        let expected_scope = [
            "tenant",
            "region",
            "purposeId",
            "purposeVersion",
            "collectionPoint",
            "consentWindow",
            "subjectReferenceHash",
            "policyRevision",
            "missionIdAndRevision",
            "projectIdAndRevision",
            "consentIdAndRevision",
            "workProductIdAndRevision",
            "permissionDigest",
            "scopeDigest",
        ];
        if scope.get("secret").and_then(Value::as_str) != Some("opaque_secret_reference_only")
            || scope.get("subject").and_then(Value::as_str)
                != Some("scope_bound_salted_opaque_hash_only")
            || expected_scope.iter().any(|field| {
                !scope_required
                    .iter()
                    .any(|value| value.as_str() == Some(*field))
            })
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust scope or subject fence drifted".to_owned(),
            ));
        }
        let registration = object
            .get("registration")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("registration is missing".to_owned())
            })?;
        let registration_flags = [
            "versionBound",
            "contractDigestBound",
            "providerIdBound",
            "providerImplementationBound",
            "providerVersionBound",
            "providerRevisionBound",
            "providerDigestBound",
            "provenanceBound",
            "scopeDigestBound",
            "permissionDigestBound",
            "missionRevisionBound",
            "projectRevisionBound",
            "consentRevisionBound",
            "workProductRevisionBound",
            "evidenceDigestBound",
            "sharedLiveRevocationFence",
            "reversible",
            "revocable",
        ];
        if registration_flags
            .iter()
            .any(|key| registration.get(*key) != Some(&Value::Bool(true)))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust registration fences drifted".to_owned(),
            ));
        }
        let bounds = object
            .get("bounds")
            .and_then(Value::as_object)
            .ok_or_else(|| OneTrustConsentResultError::Contract("bounds are missing".to_owned()))?;
        if bounds.get("maxResponseBytes").and_then(Value::as_u64)
            != Some(ONETRUST_MAX_RESPONSE_BYTES as u64)
            || bounds.get("maxPages").and_then(Value::as_u64) != Some(u64::from(ONETRUST_MAX_PAGES))
            || bounds.get("pageSize").and_then(Value::as_u64) != Some(u64::from(ONETRUST_PAGE_SIZE))
            || bounds.get("maxRequestsPerMinute").and_then(Value::as_u64)
                != Some(u64::from(ONETRUST_MAX_REQUESTS_PER_MINUTE))
            || bounds.get("maxConsentWindowHours").and_then(Value::as_i64)
                != Some(ONETRUST_MAX_CONSENT_WINDOW_HOURS)
            || bounds.get("maxObservations").and_then(Value::as_u64)
                != Some(ONETRUST_MAX_OBSERVATIONS as u64)
            || bounds.get("maxRecordingReplayKeys").and_then(Value::as_u64)
                != Some(crate::ONETRUST_MAX_RECORDING_REPLAY_KEYS as u64)
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust bounds drifted".to_owned(),
            ));
        }
        let evidence = object
            .get("evidence")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("evidence boundary is missing".to_owned())
            })?;
        let evidence_flags = [
            "rawPreferencePayload",
            "rawSubjectIdentifier",
            "rawJwt",
            "rawPii",
        ];
        if evidence_flags
            .iter()
            .any(|key| evidence.get(*key) != Some(&Value::Bool(false)))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust evidence redaction boundary drifted".to_owned(),
            ));
        }
        let authority = object
            .get("authority")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("authority boundary is missing".to_owned())
            })?;
        let authority_flags = [
            "consentReceiptCreation",
            "consentWithdrawal",
            "preferenceUpdate",
            "preferenceCenterWrite",
            "dataSubjectMutation",
            "externalWrites",
            "effect",
            "receipt",
            "verification",
            "truth",
            "outcome",
            "workProductAdoption",
            "connected",
            "native",
        ];
        if authority.get("readOnly") != Some(&Value::Bool(true))
            || authority.get("proposalOnly") != Some(&Value::Bool(true))
            || authority_flags
                .iter()
                .any(|key| authority.get(*key) != Some(&Value::Bool(false)))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust authority boundary drifted".to_owned(),
            ));
        }
        let projections = object
            .get("projections")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("projections are missing".to_owned())
            })?;
        if projections.get("failClosed") != Some(&Value::Bool(true))
            || projections.get("adopted") != Some(&Value::Bool(false))
            || projections.get("kernelAuthority") != Some(&Value::Bool(false))
            || projections.get("partial") != Some(&Value::Bool(true))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust projection boundary drifted".to_owned(),
            ));
        }
        let honesty = object
            .get("honesty")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("honesty boundary is missing".to_owned())
            })?;
        if honesty.get("nativeStatus").and_then(Value::as_str) != Some("BLOCKED_ENV")
            || [
                "blockedEnvironmentIsNative",
                "fixtureIsNative",
                "recordingIsNative",
                "loopbackIsNative",
                "connectedClaim",
                "firstPartyEvidenceClaim",
            ]
            .iter()
            .any(|key| honesty.get(*key) != Some(&Value::Bool(false)))
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust honesty boundary drifted".to_owned(),
            ));
        }
        let recording = object
            .get("recording")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                OneTrustConsentResultError::Contract("recording fence is missing".to_owned())
            })?;
        if recording.get("replayFence").and_then(Value::as_str)
            != Some("registration_request_proposal_receipt_mission_tuple")
            || recording.get("duplicateReplay").and_then(Value::as_str) != Some("reject")
            || recording.get("resealedReplay").and_then(Value::as_str) != Some("reject")
            || recording.get("maxReplayKeys").and_then(Value::as_u64)
                != Some(crate::ONETRUST_MAX_RECORDING_REPLAY_KEYS as u64)
            || recording.get("stateDurability").and_then(Value::as_str)
                != Some("process_lifecycle_bounded_not_restart_durable")
        {
            return Err(OneTrustConsentResultError::Contract(
                "OneTrust recording replay fence drifted".to_owned(),
            ));
        }
        Ok(())
    }
}
