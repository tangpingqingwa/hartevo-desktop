//! Standalone Layer-1 governed Google Cloud Spanner database posture result.
//!
//! This crate owns only bounded, redacted management-plane evidence for one
//! exact instance, database, and optionally referenced long-running operation.
//! It is below Hartevo Truth, Consent, Effect, Receipt, Verification, Outcome,
//! and durable Work Product authority. OAuth/service-account resolution, live
//! HTTPS, provider receipts, and native adoption remain Layer 2.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::derivable_impls,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionGcpSpannerDatabaseConsumer, MissionGcpSpannerDatabaseConsumerError,
    MissionGcpSpannerDatabaseResult,
};
pub use error::{GcpSpannerError, GcpSpannerTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvGcpSpannerTransport, BlockedEnvTransport, FakeTransport, FixtureTransport,
    GcpSpannerAdminProvider, GcpSpannerFakeTransport, GcpSpannerFixtureTransport,
    GcpSpannerLoopbackTransport, GcpSpannerOperation, GcpSpannerProviderDefinition,
    GcpSpannerTransport, GetDatabaseRequest, GetDatabaseResponse, GetInstanceRequest,
    GetInstanceResponse, GetOperationRequest, GetOperationResponse, ListDatabasesRequest,
    ListDatabasesResponse, ListInstancesRequest, ListInstancesResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    CapabilityDescription, FailureEvidence, GcpSpannerDatabaseEvidenceState,
    GcpSpannerDatabaseResultEvidence, GcpSpannerDatabaseResultProposal,
    GcpSpannerDatabaseResultRegistration, GcpSpannerDatabaseResultService,
    GcpSpannerDatabaseResultServiceError, GcpSpannerIntegrityReport, GcpSpannerRecordReceipt,
    GcpSpannerRecordedResult, GcpSpannerRegistration, GcpSpannerRegistrationStatus,
    GcpSpannerService, RegistrationTransitionEvidence,
};

pub type GcpSpannerDatabaseResult = GcpSpannerDatabaseResultProposal;
pub type GcpSpannerEvidence = GcpSpannerDatabaseResultEvidence;
pub type GcpSpannerEvidenceState = GcpSpannerDatabaseEvidenceState;
pub type GcpSpannerProvider<T> = GcpSpannerAdminProvider<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.gcp-spanner-database-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-GCP-SPANNER-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "gcp.spanner.database.result";
pub const SERVICE_ID: &str = "gcp.spanner.database.result.read";
pub const PROVIDER_ID: &str = "gcp.spanner.admin";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const API_REVISION: &str = "spanner-instances-get-databases-get-operations-get-r1";
pub const CONSUMER_ID: &str = "mission.gcp-spanner-database.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.gcp-spanner-database-result/v1|layer=1|service=gcp.spanner.database.result.read|provider=gcp.spanner.admin|consumer=mission.gcp-spanner-database.consumer|api=spanner-instances-get-databases-get-operations-get-r1";
pub const CONTRACT_DIGEST: &str =
    "91ec46160031edcafbc6e8dae33d2f0dfebd92a43aab15d631a31f8def8d70ee";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 32;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "spanner.instances.get",
    "spanner.databases.get",
    "spanner.operations.get",
    "spanner.instances.list",
    "spanner.databases.list",
    "mission.scope",
];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-spanner-database-result/gcp-spanner-database-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpSpannerDatabaseResultContract {
    value: serde_json::Value,
}

impl GcpSpannerDatabaseResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| GcpSpannerError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(GcpSpannerError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(GcpSpannerError::ContractDrift);
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
            || contract_digest().as_str() != CONTRACT_DIGEST
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        if service.get("type").and_then(serde_json::Value::as_str)
            != Some("GcpSpannerDatabaseResultService")
            || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        if provider.get("type").and_then(serde_json::Value::as_str)
            != Some("GcpSpannerAdminProvider")
            || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        if consumer.get("type").and_then(serde_json::Value::as_str)
            != Some("MissionGcpSpannerDatabaseConsumer")
            || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("debugRedacted") != Some(&serde_json::Value::Bool(true))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        for key in ["connected", "native", "firstParty", "providerReceipt"] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(GcpSpannerError::ContractDrift);
            }
        }

        let evidence = object
            .get("evidence")
            .and_then(serde_json::Value::as_object)
            .ok_or(GcpSpannerError::ContractDrift)?;
        let expected_states = [
            "CREATING",
            "READY",
            "UPDATING",
            "RESTORING",
            "BACKING_UP",
            "FAILED",
            "PARTIAL",
            "ACCESS_LOST",
            "PROVIDER_UNKNOWN",
            "TAMPERED",
            "REVOKED",
        ];
        if evidence
            .get("states")
            .and_then(serde_json::Value::as_array)
            .is_none_or(|states| {
                states.len() != expected_states.len()
                    || states
                        .iter()
                        .zip(expected_states)
                        .any(|(actual, expected)| actual.as_str() != Some(expected))
            })
        {
            return Err(GcpSpannerError::ContractDrift);
        }

        let forbidden = object
            .get("forbiddenEffects")
            .and_then(serde_json::Value::as_array)
            .ok_or(GcpSpannerError::ContractDrift)?;
        for required in [
            "execute_sql",
            "create_session",
            "read_rows",
            "read_schema",
            "read_iam",
            "create_backup",
            "restore_backup",
            "scale_instance",
            "resolve_live_credentials",
            "adopt_kernel_outcome",
            "claim_provider_receipt",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(GcpSpannerError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn truth_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn consent_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn effect_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn verification_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_the_typed_layer_one_boundary() {
        let contract = GcpSpannerDatabaseResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::consent_authority());
        assert!(!Layer1Authority::effect_authority());
        assert!(!Layer1Authority::verification_authority());
        assert!(!Layer1Authority::outcome_authority());
    }
}
