//! Standalone Layer-1 governed Azure Container Apps revision result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded app/revision/list metadata, digest fences, reversible registration,
//! and Mission-scoped review-only proposal/recording seams.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAzureContainerAppsRevisionConsumer, MissionAzureContainerAppsRevisionResult,
    ProposalDisposition, RecordedAzureContainerAppsRevisionResult,
};
pub use error::{AzureContainerAppsRevisionResultError, AzureContainerAppsTransportError, Result};
pub use model::*;
pub use provider::{
    AzureContainerAppsOperation, AzureContainerAppsProvider, AzureContainerAppsProviderDefinition,
    AzureContainerAppsTransport, BlockedEnvTransport, Cursor, FakeTransport, FixtureTransport,
    GetAppRequest, GetAppResponse, GetContainerAppRequest, GetContainerAppResponse,
    GetRevisionRequest, GetRevisionResponse, ListRevisionRequest, ListRevisionResponse,
    ListRevisionsRequest, ListRevisionsResponse, LoopbackTransport, OpaquePageToken,
    RecordedRequest, RecordingTransport, TransportResult,
};
pub use service::{
    AzureContainerAppsRevisionEvidenceRequest, AzureContainerAppsRevisionProposal,
    AzureContainerAppsRevisionRegistration, AzureContainerAppsRevisionResultService,
    CapabilityDescription, LocalIntegrityFailure, LocalIntegrityReport, RegistrationStatus,
    RegistrationTransitionEvidence,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.azure-container-apps-revision-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AZURE-CONTAINER-APPS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.azure-container-apps-revision-result/v1|layer=1|service=azure.container-apps.revision.result.read|provider=azure.container-apps.revision.result.recording|consumer=mission.azure-container-apps-revision.consumer|api=azure-container-apps-get-get-revision-list-revisions-2026-01-01-r1";
pub const CONTRACT_DIGEST: &str =
    "19259fdc1520e1afe2eadb68895c4b63ef5d9891cd48632c03e8e4399fc992f1";
pub const PLUGIN_ID: &str = "azure.container-apps.revision.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "azure.container-apps.revision.result.read";
pub const PROVIDER_ID: &str = "azure.container-apps.revision.result.recording";
pub const API_REVISION: &str = "azure-container-apps-get-get-revision-list-revisions-2026-01-01-r1";
pub const CONSUMER_ID: &str = "mission.azure-container-apps-revision.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const EVIDENCE_SCHEMA: &str = "hartevo.azure-container-apps-revision-result.evidence/v1";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1_024 * 1_024;
pub const MAX_NEXT_LINK_BYTES: usize = 8_192;
pub const MAX_REPLICAS: u32 = 1_000_000;
pub const MAX_TRAFFIC_WEIGHT: u16 = 100;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 3] = [
    "Microsoft.App/containerApps/read",
    "Microsoft.App/containerApps/revisions/read",
    "mission.scope",
];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-container-apps-revision-result/azure-container-apps-revision-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureContainerAppsRevisionResultContract {
    value: serde_json::Value,
}

impl AzureContainerAppsRevisionResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str(CONTRACT_JSON)
            .map_err(|_| AzureContainerAppsRevisionResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(AzureContainerAppsRevisionResultError::ContractDrift)?;
        for key in [
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
                return Err(AzureContainerAppsRevisionResultError::ContractDrift);
            }
        }
        let string_matches = [
            ("schemaVersion", CONTRACT_SCHEMA),
            ("contractVersion", CONTRACT_VERSION),
            ("pluginVersion", PLUGIN_VERSION),
            ("pluginId", PLUGIN_ID),
            ("layer", "Layer-1"),
            ("evidenceLevel", EVIDENCE_LEVEL),
            ("digestInput", CONTRACT_DIGEST_INPUT),
            ("contractDigest", CONTRACT_DIGEST),
        ];
        if string_matches.iter().any(|(key, expected)| {
            object.get(*key).and_then(serde_json::Value::as_str) != Some(*expected)
        }) || contract_digest().as_str() != CONTRACT_DIGEST
        {
            return Err(AzureContainerAppsRevisionResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureContainerAppsRevisionResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AzureContainerAppsRevisionResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureContainerAppsRevisionResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AzureContainerAppsRevisionResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureContainerAppsRevisionResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || [
                "adoptsOutcome",
                "adoptsWorkProduct",
                "truthAuthority",
                "consentAuthority",
                "effectAuthority",
                "receiptAuthority",
                "verificationAuthority",
            ]
            .iter()
            .any(|key| consumer.get(*key) != Some(&serde_json::Value::Bool(false)))
        {
            return Err(AzureContainerAppsRevisionResultError::ContractDrift);
        }
        let scope = object
            .get("scope")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureContainerAppsRevisionResultError::ContractDrift)?;
        if scope.get("maxPages") != Some(&serde_json::Value::from(MAX_PAGES))
            || scope.get("maxPageSize") != Some(&serde_json::Value::from(MAX_PAGE_SIZE))
            || scope.get("maxResponseBytes") != Some(&serde_json::Value::from(MAX_RESPONSE_BYTES))
        {
            return Err(AzureContainerAppsRevisionResultError::ContractDrift);
        }
        for forbidden in [
            "activate_revision",
            "deactivate_revision",
            "traffic_mutation",
            "scale_mutation",
            "exec",
            "log_download",
            "secret_read",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(AzureContainerAppsRevisionResultError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }
    pub const fn native() -> bool {
        false
    }
    pub const fn first_party() -> bool {
        false
    }
    pub const fn durable_provider_receipt() -> bool {
        false
    }
    pub const fn truth_authority() -> bool {
        false
    }
    pub const fn consent_authority() -> bool {
        false
    }
    pub const fn effect_authority() -> bool {
        false
    }
    pub const fn verification_authority() -> bool {
        false
    }
    pub const fn outcome_authority() -> bool {
        false
    }
    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_layer_one_and_honest_provenance() {
        let contract = AzureContainerAppsRevisionResultContract::baseline().expect("contract");
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
        assert!(!Layer1Authority::adopts_work_product());
    }
}
