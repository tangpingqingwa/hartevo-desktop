//! Standalone Layer-1 governed Azure Event Hub posture result boundary.
//!
//! This crate exposes only bounded Azure Resource Manager metadata seams for
//! one exact Event Hub scope. It has no AMQP or data-plane operation, no
//! credential resolver, no mutation, and no Hartevo Truth, Consent, Effect,
//! Receipt, Verification, Outcome, or durable Work Product authority.
//! Recording, fixture, fake, loopback, and `BLOCKED_ENV` transports are always
//! non-connected, non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::fn_params_excessive_bools,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAzureEventHubPostureConsumer, MissionAzureEventHubPostureResult, ProposalDisposition,
    RecordedAzureEventHubPostureResult,
};
pub use error::{AzureEventHubPostureResultError, AzureEventHubTransportError, Result};
pub use model::*;
pub use provider::{
    AzureEventHubOperation, AzureEventHubsProvider, AzureEventHubsProviderDefinition,
    AzureEventHubsTransport, BlockedEnvTransport, ConsumerGroupCursor, Cursor, FakeTransport,
    FixtureTransport, GetConsumerGroupRequest, GetConsumerGroupResponse, GetEventHubRequest,
    GetEventHubResponse, GetNamespaceRequest, GetNamespaceResponse, ListConsumerGroupsRequest,
    ListConsumerGroupsResponse, LoopbackTransport, RecordedRequest, RecordingTransport,
};
pub use service::{
    AzureEventHubPostureEvidenceRequest, AzureEventHubPostureProposal,
    AzureEventHubPostureRegistration, AzureEventHubPostureResultService, AzureEventHubRegistration,
    AzureEventHubService, CapabilityDescription, FailureEvidence, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.azure-event-hub-posture-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AZURE-EVENT-HUB-01-L1/v1";
pub const PLUGIN_ID: &str = "azure.event-hub.posture.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "azure.event-hub.posture.result.read";
pub const PROVIDER_ID: &str = "azure.eventhubs.posture.result.recording";
pub const ARM_API_VERSION: &str = "2024-01-01";
pub const API_REVISION: &str =
    "eventhub-namespaces-get-event-hubs-get-consumer-groups-list-by-event-hub-2024-01-01-r1";
pub const CONSUMER_ID: &str = "mission.azure-event-hub-posture.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.azure-event-hub-posture-result/v1|layer=1|service=azure.event-hub.posture.result.read|provider=azure.eventhubs.posture.result.recording|consumer=mission.azure-event-hub-posture.consumer|api=eventhub-namespaces-get-event-hubs-get-consumer-groups-list-by-event-hub-2024-01-01-r1";
pub const CONTRACT_DIGEST: &str =
    "ce411664bd0dbcb71fb2696ec4275f8c4da7ee9110f6f07e7d42c6faa22e6ee3";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_PARTITION_COUNT: u32 = 4_096;
pub const MAX_RETENTION_DAYS: u32 = 7_305;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "Microsoft.EventHub/namespaces/read",
    "Microsoft.EventHub/namespaces/eventhubs/read",
    "Microsoft.EventHub/namespaces/eventhubs/consumergroups/read",
    "mission.scope",
];

pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-event-hub-posture-result/azure-event-hub-posture-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureEventHubPostureContract {
    value: serde_json::Value,
}

impl AzureEventHubPostureContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AzureEventHubPostureResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "status",
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
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(AzureEventHubPostureResultError::ContractDrift);
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
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AzureEventHubPostureResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
            || service.get("workProductAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AzureEventHubPostureResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("armApiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(ARM_API_VERSION)
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
            return Err(AzureEventHubPostureResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AzureEventHubPostureResultError::ContractDrift);
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
            || credentials.get("accessTokenRetained") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AzureEventHubPostureResultError::ContractDrift);
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AzureEventHubPostureResultError::ContractDrift)?;
        for key in ["connected", "native", "firstParty", "providerReceipt"] {
            if provenance.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(AzureEventHubPostureResultError::ContractDrift);
            }
        }
        for forbidden in [
            "send_event",
            "receive_event",
            "peek_event",
            "write_checkpoint",
            "claim_lag_truth",
            "mutate_namespace",
            "mutate_event_hub",
            "mutate_consumer_group",
            "mutate_capture",
            "mutate_network_rules",
            "capture_event_body",
            "retain_raw_provider_body",
            "claim_delivery_guarantee",
            "issue_provider_receipt",
            "adopt_outcome",
            "adopt_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(AzureEventHubPostureResultError::ContractDrift);
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

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        API_REVISION, ARM_API_VERSION, AzureEventHubPostureContract, CONSUMER_ID, CONTRACT_DIGEST,
        CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
        PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn baseline_contract_is_layer_one_and_non_native() {
        let contract = AzureEventHubPostureContract::baseline().expect("baseline contract");
        let value = contract.value();
        assert_eq!(value["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(value["contractVersion"], CONTRACT_VERSION);
        assert_eq!(value["pluginId"], PLUGIN_ID);
        assert_eq!(value["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(value["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(value["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(value["service"]["id"], SERVICE_ID);
        assert_eq!(value["provider"]["id"], PROVIDER_ID);
        assert_eq!(value["provider"]["armApiVersion"], ARM_API_VERSION);
        assert_eq!(value["provider"]["apiRevision"], API_REVISION);
        assert_eq!(value["consumer"]["id"], CONSUMER_ID);
        assert!(!value["provider"]["connected"].as_bool().unwrap_or(true));
        assert!(!value["provider"]["native"].as_bool().unwrap_or(true));
        assert!(!value["provider"]["firstParty"].as_bool().unwrap_or(true));
        assert!(!value["consumer"]["adoptsOutcome"].as_bool().unwrap_or(true));
        assert!(
            !value["consumer"]["adoptsWorkProduct"]
                .as_bool()
                .unwrap_or(true)
        );
        assert!(!CONTRACT_JSON.is_empty());
    }
}
