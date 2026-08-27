//! Standalone Layer-1 AWS Control Tower landing-zone governance result.
//!
//! This crate models bounded read proposals, redacted evidence, reversible
//! registration, Mission-scoped recording, and verification.  It is not a
//! Control Tower manager: fixture, recording, loopback, and `BLOCKED_ENV`
//! transports can never claim connected, native, first-party, durable,
//! compliant, or deployment-success evidence.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsControlTowerConsumer, MissionAwsControlTowerDecision,
    MissionAwsControlTowerDecisionState, MissionAwsControlTowerResult,
    RecordedAwsControlTowerResult, RecordedMissionAwsControlTower,
};
pub use model::*;
pub use provider::{
    AwsControlTowerProvider, AwsControlTowerProviderDefinition, AwsControlTowerProviderIdentity,
    AwsControlTowerProviderResponse, AwsControlTowerReadRecord, AwsControlTowerReadRequest,
    AwsControlTowerTransport, BlockedEnvAwsControlTowerTransport, BlockedEnvTransport,
    EnabledBaselineFilter, FixtureAwsControlTowerTransport, FixtureTransport,
    GetLandingZoneOperationRequest, GetLandingZoneOperationResponse, GetLandingZoneRequest,
    GetLandingZoneResponse, ListEnabledBaselinesPage, ListEnabledBaselinesRequest,
    ListEnabledBaselinesResponse, ListLandingZonesPage, ListLandingZonesRequest,
    ListLandingZonesResponse, LoopbackAwsControlTowerTransport, LoopbackTransport, ProviderError,
    ProviderProvenance, RecordedRequest, RecordingAwsControlTowerTransport, RecordingTransport,
    TransportError,
};
pub use service::{
    AuthorityBoundary, AwsControlTowerGovernanceEvidence, AwsControlTowerGovernanceProposal,
    AwsControlTowerGovernanceService, AwsControlTowerRecordReceipt, AwsControlTowerRegistration,
    AwsControlTowerServiceError, CapabilityDescription, EvidenceDigests, FailureEvidence,
    PaginationEvidence, RecordedAwsControlTowerResult as ServiceRecordedAwsControlTowerResult,
    RedactionSummary, Registration, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo-aws-control-tower-governance-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-CONTROL-TOWER-01-L1/v1";
pub const PLUGIN_ID: &str = "aws.controltower.governance.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.controltower.governance.result";
pub const PROVIDER_ID: &str = "aws.controltower.read";
pub const PROVIDER_VERSION: &str = "aws-controltower-provider/v1";
pub const API_VERSION: &str = "2018-05-10";
pub const API_REVISION: &str = "controltower-list-landing-zones-get-landing-zone-get-landing-zone-operation-list-enabled-baselines-1";
pub const API_DIGEST: &str = "controltower:ListLandingZones|controltower:GetLandingZone|controltower:GetLandingZoneOperation|controltower:ListEnabledBaselines";
pub const CONSUMER_ID: &str = "mission.aws-control-tower.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo-aws-control-tower-governance-result/v1|layer=1|service=aws.controltower.governance.result|provider=aws.controltower.read|consumer=mission.aws-control-tower.consumer";
pub const CONTRACT_DIGEST: &str =
    "51b838b52a13752eb92d862eadc93b2a54eab456c07d3957ca368c9a24a05123";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-control-tower-governance-result/aws-control-tower-governance-result.v1.json"
);

pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_ITEMS: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const OPERATION_RETENTION_DAYS: i64 = 90;

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "controltower:ListLandingZones",
    "controltower:GetLandingZone",
    "controltower:GetLandingZoneOperation",
    "controltower:ListEnabledBaselines",
    "mission.scope",
];

/// Layer-1 has no connected, native, authorization, or kernel truth
/// authority.  These constants make the negative boundary testable without
/// depending on a host application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn compliance_claim() -> bool {
        false
    }

    pub const fn deployment_success_claim() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST).expect("contract digest constant is valid")
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsControlTowerGovernanceContract {
    value: serde_json::Value,
}

impl AwsControlTowerGovernanceContract {
    pub fn baseline() -> std::result::Result<Self, ContractValidationError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractValidationError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), ContractValidationError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractValidationError::Shape("contract is not an object"))?;
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
            "boundedReads",
            "redaction",
            "honesty",
            "forbidden",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(ContractValidationError::Shape(
                    "required contract key missing",
                ));
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
        {
            return Err(ContractValidationError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsControlTowerGovernanceService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
            || service.get("workProductAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "service authority widened",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(serde_json::Value::as_str)
                != Some("AwsControlTowerProvider")
            || provider
                .get("apiVersion")
                .and_then(serde_json::Value::as_str)
                != Some(API_VERSION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "provider authority widened",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(serde_json::Value::as_str)
                != Some("MissionAwsControlTowerConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "consumer authority widened",
            ));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape(
                "credentials is not an object",
            ))?;
        if credentials.get("serializable") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialRetained") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary(
                "credential boundary widened",
            ));
        }
        let honesty = object
            .get("honesty")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractValidationError::Shape("honesty is not an object"))?;
        if honesty
            .values()
            .any(|value| value != &serde_json::Value::Bool(false))
        {
            return Err(ContractValidationError::Boundary("honesty flags widened"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        API_VERSION, AwsControlTowerGovernanceContract, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID,
        contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = AwsControlTowerGovernanceContract::baseline().expect("valid contract");
        let object = contract.value().as_object().expect("contract object");
        assert_eq!(object["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(object["contractVersion"], CONTRACT_VERSION);
        assert_eq!(object["pluginId"], PLUGIN_ID);
        assert_eq!(object["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(object["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(object["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(object["service"]["id"], SERVICE_ID);
        assert_eq!(object["provider"]["id"], PROVIDER_ID);
        assert_eq!(object["provider"]["apiVersion"], API_VERSION);
        assert_eq!(object["provider"]["native"], false);
        assert_eq!(object["provider"]["connected"], false);
        assert_eq!(object["consumer"]["adoptsOutcome"], false);
        assert_eq!(object["consumer"]["truthAuthority"], false);
    }
}
