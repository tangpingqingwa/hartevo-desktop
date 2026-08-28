//! Standalone Layer-1 AWS RDS health and event result boundary.
//!
//! This crate owns only bounded, redacted RDS reads and the resulting Mission
//! decision proposal/recording seam. It does not own Hartevo Truth, Effect,
//! Receipt, Verification, Outcome, or Work Product authority. Native SigV4,
//! native HTTPS, durable provider receipts, and independent read-back remain
//! Layer-2 host responsibilities.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionAwsRdsConsumer, MissionAwsRdsDecision, MissionAwsRdsResult, RecordedAwsRdsResult,
};
pub use model::*;
pub use provider::{
    AwsRdsProvider, AwsRdsProviderDefinition, AwsRdsProviderError, AwsRdsTransport,
    AwsRdsTransportError, BlockedEnvAwsRdsTransport, BlockedEnvTransport, FixtureAwsRdsTransport,
    FixtureTransport, LoopbackAwsRdsTransport, LoopbackTransport, RecordingAwsRdsTransport,
    RecordingTransport,
};
pub use service::{
    AwsRdsHealthCapabilities, AwsRdsHealthProposal, AwsRdsHealthReadResult, AwsRdsHealthService,
    AwsRdsHealthServiceDefinition, AwsRdsRecordReceipt, AwsRdsRegistration, AwsRdsServiceError,
    AwsRdsVerifiedRecord, RegistrationState, RegistrationTransitionEvidence, VerificationFailure,
    VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-rds-health-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSRDS-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-rds-health-result/v1|layer=1|service=aws.rds.health-result.read|provider=aws.rds.health-result.recording|consumer=mission.aws-rds-health.consumer";
pub const CONTRACT_DIGEST: &str =
    "2d4357e4b21eefa0feb20bd408799d2f6c3b36ee502351271bfbdb737ce16642";
pub const PLUGIN_ID: &str = "aws.rds.health-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.rds.health-result.read";
pub const PROVIDER_ID: &str = "aws.rds.health-result.recording";
pub const PROVIDER_API_REVISION: &str = "rds-describe-db-instances-clusters-events-maintenance-1";
pub const CONSUMER_ID: &str = "mission.aws-rds-health.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-rds-health-result/contract.v1.json");

/// The canonical digest of the versioned contract input string.
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsRdsHealthContract {
    value: serde_json::Value,
    digest: Digest,
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ContractError {
    #[error("AWS RDS contract JSON is invalid: {0}")]
    Json(String),
    #[error("AWS RDS contract values drifted")]
    Drift,
}

impl AwsRdsHealthContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        let contract = Self {
            value,
            digest: contract_digest(),
        };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let matches = self
            .value
            .get("schemaVersion")
            .and_then(|value| value.as_str())
            == Some(CONTRACT_SCHEMA)
            && self
                .value
                .get("contractVersion")
                .and_then(|value| value.as_str())
                == Some(CONTRACT_VERSION)
            && self.value.get("pluginId").and_then(|value| value.as_str()) == Some(PLUGIN_ID)
            && self.value.get("layer").and_then(serde_json::Value::as_u64) == Some(1)
            && self
                .value
                .get("digestInput")
                .and_then(|value| value.as_str())
                == Some(CONTRACT_DIGEST_INPUT)
            && self
                .value
                .get("contractDigest")
                .and_then(|value| value.as_str())
                == Some(CONTRACT_DIGEST)
            && self.digest.as_str() == CONTRACT_DIGEST;
        if matches {
            Ok(())
        } else {
            Err(ContractError::Drift)
        }
    }
}

pub type AwsRdsContract = AwsRdsHealthContract;

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON, CONTRACT_SCHEMA,
        CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        layer: u8,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: EndpointDocument,
        provider: EndpointDocument,
        consumer: EndpointDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EndpointDocument {
        id: String,
        read_only: bool,
        connected: bool,
        native: bool,
        first_party: Option<bool>,
    }

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("RDS contract JSON");
        assert_eq!(contract.schema_version, CONTRACT_SCHEMA);
        assert_eq!(contract.contract_version, CONTRACT_VERSION);
        assert_eq!(contract.plugin_id, PLUGIN_ID);
        assert_eq!(contract.layer, 1);
        assert_eq!(contract.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(contract.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(contract.contract_digest, CONTRACT_DIGEST);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert_eq!(contract.service.id, SERVICE_ID);
        assert!(contract.service.read_only);
        assert!(!contract.service.connected);
        assert!(!contract.service.native);
        assert_eq!(contract.provider.id, PROVIDER_ID);
        assert!(contract.provider.read_only);
        assert!(!contract.provider.connected);
        assert!(!contract.provider.native);
        assert_eq!(contract.provider.first_party, Some(false));
        assert_eq!(contract.consumer.id, CONSUMER_ID);
        assert!(contract.consumer.read_only);
        assert!(!contract.consumer.connected);
        assert!(!contract.consumer.native);
    }
}
