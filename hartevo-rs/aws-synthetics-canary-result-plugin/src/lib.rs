//! Standalone Layer-1 governed AWS CloudWatch Synthetics canary-result slice.
//!
//! The crate stops at bounded canary-run evidence, a non-authoritative Mission
//! endpoint-verification decision proposal, recording, and verification.  It
//! does not resolve credentials, make native AWS calls, mutate canaries or
//! endpoints, retain raw provider payloads, claim Connected/native/first-party
//! provenance, certify an endpoint, or adopt a kernel outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

use thiserror::Error;

pub use consumer::{
    ConsumerError, MissionAwsSyntheticsConsumer, MissionAwsSyntheticsDecision,
    MissionAwsSyntheticsDecisionState, MissionAwsSyntheticsEndpointDecision,
    MissionAwsSyntheticsResult,
};
pub use model::*;
pub use provider::{
    AwsSyntheticsProvider, AwsSyntheticsProviderError, AwsSyntheticsProviderIdentity,
    AwsSyntheticsTransport, BlockedEnvAwsSyntheticsTransport, BlockedEnvTransport,
    FakeAwsSyntheticsTransport, FixtureAwsSyntheticsTransport, LoopbackAwsSyntheticsTransport,
    ProviderDefinitionError, ProviderProvenance, RecordingAwsSyntheticsTransport, TransportError,
    is_access_loss,
};
pub use service::{
    AwsSyntheticsCanaryProposal, AwsSyntheticsCanaryService, AwsSyntheticsCanaryServiceError,
    AwsSyntheticsCapabilities, AwsSyntheticsReadResult, AwsSyntheticsRecordReceipt,
    AwsSyntheticsRegistration, AwsSyntheticsRegistrationReceipt, AwsSyntheticsService,
    AwsSyntheticsServiceError, AwsSyntheticsVerifiedRecord, RegistrationError, RegistrationState,
};

pub const AWS_SYNTHETICS_SCHEMA_VERSION: &str = "hartevo.aws-synthetics-canary-result.contract/v1";
pub const AWS_SYNTHETICS_CONTRACT_VERSION: &str = "aws-synthetics-canary-result/v1";
pub const AWS_SYNTHETICS_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_SYNTHETICS_SERVICE_ID: &str = "hartevo.aws.synthetics.canary-result";
pub const AWS_SYNTHETICS_PROVIDER_ID: &str = "aws.synthetics";
pub const AWS_SYNTHETICS_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_SYNTHETICS_API_REVISION: &str = "aws-synthetics-read-r1";
pub const AWS_SYNTHETICS_CONSUMER_ID: &str = "mission.aws.synthetics.endpoint-verification";
pub const AWS_SYNTHETICS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_SYNTHETICS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-synthetics-canary-result/aws-synthetics-canary-result.v1.json"
);

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_SYNTHETICS_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsSyntheticsCanaryContract {
    value: serde_json::Value,
}

impl AwsSyntheticsCanaryContract {
    pub fn baseline() -> Result<Self, AwsSyntheticsContractError> {
        let value = serde_json::from_str::<serde_json::Value>(AWS_SYNTHETICS_CONTRACT_JSON)
            .map_err(|error| AwsSyntheticsContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), AwsSyntheticsContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsSyntheticsContractError::Shape(
                "contract is not an object",
            ))?;
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
            "redaction",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(AwsSyntheticsContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(AWS_SYNTHETICS_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_SYNTHETICS_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_SYNTHETICS_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(AwsSyntheticsContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSyntheticsContractError::Shape(
                "service definition missing",
            ))?;
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSyntheticsContractError::Shape(
                "provider definition missing",
            ))?;
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsSyntheticsContractError::Shape(
                "consumer definition missing",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(AWS_SYNTHETICS_SERVICE_ID)
            || provider.get("id").and_then(serde_json::Value::as_str)
                != Some(AWS_SYNTHETICS_PROVIDER_ID)
            || consumer.get("id").and_then(serde_json::Value::as_str)
                != Some(AWS_SYNTHETICS_CONSUMER_ID)
        {
            return Err(AwsSyntheticsContractError::Identity(
                "service, provider, or consumer identity drifted",
            ));
        }
        for (section, key) in [
            ("service", "readOnly"),
            ("service", "proposalOnly"),
            ("provider", "native"),
            ("provider", "connected"),
            ("provider", "firstParty"),
            ("consumer", "adoptsOutcome"),
            ("consumer", "truthAuthority"),
        ] {
            let section_value = object
                .get(section)
                .and_then(serde_json::Value::as_object)
                .and_then(|value| value.get(key))
                .and_then(serde_json::Value::as_bool);
            let expected = matches!(key, "readOnly" | "proposalOnly");
            if section_value != Some(expected) {
                return Err(AwsSyntheticsContractError::Authority(
                    "Layer-1 authority flags are unsafe",
                ));
            }
        }
        let transports = provider
            .get("acceptedTransports")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsSyntheticsContractError::Shape(
                "accepted transport list missing",
            ))?;
        for transport in [
            "fixture",
            "recording",
            "loopback",
            AWS_SYNTHETICS_BLOCKED_ENV,
        ] {
            if !transports
                .iter()
                .any(|value| value.as_str() == Some(transport))
            {
                return Err(AwsSyntheticsContractError::Shape(
                    "required deterministic transport missing",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsSyntheticsContractError {
    #[error("AWS Synthetics contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Synthetics contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Synthetics contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Synthetics contract authority is unsafe: {0}")]
    Authority(&'static str),
}

#[derive(Debug)]
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

    pub const fn certification() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsSyntheticsCanaryContract::baseline().expect("valid contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::certification());
        assert!(!Layer1Authority::outcome_authority());
    }
}
