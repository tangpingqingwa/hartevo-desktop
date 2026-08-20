//! Standalone Layer-1 governed AWS ECR image scan result plugin.
//!
//! The crate exposes typed `EcrImageScanResultService`, `EcrProvider`, and
//! `MissionEcrImageConsumer` seams for digest-pinned, bounded ECR image scan
//! evidence. It never resolves SigV4 credentials, sends native HTTPS,
//! mutates an image or repository, retains raw layers/bytes/tags/PII, creates
//! a durable native receipt, performs independent readback, or adopts an
//! Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
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
    MissionEcrImageConsumer, MissionEcrImageConsumerError, MissionEcrImageObservation,
    MissionEcrImageResult, MissionEcrImageScanResult, MissionEcrImageScanResultConsumer,
    MissionEcrImageScanState, MissionEcrImageState, MissionResultState,
};
pub use model::*;
pub use provider::{
    AWS_ECR_API_REVISION, AWS_ECR_PROVIDER_ID, AWS_ECR_PROVIDER_SCHEMA, AWS_ECR_PROVIDER_VERSION,
    BlockedEnvEcrTransport, DescribeImageScanFindingsPage, DescribeImageScanFindingsRequest,
    DescribeImagesPage, DescribeImagesRequest, EcrDescribeImageScanFindingsRequest,
    EcrDescribeImagesRequest, EcrImageScanProvider, EcrImageScanProviderDefinition,
    EcrImageScanTransport, EcrOpaquePageToken, EcrProvider, EcrProviderDefinition,
    EcrProviderError, EcrProviderErrorKind, EcrProviderIdentity, EcrTransport, FakeEcrTransport,
    FixtureEcrTransport, LoopbackEcrTransport, OpaqueCursor, OpaquePageToken,
    ProviderDefinitionError, RecordingEcrTransport, TransportError,
};
pub use service::{
    ECR_IMAGE_SCAN_SERVICE_ID, ECR_IMAGE_SCAN_SERVICE_NAME, EcrImageScanCapability,
    EcrImageScanObservation, EcrImageScanProposal, EcrImageScanProposalEnvelope,
    EcrImageScanRecord, EcrImageScanRegistration, EcrImageScanResultEvidence,
    EcrImageScanResultProposal, EcrImageScanResultRecord, EcrImageScanResultService,
    EcrImageScanResultVerification, EcrImageScanService, EcrImageScanServiceDefinition,
    EcrImageScanServiceError, EcrImageScanVerification, EcrRegistration,
    MISSION_ECR_IMAGE_SCAN_CONSUMER_ID, RegistrationError, RegistrationState,
};
use thiserror::Error;

pub const ECR_IMAGE_SCAN_SCHEMA_VERSION: &str = "hartevo.aws-ecr-image-scan-result-contract/v1";
pub const ECR_IMAGE_SCAN_CONTRACT_VERSION: &str = "aws-ecr-image-scan-result/v1";
pub const ECR_IMAGE_SCAN_PLUGIN_VERSION: &str = "1.0.0";
pub const ECR_IMAGE_SCAN_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const ECR_IMAGE_SCAN_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-ecr-image-scan-result/aws-ecr-image-scan-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(ECR_IMAGE_SCAN_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn version_digest() -> Digest {
    Digest::from_text(ECR_IMAGE_SCAN_PLUGIN_VERSION)
}

#[must_use]
pub fn provider_schema_digest() -> Digest {
    Digest::from_text(AWS_ECR_PROVIDER_SCHEMA)
}

#[must_use]
pub fn permission_digest() -> Digest {
    PermissionFence::for_layer_one(1)
        .expect("Layer-1 ECR permission fence is valid")
        .digest()
        .clone()
}

#[must_use]
pub const fn contract_json_is_embedded() -> bool {
    !ECR_IMAGE_SCAN_CONTRACT_JSON.is_empty()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcrImageScanContract {
    value: serde_json::Value,
}

impl EcrImageScanContract {
    pub fn baseline() -> Result<Self, EcrImageScanContractError> {
        let value = serde_json::from_str::<serde_json::Value>(ECR_IMAGE_SCAN_CONTRACT_JSON)
            .map_err(|error| EcrImageScanContractError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), EcrImageScanContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(EcrImageScanContractError::Shape(
                "contract is not an object",
            ))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "officialReferences",
            "service",
            "provider",
            "consumer",
            "scope",
            "allowlist",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "authority",
            "honesty",
            "distinction",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(EcrImageScanContractError::Shape(
                    "required contract key missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(ECR_IMAGE_SCAN_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(ECR_IMAGE_SCAN_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(ECR_IMAGE_SCAN_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(EcrImageScanContractError::Identity(
                "contract identity drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(EcrImageScanContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(ECR_IMAGE_SCAN_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some(ECR_IMAGE_SCAN_SERVICE_NAME)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(EcrImageScanContractError::Identity(
                "service identity drifted",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(EcrImageScanContractError::Shape(
                "provider is not an object",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(AWS_ECR_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("EcrProvider")
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(AWS_ECR_API_REVISION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(EcrImageScanContractError::Identity(
                "provider identity drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(EcrImageScanContractError::Shape(
                "consumer is not an object",
            ))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(MISSION_ECR_IMAGE_SCAN_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionEcrImageConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("deploymentAuthority") != Some(&serde_json::Value::Bool(false))
            || consumer.get("remediationAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(EcrImageScanContractError::Identity(
                "consumer identity drifted",
            ));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(EcrImageScanContractError::Shape(
                "authority is not an object",
            ))?;
        for key in [
            "externalWrites",
            "imagePush",
            "imageDelete",
            "imageTagMutation",
            "startImageScan",
            "inspectorRemediation",
            "rawLayers",
            "rawImageBytes",
            "rawPii",
            "credentialResolution",
            "connected",
            "native",
            "durableReceipt",
            "independentReadback",
            "deploymentAuthority",
            "remediationAuthority",
            "kernelOutcomeAdoption",
            "workProductAdoption",
            "snykProjectSnapshot",
            "codeqlCodeAnalysis",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(EcrImageScanContractError::Boundary(
                    "Layer-1 authority widened",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EcrImageScanContractError {
    #[error("AWS ECR image-scan contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS ECR image-scan contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS ECR image-scan contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS ECR image-scan contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
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
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_readback() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_outcome() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_layers() -> bool {
        false
    }

    #[must_use]
    pub const fn raw_image_bytes() -> bool {
        false
    }

    #[must_use]
    pub const fn remediation() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        EcrImageScanContract::baseline().expect("ECR contract");
        assert!(contract_json_is_embedded());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::independent_readback());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::raw_layers());
        assert!(!Layer1Authority::raw_image_bytes());
        assert!(!Layer1Authority::remediation());
    }
}
