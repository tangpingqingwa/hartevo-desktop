//! Standalone Layer-1 governed AWS Audit Manager assessment-evidence result slice.
//!
//! The crate owns bounded, typed Audit Manager metadata reads, digest-bound
//! reversible registration, redacted proposal/recording/verification seams,
//! and a Mission-scoped review proposal.  Recording, fixture, loopback, and
//! `BLOCKED_ENV` transports are always non-connected, non-native, and
//! non-first-party.  Native SigV4 resolution, live HTTPS, evidence/report
//! downloads, assessment/control mutation, certification, and kernel Outcome
//! authority remain outside this root.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
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
    ConsumerError, MissionAwsAuditManagerConsumer, MissionAwsAuditManagerDecisionState,
    MissionAwsAuditManagerResult,
};
pub use error::{
    AwsAuditManagerError, AwsAuditManagerServiceError, AwsAuditManagerTransportError, Result,
};
pub use model::*;
pub use provider::{
    AwsAuditManagerOperation, AwsAuditManagerProvider, AwsAuditManagerProviderDefinition,
    AwsAuditManagerProviderDefinitionError, AwsAuditManagerProviderError,
    AwsAuditManagerReadRequest, AwsAuditManagerTransport, BlockedEnvAwsAuditManagerTransport,
    BlockedEnvTransport, FakeAwsAuditManagerTransport, FakeTransport,
    FixtureAwsAuditManagerTransport, FixtureTransport, LoopbackAwsAuditManagerTransport,
    LoopbackTransport, ProviderError, ProviderRead, QueuedTransport, RecordedRequest,
    RecordedRequestKind, RecordingAwsAuditManagerTransport, RecordingTransport, is_access_loss,
};
pub use service::{
    AwsAuditManagerCapabilities, AwsAuditManagerProposal, AwsAuditManagerRecordReceipt,
    AwsAuditManagerRegistration, AwsAuditManagerRegistrationReceipt, AwsAuditManagerResult,
    AwsAuditManagerService, AwsAuditManagerVerificationReport, CapabilityDescription,
    RecordedAwsAuditManagerResult, RegistrationState, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const AWS_AUDIT_MANAGER_SCHEMA_VERSION: &str = "hartevo.aws-audit-manager-result/v1";
pub const AWS_AUDIT_MANAGER_CONTRACT_VERSION: &str = "EXT-AWS-AUDIT-MANAGER-01-L1/v1";
pub const AWS_AUDIT_MANAGER_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_AUDIT_MANAGER_PLUGIN_ID: &str = "aws.audit-manager.result";
pub const AWS_AUDIT_MANAGER_SERVICE_ID: &str = "aws.audit-manager.result.read";
pub const AWS_AUDIT_MANAGER_PROVIDER_ID: &str = "aws.audit-manager.result.recording";
pub const AWS_AUDIT_MANAGER_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_AUDIT_MANAGER_API_REVISION: &str =
    "audit-manager-list-assessments-get-assessment-list-assessment-reports-2020-07-01-r1";
pub const AWS_AUDIT_MANAGER_CONSUMER_ID: &str = "mission.aws-audit-manager.consumer";
pub const AWS_AUDIT_MANAGER_SERVICE_NAME: &str = "AwsAuditManagerService";
pub const AWS_AUDIT_MANAGER_PROVIDER_NAME: &str = "AwsAuditManagerProvider";
pub const MISSION_AWS_AUDIT_MANAGER_CONSUMER_NAME: &str = "MissionAwsAuditManagerConsumer";
pub const AWS_AUDIT_MANAGER_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const CONTRACT_SCHEMA: &str = AWS_AUDIT_MANAGER_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_AUDIT_MANAGER_CONTRACT_VERSION;
pub const PLUGIN_VERSION: &str = AWS_AUDIT_MANAGER_PLUGIN_VERSION;
pub const PLUGIN_ID: &str = AWS_AUDIT_MANAGER_PLUGIN_ID;
pub const SERVICE_ID: &str = AWS_AUDIT_MANAGER_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_AUDIT_MANAGER_PROVIDER_ID;
pub const PROVIDER_API_REVISION: &str = AWS_AUDIT_MANAGER_API_REVISION;
pub const CONSUMER_ID: &str = AWS_AUDIT_MANAGER_CONSUMER_ID;

pub const CONTRACT_DIGEST_INPUT: &str = concat!(
    "hartevo.aws-audit-manager-result/v1|layer=1|service=aws.audit-manager.result.read|",
    "provider=aws.audit-manager.result.recording|consumer=mission.aws-audit-manager.consumer"
);

// The contract document records the digest of the stable identity input, not
// a mutable JSON serialization.  This prevents formatting changes from
// silently changing registration identity while the checked-in contract is
// still validated structurally.
pub const CONTRACT_DIGEST: &str =
    "8923ecbda1bdc59a01bdcd0558e63e67ffb38a99f54d70dfd49eb9426798fcd5";

pub const AWS_AUDIT_MANAGER_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-audit-manager-result/contract.v1.json");
pub const CONTRACT_JSON: &str = AWS_AUDIT_MANAGER_CONTRACT_JSON;

pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "auditmanager:ListAssessments",
    "auditmanager:GetAssessment",
    "auditmanager:ListAssessmentReports",
    "mission.scope",
];

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_CONTROL_SETS: usize = 32;
pub const MAX_REPORTS: usize = 128;
pub const MAX_RESULT_DIGESTS: usize = 256;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_RESPONSE_BYTES_USIZE: usize = 1_048_576;
pub const MAX_RETRIES: u8 = 2;

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

pub fn validate_contract_document() -> std::result::Result<(), ContractDocumentError> {
    AwsAuditManagerContract::baseline().map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAuditManagerContract {
    value: serde_json::Value,
}

impl AwsAuditManagerContract {
    pub fn baseline() -> std::result::Result<Self, ContractDocumentError> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|error| ContractDocumentError::InvalidJson(error.to_string()))?;
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

    pub fn validate(&self) -> std::result::Result<(), ContractDocumentError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractDocumentError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
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
            "evidence",
            "redaction",
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractDocumentError::Shape(
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
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST)
        {
            return Err(ContractDocumentError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Shape("service is not an object"))?;
        let operations = service
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::Shape("service operations missing"))?;
        let expected_operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "reverse_registration",
            "restore_registration",
            "ListAssessments",
            "GetAssessment",
            "ListAssessmentReports",
            "read",
            "propose",
            "record",
            "verify",
        ];
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("type").and_then(serde_json::Value::as_str)
                != Some(AWS_AUDIT_MANAGER_SERVICE_NAME)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || operations.len() != expected_operations.len()
            || operations
                .iter()
                .zip(expected_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractDocumentError::Boundary("service boundary drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Shape("provider is not an object"))?;
        let provider_operations = provider
            .get("operations")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::Shape("provider operations missing"))?;
        let expected_provider_operations =
            ["ListAssessments", "GetAssessment", "ListAssessmentReports"];
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("type").and_then(serde_json::Value::as_str)
                != Some(AWS_AUDIT_MANAGER_PROVIDER_NAME)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(PROVIDER_API_REVISION)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstPartyEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
            || provider_operations.len() != expected_provider_operations.len()
            || provider_operations
                .iter()
                .zip(expected_provider_operations)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err(ContractDocumentError::Boundary("provider boundary drifted"));
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Shape("credentials is not an object"))?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
            || credentials.get("debugRedacted") != Some(&serde_json::Value::Bool(true))
        {
            return Err(ContractDocumentError::Boundary(
                "credential boundary drifted",
            ));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("type").and_then(serde_json::Value::as_str)
                != Some(MISSION_AWS_AUDIT_MANAGER_CONSUMER_NAME)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Boundary("consumer boundary drifted"));
        }
        let authority = object
            .get("authorityBoundary")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractDocumentError::Shape(
                "authority boundary is not an object",
            ))?;
        if authority.get("connected") != Some(&serde_json::Value::Bool(false))
            || authority.get("native") != Some(&serde_json::Value::Bool(false))
            || authority.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || authority.get("certification") != Some(&serde_json::Value::Bool(false))
            || authority.get("legalAdvice") != Some(&serde_json::Value::Bool(false))
            || authority.get("kernelOutcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractDocumentError::Boundary(
                "authority boundary widened",
            ));
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(ContractDocumentError::Shape("forbidden list missing"))?;
        for required in [
            "CreateAssessment",
            "UpdateAssessment",
            "DeleteAssessment",
            "UploadEvidence",
            "UpdateControlSet",
            "DeleteControlSet",
            "DownloadAssessmentReport",
            "resolve_live_credentials",
            "claim_compliance_certification",
            "provide_legal_advice",
            "adopt_kernel_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|entry| entry.as_str() == Some(required))
            {
                return Err(ContractDocumentError::Boundary(
                    "forbidden operation missing",
                ));
            }
        }
        Ok(())
    }
}

pub type AwsAuditManagerContractError = ContractDocumentError;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractDocumentError {
    #[error("AWS Audit Manager contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("AWS Audit Manager contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("AWS Audit Manager contract identity is invalid: {0}")]
    Identity(&'static str),
    #[error("AWS Audit Manager contract authority boundary is invalid: {0}")]
    Boundary(&'static str),
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

    pub const fn certification_authority() -> bool {
        false
    }

    pub const fn legal_advice() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_in_contract_matches_typed_boundary() {
        let contract = AwsAuditManagerContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
    }
}
