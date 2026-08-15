//! Standalone Layer-1 Adobe Workfront review-approval result boundary.
//!
//! This crate models only bounded project/task/review/approval reads, exact
//! Mission/Project/Work Product scope, digest-bound reversible registration,
//! redacted recording, and non-mutating Mission proposals. It never resolves
//! native credentials, opens native HTTPS, mutates Workfront, exposes
//! document bytes or reviewer PII, claims Connected/native/first-party
//! evidence, or adopts kernel authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::type_complexity,
    clippy::unnecessary_wraps
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionWorkfrontReviewConsumer, MissionWorkfrontReviewResult, ProposalDisposition,
    RecordedWorkfrontReviewResult,
};
pub use error::{Result, WorkfrontReviewResultError, WorkfrontTransportError};
pub use model::*;
pub use provider::{
    ApprovalReadResponse, BlockedEnvTransport, FixtureTransport, LoopbackTransport,
    ProjectReadResponse, RecordingTransport, ReviewReadResponse, TaskReadResponse,
    WorkfrontOperation, WorkfrontProvider, WorkfrontProviderDefinition, WorkfrontReadRequest,
    WorkfrontTransport,
};
pub use service::{
    CapabilityDescription, FailureEvidence, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport, WorkfrontEvidenceRequest, WorkfrontRecordReceipt,
    WorkfrontReviewProposal, WorkfrontReviewRegistration, WorkfrontReviewResultService,
};

pub type WorkfrontScope = WorkfrontReviewScope;
pub type WorkfrontReviewResult = WorkfrontReviewProposal;
pub type WorkfrontService<T> = WorkfrontReviewResultService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.workfront-review-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-WORKFRONT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.workfront-review-result/v1|layer=1|service=workfront.review.result.read|provider=workfront.review.result.recording|consumer=mission.workfront-review-result.consumer|api=workfront-attask-v15-unified-review-approvals-r1";
pub const CONTRACT_DIGEST: &str =
    "3e15b2ecfff2f5fb3b7d5e6c198d1a33ba77d7f43876a18281ec5141f005e95c";
pub const PLUGIN_ID: &str = "workfront.review.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "workfront.review.result.read";
pub const PROVIDER_ID: &str = "workfront.review.result.recording";
pub const API_REVISION: &str = "workfront-attask-v15-unified-review-approvals-r1";
pub const CONSUMER_ID: &str = "mission.workfront-review-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_REVIEWER_ROLE_DIGESTS: usize = 16;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/workfront-review-result/workfront-review-result.v1.json"
);

pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "workfront:project:read",
    "workfront:task:read",
    "workfront:review:read",
    "workfront:approval:read",
    "mission.scope",
];

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

/// Checked-in contract document and its typed identity checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkfrontReviewResultContract {
    value: serde_json::Value,
}

impl WorkfrontReviewResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| WorkfrontReviewResultError::ContractDrift)?;
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
            .ok_or(WorkfrontReviewResultError::ContractDrift)?;
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
                return Err(WorkfrontReviewResultError::ContractDrift);
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
            return Err(WorkfrontReviewResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(WorkfrontReviewResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(WorkfrontReviewResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(WorkfrontReviewResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(WorkfrontReviewResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(WorkfrontReviewResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(WorkfrontReviewResultError::ContractDrift);
        }
        let forbidden = object
            .get("forbiddenEffects")
            .and_then(serde_json::Value::as_array)
            .ok_or(WorkfrontReviewResultError::ContractDrift)?;
        for required in [
            "approve_review",
            "reject_review",
            "approve_approval",
            "download_document",
            "serialize_reviewer_pii",
            "resolve_live_secret",
            "claim_connected",
            "adopt_outcome",
        ] {
            if !forbidden
                .iter()
                .any(|value| value.as_str() == Some(required))
            {
                return Err(WorkfrontReviewResultError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{
        CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
        PLUGIN_ID, WorkfrontReviewResultContract, contract_digest,
    };

    #[test]
    fn checked_contract_is_versioned_and_non_native() {
        let contract = WorkfrontReviewResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), contract_digest());
        let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("json");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginVersion"], "1.0.0");
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["layer"], "Layer-1");
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert!(!document["provider"]["connected"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["native"].as_bool().unwrap_or(true));
        assert!(!document["provider"]["firstParty"].as_bool().unwrap_or(true));
    }
}
