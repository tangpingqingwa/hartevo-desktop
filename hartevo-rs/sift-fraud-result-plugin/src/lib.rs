//! Standalone Layer-1 governed Sift fraud decision evidence result plugin.
//!
//! The crate exposes typed, bounded, redacted decision/score/review/workflow
//! read seams for [`SiftFraudResultService`], [`SiftProvider`], and
//! [`MissionSiftFraudConsumer`]. It never resolves a native API key, opens
//! live HTTPS, retains raw user/order PII, ingests events, mutates Sift,
//! applies a block/allow effect, asserts fraud certainty, creates a kernel
//! receipt, or adopts an Outcome/Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub const CONTRACT_SCHEMA: &str = "hartevo.sift-fraud-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-SIFT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.sift-fraud-result/v1|layer=1|service=sift.fraud.result.read|provider=sift.fraud.result.recording|consumer=mission.sift-fraud.consumer|api=sift-decisions-score-workflow-status-r1";
pub const CONTRACT_DIGEST: &str =
    "fb97bd26f07c1babdee7eed8c41001a0dbbeb51ff42e1a9409fe078ec841eab3";
pub const PLUGIN_ID: &str = "sift.fraud.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "sift.fraud.result.read";
pub const PROVIDER_ID: &str = "sift.fraud.result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const CONSUMER_ID: &str = "mission.sift-fraud.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "sift:decisions:read",
    "sift:scores:read",
    "sift:workflows:read",
    "mission.scope",
];
pub const CONTRACT_PATH: &str = "contracts/plugins/sift-fraud-result/sift-fraud-result.v1.json";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/sift-fraud-result/sift-fraud-result.v1.json");

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionSiftFraudConsumer, MissionSiftFraudConsumerError, MissionSiftFraudResult,
    ProposalDisposition, RecordedSiftFraudResult,
};
pub use error::{Result, SiftFraudResultError, SiftTransportError};
pub use model::{
    ConsentScope, Digest, MAX_ABUSE_TYPES, MAX_RESPONSE_BYTES as MODEL_MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_SECONDS as MODEL_MAX_RETRY_AFTER_SECONDS, MAX_REVIEW_RECORDS,
    MAX_SECRET_REFERENCE_BYTES, MAX_WORKFLOW_STATUSES, MissionIdentity, MissionProjection,
    ProjectIdentity, ProjectProjection, RegistrationStatus, RegistrationTransitionEvidence,
    SecretReference, SiftAccountId, SiftDecisionDisposition, SiftDecisionId,
    SiftFraudResultRegistration, SiftFraudResultScope, SiftFraudResultState, SiftOrderId,
    SiftPermissionSnapshot, SiftReviewId, SiftReviewProjection, SiftReviewState, SiftScoreId,
    SiftScoreProjection, SiftUserId, SiftWorkflowProjection, SiftWorkflowState,
    TransportProvenance, WorkProductIdentity, WorkProductProjection, canonical_digest,
    sha256_digest,
};
pub use provider::{
    BlockedEnvTransport, FakeTransport, FixtureTransport, LoopbackTransport, RateLimitReceipt,
    RecordingTransport, SIFT_API_BASE_URL, SIFT_API_REVISION, SIFT_PROVIDER_ID,
    SIFT_PROVIDER_VERSION, SiftOperation, SiftProvider, SiftProviderDefinition, SiftProviderRead,
    SiftReadReceipt, SiftRequest, SiftResponse, SiftTransport,
};
pub use service::{
    CapabilityDescription, ObservationFailure, SIFT_FRAUD_RESULT_SERVICE_ID, SiftEvidence,
    SiftFraudResultEvidence, SiftFraudResultProposal, SiftFraudResultRequest,
    SiftFraudResultService, SiftFraudResultServiceDefinition, SiftProposal, SiftProviderError,
    SiftRegistration, SiftResultState, VerificationFailure, VerificationReport,
};

pub type Project = ProjectIdentity;
pub type Mission = MissionIdentity;
pub type WorkProduct = WorkProductIdentity;
pub type SiftScope = SiftFraudResultScope;
pub type SiftApiKeyReference = SecretReference;

pub const SIFT_FRAUD_RESULT_SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const SIFT_FRAUD_RESULT_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const SIFT_FRAUD_RESULT_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const SIFT_BLOCKED_ENV: &str = BLOCKED_ENV;
pub const SIFT_FRAUD_RESULT_CONTRACT_PATH: &str = CONTRACT_PATH;
pub const SIFT_FRAUD_RESULT_CONTRACT_JSON: &str = CONTRACT_JSON;

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[must_use]
pub fn contract_digest_hex() -> &'static str {
    CONTRACT_DIGEST
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party_provider() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn fraud_certainty() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn event_ingestion() -> bool {
        false
    }

    pub const fn decision_mutation() -> bool {
        false
    }

    pub const fn workflow_mutation() -> bool {
        false
    }

    pub const fn outcome_authority() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContractValidationError {
    #[error("contract JSON is invalid: {0}")]
    Json(String),
    #[error("contract field {0} is not the frozen Layer-1 value")]
    FrozenField(&'static str),
}

/// Validates the checked-in contract and its immutable Layer-1 honesty pins.
pub fn validate_contract() -> std::result::Result<(), ContractValidationError> {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|error| ContractValidationError::Json(error.to_string()))?;
    let is = |path: &'static str, condition: bool| {
        if condition {
            Ok(())
        } else {
            Err(ContractValidationError::FrozenField(path))
        }
    };
    is(
        "schemaVersion",
        contract["schemaVersion"] == CONTRACT_SCHEMA,
    )?;
    is(
        "contractVersion",
        contract["contractVersion"] == CONTRACT_VERSION,
    )?;
    is("pluginId", contract["pluginId"] == PLUGIN_ID)?;
    is("pluginVersion", contract["pluginVersion"] == PLUGIN_VERSION)?;
    is("layer", contract["layer"] == 1)?;
    is("evidenceLevel", contract["evidenceLevel"] == EVIDENCE_LEVEL)?;
    is(
        "digestInput",
        contract["digestInput"] == CONTRACT_DIGEST_INPUT,
    )?;
    is(
        "contractDigest",
        contract["contractDigest"] == CONTRACT_DIGEST,
    )?;
    is("service.id", contract["service"]["id"] == SERVICE_ID)?;
    is("provider.id", contract["provider"]["id"] == PROVIDER_ID)?;
    is(
        "provider.apiRevision",
        contract["provider"]["apiRevision"] == provider::SIFT_API_REVISION,
    )?;
    is("consumer.id", contract["consumer"]["id"] == CONSUMER_ID)?;
    is(
        "authority.connected",
        contract["authority"]["connected"] == false,
    )?;
    is(
        "authority.nativeProvider",
        contract["authority"]["nativeProvider"] == false,
    )?;
    is(
        "authority.externalWrites",
        contract["authority"]["externalWrites"] == false,
    )?;
    is(
        "authority.fraudCertainty",
        contract["authority"]["fraudCertainty"] == false,
    )?;
    is(
        "provider.connected",
        contract["provider"]["connected"] == false,
    )?;
    is("provider.native", contract["provider"]["native"] == false)?;
    is(
        "provider.firstParty",
        contract["provider"]["firstParty"] == false,
    )?;
    is(
        "provider.externalWrites",
        contract["provider"]["externalWrites"] == false,
    )?;
    is(
        "registration.reversible",
        contract["registration"]["reversible"] == true,
    )?;
    is(
        "registration.revocable",
        contract["registration"]["revocable"] == true,
    )?;
    is(
        "provenance.connected",
        contract["provenance"]["connected"] == false,
    )?;
    is(
        "provenance.native",
        contract["provenance"]["native"] == false,
    )?;
    is(
        "provenance.providerReceipt",
        contract["provenance"]["providerReceipt"] == false,
    )?;
    is(
        "layer2Gaps",
        contract["layer2Gaps"]
            .as_array()
            .is_some_and(|gaps| !gaps.is_empty()),
    )?;
    if contract_digest().as_str() != CONTRACT_DIGEST {
        return Err(ContractValidationError::FrozenField(
            "contractDigest calculation",
        ));
    }
    Ok(())
}
