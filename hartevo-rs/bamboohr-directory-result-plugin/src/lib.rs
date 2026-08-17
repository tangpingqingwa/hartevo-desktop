//! Standalone Layer-1 BambooHR employee-directory result evidence plugin.
//!
//! This crate is intentionally below Hartevo kernel Truth, Consent, Effect,
//! Receipt, Verification, Outcome, identity, access-grant, and Work Product
//! authority. It contains only bounded typed read, proposal, recording, and
//! read-back seams plus non-native test transports.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]
#![allow(clippy::large_enum_variant)]

use thiserror::Error;

mod canonical;
pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    BambooHrDirectoryAdoptionProposal, MissionBambooHrDirectoryConsumer,
    MissionBambooHrDirectoryContext,
};
pub use model::*;
pub use provider::{
    BambooHrDirectoryFixture, BambooHrDirectoryResponse, BambooHrDirectoryTransport,
    BambooHrEmployeeListPage, BambooHrProvider, BambooHrProviderDefinition,
    BlockedEnvBambooHrTransport, ProviderError, ProviderFailureClass, ProviderProvenance,
    RecordingBambooHrTransport, ScriptedBambooHrTransport, TransportProvenance,
};
pub use service::{
    BambooHrDirectoryCapabilities, BambooHrDirectoryEvidence, BambooHrDirectoryEvidenceStatus,
    BambooHrDirectoryProposal, BambooHrDirectoryReadBack, BambooHrDirectoryRecordedProposal,
    BambooHrDirectoryRegistration, BambooHrDirectoryRequestReceipt, BambooHrDirectoryResultService,
    BambooHrEmployeeListRequestReceipt, BambooHrEmployeeMetadataEvidence,
    BambooHrEmployeeMetadataProposal, EvidenceStatus, RegistrationStatus,
    RegistrationTransitionEvidence,
};

pub const BAMBOOHR_DIRECTORY_RESULT_SCHEMA_VERSION: &str =
    "hartevo.bamboohr-directory-result.contract/v1";
pub const BAMBOOHR_DIRECTORY_RESULT_CONTRACT_VERSION: &str = "EXT-BAMBOOHR-01/v1";
pub const BAMBOOHR_DIRECTORY_RESULT_PLUGIN_ID: &str = "hartevo.bamboohr.directory-result";
pub const BAMBOOHR_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const BAMBOOHR_DIRECTORY_SERVICE_ID: &str = "hartevo.bamboohr.directory.result";
pub const BAMBOOHR_DIRECTORY_SERVICE_IMPLEMENTATION: &str = "BambooHrDirectoryResultService";
pub const BAMBOOHR_DIRECTORY_PROVIDER_ID: &str = "bamboohr.employees.directory.read";
pub const BAMBOOHR_DIRECTORY_PROVIDER_IMPLEMENTATION: &str = "BambooHrProvider";
pub const BAMBOOHR_DIRECTORY_CONSUMER_ID: &str = "mission.bamboohr-directory-result";
pub const BAMBOOHR_DIRECTORY_CONSUMER_IMPLEMENTATION: &str = "MissionBambooHrDirectoryConsumer";
pub const BAMBOOHR_DIRECTORY_API_BASE: &str =
    "https://{companyDomain}.bamboohr.com/api/v1/employees/directory";
pub const BAMBOOHR_DIRECTORY_API_REVISION: &str = "bamboohr-get-employees-directory-v1-r1";
pub const BAMBOOHR_DIRECTORY_PERMISSION: &str = "employee_directory";
pub const BAMBOOHR_DIRECTORY_RESULT_CONTRACT_DIGEST_INPUT: &str = concat!(
    "hartevo.bamboohr-directory-result.contract/v1",
    "|contract=EXT-BAMBOOHR-01/v1",
    "|service=hartevo.bamboohr.directory.result",
    "|provider=bamboohr.employees.directory.read",
    "|api=bamboohr-get-employees-directory-v1-r1",
    "|permission=employee_directory",
    "|evidence=bamboohr-directory-evidence/v1"
);
pub const BAMBOOHR_DIRECTORY_EVIDENCE_SCHEMA: &str = "bamboohr-directory-evidence/v1";
pub const BAMBOOHR_DIRECTORY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/bamboohr-directory-result/bamboohr-directory-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(BAMBOOHR_DIRECTORY_RESULT_CONTRACT_DIGEST_INPUT)
}

#[must_use]
pub fn api_digest() -> Digest {
    Digest::from_text(BAMBOOHR_DIRECTORY_API_REVISION)
}

#[must_use]
pub fn permission_digest() -> Digest {
    PermissionScope::read_only().digest().clone()
}

#[must_use]
pub fn evidence_schema_digest() -> Digest {
    Digest::from_text(BAMBOOHR_DIRECTORY_EVIDENCE_SCHEMA)
}

#[must_use]
pub fn provider_digest() -> Digest {
    Digest::from_fields(
        "bamboohr-directory-provider/v1",
        &[
            BAMBOOHR_DIRECTORY_PROVIDER_ID.to_owned(),
            BAMBOOHR_DIRECTORY_API_REVISION.to_owned(),
            BAMBOOHR_DIRECTORY_PERMISSION.to_owned(),
            "GET /api/v1/employees/directory".to_owned(),
            "GET /api/v1/employees".to_owned(),
            "fields=jobTitleName,department,division,location,supervisor,status".to_owned(),
            "cursor=after|before|opaque_digest_only".to_owned(),
            "change_fence=required_and_stable_across_pages".to_owned(),
            "accept=application/json".to_owned(),
            "onlyCurrent=true|false".to_owned(),
            "fixture|recording|loopback|BLOCKED_ENV".to_owned(),
            "connected=false|native=false|first_party=false".to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BambooHrDirectoryResultError {
    #[error("BambooHR directory result model validation failed: {0}")]
    Model(#[from] model::ModelError),
    #[error("BambooHR directory provider failed: {0}")]
    Provider(#[from] provider::ProviderError),
    #[error("BambooHR directory registration is not active")]
    RegistrationInactive,
    #[error("BambooHR directory registration is revoked")]
    RegistrationRevoked,
    #[error("BambooHR directory registration or scope digest drifted")]
    RegistrationDrift,
    #[error("BambooHR directory SecretReference was revoked")]
    SecretReferenceRevoked,
    #[error("BambooHR directory scope does not match the request")]
    ScopeMismatch,
    #[error("BambooHR directory provider revision changed during the bounded read")]
    RevisionDrift,
    #[error("BambooHR directory response was partial or exceeded the configured bounds")]
    PartialResponse,
    #[error("BambooHR directory response contained duplicate or conflicting records")]
    RecordMismatch,
    #[error("BambooHR directory evidence or proposal digest was tampered")]
    TamperedEvidence,
    #[error("BambooHR directory proposal is stale, duplicated, or outside the registration")]
    StaleProposal,
    #[error(
        "BambooHR directory recorded proposal is stale, duplicated, or outside the registration"
    )]
    StaleRecord,
    #[error("BambooHR directory read-back fence failed")]
    ReadBackFence,
    #[error("BambooHR directory registration transition is invalid")]
    InvalidRegistrationTransition,
    #[error("BambooHR Layer-1 authority boundary was violated")]
    AuthorityViolation,
}

pub type Result<T> = std::result::Result<T, BambooHrDirectoryResultError>;
