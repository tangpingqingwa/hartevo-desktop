//! Standalone Layer-1 WorkOS Directory Sync result evidence plugin.
//!
//! The crate is intentionally below kernel identity, Consent, Effect,
//! Receipt, Verification, and Outcome authority. It contains only bounded
//! typed read/proposal/record/read-back seams and test-only transports.

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
    MissionWorkOsDirectoryConsumer, MissionWorkOsDirectoryContext, WorkOsDirectoryAdoptionProposal,
};
pub use model::*;
pub use provider::{
    BlockedEnvWorkOsDirectoryTransport, ProviderError, ScriptedWorkOsDirectoryTransport,
    WorkOsDirectoryFixture, WorkOsDirectoryPage, WorkOsDirectoryPageRequest,
    WorkOsDirectoryProvider, WorkOsDirectoryTransport,
};
pub use service::{
    ReadBackVerification, RegistrationStatus, RegistrationTransitionEvidence,
    WorkOsDirectoryCapabilities, WorkOsDirectoryEvidence, WorkOsDirectoryRecordedProposal,
    WorkOsDirectoryRegistration, WorkOsDirectoryResultProposal, WorkOsDirectoryResultService,
};

pub const WORKOS_DIRECTORY_RESULT_SCHEMA_VERSION: &str =
    "hartevo.workos-directory-result.contract/v1";
pub const WORKOS_DIRECTORY_RESULT_CONTRACT_VERSION: &str = "workos-directory-result/v1";
pub const WORKOS_DIRECTORY_RESULT_PLUGIN_ID: &str = "hartevo.workos.directory-result";
pub const WORKOS_DIRECTORY_RESULT_PLUGIN_VERSION_TEXT: &str = "1.0.0";
pub const WORKOS_DIRECTORY_SERVICE_ID: &str = "hartevo.workos.directory.result";
pub const WORKOS_DIRECTORY_SERVICE_IMPLEMENTATION: &str = "WorkOsDirectoryResultService";
pub const WORKOS_DIRECTORY_PROVIDER_ID: &str = "workos.directory-sync.read";
pub const WORKOS_DIRECTORY_PROVIDER_IMPLEMENTATION: &str = "WorkOsDirectoryProvider";
pub const WORKOS_DIRECTORY_CONSUMER_ID: &str = "mission.workos-directory-result";
pub const WORKOS_DIRECTORY_CONSUMER_IMPLEMENTATION: &str = "MissionWorkOsDirectoryConsumer";
pub const WORKOS_DIRECTORY_API_BASE: &str = "https://api.workos.com";
pub const WORKOS_DIRECTORY_API_REVISION: &str = "workos-directory-sync-api-v1";
pub const WORKOS_DIRECTORY_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/workos-directory-result/workos-directory-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(WORKOS_DIRECTORY_CONTRACT_JSON)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WorkOsDirectoryResultError {
    #[error("WorkOS Directory result model validation failed: {0}")]
    Model(#[from] model::ModelError),
    #[error("WorkOS Directory provider failed: {0}")]
    Provider(#[from] provider::ProviderError),
    #[error("WorkOS Directory registration is not active")]
    RegistrationInactive,
    #[error("WorkOS Directory registration is revoked")]
    RegistrationRevoked,
    #[error("WorkOS Directory registration or scope digest drifted")]
    RegistrationDrift,
    #[error("WorkOS Directory SecretReference was revoked")]
    SecretReferenceRevoked,
    #[error("WorkOS Directory scope does not match the request")]
    ScopeMismatch,
    #[error("WorkOS Directory provider revision changed during the bounded read")]
    RevisionDrift,
    #[error("WorkOS Directory pagination cursor was replayed")]
    CursorReplay,
    #[error("WorkOS Directory pagination cursor expired")]
    CursorExpired,
    #[error("WorkOS Directory pagination ended without a complete bounded snapshot")]
    IncompletePagination,
    #[error("WorkOS Directory evidence exceeded the configured bounds")]
    BoundsExceeded,
    #[error("WorkOS Directory returned a duplicate or conflicting membership record")]
    MembershipMismatch,
    #[error("WorkOS Directory evidence or proposal digest was tampered")]
    TamperedEvidence,
    #[error("WorkOS Directory proposal is stale, duplicated, or outside the registration")]
    StaleProposal,
    #[error("WorkOS Directory recorded proposal is stale, duplicated, or outside the registration")]
    StaleRecord,
    #[error("WorkOS Directory read-back fence failed")]
    ReadBackFence,
    #[error("WorkOS Directory Layer-1 authority boundary was violated")]
    AuthorityViolation,
    #[error("WorkOS Directory registration transition is invalid")]
    InvalidRegistrationTransition,
}

pub type Result<T> = std::result::Result<T, WorkOsDirectoryResultError>;
