#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 TestRail governed test-run result plugin."]
//!
//! This crate is intentionally below Hartevo kernel authority.  It provides a
//! typed, bounded TestRail read surface plus redacted evidence, a canonical
//! non-mutating Mission proposal, and a local recording fence.  It cannot
//! resolve credentials, create or update TestRail data, claim native HTTPS or
//! Connected evidence, or adopt a Work Product/Outcome.

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::*;
pub use model::*;
pub use provider::*;
pub use service::*;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.testrail-test-result-contract/v1";
pub const CONTRACT_VERSION: &str = "testrail-test-result-01-layer-1/v1";
pub const SERVICE_ID: &str = "testrail.test-result.read";
pub const PROVIDER_ID: &str = "testrail.test-result.recording";
pub const CONSUMER_ID: &str = "mission.testrail-test-result.consumer";
pub const API_REVISION: &str = "testrail-api-v2-read-1";
pub const PLUGIN_VERSION: Version = Version::new(0, 1, 0);
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.testrail-test-result-contract/v1|layer=1|service=testrail.test-result.read|provider=testrail.test-result.recording|consumer=mission.testrail-test-result.consumer";

pub const MAX_PAGE_SIZE: usize = 250;
pub const MAX_PAGES: usize = 32;
pub const MAX_ITEMS: usize = 8_192;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_HOST_BYTES: usize = 256;
pub const MAX_DEFECTS: usize = 32;
pub const MAX_DEFECT_BYTES: usize = 256;
pub const MAX_COMMENT_BYTES: usize = 64 * 1024;
pub const MAX_VERSION_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorClass {
    Input,
    Registration,
    Transport,
    Provider,
    Service,
    Consumer,
    Integrity,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TestRailError {
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("unsupported TestRail API version")]
    UnsupportedApiVersion,
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid opaque SecretReference")]
    InvalidSecretReference,
    #[error("permission snapshot is not read-only or is incomplete")]
    PermissionDrift,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration does not match the requested scope")]
    RegistrationMismatch,
    #[error("registration binding digest was tampered")]
    RegistrationTampered,
    #[error("registration was already terminal")]
    RegistrationAlreadyTerminal,
    #[error("scope host drift")]
    HostDrift,
    #[error("scope project drift")]
    ProjectDrift,
    #[error("scope suite drift")]
    SuiteDrift,
    #[error("scope section drift")]
    SectionDrift,
    #[error("scope run drift")]
    RunDrift,
    #[error("scope run revision or timestamp drift")]
    RunRevisionDrift,
    #[error("scope test drift")]
    TestDrift,
    #[error("scope result drift")]
    ResultDrift,
    #[error("scope status drift")]
    StatusDrift,
    #[error("scope defect drift")]
    DefectDrift,
    #[error("scope source or release drift")]
    SourceDrift,
    #[error("scope Mission drift")]
    MissionDrift,
    #[error("scope Project drift")]
    HartevoProjectDrift,
    #[error("scope Work Product drift")]
    WorkProductDrift,
    #[error("provider/API drift")]
    ProviderDrift,
    #[error("malformed or partial provider response")]
    MalformedResponse,
    #[error("provider response was partial")]
    PartialResponse,
    #[error("response exceeded the byte bound")]
    ResponseTooLarge,
    #[error("response was truncated")]
    ResponseTruncated,
    #[error("pagination offset was repeated or moved backwards")]
    PaginationLoop,
    #[error("pagination exceeded the page or item bound")]
    PaginationLimit,
    #[error("provider status is not in the registration allowlist")]
    StatusNotAllowlisted,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("transport error: {0}")]
    Transport(TransportError),
    #[error("proposal is stale for the current Mission revision")]
    StaleMissionRevision,
    #[error("proposal or evidence fingerprint was tampered")]
    TamperDetected,
    #[error("proposal fingerprint is a duplicate")]
    DuplicateProposal,
    #[error("recording fingerprint is a duplicate with different content")]
    DuplicateRecording,
    #[error("recording proposal is not bound to this registration")]
    RecordingMismatch,
    #[error("recording proposal cannot claim adoption")]
    AdoptionAuthorityDenied,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("HTTP 401 unauthorized")]
    Unauthorized,
    #[error("HTTP 403 forbidden")]
    Forbidden,
    #[error("HTTP 404 not found")]
    NotFound,
    #[error("HTTP 409 conflict")]
    Conflict,
    #[error("HTTP 429 rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("HTTP server error {0}")]
    ServerError(u16),
    #[error("HTTP status {0}")]
    HttpStatus(u16),
    #[error("request timed out")]
    Timeout,
    #[error("environment is blocked; no native transport is available")]
    BlockedEnv,
    #[error("transport returned a malformed response")]
    MalformedResponse,
    #[error("transport returned a partial response")]
    PartialResponse,
    #[error("transport returned a repeated response")]
    RepeatedResponse,
    #[error("transport received an unexpected request")]
    UnexpectedRequest,
    #[error("transport payload digest did not match its recording")]
    ByteDigestMismatch,
}

impl TransportError {
    pub const fn from_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => Self::ServerError(status),
            other => Self::HttpStatus(other),
        }
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}
