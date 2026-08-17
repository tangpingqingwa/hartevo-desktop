//! Bounded GitHub artifact-attestation listing seams.
//!
//! There is intentionally no GitHub SDK, HTTP client, App/OAuth resolver,
//! bundle downloader, deletion method, trust-root mutator, or raw response
//! representation in this Layer-1 provider. Transports return already-redacted
//! typed pages.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    API_REVISION, PROVIDER_ID, PROVIDER_VERSION,
    model::{
        GithubArtifactAttestationScope, GithubAttestationPage, ModelError, OpaquePageToken,
        PermissionSnapshot, PredicateType, RepositoryAccess, SubjectDigest, TransportProvenance,
        Version, canonical_digest,
    },
};

pub const LIST_ATTESTATIONS_ENDPOINT: &str = "/repos/{owner}/{repo}/attestations/{subject_digest}";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider definition is not the frozen GitHub artifact-attestation Layer-1 definition")]
    Frozen,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationProviderDefinition {
    pub provider_id: String,
    pub provider_version: Version,
    pub api_revision: String,
    pub provenance: TransportProvenance,
    pub permissions: PermissionSnapshot,
    pub api_digest: String,
    pub provider_digest: String,
}

impl GithubArtifactAttestationProviderDefinition {
    pub fn new(
        provider_version: Version,
        provenance: TransportProvenance,
        permissions: PermissionSnapshot,
    ) -> Result<Self, ProviderDefinitionError> {
        permissions.validate()?;
        let api_revision = API_REVISION.to_owned();
        if provider_version.to_string() != PROVIDER_VERSION {
            return Err(ProviderDefinitionError::Frozen);
        }
        let api_digest = canonical_digest(&(LIST_ATTESTATIONS_ENDPOINT, &api_revision));
        let mut value = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            api_revision,
            provenance,
            permissions,
            api_digest,
            provider_digest: String::new(),
        };
        value.provider_digest = value.computed_digest();
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        self.permissions.validate()?;
        if self.provider_id != PROVIDER_ID
            || self.provider_version.to_string() != PROVIDER_VERSION
            || self.api_revision != API_REVISION
            || self.api_digest
                != canonical_digest(&(LIST_ATTESTATIONS_ENDPOINT, &self.api_revision))
            || self.provider_digest != self.computed_digest()
        {
            Err(ProviderDefinitionError::Frozen)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn computed_digest(&self) -> String {
        canonical_digest(&(
            &self.provider_id,
            &self.provider_version,
            &self.api_revision,
            self.provenance,
            &self.permissions,
            &self.api_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubArtifactAttestationListRequest {
    pub installation_id: crate::InstallationId,
    pub organization: crate::GithubOrganization,
    pub repository: crate::GithubRepository,
    pub subject_digest: SubjectDigest,
    pub predicate_type: PredicateType,
    pub page: u32,
    pub page_size: u32,
    pub after: Option<OpaquePageToken>,
    pub request_digest: String,
}

impl GithubArtifactAttestationListRequest {
    pub fn from_scope(
        scope: &GithubArtifactAttestationScope,
        page: u32,
        page_size: u32,
        after: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page == 0 || page_size == 0 || page_size > crate::model::MAX_PAGE_SIZE {
            return Err(ModelError::InvalidScope);
        }
        let mut value = Self {
            installation_id: scope.installation_id.clone(),
            organization: scope.organization.clone(),
            repository: scope.repository.clone(),
            subject_digest: scope.subject_digest.clone(),
            predicate_type: scope.predicate_type.clone(),
            page,
            page_size,
            after,
            request_digest: String::new(),
        };
        value.request_digest = value.computed_digest();
        Ok(value)
    }

    #[must_use]
    pub fn computed_digest(&self) -> String {
        canonical_digest(&(
            &self.installation_id,
            &self.organization,
            &self.repository,
            &self.subject_digest,
            &self.predicate_type,
            self.page,
            self.page_size,
            &self.after,
        ))
    }

    #[must_use]
    pub const fn endpoint_template() -> &'static str {
        LIST_ATTESTATIONS_ENDPOINT
    }

    #[must_use]
    pub fn predicate_query(&self) -> &PredicateType {
        &self.predicate_type
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRequestRecord {
    ListAttestations,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Unprocessable,
    RateLimited,
    ServerFailure,
    Timeout,
    Truncated,
    TamperedEvidence,
    SubjectMismatch,
    PredicateMismatch,
    RepositoryMismatch,
    VisibilityMismatch,
    AccessLoss,
    SignerMismatch,
    CertificateMismatch,
    SignatureMismatch,
    TimestampMismatch,
    PaginationMismatch,
    BlockedEnv,
    Unknown,
}

impl ProviderErrorKind {
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::ServerFailure | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: String,
    pub truncated: bool,
    pub blocked_env: bool,
}

impl TransportError {
    #[must_use]
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            retryable: kind.retryable(),
            truncated: matches!(kind, ProviderErrorKind::Truncated),
            blocked_env: matches!(kind, ProviderErrorKind::BlockedEnv),
            kind,
            status_code,
            diagnostic_digest: crate::metadata_digest_bounded(diagnostic.as_ref()),
        }
    }

    #[must_use]
    pub fn http(status_code: u16, diagnostic: impl AsRef<[u8]>) -> Self {
        let kind = match status_code {
            400 => ProviderErrorKind::BadRequest,
            401 => ProviderErrorKind::Unauthenticated,
            403 => ProviderErrorKind::PermissionDenied,
            404 => ProviderErrorKind::NotFound,
            409 => ProviderErrorKind::Conflict,
            422 => ProviderErrorKind::Unprocessable,
            429 => ProviderErrorKind::RateLimited,
            500..=599 => ProviderErrorKind::ServerFailure,
            _ => ProviderErrorKind::Unknown,
        };
        Self::new(kind, Some(status_code), diagnostic)
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, b"timeout")
    }

    #[must_use]
    pub fn truncated() -> Self {
        Self::new(ProviderErrorKind::Truncated, None, b"response truncated")
    }

    #[must_use]
    pub fn tampered() -> Self {
        Self::new(
            ProviderErrorKind::TamperedEvidence,
            None,
            b"tampered evidence",
        )
    }

    #[must_use]
    pub fn blocked_env(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, diagnostic)
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self.kind,
            ProviderErrorKind::Unauthenticated
                | ProviderErrorKind::PermissionDenied
                | ProviderErrorKind::NotFound
                | ProviderErrorKind::AccessLoss
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReadScript {
    pub pages: VecDeque<Result<GithubAttestationPage, TransportError>>,
}

impl ReadScript {
    #[must_use]
    pub fn new(
        pages: impl IntoIterator<Item = Result<GithubAttestationPage, TransportError>>,
    ) -> Self {
        Self {
            pages: pages.into_iter().collect(),
        }
    }
}

pub trait GithubArtifactAttestationTransport: fmt::Debug {
    fn list_attestations(
        &mut self,
        request: &GithubArtifactAttestationListRequest,
    ) -> Result<GithubAttestationPage, TransportError>;
}

macro_rules! scripted_transport {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            script: ReadScript,
            calls: Vec<TransportRequestRecord>,
        }

        impl $name {
            #[must_use]
            pub fn new(script: ReadScript) -> Self {
                Self {
                    script,
                    calls: Vec::new(),
                }
            }

            #[must_use]
            pub fn calls(&self) -> &[TransportRequestRecord] {
                &self.calls
            }

            fn next_page(&mut self) -> Result<GithubAttestationPage, TransportError> {
                self.script
                    .pages
                    .pop_front()
                    .unwrap_or_else(|| Err(TransportError::blocked_env(b"script page absent")))
            }
        }

        impl GithubArtifactAttestationTransport for $name {
            fn list_attestations(
                &mut self,
                _request: &GithubArtifactAttestationListRequest,
            ) -> Result<GithubAttestationPage, TransportError> {
                self.calls.push(TransportRequestRecord::ListAttestations);
                self.next_page()
            }
        }
    };
}

scripted_transport!(FixtureGithubArtifactAttestationTransport);
scripted_transport!(RecordingGithubArtifactAttestationTransport);
scripted_transport!(LoopbackGithubArtifactAttestationTransport);

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvGithubArtifactAttestationTransport {
    calls: Vec<TransportRequestRecord>,
}

impl BlockedEnvGithubArtifactAttestationTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self { calls: Vec::new() }
    }

    #[must_use]
    pub fn calls(&self) -> &[TransportRequestRecord] {
        &self.calls
    }
}

impl GithubArtifactAttestationTransport for BlockedEnvGithubArtifactAttestationTransport {
    fn list_attestations(
        &mut self,
        _request: &GithubArtifactAttestationListRequest,
    ) -> Result<GithubAttestationPage, TransportError> {
        self.calls.push(TransportRequestRecord::ListAttestations);
        Err(TransportError::blocked_env(
            b"native GitHub App/OAuth resolution is unavailable",
        ))
    }
}

pub struct GithubArtifactAttestationProvider<T> {
    definition: GithubArtifactAttestationProviderDefinition,
    transport: T,
}

impl<T: fmt::Debug> fmt::Debug for GithubArtifactAttestationProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubArtifactAttestationProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: GithubArtifactAttestationTransport> GithubArtifactAttestationProvider<T> {
    pub fn new(
        transport: T,
        provider_version: Version,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_permissions(
            transport,
            provider_version,
            provenance,
            PermissionSnapshot::least_privilege(),
        )
    }

    pub fn with_permissions(
        transport: T,
        provider_version: Version,
        provenance: TransportProvenance,
        permissions: PermissionSnapshot,
    ) -> Result<Self, ProviderDefinitionError> {
        Ok(Self {
            definition: GithubArtifactAttestationProviderDefinition::new(
                provider_version,
                provenance,
                permissions,
            )?,
            transport,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GithubArtifactAttestationProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub const fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn list_attestations(
        &mut self,
        request: &GithubArtifactAttestationListRequest,
    ) -> Result<GithubAttestationPage, TransportError> {
        if request.request_digest != request.computed_digest() {
            return Err(TransportError::tampered());
        }
        self.transport.list_attestations(request)
    }
}

pub type FixtureTransport = FixtureGithubArtifactAttestationTransport;
pub type RecordingTransport = RecordingGithubArtifactAttestationTransport;
pub type LoopbackTransport = LoopbackGithubArtifactAttestationTransport;
pub type BlockedEnvTransport = BlockedEnvGithubArtifactAttestationTransport;

pub type ListAttestationsRequest = GithubArtifactAttestationListRequest;
pub type AttestationPage = GithubAttestationPage;
pub type AttestationRecord = crate::GithubAttestationRecord;
pub type GithubAttestationProviderError = TransportError;
pub type GithubArtifactAttestationAccess = RepositoryAccess;
