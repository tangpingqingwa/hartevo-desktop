//! Bounded provider seams for ECR `DescribeImages` and
//! `DescribeImageScanFindings`.

use std::{collections::VecDeque, fmt};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AccountId, AwsRegion, Digest, EcrImageDescriptor, EcrImageScanScope, EcrOperation,
    FindingRevision, ImageDigest, InspectorFindingRevision, MAX_CURSOR_BYTES, MAX_FINDINGS,
    MAX_PAGES, MAX_RESPONSE_BYTES, MAX_SEVERITY_ENTRIES, ModelError, PAGE_SIZE, PermissionAction,
    RedactedFinding, RegistryId, Revision, ScanLifecycle, ScanRevision, ScanType, Severity,
    SeverityCount, TransportProvenance, serialized_digest,
};

pub const AWS_ECR_PROVIDER_ID: &str = "aws.ecr.image-scan";
pub const AWS_ECR_PROVIDER_VERSION: &str = "1.0.0";
pub const AWS_ECR_PROVIDER_SCHEMA: &str = "aws-ecr-image-scan-read-r1";
pub const AWS_ECR_API_REVISION: &str = AWS_ECR_PROVIDER_SCHEMA;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("ECR provider definition drifted from the Layer-1 contract")]
    DefinitionDrift,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("ECR request is invalid")]
    InvalidRequest,
    #[error("ECR credentials are unauthorized")]
    Unauthorized,
    #[error("ECR permission was denied")]
    Forbidden,
    #[error("ECR image or repository was not found")]
    NotFound,
    #[error("ECR request was rate limited")]
    RateLimited,
    #[error("ECR provider returned a server failure")]
    ServerFailure,
    #[error("ECR transport timed out")]
    Timeout,
    #[error("ECR transport is blocked in this environment")]
    BlockedEnv,
    #[error("ECR response was malformed")]
    MalformedResponse,
    #[error("ECR response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("ECR response scan revision is stale")]
    StaleRevision,
    #[error("ECR response failed its typed integrity fence")]
    Tampered,
}

impl TransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited => Some(429),
            Self::ServerFailure => Some(500),
            Self::Timeout
            | Self::BlockedEnv
            | Self::MalformedResponse
            | Self::ResponseTooLarge
            | Self::StaleRevision
            | Self::Tampered => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden | Self::NotFound)
    }

    #[must_use]
    pub const fn is_stale(&self) -> bool {
        matches!(self, Self::StaleRevision)
    }

    #[must_use]
    pub const fn is_tampered(&self) -> bool {
        matches!(self, Self::Tampered)
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::ServerFailure => "server_failure",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "blocked_env",
            Self::MalformedResponse => "malformed_response",
            Self::ResponseTooLarge => "response_too_large",
            Self::StaleRevision => "stale_revision",
            Self::Tampered => "tampered",
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.kind())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EcrProviderError {
    #[error("ECR provider definition drifted")]
    DefinitionDrift,
    #[error("ECR provider request is invalid")]
    InvalidRequest,
    #[error("ECR provider response is invalid")]
    InvalidResponse,
    #[error("ECR provider response exceeded its byte bound")]
    ResponseTooLarge,
    #[error("ECR provider page did not match its request")]
    PageMismatch,
    #[error("ECR provider scope did not match the request")]
    ScopeMismatch,
    #[error("ECR provider response is stale")]
    StaleRevision,
    #[error("ECR provider response was tampered")]
    Tampered,
    #[error(transparent)]
    Transport(#[from] TransportError),
}

impl EcrProviderError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Transport(error) => error.status_code(),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Transport(error) if error.is_access_loss())
    }

    #[must_use]
    pub const fn is_stale(&self) -> bool {
        match self {
            Self::StaleRevision => true,
            Self::Transport(error) => error.is_stale(),
            _ => false,
        }
    }

    #[must_use]
    pub const fn is_tampered(&self) -> bool {
        match self {
            Self::Tampered | Self::PageMismatch => true,
            Self::Transport(error) => error.is_tampered(),
            _ => false,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            Self::Transport(error) => error.digest(),
            Self::DefinitionDrift => Digest::from_text("definition_drift"),
            Self::InvalidRequest => Digest::from_text("invalid_request"),
            Self::InvalidResponse => Digest::from_text("invalid_response"),
            Self::ResponseTooLarge => Digest::from_text("response_too_large"),
            Self::PageMismatch => Digest::from_text("page_mismatch"),
            Self::ScopeMismatch => Digest::from_text("scope_mismatch"),
            Self::StaleRevision => Digest::from_text("stale_revision"),
            Self::Tampered => Digest::from_text("tampered"),
        }
    }
}

pub type EcrProviderErrorKind = TransportError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub allowlisted_operations: Vec<EcrOperation>,
    pub permissions: Vec<PermissionAction>,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_findings: usize,
}

impl EcrProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        let definition = Self {
            id: AWS_ECR_PROVIDER_ID.to_owned(),
            version: AWS_ECR_PROVIDER_VERSION.to_owned(),
            api_revision: AWS_ECR_API_REVISION.to_owned(),
            allowlisted_operations: vec![
                EcrOperation::DescribeImages,
                EcrOperation::DescribeImageScanFindings,
            ],
            permissions: vec![
                PermissionAction::EcrDescribeImages,
                PermissionAction::EcrDescribeImageScanFindings,
            ],
            provenance,
            read_only: true,
            native: false,
            connected: false,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: MAX_PAGES,
            page_size: PAGE_SIZE,
            max_findings: MAX_FINDINGS,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self {
            id: AWS_ECR_PROVIDER_ID.to_owned(),
            version: AWS_ECR_PROVIDER_VERSION.to_owned(),
            api_revision: AWS_ECR_API_REVISION.to_owned(),
            allowlisted_operations: vec![
                EcrOperation::DescribeImages,
                EcrOperation::DescribeImageScanFindings,
            ],
            permissions: vec![
                PermissionAction::EcrDescribeImages,
                PermissionAction::EcrDescribeImageScanFindings,
            ],
            provenance: self.provenance,
            read_only: true,
            native: false,
            connected: false,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: MAX_PAGES,
            page_size: PAGE_SIZE,
            max_findings: MAX_FINDINGS,
        };
        if self != &expected {
            Err(ProviderDefinitionError::DefinitionDrift)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        serialized_digest(self)
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }
}

pub type EcrProviderIdentity = EcrProviderDefinition;

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    raw: String,
    binding_digest: Digest,
}

impl OpaquePageToken {
    pub fn new(raw: impl Into<String>, binding_digest: Digest) -> Result<Self, ModelError> {
        let raw = raw.into();
        if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES || raw.chars().any(char::is_control) {
            return Err(ModelError::Invalid {
                field: "opaque ECR pagination token",
            });
        }
        if Digest::parse(
            binding_digest.as_str().to_owned(),
            "pagination binding digest",
        )
        .is_err()
        {
            return Err(ModelError::InvalidDigest {
                field: "pagination binding digest",
            });
        }
        Ok(Self {
            raw,
            binding_digest,
        })
    }

    #[must_use]
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "ecr-opaque-page-token/v1",
            [&self.raw, self.binding_digest.as_str()],
        )
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("OpaquePageToken", 1)?;
        value.serialize_field("opaque", &true)?;
        value.end()
    }
}

pub type OpaqueCursor = OpaquePageToken;
pub type EcrOpaquePageToken = OpaquePageToken;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeImagesRequest {
    pub registry: RegistryId,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub repository: crate::RepositoryName,
    pub image_digest: ImageDigest,
    pub scan_type: ScanType,
    pub scan_revision: Revision,
    pub inspector_finding_revision: Revision,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl DescribeImagesRequest {
    pub fn new(
        scope: &EcrImageScanScope,
        page_size: u16,
        max_pages: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "DescribeImages pagination bound",
            });
        }
        let binding_digest =
            pagination_binding_digest(scope, EcrOperation::DescribeImages, page_size, max_pages);
        if page_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &binding_digest)
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeImages pagination token",
            });
        }
        let request_material = RequestDigestMaterial {
            operation: EcrOperation::DescribeImages,
            registry: scope.registry(),
            account_id: scope.account_id(),
            region: scope.region(),
            repository: scope.repository(),
            image_digest: scope.image_digest(),
            scan_type: scope.scan_type(),
            scan_revision: scope.scan_revision(),
            finding_revision: scope.inspector_finding_revision(),
            page_size,
            max_pages,
            page_token_digest: page_token.as_ref().map(OpaquePageToken::digest),
            scope_digest: scope.scope_digest(),
        };
        let request_digest = serialized_digest(&request_material);
        Ok(Self {
            registry: scope.registry().clone(),
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            repository: scope.repository().clone(),
            image_digest: scope.image_digest().clone(),
            scan_type: scope.scan_type(),
            scan_revision: scope.scan_revision(),
            inspector_finding_revision: scope.inspector_finding_revision(),
            scope_digest: scope.scope_digest().clone(),
            page_size,
            max_pages,
            page_token,
            request_digest,
        })
    }

    #[must_use]
    pub fn pagination_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "ecr-pagination-binding/v1",
            [
                EcrOperation::DescribeImages.target(),
                self.registry.as_str(),
                self.account_id.as_str(),
                self.region.as_str(),
                self.repository.as_str(),
                self.image_digest.as_str(),
                self.scan_type.as_str(),
                self.scan_revision.get().to_string().as_str(),
                self.inspector_finding_revision.get().to_string().as_str(),
                self.page_size.to_string().as_str(),
                self.max_pages.to_string().as_str(),
            ],
        )
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn with_page_token(&self, token: OpaquePageToken) -> Result<Self, ModelError> {
        if token.binding_digest() != &self.pagination_binding_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeImages pagination token",
            });
        }
        let request_digest = serialized_digest(&RequestDigestMaterial {
            operation: EcrOperation::DescribeImages,
            registry: &self.registry,
            account_id: &self.account_id,
            region: &self.region,
            repository: &self.repository,
            image_digest: &self.image_digest,
            scan_type: self.scan_type,
            scan_revision: self.scan_revision,
            finding_revision: self.inspector_finding_revision,
            page_size: self.page_size,
            max_pages: self.max_pages,
            page_token_digest: Some(token.digest()),
            scope_digest: &self.scope_digest,
        });
        let mut next = self.clone();
        next.page_token = Some(token);
        next.request_digest = request_digest;
        Ok(next)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeImageScanFindingsRequest {
    pub registry: crate::RegistryId,
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub repository: crate::RepositoryName,
    pub image_digest: ImageDigest,
    pub scan_type: ScanType,
    pub scan_revision: Revision,
    pub inspector_finding_revision: Revision,
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl DescribeImageScanFindingsRequest {
    pub fn new(
        scope: &EcrImageScanScope,
        page_size: u16,
        max_pages: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "DescribeImageScanFindings pagination bound",
            });
        }
        let binding_digest = pagination_binding_digest(
            scope,
            EcrOperation::DescribeImageScanFindings,
            page_size,
            max_pages,
        );
        if page_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &binding_digest)
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeImageScanFindings pagination token",
            });
        }
        let request_material = RequestDigestMaterial {
            operation: EcrOperation::DescribeImageScanFindings,
            registry: scope.registry(),
            account_id: scope.account_id(),
            region: scope.region(),
            repository: scope.repository(),
            image_digest: scope.image_digest(),
            scan_type: scope.scan_type(),
            scan_revision: scope.scan_revision(),
            finding_revision: scope.inspector_finding_revision(),
            page_size,
            max_pages,
            page_token_digest: page_token.as_ref().map(OpaquePageToken::digest),
            scope_digest: scope.scope_digest(),
        };
        let request_digest = serialized_digest(&request_material);
        Ok(Self {
            registry: scope.registry().clone(),
            account_id: scope.account_id().clone(),
            region: scope.region().clone(),
            repository: scope.repository().clone(),
            image_digest: scope.image_digest().clone(),
            scan_type: scope.scan_type(),
            scan_revision: scope.scan_revision(),
            inspector_finding_revision: scope.inspector_finding_revision(),
            scope_digest: scope.scope_digest().clone(),
            page_size,
            max_pages,
            page_token,
            request_digest,
        })
    }

    #[must_use]
    pub fn pagination_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "ecr-pagination-binding/v1",
            [
                EcrOperation::DescribeImageScanFindings.target(),
                self.registry.as_str(),
                self.account_id.as_str(),
                self.region.as_str(),
                self.repository.as_str(),
                self.image_digest.as_str(),
                self.scan_type.as_str(),
                self.scan_revision.get().to_string().as_str(),
                self.inspector_finding_revision.get().to_string().as_str(),
                self.page_size.to_string().as_str(),
                self.max_pages.to_string().as_str(),
            ],
        )
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn with_page_token(&self, token: OpaquePageToken) -> Result<Self, ModelError> {
        if token.binding_digest() != &self.pagination_binding_digest() {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeImageScanFindings pagination token",
            });
        }
        let request_digest = serialized_digest(
            &(RequestDigestMaterial {
                operation: EcrOperation::DescribeImageScanFindings,
                registry: &self.registry,
                account_id: &self.account_id,
                region: &self.region,
                repository: &self.repository,
                image_digest: &self.image_digest,
                scan_type: self.scan_type,
                scan_revision: self.scan_revision,
                finding_revision: self.inspector_finding_revision,
                page_size: self.page_size,
                max_pages: self.max_pages,
                page_token_digest: Some(token.digest()),
                scope_digest: &self.scope_digest,
            }),
        );
        Ok(Self {
            registry: self.registry.clone(),
            account_id: self.account_id.clone(),
            region: self.region.clone(),
            repository: self.repository.clone(),
            image_digest: self.image_digest.clone(),
            scan_type: self.scan_type,
            scan_revision: self.scan_revision,
            inspector_finding_revision: self.inspector_finding_revision,
            scope_digest: self.scope_digest.clone(),
            page_size: self.page_size,
            max_pages: self.max_pages,
            page_token: Some(token),
            request_digest,
        })
    }
}

pub type EcrDescribeImagesRequest = DescribeImagesRequest;
pub type EcrDescribeImageScanFindingsRequest = DescribeImageScanFindingsRequest;

#[derive(Serialize)]
struct RequestDigestMaterial<'a> {
    operation: EcrOperation,
    registry: &'a crate::RegistryId,
    account_id: &'a AccountId,
    region: &'a AwsRegion,
    repository: &'a crate::RepositoryName,
    image_digest: &'a ImageDigest,
    scan_type: ScanType,
    scan_revision: Revision,
    finding_revision: FindingRevision,
    page_size: u16,
    max_pages: u16,
    page_token_digest: Option<Digest>,
    scope_digest: &'a Digest,
}

fn pagination_binding_digest(
    scope: &EcrImageScanScope,
    operation: EcrOperation,
    page_size: u16,
    max_pages: u16,
) -> Digest {
    Digest::from_parts(
        "ecr-pagination-binding/v1",
        [
            operation.target(),
            scope.registry().as_str(),
            scope.account_id().as_str(),
            scope.region().as_str(),
            scope.repository().as_str(),
            scope.image_digest().as_str(),
            scope.scan_type().as_str(),
            scope.scan_revision().get().to_string().as_str(),
            scope
                .inspector_finding_revision()
                .get()
                .to_string()
                .as_str(),
            page_size.to_string().as_str(),
            max_pages.to_string().as_str(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeImagesPage {
    pub request_digest: Digest,
    pub page_number: u16,
    pub images: Vec<EcrImageDescriptor>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl DescribeImagesPage {
    pub fn new(
        request: &DescribeImagesRequest,
        page_number: u16,
        images: Vec<EcrImageDescriptor>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || page_number > request.max_pages
            || images.len() > usize::from(request.page_size)
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::Invalid {
                field: "DescribeImages page bound",
            });
        }
        if next_page_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeImages next page token",
            });
        }
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(ModelError::Invalid {
                field: "ECR provider revision",
            });
        }
        let page_digest = serialized_digest(&ImagesPageDigestMaterial {
            request_digest: request.request_digest(),
            page_number,
            images: &images,
            next_page_digest: next_page_token.as_ref().map(OpaquePageToken::digest),
            response_bytes,
            provider_revision: &provider_revision,
        });
        Ok(Self {
            request_digest: request.request_digest().clone(),
            page_number,
            images,
            next_page_token,
            response_bytes,
            provider_revision,
            page_digest,
        })
    }

    pub fn validate_for(&self, request: &DescribeImagesRequest) -> Result<(), EcrProviderError> {
        if self.request_digest != *request.request_digest()
            || self.page_number == 0
            || self.page_number > request.max_pages
            || self.images.len() > usize::from(request.page_size)
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self
                .next_page_token
                .as_ref()
                .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
            || self.page_digest
                != serialized_digest(&ImagesPageDigestMaterial {
                    request_digest: &self.request_digest,
                    page_number: self.page_number,
                    images: &self.images,
                    next_page_digest: self.next_page_token.as_ref().map(OpaquePageToken::digest),
                    response_bytes: self.response_bytes,
                    provider_revision: &self.provider_revision,
                })
        {
            return Err(EcrProviderError::PageMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ImagesPageDigestMaterial<'a> {
    request_digest: &'a Digest,
    page_number: u16,
    images: &'a [EcrImageDescriptor],
    next_page_digest: Option<Digest>,
    response_bytes: usize,
    provider_revision: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescribeImageScanFindingsPage {
    pub request_digest: Digest,
    pub page_number: u16,
    pub lifecycle: ScanLifecycle,
    pub scan_revision: ScanRevision,
    pub inspector_finding_revision: InspectorFindingRevision,
    pub severity_counts: Vec<SeverityCount>,
    pub findings: Vec<RedactedFinding>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub provider_revision: String,
    pub page_digest: Digest,
}

impl DescribeImageScanFindingsPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &DescribeImageScanFindingsRequest,
        page_number: u16,
        lifecycle: ScanLifecycle,
        scan_revision: ScanRevision,
        inspector_finding_revision: InspectorFindingRevision,
        severity_counts: Vec<SeverityCount>,
        findings: Vec<RedactedFinding>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: usize,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        validate_findings_page(
            request,
            page_number,
            &severity_counts,
            &findings,
            next_page_token.as_ref(),
            response_bytes,
        )?;
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(ModelError::Invalid {
                field: "ECR provider revision",
            });
        }
        let page_digest = serialized_digest(&FindingsPageDigestMaterial {
            request_digest: request.request_digest(),
            page_number,
            lifecycle,
            scan_revision,
            inspector_finding_revision,
            severity_counts: &severity_counts,
            findings: &findings,
            next_page_digest: next_page_token.as_ref().map(OpaquePageToken::digest),
            response_bytes,
            provider_revision: &provider_revision,
        });
        Ok(Self {
            request_digest: request.request_digest().clone(),
            page_number,
            lifecycle,
            scan_revision,
            inspector_finding_revision,
            severity_counts,
            findings,
            next_page_token,
            response_bytes,
            provider_revision,
            page_digest,
        })
    }

    pub fn validate_for(
        &self,
        request: &DescribeImageScanFindingsRequest,
    ) -> Result<(), EcrProviderError> {
        validate_findings_page(
            request,
            self.page_number,
            &self.severity_counts,
            &self.findings,
            self.next_page_token.as_ref(),
            self.response_bytes,
        )
        .map_err(|_| EcrProviderError::PageMismatch)?;
        if self.request_digest != *request.request_digest()
            || self.page_digest
                != serialized_digest(&FindingsPageDigestMaterial {
                    request_digest: &self.request_digest,
                    page_number: self.page_number,
                    lifecycle: self.lifecycle,
                    scan_revision: self.scan_revision,
                    inspector_finding_revision: self.inspector_finding_revision,
                    severity_counts: &self.severity_counts,
                    findings: &self.findings,
                    next_page_digest: self.next_page_token.as_ref().map(OpaquePageToken::digest),
                    response_bytes: self.response_bytes,
                    provider_revision: &self.provider_revision,
                })
        {
            return Err(EcrProviderError::PageMismatch);
        }
        Ok(())
    }
}

fn validate_findings_page(
    request: &DescribeImageScanFindingsRequest,
    page_number: u16,
    severity_counts: &[SeverityCount],
    findings: &[RedactedFinding],
    next_page_token: Option<&OpaquePageToken>,
    response_bytes: usize,
) -> Result<(), ModelError> {
    if page_number == 0
        || page_number > request.max_pages
        || findings.len() > usize::from(request.page_size)
        || findings.len() > MAX_FINDINGS
        || severity_counts.len() > MAX_SEVERITY_ENTRIES
        || response_bytes > MAX_RESPONSE_BYTES
        || next_page_token
            .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
        || findings.iter().any(|finding| finding.validate().is_err())
    {
        return Err(ModelError::Invalid {
            field: "DescribeImageScanFindings page bound",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    if severity_counts
        .iter()
        .any(|entry| !seen.insert(entry.severity))
    {
        return Err(ModelError::Duplicate {
            field: "severity count",
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct FindingsPageDigestMaterial<'a> {
    request_digest: &'a Digest,
    page_number: u16,
    lifecycle: ScanLifecycle,
    scan_revision: ScanRevision,
    inspector_finding_revision: InspectorFindingRevision,
    severity_counts: &'a [SeverityCount],
    findings: &'a [RedactedFinding],
    next_page_digest: Option<Digest>,
    response_bytes: usize,
    provider_revision: &'a str,
}

pub trait EcrTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_images(
        &mut self,
        request: &DescribeImagesRequest,
    ) -> Result<DescribeImagesPage, TransportError>;

    fn describe_image_scan_findings(
        &mut self,
        request: &DescribeImageScanFindingsRequest,
    ) -> Result<DescribeImageScanFindingsPage, TransportError>;
}

pub type EcrImageScanTransport = dyn EcrTransport;

#[derive(Clone, Debug)]
pub struct EcrProvider<T: EcrTransport> {
    definition: EcrProviderDefinition,
    transport: T,
}

impl<T: EcrTransport> EcrProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition = EcrProviderDefinition::new(transport.provenance())?;
        Ok(Self {
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &EcrProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_images(
        &mut self,
        request: &DescribeImagesRequest,
    ) -> Result<DescribeImagesPage, EcrProviderError> {
        self.definition
            .validate()
            .map_err(|_| EcrProviderError::DefinitionDrift)?;
        validate_images_request(request).map_err(|_| EcrProviderError::InvalidRequest)?;
        let page = self.transport.describe_images(request)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn describe_image_scan_findings(
        &mut self,
        request: &DescribeImageScanFindingsRequest,
    ) -> Result<DescribeImageScanFindingsPage, EcrProviderError> {
        self.definition
            .validate()
            .map_err(|_| EcrProviderError::DefinitionDrift)?;
        validate_findings_request(request).map_err(|_| EcrProviderError::InvalidRequest)?;
        let page = self.transport.describe_image_scan_findings(request)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn parse_describe_images_page(
        request: &DescribeImagesRequest,
        page_number: u16,
        body: &[u8],
    ) -> Result<DescribeImagesPage, EcrProviderError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(EcrProviderError::ResponseTooLarge);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| EcrProviderError::InvalidResponse)?;
        let image_details = value
            .get("imageDetails")
            .and_then(Value::as_array)
            .ok_or(EcrProviderError::InvalidResponse)?;
        let mut images = Vec::new();
        for image in image_details {
            let object = image.as_object().ok_or(EcrProviderError::InvalidResponse)?;
            if let Some(registry_id) = object.get("registryId").and_then(Value::as_str)
                && registry_id != request.account_id.as_str()
            {
                return Err(EcrProviderError::ScopeMismatch);
            }
            if let Some(repository) = object.get("repositoryName").and_then(Value::as_str)
                && repository != request.repository.as_str()
            {
                return Err(EcrProviderError::ScopeMismatch);
            }
            let digest = object
                .get("imageDigest")
                .and_then(Value::as_str)
                .ok_or(EcrProviderError::InvalidResponse)?;
            images.push(
                EcrImageDescriptor::from_digest(digest)
                    .map_err(|_| EcrProviderError::InvalidResponse)?,
            );
        }
        let next = parse_next_token(&value, request.pagination_binding_digest())?;
        DescribeImagesPage::new(
            request,
            page_number,
            images,
            next,
            body.len(),
            AWS_ECR_API_REVISION,
        )
        .map_err(|_| EcrProviderError::InvalidResponse)
    }

    pub fn parse_describe_image_scan_findings_page(
        request: &DescribeImageScanFindingsRequest,
        page_number: u16,
        body: &[u8],
    ) -> Result<DescribeImageScanFindingsPage, EcrProviderError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(EcrProviderError::ResponseTooLarge);
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| EcrProviderError::InvalidResponse)?;
        let findings_container = value
            .get("imageScanFindings")
            .and_then(Value::as_object)
            .ok_or(EcrProviderError::InvalidResponse)?;
        if let Some(registry_id) = value.get("registryId").and_then(Value::as_str)
            && registry_id != request.account_id.as_str()
        {
            return Err(EcrProviderError::ScopeMismatch);
        }
        if let Some(repository) = value.get("repositoryName").and_then(Value::as_str)
            && repository != request.repository.as_str()
        {
            return Err(EcrProviderError::ScopeMismatch);
        }
        if let Some(image_id) = value.get("imageId") {
            let image_id = image_id
                .as_object()
                .ok_or(EcrProviderError::InvalidResponse)?;
            if let Some(image_digest) = image_id.get("imageDigest").and_then(Value::as_str)
                && image_digest != request.image_digest.as_str()
            {
                return Err(EcrProviderError::ScopeMismatch);
            }
        }
        let status_object = value
            .get("imageScanStatus")
            .and_then(Value::as_object)
            .or_else(|| {
                findings_container
                    .get("imageScanStatus")
                    .and_then(Value::as_object)
            });
        let lifecycle = status_object
            .and_then(|object| object.get("status"))
            .and_then(Value::as_str)
            .map_or(ScanLifecycle::Unknown, ScanLifecycle::parse);
        let severity_counts = parse_severity_counts(findings_container)?;
        let findings = parse_findings(findings_container)?;
        let scan_revision = parse_revision(
            findings_container
                .get("scanRevision")
                .or_else(|| value.get("scanRevision")),
            request.scan_revision,
        )?;
        let inspector_finding_revision = parse_revision(
            findings_container
                .get("findingRevision")
                .or_else(|| findings_container.get("inspectorFindingRevision"))
                .or_else(|| value.get("findingRevision")),
            request.inspector_finding_revision,
        )?;
        let next = parse_next_token(&value, request.pagination_binding_digest())?;
        DescribeImageScanFindingsPage::new(
            request,
            page_number,
            lifecycle,
            scan_revision,
            inspector_finding_revision,
            severity_counts,
            findings,
            next,
            body.len(),
            AWS_ECR_API_REVISION,
        )
        .map_err(|_| EcrProviderError::InvalidResponse)
    }
}

pub type EcrImageScanProvider<T> = EcrProvider<T>;

fn validate_images_request(request: &DescribeImagesRequest) -> Result<(), ModelError> {
    if request.page_size == 0
        || request.page_size > PAGE_SIZE
        || request.max_pages == 0
        || request.max_pages > MAX_PAGES
        || request
            .page_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
    {
        Err(ModelError::Invalid {
            field: "DescribeImages request",
        })
    } else {
        Ok(())
    }
}

fn validate_findings_request(request: &DescribeImageScanFindingsRequest) -> Result<(), ModelError> {
    if request.page_size == 0
        || request.page_size > PAGE_SIZE
        || request.max_pages == 0
        || request.max_pages > MAX_PAGES
        || request
            .page_token
            .as_ref()
            .is_some_and(|token| token.binding_digest() != &request.pagination_binding_digest())
    {
        Err(ModelError::Invalid {
            field: "DescribeImageScanFindings request",
        })
    } else {
        Ok(())
    }
}

fn parse_next_token(
    value: &Value,
    binding_digest: Digest,
) -> Result<Option<OpaquePageToken>, EcrProviderError> {
    match value.get("nextToken") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(token)) => OpaquePageToken::new(token, binding_digest)
            .map(Some)
            .map_err(|_| EcrProviderError::InvalidResponse),
        Some(_) => Err(EcrProviderError::InvalidResponse),
    }
}

fn parse_revision(value: Option<&Value>, fallback: Revision) -> Result<Revision, EcrProviderError> {
    let Some(value) = value else {
        return Ok(fallback);
    };
    let number = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        .ok_or(EcrProviderError::InvalidResponse)?;
    Revision::new(number).map_err(|_| EcrProviderError::InvalidResponse)
}

fn parse_severity_counts(
    container: &serde_json::Map<String, Value>,
) -> Result<Vec<SeverityCount>, EcrProviderError> {
    let Some(counts) = container.get("findingSeverityCounts") else {
        return Ok(Vec::new());
    };
    let counts = counts
        .as_object()
        .ok_or(EcrProviderError::InvalidResponse)?;
    if counts.len() > MAX_SEVERITY_ENTRIES {
        return Err(EcrProviderError::InvalidResponse);
    }
    let mut result = Vec::with_capacity(counts.len());
    for (severity, count) in counts {
        let count = count.as_u64().ok_or(EcrProviderError::InvalidResponse)?;
        result.push(SeverityCount::new(Severity::parse(severity), count));
    }
    result.sort_by_key(|entry| entry.severity);
    Ok(result)
}

fn parse_findings(
    container: &serde_json::Map<String, Value>,
) -> Result<Vec<RedactedFinding>, EcrProviderError> {
    let Some(findings) = container
        .get("findings")
        .filter(|value| !value.is_null())
        .or_else(|| container.get("enhancedFindings"))
    else {
        return Ok(Vec::new());
    };
    let findings = findings
        .as_array()
        .ok_or(EcrProviderError::InvalidResponse)?;
    if findings.len() > MAX_FINDINGS {
        return Err(EcrProviderError::InvalidResponse);
    }
    let mut result = Vec::with_capacity(findings.len());
    for finding in findings {
        let object = finding
            .as_object()
            .ok_or(EcrProviderError::InvalidResponse)?;
        let severity = object
            .get("severity")
            .and_then(Value::as_str)
            .map_or(Severity::Unknown, Severity::parse);
        let package_details = object
            .get("packageVulnerabilityDetails")
            .and_then(Value::as_object);
        let cve = package_details
            .and_then(|details| details.get("vulnerabilityId"))
            .and_then(Value::as_str)
            .or_else(|| attribute_value(object, "cve"))
            .or_else(|| object.get("name").and_then(Value::as_str));
        let package = package_details
            .and_then(|details| details.get("vulnerablePackages"))
            .and_then(Value::as_array)
            .and_then(|packages| packages.first())
            .and_then(Value::as_object);
        let package_name = package
            .and_then(|package| package.get("name"))
            .and_then(Value::as_str)
            .or_else(|| attribute_value(object, "package_name"));
        let installed_version = package
            .and_then(|package| package.get("version"))
            .and_then(Value::as_str)
            .or_else(|| attribute_value(object, "package_version"));
        let fixed_version = package
            .and_then(|package| package.get("fixedInVersion"))
            .and_then(Value::as_str);
        result.push(
            RedactedFinding::from_raw(
                severity,
                cve,
                package_name,
                installed_version,
                fixed_version,
            )
            .map_err(|_| EcrProviderError::InvalidResponse)?,
        );
    }
    Ok(result)
}

fn attribute_value<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get("attributes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(32)
        .filter_map(Value::as_object)
        .find_map(|attribute| {
            (attribute.get("key").and_then(Value::as_str) == Some(key))
                .then(|| attribute.get("value").and_then(Value::as_str))
                .flatten()
        })
}

#[derive(Clone, Debug)]
pub struct RecordingEcrTransport {
    provenance: TransportProvenance,
    describe_images_responses: VecDeque<Result<DescribeImagesPage, TransportError>>,
    findings_responses: VecDeque<Result<DescribeImageScanFindingsPage, TransportError>>,
    last_describe_images_response: Option<Result<DescribeImagesPage, TransportError>>,
    last_findings_response: Option<Result<DescribeImageScanFindingsPage, TransportError>>,
    describe_images_requests: Vec<DescribeImagesRequest>,
    findings_requests: Vec<DescribeImageScanFindingsRequest>,
}

impl Default for RecordingEcrTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl RecordingEcrTransport {
    #[must_use]
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            describe_images_responses: VecDeque::new(),
            findings_responses: VecDeque::new(),
            last_describe_images_response: None,
            last_findings_response: None,
            describe_images_requests: Vec::new(),
            findings_requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::new(TransportProvenance::Fixture)
    }

    pub fn push_describe_images_response(
        &mut self,
        response: Result<DescribeImagesPage, TransportError>,
    ) {
        self.describe_images_responses.push_back(response);
    }

    pub fn push_findings_response(
        &mut self,
        response: Result<DescribeImageScanFindingsPage, TransportError>,
    ) {
        self.findings_responses.push_back(response);
    }

    #[must_use]
    pub fn describe_images_requests(&self) -> &[DescribeImagesRequest] {
        &self.describe_images_requests
    }

    #[must_use]
    pub fn findings_requests(&self) -> &[DescribeImageScanFindingsRequest] {
        &self.findings_requests
    }

    #[must_use]
    pub fn describe_image_scan_findings_requests(&self) -> &[DescribeImageScanFindingsRequest] {
        &self.findings_requests
    }
}

impl EcrTransport for RecordingEcrTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_images(
        &mut self,
        request: &DescribeImagesRequest,
    ) -> Result<DescribeImagesPage, TransportError> {
        self.describe_images_requests.push(request.clone());
        let response = self
            .describe_images_responses
            .pop_front()
            .or_else(|| self.last_describe_images_response.clone())
            .unwrap_or(Err(TransportError::Timeout));
        self.last_describe_images_response = Some(response.clone());
        response
    }

    fn describe_image_scan_findings(
        &mut self,
        request: &DescribeImageScanFindingsRequest,
    ) -> Result<DescribeImageScanFindingsPage, TransportError> {
        self.findings_requests.push(request.clone());
        let response = self
            .findings_responses
            .pop_front()
            .or_else(|| self.last_findings_response.clone())
            .unwrap_or(Err(TransportError::Timeout));
        self.last_findings_response = Some(response.clone());
        response
    }
}

pub type FixtureEcrTransport = RecordingEcrTransport;

#[derive(Clone, Debug)]
pub struct FakeEcrTransport {
    provenance: TransportProvenance,
    describe_images_requests: Vec<DescribeImagesRequest>,
    findings_requests: Vec<DescribeImageScanFindingsRequest>,
}

impl Default for FakeEcrTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Loopback)
    }
}

impl FakeEcrTransport {
    #[must_use]
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            describe_images_requests: Vec::new(),
            findings_requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn describe_images_requests(&self) -> &[DescribeImagesRequest] {
        &self.describe_images_requests
    }

    #[must_use]
    pub fn findings_requests(&self) -> &[DescribeImageScanFindingsRequest] {
        &self.findings_requests
    }
}

impl EcrTransport for FakeEcrTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_images(
        &mut self,
        request: &DescribeImagesRequest,
    ) -> Result<DescribeImagesPage, TransportError> {
        self.describe_images_requests.push(request.clone());
        DescribeImagesPage::new(
            request,
            1,
            vec![EcrImageDescriptor::new(request.image_digest.clone())],
            None,
            128,
            AWS_ECR_API_REVISION,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }

    fn describe_image_scan_findings(
        &mut self,
        request: &DescribeImageScanFindingsRequest,
    ) -> Result<DescribeImageScanFindingsPage, TransportError> {
        self.findings_requests.push(request.clone());
        DescribeImageScanFindingsPage::new(
            request,
            1,
            ScanLifecycle::Complete,
            request.scan_revision,
            request.inspector_finding_revision,
            Vec::new(),
            Vec::new(),
            None,
            128,
            AWS_ECR_API_REVISION,
        )
        .map_err(|_| TransportError::MalformedResponse)
    }
}

pub type LoopbackEcrTransport = FakeEcrTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvEcrTransport;

impl EcrTransport for BlockedEnvEcrTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_images(
        &mut self,
        _request: &DescribeImagesRequest,
    ) -> Result<DescribeImagesPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn describe_image_scan_findings(
        &mut self,
        _request: &DescribeImageScanFindingsRequest,
    ) -> Result<DescribeImageScanFindingsPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type EcrImageScanProviderDefinition = EcrProviderDefinition;
