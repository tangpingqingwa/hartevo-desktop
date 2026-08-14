//! Frame.io provider definition and bounded read adapter.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    FRAME_IO_PROVIDER_ID, FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION,
    model::{
        Digest, FrameIoApiEndpoint, FrameIoApprovalSummary, FrameIoAssetSummary, FrameIoBounds,
        FrameIoCommentSummary, FrameIoHttpMethod, FrameIoPayload, FrameIoReadOperation,
        FrameIoReviewLinkSummary, FrameIoRevisionFence, FrameIoVersionSummary, ModelError,
        ProviderId,
    },
    transport::{
        FrameIoGetRequest, FrameIoGetResponse, FrameIoTransport, FrameIoTransportError,
        FrameIoTransportErrorKind,
    },
};

pub type FrameIoProviderRevision = String;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameIoTransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl FrameIoTransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Frame.io provider version is empty or malformed")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native or Connected Frame.io provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoProviderDefinition {
    pub schema_version: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub capability_digest: Digest,
    pub provenance: FrameIoTransportProvenance,
    pub operations: Vec<FrameIoReadOperation>,
    pub native: bool,
    pub connected: bool,
    pub live_execution: bool,
}

impl FrameIoProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: FrameIoTransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() || provider_version.len() > 128 {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() || provenance.is_connected() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = ProviderId::new(FRAME_IO_PROVIDER_ID)?;
        let operations = vec![
            FrameIoReadOperation::AssetMetadata,
            FrameIoReadOperation::AssetVersion,
            FrameIoReadOperation::ReviewLink,
            FrameIoReadOperation::ApprovalStatus,
            FrameIoReadOperation::CommentSummary,
        ];
        let capability_digest = Digest::from_fields(
            "frameio-provider-capability/v1",
            &[
                FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION.to_owned(),
                FRAME_IO_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                operations
                    .iter()
                    .map(|operation| operation.contract_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                "GET-only".to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: FRAME_IO_REVIEW_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id,
            provider_version,
            capability_digest,
            provenance,
            operations,
            native: false,
            connected: false,
            live_execution: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "frameio-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.operations
                    .iter()
                    .map(|operation| operation.contract_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.native.to_string(),
                self.connected.to_string(),
                self.live_execution.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReadReceipt {
    pub operation: FrameIoReadOperation,
    pub endpoint: FrameIoApiEndpoint,
    pub method: FrameIoHttpMethod,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoRetryEvidence {
    pub operation: FrameIoReadOperation,
    pub attempt: u8,
    pub kind: FrameIoTransportErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub backoff_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameIoReadFailure {
    pub operation: FrameIoReadOperation,
    pub kind: FrameIoTransportErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub provenance: FrameIoTransportProvenance,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FrameIoProviderError {
    #[error("Frame.io request is invalid: {0}")]
    Request(String),
    #[error("Frame.io transport failed: {0}")]
    Transport(#[source] FrameIoTransportError),
    #[error("Frame.io response exceeded the safe response bound: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("Frame.io response integrity validation failed: {0}")]
    ResponseIntegrity(String),
    #[error("Frame.io response operation does not match the request")]
    OperationMismatch,
    #[error("Frame.io response scope or permission fence does not match the request")]
    ScopeMismatch,
    #[error("Frame.io response revision or credential fence does not match the request")]
    RevisionMismatch,
    #[error("Frame.io returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("Frame.io response payload is not the typed shape for the requested read")]
    InvalidPayload,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameIoProviderRead {
    pub response: FrameIoGetResponse,
    pub receipt: FrameIoReadReceipt,
    pub retries: Vec<FrameIoRetryEvidence>,
}

pub struct FrameIoProvider<T> {
    transport: T,
    definition: FrameIoProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for FrameIoProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameIoProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: FrameIoTransport> FrameIoProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: FrameIoTransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = FrameIoProviderDefinition::new(provider_version, provenance)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &FrameIoProviderDefinition {
        &self.definition
    }

    pub fn definition_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn provenance(&self) -> FrameIoTransportProvenance {
        self.definition.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &FrameIoGetRequest,
        bounds: FrameIoBounds,
    ) -> Result<FrameIoProviderRead, FrameIoProviderError> {
        if request.page_number == 0
            || request.page_number > bounds.max_pages()
            || request.page_size > bounds.page_size()
            || request.method != FrameIoHttpMethod::Get
            || request.endpoint != FrameIoApiEndpoint::for_operation(request.operation)
        {
            return Err(FrameIoProviderError::Request(
                "only bounded allowlisted GET requests are accepted".to_owned(),
            ));
        }
        let mut retries = Vec::new();
        let mut attempts = 0_u8;
        loop {
            attempts = attempts.saturating_add(1);
            match self.transport.get(request) {
                Ok(response) => {
                    Self::validate_response(request, bounds, &response)?;
                    let request_digest = request.request_digest()?;
                    let receipt = FrameIoReadReceipt {
                        operation: request.operation,
                        endpoint: request.endpoint,
                        method: request.method,
                        request_digest,
                        response_status: response.status,
                        response_size: response.response_size,
                        response_digest: response.response_digest.clone(),
                        provider_revision: response.provider_revision.clone(),
                        attempts,
                    };
                    return Ok(FrameIoProviderRead {
                        response,
                        receipt,
                        retries,
                    });
                }
                Err(error) if error.is_retryable() && attempts < bounds.max_retry_attempts() => {
                    retries.push(FrameIoRetryEvidence {
                        operation: request.operation,
                        attempt: attempts,
                        kind: error.kind,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                        backoff_ms: bounded_backoff_ms(attempts),
                    });
                }
                Err(error) => return Err(FrameIoProviderError::Transport(error)),
            }
        }
    }

    fn validate_response(
        request: &FrameIoGetRequest,
        bounds: FrameIoBounds,
        response: &FrameIoGetResponse,
    ) -> Result<(), FrameIoProviderError> {
        response
            .validate_integrity()
            .map_err(|error| FrameIoProviderError::ResponseIntegrity(error.to_string()))?;
        if response.operation != request.operation {
            return Err(FrameIoProviderError::OperationMismatch);
        }
        if response.scope_digest != request.scope_digest
            || response.permission_digest != request.permission_digest
            || response.consent_digest != request.consent_digest
        {
            return Err(FrameIoProviderError::ScopeMismatch);
        }
        if response.revision_fence != expected_revision_fence(request) {
            return Err(FrameIoProviderError::RevisionMismatch);
        }
        if response.credential_revision != request.credential_revision {
            return Err(FrameIoProviderError::RevisionMismatch);
        }
        if !(200..=299).contains(&response.status) {
            return Err(FrameIoProviderError::UnexpectedStatus {
                status: response.status,
            });
        }
        if response.response_size > bounds.max_response_bytes() {
            return Err(FrameIoProviderError::ResponseTooLarge {
                size: response.response_size,
            });
        }
        if response.provider_revision.is_empty() {
            return Err(FrameIoProviderError::ResponseIntegrity(
                "empty provider revision".to_owned(),
            ));
        }
        validate_payload(request, response)
    }
}

fn expected_revision_fence(request: &FrameIoGetRequest) -> FrameIoRevisionFence {
    request.revision_fence
}

fn validate_payload(
    request: &FrameIoGetRequest,
    response: &FrameIoGetResponse,
) -> Result<(), FrameIoProviderError> {
    match (request.operation, &response.payload) {
        (FrameIoReadOperation::AssetMetadata, FrameIoPayload::Asset(asset))
            if asset.asset_id == request.asset_id
                && asset.frameio_project_id == request.frameio_project_id =>
        {
            validate_asset_digest(asset)
        }
        (FrameIoReadOperation::AssetVersion, FrameIoPayload::Version(version))
            if version.asset_id == request.asset_id
                && version.version_id == request.asset_version_id =>
        {
            validate_version_digest(version)
        }
        (FrameIoReadOperation::ReviewLink, FrameIoPayload::ReviewLink(review_link))
            if review_link.review_link_id == request.review_link_id =>
        {
            validate_review_link_digest(review_link)
        }
        (FrameIoReadOperation::ApprovalStatus, FrameIoPayload::Approval(approval)) => {
            validate_approval_digest(approval)
        }
        (FrameIoReadOperation::CommentSummary, FrameIoPayload::Comments(comments)) => {
            validate_comment_digest(comments)
        }
        _ => Err(FrameIoProviderError::InvalidPayload),
    }
}

fn validate_asset_digest(asset: &FrameIoAssetSummary) -> Result<(), FrameIoProviderError> {
    let expected = FrameIoAssetSummary::new(
        asset.asset_id.clone(),
        asset.frameio_project_id.clone(),
        asset.status,
        asset.observed_at,
        asset.revision,
    )
    .asset_digest;
    if expected == asset.asset_digest {
        Ok(())
    } else {
        Err(FrameIoProviderError::ResponseIntegrity(
            "asset digest mismatch".to_owned(),
        ))
    }
}

fn validate_version_digest(version: &FrameIoVersionSummary) -> Result<(), FrameIoProviderError> {
    let expected = FrameIoVersionSummary::new(
        version.asset_id.clone(),
        version.version_id.clone(),
        version.status,
        version.observed_at,
        version.revision,
    )
    .version_digest;
    if expected == version.version_digest {
        Ok(())
    } else {
        Err(FrameIoProviderError::ResponseIntegrity(
            "version digest mismatch".to_owned(),
        ))
    }
}

fn validate_review_link_digest(
    review_link: &FrameIoReviewLinkSummary,
) -> Result<(), FrameIoProviderError> {
    let expected = FrameIoReviewLinkSummary::new(
        review_link.review_link_id.clone(),
        review_link.state,
        review_link.approval,
        review_link.expires_at,
        review_link.reviewer_count,
        review_link.observed_at,
        review_link.revision,
    )
    .review_link_digest;
    if expected == review_link.review_link_digest {
        Ok(())
    } else {
        Err(FrameIoProviderError::ResponseIntegrity(
            "review-link digest mismatch".to_owned(),
        ))
    }
}

fn validate_approval_digest(approval: &FrameIoApprovalSummary) -> Result<(), FrameIoProviderError> {
    let expected =
        FrameIoApprovalSummary::new(approval.status, approval.observed_at, approval.revision)
            .approval_digest;
    if expected == approval.approval_digest {
        Ok(())
    } else {
        Err(FrameIoProviderError::ResponseIntegrity(
            "approval digest mismatch".to_owned(),
        ))
    }
}

fn validate_comment_digest(comments: &FrameIoCommentSummary) -> Result<(), FrameIoProviderError> {
    let expected = FrameIoCommentSummary::new(
        comments.total_count,
        comments.open_count,
        comments.completed_count,
        comments.reply_count,
        comments.redacted_annotation_count,
        comments.first_observed_at,
        comments.last_observed_at,
        comments.partial,
        comments.revision,
    )
    .map_err(|_| FrameIoProviderError::InvalidPayload)?
    .comment_digest;
    if expected == comments.comment_digest {
        Ok(())
    } else {
        Err(FrameIoProviderError::ResponseIntegrity(
            "comment digest mismatch".to_owned(),
        ))
    }
}

fn bounded_backoff_ms(attempt: u8) -> u64 {
    100_u64
        .saturating_mul(2_u64.saturating_pow(u32::from(attempt.saturating_sub(1))))
        .min(1_000)
}
