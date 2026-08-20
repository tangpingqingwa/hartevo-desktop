use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    PROVIDER_ID, PluginVersion,
    canonical::digest_serializable,
    registration::{HeyGenVideoResultRegistration, RegistrationError},
    types::{
        ArtifactId, ArtifactMetadata, AsyncVideoStatus, AvatarId, ConsentReference, Digest,
        GenerationProposal, IdentityKind, MediaUrl, MissionScope, MissionVideoSource, OperationId,
        SourceDigests, TemplateId, VideoId,
    },
};

/// Layer-1 provider provenance. None of these variants are Connected/native.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

/// Typed status returned by the provider boundary; it cannot claim Connected.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    ProbeObservation,
    ProposalOnly,
    RecordedReceipt,
    BlockedEnv,
}

/// Non-Connected evidence attached to every provider observation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEvidence {
    provenance: ProviderProvenance,
    status: ProviderStatus,
    connected: bool,
    native: bool,
    evidence_digest: Digest,
}

impl ProviderEvidence {
    fn new<T: Serialize>(
        provenance: ProviderProvenance,
        status: ProviderStatus,
        scope: &MissionScope,
        value: &T,
    ) -> Self {
        let evidence_digest = digest_serializable(&EvidenceMaterial {
            provenance,
            status,
            scope_digest: scope.digest(),
            value_digest: digest_serializable(value),
        });
        Self {
            provenance,
            status,
            connected: false,
            native: false,
            evidence_digest,
        }
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn status(&self) -> ProviderStatus {
        self.status
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceMaterial {
    provenance: ProviderProvenance,
    status: ProviderStatus,
    scope_digest: Digest,
    value_digest: Digest,
}

/// Transport-level failures remain explicit non-Connected evidence.
#[derive(Clone, Debug, Eq, Error, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    #[error("provider rate limited the request")]
    RateLimited { retry_after_seconds: u64 },
    #[error("provider quota or credits are exhausted")]
    QuotaExhausted,
    #[error("provider transport timed out")]
    Timeout,
    #[error("provider does not support the requested resource")]
    Unsupported,
    #[error("provider refused the request for safety reasons")]
    SafetyRefusal,
    #[error("provider returned an explicit failure")]
    ProviderFailure,
    #[error("provider create result is ambiguous")]
    AmbiguousCreate,
    #[error("provider response is malformed or tampered")]
    Malformed,
    #[error("environment is blocked for native transport")]
    BlockedEnv,
}

/// Errors at the provider boundary.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("transport is blocked by the environment")]
    BlockedEnv,
    #[error("transport failed: {0}")]
    Failure(#[from] TransportFailure),
    #[error("transport response type does not match its typed request")]
    ResponseTypeMismatch,
    #[error("transport request scope does not match the provider scope")]
    ScopeMismatch,
}

/// Provider-specific failure categories exposed without raw JSON.
#[derive(Clone, Debug, Eq, Error, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    #[error("missing operation identity")]
    MissingOperationIdentity,
    #[error("operation identity is ambiguous")]
    AmbiguousOperation,
    #[error("status receipt is stale or regresses the operation")]
    StaleStatus,
    #[error("status receipt scope does not match")]
    StatusScopeMismatch,
    #[error("status receipt has invalid terminal evidence")]
    InvalidTerminalEvidence,
    #[error("artifact metadata does not match the Mission expectation")]
    ArtifactMetadataMismatch,
    #[error("artifact URL has expired")]
    ExpiredUrl,
    #[error("artifact content digest is missing")]
    MissingIndependentContentDigest,
    #[error("artifact content digest does not match the provider digest")]
    ContentDigestMismatch,
    #[error("duplicate idempotency fingerprint")]
    DuplicateFingerprint,
}

/// Provider errors never collapse blocked, failed, or ambiguous evidence into success.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("input type error: {0}")]
    Input(#[from] crate::types::TypeError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("provider operation error: {0}")]
    Operation(#[from] ProviderErrorKind),
}

/// Only read/probe operations may cross the HTTPS seam in Layer 1.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsOperation {
    ProbeCapability,
    ProbeTemplate,
    ProbeAvatar,
    ProbeVoice,
}

/// Typed resources for the HTTPS seam; raw provider JSON is not accepted.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "resource")]
pub enum HttpsRequestResource {
    Capability { capability: Capability },
    Template { template_id: TemplateId },
    Avatar { avatar_id: AvatarId },
    Voice { voice_id: crate::VoiceId },
}

/// A typed HTTPS request carrying only an opaque scope and resource reference.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpsRequest {
    operation: HttpsOperation,
    scope: MissionScope,
    resource: HttpsRequestResource,
}

impl HttpsRequest {
    pub fn operation(&self) -> HttpsOperation {
        self.operation
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn resource(&self) -> &HttpsRequestResource {
        &self.resource
    }
}

/// Typed HTTPS responses used by fixtures and recordings.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "response")]
pub enum HttpsResponse {
    Capability {
        capability: Capability,
        supported: bool,
    },
    Template {
        template_id: TemplateId,
        supported: bool,
        template_digest: Option<Digest>,
    },
    Identity {
        identity_kind: IdentityKind,
        identity_id: String,
        supported: bool,
        identity_digest: Option<Digest>,
    },
}

/// Compatibility name for fixture responses.
pub type FixtureResponse = HttpsResponse;

/// The provider capability vocabulary, including proposal/read-only operations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    CapabilityProbe,
    TemplateProbe,
    AvatarProbe,
    VoiceProbe,
    GenerationProposal,
    GenerationStatusReceipt,
    VideoResultAdoptionProposal,
}

/// HTTPS transport seam. Layer 1 ships only fixture, recording, loopback, and
/// blocked-environment implementations; no native network transport exists.
pub trait HttpsTransport {
    fn execute(
        &mut self,
        request: HttpsRequest,
        secret: &crate::SecretReference,
    ) -> Result<HttpsResponse, TransportError>;

    fn provenance(&self) -> ProviderProvenance;
}

/// Redacted record of a typed transport exchange.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingExchange {
    request_digest: Digest,
    secret_reference_digest: Digest,
    response_digest: Option<Digest>,
    failure: Option<TransportFailure>,
}

impl RecordingExchange {
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn response_digest(&self) -> Option<&Digest> {
        self.response_digest.as_ref()
    }

    pub fn failure(&self) -> Option<&TransportFailure> {
        self.failure.as_ref()
    }
}

/// Deterministic recording transport. It never opens a socket.
pub struct RecordingHttpsTransport {
    provenance: ProviderProvenance,
    responses: VecDeque<Result<HttpsResponse, TransportError>>,
    exchanges: Vec<RecordingExchange>,
}

impl RecordingHttpsTransport {
    pub fn new(
        provenance: ProviderProvenance,
        responses: impl IntoIterator<Item = Result<HttpsResponse, TransportError>>,
    ) -> Self {
        Self {
            provenance,
            responses: responses.into_iter().collect(),
            exchanges: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<HttpsResponse, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Fixture, responses)
    }

    pub fn recording(
        responses: impl IntoIterator<Item = Result<HttpsResponse, TransportError>>,
    ) -> Self {
        Self::new(ProviderProvenance::Recording, responses)
    }

    pub fn exchanges(&self) -> &[RecordingExchange] {
        &self.exchanges
    }
}

impl fmt::Debug for RecordingHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingHttpsTransport")
            .field("provenance", &self.provenance)
            .field("queued_responses", &self.responses.len())
            .field("exchanges", &self.exchanges)
            .finish()
    }
}

impl HttpsTransport for RecordingHttpsTransport {
    fn execute(
        &mut self,
        request: HttpsRequest,
        secret: &crate::SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        let result = self
            .responses
            .pop_front()
            .unwrap_or(Err(TransportError::BlockedEnv));
        let exchange = RecordingExchange {
            request_digest: digest_serializable(&request),
            secret_reference_digest: secret.reference_digest(),
            response_digest: result.as_ref().ok().map(digest_serializable),
            failure: result.as_ref().err().and_then(|error| match error {
                TransportError::BlockedEnv => Some(TransportFailure::BlockedEnv),
                TransportError::Failure(failure) => Some(failure.clone()),
                TransportError::ResponseTypeMismatch | TransportError::ScopeMismatch => None,
            }),
        };
        self.exchanges.push(exchange);
        result
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

/// Named fixture transport for callers that do not need to inspect exchanges.
pub struct FixtureHttpsTransport(RecordingHttpsTransport);

impl FixtureHttpsTransport {
    pub fn new(responses: impl IntoIterator<Item = Result<HttpsResponse, TransportError>>) -> Self {
        Self(RecordingHttpsTransport::fixture(responses))
    }

    pub fn exchanges(&self) -> &[RecordingExchange] {
        self.0.exchanges()
    }
}

impl fmt::Debug for FixtureHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl HttpsTransport for FixtureHttpsTransport {
    fn execute(
        &mut self,
        request: HttpsRequest,
        secret: &crate::SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        self.0.execute(request, secret)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }
}

/// Loopback transport for deterministic component tests; it never contacts HeyGen.
pub struct LoopbackHttpsTransport {
    exchanges: Vec<RecordingExchange>,
}

impl LoopbackHttpsTransport {
    pub const fn new() -> Self {
        Self {
            exchanges: Vec::new(),
        }
    }

    pub fn exchanges(&self) -> &[RecordingExchange] {
        &self.exchanges
    }
}

impl Default for LoopbackHttpsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LoopbackHttpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackHttpsTransport")
            .field("exchanges", &self.exchanges)
            .finish()
    }
}

impl HttpsTransport for LoopbackHttpsTransport {
    fn execute(
        &mut self,
        request: HttpsRequest,
        secret: &crate::SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        let response = match request.resource() {
            HttpsRequestResource::Capability { capability } => HttpsResponse::Capability {
                capability: *capability,
                supported: true,
            },
            HttpsRequestResource::Template { template_id } => HttpsResponse::Template {
                template_id: template_id.clone(),
                supported: true,
                template_digest: Some(Digest::from_text(template_id.as_str())),
            },
            HttpsRequestResource::Avatar { avatar_id } => HttpsResponse::Identity {
                identity_kind: IdentityKind::Avatar,
                identity_id: avatar_id.as_str().to_owned(),
                supported: true,
                identity_digest: Some(Digest::from_text(avatar_id.as_str())),
            },
            HttpsRequestResource::Voice { voice_id } => HttpsResponse::Identity {
                identity_kind: IdentityKind::Voice,
                identity_id: voice_id.as_str().to_owned(),
                supported: true,
                identity_digest: Some(Digest::from_text(voice_id.as_str())),
            },
        };
        self.exchanges.push(RecordingExchange {
            request_digest: digest_serializable(&request),
            secret_reference_digest: secret.reference_digest(),
            response_digest: Some(digest_serializable(&response)),
            failure: None,
        });
        Ok(response)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}

/// Explicit `BLOCKED_ENV` transport. It is never interpreted as Connected.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockedEnvTransport;

impl HttpsTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _request: HttpsRequest,
        _secret: &crate::SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

/// Capability probe receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityProbeReceipt {
    scope: MissionScope,
    capability: Capability,
    supported: bool,
    provider_version: PluginVersion,
    registration_digest: Digest,
    observed_at: u64,
    evidence: ProviderEvidence,
    receipt_digest: Digest,
}

impl CapabilityProbeReceipt {
    pub fn supported(&self) -> bool {
        self.supported
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
}

/// Template probe receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateProbeReceipt {
    scope: MissionScope,
    template_id: TemplateId,
    supported: bool,
    template_digest: Option<Digest>,
    provider_version: PluginVersion,
    registration_digest: Digest,
    observed_at: u64,
    evidence: ProviderEvidence,
    receipt_digest: Digest,
}

impl TemplateProbeReceipt {
    pub fn template_id(&self) -> &TemplateId {
        &self.template_id
    }

    pub fn supported(&self) -> bool {
        self.supported
    }

    pub fn template_digest(&self) -> Option<&Digest> {
        self.template_digest.as_ref()
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }
}

/// Avatar or voice probe receipt.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProbeReceipt {
    scope: MissionScope,
    identity_kind: IdentityKind,
    identity_id: String,
    supported: bool,
    identity_digest: Option<Digest>,
    provider_version: PluginVersion,
    registration_digest: Digest,
    observed_at: u64,
    evidence: ProviderEvidence,
    receipt_digest: Digest,
}

/// Semantic alias for avatar probe callers.
pub type AvatarProbeReceipt = IdentityProbeReceipt;

impl IdentityProbeReceipt {
    pub fn identity_kind(&self) -> IdentityKind {
        self.identity_kind
    }

    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    pub fn supported(&self) -> bool {
        self.supported
    }

    pub fn identity_digest(&self) -> Option<&Digest> {
        self.identity_digest.as_ref()
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }
}

/// Operation/status receipt. `video_id` is the provider operation identity;
/// the CDN URL is never used as identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationReceipt {
    operation_id: OperationId,
    video_id: Option<VideoId>,
    proposal_fingerprint: Digest,
    scope: MissionScope,
    source_digests: SourceDigests,
    provider_version: PluginVersion,
    registration_digest: Digest,
    status: AsyncVideoStatus,
    observed_at: u64,
    evidence: ProviderEvidence,
    receipt_digest: Digest,
}

/// Semantic alias for a recorded generation status receipt.
pub type StatusReceipt = OperationReceipt;

impl OperationReceipt {
    pub fn recorded(
        proposal: &GenerationProposal,
        video_id: Option<VideoId>,
        status: AsyncVideoStatus,
        observed_at: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderError> {
        if observed_at == 0 {
            return Err(ProviderError::Input(
                crate::types::TypeError::InvalidRevision,
            ));
        }
        let evidence = ProviderEvidence::new(
            provenance,
            ProviderStatus::RecordedReceipt,
            proposal.scope(),
            &status,
        );
        let receipt_digest = digest_serializable(&OperationReceiptMaterial {
            operation_id: proposal.fence().operation_id().clone(),
            video_id: video_id.clone(),
            proposal_fingerprint: proposal.fence().fingerprint().clone(),
            scope_digest: proposal.scope().digest(),
            source_digest: proposal.source_digests().source_digest().clone(),
            provider_version: proposal.provider_version(),
            registration_digest: proposal.registration_digest().clone(),
            status: status.clone(),
            observed_at,
            evidence_digest: evidence.evidence_digest().clone(),
        });
        Ok(Self {
            operation_id: proposal.fence().operation_id().clone(),
            video_id,
            proposal_fingerprint: proposal.fence().fingerprint().clone(),
            scope: proposal.scope().clone(),
            source_digests: proposal.source_digests().clone(),
            provider_version: proposal.provider_version(),
            registration_digest: proposal.registration_digest().clone(),
            status,
            observed_at,
            evidence,
            receipt_digest,
        })
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn video_id(&self) -> Option<&VideoId> {
        self.video_id.as_ref()
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn source_digests(&self) -> &SourceDigests {
        &self.source_digests
    }

    pub fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn status(&self) -> &AsyncVideoStatus {
        &self.status
    }

    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn projection(&self) -> crate::GenerationStatusProjection {
        (&self.status).into()
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationReceiptMaterial {
    operation_id: OperationId,
    video_id: Option<VideoId>,
    proposal_fingerprint: Digest,
    scope_digest: Digest,
    source_digest: Digest,
    provider_version: PluginVersion,
    registration_digest: Digest,
    status: AsyncVideoStatus,
    observed_at: u64,
    evidence_digest: Digest,
}

/// Artifact receipt carrying URL expiry and metadata; raw URL bytes remain redacted.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReceipt {
    artifact_id: ArtifactId,
    operation_id: OperationId,
    video_id: VideoId,
    operation_receipt_digest: Digest,
    scope: MissionScope,
    provider_version: PluginVersion,
    registration_digest: Digest,
    url: MediaUrl,
    url_expires_at: u64,
    metadata: ArtifactMetadata,
    metadata_digest: Digest,
    provider_artifact_digest: Option<Digest>,
    independent_content_digest: Option<Digest>,
    observed_at: u64,
    evidence: ProviderEvidence,
    receipt_digest: Digest,
}

impl ArtifactReceipt {
    pub fn builder(
        artifact_id: ArtifactId,
        operation: &OperationReceipt,
        url: MediaUrl,
        url_expires_at: u64,
        metadata: ArtifactMetadata,
        observed_at: u64,
        provenance: ProviderProvenance,
    ) -> ArtifactReceiptBuilder {
        ArtifactReceiptBuilder {
            artifact_id,
            operation: operation.clone(),
            url,
            url_expires_at,
            metadata,
            provider_artifact_digest: None,
            independent_content_digest: None,
            observed_at,
            provenance,
        }
    }

    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn video_id(&self) -> &VideoId {
        &self.video_id
    }

    pub fn operation_receipt_digest(&self) -> &Digest {
        &self.operation_receipt_digest
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn url(&self) -> &MediaUrl {
        &self.url
    }

    pub const fn url_expires_at(&self) -> u64 {
        self.url_expires_at
    }

    pub fn metadata(&self) -> &ArtifactMetadata {
        &self.metadata
    }

    pub fn metadata_digest(&self) -> &Digest {
        &self.metadata_digest
    }

    pub fn provider_artifact_digest(&self) -> Option<&Digest> {
        self.provider_artifact_digest.as_ref()
    }

    pub fn independent_content_digest(&self) -> Option<&Digest> {
        self.independent_content_digest.as_ref()
    }

    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn url_expiry_receipt(&self) -> UrlExpiryReceipt {
        UrlExpiryReceipt {
            artifact_id: self.artifact_id.clone(),
            operation_id: self.operation_id.clone(),
            video_id: self.video_id.clone(),
            scope_digest: self.scope.digest(),
            url_digest: self.url.digest(),
            expires_at: self.url_expires_at,
            artifact_receipt_digest: self.receipt_digest.clone(),
        }
    }
}

/// A separate receipt for ephemeral URL lifetime. The URL itself is never
/// used as a durable Work Product identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlExpiryReceipt {
    artifact_id: ArtifactId,
    operation_id: OperationId,
    video_id: VideoId,
    scope_digest: Digest,
    url_digest: Digest,
    expires_at: u64,
    artifact_receipt_digest: Digest,
}

impl UrlExpiryReceipt {
    pub fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn video_id(&self) -> &VideoId {
        &self.video_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn url_digest(&self) -> &Digest {
        &self.url_digest
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn artifact_receipt_digest(&self) -> &Digest {
        &self.artifact_receipt_digest
    }
}

/// Builder for a typed artifact receipt. It never downloads or stores media.
pub struct ArtifactReceiptBuilder {
    artifact_id: ArtifactId,
    operation: OperationReceipt,
    url: MediaUrl,
    url_expires_at: u64,
    metadata: ArtifactMetadata,
    provider_artifact_digest: Option<Digest>,
    independent_content_digest: Option<Digest>,
    observed_at: u64,
    provenance: ProviderProvenance,
}

impl fmt::Debug for ArtifactReceiptBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReceiptBuilder")
            .field("artifact_id", &self.artifact_id)
            .field("operation_id", &self.operation.operation_id())
            .field("url", &self.url)
            .field("url_expires_at", &self.url_expires_at)
            .field("metadata", &self.metadata)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl ArtifactReceiptBuilder {
    #[must_use]
    pub fn provider_artifact_digest(mut self, digest: Digest) -> Self {
        self.provider_artifact_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn independent_content_digest(mut self, digest: Digest) -> Self {
        self.independent_content_digest = Some(digest);
        self
    }

    pub fn build(self) -> Result<ArtifactReceipt, ProviderError> {
        if self.url_expires_at == 0
            || self.observed_at == 0
            || self
                .url
                .is_expiring_before(self.operation.observed_at(), self.url_expires_at)
        {
            return Err(ProviderError::Operation(ProviderErrorKind::ExpiredUrl));
        }
        if self
            .provider_artifact_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
            || self
                .independent_content_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
        {
            return Err(ProviderError::Input(crate::types::TypeError::InvalidDigest));
        }
        if self.operation.video_id.is_none() {
            return Err(ProviderError::Operation(
                ProviderErrorKind::MissingOperationIdentity,
            ));
        }
        let video_id = self
            .operation
            .video_id
            .clone()
            .ok_or(ProviderErrorKind::MissingOperationIdentity)?;
        let operation_id = self.operation.operation_id.clone();
        let operation_receipt_digest = self.operation.receipt_digest().clone();
        let scope = self.operation.scope.clone();
        let provider_version = self.operation.provider_version();
        let registration_digest = self.operation.registration_digest().clone();
        let metadata_digest = self.metadata.digest();
        let evidence = ProviderEvidence::new(
            self.provenance,
            ProviderStatus::RecordedReceipt,
            &scope,
            &metadata_digest,
        );
        let receipt_digest = digest_serializable(&ArtifactReceiptMaterial {
            artifact_id: self.artifact_id.clone(),
            operation_id: operation_id.clone(),
            video_id: video_id.clone(),
            operation_receipt_digest: operation_receipt_digest.clone(),
            scope_digest: scope.digest(),
            provider_version,
            registration_digest: registration_digest.clone(),
            url_digest: self.url.digest(),
            url_expires_at: self.url_expires_at,
            metadata_digest: metadata_digest.clone(),
            provider_artifact_digest: self.provider_artifact_digest.clone(),
            independent_content_digest: self.independent_content_digest.clone(),
            observed_at: self.observed_at,
            evidence_digest: evidence.evidence_digest().clone(),
        });
        Ok(ArtifactReceipt {
            artifact_id: self.artifact_id,
            operation_id,
            video_id,
            operation_receipt_digest,
            scope,
            provider_version,
            registration_digest,
            url: self.url,
            url_expires_at: self.url_expires_at,
            metadata: self.metadata,
            metadata_digest,
            provider_artifact_digest: self.provider_artifact_digest,
            independent_content_digest: self.independent_content_digest,
            observed_at: self.observed_at,
            evidence,
            receipt_digest,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactReceiptMaterial {
    artifact_id: ArtifactId,
    operation_id: OperationId,
    video_id: VideoId,
    operation_receipt_digest: Digest,
    scope_digest: Digest,
    provider_version: PluginVersion,
    registration_digest: Digest,
    url_digest: Digest,
    url_expires_at: u64,
    metadata_digest: Digest,
    provider_artifact_digest: Option<Digest>,
    independent_content_digest: Option<Digest>,
    observed_at: u64,
    evidence_digest: Digest,
}

/// A typed HeyGen provider backed by an injected read-only transport seam.
pub struct HeyGenVideoProvider<T> {
    registration: HeyGenVideoResultRegistration,
    secret: crate::SecretReference,
    transport: T,
}

impl<T: HttpsTransport> HeyGenVideoProvider<T> {
    pub fn new(
        registration: HeyGenVideoResultRegistration,
        secret: crate::SecretReference,
        transport: T,
    ) -> Result<Self, ProviderError> {
        registration.ensure_active()?;
        if secret.scope().workspace_id() != registration.scope().workspace_id()
            || secret.scope().project_id() != registration.scope().project_id()
            || secret.scope().mission_id() != registration.scope().mission_id()
            || secret.scope().provider_id() != PROVIDER_ID
        {
            return Err(ProviderError::Registration(
                RegistrationError::ScopeMismatch,
            ));
        }
        Ok(Self {
            registration,
            secret,
            transport,
        })
    }

    pub fn registration(&self) -> &HeyGenVideoResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MissionScope {
        self.registration.scope()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn propose_generation(
        &self,
        source: &MissionVideoSource,
    ) -> Result<GenerationProposal, ProviderError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(source.scope())?;
        Ok(GenerationProposal::new(
            source,
            PROVIDER_ID,
            self.registration.provider_version(),
            self.registration.registration_digest().clone(),
        )?)
    }

    pub fn record_status(
        &self,
        receipt: OperationReceipt,
    ) -> Result<OperationReceipt, ProviderError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(receipt.scope())?;
        if receipt.registration_digest() != self.registration.registration_digest()
            || receipt.provider_version() != self.registration.provider_version()
        {
            return Err(ProviderError::Operation(
                ProviderErrorKind::StatusScopeMismatch,
            ));
        }
        if receipt.video_id().is_none() {
            return Err(ProviderError::Operation(
                ProviderErrorKind::MissingOperationIdentity,
            ));
        }
        Ok(receipt)
    }

    pub fn record_artifact(
        &self,
        receipt: ArtifactReceipt,
    ) -> Result<ArtifactReceipt, ProviderError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(receipt.scope())?;
        if receipt.registration_digest() != self.registration.registration_digest()
            || receipt.provider_version() != self.registration.provider_version()
        {
            return Err(ProviderError::Operation(
                ProviderErrorKind::StatusScopeMismatch,
            ));
        }
        Ok(receipt)
    }

    fn execute_probe(
        &mut self,
        operation: HttpsOperation,
        resource: HttpsRequestResource,
    ) -> Result<HttpsResponse, ProviderError> {
        self.registration.ensure_active()?;
        let request = HttpsRequest {
            operation,
            scope: self.registration.scope().clone(),
            resource,
        };
        if request.scope() != self.registration.scope() {
            return Err(ProviderError::Transport(TransportError::ScopeMismatch));
        }
        let response = self.transport.execute(request, &self.secret)?;
        Ok(response)
    }

    pub fn probe_capability(
        &mut self,
        capability: Capability,
        observed_at: u64,
    ) -> Result<CapabilityProbeReceipt, ProviderError> {
        let response = self.execute_probe(
            HttpsOperation::ProbeCapability,
            HttpsRequestResource::Capability { capability },
        )?;
        let HttpsResponse::Capability {
            capability: response_capability,
            supported,
        } = response
        else {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        };
        if response_capability != capability || observed_at == 0 {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        }
        let evidence = ProviderEvidence::new(
            self.transport.provenance(),
            ProviderStatus::ProbeObservation,
            self.scope(),
            &response_capability,
        );
        let receipt_digest = digest_serializable(&(
            capability,
            supported,
            observed_at,
            evidence.evidence_digest(),
        ));
        Ok(CapabilityProbeReceipt {
            scope: self.scope().clone(),
            capability,
            supported,
            provider_version: self.registration.provider_version(),
            registration_digest: self.registration.registration_digest().clone(),
            observed_at,
            evidence,
            receipt_digest,
        })
    }

    pub fn probe_template(
        &mut self,
        template_id: TemplateId,
        observed_at: u64,
    ) -> Result<TemplateProbeReceipt, ProviderError> {
        if &template_id != self.scope().template_id() {
            return Err(ProviderError::Registration(
                RegistrationError::ScopeMismatch,
            ));
        }
        let response = self.execute_probe(
            HttpsOperation::ProbeTemplate,
            HttpsRequestResource::Template {
                template_id: template_id.clone(),
            },
        )?;
        let HttpsResponse::Template {
            template_id: response_template,
            supported,
            template_digest,
        } = response
        else {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        };
        if response_template != template_id || observed_at == 0 {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        }
        if template_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
        {
            return Err(ProviderError::Input(crate::types::TypeError::InvalidDigest));
        }
        let evidence = ProviderEvidence::new(
            self.transport.provenance(),
            ProviderStatus::ProbeObservation,
            self.scope(),
            &response_template,
        );
        let receipt_digest = digest_serializable(&(
            template_id.clone(),
            supported,
            &template_digest,
            observed_at,
            evidence.evidence_digest(),
        ));
        Ok(TemplateProbeReceipt {
            scope: self.scope().clone(),
            template_id,
            supported,
            template_digest,
            provider_version: self.registration.provider_version(),
            registration_digest: self.registration.registration_digest().clone(),
            observed_at,
            evidence,
            receipt_digest,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn probe_avatar(
        &mut self,
        avatar_id: AvatarId,
        consent: Option<&ConsentReference>,
        observed_at: u64,
    ) -> Result<IdentityProbeReceipt, ProviderError> {
        if self.scope().avatar().avatar_id() != &avatar_id
            || self.scope().avatar().consent() != consent
        {
            return Err(ProviderError::Registration(
                RegistrationError::ScopeMismatch,
            ));
        }
        self.probe_identity(
            IdentityKind::Avatar,
            avatar_id.as_str().to_owned(),
            consent,
            observed_at,
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn probe_voice(
        &mut self,
        voice_id: crate::VoiceId,
        consent: Option<&ConsentReference>,
        observed_at: u64,
    ) -> Result<IdentityProbeReceipt, ProviderError> {
        if self.scope().voice().voice_id() != &voice_id || self.scope().voice().consent() != consent
        {
            return Err(ProviderError::Registration(
                RegistrationError::ScopeMismatch,
            ));
        }
        self.probe_identity(
            IdentityKind::Voice,
            voice_id.as_str().to_owned(),
            consent,
            observed_at,
        )
    }

    fn probe_identity(
        &mut self,
        identity_kind: IdentityKind,
        identity_id: String,
        consent: Option<&ConsentReference>,
        observed_at: u64,
    ) -> Result<IdentityProbeReceipt, ProviderError> {
        if matches!(identity_kind, IdentityKind::Avatar | IdentityKind::Voice)
            && self
                .scope()
                .avatar()
                .consent()
                .is_some_and(|_| identity_kind == IdentityKind::Avatar)
            && consent.is_none()
        {
            return Err(ProviderError::Operation(
                ProviderErrorKind::InvalidTerminalEvidence,
            ));
        }
        let operation = match identity_kind {
            IdentityKind::Avatar => HttpsOperation::ProbeAvatar,
            IdentityKind::Voice => HttpsOperation::ProbeVoice,
        };
        let resource = match identity_kind {
            IdentityKind::Avatar => HttpsRequestResource::Avatar {
                avatar_id: AvatarId::new(identity_id.clone())?,
            },
            IdentityKind::Voice => HttpsRequestResource::Voice {
                voice_id: crate::VoiceId::new(identity_id.clone())?,
            },
        };
        let response = self.execute_probe(operation, resource)?;
        let HttpsResponse::Identity {
            identity_kind: response_kind,
            identity_id: response_id,
            supported,
            identity_digest,
        } = response
        else {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        };
        if response_kind != identity_kind || response_id != identity_id || observed_at == 0 {
            return Err(ProviderError::Transport(
                TransportError::ResponseTypeMismatch,
            ));
        }
        if identity_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
        {
            return Err(ProviderError::Input(crate::types::TypeError::InvalidDigest));
        }
        let evidence = ProviderEvidence::new(
            self.transport.provenance(),
            ProviderStatus::ProbeObservation,
            self.scope(),
            &identity_id,
        );
        let receipt_digest = digest_serializable(&(
            identity_kind,
            &identity_id,
            supported,
            &identity_digest,
            observed_at,
            evidence.evidence_digest(),
        ));
        Ok(IdentityProbeReceipt {
            scope: self.scope().clone(),
            identity_kind,
            identity_id,
            supported,
            identity_digest,
            provider_version: self.registration.provider_version(),
            registration_digest: self.registration.registration_digest().clone(),
            observed_at,
            evidence,
            receipt_digest,
        })
    }
}

impl<T: HttpsTransport> fmt::Debug for HeyGenVideoProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeyGenVideoProvider")
            .field("registration", &self.registration)
            .field("secret", &self.secret)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}
