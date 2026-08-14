use std::{collections::VecDeque, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    PROVIDER_ID,
    canonical::digest_serializable,
    registration::{ElevenLabsAudioResultRegistration, RegistrationError},
    types::{
        ApiHost, AudioGenerationProposal, Digest, MAX_AUDIO_DURATION_MILLISECONDS,
        MAX_RECORDED_USAGE_CHARACTERS, MissionScope, OperationId, OutputFormat, PluginVersion,
        SecretReference, SynthesisBinding, TypeError,
    },
};

/// Source of a provider observation. None of these values imply Connected or
/// native evidence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

/// Provider evidence status retained on every receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    RecordedEvidence,
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

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn status(&self) -> ProviderStatus {
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

/// Redaction state for bounded metadata. `Truncated` is never adoptable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    Complete,
    Redacted,
    Truncated,
}

impl RedactionState {
    pub const fn is_truncated(self) -> bool {
        matches!(self, Self::Truncated)
    }
}

/// Bounded character, duration, and format usage evidence. It contains no
/// source text or raw provider payload.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageEvidence {
    input_character_count: u32,
    billed_character_count: Option<u32>,
    duration_milliseconds: Option<u64>,
    output_format: OutputFormat,
    redaction: RedactionState,
    usage_digest: Digest,
}

impl UsageEvidence {
    pub fn new(
        input_character_count: u32,
        billed_character_count: Option<u32>,
        duration_milliseconds: Option<u64>,
        output_format: OutputFormat,
        redaction: RedactionState,
    ) -> Result<Self, ProviderError> {
        if input_character_count == 0 || input_character_count > MAX_RECORDED_USAGE_CHARACTERS {
            return Err(ProviderError::Operation(
                ProviderErrorKind::UsageLimitExceeded,
            ));
        }
        if billed_character_count
            .is_some_and(|count| count == 0 || count > MAX_RECORDED_USAGE_CHARACTERS)
        {
            return Err(ProviderError::Operation(
                ProviderErrorKind::UsageLimitExceeded,
            ));
        }
        if duration_milliseconds
            .is_some_and(|duration| duration == 0 || duration > MAX_AUDIO_DURATION_MILLISECONDS)
        {
            return Err(ProviderError::Operation(
                ProviderErrorKind::UsageLimitExceeded,
            ));
        }
        let usage_digest = digest_serializable(&UsageMaterial {
            input_character_count,
            billed_character_count,
            duration_milliseconds,
            output_format: output_format.clone(),
            redaction,
        });
        Ok(Self {
            input_character_count,
            billed_character_count,
            duration_milliseconds,
            output_format,
            redaction,
            usage_digest,
        })
    }

    pub const fn input_character_count(&self) -> u32 {
        self.input_character_count
    }

    pub const fn billed_character_count(&self) -> Option<u32> {
        self.billed_character_count
    }

    pub const fn duration_milliseconds(&self) -> Option<u64> {
        self.duration_milliseconds
    }

    pub fn output_format(&self) -> &OutputFormat {
        &self.output_format
    }

    pub const fn redaction(&self) -> RedactionState {
        self.redaction
    }

    pub fn usage_digest(&self) -> &Digest {
        &self.usage_digest
    }

    pub fn verify_digest(&self) -> bool {
        digest_serializable(&UsageMaterial {
            input_character_count: self.input_character_count,
            billed_character_count: self.billed_character_count,
            duration_milliseconds: self.duration_milliseconds,
            output_format: self.output_format.clone(),
            redaction: self.redaction,
        }) == self.usage_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageMaterial {
    input_character_count: u32,
    billed_character_count: Option<u32>,
    duration_milliseconds: Option<u64>,
    output_format: OutputFormat,
    redaction: RedactionState,
}

/// Exact audio content digest evidence without a byte buffer, file path, URL,
/// download capability, or retained audio bytes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioContentEvidence {
    audio_content_digest: Digest,
    independent_content_digest: Option<Digest>,
    output_format: OutputFormat,
    duration_milliseconds: u64,
    byte_length: Option<u64>,
    redaction: RedactionState,
    evidence_digest: Digest,
}

impl AudioContentEvidence {
    pub fn new(
        audio_content_digest: Digest,
        output_format: OutputFormat,
        duration_milliseconds: u64,
        byte_length: Option<u64>,
        redaction: RedactionState,
    ) -> Result<Self, ProviderError> {
        if !audio_content_digest.is_valid() {
            return Err(ProviderError::Input(TypeError::InvalidDigest));
        }
        if duration_milliseconds == 0 || duration_milliseconds > MAX_AUDIO_DURATION_MILLISECONDS {
            return Err(ProviderError::Operation(
                ProviderErrorKind::UsageLimitExceeded,
            ));
        }
        if byte_length.is_some_and(|length| length == 0) {
            return Err(ProviderError::Operation(
                ProviderErrorKind::UsageLimitExceeded,
            ));
        }
        let evidence_digest = digest_serializable(&ContentMaterial {
            audio_content_digest: audio_content_digest.clone(),
            independent_content_digest: None,
            output_format: output_format.clone(),
            duration_milliseconds,
            byte_length,
            redaction,
        });
        Ok(Self {
            audio_content_digest,
            independent_content_digest: None,
            output_format,
            duration_milliseconds,
            byte_length,
            redaction,
            evidence_digest,
        })
    }

    #[must_use]
    pub fn with_independent_content_digest(mut self, digest: Digest) -> Self {
        self.independent_content_digest = Some(digest);
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub fn audio_content_digest(&self) -> &Digest {
        &self.audio_content_digest
    }

    pub fn independent_content_digest(&self) -> Option<&Digest> {
        self.independent_content_digest.as_ref()
    }

    pub fn output_format(&self) -> &OutputFormat {
        &self.output_format
    }

    pub const fn duration_milliseconds(&self) -> u64 {
        self.duration_milliseconds
    }

    pub const fn byte_length(&self) -> Option<u64> {
        self.byte_length
    }

    pub const fn redaction(&self) -> RedactionState {
        self.redaction
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn bytes_retained(&self) -> bool {
        false
    }

    pub fn is_consistent(&self) -> bool {
        self.independent_content_digest
            .as_ref()
            .is_none_or(|independent| independent == &self.audio_content_digest)
    }

    pub fn verify_digest(&self) -> bool {
        self.calculate_digest() == self.evidence_digest
    }

    fn calculate_digest(&self) -> Digest {
        digest_serializable(&ContentMaterial {
            audio_content_digest: self.audio_content_digest.clone(),
            independent_content_digest: self.independent_content_digest.clone(),
            output_format: self.output_format.clone(),
            duration_milliseconds: self.duration_milliseconds,
            byte_length: self.byte_length,
            redaction: self.redaction,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentMaterial {
    audio_content_digest: Digest,
    independent_content_digest: Option<Digest>,
    output_format: OutputFormat,
    duration_milliseconds: u64,
    byte_length: Option<u64>,
    redaction: RedactionState,
}

/// Bounded synthesis status retained by the Mission consumer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesisStatus {
    Pending,
    Completed,
    Failed,
    Expired,
    ProviderUnknown,
}

impl SynthesisStatus {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }

    pub const fn is_completed(self) -> bool {
        matches!(self, Self::Completed)
    }

    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Completed => 1,
            Self::Failed | Self::Expired | Self::ProviderUnknown => 2,
        }
    }
}

/// Compatibility name for status consumers.
pub type AudioStatus = SynthesisStatus;

/// Transport-level failures remain explicit non-Connected evidence.
#[derive(Clone, Debug, Eq, Error, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    #[error("provider returned HTTP status {status_code}")]
    HttpStatus {
        status_code: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("provider transport timed out")]
    Timeout,
    #[error("provider returned a malformed response")]
    MalformedResponse,
    #[error("provider returned a partial response")]
    PartialResponse,
    #[error("provider and recorded audio byte digests disagree")]
    ByteDigestMismatch,
    #[error("provider access was revoked or lost")]
    AccessRevoked,
    #[error("environment is blocked for native transport")]
    BlockedEnv,
}

impl TransportFailure {
    pub const fn http(status_code: u16) -> Self {
        Self::HttpStatus {
            status_code,
            retry_after_seconds: None,
        }
    }

    pub const fn unauthorized() -> Self {
        Self::http(401)
    }

    pub const fn forbidden() -> Self {
        Self::http(403)
    }

    pub const fn not_found() -> Self {
        Self::http(404)
    }

    pub const fn conflict() -> Self {
        Self::http(409)
    }

    pub const fn rate_limited(retry_after_seconds: u64) -> Self {
        Self::HttpStatus {
            status_code: 429,
            retry_after_seconds: Some(retry_after_seconds),
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status_code, .. } => Some(*status_code),
            Self::Timeout
            | Self::MalformedResponse
            | Self::PartialResponse
            | Self::ByteDigestMismatch
            | Self::AccessRevoked
            | Self::BlockedEnv => None,
        }
    }
}

/// Errors at the typed recording transport boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("transport is blocked by the environment")]
    BlockedEnv,
    #[error("transport failed: {0}")]
    Failure(#[from] TransportFailure),
    #[error("transport response type does not match its typed request")]
    ResponseTypeMismatch,
    #[error("transport request scope does not match the provider scope")]
    ScopeMismatch,
    #[error("transport host is not the official ElevenLabs host")]
    HostMismatch,
}

/// Provider-specific failure categories exposed without raw JSON.
#[derive(Clone, Debug, Eq, Error, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    #[error("proposal does not bind the exact provider registration")]
    ProposalMismatch,
    #[error("response does not bind the exact host")]
    HostMismatch,
    #[error("response voice binding drifted")]
    VoiceDrift,
    #[error("response model binding drifted")]
    ModelDrift,
    #[error("response language binding mismatched")]
    LanguageMismatch,
    #[error("response output format mismatched")]
    OutputFormatMismatch,
    #[error("response config revision or digest mismatched")]
    ConfigMismatch,
    #[error("response text revision or digest mismatched")]
    TextMismatch,
    #[error("response binding digest mismatched")]
    BindingDrift,
    #[error("response operation identity mismatched")]
    OperationMismatch,
    #[error("completed response is missing usage evidence")]
    MissingUsage,
    #[error("completed response is missing exact audio content digest evidence")]
    MissingContentDigest,
    #[error("response usage evidence is invalid or tampered")]
    UsageEvidenceTampered,
    #[error("response usage does not match the bounded proposal")]
    UsageMismatch,
    #[error("response usage exceeds the bounded objective")]
    UsageLimitExceeded,
    #[error("response audio content evidence is invalid or tampered")]
    ContentEvidenceTampered,
    #[error("provider and independent audio content digests disagree")]
    ContentDigestMismatch,
    #[error("response status evidence is malformed or partial")]
    PartialResponse,
    #[error("status receipt digest is invalid or tampered")]
    ReceiptDigestMismatch,
    #[error("status receipt is stale or regresses the operation")]
    StaleStatus,
}

/// Provider errors never collapse blocked, failed, or ambiguous evidence into
/// a successful synthesis.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("input type error: {0}")]
    Input(#[from] TypeError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("provider evidence error: {0}")]
    Evidence(#[from] ProviderErrorKind),
    #[error("provider operation error: {0}")]
    Operation(ProviderErrorKind),
}

/// Only a typed recording operation crosses the injected HTTPS seam in
/// Layer 1. It never performs live synthesis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpsOperation {
    RecordSynthesisEvidence,
}

/// Typed request for the official endpoint shape. Raw text and secret bytes
/// are intentionally absent; the exact text is represented by its digest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpsRequest {
    operation: HttpsOperation,
    host: ApiHost,
    path: String,
    scope: MissionScope,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    character_count: u32,
}

impl HttpsRequest {
    pub fn for_proposal(proposal: &AudioGenerationProposal) -> Self {
        Self {
            operation: HttpsOperation::RecordSynthesisEvidence,
            host: proposal.scope().host().clone(),
            path: format!(
                "/v1/text-to-speech/{}",
                proposal.scope().voice().voice_id().as_str()
            ),
            scope: proposal.scope().clone(),
            operation_id: proposal.fence().operation_id().clone(),
            proposal_fingerprint: proposal.fence().fingerprint().clone(),
            binding: proposal.binding().clone(),
            character_count: proposal.text_character_count(),
        }
    }

    pub const fn operation(&self) -> HttpsOperation {
        self.operation
    }

    pub fn host(&self) -> &ApiHost {
        &self.host
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub fn binding(&self) -> &SynthesisBinding {
        &self.binding
    }

    pub const fn character_count(&self) -> u32 {
        self.character_count
    }
}

/// A typed response containing only bounded metadata and digests.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "response")]
pub enum HttpsResponse {
    Synthesis(SynthesisResponse),
}

/// Compatibility name for fixture callers.
pub type FixtureResponse = HttpsResponse;

/// Recorded TTS response. It cannot hold raw audio bytes.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SynthesisResponse {
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    observed_at: u64,
    response_digest: Digest,
}

/// Compatibility name for callers using receipt language at the transport
/// boundary.
pub type RecordedSynthesis = SynthesisResponse;

impl SynthesisResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn recorded(
        operation_id: OperationId,
        proposal_fingerprint: Digest,
        binding: SynthesisBinding,
        status: SynthesisStatus,
        usage: Option<UsageEvidence>,
        content: Option<AudioContentEvidence>,
        failure: Option<TransportFailure>,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        if !proposal_fingerprint.is_valid() || !binding.text_digest().is_valid() {
            return Err(ProviderError::Input(TypeError::InvalidDigest));
        }
        if observed_at == 0 {
            return Err(ProviderError::Input(TypeError::InvalidRevision));
        }
        let response_digest = digest_serializable(&ResponseMaterial {
            operation_id: operation_id.clone(),
            proposal_fingerprint: proposal_fingerprint.clone(),
            binding: binding.clone(),
            status,
            usage: usage.clone(),
            content: content.clone(),
            failure: failure.clone(),
            observed_at,
        });
        Ok(Self {
            operation_id,
            proposal_fingerprint,
            binding,
            status,
            usage,
            content,
            failure,
            observed_at,
            response_digest,
        })
    }

    pub fn pending(
        proposal: &AudioGenerationProposal,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        Self::recorded(
            proposal.fence().operation_id().clone(),
            proposal.fence().fingerprint().clone(),
            proposal.binding().clone(),
            SynthesisStatus::Pending,
            None,
            None,
            None,
            observed_at,
        )
    }

    pub fn completed(
        proposal: &AudioGenerationProposal,
        usage: UsageEvidence,
        content: AudioContentEvidence,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        Self::recorded(
            proposal.fence().operation_id().clone(),
            proposal.fence().fingerprint().clone(),
            proposal.binding().clone(),
            SynthesisStatus::Completed,
            Some(usage),
            Some(content),
            None,
            observed_at,
        )
    }

    pub fn failed(
        proposal: &AudioGenerationProposal,
        failure: TransportFailure,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        Self::recorded(
            proposal.fence().operation_id().clone(),
            proposal.fence().fingerprint().clone(),
            proposal.binding().clone(),
            SynthesisStatus::Failed,
            None,
            None,
            Some(failure),
            observed_at,
        )
    }

    pub fn expired(
        proposal: &AudioGenerationProposal,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        Self::recorded(
            proposal.fence().operation_id().clone(),
            proposal.fence().fingerprint().clone(),
            proposal.binding().clone(),
            SynthesisStatus::Expired,
            None,
            None,
            Some(TransportFailure::Timeout),
            observed_at,
        )
    }

    pub fn provider_unknown(
        proposal: &AudioGenerationProposal,
        failure: TransportFailure,
        observed_at: u64,
    ) -> Result<Self, ProviderError> {
        Self::recorded(
            proposal.fence().operation_id().clone(),
            proposal.fence().fingerprint().clone(),
            proposal.binding().clone(),
            SynthesisStatus::ProviderUnknown,
            None,
            None,
            Some(failure),
            observed_at,
        )
    }

    fn completed_for_request(request: &HttpsRequest) -> Result<Self, ProviderError> {
        let usage = UsageEvidence::new(
            request.character_count(),
            Some(request.character_count()),
            Some(1_000),
            request.binding().output_format().clone(),
            RedactionState::Redacted,
        )?;
        let content = AudioContentEvidence::new(
            Digest::from_text(format!(
                "loopback-audio:{}",
                request.proposal_fingerprint().as_str()
            )),
            request.binding().output_format().clone(),
            1_000,
            Some(1),
            RedactionState::Redacted,
        )?;
        Self::recorded(
            request.operation_id().clone(),
            request.proposal_fingerprint().clone(),
            request.binding().clone(),
            SynthesisStatus::Completed,
            Some(usage),
            Some(content),
            None,
            1,
        )
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub fn binding(&self) -> &SynthesisBinding {
        &self.binding
    }

    pub const fn status(&self) -> SynthesisStatus {
        self.status
    }

    pub fn usage(&self) -> Option<&UsageEvidence> {
        self.usage.as_ref()
    }

    pub fn content(&self) -> Option<&AudioContentEvidence> {
        self.content.as_ref()
    }

    pub fn failure(&self) -> Option<&TransportFailure> {
        self.failure.as_ref()
    }

    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn verify_digest(&self) -> bool {
        digest_serializable(&ResponseMaterial {
            operation_id: self.operation_id.clone(),
            proposal_fingerprint: self.proposal_fingerprint.clone(),
            binding: self.binding.clone(),
            status: self.status,
            usage: self.usage.clone(),
            content: self.content.clone(),
            failure: self.failure.clone(),
            observed_at: self.observed_at,
        }) == self.response_digest
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseMaterial {
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    observed_at: u64,
}

/// Typed status/usage/content receipt enriched with registration evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SynthesisReceipt {
    scope: MissionScope,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    provider_version: PluginVersion,
    registration_digest: Digest,
    observed_at: u64,
    evidence: ProviderEvidence,
    response_digest: Digest,
    receipt_digest: Digest,
}

/// Compatibility name for status receipt consumers.
pub type StatusReceipt = SynthesisReceipt;

impl SynthesisReceipt {
    fn from_response(
        proposal: &AudioGenerationProposal,
        response: &SynthesisResponse,
        provenance: ProviderProvenance,
        provider_version: PluginVersion,
        registration_digest: &Digest,
    ) -> Result<Self, ProviderError> {
        if !response.verify_digest() {
            return Err(ProviderError::Evidence(
                ProviderErrorKind::ReceiptDigestMismatch,
            ));
        }
        validate_binding(proposal, response)?;
        validate_status_shape(response)?;
        if let Some(content) = response.content() {
            if !content.verify_digest() {
                return Err(ProviderError::Evidence(
                    ProviderErrorKind::ContentEvidenceTampered,
                ));
            }
            if !content.is_consistent() {
                return Err(ProviderError::Evidence(
                    ProviderErrorKind::ContentDigestMismatch,
                ));
            }
        }
        if let Some(usage) = response.usage()
            && !usage.verify_digest()
        {
            return Err(ProviderError::Evidence(
                ProviderErrorKind::UsageEvidenceTampered,
            ));
        }
        let evidence_value = SynthesisResponseMaterial {
            operation_id: response.operation_id().clone(),
            proposal_fingerprint: response.proposal_fingerprint().clone(),
            binding: response.binding().clone(),
            status: response.status(),
            usage: response.usage().cloned(),
            content: response.content().cloned(),
            failure: response.failure().cloned(),
            response_digest: response.response_digest().clone(),
        };
        let evidence = ProviderEvidence::new(
            provenance,
            if provenance == ProviderProvenance::BlockedEnv {
                ProviderStatus::BlockedEnv
            } else {
                ProviderStatus::RecordedEvidence
            },
            proposal.scope(),
            &evidence_value,
        );
        let receipt_digest = digest_serializable(&ReceiptMaterial {
            scope_digest: proposal.scope().digest(),
            operation_id: response.operation_id().clone(),
            proposal_fingerprint: response.proposal_fingerprint().clone(),
            binding: response.binding().clone(),
            status: response.status(),
            usage: response.usage().cloned(),
            content: response.content().cloned(),
            failure: response.failure().cloned(),
            provider_version,
            registration_digest: registration_digest.clone(),
            observed_at: response.observed_at(),
            evidence_digest: evidence.evidence_digest().clone(),
            response_digest: response.response_digest().clone(),
        });
        Ok(Self {
            scope: proposal.scope().clone(),
            operation_id: response.operation_id().clone(),
            proposal_fingerprint: response.proposal_fingerprint().clone(),
            binding: response.binding().clone(),
            status: response.status(),
            usage: response.usage().cloned(),
            content: response.content().cloned(),
            failure: response.failure().cloned(),
            provider_version,
            registration_digest: registration_digest.clone(),
            observed_at: response.observed_at(),
            evidence,
            response_digest: response.response_digest().clone(),
            receipt_digest,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub fn binding(&self) -> &SynthesisBinding {
        &self.binding
    }

    pub const fn status(&self) -> SynthesisStatus {
        self.status
    }

    pub fn usage(&self) -> Option<&UsageEvidence> {
        self.usage.as_ref()
    }

    pub fn content(&self) -> Option<&AudioContentEvidence> {
        self.content.as_ref()
    }

    pub fn failure(&self) -> Option<&TransportFailure> {
        self.failure.as_ref()
    }

    pub const fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    pub fn evidence(&self) -> &ProviderEvidence {
        &self.evidence
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn verify_digest(&self) -> bool {
        let expected_response_digest = digest_serializable(&ResponseMaterial {
            operation_id: self.operation_id.clone(),
            proposal_fingerprint: self.proposal_fingerprint.clone(),
            binding: self.binding.clone(),
            status: self.status,
            usage: self.usage.clone(),
            content: self.content.clone(),
            failure: self.failure.clone(),
            observed_at: self.observed_at,
        });
        if expected_response_digest != self.response_digest {
            return false;
        }
        if self
            .usage
            .as_ref()
            .is_some_and(|usage| !usage.verify_digest())
        {
            return false;
        }
        if self
            .content
            .as_ref()
            .is_some_and(|content| !content.verify_digest() || !content.is_consistent())
        {
            return false;
        }
        let evidence = ProviderEvidence::new(
            self.evidence.provenance(),
            self.evidence.status(),
            &self.scope,
            &SynthesisResponseMaterial {
                operation_id: self.operation_id.clone(),
                proposal_fingerprint: self.proposal_fingerprint.clone(),
                binding: self.binding.clone(),
                status: self.status,
                usage: self.usage.clone(),
                content: self.content.clone(),
                failure: self.failure.clone(),
                response_digest: self.response_digest.clone(),
            },
        );
        if evidence.evidence_digest() != self.evidence.evidence_digest() {
            return false;
        }
        digest_serializable(&ReceiptMaterial {
            scope_digest: self.scope.digest(),
            operation_id: self.operation_id.clone(),
            proposal_fingerprint: self.proposal_fingerprint.clone(),
            binding: self.binding.clone(),
            status: self.status,
            usage: self.usage.clone(),
            content: self.content.clone(),
            failure: self.failure.clone(),
            provider_version: self.provider_version,
            registration_digest: self.registration_digest.clone(),
            observed_at: self.observed_at,
            evidence_digest: self.evidence.evidence_digest().clone(),
            response_digest: self.response_digest.clone(),
        }) == self.receipt_digest
    }

    pub fn projection(&self) -> AudioStatusProjection {
        AudioStatusProjection {
            scope: self.scope.clone(),
            operation_id: self.operation_id.clone(),
            proposal_fingerprint: self.proposal_fingerprint.clone(),
            status: self.status,
            usage: self.usage.clone(),
            content: self.content.clone(),
            failure: self.failure.clone(),
            provider_provenance: self.evidence.provenance(),
            receipt_digest: self.receipt_digest.clone(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SynthesisResponseMaterial {
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    response_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptMaterial {
    scope_digest: Digest,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    binding: SynthesisBinding,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    provider_version: PluginVersion,
    registration_digest: Digest,
    observed_at: u64,
    evidence_digest: Digest,
    response_digest: Digest,
}

/// Redacted bounded status projection for Mission state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioStatusProjection {
    scope: MissionScope,
    operation_id: OperationId,
    proposal_fingerprint: Digest,
    status: SynthesisStatus,
    usage: Option<UsageEvidence>,
    content: Option<AudioContentEvidence>,
    failure: Option<TransportFailure>,
    provider_provenance: ProviderProvenance,
    receipt_digest: Digest,
}

/// Compatibility name for generic result projection callers.
pub type GenerationStatusProjection = AudioStatusProjection;

impl AudioStatusProjection {
    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn proposal_fingerprint(&self) -> &Digest {
        &self.proposal_fingerprint
    }

    pub const fn status(&self) -> SynthesisStatus {
        self.status
    }

    pub fn usage(&self) -> Option<&UsageEvidence> {
        self.usage.as_ref()
    }

    pub fn content(&self) -> Option<&AudioContentEvidence> {
        self.content.as_ref()
    }

    pub fn failure(&self) -> Option<&TransportFailure> {
        self.failure.as_ref()
    }

    pub const fn provider_provenance(&self) -> ProviderProvenance {
        self.provider_provenance
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
}

/// HTTPS transport seam. Layer 1 ships only fixture, recording, loopback, and
/// blocked-environment implementations; no native network transport exists.
pub trait HttpsTransport {
    fn execute(
        &mut self,
        request: HttpsRequest,
        secret: &SecretReference,
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

/// Deterministic fixture/recording transport. It never opens a socket.
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
        secret: &SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        if request.host().as_str() != ApiHost::OFFICIAL {
            return Err(TransportError::HostMismatch);
        }
        if request.scope() != secret.scope() {
            return Err(TransportError::ScopeMismatch);
        }
        let result = self
            .responses
            .pop_front()
            .unwrap_or(Err(TransportError::BlockedEnv));
        let exchange = RecordingExchange {
            request_digest: digest_serializable(&request),
            secret_reference_digest: secret.reference_digest(),
            response_digest: result.as_ref().ok().map(digest_serializable),
            failure: result.as_ref().err().and_then(transport_failure),
        };
        self.exchanges.push(exchange);
        result
    }

    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

fn transport_failure(error: &TransportError) -> Option<TransportFailure> {
    match error {
        TransportError::BlockedEnv => Some(TransportFailure::BlockedEnv),
        TransportError::Failure(failure) => Some(failure.clone()),
        TransportError::ResponseTypeMismatch
        | TransportError::ScopeMismatch
        | TransportError::HostMismatch => None,
    }
}

/// Named fixture transport for callers that do not need to inspect its
/// mutable response queue.
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
        secret: &SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        self.0.execute(request, secret)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }
}

/// Loopback transport for deterministic component tests; it never contacts
/// ElevenLabs and emits only synthetic redacted metadata.
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
        secret: &SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        if request.scope() != secret.scope() {
            return Err(TransportError::ScopeMismatch);
        }
        let response = SynthesisResponse::completed_for_request(&request)
            .map(HttpsResponse::Synthesis)
            .map_err(|_| TransportError::ResponseTypeMismatch)?;
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
        _secret: &SecretReference,
    ) -> Result<HttpsResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

/// A typed ElevenLabs provider backed by an injected read/record transport.
pub struct ElevenLabsProvider<T> {
    registration: ElevenLabsAudioResultRegistration,
    secret: SecretReference,
    transport: T,
}

impl<T: HttpsTransport> ElevenLabsProvider<T> {
    pub fn new(
        registration: ElevenLabsAudioResultRegistration,
        secret: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderError> {
        registration.ensure_active()?;
        if !registration.verify_digest() {
            return Err(ProviderError::Registration(
                RegistrationError::InvalidDigest,
            ));
        }
        registration.ensure_scope(secret.scope())?;
        if secret.provider_id() != PROVIDER_ID {
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

    pub fn registration(&self) -> &ElevenLabsAudioResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MissionScope {
        self.registration.scope()
    }

    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn propose_audio(
        &self,
        objective: &crate::AudioCreationObjective,
    ) -> Result<AudioGenerationProposal, ProviderError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(objective.scope())?;
        Ok(AudioGenerationProposal::new(
            objective.clone(),
            PROVIDER_ID,
            self.registration.provider_version(),
            self.registration.registration_digest().clone(),
        )?)
    }

    pub fn propose_generation(
        &self,
        objective: &crate::AudioCreationObjective,
    ) -> Result<AudioGenerationProposal, ProviderError> {
        self.propose_audio(objective)
    }

    /// Records a fixture/recording/loopback response; no live synthesis is
    /// performed by this method.
    pub fn record_synthesis(
        &mut self,
        proposal: &AudioGenerationProposal,
    ) -> Result<SynthesisReceipt, ProviderError> {
        self.ensure_proposal(proposal)?;
        let request = HttpsRequest::for_proposal(proposal);
        let response = self.transport.execute(request, &self.secret)?;
        let HttpsResponse::Synthesis(response) = response;
        self.record_response(proposal, response)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn record_response(
        &self,
        proposal: &AudioGenerationProposal,
        response: SynthesisResponse,
    ) -> Result<SynthesisReceipt, ProviderError> {
        self.ensure_proposal(proposal)?;
        SynthesisReceipt::from_response(
            proposal,
            &response,
            self.transport.provenance(),
            self.registration.provider_version(),
            self.registration.registration_digest(),
        )
    }

    pub fn record_status(
        &self,
        proposal: &AudioGenerationProposal,
        receipt: SynthesisReceipt,
    ) -> Result<SynthesisReceipt, ProviderError> {
        self.ensure_proposal(proposal)?;
        self.registration.ensure_scope(receipt.scope())?;
        if receipt.registration_digest() != self.registration.registration_digest()
            || receipt.provider_version() != self.registration.provider_version()
            || receipt.proposal_fingerprint() != proposal.fence().fingerprint()
        {
            return Err(ProviderError::Evidence(ProviderErrorKind::ProposalMismatch));
        }
        if receipt.operation_id() != proposal.fence().operation_id() {
            return Err(ProviderError::Evidence(
                ProviderErrorKind::OperationMismatch,
            ));
        }
        if !receipt.verify_digest() {
            return Err(ProviderError::Evidence(
                ProviderErrorKind::ReceiptDigestMismatch,
            ));
        }
        Ok(receipt)
    }

    fn ensure_proposal(&self, proposal: &AudioGenerationProposal) -> Result<(), ProviderError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(proposal.scope())?;
        if !proposal.verify_digest()
            || proposal.registration_digest() != self.registration.registration_digest()
            || proposal.provider_version() != self.registration.provider_version()
            || proposal.provider_id() != PROVIDER_ID
        {
            return Err(ProviderError::Evidence(ProviderErrorKind::ProposalMismatch));
        }
        Ok(())
    }
}

impl<T: HttpsTransport> fmt::Debug for ElevenLabsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ElevenLabsProvider")
            .field("registration", &self.registration)
            .field("secret", &self.secret)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

fn validate_binding(
    proposal: &AudioGenerationProposal,
    response: &SynthesisResponse,
) -> Result<(), ProviderError> {
    if response.proposal_fingerprint() != proposal.fence().fingerprint() {
        return Err(ProviderError::Evidence(ProviderErrorKind::ProposalMismatch));
    }
    if response.operation_id() != proposal.fence().operation_id() {
        return Err(ProviderError::Evidence(
            ProviderErrorKind::OperationMismatch,
        ));
    }
    let expected = proposal.binding();
    let actual = response.binding();
    if actual.host() != expected.host() {
        return Err(ProviderError::Evidence(ProviderErrorKind::HostMismatch));
    }
    if actual.voice() != expected.voice() {
        return Err(ProviderError::Evidence(ProviderErrorKind::VoiceDrift));
    }
    if actual.model() != expected.model() {
        return Err(ProviderError::Evidence(ProviderErrorKind::ModelDrift));
    }
    if actual.language() != expected.language() {
        return Err(ProviderError::Evidence(ProviderErrorKind::LanguageMismatch));
    }
    if actual.output_format() != expected.output_format() {
        return Err(ProviderError::Evidence(
            ProviderErrorKind::OutputFormatMismatch,
        ));
    }
    if actual.config_revision() != expected.config_revision()
        || actual.config_digest() != expected.config_digest()
    {
        return Err(ProviderError::Evidence(ProviderErrorKind::ConfigMismatch));
    }
    if actual.text_revision() != expected.text_revision()
        || actual.text_digest() != expected.text_digest()
    {
        return Err(ProviderError::Evidence(ProviderErrorKind::TextMismatch));
    }
    if actual.digest() != expected.digest() {
        return Err(ProviderError::Evidence(ProviderErrorKind::BindingDrift));
    }
    Ok(())
}

fn validate_status_shape(response: &SynthesisResponse) -> Result<(), ProviderError> {
    match response.status() {
        SynthesisStatus::Pending => {
            if response.usage().is_some()
                || response.content().is_some()
                || response.failure().is_some()
            {
                return Err(ProviderError::Evidence(ProviderErrorKind::PartialResponse));
            }
        }
        SynthesisStatus::Completed => {
            if response.usage().is_none() {
                return Err(ProviderError::Evidence(ProviderErrorKind::MissingUsage));
            }
            if response.content().is_none() {
                return Err(ProviderError::Evidence(
                    ProviderErrorKind::MissingContentDigest,
                ));
            }
            if response.failure().is_some() {
                return Err(ProviderError::Evidence(ProviderErrorKind::PartialResponse));
            }
        }
        SynthesisStatus::Failed | SynthesisStatus::ProviderUnknown | SynthesisStatus::Expired => {
            if response.failure().is_none()
                || response.usage().is_some()
                || response.content().is_some()
            {
                return Err(ProviderError::Evidence(ProviderErrorKind::PartialResponse));
            }
        }
    }
    Ok(())
}
