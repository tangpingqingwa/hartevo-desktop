use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{DeepgramProviderError, DeepgramResultError, DeepgramTransportError};
use crate::model::{
    DeepgramLanguageIndicator, DeepgramQualityIndicators, DeepgramScope,
    DeepgramTranscriptMetadata, DeepgramTranscriptResultEvidence, Digest, RedactionState,
    SecretReference, SegmentEvidence, TranscriptStatus, TransportProvenance, content_digest_for,
    evidence_digest_for, segment_digest_for,
};
use crate::service::DeepgramRegistration;
use crate::transport::{DeepgramReadRequest, DeepgramTransport, RawTranscriptPage, SecretMaterial};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, MAX_BACKOFF_SECONDS, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS,
    MAX_UTTERANCE_SEGMENTS, PLUGIN_VERSION, PROVIDER_ID,
};

/// Host-owned secret resolver boundary. Layer 1 ships only deterministic test
/// resolvers; native keyring/environment resolution remains Layer 2.
pub trait DeepgramCredentialResolver: Clone + fmt::Debug {
    fn resolve(&self, reference: &SecretReference)
    -> Result<SecretMaterial, DeepgramProviderError>;
}

/// Deterministic fixture resolver. Its material is never serialized or shown
/// in Debug, and the provider stores only the opaque reference.
#[derive(Clone, Eq, PartialEq)]
pub struct StaticApiKeyCredentialResolver {
    material: String,
}

impl StaticApiKeyCredentialResolver {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            material: value.into(),
        }
    }

    pub fn api_key(value: impl Into<String>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for StaticApiKeyCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticApiKeyCredentialResolver(<redacted>)")
    }
}

impl DeepgramCredentialResolver for StaticApiKeyCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, DeepgramProviderError> {
        if reference.is_revoked() {
            return Err(DeepgramProviderError::SecretRevoked);
        }
        Ok(SecretMaterial::new(self.material.clone()))
    }
}

/// Explicit native-gap resolver. It can never claim Connected or native.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl DeepgramCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, DeepgramProviderError> {
        Err(DeepgramProviderError::Transport(
            DeepgramTransportError::EnvironmentBlocked,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeepgramProviderState {
    Active,
    Revoked,
    Reversed,
    BlockedEnv,
    AccessDenied,
    Expired,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeepgramRetryPolicy {
    pub max_attempts: u8,
    pub max_backoff_seconds: u32,
}

impl Default for DeepgramRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_RETRY_ATTEMPTS,
            max_backoff_seconds: MAX_BACKOFF_SECONDS,
        }
    }
}

impl DeepgramRetryPolicy {
    pub fn new(max_attempts: u8, max_backoff_seconds: u32) -> Result<Self, DeepgramResultError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&max_attempts)
            || max_backoff_seconds > MAX_BACKOFF_SECONDS
        {
            return Err(DeepgramResultError::InvalidScope);
        }
        Ok(Self {
            max_attempts,
            max_backoff_seconds,
        })
    }

    #[must_use]
    pub fn backoff_seconds(&self, attempt: u8, retry_after_seconds: u32) -> u32 {
        let exponential = 1u32
            .checked_shl(u32::from(attempt.saturating_sub(1)))
            .unwrap_or(u32::MAX);
        retry_after_seconds
            .max(exponential)
            .min(self.max_backoff_seconds)
    }
}

/// Typed bounded Deepgram result provider. It reads only the registered,
/// digest-bound result seam and never submits or stores audio/media.
#[derive(Clone, Debug)]
pub struct DeepgramProvider<T, R>
where
    T: DeepgramTransport,
    R: DeepgramCredentialResolver,
{
    registration: DeepgramRegistration,
    transport: T,
    resolver: R,
    retry_policy: DeepgramRetryPolicy,
    state: DeepgramProviderState,
}

impl<T, R> DeepgramProvider<T, R>
where
    T: DeepgramTransport,
    R: DeepgramCredentialResolver,
{
    pub fn new(
        registration: DeepgramRegistration,
        transport: T,
        resolver: R,
    ) -> Result<Self, DeepgramProviderError> {
        Self::with_retry_policy(
            registration,
            transport,
            resolver,
            DeepgramRetryPolicy::default(),
        )
    }

    pub fn with_retry_policy(
        registration: DeepgramRegistration,
        transport: T,
        resolver: R,
        retry_policy: DeepgramRetryPolicy,
    ) -> Result<Self, DeepgramProviderError> {
        registration.validate()?;
        match registration.state() {
            crate::model::RegistrationState::Active => {}
            crate::model::RegistrationState::Revoked => {
                return Err(DeepgramProviderError::RegistrationRevoked);
            }
            crate::model::RegistrationState::Reversed => {
                return Err(DeepgramProviderError::RegistrationReversed);
            }
        }
        Ok(Self {
            registration,
            transport,
            resolver,
            retry_policy,
            state: DeepgramProviderState::Active,
        })
    }

    #[must_use]
    pub fn registration(&self) -> &DeepgramRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    #[must_use]
    pub const fn state(&self) -> DeepgramProviderState {
        self.state
    }

    #[must_use]
    pub const fn retry_policy(&self) -> DeepgramRetryPolicy {
        self.retry_policy
    }

    pub fn operations(&self) -> Vec<crate::transport::DeepgramTransportOperation> {
        self.transport.operations()
    }

    pub fn describe_scope(
        &self,
    ) -> Result<DeepgramProviderScopeDescription, DeepgramProviderError> {
        self.registration.validate()?;
        Ok(DeepgramProviderScopeDescription {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: self.registration.contract_digest().clone(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.registration.scope_digest().clone(),
            host_digest: self.registration.scope().host.digest(),
            project_digest: self.registration.scope().deepgram_project.digest(),
            request_digest: self.registration.scope().request.digest(),
            consent_digest: self.registration.scope().consent.digest(),
            provenance: self.transport.provenance(),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke(&self) -> Result<(), DeepgramResultError> {
        self.registration.revoke()
    }

    pub fn reverse(&self) -> Result<(), DeepgramResultError> {
        self.registration.reverse()
    }

    pub fn read(&mut self) -> Result<DeepgramTranscriptResultEvidence, DeepgramProviderError> {
        self.read_transcript_result()
    }

    pub fn read_transcript_result(
        &mut self,
    ) -> Result<DeepgramTranscriptResultEvidence, DeepgramProviderError> {
        let scope = self.registration.scope().clone();
        self.read_for_scope(&scope)
    }

    pub fn read_for_scope(
        &mut self,
        requested_scope: &DeepgramScope,
    ) -> Result<DeepgramTranscriptResultEvidence, DeepgramProviderError> {
        self.ensure_active()?;
        if requested_scope != self.registration.scope() {
            return Err(DeepgramProviderError::ScopeMismatch);
        }
        let secret = match self.resolver.resolve(self.registration.secret_reference()) {
            Ok(secret) => secret,
            Err(DeepgramProviderError::Transport(DeepgramTransportError::EnvironmentBlocked)) => {
                self.state = DeepgramProviderState::BlockedEnv;
                return Err(DeepgramProviderError::Transport(
                    DeepgramTransportError::EnvironmentBlocked,
                ));
            }
            Err(error) => return Err(error),
        };

        let mut page_token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_segments = BTreeSet::new();
        let mut page_count = 0usize;
        let mut segments = Vec::new();
        let mut baseline = None;
        let mut attempts = 0u8;

        loop {
            if page_count >= self.registration.scope().utterance_window.max_pages {
                self.state = DeepgramProviderState::AccessDenied;
                return Err(DeepgramProviderError::PaginationLimit);
            }
            let request =
                DeepgramReadRequest::new(self.registration.scope().clone(), page_token.clone());
            attempts = attempts.saturating_add(1);
            let page = match self.transport.read_transcript_result(&request, &secret) {
                Ok(page) => {
                    attempts = 0;
                    page
                }
                Err(error) if Self::is_retryable(&error) => {
                    if attempts < self.retry_policy.max_attempts {
                        let _ = self
                            .retry_policy
                            .backoff_seconds(attempts, error.retry_after_seconds().unwrap_or(0));
                        continue;
                    }
                    if let DeepgramTransportError::RateLimited {
                        retry_after_seconds,
                    } = error
                    {
                        self.state = DeepgramProviderState::RateLimited;
                        return Err(DeepgramProviderError::RateLimited {
                            retry_after_seconds: retry_after_seconds
                                .min(self.retry_policy.max_backoff_seconds),
                            attempts,
                        });
                    }
                    return Err(DeepgramProviderError::Transport(error));
                }
                Err(error) => {
                    self.update_state_for_transport(&error);
                    return Err(map_transport_error(error));
                }
            };
            page_count += 1;
            self.validate_page(&request, &page)?;
            let snapshot = page.snapshot.clone();
            if let Some(previous) = &baseline {
                self.validate_snapshot_continuity(previous, &snapshot)?;
            } else {
                baseline = Some(snapshot);
            }
            for segment in &page.segments {
                if !seen_segments.insert(segment.segment_id.clone()) {
                    return Err(DeepgramProviderError::DuplicateSegment);
                }
            }
            segments.extend(page.segments);
            if segments.len() > self.registration.scope().utterance_window.max_segments {
                return Err(DeepgramProviderError::SegmentLimit);
            }
            let Some(next_token) = page.next_page_token else {
                break;
            };
            if !seen_tokens.insert(next_token.digest()) {
                return Err(DeepgramProviderError::PaginationLoop);
            }
            page_token = Some(next_token);
        }

        let snapshot = baseline.ok_or(DeepgramProviderError::IncompleteEvidence)?;
        self.project(snapshot, segments, page_count)
    }

    pub fn verify(
        &self,
        evidence: &DeepgramTranscriptResultEvidence,
    ) -> Result<(), DeepgramProviderError> {
        if evidence.registration_digest != *self.registration.binding_digest() {
            return Err(DeepgramProviderError::RegistrationDigestMismatch);
        }
        if evidence.scope_digest != *self.registration.scope_digest() {
            return Err(DeepgramProviderError::ScopeMismatch);
        }
        evidence.validate_integrity().map_err(map_result_error)
    }

    fn is_retryable(error: &DeepgramTransportError) -> bool {
        matches!(
            error,
            DeepgramTransportError::RateLimited { .. }
                | DeepgramTransportError::Timeout
                | DeepgramTransportError::Server5xx { .. }
        )
    }

    fn update_state_for_transport(&mut self, error: &DeepgramTransportError) {
        match error {
            DeepgramTransportError::EnvironmentBlocked => {
                self.state = DeepgramProviderState::BlockedEnv;
            }
            DeepgramTransportError::Unauthorized401
            | DeepgramTransportError::Forbidden403
            | DeepgramTransportError::NotFound404
            | DeepgramTransportError::AccessLost => {
                self.state = DeepgramProviderState::AccessDenied;
            }
            DeepgramTransportError::Expired => self.state = DeepgramProviderState::Expired,
            _ => {}
        }
    }

    fn ensure_active(&mut self) -> Result<(), DeepgramProviderError> {
        match self.registration.ensure_active() {
            Ok(()) if self.state == DeepgramProviderState::Active => Ok(()),
            Ok(()) => Err(DeepgramProviderError::RegistrationDrift),
            Err(DeepgramResultError::RegistrationRevoked) => {
                self.state = DeepgramProviderState::Revoked;
                Err(DeepgramProviderError::RegistrationRevoked)
            }
            Err(DeepgramResultError::RegistrationReversed) => {
                self.state = DeepgramProviderState::Reversed;
                Err(DeepgramProviderError::RegistrationReversed)
            }
            Err(DeepgramResultError::SecretRevoked) => Err(DeepgramProviderError::SecretRevoked),
            Err(error) => Err(DeepgramProviderError::Registration(error)),
        }
    }

    fn validate_page(
        &self,
        request: &DeepgramReadRequest,
        page: &RawTranscriptPage,
    ) -> Result<(), DeepgramProviderError> {
        page.validate_integrity().map_err(map_transport_error)?;
        if page.bounded_size() > MAX_RESPONSE_BYTES {
            return Err(DeepgramProviderError::ResponseTooLarge);
        }
        if page.request_page_token_digest != request.page_token_digest() {
            return Err(DeepgramProviderError::Tamper);
        }
        self.validate_snapshot_scope(&page.snapshot.scope)?;
        if !page.snapshot.redact {
            return Err(DeepgramProviderError::UnredactedContent);
        }
        if page.segments.len() > MAX_UTTERANCE_SEGMENTS {
            return Err(DeepgramProviderError::Partial);
        }
        for segment in &page.segments {
            if !segment.redacted {
                return Err(DeepgramProviderError::UnredactedContent);
            }
        }
        Ok(())
    }

    fn validate_snapshot_scope(&self, actual: &DeepgramScope) -> Result<(), DeepgramProviderError> {
        let expected = self.registration.scope();
        if actual.host != expected.host {
            return Err(DeepgramProviderError::HostDrift);
        }
        if actual.deepgram_project != expected.deepgram_project {
            return Err(DeepgramProviderError::ProjectDrift);
        }
        if actual.request != expected.request {
            return Err(DeepgramProviderError::RequestDrift);
        }
        if actual.model != expected.model {
            return Err(DeepgramProviderError::ModelDrift);
        }
        if actual.audio_fingerprint != expected.audio_fingerprint {
            return Err(DeepgramProviderError::AudioFingerprintDrift);
        }
        if actual.utterance_window != expected.utterance_window {
            return Err(DeepgramProviderError::UtteranceWindowDrift);
        }
        if actual.project != expected.project {
            return Err(DeepgramProviderError::HartevoProjectDrift);
        }
        if actual.mission != expected.mission {
            return Err(DeepgramProviderError::MissionDrift);
        }
        if actual.work_product != expected.work_product {
            return Err(DeepgramProviderError::WorkProductDrift);
        }
        if actual.consent != expected.consent {
            return Err(DeepgramProviderError::ConsentDrift);
        }
        Ok(())
    }

    fn validate_snapshot_continuity(
        &self,
        previous: &crate::transport::RawTranscriptSnapshot,
        current: &crate::transport::RawTranscriptSnapshot,
    ) -> Result<(), DeepgramProviderError> {
        self.validate_snapshot_scope(&current.scope)?;
        if previous.status != current.status {
            return Err(DeepgramProviderError::StatusDrift);
        }
        if previous.request_id_digest != current.request_id_digest
            || previous.detected_language != current.detected_language
            || previous.language_confidence != current.language_confidence
            || previous.transcript_confidence != current.transcript_confidence
            || previous.redact != current.redact
        {
            return Err(DeepgramProviderError::RevisionDrift);
        }
        Ok(())
    }

    fn project(
        &self,
        snapshot: crate::transport::RawTranscriptSnapshot,
        raw_segments: Vec<crate::transport::RawSegment>,
        page_count: usize,
    ) -> Result<DeepgramTranscriptResultEvidence, DeepgramProviderError> {
        let segments: Vec<SegmentEvidence> = raw_segments
            .iter()
            .map(crate::transport::RawSegment::projected)
            .collect();
        let actual_segment_digest = segment_digest_for(&segments);
        let actual_content_digest = content_digest_for(&segments);
        if snapshot.expected_segment_digest != actual_segment_digest {
            return Err(DeepgramProviderError::SegmentMismatch);
        }
        if snapshot.expected_content_digest != actual_content_digest {
            return Err(DeepgramProviderError::ContentMismatch);
        }
        let status = TranscriptStatus::from_provider(&snapshot.status);
        let language = DeepgramLanguageIndicator {
            code: snapshot.detected_language,
            detected: true,
            confidence: snapshot.language_confidence,
        };
        let covered_duration_ms = segments
            .iter()
            .map(|segment| segment.end_ms)
            .max()
            .unwrap_or(0)
            .saturating_sub(
                segments
                    .iter()
                    .map(|segment| segment.start_ms)
                    .min()
                    .unwrap_or(0),
            );
        let confidences = segments
            .iter()
            .map(|segment| segment.confidence)
            .collect::<Vec<_>>();
        let quality = DeepgramQualityIndicators::from_confidences(
            snapshot.transcript_confidence,
            &confidences,
            covered_duration_ms,
        )
        .map_err(map_result_error)?;
        let metadata = DeepgramTranscriptMetadata {
            request_id_digest: snapshot.request_id_digest,
            created_digest: snapshot.created_digest,
            duration_ms: snapshot.duration_ms,
            channel_count: snapshot.channel_count,
            response_bytes: 0,
        };
        let scope = self.registration.scope();
        let mut evidence = DeepgramTranscriptResultEvidence {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST.to_owned())
                .map_err(map_result_error)?,
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.registration.scope_digest().clone(),
            registration_digest: self.registration.binding_digest().clone(),
            project_digest: scope.project.digest(),
            mission_digest: scope.mission.digest(),
            work_product_digest: scope.work_product.digest(),
            consent_digest: scope.consent.digest(),
            request_digest: scope.request.digest(),
            model_digest: scope.model.digest(),
            audio_fingerprint_digest: scope.audio_fingerprint.scope_digest(),
            utterance_window_digest: scope.utterance_window.digest(),
            metadata,
            language,
            quality,
            status: status.clone(),
            status_digest: status.digest(),
            segment_count: segments.len(),
            segments,
            segment_digest: actual_segment_digest,
            content_digest: actual_content_digest,
            segment_page_count: page_count,
            redaction: RedactionState::DigestOnly,
            provenance: self.transport.provenance(),
            connected: false,
            native: false,
            first_party: false,
            complete: status.is_complete(),
            evidence_digest: Digest::from_text("unsealed-evidence-digest"),
        };
        evidence.evidence_digest = evidence_digest_for(&evidence);
        evidence.validate_integrity().map_err(map_result_error)?;
        Ok(evidence)
    }
}

fn map_transport_error(error: DeepgramTransportError) -> DeepgramProviderError {
    match error {
        DeepgramTransportError::EnvironmentBlocked => {
            DeepgramProviderError::Transport(DeepgramTransportError::EnvironmentBlocked)
        }
        DeepgramTransportError::Unauthorized401
        | DeepgramTransportError::Forbidden403
        | DeepgramTransportError::NotFound404
        | DeepgramTransportError::AccessLost => DeepgramProviderError::Denied,
        DeepgramTransportError::Expired => DeepgramProviderError::Expired,
        DeepgramTransportError::PartialResponse => DeepgramProviderError::Partial,
        DeepgramTransportError::MalformedResponse => DeepgramProviderError::Tamper,
        DeepgramTransportError::RateLimited {
            retry_after_seconds,
        } => DeepgramProviderError::RateLimited {
            retry_after_seconds,
            attempts: 1,
        },
        other => DeepgramProviderError::Transport(other),
    }
}

fn map_result_error(error: DeepgramResultError) -> DeepgramProviderError {
    match error {
        DeepgramResultError::Denied => DeepgramProviderError::Denied,
        DeepgramResultError::Partial => DeepgramProviderError::Partial,
        DeepgramResultError::Expired => DeepgramProviderError::Expired,
        DeepgramResultError::RateLimited => DeepgramProviderError::RateLimited {
            retry_after_seconds: 0,
            attempts: 1,
        },
        DeepgramResultError::ProviderUnknown => DeepgramProviderError::ProviderUnknown,
        DeepgramResultError::Tamper
        | DeepgramResultError::DigestMismatch
        | DeepgramResultError::SegmentMismatch
        | DeepgramResultError::ContentMismatch
        | DeepgramResultError::DuplicateSegment => DeepgramProviderError::Tamper,
        DeepgramResultError::UnredactedContent => DeepgramProviderError::UnredactedContent,
        DeepgramResultError::InvalidConfidence => DeepgramProviderError::InvalidConfidence,
        DeepgramResultError::ResponseTooLarge => DeepgramProviderError::ResponseTooLarge,
        DeepgramResultError::PaginationLoop => DeepgramProviderError::PaginationLoop,
        DeepgramResultError::PaginationLimit => DeepgramProviderError::PaginationLimit,
        DeepgramResultError::SegmentLimit => DeepgramProviderError::SegmentLimit,
        other => DeepgramProviderError::Registration(other),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramProviderScopeDescription {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: crate::model::PluginVersion,
    pub scope_digest: Digest,
    pub host_digest: Digest,
    pub project_digest: Digest,
    pub request_digest: Digest,
    pub consent_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[cfg(test)]
mod provider_tests {
    use super::DeepgramRetryPolicy;

    #[test]
    fn backoff_is_bounded_and_deterministic() {
        let policy = DeepgramRetryPolicy::default();
        assert_eq!(policy.backoff_seconds(1, 0), 1);
        assert_eq!(policy.backoff_seconds(3, 100), 30);
    }
}
