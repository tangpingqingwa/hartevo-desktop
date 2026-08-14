use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::consumer::ProposalDisposition;
use crate::error::{AssemblyAiProviderError, AssemblyAiResultError, AssemblyAiTransportError};
use crate::model::{
    AssemblyAiScope, ConfigurationProjection, Digest, ModelProjection, RedactionState,
    SecretReference, TranscriptResultProjection, TranscriptStatusProjection, TransportProvenance,
    UtteranceEvidence, content_digest_for, evidence_digest_for, segment_digest_for,
    validate_confidence,
};
use crate::service::AssemblyAiRegistration;
use crate::transport::{
    AssemblyAiTransport, RawTranscriptPage, SecretMaterial, TranscriptReadRequest,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, MAX_CHAPTERS, MAX_RESPONSE_BYTES, MAX_SEGMENTS,
    PLUGIN_VERSION, PROVIDER_ID,
};

/// Host-owned API-key resolver. Native keyring/environment resolution is
/// deliberately absent; the static resolver is deterministic fixture support.
pub trait AssemblyAiCredentialResolver: Clone + fmt::Debug {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, AssemblyAiProviderError>;
}

/// Deterministic test-only API-key material resolver. The material is never
/// serialized or formatted, and the provider stores only the opaque reference.
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

impl AssemblyAiCredentialResolver for StaticApiKeyCredentialResolver {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, AssemblyAiProviderError> {
        if reference.is_revoked() {
            return Err(AssemblyAiProviderError::SecretRevoked);
        }
        Ok(SecretMaterial::new(self.material.clone()))
    }
}

/// Explicit Layer-2 native-gap credential resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl AssemblyAiCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, AssemblyAiProviderError> {
        Err(AssemblyAiProviderError::Transport(
            AssemblyAiTransportError::EnvironmentBlocked,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AssemblyAiProviderState {
    Active,
    Revoked,
    Reversed,
    BlockedEnv,
    AccessLost,
}

/// Typed AssemblyAI provider boundary. It reads bounded fixture-like pages,
/// checks exact scope and response digests, and projects redacted evidence.
#[derive(Clone, Debug)]
pub struct AssemblyAiProvider<T, R>
where
    T: AssemblyAiTransport,
    R: AssemblyAiCredentialResolver,
{
    registration: AssemblyAiRegistration,
    transport: T,
    resolver: R,
    state: AssemblyAiProviderState,
}

impl<T, R> AssemblyAiProvider<T, R>
where
    T: AssemblyAiTransport,
    R: AssemblyAiCredentialResolver,
{
    pub fn new(
        registration: AssemblyAiRegistration,
        transport: T,
        resolver: R,
    ) -> Result<Self, AssemblyAiProviderError> {
        registration.validate()?;
        match registration.state() {
            crate::model::RegistrationState::Active => {}
            crate::model::RegistrationState::Revoked => {
                return Err(AssemblyAiProviderError::RegistrationRevoked);
            }
            crate::model::RegistrationState::Reversed => {
                return Err(AssemblyAiProviderError::RegistrationReversed);
            }
        }
        Ok(Self {
            registration,
            transport,
            resolver,
            state: AssemblyAiProviderState::Active,
        })
    }

    #[must_use]
    pub fn registration(&self) -> &AssemblyAiRegistration {
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
    pub const fn state(&self) -> AssemblyAiProviderState {
        self.state
    }

    pub fn operations(&self) -> Vec<crate::transport::AssemblyAiTransportOperation> {
        self.transport.operations()
    }

    pub fn describe_scope(&self) -> Result<ProviderScopeDescription, AssemblyAiProviderError> {
        self.registration.validate()?;
        Ok(ProviderScopeDescription {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: self.registration.contract_digest().clone(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.registration.scope_digest().clone(),
            host_digest: self.registration.scope().host.digest(),
            account_digest: self.registration.scope().account.digest(),
            permission_digest: self.registration.permission_snapshot().digest().clone(),
            provenance: self.transport.provenance(),
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke(&self) -> Result<(), AssemblyAiResultError> {
        self.registration.revoke()
    }

    pub fn reverse(&self) -> Result<(), AssemblyAiResultError> {
        self.registration.reverse()
    }

    /// Read exactly the registered transcript scope. This method performs no
    /// submission or polling operation; it only consumes bounded result pages.
    pub fn read_transcript(
        &mut self,
    ) -> Result<TranscriptResultProjection, AssemblyAiProviderError> {
        let scope = self.registration.scope().clone();
        self.read_transcript_for_scope(&scope)
    }

    pub fn read_transcript_for_scope(
        &mut self,
        requested_scope: &AssemblyAiScope,
    ) -> Result<TranscriptResultProjection, AssemblyAiProviderError> {
        self.ensure_active()?;
        self.registration
            .scope()
            .validate()
            .map_err(AssemblyAiProviderError::Registration)?;
        if requested_scope != self.registration.scope() {
            return Err(AssemblyAiProviderError::ScopeMismatch);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AssemblyAiProviderError::SecretRevoked);
        }
        let secret = match self.resolver.resolve(self.registration.secret_reference()) {
            Ok(secret) => secret,
            Err(AssemblyAiProviderError::Transport(
                AssemblyAiTransportError::EnvironmentBlocked,
            )) => {
                self.state = AssemblyAiProviderState::BlockedEnv;
                return Err(AssemblyAiProviderError::Transport(
                    AssemblyAiTransportError::EnvironmentBlocked,
                ));
            }
            Err(error) => return Err(error),
        };

        let mut token = None;
        let mut seen_tokens = BTreeSet::new();
        let mut page_count = 0usize;
        let mut raw_utterances = Vec::new();
        let mut baseline = None;

        loop {
            if page_count >= self.registration.scope().segment.max_pages {
                self.state = AssemblyAiProviderState::AccessLost;
                return Err(AssemblyAiProviderError::PaginationLimit);
            }
            let request =
                TranscriptReadRequest::new(self.registration.scope().clone(), token.clone());
            let page = match self.transport.read_transcript(&request, &secret) {
                Ok(page) => page,
                Err(error) => {
                    if matches!(error, AssemblyAiTransportError::EnvironmentBlocked) {
                        self.state = AssemblyAiProviderState::BlockedEnv;
                    } else if matches!(error, AssemblyAiTransportError::AccessLost) {
                        self.state = AssemblyAiProviderState::AccessLost;
                    }
                    return Err(AssemblyAiProviderError::Transport(error));
                }
            };
            page_count += 1;
            self.validate_page(&request, &page)?;
            let page_snapshot = page.snapshot.clone();
            if let Some(previous) = &baseline {
                self.validate_snapshot_continuity(previous, &page_snapshot)?;
            } else {
                baseline = Some(page_snapshot);
            }
            raw_utterances.extend(page.utterances);
            if raw_utterances.len() > self.registration.scope().segment.max_segments {
                return Err(AssemblyAiProviderError::SegmentLimit);
            }
            let Some(next_token) = page.next_page_token else {
                break;
            };
            if !seen_tokens.insert(next_token.digest()) {
                return Err(AssemblyAiProviderError::PaginationLoop);
            }
            token = Some(next_token);
        }

        let snapshot = baseline.ok_or(AssemblyAiProviderError::IncompleteEvidence)?;
        self.project(snapshot, raw_utterances, page_count)
    }

    /// Re-verify the public status, segment, content, scope, and registration
    /// fences without performing another provider read.
    pub fn verify_projection(
        &self,
        projection: &TranscriptResultProjection,
    ) -> Result<(), AssemblyAiProviderError> {
        if projection.registration_digest != *self.registration.binding_digest() {
            return Err(AssemblyAiProviderError::RegistrationDigestMismatch);
        }
        if projection.scope_digest != *self.registration.scope_digest() {
            return Err(AssemblyAiProviderError::ScopeMismatch);
        }
        projection
            .validate_integrity()
            .map_err(map_projection_error)
    }

    fn ensure_active(&mut self) -> Result<(), AssemblyAiProviderError> {
        match self.registration.ensure_active() {
            Ok(()) if self.state == AssemblyAiProviderState::Active => Ok(()),
            Ok(()) => Err(AssemblyAiProviderError::RegistrationDrift),
            Err(AssemblyAiResultError::RegistrationRevoked) => {
                self.state = AssemblyAiProviderState::Revoked;
                Err(AssemblyAiProviderError::RegistrationRevoked)
            }
            Err(AssemblyAiResultError::RegistrationReversed) => {
                self.state = AssemblyAiProviderState::Reversed;
                Err(AssemblyAiProviderError::RegistrationReversed)
            }
            Err(AssemblyAiResultError::SecretRevoked) => {
                Err(AssemblyAiProviderError::SecretRevoked)
            }
            Err(error) => Err(AssemblyAiProviderError::Registration(error)),
        }
    }

    fn validate_page(
        &self,
        request: &TranscriptReadRequest,
        page: &RawTranscriptPage,
    ) -> Result<(), AssemblyAiProviderError> {
        page.validate_integrity().map_err(|error| match error {
            AssemblyAiTransportError::PartialResponse => AssemblyAiProviderError::PartialResponse,
            _ => AssemblyAiProviderError::MalformedResponse,
        })?;
        let response_size = serde_json::to_vec(&(
            &page.snapshot,
            &page.utterances,
            &page.request_page_token_digest,
            &page
                .next_page_token
                .as_ref()
                .map(crate::model::TranscriptPageToken::digest),
        ))
        .map_err(|_| AssemblyAiProviderError::MalformedResponse)?
        .len();
        if response_size > MAX_RESPONSE_BYTES {
            return Err(AssemblyAiProviderError::ResponseTooLarge);
        }
        if page.request_page_token_digest != request.page_token_digest() {
            return Err(AssemblyAiProviderError::MalformedResponse);
        }
        self.validate_snapshot_scope(&page.snapshot.scope)?;
        if page.snapshot.language_code != self.registration.scope().configuration.language_code
            || page.snapshot.language_detection
                != self.registration.scope().configuration.language_detection
            || page.snapshot.redact_pii != self.registration.scope().configuration.redact_pii
        {
            return Err(AssemblyAiProviderError::ConfigurationDrift);
        }
        if !page.snapshot.redact_pii {
            return Err(AssemblyAiProviderError::UnredactedContent);
        }
        if let Some(confidence) = page.snapshot.language_confidence {
            validate_confidence(confidence)
                .map_err(|_| AssemblyAiProviderError::InvalidConfidence)?;
        }
        if let Some(confidence) = page.snapshot.transcript_confidence {
            validate_confidence(confidence)
                .map_err(|_| AssemblyAiProviderError::InvalidConfidence)?;
        }
        if page.snapshot.chapters.len() > MAX_CHAPTERS {
            return Err(AssemblyAiProviderError::SegmentLimit);
        }
        for chapter in &page.snapshot.chapters {
            if chapter.end_ms < chapter.start_ms
                || chapter.title_digest.as_ref().is_some_and(|d| !d.is_valid())
                || chapter
                    .summary_digest
                    .as_ref()
                    .is_some_and(|d| !d.is_valid())
            {
                return Err(AssemblyAiProviderError::MalformedResponse);
            }
        }
        if let Some(summary) = &page.snapshot.summary
            && (!summary.metadata_digest.is_valid()
                || summary
                    .kind_digest
                    .as_ref()
                    .is_some_and(|digest| !digest.is_valid())
                || summary
                    .model_digest
                    .as_ref()
                    .is_some_and(|digest| !digest.is_valid())
                || summary
                    .content_digest
                    .as_ref()
                    .is_some_and(|digest| !digest.is_valid()))
        {
            return Err(AssemblyAiProviderError::MalformedResponse);
        }
        for utterance in &page.utterances {
            if !utterance.redacted {
                return Err(AssemblyAiProviderError::UnredactedContent);
            }
            validate_confidence(utterance.confidence)
                .map_err(|_| AssemblyAiProviderError::InvalidConfidence)?;
        }
        Ok(())
    }

    fn validate_snapshot_scope(
        &self,
        actual: &AssemblyAiScope,
    ) -> Result<(), AssemblyAiProviderError> {
        let expected = self.registration.scope();
        if actual.host != expected.host {
            return Err(AssemblyAiProviderError::HostDrift);
        }
        if actual.account != expected.account {
            return Err(AssemblyAiProviderError::AccountDrift);
        }
        if actual.source != expected.source {
            return Err(AssemblyAiProviderError::SourceDrift);
        }
        if actual.transcript != expected.transcript {
            return Err(AssemblyAiProviderError::TranscriptDrift);
        }
        if actual.model != expected.model {
            return Err(AssemblyAiProviderError::ModelDrift);
        }
        if actual.configuration != expected.configuration {
            return Err(AssemblyAiProviderError::ConfigurationDrift);
        }
        if actual.segment != expected.segment {
            return Err(AssemblyAiProviderError::SegmentScopeDrift);
        }
        if actual.mission != expected.mission {
            return Err(AssemblyAiProviderError::MissionDrift);
        }
        if actual.project != expected.project {
            return Err(AssemblyAiProviderError::ProjectDrift);
        }
        if actual.work_product != expected.work_product {
            return Err(AssemblyAiProviderError::WorkProductDrift);
        }
        if actual.permission != expected.permission {
            return Err(AssemblyAiProviderError::PermissionDrift);
        }
        Ok(())
    }

    fn validate_snapshot_continuity(
        &self,
        previous: &crate::transport::RawTranscriptSnapshot,
        current: &crate::transport::RawTranscriptSnapshot,
    ) -> Result<(), AssemblyAiProviderError> {
        self.validate_snapshot_scope(&current.scope)?;
        if previous.status != current.status {
            return Err(AssemblyAiProviderError::StatusDrift);
        }
        if previous.language_code != current.language_code
            || previous.language_detection != current.language_detection
            || previous.redact_pii != current.redact_pii
            || previous.transcript_confidence != current.transcript_confidence
            || previous.language_confidence != current.language_confidence
            || previous.chapters != current.chapters
            || previous.summary != current.summary
        {
            return Err(AssemblyAiProviderError::ConfigurationDrift);
        }
        Ok(())
    }

    fn project(
        &self,
        snapshot: crate::transport::RawTranscriptSnapshot,
        raw_utterances: Vec<crate::transport::RawUtterance>,
        page_count: usize,
    ) -> Result<TranscriptResultProjection, AssemblyAiProviderError> {
        let mut seen_segment_ids = BTreeSet::new();
        let utterances: Vec<UtteranceEvidence> = raw_utterances
            .into_iter()
            .map(|raw| {
                if !seen_segment_ids.insert(raw.segment_id.clone()) {
                    return Err(AssemblyAiProviderError::DuplicateSegment);
                }
                if !raw.redacted {
                    return Err(AssemblyAiProviderError::UnredactedContent);
                }
                let utterance = UtteranceEvidence {
                    segment_id: raw.segment_id,
                    speaker_label: raw.speaker_label,
                    start_ms: raw.start_ms,
                    end_ms: raw.end_ms,
                    confidence: raw.confidence,
                    content_digest: raw.content_digest,
                };
                utterance.validate().map_err(map_projection_error)?;
                Ok(utterance)
            })
            .collect::<Result<_, AssemblyAiProviderError>>()?;
        if utterances.len() > MAX_SEGMENTS {
            return Err(AssemblyAiProviderError::SegmentLimit);
        }
        let actual_segment_digest = segment_digest_for(&utterances);
        let actual_content_digest = content_digest_for(&utterances);
        if snapshot.expected_segment_digest != actual_segment_digest {
            return Err(AssemblyAiProviderError::SegmentMismatch);
        }
        if snapshot.expected_content_digest != actual_content_digest {
            return Err(AssemblyAiProviderError::ContentMismatch);
        }
        let status = TranscriptStatusProjection::from_provider(&snapshot.status);
        let language = crate::model::TranscriptLanguage {
            code: snapshot.language_code,
            detected: snapshot.language_detection,
            confidence: snapshot.language_confidence,
        };
        let confidence_values: Vec<f32> = utterances.iter().map(|item| item.confidence).collect();
        let confidence = crate::model::ConfidenceSummary::from_values(
            snapshot.transcript_confidence,
            &confidence_values,
        )
        .map_err(map_projection_error)?;
        let model = ModelProjection {
            revision: self.registration.scope().model.revision,
            speech_model_digest: self
                .registration
                .scope()
                .model
                .speech_model
                .as_ref()
                .map(crate::model::ModelId::digest),
            language_model_digest: self
                .registration
                .scope()
                .model
                .language_model
                .as_ref()
                .map(crate::model::ModelId::digest),
            acoustic_model_digest: self
                .registration
                .scope()
                .model
                .acoustic_model
                .as_ref()
                .map(crate::model::ModelId::digest),
        };
        let configuration = ConfigurationProjection {
            id_digest: self.registration.scope().configuration.id.digest(),
            revision: self.registration.scope().configuration.revision,
            configuration_digest: self.registration.scope().configuration.digest(),
            language_code: self
                .registration
                .scope()
                .configuration
                .language_code
                .clone(),
            language_detection: self.registration.scope().configuration.language_detection,
            speaker_labels: self.registration.scope().configuration.speaker_labels,
            redact_pii: self.registration.scope().configuration.redact_pii,
            summary_enabled: self.registration.scope().configuration.summary_enabled,
            chapter_enabled: self.registration.scope().configuration.chapter_enabled,
        };
        let speaker_label_digests = utterances
            .iter()
            .filter_map(|utterance| utterance.speaker_label.as_deref())
            .map(Digest::from_text)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let chapters = snapshot
            .chapters
            .into_iter()
            .map(|chapter| crate::model::ChapterMetadata {
                ordinal: chapter.ordinal,
                start_ms: chapter.start_ms,
                end_ms: chapter.end_ms,
                title_digest: chapter.title_digest,
                summary_digest: chapter.summary_digest,
            })
            .collect();
        let summary = snapshot
            .summary
            .map(|summary| crate::model::SummaryMetadata {
                kind_digest: summary.kind_digest,
                model_digest: summary.model_digest,
                content_digest: summary.content_digest,
                metadata_digest: summary.metadata_digest,
            });
        let mut projection = TranscriptResultProjection {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::from_hex(CONTRACT_DIGEST.to_owned())
                .map_err(map_projection_error)?,
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION,
            scope_digest: self.registration.scope_digest().clone(),
            registration_digest: self.registration.binding_digest().clone(),
            source: self.registration.scope().source.clone(),
            transcript: self.registration.scope().transcript.clone(),
            status: status.clone(),
            language,
            model,
            configuration,
            speaker_count: speaker_label_digests.len(),
            speaker_label_digests,
            utterance_count: utterances.len(),
            utterances,
            confidence,
            chapters,
            summary,
            redaction: RedactionState::Redacted,
            content_digest: actual_content_digest,
            segment_digest: actual_segment_digest,
            segment_scope_digest: self.registration.scope().segment.digest(),
            segment_page_count: page_count,
            status_digest: status.digest(),
            provenance: self.transport.provenance(),
            connected: false,
            native: false,
            first_party: false,
            complete: true,
            evidence_digest: Digest::from_text("unsealed-evidence-digest"),
        };
        projection.evidence_digest = evidence_digest_for(&projection);
        projection
            .validate_integrity()
            .map_err(map_projection_error)?;
        Ok(projection)
    }
}

fn map_projection_error(error: AssemblyAiResultError) -> AssemblyAiProviderError {
    match error {
        AssemblyAiResultError::InvalidConfidence => AssemblyAiProviderError::InvalidConfidence,
        AssemblyAiResultError::UnredactedContent => AssemblyAiProviderError::UnredactedContent,
        AssemblyAiResultError::SpeakerIdentityMismatch => {
            AssemblyAiProviderError::SpeakerIdentityMismatch
        }
        AssemblyAiResultError::SegmentMismatch => AssemblyAiProviderError::SegmentMismatch,
        AssemblyAiResultError::ContentMismatch => AssemblyAiProviderError::ContentMismatch,
        AssemblyAiResultError::DigestMismatch => {
            AssemblyAiProviderError::RegistrationDigestMismatch
        }
        AssemblyAiResultError::InvalidProposal => AssemblyAiProviderError::IncompleteEvidence,
        _ => AssemblyAiProviderError::MalformedResponse,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderScopeDescription {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: crate::model::PluginVersion,
    pub scope_digest: Digest,
    pub host_digest: Digest,
    pub account_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

// Keep the import visible to rustdoc users without exposing a proposal as a
// provider authority. It is also a compile-time guard against accidental use.
#[allow(dead_code)]
const _PROPOSAL_BOUNDARY: ProposalDisposition = ProposalDisposition::DecisionPending;

#[cfg(test)]
mod provider_tests {
    use super::AssemblyAiProvider;

    #[test]
    fn provider_type_is_generic_over_fixture_transport_and_resolver() {
        fn assert_provider<T, R>(_provider: &AssemblyAiProvider<T, R>)
        where
            T: crate::transport::AssemblyAiTransport,
            R: crate::provider::AssemblyAiCredentialResolver,
        {
        }
        let _ = assert_provider::<
            crate::transport::FakeTransport,
            crate::provider::StaticApiKeyCredentialResolver,
        >;
    }
}
