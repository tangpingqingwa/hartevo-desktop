use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::DeepgramTransportError;
use crate::model::{
    DeepgramPageToken, DeepgramScope, Digest, SegmentEvidence, SegmentId, TransportProvenance,
    canonical_digest, content_digest_for, segment_digest_for,
};
use crate::{MAX_RESPONSE_BYTES, MAX_UTTERANCE_SEGMENTS, MAX_WINDOW_PAGES};

/// Credential material is visible only to a test resolver/transport call. It
/// has no serialization and its Debug implementation is redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretMaterial {
    value: String,
}

impl SecretMaterial {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// A bounded read request. The opaque page token itself never crosses the
/// serializable operation boundary.
#[derive(Clone, Debug)]
pub struct DeepgramReadRequest {
    pub scope: DeepgramScope,
    pub page_token: Option<DeepgramPageToken>,
}

impl DeepgramReadRequest {
    pub fn new(scope: DeepgramScope, page_token: Option<DeepgramPageToken>) -> Self {
        Self { scope, page_token }
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(DeepgramPageToken::digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTransportOperation {
    pub endpoint: String,
    pub request_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub outcome: TransportOutcome,
    pub retry_after_seconds: Option<u32>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportOutcome {
    Success,
    Error,
}

/// Layer-1 transport seam. There is intentionally no live HTTP implementation
/// and no write method.
pub trait DeepgramTransport: Clone + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_transcript_result(
        &mut self,
        request: &DeepgramReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError>;

    fn operations(&self) -> Vec<DeepgramTransportOperation>;
}

/// A segment input retains only a content digest. The constructor accepts test
/// text solely to hash it immediately; the text is never stored.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawSegment {
    pub segment_id: SegmentId,
    pub start_ms: u64,
    pub end_ms: u64,
    pub channel: u16,
    pub speaker_index: Option<u16>,
    pub confidence: f32,
    pub content_digest: Digest,
    pub redacted: bool,
}

impl RawSegment {
    pub fn new(
        segment_id: SegmentId,
        start_ms: u64,
        end_ms: u64,
        channel: u16,
        speaker_index: Option<u16>,
        confidence: f32,
        redacted_text: impl AsRef<str>,
    ) -> Self {
        Self {
            segment_id,
            start_ms,
            end_ms,
            channel,
            speaker_index,
            confidence,
            content_digest: Digest::from_text(redacted_text.as_ref()),
            redacted: true,
        }
    }

    /// Test-only redaction failure fixture. It still stores no source text.
    pub fn unredacted_for_test(
        segment_id: SegmentId,
        start_ms: u64,
        end_ms: u64,
        channel: u16,
        speaker_index: Option<u16>,
        confidence: f32,
        text: impl AsRef<str>,
    ) -> Self {
        let mut segment = Self::new(
            segment_id,
            start_ms,
            end_ms,
            channel,
            speaker_index,
            confidence,
            text,
        );
        segment.redacted = false;
        segment
    }

    pub fn projected(&self) -> SegmentEvidence {
        SegmentEvidence {
            segment_id: self.segment_id.clone(),
            start_ms: self.start_ms,
            end_ms: self.end_ms,
            channel: self.channel,
            speaker_index: self.speaker_index,
            confidence: self.confidence,
            content_digest: self.content_digest.clone(),
        }
    }

    fn validate(&self) -> Result<(), DeepgramTransportError> {
        self.segment_id
            .validate()
            .map_err(|_| DeepgramTransportError::MalformedResponse)?;
        if self.end_ms < self.start_ms
            || self.channel == 0
            || !self.content_digest.is_valid()
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.confidence)
        {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        Ok(())
    }
}

/// Bounded metadata repeated in each fixture page. It contains no provider
/// transcript body, words, media, or free-form error text.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawTranscriptSnapshot {
    pub scope: DeepgramScope,
    pub status: String,
    pub request_id_digest: Digest,
    pub created_digest: Option<Digest>,
    pub duration_ms: u64,
    pub channel_count: u16,
    pub detected_language: Option<String>,
    pub language_confidence: Option<f32>,
    pub transcript_confidence: Option<f32>,
    pub redact: bool,
    pub expected_segment_digest: Digest,
    pub expected_content_digest: Digest,
    pub error_code_digest: Option<Digest>,
}

impl RawTranscriptSnapshot {
    pub fn for_scope(
        scope: &DeepgramScope,
        status: impl Into<String>,
    ) -> Result<Self, DeepgramTransportError> {
        scope
            .validate()
            .map_err(|_| DeepgramTransportError::MalformedResponse)?;
        let status = status.into();
        if status.is_empty() || status.len() > 64 || status.chars().any(char::is_control) {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        Ok(Self {
            scope: scope.clone(),
            status,
            request_id_digest: scope.request.id.digest(),
            created_digest: Some(Digest::from_text("fixture-created")),
            duration_ms: 1_000,
            channel_count: 1,
            detected_language: scope.model.language.clone(),
            language_confidence: Some(0.99),
            transcript_confidence: Some(0.95),
            redact: scope.model.features.redact,
            expected_segment_digest: Digest::from_text("unsealed-segment-digest"),
            expected_content_digest: Digest::from_text("unsealed-content-digest"),
            error_code_digest: None,
        })
    }

    #[must_use]
    pub fn with_expected_digests(mut self, segment: Digest, content: Digest) -> Self {
        self.expected_segment_digest = segment;
        self.expected_content_digest = content;
        self
    }

    #[must_use]
    pub fn with_language(mut self, code: Option<String>, confidence: Option<f32>) -> Self {
        self.detected_language = code;
        self.language_confidence = confidence;
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, duration_ms: u64, channel_count: u16) -> Self {
        self.duration_ms = duration_ms;
        self.channel_count = channel_count;
        self
    }

    #[must_use]
    pub fn with_error_code_digest(mut self, digest: Option<Digest>) -> Self {
        self.error_code_digest = digest;
        self
    }

    fn validate(&self) -> Result<(), DeepgramTransportError> {
        self.scope
            .validate()
            .map_err(|_| DeepgramTransportError::MalformedResponse)?;
        if self.status.is_empty()
            || self.status.len() > 64
            || self.status.chars().any(char::is_control)
            || !self.request_id_digest.is_valid()
            || self.created_digest.as_ref().is_some_and(|d| !d.is_valid())
            || self.channel_count == 0
            || !self.expected_segment_digest.is_valid()
            || !self.expected_content_digest.is_valid()
            || self
                .error_code_digest
                .as_ref()
                .is_some_and(|d| !d.is_valid())
        {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        if let Some(confidence) = self.language_confidence
            && (!confidence.is_finite() || !(0.0..=1.0).contains(&confidence))
        {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        if let Some(confidence) = self.transcript_confidence
            && (!confidence.is_finite() || !(0.0..=1.0).contains(&confidence))
        {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        Ok(())
    }
}

/// One bounded result page. It is intentionally not Serialize because the
/// continuation token has a private raw field; operations expose only its
/// digest.
#[derive(Clone, Debug, PartialEq)]
pub struct RawTranscriptPage {
    pub snapshot: RawTranscriptSnapshot,
    pub segments: Vec<RawSegment>,
    pub request_page_token_digest: Option<Digest>,
    pub next_page_token: Option<DeepgramPageToken>,
    pub payload_digest: Digest,
}

impl RawTranscriptPage {
    pub fn new(
        snapshot: RawTranscriptSnapshot,
        segments: Vec<RawSegment>,
        next_page_token: Option<DeepgramPageToken>,
    ) -> Result<Self, DeepgramTransportError> {
        for segment in &segments {
            segment.validate()?;
        }
        let mut page = Self {
            snapshot,
            segments,
            request_page_token_digest: None,
            next_page_token,
            payload_digest: Digest::from_text("unsealed-page-digest"),
        };
        page.refresh_digest();
        Ok(page)
    }

    pub fn refresh_digest(&mut self) {
        self.payload_digest = self.calculate_payload_digest();
    }

    #[must_use]
    pub fn with_request_page_token(mut self, token: Option<DeepgramPageToken>) -> Self {
        self.request_page_token_digest = token.map(|value| value.digest());
        self.refresh_digest();
        self
    }

    #[must_use]
    pub fn with_expected_digests(mut self, segment: Digest, content: Digest) -> Self {
        self.snapshot = self.snapshot.with_expected_digests(segment, content);
        self.refresh_digest();
        self
    }

    pub fn validate_integrity(&self) -> Result<(), DeepgramTransportError> {
        if self.payload_digest != self.calculate_payload_digest() {
            return Err(DeepgramTransportError::MalformedResponse);
        }
        self.snapshot.validate()?;
        if self.segments.len() > MAX_UTTERANCE_SEGMENTS {
            return Err(DeepgramTransportError::PartialResponse);
        }
        for segment in &self.segments {
            segment.validate()?;
        }
        Ok(())
    }

    pub(crate) fn bounded_size(&self) -> usize {
        serde_json::to_vec(&PageDigestMaterial {
            snapshot: &self.snapshot,
            segments: &self.segments,
            request_page_token_digest: &self.request_page_token_digest,
            next_page_token_digest: self.next_page_token.as_ref().map(DeepgramPageToken::digest),
        })
        .map_or(MAX_RESPONSE_BYTES + 1, |bytes| bytes.len())
    }

    fn calculate_payload_digest(&self) -> Digest {
        canonical_digest(&PageDigestMaterial {
            snapshot: &self.snapshot,
            segments: &self.segments,
            request_page_token_digest: &self.request_page_token_digest,
            next_page_token_digest: self.next_page_token.as_ref().map(DeepgramPageToken::digest),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PageDigestMaterial<'a> {
    snapshot: &'a RawTranscriptSnapshot,
    segments: &'a [RawSegment],
    request_page_token_digest: &'a Option<Digest>,
    next_page_token_digest: Option<Digest>,
}

/// Deterministic bounded pages shared by all non-native transports.
#[derive(Clone, Debug)]
pub struct TranscriptFixture {
    pages: Vec<RawTranscriptPage>,
}

impl TranscriptFixture {
    pub fn new(mut pages: Vec<RawTranscriptPage>) -> Result<Self, DeepgramTransportError> {
        if pages.is_empty() || pages.len() > MAX_WINDOW_PAGES {
            return Err(DeepgramTransportError::PartialResponse);
        }
        for index in 0..pages.len() {
            if index > 0 {
                let token = pages[index - 1]
                    .next_page_token
                    .clone()
                    .ok_or(DeepgramTransportError::PartialResponse)?;
                pages[index] = pages[index].clone().with_request_page_token(Some(token));
            }
            pages[index].validate_integrity()?;
        }
        let segment_count: usize = pages.iter().map(|page| page.segments.len()).sum();
        if segment_count > MAX_UTTERANCE_SEGMENTS {
            return Err(DeepgramTransportError::PartialResponse);
        }
        Ok(Self { pages })
    }

    /// Used by tamper tests to hold a deliberately invalid page without
    /// normalizing or validating it.
    pub fn from_pages_unchecked(
        pages: Vec<RawTranscriptPage>,
    ) -> Result<Self, DeepgramTransportError> {
        if pages.is_empty() || pages.len() > MAX_WINDOW_PAGES {
            return Err(DeepgramTransportError::PartialResponse);
        }
        Ok(Self { pages })
    }

    pub fn from_segments(
        scope: &DeepgramScope,
        status: impl Into<String>,
        segments: Vec<RawSegment>,
    ) -> Result<Self, DeepgramTransportError> {
        let projected: Vec<SegmentEvidence> = segments.iter().map(RawSegment::projected).collect();
        let snapshot = RawTranscriptSnapshot::for_scope(scope, status)?.with_expected_digests(
            segment_digest_for(&projected),
            content_digest_for(&projected),
        );
        Self::new(vec![RawTranscriptPage::new(snapshot, segments, None)?])
    }

    pub fn pages(&self) -> &[RawTranscriptPage] {
        &self.pages
    }

    fn page_for(&self, token: Option<&Digest>) -> Option<RawTranscriptPage> {
        self.pages
            .iter()
            .find(|page| page.request_page_token_digest.as_ref() == token)
            .cloned()
    }
}

#[derive(Clone, Debug)]
struct FixtureEngine {
    fixture: TranscriptFixture,
    provenance: TransportProvenance,
    errors: Vec<DeepgramTransportError>,
    error_index: usize,
    operations: Vec<DeepgramTransportOperation>,
}

impl FixtureEngine {
    fn new(fixture: TranscriptFixture, provenance: TransportProvenance) -> Self {
        Self {
            fixture,
            provenance,
            errors: Vec::new(),
            error_index: 0,
            operations: Vec::new(),
        }
    }

    fn with_errors(mut self, errors: Vec<DeepgramTransportError>) -> Self {
        self.errors = errors;
        self
    }

    fn read(
        &mut self,
        request: &DeepgramReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        let request_digest = request.scope.request.digest();
        if secret.is_empty() {
            return self.fail(request, DeepgramTransportError::MalformedResponse);
        }
        if let Some(error) = self.errors.get(self.error_index).cloned() {
            self.error_index += 1;
            return self.fail(request, error);
        }
        let Some(page) = self.fixture.page_for(request.page_token_digest().as_ref()) else {
            return self.fail(request, DeepgramTransportError::MalformedResponse);
        };
        self.operations.push(DeepgramTransportOperation {
            endpoint: "/v1/listen".to_owned(),
            request_digest,
            page_token_digest: request.page_token_digest(),
            outcome: TransportOutcome::Success,
            retry_after_seconds: None,
            provenance: self.provenance,
            connected: false,
            native: false,
            first_party: false,
        });
        Ok(page)
    }

    fn fail(
        &mut self,
        request: &DeepgramReadRequest,
        error: DeepgramTransportError,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        self.operations.push(DeepgramTransportOperation {
            endpoint: "/v1/listen".to_owned(),
            request_digest: request.scope.request.digest(),
            page_token_digest: request.page_token_digest(),
            outcome: TransportOutcome::Error,
            retry_after_seconds: error
                .retry_after_seconds()
                .map(|value| value.min(crate::MAX_BACKOFF_SECONDS)),
            provenance: self.provenance,
            connected: false,
            native: false,
            first_party: false,
        });
        Err(error)
    }

    fn operations(&self) -> Vec<DeepgramTransportOperation> {
        self.operations.clone()
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    engine: FixtureEngine,
}

impl FakeTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            engine: FixtureEngine::new(fixture, TransportProvenance::Fake),
        }
    }

    #[must_use]
    pub fn with_error(self, error: DeepgramTransportError) -> Self {
        self.with_errors(vec![error])
    }

    #[must_use]
    pub fn with_errors(mut self, errors: Vec<DeepgramTransportError>) -> Self {
        self.engine = self.engine.with_errors(errors);
        self
    }

    #[must_use]
    pub fn request_count(&self) -> usize {
        self.engine.operations.len()
    }
}

pub type FixtureTransport = FakeTransport;

impl DeepgramTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        self.engine.provenance
    }

    fn read_transcript_result(
        &mut self,
        request: &DeepgramReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        self.engine.read(request, secret)
    }

    fn operations(&self) -> Vec<DeepgramTransportOperation> {
        self.engine.operations()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    engine: FixtureEngine,
}

impl RecordingTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            engine: FixtureEngine::new(fixture, TransportProvenance::Recording),
        }
    }

    #[must_use]
    pub fn with_errors(mut self, errors: Vec<DeepgramTransportError>) -> Self {
        self.engine = self.engine.with_errors(errors);
        self
    }

    #[must_use]
    pub fn recording_digest(&self) -> Digest {
        canonical_digest(&self.engine.operations)
    }
}

impl DeepgramTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.engine.provenance
    }

    fn read_transcript_result(
        &mut self,
        request: &DeepgramReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        self.engine.read(request, secret)
    }

    fn operations(&self) -> Vec<DeepgramTransportOperation> {
        self.engine.operations()
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    engine: FixtureEngine,
}

impl LoopbackTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            engine: FixtureEngine::new(fixture, TransportProvenance::Loopback),
        }
    }
}

impl DeepgramTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.engine.provenance
    }

    fn read_transcript_result(
        &mut self,
        request: &DeepgramReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        self.engine.read(request, secret)
    }

    fn operations(&self) -> Vec<DeepgramTransportOperation> {
        self.engine.operations()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport {
    operations: Vec<DeepgramTransportOperation>,
}

impl DeepgramTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_transcript_result(
        &mut self,
        request: &DeepgramReadRequest,
        _secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, DeepgramTransportError> {
        self.operations.push(DeepgramTransportOperation {
            endpoint: "/v1/listen".to_owned(),
            request_digest: request.scope.request.digest(),
            page_token_digest: request.page_token_digest(),
            outcome: TransportOutcome::Error,
            retry_after_seconds: None,
            provenance: TransportProvenance::BlockedEnv,
            connected: false,
            native: false,
            first_party: false,
        });
        Err(DeepgramTransportError::EnvironmentBlocked)
    }

    fn operations(&self) -> Vec<DeepgramTransportOperation> {
        self.operations.clone()
    }
}
