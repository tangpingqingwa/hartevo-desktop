use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::AssemblyAiTransportError;
use crate::model::{
    AssemblyAiScope, Digest, TranscriptPageToken, TransportProvenance, canonical_digest,
    content_digest_for, segment_digest_for,
};
use crate::{MAX_PAGES, MAX_SEGMENTS};

/// Secret material is only available inside a fixture resolver/transport call.
/// It has no serialization or raw `Debug` representation.
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

/// A read request with an opaque continuation token. The token is never
/// serializable or printable; only its digest is recorded in operations.
#[derive(Clone, Debug)]
pub struct TranscriptReadRequest {
    pub scope: AssemblyAiScope,
    pub page_token: Option<TranscriptPageToken>,
}

impl TranscriptReadRequest {
    pub fn new(scope: AssemblyAiScope, page_token: Option<TranscriptPageToken>) -> Self {
        Self { scope, page_token }
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(TranscriptPageToken::digest)
    }
}

/// A bounded transport operation record. It is diagnostic recording, not a
/// durable provider receipt and contains no secret or opaque token value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyAiTransportOperation {
    pub endpoint: String,
    pub page_token_digest: Option<Digest>,
    pub outcome: TransportOutcome,
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

/// The transport seam is intentionally read-only. Layer 1 implementations
/// can provide deterministic fixture, recording, loopback, or blocked-env
/// behavior, but no live HTTP implementation exists in this crate.
pub trait AssemblyAiTransport: Clone + fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read_transcript(
        &mut self,
        request: &TranscriptReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError>;

    fn operations(&self) -> Vec<AssemblyAiTransportOperation>;
}

/// A redacted utterance input. The constructor hashes the supplied fixture
/// text immediately and retains no text, making raw transcript export
/// structurally impossible through this type.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawUtterance {
    pub segment_id: crate::model::SegmentId,
    pub speaker_label: Option<String>,
    pub start_ms: u64,
    pub end_ms: u64,
    pub confidence: f32,
    pub content_digest: Digest,
    pub redacted: bool,
}

impl RawUtterance {
    pub fn new(
        segment_id: crate::model::SegmentId,
        speaker_label: Option<String>,
        start_ms: u64,
        end_ms: u64,
        confidence: f32,
        redacted_text: impl AsRef<str>,
    ) -> Self {
        Self {
            segment_id,
            speaker_label,
            start_ms,
            end_ms,
            confidence,
            content_digest: Digest::from_text(redacted_text.as_ref()),
            redacted: true,
        }
    }

    pub fn unredacted_for_test(
        segment_id: crate::model::SegmentId,
        speaker_label: Option<String>,
        start_ms: u64,
        end_ms: u64,
        confidence: f32,
        text: impl AsRef<str>,
    ) -> Self {
        let mut value = Self::new(
            segment_id,
            speaker_label,
            start_ms,
            end_ms,
            confidence,
            text,
        );
        value.redacted = false;
        value
    }

    fn validate(&self) -> Result<(), AssemblyAiTransportError> {
        self.segment_id
            .validate()
            .map_err(|_| AssemblyAiTransportError::MalformedResponse)?;
        if self.end_ms < self.start_ms || !self.content_digest.is_valid() {
            return Err(AssemblyAiTransportError::MalformedResponse);
        }
        if let Some(label) = &self.speaker_label
            && (label.is_empty()
                || label.len() > 32
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)))
        {
            return Err(AssemblyAiTransportError::MalformedResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawChapter {
    pub ordinal: usize,
    pub start_ms: u64,
    pub end_ms: u64,
    pub title_digest: Option<Digest>,
    pub summary_digest: Option<Digest>,
}

impl RawChapter {
    pub fn new(
        ordinal: usize,
        start_ms: u64,
        end_ms: u64,
        title: Option<&str>,
        summary: Option<&str>,
    ) -> Self {
        Self {
            ordinal,
            start_ms,
            end_ms,
            title_digest: title.map(Digest::from_text),
            summary_digest: summary.map(Digest::from_text),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawSummary {
    pub kind_digest: Option<Digest>,
    pub model_digest: Option<Digest>,
    pub content_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl RawSummary {
    pub fn new(
        kind: Option<&str>,
        model: Option<&str>,
        content: Option<&str>,
        metadata: &str,
    ) -> Self {
        Self {
            kind_digest: kind.map(Digest::from_text),
            model_digest: model.map(Digest::from_text),
            content_digest: content.map(Digest::from_text),
            metadata_digest: Digest::from_text(metadata),
        }
    }
}

/// The bounded metadata snapshot repeated in each fixture page. It binds the
/// exact registered scope and stores only redacted metadata/digests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawTranscriptSnapshot {
    pub scope: AssemblyAiScope,
    pub status: String,
    pub language_code: Option<String>,
    pub language_detection: bool,
    pub language_confidence: Option<f32>,
    pub transcript_confidence: Option<f32>,
    pub redact_pii: bool,
    pub chapters: Vec<RawChapter>,
    pub summary: Option<RawSummary>,
    pub expected_segment_digest: Digest,
    pub expected_content_digest: Digest,
    pub error_digest: Option<Digest>,
}

impl RawTranscriptSnapshot {
    pub fn for_scope(
        scope: &AssemblyAiScope,
        status: impl Into<String>,
    ) -> Result<Self, AssemblyAiTransportError> {
        scope
            .validate()
            .map_err(|_| AssemblyAiTransportError::MalformedResponse)?;
        Ok(Self {
            scope: scope.clone(),
            status: status.into(),
            language_code: scope.configuration.language_code.clone(),
            language_detection: scope.configuration.language_detection,
            language_confidence: None,
            transcript_confidence: None,
            redact_pii: scope.configuration.redact_pii,
            chapters: Vec::new(),
            summary: None,
            expected_segment_digest: Digest::from_text("unsealed-segment-digest"),
            expected_content_digest: Digest::from_text("unsealed-content-digest"),
            error_digest: None,
        })
    }
}

/// One bounded page from the transcript read seam. A page has no transcript
/// body; it carries only redacted utterance metadata and content digests.
#[derive(Clone, Debug, PartialEq)]
pub struct RawTranscriptPage {
    pub snapshot: RawTranscriptSnapshot,
    pub utterances: Vec<RawUtterance>,
    pub request_page_token_digest: Option<Digest>,
    pub next_page_token: Option<TranscriptPageToken>,
    pub payload_digest: Digest,
}

impl RawTranscriptPage {
    pub fn new(
        snapshot: RawTranscriptSnapshot,
        utterances: Vec<RawUtterance>,
        next_page_token: Option<TranscriptPageToken>,
    ) -> Result<Self, AssemblyAiTransportError> {
        for utterance in &utterances {
            utterance.validate()?;
        }
        let mut page = Self {
            snapshot,
            utterances,
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

    fn calculate_payload_digest(&self) -> Digest {
        canonical_digest(&RawTranscriptPageMaterial {
            snapshot: &self.snapshot,
            utterances: &self.utterances,
            request_page_token_digest: &self.request_page_token_digest,
            next_page_token_digest: self
                .next_page_token
                .as_ref()
                .map(TranscriptPageToken::digest),
        })
    }

    pub fn validate_integrity(&self) -> Result<(), AssemblyAiTransportError> {
        if self.payload_digest != self.calculate_payload_digest() {
            return Err(AssemblyAiTransportError::MalformedResponse);
        }
        if self.utterances.len() > MAX_SEGMENTS {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        for utterance in &self.utterances {
            utterance.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn with_request_page_token(mut self, token: Option<TranscriptPageToken>) -> Self {
        self.request_page_token_digest = token.map(|token| token.digest());
        self.refresh_digest();
        self
    }

    #[must_use]
    pub fn with_expected_digests(mut self, segment_digest: Digest, content_digest: Digest) -> Self {
        self.snapshot.expected_segment_digest = segment_digest;
        self.snapshot.expected_content_digest = content_digest;
        self.refresh_digest();
        self
    }
}

/// Deterministic bounded pages used by all Layer-1 transports.
#[derive(Clone, Debug)]
pub struct TranscriptFixture {
    pages: Vec<RawTranscriptPage>,
}

impl TranscriptFixture {
    pub fn new(mut pages: Vec<RawTranscriptPage>) -> Result<Self, AssemblyAiTransportError> {
        if pages.is_empty() || pages.len() > MAX_PAGES {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        let all_utterances: Vec<_> = pages
            .iter()
            .flat_map(|page| page.utterances.iter().cloned())
            .collect();
        if all_utterances.len() > MAX_SEGMENTS {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        let segment_digest = segment_digest_for(
            &all_utterances
                .iter()
                .map(|raw| crate::model::UtteranceEvidence {
                    segment_id: raw.segment_id.clone(),
                    speaker_label: raw.speaker_label.clone(),
                    start_ms: raw.start_ms,
                    end_ms: raw.end_ms,
                    confidence: raw.confidence,
                    content_digest: raw.content_digest.clone(),
                })
                .collect::<Vec<_>>(),
        );
        let content_digest = content_digest_for(
            &all_utterances
                .iter()
                .map(|raw| crate::model::UtteranceEvidence {
                    segment_id: raw.segment_id.clone(),
                    speaker_label: raw.speaker_label.clone(),
                    start_ms: raw.start_ms,
                    end_ms: raw.end_ms,
                    confidence: raw.confidence,
                    content_digest: raw.content_digest.clone(),
                })
                .collect::<Vec<_>>(),
        );
        for (index, page) in pages.iter_mut().enumerate() {
            page.snapshot.expected_segment_digest = segment_digest.clone();
            page.snapshot.expected_content_digest = content_digest.clone();
            if index == 0 {
                page.request_page_token_digest = None;
            }
            page.refresh_digest();
        }
        Ok(Self { pages })
    }

    pub fn for_scope(
        scope: &AssemblyAiScope,
        status: impl Into<String>,
    ) -> Result<Self, AssemblyAiTransportError> {
        let snapshot = RawTranscriptSnapshot::for_scope(scope, status)?;
        Self::new(vec![RawTranscriptPage::new(snapshot, Vec::new(), None)?])
    }

    /// Build pages without normalizing the provider-supplied expected digests.
    /// This is used to exercise content/segment mismatch and tamper handling.
    pub fn from_pages(pages: Vec<RawTranscriptPage>) -> Result<Self, AssemblyAiTransportError> {
        if pages.is_empty() || pages.len() > MAX_PAGES {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        for page in &pages {
            page.validate_integrity()?;
        }
        Ok(Self { pages })
    }

    /// Test-only-shaped construction that preserves a tampered page so the
    /// provider, rather than the fixture constructor, can reject it.
    pub fn from_pages_unchecked(
        pages: Vec<RawTranscriptPage>,
    ) -> Result<Self, AssemblyAiTransportError> {
        if pages.is_empty() || pages.len() > MAX_PAGES {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        Ok(Self { pages })
    }

    pub fn from_utterances(
        scope: &AssemblyAiScope,
        status: impl Into<String>,
        utterances: Vec<RawUtterance>,
    ) -> Result<Self, AssemblyAiTransportError> {
        let status = status.into();
        if utterances.len() > scope.segment.max_segments {
            return Err(AssemblyAiTransportError::PartialResponse);
        }
        let chunks = utterances.chunks(scope.segment.page_size);
        let mut pages = Vec::new();
        for (index, chunk) in chunks.enumerate() {
            let snapshot = RawTranscriptSnapshot::for_scope(scope, status.clone())?;
            let next = if index + 1 < utterances.len().div_ceil(scope.segment.page_size) {
                Some(
                    TranscriptPageToken::new(format!("assemblyai-fixture-page-{}", index + 1))
                        .map_err(|_| AssemblyAiTransportError::MalformedResponse)?,
                )
            } else {
                None
            };
            pages.push(RawTranscriptPage::new(snapshot, chunk.to_vec(), next)?);
        }
        if pages.is_empty() {
            return Self::for_scope(scope, status);
        }
        for (index, page) in pages.iter_mut().enumerate().skip(1) {
            let token = TranscriptPageToken::new(format!("assemblyai-fixture-page-{index}"))
                .map_err(|_| AssemblyAiTransportError::MalformedResponse)?;
            *page = page.clone().with_request_page_token(Some(token));
        }
        Self::new(pages)
    }

    pub fn pages(&self) -> &[RawTranscriptPage] {
        &self.pages
    }
}

fn validate_secret(secret: &SecretMaterial) -> Result<(), AssemblyAiTransportError> {
    if secret.is_empty() {
        Err(AssemblyAiTransportError::Unauthorized401)
    } else {
        Ok(())
    }
}

fn fixture_read(
    fixture: &TranscriptFixture,
    request: &TranscriptReadRequest,
    secret: &SecretMaterial,
) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
    validate_secret(secret)?;
    let index = match &request.page_token {
        None => 0,
        Some(token) => {
            let token_digest = token.digest();
            fixture
                .pages()
                .iter()
                .position(|page| page.request_page_token_digest.as_ref() == Some(&token_digest))
                .ok_or(AssemblyAiTransportError::MalformedResponse)?
        }
    };
    let page = fixture
        .pages()
        .get(index)
        .ok_or(AssemblyAiTransportError::PartialResponse)?;
    if page.request_page_token_digest != request.page_token_digest() {
        return Err(AssemblyAiTransportError::MalformedResponse);
    }
    Ok(page.clone())
}

fn success_operation(
    provenance: TransportProvenance,
    request: &TranscriptReadRequest,
) -> AssemblyAiTransportOperation {
    AssemblyAiTransportOperation {
        endpoint: String::from("GET /v2/transcript/{transcript_id}"),
        page_token_digest: request.page_token_digest(),
        outcome: TransportOutcome::Success,
        provenance,
        connected: false,
        native: false,
        first_party: false,
    }
}

fn error_operation(
    provenance: TransportProvenance,
    request: &TranscriptReadRequest,
) -> AssemblyAiTransportOperation {
    AssemblyAiTransportOperation {
        outcome: TransportOutcome::Error,
        ..success_operation(provenance, request)
    }
}

#[derive(Clone, Debug)]
struct FixtureTransportState {
    fixture: TranscriptFixture,
    operations: Vec<AssemblyAiTransportOperation>,
    error: Option<AssemblyAiTransportError>,
    provenance: TransportProvenance,
}

impl FixtureTransportState {
    fn new(fixture: TranscriptFixture, provenance: TransportProvenance) -> Self {
        Self {
            fixture,
            operations: Vec::new(),
            error: None,
            provenance,
        }
    }

    fn read(
        &mut self,
        request: &TranscriptReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
        if let Some(error) = self.error.clone() {
            self.operations
                .push(error_operation(self.provenance, request));
            return Err(error);
        }
        let result = fixture_read(&self.fixture, request, secret);
        self.operations.push(if result.is_ok() {
            success_operation(self.provenance, request)
        } else {
            error_operation(self.provenance, request)
        });
        result
    }
}

/// Deterministic non-native fake provider transport.
#[derive(Clone, Debug)]
pub struct FakeTransport {
    state: FixtureTransportState,
}

impl FakeTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            state: FixtureTransportState::new(fixture, TransportProvenance::Fake),
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: AssemblyAiTransportError) -> Self {
        self.state.error = Some(error);
        self
    }
}

impl AssemblyAiTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn read_transcript(
        &mut self,
        request: &TranscriptReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
        self.state.read(request, secret)
    }

    fn operations(&self) -> Vec<AssemblyAiTransportOperation> {
        self.state.operations.clone()
    }
}

/// In-memory recording transport. It records bounded operation metadata only;
/// it is not a durable provider receipt.
#[derive(Clone, Debug)]
pub struct RecordingTransport {
    state: FixtureTransportState,
}

impl RecordingTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            state: FixtureTransportState::new(fixture, TransportProvenance::Recording),
        }
    }

    #[must_use]
    pub fn request_count(&self) -> usize {
        self.state.operations.len()
    }

    #[must_use]
    pub fn recording_digest(&self) -> Digest {
        canonical_digest(&self.state.operations)
    }
}

impl AssemblyAiTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn read_transcript(
        &mut self,
        request: &TranscriptReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
        self.state.read(request, secret)
    }

    fn operations(&self) -> Vec<AssemblyAiTransportOperation> {
        self.state.operations.clone()
    }
}

/// Deterministic loopback transport. It does not open a socket; its name only
/// indicates that it exercises the same bounded request/response seam.
#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    state: FixtureTransportState,
}

impl LoopbackTransport {
    pub fn new(fixture: TranscriptFixture) -> Self {
        Self {
            state: FixtureTransportState::new(fixture, TransportProvenance::Loopback),
        }
    }
}

impl AssemblyAiTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        self.state.provenance
    }

    fn read_transcript(
        &mut self,
        request: &TranscriptReadRequest,
        secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
        self.state.read(request, secret)
    }

    fn operations(&self) -> Vec<AssemblyAiTransportOperation> {
        self.state.operations.clone()
    }
}

/// Explicitly blocked environment transport for native-gap evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl BlockedEnvTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl AssemblyAiTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_transcript(
        &mut self,
        _request: &TranscriptReadRequest,
        _secret: &SecretMaterial,
    ) -> Result<RawTranscriptPage, AssemblyAiTransportError> {
        Err(AssemblyAiTransportError::EnvironmentBlocked)
    }

    fn operations(&self) -> Vec<AssemblyAiTransportOperation> {
        Vec::new()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RawTranscriptPageMaterial<'a> {
    snapshot: &'a RawTranscriptSnapshot,
    utterances: &'a [RawUtterance],
    request_page_token_digest: &'a Option<Digest>,
    next_page_token_digest: Option<Digest>,
}
