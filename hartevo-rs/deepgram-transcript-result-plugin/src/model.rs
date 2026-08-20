use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::DeepgramResultError;
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE, MAX_UTTERANCE_SEGMENTS,
    MAX_WINDOW_PAGES, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
};

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), DeepgramResultError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(DeepgramResultError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), DeepgramResultError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-@=".contains(&byte))
    {
        return Err(DeepgramResultError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &Digest,
    field: &'static str,
) -> Result<(), DeepgramResultError> {
    if value.is_valid() {
        Ok(())
    } else {
        Err(DeepgramResultError::InvalidDigest { field })
    }
}

pub(crate) fn validate_revision(revision: u64) -> Result<(), DeepgramResultError> {
    (revision != 0)
        .then_some(())
        .ok_or(DeepgramResultError::InvalidRevision)
}

pub(crate) fn validate_confidence(value: f32) -> Result<(), DeepgramResultError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(DeepgramResultError::InvalidConfidence)
    }
}

/// Lowercase SHA-256 evidence digest. It never contains secret material unless
/// a caller explicitly hashes a caller-owned value before passing it here.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

    #[must_use]
    pub fn from_parts<I, S>(parts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut bytes = Vec::new();
        for part in parts {
            let part = part.as_ref();
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part.as_bytes());
        }
        Self::from_bytes(&bytes)
    }

    pub fn from_hex(value: impl Into<String>) -> Result<Self, DeepgramResultError> {
        let digest = Self(value.into());
        validate_digest(&digest, "digest")?;
        Ok(digest)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("contract values must serialize"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DeepgramResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(&self.0)
            }

            pub fn validate(&self) -> Result<(), DeepgramResultError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple($field)
                    .field(&format!("sha256:{}", &self.digest().as_str()[..16]))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(ProviderProjectId, "deepgram_project_id");
identifier_type!(RequestId, "request_id");
identifier_type!(ModelId, "model_id");
identifier_type!(WindowId, "utterance_window_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(WorkProductId, "work_product_id");
identifier_type!(ConsentId, "consent_id");
identifier_type!(RegistrationId, "registration_id");
identifier_type!(SegmentId, "segment_id");

pub type DeepgramProjectId = ProviderProjectId;
pub type DeepgramRequestId = RequestId;
pub type LanguageCode = String;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeepgramHost(String);

impl DeepgramHost {
    pub fn new(value: impl Into<String>) -> Result<Self, DeepgramResultError> {
        let mut value = value.into();
        while value.ends_with('/') {
            value.pop();
        }
        let Some(authority) = value.strip_prefix("https://") else {
            return Err(DeepgramResultError::InvalidHost);
        };
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
            || value.len() > MAX_IDENTIFIER_BYTES
        {
            return Err(DeepgramResultError::InvalidHost);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Debug for DeepgramHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeepgramHost")
            .field(&format!("sha256:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl fmt::Display for DeepgramHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! revisioned_reference {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: $id, revision: u64) -> Result<Self, DeepgramResultError> {
                id.validate()?;
                validate_revision(revision)?;
                Ok(Self { id, revision })
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }

            pub fn validate(&self) -> Result<(), DeepgramResultError> {
                self.id.validate()?;
                validate_revision(self.revision)
            }
        }
    };
}

revisioned_reference!(
    DeepgramProjectReference,
    ProviderProjectId,
    "deepgram_project"
);
revisioned_reference!(ProjectReference, ProjectId, "project");
revisioned_reference!(MissionReference, MissionId, "mission");
revisioned_reference!(WorkProductReference, WorkProductId, "work_product");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOperation {
    ListenRead,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramRequestReference {
    pub id: RequestId,
    pub revision: u64,
    pub operation: RequestOperation,
    pub parameters_digest: Digest,
}

impl DeepgramRequestReference {
    pub fn new(
        id: RequestId,
        revision: u64,
        operation: RequestOperation,
        parameters_digest: Digest,
    ) -> Result<Self, DeepgramResultError> {
        let request = Self {
            id,
            revision,
            operation,
            parameters_digest,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn from_parameters(
        id: RequestId,
        revision: u64,
        parameters: impl Serialize,
    ) -> Result<Self, DeepgramResultError> {
        Self::new(
            id,
            revision,
            RequestOperation::ListenRead,
            canonical_digest(&parameters),
        )
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.id.validate()?;
        validate_revision(self.revision)?;
        validate_digest(&self.parameters_digest, "request_parameters_digest")
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AudioFingerprint {
    pub digest: Digest,
    pub revision: u64,
}

impl AudioFingerprint {
    pub fn new(fingerprint: impl AsRef<str>, revision: u64) -> Result<Self, DeepgramResultError> {
        validate_text(
            fingerprint.as_ref(),
            "audio_fingerprint",
            MAX_IDENTIFIER_BYTES,
        )?;
        Self::from_digest(Digest::from_text(fingerprint.as_ref()), revision)
    }

    pub fn from_digest(digest: Digest, revision: u64) -> Result<Self, DeepgramResultError> {
        validate_digest(&digest, "audio_fingerprint_digest")?;
        validate_revision(revision)?;
        Ok(Self { digest, revision })
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        validate_digest(&self.digest, "audio_fingerprint_digest")?;
        validate_revision(self.revision)
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramModelFeatures {
    pub diarize: bool,
    pub punctuate: bool,
    pub paragraphs: bool,
    pub summarize: bool,
    pub smart_format: bool,
    pub redact: bool,
}

impl Default for DeepgramModelFeatures {
    fn default() -> Self {
        Self {
            diarize: false,
            punctuate: true,
            paragraphs: false,
            summarize: false,
            smart_format: false,
            redact: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramModelRevision {
    pub id: ModelId,
    pub version: Option<String>,
    pub language: Option<LanguageCode>,
    pub revision: u64,
    pub features: DeepgramModelFeatures,
}

impl DeepgramModelRevision {
    pub fn new(
        id: ModelId,
        version: Option<String>,
        language: Option<LanguageCode>,
        revision: u64,
        features: DeepgramModelFeatures,
    ) -> Result<Self, DeepgramResultError> {
        let model = Self {
            id,
            version,
            language,
            revision,
            features,
        };
        model.validate()?;
        Ok(model)
    }

    pub fn simple(id: ModelId, revision: u64) -> Result<Self, DeepgramResultError> {
        Self::new(id, None, None, revision, DeepgramModelFeatures::default())
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.id.validate()?;
        validate_revision(self.revision)?;
        if let Some(version) = &self.version {
            validate_text(version, "model_version", MAX_IDENTIFIER_BYTES)?;
        }
        if let Some(language) = &self.language {
            validate_text(language, "model_language", 32)?;
        }
        if !self.features.redact {
            return Err(DeepgramResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramUtteranceWindow {
    pub id: WindowId,
    pub revision: u64,
    pub start_ms: u64,
    pub end_ms: Option<u64>,
    pub page_size: usize,
    pub max_pages: usize,
    pub max_segments: usize,
}

impl DeepgramUtteranceWindow {
    pub fn new(
        id: WindowId,
        revision: u64,
        start_ms: u64,
        end_ms: Option<u64>,
        page_size: usize,
        max_pages: usize,
        max_segments: usize,
    ) -> Result<Self, DeepgramResultError> {
        let window = Self {
            id,
            revision,
            start_ms,
            end_ms,
            page_size,
            max_pages,
            max_segments,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.id.validate()?;
        validate_revision(self.revision)?;
        if self.end_ms.is_some_and(|end| end < self.start_ms)
            || !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_WINDOW_PAGES).contains(&self.max_pages)
            || !(1..=MAX_UTTERANCE_SEGMENTS).contains(&self.max_segments)
            || self.page_size > self.max_segments
        {
            return Err(DeepgramResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    pub id: ConsentId,
    pub revision: u64,
    pub purpose_digest: Digest,
}

impl ConsentReference {
    pub fn new(
        id: ConsentId,
        revision: u64,
        purpose: impl AsRef<str>,
    ) -> Result<Self, DeepgramResultError> {
        validate_text(purpose.as_ref(), "consent_purpose", MAX_IDENTIFIER_BYTES)?;
        let consent = Self {
            id,
            revision,
            purpose_digest: Digest::from_text(purpose.as_ref()),
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn from_digest(
        id: ConsentId,
        revision: u64,
        purpose_digest: Digest,
    ) -> Result<Self, DeepgramResultError> {
        let consent = Self {
            id,
            revision,
            purpose_digest,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.id.validate()?;
        validate_revision(self.revision)?;
        validate_digest(&self.purpose_digest, "consent_purpose_digest")
            .map_err(|_| DeepgramResultError::InvalidConsent)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Exact provider/host/request/model/audio/window/Project/Mission/Work Product
/// and consent scope for one bounded result read.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptResultScope {
    pub host: DeepgramHost,
    pub deepgram_project: DeepgramProjectReference,
    pub request: DeepgramRequestReference,
    pub audio_fingerprint: AudioFingerprint,
    pub model: DeepgramModelRevision,
    pub utterance_window: DeepgramUtteranceWindow,
    pub project: ProjectReference,
    pub mission: MissionReference,
    pub work_product: WorkProductReference,
    pub consent: ConsentReference,
}

pub type DeepgramScope = DeepgramTranscriptResultScope;

impl DeepgramTranscriptResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: DeepgramHost,
        deepgram_project: DeepgramProjectReference,
        request: DeepgramRequestReference,
        audio_fingerprint: AudioFingerprint,
        model: DeepgramModelRevision,
        utterance_window: DeepgramUtteranceWindow,
        project: ProjectReference,
        mission: MissionReference,
        work_product: WorkProductReference,
        consent: ConsentReference,
    ) -> Result<Self, DeepgramResultError> {
        let scope = Self {
            host,
            deepgram_project,
            request,
            audio_fingerprint,
            model,
            utterance_window,
            project,
            mission,
            work_product,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        if self.host.as_str().is_empty() {
            return Err(DeepgramResultError::InvalidScope);
        }
        self.deepgram_project.validate()?;
        self.request.validate()?;
        self.audio_fingerprint.validate()?;
        self.model.validate()?;
        self.utterance_window.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.consent.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    Queued,
    Processing,
    Completed,
    Denied,
    Partial,
    Expired,
    RateLimited,
    ProviderUnknown { code_digest: Digest },
}

impl TranscriptStatus {
    #[must_use]
    pub fn from_provider(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "processing" => Self::Processing,
            "completed" | "success" => Self::Completed,
            "denied" | "unauthorized" | "forbidden" => Self::Denied,
            "partial" => Self::Partial,
            "expired" => Self::Expired,
            "rate_limited" | "rate-limited" => Self::RateLimited,
            other => Self::ProviderUnknown {
                code_digest: Digest::from_text(other),
            },
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramLanguageIndicator {
    pub code: Option<LanguageCode>,
    pub detected: bool,
    pub confidence: Option<f32>,
}

impl DeepgramLanguageIndicator {
    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        if let Some(code) = &self.code {
            validate_text(code, "language_code", 32)?;
        }
        if let Some(confidence) = self.confidence {
            validate_confidence(confidence)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramQualityIndicators {
    pub transcript_confidence: Option<f32>,
    pub minimum_segment_confidence: Option<f32>,
    pub maximum_segment_confidence: Option<f32>,
    pub mean_segment_confidence: Option<f32>,
    pub segment_count: usize,
    pub covered_duration_ms: u64,
}

impl DeepgramQualityIndicators {
    pub fn from_confidences(
        transcript_confidence: Option<f32>,
        confidences: &[f32],
        covered_duration_ms: u64,
    ) -> Result<Self, DeepgramResultError> {
        if let Some(confidence) = transcript_confidence {
            validate_confidence(confidence)?;
        }
        for confidence in confidences {
            validate_confidence(*confidence)?;
        }
        let (minimum, maximum, mean) = if confidences.is_empty() {
            (None, None, None)
        } else {
            let minimum = confidences.iter().copied().fold(f32::INFINITY, f32::min);
            let maximum = confidences
                .iter()
                .copied()
                .fold(f32::NEG_INFINITY, f32::max);
            let mean = confidences.iter().sum::<f32>() / confidences.len() as f32;
            (Some(minimum), Some(maximum), Some(mean))
        };
        Ok(Self {
            transcript_confidence,
            minimum_segment_confidence: minimum,
            maximum_segment_confidence: maximum,
            mean_segment_confidence: mean,
            segment_count: confidences.len(),
            covered_duration_ms,
        })
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        for confidence in [
            self.transcript_confidence,
            self.minimum_segment_confidence,
            self.maximum_segment_confidence,
            self.mean_segment_confidence,
        ]
        .into_iter()
        .flatten()
        {
            validate_confidence(confidence)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptMetadata {
    pub request_id_digest: Digest,
    pub created_digest: Option<Digest>,
    pub duration_ms: u64,
    pub channel_count: u16,
    pub response_bytes: usize,
}

impl DeepgramTranscriptMetadata {
    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        validate_digest(&self.request_id_digest, "provider_request_id_digest")?;
        if self
            .created_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
            || self.channel_count == 0
        {
            return Err(DeepgramResultError::Tamper);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramModelProjection {
    pub model_digest: Digest,
    pub version_digest: Option<Digest>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentEvidence {
    pub segment_id: SegmentId,
    pub start_ms: u64,
    pub end_ms: u64,
    pub channel: u16,
    pub speaker_index: Option<u16>,
    pub confidence: f32,
    pub content_digest: Digest,
}

impl SegmentEvidence {
    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        self.segment_id.validate()?;
        if self.end_ms < self.start_ms || self.channel == 0 {
            return Err(DeepgramResultError::Tamper);
        }
        validate_confidence(self.confidence)?;
        validate_digest(&self.content_digest, "segment_content_digest")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    DigestOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }
}

/// Public result evidence contains metadata, quality indicators, and only
/// digest-bound segment evidence. It cannot carry raw transcript words or
/// media bytes by construction.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramTranscriptResultEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub model_digest: Digest,
    pub audio_fingerprint_digest: Digest,
    pub utterance_window_digest: Digest,
    pub metadata: DeepgramTranscriptMetadata,
    pub language: DeepgramLanguageIndicator,
    pub quality: DeepgramQualityIndicators,
    pub status: TranscriptStatus,
    pub status_digest: Digest,
    pub segments: Vec<SegmentEvidence>,
    pub segment_count: usize,
    pub segment_digest: Digest,
    pub content_digest: Digest,
    pub segment_page_count: usize,
    pub redaction: RedactionState,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub complete: bool,
    pub evidence_digest: Digest,
}

impl DeepgramTranscriptResultEvidence {
    pub fn validate_integrity(&self) -> Result<(), DeepgramResultError> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PLUGIN_VERSION
            || !self.scope_digest.is_valid()
            || !self.registration_digest.is_valid()
            || !self.project_digest.is_valid()
            || !self.mission_digest.is_valid()
            || !self.work_product_digest.is_valid()
            || !self.consent_digest.is_valid()
            || !self.request_digest.is_valid()
            || !self.model_digest.is_valid()
            || !self.audio_fingerprint_digest.is_valid()
            || !self.utterance_window_digest.is_valid()
            || self.redaction != RedactionState::DigestOnly
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.segment_count != self.segments.len()
            || self.segments.len() > MAX_UTTERANCE_SEGMENTS
            || self.segment_page_count == 0
            || self.segment_page_count > MAX_WINDOW_PAGES
            || self.complete != self.status.is_complete()
        {
            return Err(DeepgramResultError::Tamper);
        }
        self.metadata.validate()?;
        self.language.validate()?;
        self.quality.validate()?;
        if let TranscriptStatus::ProviderUnknown { code_digest } = &self.status {
            validate_digest(code_digest, "provider_unknown_code_digest")?;
        }
        let mut ids = BTreeSet::new();
        for segment in &self.segments {
            segment.validate()?;
            if !ids.insert(segment.segment_id.clone()) {
                return Err(DeepgramResultError::DuplicateSegment);
            }
        }
        if self.segment_digest != segment_digest_for(&self.segments) {
            return Err(DeepgramResultError::SegmentMismatch);
        }
        if self.content_digest != content_digest_for(&self.segments) {
            return Err(DeepgramResultError::ContentMismatch);
        }
        if self.status_digest != self.status.digest() {
            return Err(DeepgramResultError::DigestMismatch);
        }
        if self.quality.segment_count != self.segment_count {
            return Err(DeepgramResultError::Tamper);
        }
        if self.evidence_digest != evidence_digest_for(self) {
            return Err(DeepgramResultError::DigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[must_use]
pub fn segment_digest_for(segments: &[SegmentEvidence]) -> Digest {
    canonical_digest(segments)
}

#[must_use]
pub fn content_digest_for(segments: &[SegmentEvidence]) -> Digest {
    canonical_digest(
        &segments
            .iter()
            .map(|segment| {
                (
                    &segment.segment_id,
                    &segment.start_ms,
                    &segment.end_ms,
                    &segment.channel,
                    &segment.speaker_index,
                    &segment.confidence,
                    &segment.content_digest,
                )
            })
            .collect::<Vec<_>>(),
    )
}

#[must_use]
pub fn evidence_digest_for(evidence: &DeepgramTranscriptResultEvidence) -> Digest {
    canonical_digest(&EvidenceDigestMaterial {
        contract_version: &evidence.contract_version,
        contract_digest: &evidence.contract_digest,
        provider_id: &evidence.provider_id,
        provider_version: &evidence.provider_version,
        scope_digest: &evidence.scope_digest,
        registration_digest: &evidence.registration_digest,
        project_digest: &evidence.project_digest,
        mission_digest: &evidence.mission_digest,
        work_product_digest: &evidence.work_product_digest,
        consent_digest: &evidence.consent_digest,
        request_digest: &evidence.request_digest,
        model_digest: &evidence.model_digest,
        audio_fingerprint_digest: &evidence.audio_fingerprint_digest,
        utterance_window_digest: &evidence.utterance_window_digest,
        metadata: &evidence.metadata,
        language: &evidence.language,
        quality: &evidence.quality,
        status: &evidence.status,
        status_digest: &evidence.status_digest,
        segments: &evidence.segments,
        segment_count: evidence.segment_count,
        segment_digest: &evidence.segment_digest,
        content_digest: &evidence.content_digest,
        segment_page_count: evidence.segment_page_count,
        redaction: evidence.redaction,
        provenance: evidence.provenance,
        connected: evidence.connected,
        native: evidence.native,
        first_party: evidence.first_party,
        complete: evidence.complete,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a PluginVersion,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    project_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    request_digest: &'a Digest,
    model_digest: &'a Digest,
    audio_fingerprint_digest: &'a Digest,
    utterance_window_digest: &'a Digest,
    metadata: &'a DeepgramTranscriptMetadata,
    language: &'a DeepgramLanguageIndicator,
    quality: &'a DeepgramQualityIndicators,
    status: &'a TranscriptStatus,
    status_digest: &'a Digest,
    segments: &'a [SegmentEvidence],
    segment_count: usize,
    segment_digest: &'a Digest,
    content_digest: &'a Digest,
    segment_page_count: usize,
    redaction: RedactionState,
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    complete: bool,
}

/// Opaque continuation token: only its digest can cross the transport
/// boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct DeepgramPageToken {
    pub(crate) raw: String,
}

impl DeepgramPageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, DeepgramResultError> {
        let raw = value.into();
        validate_text(&raw, "page_token", crate::MAX_PAGE_TOKEN_BYTES)?;
        Ok(Self { raw })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.raw)
    }
}

impl fmt::Debug for DeepgramPageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DeepgramPageToken")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeepgramProviderIdentity {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub release: String,
}

impl DeepgramProviderIdentity {
    pub fn new(
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self, DeepgramResultError> {
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release: release.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(DeepgramResultError::InvalidRegistration);
        }
        validate_text(&self.release, "provider_release", MAX_IDENTIFIER_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

/// Only redacted registration evidence is serializable. The opaque reference
/// itself intentionally has no Serialize implementation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider: DeepgramProviderIdentity,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub secret_revision: u64,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub state: RegistrationState,
}

/// The only credential boundary. The caller-owned reference identifier is
/// immediately hashed and never retained, serialized, or printed.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    kind: SecretKind,
    revoked: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

impl SecretReference {
    pub fn api_key(
        reference_id: impl AsRef<str>,
        scope_digest: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, DeepgramResultError> {
        validate_text(
            reference_id.as_ref(),
            "secret_reference",
            MAX_IDENTIFIER_BYTES,
        )?;
        let scope_digest = Digest::from_hex(scope_digest.as_ref().to_owned())?;
        validate_revision(revision)?;
        Ok(Self {
            reference_digest: Digest::from_parts([
                "deepgram-api-key-reference",
                reference_id.as_ref(),
            ]),
            scope_digest,
            revision,
            kind: SecretKind::ApiKey,
            revoked: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn new(
        reference_id: impl AsRef<str>,
        scope_digest: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, DeepgramResultError> {
        Self::api_key(reference_id, scope_digest, revision)
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    pub fn validate(&self) -> Result<(), DeepgramResultError> {
        if self.kind != SecretKind::ApiKey
            || !self.reference_digest.is_valid()
            || !self.scope_digest.is_valid()
            || self.revision == 0
        {
            return Err(DeepgramResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.is_revoked())
            .finish()
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            kind: self.kind,
            revoked: Arc::clone(&self.revoked),
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.revision == other.revision
            && self.kind == other.kind
            && self.is_revoked() == other.is_revoked()
    }
}

impl Eq for SecretReference {}

#[cfg(test)]
mod tests {
    use super::Digest;

    #[test]
    fn digest_is_lowercase_sha256() {
        let digest = Digest::from_text("deepgram");
        assert!(digest.is_valid());
        assert_eq!(digest.as_str().len(), 64);
    }
}
