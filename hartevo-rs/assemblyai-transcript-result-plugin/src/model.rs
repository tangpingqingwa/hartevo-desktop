use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::AssemblyAiResultError;
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, MAX_CHAPTERS, MAX_IDENTIFIER_BYTES, MAX_PAGE_SIZE,
    MAX_PAGES, MAX_SEGMENTS, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
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
) -> Result<(), AssemblyAiResultError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AssemblyAiResultError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), AssemblyAiResultError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-@=".contains(&byte))
    {
        return Err(AssemblyAiResultError::InvalidIdentifier { field });
    }
    Ok(())
}

pub(crate) fn validate_digest(
    value: &Digest,
    field: &'static str,
) -> Result<(), AssemblyAiResultError> {
    if value.is_valid() {
        Ok(())
    } else {
        Err(AssemblyAiResultError::InvalidDigest { field })
    }
}

pub(crate) fn validate_revision(revision: u64) -> Result<(), AssemblyAiResultError> {
    if revision == 0 {
        Err(AssemblyAiResultError::InvalidRevision)
    } else {
        Ok(())
    }
}

/// Lowercase SHA-256 digest used at every public evidence and registration
/// fence. It contains no source text or secret material.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_hex(bytes))
    }

    pub fn from_text(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }

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

    pub fn from_hex(value: impl Into<String>) -> Result<Self, AssemblyAiResultError> {
        let value = value.into();
        let digest = Self(value);
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

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("contract values must serialize"))
}

/// Semantic version bound into registration and proposal evidence.
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

    pub fn parse(value: &str) -> Result<Self, AssemblyAiResultError> {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() != 3 {
            return Err(AssemblyAiResultError::InvalidRegistration);
        }
        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| AssemblyAiResultError::InvalidRegistration)?,
            minor: parts[1]
                .parse()
                .map_err(|_| AssemblyAiResultError::InvalidRegistration)?,
            patch: parts[2]
                .parse()
                .map_err(|_| AssemblyAiResultError::InvalidRegistration)?,
        })
    }
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
            pub fn new(value: impl Into<String>) -> Result<Self, AssemblyAiResultError> {
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

            pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
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

identifier_type!(AccountId, "account_id");
identifier_type!(SourceId, "source_id");
identifier_type!(TranscriptId, "transcript_id");
identifier_type!(ModelId, "model_id");
identifier_type!(ConfigId, "config_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(WorkProductId, "work_product_id");
identifier_type!(RegistrationId, "registration_id");
identifier_type!(SegmentId, "segment_id");

/// Exact HTTPS origin. Paths, query strings, fragments, credentials, and
/// whitespace are rejected so a registration cannot silently change host.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AssemblyAiHost(String);

impl AssemblyAiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, AssemblyAiResultError> {
        let mut value = value.into();
        while value.ends_with('/') {
            value.pop();
        }
        let Some(authority) = value.strip_prefix("https://") else {
            return Err(AssemblyAiResultError::InvalidHost);
        };
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
        {
            return Err(AssemblyAiResultError::InvalidHost);
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

impl fmt::Debug for AssemblyAiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AssemblyAiHost")
            .field(&format!("sha256:{}", &self.digest().as_str()[..16]))
            .finish()
    }
}

impl fmt::Display for AssemblyAiHost {
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
            pub fn new(id: $id, revision: u64) -> Result<Self, AssemblyAiResultError> {
                id.validate()?;
                validate_revision(revision)?;
                Ok(Self { id, revision })
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }

            pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
                self.id.validate()?;
                validate_revision(self.revision)
            }
        }
    };
}

revisioned_reference!(SourceReference, SourceId, "source");
revisioned_reference!(TranscriptReference, TranscriptId, "transcript");
revisioned_reference!(MissionReference, MissionId, "mission");
revisioned_reference!(ProjectReference, ProjectId, "project");
revisioned_reference!(WorkProductReference, WorkProductId, "work_product");

/// Exact model family/revision observed by the provider. Model names are
/// represented in public evidence by digests; the scope still fences every
/// selected model field exactly.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelRevision {
    pub speech_model: Option<ModelId>,
    pub language_model: Option<ModelId>,
    pub acoustic_model: Option<ModelId>,
    pub revision: u64,
}

impl ModelRevision {
    pub fn new(
        speech_model: Option<ModelId>,
        language_model: Option<ModelId>,
        acoustic_model: Option<ModelId>,
        revision: u64,
    ) -> Result<Self, AssemblyAiResultError> {
        let model = Self {
            speech_model,
            language_model,
            acoustic_model,
            revision,
        };
        model.validate()?;
        Ok(model)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        for model in [
            &self.speech_model,
            &self.language_model,
            &self.acoustic_model,
        ]
        .into_iter()
        .flatten()
        {
            model.validate()?;
        }
        validate_revision(self.revision)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Exact transcription configuration revision. The language and redaction
/// switches are part of the fence because changing either changes evidence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranscriptConfigRevision {
    pub id: ConfigId,
    pub revision: u64,
    pub language_code: Option<String>,
    pub language_detection: bool,
    pub speaker_labels: bool,
    pub redact_pii: bool,
    pub summary_enabled: bool,
    pub chapter_enabled: bool,
}

impl TranscriptConfigRevision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ConfigId,
        revision: u64,
        language_code: Option<String>,
        language_detection: bool,
        speaker_labels: bool,
        redact_pii: bool,
        summary_enabled: bool,
        chapter_enabled: bool,
    ) -> Result<Self, AssemblyAiResultError> {
        let configuration = Self {
            id,
            revision,
            language_code,
            language_detection,
            speaker_labels,
            redact_pii,
            summary_enabled,
            chapter_enabled,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        self.id.validate()?;
        validate_revision(self.revision)?;
        if let Some(language) = &self.language_code {
            validate_text(language, "language_code", 32)?;
        }
        if !self.redact_pii {
            return Err(AssemblyAiResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Bounded utterance-page scope. It is registered as an exact revision so a
/// later consumer cannot silently widen a transcript read.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SegmentScope {
    pub revision: u64,
    pub page_size: usize,
    pub max_pages: usize,
    pub max_segments: usize,
}

impl SegmentScope {
    pub fn new(
        revision: u64,
        page_size: usize,
        max_pages: usize,
        max_segments: usize,
    ) -> Result<Self, AssemblyAiResultError> {
        let scope = Self {
            revision,
            page_size,
            max_pages,
            max_segments,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        validate_revision(self.revision)?;
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || !(1..=MAX_SEGMENTS).contains(&self.max_segments)
            || self.page_size > self.max_segments
        {
            return Err(AssemblyAiResultError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type PermissionRevision = u64;

pub const REQUIRED_READ_PERMISSIONS: [&str; 6] = [
    "account.read",
    "transcript.read",
    "utterance.read",
    "speaker.read",
    "metadata.read",
    "redacted_content_digest.read",
];

/// Read-only permission snapshot bound into the registration and scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyAiPermissionSnapshot {
    pub revision: PermissionRevision,
    pub permissions: BTreeSet<String>,
    pub digest: Digest,
}

impl AssemblyAiPermissionSnapshot {
    pub fn read_only(revision: PermissionRevision) -> Result<Self, AssemblyAiResultError> {
        Self::new(
            revision,
            REQUIRED_READ_PERMISSIONS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        )
    }

    pub fn new(
        revision: PermissionRevision,
        permissions: BTreeSet<String>,
    ) -> Result<Self, AssemblyAiResultError> {
        let snapshot = Self {
            revision,
            permissions,
            digest: Digest::from_text("unsealed-assemblyai-permission"),
        };
        snapshot.validate_permissions()?;
        let mut snapshot = snapshot;
        snapshot.digest = snapshot.calculate_digest();
        Ok(snapshot)
    }

    fn validate_permissions(&self) -> Result<(), AssemblyAiResultError> {
        validate_revision(self.revision)?;
        if self.permissions.is_empty()
            || self.permissions.iter().any(|permission| {
                permission.ends_with(".write")
                    || matches!(
                        permission.as_str(),
                        "audio.upload"
                            | "transcript.submit"
                            | "transcript.poll"
                            | "audio.fetch"
                            | "transcript.raw.read"
                            | "speaker.identity.write"
                            | "model.training.write"
                            | "external.write"
                    )
            })
            || REQUIRED_READ_PERMISSIONS
                .iter()
                .any(|required| !self.permissions.contains(*required))
        {
            return Err(AssemblyAiResultError::InvalidPermissionSnapshot);
        }
        for permission in &self.permissions {
            validate_text(permission, "permission", 96)?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&(&self.revision, &self.permissions))
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        self.validate_permissions()?;
        if self.digest != self.calculate_digest() {
            return Err(AssemblyAiResultError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// The only secret material boundary. The opaque reference id is immediately
/// hashed and the raw id is never serialized, displayed, or included in a
/// scope digest.
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
    ) -> Result<Self, AssemblyAiResultError> {
        let reference_id = reference_id.as_ref();
        validate_text(reference_id, "secret_reference", MAX_IDENTIFIER_BYTES)?;
        let scope_digest = Digest::from_hex(scope_digest.as_ref().to_owned())?;
        validate_revision(revision)?;
        Ok(Self {
            reference_digest: Digest::from_parts(["assemblyai-api-key-reference", reference_id]),
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
    ) -> Result<Self, AssemblyAiResultError> {
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

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        if self.kind != SecretKind::ApiKey
            || !self.reference_digest.is_valid()
            || !self.scope_digest.is_valid()
            || self.revision == 0
        {
            return Err(AssemblyAiResultError::InvalidSecretReference);
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

/// Exact provider scope for one bounded transcript-result read.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyAiTranscriptResultScope {
    pub host: AssemblyAiHost,
    #[serde(rename = "accountId")]
    pub account: AccountId,
    pub source: SourceReference,
    pub transcript: TranscriptReference,
    pub model: ModelRevision,
    pub configuration: TranscriptConfigRevision,
    pub segment: SegmentScope,
    pub mission: MissionReference,
    pub project: ProjectReference,
    pub work_product: WorkProductReference,
    pub permission: AssemblyAiPermissionSnapshot,
}

pub type AssemblyAiScope = AssemblyAiTranscriptResultScope;

impl AssemblyAiTranscriptResultScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: AssemblyAiHost,
        account: AccountId,
        source: SourceReference,
        transcript: TranscriptReference,
        model: ModelRevision,
        configuration: TranscriptConfigRevision,
        segment: SegmentScope,
        mission: MissionReference,
        project: ProjectReference,
        work_product: WorkProductReference,
        permission: AssemblyAiPermissionSnapshot,
    ) -> Result<Self, AssemblyAiResultError> {
        let scope = Self {
            host,
            account,
            source,
            transcript,
            model,
            configuration,
            segment,
            mission,
            project,
            work_product,
            permission,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        if self.host.as_str().is_empty() {
            return Err(AssemblyAiResultError::InvalidScope);
        }
        self.account.validate()?;
        self.source.validate()?;
        self.transcript.validate()?;
        self.model.validate()?;
        self.configuration.validate()?;
        self.segment.validate()?;
        self.mission.validate()?;
        self.project.validate()?;
        self.work_product.validate()?;
        self.permission.validate()
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type MissionScope = AssemblyAiTranscriptResultScope;

/// Provider status is deliberately finite. Unknown provider strings are
/// reduced to a digest and can never escape as arbitrary provider content.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatusProjection {
    Queued,
    Processing,
    Completed,
    Error,
    Canceled,
    Expired,
    ProviderUnknown(ProviderUnknownStatus),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderUnknownStatus {
    pub code_digest: Digest,
}

impl TranscriptStatusProjection {
    pub fn from_provider(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "processing" => Self::Processing,
            "completed" => Self::Completed,
            "error" => Self::Error,
            "canceled" | "cancelled" => Self::Canceled,
            "expired" => Self::Expired,
            other => Self::ProviderUnknown(ProviderUnknownStatus {
                code_digest: Digest::from_text(other),
            }),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranscriptLanguage {
    pub code: Option<String>,
    pub detected: bool,
    pub confidence: Option<f32>,
}

impl TranscriptLanguage {
    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
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
pub struct ConfidenceSummary {
    pub transcript: Option<f32>,
    pub minimum: Option<f32>,
    pub maximum: Option<f32>,
    pub mean: Option<f32>,
    pub sample_count: usize,
}

impl ConfidenceSummary {
    pub fn from_values(
        transcript: Option<f32>,
        values: &[f32],
    ) -> Result<Self, AssemblyAiResultError> {
        for value in values {
            validate_confidence(*value)?;
        }
        if let Some(value) = transcript {
            validate_confidence(value)?;
        }
        let (minimum, maximum, mean) = if values.is_empty() {
            (None, None, None)
        } else {
            let minimum = values.iter().copied().fold(f32::INFINITY, f32::min);
            let maximum = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let mean = values.iter().sum::<f32>() / values.len() as f32;
            (Some(minimum), Some(maximum), Some(mean))
        };
        Ok(Self {
            transcript,
            minimum,
            maximum,
            mean,
            sample_count: values.len(),
        })
    }
}

pub(crate) fn validate_confidence(value: f32) -> Result<(), AssemblyAiResultError> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(AssemblyAiResultError::InvalidConfidence)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelProjection {
    pub revision: u64,
    pub speech_model_digest: Option<Digest>,
    pub language_model_digest: Option<Digest>,
    pub acoustic_model_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationProjection {
    pub id_digest: Digest,
    pub revision: u64,
    pub configuration_digest: Digest,
    pub language_code: Option<String>,
    pub language_detection: bool,
    pub speaker_labels: bool,
    pub redact_pii: bool,
    pub summary_enabled: bool,
    pub chapter_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UtteranceEvidence {
    pub segment_id: SegmentId,
    pub speaker_label: Option<String>,
    pub start_ms: u64,
    pub end_ms: u64,
    pub confidence: f32,
    pub content_digest: Digest,
}

impl UtteranceEvidence {
    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        self.segment_id.validate()?;
        if self.end_ms < self.start_ms {
            return Err(AssemblyAiResultError::MalformedResponse);
        }
        validate_confidence(self.confidence)?;
        validate_digest(&self.content_digest, "utterance_content_digest")?;
        if let Some(label) = &self.speaker_label {
            validate_text(label, "speaker_label", 32)?;
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            {
                return Err(AssemblyAiResultError::SpeakerIdentityMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChapterMetadata {
    pub ordinal: usize,
    pub start_ms: u64,
    pub end_ms: u64,
    pub title_digest: Option<Digest>,
    pub summary_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SummaryMetadata {
    pub kind_digest: Option<Digest>,
    pub model_digest: Option<Digest>,
    pub content_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionState {
    Redacted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fake,
    Recording,
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

/// Digest-only bounded result projection. It never contains transcript words,
/// audio bytes, provider error text, opaque page tokens, or speaker names.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranscriptResultProjection {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub source: SourceReference,
    pub transcript: TranscriptReference,
    pub status: TranscriptStatusProjection,
    pub language: TranscriptLanguage,
    pub model: ModelProjection,
    pub configuration: ConfigurationProjection,
    pub speaker_count: usize,
    pub speaker_label_digests: Vec<Digest>,
    pub utterance_count: usize,
    pub utterances: Vec<UtteranceEvidence>,
    pub confidence: ConfidenceSummary,
    pub chapters: Vec<ChapterMetadata>,
    pub summary: Option<SummaryMetadata>,
    pub redaction: RedactionState,
    pub content_digest: Digest,
    pub segment_digest: Digest,
    pub segment_scope_digest: Digest,
    pub segment_page_count: usize,
    pub status_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub complete: bool,
    pub evidence_digest: Digest,
}

impl TranscriptResultProjection {
    pub fn validate_integrity(&self) -> Result<(), AssemblyAiResultError> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != PROVIDER_ID
            || self.provider_version != PLUGIN_VERSION
            || !self.scope_digest.is_valid()
            || !self.registration_digest.is_valid()
            || self.redaction != RedactionState::Redacted
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || !self.complete
            || self.utterance_count != self.utterances.len()
            || self.utterances.len() > MAX_SEGMENTS
            || self.chapters.len() > MAX_CHAPTERS
            || !self.segment_scope_digest.is_valid()
            || self.segment_page_count == 0
            || self.segment_page_count > MAX_PAGES
        {
            return Err(AssemblyAiResultError::InvalidProposal);
        }
        self.language.validate()?;
        for utterance in &self.utterances {
            utterance.validate()?;
        }
        if self.speaker_count != self.speaker_label_digests.len() {
            return Err(AssemblyAiResultError::InvalidProposal);
        }
        for digest in &self.speaker_label_digests {
            validate_digest(digest, "speaker_label_digest")?;
        }
        let expected_segment = segment_digest_for(&self.utterances);
        if self.segment_digest != expected_segment {
            return Err(AssemblyAiResultError::SegmentMismatch);
        }
        let expected_content = content_digest_for(&self.utterances);
        if self.content_digest != expected_content {
            return Err(AssemblyAiResultError::ContentMismatch);
        }
        if self.status_digest != self.status.digest() {
            return Err(AssemblyAiResultError::DigestMismatch);
        }
        let expected_evidence = evidence_digest_for(self);
        if self.evidence_digest != expected_evidence {
            return Err(AssemblyAiResultError::DigestMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_review_only(&self) -> bool {
        true
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

pub fn segment_digest_for(utterances: &[UtteranceEvidence]) -> Digest {
    canonical_digest(utterances)
}

pub fn content_digest_for(utterances: &[UtteranceEvidence]) -> Digest {
    canonical_digest(
        &utterances
            .iter()
            .map(|utterance| {
                (
                    &utterance.segment_id,
                    &utterance.start_ms,
                    &utterance.end_ms,
                    &utterance.speaker_label,
                    &utterance.confidence,
                    &utterance.content_digest,
                )
            })
            .collect::<Vec<_>>(),
    )
}

pub fn evidence_digest_for(projection: &TranscriptResultProjection) -> Digest {
    canonical_digest(&EvidenceDigestMaterial {
        contract_version: &projection.contract_version,
        contract_digest: &projection.contract_digest,
        provider_id: &projection.provider_id,
        provider_version: &projection.provider_version,
        scope_digest: &projection.scope_digest,
        registration_digest: &projection.registration_digest,
        source: &projection.source,
        transcript: &projection.transcript,
        status: &projection.status,
        language: &projection.language,
        model: &projection.model,
        configuration: &projection.configuration,
        speaker_count: projection.speaker_count,
        speaker_label_digests: &projection.speaker_label_digests,
        utterance_count: projection.utterance_count,
        utterances: &projection.utterances,
        confidence: &projection.confidence,
        chapters: &projection.chapters,
        summary: &projection.summary,
        redaction: &projection.redaction,
        content_digest: &projection.content_digest,
        segment_digest: &projection.segment_digest,
        segment_scope_digest: &projection.segment_scope_digest,
        segment_page_count: projection.segment_page_count,
        status_digest: &projection.status_digest,
        provenance: projection.provenance,
        connected: projection.connected,
        native: projection.native,
        first_party: projection.first_party,
        complete: projection.complete,
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
    source: &'a SourceReference,
    transcript: &'a TranscriptReference,
    status: &'a TranscriptStatusProjection,
    language: &'a TranscriptLanguage,
    model: &'a ModelProjection,
    configuration: &'a ConfigurationProjection,
    speaker_count: usize,
    speaker_label_digests: &'a [Digest],
    utterance_count: usize,
    utterances: &'a [UtteranceEvidence],
    confidence: &'a ConfidenceSummary,
    chapters: &'a [ChapterMetadata],
    summary: &'a Option<SummaryMetadata>,
    redaction: &'a RedactionState,
    content_digest: &'a Digest,
    segment_digest: &'a Digest,
    segment_scope_digest: &'a Digest,
    segment_page_count: usize,
    status_digest: &'a Digest,
    provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    complete: bool,
}

/// Opaque page token. Only a digest is exposed outside the transport module.
#[derive(Clone, Eq, PartialEq)]
pub struct TranscriptPageToken {
    raw: String,
}

impl TranscriptPageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, AssemblyAiResultError> {
        let raw = value.into();
        validate_text(&raw, "page_token", crate::MAX_PAGE_TOKEN_BYTES)?;
        Ok(Self { raw })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.raw)
    }
}

impl fmt::Debug for TranscriptPageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TranscriptPageToken")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssemblyAiProviderIdentity {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub release: String,
}

impl AssemblyAiProviderIdentity {
    pub fn new(
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self, AssemblyAiResultError> {
        let identity = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            release: release.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), AssemblyAiResultError> {
        if self.provider_id != PROVIDER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_revision == 0
        {
            return Err(AssemblyAiResultError::InvalidRegistration);
        }
        validate_text(&self.release, "provider_release", 128)
    }
}

/// Registration lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

/// Serializable registration evidence. The API key itself is absent; only its
/// opaque reference digest and revision can be audited.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_id: RegistrationId,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider: AssemblyAiProviderIdentity,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub secret_revision: u64,
    pub registration_revision: u64,
    pub binding_digest: Digest,
    pub state: RegistrationState,
}
