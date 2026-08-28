use std::{fmt, str::FromStr};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::canonical::digest_serializable;

/// Maximum text accepted by the Layer-1 proposal boundary.
pub const MAX_TEXT_CHARACTERS: usize = 10_000;
/// Maximum configured audio duration accepted by the Layer-1 boundary.
pub const MAX_AUDIO_DURATION_MILLISECONDS: u64 = 3_600_000;
/// Maximum character count accepted in a recorded usage receipt.
pub const MAX_RECORDED_USAGE_CHARACTERS: u32 = 100_000;

/// Errors raised while constructing a typed ElevenLabs input or scope value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TypeError {
    #[error("{0} cannot be empty")]
    Empty(&'static str),
    #[error("{0} is not a valid identifier")]
    InvalidIdentifier(&'static str),
    #[error("digest is not 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("host must be the official ElevenLabs API host")]
    InvalidHost,
    #[error("language code is not an ISO-639-shaped identifier")]
    InvalidLanguage,
    #[error("output format is not a bounded ElevenLabs format token")]
    InvalidOutputFormat,
    #[error("revision must be positive")]
    InvalidRevision,
    #[error("configured limit is invalid")]
    InvalidLimit,
    #[error("configured duration is invalid")]
    InvalidDuration,
    #[error("text exceeds the bounded character limit")]
    TextTooLong,
    #[error("text contains a disallowed control character")]
    InvalidText,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<(), TypeError> {
    if value.is_empty() {
        return Err(TypeError::Empty(kind));
    }
    if value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(TypeError::InvalidIdentifier(kind));
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $name {
            type Err = TypeError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(WorkspaceId, "workspace id");
identifier_type!(ProjectId, "project id");
identifier_type!(MissionId, "mission id");
identifier_type!(WorkProductId, "work product id");
identifier_type!(ObjectiveId, "objective id");
identifier_type!(VoiceId, "voice id");
identifier_type!(ModelId, "model id");
identifier_type!(OperationId, "operation id");

/// A validated SHA-256 digest used at every immutable proposal boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use sha2::{Digest as ShaDigest, Sha256};

        let digest = Sha256::digest(bytes);
        let mut output = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(output)
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }

    pub(crate) fn from_hex_unchecked(value: String) -> Self {
        Self(value)
    }
}

/// A semver-like immutable registration version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    major: u16,
    minor: u16,
    patch: u16,
}

impl PluginVersion {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

/// The one official host allowed by this Layer-1 provider boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ApiHost(String);

impl ApiHost {
    pub const OFFICIAL: &'static str = "https://api.elevenlabs.io";

    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if value == Self::OFFICIAL {
            Ok(Self(value))
        } else {
            Err(TypeError::InvalidHost)
        }
    }

    pub fn official() -> Self {
        Self(Self::OFFICIAL.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded ISO-639-shaped language binding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LanguageCode(String);

impl LanguageCode {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let mut parts = value.split('-');
        let Some(primary) = parts.next() else {
            return Err(TypeError::InvalidLanguage);
        };
        let valid_primary = (2..=3).contains(&primary.len())
            && primary.bytes().all(|byte| byte.is_ascii_alphabetic());
        let valid_region = parts.all(|part| {
            (2..=8).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        });
        if !valid_primary || !valid_region || value.len() > 16 {
            return Err(TypeError::InvalidLanguage);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An exact output format token from the ElevenLabs TTS API vocabulary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OutputFormat(String);

impl OutputFormat {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && !value.starts_with('_')
            && !value.ends_with('_')
            && !value.contains("__")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid {
            return Err(TypeError::InvalidOutputFormat);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A selected existing voice binding. It has no clone, delete, or download
/// authority; the revision and digest are required to detect provider drift.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct VoiceSelection {
    voice_id: VoiceId,
    voice_revision: u64,
    voice_digest: Digest,
}

impl VoiceSelection {
    pub fn new(
        voice_id: VoiceId,
        voice_revision: u64,
        voice_digest: Digest,
    ) -> Result<Self, TypeError> {
        if voice_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        if !voice_digest.is_valid() {
            return Err(TypeError::InvalidDigest);
        }
        Ok(Self {
            voice_id,
            voice_revision,
            voice_digest,
        })
    }

    pub fn voice_id(&self) -> &VoiceId {
        &self.voice_id
    }

    pub const fn voice_revision(&self) -> u64 {
        self.voice_revision
    }

    pub fn voice_digest(&self) -> &Digest {
        &self.voice_digest
    }

    pub fn binding_digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// A selected model binding. It is an exact model revision, not a generic
/// model registry or arbitrary selection authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct ModelSelection {
    model_id: ModelId,
    model_revision: u64,
    model_digest: Digest,
}

impl ModelSelection {
    pub fn new(
        model_id: ModelId,
        model_revision: u64,
        model_digest: Digest,
    ) -> Result<Self, TypeError> {
        if model_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        if !model_digest.is_valid() {
            return Err(TypeError::InvalidDigest);
        }
        Ok(Self {
            model_id,
            model_revision,
            model_digest,
        })
    }

    pub fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    pub const fn model_revision(&self) -> u64 {
        self.model_revision
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn binding_digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// Exact Project scope and revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectScope {
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    project_revision: u64,
}

impl ProjectScope {
    pub fn new(
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        project_revision: u64,
    ) -> Result<Self, TypeError> {
        if project_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        Ok(Self {
            workspace_id,
            project_id,
            project_revision,
        })
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }
}

/// Exact Work Product scope and revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductScope {
    work_product_id: WorkProductId,
    work_product_revision: u64,
}

impl WorkProductScope {
    pub fn new(
        work_product_id: WorkProductId,
        work_product_revision: u64,
    ) -> Result<Self, TypeError> {
        if work_product_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        Ok(Self {
            work_product_id,
            work_product_revision,
        })
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }
}

/// Bounded voice settings copied into the exact config revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoiceSettings {
    stability_milli: u16,
    similarity_boost_milli: u16,
    style_milli: u16,
    use_speaker_boost: bool,
}

impl VoiceSettings {
    pub fn new(
        stability_milli: u16,
        similarity_boost_milli: u16,
        style_milli: u16,
        use_speaker_boost: bool,
    ) -> Result<Self, TypeError> {
        if stability_milli > 1_000 || similarity_boost_milli > 1_000 || style_milli > 1_000 {
            return Err(TypeError::InvalidLimit);
        }
        Ok(Self {
            stability_milli,
            similarity_boost_milli,
            style_milli,
            use_speaker_boost,
        })
    }

    pub const fn stability_milli(&self) -> u16 {
        self.stability_milli
    }

    pub const fn similarity_boost_milli(&self) -> u16 {
        self.similarity_boost_milli
    }

    pub const fn style_milli(&self) -> u16 {
        self.style_milli
    }

    pub const fn use_speaker_boost(&self) -> bool {
        self.use_speaker_boost
    }
}

/// The text-normalization mode bound into a TTS config revision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TextNormalization {
    Auto,
    On,
    Off,
}

/// Exact bounded ElevenLabs request configuration.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioConfig {
    config_revision: u64,
    output_format: OutputFormat,
    max_character_count: u32,
    max_duration_milliseconds: u64,
    voice_settings: Option<VoiceSettings>,
    text_normalization: TextNormalization,
    language_text_normalization: bool,
    seed: Option<u32>,
    enable_logging: bool,
    optimize_streaming_latency: Option<u8>,
}

impl AudioConfig {
    pub fn new(
        config_revision: u64,
        output_format: OutputFormat,
        max_character_count: u32,
        max_duration_milliseconds: u64,
    ) -> Result<Self, TypeError> {
        if config_revision == 0
            || max_character_count == 0
            || max_character_count as usize > MAX_TEXT_CHARACTERS
        {
            return Err(TypeError::InvalidLimit);
        }
        if max_duration_milliseconds == 0
            || max_duration_milliseconds > MAX_AUDIO_DURATION_MILLISECONDS
        {
            return Err(TypeError::InvalidDuration);
        }
        Ok(Self {
            config_revision,
            output_format,
            max_character_count,
            max_duration_milliseconds,
            voice_settings: None,
            text_normalization: TextNormalization::Auto,
            language_text_normalization: false,
            seed: None,
            enable_logging: true,
            optimize_streaming_latency: None,
        })
    }

    #[must_use]
    pub fn with_voice_settings(mut self, voice_settings: VoiceSettings) -> Self {
        self.voice_settings = Some(voice_settings);
        self
    }

    #[must_use]
    pub const fn with_text_normalization(mut self, mode: TextNormalization) -> Self {
        self.text_normalization = mode;
        self
    }

    #[must_use]
    pub const fn with_language_text_normalization(mut self, enabled: bool) -> Self {
        self.language_text_normalization = enabled;
        self
    }

    #[must_use]
    pub const fn with_seed(mut self, seed: u32) -> Self {
        self.seed = Some(seed);
        self
    }

    #[must_use]
    pub const fn with_enable_logging(mut self, enabled: bool) -> Self {
        self.enable_logging = enabled;
        self
    }

    #[must_use]
    pub const fn with_optimize_streaming_latency(mut self, value: u8) -> Self {
        self.optimize_streaming_latency = Some(value);
        self
    }

    pub const fn config_revision(&self) -> u64 {
        self.config_revision
    }

    pub fn output_format(&self) -> &OutputFormat {
        &self.output_format
    }

    pub const fn max_character_count(&self) -> u32 {
        self.max_character_count
    }

    pub const fn max_duration_milliseconds(&self) -> u64 {
        self.max_duration_milliseconds
    }

    pub fn voice_settings(&self) -> Option<&VoiceSettings> {
        self.voice_settings.as_ref()
    }

    pub const fn text_normalization(&self) -> TextNormalization {
        self.text_normalization
    }

    pub const fn language_text_normalization(&self) -> bool {
        self.language_text_normalization
    }

    pub const fn seed(&self) -> Option<u32> {
        self.seed
    }

    pub const fn enable_logging(&self) -> bool {
        self.enable_logging
    }

    pub const fn optimize_streaming_latency(&self) -> Option<u8> {
        self.optimize_streaming_latency
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// Complete Mission/Project/Work Product and exact TTS binding scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    project: ProjectScope,
    mission_id: MissionId,
    mission_revision: u64,
    work_product: WorkProductScope,
    host: ApiHost,
    voice: VoiceSelection,
    model: ModelSelection,
    language: LanguageCode,
    config: AudioConfig,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectScope,
        mission_id: MissionId,
        mission_revision: u64,
        work_product: WorkProductScope,
        host: ApiHost,
        voice: VoiceSelection,
        model: ModelSelection,
        language: LanguageCode,
        config: AudioConfig,
    ) -> Result<Self, TypeError> {
        if mission_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        Ok(Self {
            project,
            mission_id,
            mission_revision,
            work_product,
            host,
            voice,
            model,
            language,
            config,
        })
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        self.project.workspace_id()
    }

    pub fn project_id(&self) -> &ProjectId {
        self.project.project_id()
    }

    pub const fn project_revision(&self) -> u64 {
        self.project.project_revision()
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn host(&self) -> &ApiHost {
        &self.host
    }

    pub fn voice(&self) -> &VoiceSelection {
        &self.voice
    }

    pub fn model(&self) -> &ModelSelection {
        &self.model
    }

    pub fn language(&self) -> &LanguageCode {
        &self.language
    }

    pub fn config(&self) -> &AudioConfig {
        &self.config
    }

    pub fn output_format(&self) -> &OutputFormat {
        self.config.output_format()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// The exact request binding, including the text digest but never raw text.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SynthesisBinding {
    host: ApiHost,
    voice: VoiceSelection,
    model: ModelSelection,
    language: LanguageCode,
    output_format: OutputFormat,
    config_revision: u64,
    config_digest: Digest,
    text_revision: u64,
    text_digest: Digest,
}

impl SynthesisBinding {
    pub fn for_scope(scope: &MissionScope, text_revision: u64, text_digest: Digest) -> Self {
        Self {
            host: scope.host().clone(),
            voice: scope.voice().clone(),
            model: scope.model().clone(),
            language: scope.language().clone(),
            output_format: scope.output_format().clone(),
            config_revision: scope.config().config_revision(),
            config_digest: scope.config().digest(),
            text_revision,
            text_digest,
        }
    }

    pub fn host(&self) -> &ApiHost {
        &self.host
    }

    pub fn voice(&self) -> &VoiceSelection {
        &self.voice
    }

    pub fn model(&self) -> &ModelSelection {
        &self.model
    }

    pub fn language(&self) -> &LanguageCode {
        &self.language
    }

    pub fn output_format(&self) -> &OutputFormat {
        &self.output_format
    }

    pub const fn config_revision(&self) -> u64 {
        self.config_revision
    }

    pub fn config_digest(&self) -> &Digest {
        &self.config_digest
    }

    pub const fn text_revision(&self) -> u64 {
        self.text_revision
    }

    pub fn text_digest(&self) -> &Digest {
        &self.text_digest
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// Bounded exact text. Serialization and debug output contain only digest and
/// character-count evidence, preventing accidental PII export.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ScriptText(String);

impl ScriptText {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let character_count = value.chars().count();
        if character_count == 0 {
            return Err(TypeError::Empty("text"));
        }
        if character_count > MAX_TEXT_CHARACTERS {
            return Err(TypeError::TextTooLong);
        }
        if value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
        {
            return Err(TypeError::InvalidText);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn character_count(&self) -> u32 {
        u32::try_from(self.0.chars().count()).expect("bounded text fits u32")
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.0.as_bytes())
    }
}

impl fmt::Debug for ScriptText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptText")
            .field("character_count", &self.character_count())
            .field("digest", &self.digest())
            .finish()
    }
}

impl Serialize for ScriptText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ScriptTextEvidence", 2)?;
        state.serialize_field("characterCount", &self.character_count())?;
        state.serialize_field("digest", &self.digest())?;
        state.end()
    }
}

/// A Mission-bound audio-creation objective.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioCreationObjective {
    scope: MissionScope,
    objective_id: ObjectiveId,
    text_revision: u64,
    text: ScriptText,
}

impl AudioCreationObjective {
    pub fn new(
        scope: MissionScope,
        objective_id: ObjectiveId,
        text_revision: u64,
        text: ScriptText,
    ) -> Result<Self, TypeError> {
        if text_revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        if text.character_count() > scope.config().max_character_count() {
            return Err(TypeError::TextTooLong);
        }
        Ok(Self {
            scope,
            objective_id,
            text_revision,
            text,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn objective_id(&self) -> &ObjectiveId {
        &self.objective_id
    }

    pub const fn text_revision(&self) -> u64 {
        self.text_revision
    }

    pub fn text(&self) -> &ScriptText {
        &self.text
    }

    pub fn text_digest(&self) -> Digest {
        self.text.digest()
    }

    pub fn text_character_count(&self) -> u32 {
        self.text.character_count()
    }

    pub fn binding(&self) -> SynthesisBinding {
        SynthesisBinding::for_scope(&self.scope, self.text_revision, self.text_digest())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// Compatibility name for callers that use the shorter objective term.
pub type AudioObjective = AudioCreationObjective;

/// Exact operation/fingerprint fence for replay prevention.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdempotencyFence {
    operation_id: OperationId,
    fingerprint: Digest,
}

impl IdempotencyFence {
    pub fn new(operation_id: OperationId, fingerprint: Digest) -> Result<Self, TypeError> {
        if !fingerprint.is_valid() {
            return Err(TypeError::InvalidDigest);
        }
        Ok(Self {
            operation_id,
            fingerprint,
        })
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }
}

/// Immutable provider proposal; raw text remains only inside the redacted
/// objective value and is never emitted in serialized evidence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AudioGenerationProposal {
    objective: AudioCreationObjective,
    provider_id: String,
    provider_version: PluginVersion,
    registration_digest: Digest,
    binding: SynthesisBinding,
    fence: IdempotencyFence,
    proposal_digest: Digest,
}

impl AudioGenerationProposal {
    pub fn new(
        objective: AudioCreationObjective,
        provider_id: impl Into<String>,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, TypeError> {
        let provider_id = provider_id.into();
        if provider_id != crate::PROVIDER_ID {
            return Err(TypeError::InvalidScope("provider id"));
        }
        if !registration_digest.is_valid() {
            return Err(TypeError::InvalidDigest);
        }
        let binding = objective.binding();
        let fingerprint = digest_serializable(&ProposalMaterial {
            objective_id: objective.objective_id().clone(),
            scope_digest: objective.scope().digest(),
            text_revision: objective.text_revision(),
            text_digest: objective.text_digest(),
            binding_digest: binding.digest(),
            provider_id: provider_id.clone(),
            provider_version,
            registration_digest: registration_digest.clone(),
        });
        let operation_id = OperationId::new(format!("audio-op-{}", &fingerprint.as_str()[..24]))?;
        let fence = IdempotencyFence::new(operation_id, fingerprint)?;
        let proposal_digest = digest_serializable(&ProposalDigestMaterial {
            fingerprint: fence.fingerprint().clone(),
            binding: binding.clone(),
            registration_digest: registration_digest.clone(),
        });
        Ok(Self {
            objective,
            provider_id,
            provider_version,
            registration_digest,
            binding,
            fence,
            proposal_digest,
        })
    }

    pub fn objective(&self) -> &AudioCreationObjective {
        &self.objective
    }

    pub fn scope(&self) -> &MissionScope {
        self.objective.scope()
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn binding(&self) -> &SynthesisBinding {
        &self.binding
    }

    pub fn text_digest(&self) -> Digest {
        self.objective.text_digest()
    }

    pub fn text_character_count(&self) -> u32 {
        self.objective.text_character_count()
    }

    pub fn config_digest(&self) -> Digest {
        self.scope().config().digest()
    }

    pub fn fence(&self) -> &IdempotencyFence {
        &self.fence
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn verify_digest(&self) -> bool {
        digest_serializable(&ProposalDigestMaterial {
            fingerprint: self.fence.fingerprint().clone(),
            binding: self.binding.clone(),
            registration_digest: self.registration_digest.clone(),
        }) == self.proposal_digest
    }
}

/// Opaque API-key reference. The supplied label is hashed and discarded; no
/// secret material is stored, serialized, or displayed.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    scope: MissionScope,
    provider_id: String,
    reference_digest: Digest,
}

impl SecretReference {
    pub fn new(scope: &MissionScope, reference_label: impl AsRef<str>) -> Result<Self, TypeError> {
        Self::for_provider(scope, crate::PROVIDER_ID, reference_label)
    }

    pub fn for_provider(
        scope: &MissionScope,
        provider_id: impl Into<String>,
        reference_label: impl AsRef<str>,
    ) -> Result<Self, TypeError> {
        let provider_id = provider_id.into();
        let reference_label = reference_label.as_ref();
        if reference_label.is_empty() {
            return Err(TypeError::Empty("secret reference"));
        }
        let reference_digest =
            digest_serializable(&(provider_id.clone(), scope.digest(), reference_label));
        Ok(Self {
            scope: scope.clone(),
            provider_id,
            reference_digest,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn reference_digest(&self) -> Digest {
        self.reference_digest.clone()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("scope_digest", &self.scope.digest())
            .field("provider_id", &self.provider_id)
            .field("reference_digest", &self.reference_digest)
            .field("secret", &"<opaque>")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalMaterial {
    objective_id: ObjectiveId,
    scope_digest: Digest,
    text_revision: u64,
    text_digest: Digest,
    binding_digest: Digest,
    provider_id: String,
    provider_version: PluginVersion,
    registration_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposalDigestMaterial {
    fingerprint: Digest,
    binding: SynthesisBinding,
    registration_digest: Digest,
}
