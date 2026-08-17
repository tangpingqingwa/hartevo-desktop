use std::{fmt, str::FromStr};

use serde::{Serialize, Serializer};
use thiserror::Error;

use crate::canonical::digest_serializable;

/// Errors raised while constructing a typed HeyGen input or scope value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TypeError {
    #[error("{0} cannot be empty")]
    Empty(&'static str),
    #[error("{0} is not a valid identifier")]
    InvalidIdentifier(&'static str),
    #[error("digest is not 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("locale is not a valid BCP-47-shaped identifier")]
    InvalidLocale,
    #[error("media type is invalid")]
    InvalidMediaType,
    #[error("URL must be an HTTPS URL without whitespace")]
    InvalidUrl,
    #[error("revision must be positive")]
    InvalidRevision,
    #[error("scene order must be positive and contiguous")]
    InvalidSceneOrder,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("consent reference does not bind the selected custom identity")]
    InvalidConsent,
    #[error("input asset metadata is invalid")]
    InvalidAsset,
    #[error("render expectation is invalid")]
    InvalidRender,
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<(), TypeError> {
    if value.is_empty() || value.len() > 128 {
        return Err(if value.is_empty() {
            TypeError::Empty(kind)
        } else {
            TypeError::InvalidIdentifier(kind)
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) || !value
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
identifier_type!(TemplateId, "template id");
identifier_type!(AvatarId, "avatar id");
identifier_type!(VoiceId, "voice id");
identifier_type!(VideoId, "video id");
identifier_type!(OperationId, "operation id");
identifier_type!(ArtifactId, "artifact id");
identifier_type!(AssetId, "asset id");
identifier_type!(VariableName, "variable name");

/// A validated SHA-256 digest used for every immutable proposal boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut output = String::with_capacity(64);
        for byte in sha256(bytes) {
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as ShaDigest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.into()
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

/// A locale binding kept inside the Mission scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Locale(String);

impl Locale {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let mut pieces = value.split('-');
        let Some(language) = pieces.next() else {
            return Err(TypeError::InvalidLocale);
        };
        if language.len() < 2
            || language.len() > 8
            || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
            || pieces.any(|piece| {
                piece.is_empty()
                    || piece.len() > 8
                    || !piece.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
        {
            return Err(TypeError::InvalidLocale);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An artifact media type with no raw provider payload.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MediaType(String);

impl MediaType {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let mut parts = value.split('/');
        let Some(major) = parts.next() else {
            return Err(TypeError::InvalidMediaType);
        };
        let Some(minor) = parts.next() else {
            return Err(TypeError::InvalidMediaType);
        };
        if parts.next().is_some()
            || major.is_empty()
            || minor.is_empty()
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'+' | b'.')
            })
        {
            return Err(TypeError::InvalidMediaType);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An HTTPS URL held as an opaque, redacted value.
#[derive(Ord, PartialOrd)]
pub struct MediaUrl(String);

impl MediaUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if !value.starts_with("https://")
            || value.chars().any(char::is_whitespace)
            || value.len() <= "https://".len()
        {
            return Err(TypeError::InvalidUrl);
        }
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }

    pub(crate) fn is_expiring_before(&self, now: u64, expiry: u64) -> bool {
        let _ = self;
        expiry <= now
    }
}

impl Clone for MediaUrl {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Eq for MediaUrl {}

impl PartialEq for MediaUrl {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Debug for MediaUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaUrl")
            .field("url_digest", &self.digest())
            .field("redacted", &true)
            .finish()
    }
}

impl Serialize for MediaUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[redacted-media-url]")
    }
}

/// A secret-store reference. It cannot contain or resolve API-key bytes.
pub struct SecretReference {
    reference_id: String,
    scope: CredentialScope,
    revision: u64,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: CredentialScope,
        revision: u64,
    ) -> Result<Self, TypeError> {
        let reference_id = reference_id.into();
        if !reference_id.starts_with("secret-ref-") {
            return Err(TypeError::InvalidIdentifier("secret reference"));
        }
        validate_identifier(&reference_id, "secret reference")?;
        if revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        Ok(Self {
            reference_id,
            scope,
            revision,
        })
    }

    pub fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_text(&self.reference_id)
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            scope: self.scope.clone(),
            revision: self.revision,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.scope == other.scope
            && self.revision == other.revision
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope.digest())
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RedactedSecret<'a> {
            reference_digest: Digest,
            scope_digest: Digest,
            revision: u64,
            #[serde(skip)]
            _scope: &'a CredentialScope,
        }
        RedactedSecret {
            reference_digest: self.reference_digest(),
            scope_digest: self.scope.digest(),
            revision: self.revision,
            _scope: &self.scope,
        }
        .serialize(serializer)
    }
}

/// Provider credential scope. It is separate from Mission render scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct CredentialScope {
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    mission_id: MissionId,
    provider_id: String,
}

impl CredentialScope {
    pub fn new(
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        mission_id: MissionId,
        provider_id: impl Into<String>,
    ) -> Result<Self, TypeError> {
        let provider_id = provider_id.into();
        validate_identifier(&provider_id, "provider id")?;
        Ok(Self {
            workspace_id,
            project_id,
            mission_id,
            provider_id,
        })
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

/// The identity class guarded by a consent reference.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    Avatar,
    Voice,
}

/// An opaque reference to an already-authorized custom avatar or voice.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentReference {
    reference_digest: Digest,
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    mission_id: MissionId,
    identity_kind: IdentityKind,
    identity_id: String,
    revision: u64,
}

impl ConsentReference {
    pub fn new(
        reference_id: impl Into<String>,
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        mission_id: MissionId,
        identity_kind: IdentityKind,
        identity_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, TypeError> {
        let reference_id = reference_id.into();
        let identity_id = identity_id.into();
        validate_identifier(&reference_id, "consent reference")?;
        validate_identifier(&identity_id, "consented identity")?;
        if revision == 0 {
            return Err(TypeError::InvalidRevision);
        }
        Ok(Self {
            reference_digest: Digest::from_text(reference_id),
            workspace_id,
            project_id,
            mission_id,
            identity_kind,
            identity_id,
            revision,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn identity_kind(&self) -> IdentityKind {
        self.identity_kind
    }

    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    fn matches_scope(
        &self,
        workspace_id: &WorkspaceId,
        project_id: &ProjectId,
        mission_id: &MissionId,
        identity_kind: IdentityKind,
        identity_id: &str,
    ) -> bool {
        &self.workspace_id == workspace_id
            && &self.project_id == project_id
            && &self.mission_id == mission_id
            && self.identity_kind == identity_kind
            && self.identity_id == identity_id
    }
}

/// A provider-default or consent-bound custom avatar selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum AvatarSelection {
    ProviderDefault {
        avatar_id: AvatarId,
    },
    Custom {
        avatar_id: AvatarId,
        consent: ConsentReference,
    },
}

impl AvatarSelection {
    pub fn provider_default(avatar_id: AvatarId) -> Self {
        Self::ProviderDefault { avatar_id }
    }

    pub fn custom(avatar_id: AvatarId, consent: ConsentReference) -> Self {
        Self::Custom { avatar_id, consent }
    }

    pub fn avatar_id(&self) -> &AvatarId {
        match self {
            Self::ProviderDefault { avatar_id } | Self::Custom { avatar_id, .. } => avatar_id,
        }
    }

    pub fn consent(&self) -> Option<&ConsentReference> {
        match self {
            Self::ProviderDefault { .. } => None,
            Self::Custom { consent, .. } => Some(consent),
        }
    }
}

/// A provider-default or consent-bound custom voice selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum VoiceSelection {
    ProviderDefault {
        voice_id: VoiceId,
    },
    Custom {
        voice_id: VoiceId,
        consent: ConsentReference,
    },
}

impl VoiceSelection {
    pub fn provider_default(voice_id: VoiceId) -> Self {
        Self::ProviderDefault { voice_id }
    }

    pub fn custom(voice_id: VoiceId, consent: ConsentReference) -> Self {
        Self::Custom { voice_id, consent }
    }

    pub fn voice_id(&self) -> &VoiceId {
        match self {
            Self::ProviderDefault { voice_id } | Self::Custom { voice_id, .. } => voice_id,
        }
    }

    pub fn consent(&self) -> Option<&ConsentReference> {
        match self {
            Self::ProviderDefault { .. } => None,
            Self::Custom { consent, .. } => Some(consent),
        }
    }
}

/// Exact workspace, Project, Mission, template, identity, and locale scope.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    workspace_id: WorkspaceId,
    project_id: ProjectId,
    mission_id: MissionId,
    template_id: TemplateId,
    avatar: AvatarSelection,
    voice: VoiceSelection,
    locale: Locale,
}

impl MissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        project_id: ProjectId,
        mission_id: MissionId,
        template_id: TemplateId,
        avatar: AvatarSelection,
        voice: VoiceSelection,
        locale: Locale,
    ) -> Result<Self, TypeError> {
        let scope = Self {
            workspace_id,
            project_id,
            mission_id,
            template_id,
            avatar,
            voice,
            locale,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn template_id(&self) -> &TemplateId {
        &self.template_id
    }

    pub fn avatar(&self) -> &AvatarSelection {
        &self.avatar
    }

    pub fn voice(&self) -> &VoiceSelection {
        &self.voice
    }

    pub fn locale(&self) -> &Locale {
        &self.locale
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    fn validate(&self) -> Result<(), TypeError> {
        if let AvatarSelection::Custom { avatar_id, consent } = &self.avatar
            && !consent.matches_scope(
                &self.workspace_id,
                &self.project_id,
                &self.mission_id,
                IdentityKind::Avatar,
                avatar_id.as_str(),
            )
        {
            return Err(TypeError::InvalidConsent);
        }
        if let VoiceSelection::Custom { voice_id, consent } = &self.voice
            && !consent.matches_scope(
                &self.workspace_id,
                &self.project_id,
                &self.mission_id,
                IdentityKind::Voice,
                voice_id.as_str(),
            )
        {
            return Err(TypeError::InvalidConsent);
        }
        Ok(())
    }
}

/// Script material kept in memory only; serialization and Debug expose its digest.
pub struct ScriptText {
    value: String,
    digest: Digest,
}

impl ScriptText {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TypeError::Empty("script"));
        }
        Ok(Self {
            digest: Digest::from_text(&value),
            value,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn character_count(&self) -> usize {
        self.value.chars().count()
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Clone for ScriptText {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            digest: self.digest.clone(),
        }
    }
}

impl PartialEq for ScriptText {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest && self.value == other.value
    }
}

impl Eq for ScriptText {}

impl fmt::Debug for ScriptText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptText")
            .field("digest", &self.digest)
            .field("character_count", &self.character_count())
            .field("redacted", &true)
            .finish_non_exhaustive()
    }
}

impl Serialize for ScriptText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RedactedScript {
            digest: Digest,
            character_count: usize,
        }
        RedactedScript {
            digest: self.digest(),
            character_count: self.character_count(),
        }
        .serialize(serializer)
    }
}

/// A template variable value; the value is digest-bound and redacted in logs.
pub struct VariableValue {
    value: String,
    digest: Digest,
}

impl VariableValue {
    pub fn new(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(TypeError::Empty("variable value"));
        }
        Ok(Self {
            digest: Digest::from_text(&value),
            value,
        })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Clone for VariableValue {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            digest: self.digest.clone(),
        }
    }
}

impl PartialEq for VariableValue {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest && self.value == other.value
    }
}

impl Eq for VariableValue {}

impl fmt::Debug for VariableValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VariableValue")
            .field("digest", &self.digest)
            .field("redacted", &true)
            .finish_non_exhaustive()
    }
}

impl Serialize for VariableValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.digest.serialize(serializer)
    }
}

/// One ordered scene in the exact Mission render input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct Scene {
    order: u32,
    scene_id: String,
    script: ScriptText,
}

impl Scene {
    pub fn new(
        order: u32,
        scene_id: impl Into<String>,
        script: ScriptText,
    ) -> Result<Self, TypeError> {
        if order == 0 {
            return Err(TypeError::InvalidSceneOrder);
        }
        let scene_id = scene_id.into();
        validate_identifier(&scene_id, "scene id")?;
        Ok(Self {
            order,
            scene_id,
            script,
        })
    }

    pub const fn order(&self) -> u32 {
        self.order
    }

    pub fn scene_id(&self) -> &str {
        &self.scene_id
    }

    pub fn script(&self) -> &ScriptText {
        &self.script
    }
}

/// One ordered template variable in the exact Mission render input.
#[derive(Clone, Eq, PartialEq)]
pub struct TemplateVariable {
    name: VariableName,
    value: VariableValue,
}

impl fmt::Debug for TemplateVariable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateVariable")
            .field("name_digest", &Digest::from_text(self.name.as_str()))
            .field("value", &self.value)
            .field("redacted", &true)
            .finish_non_exhaustive()
    }
}

impl Serialize for TemplateVariable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RedactedVariable {
            name_digest: Digest,
            value_digest: Digest,
        }
        RedactedVariable {
            name_digest: Digest::from_text(self.name.as_str()),
            value_digest: self.value.digest(),
        }
        .serialize(serializer)
    }
}

impl TemplateVariable {
    pub fn new(name: VariableName, value: VariableValue) -> Result<Self, TypeError> {
        if name.as_str().starts_with('$') {
            return Err(TypeError::InvalidIdentifier("variable name"));
        }
        Ok(Self { name, value })
    }

    pub fn name(&self) -> &VariableName {
        &self.name
    }

    pub fn value(&self) -> &VariableValue {
        &self.value
    }
}

/// An input asset is referenced by immutable digest, never by media bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputAsset {
    asset_id: AssetId,
    input_digest: Digest,
    byte_length: u64,
    media_type: MediaType,
}

impl InputAsset {
    pub fn new(
        asset_id: AssetId,
        input_digest: Digest,
        byte_length: u64,
        media_type: MediaType,
    ) -> Result<Self, TypeError> {
        if !input_digest.is_valid() || byte_length == 0 {
            return Err(TypeError::InvalidAsset);
        }
        Ok(Self {
            asset_id,
            input_digest,
            byte_length,
            media_type,
        })
    }

    pub fn asset_id(&self) -> &AssetId {
        &self.asset_id
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn media_type(&self) -> &MediaType {
        &self.media_type
    }
}

/// Expected output dimensions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoDimensions {
    width: u32,
    height: u32,
}

impl VideoDimensions {
    pub fn new(width: u32, height: u32) -> Result<Self, TypeError> {
        if width == 0 || height == 0 || width > 16_384 || height > 16_384 {
            return Err(TypeError::InvalidRender);
        }
        Ok(Self { width, height })
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }
}

/// Expected output duration range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurationExpectation {
    minimum_seconds: u32,
    maximum_seconds: u32,
}

impl DurationExpectation {
    pub fn new(minimum_seconds: u32, maximum_seconds: u32) -> Result<Self, TypeError> {
        if maximum_seconds == 0 || minimum_seconds > maximum_seconds || maximum_seconds > 86_400 {
            return Err(TypeError::InvalidRender);
        }
        Ok(Self {
            minimum_seconds,
            maximum_seconds,
        })
    }

    pub const fn minimum_seconds(self) -> u32 {
        self.minimum_seconds
    }

    pub const fn maximum_seconds(self) -> u32 {
        self.maximum_seconds
    }
}

/// Caption expectation bound into the idempotency fence and artifact metadata.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptionExpectation {
    Required,
    Optional,
    Forbidden,
}

/// Exact output expectations for a Mission video result.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderExpectations {
    dimensions: VideoDimensions,
    duration: DurationExpectation,
    captions: CaptionExpectation,
}

impl RenderExpectations {
    pub fn new(
        dimensions: VideoDimensions,
        duration: DurationExpectation,
        captions: CaptionExpectation,
    ) -> Self {
        Self {
            dimensions,
            duration,
            captions,
        }
    }

    pub const fn dimensions(self) -> VideoDimensions {
        self.dimensions
    }

    pub const fn duration(self) -> DurationExpectation {
        self.duration
    }

    pub const fn captions(self) -> CaptionExpectation {
        self.captions
    }
}

/// Digests for every source component, plus the complete source revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub struct SourceDigests {
    script_digest: Digest,
    scene_digest: Digest,
    variable_digest: Digest,
    input_asset_digest: Digest,
    source_digest: Digest,
}

impl SourceDigests {
    pub fn script_digest(&self) -> &Digest {
        &self.script_digest
    }

    pub fn scene_digest(&self) -> &Digest {
        &self.scene_digest
    }

    pub fn variable_digest(&self) -> &Digest {
        &self.variable_digest
    }

    pub fn input_asset_digest(&self) -> &Digest {
        &self.input_asset_digest
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }
}

/// Complete Mission-bound input for a HeyGen generation proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionVideoSource {
    scope: MissionScope,
    mission_revision: u64,
    source_revision: u64,
    script: ScriptText,
    scenes: Vec<Scene>,
    variables: Vec<TemplateVariable>,
    input_assets: Vec<InputAsset>,
    render: RenderExpectations,
}

impl MissionVideoSource {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: MissionScope,
        mission_revision: u64,
        source_revision: u64,
        script: ScriptText,
        scenes: Vec<Scene>,
        variables: Vec<TemplateVariable>,
        input_assets: Vec<InputAsset>,
        render: RenderExpectations,
    ) -> Result<Self, TypeError> {
        if mission_revision == 0 || source_revision == 0 || scenes.is_empty() {
            return Err(TypeError::InvalidRevision);
        }
        for (index, scene) in scenes.iter().enumerate() {
            let expected_order = u32::try_from(index)
                .map_err(|_| TypeError::InvalidSceneOrder)?
                .saturating_add(1);
            if scene.order() != expected_order {
                return Err(TypeError::InvalidSceneOrder);
            }
        }
        if has_duplicate(variables.iter().map(|variable| variable.name().as_str()))
            || has_duplicate(input_assets.iter().map(|asset| asset.asset_id().as_str()))
        {
            return Err(TypeError::InvalidAsset);
        }
        Ok(Self {
            scope,
            mission_revision,
            source_revision,
            script,
            scenes,
            variables,
            input_assets,
            render,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn script(&self) -> &ScriptText {
        &self.script
    }

    pub fn scenes(&self) -> &[Scene] {
        &self.scenes
    }

    pub fn variables(&self) -> &[TemplateVariable] {
        &self.variables
    }

    pub fn input_assets(&self) -> &[InputAsset] {
        &self.input_assets
    }

    pub const fn render(&self) -> RenderExpectations {
        self.render
    }

    pub fn digests(&self) -> SourceDigests {
        let script_digest = self.script.digest();
        let scene_digest = digest_serializable(
            &self
                .scenes
                .iter()
                .map(|scene| SceneDigestMaterial {
                    order: scene.order,
                    scene_id: scene.scene_id.clone(),
                    script_digest: scene.script.digest(),
                })
                .collect::<Vec<_>>(),
        );
        let variable_digest = digest_serializable(
            &self
                .variables
                .iter()
                .map(|variable| VariableDigestMaterial {
                    name: variable.name.as_str(),
                    value_digest: variable.value.digest(),
                })
                .collect::<Vec<_>>(),
        );
        let input_asset_digest = digest_serializable(
            &self
                .input_assets
                .iter()
                .map(|asset| AssetDigestMaterial {
                    asset_id: asset.asset_id.as_str(),
                    input_digest: asset.input_digest.clone(),
                    byte_length: asset.byte_length,
                    media_type: asset.media_type.as_str(),
                })
                .collect::<Vec<_>>(),
        );
        let source_digest = digest_serializable(&SourceDigestMaterial {
            scope_digest: self.scope.digest(),
            mission_revision: self.mission_revision,
            source_revision: self.source_revision,
            script_digest: script_digest.clone(),
            scene_digest: scene_digest.clone(),
            variable_digest: variable_digest.clone(),
            input_asset_digest: input_asset_digest.clone(),
            render: self.render,
        });
        SourceDigests {
            script_digest,
            scene_digest,
            variable_digest,
            input_asset_digest,
            source_digest,
        }
    }
}

fn has_duplicate<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SceneDigestMaterial {
    order: u32,
    scene_id: String,
    script_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VariableDigestMaterial<'a> {
    name: &'a str,
    value_digest: Digest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssetDigestMaterial<'a> {
    asset_id: &'a str,
    input_digest: Digest,
    byte_length: u64,
    media_type: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceDigestMaterial {
    scope_digest: Digest,
    mission_revision: u64,
    source_revision: u64,
    script_digest: Digest,
    scene_digest: Digest,
    variable_digest: Digest,
    input_asset_digest: Digest,
    render: RenderExpectations,
}

/// Async provider status preserved without collapsing terminal and non-terminal states.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum AsyncVideoStatus {
    Pending,
    Waiting,
    Processing,
    Completed,
    Failed { code: String },
    Cancelled,
    ProviderUnknown { reason: String },
}

impl AsyncVideoStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed { .. } | Self::Cancelled | Self::ProviderUnknown { .. }
        )
    }

    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// Projection exposed to a Mission consumer; it retains all observed status distinctions.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum GenerationStatusProjection {
    Pending,
    Waiting,
    Processing,
    Completed,
    Failed { code: String },
    Cancelled,
    ProviderUnknown { reason: String },
}

impl From<&AsyncVideoStatus> for GenerationStatusProjection {
    fn from(status: &AsyncVideoStatus) -> Self {
        match status {
            AsyncVideoStatus::Pending => Self::Pending,
            AsyncVideoStatus::Waiting => Self::Waiting,
            AsyncVideoStatus::Processing => Self::Processing,
            AsyncVideoStatus::Completed => Self::Completed,
            AsyncVideoStatus::Failed { code } => Self::Failed { code: code.clone() },
            AsyncVideoStatus::Cancelled => Self::Cancelled,
            AsyncVideoStatus::ProviderUnknown { reason } => Self::ProviderUnknown {
                reason: reason.clone(),
            },
        }
    }
}

/// The idempotency fence used by generation and adoption proposals.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdempotencyFence {
    fingerprint: Digest,
    operation_id: OperationId,
    scope_digest: Digest,
    registration_digest: Digest,
}

impl IdempotencyFence {
    pub(crate) fn new(
        fingerprint: Digest,
        operation_id: OperationId,
        scope_digest: Digest,
        registration_digest: Digest,
    ) -> Self {
        Self {
            fingerprint,
            operation_id,
            scope_digest,
            registration_digest,
        }
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.fingerprint
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

/// A generation request that has not been submitted to a live provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationProposal {
    scope: MissionScope,
    mission_revision: u64,
    source_revision: u64,
    source_digests: SourceDigests,
    render: RenderExpectations,
    provider_version: PluginVersion,
    provider_id: String,
    registration_digest: Digest,
    fence: IdempotencyFence,
}

impl GenerationProposal {
    pub(crate) fn new(
        source: &MissionVideoSource,
        provider_id: impl Into<String>,
        provider_version: PluginVersion,
        registration_digest: Digest,
    ) -> Result<Self, TypeError> {
        let provider_id = provider_id.into();
        validate_identifier(&provider_id, "provider id")?;
        let source_digests = source.digests();
        let fingerprint = digest_serializable(&GenerationFingerprintMaterial {
            scope_digest: source.scope.digest(),
            mission_revision: source.mission_revision,
            source_revision: source.source_revision,
            source_digests: source_digests.clone(),
            provider_id: provider_id.clone(),
            provider_version,
            registration_digest: registration_digest.clone(),
            template_id: source.scope.template_id.as_str().to_owned(),
            avatar_id: source.scope.avatar().avatar_id().as_str().to_owned(),
            voice_id: source.scope.voice().voice_id().as_str().to_owned(),
            locale: source.scope.locale.as_str().to_owned(),
            render: source.render,
        });
        let operation_id = OperationId::new(format!("operation-{}", &fingerprint.as_str()[..24]))?;
        let fence = IdempotencyFence::new(
            fingerprint,
            operation_id,
            source.scope.digest(),
            registration_digest.clone(),
        );
        Ok(Self {
            scope: source.scope.clone(),
            mission_revision: source.mission_revision,
            source_revision: source.source_revision,
            source_digests,
            render: source.render,
            provider_version,
            provider_id,
            registration_digest,
            fence,
        })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn source_digests(&self) -> &SourceDigests {
        &self.source_digests
    }

    pub const fn render(&self) -> RenderExpectations {
        self.render
    }

    pub fn provider_version(&self) -> PluginVersion {
        self.provider_version
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn fence(&self) -> &IdempotencyFence {
        &self.fence
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationFingerprintMaterial {
    scope_digest: Digest,
    mission_revision: u64,
    source_revision: u64,
    source_digests: SourceDigests,
    provider_id: String,
    provider_version: PluginVersion,
    registration_digest: Digest,
    template_id: String,
    avatar_id: String,
    voice_id: String,
    locale: String,
    render: RenderExpectations,
}

/// Fingerprint for a future adoption proposal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AdoptionFingerprint(Digest);

impl AdoptionFingerprint {
    pub(crate) fn new(value: Digest) -> Self {
        Self(value)
    }

    pub fn digest(&self) -> &Digest {
        &self.0
    }
}

/// Artifact metadata required for a future Work Product adoption review.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactMetadata {
    media_type: MediaType,
    byte_length: u64,
    dimensions: VideoDimensions,
    duration_seconds: u32,
    captions: CaptionExpectation,
}

impl ArtifactMetadata {
    pub fn new(
        media_type: MediaType,
        byte_length: u64,
        dimensions: VideoDimensions,
        duration_seconds: u32,
        captions: CaptionExpectation,
    ) -> Result<Self, TypeError> {
        if byte_length == 0 || duration_seconds == 0 {
            return Err(TypeError::InvalidAsset);
        }
        Ok(Self {
            media_type,
            byte_length,
            dimensions,
            duration_seconds,
            captions,
        })
    }

    pub fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub const fn dimensions(&self) -> VideoDimensions {
        self.dimensions
    }

    pub const fn duration_seconds(&self) -> u32 {
        self.duration_seconds
    }

    pub const fn captions(&self) -> CaptionExpectation {
        self.captions
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}
