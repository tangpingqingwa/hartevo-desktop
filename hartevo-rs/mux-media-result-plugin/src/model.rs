//! Typed Mux scope, redacted projections, digests, and proposal/evidence
//! models.  The model intentionally has no raw HTTP body, token, URL, or
//! viewer identifier field.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

use crate::{
    MUX_API_ORIGIN, MUX_MAX_CURSOR_BYTES, MUX_MAX_PAGES, MUX_MAX_PLAYBACK_IDS,
    MUX_MAX_RESPONSE_BYTES, MUX_MAX_TRACKS, MUX_MEDIA_RESULT_CONTRACT_VERSION,
    MUX_MEDIA_RESULT_PLUGIN_VERSION, MUX_MEDIA_RESULT_PROVIDER_ID,
    MUX_MEDIA_RESULT_PROVIDER_REVISION, contract_digest, plugin_version_digest, provider_digest,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SCOPE_LABEL_BYTES: usize = 128;
pub const MAX_POLICY_LABEL_BYTES: usize = 64;

/// Errors are deliberately projected.  They never carry provider response
/// bodies, authorization values, URLs, media bytes, or viewer data.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MuxError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("invalid digest: {0}")]
    InvalidDigest(&'static str),
    #[error("contract invalid: {0}")]
    ContractInvalid(&'static str),
    #[error("scope mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("scope revision drift: {0}")]
    ScopeRevisionDrift(&'static str),
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is stale or tampered")]
    RegistrationTampered,
    #[error("proposal is stale or tampered")]
    ProposalTampered,
    #[error("evidence is stale or tampered")]
    EvidenceTampered,
    #[error("duplicate proposal or evidence was rejected")]
    DuplicateEvidence,
    #[error("asset revision drifted from the pinned binding")]
    AssetRevisionDrift,
    #[error("playback revision or association drifted from the pinned binding")]
    PlaybackRevisionDrift,
    #[error("track revision drifted from the pinned binding")]
    TrackRevisionDrift,
    #[error("encoding revision drifted from the pinned binding")]
    EncodingRevisionDrift,
    #[error("playback policy drifted from the pinned binding")]
    PlaybackPolicyDrift,
    #[error("provider revision drifted from the pinned binding")]
    ProviderRevisionDrift,
    #[error("contract revision drifted from the pinned binding")]
    ContractRevisionDrift,
    #[error("version drifted from the pinned binding")]
    VersionDrift,
    #[error("cursor exceeds the bounded request limit")]
    CursorLimitExceeded,
    #[error("response exceeds the bounded response limit")]
    ResponseLimitExceeded,
    #[error("track count exceeds the bounded response limit")]
    TrackLimitExceeded,
    #[error("playback-ID count exceeds the bounded response limit")]
    PlaybackIdLimitExceeded,
    #[error("requested track is not present in the asset projection")]
    TrackNotFound,
    #[error("requested playback ID is not associated with the scoped asset")]
    PlaybackNotFound,
    #[error("asset access is unavailable in the provider response")]
    AccessLost,
    #[error("provider response is malformed or incomplete")]
    MalformedResponse,
    #[error("provider returned an unsupported status")]
    UnsupportedStatus(u16),
    #[error("provider rate/backoff bound was exhausted")]
    RetryLimitExceeded,
    #[error("provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("native Mux execution is a Layer-2 gap")]
    NativeExecutionUnavailable,
    #[error("forbidden provider operation")]
    ForbiddenOperation,
    #[error("serialization failed while computing a deterministic digest")]
    Serialization,
}

/// A lowercase SHA-256 digest used for every externally meaningful binding.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes.as_ref());
        Self(hex_encode(&hasher.finalize()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, MuxError> {
        let value = value.into();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(MuxError::InvalidDigest(
                "expected a 64-character SHA-256 digest",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    Digest::sha256(bytes)
}

pub(crate) fn domain_digest<T: Serialize + ?Sized>(domain: &str, value: &T) -> Digest {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(&serde_json::to_vec(value).unwrap_or_default());
    Digest::sha256(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
    allow_whitespace: bool,
) -> Result<(), MuxError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || (!allow_whitespace && value.chars().any(char::is_whitespace))
    {
        return Err(MuxError::InvalidField {
            field,
            reason: "must be bounded, non-empty, and free of control characters",
        });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, MuxError> {
                let value = value.into();
                validate_bounded_text(&value, $field, MAX_IDENTIFIER_BYTES, false)?;
                if value.contains('/') || value.contains('?') || value.contains('#') {
                    return Err(MuxError::InvalidField {
                        field: $field,
                        reason: "must not contain URL path separators or query delimiters",
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                domain_digest(concat!("hartevo:mux-media-result:", $field, ":v1"), &self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.digest())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

bounded_id!(MuxAssetId, "asset_id");
bounded_id!(MuxPlaybackId, "playback_id");
bounded_id!(MuxTrackId, "track_id");

/// The only API host accepted by the native Mux contract.  Native transport
/// remains unavailable in this Layer-1 crate even though the host is modeled.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MuxApiHost(String);

impl MuxApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, MuxError> {
        let value = value.into().trim_end_matches('/').to_owned();
        if value != MUX_API_ORIGIN
            || value.contains('?')
            || value.contains('#')
            || value.contains('@')
            || value.chars().any(char::is_whitespace)
        {
            return Err(MuxError::InvalidField {
                field: "mux_api_host",
                reason: "must be the exact HTTPS Mux API origin without credentials or query",
            });
        }
        Ok(Self(value))
    }

    pub fn mux() -> Self {
        Self(MUX_API_ORIGIN.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:mux-media-result:api-host:v1", &self.0)
    }
}

impl fmt::Debug for MuxApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MuxApiHost")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxSecretKind {
    ApiCredential,
    HostManaged,
}

/// Opaque host-owned secret binding.  The supplied handle is hashed during
/// construction and is never retained, serialized, or printed.  This type
/// cannot represent a token ID/secret pair or a signing key.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: MuxSecretKind,
    revision: u64,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        kind: MuxSecretKind,
        revision: u64,
    ) -> Result<Self, MuxError> {
        let reference = opaque_reference.as_ref();
        validate_bounded_text(
            reference,
            "opaque_secret_reference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        if revision == 0 {
            return Err(MuxError::InvalidField {
                field: "secret_reference_revision",
                reason: "must be positive",
            });
        }
        Ok(Self {
            reference_digest: domain_digest(
                "hartevo:mux-media-result:secret-reference:v1",
                &(reference, kind, revision),
            ),
            kind,
            revision,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> MuxSecretKind {
        self.kind
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish()
    }
}

macro_rules! positive_revision {
    ($name:ident, $domain:literal) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, MuxError> {
                if value == 0 {
                    return Err(MuxError::InvalidField {
                        field: "revision",
                        reason: "must be positive",
                    });
                }
                Ok(Self(value))
            }

            pub const fn value(self) -> u64 {
                self.0
            }

            pub fn digest(self) -> Digest {
                domain_digest($domain, &self.0)
            }
        }
    };
}

positive_revision!(
    MuxAssetRevision,
    "hartevo:mux-media-result:asset-revision:v1"
);
positive_revision!(
    MuxPlaybackRevision,
    "hartevo:mux-media-result:playback-revision:v1"
);
positive_revision!(
    MuxTrackRevision,
    "hartevo:mux-media-result:track-revision:v1"
);
positive_revision!(
    MuxEncodingRevision,
    "hartevo:mux-media-result:encoding-revision:v1"
);
positive_revision!(
    PlaybackPolicyRevision,
    "hartevo:mux-media-result:policy-revision:v1"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxEnvironment {
    pub id: String,
    pub revision: u64,
    pub api_host: MuxApiHost,
}

pub type MuxEnvironmentScope = MuxEnvironment;

impl MuxEnvironment {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        Self::with_host(id, revision, MuxApiHost::mux())
    }

    pub fn with_host(
        id: impl Into<String>,
        revision: u64,
        api_host: MuxApiHost,
    ) -> Result<Self, MuxError> {
        let id = id.into();
        validate_bounded_text(&id, "mux_environment_id", MAX_SCOPE_LABEL_BYTES, false)?;
        if revision == 0 {
            return Err(MuxError::InvalidField {
                field: "mux_environment_revision",
                reason: "must be positive",
            });
        }
        Ok(Self {
            id,
            revision,
            api_host,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:environment:v1",
            &(&self.id, self.revision, &self.api_host),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub id: String,
    pub revision: u64,
}

pub type MuxProjectScope = ProjectScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentOperation {
    MetadataRead,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: String,
    pub revision: u64,
    pub operation: ConsentOperation,
}

fn validate_scope_ref(id: &str, revision: u64, field: &'static str) -> Result<(), MuxError> {
    validate_bounded_text(id, field, MAX_SCOPE_LABEL_BYTES, true)?;
    if revision == 0 {
        return Err(MuxError::InvalidField {
            field,
            reason: "revision must be positive",
        });
    }
    Ok(())
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        let id = id.into();
        validate_scope_ref(&id, revision, "project_id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:project:v1",
            &(self.id.as_str(), self.revision),
        )
    }
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        let id = id.into();
        validate_scope_ref(&id, revision, "mission_id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:mission:v1",
            &(self.id.as_str(), self.revision),
        )
    }
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        let id = id.into();
        validate_scope_ref(&id, revision, "work_product_id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:work-product:v1",
            &(self.id.as_str(), self.revision),
        )
    }
}

impl ConsentScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        operation: ConsentOperation,
    ) -> Result<Self, MuxError> {
        let id = id.into();
        validate_scope_ref(&id, revision, "consent_id")?;
        Ok(Self {
            id,
            revision,
            operation,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:consent:v1",
            &(self.id.as_str(), self.revision, self.operation),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxPlaybackPolicy {
    Public,
    Signed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxTrackKind {
    Video,
    Audio,
    Text,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxAssetState {
    Preparing,
    Ready,
    Errored,
    Archived,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxTrackStatus {
    Preparing,
    Ready,
    Errored,
    Archived,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetScope {
    pub id: MuxAssetId,
    pub revision: MuxAssetRevision,
}

impl AssetScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        Ok(Self {
            id: MuxAssetId::new(id)?,
            revision: MuxAssetRevision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:asset-scope:v1",
            &(&self.id, self.revision),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlaybackScope {
    pub id: MuxPlaybackId,
    pub revision: MuxPlaybackRevision,
    pub policy: MuxPlaybackPolicy,
    pub policy_revision: PlaybackPolicyRevision,
}

pub type MuxPlaybackScope = PlaybackScope;

impl PlaybackScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        policy: MuxPlaybackPolicy,
        policy_revision: u64,
    ) -> Result<Self, MuxError> {
        Ok(Self {
            id: MuxPlaybackId::new(id)?,
            revision: MuxPlaybackRevision::new(revision)?,
            policy,
            policy_revision: PlaybackPolicyRevision::new(policy_revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:playback-scope:v1",
            &(&self.id, self.revision, self.policy, self.policy_revision),
        )
    }

    pub fn policy_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:playback-policy:v1",
            &(self.policy, self.policy_revision),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrackScope {
    pub id: MuxTrackId,
    pub revision: MuxTrackRevision,
}

pub type MuxTrackScope = TrackScope;

impl TrackScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        Ok(Self {
            id: MuxTrackId::new(id)?,
            revision: MuxTrackRevision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:track-scope:v1",
            &(&self.id, self.revision),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticRenditionScope {
    pub id: String,
    pub revision: u64,
}

impl StaticRenditionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        let id = id.into();
        validate_scope_ref(&id, revision, "static_rendition_id")?;
        Ok(Self { id, revision })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:static-rendition-scope:v1",
            &(self.id.as_str(), self.revision),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncodingScope {
    pub profile: String,
    pub revision: MuxEncodingRevision,
}

impl EncodingScope {
    pub fn new(profile: impl Into<String>, revision: u64) -> Result<Self, MuxError> {
        let profile = profile.into();
        validate_bounded_text(&profile, "encoding_profile", MAX_POLICY_LABEL_BYTES, false)?;
        Ok(Self {
            profile,
            revision: MuxEncodingRevision::new(revision)?,
        })
    }

    pub fn digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:encoding-scope:v1",
            &(self.profile.as_str(), self.revision),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxScopeInput {
    pub environment: MuxEnvironment,
    pub asset: AssetScope,
    pub playback: Option<PlaybackScope>,
    pub track: Option<TrackScope>,
    pub static_rendition: Option<StaticRenditionScope>,
    pub encoding: EncodingScope,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub consent: ConsentScope,
    pub secret: SecretReference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxScope {
    environment: MuxEnvironment,
    asset: AssetScope,
    playback: Option<PlaybackScope>,
    track: Option<TrackScope>,
    static_rendition: Option<StaticRenditionScope>,
    encoding: EncodingScope,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
    secret: SecretReference,
    scope_digest: Digest,
}

impl MuxScope {
    pub fn new(input: MuxScopeInput) -> Result<Self, MuxError> {
        if let Some(track) = &input.track
            && track.id.as_str().is_empty()
        {
            return Err(MuxError::InvalidField {
                field: "track_id",
                reason: "must not be empty",
            });
        }
        let mut scope = Self {
            environment: input.environment,
            asset: input.asset,
            playback: input.playback,
            track: input.track,
            static_rendition: input.static_rendition,
            encoding: input.encoding,
            project: input.project,
            mission: input.mission,
            work_product: input.work_product,
            consent: input.consent,
            secret: input.secret,
            scope_digest: Digest::sha256([]),
        };
        scope.scope_digest = scope.compute_digest();
        Ok(scope)
    }

    pub fn fixture(secret: SecretReference) -> Result<Self, MuxError> {
        Self::new(MuxScopeInput {
            environment: MuxEnvironment::new("mux-env-1", 1)?,
            asset: AssetScope::new("asset-1", 1)?,
            playback: Some(PlaybackScope::new(
                "playback-1",
                1,
                MuxPlaybackPolicy::Public,
                1,
            )?),
            track: Some(TrackScope::new("track-video-1", 1)?),
            static_rendition: None,
            encoding: EncodingScope::new("baseline", 1)?,
            project: ProjectScope::new("project-1", 1)?,
            mission: MissionScope::new("mission-1", 1)?,
            work_product: WorkProductScope::new("work-product-1", 1)?,
            consent: ConsentScope::new("consent-1", 1, ConsentOperation::MetadataRead)?,
            secret,
        })
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn environment(&self) -> &MuxEnvironment {
        &self.environment
    }

    pub fn environment_digest(&self) -> Digest {
        self.environment.digest()
    }

    pub fn asset(&self) -> &AssetScope {
        &self.asset
    }

    pub fn asset_digest(&self) -> Digest {
        self.asset.digest()
    }

    pub fn playback(&self) -> Option<&PlaybackScope> {
        self.playback.as_ref()
    }

    pub fn playback_digest(&self) -> Option<Digest> {
        self.playback.as_ref().map(PlaybackScope::digest)
    }

    pub fn track(&self) -> Option<&TrackScope> {
        self.track.as_ref()
    }

    pub fn track_digest(&self) -> Option<Digest> {
        self.track.as_ref().map(TrackScope::digest)
    }

    pub fn static_rendition(&self) -> Option<&StaticRenditionScope> {
        self.static_rendition.as_ref()
    }

    pub fn static_rendition_digest(&self) -> Option<Digest> {
        self.static_rendition
            .as_ref()
            .map(StaticRenditionScope::digest)
    }

    pub fn encoding(&self) -> &EncodingScope {
        &self.encoding
    }

    pub fn encoding_digest(&self) -> Digest {
        self.encoding.digest()
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    pub fn validate_request(&self, request: &MuxMediaResultRequest) -> Result<(), MuxError> {
        if request.asset != self.asset.id {
            return Err(MuxError::ScopeMismatch(
                "asset ID is outside the registration scope",
            ));
        }
        if request.playback != self.playback.as_ref().map(|binding| binding.id.clone()) {
            return Err(MuxError::ScopeMismatch(
                "playback ID is outside the registration scope",
            ));
        }
        if request.track != self.track.as_ref().map(|binding| binding.id.clone()) {
            return Err(MuxError::ScopeMismatch(
                "track ID is outside the registration scope",
            ));
        }
        if let Some(cursor) = &request.cursor
            && cursor.byte_len > MUX_MAX_CURSOR_BYTES
        {
            return Err(MuxError::CursorLimitExceeded);
        }
        if request.page == 0 || request.page > MUX_MAX_PAGES {
            return Err(MuxError::CursorLimitExceeded);
        }
        if request.max_response_bytes == 0 || request.max_response_bytes > MUX_MAX_RESPONSE_BYTES {
            return Err(MuxError::ResponseLimitExceeded);
        }
        if !request.include_delivery_readiness
            || !request.include_track_metadata && self.track.is_some()
        {
            return Err(MuxError::ForbiddenOperation);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:scope:v1",
            &(
                &self.environment,
                &self.asset,
                &self.playback,
                &self.track,
                &self.static_rendition,
                &self.encoding,
                &self.project,
                &self.mission,
                &self.work_product,
                &self.consent,
                &self.secret,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxTransportMode {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxCursor {
    digest: Digest,
    byte_len: usize,
}

impl MuxCursor {
    pub fn new(opaque_cursor: impl AsRef<str>) -> Result<Self, MuxError> {
        let value = opaque_cursor.as_ref();
        validate_bounded_text(value, "mux_cursor", MUX_MAX_CURSOR_BYTES, false)?;
        Ok(Self {
            digest: domain_digest("hartevo:mux-media-result:cursor:v1", &value),
            byte_len: value.len(),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultRequest {
    pub asset: MuxAssetId,
    pub playback: Option<MuxPlaybackId>,
    pub track: Option<MuxTrackId>,
    pub expected_asset_digest: Option<Digest>,
    pub expected_playback_digest: Option<Digest>,
    pub expected_track_digest: Option<Digest>,
    pub expected_encoding_digest: Option<Digest>,
    pub cursor: Option<MuxCursor>,
    pub page: u16,
    pub max_response_bytes: usize,
    pub include_playback_association: bool,
    pub include_track_metadata: bool,
    pub include_delivery_readiness: bool,
}

pub type MuxReadRequest = MuxMediaResultRequest;

impl MuxMediaResultRequest {
    pub fn new(scope: &MuxScope) -> Self {
        Self {
            asset: scope.asset.id.clone(),
            playback: scope.playback.as_ref().map(|binding| binding.id.clone()),
            track: scope.track.as_ref().map(|binding| binding.id.clone()),
            expected_asset_digest: None,
            expected_playback_digest: None,
            expected_track_digest: None,
            expected_encoding_digest: None,
            cursor: None,
            page: 1,
            max_response_bytes: MUX_MAX_RESPONSE_BYTES,
            include_playback_association: scope.playback.is_some(),
            include_track_metadata: scope.track.is_some(),
            include_delivery_readiness: true,
        }
    }

    #[must_use]
    pub fn with_expected_asset_digest(mut self, digest: Digest) -> Self {
        self.expected_asset_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn with_expected_playback_digest(mut self, digest: Digest) -> Self {
        self.expected_playback_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn with_expected_track_digest(mut self, digest: Digest) -> Self {
        self.expected_track_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn with_expected_encoding_digest(mut self, digest: Digest) -> Self {
        self.expected_encoding_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: MuxCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    #[must_use]
    pub fn with_page(mut self, page: u16) -> Self {
        self.page = page;
        self
    }

    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn digest(&self) -> Digest {
        domain_digest("hartevo:mux-media-result:request:v1", self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    HostRequested,
    ScopeExpired,
    ProviderDrift,
    ContractDrift,
    SecurityFence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxRegistration {
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub environment_digest: Digest,
    pub asset_digest: Digest,
    pub playback_digest: Option<Digest>,
    pub track_digest: Option<Digest>,
    pub static_rendition_digest: Option<Digest>,
    pub encoding_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl MuxRegistration {
    pub fn new(scope: &MuxScope) -> Self {
        let mut registration = Self {
            plugin_version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            plugin_version_digest: plugin_version_digest(),
            contract_version: MUX_MEDIA_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            provider_digest: provider_digest(),
            scope_digest: scope.digest(),
            environment_digest: scope.environment_digest(),
            asset_digest: scope.asset_digest(),
            playback_digest: scope.playback_digest(),
            track_digest: scope.track_digest(),
            static_rendition_digest: scope.static_rendition_digest(),
            encoding_digest: scope.encoding_digest(),
            project_digest: scope.project.digest(),
            mission_digest: scope.mission.digest(),
            work_product_digest: scope.work_product.digest(),
            consent_digest: scope.consent.digest(),
            secret_reference_digest: scope.secret.reference_digest().clone(),
            registration_digest: Digest::sha256([]),
            state: RegistrationState::Active,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    pub fn validate_against(&self, scope: &MuxScope) -> Result<(), MuxError> {
        let expected = Self::new(scope);
        if self.plugin_version != expected.plugin_version
            || self.plugin_version_digest != expected.plugin_version_digest
            || self.contract_version != expected.contract_version
            || self.contract_digest != expected.contract_digest
            || self.provider_id != expected.provider_id
            || self.provider_revision != expected.provider_revision
            || self.provider_digest != expected.provider_digest
            || self.scope_digest != expected.scope_digest
            || self.environment_digest != expected.environment_digest
            || self.asset_digest != expected.asset_digest
            || self.playback_digest != expected.playback_digest
            || self.track_digest != expected.track_digest
            || self.static_rendition_digest != expected.static_rendition_digest
            || self.encoding_digest != expected.encoding_digest
            || self.project_digest != expected.project_digest
            || self.mission_digest != expected.mission_digest
            || self.work_product_digest != expected.work_product_digest
            || self.consent_digest != expected.consent_digest
            || self.secret_reference_digest != expected.secret_reference_digest
            || self.registration_digest != expected.registration_digest
            || !self.registration_digest.is_sha256()
        {
            return Err(MuxError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn revoke(&mut self, _reason: RevocationReason) -> Result<(), MuxError> {
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    fn compute_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:registration:v1",
            &serde_json::json!([
                &self.plugin_version,
                &self.plugin_version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_revision,
                &self.provider_digest,
                &self.scope_digest,
                &self.environment_digest,
                &self.asset_digest,
                &self.playback_digest,
                &self.track_digest,
                &self.static_rendition_digest,
                &self.encoding_digest,
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
                &self.consent_digest,
                &self.secret_reference_digest,
            ]),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultProposal {
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub asset_digest: Digest,
    pub playback_digest: Option<Digest>,
    pub playback_policy_digest: Option<Digest>,
    pub track_digest: Option<Digest>,
    pub static_rendition_digest: Option<Digest>,
    pub encoding_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub request_digest: Digest,
    pub expected_asset_digest: Option<Digest>,
    pub expected_playback_digest: Option<Digest>,
    pub expected_track_digest: Option<Digest>,
    pub expected_encoding_digest: Option<Digest>,
    pub include_playback_association: bool,
    pub include_track_metadata: bool,
    pub include_delivery_readiness: bool,
    pub proposal_digest: Digest,
}

impl MuxMediaResultProposal {
    pub fn compile(
        scope: &MuxScope,
        registration: &MuxRegistration,
        request: &MuxMediaResultRequest,
    ) -> Result<Self, MuxError> {
        registration.validate_against(scope)?;
        if !registration.is_active() {
            return Err(MuxError::RegistrationRevoked);
        }
        scope.validate_request(request)?;
        let mut proposal = Self {
            plugin_version: MUX_MEDIA_RESULT_PLUGIN_VERSION.to_owned(),
            plugin_version_digest: plugin_version_digest(),
            contract_version: MUX_MEDIA_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: MUX_MEDIA_RESULT_PROVIDER_ID.to_owned(),
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            provider_digest: provider_digest(),
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest.clone(),
            asset_digest: scope.asset_digest(),
            playback_digest: scope.playback_digest(),
            playback_policy_digest: scope.playback().map(PlaybackScope::policy_digest),
            track_digest: scope.track_digest(),
            static_rendition_digest: scope.static_rendition_digest(),
            encoding_digest: scope.encoding_digest(),
            project_digest: scope.project.digest(),
            mission_digest: scope.mission.digest(),
            work_product_digest: scope.work_product.digest(),
            consent_digest: scope.consent.digest(),
            request_digest: request.digest(),
            expected_asset_digest: request.expected_asset_digest.clone(),
            expected_playback_digest: request.expected_playback_digest.clone(),
            expected_track_digest: request.expected_track_digest.clone(),
            expected_encoding_digest: request.expected_encoding_digest.clone(),
            include_playback_association: request.include_playback_association,
            include_track_metadata: request.include_track_metadata,
            include_delivery_readiness: request.include_delivery_readiness,
            proposal_digest: Digest::sha256([]),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    pub fn verify_integrity(&self) -> Result<(), MuxError> {
        if !self.proposal_digest.is_sha256() || self.proposal_digest != self.compute_digest() {
            return Err(MuxError::ProposalTampered);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn compute_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:proposal:v1",
            &serde_json::json!([
                &self.plugin_version,
                &self.plugin_version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_revision,
                &self.provider_digest,
                &self.scope_digest,
                &self.registration_digest,
                &self.asset_digest,
                &self.playback_digest,
                &self.playback_policy_digest,
                &self.track_digest,
                &self.static_rendition_digest,
                &self.encoding_digest,
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
                &self.consent_digest,
                &self.request_digest,
                &self.expected_asset_digest,
                &self.expected_playback_digest,
                &self.expected_track_digest,
                &self.expected_encoding_digest,
                self.include_playback_association,
                self.include_track_metadata,
                self.include_delivery_readiness,
            ]),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxEndpointKind {
    AssetListMetadata,
    AssetMetadata,
    PlaybackAssociation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxReadReceipt {
    pub endpoint: MuxEndpointKind,
    pub method: String,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub attempts: u8,
    pub retry_after_seconds: Option<u32>,
    pub raw_provider_payload_retained: bool,
    pub credential_material_retained: bool,
    pub media_bytes_retained: bool,
    pub viewer_identifiers_retained: bool,
    pub receipt_digest: Digest,
}

impl MuxReadReceipt {
    pub fn new(
        endpoint: MuxEndpointKind,
        request_digest: Digest,
        scope_digest: Digest,
        path_digest: Digest,
        response_status: u16,
        response_size: usize,
        response_digest: Digest,
        attempts: u8,
        retry_after_seconds: Option<u32>,
    ) -> Self {
        let mut receipt = Self {
            endpoint,
            method: "GET".to_owned(),
            path_digest,
            request_digest,
            scope_digest,
            response_status,
            response_size,
            response_digest,
            provider_revision: MUX_MEDIA_RESULT_PROVIDER_REVISION.to_owned(),
            attempts,
            retry_after_seconds,
            raw_provider_payload_retained: false,
            credential_material_retained: false,
            media_bytes_retained: false,
            viewer_identifiers_retained: false,
            receipt_digest: Digest::sha256([]),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    pub fn verify_integrity(&self) -> Result<(), MuxError> {
        if self.method != "GET"
            || self.raw_provider_payload_retained
            || self.credential_material_retained
            || self.media_bytes_retained
            || self.viewer_identifiers_retained
            || self.receipt_digest != self.compute_digest()
        {
            return Err(MuxError::EvidenceTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:receipt:v1",
            &(
                self.endpoint,
                &self.method,
                &self.path_digest,
                &self.request_digest,
                &self.scope_digest,
                self.response_status,
                self.response_size,
                &self.response_digest,
                &self.provider_revision,
                self.attempts,
                self.retry_after_seconds,
                self.raw_provider_payload_retained,
                self.credential_material_retained,
                self.media_bytes_retained,
                self.viewer_identifiers_retained,
            ),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DimensionProjection {
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncodingProjection {
    pub profile: String,
    pub state: MuxAssetState,
    pub tier_label: Option<String>,
    pub quality_label: Option<String>,
    pub revision_digest: Digest,
    pub encoding_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxTrackProjection {
    pub track_digest: Digest,
    pub track_snapshot_digest: Digest,
    pub kind: MuxTrackKind,
    pub status: MuxTrackStatus,
    pub dimensions: Option<DimensionProjection>,
    pub duration_ms: Option<u64>,
    pub frame_rate_milli: Option<u32>,
    pub channels: Option<u16>,
    pub language_label: Option<String>,
    pub text_type_label: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxPlaybackProjection {
    pub playback_digest: Digest,
    pub playback_snapshot_digest: Digest,
    pub policy: MuxPlaybackPolicy,
    pub policy_digest: Digest,
    pub associated_asset_digest: Option<Digest>,
    pub association_state: MuxAssetState,
    pub playback_token_redacted: bool,
    pub signed_url_redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetMetadataProjection {
    pub asset_digest: Digest,
    pub asset_snapshot_digest: Digest,
    pub state: MuxAssetState,
    pub duration_ms: Option<u64>,
    pub created_at_epoch_seconds: Option<i64>,
    pub dimensions: Option<DimensionProjection>,
    pub encoding: EncodingProjection,
    pub tracks: Vec<MuxTrackProjection>,
    pub playback_ids: Vec<MuxPlaybackProjection>,
    pub provider_status_label: String,
    pub raw_provider_payload_retained: bool,
    pub media_bytes_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryReadinessProjection {
    pub delivery_digest: Digest,
    pub state: MuxAssetState,
    pub metadata_ready: bool,
    pub encoding_ready: bool,
    pub track_metadata_ready: bool,
    pub playback_policy_observed: bool,
    pub authorization_proven: bool,
    pub playback_success_proven: bool,
    pub content_correctness_proven: bool,
    pub publication_authority: bool,
    pub readiness_label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxMediaResultEvidence {
    pub plugin_version: String,
    pub plugin_version_digest: Digest,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub static_rendition_digest: Option<Digest>,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub provenance: MuxTransportMode,
    pub asset: AssetMetadataProjection,
    pub playback: Option<MuxPlaybackProjection>,
    pub track: Option<MuxTrackProjection>,
    pub delivery: DeliveryReadinessProjection,
    pub receipts: Vec<MuxReadReceipt>,
    pub native_connected: bool,
    pub external_write_performed: bool,
    pub media_bytes_retained: bool,
    pub viewer_identifiers_retained: bool,
    pub playback_success_proven: bool,
    pub content_correctness_proven: bool,
    pub publication_authority: bool,
    pub evidence_digest: Digest,
}

impl MuxMediaResultEvidence {
    pub fn verify_integrity(&self) -> Result<(), MuxError> {
        if !self.evidence_digest.is_sha256() || self.evidence_digest != self.compute_digest() {
            return Err(MuxError::EvidenceTampered);
        }
        if self.native_connected
            || self.external_write_performed
            || self.media_bytes_retained
            || self.viewer_identifiers_retained
            || self.playback_success_proven
            || self.content_correctness_proven
            || self.publication_authority
            || self.asset.raw_provider_payload_retained
            || self.asset.media_bytes_retained
        {
            return Err(MuxError::EvidenceTampered);
        }
        for receipt in &self.receipts {
            receipt.verify_integrity()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub(crate) fn with_digest(mut self) -> Self {
        self.evidence_digest = self.compute_digest();
        self
    }

    fn compute_digest(&self) -> Digest {
        domain_digest(
            "hartevo:mux-media-result:evidence:v1",
            &serde_json::json!([
                &self.plugin_version,
                &self.plugin_version_digest,
                &self.contract_version,
                &self.contract_digest,
                &self.provider_id,
                &self.provider_revision,
                &self.provider_digest,
                &self.consumer_id,
                &self.scope_digest,
                &self.registration_digest,
                &self.static_rendition_digest,
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
                &self.consent_digest,
                &self.proposal_digest,
                &self.request_digest,
                self.provenance,
                &self.asset,
                &self.playback,
                &self.track,
                &self.delivery,
                &self.receipts,
                self.native_connected,
                self.external_write_performed,
                self.media_bytes_retained,
                self.viewer_identifiers_retained,
                self.playback_success_proven,
                self.content_correctness_proven,
                self.publication_authority,
            ]),
        )
    }
}

pub(crate) fn normalize_asset_state(status: &str, progress: Option<u8>) -> MuxAssetState {
    match status.to_ascii_lowercase().as_str() {
        "preparing" | "processing" => MuxAssetState::Preparing,
        "ready" | "completed" if progress.unwrap_or(100) >= 100 => MuxAssetState::Ready,
        "ready" | "completed" => MuxAssetState::Partial,
        "errored" | "error" | "failed" => MuxAssetState::Errored,
        "archived" | "deleted" => MuxAssetState::Archived,
        "partial" => MuxAssetState::Partial,
        _ => MuxAssetState::ProviderUnknown,
    }
}

pub(crate) fn normalize_track_status(
    status: Option<&str>,
    asset_state: MuxAssetState,
) -> MuxTrackStatus {
    match status.map(str::to_ascii_lowercase).as_deref() {
        Some("ready" | "completed") => MuxTrackStatus::Ready,
        Some("preparing" | "processing") => MuxTrackStatus::Preparing,
        Some("errored" | "error" | "failed") => MuxTrackStatus::Errored,
        Some("archived" | "deleted") => MuxTrackStatus::Archived,
        Some("partial") => MuxTrackStatus::Partial,
        _ => match asset_state {
            MuxAssetState::Ready => MuxTrackStatus::Ready,
            MuxAssetState::Preparing => MuxTrackStatus::Preparing,
            MuxAssetState::Errored => MuxTrackStatus::Errored,
            MuxAssetState::Archived => MuxTrackStatus::Archived,
            MuxAssetState::Partial => MuxTrackStatus::Partial,
            MuxAssetState::AccessLost => MuxTrackStatus::AccessLost,
            MuxAssetState::ProviderUnknown => MuxTrackStatus::ProviderUnknown,
        },
    }
}

pub(crate) fn normalize_track_kind(value: &str) -> MuxTrackKind {
    match value.to_ascii_lowercase().as_str() {
        "video" => MuxTrackKind::Video,
        "audio" => MuxTrackKind::Audio,
        "text" | "subtitle" | "captions" => MuxTrackKind::Text,
        _ => MuxTrackKind::Unknown,
    }
}

pub(crate) fn normalize_policy(value: Option<&str>) -> MuxPlaybackPolicy {
    match value.map(str::to_ascii_lowercase).as_deref() {
        Some("public") => MuxPlaybackPolicy::Public,
        Some("signed") => MuxPlaybackPolicy::Signed,
        _ => MuxPlaybackPolicy::Unknown,
    }
}

/// Public typed fixture payload.  It contains bounded metadata only; JSON
/// fields such as URLs, tokens, bytes, or viewers are never represented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxTrackPayload {
    pub id: MuxTrackId,
    pub kind: String,
    pub status: Option<String>,
    pub max_width: Option<u32>,
    pub max_height: Option<u32>,
    pub max_frame_rate_milli: Option<u32>,
    pub max_channels: Option<u16>,
    pub duration_ms: Option<u64>,
    pub language_code: Option<String>,
    pub text_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxPlaybackPayload {
    pub id: MuxPlaybackId,
    pub policy: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxProgressPayload {
    pub state: Option<String>,
    pub progress: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxAssetPayload {
    pub id: MuxAssetId,
    pub status: String,
    pub tracks: Vec<MuxTrackPayload>,
    pub playback_ids: Vec<MuxPlaybackPayload>,
    pub duration_ms: Option<u64>,
    pub created_at_epoch_seconds: Option<i64>,
    pub max_stored_resolution: Option<String>,
    pub resolution_tier: Option<String>,
    pub encoding_tier: Option<String>,
    pub video_quality: Option<String>,
    pub progress: Option<MuxProgressPayload>,
}

impl MuxAssetPayload {
    pub fn validate(&self) -> Result<(), MuxError> {
        if self.tracks.len() > MUX_MAX_TRACKS {
            return Err(MuxError::TrackLimitExceeded);
        }
        if self.playback_ids.len() > MUX_MAX_PLAYBACK_IDS {
            return Err(MuxError::PlaybackIdLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MuxPlaybackAssociationPayload {
    pub id: MuxPlaybackId,
    pub policy: Option<String>,
    pub object_type: String,
    pub object_id: MuxAssetId,
}

impl MuxAssetPayload {
    pub(crate) fn project(&self, scope: &MuxScope) -> Result<AssetMetadataProjection, MuxError> {
        self.validate()?;
        if self.id != scope.asset.id {
            return Err(MuxError::ScopeMismatch(
                "asset response ID differs from scope",
            ));
        }
        let progress = self.progress.as_ref().and_then(|value| value.progress);
        let state = normalize_asset_state(&self.status, progress);
        let tracks = self
            .tracks
            .iter()
            .map(|track| project_track(track, state))
            .collect::<Result<Vec<_>, _>>()?;
        let dimensions = tracks.iter().find_map(|track| track.dimensions.clone());
        let encoding_state = state;
        let encoding = EncodingProjection {
            profile: scope.encoding.profile.clone(),
            state: encoding_state,
            tier_label: self
                .resolution_tier
                .clone()
                .or_else(|| self.max_stored_resolution.clone()),
            quality_label: self.video_quality.clone(),
            revision_digest: scope.encoding.revision.digest(),
            encoding_digest: domain_digest(
                "hartevo:mux-media-result:encoding-projection:v1",
                &(
                    &scope.encoding,
                    &self.resolution_tier,
                    &self.max_stored_resolution,
                    &self.encoding_tier,
                    &self.video_quality,
                    state,
                ),
            ),
        };
        let playback_ids = self
            .playback_ids
            .iter()
            .map(|playback| project_playback(playback, self.id.digest(), state))
            .collect::<Vec<_>>();
        Ok(AssetMetadataProjection {
            asset_digest: self.id.digest(),
            asset_snapshot_digest: domain_digest(
                "hartevo:mux-media-result:asset-snapshot:v1",
                self,
            ),
            state,
            duration_ms: self.duration_ms,
            created_at_epoch_seconds: self.created_at_epoch_seconds,
            dimensions,
            encoding,
            tracks,
            playback_ids,
            provider_status_label: bounded_status_label(&self.status),
            raw_provider_payload_retained: false,
            media_bytes_retained: false,
        })
    }
}

fn bounded_status_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
        })
        .take(MAX_POLICY_LABEL_BYTES)
        .collect()
}

fn project_track(
    payload: &MuxTrackPayload,
    asset_state: MuxAssetState,
) -> Result<MuxTrackProjection, MuxError> {
    let kind = normalize_track_kind(&payload.kind);
    let dimensions = payload
        .max_width
        .zip(payload.max_height)
        .map(|(width, height)| DimensionProjection { width, height });
    let status = normalize_track_status(payload.status.as_deref(), asset_state);
    Ok(MuxTrackProjection {
        track_digest: payload.id.digest(),
        track_snapshot_digest: domain_digest("hartevo:mux-media-result:track-snapshot:v1", payload),
        kind,
        status,
        dimensions,
        duration_ms: payload.duration_ms,
        frame_rate_milli: payload.max_frame_rate_milli,
        channels: payload.max_channels,
        language_label: payload.language_code.clone(),
        text_type_label: payload.text_type.clone(),
    })
}

fn project_playback(
    payload: &MuxPlaybackPayload,
    asset_digest: Digest,
    asset_state: MuxAssetState,
) -> MuxPlaybackProjection {
    let policy = normalize_policy(payload.policy.as_deref());
    let policy_digest = domain_digest(
        "hartevo:mux-media-result:playback-policy-projection:v1",
        &(policy, payload.id.digest()),
    );
    MuxPlaybackProjection {
        playback_digest: payload.id.digest(),
        playback_snapshot_digest: domain_digest(
            "hartevo:mux-media-result:playback-snapshot:v1",
            &(payload, &asset_digest, asset_state),
        ),
        policy,
        policy_digest,
        associated_asset_digest: Some(asset_digest),
        association_state: asset_state,
        playback_token_redacted: true,
        signed_url_redacted: true,
    }
}

pub(crate) fn project_playback_association(
    payload: &MuxPlaybackAssociationPayload,
    scope: &MuxScope,
    asset_state: MuxAssetState,
) -> Result<MuxPlaybackProjection, MuxError> {
    let Some(expected) = scope.playback() else {
        return Err(MuxError::ScopeMismatch(
            "playback association was not scoped",
        ));
    };
    if payload.id != expected.id {
        return Err(MuxError::PlaybackRevisionDrift);
    }
    if !payload.object_type.eq_ignore_ascii_case("asset") || payload.object_id != scope.asset.id {
        return Err(MuxError::PlaybackNotFound);
    }
    let projection = project_playback(
        &MuxPlaybackPayload {
            id: payload.id.clone(),
            policy: payload.policy.clone(),
        },
        scope.asset.id.digest(),
        asset_state,
    );
    if expected.policy != projection.policy {
        return Err(MuxError::PlaybackPolicyDrift);
    }
    Ok(projection)
}

pub(crate) fn delivery_projection(
    asset: &AssetMetadataProjection,
    playback: Option<&MuxPlaybackProjection>,
    track: Option<&MuxTrackProjection>,
) -> DeliveryReadinessProjection {
    let metadata_ready =
        asset.state == MuxAssetState::Ready || asset.state == MuxAssetState::Partial;
    let encoding_ready = asset.encoding.state == MuxAssetState::Ready;
    let track_metadata_ready = track.map_or(!asset.tracks.is_empty(), |value| {
        matches!(
            value.status,
            MuxTrackStatus::Ready | MuxTrackStatus::Partial
        )
    });
    let playback_policy_observed = playback.is_some_and(|value| {
        value.policy != MuxPlaybackPolicy::Unknown
            && value.association_state != MuxAssetState::AccessLost
    });
    let playback_access_lost =
        playback.is_some_and(|value| value.association_state == MuxAssetState::AccessLost);
    let state = if asset.state == MuxAssetState::AccessLost || playback_access_lost {
        MuxAssetState::AccessLost
    } else if asset.state == MuxAssetState::Errored {
        MuxAssetState::Errored
    } else if !metadata_ready || !encoding_ready || !track_metadata_ready {
        MuxAssetState::Partial
    } else {
        MuxAssetState::Ready
    };
    let readiness_label = match state {
        MuxAssetState::Ready => "metadata_ready_only",
        MuxAssetState::Preparing => "preparing",
        MuxAssetState::Errored => "errored",
        MuxAssetState::Archived => "archived",
        MuxAssetState::Partial => "partial_metadata",
        MuxAssetState::AccessLost => "access_lost",
        MuxAssetState::ProviderUnknown => "provider_unknown",
    }
    .to_owned();
    let delivery_digest = domain_digest(
        "hartevo:mux-media-result:delivery-readiness:v1",
        &(
            &asset.asset_digest,
            &asset.asset_snapshot_digest,
            asset.state,
            metadata_ready,
            encoding_ready,
            track_metadata_ready,
            playback_policy_observed,
            state,
        ),
    );
    DeliveryReadinessProjection {
        delivery_digest,
        state,
        metadata_ready,
        encoding_ready,
        track_metadata_ready,
        playback_policy_observed,
        authorization_proven: false,
        playback_success_proven: false,
        content_correctness_proven: false,
        publication_authority: false,
        readiness_label,
    }
}

pub(crate) fn access_lost_asset(scope: &MuxScope) -> AssetMetadataProjection {
    let encoding = EncodingProjection {
        profile: scope.encoding.profile.clone(),
        state: MuxAssetState::AccessLost,
        tier_label: None,
        quality_label: None,
        revision_digest: scope.encoding.revision.digest(),
        encoding_digest: scope.encoding.digest(),
    };
    AssetMetadataProjection {
        asset_digest: scope.asset.id.digest(),
        asset_snapshot_digest: domain_digest(
            "hartevo:mux-media-result:access-lost-asset:v1",
            &scope.digest(),
        ),
        state: MuxAssetState::AccessLost,
        duration_ms: None,
        created_at_epoch_seconds: None,
        dimensions: None,
        encoding,
        tracks: Vec::new(),
        playback_ids: Vec::new(),
        provider_status_label: "access_lost".to_owned(),
        raw_provider_payload_retained: false,
        media_bytes_retained: false,
    }
}
