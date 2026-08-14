//! Layer-1 Zoom meeting decision-artifact capability.
//!
//! This crate is intentionally standalone. It owns a typed service, provider,
//! and Mission consumer seam, but it does not become a kernel authority. The
//! provider projects bounded metadata from controlled transports; it never
//! accepts OAuth material, reads content bytes, persists download URLs, or
//! adopts a Work Product.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::Write as _,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

/// The versioned contract document owned by this plugin.
pub const CONTRACT_DOCUMENT: &str =
    include_str!("../../../contracts/plugins/zoom-meeting-result/contract.v1.json");
pub const PLUGIN_ID: &str = "hartevo.zoom-meeting-result";
pub const SERVICE_ID: &str = "zoom.meeting-result.service";
pub const PROVIDER_ID: &str = "zoom.meeting-result.provider";
pub const CONSUMER_ID: &str = "mission.zoom-meeting-result.consumer";
pub const DEFAULT_MAX_PAGES: u16 = 16;
pub const DEFAULT_MAX_FILES: u16 = 128;
pub const DEFAULT_PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ZoomMeetingResultError> {
    serde_json::to_vec(value).map_err(|_| ZoomMeetingResultError::Serialization)
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ZoomMeetingResultError> {
    Ok(sha256_hex(&canonical_json(value)?))
}

fn valid_identifier(value: &str, prefix: Option<&str>) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && prefix.is_none_or(|expected| value.starts_with(expected))
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'+' | b'=')
        })
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

macro_rules! identifier_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ZoomMeetingResultError> {
                let value = value.into();
                if valid_identifier(&value, None) {
                    Ok(Self(value))
                } else {
                    Err(ZoomMeetingResultError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier_type!(AccountId);
identifier_type!(UserId);
identifier_type!(HostId);
identifier_type!(MeetingId);
identifier_type!(ProjectId);
identifier_type!(MissionId);
identifier_type!(FileId);

/// A canonical Zoom occurrence UUID. Meeting IDs and occurrence UUIDs are
/// separate values throughout the API so a recurring meeting cannot silently
/// collapse into one logical occurrence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OccurrenceUuid(String);

impl OccurrenceUuid {
    pub fn new(value: impl Into<String>) -> Result<Self, ZoomMeetingResultError> {
        let value = value.into().to_ascii_lowercase();
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                    || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(ZoomMeetingResultError::InvalidOccurrenceUuid)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A content-free fingerprint used for contract, scope, metadata, and
/// proposal identity. It never represents a recording or transcript byte
/// digest in Layer 1.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn from_hex(value: impl Into<String>) -> Result<Self, ZoomMeetingResultError> {
        Self::new(value.into())
    }

    fn new(value: String) -> Result<Self, ZoomMeetingResultError> {
        if valid_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ZoomMeetingResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Fingerprint").field(&self.0).finish()
    }
}

/// The immutable OAuth keyring boundary. There is deliberately no token,
/// refresh token, signed URL, or credential byte field in this type.
pub struct SecretReference {
    reference_id: String,
    scope_digest: String,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field(
                "scope_digest",
                &Fingerprint::new(self.scope_digest.clone()).ok(),
            )
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let reference_id = reference_id.into();
        let scope_digest = scope_digest.into();
        if !valid_identifier(&reference_id, Some("secret-ref-"))
            || !valid_digest(&scope_digest)
            || credential_revision == 0
        {
            return Err(ZoomMeetingResultError::InvalidSecretReference);
        }
        Ok(Self {
            reference_id,
            scope_digest,
            credential_revision,
            revoked: false,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// A kernel-issued consent reference represented only by identity, scope
/// digest, revision, and optional expiry metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReference {
    reference_id: String,
    scope_digest: String,
    consent_revision: u64,
    expires_at_millis: Option<u64>,
}

impl ConsentReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: impl Into<String>,
        consent_revision: u64,
        expires_at_millis: Option<u64>,
    ) -> Result<Self, ZoomMeetingResultError> {
        let reference_id = reference_id.into();
        let scope_digest = scope_digest.into();
        if !valid_identifier(&reference_id, Some("consent-ref-"))
            || !valid_digest(&scope_digest)
            || consent_revision == 0
        {
            return Err(ZoomMeetingResultError::InvalidConsentReference);
        }
        Ok(Self {
            reference_id,
            scope_digest,
            consent_revision,
            expires_at_millis,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn consent_revision(&self) -> u64 {
        self.consent_revision
    }

    pub const fn expires_at_millis(&self) -> Option<u64> {
        self.expires_at_millis
    }

    pub const fn is_expired_at(&self, now_millis: u64) -> bool {
        match self.expires_at_millis {
            Some(expiry) => now_millis >= expiry,
            None => false,
        }
    }
}

/// Exact Zoom and Mission/Project identity fenced by a consent reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultScopeBinding {
    account_id: AccountId,
    user_id: UserId,
    host_id: HostId,
    meeting_id: MeetingId,
    occurrence_uuid: OccurrenceUuid,
    selected_recording_file_ids: BTreeSet<FileId>,
    selected_transcript_file_ids: BTreeSet<FileId>,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
}

impl ZoomMeetingResultScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        user_id: impl Into<String>,
        host_id: impl Into<String>,
        meeting_id: impl Into<String>,
        occurrence_uuid: impl Into<String>,
        selected_recording_file_ids: impl IntoIterator<Item = String>,
        selected_transcript_file_ids: impl IntoIterator<Item = String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        if mission_revision == 0 {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        let binding = Self {
            account_id: AccountId::new(account_id)?,
            user_id: UserId::new(user_id)?,
            host_id: HostId::new(host_id)?,
            meeting_id: MeetingId::new(meeting_id)?,
            occurrence_uuid: OccurrenceUuid::new(occurrence_uuid)?,
            selected_recording_file_ids: selected_recording_file_ids
                .into_iter()
                .map(FileId::new)
                .collect::<Result<_, _>>()?,
            selected_transcript_file_ids: selected_transcript_file_ids
                .into_iter()
                .map(FileId::new)
                .collect::<Result<_, _>>()?,
            project_id: ProjectId::new(project_id)?,
            mission_id: MissionId::new(mission_id)?,
            mission_revision,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), ZoomMeetingResultError> {
        if self.selected_recording_file_ids.is_empty()
            && self.selected_transcript_file_ids.is_empty()
        {
            return Err(ZoomMeetingResultError::NoSelectedFiles);
        }
        if self
            .selected_recording_file_ids
            .is_disjoint(&self.selected_transcript_file_ids)
        {
            Ok(())
        } else {
            Err(ZoomMeetingResultError::DuplicateSelectedFileId)
        }
    }

    pub fn scope_digest(&self) -> Result<String, ZoomMeetingResultError> {
        canonical_digest(self)
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub fn meeting_id(&self) -> &MeetingId {
        &self.meeting_id
    }

    pub fn occurrence_uuid(&self) -> &OccurrenceUuid {
        &self.occurrence_uuid
    }

    pub fn selected_recording_file_ids(&self) -> &BTreeSet<FileId> {
        &self.selected_recording_file_ids
    }

    pub fn selected_transcript_file_ids(&self) -> &BTreeSet<FileId> {
        &self.selected_transcript_file_ids
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn selected_file_ids(&self) -> BTreeSet<FileId> {
        self.selected_recording_file_ids
            .union(&self.selected_transcript_file_ids)
            .cloned()
            .collect()
    }
}

/// The full Mission/Project/consent scope consumed by the capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultScope {
    binding: ZoomMeetingResultScopeBinding,
    consent_reference: ConsentReference,
}

impl ZoomMeetingResultScope {
    pub fn new(
        binding: ZoomMeetingResultScopeBinding,
        consent_reference: ConsentReference,
    ) -> Result<Self, ZoomMeetingResultError> {
        if binding.scope_digest()? != consent_reference.scope_digest() {
            return Err(ZoomMeetingResultError::ConsentScopeMismatch);
        }
        Ok(Self {
            binding,
            consent_reference,
        })
    }

    pub fn binding(&self) -> &ZoomMeetingResultScopeBinding {
        &self.binding
    }

    pub fn consent_reference(&self) -> &ConsentReference {
        &self.consent_reference
    }

    pub fn scope_digest(&self) -> Result<String, ZoomMeetingResultError> {
        canonical_digest(self)
    }

    pub fn project_id(&self) -> &ProjectId {
        self.binding.project_id()
    }

    pub fn mission_id(&self) -> &MissionId {
        self.binding.mission_id()
    }

    pub const fn mission_revision(&self) -> u64 {
        self.binding.mission_revision()
    }

    pub fn occurrence_uuid(&self) -> &OccurrenceUuid {
        self.binding.occurrence_uuid()
    }
}

/// A current Mission snapshot supplied by the consumer. It exists solely to
/// reject stale Mission revisions or consent references before projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionContext {
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    consent_reference: ConsentReference,
}

impl MissionContext {
    pub fn from_scope(scope: &ZoomMeetingResultScope) -> Self {
        Self {
            project_id: scope.project_id().clone(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            consent_reference: scope.consent_reference().clone(),
        }
    }

    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
        consent_reference: ConsentReference,
    ) -> Result<Self, ZoomMeetingResultError> {
        if mission_revision == 0 {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        Ok(Self {
            project_id: ProjectId::new(project_id)?,
            mission_id: MissionId::new(mission_id)?,
            mission_revision,
            consent_reference,
        })
    }

    fn matches(&self, scope: &ZoomMeetingResultScope) -> Result<(), ZoomMeetingResultError> {
        if self.project_id != *scope.project_id() || self.mission_id != *scope.mission_id() {
            return Err(ZoomMeetingResultError::MissionScopeMismatch);
        }
        if self.mission_revision != scope.mission_revision() {
            return Err(ZoomMeetingResultError::StaleMissionRevision);
        }
        if self.consent_reference != *scope.consent_reference() {
            return Err(ZoomMeetingResultError::StaleConsentReference);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ZoomMeetingResultError {
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("occurrence UUID is invalid")]
    InvalidOccurrenceUuid,
    #[error("digest is invalid")]
    InvalidDigest,
    #[error("serialization failed")]
    Serialization,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("scope has no selected recording or transcript file")]
    NoSelectedFiles,
    #[error("a selected file ID is present in both recording and transcript sets")]
    DuplicateSelectedFileId,
    #[error("consent reference is invalid")]
    InvalidConsentReference,
    #[error("consent reference does not bind the exact Zoom/Mission scope")]
    ConsentScopeMismatch,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("secret reference does not bind the exact scope")]
    SecretScopeMismatch,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("registration version is not the requested version")]
    RegistrationVersionMismatch,
    #[error("registration contract digest does not match the versioned contract")]
    RegistrationContractMismatch,
    #[error("registration provider revision is stale")]
    RegistrationProviderRevisionMismatch,
    #[error("registration scope digest does not match the exact scope")]
    RegistrationScopeMismatch,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("Mission/Project scope does not match the registered scope")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("consent reference is stale")]
    StaleConsentReference,
    #[error("consent reference has expired")]
    ExpiredConsent,
    #[error("provider returned a duplicate file ID: {0}")]
    DuplicateFileId(String),
    #[error("selected file was not projected: {0}")]
    SelectedFileMissing(String),
    #[error("selected file type does not match its recording/transcript scope")]
    SelectedFileTypeMismatch,
    #[error("page budget was exceeded")]
    PageBudgetExceeded,
    #[error("provider pagination cursor repeated")]
    PaginationLoop,
    #[error("provider revision drifted during projection")]
    ProviderRevisionDrift,
    #[error("occurrence identity is ambiguous")]
    OccurrenceAmbiguous,
    #[error("metadata projection does not match its proposal")]
    ProjectionMismatch,
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
}

/// Semantic plugin version included in every registration and capability
/// description.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

/// A typed service definition. It is a capability seam, not a catalog card.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultServiceDefinition {
    service_id: String,
    version: PluginVersion,
    contract_digest: Fingerprint,
    operations: Vec<String>,
    oauth_capabilities: Vec<ZoomOAuthCapabilityRequirement>,
}

/// Exact Layer-1 logical read capabilities and the Zoom OAuth scopes that may
/// satisfy each one. No write or content-download capability is requested.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomOAuthCapabilityRequirement {
    capability_id: String,
    allowed_zoom_scopes: Vec<String>,
    read_only: bool,
    content_bytes_requested: bool,
}

impl ZoomOAuthCapabilityRequirement {
    fn new(capability_id: &str, allowed_zoom_scopes: &[&str]) -> Self {
        Self {
            capability_id: capability_id.to_owned(),
            allowed_zoom_scopes: allowed_zoom_scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            read_only: true,
            content_bytes_requested: false,
        }
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn allowed_zoom_scopes(&self) -> &[String] {
        &self.allowed_zoom_scopes
    }

    pub const fn read_only(&self) -> bool {
        self.read_only
    }

    pub const fn content_bytes_requested(&self) -> bool {
        self.content_bytes_requested
    }
}

fn required_oauth_capabilities() -> Vec<ZoomOAuthCapabilityRequirement> {
    vec![
        ZoomOAuthCapabilityRequirement::new(
            "meeting_occurrence_metadata.read",
            &["meeting:read", "meeting:read:admin"],
        ),
        ZoomOAuthCapabilityRequirement::new(
            "cloud_recording_metadata.read",
            &["recording:read", "recording:read:admin"],
        ),
        ZoomOAuthCapabilityRequirement::new(
            "transcript_metadata.read",
            &["recording:read", "recording:read:admin"],
        ),
        ZoomOAuthCapabilityRequirement::new(
            "meeting_summary_metadata.read",
            &["meeting_summary:read", "meeting_summary:read:admin"],
        ),
    ]
}

impl ZoomMeetingResultServiceDefinition {
    fn new(contract_digest: Fingerprint) -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            version: DEFAULT_PLUGIN_VERSION,
            contract_digest,
            operations: vec![
                "describe_capabilities".to_owned(),
                "probe_meeting_occurrence".to_owned(),
                "list_decision_artifacts".to_owned(),
                "compile_adoption_proposal".to_owned(),
                "verify_artifact_projection".to_owned(),
            ],
            oauth_capabilities: required_oauth_capabilities(),
        }
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn contract_digest(&self) -> &Fingerprint {
        &self.contract_digest
    }

    pub fn operations(&self) -> &[String] {
        &self.operations
    }

    pub fn oauth_capabilities(&self) -> &[ZoomOAuthCapabilityRequirement] {
        &self.oauth_capabilities
    }
}

/// Provider metadata exposed alongside the typed provider seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultProviderDefinition {
    provider_id: String,
    provider_revision: u64,
    mode: ProviderMode,
    provenance: ProviderProvenance,
}

impl ZoomMeetingResultProviderDefinition {
    fn new(state: ProviderState) -> Self {
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: state.provider_revision,
            mode: state.mode,
            provenance: state.provenance,
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
}

/// Typed Mission consumer definition. No UI surface or dashboard is part of
/// this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionZoomMeetingResultConsumerDefinition {
    consumer_id: String,
    service_id: String,
    mission_scoped: bool,
    proposal_only: bool,
}

impl MissionZoomMeetingResultConsumerDefinition {
    fn new() -> Self {
        Self {
            consumer_id: CONSUMER_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            mission_scoped: true,
            proposal_only: true,
        }
    }

    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub const fn mission_scoped(&self) -> bool {
        self.mission_scoped
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }
}

/// Complete capability composition returned by `describe_capabilities`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultCapabilityDescription {
    plugin_id: String,
    version: PluginVersion,
    service: ZoomMeetingResultServiceDefinition,
    provider: ZoomMeetingResultProviderDefinition,
    consumer: MissionZoomMeetingResultConsumerDefinition,
    registration: ZoomMeetingResultRegistration,
    metadata_only: bool,
    content_bytes_read: bool,
    content_byte_verification: ContentByteVerification,
}

impl ZoomMeetingResultCapabilityDescription {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn service(&self) -> &ZoomMeetingResultServiceDefinition {
        &self.service
    }

    pub fn provider(&self) -> &ZoomMeetingResultProviderDefinition {
        &self.provider
    }

    pub fn consumer(&self) -> &MissionZoomMeetingResultConsumerDefinition {
        &self.consumer
    }

    pub fn registration(&self) -> &ZoomMeetingResultRegistration {
        &self.registration
    }

    pub const fn metadata_only(&self) -> bool {
        self.metadata_only
    }

    pub const fn content_bytes_read(&self) -> bool {
        self.content_bytes_read
    }

    pub const fn content_byte_verification(&self) -> ContentByteVerification {
        self.content_byte_verification
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentByteVerification {
    NotPerformed,
}

/// Registration input is explicit so callers cannot accidentally mount a
/// provider under a different version, contract, revision, or scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRequest {
    plugin_version: PluginVersion,
    contract_digest: Fingerprint,
    provider_revision: u64,
    scope_digest: Fingerprint,
}

impl RegistrationRequest {
    pub fn new(
        plugin_version: PluginVersion,
        contract_digest: Fingerprint,
        provider_revision: u64,
        scope_digest: Fingerprint,
    ) -> Result<Self, ZoomMeetingResultError> {
        if provider_revision == 0 {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        Ok(Self {
            plugin_version,
            contract_digest,
            provider_revision,
            scope_digest,
        })
    }

    pub fn current(
        provider_revision: u64,
        scope: &ZoomMeetingResultScope,
    ) -> Result<Self, ZoomMeetingResultError> {
        Self::new(
            DEFAULT_PLUGIN_VERSION,
            contract_digest()?,
            provider_revision,
            Fingerprint::new(scope.scope_digest()?)?,
        )
    }

    pub const fn plugin_version(&self) -> PluginVersion {
        self.plugin_version
    }

    pub fn contract_digest(&self) -> &Fingerprint {
        &self.contract_digest
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn scope_digest(&self) -> &Fingerprint {
        &self.scope_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

/// A deterministic, scope-bound registration receipt. It contains no
/// credential material and can be revoked without touching kernel authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoomMeetingResultRegistration {
    plugin_id: String,
    request: RegistrationRequest,
    registration_digest: Fingerprint,
    state: RegistrationState,
}

impl ZoomMeetingResultRegistration {
    fn create(request: RegistrationRequest) -> Result<Self, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct RegistrationBody<'a> {
            plugin_id: &'a str,
            request: &'a RegistrationRequest,
        }
        let registration_digest = Fingerprint::new(canonical_digest(&RegistrationBody {
            plugin_id: PLUGIN_ID,
            request: &request,
        })?)?;
        Ok(Self {
            plugin_id: PLUGIN_ID.to_owned(),
            request,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn request(&self) -> &RegistrationRequest {
        &self.request
    }

    pub fn registration_digest(&self) -> &Fingerprint {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    fn revoke(&mut self) {
        self.state = RegistrationState::Revoked;
    }
}

/// SHA-256 of the exact versioned contract bytes. This is intentionally
/// exposed as metadata, not confused with a content-byte verification digest.
pub fn contract_digest() -> Result<Fingerprint, ZoomMeetingResultError> {
    Fingerprint::new(sha256_hex(CONTRACT_DOCUMENT.as_bytes()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Recording,
    Fake,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    ControlledRecording,
    Fixture,
    BlockedEnvironment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvReason {
    NativeOauthHttpsContentAccessNotImplemented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycle {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderState {
    mode: ProviderMode,
    provenance: ProviderProvenance,
    lifecycle: ProviderLifecycle,
    provider_revision: u64,
}

impl ProviderState {
    pub fn new(
        mode: ProviderMode,
        provenance: ProviderProvenance,
        provider_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        if provider_revision == 0 {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        Ok(Self {
            mode,
            provenance,
            lifecycle: ProviderLifecycle::Active,
            provider_revision,
        })
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub const fn lifecycle(&self) -> ProviderLifecycle {
        self.lifecycle
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn revoke(&mut self) {
        self.lifecycle = ProviderLifecycle::Revoked;
    }

    /// Layer 1 has no native/first-party/connected state by construction.
    pub const fn can_claim_native_or_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeetingOccurrenceStatus {
    Available,
    Processing,
    Partial,
    Deleted,
    RetentionExpired,
    PermissionDenied,
    NotFound,
    RateLimited,
    OccurrenceAmbiguous,
    CursorExpired,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingFileType {
    Audio,
    Video,
    Transcript,
    Summary,
    Chat,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingType {
    AudioOnly,
    SharedScreen,
    SpeakerView,
    GalleryView,
    Transcript,
    Summary,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingFileStatus {
    Available,
    Processing,
    Partial,
    Deleted,
    RetentionExpired,
    PermissionDenied,
    NotFound,
    RateLimited,
    UrlExpired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionState {
    Unknown,
    Active,
    AutoDeleteScheduled,
    Expired,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PageCursor(String);

impl PageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ZoomMeetingResultError> {
        let value = value.into();
        if valid_identifier(&value, None) && value.len() <= 128 {
            Ok(Self(value))
        } else {
            Err(ZoomMeetingResultError::InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageBudget {
    max_pages: u16,
    max_files: u16,
}

impl PageBudget {
    pub const fn new(max_pages: u16, max_files: u16) -> Result<Self, ZoomMeetingResultError> {
        if max_pages == 0 || max_files == 0 {
            Err(ZoomMeetingResultError::InvalidScope)
        } else {
            Ok(Self {
                max_pages,
                max_files,
            })
        }
    }

    pub const fn bounded() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            max_files: DEFAULT_MAX_FILES,
        }
    }

    pub const fn max_pages(self) -> u16 {
        self.max_pages
    }

    pub const fn max_files(self) -> u16 {
        self.max_files
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOutcomeState {
    PermissionDenied,
    NotFound,
    RateLimited,
    Processing,
    Deleted,
    RetentionExpired,
    CursorExpired,
    OccurrenceAmbiguous,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum ProviderError {
    #[error("provider is revoked")]
    ProviderRevoked,
    #[error("provider request is invalid")]
    InvalidRequest,
    #[error("provider access is blocked by the environment")]
    BlockedEnvironment,
    #[error("provider returned HTTP 403 permission denial")]
    Forbidden,
    #[error("provider returned HTTP 404 resource not found")]
    NotFound,
    #[error("provider returned HTTP 429 rate limit")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider permission scope was lost")]
    PermissionScopeLost,
    #[error("provider consent scope was lost")]
    ConsentScopeLost,
    #[error("provider retention has expired")]
    RetentionExpired,
    #[error("provider resource is still processing")]
    Processing,
    #[error("provider resource was deleted")]
    Deleted,
    #[error("provider pagination cursor expired")]
    CursorExpired,
    #[error("provider returned an ambiguous occurrence")]
    OccurrenceAmbiguous,
    #[error("provider page is malformed")]
    MalformedPage,
}

impl ProviderError {
    pub fn from_http_status(status: u16) -> Self {
        match status {
            403 => Self::Forbidden,
            404 => Self::NotFound,
            429 => Self::RateLimited {
                retry_after_seconds: None,
            },
            _ => Self::InvalidRequest,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }

    pub const fn outcome_state(&self) -> Option<ProviderOutcomeState> {
        match self {
            Self::BlockedEnvironment => Some(ProviderOutcomeState::BlockedEnv),
            Self::Forbidden | Self::PermissionScopeLost | Self::ConsentScopeLost => {
                Some(ProviderOutcomeState::PermissionDenied)
            }
            Self::NotFound => Some(ProviderOutcomeState::NotFound),
            Self::RateLimited { .. } => Some(ProviderOutcomeState::RateLimited),
            Self::RetentionExpired => Some(ProviderOutcomeState::RetentionExpired),
            Self::Processing => Some(ProviderOutcomeState::Processing),
            Self::Deleted => Some(ProviderOutcomeState::Deleted),
            Self::CursorExpired => Some(ProviderOutcomeState::CursorExpired),
            Self::OccurrenceAmbiguous => Some(ProviderOutcomeState::OccurrenceAmbiguous),
            Self::ProviderRevoked | Self::InvalidRequest | Self::MalformedPage => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MeetingOccurrenceMetadata {
    meeting_id: MeetingId,
    occurrence_uuid: OccurrenceUuid,
    status: MeetingOccurrenceStatus,
    start_at_millis: Option<u64>,
    end_at_millis: Option<u64>,
    provider_updated_at_millis: u64,
    metadata_fingerprint: Fingerprint,
}

impl MeetingOccurrenceMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        meeting_id: MeetingId,
        occurrence_uuid: OccurrenceUuid,
        status: MeetingOccurrenceStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        provider_updated_at_millis: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let metadata_fingerprint = Self::fingerprint_for(
            &meeting_id,
            &occurrence_uuid,
            status,
            start_at_millis,
            end_at_millis,
            provider_updated_at_millis,
        )?;
        Ok(Self {
            meeting_id,
            occurrence_uuid,
            status,
            start_at_millis,
            end_at_millis,
            provider_updated_at_millis,
            metadata_fingerprint,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_metadata_fingerprint(
        meeting_id: MeetingId,
        occurrence_uuid: OccurrenceUuid,
        status: MeetingOccurrenceStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        provider_updated_at_millis: u64,
        metadata_fingerprint: impl Into<String>,
    ) -> Result<Self, ZoomMeetingResultError> {
        Ok(Self {
            meeting_id,
            occurrence_uuid,
            status,
            start_at_millis,
            end_at_millis,
            provider_updated_at_millis,
            metadata_fingerprint: Fingerprint::new(metadata_fingerprint.into())?,
        })
    }

    fn fingerprint_for(
        meeting_id: &MeetingId,
        occurrence_uuid: &OccurrenceUuid,
        status: MeetingOccurrenceStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        provider_updated_at_millis: u64,
    ) -> Result<Fingerprint, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            meeting_id: &'a MeetingId,
            occurrence_uuid: &'a OccurrenceUuid,
            status: MeetingOccurrenceStatus,
            start_at_millis: Option<u64>,
            end_at_millis: Option<u64>,
            provider_updated_at_millis: u64,
        }
        Fingerprint::new(canonical_digest(&Body {
            meeting_id,
            occurrence_uuid,
            status,
            start_at_millis,
            end_at_millis,
            provider_updated_at_millis,
        })?)
    }

    fn validate_fingerprint(&self) -> Result<(), ProviderError> {
        let expected = Self::fingerprint_for(
            &self.meeting_id,
            &self.occurrence_uuid,
            self.status,
            self.start_at_millis,
            self.end_at_millis,
            self.provider_updated_at_millis,
        )
        .map_err(|_| ProviderError::MalformedPage)?;
        if expected == self.metadata_fingerprint {
            Ok(())
        } else {
            Err(ProviderError::MalformedPage)
        }
    }

    pub fn meeting_id(&self) -> &MeetingId {
        &self.meeting_id
    }

    pub fn occurrence_uuid(&self) -> &OccurrenceUuid {
        &self.occurrence_uuid
    }

    pub const fn status(&self) -> MeetingOccurrenceStatus {
        self.status
    }

    pub const fn start_at_millis(&self) -> Option<u64> {
        self.start_at_millis
    }

    pub const fn end_at_millis(&self) -> Option<u64> {
        self.end_at_millis
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub fn metadata_fingerprint(&self) -> &Fingerprint {
        &self.metadata_fingerprint
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordingFileMetadata {
    file_id: FileId,
    file_type: RecordingFileType,
    recording_type: RecordingType,
    status: RecordingFileStatus,
    start_at_millis: Option<u64>,
    end_at_millis: Option<u64>,
    size_bytes: Option<u64>,
    provider_updated_at_millis: u64,
    retention_state: RetentionState,
    auto_delete_at_millis: Option<u64>,
    download_url_expires_at_millis: Option<u64>,
    metadata_fingerprint: Fingerprint,
}

impl RecordingFileMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_id: FileId,
        file_type: RecordingFileType,
        recording_type: RecordingType,
        status: RecordingFileStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        size_bytes: Option<u64>,
        provider_updated_at_millis: u64,
        retention_state: RetentionState,
        auto_delete_at_millis: Option<u64>,
        download_url_expires_at_millis: Option<u64>,
    ) -> Result<Self, ZoomMeetingResultError> {
        let metadata_fingerprint = Self::fingerprint_for(
            &file_id,
            file_type,
            recording_type,
            status,
            start_at_millis,
            end_at_millis,
            size_bytes,
            provider_updated_at_millis,
            retention_state,
            auto_delete_at_millis,
            download_url_expires_at_millis,
        )?;
        Ok(Self {
            file_id,
            file_type,
            recording_type,
            status,
            start_at_millis,
            end_at_millis,
            size_bytes,
            provider_updated_at_millis,
            retention_state,
            auto_delete_at_millis,
            download_url_expires_at_millis,
            metadata_fingerprint,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_metadata_fingerprint(
        file_id: FileId,
        file_type: RecordingFileType,
        recording_type: RecordingType,
        status: RecordingFileStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        size_bytes: Option<u64>,
        provider_updated_at_millis: u64,
        retention_state: RetentionState,
        auto_delete_at_millis: Option<u64>,
        download_url_expires_at_millis: Option<u64>,
        metadata_fingerprint: impl Into<String>,
    ) -> Result<Self, ZoomMeetingResultError> {
        Ok(Self {
            file_id,
            file_type,
            recording_type,
            status,
            start_at_millis,
            end_at_millis,
            size_bytes,
            provider_updated_at_millis,
            retention_state,
            auto_delete_at_millis,
            download_url_expires_at_millis,
            metadata_fingerprint: Fingerprint::new(metadata_fingerprint.into())?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn fingerprint_for(
        file_id: &FileId,
        file_type: RecordingFileType,
        recording_type: RecordingType,
        status: RecordingFileStatus,
        start_at_millis: Option<u64>,
        end_at_millis: Option<u64>,
        size_bytes: Option<u64>,
        provider_updated_at_millis: u64,
        retention_state: RetentionState,
        auto_delete_at_millis: Option<u64>,
        download_url_expires_at_millis: Option<u64>,
    ) -> Result<Fingerprint, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            file_id: &'a FileId,
            file_type: RecordingFileType,
            recording_type: RecordingType,
            status: RecordingFileStatus,
            start_at_millis: Option<u64>,
            end_at_millis: Option<u64>,
            size_bytes: Option<u64>,
            provider_updated_at_millis: u64,
            retention_state: RetentionState,
            auto_delete_at_millis: Option<u64>,
            download_url_expires_at_millis: Option<u64>,
        }
        Fingerprint::new(canonical_digest(&Body {
            file_id,
            file_type,
            recording_type,
            status,
            start_at_millis,
            end_at_millis,
            size_bytes,
            provider_updated_at_millis,
            retention_state,
            auto_delete_at_millis,
            download_url_expires_at_millis,
        })?)
    }

    fn validate_fingerprint(&self) -> Result<(), ProviderError> {
        let expected = Self::fingerprint_for(
            &self.file_id,
            self.file_type,
            self.recording_type,
            self.status,
            self.start_at_millis,
            self.end_at_millis,
            self.size_bytes,
            self.provider_updated_at_millis,
            self.retention_state,
            self.auto_delete_at_millis,
            self.download_url_expires_at_millis,
        )
        .map_err(|_| ProviderError::MalformedPage)?;
        if expected == self.metadata_fingerprint {
            Ok(())
        } else {
            Err(ProviderError::MalformedPage)
        }
    }

    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    pub const fn file_type(&self) -> RecordingFileType {
        self.file_type
    }

    pub const fn recording_type(&self) -> RecordingType {
        self.recording_type
    }

    pub const fn status(&self) -> RecordingFileStatus {
        self.status
    }

    pub const fn start_at_millis(&self) -> Option<u64> {
        self.start_at_millis
    }

    pub const fn end_at_millis(&self) -> Option<u64> {
        self.end_at_millis
    }

    pub const fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub const fn retention_state(&self) -> RetentionState {
        self.retention_state
    }

    pub const fn auto_delete_at_millis(&self) -> Option<u64> {
        self.auto_delete_at_millis
    }

    pub const fn download_url_expires_at_millis(&self) -> Option<u64> {
        self.download_url_expires_at_millis
    }

    pub fn metadata_fingerprint(&self) -> &Fingerprint {
        &self.metadata_fingerprint
    }
}

/// Transcript metadata intentionally has no transcript text or byte field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranscriptMetadata {
    file_id: FileId,
    status: RecordingFileStatus,
    language: Option<String>,
    provider_updated_at_millis: u64,
    metadata_fingerprint: Fingerprint,
}

impl TranscriptMetadata {
    pub fn new(
        file_id: FileId,
        status: RecordingFileStatus,
        language: Option<String>,
        provider_updated_at_millis: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let metadata_fingerprint = Self::fingerprint_for(
            &file_id,
            status,
            language.as_deref(),
            provider_updated_at_millis,
        )?;
        Ok(Self {
            file_id,
            status,
            language,
            provider_updated_at_millis,
            metadata_fingerprint,
        })
    }

    fn fingerprint_for(
        file_id: &FileId,
        status: RecordingFileStatus,
        language: Option<&str>,
        provider_updated_at_millis: u64,
    ) -> Result<Fingerprint, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            file_id: &'a FileId,
            status: RecordingFileStatus,
            language: Option<&'a str>,
            provider_updated_at_millis: u64,
        }
        Fingerprint::new(canonical_digest(&Body {
            file_id,
            status,
            language,
            provider_updated_at_millis,
        })?)
    }

    fn validate_fingerprint(&self) -> Result<(), ProviderError> {
        let expected = Self::fingerprint_for(
            &self.file_id,
            self.status,
            self.language.as_deref(),
            self.provider_updated_at_millis,
        )
        .map_err(|_| ProviderError::MalformedPage)?;
        if expected == self.metadata_fingerprint {
            Ok(())
        } else {
            Err(ProviderError::MalformedPage)
        }
    }

    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    pub const fn status(&self) -> RecordingFileStatus {
        self.status
    }

    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub fn metadata_fingerprint(&self) -> &Fingerprint {
        &self.metadata_fingerprint
    }
}

/// Summary metadata is likewise content-free.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SummaryMetadata {
    file_id: Option<FileId>,
    status: RecordingFileStatus,
    provider_updated_at_millis: u64,
    metadata_fingerprint: Fingerprint,
}

impl SummaryMetadata {
    pub fn new(
        file_id: Option<FileId>,
        status: RecordingFileStatus,
        provider_updated_at_millis: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let metadata_fingerprint =
            Self::fingerprint_for(file_id.as_ref(), status, provider_updated_at_millis)?;
        Ok(Self {
            file_id,
            status,
            provider_updated_at_millis,
            metadata_fingerprint,
        })
    }

    fn fingerprint_for(
        file_id: Option<&FileId>,
        status: RecordingFileStatus,
        provider_updated_at_millis: u64,
    ) -> Result<Fingerprint, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            file_id: Option<&'a FileId>,
            status: RecordingFileStatus,
            provider_updated_at_millis: u64,
        }
        Fingerprint::new(canonical_digest(&Body {
            file_id,
            status,
            provider_updated_at_millis,
        })?)
    }

    fn validate_fingerprint(&self) -> Result<(), ProviderError> {
        let expected = Self::fingerprint_for(
            self.file_id.as_ref(),
            self.status,
            self.provider_updated_at_millis,
        )
        .map_err(|_| ProviderError::MalformedPage)?;
        if expected == self.metadata_fingerprint {
            Ok(())
        } else {
            Err(ProviderError::MalformedPage)
        }
    }

    pub fn file_id(&self) -> Option<&FileId> {
        self.file_id.as_ref()
    }

    pub const fn status(&self) -> RecordingFileStatus {
        self.status
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub fn metadata_fingerprint(&self) -> &Fingerprint {
        &self.metadata_fingerprint
    }
}

/// One bounded provider response. A response carries only metadata and an
/// opaque pagination cursor; it cannot carry a download URL or content body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderPage {
    occurrence: MeetingOccurrenceMetadata,
    files: Vec<RecordingFileMetadata>,
    transcript: Option<TranscriptMetadata>,
    summary: Option<SummaryMetadata>,
    next_cursor: Option<PageCursor>,
    provider_revision: u64,
}

impl ProviderPage {
    pub fn new(
        occurrence: MeetingOccurrenceMetadata,
        files: Vec<RecordingFileMetadata>,
        transcript: Option<TranscriptMetadata>,
        summary: Option<SummaryMetadata>,
        next_cursor: Option<PageCursor>,
        provider_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let page = Self {
            occurrence,
            files,
            transcript,
            summary,
            next_cursor,
            provider_revision,
        };
        page.validate().map_err(ZoomMeetingResultError::Provider)?;
        Ok(page)
    }

    fn validate(&self) -> Result<(), ProviderError> {
        if self.provider_revision == 0 {
            return Err(ProviderError::MalformedPage);
        }
        self.occurrence.validate_fingerprint()?;
        if self
            .files
            .iter()
            .try_fold(BTreeSet::new(), |mut ids, file| {
                file.validate_fingerprint()?;
                if ids.insert(file.file_id.clone()) {
                    Ok(ids)
                } else {
                    Err(ProviderError::MalformedPage)
                }
            })
            .is_err()
        {
            return Err(ProviderError::MalformedPage);
        }
        if let Some(transcript) = &self.transcript {
            transcript.validate_fingerprint()?;
        }
        if let Some(summary) = &self.summary {
            summary.validate_fingerprint()?;
        }
        Ok(())
    }

    pub fn occurrence(&self) -> &MeetingOccurrenceMetadata {
        &self.occurrence
    }

    pub fn files(&self) -> &[RecordingFileMetadata] {
        &self.files
    }

    pub fn transcript(&self) -> Option<&TranscriptMetadata> {
        self.transcript.as_ref()
    }

    pub fn summary(&self) -> Option<&SummaryMetadata> {
        self.summary.as_ref()
    }

    pub fn next_cursor(&self) -> Option<&PageCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
}

#[derive(Clone, Debug)]
pub struct ProviderRequest<'a> {
    scope: &'a ZoomMeetingResultScope,
    secret_reference: &'a SecretReference,
    cursor: Option<&'a PageCursor>,
    page_size: u16,
}

impl<'a> ProviderRequest<'a> {
    fn new(
        scope: &'a ZoomMeetingResultScope,
        secret_reference: &'a SecretReference,
        cursor: Option<&'a PageCursor>,
        page_size: u16,
    ) -> Result<Self, ZoomMeetingResultError> {
        if page_size == 0 {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        Ok(Self {
            scope,
            secret_reference,
            cursor,
            page_size,
        })
    }

    pub fn scope(&self) -> &ZoomMeetingResultScope {
        self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.secret_reference
    }

    pub fn cursor(&self) -> Option<&PageCursor> {
        self.cursor
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }
}

/// The typed provider port consumed by the service. Implementations receive
/// only an opaque `SecretReference` and metadata requests.
pub trait ZoomMeetingResultProviderPort: fmt::Debug {
    fn provider_revision(&self) -> u64;
    fn state(&self) -> ProviderState;
    fn fetch_page(&self, request: ProviderRequest<'_>) -> Result<ProviderPage, ProviderError>;
    fn revoke(&mut self);
}

/// A deterministic controlled transport implementing recording, fake, and
/// BLOCKED_ENV provider modes. It has no native HTTP/OAuth path by design.
#[derive(Clone, Debug)]
pub struct ZoomMeetingResultProvider {
    state: ProviderState,
    pages: Vec<ProviderPage>,
    blocked_reason: Option<BlockedEnvReason>,
}

impl ZoomMeetingResultProvider {
    pub fn recording(
        pages: Vec<ProviderPage>,
        provider_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        Self::new(ProviderMode::Recording, provider_revision, pages, None)
    }

    pub fn fake(
        pages: Vec<ProviderPage>,
        provider_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        Self::new(ProviderMode::Fake, provider_revision, pages, None)
    }

    pub fn blocked_env(
        reason: impl Into<String>,
        provider_revision: u64,
    ) -> Result<Self, ZoomMeetingResultError> {
        let reason = reason.into();
        if reason.is_empty() || reason.len() > 256 || reason.contains(['\n', '\r']) {
            return Err(ZoomMeetingResultError::InvalidIdentifier);
        }
        Self::new(
            ProviderMode::BlockedEnv,
            provider_revision,
            Vec::new(),
            Some(BlockedEnvReason::NativeOauthHttpsContentAccessNotImplemented),
        )
    }

    fn new(
        mode: ProviderMode,
        provider_revision: u64,
        pages: Vec<ProviderPage>,
        blocked_reason: Option<BlockedEnvReason>,
    ) -> Result<Self, ZoomMeetingResultError> {
        let provenance = match mode {
            ProviderMode::Recording => ProviderProvenance::ControlledRecording,
            ProviderMode::Fake => ProviderProvenance::Fixture,
            ProviderMode::BlockedEnv => ProviderProvenance::BlockedEnvironment,
        };
        if mode != ProviderMode::BlockedEnv && pages.is_empty() {
            return Err(ZoomMeetingResultError::InvalidScope);
        }
        for page in &pages {
            page.validate().map_err(ZoomMeetingResultError::Provider)?;
        }
        Ok(Self {
            state: ProviderState::new(mode, provenance, provider_revision)?,
            pages,
            blocked_reason,
        })
    }

    pub fn mode(&self) -> ProviderMode {
        self.state.mode
    }

    pub fn state(&self) -> ProviderState {
        self.state
    }

    pub const fn provider_revision(&self) -> u64 {
        self.state.provider_revision
    }

    pub fn revoke(&mut self) {
        self.state.revoke();
    }

    pub const fn blocked_reason(&self) -> Option<BlockedEnvReason> {
        self.blocked_reason
    }
}

impl ZoomMeetingResultProviderPort for ZoomMeetingResultProvider {
    fn provider_revision(&self) -> u64 {
        self.state.provider_revision
    }

    fn state(&self) -> ProviderState {
        self.state
    }

    fn fetch_page(&self, request: ProviderRequest<'_>) -> Result<ProviderPage, ProviderError> {
        if self.state.lifecycle == ProviderLifecycle::Revoked {
            return Err(ProviderError::ProviderRevoked);
        }
        if request.secret_reference.is_revoked() {
            return Err(ProviderError::PermissionScopeLost);
        }
        let scope_digest = request
            .scope
            .scope_digest()
            .map_err(|_| ProviderError::InvalidRequest)?;
        if request.secret_reference.scope_digest() != scope_digest {
            return Err(ProviderError::PermissionScopeLost);
        }
        if self.state.mode == ProviderMode::BlockedEnv {
            return Err(ProviderError::BlockedEnvironment);
        }
        let page_index = request.cursor.map_or(Ok(0), |cursor| {
            cursor
                .as_str()
                .strip_prefix("page-")
                .ok_or(ProviderError::CursorExpired)
                .and_then(|index| {
                    index
                        .parse::<usize>()
                        .map_err(|_| ProviderError::CursorExpired)
                })
        })?;
        self.pages
            .get(page_index)
            .cloned()
            .ok_or(ProviderError::CursorExpired)
    }

    fn revoke(&mut self) {
        Self::revoke(self);
    }
}

pub type MeetingOccurrence = MeetingOccurrenceMetadata;
pub type RecordingFileProjection = RecordingFileMetadata;
pub type TranscriptProjection = TranscriptMetadata;
pub type SummaryProjection = SummaryMetadata;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionReceipt {
    file_id: FileId,
    retention_state: RetentionState,
    auto_delete_at_millis: Option<u64>,
    provider_updated_at_millis: u64,
    metadata_fingerprint: Fingerprint,
}

impl RetentionReceipt {
    fn from_file(file: &RecordingFileMetadata) -> Self {
        Self {
            file_id: file.file_id.clone(),
            retention_state: file.retention_state,
            auto_delete_at_millis: file.auto_delete_at_millis,
            provider_updated_at_millis: file.provider_updated_at_millis,
            metadata_fingerprint: file.metadata_fingerprint.clone(),
        }
    }

    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    pub const fn retention_state(&self) -> RetentionState {
        self.retention_state
    }

    pub const fn auto_delete_at_millis(&self) -> Option<u64> {
        self.auto_delete_at_millis
    }

    pub const fn provider_updated_at_millis(&self) -> u64 {
        self.provider_updated_at_millis
    }

    pub fn metadata_fingerprint(&self) -> &Fingerprint {
        &self.metadata_fingerprint
    }
}

/// Bounded, exact-scope projection returned by the service. Its digest is a
/// digest of this metadata projection, never a digest of recording or
/// transcript bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionArtifactListing {
    scope: ZoomMeetingResultScope,
    occurrence: MeetingOccurrenceMetadata,
    recording_files: Vec<RecordingFileProjection>,
    transcript: Option<TranscriptProjection>,
    summary: Option<SummaryProjection>,
    retention_receipts: Vec<RetentionReceipt>,
    provider_revision: u64,
    provider_mode: ProviderMode,
    provider_provenance: ProviderProvenance,
    pages_examined: u16,
    projection_digest: Fingerprint,
}

impl DecisionArtifactListing {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: ZoomMeetingResultScope,
        occurrence: MeetingOccurrenceMetadata,
        recording_files: Vec<RecordingFileProjection>,
        transcript: Option<TranscriptProjection>,
        summary: Option<SummaryProjection>,
        provider_revision: u64,
        provider_state: ProviderState,
        pages_examined: u16,
    ) -> Result<Self, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            scope: &'a ZoomMeetingResultScope,
            occurrence: &'a MeetingOccurrenceMetadata,
            recording_files: &'a [RecordingFileProjection],
            transcript: &'a Option<TranscriptProjection>,
            summary: &'a Option<SummaryProjection>,
            retention_receipts: &'a [RetentionReceipt],
            provider_revision: u64,
            provider_mode: ProviderMode,
            provider_provenance: ProviderProvenance,
            pages_examined: u16,
        }
        let retention_receipts = recording_files
            .iter()
            .map(RetentionReceipt::from_file)
            .collect::<Vec<_>>();
        let projection_digest = Fingerprint::new(canonical_digest(&Body {
            scope: &scope,
            occurrence: &occurrence,
            recording_files: &recording_files,
            transcript: &transcript,
            summary: &summary,
            retention_receipts: &retention_receipts,
            provider_revision,
            provider_mode: provider_state.mode,
            provider_provenance: provider_state.provenance,
            pages_examined,
        })?)?;
        Ok(Self {
            scope,
            occurrence,
            recording_files,
            transcript,
            summary,
            retention_receipts,
            provider_revision,
            provider_mode: provider_state.mode,
            provider_provenance: provider_state.provenance,
            pages_examined,
            projection_digest,
        })
    }

    pub fn scope(&self) -> &ZoomMeetingResultScope {
        &self.scope
    }

    pub fn occurrence(&self) -> &MeetingOccurrenceMetadata {
        &self.occurrence
    }

    pub fn recording_files(&self) -> &[RecordingFileProjection] {
        &self.recording_files
    }

    pub fn transcript(&self) -> Option<&TranscriptProjection> {
        self.transcript.as_ref()
    }

    pub fn summary(&self) -> Option<&SummaryProjection> {
        self.summary.as_ref()
    }

    pub fn retention_receipts(&self) -> &[RetentionReceipt] {
        &self.retention_receipts
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub const fn provider_mode(&self) -> ProviderMode {
        self.provider_mode
    }

    pub const fn provider_provenance(&self) -> ProviderProvenance {
        self.provider_provenance
    }

    pub const fn pages_examined(&self) -> u16 {
        self.pages_examined
    }

    pub fn projection_digest(&self) -> &Fingerprint {
        &self.projection_digest
    }
}

/// A canonical proposal. It is deliberately not an adoption command and has
/// no external effect handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionArtifactProposal {
    proposal_schema: String,
    project_id: ProjectId,
    mission_id: MissionId,
    mission_revision: u64,
    consent_reference: ConsentReference,
    account_id: AccountId,
    user_id: UserId,
    host_id: HostId,
    meeting_id: MeetingId,
    occurrence_uuid: OccurrenceUuid,
    selected_recording_file_ids: BTreeSet<FileId>,
    selected_transcript_file_ids: BTreeSet<FileId>,
    provider_revision: u64,
    provider_mode: ProviderMode,
    provider_provenance: ProviderProvenance,
    projection_digest: Fingerprint,
    evidence_kind: EvidenceKind,
    content_byte_verification: ContentByteVerification,
    non_mutating: bool,
    work_product_adopted: bool,
    proposal_digest: Fingerprint,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MetadataFingerprintOnly,
}

impl DecisionArtifactProposal {
    fn from_listing(listing: &DecisionArtifactListing) -> Result<Self, ZoomMeetingResultError> {
        #[derive(Serialize)]
        struct Body<'a> {
            proposal_schema: &'a str,
            project_id: &'a ProjectId,
            mission_id: &'a MissionId,
            mission_revision: u64,
            consent_reference: &'a ConsentReference,
            account_id: &'a AccountId,
            user_id: &'a UserId,
            host_id: &'a HostId,
            meeting_id: &'a MeetingId,
            occurrence_uuid: &'a OccurrenceUuid,
            selected_recording_file_ids: &'a BTreeSet<FileId>,
            selected_transcript_file_ids: &'a BTreeSet<FileId>,
            provider_revision: u64,
            provider_mode: ProviderMode,
            provider_provenance: ProviderProvenance,
            projection_digest: &'a Fingerprint,
            evidence_kind: EvidenceKind,
            content_byte_verification: ContentByteVerification,
            non_mutating: bool,
            work_product_adopted: bool,
        }
        let binding = listing.scope.binding();
        let proposal_schema = "hartevo.zoom-meeting-result/decision-artifact-proposal/v1";
        let body = Body {
            proposal_schema,
            project_id: binding.project_id(),
            mission_id: binding.mission_id(),
            mission_revision: binding.mission_revision(),
            consent_reference: listing.scope.consent_reference(),
            account_id: binding.account_id(),
            user_id: binding.user_id(),
            host_id: binding.host_id(),
            meeting_id: binding.meeting_id(),
            occurrence_uuid: binding.occurrence_uuid(),
            selected_recording_file_ids: binding.selected_recording_file_ids(),
            selected_transcript_file_ids: binding.selected_transcript_file_ids(),
            provider_revision: listing.provider_revision,
            provider_mode: listing.provider_mode,
            provider_provenance: listing.provider_provenance,
            projection_digest: &listing.projection_digest,
            evidence_kind: EvidenceKind::MetadataFingerprintOnly,
            content_byte_verification: ContentByteVerification::NotPerformed,
            non_mutating: true,
            work_product_adopted: false,
        };
        let proposal_digest = Fingerprint::new(canonical_digest(&body)?)?;
        Ok(Self {
            proposal_schema: proposal_schema.to_owned(),
            project_id: binding.project_id().clone(),
            mission_id: binding.mission_id().clone(),
            mission_revision: binding.mission_revision(),
            consent_reference: listing.scope.consent_reference().clone(),
            account_id: binding.account_id().clone(),
            user_id: binding.user_id().clone(),
            host_id: binding.host_id().clone(),
            meeting_id: binding.meeting_id().clone(),
            occurrence_uuid: binding.occurrence_uuid().clone(),
            selected_recording_file_ids: binding.selected_recording_file_ids().clone(),
            selected_transcript_file_ids: binding.selected_transcript_file_ids().clone(),
            provider_revision: listing.provider_revision,
            provider_mode: listing.provider_mode,
            provider_provenance: listing.provider_provenance,
            projection_digest: listing.projection_digest.clone(),
            evidence_kind: EvidenceKind::MetadataFingerprintOnly,
            content_byte_verification: ContentByteVerification::NotPerformed,
            non_mutating: true,
            work_product_adopted: false,
            proposal_digest,
        })
    }

    pub fn proposal_schema(&self) -> &str {
        &self.proposal_schema
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn consent_reference(&self) -> &ConsentReference {
        &self.consent_reference
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn host_id(&self) -> &HostId {
        &self.host_id
    }

    pub fn meeting_id(&self) -> &MeetingId {
        &self.meeting_id
    }

    pub fn occurrence_uuid(&self) -> &OccurrenceUuid {
        &self.occurrence_uuid
    }

    pub fn selected_recording_file_ids(&self) -> &BTreeSet<FileId> {
        &self.selected_recording_file_ids
    }

    pub fn selected_transcript_file_ids(&self) -> &BTreeSet<FileId> {
        &self.selected_transcript_file_ids
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub const fn provider_mode(&self) -> ProviderMode {
        self.provider_mode
    }

    pub const fn provider_provenance(&self) -> ProviderProvenance {
        self.provider_provenance
    }

    pub fn projection_digest(&self) -> &Fingerprint {
        &self.projection_digest
    }

    pub const fn evidence_kind(&self) -> EvidenceKind {
        self.evidence_kind
    }

    pub const fn content_byte_verification(&self) -> ContentByteVerification {
        self.content_byte_verification
    }

    pub const fn non_mutating(&self) -> bool {
        self.non_mutating
    }

    pub const fn work_product_adopted(&self) -> bool {
        self.work_product_adopted
    }

    pub fn proposal_digest(&self) -> &Fingerprint {
        &self.proposal_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactVerificationStatus {
    MetadataFingerprintBound,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactVerification {
    status: ArtifactVerificationStatus,
    projection_digest: Fingerprint,
    proposal_digest: Fingerprint,
    metadata_only: bool,
    content_bytes_read: bool,
    content_byte_verification: ContentByteVerification,
}

impl ArtifactVerification {
    pub fn status(&self) -> ArtifactVerificationStatus {
        self.status
    }

    pub fn projection_digest(&self) -> &Fingerprint {
        &self.projection_digest
    }

    pub fn proposal_digest(&self) -> &Fingerprint {
        &self.proposal_digest
    }

    pub const fn metadata_only(&self) -> bool {
        self.metadata_only
    }

    pub const fn content_bytes_read(&self) -> bool {
        self.content_bytes_read
    }

    pub const fn content_byte_verification(&self) -> ContentByteVerification {
        self.content_byte_verification
    }
}

/// The typed service consumed by a Mission. It owns one exact scope and one
/// opaque secret reference for the lifetime of a registration.
#[derive(Debug)]
pub struct ZoomMeetingResultService<P: ZoomMeetingResultProviderPort> {
    provider: P,
    scope: ZoomMeetingResultScope,
    secret_reference: SecretReference,
    registration: ZoomMeetingResultRegistration,
}

impl<P: ZoomMeetingResultProviderPort> ZoomMeetingResultService<P> {
    pub fn new(
        provider: P,
        scope: ZoomMeetingResultScope,
        secret_reference: SecretReference,
    ) -> Result<Self, ZoomMeetingResultError> {
        let request = RegistrationRequest::current(provider.provider_revision(), &scope)?;
        Self::register(provider, scope, secret_reference, request)
    }

    pub fn register(
        provider: P,
        scope: ZoomMeetingResultScope,
        secret_reference: SecretReference,
        request: RegistrationRequest,
    ) -> Result<Self, ZoomMeetingResultError> {
        if request.plugin_version != DEFAULT_PLUGIN_VERSION {
            return Err(ZoomMeetingResultError::RegistrationVersionMismatch);
        }
        if request.contract_digest != contract_digest()? {
            return Err(ZoomMeetingResultError::RegistrationContractMismatch);
        }
        if request.provider_revision != provider.provider_revision() {
            return Err(ZoomMeetingResultError::RegistrationProviderRevisionMismatch);
        }
        let scope_digest = Fingerprint::new(scope.scope_digest()?)?;
        if request.scope_digest != scope_digest {
            return Err(ZoomMeetingResultError::RegistrationScopeMismatch);
        }
        if secret_reference.scope_digest() != scope_digest.as_str() {
            return Err(ZoomMeetingResultError::SecretScopeMismatch);
        }
        if secret_reference.is_revoked() {
            return Err(ZoomMeetingResultError::SecretRevoked);
        }
        if provider.state().lifecycle == ProviderLifecycle::Revoked {
            return Err(ZoomMeetingResultError::Provider(
                ProviderError::ProviderRevoked,
            ));
        }
        let registration = ZoomMeetingResultRegistration::create(request)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
        })
    }

    fn ensure_active(&self) -> Result<(), ZoomMeetingResultError> {
        if self.registration.state == RegistrationState::Revoked {
            return Err(ZoomMeetingResultError::RegistrationRevoked);
        }
        if self.secret_reference.is_revoked() {
            return Err(ZoomMeetingResultError::SecretRevoked);
        }
        if self.provider.state().lifecycle == ProviderLifecycle::Revoked {
            return Err(ZoomMeetingResultError::Provider(
                ProviderError::ProviderRevoked,
            ));
        }
        Ok(())
    }

    pub fn scope(&self) -> &ZoomMeetingResultScope {
        &self.scope
    }

    pub fn registration(&self) -> &ZoomMeetingResultRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider_state(&self) -> ProviderState {
        self.provider.state()
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<ZoomMeetingResultCapabilityDescription, ZoomMeetingResultError> {
        self.ensure_active()?;
        let digest = contract_digest()?;
        Ok(ZoomMeetingResultCapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            version: DEFAULT_PLUGIN_VERSION,
            service: ZoomMeetingResultServiceDefinition::new(digest),
            provider: ZoomMeetingResultProviderDefinition::new(self.provider.state()),
            consumer: MissionZoomMeetingResultConsumerDefinition::new(),
            registration: self.registration.clone(),
            metadata_only: true,
            content_bytes_read: false,
            content_byte_verification: ContentByteVerification::NotPerformed,
        })
    }

    pub fn probe_meeting_occurrence(&self) -> Result<MeetingOccurrence, ZoomMeetingResultError> {
        self.ensure_active()?;
        let request = ProviderRequest::new(&self.scope, &self.secret_reference, None, 1)?;
        let page = self.provider.fetch_page(request)?;
        self.validate_page_identity(&page)?;
        if page.occurrence.status == MeetingOccurrenceStatus::OccurrenceAmbiguous {
            return Err(ZoomMeetingResultError::OccurrenceAmbiguous);
        }
        if page.provider_revision != self.provider.provider_revision() {
            return Err(ZoomMeetingResultError::ProviderRevisionDrift);
        }
        Ok(page.occurrence)
    }

    pub fn list_decision_artifacts(
        &self,
        budget: PageBudget,
    ) -> Result<DecisionArtifactListing, ZoomMeetingResultError> {
        self.ensure_active()?;
        let provider_state = self.provider.state();
        let provider_revision = self.provider.provider_revision();
        let mut cursor: Option<PageCursor> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_page_digests = BTreeSet::new();
        let mut occurrence: Option<MeetingOccurrenceMetadata> = None;
        let mut files = BTreeMap::new();
        let mut transcript: Option<TranscriptMetadata> = None;
        let mut summary: Option<SummaryMetadata> = None;
        let mut pages_examined = 0_u16;

        loop {
            if pages_examined >= budget.max_pages {
                return Err(ZoomMeetingResultError::PageBudgetExceeded);
            }
            if let Some(page_cursor) = &cursor
                && !seen_cursors.insert(page_cursor.as_str().to_owned())
            {
                return Err(ZoomMeetingResultError::PaginationLoop);
            }
            let request = ProviderRequest::new(
                &self.scope,
                &self.secret_reference,
                cursor.as_ref(),
                budget.max_files,
            )?;
            let page = self.provider.fetch_page(request)?;
            pages_examined = pages_examined.saturating_add(1);
            let page_digest = canonical_digest(&page)?;
            if !seen_page_digests.insert(page_digest) {
                return Err(ZoomMeetingResultError::PaginationLoop);
            }
            self.validate_page_identity(&page)?;
            if page.provider_revision != provider_revision {
                return Err(ZoomMeetingResultError::ProviderRevisionDrift);
            }
            if page.occurrence.status == MeetingOccurrenceStatus::OccurrenceAmbiguous {
                return Err(ZoomMeetingResultError::OccurrenceAmbiguous);
            }
            if let Some(existing) = &occurrence {
                if existing.meeting_id != page.occurrence.meeting_id
                    || existing.occurrence_uuid != page.occurrence.occurrence_uuid
                {
                    return Err(ZoomMeetingResultError::OccurrenceAmbiguous);
                }
            } else {
                occurrence = Some(page.occurrence.clone());
            }
            for file in page.files {
                if files.len() >= usize::from(budget.max_files) {
                    return Err(ZoomMeetingResultError::PageBudgetExceeded);
                }
                let file_id = file.file_id.clone();
                if files.contains_key(&file_id) {
                    let duplicate = file_id.as_str().to_owned();
                    return Err(ZoomMeetingResultError::DuplicateFileId(duplicate));
                }
                files.insert(file_id, file);
            }
            if let Some(page_transcript) = page.transcript {
                if let Some(existing) = &transcript
                    && existing != &page_transcript
                {
                    return Err(ZoomMeetingResultError::Provider(
                        ProviderError::MalformedPage,
                    ));
                }
                transcript = Some(page_transcript);
            }
            if let Some(page_summary) = page.summary {
                if let Some(existing) = &summary
                    && existing != &page_summary
                {
                    return Err(ZoomMeetingResultError::Provider(
                        ProviderError::MalformedPage,
                    ));
                }
                summary = Some(page_summary);
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        let occurrence = occurrence.ok_or(ZoomMeetingResultError::Provider(
            ProviderError::MalformedPage,
        ))?;
        self.validate_selected_files(&files)?;
        let listing = DecisionArtifactListing::new(
            self.scope.clone(),
            occurrence,
            files.into_values().collect(),
            transcript,
            summary,
            provider_revision,
            provider_state,
            pages_examined,
        )?;
        Self::validate_listing_digest(&listing)?;
        Ok(listing)
    }

    pub fn compile_adoption_proposal(
        &self,
        listing: &DecisionArtifactListing,
    ) -> Result<DecisionArtifactProposal, ZoomMeetingResultError> {
        self.ensure_active()?;
        Self::validate_listing_scope(&self.scope, listing)?;
        Self::validate_listing_digest(listing)?;
        if listing.provider_revision != self.provider.provider_revision() {
            return Err(ZoomMeetingResultError::ProviderRevisionDrift);
        }
        DecisionArtifactProposal::from_listing(listing)
    }

    pub fn verify_artifact_projection(
        &self,
        proposal: &DecisionArtifactProposal,
        listing: &DecisionArtifactListing,
    ) -> Result<ArtifactVerification, ZoomMeetingResultError> {
        self.ensure_active()?;
        Self::validate_listing_scope(&self.scope, listing)?;
        Self::validate_listing_digest(listing)?;
        if proposal.projection_digest != listing.projection_digest
            || proposal.provider_revision != listing.provider_revision
            || proposal.work_product_adopted
            || !proposal.non_mutating
        {
            return Err(ZoomMeetingResultError::ProjectionMismatch);
        }
        let expected_proposal = DecisionArtifactProposal::from_listing(listing)?;
        if expected_proposal.proposal_digest != proposal.proposal_digest {
            return Err(ZoomMeetingResultError::ProjectionMismatch);
        }
        Ok(ArtifactVerification {
            status: ArtifactVerificationStatus::MetadataFingerprintBound,
            projection_digest: listing.projection_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            metadata_only: true,
            content_bytes_read: false,
            content_byte_verification: ContentByteVerification::NotPerformed,
        })
    }

    pub fn revoke(&mut self) -> ZoomMeetingResultRegistration {
        self.registration.revoke();
        self.secret_reference.revoke();
        self.provider.revoke();
        self.registration.clone()
    }

    pub fn unregister(mut self) -> ZoomMeetingResultRegistration {
        self.revoke()
    }

    fn validate_page_identity(&self, page: &ProviderPage) -> Result<(), ZoomMeetingResultError> {
        let binding = self.scope.binding();
        if page.occurrence.meeting_id != *binding.meeting_id()
            || page.occurrence.occurrence_uuid != *binding.occurrence_uuid()
        {
            return Err(ZoomMeetingResultError::OccurrenceAmbiguous);
        }
        Ok(())
    }

    fn validate_selected_files(
        &self,
        files: &BTreeMap<FileId, RecordingFileMetadata>,
    ) -> Result<(), ZoomMeetingResultError> {
        let binding = self.scope.binding();
        for file_id in binding.selected_file_ids() {
            let file = files.get(&file_id).ok_or_else(|| {
                ZoomMeetingResultError::SelectedFileMissing(file_id.as_str().to_owned())
            })?;
            if binding.selected_recording_file_ids().contains(&file_id)
                && file.file_type == RecordingFileType::Transcript
            {
                return Err(ZoomMeetingResultError::SelectedFileTypeMismatch);
            }
            if binding.selected_transcript_file_ids().contains(&file_id)
                && file.file_type != RecordingFileType::Transcript
            {
                return Err(ZoomMeetingResultError::SelectedFileTypeMismatch);
            }
        }
        Ok(())
    }

    fn validate_listing_scope(
        scope: &ZoomMeetingResultScope,
        listing: &DecisionArtifactListing,
    ) -> Result<(), ZoomMeetingResultError> {
        if listing.scope != *scope {
            return Err(ZoomMeetingResultError::RegistrationScopeMismatch);
        }
        Ok(())
    }

    fn validate_listing_digest(
        listing: &DecisionArtifactListing,
    ) -> Result<(), ZoomMeetingResultError> {
        let expected = DecisionArtifactListing::new(
            listing.scope.clone(),
            listing.occurrence.clone(),
            listing.recording_files.clone(),
            listing.transcript.clone(),
            listing.summary.clone(),
            listing.provider_revision,
            ProviderState {
                mode: listing.provider_mode,
                provenance: listing.provider_provenance,
                lifecycle: ProviderLifecycle::Active,
                provider_revision: listing.provider_revision,
            },
            listing.pages_examined,
        )?;
        if expected.projection_digest == listing.projection_digest {
            Ok(())
        } else {
            Err(ZoomMeetingResultError::ProjectionMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionZoomMeetingResult {
    listing: DecisionArtifactListing,
    proposal: DecisionArtifactProposal,
    verification: ArtifactVerification,
}

impl MissionZoomMeetingResult {
    pub fn listing(&self) -> &DecisionArtifactListing {
        &self.listing
    }

    pub fn proposal(&self) -> &DecisionArtifactProposal {
        &self.proposal
    }

    pub fn verification(&self) -> &ArtifactVerification {
        &self.verification
    }
}

/// The Mission consumer is the only public path that composes a listing,
/// proposal, and metadata verification for a current Mission context.
#[derive(Debug)]
pub struct MissionZoomMeetingResultConsumer<P: ZoomMeetingResultProviderPort> {
    service: ZoomMeetingResultService<P>,
}

impl<P: ZoomMeetingResultProviderPort> MissionZoomMeetingResultConsumer<P> {
    pub fn new(service: ZoomMeetingResultService<P>) -> Self {
        Self { service }
    }

    pub fn definition() -> MissionZoomMeetingResultConsumerDefinition {
        MissionZoomMeetingResultConsumerDefinition::new()
    }

    pub fn service(&self) -> &ZoomMeetingResultService<P> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut ZoomMeetingResultService<P> {
        &mut self.service
    }

    pub fn consume(
        &self,
        context: &MissionContext,
        budget: PageBudget,
    ) -> Result<MissionZoomMeetingResult, ZoomMeetingResultError> {
        self.consume_at(context, budget, None)
    }

    pub fn consume_at(
        &self,
        context: &MissionContext,
        budget: PageBudget,
        now_millis: Option<u64>,
    ) -> Result<MissionZoomMeetingResult, ZoomMeetingResultError> {
        context.matches(&self.service.scope)?;
        if now_millis.is_some_and(|now| context.consent_reference.is_expired_at(now)) {
            return Err(ZoomMeetingResultError::ExpiredConsent);
        }
        let listing = self.service.list_decision_artifacts(budget)?;
        let proposal = self.service.compile_adoption_proposal(&listing)?;
        let verification = self
            .service
            .verify_artifact_projection(&proposal, &listing)?;
        Ok(MissionZoomMeetingResult {
            listing,
            proposal,
            verification,
        })
    }

    pub fn into_service(self) -> ZoomMeetingResultService<P> {
        self.service
    }
}
