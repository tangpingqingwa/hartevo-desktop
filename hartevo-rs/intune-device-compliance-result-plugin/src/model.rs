use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_POLICY_FINGERPRINTS: usize = 64;
pub const MAX_PAGES: u8 = 8;
pub const MAX_RECORDS: usize = 512;
pub const MAX_RECORDS_PER_PAGE: usize = 128;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_NEXT_LINK_BYTES: usize = 8 * 1024;
pub const MAX_TIMESTAMP_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp is not a bounded UTC timestamp")]
    InvalidTimestamp,
    #[error("compliance window is empty or reversed")]
    InvalidComplianceWindow,
    #[error("scope is missing a required exact field")]
    InvalidScope,
    #[error("policy fingerprint set is malformed or too large")]
    InvalidPolicyFingerprints,
    #[error("query bounds are outside the Layer-1 limits")]
    InvalidBounds,
    #[error("opaque SecretReference is invalid")]
    InvalidSecretReference,
    #[error("opaque next link is invalid or outside its scope")]
    InvalidNextLink,
    #[error("read request has no surfaces or duplicate surfaces")]
    InvalidReadRequest,
    #[error("compliance record is malformed or outside the governed scope")]
    InvalidRecord,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
    #[error("scope or revision fence does not match")]
    ScopeMismatch,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

string_identifier!(ProjectId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);

impl Timestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid = value.len() <= MAX_TIMESTAMP_BYTES
            && value.len() >= 10
            && value.contains('T')
            && value.ends_with('Z')
            && value.trim() == value
            && !value.chars().any(char::is_control);
        if valid {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidTimestamp)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceWindow {
    pub start: Timestamp,
    pub end: Timestamp,
}

impl ComplianceWindow {
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ModelError> {
        if start.as_str() >= end.as_str() {
            Err(ModelError::InvalidComplianceWindow)
        } else {
            Ok(Self { start, end })
        }
    }

    #[must_use]
    pub fn contains(&self, timestamp: &Timestamp) -> bool {
        self.start.as_str() <= timestamp.as_str() && timestamp.as_str() <= self.end.as_str()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NationalCloud {
    Global,
    UsGovL4,
    UsGovL5,
    China,
}

impl NationalCloud {
    #[must_use]
    pub const fn graph_host(self) -> &'static str {
        match self {
            Self::Global => "graph.microsoft.com",
            Self::UsGovL4 => "graph.microsoft.us",
            Self::UsGovL5 => "dod-graph.microsoft.us",
            Self::China => "microsoftgraph.chinacloudapi.cn",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Platform {
    Windows,
    MacOs,
    Ios,
    Android,
    Linux,
    Unknown,
}

impl Platform {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Linux => "linux",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn parse(value: &str) -> Self {
        let value = value.to_ascii_lowercase();
        if value.contains("windows") {
            Self::Windows
        } else if value.contains("mac") || value.contains("osx") {
            Self::MacOs
        } else if value.contains("ios") {
            Self::Ios
        } else if value.contains("android") {
            Self::Android
        } else if value.contains("linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DeviceSelector {
    AllManagedDevices,
    DeviceDigest(Digest),
}

impl DeviceSelector {
    #[must_use]
    pub fn digest(&self) -> Digest {
        match self {
            Self::AllManagedDevices => Digest::from_text("all-managed-devices"),
            Self::DeviceDigest(digest) => digest.clone(),
        }
    }

    #[must_use]
    pub(crate) fn accepts(&self, device_digest: &Digest) -> bool {
        match self {
            Self::AllManagedDevices => true,
            Self::DeviceDigest(expected) => expected == device_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyFingerprints(Vec<Digest>);

impl PolicyFingerprints {
    pub fn new<I>(fingerprints: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = Digest>,
    {
        let mut values = fingerprints.into_iter().collect::<Vec<_>>();
        values.sort();
        values.dedup();
        if values.len() > MAX_POLICY_FINGERPRINTS {
            Err(ModelError::InvalidPolicyFingerprints)
        } else {
            Ok(Self(values))
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Digest] {
        &self.0
    }

    #[must_use]
    pub(crate) fn accepts(&self, policy_digest: &Digest) -> bool {
        self.0.is_empty() || self.0.contains(policy_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneScope {
    pub tenant_digest: Digest,
    pub national_cloud: NationalCloud,
    pub policy_fingerprints: PolicyFingerprints,
    pub device_selector: DeviceSelector,
    pub platform: Platform,
    pub compliance_window: ComplianceWindow,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission_digest: Digest,
}

impl IntuneScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: impl AsRef<str>,
        national_cloud: NationalCloud,
        policy_fingerprints: PolicyFingerprints,
        device_selector: DeviceSelector,
        platform: Platform,
        compliance_window: ComplianceWindow,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let tenant = tenant.as_ref();
        if tenant.is_empty() || tenant.len() > MAX_IDENTIFIER_BYTES || tenant.trim() != tenant {
            return Err(ModelError::InvalidScope);
        }
        Ok(Self {
            tenant_digest: Digest::from_text(tenant),
            national_cloud,
            policy_fingerprints,
            device_selector,
            platform,
            compliance_window,
            project,
            mission,
            work_product,
            permission_digest,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        Digest::from_fields("intune.scope.v1", &self.scope_fields())
    }

    #[must_use]
    pub(crate) fn revision_fence(&self) -> Digest {
        Digest::from_fields(
            "intune.scope.revisions.v1",
            &[
                self.project.revision.get().to_string(),
                self.mission.revision.get().to_string(),
                self.work_product.revision.get().to_string(),
            ],
        )
    }

    fn scope_fields(&self) -> Vec<String> {
        let mut fields = vec![
            self.tenant_digest.as_str().to_owned(),
            format!("{:?}", self.national_cloud),
            self.device_selector.digest().as_str().to_owned(),
            self.platform.as_str().to_owned(),
            self.compliance_window.start.as_str().to_owned(),
            self.compliance_window.end.as_str().to_owned(),
            self.project.id.as_str().to_owned(),
            self.project.revision.get().to_string(),
            self.mission.id.as_str().to_owned(),
            self.mission.revision.get().to_string(),
            self.work_product.id.as_str().to_owned(),
            self.work_product.revision.get().to_string(),
            self.permission_digest.as_str().to_owned(),
        ];
        fields.extend(
            self.policy_fingerprints
                .as_slice()
                .iter()
                .map(|digest| digest.as_str().to_owned()),
        );
        fields
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    handle_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
}

impl SecretReference {
    pub fn new(
        handle: impl AsRef<str>,
        scope: &IntuneScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let handle = handle.as_ref();
        if handle.is_empty() || handle.len() > MAX_IDENTIFIER_BYTES || handle.trim() != handle {
            return Err(ModelError::InvalidSecretReference);
        }
        Ok(Self {
            handle_digest: Digest::from_text(handle),
            scope_digest: scope.scope_digest(),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision(&self) -> Revision {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("handle_digest", &"<redacted>")
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryBounds {
    pub max_pages: u8,
    pub max_records: usize,
    pub max_records_per_page: usize,
    pub max_response_bytes: usize,
}

impl QueryBounds {
    pub fn new(
        max_pages: u8,
        max_records: usize,
        max_records_per_page: usize,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let bounds = Self {
            max_pages,
            max_records,
            max_records_per_page,
            max_response_bytes,
        };
        if max_pages == 0
            || max_pages > MAX_PAGES
            || max_records == 0
            || max_records > MAX_RECORDS
            || max_records_per_page == 0
            || max_records_per_page > MAX_RECORDS_PER_PAGE
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            Err(ModelError::InvalidBounds)
        } else {
            Ok(bounds)
        }
    }

    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            max_pages: MAX_PAGES,
            max_records: MAX_RECORDS,
            max_records_per_page: MAX_RECORDS_PER_PAGE,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ReadSurface {
    PolicyMetadata,
    ManagedDeviceCompliance,
    PolicyStateSummary,
}

impl ReadSurface {
    #[must_use]
    pub const fn endpoint_path(self) -> &'static str {
        match self {
            Self::PolicyMetadata => "/v1.0/deviceManagement/deviceCompliancePolicies",
            Self::ManagedDeviceCompliance => "/v1.0/deviceManagement/managedDevices",
            Self::PolicyStateSummary => {
                "/v1.0/deviceManagement/deviceCompliancePolicySettingStateSummaries"
            }
        }
    }

    #[must_use]
    pub const fn select_fields(self) -> &'static [&'static str] {
        match self {
            Self::PolicyMetadata => &["id", "platforms", "createdDateTime", "lastModifiedDateTime"],
            Self::ManagedDeviceCompliance => &[
                "id",
                "complianceState",
                "operatingSystem",
                "lastSyncDateTime",
            ],
            Self::PolicyStateSummary => &[
                "id",
                "settingName",
                "compliantDeviceCount",
                "nonCompliantDeviceCount",
                "errorDeviceCount",
                "conflictDeviceCount",
                "unknownDeviceCount",
                "retiredDeviceCount",
            ],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntuneReadRequest {
    scope: IntuneScope,
    surfaces: Vec<ReadSurface>,
    bounds: QueryBounds,
}

impl IntuneReadRequest {
    pub fn new(
        scope: &IntuneScope,
        surfaces: impl IntoIterator<Item = ReadSurface>,
        bounds: QueryBounds,
    ) -> Result<Self, ModelError> {
        let surfaces = surfaces.into_iter().collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        if surfaces.is_empty() || surfaces.iter().any(|surface| !seen.insert(*surface)) {
            return Err(ModelError::InvalidReadRequest);
        }
        Ok(Self {
            scope: scope.clone(),
            surfaces,
            bounds,
        })
    }

    pub fn for_surface(scope: &IntuneScope, surface: ReadSurface) -> Result<Self, ModelError> {
        Self::new(scope, [surface], QueryBounds::layer1())
    }

    pub fn all_surfaces(scope: &IntuneScope) -> Result<Self, ModelError> {
        Self::new(
            scope,
            [
                ReadSurface::PolicyMetadata,
                ReadSurface::ManagedDeviceCompliance,
                ReadSurface::PolicyStateSummary,
            ],
            QueryBounds::layer1(),
        )
    }

    #[must_use]
    pub fn scope(&self) -> &IntuneScope {
        &self.scope
    }

    #[must_use]
    pub fn surfaces(&self) -> &[ReadSurface] {
        &self.surfaces
    }

    #[must_use]
    pub const fn bounds(&self) -> QueryBounds {
        self.bounds
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueNextLink {
    digest: Digest,
    raw: String,
}

impl OpaqueNextLink {
    pub(crate) fn from_raw(
        raw: impl Into<String>,
        scope: &IntuneScope,
        surface: ReadSurface,
    ) -> Result<Self, ModelError> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > MAX_NEXT_LINK_BYTES
            || raw.chars().any(char::is_control)
            || raw.contains("$filter")
            || raw.contains("%24filter")
        {
            return Err(ModelError::InvalidNextLink);
        }
        let Some((scheme, remainder)) = raw.split_once("://") else {
            return Err(ModelError::InvalidNextLink);
        };
        if scheme != "https" {
            return Err(ModelError::InvalidNextLink);
        }
        let Some((host, path_and_query)) = remainder.split_once('/') else {
            return Err(ModelError::InvalidNextLink);
        };
        let path = format!("/{path_and_query}");
        let path_without_query = path.split('?').next().unwrap_or(&path);
        if host != scope.national_cloud.graph_host()
            || path_without_query != surface.endpoint_path()
            || !path.contains("$skiptoken=")
        {
            return Err(ModelError::InvalidNextLink);
        }
        Ok(Self {
            digest: Digest::from_text(&raw),
            raw,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueNextLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextLink")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    Error,
    Conflict,
    Unknown,
    Retired,
}

impl ComplianceState {
    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "compliant" => Self::Compliant,
            "noncompliant" | "non_compliant" | "non-compliant" => Self::NonCompliant,
            "error" => Self::Error,
            "conflict" => Self::Conflict,
            "retired" => Self::Retired,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ComplianceSummary {
    Compliant,
    NonCompliant,
    Error,
    Conflict,
    Unknown,
    Retired,
    Mixed,
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
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

    #[must_use]
    pub const fn is_native(self) -> bool {
        self.native()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Layer1Authority {
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub https_transport: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub verification: bool,
    pub external_writes: bool,
    pub certification: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub truth_authority: bool,
}

impl Layer1Authority {
    #[must_use]
    pub const fn layer1() -> Self {
        Self {
            connected: false,
            native_provider: false,
            first_party: false,
            https_transport: false,
            durable_receipt: false,
            independent_readback: false,
            verification: false,
            external_writes: false,
            certification: false,
            outcome_authority: false,
            work_product_adoption: false,
            truth_authority: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyMetadataProjection {
    pub policy_digest: Digest,
    pub platforms: Vec<Platform>,
    pub created_at: Option<Timestamp>,
    pub modified_at: Option<Timestamp>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceRecord {
    pub device_digest: Digest,
    pub policy_digest: Option<Digest>,
    pub platform: Platform,
    pub state: ComplianceState,
    pub observed_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyStateSummary {
    pub summary_digest: Digest,
    pub policy_digest: Option<Digest>,
    pub compliant_count: u32,
    pub non_compliant_count: u32,
    pub error_count: u32,
    pub conflict_count: u32,
    pub unknown_count: u32,
    pub retired_count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProviderErrorKind {
    Timeout,
    BlockedEnv,
    Transport,
    HttpStatus(u16),
    AccessDenied,
    NotFound,
    RateLimited,
    Conflict,
    MalformedResponse,
    ResponseTooLarge,
    RecordLimit,
    ScopeMismatch,
    NextLinkScopeMismatch,
    NextLinkReplay,
    PartialPage,
    RevisionMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub detail_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneEvidence {
    pub scope_digest: Digest,
    pub revision_fence: Digest,
    pub provenance: ProviderProvenance,
    pub status: EvidenceStatus,
    pub summary: ComplianceSummary,
    pub pages_observed: u8,
    pub records: Vec<ComplianceRecord>,
    pub policies: Vec<PolicyMetadataProjection>,
    pub policy_summaries: Vec<PolicyStateSummary>,
    pub response_digests: Vec<Digest>,
    pub next_link_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub authority: Layer1Authority,
}

impl IntuneEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(serde_json::to_vec(self).unwrap_or_default())
    }

    #[must_use]
    pub fn connected(&self) -> bool {
        self.authority.connected
    }

    #[must_use]
    pub fn native(&self) -> bool {
        self.authority.native_provider
    }

    #[must_use]
    pub fn first_party(&self) -> bool {
        self.authority.first_party
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub reason_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationBinding {
    pub provider_digest: Digest,
    pub provider_api_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
}

impl RegistrationBinding {
    #[must_use]
    pub(crate) fn digest(&self) -> Digest {
        Digest::from_fields(
            "intune.registration.v1",
            &[
                self.provider_digest.as_str().to_owned(),
                self.provider_api_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.plugin_version.clone(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneRegistration {
    pub binding: RegistrationBinding,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub revocation: Option<RegistrationRevocation>,
}

impl IntuneRegistration {
    pub(crate) fn active(binding: RegistrationBinding) -> Self {
        let registration_digest = binding.digest();
        Self {
            binding,
            registration_digest,
            state: RegistrationState::Active,
            revocation: None,
        }
    }

    pub(crate) fn revoke(&mut self, reason: impl AsRef<str>) -> Result<(), ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revocation = Some(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            reason_digest: Digest::from_text(reason.as_ref()),
        });
        Ok(())
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }
}
