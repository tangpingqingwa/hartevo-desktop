use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use crate::error::BoxArtifactError;

pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const MAX_CONTENT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PAGES: u32 = 16;

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, BoxArtifactError> {
                let value = value.into();
                let identifier = Self(value);
                identifier.validate()?;
                Ok(identifier)
            }

            pub fn validate(&self) -> Result<(), BoxArtifactError> {
                if self.0.is_empty()
                    || self.0.len() > 256
                    || self.0.chars().any(char::is_control)
                    || self.0.chars().any(char::is_whitespace)
                    || self
                        .0
                        .bytes()
                        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'%'))
                {
                    return Err(BoxArtifactError::InvalidIdentifier { kind: $kind });
                }
                Ok(())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple($kind)
                    .field(&redacted_identifier(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = BoxArtifactError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(EnterpriseId, "enterprise");
identifier_type!(UserId, "user");
identifier_type!(FolderId, "folder");
identifier_type!(FileId, "file");
identifier_type!(VersionId, "version");
identifier_type!(ProjectId, "project");
identifier_type!(MissionId, "mission");
identifier_type!(ResultId, "result");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha1Digest(String);

impl Sha1Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, BoxArtifactError> {
        let value = value.into().to_ascii_lowercase();
        if !is_hex_digest(&value, 40) {
            return Err(BoxArtifactError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_digest(Sha1::digest(bytes).as_slice()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sha1Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Sha1Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Sha1Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, BoxArtifactError> {
        let value = value.into().to_ascii_lowercase();
        if !is_hex_digest(&value, 64) {
            return Err(BoxArtifactError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_digest(Sha256::digest(bytes).as_slice()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ContentDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxAuthMethod {
    OAuth2Bearer,
    JwtBearer,
}

/// Opaque identity for a secret held by the host.  It contains no token or
/// JWT bytes and is safe to carry in a registration receipt.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_id: String,
    pub scope_digest: ContentDigest,
    pub credential_revision: u64,
    pub auth_method: BoxAuthMethod,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_id", &redacted_identifier(&self.reference_id))
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: ContentDigest,
        credential_revision: u64,
        auth_method: BoxAuthMethod,
    ) -> Result<Self, BoxArtifactError> {
        let reference_id = reference_id.into();
        let reference = Self {
            reference_id,
            scope_digest,
            credential_revision,
            auth_method,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        if self.reference_id.trim().is_empty()
            || self.reference_id.len() > 256
            || self.reference_id.chars().any(char::is_control)
            || self.reference_id.chars().any(char::is_whitespace)
            || self.credential_revision == 0
        {
            return Err(BoxArtifactError::InvalidInput {
                field: "secret reference",
                reason: "must have a bounded id and non-zero revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    NativeHttps,
    Loopback,
    Fixture,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(&self) -> bool {
        matches!(self, Self::NativeHttps)
    }

    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    ReadOnlyNativeSeam,
    VerifiedLoopbackNotConnected,
    VerifiedFixtureNotConnected,
    BlockedEnv,
}

impl ProbeStatus {
    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAvailability {
    Present,
    Deleted,
    Trashed,
    AccessLost,
    NotFound,
    ProviderUnknown,
}

impl ArtifactAvailability {
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxArtifactScope {
    pub enterprise_id: EnterpriseId,
    pub user_id: UserId,
    pub folder_id: Option<FolderId>,
    pub file_id: Option<FileId>,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
}

impl fmt::Debug for BoxArtifactScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxArtifactScope")
            .field("enterprise_id", &self.enterprise_id)
            .field("user_id", &self.user_id)
            .field("folder_id", &self.folder_id)
            .field("file_id", &self.file_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .finish()
    }
}

impl BoxArtifactScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        enterprise_id: EnterpriseId,
        user_id: UserId,
        folder_id: Option<FolderId>,
        file_id: Option<FileId>,
        project_id: ProjectId,
        mission_id: MissionId,
    ) -> Result<Self, BoxArtifactError> {
        let scope = Self {
            enterprise_id,
            user_id,
            folder_id,
            file_id,
            project_id,
            mission_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        if self.folder_id.is_none() && self.file_id.is_none() {
            return Err(BoxArtifactError::InvalidInput {
                field: "Box artifact scope",
                reason: "folder_id or file_id is required",
            });
        }
        self.enterprise_id.validate()?;
        self.user_id.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        if let Some(folder_id) = &self.folder_id {
            folder_id.validate()?;
        }
        if let Some(file_id) = &self.file_id {
            file_id.validate()?;
        }
        Ok(())
    }

    pub fn digest(&self) -> ContentDigest {
        ContentDigest::from_bytes(self.canonical().as_bytes())
    }

    pub fn same_mission_scope(&self, other: &Self) -> bool {
        self.enterprise_id == other.enterprise_id
            && self.user_id == other.user_id
            && self.project_id == other.project_id
            && self.mission_id == other.mission_id
    }

    pub fn permits_folder(&self, folder_id: &FolderId) -> bool {
        self.folder_id
            .as_ref()
            .is_some_and(|bound| bound == folder_id)
    }

    pub fn permits_file(&self, file_id: &FileId) -> bool {
        self.file_id.as_ref().is_none_or(|bound| bound == file_id)
    }

    fn canonical(&self) -> String {
        format!(
            "enterprise={}\nuser={}\nfolder={}\nfile={}\nproject={}\nmission={}",
            self.enterprise_id.as_str(),
            self.user_id.as_str(),
            self.folder_id.as_ref().map_or("", FolderId::as_str),
            self.file_id.as_ref().map_or("", FileId::as_str),
            self.project_id.as_str(),
            self.mission_id.as_str()
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorKind {
    FolderItems,
    FileVersions,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactCursor {
    pub kind: CursorKind,
    pub scope_digest: ContentDigest,
    pub resource_id: String,
    pub offset: u64,
}

impl fmt::Debug for ArtifactCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactCursor")
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("resource_id", &redacted_identifier(&self.resource_id))
            .field("offset", &self.offset)
            .finish()
    }
}

impl ArtifactCursor {
    pub fn folder(scope: &BoxArtifactScope, folder_id: &FolderId, offset: u64) -> Self {
        Self {
            kind: CursorKind::FolderItems,
            scope_digest: scope.digest(),
            resource_id: folder_id.as_str().to_owned(),
            offset,
        }
    }

    pub fn versions(scope: &BoxArtifactScope, file_id: &FileId, offset: u64) -> Self {
        Self {
            kind: CursorKind::FileVersions,
            scope_digest: scope.digest(),
            resource_id: file_id.as_str().to_owned(),
            offset,
        }
    }

    pub fn validate_for(
        &self,
        scope: &BoxArtifactScope,
        kind: CursorKind,
        resource_id: &str,
    ) -> Result<(), BoxArtifactError> {
        if self.scope_digest != scope.digest() {
            return Err(BoxArtifactError::CursorScopeMismatch);
        }
        if self.kind != kind || self.resource_id != resource_id {
            return Err(BoxArtifactError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: u64,
}

impl ByteRange {
    pub fn new(start: u64, end_inclusive: u64) -> Result<Self, BoxArtifactError> {
        let range = Self {
            start,
            end_inclusive,
        };
        range.validate()?;
        Ok(range)
    }

    pub fn validate(self) -> Result<(), BoxArtifactError> {
        if self.is_empty() {
            return Err(BoxArtifactError::InvalidInput {
                field: "content range",
                reason: "end must not precede start",
            });
        }
        if self.len() > MAX_CONTENT_BYTES {
            return Err(BoxArtifactError::InvalidInput {
                field: "content range",
                reason: "range exceeds the bounded content limit",
            });
        }
        Ok(())
    }

    pub const fn len(self) -> u64 {
        self.end_inclusive
            .saturating_sub(self.start)
            .saturating_add(1)
    }

    pub const fn is_empty(self) -> bool {
        self.end_inclusive < self.start
    }

    pub const fn is_full_file(self, size: u64) -> bool {
        size > 0
            && self.start == 0
            && self.end_inclusive != u64::MAX
            && self.end_inclusive + 1 == size
    }

    pub fn header_value(self) -> String {
        format!("bytes={}-{}", self.start, self.end_inclusive)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxUserRecord {
    pub enterprise_id: EnterpriseId,
    pub user_id: UserId,
    pub display_name: Option<String>,
    pub email_address: Option<String>,
}

impl fmt::Debug for BoxUserRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxUserRecord")
            .field("enterprise_id", &self.enterprise_id)
            .field("user_id", &self.user_id)
            .field("display_name", &"<redacted>")
            .field("email_address", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFolderRecord {
    pub enterprise_id: EnterpriseId,
    pub user_id: UserId,
    pub folder_id: FolderId,
    pub parent_folder_id: Option<FolderId>,
    pub name: String,
}

impl fmt::Debug for BoxFolderRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxFolderRecord")
            .field("enterprise_id", &self.enterprise_id)
            .field("user_id", &self.user_id)
            .field("folder_id", &self.folder_id)
            .field("parent_folder_id", &self.parent_folder_id)
            .field("name", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFileRecord {
    pub enterprise_id: EnterpriseId,
    pub owner_user_id: UserId,
    pub file_id: FileId,
    pub parent_folder_id: FolderId,
    pub name: String,
    pub media_type: String,
    pub size: u64,
    pub sha1: Sha1Digest,
    pub version_id: VersionId,
    pub trashed: bool,
    pub deleted: bool,
}

impl fmt::Debug for BoxFileRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxFileRecord")
            .field("enterprise_id", &self.enterprise_id)
            .field("owner_user_id", &self.owner_user_id)
            .field("file_id", &self.file_id)
            .field("parent_folder_id", &self.parent_folder_id)
            .field("name", &"<redacted>")
            .field("media_type", &self.media_type)
            .field("size", &self.size)
            .field("sha1", &self.sha1)
            .field("version_id", &self.version_id)
            .field("trashed", &self.trashed)
            .field("deleted", &self.deleted)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxVersionRecord {
    pub file_id: FileId,
    pub version_id: VersionId,
    pub size: u64,
    pub sha1: Sha1Digest,
    pub trashed: bool,
    pub deleted: bool,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFolderItemsPage {
    pub folder_id: FolderId,
    pub offset: u64,
    pub total_count: u64,
    pub entries: Vec<BoxFileRecord>,
    pub next_offset: Option<u64>,
}

impl fmt::Debug for BoxFolderItemsPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxFolderItemsPage")
            .field("folder_id", &self.folder_id)
            .field("offset", &self.offset)
            .field("total_count", &self.total_count)
            .field("entry_count", &self.entries.len())
            .field("next_offset", &self.next_offset)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxVersionPage {
    pub file_id: FileId,
    pub offset: u64,
    pub total_count: u64,
    pub entries: Vec<BoxVersionRecord>,
    pub next_offset: Option<u64>,
}

impl fmt::Debug for BoxVersionPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxVersionPage")
            .field("file_id", &self.file_id)
            .field("offset", &self.offset)
            .field("total_count", &self.total_count)
            .field("entry_count", &self.entries.len())
            .field("next_offset", &self.next_offset)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxContentResponse {
    pub file_id: FileId,
    pub version_id: VersionId,
    pub range: ByteRange,
    pub status: u16,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for BoxContentResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxContentResponse")
            .field("file_id", &self.file_id)
            .field("version_id", &self.version_id)
            .field("range", &self.range)
            .field("status", &self.status)
            .field("byte_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxUserMetadata {
    pub enterprise_id: EnterpriseId,
    pub user_id: UserId,
    pub display_name: Option<String>,
    pub email_address: Option<String>,
}

impl fmt::Debug for BoxUserMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxUserMetadata")
            .field("enterprise_id", &self.enterprise_id)
            .field("user_id", &self.user_id)
            .field("display_name", &"<redacted>")
            .field("email_address", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFolderMetadata {
    pub enterprise_id: EnterpriseId,
    pub user_id: UserId,
    pub folder_id: FolderId,
    pub parent_folder_id: Option<FolderId>,
    pub name: String,
}

impl fmt::Debug for BoxFolderMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxFolderMetadata")
            .field("enterprise_id", &self.enterprise_id)
            .field("user_id", &self.user_id)
            .field("folder_id", &self.folder_id)
            .field("parent_folder_id", &self.parent_folder_id)
            .field("name", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFileMetadata {
    pub enterprise_id: EnterpriseId,
    pub owner_user_id: UserId,
    pub file_id: FileId,
    pub parent_folder_id: FolderId,
    pub name: String,
    pub media_type: String,
    pub size: u64,
    pub sha1: Sha1Digest,
    pub version_id: VersionId,
    pub trashed: bool,
    pub deleted: bool,
}

impl fmt::Debug for BoxFileMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxFileMetadata")
            .field("enterprise_id", &self.enterprise_id)
            .field("owner_user_id", &self.owner_user_id)
            .field("file_id", &self.file_id)
            .field("parent_folder_id", &self.parent_folder_id)
            .field("name", &"<redacted>")
            .field("media_type", &self.media_type)
            .field("size", &self.size)
            .field("sha1", &self.sha1)
            .field("version_id", &self.version_id)
            .field("trashed", &self.trashed)
            .field("deleted", &self.deleted)
            .finish()
    }
}

impl BoxFileMetadata {
    pub fn revision(&self) -> ArtifactRevisionFence {
        ArtifactRevisionFence {
            file_id: self.file_id.clone(),
            version_id: self.version_id.clone(),
            sha1: self.sha1.clone(),
            size: self.size,
        }
    }

    pub fn availability(&self) -> ArtifactAvailability {
        if self.deleted {
            ArtifactAvailability::Deleted
        } else if self.trashed {
            ArtifactAvailability::Trashed
        } else {
            ArtifactAvailability::Present
        }
    }
}

impl BoxFileRecord {
    pub fn revision(&self) -> ArtifactRevisionFence {
        ArtifactRevisionFence {
            file_id: self.file_id.clone(),
            version_id: self.version_id.clone(),
            sha1: self.sha1.clone(),
            size: self.size,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxFileVersion {
    pub file_id: FileId,
    pub version_id: VersionId,
    pub size: u64,
    pub sha1: Sha1Digest,
    pub trashed: bool,
    pub deleted: bool,
}

impl BoxFileVersion {
    pub fn availability(&self) -> ArtifactAvailability {
        if self.deleted {
            ArtifactAvailability::Deleted
        } else if self.trashed {
            ArtifactAvailability::Trashed
        } else {
            ArtifactAvailability::Present
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRevisionFence {
    pub file_id: FileId,
    pub version_id: VersionId,
    pub sha1: Sha1Digest,
    pub size: u64,
}

impl ArtifactRevisionFence {
    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        if self.size > MAX_CONTENT_BYTES * u64::from(MAX_PAGES) {
            return Err(BoxArtifactError::InvalidInput {
                field: "artifact revision size",
                reason: "file is outside the bounded read surface",
            });
        }
        self.file_id.validate()?;
        self.version_id.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserReadProjection {
    pub scope: BoxArtifactScope,
    pub user: BoxUserMetadata,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolderReadProjection {
    pub scope: BoxArtifactScope,
    pub folder: BoxFolderMetadata,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolderItemsProjection {
    pub scope: BoxArtifactScope,
    pub folder_id: FolderId,
    pub entries: Vec<BoxFileMetadata>,
    pub next_cursor: Option<ArtifactCursor>,
    pub total_count: u64,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReadProjection {
    pub scope: BoxArtifactScope,
    pub file_id: FileId,
    pub availability: ArtifactAvailability,
    pub metadata: Option<BoxFileMetadata>,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionPageProjection {
    pub scope: BoxArtifactScope,
    pub file_id: FileId,
    pub versions: Vec<BoxFileVersion>,
    pub next_cursor: Option<ArtifactCursor>,
    pub total_count: u64,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentReadProjection {
    pub scope: BoxArtifactScope,
    pub revision: ArtifactRevisionFence,
    pub requested_range: ByteRange,
    pub returned_range: ByteRange,
    pub bytes: Vec<u8>,
    pub content_digest: ContentDigest,
    pub sha1_verified: bool,
    pub complete: bool,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub read_digest: ContentDigest,
}

impl fmt::Debug for ContentReadProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentReadProjection")
            .field("scope", &self.scope)
            .field("revision", &self.revision)
            .field("requested_range", &self.requested_range)
            .field("returned_range", &self.returned_range)
            .field("byte_len", &self.bytes.len())
            .field("content_digest", &self.content_digest)
            .field("sha1_verified", &self.sha1_verified)
            .field("complete", &self.complete)
            .field("provider_version", &self.provider_version)
            .field("registration_digest", &self.registration_digest)
            .field("provenance", &self.provenance)
            .field("native_transport", &self.native_transport)
            .field("native_connected", &self.native_connected)
            .field("read_digest", &self.read_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionResultBinding {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub result_id: ResultId,
    pub result_revision: u64,
}

impl MissionResultBinding {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        result_id: ResultId,
        result_revision: u64,
    ) -> Result<Self, BoxArtifactError> {
        if mission_revision == 0 || result_revision == 0 {
            return Err(BoxArtifactError::InvalidInput {
                field: "Mission/result revision",
                reason: "revision must be non-zero",
            });
        }
        Ok(Self {
            project_id,
            mission_id,
            mission_revision,
            result_id,
            result_revision,
        })
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.result_id.validate()?;
        if self.mission_revision == 0 || self.result_revision == 0 {
            return Err(BoxArtifactError::InvalidInput {
                field: "Mission/result revision",
                reason: "revision must be non-zero",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolderItemsRequest {
    pub scope: BoxArtifactScope,
    pub folder_id: FolderId,
    pub cursor: Option<ArtifactCursor>,
    pub page_size: u32,
}

impl FolderItemsRequest {
    pub fn new(
        scope: BoxArtifactScope,
        folder_id: FolderId,
        cursor: Option<ArtifactCursor>,
        page_size: u32,
    ) -> Result<Self, BoxArtifactError> {
        validate_page_size(page_size)?;
        scope.validate()?;
        folder_id.validate()?;
        if !scope.permits_folder(&folder_id) {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(&scope, CursorKind::FolderItems, folder_id.as_str())?;
        }
        Ok(Self {
            scope,
            folder_id,
            cursor,
            page_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionReadRequest {
    pub scope: BoxArtifactScope,
    pub file_id: FileId,
    pub cursor: Option<ArtifactCursor>,
    pub page_size: u32,
}

impl VersionReadRequest {
    pub fn new(
        scope: BoxArtifactScope,
        file_id: FileId,
        cursor: Option<ArtifactCursor>,
        page_size: u32,
    ) -> Result<Self, BoxArtifactError> {
        validate_page_size(page_size)?;
        scope.validate()?;
        file_id.validate()?;
        if !scope.permits_file(&file_id) {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(&scope, CursorKind::FileVersions, file_id.as_str())?;
        }
        Ok(Self {
            scope,
            file_id,
            cursor,
            page_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReadRequest {
    pub scope: BoxArtifactScope,
    pub file_id: FileId,
}

impl FileReadRequest {
    pub fn new(scope: BoxArtifactScope, file_id: FileId) -> Result<Self, BoxArtifactError> {
        scope.validate()?;
        file_id.validate()?;
        if !scope.permits_file(&file_id) {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        Ok(Self { scope, file_id })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentReadRequest {
    pub scope: BoxArtifactScope,
    pub revision: ArtifactRevisionFence,
    pub range: ByteRange,
}

impl ContentReadRequest {
    pub fn new(
        scope: BoxArtifactScope,
        revision: ArtifactRevisionFence,
        range: ByteRange,
    ) -> Result<Self, BoxArtifactError> {
        scope.validate()?;
        revision.validate()?;
        range.validate()?;
        if !scope.permits_file(&revision.file_id) {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        if range.start >= revision.size || range.end_inclusive >= revision.size {
            return Err(BoxArtifactError::InvalidInput {
                field: "content range",
                reason: "range is outside the fenced file revision",
            });
        }
        Ok(Self {
            scope,
            revision,
            range,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactProposalRequest {
    pub scope: BoxArtifactScope,
    pub source: MissionResultBinding,
    pub revision: ArtifactRevisionFence,
    pub range: ByteRange,
}

impl ArtifactProposalRequest {
    pub fn new(
        scope: BoxArtifactScope,
        source: MissionResultBinding,
        revision: ArtifactRevisionFence,
        range: ByteRange,
    ) -> Result<Self, BoxArtifactError> {
        let request = Self {
            scope,
            source,
            revision,
            range,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.scope.validate()?;
        self.source.validate()?;
        self.revision.validate()?;
        self.range.validate()?;
        if self.scope.project_id != self.source.project_id
            || self.scope.mission_id != self.source.mission_id
            || !self.scope.permits_file(&self.revision.file_id)
        {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        if self.range.start >= self.revision.size || self.range.end_inclusive >= self.revision.size
        {
            return Err(BoxArtifactError::InvalidInput {
                field: "proposal content range",
                reason: "range is outside the fenced file revision",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProposalStatus {
    Proposed,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactAdoptionProposal {
    pub proposal_id: String,
    pub proposal_digest: ContentDigest,
    pub scope: BoxArtifactScope,
    pub source: MissionResultBinding,
    pub file_id: FileId,
    pub version_id: VersionId,
    pub sha1: Sha1Digest,
    pub content_digest: ContentDigest,
    pub size: u64,
    pub media_type: String,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub status: ArtifactProposalStatus,
    pub non_mutating: bool,
    pub external_write_performed: bool,
    pub durable_readback_verified: bool,
}

impl ArtifactAdoptionProposal {
    pub const VERSION: u64 = 1;

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.scope.validate()?;
        self.source.validate()?;
        if self.status != ArtifactProposalStatus::Proposed
            || self.provider_version != crate::BOX_ARTIFACT_PROVIDER_VERSION
            || self.scope.project_id != self.source.project_id
            || self.scope.mission_id != self.source.mission_id
            || !self.non_mutating
            || self.external_write_performed
            || self.durable_readback_verified
            || self.native_connected
            || self.native_transport != self.provenance.is_native()
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "proposal contains a forbidden Layer 2 or native-connected claim",
            });
        }
        self.file_id.validate()?;
        self.version_id.validate()?;
        if self.media_type.trim().is_empty() || self.media_type.chars().any(char::is_control) {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "proposal media type is invalid",
            });
        }
        if self.proposal_digest.as_str() != self.compute_digest()
            || self.proposal_id != proposal_id_for(&self.proposal_digest)
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "proposal digest is not canonical",
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> String {
        proposal_digest_parts([
            self.scope.digest().as_str(),
            self.source.project_id.as_str(),
            self.source.mission_id.as_str(),
            &self.source.mission_revision.to_string(),
            self.source.result_id.as_str(),
            &self.source.result_revision.to_string(),
            self.file_id.as_str(),
            self.version_id.as_str(),
            self.sha1.as_str(),
            self.content_digest.as_str(),
            &self.size.to_string(),
            self.media_type.as_str(),
            &self.provider_version.to_string(),
            self.registration_digest.as_str(),
            &self.provenance.to_string(),
            &self.native_transport.to_string(),
            &self.native_connected.to_string(),
            &self.status.to_string(),
            &self.non_mutating.to_string(),
            &self.external_write_performed.to_string(),
            &self.durable_readback_verified.to_string(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionArtifactResultStatus {
    Proposed,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionArtifactResult {
    pub result_id: String,
    pub result_digest: ContentDigest,
    pub status: MissionArtifactResultStatus,
    pub proposal: ArtifactAdoptionProposal,
    pub source_mission_revision: u64,
    pub source_result_revision: u64,
    pub model_visible: bool,
    pub adopted: bool,
    pub external_write_performed: bool,
    pub native_connected: bool,
}

impl MissionArtifactResult {
    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.proposal.validate()?;
        if self.status != MissionArtifactResultStatus::Proposed
            || self.source_mission_revision != self.proposal.source.mission_revision
            || self.source_result_revision != self.proposal.source.result_revision
            || !self.model_visible
            || !self.adopted
            || self.external_write_performed
            || self.native_connected
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "Mission result is not a non-mutating Layer 1 proposal",
            });
        }
        let expected = ContentDigest::from_bytes(
            format!(
                "mission-artifact-result/v1\n{}\n{}",
                self.proposal.proposal_digest.as_str(),
                self.proposal.scope.digest().as_str()
            )
            .as_bytes(),
        );
        if self.result_digest != expected
            || self.result_id != format!("mission-artifact-{}", &expected.as_str()[..24])
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "Mission result digest is not canonical",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxArtifactPluginRegistration {
    pub plugin_id: String,
    pub plugin_version: u64,
    pub provider_version: u64,
    pub contract_digest: ContentDigest,
    pub provider_digest: ContentDigest,
    pub scope: BoxArtifactScope,
    pub secret_reference: SecretReference,
    pub registration_digest: ContentDigest,
    pub registration_revision: u64,
    pub active: bool,
}

impl BoxArtifactPluginRegistration {
    pub fn new(
        scope: BoxArtifactScope,
        secret_reference: SecretReference,
    ) -> Result<Self, BoxArtifactError> {
        if secret_reference.scope_digest != scope.digest() {
            return Err(BoxArtifactError::ScopeMismatch);
        }
        let contract_digest = crate::contract_digest();
        let provider_digest = ContentDigest::from_bytes(
            format!(
                "{}\n{}\n{}",
                crate::BOX_ARTIFACT_PROVIDER_ID,
                crate::BOX_ARTIFACT_PROVIDER_VERSION,
                contract_digest.as_str()
            )
            .as_bytes(),
        );
        let registration_digest = registration_digest_parts(
            scope.digest().as_str(),
            secret_reference.reference_id.as_str(),
            secret_reference.credential_revision,
            &secret_reference.auth_method.to_string(),
            provider_digest.as_str(),
        );
        Ok(Self {
            plugin_id: crate::BOX_ARTIFACT_PLUGIN_ID.to_owned(),
            plugin_version: crate::BOX_ARTIFACT_PLUGIN_VERSION,
            provider_version: crate::BOX_ARTIFACT_PROVIDER_VERSION,
            contract_digest,
            provider_digest,
            scope,
            secret_reference,
            registration_digest,
            registration_revision: 1,
            active: true,
        })
    }

    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.plugin_id != crate::BOX_ARTIFACT_PLUGIN_ID
            || self.plugin_version != crate::BOX_ARTIFACT_PLUGIN_VERSION
            || self.provider_version != crate::BOX_ARTIFACT_PROVIDER_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.secret_reference.scope_digest != self.scope.digest()
            || self.registration_revision == 0
            || self.registration_digest
                != registration_digest_parts(
                    self.scope.digest().as_str(),
                    self.secret_reference.reference_id.as_str(),
                    self.secret_reference.credential_revision,
                    &self.secret_reference.auth_method.to_string(),
                    self.provider_digest.as_str(),
                )
        {
            return Err(BoxArtifactError::RegistrationDigestMismatch);
        }
        let expected_provider_digest = ContentDigest::from_bytes(
            format!(
                "{}\n{}\n{}",
                crate::BOX_ARTIFACT_PROVIDER_ID,
                crate::BOX_ARTIFACT_PROVIDER_VERSION,
                self.contract_digest.as_str()
            )
            .as_bytes(),
        );
        if self.provider_digest != expected_provider_digest {
            return Err(BoxArtifactError::RegistrationDigestMismatch);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, BoxArtifactError> {
        if !self.active {
            return Err(BoxArtifactError::Revoked);
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(BoxArtifactError::RegistrationRevisionOverflow)?;
        self.active = false;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope.digest(),
            revocation_revision: self.registration_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: ContentDigest,
    pub scope_digest: ContentDigest,
    pub revocation_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoxProviderProbe {
    pub scope: BoxArtifactScope,
    pub user: BoxUserMetadata,
    pub status: ProbeStatus,
    pub provenance: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub provider_version: u64,
    pub registration_digest: ContentDigest,
    pub probe_digest: ContentDigest,
}

impl BoxProviderProbe {
    pub fn validate(&self) -> Result<(), BoxArtifactError> {
        self.scope.validate()?;
        if self.native_connected
            || self.status.is_connected()
            || self.provenance.is_connected()
            || self.native_transport != self.provenance.is_native()
        {
            return Err(BoxArtifactError::NotAdoptable {
                reason: "Layer 1 probe cannot claim Connected evidence",
            });
        }
        Ok(())
    }
}

fn validate_page_size(page_size: u32) -> Result<(), BoxArtifactError> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(BoxArtifactError::InvalidInput {
            field: "page size",
            reason: "must be between 1 and 1000",
        });
    }
    Ok(())
}

fn is_hex_digest(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> ContentDigest {
    let canonical = parts.into_iter().collect::<Vec<_>>().join("\n");
    ContentDigest::from_bytes(canonical.as_bytes())
}

pub(crate) fn registration_digest_parts(
    scope_digest: &str,
    reference_id: &str,
    credential_revision: u64,
    auth_method: &str,
    provider_digest: &str,
) -> ContentDigest {
    digest_parts([
        crate::BOX_ARTIFACT_PLUGIN_ID,
        &crate::BOX_ARTIFACT_PLUGIN_VERSION.to_string(),
        crate::BOX_ARTIFACT_PROVIDER_ID,
        &crate::BOX_ARTIFACT_PROVIDER_VERSION.to_string(),
        scope_digest,
        reference_id,
        &credential_revision.to_string(),
        auth_method,
        provider_digest,
    ])
}

pub(crate) fn proposal_digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    digest_parts(parts).as_str().to_owned()
}

pub(crate) fn proposal_id_for(digest: &ContentDigest) -> String {
    format!("box-artifact-proposal-{}", &digest.as_str()[..24])
}

pub(crate) fn redacted_identifier(value: &str) -> String {
    let digest = ContentDigest::from_bytes(value.as_bytes());
    format!("<id:{}>", &digest.as_str()[..12])
}

impl fmt::Display for BoxAuthMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OAuth2Bearer => formatter.write_str("oauth2_bearer"),
            Self::JwtBearer => formatter.write_str("jwt_bearer"),
        }
    }
}

impl fmt::Display for ProviderProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeHttps => formatter.write_str("native_https"),
            Self::Loopback => formatter.write_str("loopback"),
            Self::Fixture => formatter.write_str("fixture"),
            Self::BlockedEnv => formatter.write_str("blocked_env"),
        }
    }
}

impl fmt::Display for ArtifactProposalStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proposed")
    }
}
