use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::str::FromStr;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::DovetailResearchResultError;

pub const DOVETAIL_API_BASE_URL: &str = "https://dovetail.com/api/v1";
pub const DOVETAIL_PROJECTS_PATH: &str = "/projects";
pub const DOVETAIL_FOLDERS_PATH: &str = "/folders";
pub const DOVETAIL_DATA_PATH: &str = "/data";
pub const DOVETAIL_HIGHLIGHTS_PATH: &str = "/highlights";
pub const DOVETAIL_TAGS_PATH: &str = "/tags";
pub const DOVETAIL_INSIGHTS_PATH: &str = "/insights";
pub const DOVETAIL_DOCS_PATH: &str = "/docs";
pub const DOVETAIL_SECRET_REFERENCE_ENV: &str = "HARTEVO_DOVETAIL_API_TOKEN_REFERENCE";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SECRET_REFERENCE_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES_PER_OPERATION: u8 = 8;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_ITEMS_PER_OPERATION: usize = 512;
pub const MAX_DATA_IDS: usize = 64;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_RETRIES: u8 = 3;
pub const MAX_BACKOFF_MS: u64 = 30_000;
pub const MAX_TIME_WINDOW_BYTES: usize = 64;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_QUERY_VALUE_BYTES: usize = 1024;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Layer-1 contract values must serialize");
    Digest(sha256_hex(&bytes))
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> crate::Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(DovetailResearchResultError::InvalidInput {
            field,
            reason: "must be non-empty, trimmed, bounded, and content-safe",
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &Digest, field: &'static str) -> crate::Result<()> {
    if value.is_valid() {
        Ok(())
    } else {
        Err(DovetailResearchResultError::InvalidDigest { field })
    }
}

/// A lower-case SHA-256 digest. Digests are retained instead of free-form
/// provider bodies so result and revision fences remain deterministic.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub fn from_serialized<T: Serialize + ?Sized>(value: &T) -> Self {
        digest_serialized(value)
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::from(label);
        for (name, value) in values {
            write!(canonical, "|{name}:{}:{value}", value.len())
                .expect("writing to a String cannot fail");
        }
        Self::from_text(canonical)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> crate::Result<Self> {
        let value = Self(value.into());
        validate_digest(&value, field)?;
        Ok(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn validate(&self, field: &'static str) -> crate::Result<()> {
        validate_digest(self, field)
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

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> crate::Result<Self> {
                let value = value.into();
                validate_text(&value, $field, MAX_IDENTIFIER_BYTES)?;
                if value.chars().any(char::is_whitespace) {
                    return Err(DovetailResearchResultError::InvalidInput {
                        field: $field,
                        reason: "identifier must not contain whitespace",
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.0.as_bytes())
            }

            pub fn validate(&self) -> crate::Result<()> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DovetailResearchResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(WorkspaceId, "workspaceId");
bounded_identifier!(DovetailProjectId, "dovetailProjectId");
bounded_identifier!(FolderId, "folderId");
bounded_identifier!(DataId, "dataId");
bounded_identifier!(HighlightId, "highlightId");
bounded_identifier!(TagId, "tagId");
bounded_identifier!(InsightId, "insightId");
bounded_identifier!(DocId, "docId");
bounded_identifier!(ProjectId, "projectId");
bounded_identifier!(MissionId, "missionId");
bounded_identifier!(WorkProductId, "workProductId");
bounded_identifier!(RegistrationId, "registrationId");
bounded_identifier!(ConsentId, "consentId");

pub type HartevoProjectId = ProjectId;

/// Semantic version frozen into a registration and every proposal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> crate::Result<Self> {
        let mut parts = value.split('.');
        let mut numbers = [0_u16; 3];
        for number in &mut numbers {
            let part = parts
                .next()
                .ok_or(DovetailResearchResultError::InvalidInput {
                    field: "pluginVersion",
                    reason: "must have major.minor.patch form",
                })?;
            *number = part
                .parse()
                .map_err(|_| DovetailResearchResultError::InvalidInput {
                    field: "pluginVersion",
                    reason: "version components must be unsigned integers",
                })?;
        }
        if parts.next().is_some() {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "pluginVersion",
                reason: "must have exactly three components",
            });
        }
        Ok(Self {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Token kind without exposing the token value.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
}

/// Opaque host-owned credential reference. The constructor hashes and drops
/// the supplied handle; the handle and Dovetail `api.` token are never stored,
/// serialized, formatted, or passed to a transport.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> crate::Result<Self> {
        Self::new(SecretKind::ApiToken, opaque_id, revision)
    }

    pub fn new(
        kind: SecretKind,
        opaque_id: impl Into<String>,
        revision: u64,
    ) -> crate::Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_SECRET_REFERENCE_BYTES)?;
        if revision == 0 {
            return Err(DovetailResearchResultError::InvalidSecretReference);
        }
        let reference_digest = Digest::from_parts(
            "dovetail-opaque-secret-reference/v1",
            &[
                ("kind", format!("{kind:?}")),
                ("opaque_id", opaque_id),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            kind,
            reference_digest,
            revision,
            revoked: false,
        })
    }

    pub fn from_serialized_digest(
        kind: SecretKind,
        reference_digest: Digest,
        revision: u64,
        revoked: bool,
    ) -> crate::Result<Self> {
        reference_digest.validate("secretReferenceDigest")?;
        if revision == 0 {
            return Err(DovetailResearchResultError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            reference_digest,
            revision,
            revoked,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> crate::Result<()> {
        self.reference_digest.validate("secretReferenceDigest")?;
        if self.revision == 0 {
            return Err(DovetailResearchResultError::InvalidSecretReference);
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
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl Serialize for SecretReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("SecretReference", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("referenceDigest", &self.reference_digest)?;
        state.serialize_field("revision", &self.revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct SecretReferenceWire {
            kind: SecretKind,
            reference_digest: Digest,
            revision: u64,
            revoked: bool,
        }

        let wire = SecretReferenceWire::deserialize(deserializer)?;
        Self::from_serialized_digest(
            wire.kind,
            wire.reference_digest,
            wire.revision,
            wire.revoked,
        )
        .map_err(D::Error::custom)
    }
}

/// Provider identity is explicit and digest-bound. It is not a native
/// Connected claim; it identifies the allowlisted API revision only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailProviderIdentity {
    pub id: String,
    pub version: u64,
    pub api_revision: String,
    pub digest: Digest,
}

impl DovetailProviderIdentity {
    pub fn new(
        id: impl Into<String>,
        version: u64,
        api_revision: impl Into<String>,
    ) -> crate::Result<Self> {
        let id = id.into();
        let api_revision = api_revision.into();
        validate_text(&id, "providerId", MAX_IDENTIFIER_BYTES)?;
        validate_text(&api_revision, "providerRevision", MAX_IDENTIFIER_BYTES)?;
        if version == 0 {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "providerVersion",
                reason: "must be positive",
            });
        }
        let digest = Digest::from_parts(
            "dovetail-provider/v1",
            &[
                ("id", id.clone()),
                ("version", version.to_string()),
                ("api_revision", api_revision.clone()),
            ],
        );
        Ok(Self {
            id,
            version,
            api_revision,
            digest,
        })
    }

    pub fn layer1() -> crate::Result<Self> {
        Self::new(
            "DovetailProvider",
            1,
            "dovetail-public-api-v1-metadata-read",
        )
    }

    pub fn validate(&self) -> crate::Result<()> {
        let expected = Self::new(self.id.clone(), self.version, self.api_revision.clone())?;
        if self.id != crate::PROVIDER_ID
            || self.api_revision != "dovetail-public-api-v1-metadata-read"
        {
            return Err(DovetailResearchResultError::ProviderMismatch);
        }
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::ProviderMismatch)
        }
    }
}

/// Explicitly read-only permission snapshot. Dovetail uses API-token
/// permissions rather than OAuth scopes, so this snapshot is a host-owned
/// contract fence and not a claim that the token has been resolved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DovetailReadPermission {
    ProjectsRead,
    FoldersRead,
    DataRead,
    HighlightsRead,
    TagsRead,
    InsightsRead,
    DocsRead,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailPermissionSnapshot {
    pub read_only: bool,
    pub allowed_operations: BTreeSet<DovetailReadPermission>,
    pub revision: u64,
    pub digest: Digest,
}

impl DovetailPermissionSnapshot {
    pub fn read_only(revision: u64) -> crate::Result<Self> {
        if revision == 0 {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "permissionRevision",
                reason: "must be positive",
            });
        }
        let allowed_operations = BTreeSet::from([
            DovetailReadPermission::ProjectsRead,
            DovetailReadPermission::FoldersRead,
            DovetailReadPermission::DataRead,
            DovetailReadPermission::HighlightsRead,
            DovetailReadPermission::TagsRead,
            DovetailReadPermission::InsightsRead,
            DovetailReadPermission::DocsRead,
        ]);
        let digest = Digest::from_serialized(&(true, &allowed_operations, revision));
        Ok(Self {
            read_only: true,
            allowed_operations,
            revision,
            digest,
        })
    }

    pub fn validate(&self) -> crate::Result<()> {
        if !self.read_only || self.revision == 0 {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "permissionSnapshot",
                reason: "must be positive and read-only",
            });
        }
        let expected =
            Digest::from_serialized(&(self.read_only, &self.allowed_operations, self.revision));
        if expected == self.digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::PermissionMismatch)
        }
    }
}

macro_rules! revision_binding {
    ($name:ident, $id:ident, $field:literal, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: u64,
            pub revision_digest: Digest,
        }

        impl $name {
            pub fn new(id: $id, revision: u64) -> crate::Result<Self> {
                let revision_digest = Digest::from_parts(
                    $label,
                    &[("id", id.to_string()), ("revision", revision.to_string())],
                );
                Self::with_digest(id, revision, revision_digest)
            }

            pub fn with_digest(
                id: $id,
                revision: u64,
                revision_digest: Digest,
            ) -> crate::Result<Self> {
                id.validate()?;
                revision_digest.validate($field)?;
                if revision == 0 {
                    return Err(DovetailResearchResultError::InvalidInput {
                        field: $field,
                        reason: "revision must be positive",
                    });
                }
                Ok(Self {
                    id,
                    revision,
                    revision_digest,
                })
            }

            pub fn validate(&self) -> crate::Result<()> {
                Self::with_digest(self.id.clone(), self.revision, self.revision_digest.clone())
                    .map(|_| ())
            }
        }
    };
}

revision_binding!(
    WorkspaceBinding,
    WorkspaceId,
    "workspaceDigest",
    "dovetail-workspace/v1"
);
revision_binding!(
    DovetailProjectBinding,
    DovetailProjectId,
    "dovetailProjectDigest",
    "dovetail-project/v1"
);
revision_binding!(
    FolderBinding,
    FolderId,
    "folderDigest",
    "dovetail-folder/v1"
);
revision_binding!(
    HartevoProjectBinding,
    ProjectId,
    "projectDigest",
    "hartevo-project/v1"
);
revision_binding!(MissionBinding, MissionId, "missionDigest", "mission/v1");
revision_binding!(
    WorkProductBinding,
    WorkProductId,
    "workProductDigest",
    "work-product/v1"
);

pub type DovetailWorkspaceBinding = WorkspaceBinding;
pub type DovetailFolderBinding = FolderBinding;
pub type ProjectBinding = HartevoProjectBinding;
pub type MissionScope = MissionBinding;
pub type WorkProductScope = WorkProductBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailDataScope {
    pub data_ids: Vec<DataId>,
    pub revision_digest: Digest,
    pub scope_digest: Digest,
}

impl DovetailDataScope {
    pub fn new(mut data_ids: Vec<DataId>, revision_digest: Digest) -> crate::Result<Self> {
        data_ids.sort();
        data_ids.dedup();
        if data_ids.is_empty() || data_ids.len() > MAX_DATA_IDS {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "dataIds",
                reason: "must contain between one and the configured maximum number of IDs",
            });
        }
        for data_id in &data_ids {
            data_id.validate()?;
        }
        revision_digest.validate("dataRevisionDigest")?;
        let scope_digest = Digest::from_serialized(&(&data_ids, &revision_digest));
        Ok(Self {
            data_ids,
            revision_digest,
            scope_digest,
        })
    }

    pub fn validate(&self) -> crate::Result<()> {
        let expected = Self::new(self.data_ids.clone(), self.revision_digest.clone())?;
        if expected.scope_digest == self.scope_digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::ScopeMismatch)
        }
    }

    pub fn contains(&self, id: &DataId) -> bool {
        self.data_ids.binary_search(id).is_ok()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDataClass {
    Metadata,
    Counts,
    ThemeIds,
    Timestamps,
    RedactedDigests,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: ConsentId,
    pub revision: u64,
    pub purpose: String,
    pub permitted_data_classes: BTreeSet<ConsentDataClass>,
    pub digest: Digest,
}

impl ConsentScope {
    pub fn new(
        id: ConsentId,
        revision: u64,
        purpose: impl Into<String>,
        permitted_data_classes: BTreeSet<ConsentDataClass>,
    ) -> crate::Result<Self> {
        let purpose = purpose.into();
        id.validate()?;
        validate_text(&purpose, "consentPurpose", MAX_IDENTIFIER_BYTES)?;
        if revision == 0 || permitted_data_classes.is_empty() {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "consentScope",
                reason: "revision and permitted data classes must be present",
            });
        }
        let digest = Digest::from_serialized(&(&id, revision, &purpose, &permitted_data_classes));
        Ok(Self {
            id,
            revision,
            purpose,
            permitted_data_classes,
            digest,
        })
    }

    pub fn metadata_only(id: ConsentId, revision: u64) -> crate::Result<Self> {
        Self::new(
            id,
            revision,
            "bounded_customer_research_metadata",
            BTreeSet::from([
                ConsentDataClass::Metadata,
                ConsentDataClass::Counts,
                ConsentDataClass::ThemeIds,
                ConsentDataClass::Timestamps,
                ConsentDataClass::RedactedDigests,
            ]),
        )
    }

    pub fn validate(&self) -> crate::Result<()> {
        let expected = Self::new(
            self.id.clone(),
            self.revision,
            self.purpose.clone(),
            self.permitted_data_classes.clone(),
        )?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::ConsentDrift)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchScope {
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider: DovetailProviderIdentity,
    pub workspace: WorkspaceBinding,
    pub dovetail_project: DovetailProjectBinding,
    pub dovetail_folder: Option<FolderBinding>,
    pub dovetail_data: DovetailDataScope,
    pub hartevo_project: HartevoProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
}

impl DovetailResearchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_version: PluginVersion,
        contract_version: impl Into<String>,
        contract_digest: Digest,
        provider: DovetailProviderIdentity,
        workspace: WorkspaceBinding,
        dovetail_project: DovetailProjectBinding,
        dovetail_folder: Option<FolderBinding>,
        dovetail_data: DovetailDataScope,
        hartevo_project: HartevoProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
        permission_digest: Digest,
    ) -> crate::Result<Self> {
        let contract_version = contract_version.into();
        validate_text(&contract_version, "contractVersion", MAX_IDENTIFIER_BYTES)?;
        contract_digest.validate("contractDigest")?;
        if contract_digest != crate::contract_digest() {
            return Err(DovetailResearchResultError::InvalidContract);
        }
        permission_digest.validate("permissionDigest")?;
        provider.validate()?;
        workspace.validate()?;
        dovetail_project.validate()?;
        if let Some(folder) = &dovetail_folder {
            folder.validate()?;
        }
        dovetail_data.validate()?;
        hartevo_project.validate()?;
        mission.validate()?;
        work_product.validate()?;
        consent.validate()?;
        let scope_digest = Self::calculate_digest(
            plugin_version,
            &contract_version,
            &contract_digest,
            &provider,
            &workspace,
            &dovetail_project,
            dovetail_folder.as_ref(),
            &dovetail_data,
            &hartevo_project,
            &mission,
            &work_product,
            &consent,
            &permission_digest,
        );
        Ok(Self {
            plugin_version,
            contract_version,
            contract_digest,
            provider,
            workspace,
            dovetail_project,
            dovetail_folder,
            dovetail_data,
            hartevo_project,
            mission,
            work_product,
            consent,
            permission_digest,
            scope_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn calculate_digest(
        plugin_version: PluginVersion,
        contract_version: &str,
        contract_digest: &Digest,
        provider: &DovetailProviderIdentity,
        workspace: &WorkspaceBinding,
        dovetail_project: &DovetailProjectBinding,
        dovetail_folder: Option<&FolderBinding>,
        dovetail_data: &DovetailDataScope,
        hartevo_project: &HartevoProjectBinding,
        mission: &MissionBinding,
        work_product: &WorkProductBinding,
        consent: &ConsentScope,
        permission_digest: &Digest,
    ) -> Digest {
        Digest::from_serialized(&(
            plugin_version,
            contract_version,
            contract_digest,
            provider,
            workspace,
            dovetail_project,
            dovetail_folder,
            dovetail_data,
            hartevo_project,
            mission,
            work_product,
            consent,
            permission_digest,
        ))
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.plugin_version != PluginVersion::V1 {
            return Err(DovetailResearchResultError::InvalidContract);
        }
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(DovetailResearchResultError::InvalidContract);
        }
        self.contract_digest.validate("contractDigest")?;
        if self.contract_digest != crate::contract_digest() {
            return Err(DovetailResearchResultError::InvalidContract);
        }
        self.permission_digest.validate("permissionDigest")?;
        self.provider.validate()?;
        self.workspace.validate()?;
        self.dovetail_project.validate()?;
        if let Some(folder) = &self.dovetail_folder {
            folder.validate()?;
        }
        self.dovetail_data.validate()?;
        self.hartevo_project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()?;
        self.consent.validate()?;
        let expected = Self::calculate_digest(
            self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider,
            &self.workspace,
            &self.dovetail_project,
            self.dovetail_folder.as_ref(),
            &self.dovetail_data,
            &self.hartevo_project,
            &self.mission,
            &self.work_product,
            &self.consent,
            &self.permission_digest,
        );
        if expected == self.scope_digest {
            Ok(())
        } else {
            Err(DovetailResearchResultError::ScopeMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResearchTimeWindow {
    pub start: String,
    pub end: String,
}

impl ResearchTimeWindow {
    pub fn new(start: impl Into<String>, end: impl Into<String>) -> crate::Result<Self> {
        let start = start.into();
        let end = end.into();
        validate_text(&start, "timeWindowStart", MAX_TIME_WINDOW_BYTES)?;
        validate_text(&end, "timeWindowEnd", MAX_TIME_WINDOW_BYTES)?;
        if start > end {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "timeWindow",
                reason: "start must not be after end",
            });
        }
        Ok(Self { start, end })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailReadBounds {
    pub page_size: u16,
    pub max_pages_per_operation: u8,
    pub max_response_bytes: usize,
    pub max_items_per_operation: usize,
    pub max_retries: u8,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
    pub time_window: Option<ResearchTimeWindow>,
}

impl Default for DovetailReadBounds {
    fn default() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages_per_operation: MAX_PAGES_PER_OPERATION,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_items_per_operation: MAX_ITEMS_PER_OPERATION,
            max_retries: MAX_RETRIES,
            backoff_initial_ms: 250,
            backoff_max_ms: MAX_BACKOFF_MS,
            time_window: None,
        }
    }
}

impl DovetailReadBounds {
    pub fn validate(&self) -> crate::Result<()> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES_PER_OPERATION).contains(&self.max_pages_per_operation)
            || !(1..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes)
            || !(1..=MAX_ITEMS_PER_OPERATION).contains(&self.max_items_per_operation)
            || self.max_retries > MAX_RETRIES
            || self.backoff_initial_ms > self.backoff_max_ms
            || self.backoff_max_ms > MAX_BACKOFF_MS
        {
            return Err(DovetailResearchResultError::InvalidInput {
                field: "readBounds",
                reason: "one or more pagination, response, retry, or backoff bounds exceed Layer 1 limits",
            });
        }
        Ok(())
    }

    pub fn backoff_ms(&self, retry_attempt: u8, retry_after_seconds: Option<u64>) -> u64 {
        let retry_after_ms = retry_after_seconds
            .unwrap_or_default()
            .saturating_mul(1_000)
            .min(self.backoff_max_ms);
        let exponential = self
            .backoff_initial_ms
            .saturating_mul(2_u64.saturating_pow(u32::from(retry_attempt)))
            .min(self.backoff_max_ms);
        exponential.max(retry_after_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchReadRequest {
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub bounds: DovetailReadBounds,
}

impl DovetailResearchReadRequest {
    pub fn for_scope(
        scope: &DovetailResearchScope,
        bounds: DovetailReadBounds,
    ) -> crate::Result<Self> {
        scope.validate()?;
        bounds.validate()?;
        Ok(Self {
            scope_digest: scope.scope_digest.clone(),
            provider_digest: scope.provider.digest.clone(),
            bounds,
        })
    }

    pub fn validate_against(&self, scope: &DovetailResearchScope) -> crate::Result<()> {
        self.bounds.validate()?;
        if self.scope_digest != scope.scope_digest {
            return Err(DovetailResearchResultError::ScopeMismatch);
        }
        if self.provider_digest != scope.provider.digest {
            return Err(DovetailResearchResultError::ProviderMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_non_native(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DovetailReadOperation {
    ListProjectMetadata,
    ListFolderMetadata,
    ListDataPointMetadata,
    ListHighlightSummaries,
    ListThemeTagSummaries,
    ListInsightMetadata,
    ListDocumentMetadata,
}

impl DovetailReadOperation {
    pub const ALL: [Self; 7] = [
        Self::ListProjectMetadata,
        Self::ListFolderMetadata,
        Self::ListDataPointMetadata,
        Self::ListHighlightSummaries,
        Self::ListThemeTagSummaries,
        Self::ListInsightMetadata,
        Self::ListDocumentMetadata,
    ];

    pub const fn path(self) -> &'static str {
        match self {
            Self::ListProjectMetadata => DOVETAIL_PROJECTS_PATH,
            Self::ListFolderMetadata => DOVETAIL_FOLDERS_PATH,
            Self::ListDataPointMetadata => DOVETAIL_DATA_PATH,
            Self::ListHighlightSummaries => DOVETAIL_HIGHLIGHTS_PATH,
            Self::ListThemeTagSummaries => DOVETAIL_TAGS_PATH,
            Self::ListInsightMetadata => DOVETAIL_INSIGHTS_PATH,
            Self::ListDocumentMetadata => DOVETAIL_DOCS_PATH,
        }
    }

    pub const fn permission(self) -> DovetailReadPermission {
        match self {
            Self::ListProjectMetadata => DovetailReadPermission::ProjectsRead,
            Self::ListFolderMetadata => DovetailReadPermission::FoldersRead,
            Self::ListDataPointMetadata => DovetailReadPermission::DataRead,
            Self::ListHighlightSummaries => DovetailReadPermission::HighlightsRead,
            Self::ListThemeTagSummaries => DovetailReadPermission::TagsRead,
            Self::ListInsightMetadata => DovetailReadPermission::InsightsRead,
            Self::ListDocumentMetadata => DovetailReadPermission::DocsRead,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchEvidenceState {
    Indexed,
    Processing,
    Present,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCompleteness {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectMetadata {
    pub id: DovetailProjectId,
    pub folder_id: Option<FolderId>,
    pub title_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolderMetadata {
    pub id: FolderId,
    pub parent_folder_id: Option<FolderId>,
    pub title_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataContentKind {
    Text,
    Audio,
    Video,
    File,
    Mixed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataPointMetadata {
    pub id: DataId,
    pub project_id: DovetailProjectId,
    pub folder_id: Option<FolderId>,
    pub title_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted: bool,
    pub content_kind: DataContentKind,
    pub raw_content_redacted: bool,
    pub transcript_redacted: bool,
    pub media_links_redacted: bool,
    pub participant_pii_redacted: bool,
    pub notes_and_comments_redacted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HighlightSummary {
    pub id: HighlightId,
    pub project_id: DovetailProjectId,
    pub data_id: DataId,
    pub tag_ids: Vec<TagId>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub position_digest: Option<Digest>,
    pub transcript_and_quote_redacted: bool,
    pub participant_pii_redacted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ThemeSummary {
    pub id: TagId,
    pub project_id: DovetailProjectId,
    pub label_digest: Option<Digest>,
    pub highlight_count: u32,
    pub data_count: Option<u32>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InsightMetadata {
    pub id: InsightId,
    pub project_id: Option<DovetailProjectId>,
    pub folder_id: Option<FolderId>,
    pub title_digest: Option<Digest>,
    pub body_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub body_redacted: bool,
    pub comments_redacted: bool,
    pub participant_pii_redacted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentMetadata {
    pub id: DocId,
    pub project_id: Option<DovetailProjectId>,
    pub folder_id: Option<FolderId>,
    pub title_digest: Option<Digest>,
    pub body_digest: Option<Digest>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub body_redacted: bool,
    pub comments_redacted: bool,
    pub participant_pii_redacted: bool,
    pub revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationCounts {
    pub projects: u32,
    pub folders: u32,
    pub data_points: u32,
    pub highlights: u32,
    pub themes: u32,
    pub insights: u32,
    pub documents: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevisionDigests {
    pub project: Digest,
    pub folder: Option<Digest>,
    pub data: Digest,
    pub highlights: Digest,
    pub themes: Digest,
    pub insights: Digest,
    pub documents: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DovetailResearchObservation {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
    pub state: ResearchEvidenceState,
    pub completeness: ObservationCompleteness,
    pub projects: Vec<ProjectMetadata>,
    pub folders: Vec<FolderMetadata>,
    pub data_points: Vec<DataPointMetadata>,
    pub highlights: Vec<HighlightSummary>,
    pub themes: Vec<ThemeSummary>,
    pub insights: Vec<InsightMetadata>,
    pub documents: Vec<DocumentMetadata>,
    pub counts: ObservationCounts,
    pub revision_digests: RevisionDigests,
    pub response_digests: BTreeMap<String, Digest>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u16,
    pub raw_provider_payload_retained: bool,
    pub transcripts_retained: bool,
    pub media_retained: bool,
    pub participant_pii_retained: bool,
    pub raw_notes_or_comments_retained: bool,
    pub free_form_bodies_retained: bool,
    pub sentiment_claim: bool,
    pub theme_absence_proves_completeness: bool,
    pub result_digest: Digest,
}

impl DovetailResearchObservation {
    pub fn calculate_result_digest(&self) -> Digest {
        let identity = (
            &self.schema_version,
            &self.scope_digest,
            &self.provider_id,
            &self.provider_digest,
            self.provenance,
            self.state,
            self.completeness,
        );
        let resources = (
            &self.projects,
            &self.folders,
            &self.data_points,
            &self.highlights,
            &self.themes,
            &self.insights,
            &self.documents,
        );
        let digests_and_counts = (
            &self.counts,
            &self.revision_digests,
            &self.response_digests,
            self.page_count,
            self.request_count,
            self.retry_count,
        );
        let redaction_flags = (
            self.raw_provider_payload_retained,
            self.transcripts_retained,
            self.media_retained,
            self.participant_pii_retained,
            self.raw_notes_or_comments_retained,
            self.free_form_bodies_retained,
            self.sentiment_claim,
            self.theme_absence_proves_completeness,
        );
        Digest::from_serialized(&(identity, resources, digests_and_counts, redaction_flags))
    }

    pub fn validate_integrity(&self) -> crate::Result<()> {
        if self.schema_version != crate::CONTRACT_SCHEMA
            || self.provider_id != "DovetailProvider"
            || self.raw_provider_payload_retained
            || self.transcripts_retained
            || self.media_retained
            || self.participant_pii_retained
            || self.raw_notes_or_comments_retained
            || self.free_form_bodies_retained
            || self.sentiment_claim
            || self.theme_absence_proves_completeness
            || !self.provenance.is_non_native()
            || self.result_digest != self.calculate_result_digest()
        {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        let expected_counts = ObservationCounts {
            projects: cap_u32(self.projects.len()),
            folders: cap_u32(self.folders.len()),
            data_points: cap_u32(self.data_points.len()),
            highlights: cap_u32(self.highlights.len()),
            themes: cap_u32(self.themes.len()),
            insights: cap_u32(self.insights.len()),
            documents: cap_u32(self.documents.len()),
        };
        let expected_revisions = RevisionDigests {
            project: digest_values(&self.projects),
            folder: if self.folders.is_empty() {
                None
            } else {
                Some(digest_values(&self.folders))
            },
            data: digest_values(&self.data_points),
            highlights: digest_values(&self.highlights),
            themes: digest_values(&self.themes),
            insights: digest_values(&self.insights),
            documents: digest_values(&self.documents),
        };
        if self.counts != expected_counts || self.revision_digests != expected_revisions {
            return Err(DovetailResearchResultError::TamperedResult);
        }
        self.scope_digest.validate("scopeDigest")?;
        self.provider_digest.validate("providerDigest")?;
        self.revision_digests
            .project
            .validate("projectRevisionDigest")?;
        if let Some(folder) = &self.revision_digests.folder {
            folder.validate("folderRevisionDigest")?;
        }
        self.revision_digests.data.validate("dataRevisionDigest")?;
        self.revision_digests
            .highlights
            .validate("highlightRevisionDigest")?;
        self.revision_digests
            .themes
            .validate("themeRevisionDigest")?;
        self.revision_digests
            .insights
            .validate("insightRevisionDigest")?;
        self.revision_digests
            .documents
            .validate("documentRevisionDigest")?;
        Ok(())
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn can_claim_sentiment(&self) -> bool {
        false
    }
}

pub(crate) fn bounded_timestamp(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        if value.is_empty()
            || value.len() > MAX_TIMESTAMP_BYTES
            || value.chars().any(char::is_control)
        {
            None
        } else {
            Some(value.to_owned())
        }
    })
}

pub(crate) fn digest_optional_text(value: Option<&str>) -> Option<Digest> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(Digest::from_text)
}

pub(crate) fn digest_values<T: Serialize>(values: &[T]) -> Digest {
    Digest::from_serialized(values)
}

pub(crate) fn cap_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
