use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::SharePointKnowledgeResultError;

pub type Digest = String;

pub const GRAPH_API_VERSION: &str = "v1.0";
pub const SHAREPOINT_PLUGIN_VERSION: &str = "1.0.0";
pub const SHAREPOINT_CONTRACT_VERSION: &str = "EXT-SHAREPOINT-KNOWLEDGE-01-L1/v1";
pub const SHAREPOINT_PROVIDER_REVISION: &str = "microsoft-graph-v1.0-sharepoint-r1";
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RESPONSE_FIELD_BYTES: usize = 4_096;
pub const MAX_PAGES: u16 = 4;
pub const PAGE_SIZE: u16 = 50;
pub const MAX_CHILDREN: usize = 256;
pub const MAX_SEARCH_HITS: usize = 128;
pub const MAX_VERSIONS: usize = 64;
pub const MAX_DELTA_ENTRIES: usize = 256;
pub const MAX_QUERY_BYTES: usize = 512;

pub fn sha256_digest(value: impl AsRef<[u8]>) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    format!("{:x}", hasher.finalize())
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    let encoded = serde_json::to_vec(value).expect("canonical digest input is serializable");
    sha256_digest(encoded)
}

pub fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> Digest {
    let mut encoded = Vec::new();
    for part in parts {
        encoded.extend_from_slice(part.as_bytes());
        encoded.push(0);
    }
    sha256_digest(encoded)
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

macro_rules! opaque_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, SharePointKnowledgeResultError> {
                let value = value.into();
                if value.trim().is_empty() || value.len() > 256 {
                    return Err(SharePointKnowledgeResultError::InvalidInput {
                        field: $field,
                        reason: String::from("must be non-empty and bounded"),
                    });
                }
                if value.chars().any(char::is_control) {
                    return Err(SharePointKnowledgeResultError::InvalidInput {
                        field: $field,
                        reason: String::from("must not contain control characters"),
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }

            pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
                Self::new(self.0.clone())
                    .map(|_| ())
                    .map_err(|_| SharePointKnowledgeResultError::InvalidScope)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

opaque_id!(TenantId, "tenantId");
opaque_id!(SiteId, "siteId");
opaque_id!(DriveId, "driveId");
opaque_id!(ListId, "listId");
opaque_id!(DriveItemId, "itemId");
opaque_id!(ItemVersionId, "itemVersion");
opaque_id!(ProjectId, "projectId");
opaque_id!(MissionId, "missionId");
opaque_id!(WorkProductId, "workProductId");
opaque_id!(ConsentId, "consentId");

/// Host-owned Entra secret locator. It intentionally has no Serialize or
/// Deserialize implementation, and its Debug output contains only a digest.
#[derive(Clone, Eq, PartialEq)]
pub struct EntraSecretReference {
    reference_id: String,
    tenant_id: String,
    client_id: String,
    revision: u64,
    reference_digest: Digest,
}

pub type SecretReference = EntraSecretReference;

impl fmt::Debug for EntraSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraSecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl EntraSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let reference_id = reference_id.into();
        let tenant_id = tenant_id.into();
        let client_id = client_id.into();
        if reference_id.trim().is_empty()
            || tenant_id.trim().is_empty()
            || client_id.trim().is_empty()
            || revision == 0
            || reference_id.chars().any(char::is_control)
            || tenant_id.chars().any(char::is_control)
            || client_id.chars().any(char::is_control)
        {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "entraSecretReference",
                reason: String::from("locator fields must be non-empty and bounded"),
            });
        }
        let reference_digest = digest_parts([
            reference_id.as_str(),
            tenant_id.as_str(),
            client_id.as_str(),
            &revision.to_string(),
        ]);
        Ok(Self {
            reference_id,
            tenant_id,
            client_id,
            revision,
            reference_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        let expected = digest_parts([
            self.reference_id.as_str(),
            self.tenant_id.as_str(),
            self.client_id.as_str(),
            &self.revision.to_string(),
        ]);
        if self.revision == 0 || self.reference_digest != expected {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

/// Microsoft Graph national-cloud selection is part of the immutable scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NationalCloud {
    Global,
    UsGovernment,
    UsGovernmentDod,
    China,
}

impl NationalCloud {
    pub const fn api_origin(self) -> &'static str {
        match self {
            Self::Global => "https://graph.microsoft.com",
            Self::UsGovernment => "https://graph.microsoft.us",
            Self::UsGovernmentDod => "https://dod-graph.microsoft.us",
            Self::China => "https://microsoftgraph.chinacloudapi.cn",
        }
    }
}

/// SharePoint host is safe to retain as a routing fence; item names, paths,
/// content, and authorization values are not retained by Layer 1.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SiteHostname(String);

impl SiteHostname {
    pub fn new(value: impl Into<String>) -> Result<Self, SharePointKnowledgeResultError> {
        let value = value.into().to_ascii_lowercase();
        if value.trim().is_empty()
            || value.len() > 253
            || value.contains('/')
            || value.contains(' ')
            || value.chars().any(char::is_control)
        {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "siteHostname",
                reason: String::from("must be a bounded hostname"),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        let canonical =
            Self::new(self.0.clone()).map_err(|_| SharePointKnowledgeResultError::InvalidScope)?;
        if canonical != *self {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

impl fmt::Display for SiteHostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Opaque provenance. There is deliberately no Connected or Native variant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_layer1_sealed(self) -> bool {
        matches!(
            self,
            Self::Recording | Self::Fixture | Self::Loopback | Self::BlockedEnv
        )
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn native_connected_claim(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeProbeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProbe {
    pub status: NativeProbeStatus,
    pub native_connected_claim: bool,
}

/// Capabilities are consent-scoped read operations only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePointCapability {
    DescribeScope,
    ReadDriveItemMetadata,
    ReadDriveItemChildren,
    SearchDriveItems,
    ReadDriveItemVersions,
    ReadDriveItemDelta,
    CompileKnowledgeResult,
}

impl SharePointCapability {
    pub const fn all_layer1() -> [Self; 7] {
        [
            Self::DescribeScope,
            Self::ReadDriveItemMetadata,
            Self::ReadDriveItemChildren,
            Self::SearchDriveItems,
            Self::ReadDriveItemVersions,
            Self::ReadDriveItemDelta,
            Self::CompileKnowledgeResult,
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub consent_id: ConsentId,
    pub policy_revision: u64,
    pub capabilities: Vec<SharePointCapability>,
    pub consent_scope_digest: Digest,
}

impl ConsentScope {
    pub fn new(
        consent_id: impl Into<String>,
        policy_revision: u64,
        capabilities: impl IntoIterator<Item = SharePointCapability>,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let consent_id = ConsentId::new(consent_id)?;
        if policy_revision == 0 {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "consent policyRevision",
                reason: String::from("must be non-zero"),
            });
        }
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "consent capabilities",
                reason: String::from("must grant at least one bounded capability"),
            });
        }
        let capabilities = capabilities.iter().copied().collect::<Vec<_>>();
        let consent_scope_digest = canonical_digest(&(&consent_id, policy_revision, &capabilities));
        Ok(Self {
            consent_id,
            policy_revision,
            capabilities,
            consent_scope_digest,
        })
    }

    pub fn permits(&self, capability: SharePointCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn digest(&self) -> Digest {
        self.consent_scope_digest.clone()
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        if self.consent_id.validate().is_err()
            || self.policy_revision == 0
            || self.capabilities.is_empty()
            || self
                .capabilities
                .windows(2)
                .any(|window| window[0] >= window[1])
            || self.consent_scope_digest
                != canonical_digest(&(&self.consent_id, self.policy_revision, &self.capabilities))
        {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointSearchScope {
    pub root_item_id: Option<DriveItemId>,
    pub allow_name_match: bool,
    pub allow_content_match: bool,
    pub max_query_bytes: usize,
    pub policy_revision: u64,
    pub search_scope_digest: Digest,
}

impl SharePointSearchScope {
    pub fn new(
        root_item_id: Option<DriveItemId>,
        allow_name_match: bool,
        allow_content_match: bool,
        max_query_bytes: usize,
        policy_revision: u64,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        if max_query_bytes == 0 || max_query_bytes > MAX_QUERY_BYTES || policy_revision == 0 {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "search scope",
                reason: String::from("query bound and policy revision are invalid"),
            });
        }
        if !allow_name_match && !allow_content_match {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "search scope",
                reason: String::from("at least one search field must be allowed"),
            });
        }
        let search_scope_digest = canonical_digest(&(
            &root_item_id,
            allow_name_match,
            allow_content_match,
            max_query_bytes,
            policy_revision,
        ));
        Ok(Self {
            root_item_id,
            allow_name_match,
            allow_content_match,
            max_query_bytes,
            policy_revision,
            search_scope_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        self.search_scope_digest.clone()
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        if self
            .root_item_id
            .as_ref()
            .is_some_and(|item_id| item_id.validate().is_err())
        {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        let expected = Self::new(
            self.root_item_id.clone(),
            self.allow_name_match,
            self.allow_content_match,
            self.max_query_bytes,
            self.policy_revision,
        )?
        .search_scope_digest;
        if self.search_scope_digest != expected {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointPermissionScope {
    pub permission_digest: Digest,
    pub metadata_read: bool,
    pub children_read: bool,
    pub search_read: bool,
    pub versions_read: bool,
    pub delta_read: bool,
}

impl SharePointPermissionScope {
    pub fn read_only(
        permission_digest: impl Into<String>,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let permission_digest = permission_digest.into();
        if !is_sha256(&permission_digest) {
            return Err(SharePointKnowledgeResultError::InvalidDigest {
                field: "permissionDigest",
            });
        }
        Ok(Self {
            permission_digest,
            metadata_read: true,
            children_read: true,
            search_read: true,
            versions_read: true,
            delta_read: true,
        })
    }

    pub fn digest(&self) -> &str {
        &self.permission_digest
    }

    pub fn permits(&self, capability: SharePointCapability) -> bool {
        match capability {
            SharePointCapability::DescribeScope | SharePointCapability::CompileKnowledgeResult => {
                true
            }
            SharePointCapability::ReadDriveItemMetadata => self.metadata_read,
            SharePointCapability::ReadDriveItemChildren => self.children_read,
            SharePointCapability::SearchDriveItems => self.search_read,
            SharePointCapability::ReadDriveItemVersions => self.versions_read,
            SharePointCapability::ReadDriveItemDelta => self.delta_read,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeScopeInput {
    pub tenant_id: String,
    pub national_cloud: NationalCloud,
    pub site_id: String,
    pub site_hostname: String,
    pub drive_id: String,
    pub list_id: String,
    pub item_id: String,
    pub item_version: String,
    pub search_scope: SharePointSearchScope,
    pub permission_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_scope: ConsentScope,
}

pub type SharePointScopeInput = SharePointKnowledgeScopeInput;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeScope {
    pub tenant_id: TenantId,
    pub national_cloud: NationalCloud,
    pub site_id: SiteId,
    pub site_hostname: SiteHostname,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub item_version: ItemVersionId,
    pub search_scope: SharePointSearchScope,
    pub permission_digest: Digest,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub consent_scope: ConsentScope,
}

pub type SharePointScope = SharePointKnowledgeScope;

impl SharePointKnowledgeScope {
    pub fn new(
        input: SharePointKnowledgeScopeInput,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        let scope = Self {
            tenant_id: TenantId::new(input.tenant_id)?,
            national_cloud: input.national_cloud,
            site_id: SiteId::new(input.site_id)?,
            site_hostname: SiteHostname::new(input.site_hostname)?,
            drive_id: DriveId::new(input.drive_id)?,
            list_id: ListId::new(input.list_id)?,
            item_id: DriveItemId::new(input.item_id)?,
            item_version: ItemVersionId::new(input.item_version)?,
            search_scope: input.search_scope,
            permission_digest: input.permission_digest,
            project_id: ProjectId::new(input.project_id)?,
            mission_id: MissionId::new(input.mission_id)?,
            work_product_id: WorkProductId::new(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
            consent_scope: input.consent_scope,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn permission_scope(
        &self,
    ) -> Result<SharePointPermissionScope, SharePointKnowledgeResultError> {
        SharePointPermissionScope::read_only(self.permission_digest.clone())
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.tenant_id.validate()?;
        self.site_id.validate()?;
        self.site_hostname.validate()?;
        self.drive_id.validate()?;
        self.list_id.validate()?;
        self.item_id.validate()?;
        self.item_version.validate()?;
        self.project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        if self.work_product_revision == 0 || !is_sha256(&self.permission_digest) {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        self.search_scope.validate()?;
        self.consent_scope.validate()?;
        Ok(())
    }

    pub fn permits(&self, capability: SharePointCapability) -> bool {
        self.consent_scope.permits(capability)
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointProviderManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: u64,
    pub provider_revision: String,
    pub api_version: String,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub native_transport: bool,
    pub native_connected: bool,
    pub raw_bytes: bool,
    pub download_urls: bool,
    pub pii: bool,
    pub manifest_digest: Digest,
}

impl SharePointProviderManifest {
    pub fn layer1(scope: &SharePointKnowledgeScope) -> Self {
        let mut manifest = Self {
            schema_version: crate::SHAREPOINT_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: crate::SHAREPOINT_PROVIDER_ID.to_owned(),
            provider_version: 1,
            provider_revision: crate::SHAREPOINT_PROVIDER_REVISION.to_owned(),
            api_version: GRAPH_API_VERSION.to_owned(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            operations: vec![
                String::from("driveItem.metadata"),
                String::from("driveItem.children"),
                String::from("driveItem.search"),
                String::from("driveItem.versions"),
                String::from("driveItem.delta"),
            ],
            read_only: true,
            native_transport: false,
            native_connected: false,
            raw_bytes: false,
            download_urls: false,
            pii: false,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        manifest
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.schema_version,
            &self.provider_id,
            self.provider_version,
            &self.provider_revision,
            &self.api_version,
            &self.scope_digest,
            &self.permission_digest,
            &self.operations,
            self.read_only,
            self.native_transport,
            self.native_connected,
            self.raw_bytes,
            self.download_urls,
            self.pii,
        ))
    }

    pub fn digest(&self) -> Digest {
        self.manifest_digest.clone()
    }

    pub fn validate(
        &self,
        scope: &SharePointKnowledgeScope,
    ) -> Result<(), SharePointKnowledgeResultError> {
        scope.validate()?;
        let expected = Self::layer1(scope);
        if self != &expected {
            return Err(SharePointKnowledgeResultError::InvalidProviderManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revocation_revision: u64,
    pub revoked: bool,
}

/// Registration is a reversible/revocable, fail-closed binding. The opaque
/// secret itself lives only in the provider and contributes by digest here.
#[allow(clippy::struct_excessive_bools, clippy::needless_pass_by_value)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointPluginRegistration {
    pub plugin_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: u64,
    pub provider_revision: String,
    pub provider_manifest_digest: Digest,
    pub scope: SharePointKnowledgeScope,
    pub tenant_digest: Digest,
    pub national_cloud: NationalCloud,
    pub site_digest: Digest,
    pub drive_digest: Digest,
    pub list_digest: Digest,
    pub item_digest: Digest,
    pub version_digest: Digest,
    pub search_scope_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_scope_digest: Digest,
    pub entra_secret_reference_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on_drift: bool,
    pub registration_revision: u64,
    pub active: bool,
    pub registration_digest: Digest,
}

pub type SharePointRegistration = SharePointPluginRegistration;

impl SharePointPluginRegistration {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        scope: SharePointKnowledgeScope,
        secret_reference: EntraSecretReference,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        scope.validate()?;
        secret_reference.validate()?;
        let secret_reference_digest = secret_reference.digest();
        let manifest = SharePointProviderManifest::layer1(&scope);
        let mut registration = Self {
            plugin_id: crate::SHAREPOINT_PLUGIN_ID.to_owned(),
            plugin_version: SHAREPOINT_PLUGIN_VERSION.to_owned(),
            contract_version: SHAREPOINT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::SHAREPOINT_PROVIDER_ID.to_owned(),
            provider_version: 1,
            provider_revision: SHAREPOINT_PROVIDER_REVISION.to_owned(),
            provider_manifest_digest: manifest.digest(),
            scope: scope.clone(),
            tenant_digest: scope.tenant_id.digest(),
            national_cloud: scope.national_cloud,
            site_digest: scope.site_id.digest(),
            drive_digest: scope.drive_id.digest(),
            list_digest: scope.list_id.digest(),
            item_digest: scope.item_id.digest(),
            version_digest: scope.item_version.digest(),
            search_scope_digest: scope.search_scope.digest(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.digest(),
            project_digest: scope.project_id.digest(),
            mission_digest: scope.mission_id.digest(),
            work_product_digest: scope.work_product_id.digest(),
            consent_scope_digest: scope.consent_scope.digest(),
            entra_secret_reference_digest: secret_reference_digest,
            reversible: true,
            revocable: true,
            fail_closed_on_drift: true,
            registration_revision: 1,
            active: true,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            &self.plugin_id,
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            self.provider_version,
            &self.provider_revision,
            &self.provider_manifest_digest,
            &self.scope,
            &self.tenant_digest,
            self.national_cloud,
            &self.site_digest,
            &self.drive_digest,
            &self.list_digest,
            &self.item_digest,
            &self.version_digest,
            &self.search_scope_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
            &self.consent_scope_digest,
            &self.entra_secret_reference_digest,
            self.reversible,
            self.revocable,
            self.fail_closed_on_drift,
            self.registration_revision,
            self.active,
        ]))
    }

    pub fn validate(
        &self,
        scope: &SharePointKnowledgeScope,
        provider_manifest: &SharePointProviderManifest,
    ) -> Result<(), SharePointKnowledgeResultError> {
        scope.validate()?;
        provider_manifest.validate(scope)?;
        if self.plugin_id != crate::SHAREPOINT_PLUGIN_ID
            || self.plugin_version != SHAREPOINT_PLUGIN_VERSION
            || self.contract_version != SHAREPOINT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::SHAREPOINT_PROVIDER_ID
            || self.provider_version != 1
            || self.provider_revision != SHAREPOINT_PROVIDER_REVISION
            || self.provider_manifest_digest != provider_manifest.digest()
            || self.scope.digest() != scope.digest()
            || self.tenant_digest != scope.tenant_id.digest()
            || self.national_cloud != scope.national_cloud
            || self.site_digest != scope.site_id.digest()
            || self.drive_digest != scope.drive_id.digest()
            || self.list_digest != scope.list_id.digest()
            || self.item_digest != scope.item_id.digest()
            || self.version_digest != scope.item_version.digest()
            || self.search_scope_digest != scope.search_scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.scope_digest != scope.digest()
            || self.project_digest != scope.project_id.digest()
            || self.mission_digest != scope.mission_id.digest()
            || self.work_product_digest != scope.work_product_id.digest()
            || self.consent_scope_digest != scope.consent_scope.digest()
            || !self.reversible
            || !self.revocable
            || !self.fail_closed_on_drift
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        scope: &SharePointKnowledgeScope,
        provider_manifest: &SharePointProviderManifest,
    ) -> Result<RegistrationRevocation, SharePointKnowledgeResultError> {
        self.validate(scope, provider_manifest)?;
        if !self.active {
            return Err(SharePointKnowledgeResultError::RegistrationRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(SharePointKnowledgeResultError::InvalidScope)?;
        self.active = false;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revocation_revision: self.registration_revision,
            revoked: true,
        })
    }
}

/// The query is accepted at the transport edge but is deliberately opaque
/// and cannot be serialized or printed as text.
#[derive(Clone, Eq, PartialEq)]
pub struct SearchQuery(String);

impl fmt::Debug for SearchQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchQuery")
            .field("digest", &self.digest())
            .field("byte_length", &self.0.len())
            .finish()
    }
}

impl SearchQuery {
    pub fn new(value: impl Into<String>) -> Result<Self, SharePointKnowledgeResultError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > MAX_QUERY_BYTES {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "searchQuery",
                reason: String::from("must be non-empty and bounded"),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "searchQuery",
                reason: String::from("must not contain control characters"),
            });
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueGraphNextLink {
    digest: Digest,
}

impl fmt::Debug for OpaqueGraphNextLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueGraphNextLink")
            .field("digest", &self.digest)
            .field("redacted", &true)
            .finish()
    }
}

impl OpaqueGraphNextLink {
    pub fn new(value: impl Into<String>) -> Result<Self, SharePointKnowledgeResultError> {
        let value = value.into();
        if value.len() > 4096
            || !value.starts_with("https://")
            || value.chars().any(char::is_control)
        {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "@odata.nextLink",
                reason: String::from("must be a bounded HTTPS URL"),
            });
        }
        let digest = sha256_digest(value.as_bytes());
        Ok(Self { digest })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn is_redacted(&self) -> bool {
        true
    }
}

impl Serialize for OpaqueGraphNextLink {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Redacted<'a> {
            present: bool,
            digest: &'a str,
        }
        Redacted {
            present: true,
            digest: &self.digest,
        }
        .serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriveItemKind {
    File,
    Folder,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaChange {
    Upserted,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemSummary {
    pub item_id: DriveItemId,
    pub parent_item_id: Option<DriveItemId>,
    pub kind: DriveItemKind,
    pub size_bytes: Option<u64>,
    pub name_digest: Digest,
    pub e_tag_digest: Digest,
    pub version: ItemVersionId,
    pub permission_digest: Digest,
    pub item_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemMetadata {
    pub item: DriveItemSummary,
    pub list_id: ListId,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemSearchHit {
    pub item_id: DriveItemId,
    pub version: ItemVersionId,
    pub name_digest: Digest,
    pub path_digest: Digest,
    pub rank: u32,
    pub permission_digest: Digest,
    pub hit_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemVersion {
    pub item_id: DriveItemId,
    pub version_id: ItemVersionId,
    pub modified_at_epoch_seconds: u64,
    pub version_digest: Digest,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemDeltaEntry {
    pub item_id: DriveItemId,
    pub change: DeltaChange,
    pub item_digest: Digest,
    pub version: Option<ItemVersionId>,
    pub permission_digest: Digest,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceEnvelope {
    pub scope_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: String,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub raw_bytes_retained: bool,
    pub download_url_retained: bool,
    pub pii_retained: bool,
}

impl EvidenceEnvelope {
    pub fn layer1(
        scope_digest: Digest,
        provider_manifest_digest: Digest,
        registration_digest: Digest,
        evidence_source: ProviderProvenance,
    ) -> Self {
        Self {
            scope_digest,
            provider_manifest_digest,
            registration_digest,
            provider_revision: SHAREPOINT_PROVIDER_REVISION.to_owned(),
            evidence_source,
            native_transport: false,
            native_connected: false,
            raw_bytes_retained: false,
            download_url_retained: false,
            pii_retained: false,
        }
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        if !is_sha256(&self.scope_digest)
            || !is_sha256(&self.provider_manifest_digest)
            || !is_sha256(&self.registration_digest)
            || !self.evidence_source.is_layer1_sealed()
            || self.provider_revision != SHAREPOINT_PROVIDER_REVISION
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
            || self.native_transport
            || self.native_connected
            || self.raw_bytes_retained
            || self.download_url_retained
            || self.pii_retained
        {
            return Err(SharePointKnowledgeResultError::ExternalWriteAuthority);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemMetadataEvidence {
    pub envelope: EvidenceEnvelope,
    pub metadata: DriveItemMetadata,
    pub next_link_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemChildrenEvidence {
    pub envelope: EvidenceEnvelope,
    pub item_id: DriveItemId,
    pub children: Vec<DriveItemSummary>,
    pub page_count: u16,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemSearchEvidence {
    pub envelope: EvidenceEnvelope,
    pub query_digest: Digest,
    pub hits: Vec<DriveItemSearchHit>,
    pub page_count: u16,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemVersionsEvidence {
    pub envelope: EvidenceEnvelope,
    pub item_id: DriveItemId,
    pub versions: Vec<DriveItemVersion>,
    pub page_count: u16,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemDeltaEvidence {
    pub envelope: EvidenceEnvelope,
    pub item_id: DriveItemId,
    pub entries: Vec<DriveItemDeltaEntry>,
    pub page_count: u16,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

macro_rules! evidence_digest_impl {
    ($type:ty) => {
        impl $type {
            pub fn digest(&self) -> &str {
                &self.evidence_digest
            }
        }
    };
}

evidence_digest_impl!(DriveItemMetadataEvidence);
evidence_digest_impl!(DriveItemChildrenEvidence);
evidence_digest_impl!(DriveItemSearchEvidence);
evidence_digest_impl!(DriveItemVersionsEvidence);
evidence_digest_impl!(DriveItemDeltaEvidence);

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeEvidence {
    pub scope: SharePointKnowledgeScope,
    pub metadata: DriveItemMetadataEvidence,
    pub children: Option<DriveItemChildrenEvidence>,
    pub search: Option<DriveItemSearchEvidence>,
    pub versions: Option<DriveItemVersionsEvidence>,
    pub delta: Option<DriveItemDeltaEvidence>,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub native_connected: bool,
    pub raw_bytes_retained: bool,
    pub download_url_retained: bool,
    pub pii_retained: bool,
    pub evidence_digest: Digest,
}

impl SharePointKnowledgeEvidence {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.metadata,
            &self.children,
            &self.search,
            &self.versions,
            &self.delta,
            &self.provider_manifest_digest,
            &self.registration_digest,
            self.evidence_source,
            self.native_connected,
            self.raw_bytes_retained,
            self.download_url_retained,
            self.pii_retained,
        ))
    }

    pub fn digest(&self) -> &str {
        &self.evidence_digest
    }

    #[allow(clippy::collapsible_if, clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.scope.validate()?;
        self.metadata.envelope.validate()?;
        if self
            .children
            .as_ref()
            .is_some_and(|value| value.children.len() > MAX_CHILDREN)
            || self
                .search
                .as_ref()
                .is_some_and(|value| value.hits.len() > MAX_SEARCH_HITS)
            || self
                .versions
                .as_ref()
                .is_some_and(|value| value.versions.len() > MAX_VERSIONS)
            || self
                .delta
                .as_ref()
                .is_some_and(|value| value.entries.len() > MAX_DELTA_ENTRIES)
        {
            return Err(SharePointKnowledgeResultError::InvalidEvidence);
        }
        if !is_sha256(&self.provider_manifest_digest)
            || !is_sha256(&self.registration_digest)
            || self.metadata.envelope.scope_digest != self.scope.digest()
            || self.metadata.envelope.provider_manifest_digest != self.provider_manifest_digest
            || self.metadata.envelope.registration_digest != self.registration_digest
            || self.evidence_source != self.metadata.envelope.evidence_source
            || self.native_connected
            || self.raw_bytes_retained
            || self.download_url_retained
            || self.pii_retained
            || !self.evidence_source.is_layer1_sealed()
            || self.metadata.metadata.list_id != self.scope.list_id
            || self.metadata.metadata.item.item_id != self.scope.item_id
            || self.metadata.metadata.item.version != self.scope.item_version
            || self.metadata.metadata.item.permission_digest != self.scope.permission_digest
            || self
                .metadata
                .next_link_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.metadata.metadata.metadata_digest
                != canonical_digest(&(
                    &self.metadata.metadata.item,
                    &self.metadata.metadata.list_id,
                ))
            || self.metadata.metadata.item.item_digest
                != summary_digest(&self.metadata.metadata.item)
            || self.metadata.evidence_digest
                != canonical_digest(&(
                    &self.metadata.envelope,
                    &self.metadata.metadata,
                    &self.metadata.next_link_digest,
                ))
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
        }
        if !valid_cursor_digests(
            self.children
                .as_ref()
                .map(|value| (value.cursor_digests.as_slice(), value.page_count)),
        ) || !valid_cursor_digests(
            self.search
                .as_ref()
                .map(|value| (value.cursor_digests.as_slice(), value.page_count)),
        ) || !valid_cursor_digests(
            self.versions
                .as_ref()
                .map(|value| (value.cursor_digests.as_slice(), value.page_count)),
        ) || !valid_cursor_digests(
            self.delta
                .as_ref()
                .map(|value| (value.cursor_digests.as_slice(), value.page_count)),
        ) {
            return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
        }
        if let Some(children) = &self.children {
            if children.item_id.validate().is_err()
                || children.item_id != self.scope.item_id
                || children
                    .children
                    .iter()
                    .any(|item| !valid_summary(item, &self.scope.permission_digest))
                || children.evidence_digest
                    != canonical_digest(&(
                        &children.envelope,
                        &children.item_id,
                        &children.children,
                        children.page_count,
                        &children.cursor_digests,
                    ))
            {
                return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
            }
        }
        if let Some(search) = &self.search {
            if !is_sha256(&search.query_digest)
                || search.hits.iter().any(|hit| {
                    hit.item_id.validate().is_err()
                        || hit.version.validate().is_err()
                        || !is_sha256(&hit.name_digest)
                        || !is_sha256(&hit.path_digest)
                        || !is_sha256(&hit.hit_digest)
                        || hit.permission_digest != self.scope.permission_digest
                        || hit.hit_digest
                            != canonical_digest(&(
                                &hit.item_id,
                                &hit.version,
                                &hit.name_digest,
                                &hit.path_digest,
                                hit.rank,
                                &hit.permission_digest,
                            ))
                })
                || search.evidence_digest
                    != canonical_digest(&(
                        &search.envelope,
                        &search.query_digest,
                        &search.hits,
                        search.page_count,
                        &search.cursor_digests,
                    ))
            {
                return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
            }
        }
        if let Some(versions) = &self.versions {
            if versions.item_id != self.scope.item_id
                || versions.versions.iter().any(|version| {
                    version.item_id.validate().is_err()
                        || version.version_id.validate().is_err()
                        || !is_sha256(&version.version_digest)
                        || version.item_id != self.scope.item_id
                        || version.permission_digest != self.scope.permission_digest
                })
                || versions.evidence_digest
                    != canonical_digest(&(
                        &versions.envelope,
                        &versions.item_id,
                        &versions.versions,
                        versions.page_count,
                        &versions.cursor_digests,
                    ))
            {
                return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
            }
        }
        if let Some(delta) = &self.delta {
            if delta.item_id != self.scope.item_id
                || delta.entries.iter().any(|entry| {
                    entry.item_id.validate().is_err()
                        || entry
                            .version
                            .as_ref()
                            .is_some_and(|version| version.validate().is_err())
                        || !is_sha256(&entry.item_digest)
                        || entry.item_id != self.scope.item_id
                        || entry.permission_digest != self.scope.permission_digest
                })
                || delta.evidence_digest
                    != canonical_digest(&(
                        &delta.envelope,
                        &delta.item_id,
                        &delta.entries,
                        delta.page_count,
                        &delta.cursor_digests,
                    ))
            {
                return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
            }
        }
        for envelope in [
            self.children.as_ref().map(|value| &value.envelope),
            self.search.as_ref().map(|value| &value.envelope),
            self.versions.as_ref().map(|value| &value.envelope),
            self.delta.as_ref().map(|value| &value.envelope),
        ]
        .into_iter()
        .flatten()
        {
            envelope.validate()?;
            if envelope.scope_digest != self.scope.digest()
                || envelope.provider_manifest_digest != self.provider_manifest_digest
                || envelope.registration_digest != self.registration_digest
                || envelope.evidence_source != self.evidence_source
            {
                return Err(SharePointKnowledgeResultError::EvidenceDigestMismatch);
            }
        }
        Ok(())
    }
}

fn valid_cursor_digests(projection: Option<(&[Digest], u16)>) -> bool {
    projection.is_none_or(|(digests, page_count)| {
        page_count > 0
            && page_count <= MAX_PAGES
            && digests.len() == usize::from(page_count.saturating_sub(1))
            && digests.iter().all(|digest| is_sha256(digest))
    })
}

fn valid_summary(summary: &DriveItemSummary, permission_digest: &str) -> bool {
    summary.item_id.validate().is_ok()
        && summary
            .parent_item_id
            .as_ref()
            .is_none_or(|item_id| item_id.validate().is_ok())
        && summary.version.validate().is_ok()
        && is_sha256(&summary.name_digest)
        && is_sha256(&summary.e_tag_digest)
        && is_sha256(&summary.permission_digest)
        && summary.permission_digest == permission_digest
        && summary.item_digest == summary_digest(summary)
}

fn summary_digest(summary: &DriveItemSummary) -> Digest {
    canonical_digest(&(
        &summary.item_id,
        &summary.parent_item_id,
        summary.kind,
        summary.size_bytes,
        &summary.name_digest,
        &summary.e_tag_digest,
        &summary.version,
        &summary.permission_digest,
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProduct {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub revision: u64,
    pub content_digest: Digest,
}

impl MissionWorkProduct {
    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        if self.project_id.validate().is_err()
            || self.mission_id.validate().is_err()
            || self.work_product_id.validate().is_err()
            || self.revision == 0
            || !is_sha256(&self.content_digest)
        {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "work product",
                reason: String::from("revision and content digest are required"),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeResultStatus {
    Proposed,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeResultProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub evidence_digest: Digest,
    pub metadata_digest: Digest,
    pub children_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
    pub versions_digest: Option<Digest>,
    pub delta_digest: Option<Digest>,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub status: KnowledgeResultStatus,
    pub non_mutating: bool,
    pub external_write_performed: bool,
    pub durable_native_receipt: bool,
    pub native_connected: bool,
}

pub type KnowledgeResultProposal = SharePointKnowledgeResultProposal;

impl SharePointKnowledgeResultProposal {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            &self.proposal_id,
            &self.scope_digest,
            &self.project_id,
            &self.mission_id,
            &self.work_product_id,
            self.work_product_revision,
            &self.evidence_digest,
            &self.metadata_digest,
            &self.children_digest,
            &self.search_digest,
            &self.versions_digest,
            &self.delta_digest,
            &self.provider_manifest_digest,
            &self.registration_digest,
            self.evidence_source,
            self.status,
            self.non_mutating,
            self.external_write_performed,
            self.durable_native_receipt,
            self.native_connected,
        ]))
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        if self.proposal_id.trim().is_empty()
            || self.proposal_id.len() > 256
            || self.proposal_id.chars().any(char::is_control)
            || !is_sha256(&self.proposal_digest)
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.metadata_digest)
            || !is_sha256(&self.provider_manifest_digest)
            || !is_sha256(&self.registration_digest)
            || self.project_id.validate().is_err()
            || self.mission_id.validate().is_err()
            || self.work_product_id.validate().is_err()
            || self
                .children_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .search_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .versions_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self
                .delta_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.work_product_revision == 0
            || !self.evidence_source.is_layer1_sealed()
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
            || !self.non_mutating
            || self.external_write_performed
            || self.durable_native_receipt
            || self.native_connected
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(SharePointKnowledgeResultError::InvalidProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointScopeDescription {
    pub scope: SharePointKnowledgeScope,
    pub scope_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
}

impl SharePointScopeDescription {
    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.scope.validate()?;
        if !is_sha256(&self.scope_digest)
            || !is_sha256(&self.provider_manifest_digest)
            || !is_sha256(&self.permission_digest)
            || !self.evidence_source.is_layer1_sealed()
            || self.scope.digest() != self.scope_digest
            || self.permission_digest != self.scope.permission_digest
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
            || self.native_transport
            || self.native_connected
        {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointKnowledgeReadRequest {
    pub scope: SharePointKnowledgeScope,
    pub include_children: bool,
    pub include_search: bool,
    pub include_versions: bool,
    pub include_delta: bool,
    pub search_query_digest: Option<Digest>,
}

impl SharePointKnowledgeReadRequest {
    pub fn metadata(scope: SharePointKnowledgeScope) -> Self {
        Self {
            scope,
            include_children: false,
            include_search: false,
            include_versions: false,
            include_delta: false,
            search_query_digest: None,
        }
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.scope.validate()?;
        if self
            .search_query_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(SharePointKnowledgeResultError::InvalidDigest {
                field: "searchQueryDigest",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveItemReadRequest {
    pub scope: SharePointKnowledgeScope,
    pub expected_version: ItemVersionId,
}

impl DriveItemReadRequest {
    pub fn new(scope: SharePointKnowledgeScope) -> Self {
        Self {
            expected_version: scope.item_version.clone(),
            scope,
        }
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.scope.validate()?;
        self.expected_version.validate()?;
        if self.expected_version != self.scope.item_version {
            return Err(SharePointKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharePointSearchRequest {
    pub scope: SharePointKnowledgeScope,
    pub query: SearchQuery,
    pub page_size: u16,
    pub cursor: Option<OpaqueGraphNextLink>,
}

impl SharePointSearchRequest {
    pub fn new(
        scope: SharePointKnowledgeScope,
        query: impl Into<String>,
    ) -> Result<Self, SharePointKnowledgeResultError> {
        scope.validate()?;
        let query = SearchQuery::new(query)?;
        if query.as_str().len() > scope.search_scope.max_query_bytes {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "searchQuery",
                reason: String::from("exceeds the registered search scope bound"),
            });
        }
        Ok(Self {
            scope,
            query,
            page_size: PAGE_SIZE,
            cursor: None,
        })
    }

    pub fn validate(&self) -> Result<(), SharePointKnowledgeResultError> {
        self.scope.validate()?;
        if self.query.as_str().len() > self.scope.search_scope.max_query_bytes
            || self.page_size == 0
            || self.page_size > PAGE_SIZE
        {
            return Err(SharePointKnowledgeResultError::InvalidInput {
                field: "search request",
                reason: String::from("request exceeds the registered search bounds"),
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: OpaqueGraphNextLink) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharePointCursorRequest {
    pub scope: SharePointKnowledgeScope,
    pub cursor: Option<OpaqueGraphNextLink>,
}

impl SharePointCursorRequest {
    pub fn new(scope: SharePointKnowledgeScope) -> Self {
        Self {
            scope,
            cursor: None,
        }
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: OpaqueGraphNextLink) -> Self {
        self.cursor = Some(cursor);
        self
    }
}
