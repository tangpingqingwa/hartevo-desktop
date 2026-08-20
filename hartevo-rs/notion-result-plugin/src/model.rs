use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::NotionResultError;

/// Contract/schema identifier for the Layer 1 crate.
pub const NOTION_RESULT_SCHEMA_VERSION: &str = "hartevo.notion-result/v1";
/// Contract version for EXT-NOTION-01's root draft.
pub const NOTION_RESULT_CONTRACT_VERSION: &str = "EXT-NOTION-01-L1/v1";
/// Current Notion API version used by the typed boundary.
pub const NOTION_API_VERSION: &str = "2026-03-11";
/// Environment variable reserved for a future native provider.
pub const NOTION_ACCESS_TOKEN_ENV: &str = "HARTEVO_NOTION_ACCESS_TOKEN";
/// Official Notion API base URL.  Layer 1 does not make requests to it.
pub const NOTION_API_BASE_URL: &str = "https://api.notion.com/v1";
/// Maximum page size accepted by the Notion list endpoints.
pub const MAX_PAGE_SIZE: u32 = 100;
/// Maximum number of pages a future read-back poll may consume.
pub const MAX_PAGES: u16 = 100;
/// Maximum number of polls represented by the future async template.
pub const MAX_POLLS: u16 = 20;
/// Maximum body size admitted to a proposal.
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
/// Maximum title size admitted to a proposal.
pub const MAX_TITLE_BYTES: usize = 512;

/// A lowercase SHA-256 digest represented at serialization boundaries.
pub type Digest = String;

/// Hash canonical JSON for deterministic proposal and manifest bindings.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Notion contract values must serialize");
    sha256_digest(&bytes)
}

/// Hash bytes with lowercase hexadecimal output.
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing a String cannot fail");
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), NotionResultError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(NotionResultError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), NotionResultError> {
    if value.trim().is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(NotionResultError::InvalidInput {
            field,
            reason: String::from("must contain only bounded identifier characters"),
        });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = NotionResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(TenantId, "tenant_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(WorkProductId, "work_product_id");
identifier_type!(NotionPageId, "Notion page_id");
identifier_type!(NotionDataSourceId, "Notion data_source_id");

/// Data-source property names are user-authored Notion schema labels and may
/// contain spaces; they remain bounded and content-safe rather than using the
/// stricter ID grammar above.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NotionPropertyKey(String);

impl NotionPropertyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
        let value = value.into();
        validate_text(&value, "Notion property key", 128)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for NotionPropertyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for NotionPropertyKey {
    type Err = NotionResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// A Notion API version string.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NotionApiVersion(String);

impl NotionApiVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
        let value = value.into();
        if value.len() != 10
            || value.as_bytes().get(4) != Some(&b'-')
            || value.as_bytes().get(7) != Some(&b'-')
            || !value
                .bytes()
                .enumerate()
                .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
        {
            return Err(NotionResultError::InvalidInput {
                field: "Notion API version",
                reason: String::from("must use YYYY-MM-DD"),
            });
        }
        Ok(Self(value))
    }

    pub fn current() -> Self {
        Self(String::from(NOTION_API_VERSION))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NotionApiVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The parent kinds intentionally distinguish a page parent from a data source
/// parent.  A database parent is not represented as a data source alias.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "type")]
pub enum NotionParent {
    #[serde(rename = "page_id")]
    Page { page_id: NotionPageId },
    #[serde(rename = "data_source_id")]
    DataSource { data_source_id: NotionDataSourceId },
}

impl NotionParent {
    pub fn page(page_id: NotionPageId) -> Self {
        Self::Page { page_id }
    }

    pub fn data_source(data_source_id: NotionDataSourceId) -> Self {
        Self::DataSource { data_source_id }
    }

    pub fn resource_id(&self) -> &str {
        match self {
            Self::Page { page_id } => page_id.as_str(),
            Self::DataSource { data_source_id } => data_source_id.as_str(),
        }
    }

    pub const fn api_type(&self) -> &'static str {
        match self {
            Self::Page { .. } => "page_id",
            Self::DataSource { .. } => "data_source_id",
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        validate_identifier(self.resource_id(), self.api_type())
    }
}

/// Notion connection capabilities relevant to a result adoption proposal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionCapability {
    ReadContent,
    InsertContent,
    UpdateContent,
}

impl NotionCapability {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ReadContent => "read_content",
            Self::InsertContent => "insert_content",
            Self::UpdateContent => "update_content",
        }
    }
}

/// User consent as a provider-bound, scope-bound capability grant.  It carries
/// no token and is not included in provider receipts beyond its digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionConsent {
    pub consent_id: String,
    pub capabilities: BTreeSet<NotionCapability>,
    pub parent_scope_digest: Digest,
}

impl NotionConsent {
    pub fn new(
        consent_id: impl Into<String>,
        parent: &NotionParent,
        capabilities: BTreeSet<NotionCapability>,
    ) -> Result<Self, NotionResultError> {
        let consent_id = consent_id.into();
        validate_identifier(&consent_id, "consent_id")?;
        parent.validate()?;
        if capabilities.is_empty() {
            return Err(NotionResultError::InvalidScope);
        }
        Ok(Self {
            consent_id,
            capabilities,
            parent_scope_digest: canonical_digest(parent),
        })
    }

    pub fn grants(&self, capability: NotionCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        validate_identifier(&self.consent_id, "consent_id")?;
        if self.capabilities.is_empty() || !is_sha256(&self.parent_scope_digest) {
            return Err(NotionResultError::InvalidScope);
        }
        Ok(())
    }
}

/// Explicit page/data-source scope plus the consent that authorizes it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionScope {
    pub parent: NotionParent,
    pub consent: NotionConsent,
}

impl NotionScope {
    pub fn new(parent: NotionParent, consent: NotionConsent) -> Result<Self, NotionResultError> {
        parent.validate()?;
        if consent.parent_scope_digest != canonical_digest(&parent) {
            return Err(NotionResultError::InvalidScope);
        }
        Ok(Self { parent, consent })
    }

    pub fn page(
        page_id: NotionPageId,
        consent_id: impl Into<String>,
        capabilities: BTreeSet<NotionCapability>,
    ) -> Result<Self, NotionResultError> {
        let parent = NotionParent::page(page_id);
        Self::new(
            parent.clone(),
            NotionConsent::new(consent_id, &parent, capabilities)?,
        )
    }

    pub fn data_source(
        data_source_id: NotionDataSourceId,
        consent_id: impl Into<String>,
        capabilities: BTreeSet<NotionCapability>,
    ) -> Result<Self, NotionResultError> {
        let parent = NotionParent::data_source(data_source_id);
        Self::new(
            parent.clone(),
            NotionConsent::new(consent_id, &parent, capabilities)?,
        )
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn requires(&self, capability: NotionCapability) -> Result<(), NotionResultError> {
        if self.consent.grants(capability) {
            Ok(())
        } else {
            Err(NotionResultError::ConsentRequired { capability })
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        self.parent.validate()?;
        self.consent.validate()?;
        if self.consent.parent_scope_digest != canonical_digest(&self.parent) {
            return Err(NotionResultError::InvalidScope);
        }
        Ok(())
    }
}

/// A bounded opaque cursor used by the future Notion list/read endpoints.
/// Its Debug implementation never exposes the cursor bytes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NotionCursor(String);

impl NotionCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
        let value = value.into();
        validate_identifier(&value, "Notion cursor")?;
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for NotionCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NotionCursor")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// Cursor/page-size policy shared by description and content read-back.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPaginationTemplate {
    pub page_size: u32,
    pub max_pages: u16,
    pub cursor_field: String,
    pub has_more_field: String,
}

impl NotionPaginationTemplate {
    pub fn layer1() -> Self {
        Self {
            page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            cursor_field: String::from("next_cursor"),
            has_more_field: String::from("has_more"),
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_PAGES).contains(&self.max_pages)
            || self.cursor_field != "next_cursor"
            || self.has_more_field != "has_more"
        {
            return Err(NotionResultError::InvalidInput {
                field: "pagination template",
                reason: String::from("must use bounded Notion next_cursor/has_more pagination"),
            });
        }
        Ok(())
    }
}

/// Async task policy for a future native provider.  Layer 1 records the
/// template but never starts a task or polls a webhook.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionAsyncMode {
    Synchronous,
    TaskPollingTemplate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionAsyncTemplate {
    pub mode: NotionAsyncMode,
    pub max_polls: u16,
    pub poll_interval_ms: u64,
    pub task_endpoint: String,
    pub native_status: NativeStatus,
}

impl NotionAsyncTemplate {
    pub fn layer1() -> Self {
        Self {
            mode: NotionAsyncMode::TaskPollingTemplate,
            max_polls: MAX_POLLS,
            poll_interval_ms: 5_000,
            task_endpoint: String::from("/tasks/{task_id}"),
            native_status: NativeStatus::BlockedEnv,
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if self.mode != NotionAsyncMode::TaskPollingTemplate
            || !(1..=MAX_POLLS).contains(&self.max_polls)
            || self.poll_interval_ms == 0
            || self.task_endpoint != "/tasks/{task_id}"
            || self.native_status != NativeStatus::BlockedEnv
        {
            return Err(NotionResultError::InvalidInput {
                field: "async template",
                reason: String::from("Layer 1 async execution must remain a blocked template"),
            });
        }
        Ok(())
    }
}

/// Native status is deliberately separate from recording evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionEvidenceSource {
    Recording,
    Fake,
}

/// Narrow API operation templates kept distinct from operation receipts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionEndpointOperation {
    CreatePage,
    UpdatePage,
    AppendBlockChildren,
    RetrievePage,
    RetrieveBlockChildren,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NotionHttpMethod {
    Get,
    Post,
    Patch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionEndpointEffect {
    ReadOnly,
    ProposalOnly,
    TemplateOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionEndpointTemplate {
    pub operation: NotionEndpointOperation,
    pub method: NotionHttpMethod,
    pub path: String,
    pub effect: NotionEndpointEffect,
    pub paginated: bool,
}

impl NotionEndpointTemplate {
    pub fn layer1() -> Vec<Self> {
        vec![
            Self {
                operation: NotionEndpointOperation::CreatePage,
                method: NotionHttpMethod::Post,
                path: String::from("/pages"),
                effect: NotionEndpointEffect::ProposalOnly,
                paginated: false,
            },
            Self {
                operation: NotionEndpointOperation::UpdatePage,
                method: NotionHttpMethod::Patch,
                path: String::from("/pages/{page_id}"),
                effect: NotionEndpointEffect::ProposalOnly,
                paginated: false,
            },
            Self {
                operation: NotionEndpointOperation::AppendBlockChildren,
                method: NotionHttpMethod::Patch,
                path: String::from("/blocks/{block_id}/children"),
                effect: NotionEndpointEffect::ProposalOnly,
                paginated: false,
            },
            Self {
                operation: NotionEndpointOperation::RetrievePage,
                method: NotionHttpMethod::Get,
                path: String::from("/pages/{page_id}"),
                effect: NotionEndpointEffect::ReadOnly,
                paginated: false,
            },
            Self {
                operation: NotionEndpointOperation::RetrieveBlockChildren,
                method: NotionHttpMethod::Get,
                path: String::from("/blocks/{block_id}/children"),
                effect: NotionEndpointEffect::ReadOnly,
                paginated: true,
            },
        ]
    }
}

/// Typed provider manifest, including its immutable contract and scope digest.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionProviderManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub provider_id: String,
    pub service_id: String,
    pub version: PluginVersion,
    pub api_version: NotionApiVersion,
    pub contract_digest: Digest,
    pub scope: NotionScope,
    pub capabilities: BTreeSet<NotionCapability>,
    pub pagination: NotionPaginationTemplate,
    pub async_template: NotionAsyncTemplate,
    pub endpoints: Vec<NotionEndpointTemplate>,
    pub native_status: NativeStatus,
    pub external_write: bool,
    pub store_authority: bool,
    pub keyring_authority: bool,
    pub browser_profile_authority: bool,
    pub effect_authority: bool,
    pub manifest_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize)]
struct ManifestDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    plugin_id: &'a str,
    provider_id: &'a str,
    service_id: &'a str,
    version: PluginVersion,
    api_version: &'a NotionApiVersion,
    contract_digest: &'a str,
    scope: &'a NotionScope,
    capabilities: &'a BTreeSet<NotionCapability>,
    pagination: &'a NotionPaginationTemplate,
    async_template: &'a NotionAsyncTemplate,
    endpoints: &'a [NotionEndpointTemplate],
    native_status: NativeStatus,
    external_write: bool,
    store_authority: bool,
    keyring_authority: bool,
    browser_profile_authority: bool,
    effect_authority: bool,
}

impl NotionProviderManifest {
    pub fn layer1(scope: NotionScope) -> Result<Self, NotionResultError> {
        scope.validate()?;
        let mut manifest = Self {
            schema_version: String::from(NOTION_RESULT_SCHEMA_VERSION),
            contract_version: String::from(NOTION_RESULT_CONTRACT_VERSION),
            plugin_id: String::from("notion-result.knowledge-result"),
            provider_id: String::from("notion.knowledge-result"),
            service_id: String::from("notion-result.publish-proposal"),
            version: PluginVersion::V1,
            api_version: NotionApiVersion::current(),
            contract_digest: sha256_digest(crate::NOTION_RESULT_CONTRACT_JSON.as_bytes()),
            scope,
            capabilities: BTreeSet::from([
                NotionCapability::ReadContent,
                NotionCapability::InsertContent,
                NotionCapability::UpdateContent,
            ]),
            pagination: NotionPaginationTemplate::layer1(),
            async_template: NotionAsyncTemplate::layer1(),
            endpoints: NotionEndpointTemplate::layer1(),
            native_status: NativeStatus::BlockedEnv,
            external_write: false,
            store_authority: false,
            keyring_authority: false,
            browser_profile_authority: false,
            effect_authority: false,
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn digest(&self) -> Digest {
        self.manifest_digest.clone()
    }

    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&ManifestDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_id: &self.plugin_id,
            provider_id: &self.provider_id,
            service_id: &self.service_id,
            version: self.version,
            api_version: &self.api_version,
            contract_digest: &self.contract_digest,
            scope: &self.scope,
            capabilities: &self.capabilities,
            pagination: &self.pagination,
            async_template: &self.async_template,
            endpoints: &self.endpoints,
            native_status: self.native_status,
            external_write: self.external_write,
            store_authority: self.store_authority,
            keyring_authority: self.keyring_authority,
            browser_profile_authority: self.browser_profile_authority,
            effect_authority: self.effect_authority,
        })
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if self.schema_version != NOTION_RESULT_SCHEMA_VERSION
            || self.contract_version != NOTION_RESULT_CONTRACT_VERSION
            || self.plugin_id != "notion-result.knowledge-result"
            || self.provider_id != "notion.knowledge-result"
            || self.service_id != "notion-result.publish-proposal"
            || self.version != PluginVersion::V1
            || self.api_version.as_str() != NOTION_API_VERSION
            || self.contract_digest != sha256_digest(crate::NOTION_RESULT_CONTRACT_JSON.as_bytes())
            || !is_sha256(&self.contract_digest)
            || !is_sha256(&self.manifest_digest)
            || self.manifest_digest != self.calculate_digest()
            || self.capabilities
                != BTreeSet::from([
                    NotionCapability::ReadContent,
                    NotionCapability::InsertContent,
                    NotionCapability::UpdateContent,
                ])
            || self.native_status != NativeStatus::BlockedEnv
            || self.external_write
            || self.store_authority
            || self.keyring_authority
            || self.browser_profile_authority
            || self.effect_authority
            || self.endpoints != NotionEndpointTemplate::layer1()
        {
            return Err(NotionResultError::InvalidProviderManifest);
        }
        self.scope.validate()?;
        self.pagination.validate()?;
        self.async_template.validate()?;
        Ok(())
    }
}

/// A typed projection of an existing domain WorkProduct at the Mission seam.
/// The crate does not own or persist the domain object.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProduct {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub content_digest: Digest,
    pub manifest_digest: Digest,
    pub title: String,
    pub content: String,
}

impl MissionWorkProduct {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        content_digest: Digest,
        manifest_digest: Digest,
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, NotionResultError> {
        let product = Self {
            tenant_id,
            project_id,
            mission_id,
            work_product_id,
            work_product_revision,
            content_digest,
            manifest_digest,
            title: title.into(),
            content: content.into(),
        };
        product.validate()?;
        Ok(product)
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        validate_identifier(self.tenant_id.as_str(), "tenant_id")?;
        validate_identifier(self.project_id.as_str(), "project_id")?;
        validate_identifier(self.mission_id.as_str(), "mission_id")?;
        validate_identifier(self.work_product_id.as_str(), "work_product_id")?;
        if self.work_product_revision == 0 {
            return Err(NotionResultError::InvalidInput {
                field: "work_product_revision",
                reason: String::from("must be positive"),
            });
        }
        if !is_sha256(&self.content_digest) {
            return Err(NotionResultError::InvalidDigest {
                field: "content_digest",
            });
        }
        if !is_sha256(&self.manifest_digest) {
            return Err(NotionResultError::InvalidDigest {
                field: "manifest_digest",
            });
        }
        validate_text(&self.title, "work_product.title", MAX_TITLE_BYTES)?;
        if self.content.trim().is_empty() || self.content.len() > MAX_CONTENT_BYTES {
            return Err(NotionResultError::InvalidInput {
                field: "work_product.content",
                reason: format!("must be non-empty and at most {MAX_CONTENT_BYTES} bytes"),
            });
        }
        Ok(())
    }
}

/// The small block subset used by the result proposal.  It maps to a Notion
/// paragraph/rich_text block without carrying arbitrary model-authored JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionContentBlock {
    pub block_type: NotionBlockType,
    pub rich_text: Vec<NotionRichText>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionBlockType {
    Paragraph,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionRichText {
    pub text: String,
}

impl NotionContentBlock {
    pub fn paragraph(text: impl Into<String>) -> Result<Self, NotionResultError> {
        let text = text.into();
        validate_text(&text, "block.rich_text", MAX_CONTENT_BYTES)?;
        Ok(Self {
            block_type: NotionBlockType::Paragraph,
            rich_text: vec![NotionRichText { text }],
        })
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if self.rich_text.is_empty() {
            return Err(NotionResultError::InvalidInput {
                field: "block.rich_text",
                reason: String::from("must contain at least one rich text item"),
            });
        }
        for item in &self.rich_text {
            validate_text(&item.text, "block.rich_text", MAX_CONTENT_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum NotionPropertyValue {
    Title { text: String },
    RichText { text: String },
    Url { url: String },
    Number { number: i64 },
    Checkbox { checked: bool },
}

impl NotionPropertyValue {
    pub fn title(text: impl Into<String>) -> Result<Self, NotionResultError> {
        let text = text.into();
        validate_text(&text, "title property", MAX_TITLE_BYTES)?;
        Ok(Self::Title { text })
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        match self {
            Self::Title { text } | Self::RichText { text } => {
                validate_text(text, "property text", MAX_CONTENT_BYTES)
            }
            Self::Url { url } => NotionPageUrl::new(url.clone()).map(|_| ()),
            Self::Number { .. } | Self::Checkbox { .. } => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPagePayload {
    pub title: String,
    pub properties: BTreeMap<NotionPropertyKey, NotionPropertyValue>,
    pub children: Vec<NotionContentBlock>,
    pub content_fingerprint: Digest,
}

impl NotionPagePayload {
    pub fn new(
        title: impl Into<String>,
        properties: BTreeMap<NotionPropertyKey, NotionPropertyValue>,
        children: Vec<NotionContentBlock>,
    ) -> Result<Self, NotionResultError> {
        let title = title.into();
        validate_text(&title, "page.title", MAX_TITLE_BYTES)?;
        if children.is_empty() {
            return Err(NotionResultError::InvalidInput {
                field: "page.children",
                reason: String::from("must contain at least one content block"),
            });
        }
        for value in properties.values() {
            value.validate()?;
        }
        for key in properties.keys() {
            key.validate()?;
        }
        for block in &children {
            block.validate()?;
        }
        let content_fingerprint = canonical_digest(&children);
        Ok(Self {
            title,
            properties,
            children,
            content_fingerprint,
        })
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        let rebuilt = Self::new(
            self.title.clone(),
            self.properties.clone(),
            self.children.clone(),
        )?;
        if rebuilt.content_fingerprint != self.content_fingerprint {
            return Err(NotionResultError::InvalidProposal);
        }
        Ok(())
    }
}

/// Operation represented by a proposal.  There is intentionally no live write
/// method associated with these variants.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum NotionPublishOperation {
    CreatePage,
    UpdatePage { page_id: NotionPageId },
    AppendContent { page_id: NotionPageId },
}

impl NotionPublishOperation {
    pub const fn required_capability(&self) -> NotionCapability {
        match self {
            Self::CreatePage | Self::AppendContent { .. } => NotionCapability::InsertContent,
            Self::UpdatePage { .. } => NotionCapability::UpdateContent,
        }
    }

    pub const fn endpoint_operation(&self) -> NotionEndpointOperation {
        match self {
            Self::CreatePage => NotionEndpointOperation::CreatePage,
            Self::UpdatePage { .. } => NotionEndpointOperation::UpdatePage,
            Self::AppendContent { .. } => NotionEndpointOperation::AppendBlockChildren,
        }
    }

    pub fn target_page_id(&self) -> Option<&NotionPageId> {
        match self {
            Self::CreatePage => None,
            Self::UpdatePage { page_id } | Self::AppendContent { page_id } => Some(page_id),
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if let Some(page_id) = self.target_page_id() {
            validate_identifier(page_id.as_str(), "Notion page_id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPublishDestination {
    pub scope: NotionScope,
    pub operation: NotionPublishOperation,
    pub title_property: Option<NotionPropertyKey>,
}

impl NotionPublishDestination {
    pub fn new(
        scope: NotionScope,
        operation: NotionPublishOperation,
        title_property: Option<NotionPropertyKey>,
    ) -> Result<Self, NotionResultError> {
        scope.validate()?;
        operation.validate()?;
        if matches!(operation, NotionPublishOperation::CreatePage)
            && matches!(scope.parent, NotionParent::DataSource { .. })
            && title_property.is_none()
        {
            return Err(NotionResultError::InvalidInput {
                field: "title_property",
                reason: String::from("a data source page needs its title property key"),
            });
        }
        Ok(Self {
            scope,
            operation,
            title_property,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionProposalEffect {
    ProposalOnly,
}

/// A deterministic, consent-bound, non-executing Notion publish proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPublishProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub provider_manifest_digest: Digest,
    pub api_version: NotionApiVersion,
    pub scope: NotionScope,
    pub work_product: MissionWorkProduct,
    pub operation: NotionPublishOperation,
    pub payload: NotionPagePayload,
    pub content_fingerprint: Digest,
    pub idempotency_key: String,
    pub async_template: NotionAsyncTemplate,
    pub effect: NotionProposalEffect,
    pub native_status: NativeStatus,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestMaterial<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    provider_id: &'a str,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a str,
    api_version: &'a NotionApiVersion,
    scope: &'a NotionScope,
    work_product: &'a MissionWorkProduct,
    operation: &'a NotionPublishOperation,
    payload: &'a NotionPagePayload,
    content_fingerprint: &'a str,
    idempotency_key: &'a str,
    async_template: &'a NotionAsyncTemplate,
    effect: NotionProposalEffect,
    native_status: NativeStatus,
}

#[derive(Serialize)]
struct IdempotencyMaterial<'a> {
    provider_id: &'a str,
    provider_version: PluginVersion,
    provider_manifest_digest: &'a str,
    api_version: &'a NotionApiVersion,
    scope: &'a NotionScope,
    tenant_id: &'a TenantId,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
    work_product_id: &'a WorkProductId,
    work_product_revision: u64,
    content_digest: &'a str,
    manifest_digest: &'a str,
    operation: &'a NotionPublishOperation,
    content_fingerprint: &'a str,
}

impl NotionPublishProposal {
    pub fn new(
        manifest: &NotionProviderManifest,
        work_product: MissionWorkProduct,
        destination: NotionPublishDestination,
    ) -> Result<Self, NotionResultError> {
        manifest.validate()?;
        work_product.validate()?;
        destination.operation.validate()?;
        if destination.scope != manifest.scope {
            return Err(NotionResultError::ScopeMismatch);
        }
        destination
            .scope
            .requires(destination.operation.required_capability())?;
        let blocks = vec![NotionContentBlock::paragraph(work_product.content.clone())?];
        let mut properties = BTreeMap::new();
        if matches!(destination.operation, NotionPublishOperation::CreatePage)
            || matches!(
                destination.operation,
                NotionPublishOperation::UpdatePage { .. }
            )
        {
            let property_key = destination.title_property.unwrap_or_else(|| {
                NotionPropertyKey::new("title").expect("static title property key is valid")
            });
            properties.insert(
                property_key,
                NotionPropertyValue::title(work_product.title.clone())?,
            );
        }
        let payload = NotionPagePayload::new(work_product.title.clone(), properties, blocks)?;
        let content_fingerprint = payload.content_fingerprint.clone();
        let idempotency_key = format!(
            "notion-l1-{}",
            canonical_digest(&IdempotencyMaterial {
                provider_id: &manifest.provider_id,
                provider_version: manifest.version,
                provider_manifest_digest: &manifest.manifest_digest,
                api_version: &manifest.api_version,
                scope: &manifest.scope,
                tenant_id: &work_product.tenant_id,
                project_id: &work_product.project_id,
                mission_id: &work_product.mission_id,
                work_product_id: &work_product.work_product_id,
                work_product_revision: work_product.work_product_revision,
                content_digest: &work_product.content_digest,
                manifest_digest: &work_product.manifest_digest,
                operation: &destination.operation,
                content_fingerprint: &content_fingerprint,
            })
        );
        let mut proposal = Self {
            schema_version: String::from(NOTION_RESULT_SCHEMA_VERSION),
            contract_version: String::from(NOTION_RESULT_CONTRACT_VERSION),
            provider_id: manifest.provider_id.clone(),
            provider_version: manifest.version,
            provider_manifest_digest: manifest.manifest_digest.clone(),
            api_version: manifest.api_version.clone(),
            scope: manifest.scope.clone(),
            work_product,
            operation: destination.operation,
            payload,
            content_fingerprint,
            idempotency_key,
            async_template: manifest.async_template.clone(),
            effect: NotionProposalEffect::ProposalOnly,
            native_status: NativeStatus::BlockedEnv,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&ProposalDigestMaterial {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            provider_id: &self.provider_id,
            provider_version: self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            api_version: &self.api_version,
            scope: &self.scope,
            work_product: &self.work_product,
            operation: &self.operation,
            payload: &self.payload,
            content_fingerprint: &self.content_fingerprint,
            idempotency_key: &self.idempotency_key,
            async_template: &self.async_template,
            effect: self.effect,
            native_status: self.native_status,
        })
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        self.scope.validate()?;
        self.work_product.validate()?;
        self.payload.validate()?;
        self.operation.validate()?;
        self.async_template.validate()?;
        if self.schema_version != NOTION_RESULT_SCHEMA_VERSION
            || self.contract_version != NOTION_RESULT_CONTRACT_VERSION
            || self.provider_id != "notion.knowledge-result"
            || self.provider_version != PluginVersion::V1
            || self.api_version.as_str() != NOTION_API_VERSION
            || self.provider_manifest_digest.len() != 64
            || self.content_fingerprint != self.payload.content_fingerprint
            || self.idempotency_key.len() != "notion-l1-".len() + 64
            || !self.idempotency_key.starts_with("notion-l1-")
            || self.effect != NotionProposalEffect::ProposalOnly
            || self.native_status != NativeStatus::BlockedEnv
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(NotionResultError::InvalidProposal);
        }
        Ok(())
    }
}

/// Description receipt for a scoped parent/data source.  It has no page body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionScopeDescription {
    pub scope: NotionScope,
    pub resource_kind: NotionResourceKind,
    pub resource_id: String,
    pub schema_digest: Option<Digest>,
    pub pagination: NotionPaginationReceipt,
    pub provider_manifest_digest: Digest,
    pub evidence: NotionEvidenceSource,
    pub native_status: NativeStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotionResourceKind {
    Page,
    DataSource,
}

/// Only bounded pagination metadata is retained in receipts/read-backs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPaginationReceipt {
    pub pages_read: u16,
    pub has_more: bool,
    pub next_cursor_digest: Option<Digest>,
}

impl NotionPaginationReceipt {
    pub fn one_page() -> Self {
        Self {
            pages_read: 1,
            has_more: false,
            next_cursor_digest: None,
        }
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        if self.pages_read == 0
            || self.pages_read > MAX_PAGES
            || self
                .next_cursor_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || (!self.has_more && self.next_cursor_digest.is_some())
        {
            return Err(NotionResultError::InvalidInput {
                field: "pagination receipt",
                reason: String::from("cursor metadata is inconsistent or unbounded"),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionDescribeRequest {
    pub scope: NotionScope,
    pub pagination: NotionPaginationTemplate,
}

impl NotionDescribeRequest {
    pub fn new(
        scope: NotionScope,
        pagination: NotionPaginationTemplate,
    ) -> Result<Self, NotionResultError> {
        scope.validate()?;
        pagination.validate()?;
        Ok(Self { scope, pagination })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionReadRequest {
    pub page_id: NotionPageId,
    pub scope: NotionScope,
    pub pagination: NotionPaginationTemplate,
    pub cursor: Option<NotionCursor>,
}

impl NotionReadRequest {
    pub fn new(
        page_id: NotionPageId,
        scope: NotionScope,
        pagination: NotionPaginationTemplate,
        cursor: Option<NotionCursor>,
    ) -> Result<Self, NotionResultError> {
        scope.validate()?;
        pagination.validate()?;
        if let Some(cursor) = &cursor {
            cursor.validate()?;
        }
        Ok(Self {
            page_id,
            scope,
            pagination,
            cursor,
        })
    }
}

/// Receipt emitted by a provider boundary after recording a proposal.  It
/// proves only deterministic local recording, never a native Notion write.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionPageReceipt {
    pub page_id: NotionPageId,
    pub page_url: NotionPageUrl,
    pub parent: NotionParent,
    pub revision: NotionRevision,
    pub content_fingerprint: Digest,
    pub proposal_digest: Digest,
    pub idempotency_key: String,
    pub provider_manifest_digest: Digest,
    pub operation: NotionPublishOperation,
    pub evidence: NotionEvidenceSource,
    pub native_status: NativeStatus,
}

impl NotionPageReceipt {
    pub fn validate(&self) -> Result<(), NotionResultError> {
        validate_identifier(self.page_id.as_str(), "Notion page_id")?;
        self.parent.validate()?;
        self.page_url.validate()?;
        self.revision.validate()?;
        self.operation.validate()?;
        if !is_sha256(&self.content_fingerprint)
            || !is_sha256(&self.proposal_digest)
            || !is_sha256(&self.provider_manifest_digest)
            || self.idempotency_key.len() != "notion-l1-".len() + 64
            || self.native_status != NativeStatus::BlockedEnv
        {
            return Err(NotionResultError::InvalidReadback {
                field: "page receipt digest or native status",
            });
        }
        Ok(())
    }
}

/// Content-free read-back projection used for independent verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionReadback {
    pub page_id: NotionPageId,
    pub page_url: NotionPageUrl,
    pub parent: NotionParent,
    pub revision: NotionRevision,
    pub content_fingerprint: Digest,
    pub proposal_digest: Digest,
    pub idempotency_key: String,
    pub provider_manifest_digest: Digest,
    pub pagination: NotionPaginationReceipt,
    pub evidence: NotionEvidenceSource,
    pub native_status: NativeStatus,
}

impl NotionReadback {
    pub fn validate(&self) -> Result<(), NotionResultError> {
        validate_identifier(self.page_id.as_str(), "Notion page_id")?;
        self.parent.validate()?;
        self.page_url.validate()?;
        self.revision.validate()?;
        self.pagination.validate()?;
        if !is_sha256(&self.content_fingerprint)
            || !is_sha256(&self.proposal_digest)
            || !is_sha256(&self.provider_manifest_digest)
            || self.idempotency_key.len() != "notion-l1-".len() + 64
            || self.native_status != NativeStatus::BlockedEnv
        {
            return Err(NotionResultError::InvalidReadback {
                field: "readback digest or native status",
            });
        }
        Ok(())
    }
}

/// Fields independently compared by `verify_readback`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotionReadbackField {
    PageId,
    PageUrl,
    Parent,
    Revision,
    ContentFingerprint,
    ProposalDigest,
    IdempotencyKey,
    ProviderManifestDigest,
}

/// Successful content-free proof of the proposal/read-back binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotionVerifiedReadback {
    pub page_id: NotionPageId,
    pub page_url: NotionPageUrl,
    pub parent: NotionParent,
    pub revision: NotionRevision,
    pub content_fingerprint: Digest,
    pub proposal_digest: Digest,
    pub idempotency_key: String,
    pub evidence: NotionEvidenceSource,
    pub native_status: NativeStatus,
    pub verified: bool,
}

/// URL wrapper used by receipts and page properties.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NotionPageUrl(String);

impl NotionPageUrl {
    pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
        let value = value.into();
        if !value.starts_with("https://")
            || value[8..].trim().is_empty()
            || value.chars().any(char::is_whitespace)
        {
            return Err(NotionResultError::InvalidInput {
                field: "Notion page URL",
                reason: String::from("must be an HTTPS URL without whitespace"),
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for NotionPageUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Provider revision is intentionally opaque: Notion exposes last-edited
/// metadata rather than a universal page revision integer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NotionRevision(String);

impl NotionRevision {
    pub fn new(value: impl Into<String>) -> Result<Self, NotionResultError> {
        let value = value.into();
        validate_identifier(&value, "Notion revision")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), NotionResultError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for NotionRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}
