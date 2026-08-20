use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::ConfluenceKnowledgeResultError;

pub const MAX_PAGE_SIZE: u32 = 50;
pub const MAX_PAGES: u32 = 16;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_ANCESTORS: usize = 32;
pub const MAX_CHILDREN: usize = 128;
pub const MAX_LABELS: usize = 128;
pub const MAX_SEARCH_HITS: usize = 50;
pub const MAX_CQL_BYTES: usize = 512;
pub const MAX_CQL_TERM_BYTES: usize = 256;
const MAX_SEARCH_RESULTS_U32: u32 = 50;

pub const CONFLUENCE_API_VERSION: &str = "v1";
pub const CONFLUENCE_API_BASE_PATH: &str = "/wiki/rest/api";
pub const CONFLUENCE_SECRET_REFERENCE_ENV: &str = "HARTEVO_CONFLUENCE_SECRET_REFERENCE";

pub type Digest = String;

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(output, "{byte:02x}").expect("writing into a String cannot fail");
    }
    output
}

///
/// # Panics
///
/// Panics only if a contract value violates its `Serialize` implementation;
/// all values supplied by this crate are infallible JSON values.
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    sha256_digest(&bytes)
}

pub fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> Digest {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0);
    }
    sha256_digest(&bytes)
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ConfluenceKnowledgeResultError> {
    if !is_sha256(value) || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ConfluenceKnowledgeResultError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ConfluenceKnowledgeResultError> {
    if value.trim().is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        return Err(ConfluenceKnowledgeResultError::InvalidInput {
            field,
            reason: format!("must be non-empty, bounded to {max_bytes} bytes, and content-safe"),
        });
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), ConfluenceKnowledgeResultError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-~".contains(&byte))
    {
        return Err(ConfluenceKnowledgeResultError::InvalidInput {
            field,
            reason: String::from("must be a bounded identifier without whitespace or separators"),
        });
    }
    Ok(())
}

fn redacted(value: &str) -> String {
    format!("sha256:{}", &sha256_digest(value.as_bytes())[..16])
}

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ConfluenceKnowledgeResultError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                sha256_digest(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple($field)
                    .field(&redacted(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ConfluenceKnowledgeResultError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(CloudId, "cloud_id");
identifier_type!(AtlassianAccountId, "account_id");
identifier_type!(ConfluenceSpaceId, "space_id");
identifier_type!(ConfluencePageId, "page_id");
identifier_type!(ConfluenceContentId, "content_id");
identifier_type!(ProjectId, "project_id");
identifier_type!(MissionId, "mission_id");
identifier_type!(WorkProductId, "work_product_id");

/// Exact HTTPS Atlassian site identity. The site is canonicalized to an
/// origin-like value without a trailing slash, query, fragment, or path.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ConfluenceSite(String);

impl ConfluenceSite {
    pub fn new(value: impl Into<String>) -> Result<Self, ConfluenceKnowledgeResultError> {
        let mut value = value.into();
        while value.ends_with('/') {
            value.pop();
        }
        let valid = value.starts_with("https://")
            && value.len() > "https://".len()
            && !value["https://".len()..].contains('/')
            && !value.contains('?')
            && !value.contains('#')
            && !value.chars().any(char::is_whitespace);
        if !valid {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "site",
                reason: String::from("must be an exact HTTPS Atlassian site origin"),
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
}

impl fmt::Debug for ConfluenceSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConfluenceSite")
            .field(&redacted(&self.0))
            .finish()
    }
}

impl fmt::Display for ConfluenceSite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ConfluenceSite {
    type Err = ConfluenceKnowledgeResultError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    OAuth2,
    ApiToken,
}

/// Opaque host-owned credential identity. No OAuth/API token bytes are held
/// by this type or exposed in Debug, receipts, proposals, or digests.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_id: String,
    pub scope_digest: Digest,
    pub credential_revision: u64,
    pub auth_method: AuthMethod,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
        auth_method: AuthMethod,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest,
            credential_revision,
            auth_method,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_text(&self.reference_id, "secret reference", 256)?;
        validate_digest(&self.scope_digest, "secret scope digest")?;
        if self.credential_revision == 0 {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "secret credential revision",
                reason: String::from("must be non-zero"),
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_parts([
            self.reference_id.as_str(),
            self.scope_digest.as_str(),
            &self.credential_revision.to_string(),
            match self.auth_method {
                AuthMethod::OAuth2 => "oauth2",
                AuthMethod::ApiToken => "api_token",
            },
        ])
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_method", &self.auth_method)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyRepresentation {
    Storage,
    AtlasDocFormat,
    View,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyField {
    Representation,
    ValueDigest,
    ByteLength,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfluenceCapability {
    DescribeContentScope,
    ReadPageEvidence,
    SearchKnowledge,
    CompileKnowledgeProposal,
    RecordKnowledgeReceipt,
    VerifyKnowledgeResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentBinding {
    pub consent_id: String,
    pub policy_revision: u64,
    pub capabilities: BTreeSet<ConfluenceCapability>,
}

impl ConsentBinding {
    pub fn new(
        consent_id: impl Into<String>,
        policy_revision: u64,
        capabilities: BTreeSet<ConfluenceCapability>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let value = Self {
            consent_id: consent_id.into(),
            policy_revision,
            capabilities,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_text(&self.consent_id, "consent id", 128)?;
        if self.policy_revision == 0 || self.capabilities.is_empty() {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn permits(&self, capability: ConfluenceCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageVersion {
    pub number: u64,
    pub last_modified_digest: Digest,
}

impl PageVersion {
    pub fn new(
        number: u64,
        last_modified: impl Into<String>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        if number == 0 {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "page version",
                reason: String::from("version number must be non-zero"),
            });
        }
        let value = last_modified.into();
        let last_modified_digest = if is_sha256(&value) {
            value
        } else {
            sha256_digest(value.as_bytes())
        };
        validate_digest(&last_modified_digest, "last modified digest")?;
        Ok(Self {
            number,
            last_modified_digest,
        })
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.number == 0 {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        validate_digest(&self.last_modified_digest, "last modified digest")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CqlTemplate {
    template_id: String,
    space_id: ConfluenceSpaceId,
    phrase: String,
    max_results: u32,
    query_digest: Digest,
}

impl CqlTemplate {
    pub fn space_text(
        space_id: ConfluenceSpaceId,
        phrase: impl Into<String>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        Self::space_text_bounded(space_id, phrase.into(), MAX_SEARCH_RESULTS_U32)
    }

    pub fn space_text_bounded(
        space_id: ConfluenceSpaceId,
        phrase: String,
        max_results: u32,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        validate_text(&phrase, "CQL phrase", MAX_CQL_TERM_BYTES)?;
        if phrase.contains('"')
            || phrase.contains('\\')
            || phrase.contains(';')
            || phrase.contains("--")
            || phrase.contains("/*")
            || phrase.contains("*/")
            || phrase.to_ascii_lowercase().contains(" or ")
        {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "CQL phrase",
                reason: String::from("contains characters or operators outside the allowlist"),
            });
        }
        if max_results == 0 || max_results > MAX_SEARCH_RESULTS_U32 {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "CQL max results",
                reason: format!("must be between 1 and {MAX_SEARCH_HITS}"),
            });
        }
        let query = format!(
            "space = \"{}\" AND text ~ \"{}\"",
            space_id.as_str(),
            phrase
        );
        if query.len() > MAX_CQL_BYTES {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "CQL query",
                reason: format!("must be at most {MAX_CQL_BYTES} bytes"),
            });
        }
        Ok(Self {
            template_id: String::from("space_text_v1"),
            space_id,
            phrase,
            max_results,
            query_digest: sha256_digest(query.as_bytes()),
        })
    }

    /// Parse only the canonical allowlisted form. Arbitrary raw CQL is never
    /// accepted at this boundary.
    pub fn from_raw(
        space_id: ConfluenceSpaceId,
        raw_query: impl Into<String>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let raw_query = raw_query.into();
        let prefix = format!("space = \"{}\" AND text ~ \"", space_id.as_str());
        if !raw_query.starts_with(&prefix) || !raw_query.ends_with('"') {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "CQL query",
                reason: String::from("must use the exact space_text_v1 template"),
            });
        }
        let phrase_end = raw_query.len().saturating_sub(1);
        let phrase = &raw_query[prefix.len()..phrase_end];
        let template = Self::space_text(space_id, phrase.to_owned())?;
        if template.query() != raw_query {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "CQL query",
                reason: String::from("must use the exact canonical allowlisted query"),
            });
        }
        Ok(template)
    }

    pub fn template_id(&self) -> &str {
        &self.template_id
    }

    pub fn space_id(&self) -> &ConfluenceSpaceId {
        &self.space_id
    }

    pub fn max_results(&self) -> u32 {
        self.max_results
    }

    pub fn query(&self) -> String {
        format!(
            "space = \"{}\" AND text ~ \"{}\"",
            self.space_id.as_str(),
            self.phrase
        )
    }

    pub(crate) fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn digest(&self) -> Digest {
        self.query_digest.clone()
    }

    pub fn validate_for_scope(
        &self,
        scope: &ConfluenceScope,
    ) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.template_id != "space_text_v1"
            || self.space_id != scope.space_id
            || self.query_digest != sha256_digest(self.query().as_bytes())
        {
            return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
        }
        Ok(())
    }
}

impl Serialize for CqlTemplate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CqlTemplate", 5)?;
        state.serialize_field("templateId", &self.template_id)?;
        state.serialize_field("spaceId", &self.space_id)?;
        state.serialize_field("phraseDigest", &sha256_digest(self.phrase.as_bytes()))?;
        state.serialize_field("queryDigest", &self.query_digest)?;
        state.serialize_field("maxResults", &self.max_results)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CqlTemplate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            template_id: String,
            space_id: ConfluenceSpaceId,
            phrase: Option<String>,
            max_results: Option<u32>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.template_id != "space_text_v1" {
            return Err(D::Error::custom("unsupported CQL template"));
        }
        let phrase = wire.phrase.ok_or_else(|| {
            D::Error::custom("opaque CQL template cannot be deserialized without phrase")
        })?;
        Self::space_text_bounded(
            wire.space_id,
            phrase,
            wire.max_results.unwrap_or(MAX_SEARCH_RESULTS_U32),
        )
        .map_err(|error| D::Error::custom(error.to_string()))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluenceScope {
    pub site: ConfluenceSite,
    pub cloud_id: CloudId,
    pub account_id: AtlassianAccountId,
    pub space_id: ConfluenceSpaceId,
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub page_version: PageVersion,
    pub body_representation: BodyRepresentation,
    pub body_field_allowlist: BTreeSet<BodyField>,
    pub max_body_bytes: usize,
    pub cql_template: CqlTemplate,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub consent: ConsentBinding,
    pub permission_digest: Digest,
}

impl fmt::Debug for ConfluenceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfluenceScope")
            .field("site", &self.site)
            .field("cloud_id", &self.cloud_id)
            .field("account_id", &self.account_id)
            .field("space_id", &self.space_id)
            .field("page_id", &self.page_id)
            .field("content_id", &self.content_id)
            .field("page_version", &self.page_version)
            .field("body_representation", &self.body_representation)
            .field("body_field_allowlist", &self.body_field_allowlist)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("cql_template", &self.cql_template)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("work_product_id", &self.work_product_id)
            .field("work_product_revision", &self.work_product_revision)
            .field("consent_id", &redacted(&self.consent.consent_id))
            .field("policy_revision", &self.consent.policy_revision)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

impl ConfluenceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        site: ConfluenceSite,
        cloud_id: CloudId,
        account_id: AtlassianAccountId,
        space_id: ConfluenceSpaceId,
        page_id: ConfluencePageId,
        content_id: ConfluenceContentId,
        page_version: PageVersion,
        body_representation: BodyRepresentation,
        body_field_allowlist: BTreeSet<BodyField>,
        max_body_bytes: usize,
        cql_template: CqlTemplate,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        consent: ConsentBinding,
        permission_digest: Digest,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let scope = Self {
            site,
            cloud_id,
            account_id,
            space_id,
            page_id,
            content_id,
            page_version,
            body_representation,
            body_field_allowlist,
            max_body_bytes,
            cql_template,
            project_id,
            mission_id,
            work_product_id,
            work_product_revision,
            consent,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.max_body_bytes == 0 || self.max_body_bytes > MAX_BODY_BYTES {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        if self.work_product_revision == 0 {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        if !self
            .body_field_allowlist
            .contains(&BodyField::Representation)
            || !self.body_field_allowlist.contains(&BodyField::ValueDigest)
            || self.body_field_allowlist.len() > 3
        {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        self.page_version.validate()?;
        self.consent.validate()?;
        validate_digest(&self.permission_digest, "permission digest")?;
        self.cql_template.validate_for_scope(self)?;
        if !self.consent.permits(ConfluenceCapability::ReadPageEvidence)
            || !self.consent.permits(ConfluenceCapability::SearchKnowledge)
            || !self
                .consent
                .permits(ConfluenceCapability::CompileKnowledgeProposal)
            || !self
                .consent
                .permits(ConfluenceCapability::RecordKnowledgeReceipt)
            || !self
                .consent
                .permits(ConfluenceCapability::VerifyKnowledgeResult)
        {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn permits(&self, capability: ConfluenceCapability) -> bool {
        self.consent.permits(capability)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluenceProviderManifest {
    pub provider_id: String,
    pub provider_version: u64,
    pub api_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub capabilities: Vec<ConfluenceCapability>,
    pub manifest_digest: Digest,
}

impl ConfluenceProviderManifest {
    pub fn new(scope: &ConfluenceScope) -> Self {
        let contract_digest = crate::contract_digest();
        let mut manifest = Self {
            provider_id: crate::CONFLUENCE_PROVIDER_ID.to_owned(),
            provider_version: crate::CONFLUENCE_PROVIDER_VERSION,
            api_version: CONFLUENCE_API_VERSION.to_owned(),
            contract_digest,
            scope_digest: scope.digest(),
            capabilities: vec![
                ConfluenceCapability::DescribeContentScope,
                ConfluenceCapability::ReadPageEvidence,
                ConfluenceCapability::SearchKnowledge,
                ConfluenceCapability::CompileKnowledgeProposal,
                ConfluenceCapability::RecordKnowledgeReceipt,
                ConfluenceCapability::VerifyKnowledgeResult,
            ],
            manifest_digest: String::new(),
        };
        manifest.manifest_digest = manifest.calculate_digest();
        manifest
    }

    fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.provider_id,
            self.provider_version,
            &self.api_version,
            &self.contract_digest,
            &self.scope_digest,
            &self.capabilities,
        ))
    }

    pub fn digest(&self) -> Digest {
        self.manifest_digest.clone()
    }

    pub fn validate(&self, scope: &ConfluenceScope) -> Result<(), ConfluenceKnowledgeResultError> {
        scope.validate()?;
        if self.provider_id != crate::CONFLUENCE_PROVIDER_ID
            || self.provider_version != crate::CONFLUENCE_PROVIDER_VERSION
            || self.api_version != CONFLUENCE_API_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.scope_digest != scope.digest()
            || self.capabilities.len() != 6
            || self.manifest_digest != self.calculate_digest()
        {
            return Err(ConfluenceKnowledgeResultError::InvalidProviderManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageState {
    Current,
    Archived,
    Deleted,
    AccessLost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageLink {
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub title_digest: Digest,
    pub position: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabelDigest {
    pub label_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageMetadata {
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub space_id: ConfluenceSpaceId,
    pub title_digest: Digest,
    pub state: PageState,
    pub version: PageVersion,
    pub ancestors: Vec<PageLink>,
    pub children: Vec<PageLink>,
    pub labels: Vec<LabelDigest>,
    pub metadata_digest: Digest,
}

impl PageMetadata {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.page_id,
            &self.content_id,
            &self.space_id,
            &self.title_digest,
            &self.state,
            &self.version,
            &self.ancestors,
            &self.children,
            &self.labels,
        ))
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_digest(&self.title_digest, "title digest")?;
        validate_digest(&self.metadata_digest, "metadata digest")?;
        if self.metadata_digest != self.calculate_digest()
            || self.ancestors.len() > MAX_ANCESTORS
            || self.children.len() > MAX_CHILDREN
            || self.labels.len() > MAX_LABELS
        {
            return Err(ConfluenceKnowledgeResultError::AmbiguousEvidence);
        }
        self.version.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelectedBody {
    pub representation: BodyRepresentation,
    pub byte_length: usize,
    pub value_digest: Digest,
    pub truncated: bool,
}

impl SelectedBody {
    pub fn validate(&self, scope: &ConfluenceScope) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_digest(&self.value_digest, "body digest")?;
        if self.representation != scope.body_representation
            || self.byte_length > scope.max_body_bytes
            || self.truncated
        {
            return Err(ConfluenceKnowledgeResultError::AmbiguousEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct PageEvidence {
    pub scope: ConfluenceScope,
    pub metadata: PageMetadata,
    pub body: SelectedBody,
    pub version: PageVersion,
    pub permission_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub partial: bool,
    pub truncated: bool,
    pub evidence_digest: Digest,
}

impl PageEvidence {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.metadata,
            &self.body,
            &self.version,
            &self.permission_digest,
            &self.evidence_source,
            self.partial,
            self.truncated,
        ))
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.scope.validate()?;
        self.metadata.validate()?;
        self.body.validate(&self.scope)?;
        if self.metadata.page_id != self.scope.page_id
            || self.metadata.content_id != self.scope.content_id
            || self.metadata.space_id != self.scope.space_id
            || self.version != self.scope.page_version
            || self.metadata.version != self.scope.page_version
            || self.permission_digest != self.scope.permission_digest
            || self.native_transport
            || self.native_connected
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
            || self.partial
            || self.truncated
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(ConfluenceKnowledgeResultError::AmbiguousEvidence);
        }
        Ok(())
    }
}

/// Cursor value is retained only inside the live provider seam. Its public
/// representation contains digests and a bounded page number, never the raw
/// provider cursor token.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfluenceSearchCursor {
    token: String,
    pub cursor_digest: Digest,
    pub scope_digest: Digest,
    pub cql_digest: Digest,
    pub page: u32,
}

impl ConfluenceSearchCursor {
    pub(crate) fn new(
        token: String,
        scope: &ConfluenceScope,
        page: u32,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        if token.trim().is_empty() || token.len() > 512 || page == 0 || page > MAX_PAGES {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "search cursor",
                reason: String::from("must be bounded and within the page limit"),
            });
        }
        Ok(Self {
            cursor_digest: sha256_digest(token.as_bytes()),
            token,
            scope_digest: scope.digest(),
            cql_digest: scope.cql_template.digest(),
            page,
        })
    }

    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    pub fn digest(&self) -> Digest {
        self.cursor_digest.clone()
    }

    pub fn validate_for(
        &self,
        scope: &ConfluenceScope,
    ) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.scope_digest != scope.digest()
            || self.cql_digest != scope.cql_template.digest()
            || self.page == 0
            || self.page > MAX_PAGES
            || self.cursor_digest != sha256_digest(self.token.as_bytes())
        {
            return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ConfluenceSearchCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfluenceSearchCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("cql_digest", &self.cql_digest)
            .field("page", &self.page)
            .finish_non_exhaustive()
    }
}

impl Serialize for ConfluenceSearchCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConfluenceSearchCursor", 4)?;
        state.serialize_field("cursorDigest", &self.cursor_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("cqlDigest", &self.cql_digest)?;
        state.serialize_field("page", &self.page)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ConfluenceSearchCursor {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(
            "opaque Confluence cursor cannot be restored outside its live provider seam",
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluencePageReadRequest {
    pub scope: ConfluenceScope,
}

impl ConfluencePageReadRequest {
    pub fn new(scope: ConfluenceScope) -> Result<Self, ConfluenceKnowledgeResultError> {
        scope.validate()?;
        Ok(Self { scope })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluenceSearchRequest {
    pub scope: ConfluenceScope,
    pub cql_template: CqlTemplate,
    pub page_size: u32,
    pub cursor: Option<ConfluenceSearchCursor>,
}

impl ConfluenceSearchRequest {
    pub fn new(
        scope: ConfluenceScope,
        page_size: u32,
        cursor: Option<ConfluenceSearchCursor>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        scope.validate()?;
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || page_size > scope.cql_template.max_results()
        {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "search page size",
                reason: format!("must be between 1 and {MAX_PAGE_SIZE}"),
            });
        }
        if let Some(cursor) = &cursor {
            cursor.validate_for(&scope)?;
        }
        Ok(Self {
            cql_template: scope.cql_template.clone(),
            scope,
            page_size,
            cursor,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeSearchHit {
    pub page_id: ConfluencePageId,
    pub content_id: ConfluenceContentId,
    pub space_id: ConfluenceSpaceId,
    pub version: PageVersion,
    pub title_digest: Digest,
    pub excerpt_digest: Digest,
    pub metadata_digest: Digest,
    pub hit_digest: Digest,
}

impl KnowledgeSearchHit {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.page_id,
            &self.content_id,
            &self.space_id,
            &self.version,
            &self.title_digest,
            &self.excerpt_digest,
            &self.metadata_digest,
        ))
    }

    pub fn validate_for(
        &self,
        scope: &ConfluenceScope,
    ) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_digest(&self.title_digest, "search title digest")?;
        validate_digest(&self.excerpt_digest, "search excerpt digest")?;
        validate_digest(&self.metadata_digest, "search metadata digest")?;
        if self.space_id != scope.space_id || self.hit_digest != self.calculate_digest() {
            return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct KnowledgeSearchEvidence {
    pub scope: ConfluenceScope,
    pub cql_digest: Digest,
    pub hits: Vec<KnowledgeSearchHit>,
    pub next_cursor: Option<ConfluenceSearchCursor>,
    pub page: u32,
    pub empty: bool,
    pub partial: bool,
    pub truncated: bool,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub search_digest: Digest,
}

impl KnowledgeSearchEvidence {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.cql_digest,
            &self.hits,
            &self.next_cursor,
            self.page,
            self.empty,
            self.partial,
            self.truncated,
            &self.evidence_source,
        ))
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.scope.validate()?;
        validate_digest(&self.cql_digest, "CQL digest")?;
        if self.cql_digest != self.scope.cql_template.digest()
            || self.page == 0
            || self.page > MAX_PAGES
            || self.hits.len() > MAX_SEARCH_HITS
            || self.empty != self.hits.is_empty()
            || self.native_transport
            || self.native_connected
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
            || self.partial
            || self.truncated
            || self.search_digest != self.calculate_digest()
        {
            return Err(ConfluenceKnowledgeResultError::AmbiguousEvidence);
        }
        for hit in &self.hits {
            hit.validate_for(&self.scope)?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(&self.scope)?;
            if cursor.page < self.page {
                return Err(ConfluenceKnowledgeResultError::AmbiguousEvidence);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KnowledgeEvidence {
    pub page: PageEvidence,
    pub search: Option<KnowledgeSearchEvidence>,
}

impl KnowledgeEvidence {
    pub fn new(
        page: PageEvidence,
        search: Option<KnowledgeSearchEvidence>,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let evidence = Self { page, search };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.page.validate()?;
        if let Some(search) = &self.search {
            search.validate()?;
            if search.scope.digest() != self.page.scope.digest() {
                return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProduct {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub revision: u64,
    pub content_digest: Digest,
    pub objective_digest: Digest,
}

impl MissionWorkProduct {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        revision: u64,
        content_digest: Digest,
        objective_digest: Digest,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        let value = Self {
            project_id,
            mission_id,
            work_product_id,
            revision,
            content_digest,
            objective_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        if self.revision == 0 {
            return Err(ConfluenceKnowledgeResultError::InvalidInput {
                field: "work product revision",
                reason: String::from("must be non-zero"),
            });
        }
        validate_digest(&self.content_digest, "work product content digest")?;
        validate_digest(&self.objective_digest, "objective digest")
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeProposalStatus {
    Proposed,
    Recorded,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct KnowledgeResultProposal {
    pub proposal_id: String,
    pub proposal_digest: Digest,
    pub scope: ConfluenceScope,
    pub work_product: MissionWorkProduct,
    pub evidence_digest: Digest,
    pub page_evidence_digest: Digest,
    pub search_evidence_digest: Option<Digest>,
    pub content_digest: Digest,
    pub page_version: PageVersion,
    pub permission_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub status: KnowledgeProposalStatus,
    pub non_mutating: bool,
    pub external_write_performed: bool,
    pub durable_native_receipt: bool,
    pub native_connected: bool,
}

impl KnowledgeResultProposal {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.work_product,
            &self.evidence_digest,
            &self.page_evidence_digest,
            &self.search_evidence_digest,
            &self.content_digest,
            &self.page_version,
            &self.permission_digest,
            &self.provider_manifest_digest,
            &self.registration_digest,
            &self.evidence_source,
            &self.status,
            self.non_mutating,
            self.external_write_performed,
            self.durable_native_receipt,
            self.native_connected,
        ))
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.scope.validate()?;
        self.work_product.validate()?;
        validate_digest(&self.proposal_digest, "proposal digest")?;
        validate_digest(&self.evidence_digest, "evidence digest")?;
        validate_digest(&self.page_evidence_digest, "page evidence digest")?;
        validate_digest(&self.content_digest, "proposal content digest")?;
        validate_digest(&self.permission_digest, "proposal permission digest")?;
        validate_digest(&self.provider_manifest_digest, "provider manifest digest")?;
        validate_digest(&self.registration_digest, "registration digest")?;
        if let Some(digest) = &self.search_evidence_digest {
            validate_digest(digest, "search evidence digest")?;
        }
        if self.proposal_digest != self.calculate_digest()
            || self.proposal_id != format!("confluence-knowledge-{}", &self.proposal_digest[..24])
            || self.work_product.project_id != self.scope.project_id
            || self.work_product.mission_id != self.scope.mission_id
            || self.work_product.work_product_id != self.scope.work_product_id
            || self.work_product.revision != self.scope.work_product_revision
            || self.page_version != self.scope.page_version
            || self.permission_digest != self.scope.permission_digest
            || !self.non_mutating
            || self.external_write_performed
            || self.durable_native_receipt
            || self.native_connected
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
        {
            return Err(ConfluenceKnowledgeResultError::InvalidProposal);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct KnowledgeResultReceipt {
    pub receipt_id: String,
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
    pub durable_native_receipt: bool,
    pub external_write_performed: bool,
}

impl KnowledgeResultReceipt {
    pub fn calculate_digest(&self) -> Digest {
        canonical_digest(&(
            &self.proposal_digest,
            &self.scope_digest,
            &self.provider_manifest_digest,
            &self.registration_digest,
            &self.evidence_source,
            self.native_transport,
            self.native_connected,
            self.durable_native_receipt,
            self.external_write_performed,
        ))
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        validate_digest(&self.receipt_digest, "receipt digest")?;
        validate_digest(&self.proposal_digest, "receipt proposal digest")?;
        validate_digest(&self.scope_digest, "receipt scope digest")?;
        validate_digest(
            &self.provider_manifest_digest,
            "receipt provider manifest digest",
        )?;
        validate_digest(&self.registration_digest, "receipt registration digest")?;
        if self.receipt_digest != self.calculate_digest()
            || self.receipt_id != format!("confluence-recording-{}", &self.receipt_digest[..24])
            || self.native_transport
            || self.native_connected
            || self.durable_native_receipt
            || self.external_write_performed
            || self.evidence_source.is_native()
            || self.evidence_source.is_connected()
        {
            return Err(ConfluenceKnowledgeResultError::InvalidReadback);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeReadbackField {
    ProposalDigest,
    ScopeDigest,
    ProviderManifestDigest,
    RegistrationDigest,
    EvidenceSource,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedKnowledgeResult {
    pub proposal_digest: Digest,
    pub receipt_digest: Digest,
    pub scope_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub verified: bool,
    pub adopted: bool,
    pub native_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluenceScopeDescription {
    pub scope: ConfluenceScope,
    pub scope_digest: Digest,
    pub site_digest: Digest,
    pub cloud_id_digest: Digest,
    pub account_digest: Digest,
    pub space_digest: Digest,
    pub page_digest: Digest,
    pub content_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub cql_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub evidence_source: ProviderProvenance,
    pub native_transport: bool,
    pub native_connected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revocation_revision: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfluencePluginRegistration {
    pub plugin_id: String,
    pub plugin_version: u64,
    pub adapter_version: u64,
    pub provider_version: u64,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub scope: ConfluenceScope,
    pub scope_digest: Digest,
    pub site_digest: Digest,
    pub cloud_id_digest: Digest,
    pub account_digest: Digest,
    pub space_digest: Digest,
    pub page_digest: Digest,
    pub content_digest: Digest,
    pub version_digest: Digest,
    pub permission_digest: Digest,
    pub cql_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub secret_reference: SecretReference,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub active: bool,
}

impl ConfluencePluginRegistration {
    pub fn new(
        scope: ConfluenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, ConfluenceKnowledgeResultError> {
        scope.validate()?;
        secret_reference.validate()?;
        if secret_reference.scope_digest != scope.digest() {
            return Err(ConfluenceKnowledgeResultError::ScopeMismatch);
        }
        let manifest = ConfluenceProviderManifest::new(&scope);
        let mut registration = Self {
            plugin_id: crate::CONFLUENCE_PLUGIN_ID.to_owned(),
            plugin_version: crate::CONFLUENCE_PLUGIN_VERSION,
            adapter_version: crate::CONFLUENCE_ADAPTER_VERSION,
            provider_version: crate::CONFLUENCE_PROVIDER_VERSION,
            contract_version: crate::CONFLUENCE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_manifest_digest: manifest.digest(),
            scope_digest: scope.digest(),
            site_digest: scope.site.digest(),
            cloud_id_digest: scope.cloud_id.digest(),
            account_digest: scope.account_id.digest(),
            space_digest: scope.space_id.digest(),
            page_digest: scope.page_id.digest(),
            content_digest: scope.content_id.digest(),
            version_digest: scope.page_version.digest(),
            permission_digest: scope.permission_digest.clone(),
            cql_digest: scope.cql_template.digest(),
            project_digest: scope.project_id.digest(),
            mission_digest: scope.mission_id.digest(),
            work_product_digest: scope.work_product_id.digest(),
            scope,
            secret_reference,
            registration_digest: String::new(),
            registration_revision: 1,
            active: true,
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        let value = serde_json::json!([
            self.plugin_id,
            self.plugin_version,
            self.adapter_version,
            self.provider_version,
            self.contract_version,
            self.contract_digest,
            self.provider_manifest_digest,
            self.scope_digest,
            self.site_digest,
            self.cloud_id_digest,
            self.account_digest,
            self.space_digest,
            self.page_digest,
            self.content_digest,
            self.version_digest,
            self.permission_digest,
            self.cql_digest,
            self.project_digest,
            self.mission_digest,
            self.work_product_digest,
            self.secret_reference.digest(),
            self.registration_revision,
            self.active,
        ]);
        canonical_digest(&value)
    }

    pub fn validate(&self) -> Result<(), ConfluenceKnowledgeResultError> {
        self.scope.validate()?;
        self.secret_reference.validate()?;
        let manifest = ConfluenceProviderManifest::new(&self.scope);
        if self.plugin_id != crate::CONFLUENCE_PLUGIN_ID
            || self.plugin_version != crate::CONFLUENCE_PLUGIN_VERSION
            || self.adapter_version != crate::CONFLUENCE_ADAPTER_VERSION
            || self.provider_version != crate::CONFLUENCE_PROVIDER_VERSION
            || self.contract_version != crate::CONFLUENCE_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_manifest_digest != manifest.digest()
            || self.scope_digest != self.scope.digest()
            || self.site_digest != self.scope.site.digest()
            || self.cloud_id_digest != self.scope.cloud_id.digest()
            || self.account_digest != self.scope.account_id.digest()
            || self.space_digest != self.scope.space_id.digest()
            || self.page_digest != self.scope.page_id.digest()
            || self.content_digest != self.scope.content_id.digest()
            || self.version_digest != self.scope.page_version.digest()
            || self.permission_digest != self.scope.permission_digest
            || self.cql_digest != self.scope.cql_template.digest()
            || self.project_digest != self.scope.project_id.digest()
            || self.mission_digest != self.scope.mission_id.digest()
            || self.work_product_digest != self.scope.work_product_id.digest()
            || self.secret_reference.scope_digest != self.scope.digest()
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(ConfluenceKnowledgeResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ConfluenceKnowledgeResultError> {
        self.validate()?;
        if !self.active {
            return Err(ConfluenceKnowledgeResultError::Provider(
                crate::error::ConfluenceProviderError::RegistrationRevoked,
            ));
        }
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(ConfluenceKnowledgeResultError::InvalidScope)?;
        self.active = false;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revocation_revision: self.registration_revision,
            revoked: true,
        })
    }
}
