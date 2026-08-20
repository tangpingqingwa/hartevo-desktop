//! First-party web publication provider seams.
//!
//! This crate owns the GitHub Pages read/proposal and approval-bound publication
//! vertical slices. It uses the existing Connector SDK for authentication,
//! probe, read, scope, freshness, Effect execution context, reconciliation,
//! and verification. External writes require a Broker-created execution
//! capsule and an exact Mission approval binding; a provider receipt is never
//! treated as independent verification without a fresh public readback.

#![deny(unsafe_code)]

use std::fmt;

use hartevo_connector_sdk::ConnectorError;
use hartevo_domain_kernel::{ProjectId, TenantId, WorkProductId};
use hartevo_effect_broker::ProviderContractError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

mod audit;
mod github_pages;
mod publication;
#[cfg(test)]
mod tests;

pub use audit::{
    FilePublicationDurableLog, PublicationAuditEntry, PublicationDurableLog, PublicationOperation,
};
pub use github_pages::{
    BlockedEnvCredentialResolver, EnvironmentGithubCredentialResolver, GithubCredentialResolver,
    GithubPagesAdapter, GithubPagesApiBlob, GithubPagesApiBlobWrite, GithubPagesApiCommit,
    GithubPagesApiCommitWrite, GithubPagesApiObject, GithubPagesApiPages, GithubPagesApiRefUpdate,
    GithubPagesApiSource, GithubPagesApiTree, GithubPagesApiTreeEntry, GithubPagesApiTreeWrite,
    GithubPagesApiTreeWriteEntry, GithubPagesConnection, GithubPagesConnectionState,
    GithubPagesHttpTransport, GithubPagesIndependentReadback, GithubPagesProvider,
    GithubPagesProviderError, GithubPagesProviderExecution, GithubPagesProviderRead,
    GithubPagesProviderReceipt, GithubPagesProviderReconciliation, GithubPagesPublicReadback,
    GithubPagesPublicationAction, GithubPagesPublishPayload, GithubPagesRepositorySnapshot,
    GithubPagesTransportError, GithubPagesVerification, UreqGithubPagesTransport,
};
pub use publication::{
    CanonicalDiffEntry, CanonicalDiffKind, CanonicalTreeDiff, MissionPublicationAdoptableResult,
    MissionPublicationConsumer, MissionPublicationProposalResult, MissionPublicationReadResult,
    PreparedPublicationEffect, PublicationAction, PublicationApprovalBinding,
    PublicationExecutionAuthorization, PublicationOutcome, PublicationProposalInput,
    PublicationReadResult, PublicationReconcileResult, PublicationResultConsumer,
    PublicationRollbackInput, SitePublicationService,
};

pub const WEB_PUBLICATION_SCHEMA_VERSION: &str = "hartevo-web-adapters/github-pages/v1";
pub const WEB_PUBLICATION_PLUGIN_ID: &str = "site-publication.github-pages";
pub const SITE_PUBLICATION_SERVICE: &str = "SitePublicationService";
pub const GITHUB_PAGES_PROVIDER: &str = "GitHub Pages adapter";
pub const MISSION_PUBLICATION_CONSUMER: &str = "Mission capability/result";
pub const GITHUB_PROVIDER_ID: &str = "github";
pub const GITHUB_PAGES_ADAPTER_ID: &str = "web.github-pages";
pub const GITHUB_PAGES_ADAPTER_VERSION: u32 = 1;
pub const GITHUB_PAGES_PLUGIN_VERSION: &str = "github-pages-publication/v1";
pub const GITHUB_PAGES_REGISTRY_VERSION: &str = "web-publication.github-pages/v1";
pub const GITHUB_PAGES_REQUIRED_SCOPES: [&str; 3] =
    ["contents:read", "contents:write", "pages:read"];
pub const GITHUB_PAGES_CONTRACT_JSON: &str = include_str!("../contracts/github-pages.v1.json");

/// Identifiers for the typed publication projection. These are intentionally
/// separate from provider payloads and from the SDK's connector scope.
macro_rules! web_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7().to_string())
            }

            pub fn from_stable(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn validate(&self) -> Result<(), WebPublicationError> {
                if self.0.trim().is_empty() || self.0.chars().any(char::is_control) {
                    return Err(WebPublicationError::InvalidInput {
                        detail: concat!(stringify!($name), " must be non-empty").to_owned(),
                    });
                }
                Ok(())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

web_identifier!(SiteId);
web_identifier!(DomainId);
web_identifier!(PublicationId);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WebPublicationError {
    #[error("BLOCKED_ENV: {detail}")]
    BlockedEnv { detail: String },
    #[error("DISCONNECTED: {detail}")]
    Disconnected { detail: String },
    #[error("provider rejected the request: {detail}")]
    Provider { detail: String },
    #[error("invalid publication input: {detail}")]
    InvalidInput { detail: String },
    #[error("publication scope mismatch: {detail}")]
    ScopeMismatch { detail: String },
    #[error("publication contract is invalid: {detail}")]
    Contract { detail: String },
    #[error("durable publication log failed: {detail}")]
    Audit { detail: String },
    #[error("publication serialization failed: {detail}")]
    Serialization { detail: String },
}

impl WebPublicationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BlockedEnv { .. } => "BLOCKED_ENV",
            Self::Disconnected { .. } => "DISCONNECTED",
            Self::Provider { .. } => "PROVIDER_REJECTED",
            Self::InvalidInput { .. } => "INVALID_INPUT",
            Self::ScopeMismatch { .. } => "SCOPE_MISMATCH",
            Self::Contract { .. } => "CONTRACT_INVALID",
            Self::Audit { .. } => "AUDIT_FAILED",
            Self::Serialization { .. } => "SERIALIZATION_FAILED",
        }
    }
}

impl From<ConnectorError> for WebPublicationError {
    fn from(error: ConnectorError) -> Self {
        Self::Provider {
            detail: error.to_string(),
        }
    }
}

impl From<ProviderContractError> for WebPublicationError {
    fn from(error: ProviderContractError) -> Self {
        Self::Contract {
            detail: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for WebPublicationError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization {
            detail: error.to_string(),
        }
    }
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

pub(crate) fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
        digest.update(b"|");
    }
    format!("{:x}", digest.finalize())
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn validate_digest(value: &str, field: &str) -> Result<(), WebPublicationError> {
    if is_digest(value) {
        Ok(())
    } else {
        Err(WebPublicationError::InvalidInput {
            detail: format!("{field} must be a lowercase SHA-256 digest"),
        })
    }
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), WebPublicationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(WebPublicationError::InvalidInput {
            detail: format!("{field} must be non-empty"),
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteFile {
    pub path: String,
    pub content: Vec<u8>,
    pub content_digest: String,
}

impl SiteFile {
    pub fn text(
        path: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, WebPublicationError> {
        Self::new(path, content.into().into_bytes())
    }

    pub fn new(path: impl Into<String>, content: Vec<u8>) -> Result<Self, WebPublicationError> {
        let path = path.into();
        validate_site_path(&path)?;
        let content_digest = digest_bytes(&content);
        Ok(Self {
            path,
            content,
            content_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub id: SiteId,
    pub revision: u64,
    pub files: Vec<SiteFile>,
    pub content_digest: String,
    pub source_work_product_id: WorkProductId,
    pub source_work_product_revision: u64,
    pub source_work_product_digest: String,
}

impl Site {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        id: SiteId,
        revision: u64,
        files: impl IntoIterator<Item = SiteFile>,
        source_work_product_id: WorkProductId,
        source_work_product_revision: u64,
        source_work_product_digest: impl Into<String>,
    ) -> Result<Self, WebPublicationError> {
        id.validate()?;
        let files = canonical_files(files)?;
        let source_work_product_digest = source_work_product_digest.into();
        validate_digest(&source_work_product_digest, "source_work_product_digest")?;
        if revision == 0 || source_work_product_revision == 0 {
            return Err(WebPublicationError::InvalidInput {
                detail: "site and source work product revisions must be positive".to_owned(),
            });
        }
        let content_digest = file_tree_digest(&files);
        Ok(Self {
            tenant_id,
            project_id,
            id,
            revision,
            files,
            content_digest,
            source_work_product_id,
            source_work_product_revision,
            source_work_product_digest,
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        self.id.validate()?;
        if self.revision == 0 || self.source_work_product_revision == 0 {
            return Err(WebPublicationError::InvalidInput {
                detail: "site and source work product revisions must be positive".to_owned(),
            });
        }
        validate_identifier(
            self.source_work_product_id.as_str(),
            "source_work_product_id",
        )?;
        validate_digest(
            &self.source_work_product_digest,
            "source_work_product_digest",
        )?;
        let files = canonical_files(self.files.clone())?;
        if self.content_digest != file_tree_digest(&files) {
            return Err(WebPublicationError::InvalidInput {
                detail: "site content_digest does not match its canonical file tree".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub id: DomainId,
    pub hostname: String,
}

impl Domain {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        id: DomainId,
        hostname: impl Into<String>,
    ) -> Result<Self, WebPublicationError> {
        id.validate()?;
        let hostname = hostname.into();
        validate_hostname(&hostname)?;
        Ok(Self {
            tenant_id,
            project_id,
            id,
            hostname,
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        self.id.validate()?;
        validate_hostname(&self.hostname)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubPagesEnvironment {
    Staging,
    Production,
}

impl GithubPagesEnvironment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationTarget {
    pub provider: String,
    pub account_id: String,
    pub owner: String,
    pub repository: String,
    pub git_ref: String,
    pub pages_url: String,
    pub environment: GithubPagesEnvironment,
    pub configuration_digest: String,
}

impl PublicationTarget {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        provider: impl Into<String>,
        account_id: impl Into<String>,
        owner: impl Into<String>,
        repository: impl Into<String>,
        git_ref: impl Into<String>,
        pages_url: impl Into<String>,
        environment: GithubPagesEnvironment,
    ) -> Result<Self, WebPublicationError> {
        let provider = provider.into();
        let account_id = account_id.into();
        let owner = owner.into();
        let repository = repository.into();
        let git_ref = git_ref.into();
        let pages_url = canonical_pages_url(&pages_url.into())?;
        for (value, field) in [
            (provider.as_str(), "provider"),
            (account_id.as_str(), "account_id"),
            (owner.as_str(), "owner"),
            (repository.as_str(), "repository"),
            (git_ref.as_str(), "git_ref"),
        ] {
            validate_identifier(value, field)?;
        }
        if provider != GITHUB_PROVIDER_ID
            || owner.contains('/')
            || repository.contains('/')
            || git_ref.starts_with('/')
            || git_ref.contains("..")
        {
            return Err(WebPublicationError::InvalidInput {
                detail: "GitHub Pages target contains an invalid repository or ref".to_owned(),
            });
        }
        let configuration_digest = digest_parts([
            provider.as_str(),
            account_id.as_str(),
            owner.as_str(),
            repository.as_str(),
            git_ref.as_str(),
            pages_url.as_str(),
            environment.as_str(),
        ]);
        Ok(Self {
            provider,
            account_id,
            owner,
            repository,
            git_ref,
            pages_url,
            environment,
            configuration_digest,
        })
    }

    pub(crate) fn validate_domain(&self, domain: &Domain) -> Result<(), WebPublicationError> {
        let url = Url::parse(&self.pages_url).map_err(|_| WebPublicationError::InvalidInput {
            detail: "Pages URL is not a URL".to_owned(),
        })?;
        if url.host_str() != Some(domain.hostname.as_str()) {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "Domain hostname does not match the exact GitHub Pages URL".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Publication {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub id: PublicationId,
    pub connection_id: String,
    pub site_id: SiteId,
    pub domain_id: DomainId,
    pub target: PublicationTarget,
    pub source_work_product_id: WorkProductId,
    pub source_work_product_revision: u64,
    pub source_work_product_digest: String,
    pub site_revision: u64,
}

impl Publication {
    pub(crate) fn new(
        mission: &hartevo_domain_kernel::Mission,
        site: &Site,
        domain: &Domain,
        id: PublicationId,
        connection_id: impl Into<String>,
        target: PublicationTarget,
    ) -> Result<Self, WebPublicationError> {
        id.validate()?;
        let connection_id = connection_id.into();
        validate_identifier(&connection_id, "connection_id")?;
        if site.tenant_id != mission.tenant_id
            || site.project_id != mission.project_id
            || domain.tenant_id != mission.tenant_id
            || domain.project_id != mission.project_id
        {
            return Err(WebPublicationError::ScopeMismatch {
                detail: "Mission, Site, and Domain tenant/project scopes differ".to_owned(),
            });
        }
        target.validate_domain(domain)?;
        Ok(Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            id,
            connection_id,
            site_id: site.id.clone(),
            domain_id: domain.id.clone(),
            target,
            source_work_product_id: site.source_work_product_id.clone(),
            source_work_product_revision: site.source_work_product_revision,
            source_work_product_digest: site.source_work_product_digest.clone(),
            site_revision: site.revision,
        })
    }

    pub(crate) fn digest(&self) -> String {
        digest_parts([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
            self.id.as_str(),
            self.connection_id.as_str(),
            self.site_id.as_str(),
            self.domain_id.as_str(),
            self.target.configuration_digest.as_str(),
            self.source_work_product_id.as_str(),
            &self.source_work_product_revision.to_string(),
            self.source_work_product_digest.as_str(),
            &self.site_revision.to_string(),
        ])
    }
}

pub(crate) fn canonical_files(
    files: impl IntoIterator<Item = SiteFile>,
) -> Result<Vec<SiteFile>, WebPublicationError> {
    let mut files = files.into_iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));
    for pair in files.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(WebPublicationError::InvalidInput {
                detail: format!("duplicate site file path {}", pair[0].path),
            });
        }
    }
    for file in &files {
        validate_site_path(&file.path)?;
        validate_digest(&file.content_digest, "site file content_digest")?;
        if file.content_digest != digest_bytes(&file.content) {
            return Err(WebPublicationError::InvalidInput {
                detail: format!("content digest mismatch for {}", file.path),
            });
        }
    }
    Ok(files)
}

pub(crate) fn file_tree_digest(files: &[SiteFile]) -> String {
    let mut digest = Sha256::new();
    for file in files {
        digest.update(file.path.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(file.path.as_bytes());
        digest.update(b"|");
        digest.update(file.content_digest.as_bytes());
        digest.update(b"|");
    }
    format!("{:x}", digest.finalize())
}

fn validate_site_path(path: &str) -> Result<(), WebPublicationError> {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || path.chars().any(char::is_control)
    {
        return Err(WebPublicationError::InvalidInput {
            detail: format!("invalid site file path {path}"),
        });
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<(), WebPublicationError> {
    let url = Url::parse(&format!("https://{hostname}/")).map_err(|_| {
        WebPublicationError::InvalidInput {
            detail: "domain hostname is invalid".to_owned(),
        }
    })?;
    if url.host_str() != Some(hostname)
        || url.port().is_some()
        || hostname.chars().any(char::is_whitespace)
    {
        return Err(WebPublicationError::InvalidInput {
            detail: "domain must be an exact hostname without a port".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn canonical_pages_url(value: &str) -> Result<String, WebPublicationError> {
    let value = value.trim_end_matches('/');
    let url = Url::parse(value).map_err(|_| WebPublicationError::InvalidInput {
        detail: "Pages URL is invalid".to_owned(),
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(WebPublicationError::InvalidInput {
            detail: "Pages URL must be an HTTPS URL without credentials or query".to_owned(),
        });
    }
    Ok(value.to_owned())
}

pub(crate) fn digest_json<T: Serialize>(value: &T) -> Result<String, WebPublicationError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

pub(crate) fn map_provider_connector_error(error: &ConnectorError) -> WebPublicationError {
    WebPublicationError::Provider {
        detail: error.to_string(),
    }
}
