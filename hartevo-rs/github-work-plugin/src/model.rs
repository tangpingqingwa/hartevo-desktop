use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::ProviderProvenanceClass;
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId, WorkProductId};
use serde::{Deserialize, Serialize};

use crate::{
    GITHUB_ACCEPT_HEADER, GITHUB_API_VERSION, GITHUB_WORK_CAPABILITY_ID, GITHUB_WORK_MAX_PAGE_SIZE,
    GithubWorkError, digest_json, valid_digest, valid_github_sha, validate_identifier,
    validate_text,
};

pub const RESOURCE_ISSUES: &str = "issues";
pub const RESOURCE_PULL_REQUESTS: &str = "pull_requests";
pub const RESOURCE_CHECK_RUNS: &str = "check_runs";

/// The raw installation payload is decoded only inside the provider.  It is
/// intentionally not exposed as a Mission-facing projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubInstallationPayload {
    pub id: u64,
    #[serde(default)]
    pub account: Option<GithubAccountPayload>,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default)]
    pub suspended_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubAccountPayload {
    #[serde(default)]
    pub login: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubRepositoryPayload {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub owner: GithubAccountPayload,
    pub default_branch: String,
    #[serde(default)]
    pub permissions: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubIssuePayload {
    pub number: u64,
    pub title: String,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubPullRequestPayload {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub base: GithubGitRefPayload,
    pub head: GithubGitRefPayload,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub merged: bool,
    #[serde(default)]
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubGitRefPayload {
    pub ref_name: String,
    pub sha: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GithubCheckRunPayload {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    pub head_sha: String,
    #[serde(default)]
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum GithubHttpResponseBody {
    Installation(GithubInstallationPayload),
    Repository(GithubRepositoryPayload),
    Issues(Vec<GithubIssuePayload>),
    PullRequests(Vec<GithubPullRequestPayload>),
    CheckRuns(Vec<GithubCheckRunPayload>),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GithubEndpoint {
    Installation {
        installation_id: u64,
    },
    Repository {
        owner: String,
        repository: String,
    },
    Issues {
        owner: String,
        repository: String,
        page: u32,
        per_page: u32,
    },
    PullRequests {
        owner: String,
        repository: String,
        page: u32,
        per_page: u32,
    },
    CheckRuns {
        owner: String,
        repository: String,
        reference: String,
        page: u32,
        per_page: u32,
    },
}

impl GithubEndpoint {
    pub fn resource(&self) -> &'static str {
        match self {
            Self::Installation { .. } | Self::Repository { .. } => "probe",
            Self::Issues { .. } => RESOURCE_ISSUES,
            Self::PullRequests { .. } => RESOURCE_PULL_REQUESTS,
            Self::CheckRuns { .. } => RESOURCE_CHECK_RUNS,
        }
    }

    pub const fn page(&self) -> Option<u32> {
        match self {
            Self::Installation { .. } | Self::Repository { .. } => None,
            Self::Issues { page, .. }
            | Self::PullRequests { page, .. }
            | Self::CheckRuns { page, .. } => Some(*page),
        }
    }

    pub const fn per_page(&self) -> Option<u32> {
        match self {
            Self::Installation { .. } | Self::Repository { .. } => None,
            Self::Issues { per_page, .. }
            | Self::PullRequests { per_page, .. }
            | Self::CheckRuns { per_page, .. } => Some(*per_page),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubHttpRequestHeaders {
    pub accept: String,
    pub api_version: String,
    pub if_none_match: Option<String>,
}

impl GithubHttpRequestHeaders {
    pub fn new(if_none_match: Option<String>) -> Result<Self, GithubWorkError> {
        if let Some(etag) = &if_none_match {
            validate_text(etag, "etag", 512)?;
        }
        Ok(Self {
            accept: GITHUB_ACCEPT_HEADER.to_owned(),
            api_version: GITHUB_API_VERSION.to_owned(),
            if_none_match,
        })
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        if self.accept != GITHUB_ACCEPT_HEADER || self.api_version != GITHUB_API_VERSION {
            return Err(GithubWorkError::InvalidInput(
                "GitHub request headers must use the supported API version and media type"
                    .to_owned(),
            ));
        }
        if let Some(etag) = &self.if_none_match {
            validate_text(etag, "etag", 512)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubHttpRequest {
    pub endpoint: GithubEndpoint,
    pub headers: GithubHttpRequestHeaders,
    pub observed_at: DateTime<Utc>,
}

impl GithubHttpRequest {
    pub fn new(
        endpoint: GithubEndpoint,
        if_none_match: Option<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, GithubWorkError> {
        let request = Self {
            endpoint,
            headers: GithubHttpRequestHeaders::new(if_none_match)?,
            observed_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.headers.validate()?;
        if self.observed_at.timestamp() <= 0 {
            return Err(GithubWorkError::InvalidInput(
                "request observation time must be a real UTC instant".to_owned(),
            ));
        }
        match &self.endpoint {
            GithubEndpoint::Installation { installation_id } => {
                if *installation_id == 0 {
                    return Err(GithubWorkError::InvalidInput(
                        "installation id must be positive".to_owned(),
                    ));
                }
            }
            GithubEndpoint::Repository { owner, repository }
            | GithubEndpoint::Issues {
                owner, repository, ..
            }
            | GithubEndpoint::PullRequests {
                owner, repository, ..
            }
            | GithubEndpoint::CheckRuns {
                owner, repository, ..
            } => {
                validate_identifier(owner, "owner")?;
                validate_identifier(repository, "repository")?;
                if owner.contains('/') || repository.contains('/') {
                    return Err(GithubWorkError::InvalidInput(
                        "owner and repository must be one path segment".to_owned(),
                    ));
                }
            }
        }
        if let GithubEndpoint::CheckRuns { reference, .. } = &self.endpoint {
            validate_text(reference, "check reference", 256)?;
            if reference.contains("..") || reference.contains('\\') {
                return Err(GithubWorkError::InvalidInput(
                    "check reference contains an unsafe path segment".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubRateLimitReceipt {
    pub limit: u64,
    pub remaining: u64,
    pub reset_at: DateTime<Utc>,
}

impl GithubRateLimitReceipt {
    pub fn new(
        limit: u64,
        remaining: u64,
        reset_at: DateTime<Utc>,
    ) -> Result<Self, GithubWorkError> {
        if limit == 0 || remaining > limit || reset_at.timestamp() <= 0 {
            return Err(GithubWorkError::InvalidInput(
                "rate-limit receipt is outside its bounded contract".to_owned(),
            ));
        }
        Ok(Self {
            limit,
            remaining,
            reset_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubHttpResponseReceipt {
    pub status: u16,
    pub api_version: String,
    pub etag: Option<String>,
    pub rate_limit: GithubRateLimitReceipt,
    pub next_page: Option<u32>,
    pub request_id: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl GithubHttpResponseReceipt {
    pub fn new(
        status: u16,
        api_version: impl Into<String>,
        etag: Option<String>,
        rate_limit: GithubRateLimitReceipt,
        next_page: Option<u32>,
        request_id: Option<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, GithubWorkError> {
        let api_version = api_version.into();
        if !matches!(status, 200..=299 | 304)
            || api_version != GITHUB_API_VERSION
            || observed_at.timestamp() <= 0
            || next_page == Some(0)
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub response receipt is outside the supported API contract".to_owned(),
            ));
        }
        if let Some(etag) = &etag {
            validate_text(etag, "etag", 512)?;
        }
        if let Some(request_id) = &request_id {
            validate_text(request_id, "request_id", 256)?;
        }
        Ok(Self {
            status,
            api_version,
            etag,
            rate_limit,
            next_page,
            request_id,
            observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubHttpResponse {
    pub body: Option<GithubHttpResponseBody>,
    pub receipt: GithubHttpResponseReceipt,
}

impl GithubHttpResponse {
    pub fn new(
        body: Option<GithubHttpResponseBody>,
        receipt: GithubHttpResponseReceipt,
    ) -> Result<Self, GithubWorkError> {
        if receipt.status == 304 && body.is_some() {
            return Err(GithubWorkError::InvalidInput(
                "304 responses cannot carry a decoded body".to_owned(),
            ));
        }
        if receipt.status != 304 && body.is_none() {
            return Err(GithubWorkError::InvalidInput(
                "successful GitHub responses require a decoded body".to_owned(),
            ));
        }
        Ok(Self { body, receipt })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPageReceipt {
    pub resource: String,
    pub page: u32,
    pub per_page: u32,
    pub request_digest: String,
    pub response_digest: String,
    pub response: GithubHttpResponseReceipt,
}

impl GithubPageReceipt {
    pub(crate) fn from_response(
        request: &GithubHttpRequest,
        response: &GithubHttpResponse,
    ) -> Result<Self, GithubWorkError> {
        let page = request.endpoint.page().unwrap_or(1);
        let per_page = request.endpoint.per_page().unwrap_or(1);
        let request_digest = digest_json(request)?;
        let response_digest = digest_json(&response.body)?;
        if !valid_digest(&request_digest) || !valid_digest(&response_digest) {
            return Err(GithubWorkError::InvalidInput(
                "page receipt digest is not canonical".to_owned(),
            ));
        }
        Ok(Self {
            resource: request.endpoint.resource().to_owned(),
            page,
            per_page,
            request_digest,
            response_digest,
            response: response.receipt.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkReadRequest {
    pub issue_number: Option<u64>,
    pub pull_request_number: Option<u64>,
    pub check_ref: Option<String>,
    pub page_size: u32,
    pub etags: BTreeMap<String, String>,
}

impl GithubWorkReadRequest {
    pub fn new(
        issue_number: Option<u64>,
        pull_request_number: Option<u64>,
        check_ref: Option<String>,
    ) -> Result<Self, GithubWorkError> {
        let request = Self {
            issue_number,
            pull_request_number,
            check_ref,
            page_size: GITHUB_WORK_MAX_PAGE_SIZE,
            etags: BTreeMap::new(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_page_size(mut self, page_size: u32) -> Result<Self, GithubWorkError> {
        self.page_size = page_size;
        self.validate()?;
        Ok(self)
    }

    pub fn with_etag(
        mut self,
        resource: impl Into<String>,
        etag: impl Into<String>,
    ) -> Result<Self, GithubWorkError> {
        self.etags.insert(resource.into(), etag.into());
        self.validate()?;
        Ok(self)
    }

    pub fn etag_for(&self, resource: &str) -> Option<String> {
        self.etags.get(resource).cloned()
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        if self.issue_number.is_none()
            && self.pull_request_number.is_none()
            && self.check_ref.is_none()
        {
            return Err(GithubWorkError::InvalidInput(
                "a read must select an issue, pull request, or check ref".to_owned(),
            ));
        }
        if self.issue_number.is_some_and(|number| number == 0)
            || self.pull_request_number.is_some_and(|number| number == 0)
            || !(1..=GITHUB_WORK_MAX_PAGE_SIZE).contains(&self.page_size)
        {
            return Err(GithubWorkError::InvalidInput(
                "issue/PR numbers and page size must be positive and bounded".to_owned(),
            ));
        }
        if let Some(check_ref) = &self.check_ref {
            validate_text(check_ref, "check_ref", 256)?;
            if check_ref.contains("..") || check_ref.contains('\\') {
                return Err(GithubWorkError::InvalidInput(
                    "check_ref contains an unsafe path segment".to_owned(),
                ));
            }
        }
        for (resource, etag) in &self.etags {
            if !matches!(
                resource.as_str(),
                RESOURCE_ISSUES | RESOURCE_PULL_REQUESTS | RESOURCE_CHECK_RUNS
            ) {
                return Err(GithubWorkError::InvalidInput(
                    "etag resource is not a supported GitHub work read".to_owned(),
                ));
            }
            validate_text(etag, "etag", 512)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubRepositoryProjection {
    pub id: u64,
    pub owner: String,
    pub name: String,
    pub full_name: String,
    pub default_branch: String,
    pub permissions: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubIssueProjection {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub body: Option<String>,
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPullRequestProjection {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub base_ref: String,
    pub base_sha: String,
    pub head_ref: String,
    pub head_sha: String,
    pub body: Option<String>,
    pub draft: bool,
    pub merged: bool,
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubCheckRunProjection {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub head_sha: String,
    pub html_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkResultMetadata {
    pub scope_digest: String,
    pub registration_digest: String,
    pub probe_digest: String,
    pub provider_revision: u64,
    pub plugin_version: String,
    pub plugin_digest: String,
    pub provenance_class: ProviderProvenanceClass,
    pub native_transport: bool,
    pub observed_at: DateTime<Utc>,
}

impl GithubWorkResultMetadata {
    pub fn validate(&self) -> Result<(), GithubWorkError> {
        if !valid_digest(&self.scope_digest)
            || !valid_digest(&self.registration_digest)
            || !valid_digest(&self.probe_digest)
            || !valid_digest(&self.plugin_digest)
            || self.provider_revision == 0
            || self.plugin_version != crate::GITHUB_WORK_PLUGIN_VERSION_TEXT
            || self.plugin_digest != crate::github_work_plugin_digest()
            || (self.native_transport
                && self.provenance_class != ProviderProvenanceClass::ProductionProvider)
            || self.observed_at.timestamp() <= 0
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub Work result metadata is not canonical".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.native_transport
            && self.provenance_class == ProviderProvenanceClass::ProductionProvider
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkReadProjection {
    pub metadata: GithubWorkResultMetadata,
    pub repository: GithubRepositoryProjection,
    pub issue: Option<GithubIssueProjection>,
    pub pull_request: Option<GithubPullRequestProjection>,
    pub check_runs: Vec<GithubCheckRunProjection>,
    pub page_receipts: Vec<GithubPageReceipt>,
    pub result_digest: String,
}

impl GithubWorkReadProjection {
    pub(crate) fn seal(
        metadata: GithubWorkResultMetadata,
        repository: GithubRepositoryProjection,
        issue: Option<GithubIssueProjection>,
        pull_request: Option<GithubPullRequestProjection>,
        check_runs: Vec<GithubCheckRunProjection>,
        page_receipts: Vec<GithubPageReceipt>,
    ) -> Result<Self, GithubWorkError> {
        metadata.validate()?;
        let result_digest = digest_json(&(
            &metadata,
            &repository,
            &issue,
            &pull_request,
            &check_runs,
            &page_receipts,
        ))?;
        Ok(Self {
            metadata,
            repository,
            issue,
            pull_request,
            check_runs,
            page_receipts,
            result_digest,
        })
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.metadata.validate()?;
        self.repository.validate()?;
        if let Some(issue) = &self.issue {
            issue.validate()?;
        }
        if let Some(pull_request) = &self.pull_request {
            pull_request.validate()?;
        }
        for check_run in &self.check_runs {
            check_run.validate()?;
        }
        for page_receipt in &self.page_receipts {
            page_receipt.validate()?;
        }
        if !valid_digest(&self.result_digest) {
            return Err(GithubWorkError::InvalidInput(
                "GitHub Work read result digest is invalid".to_owned(),
            ));
        }
        let expected = digest_json(&(
            &self.metadata,
            &self.repository,
            &self.issue,
            &self.pull_request,
            &self.check_runs,
            &self.page_receipts,
        ))?;
        if expected != self.result_digest {
            return Err(GithubWorkError::InvalidInput(
                "GitHub Work read result digest does not match its projection".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn requested_capability(&self) -> &'static str {
        GITHUB_WORK_CAPABILITY_ID
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum GithubProposalTarget {
    IssueComment { issue_number: u64 },
    PullRequestComment { pull_request_number: u64 },
    PullRequestUpdate { pull_request_number: u64 },
}

impl GithubProposalTarget {
    pub const fn number(&self) -> u64 {
        match self {
            Self::IssueComment { issue_number }
            | Self::PullRequestComment {
                pull_request_number: issue_number,
            }
            | Self::PullRequestUpdate {
                pull_request_number: issue_number,
            } => *issue_number,
        }
    }

    pub const fn requires_pull_request(&self) -> bool {
        !matches!(self, Self::IssueComment { .. })
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        if self.number() == 0 {
            return Err(GithubWorkError::InvalidInput(
                "proposal target number must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubPermissionReceipt {
    pub installation_id: u64,
    pub permissions: BTreeMap<String, String>,
    pub required_permissions: BTreeMap<String, String>,
    pub exact_required_permissions: bool,
    pub observed_at: DateTime<Utc>,
    pub response: GithubHttpResponseReceipt,
    pub receipt_digest: String,
}

impl GithubPermissionReceipt {
    pub(crate) fn seal(
        installation_id: u64,
        permissions: BTreeMap<String, String>,
        required_permissions: BTreeMap<String, String>,
        observed_at: DateTime<Utc>,
        response: GithubHttpResponseReceipt,
    ) -> Result<Self, GithubWorkError> {
        if installation_id == 0 || observed_at.timestamp() <= 0 {
            return Err(GithubWorkError::InvalidInput(
                "permission receipt identity is invalid".to_owned(),
            ));
        }
        let exact_required_permissions = required_permissions.iter().all(|(name, required)| {
            permissions
                .get(name)
                .is_some_and(|granted| permission_level_satisfies(granted, required))
        });
        let receipt_digest = digest_json(&(
            installation_id,
            &permissions,
            &required_permissions,
            exact_required_permissions,
            observed_at,
            &response,
        ))?;
        Ok(Self {
            installation_id,
            permissions,
            required_permissions,
            exact_required_permissions,
            observed_at,
            response,
            receipt_digest,
        })
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        if self.installation_id == 0
            || !self.exact_required_permissions
            || !valid_digest(&self.receipt_digest)
        {
            return Err(GithubWorkError::PermissionDrift);
        }
        let expected = digest_json(&(
            self.installation_id,
            &self.permissions,
            &self.required_permissions,
            self.exact_required_permissions,
            self.observed_at,
            &self.response,
        ))?;
        if expected != self.receipt_digest {
            return Err(GithubWorkError::PermissionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubWorkProposal {
    pub target: GithubProposalTarget,
    pub title: Option<String>,
    pub body: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub work_product_digest: String,
    pub repository_full_name: String,
    pub default_branch: String,
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub source_read_digest: String,
    pub metadata: GithubWorkResultMetadata,
    pub preview_only: bool,
    pub external_mutation_created: bool,
    pub mutation_authority: String,
    pub proposal_digest: String,
}

impl GithubWorkProposal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        target: GithubProposalTarget,
        title: Option<String>,
        body: String,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        work_product_digest: String,
        projection: &GithubWorkReadProjection,
    ) -> Result<Self, GithubWorkError> {
        target.validate()?;
        projection.validate()?;
        if let Some(title) = &title {
            validate_text(title, "proposal title", 512)?;
        }
        validate_text(&body, "proposal body", 64 * 1024)?;
        if work_product_revision == 0
            || !valid_digest(&work_product_digest)
            || !valid_digest(&projection.result_digest)
        {
            return Err(GithubWorkError::InvalidInput(
                "proposal Work Product or read binding is invalid".to_owned(),
            ));
        }
        if target.requires_pull_request()
            && projection
                .pull_request
                .as_ref()
                .map(|pull_request| pull_request.number)
                != Some(target.number())
        {
            return Err(GithubWorkError::ScopeMismatch(
                "pull request proposal target is not the exact read projection".to_owned(),
            ));
        }
        if !target.requires_pull_request()
            && projection.issue.as_ref().map(|issue| issue.number) != Some(target.number())
        {
            return Err(GithubWorkError::ScopeMismatch(
                "issue proposal target is not the exact read projection".to_owned(),
            ));
        }
        let (base_sha, head_sha) = if target.requires_pull_request() {
            projection
                .pull_request
                .as_ref()
                .map_or((None, None), |pull_request| {
                    (
                        Some(pull_request.base_sha.clone()),
                        Some(pull_request.head_sha.clone()),
                    )
                })
        } else {
            (None, None)
        };
        let repository_full_name = projection.repository.full_name.clone();
        let default_branch = projection.repository.default_branch.clone();
        let metadata = projection.metadata.clone();
        let mut proposal = Self {
            target,
            title,
            body,
            tenant_id,
            project_id,
            mission_id,
            work_product_id,
            work_product_revision,
            work_product_digest,
            repository_full_name,
            default_branch,
            base_sha,
            head_sha,
            source_read_digest: projection.result_digest.clone(),
            metadata,
            preview_only: true,
            external_mutation_created: false,
            mutation_authority: "deferred_until_approval_and_layer2".to_owned(),
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.calculate_digest()?;
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), GithubWorkError> {
        self.target.validate()?;
        validate_text(&self.body, "proposal body", 64 * 1024)?;
        if let Some(title) = &self.title {
            validate_text(title, "proposal title", 512)?;
        }
        if self.work_product_revision == 0
            || !valid_digest(&self.work_product_digest)
            || !valid_digest(&self.source_read_digest)
            || !valid_digest(&self.proposal_digest)
            || self.repository_full_name.split('/').count() != 2
            || self.default_branch.trim().is_empty()
            || !self.preview_only
            || self.external_mutation_created
            || self.mutation_authority != "deferred_until_approval_and_layer2"
        {
            return Err(GithubWorkError::InvalidInput(
                "proposal is not a canonical preview-only binding".to_owned(),
            ));
        }
        self.metadata.validate()?;
        if self.metadata.plugin_digest != crate::github_work_plugin_digest() {
            return Err(GithubWorkError::InvalidInput(
                "proposal plugin digest is not the checked-in GitHub Work contract".to_owned(),
            ));
        }
        if self.target.requires_pull_request() {
            if self.base_sha.is_none() || self.head_sha.is_none() {
                return Err(GithubWorkError::StaleHead);
            }
        } else if self.base_sha.is_some() || self.head_sha.is_some() {
            return Err(GithubWorkError::ScopeMismatch(
                "issue comment proposals cannot carry pull request head bindings".to_owned(),
            ));
        }
        if let Some(base_sha) = &self.base_sha
            && !valid_github_sha(base_sha)
        {
            return Err(GithubWorkError::StaleHead);
        }
        if let Some(head_sha) = &self.head_sha
            && !valid_github_sha(head_sha)
        {
            return Err(GithubWorkError::StaleHead);
        }
        if self.calculate_digest()? != self.proposal_digest {
            return Err(GithubWorkError::InvalidInput(
                "proposal digest does not match its immutable fields".to_owned(),
            ));
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, GithubWorkError> {
        digest_json(&GithubWorkProposalDigest {
            target: &self.target,
            title: &self.title,
            body: &self.body,
            tenant_id: &self.tenant_id,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            work_product_digest: &self.work_product_digest,
            repository_full_name: &self.repository_full_name,
            default_branch: &self.default_branch,
            base_sha: &self.base_sha,
            head_sha: &self.head_sha,
            source_read_digest: &self.source_read_digest,
            metadata: &self.metadata,
            preview_only: self.preview_only,
            external_mutation_created: self.external_mutation_created,
            mutation_authority: &self.mutation_authority,
        })
    }
}

impl GithubRepositoryProjection {
    fn validate(&self) -> Result<(), GithubWorkError> {
        if self.id == 0 || self.full_name != format!("{}/{}", self.owner, self.name) {
            return Err(GithubWorkError::RepositoryRevoked);
        }
        validate_identifier(&self.owner, "repository owner")?;
        validate_identifier(&self.name, "repository name")?;
        validate_identifier(&self.full_name, "full_name")?;
        validate_text(&self.default_branch, "default branch", 256)
    }
}

impl GithubIssueProjection {
    fn validate(&self) -> Result<(), GithubWorkError> {
        if self.number == 0 {
            return Err(GithubWorkError::ItemNotFound);
        }
        validate_text(&self.title, "issue title", 4_096)?;
        validate_text(&self.state, "issue state", 64)
    }
}

impl GithubPullRequestProjection {
    fn validate(&self) -> Result<(), GithubWorkError> {
        if self.number == 0
            || !valid_github_sha(&self.base_sha)
            || !valid_github_sha(&self.head_sha)
        {
            return Err(GithubWorkError::StaleHead);
        }
        validate_text(&self.title, "pull request title", 4_096)?;
        validate_text(&self.state, "pull request state", 64)?;
        validate_text(&self.base_ref, "pull request base ref", 512)?;
        validate_text(&self.head_ref, "pull request head ref", 512)
    }
}

impl GithubCheckRunProjection {
    fn validate(&self) -> Result<(), GithubWorkError> {
        if self.id == 0 || !valid_github_sha(&self.head_sha) {
            return Err(GithubWorkError::StaleHead);
        }
        validate_text(&self.name, "check run name", 512)?;
        validate_text(&self.status, "check run status", 64)
    }
}

impl GithubPageReceipt {
    fn validate(&self) -> Result<(), GithubWorkError> {
        if !matches!(
            self.resource.as_str(),
            RESOURCE_ISSUES | RESOURCE_PULL_REQUESTS | RESOURCE_CHECK_RUNS
        ) || self.page == 0
            || !(1..=GITHUB_WORK_MAX_PAGE_SIZE).contains(&self.per_page)
            || !valid_digest(&self.request_digest)
            || !valid_digest(&self.response_digest)
            || self.response.api_version != GITHUB_API_VERSION
        {
            return Err(GithubWorkError::Pagination(
                "GitHub page receipt is outside the read contract".to_owned(),
            ));
        }
        if let Some(next_page) = self.response.next_page
            && (next_page <= self.page || next_page > crate::GITHUB_WORK_MAX_PAGES)
        {
            return Err(GithubWorkError::Pagination(
                "GitHub page receipt next page is not monotonic".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GithubWorkProposalDigest<'a> {
    target: &'a GithubProposalTarget,
    title: &'a Option<String>,
    body: &'a String,
    tenant_id: &'a TenantId,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
    work_product_id: &'a WorkProductId,
    work_product_revision: u64,
    work_product_digest: &'a String,
    repository_full_name: &'a String,
    default_branch: &'a String,
    base_sha: &'a Option<String>,
    head_sha: &'a Option<String>,
    source_read_digest: &'a String,
    metadata: &'a GithubWorkResultMetadata,
    preview_only: bool,
    external_mutation_created: bool,
    mutation_authority: &'a String,
}

fn permission_level_satisfies(granted: &str, required: &str) -> bool {
    matches!((granted, required), ("write" | "read", "read")) || granted == required
}
