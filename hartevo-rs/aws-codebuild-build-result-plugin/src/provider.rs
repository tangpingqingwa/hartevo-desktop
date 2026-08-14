//! Scope-bound, non-native AWS CodeBuild provider and transport recordings.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::model::{
    AccessLossEvidence, AccessLossKind, AwsCodeBuildScope, BuildSummary, Digest, MAX_BUILDS,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_PROJECTS, ModelError, ProjectSummary, ProviderProvenance,
    Revision, SecretReference,
};
use crate::{
    AWS_CODEBUILD_API_REVISION, AWS_CODEBUILD_API_VERSION, AWS_CODEBUILD_CONTRACT_VERSION,
    AWS_CODEBUILD_MAX_BUILDS_PER_REQUEST, AWS_CODEBUILD_MAX_IDENTIFIER_LENGTH,
    AWS_CODEBUILD_MAX_PROJECTS_PER_REQUEST, AWS_CODEBUILD_PLUGIN_VERSION,
    AWS_CODEBUILD_PROVIDER_ID, AwsCodeBuildError, api_digest, contract_digest,
    evidence_schema_digest, permission_digest, version_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeBuildApiOperation {
    ListBuildsForProject,
    BatchGetBuilds,
    BatchGetProjects,
}

pub type AwsCodeBuildApiOperation = CodeBuildApiOperation;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwsCodeBuildTransportError {
    #[error("BLOCKED_ENV: native AWS CodeBuild transport is unavailable")]
    BlockedEnv,
    #[error("AWS CodeBuild returned HTTP 400")]
    BadRequest,
    #[error("AWS CodeBuild returned HTTP 401")]
    Unauthorized,
    #[error("AWS CodeBuild returned HTTP 403")]
    AccessDenied,
    #[error("AWS CodeBuild returned HTTP 404")]
    NotFound,
    #[error("AWS CodeBuild returned HTTP 409")]
    Conflict,
    #[error("AWS CodeBuild request was throttled with HTTP 429")]
    Throttled,
    #[error("AWS CodeBuild returned HTTP {0}")]
    HttpStatus(u16),
    #[error("AWS CodeBuild returned a server error")]
    ServerError,
    #[error("AWS CodeBuild request timed out")]
    Timeout,
    #[error("AWS CodeBuild response was malformed")]
    MalformedResponse,
    #[error("invalid normalized AWS CodeBuild request: {0}")]
    InvalidRequest(String),
    #[error("recording AWS CodeBuild response queue is exhausted")]
    QueueExhausted,
}

impl AwsCodeBuildTransportError {
    pub const fn from_http_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::ServerError,
            _ => Self::HttpStatus(status),
        }
    }

    pub const fn http_status(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::HttpStatus(value) => Some(*value),
            Self::ServerError => Some(500),
            Self::BlockedEnv
            | Self::Timeout
            | Self::MalformedResponse
            | Self::InvalidRequest(_)
            | Self::QueueExhausted => None,
        }
    }

    pub const fn access_loss_kind(&self) -> AccessLossKind {
        match self {
            Self::BlockedEnv => AccessLossKind::BlockedEnv,
            Self::BadRequest => AccessLossKind::BadRequest,
            Self::Unauthorized => AccessLossKind::Unauthorized,
            Self::AccessDenied => AccessLossKind::AccessDenied,
            Self::NotFound => AccessLossKind::NotFound,
            Self::Conflict => AccessLossKind::Conflict,
            Self::Throttled => AccessLossKind::Throttled,
            Self::HttpStatus(status) if *status >= 500 => AccessLossKind::ProviderUnavailable,
            Self::HttpStatus(_) | Self::ServerError => AccessLossKind::ProviderUnavailable,
            Self::Timeout => AccessLossKind::Timeout,
            Self::MalformedResponse => AccessLossKind::MalformedResponse,
            Self::InvalidRequest(_) | Self::QueueExhausted => AccessLossKind::Unknown,
        }
    }

    pub fn provider_code(&self) -> String {
        match self {
            Self::BlockedEnv => "BLOCKED_ENV".to_owned(),
            Self::BadRequest => "HTTP_400".to_owned(),
            Self::Unauthorized => "HTTP_401".to_owned(),
            Self::AccessDenied => "HTTP_403".to_owned(),
            Self::NotFound => "HTTP_404".to_owned(),
            Self::Conflict => "HTTP_409".to_owned(),
            Self::Throttled => "HTTP_429".to_owned(),
            Self::HttpStatus(status) => format!("HTTP_{status}"),
            Self::ServerError => "HTTP_500".to_owned(),
            Self::Timeout => "TIMEOUT".to_owned(),
            Self::MalformedResponse => "MALFORMED_RESPONSE".to_owned(),
            Self::InvalidRequest(_) => "INVALID_REQUEST".to_owned(),
            Self::QueueExhausted => "QUEUE_EXHAUSTED".to_owned(),
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        !matches!(self, Self::InvalidRequest(_) | Self::QueueExhausted)
    }
}

/// Provider page tokens are usable only inside the transport seam. Any
/// serialization exposes a digest and never the opaque token itself.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpaquePageToken {
    token: String,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let token = value.into();
        if token.is_empty() || token.len() > AWS_CODEBUILD_MAX_IDENTIFIER_LENGTH {
            return Err(ModelError::BoundExceeded {
                field: "opaque page token",
            });
        }
        if token.chars().any(char::is_control) {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        Ok(Self { token })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-page-token/v1",
            std::slice::from_ref(&self.token),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.token.is_empty()
    }

    pub(crate) fn raw(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

impl fmt::Display for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OpaquePageToken({})", self.digest())
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    Ascending,
    #[default]
    Descending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageBinding {
    pub operation: CodeBuildApiOperation,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub build_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListBuildsForProjectRequest {
    pub operation: CodeBuildApiOperation,
    pub scope_digest: Digest,
    pub project_name: crate::model::AwsCodeBuildProjectName,
    pub sort_order: SortOrder,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl ListBuildsForProjectRequest {
    pub fn new(scope: &AwsCodeBuildScope, page_size: u16) -> Result<Self, ModelError> {
        Self::with_order(scope, page_size, SortOrder::Descending)
    }

    pub fn with_order(
        scope: &AwsCodeBuildScope,
        page_size: u16,
        sort_order: SortOrder,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded {
                field: "ListBuildsForProject page size",
            });
        }
        let mut request = Self {
            operation: CodeBuildApiOperation::ListBuildsForProject,
            scope_digest: scope.digest(),
            project_name: scope.project_name.clone(),
            sort_order,
            page_number: 1,
            page_size,
            page_token: None,
            request_digest: Digest::from_text("pending-list-builds-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn next_page(&self, token: OpaquePageToken) -> Result<Self, ModelError> {
        if token.is_empty() || self.page_number >= MAX_PAGES {
            return Err(ModelError::BoundExceeded {
                field: "ListBuildsForProject page count",
            });
        }
        let mut next = self.clone();
        next.page_number = next.page_number.saturating_add(1);
        next.page_token = Some(token);
        next.request_digest = next.compute_digest();
        Ok(next)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-list-builds-for-project-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.project_name.as_str().to_owned(),
                format!("{:?}", self.sort_order),
                self.page_number.to_string(),
                self.page_size.to_string(),
                self.page_token
                    .as_ref()
                    .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ],
        )
    }

    pub fn binding(&self) -> PageBinding {
        PageBinding {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            project_digest: Digest::from_text(self.project_name.as_str()),
            build_digest: Digest::from_text("list-builds-for-project-build-fence"),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: self.page_token.as_ref().map(OpaquePageToken::digest),
            request_digest: self.request_digest.clone(),
        }
    }

    pub fn validate(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        if self.operation != CodeBuildApiOperation::ListBuildsForProject
            || self.scope_digest != scope.digest()
            || self.project_name != scope.project_name
            || self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchGetBuildsRequest {
    pub operation: CodeBuildApiOperation,
    pub scope_digest: Digest,
    pub build_ids: Vec<crate::model::BuildId>,
    pub include_batch_metadata: bool,
    pub page_number: u16,
    pub page_size: u16,
    pub request_digest: Digest,
}

impl BatchGetBuildsRequest {
    pub fn new(
        scope: &AwsCodeBuildScope,
        build_ids: Vec<crate::model::BuildId>,
        include_batch_metadata: bool,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if build_ids.is_empty() || build_ids.len() > AWS_CODEBUILD_MAX_BUILDS_PER_REQUEST {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetBuilds ids",
            });
        }
        let page_size = u16::try_from(build_ids.len()).map_err(|_| ModelError::BoundExceeded {
            field: "BatchGetBuilds page size",
        })?;
        let mut request = Self {
            operation: CodeBuildApiOperation::BatchGetBuilds,
            scope_digest: scope.digest(),
            build_ids,
            include_batch_metadata,
            page_number: 1,
            page_size,
            request_digest: Digest::from_text("pending-batch-get-builds-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn batch(
        scope: &AwsCodeBuildScope,
        build_ids: Vec<crate::model::BuildId>,
        include_batch_metadata: bool,
    ) -> Result<Vec<Self>, ModelError> {
        if build_ids.is_empty() || build_ids.len() > MAX_BUILDS {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetBuilds total ids",
            });
        }
        build_ids
            .chunks(AWS_CODEBUILD_MAX_BUILDS_PER_REQUEST)
            .map(|chunk| Self::new(scope, chunk.to_vec(), include_batch_metadata))
            .collect()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-batch-get-builds-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.build_ids
                    .iter()
                    .map(crate::model::BuildId::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.include_batch_metadata.to_string(),
                self.page_number.to_string(),
                self.page_size.to_string(),
            ],
        )
    }

    pub fn binding(&self, scope: &AwsCodeBuildScope) -> PageBinding {
        PageBinding {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            project_digest: scope.project_digest(),
            build_digest: scope.build_digest(),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }

    pub fn validate(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        if self.operation != CodeBuildApiOperation::BatchGetBuilds
            || self.scope_digest != scope.digest()
            || self.build_ids.is_empty()
            || self.build_ids.len() > AWS_CODEBUILD_MAX_BUILDS_PER_REQUEST
            || self.page_number != 1
            || self.page_size != self.build_ids.len() as u16
            || self.request_digest != self.compute_digest()
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchGetProjectsRequest {
    pub operation: CodeBuildApiOperation,
    pub scope_digest: Digest,
    pub project_names: Vec<crate::model::AwsCodeBuildProjectName>,
    pub include_batch_metadata: bool,
    pub page_number: u16,
    pub page_size: u16,
    pub request_digest: Digest,
}

impl BatchGetProjectsRequest {
    pub fn new(
        scope: &AwsCodeBuildScope,
        project_names: Vec<crate::model::AwsCodeBuildProjectName>,
        include_batch_metadata: bool,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if project_names.is_empty() || project_names.len() > AWS_CODEBUILD_MAX_PROJECTS_PER_REQUEST
        {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetProjects names",
            });
        }
        let page_size =
            u16::try_from(project_names.len()).map_err(|_| ModelError::BoundExceeded {
                field: "BatchGetProjects page size",
            })?;
        let mut request = Self {
            operation: CodeBuildApiOperation::BatchGetProjects,
            scope_digest: scope.digest(),
            project_names,
            include_batch_metadata,
            page_number: 1,
            page_size,
            request_digest: Digest::from_text("pending-batch-get-projects-request-digest"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn for_scope(
        scope: &AwsCodeBuildScope,
        include_batch_metadata: bool,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope,
            vec![scope.project_name.clone()],
            include_batch_metadata,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-batch-get-projects-request/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.project_names
                    .iter()
                    .map(crate::model::AwsCodeBuildProjectName::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                self.include_batch_metadata.to_string(),
                self.page_number.to_string(),
                self.page_size.to_string(),
            ],
        )
    }

    pub fn binding(&self, scope: &AwsCodeBuildScope) -> PageBinding {
        PageBinding {
            operation: self.operation,
            scope_digest: self.scope_digest.clone(),
            project_digest: scope.project_digest(),
            build_digest: scope.build_digest(),
            page_number: self.page_number,
            page_size: self.page_size,
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
        }
    }

    pub fn validate(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        if self.operation != CodeBuildApiOperation::BatchGetProjects
            || self.scope_digest != scope.digest()
            || self.project_names.is_empty()
            || self.project_names.len() > AWS_CODEBUILD_MAX_PROJECTS_PER_REQUEST
            || self.page_number != 1
            || self.page_size != self.project_names.len() as u16
            || self.request_digest != self.compute_digest()
            || !self
                .project_names
                .iter()
                .any(|value| value == &scope.project_name)
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }
}

fn page_digest<T: Serialize>(namespace: &str, request_digest: &Digest, value: &T) -> Digest {
    let body = serde_json::to_vec(value).expect("normalized CodeBuild page serializes");
    Digest::from_fields(
        namespace,
        &[
            request_digest.as_str().to_owned(),
            Digest::from_bytes(&body).as_str().to_owned(),
        ],
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListBuildsForProjectPage {
    pub builds: Vec<BuildSummary>,
    pub next_page: Option<OpaquePageToken>,
    pub response_digest: Digest,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
}

impl ListBuildsForProjectPage {
    pub fn new(
        request: &ListBuildsForProjectRequest,
        builds: Vec<BuildSummary>,
        next_page: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if builds.len() > usize::from(MAX_PAGE_SIZE) {
            return Err(ModelError::BoundExceeded {
                field: "ListBuildsForProject response builds",
            });
        }
        for build in &builds {
            build.validate()?;
            if build.project_name != request.project_name {
                return Err(ModelError::ScopeDrift);
            }
        }
        let response_digest = page_digest(
            "hartevo.aws-codebuild-list-builds-for-project-response/v1",
            &request.request_digest,
            &(
                builds.clone(),
                next_page.as_ref().map(OpaquePageToken::digest),
            ),
        );
        Ok(Self {
            builds,
            next_page,
            response_digest,
            partial: false,
            access_loss: None,
        })
    }

    pub fn with_access_loss(mut self, loss: AccessLossEvidence) -> Result<Self, ModelError> {
        loss.validate()?;
        self.partial = true;
        self.access_loss = Some(loss);
        Ok(self)
    }

    fn validate_for(&self, request: &ListBuildsForProjectRequest) -> Result<(), ModelError> {
        if self.builds.len() > usize::from(MAX_PAGE_SIZE) {
            return Err(ModelError::BoundExceeded {
                field: "ListBuildsForProject response builds",
            });
        }
        for build in &self.builds {
            build.validate()?;
            if build.project_name != request.project_name {
                return Err(ModelError::ScopeDrift);
            }
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        let expected = page_digest(
            "hartevo.aws-codebuild-list-builds-for-project-response/v1",
            &request.request_digest,
            &(
                self.builds.clone(),
                self.next_page.as_ref().map(OpaquePageToken::digest),
            ),
        );
        if self.response_digest != expected {
            return Err(ModelError::InvalidDigest {
                field: "ListBuildsForProject response",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchGetBuildsPage {
    pub builds: Vec<BuildSummary>,
    pub not_found_ids: Vec<crate::model::BuildId>,
    pub batch_metadata_truncated: bool,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
}

impl BatchGetBuildsPage {
    pub fn new(
        request: &BatchGetBuildsRequest,
        builds: Vec<BuildSummary>,
        not_found_ids: Vec<crate::model::BuildId>,
    ) -> Result<Self, ModelError> {
        if builds.len() > MAX_BUILDS || not_found_ids.len() > MAX_BUILDS {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetBuilds response builds",
            });
        }
        for build in &builds {
            build.validate()?;
            if !request.build_ids.contains(&build.build_id) {
                return Err(ModelError::ScopeDrift);
            }
        }
        let response_digest = page_digest(
            "hartevo.aws-codebuild-batch-get-builds-response/v1",
            &request.request_digest,
            &(builds.clone(), not_found_ids.clone(), false),
        );
        Ok(Self {
            builds,
            not_found_ids,
            batch_metadata_truncated: false,
            request_digest: request.request_digest.clone(),
            response_digest,
            partial: false,
            access_loss: None,
        })
    }

    #[must_use]
    pub fn with_batch_metadata_truncated(mut self) -> Self {
        self.batch_metadata_truncated = true;
        self.partial = true;
        self.response_digest = page_digest(
            "hartevo.aws-codebuild-batch-get-builds-response/v1",
            &self.request_digest,
            &(
                self.builds.clone(),
                self.not_found_ids.clone(),
                self.batch_metadata_truncated,
            ),
        );
        self
    }

    pub fn with_access_loss(mut self, loss: AccessLossEvidence) -> Result<Self, ModelError> {
        loss.validate()?;
        self.partial = true;
        self.access_loss = Some(loss);
        Ok(self)
    }

    fn validate_for(&self, request: &BatchGetBuildsRequest) -> Result<(), ModelError> {
        if self.builds.len() > MAX_BUILDS || self.not_found_ids.len() > MAX_BUILDS {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetBuilds response builds",
            });
        }
        for build in &self.builds {
            build.validate()?;
            if !request.build_ids.contains(&build.build_id) {
                return Err(ModelError::ScopeDrift);
            }
        }
        for id in &self.not_found_ids {
            if !request.build_ids.contains(id) {
                return Err(ModelError::ScopeDrift);
            }
        }
        if self.request_digest != request.request_digest {
            return Err(ModelError::ScopeDrift);
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        let expected = page_digest(
            "hartevo.aws-codebuild-batch-get-builds-response/v1",
            &request.request_digest,
            &(
                self.builds.clone(),
                self.not_found_ids.clone(),
                self.batch_metadata_truncated,
            ),
        );
        if self.response_digest != expected {
            return Err(ModelError::InvalidDigest {
                field: "BatchGetBuilds response",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchGetProjectsPage {
    pub projects: Vec<ProjectSummary>,
    pub not_found_names: Vec<crate::model::AwsCodeBuildProjectName>,
    pub batch_metadata_truncated: bool,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub partial: bool,
    pub access_loss: Option<AccessLossEvidence>,
}

impl BatchGetProjectsPage {
    pub fn new(
        request: &BatchGetProjectsRequest,
        projects: Vec<ProjectSummary>,
        not_found_names: Vec<crate::model::AwsCodeBuildProjectName>,
    ) -> Result<Self, ModelError> {
        if projects.len() > MAX_PROJECTS || not_found_names.len() > MAX_PROJECTS {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetProjects response projects",
            });
        }
        for project in &projects {
            project.validate()?;
            if !request.project_names.contains(&project.project_name) {
                return Err(ModelError::ScopeDrift);
            }
        }
        let response_digest = page_digest(
            "hartevo.aws-codebuild-batch-get-projects-response/v1",
            &request.request_digest,
            &(projects.clone(), not_found_names.clone(), false),
        );
        Ok(Self {
            projects,
            not_found_names,
            batch_metadata_truncated: false,
            request_digest: request.request_digest.clone(),
            response_digest,
            partial: false,
            access_loss: None,
        })
    }

    #[must_use]
    pub fn with_batch_metadata_truncated(mut self) -> Self {
        self.batch_metadata_truncated = true;
        self.partial = true;
        self.response_digest = page_digest(
            "hartevo.aws-codebuild-batch-get-projects-response/v1",
            &self.request_digest,
            &(
                self.projects.clone(),
                self.not_found_names.clone(),
                self.batch_metadata_truncated,
            ),
        );
        self
    }

    pub fn with_access_loss(mut self, loss: AccessLossEvidence) -> Result<Self, ModelError> {
        loss.validate()?;
        self.partial = true;
        self.access_loss = Some(loss);
        Ok(self)
    }

    fn validate_for(&self, request: &BatchGetProjectsRequest) -> Result<(), ModelError> {
        if self.projects.len() > MAX_PROJECTS || self.not_found_names.len() > MAX_PROJECTS {
            return Err(ModelError::BoundExceeded {
                field: "BatchGetProjects response projects",
            });
        }
        for project in &self.projects {
            project.validate()?;
            if !request.project_names.contains(&project.project_name) {
                return Err(ModelError::ScopeDrift);
            }
        }
        for name in &self.not_found_names {
            if !request.project_names.contains(name) {
                return Err(ModelError::ScopeDrift);
            }
        }
        if self.request_digest != request.request_digest {
            return Err(ModelError::ScopeDrift);
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        let expected = page_digest(
            "hartevo.aws-codebuild-batch-get-projects-response/v1",
            &request.request_digest,
            &(
                self.projects.clone(),
                self.not_found_names.clone(),
                self.batch_metadata_truncated,
            ),
        );
        if self.response_digest != expected {
            return Err(ModelError::InvalidDigest {
                field: "BatchGetProjects response",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedListBuildsForProjectRequest {
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

impl From<&ListBuildsForProjectRequest> for RecordedListBuildsForProjectRequest {
    fn from(value: &ListBuildsForProjectRequest) -> Self {
        Self {
            scope_digest: value.scope_digest.clone(),
            project_digest: Digest::from_text(value.project_name.as_str()),
            page_number: value.page_number,
            page_size: value.page_size,
            page_token_digest: value.page_token.as_ref().map(OpaquePageToken::digest),
            request_digest: value.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedBatchGetBuildsRequest {
    pub scope_digest: Digest,
    pub build_ids_digest: Digest,
    pub build_count: usize,
    pub include_batch_metadata: bool,
    pub request_digest: Digest,
}

impl From<&BatchGetBuildsRequest> for RecordedBatchGetBuildsRequest {
    fn from(value: &BatchGetBuildsRequest) -> Self {
        Self {
            scope_digest: value.scope_digest.clone(),
            build_ids_digest: Digest::from_fields(
                "hartevo.aws-codebuild-build-id-list/v1",
                &[value
                    .build_ids
                    .iter()
                    .map(crate::model::BuildId::as_str)
                    .collect::<Vec<_>>()
                    .join(",")],
            ),
            build_count: value.build_ids.len(),
            include_batch_metadata: value.include_batch_metadata,
            request_digest: value.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedBatchGetProjectsRequest {
    pub scope_digest: Digest,
    pub project_names_digest: Digest,
    pub project_count: usize,
    pub include_batch_metadata: bool,
    pub request_digest: Digest,
}

impl From<&BatchGetProjectsRequest> for RecordedBatchGetProjectsRequest {
    fn from(value: &BatchGetProjectsRequest) -> Self {
        Self {
            scope_digest: value.scope_digest.clone(),
            project_names_digest: Digest::from_fields(
                "hartevo.aws-codebuild-project-name-list/v1",
                &[value
                    .project_names
                    .iter()
                    .map(crate::model::AwsCodeBuildProjectName::as_str)
                    .collect::<Vec<_>>()
                    .join(",")],
            ),
            project_count: value.project_names.len(),
            include_batch_metadata: value.include_batch_metadata,
            request_digest: value.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordedAwsCodeBuildRequest {
    ListBuildsForProject(RecordedListBuildsForProjectRequest),
    BatchGetBuilds(RecordedBatchGetBuildsRequest),
    BatchGetProjects(RecordedBatchGetProjectsRequest),
}

pub trait AwsCodeBuildTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_builds_for_project(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError>;

    fn batch_get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError>;

    fn batch_get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError>;

    fn is_native(&self) -> bool {
        false
    }

    fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAwsCodeBuildTransport {
    list_responses:
        VecDeque<std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError>>,
    build_responses: VecDeque<std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError>>,
    project_responses:
        VecDeque<std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError>>,
    requests: Vec<RecordedAwsCodeBuildRequest>,
    provenance: ProviderProvenance,
}

impl Default for RecordingAwsCodeBuildTransport {
    fn default() -> Self {
        Self {
            list_responses: VecDeque::new(),
            build_responses: VecDeque::new(),
            project_responses: VecDeque::new(),
            requests: Vec::new(),
            provenance: ProviderProvenance::Recording,
        }
    }
}

impl RecordingAwsCodeBuildTransport {
    pub fn new() -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            ..Self::default()
        }
    }

    pub fn fixture_mode() -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            ..Self::default()
        }
    }

    pub fn loopback_mode() -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            ..Self::default()
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_build_response(
        &mut self,
        response: std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError>,
    ) {
        self.build_responses.push_back(response);
    }

    pub fn push_project_response(
        &mut self,
        response: std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError>,
    ) {
        self.project_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedAwsCodeBuildRequest] {
        &self.requests
    }

    pub fn call_count(&self) -> usize {
        self.requests.len()
    }

    pub fn remaining_list_responses(&self) -> usize {
        self.list_responses.len()
    }

    pub fn remaining_build_responses(&self) -> usize {
        self.build_responses.len()
    }

    pub fn remaining_project_responses(&self) -> usize {
        self.project_responses.len()
    }
}

impl AwsCodeBuildTransport for RecordingAwsCodeBuildTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_builds_for_project(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::ListBuildsForProject(
                request.into(),
            ));
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeBuildTransportError::QueueExhausted))
    }

    fn batch_get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::BatchGetBuilds(request.into()));
        self.build_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeBuildTransportError::QueueExhausted))
    }

    fn batch_get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::BatchGetProjects(
                request.into(),
            ));
        self.project_responses
            .pop_front()
            .unwrap_or(Err(AwsCodeBuildTransportError::QueueExhausted))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAwsCodeBuildTransport {
    builds: Vec<BuildSummary>,
    projects: Vec<ProjectSummary>,
    requests: Vec<RecordedAwsCodeBuildRequest>,
}

impl FixtureAwsCodeBuildTransport {
    pub fn new(builds: impl IntoIterator<Item = BuildSummary>) -> Self {
        let builds: Vec<_> = builds.into_iter().collect();
        let projects = builds
            .first()
            .and_then(|build| {
                ProjectSummary::new(
                    build.project_name.clone(),
                    build.source_repository.clone(),
                    build.source_commit.clone(),
                    Some(build.artifact_metadata_digest()),
                    build
                        .batch_metadata
                        .as_ref()
                        .map(|value| value.metadata_digest.clone()),
                )
                .ok()
            })
            .into_iter()
            .collect();
        Self {
            builds,
            projects,
            requests: Vec::new(),
        }
    }

    pub fn with_projects(
        builds: impl IntoIterator<Item = BuildSummary>,
        projects: impl IntoIterator<Item = ProjectSummary>,
    ) -> Self {
        Self {
            builds: builds.into_iter().collect(),
            projects: projects.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[RecordedAwsCodeBuildRequest] {
        &self.requests
    }

    pub fn builds(&self) -> &[BuildSummary] {
        &self.builds
    }

    fn page_number(token: Option<&OpaquePageToken>) -> usize {
        token
            .and_then(|value| value.raw().strip_prefix("fixture-page-"))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
    }
}

impl AwsCodeBuildTransport for FixtureAwsCodeBuildTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_builds_for_project(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::ListBuildsForProject(
                request.into(),
            ));
        let page_number = Self::page_number(request.page_token.as_ref());
        let page_size = usize::from(request.page_size);
        let matching: Vec<_> = self
            .builds
            .iter()
            .filter(|build| build.project_name == request.project_name)
            .cloned()
            .collect();
        let start = page_number.saturating_mul(page_size);
        let end = (start + page_size).min(matching.len());
        let builds = if start < matching.len() {
            matching[start..end].to_vec()
        } else {
            Vec::new()
        };
        let next_page = (end < matching.len())
            .then(|| OpaquePageToken::new(format!("fixture-page-{}", page_number + 1)))
            .transpose()
            .map_err(|_| AwsCodeBuildTransportError::MalformedResponse)?;
        ListBuildsForProjectPage::new(request, builds, next_page)
            .map_err(|_| AwsCodeBuildTransportError::MalformedResponse)
    }

    fn batch_get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::BatchGetBuilds(request.into()));
        let mut builds = Vec::new();
        let mut not_found = Vec::new();
        for id in &request.build_ids {
            if let Some(build) = self.builds.iter().find(|build| build.build_id == *id) {
                builds.push(build.clone());
            } else {
                not_found.push(id.clone());
            }
        }
        BatchGetBuildsPage::new(request, builds, not_found)
            .map_err(|_| AwsCodeBuildTransportError::MalformedResponse)
    }

    fn batch_get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError> {
        self.requests
            .push(RecordedAwsCodeBuildRequest::BatchGetProjects(
                request.into(),
            ));
        let mut projects = Vec::new();
        let mut not_found = Vec::new();
        for name in &request.project_names {
            if let Some(project) = self
                .projects
                .iter()
                .find(|project| project.project_name == *name)
            {
                projects.push(project.clone());
            } else {
                not_found.push(name.clone());
            }
        }
        BatchGetProjectsPage::new(request, projects, not_found)
            .map_err(|_| AwsCodeBuildTransportError::MalformedResponse)
    }
}

pub type FakeAwsCodeBuildTransport = FixtureAwsCodeBuildTransport;

#[derive(Clone, Debug)]
pub struct LoopbackAwsCodeBuildTransport {
    inner: FixtureAwsCodeBuildTransport,
}

impl LoopbackAwsCodeBuildTransport {
    pub fn new(builds: impl IntoIterator<Item = BuildSummary>) -> Self {
        Self {
            inner: FixtureAwsCodeBuildTransport::new(builds),
        }
    }

    pub fn with_projects(
        builds: impl IntoIterator<Item = BuildSummary>,
        projects: impl IntoIterator<Item = ProjectSummary>,
    ) -> Self {
        Self {
            inner: FixtureAwsCodeBuildTransport::with_projects(builds, projects),
        }
    }

    pub fn requests(&self) -> &[RecordedAwsCodeBuildRequest] {
        self.inner.requests()
    }
}

impl AwsCodeBuildTransport for LoopbackAwsCodeBuildTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list_builds_for_project(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError> {
        self.inner.list_builds_for_project(request)
    }

    fn batch_get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError> {
        self.inner.batch_get_builds(request)
    }

    fn batch_get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError> {
        self.inner.batch_get_projects(request)
    }
}

pub type RecordingTransport = RecordingAwsCodeBuildTransport;
pub type BlockedEnvTransport = BlockedEnvAwsCodeBuildTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct AwsCodeBuildRegistrationRequest {
    pub scope: AwsCodeBuildScope,
    pub secret_reference: SecretReference,
    pub plugin_version: String,
    pub contract_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
}

impl AwsCodeBuildRegistrationRequest {
    pub fn new(
        scope: AwsCodeBuildScope,
        secret_reference: SecretReference,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if !secret_reference.is_for_scope(&scope) {
            return Err(ModelError::ScopeDrift);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            plugin_version: AWS_CODEBUILD_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_CODEBUILD_CONTRACT_VERSION.to_owned(),
            version_digest: version_digest(),
            contract_digest: contract_digest(),
            provider_revision: AWS_CODEBUILD_API_REVISION.to_owned(),
            provider_digest: provider_digest(),
            api_digest: api_digest(),
            permission_digest: permission_digest(),
            evidence_digest: evidence_schema_digest(),
        })
    }

    pub fn baseline(
        scope: AwsCodeBuildScope,
        secret_reference: SecretReference,
    ) -> Result<Self, ModelError> {
        Self::new(scope, secret_reference)
    }
}

#[derive(Clone)]
pub struct AwsCodeBuildRegistration {
    scope: AwsCodeBuildScope,
    secret_reference: SecretReference,
    plugin_version: String,
    contract_version: String,
    version_digest: Digest,
    contract_digest: Digest,
    provider_revision: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    evidence_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
    revocation_revision: Option<Revision>,
}

impl fmt::Debug for AwsCodeBuildRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCodeBuildRegistration")
            .field("scope_digest", &self.scope_digest)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("version_digest", &self.version_digest)
            .field("contract_digest", &self.contract_digest)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .field("revocation_revision", &self.revocation_revision)
            .finish_non_exhaustive()
    }
}

impl AwsCodeBuildRegistration {
    fn new(request: AwsCodeBuildRegistrationRequest) -> Result<Self, AwsCodeBuildError> {
        if request.scope_digest != request.scope.digest()
            || request.permission_digest != *request.scope.permission_digest()
            || request.secret_reference.scope_digest() != &request.scope_digest
            || request.plugin_version != AWS_CODEBUILD_PLUGIN_VERSION
            || request.contract_version != AWS_CODEBUILD_CONTRACT_VERSION
            || request.version_digest != version_digest()
            || request.contract_digest != contract_digest()
            || request.provider_revision != AWS_CODEBUILD_API_REVISION
            || request.api_digest != api_digest()
            || request.permission_digest != permission_digest()
            || request.evidence_digest != evidence_schema_digest()
        {
            return Err(AwsCodeBuildError::InvalidRegistration);
        }
        let mut registration = Self {
            scope: request.scope,
            secret_reference: request.secret_reference,
            plugin_version: request.plugin_version,
            contract_version: request.contract_version,
            version_digest: request.version_digest,
            contract_digest: request.contract_digest,
            provider_revision: request.provider_revision,
            provider_digest: request.provider_digest,
            api_digest: request.api_digest,
            permission_digest: request.permission_digest,
            scope_digest: request.scope_digest,
            evidence_digest: request.evidence_digest,
            registration_digest: Digest::from_text("pending-codebuild-registration-digest"),
            state: RegistrationState::Active,
            revocation_revision: None,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.version_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.provider_revision.clone(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.secret_reference.reference_digest().as_str().to_owned(),
            ],
        )
    }

    pub fn validate_for(
        &self,
        provider_revision: &str,
        provider_digest: &Digest,
    ) -> Result<(), AwsCodeBuildError> {
        if self.scope_digest != self.scope.digest()
            || self.permission_digest != *self.scope.permission_digest()
            || self.secret_reference.scope_digest() != &self.scope_digest
            || self.provider_revision != provider_revision
            || self.provider_digest != *provider_digest
            || self.plugin_version != AWS_CODEBUILD_PLUGIN_VERSION
            || self.contract_version != AWS_CODEBUILD_CONTRACT_VERSION
            || self.version_digest != version_digest()
            || self.contract_digest != contract_digest()
            || self.api_digest != api_digest()
            || self.permission_digest != permission_digest()
            || self.evidence_digest != evidence_schema_digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(AwsCodeBuildError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self, revision: Revision) -> Result<(), AwsCodeBuildError> {
        if self.state == RegistrationState::Revoked {
            return Err(AwsCodeBuildError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        self.revocation_revision = Some(revision);
        Ok(())
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn scope(&self) -> &AwsCodeBuildScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revocation_revision(&self) -> Option<Revision> {
        self.revocation_revision
    }
}

#[derive(Clone, Debug)]
pub struct AwsCodeBuildProvider<T> {
    transport: T,
    provider_revision: String,
    provider_digest: Digest,
    registration: Option<AwsCodeBuildRegistration>,
}

impl<T: AwsCodeBuildTransport> AwsCodeBuildProvider<T> {
    pub fn new(transport: T) -> Result<Self, AwsCodeBuildError> {
        Self::with_revision(transport, AWS_CODEBUILD_API_REVISION)
    }

    pub fn with_revision(
        transport: T,
        provider_revision: impl Into<String>,
    ) -> Result<Self, AwsCodeBuildError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(AwsCodeBuildError::ProviderDrift);
        }
        let provider_digest = provider_digest_for_revision(&provider_revision);
        Ok(Self {
            transport,
            provider_revision,
            provider_digest,
            registration: None,
        })
    }

    pub fn baseline(transport: T) -> Result<Self, AwsCodeBuildError> {
        Self::new(transport)
    }

    pub fn register(
        &mut self,
        request: AwsCodeBuildRegistrationRequest,
    ) -> Result<AwsCodeBuildRegistration, AwsCodeBuildError> {
        if self
            .registration
            .as_ref()
            .is_some_and(AwsCodeBuildRegistration::is_active)
        {
            return Err(AwsCodeBuildError::InvalidRegistration);
        }
        let mut request = request;
        request
            .provider_revision
            .clone_from(&self.provider_revision);
        request.provider_digest.clone_from(&self.provider_digest);
        let registration = AwsCodeBuildRegistration::new(request)?;
        self.registration = Some(registration.clone());
        Ok(registration)
    }

    pub fn register_scope(
        &mut self,
        scope: AwsCodeBuildScope,
        secret_reference: SecretReference,
    ) -> Result<AwsCodeBuildRegistration, AwsCodeBuildError> {
        self.register(AwsCodeBuildRegistrationRequest::new(
            scope,
            secret_reference,
        )?)
    }

    pub fn revoke_registration(&mut self, revision: Revision) -> Result<(), AwsCodeBuildError> {
        self.registration_mut()?.revoke(revision)
    }

    pub fn registration(&self) -> Option<&AwsCodeBuildRegistration> {
        self.registration.as_ref()
    }

    pub fn registration_mut(&mut self) -> Result<&mut AwsCodeBuildRegistration, AwsCodeBuildError> {
        self.registration
            .as_mut()
            .ok_or(AwsCodeBuildError::RegistrationMissing)
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn ensure_active(&self, scope_digest: &Digest) -> Result<(), AwsCodeBuildError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsCodeBuildError::RegistrationMissing)?;
        registration.validate_for(&self.provider_revision, &self.provider_digest)?;
        if !registration.is_active() {
            return Err(AwsCodeBuildError::RegistrationRevoked);
        }
        if registration.scope_digest() != scope_digest {
            return Err(AwsCodeBuildError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn list_builds_for_project(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> Result<ListBuildsForProjectPage, AwsCodeBuildError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsCodeBuildError::RegistrationMissing)?;
        request.validate(registration.scope())?;
        self.ensure_active(&request.scope_digest)?;
        let page = self.transport.list_builds_for_project(request)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn list_builds(
        &mut self,
        request: &ListBuildsForProjectRequest,
    ) -> Result<ListBuildsForProjectPage, AwsCodeBuildError> {
        self.list_builds_for_project(request)
    }

    pub fn batch_get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> Result<BatchGetBuildsPage, AwsCodeBuildError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsCodeBuildError::RegistrationMissing)?;
        request.validate(registration.scope())?;
        self.ensure_active(&request.scope_digest)?;
        let page = self.transport.batch_get_builds(request)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn get_builds(
        &mut self,
        request: &BatchGetBuildsRequest,
    ) -> Result<BatchGetBuildsPage, AwsCodeBuildError> {
        self.batch_get_builds(request)
    }

    pub fn batch_get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> Result<BatchGetProjectsPage, AwsCodeBuildError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or(AwsCodeBuildError::RegistrationMissing)?;
        request.validate(registration.scope())?;
        self.ensure_active(&request.scope_digest)?;
        let page = self.transport.batch_get_projects(request)?;
        page.validate_for(request)?;
        Ok(page)
    }

    pub fn get_projects(
        &mut self,
        request: &BatchGetProjectsRequest,
    ) -> Result<BatchGetProjectsPage, AwsCodeBuildError> {
        self.batch_get_projects(request)
    }
}

impl Default for AwsCodeBuildProvider<BlockedEnvAwsCodeBuildTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsCodeBuildTransport).expect("static provider revision is valid")
    }
}

pub fn provider_digest() -> Digest {
    provider_digest_for_revision(AWS_CODEBUILD_API_REVISION)
}

pub fn provider_digest_for_revision(provider_revision: &str) -> Digest {
    Digest::from_fields(
        "hartevo.aws-codebuild-provider/v1",
        &[
            AWS_CODEBUILD_PROVIDER_ID.to_owned(),
            AWS_CODEBUILD_API_VERSION.to_owned(),
            AWS_CODEBUILD_API_REVISION.to_owned(),
            provider_revision.to_owned(),
            "ListBuildsForProject".to_owned(),
            "BatchGetBuilds".to_owned(),
            "BatchGetProjects".to_owned(),
        ],
    )
}

#[derive(Clone, Copy, Debug)]
pub struct BlockedEnvAwsCodeBuildTransport;

impl AwsCodeBuildTransport for BlockedEnvAwsCodeBuildTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_builds_for_project(
        &mut self,
        _request: &ListBuildsForProjectRequest,
    ) -> std::result::Result<ListBuildsForProjectPage, AwsCodeBuildTransportError> {
        Err(AwsCodeBuildTransportError::BlockedEnv)
    }

    fn batch_get_builds(
        &mut self,
        _request: &BatchGetBuildsRequest,
    ) -> std::result::Result<BatchGetBuildsPage, AwsCodeBuildTransportError> {
        Err(AwsCodeBuildTransportError::BlockedEnv)
    }

    fn batch_get_projects(
        &mut self,
        _request: &BatchGetProjectsRequest,
    ) -> std::result::Result<BatchGetProjectsPage, AwsCodeBuildTransportError> {
        Err(AwsCodeBuildTransportError::BlockedEnv)
    }
}
