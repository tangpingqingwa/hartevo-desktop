use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{HarnessDeliveryResultError, HarnessTransportError, Result};
use crate::model::{
    DeploymentMetadata, Digest, ExecutionMetadata, HarnessDeliveryScope, HarnessDeploymentId,
    HarnessExecutionId, HarnessRunStatus, HarnessServiceId, OpaqueCursor, PipelineMetadata,
    ServiceMetadata, StageMetadata, TransportProvenance,
};
use crate::{
    MAX_METADATA_ITEMS, MAX_PAGE_SIZE, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION, PROVIDER_ID,
};

// Keep the provider API explicitly bounded to read-shaped operations.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessOperation {
    ListPipelines,
    ListExecutions,
    ListStages,
    ListServices,
    GetDeploymentMetadata,
}

impl HarnessOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListPipelines => "ListPipelines",
            Self::ListExecutions => "ListExecutions",
            Self::ListStages => "ListStageExecutions",
            Self::ListServices => "ListServices",
            Self::GetDeploymentMetadata => "GetDeploymentMetadata",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
}

impl Default for HarnessProviderDefinition {
    fn default() -> Self {
        Self::new(1, "1.0.0")
    }
}

impl HarnessProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Self {
        let release = release.into();
        let provider_digest = Digest::from_parts(
            "harness-provider-definition/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("release", release.clone()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            release,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_digest,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.api_revision != PROVIDER_API_REVISION
            || self.provider_digest
                != Digest::from_parts(
                    "harness-provider-definition/v1",
                    &[
                        ("provider_id", self.provider_id.clone()),
                        ("provider_revision", self.provider_revision.to_string()),
                        ("release", self.release.clone()),
                        ("api_revision", self.api_revision.clone()),
                    ],
                )
        {
            return Err(HarnessDeliveryResultError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPipelinesRequest {
    scope_digest: Digest,
    account_digest: Digest,
    org_digest: Digest,
    project_digest: Digest,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ListPipelinesRequest {
    pub fn new(
        scope: &HarnessDeliveryScope,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        let request_digest = request_digest("list-pipelines", scope, page_size, None);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &request_digest)?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            account_digest: scope.account().digest(),
            org_digest: scope.org().digest(),
            project_digest: scope.harness_project().digest(),
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &HarnessDeliveryScope) -> Result<Self> {
        Self::new(scope, 30, None)
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &HarnessDeliveryScope) -> String {
        format!(
            "/v1/orgs/{}/projects/{}/pipelines?page={}&limit={}",
            scope.org().as_str(),
            scope.harness_project().as_str(),
            self.cursor.as_ref().map_or(0, OpaqueCursor::page),
            self.page_size
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListExecutionsRequest {
    scope_digest: Digest,
    account_digest: Digest,
    org_digest: Digest,
    project_digest: Digest,
    pipeline_digest: Digest,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ListExecutionsRequest {
    pub fn new(
        scope: &HarnessDeliveryScope,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        let request_digest = request_digest("list-executions", scope, page_size, None);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &request_digest)?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            account_digest: scope.account().digest(),
            org_digest: scope.org().digest(),
            project_digest: scope.harness_project().digest(),
            pipeline_digest: scope.pipeline().digest(),
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &HarnessDeliveryScope) -> Result<Self> {
        Self::new(scope, 30, None)
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &HarnessDeliveryScope) -> String {
        format!(
            "/pipeline/api/pipelines/execution/summary/outline?accountIdentifier={}&orgIdentifier={}&projectIdentifier={}&pipelineIdentifier={}&page={}&size={}",
            scope.account().as_str(),
            scope.org().as_str(),
            scope.harness_project().as_str(),
            scope.pipeline().as_str(),
            self.cursor.as_ref().map_or(0, OpaqueCursor::page),
            self.page_size
        )
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListStagesRequest {
    scope_digest: Digest,
    execution_digest: Digest,
    stage_digest: Option<Digest>,
    request_digest: Digest,
}

impl ListStagesRequest {
    pub fn for_scope(scope: &HarnessDeliveryScope) -> Result<Self> {
        let execution = scope
            .execution()
            .ok_or(HarnessDeliveryResultError::ExecutionBindingMismatch)?;
        let execution_digest = execution.digest();
        let request_digest = request_digest("list-stages", scope, 1, Some(&execution_digest));
        Ok(Self {
            scope_digest: scope.digest(),
            execution_digest: execution.digest(),
            stage_digest: scope.stage().map(HarnessStageIdDigest::digest),
            request_digest,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn execution_digest(&self) -> &Digest {
        &self.execution_digest
    }

    #[must_use]
    pub fn stage_digest(&self) -> Option<&Digest> {
        self.stage_digest.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &HarnessDeliveryScope) -> String {
        format!(
            "/v1/orgs/{}/projects/{}/pipelines/{}/executions/{}/stages",
            scope.org().as_str(),
            scope.harness_project().as_str(),
            scope.pipeline().as_str(),
            scope.execution().map_or("", |value| value.as_str())
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListServicesRequest {
    scope_digest: Digest,
    org_digest: Digest,
    project_digest: Digest,
    service_digest: Option<Digest>,
    environment_digest: Option<Digest>,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    request_digest: Digest,
}

impl ListServicesRequest {
    pub fn new(
        scope: &HarnessDeliveryScope,
        page_size: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        let request_digest = request_digest("list-services", scope, page_size, None);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &request_digest)?;
        }
        Ok(Self {
            scope_digest: scope.digest(),
            org_digest: scope.org().digest(),
            project_digest: scope.harness_project().digest(),
            service_digest: scope.service().map(HarnessServiceIdDigest::digest),
            environment_digest: scope.environment().map(HarnessEnvironmentIdDigest::digest),
            page_size,
            cursor,
            request_digest,
        })
    }

    pub fn for_scope(scope: &HarnessDeliveryScope) -> Result<Self> {
        Self::new(scope, 30, None)
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &HarnessDeliveryScope) -> String {
        format!(
            "/v1/orgs/{}/projects/{}/services?page={}&limit={}",
            scope.org().as_str(),
            scope.harness_project().as_str(),
            self.cursor.as_ref().map_or(0, OpaqueCursor::page),
            self.page_size
        )
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeploymentRequest {
    scope_digest: Digest,
    execution_digest: Digest,
    service_digest: Digest,
    environment_digest: Digest,
    request_digest: Digest,
}

impl GetDeploymentRequest {
    pub fn for_scope(scope: &HarnessDeliveryScope) -> Result<Self> {
        let execution = scope
            .execution()
            .ok_or(HarnessDeliveryResultError::ExecutionBindingMismatch)?;
        let service = scope
            .service()
            .ok_or(HarnessDeliveryResultError::ExecutionBindingMismatch)?;
        let environment = scope
            .environment()
            .ok_or(HarnessDeliveryResultError::ExecutionBindingMismatch)?;
        let request_digest = request_digest("get-deployment-metadata", scope, 1, None);
        Ok(Self {
            scope_digest: scope.digest(),
            execution_digest: execution.digest(),
            service_digest: service.digest(),
            environment_digest: environment.digest(),
            request_digest,
        })
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &HarnessDeliveryScope) -> String {
        format!(
            "/v1/orgs/{}/projects/{}/deployments?execution={}&service={}&environment={}",
            scope.org().as_str(),
            scope.harness_project().as_str(),
            scope.execution().map_or("", |value| value.as_str()),
            scope.service().map_or("", |value| value.as_str()),
            scope.environment().map_or("", |value| value.as_str())
        )
    }
}

fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(HarnessDeliveryResultError::InvalidRequest);
    }
    Ok(())
}

fn request_digest(
    operation: &str,
    scope: &HarnessDeliveryScope,
    page_size: u16,
    binding: Option<&Digest>,
) -> Digest {
    Digest::from_parts(
        "harness-request/v1",
        &[
            ("operation", operation.to_owned()),
            ("scope", scope.digest().as_str().to_owned()),
            ("page_size", page_size.to_string()),
            (
                "binding",
                binding.map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
        ],
    )
}

trait HarnessStageIdDigest {
    fn digest(&self) -> Digest;
}

impl HarnessStageIdDigest for crate::model::HarnessStageId {
    fn digest(&self) -> Digest {
        crate::model::HarnessStageId::digest(self)
    }
}

trait HarnessServiceIdDigest {
    fn digest(&self) -> Digest;
}

impl HarnessServiceIdDigest for HarnessServiceId {
    fn digest(&self) -> Digest {
        HarnessServiceId::digest(self)
    }
}

trait HarnessEnvironmentIdDigest {
    fn digest(&self) -> Digest;
}

impl HarnessEnvironmentIdDigest for crate::model::HarnessEnvironmentId {
    fn digest(&self) -> Digest {
        crate::model::HarnessEnvironmentId::digest(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelinePage {
    scope_digest: Digest,
    request_digest: Digest,
    pub pipelines: Vec<PipelineMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub provenance: TransportProvenance,
}

impl PipelinePage {
    pub fn new(
        request: &ListPipelinesRequest,
        pipelines: Vec<PipelineMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if pipelines.len() > request.page_size() as usize
            || pipelines.len() > MAX_METADATA_ITEMS
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        validate_cursor(next_cursor.as_ref(), request)?;
        let response_digest = page_response_digest(
            "harness-pipeline-response/v1",
            pipelines.iter().map(PipelineMetadata::digest),
            response_bytes,
        );
        let page_digest = page_digest(
            &request.request_digest,
            &response_digest,
            next_cursor.as_ref(),
        );
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            pipelines,
            next_cursor,
            response_digest,
            page_digest,
            provenance,
        })
    }

    pub fn empty(request: &ListPipelinesRequest, provenance: TransportProvenance) -> Result<Self> {
        Self::new(request, Vec::new(), None, 0, provenance)
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request: &ListPipelinesRequest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != *request.request_digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        validate_cursor(self.next_cursor.as_ref(), request)?;
        for value in &self.pipelines {
            value.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPage {
    scope_digest: Digest,
    request_digest: Digest,
    pub executions: Vec<ExecutionMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ExecutionPage {
    pub fn new(
        request: &ListExecutionsRequest,
        executions: Vec<ExecutionMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if executions.len() > request.page_size() as usize
            || executions.len() > MAX_METADATA_ITEMS
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        validate_cursor(next_cursor.as_ref(), request)?;
        let response_digest = page_response_digest(
            "harness-execution-response/v1",
            executions.iter().map(ExecutionMetadata::digest),
            response_bytes,
        );
        let page_digest = page_digest(
            &request.request_digest,
            &response_digest,
            next_cursor.as_ref(),
        );
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            executions,
            next_cursor,
            response_digest,
            page_digest,
            provenance,
        })
    }

    pub fn empty(request: &ListExecutionsRequest, provenance: TransportProvenance) -> Result<Self> {
        Self::new(request, Vec::new(), None, 0, provenance)
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request: &ListExecutionsRequest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != *request.request_digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        validate_cursor(self.next_cursor.as_ref(), request)?;
        for value in &self.executions {
            value.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagePage {
    scope_digest: Digest,
    request_digest: Digest,
    pub stages: Vec<StageMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub provenance: TransportProvenance,
}

impl StagePage {
    pub fn new(
        request: &ListStagesRequest,
        stages: Vec<StageMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if stages.len() > MAX_METADATA_ITEMS || response_bytes > MAX_RESPONSE_BYTES {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor
                .validate_against_scope_digest(request.scope_digest(), request.request_digest())?;
        }
        let response_digest = page_response_digest(
            "harness-stage-response/v1",
            stages.iter().map(StageMetadata::digest),
            response_bytes,
        );
        let page_digest = page_digest(
            &request.request_digest,
            &response_digest,
            next_cursor.as_ref(),
        );
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            stages,
            next_cursor,
            response_digest,
            page_digest,
            provenance,
        })
    }

    pub fn empty(request: &ListStagesRequest, provenance: TransportProvenance) -> Result<Self> {
        Self::new(request, Vec::new(), None, 0, provenance)
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request: &ListStagesRequest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != *request.request_digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        for value in &self.stages {
            value.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePage {
    scope_digest: Digest,
    request_digest: Digest,
    pub services: Vec<ServiceMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_digest: Digest,
    pub page_digest: Digest,
    pub provenance: TransportProvenance,
}

impl ServicePage {
    pub fn new(
        request: &ListServicesRequest,
        services: Vec<ServiceMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if services.len() > request.page_size() as usize
            || services.len() > MAX_METADATA_ITEMS
            || response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        validate_cursor(next_cursor.as_ref(), request)?;
        let response_digest = page_response_digest(
            "harness-service-response/v1",
            services.iter().map(ServiceMetadata::digest),
            response_bytes,
        );
        let page_digest = page_digest(
            &request.request_digest,
            &response_digest,
            next_cursor.as_ref(),
        );
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            services,
            next_cursor,
            response_digest,
            page_digest,
            provenance,
        })
    }

    pub fn empty(request: &ListServicesRequest, provenance: TransportProvenance) -> Result<Self> {
        Self::new(request, Vec::new(), None, 0, provenance)
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request: &ListServicesRequest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != *request.request_digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        validate_cursor(self.next_cursor.as_ref(), request)?;
        for value in &self.services {
            value.validate(scope)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentResponse {
    scope_digest: Digest,
    request_digest: Digest,
    pub deployment: Option<DeploymentMetadata>,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl DeploymentResponse {
    pub fn new(
        request: &GetDeploymentRequest,
        deployment: Option<DeploymentMetadata>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(HarnessDeliveryResultError::PartialEvidence);
        }
        let response_digest = Digest::from_parts(
            "harness-deployment-response/v1",
            &[
                (
                    "deployment",
                    deployment
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                ("bytes", response_bytes.to_string()),
            ],
        );
        Ok(Self {
            scope_digest: request.scope_digest.clone(),
            request_digest: request.request_digest.clone(),
            deployment,
            response_digest,
            provenance,
        })
    }

    pub fn empty(request: &GetDeploymentRequest, provenance: TransportProvenance) -> Result<Self> {
        Self::new(request, None, 0, provenance)
    }

    pub(crate) fn validate_against(
        &self,
        scope: &HarnessDeliveryScope,
        request: &GetDeploymentRequest,
    ) -> Result<()> {
        if self.scope_digest != scope.digest() || self.request_digest != *request.request_digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        if let Some(value) = &self.deployment {
            value.validate(scope)?;
        }
        Ok(())
    }
}

fn validate_cursor<T>(cursor: Option<&OpaqueCursor>, request: &T) -> Result<()>
where
    T: RequestScope,
{
    if let Some(cursor) = cursor {
        cursor.validate_against_scope_digest(request.scope_digest(), request.request_digest())?;
    }
    Ok(())
}

trait RequestScope {
    fn scope_digest(&self) -> &Digest;
    fn request_digest(&self) -> &Digest;
}

impl RequestScope for ListPipelinesRequest {
    fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl RequestScope for ListExecutionsRequest {
    fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl RequestScope for ListServicesRequest {
    fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

trait CursorBound {
    fn validate_against_scope_digest(
        &self,
        scope_digest: &Digest,
        request_digest: &Digest,
    ) -> Result<()>;
}

impl CursorBound for OpaqueCursor {
    fn validate_against_scope_digest(
        &self,
        scope_digest: &Digest,
        request_digest: &Digest,
    ) -> Result<()> {
        if self.scope_digest() != scope_digest || self.request_digest() != request_digest {
            return Err(HarnessDeliveryResultError::CursorMismatch);
        }
        Ok(())
    }
}

fn page_response_digest<'a>(
    domain: &str,
    values: impl Iterator<Item = &'a Digest>,
    response_bytes: u64,
) -> Digest {
    Digest::from_parts(
        domain,
        &[
            (
                "items",
                values
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ("bytes", response_bytes.to_string()),
        ],
    )
}

fn page_digest(
    request_digest: &Digest,
    response_digest: &Digest,
    next_cursor: Option<&OpaqueCursor>,
) -> Digest {
    Digest::from_parts(
        "harness-page/v1",
        &[
            ("request", request_digest.as_str().to_owned()),
            ("response", response_digest.as_str().to_owned()),
            (
                "cursor",
                next_cursor.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
        ],
    )
}

pub trait HarnessTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_pipelines(
        &mut self,
        _request: &ListPipelinesRequest,
    ) -> std::result::Result<PipelinePage, HarnessTransportError> {
        Err(HarnessTransportError::Unsupported)
    }

    fn list_executions(
        &mut self,
        _request: &ListExecutionsRequest,
    ) -> std::result::Result<ExecutionPage, HarnessTransportError> {
        Err(HarnessTransportError::Unsupported)
    }

    fn list_stages(
        &mut self,
        _request: &ListStagesRequest,
    ) -> std::result::Result<StagePage, HarnessTransportError> {
        Err(HarnessTransportError::Unsupported)
    }

    fn list_services(
        &mut self,
        _request: &ListServicesRequest,
    ) -> std::result::Result<ServicePage, HarnessTransportError> {
        Err(HarnessTransportError::Unsupported)
    }

    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<DeploymentResponse, HarnessTransportError> {
        Err(HarnessTransportError::Unsupported)
    }
}

pub type HarnessProviderError = HarnessTransportError;

pub struct HarnessProvider<T> {
    transport: T,
    definition: HarnessProviderDefinition,
}

impl<T: HarnessTransport> fmt::Debug for HarnessProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport_provenance())
            .finish()
    }
}

impl<T: HarnessTransport> HarnessProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_definition(transport, HarnessProviderDefinition::default())
    }

    pub fn with_definition(transport: T, definition: HarnessProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &HarnessProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn transport_provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport_provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_pipelines(
        &mut self,
        scope: &HarnessDeliveryScope,
        request: &ListPipelinesRequest,
    ) -> Result<PipelinePage> {
        if request.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        self.transport
            .list_pipelines(request)
            .map_err(HarnessDeliveryResultError::Transport)
            .and_then(|response| {
                response.validate_against(scope, request)?;
                Ok(response)
            })
    }

    pub fn list_executions(
        &mut self,
        scope: &HarnessDeliveryScope,
        request: &ListExecutionsRequest,
    ) -> Result<ExecutionPage> {
        if request.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        self.transport
            .list_executions(request)
            .map_err(HarnessDeliveryResultError::Transport)
            .and_then(|response| {
                response.validate_against(scope, request)?;
                Ok(response)
            })
    }

    pub fn list_stages(
        &mut self,
        scope: &HarnessDeliveryScope,
        request: &ListStagesRequest,
    ) -> Result<StagePage> {
        if request.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        self.transport
            .list_stages(request)
            .map_err(HarnessDeliveryResultError::Transport)
            .and_then(|response| {
                response.validate_against(scope, request)?;
                Ok(response)
            })
    }

    pub fn list_services(
        &mut self,
        scope: &HarnessDeliveryScope,
        request: &ListServicesRequest,
    ) -> Result<ServicePage> {
        if request.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        self.transport
            .list_services(request)
            .map_err(HarnessDeliveryResultError::Transport)
            .and_then(|response| {
                response.validate_against(scope, request)?;
                Ok(response)
            })
    }

    pub fn get_deployment(
        &mut self,
        scope: &HarnessDeliveryScope,
        request: &GetDeploymentRequest,
    ) -> Result<DeploymentResponse> {
        if request.scope_digest() != &scope.digest() {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        self.transport
            .get_deployment(request)
            .map_err(HarnessDeliveryResultError::Transport)
            .and_then(|response| {
                response.validate_against(scope, request)?;
                Ok(response)
            })
    }
}

impl Default for HarnessProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Harness provider definition")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordedHarnessRequest {
    ListPipelines { request_digest: Digest },
    ListExecutions { request_digest: Digest },
    ListStages { request_digest: Digest },
    ListServices { request_digest: Digest },
    GetDeploymentMetadata { request_digest: Digest },
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl HarnessTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_pipelines(
        &mut self,
        _request: &ListPipelinesRequest,
    ) -> std::result::Result<PipelinePage, HarnessTransportError> {
        Err(HarnessTransportError::BlockedEnv)
    }

    fn list_executions(
        &mut self,
        _request: &ListExecutionsRequest,
    ) -> std::result::Result<ExecutionPage, HarnessTransportError> {
        Err(HarnessTransportError::BlockedEnv)
    }

    fn list_stages(
        &mut self,
        _request: &ListStagesRequest,
    ) -> std::result::Result<StagePage, HarnessTransportError> {
        Err(HarnessTransportError::BlockedEnv)
    }

    fn list_services(
        &mut self,
        _request: &ListServicesRequest,
    ) -> std::result::Result<ServicePage, HarnessTransportError> {
        Err(HarnessTransportError::BlockedEnv)
    }

    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<DeploymentResponse, HarnessTransportError> {
        Err(HarnessTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureTransport {
    pipelines: VecDeque<std::result::Result<PipelinePage, HarnessTransportError>>,
    executions: VecDeque<std::result::Result<ExecutionPage, HarnessTransportError>>,
    stages: VecDeque<std::result::Result<StagePage, HarnessTransportError>>,
    services: VecDeque<std::result::Result<ServicePage, HarnessTransportError>>,
    deployments: VecDeque<std::result::Result<DeploymentResponse, HarnessTransportError>>,
}

impl FixtureTransport {
    pub fn for_scope(_scope: &HarnessDeliveryScope, _observed_at: DateTime<Utc>) -> Self {
        Self::default()
    }

    pub fn push_pipeline_page(&mut self, page: PipelinePage) {
        self.pipelines.push_back(Ok(page));
    }

    pub fn push_pipeline_error(&mut self, error: HarnessTransportError) {
        self.pipelines.push_back(Err(error));
    }

    pub fn push_execution_page(&mut self, page: ExecutionPage) {
        self.executions.push_back(Ok(page));
    }

    pub fn push_execution_error(&mut self, error: HarnessTransportError) {
        self.executions.push_back(Err(error));
    }

    pub fn push_stage_page(&mut self, page: StagePage) {
        self.stages.push_back(Ok(page));
    }

    pub fn push_stage_error(&mut self, error: HarnessTransportError) {
        self.stages.push_back(Err(error));
    }

    pub fn push_service_page(&mut self, page: ServicePage) {
        self.services.push_back(Ok(page));
    }

    pub fn push_service_error(&mut self, error: HarnessTransportError) {
        self.services.push_back(Err(error));
    }

    pub fn push_deployment_response(&mut self, response: DeploymentResponse) {
        self.deployments.push_back(Ok(response));
    }

    pub fn push_deployment_error(&mut self, error: HarnessTransportError) {
        self.deployments.push_back(Err(error));
    }
}

impl HarnessTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_pipelines(
        &mut self,
        _request: &ListPipelinesRequest,
    ) -> std::result::Result<PipelinePage, HarnessTransportError> {
        self.pipelines
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_executions(
        &mut self,
        _request: &ListExecutionsRequest,
    ) -> std::result::Result<ExecutionPage, HarnessTransportError> {
        self.executions
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_stages(
        &mut self,
        _request: &ListStagesRequest,
    ) -> std::result::Result<StagePage, HarnessTransportError> {
        self.stages
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_services(
        &mut self,
        _request: &ListServicesRequest,
    ) -> std::result::Result<ServicePage, HarnessTransportError> {
        self.services
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<DeploymentResponse, HarnessTransportError> {
        self.deployments
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    requests: Vec<RecordedHarnessRequest>,
    pipelines: VecDeque<std::result::Result<PipelinePage, HarnessTransportError>>,
    executions: VecDeque<std::result::Result<ExecutionPage, HarnessTransportError>>,
    stages: VecDeque<std::result::Result<StagePage, HarnessTransportError>>,
    services: VecDeque<std::result::Result<ServicePage, HarnessTransportError>>,
    deployments: VecDeque<std::result::Result<DeploymentResponse, HarnessTransportError>>,
}

impl RecordingTransport {
    #[must_use]
    pub fn requests(&self) -> &[RecordedHarnessRequest] {
        &self.requests
    }

    pub fn push_pipeline_response(
        &mut self,
        response: std::result::Result<PipelinePage, HarnessTransportError>,
    ) {
        self.pipelines.push_back(response);
    }

    pub fn push_execution_response(
        &mut self,
        response: std::result::Result<ExecutionPage, HarnessTransportError>,
    ) {
        self.executions.push_back(response);
    }

    pub fn push_stage_response(
        &mut self,
        response: std::result::Result<StagePage, HarnessTransportError>,
    ) {
        self.stages.push_back(response);
    }

    pub fn push_service_response(
        &mut self,
        response: std::result::Result<ServicePage, HarnessTransportError>,
    ) {
        self.services.push_back(response);
    }

    pub fn push_deployment_response(
        &mut self,
        response: std::result::Result<DeploymentResponse, HarnessTransportError>,
    ) {
        self.deployments.push_back(response);
    }
}

impl HarnessTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_pipelines(
        &mut self,
        request: &ListPipelinesRequest,
    ) -> std::result::Result<PipelinePage, HarnessTransportError> {
        self.requests.push(RecordedHarnessRequest::ListPipelines {
            request_digest: request.request_digest().clone(),
        });
        self.pipelines
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_executions(
        &mut self,
        request: &ListExecutionsRequest,
    ) -> std::result::Result<ExecutionPage, HarnessTransportError> {
        self.requests.push(RecordedHarnessRequest::ListExecutions {
            request_digest: request.request_digest().clone(),
        });
        self.executions
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_stages(
        &mut self,
        request: &ListStagesRequest,
    ) -> std::result::Result<StagePage, HarnessTransportError> {
        self.requests.push(RecordedHarnessRequest::ListStages {
            request_digest: request.request_digest().clone(),
        });
        self.stages
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn list_services(
        &mut self,
        request: &ListServicesRequest,
    ) -> std::result::Result<ServicePage, HarnessTransportError> {
        self.requests.push(RecordedHarnessRequest::ListServices {
            request_digest: request.request_digest().clone(),
        });
        self.services
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<DeploymentResponse, HarnessTransportError> {
        self.requests
            .push(RecordedHarnessRequest::GetDeploymentMetadata {
                request_digest: request.request_digest().clone(),
            });
        self.deployments
            .pop_front()
            .unwrap_or(Err(HarnessTransportError::FixtureMissing))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope: HarnessDeliveryScope,
    observed_at: DateTime<Utc>,
}

impl LoopbackTransport {
    pub fn new(scope: HarnessDeliveryScope, observed_at: DateTime<Utc>) -> Self {
        Self { scope, observed_at }
    }

    pub fn for_scope(scope: &HarnessDeliveryScope, observed_at: DateTime<Utc>) -> Self {
        Self::new(scope.clone(), observed_at)
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        let scope = HarnessDeliveryScope::from_values(
            "account",
            "org",
            "project",
            "pipeline",
            Some("execution".to_owned()),
            Some("stage".to_owned()),
            Some("service".to_owned()),
            Some("environment".to_owned()),
            Some("commit".to_owned()),
            "mission",
            1,
            "project",
            1,
            "work-product",
            1,
        )
        .expect("valid loopback scope");
        Self::new(scope, Utc::now())
    }
}

impl HarnessTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_pipelines(
        &mut self,
        request: &ListPipelinesRequest,
    ) -> std::result::Result<PipelinePage, HarnessTransportError> {
        let pipeline = PipelineMetadata::new(
            &self.scope,
            self.scope.pipeline().clone(),
            1,
            HarnessRunStatus::Succeeded,
            self.observed_at,
        )
        .map_err(|_| HarnessTransportError::InvalidResponse)?;
        PipelinePage::new(request, vec![pipeline], None, 128, self.provenance())
            .map_err(|_| HarnessTransportError::InvalidResponse)
    }

    fn list_executions(
        &mut self,
        request: &ListExecutionsRequest,
    ) -> std::result::Result<ExecutionPage, HarnessTransportError> {
        let execution = self
            .scope
            .execution()
            .cloned()
            .unwrap_or_else(|| HarnessExecutionId::new("loopback-execution").expect("id"));
        let metadata = ExecutionMetadata::new(
            &self.scope,
            execution,
            self.scope.pipeline().clone(),
            self.scope.commit().cloned(),
            HarnessRunStatus::Succeeded,
            self.observed_at,
        )
        .map_err(|_| HarnessTransportError::InvalidResponse)?;
        ExecutionPage::new(request, vec![metadata], None, 128, self.provenance())
            .map_err(|_| HarnessTransportError::InvalidResponse)
    }

    fn list_stages(
        &mut self,
        request: &ListStagesRequest,
    ) -> std::result::Result<StagePage, HarnessTransportError> {
        let stage = self
            .scope
            .stage()
            .cloned()
            .ok_or(HarnessTransportError::InvalidResponse)?;
        let execution = self
            .scope
            .execution()
            .ok_or(HarnessTransportError::InvalidResponse)?;
        let metadata = StageMetadata::new(
            &self.scope,
            stage,
            execution,
            self.scope.service().cloned(),
            self.scope.environment().cloned(),
            HarnessRunStatus::Succeeded,
            self.observed_at,
        )
        .map_err(|_| HarnessTransportError::InvalidResponse)?;
        StagePage::new(request, vec![metadata], None, 128, self.provenance())
            .map_err(|_| HarnessTransportError::InvalidResponse)
    }

    fn list_services(
        &mut self,
        request: &ListServicesRequest,
    ) -> std::result::Result<ServicePage, HarnessTransportError> {
        let service = self
            .scope
            .service()
            .cloned()
            .ok_or(HarnessTransportError::InvalidResponse)?;
        let metadata = ServiceMetadata::new(
            &self.scope,
            service,
            self.scope.environment().cloned(),
            Some(HarnessDeploymentId::new("loopback-deployment").expect("id")),
            self.scope.commit().cloned(),
            HarnessRunStatus::Succeeded,
            self.observed_at,
        )
        .map_err(|_| HarnessTransportError::InvalidResponse)?;
        ServicePage::new(request, vec![metadata], None, 128, self.provenance())
            .map_err(|_| HarnessTransportError::InvalidResponse)
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<DeploymentResponse, HarnessTransportError> {
        let service = self
            .scope
            .service()
            .cloned()
            .ok_or(HarnessTransportError::InvalidResponse)?;
        let environment = self
            .scope
            .environment()
            .cloned()
            .ok_or(HarnessTransportError::InvalidResponse)?;
        let metadata = DeploymentMetadata::new(
            &self.scope,
            HarnessDeploymentId::new("loopback-deployment").expect("id"),
            service,
            environment,
            self.scope.commit().cloned(),
            HarnessRunStatus::Succeeded,
            self.observed_at,
        )
        .map_err(|_| HarnessTransportError::InvalidResponse)?;
        DeploymentResponse::new(request, Some(metadata), 128, self.provenance())
            .map_err(|_| HarnessTransportError::InvalidResponse)
    }
}
