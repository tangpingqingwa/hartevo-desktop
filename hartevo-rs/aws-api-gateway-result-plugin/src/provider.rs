//! Provider seam for bounded API Gateway metadata reads.
//!
//! The transport trait is intentionally a deterministic seam.  It can be
//! backed by fixtures, recordings, a loopback harness, or the honest
//! `BLOCKED_ENV` transport; no implementation in this crate resolves a live
//! credential or performs native SigV4/HTTPS.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_API_GATEWAY_API_REVISION, AWS_API_GATEWAY_PROVIDER_ID, AWS_API_GATEWAY_PROVIDER_VERSION,
    model::{
        AccountId, ApiBinding, ApiDeploymentBinding, ApiGatewayDeploymentId,
        ApiGatewayReadOperation, AwsApiGatewayScope, AwsRegion, DeploymentMetadata,
        DeploymentSummary, Digest, ErrorClassification, MAX_DEPLOYMENTS, MAX_PAGES,
        MAX_RESPONSE_BYTES, OpaquePageToken, PAGE_SIZE, ProviderErrorEvidence, ProviderId,
        ProviderProvenance, ProviderRevision, StageBinding, StageMetadata, TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS API Gateway provider version is empty")]
    EmptyVersion,
    #[error("AWS API Gateway provider revision is empty")]
    EmptyRevision,
    #[error("AWS API Gateway provider definition is not Layer-1 honest")]
    AuthorityEscalation,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("invalid provider request")]
    InvalidRequest,
    #[error("provider returned HTTP 401")]
    Unauthorized,
    #[error("provider returned HTTP 403")]
    AccessDenied,
    #[error("provider returned HTTP 404")]
    NotFound,
    #[error("provider returned HTTP 409")]
    Conflict,
    #[error("provider throttled the request")]
    Throttled { retry_after_seconds: Option<u64> },
    #[error("provider returned a server failure")]
    ServerFailure { status_code: Option<u16> },
    #[error("provider request timed out")]
    Timeout,
    #[error("the environment is blocked from native API Gateway access")]
    BlockedEnvironment,
    #[error("provider returned an incomplete response")]
    Partial,
    #[error("provider response exceeded the bounded evidence budget")]
    ResponseTooLarge,
}

impl TransportError {
    pub const fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidRequest => ErrorClassification::InvalidRequest,
            Self::Unauthorized => ErrorClassification::Unauthorized,
            Self::AccessDenied => ErrorClassification::AccessDenied,
            Self::NotFound => ErrorClassification::NotFound,
            Self::Conflict => ErrorClassification::Conflict,
            Self::Throttled { .. } => ErrorClassification::Throttled,
            Self::ServerFailure { .. } => ErrorClassification::ServerFailure,
            Self::Timeout => ErrorClassification::Timeout,
            Self::BlockedEnvironment => ErrorClassification::BlockedEnvironment,
            Self::Partial | Self::ResponseTooLarge => ErrorClassification::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::InvalidRequest
            | Self::Timeout
            | Self::BlockedEnvironment
            | Self::Partial
            | Self::ResponseTooLarge => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Throttled { .. } | Self::ServerFailure { .. } | Self::Timeout
        )
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized | Self::AccessDenied | Self::NotFound
        )
    }

    pub fn evidence(&self, attempt: u8) -> ProviderErrorEvidence {
        ProviderErrorEvidence::new(
            self.classification(),
            self.status_code(),
            self.retryable(),
            attempt,
        )
    }
}

pub fn is_access_loss(error: &TransportError) -> bool {
    error.is_access_loss()
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsApiGatewayProviderError {
    #[error(transparent)]
    Transport(TransportError),
    #[error("provider response was bound to a different API Gateway operation")]
    OperationBinding,
    #[error("provider response page number or revision is invalid")]
    PageBinding,
    #[error("provider response contains too many deployments")]
    TooManyDeployments,
    #[error("provider response is too large")]
    ResponseTooLarge,
    #[error("provider response is invalid JSON")]
    InvalidJson,
    #[error("provider response is missing bounded metadata")]
    MissingMetadata,
}

impl From<TransportError> for AwsApiGatewayProviderError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

pub type ProviderError = AwsApiGatewayProviderError;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetStageRequest {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub api: ApiBinding,
    pub stage: StageBinding,
    pub deployment: ApiDeploymentBinding,
    pub scope_digest: Digest,
}

impl GetStageRequest {
    pub fn from_scope(scope: &AwsApiGatewayScope) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            api: scope.api.clone(),
            stage: scope.stage.clone(),
            deployment: scope.deployment.clone(),
            scope_digest: scope.digest(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-get-stage-request/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                format!("{:?}", self.api.kind),
                self.api.id.as_str().to_owned(),
                self.api.revision.get().to_string(),
                self.stage.name.as_str().to_owned(),
                self.stage.revision.get().to_string(),
                self.deployment.id.as_str().to_owned(),
                self.deployment.revision.get().to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeploymentRequest {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub api: ApiBinding,
    pub stage: StageBinding,
    pub deployment: ApiDeploymentBinding,
    pub scope_digest: Digest,
}

impl GetDeploymentRequest {
    pub fn from_scope(scope: &AwsApiGatewayScope) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            api: scope.api.clone(),
            stage: scope.stage.clone(),
            deployment: scope.deployment.clone(),
            scope_digest: scope.digest(),
        }
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-get-deployment-request/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                format!("{:?}", self.api.kind),
                self.api.id.as_str().to_owned(),
                self.api.revision.get().to_string(),
                self.stage.name.as_str().to_owned(),
                self.stage.revision.get().to_string(),
                self.deployment.id.as_str().to_owned(),
                self.deployment.revision.get().to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeploymentsRequest {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub api: ApiBinding,
    pub stage: StageBinding,
    pub deployment: ApiDeploymentBinding,
    pub page_size: u16,
    pub max_pages: u16,
    pub max_response_bytes: usize,
    pub max_retries: u8,
    pub cursor: Option<OpaquePageToken>,
    pub scope_digest: Digest,
}

impl GetDeploymentsRequest {
    pub fn from_scope(scope: &AwsApiGatewayScope) -> Result<Self, crate::model::ModelError> {
        Self::with_bounds(
            scope,
            PAGE_SIZE,
            MAX_PAGES,
            MAX_RESPONSE_BYTES,
            crate::model::MAX_RETRIES,
            None,
        )
    }

    pub fn with_bounds(
        scope: &AwsApiGatewayScope,
        page_size: u16,
        max_pages: u16,
        max_response_bytes: usize,
        max_retries: u8,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, crate::model::ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE {
            return Err(crate::model::ModelError::Invalid {
                field: "API Gateway page size",
            });
        }
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(crate::model::ModelError::Invalid {
                field: "API Gateway page budget",
            });
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(crate::model::ModelError::Invalid {
                field: "API Gateway response budget",
            });
        }
        if max_retries > crate::model::MAX_RETRIES {
            return Err(crate::model::ModelError::Invalid {
                field: "API Gateway retry budget",
            });
        }
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            api: scope.api.clone(),
            stage: scope.stage.clone(),
            deployment: scope.deployment.clone(),
            page_size,
            max_pages,
            max_response_bytes,
            max_retries,
            cursor,
            scope_digest: scope.digest(),
        })
    }

    pub fn with_cursor(
        &self,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self, crate::model::ModelError> {
        let mut next = self.clone();
        next.cursor = cursor;
        Ok(next)
    }

    pub fn request_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-get-deployments-request/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                format!("{:?}", self.api.kind),
                self.api.id.as_str().to_owned(),
                self.api.revision.get().to_string(),
                self.stage.name.as_str().to_owned(),
                self.stage.revision.get().to_string(),
                self.deployment.id.as_str().to_owned(),
                self.deployment.revision.get().to_string(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.max_response_bytes.to_string(),
                self.max_retries.to_string(),
                self.cursor
                    .as_ref()
                    .map_or_else(String::new, |token| token.token_digest().to_string()),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayStageResponse {
    pub stage: StageMetadata,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
}

impl AwsApiGatewayStageResponse {
    pub fn new(
        stage: StageMetadata,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Self {
        let mut response = Self {
            stage,
            response_bytes,
            response_digest: Digest::zero(),
            provider_revision,
        };
        response.response_digest = response.recomputed_response_digest();
        response
    }

    pub fn recomputed_response_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-stage-response/v1",
            &[
                self.stage.metadata_digest.to_string(),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayDeploymentResponse {
    pub deployment: DeploymentMetadata,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
}

impl AwsApiGatewayDeploymentResponse {
    pub fn new(
        deployment: DeploymentMetadata,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Self {
        let mut response = Self {
            deployment,
            response_bytes,
            response_digest: Digest::zero(),
            provider_revision,
        };
        response.response_digest = response.recomputed_response_digest();
        response
    }

    pub fn recomputed_response_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-deployment-response/v1",
            &[
                self.deployment.metadata_digest.to_string(),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsApiGatewayDeploymentsPage {
    pub page_number: u16,
    pub deployments: Vec<DeploymentSummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
}

impl AwsApiGatewayDeploymentsPage {
    pub fn new(
        request: &GetDeploymentsRequest,
        page_number: u16,
        deployments: Vec<DeploymentSummary>,
        next_cursor: Option<OpaquePageToken>,
        response_bytes: usize,
        provider_revision: ProviderRevision,
    ) -> Result<Self, AwsApiGatewayProviderError> {
        if page_number == 0 || page_number > request.max_pages {
            return Err(AwsApiGatewayProviderError::PageBinding);
        }
        if deployments.len() > usize::from(request.page_size) {
            return Err(AwsApiGatewayProviderError::TooManyDeployments);
        }
        if response_bytes > request.max_response_bytes {
            return Err(AwsApiGatewayProviderError::ResponseTooLarge);
        }
        let mut page = Self {
            page_number,
            deployments,
            next_cursor,
            response_bytes,
            response_digest: Digest::zero(),
            provider_revision,
        };
        page.response_digest = page.recomputed_response_digest();
        Ok(page)
    }

    pub fn recomputed_response_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-api-gateway-deployments-page/v1",
            &[
                self.page_number.to_string(),
                self.deployments
                    .iter()
                    .map(|deployment| deployment.metadata_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                self.next_cursor
                    .as_ref()
                    .map_or_else(String::new, |token| token.token_digest().to_string()),
                self.response_bytes.to_string(),
                self.provider_revision.as_str().to_owned(),
            ],
        )
    }
}

pub trait AwsApiGatewayTransport {
    fn provenance(&self) -> ProviderProvenance;

    fn get_stage(
        &mut self,
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError>;

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError>;

    fn get_deployments(
        &mut self,
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum RecordedRequest {
    GetStage { request_digest: Digest },
    GetDeployment { request_digest: Digest },
    GetDeployments { request_digest: Digest },
}

impl RecordedRequest {
    pub fn digest(&self) -> &Digest {
        match self {
            Self::GetStage { request_digest }
            | Self::GetDeployment { request_digest }
            | Self::GetDeployments { request_digest } => request_digest,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AwsApiGatewayProviderDefinition {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub api_revision: ProviderRevision,
    pub api_versions: Vec<String>,
    pub allowlisted_operations: Vec<ApiGatewayReadOperation>,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub type AwsApiGatewayProviderIdentity = AwsApiGatewayProviderDefinition;

impl AwsApiGatewayProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let provider_id = ProviderId::new(AWS_API_GATEWAY_PROVIDER_ID)
            .map_err(|_| ProviderDefinitionError::EmptyRevision)?;
        let api_revision = ProviderRevision::new(AWS_API_GATEWAY_API_REVISION)
            .map_err(|_| ProviderDefinitionError::EmptyRevision)?;
        let allowlisted_operations = vec![
            ApiGatewayReadOperation::GetStage,
            ApiGatewayReadOperation::GetDeployment,
            ApiGatewayReadOperation::GetDeployments,
        ];
        let api_versions = vec!["2015-07-09".to_owned(), "2018-11-29".to_owned()];
        let api_digest = Digest::from_parts(
            "hartevo-aws-api-gateway-api-allowlist/v1",
            &[
                api_revision.as_str().to_owned(),
                api_versions.join(","),
                allowlisted_operations
                    .iter()
                    .map(|operation| operation.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        let provider_digest = Digest::from_parts(
            "hartevo-aws-api-gateway-provider-definition/v1",
            &[
                provider_id.as_str().to_owned(),
                provider_version.clone(),
                api_revision.as_str().to_owned(),
                api_digest.to_string(),
                provenance.label().to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            provider_version,
            api_revision,
            api_versions,
            allowlisted_operations,
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        self.provider_digest.clone()
    }

    pub fn api_digest(&self) -> Digest {
        self.api_digest.clone()
    }
}

pub struct AwsApiGatewayProvider<T> {
    definition: AwsApiGatewayProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for AwsApiGatewayProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsApiGatewayProvider")
            .field("definition", &self.definition)
            .field("transport", &self.definition.provenance)
            .finish()
    }
}

impl<T: AwsApiGatewayTransport> AwsApiGatewayProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Self::with_version(transport, AWS_API_GATEWAY_PROVIDER_VERSION, provenance)
    }

    pub fn with_version(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = AwsApiGatewayProviderDefinition::new(provider_version, provenance)?;
        if definition.connected || definition.native || definition.first_party {
            return Err(ProviderDefinitionError::AuthorityEscalation);
        }
        Ok(Self {
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &AwsApiGatewayProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsApiGatewayProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance.clone()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_stage(
        &mut self,
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, AwsApiGatewayProviderError> {
        let response = self.transport.get_stage(request)?;
        response
            .stage
            .validate()
            .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        if response.provider_revision != self.definition.api_revision {
            return Err(AwsApiGatewayProviderError::PageBinding);
        }
        Ok(response)
    }

    pub fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, AwsApiGatewayProviderError> {
        let response = self.transport.get_deployment(request)?;
        response
            .deployment
            .validate()
            .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        if response.provider_revision != self.definition.api_revision {
            return Err(AwsApiGatewayProviderError::PageBinding);
        }
        Ok(response)
    }

    pub fn get_deployments(
        &mut self,
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, AwsApiGatewayProviderError> {
        let response = self.transport.get_deployments(request)?;
        if response.provider_revision != self.definition.api_revision {
            return Err(AwsApiGatewayProviderError::PageBinding);
        }
        if response.deployments.len() > usize::from(request.page_size)
            || response.deployments.len() > MAX_DEPLOYMENTS
        {
            return Err(AwsApiGatewayProviderError::TooManyDeployments);
        }
        for deployment in &response.deployments {
            deployment
                .validate()
                .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        }
        Ok(response)
    }

    pub fn parse_stage_json(
        request: &GetStageRequest,
        response_bytes: usize,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsApiGatewayStageResponse, AwsApiGatewayProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsApiGatewayProviderError::ResponseTooLarge);
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsApiGatewayProviderError::InvalidJson)?;
        let object = value
            .as_object()
            .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
        let deployment_id = ApiGatewayDeploymentId::new(
            object
                .get("deploymentId")
                .and_then(Value::as_str)
                .ok_or(AwsApiGatewayProviderError::MissingMetadata)?,
        )
        .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        let last_updated = parse_timestamp(object.get("lastUpdatedDate"))?;
        let canary_traffic_percent = object
            .get("canarySettings")
            .and_then(Value::as_object)
            .and_then(|canary| canary.get("percentTraffic"))
            .and_then(Value::as_f64)
            .map(|percent| percent.clamp(0.0, 100.0).round() as u8);
        let route_auth_summary_digest =
            digest_json_fields(object, &["methodSettings", "routeSettings"]);
        let stage = StageMetadata::new(
            request.api.id.clone(),
            request.stage.name.clone(),
            deployment_id,
            request.api.revision,
            request.stage.revision,
            last_updated,
            canary_traffic_percent,
            route_auth_summary_digest,
        )
        .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        Ok(AwsApiGatewayStageResponse::new(
            stage,
            response_bytes,
            provider_revision,
        ))
    }

    pub fn parse_deployment_json(
        request: &GetDeploymentRequest,
        response_bytes: usize,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsApiGatewayDeploymentResponse, AwsApiGatewayProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsApiGatewayProviderError::ResponseTooLarge);
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsApiGatewayProviderError::InvalidJson)?;
        let object = value
            .as_object()
            .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
        let deployment_id = ApiGatewayDeploymentId::new(
            object
                .get("id")
                .and_then(Value::as_str)
                .ok_or(AwsApiGatewayProviderError::MissingMetadata)?,
        )
        .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        let created_at = parse_timestamp(object.get("createdDate"))?;
        let route_auth_summary_digest = digest_json_fields(object, &["apiSummary"]);
        let deployment = DeploymentMetadata::new(
            request.api.id.clone(),
            deployment_id,
            request.deployment.revision,
            created_at,
            request.deployment.configuration_digest.clone(),
            request.deployment.commit_digest.clone(),
            route_auth_summary_digest,
        )
        .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        Ok(AwsApiGatewayDeploymentResponse::new(
            deployment,
            response_bytes,
            provider_revision,
        ))
    }

    pub fn parse_deployments_json(
        request: &GetDeploymentsRequest,
        page_number: u16,
        response_bytes: usize,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsApiGatewayDeploymentsPage, AwsApiGatewayProviderError> {
        if response_bytes > request.max_response_bytes {
            return Err(AwsApiGatewayProviderError::ResponseTooLarge);
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsApiGatewayProviderError::InvalidJson)?;
        let object = value
            .as_object()
            .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
        let items = object
            .get("items")
            .and_then(Value::as_array)
            .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
        let mut deployments = Vec::with_capacity(items.len());
        for item in items.iter().take(MAX_DEPLOYMENTS + 1) {
            let item = item
                .as_object()
                .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
            let id = ApiGatewayDeploymentId::new(
                item.get("id")
                    .and_then(Value::as_str)
                    .ok_or(AwsApiGatewayProviderError::MissingMetadata)?,
            )
            .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
            let created_at = parse_timestamp(item.get("createdDate"))?;
            let route_auth_summary_digest = digest_json_fields(item, &["apiSummary"]);
            let metadata = DeploymentMetadata::new(
                request.api.id.clone(),
                id,
                request.deployment.revision,
                created_at,
                request.deployment.configuration_digest.clone(),
                request.deployment.commit_digest.clone(),
                route_auth_summary_digest,
            )
            .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
            deployments.push(DeploymentSummary::from_metadata(&metadata));
        }
        let next_cursor = object
            .get("position")
            .and_then(Value::as_str)
            .map(OpaquePageToken::new)
            .transpose()
            .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)?;
        AwsApiGatewayDeploymentsPage::new(
            request,
            page_number,
            deployments,
            next_cursor,
            response_bytes,
            provider_revision,
        )
    }
}

fn parse_timestamp(value: Option<&Value>) -> Result<DateTime<Utc>, AwsApiGatewayProviderError> {
    let value = value
        .and_then(Value::as_str)
        .ok_or(AwsApiGatewayProviderError::MissingMetadata)?;
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| AwsApiGatewayProviderError::MissingMetadata)
}

fn digest_json_fields(object: &serde_json::Map<String, Value>, fields: &[&str]) -> Digest {
    let values = fields
        .iter()
        .map(|field| {
            (
                (*field).to_owned(),
                object
                    .get(*field)
                    .map_or_else(String::new, Value::to_string),
            )
        })
        .collect::<Vec<_>>();
    Digest::from_text(serde_json::to_vec(&values).expect("JSON field digest is infallible"))
}

#[derive(Clone, Debug, Default)]
pub struct FixtureAwsApiGatewayTransport {
    requests: Vec<RecordedRequest>,
}

impl FixtureAwsApiGatewayTransport {
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    fn fixed_timestamp() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("fixed fixture timestamp")
    }

    fn fixture_stage(
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError> {
        let stage = StageMetadata::new(
            request.api.id.clone(),
            request.stage.name.clone(),
            request.deployment.id.clone(),
            request.api.revision,
            request.stage.revision,
            Self::fixed_timestamp(),
            Some(0),
            Digest::from_text("fixture-route-auth-summary"),
        )
        .map_err(|_| TransportError::Partial)?;
        Ok(AwsApiGatewayStageResponse::new(
            stage,
            512,
            ProviderRevision::new(AWS_API_GATEWAY_API_REVISION)
                .map_err(|_| TransportError::Partial)?,
        ))
    }

    fn fixture_deployment(
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError> {
        let deployment = DeploymentMetadata::new(
            request.api.id.clone(),
            request.deployment.id.clone(),
            request.deployment.revision,
            Self::fixed_timestamp(),
            request.deployment.configuration_digest.clone(),
            request.deployment.commit_digest.clone(),
            Digest::from_text("fixture-route-auth-summary"),
        )
        .map_err(|_| TransportError::Partial)?;
        Ok(AwsApiGatewayDeploymentResponse::new(
            deployment,
            640,
            ProviderRevision::new(AWS_API_GATEWAY_API_REVISION)
                .map_err(|_| TransportError::Partial)?,
        ))
    }

    fn fixture_page(
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError> {
        let deployment = Self::fixture_deployment(&GetDeploymentRequest {
            account_id: request.account_id.clone(),
            region: request.region.clone(),
            api: request.api.clone(),
            stage: request.stage.clone(),
            deployment: request.deployment.clone(),
            scope_digest: request.scope_digest.clone(),
        })
        .map_err(|_| TransportError::Partial)?;
        AwsApiGatewayDeploymentsPage::new(
            request,
            1,
            vec![DeploymentSummary::from_metadata(&deployment.deployment)],
            None,
            768,
            ProviderRevision::new(AWS_API_GATEWAY_API_REVISION)
                .map_err(|_| TransportError::Partial)?,
        )
        .map_err(|_| TransportError::Partial)
    }
}

impl AwsApiGatewayTransport for FixtureAwsApiGatewayTransport {
    fn provenance(&self) -> ProviderProvenance {
        TransportProvenance::Fixture
    }

    fn get_stage(
        &mut self,
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError> {
        self.requests.push(RecordedRequest::GetStage {
            request_digest: request.request_digest(),
        });
        Self::fixture_stage(request)
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError> {
        self.requests.push(RecordedRequest::GetDeployment {
            request_digest: request.request_digest(),
        });
        Self::fixture_deployment(request)
    }

    fn get_deployments(
        &mut self,
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError> {
        self.requests.push(RecordedRequest::GetDeployments {
            request_digest: request.request_digest(),
        });
        Self::fixture_page(request)
    }
}

pub type FakeAwsApiGatewayTransport = FixtureAwsApiGatewayTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsApiGatewayTransport {
    requests: Vec<RecordedRequest>,
    stage_responses: VecDeque<Result<AwsApiGatewayStageResponse, TransportError>>,
    deployment_responses: VecDeque<Result<AwsApiGatewayDeploymentResponse, TransportError>>,
    deployments_pages: VecDeque<Result<AwsApiGatewayDeploymentsPage, TransportError>>,
}

impl RecordingAwsApiGatewayTransport {
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn request_count(&self) -> usize {
        self.requests.len()
    }

    pub fn push_stage_response(
        &mut self,
        response: Result<AwsApiGatewayStageResponse, TransportError>,
    ) {
        self.stage_responses.push_back(response);
    }

    pub fn push_deployment_response(
        &mut self,
        response: Result<AwsApiGatewayDeploymentResponse, TransportError>,
    ) {
        self.deployment_responses.push_back(response);
    }

    pub fn push_deployments_page(
        &mut self,
        response: Result<AwsApiGatewayDeploymentsPage, TransportError>,
    ) {
        self.deployments_pages.push_back(response);
    }

    pub fn push_page(&mut self, response: Result<AwsApiGatewayDeploymentsPage, TransportError>) {
        self.push_deployments_page(response);
    }
}

impl AwsApiGatewayTransport for RecordingAwsApiGatewayTransport {
    fn provenance(&self) -> ProviderProvenance {
        TransportProvenance::Recording
    }

    fn get_stage(
        &mut self,
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError> {
        self.requests.push(RecordedRequest::GetStage {
            request_digest: request.request_digest(),
        });
        self.stage_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError> {
        self.requests.push(RecordedRequest::GetDeployment {
            request_digest: request.request_digest(),
        });
        self.deployment_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    fn get_deployments(
        &mut self,
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError> {
        self.requests.push(RecordedRequest::GetDeployments {
            request_digest: request.request_digest(),
        });
        self.deployments_pages
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackAwsApiGatewayTransport {
    fixture: FixtureAwsApiGatewayTransport,
}

impl LoopbackAwsApiGatewayTransport {
    pub fn requests(&self) -> &[RecordedRequest] {
        self.fixture.requests()
    }
}

impl AwsApiGatewayTransport for LoopbackAwsApiGatewayTransport {
    fn provenance(&self) -> ProviderProvenance {
        TransportProvenance::Loopback
    }

    fn get_stage(
        &mut self,
        request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError> {
        self.fixture.get_stage(request)
    }

    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError> {
        self.fixture.get_deployment(request)
    }

    fn get_deployments(
        &mut self,
        request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError> {
        self.fixture.get_deployments(request)
    }
}

pub type LoopbackTransport = LoopbackAwsApiGatewayTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsApiGatewayTransport;

impl AwsApiGatewayTransport for BlockedEnvAwsApiGatewayTransport {
    fn provenance(&self) -> ProviderProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_stage(
        &mut self,
        _request: &GetStageRequest,
    ) -> Result<AwsApiGatewayStageResponse, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }

    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> Result<AwsApiGatewayDeploymentResponse, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }

    fn get_deployments(
        &mut self,
        _request: &GetDeploymentsRequest,
    ) -> Result<AwsApiGatewayDeploymentsPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type BlockedEnvTransport = BlockedEnvAwsApiGatewayTransport;

// These imports are part of the provider's intentionally typed public seam;
// keeping the aliases here also makes downstream test fixtures concise.
pub type AwsApiGatewayStagePage = AwsApiGatewayStageResponse;
pub type AwsApiGatewayDeploymentPage = AwsApiGatewayDeploymentResponse;
pub type AwsApiGatewayListDeploymentsPage = AwsApiGatewayDeploymentsPage;
pub type AwsApiGatewayStageRequest = GetStageRequest;
pub type AwsApiGatewayDeploymentRequest = GetDeploymentRequest;
pub type AwsApiGatewayDeploymentsRequest = GetDeploymentsRequest;
