//! Typed Compute Optimizer provider and non-native transports.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    ops::Deref,
};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AwsComputeOptimizerScope, ComputeOptimizerRecommendation, Digest, MAX_RECOMMENDATIONS_PER_PAGE,
    MAX_RESPONSE_BYTES, OpaquePageCursor, RecommendationStatus, ResourceKind, ResourceSelector,
    TransportProvenance,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION,
};

pub const GET_EC2_INSTANCE_RECOMMENDATIONS_OPERATION: &str = "GetEC2InstanceRecommendations";
pub const GET_AUTO_SCALING_GROUP_RECOMMENDATIONS_OPERATION: &str =
    "GetAutoScalingGroupRecommendations";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsComputeOptimizerOperation {
    GetEc2InstanceRecommendations,
    GetAutoScalingGroupRecommendations,
    CompileResultProposal,
    RecordObservationReceipt,
    VerifyResultProposal,
    RevokeRegistration,
    RestoreRegistration,
}

impl AwsComputeOptimizerOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetEc2InstanceRecommendations => GET_EC2_INSTANCE_RECOMMENDATIONS_OPERATION,
            Self::GetAutoScalingGroupRecommendations => {
                GET_AUTO_SCALING_GROUP_RECOMMENDATIONS_OPERATION
            }
            Self::CompileResultProposal => "compile_result_proposal",
            Self::RecordObservationReceipt => "record_observation_receipt",
            Self::VerifyResultProposal => "verify_result_proposal",
            Self::RevokeRegistration => "revoke_registration",
            Self::RestoreRegistration => "restore_registration",
        }
    }

    #[must_use]
    pub const fn resource_kind(self) -> Option<ResourceKind> {
        match self {
            Self::GetEc2InstanceRecommendations => Some(ResourceKind::Ec2Instance),
            Self::GetAutoScalingGroupRecommendations => Some(ResourceKind::AutoScalingGroup),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsComputeOptimizerTransportError {
    #[error("AWS Compute Optimizer returned HTTP 400")]
    BadRequest,
    #[error("AWS Compute Optimizer returned HTTP 401")]
    Unauthorized,
    #[error("AWS Compute Optimizer returned HTTP 403")]
    Forbidden,
    #[error("AWS Compute Optimizer returned HTTP 404")]
    NotFound,
    #[error("AWS Compute Optimizer returned HTTP 409")]
    Conflict,
    #[error("AWS Compute Optimizer returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS Compute Optimizer returned server error HTTP {status}")]
    ServerError { status: u16 },
    #[error("AWS Compute Optimizer request timed out")]
    Timeout,
    #[error("AWS Compute Optimizer access was lost")]
    AccessLost,
    #[error("AWS Compute Optimizer transport is unavailable in this environment")]
    BlockedEnv,
    #[error("AWS Compute Optimizer response was invalid or truncated")]
    InvalidResponse,
}

impl AwsComputeOptimizerTransportError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerError { status } => Some(*status),
            Self::Timeout | Self::AccessLost | Self::BlockedEnv | Self::InvalidResponse => None,
        }
    }

    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsComputeOptimizerProviderError {
    #[error(transparent)]
    Transport(#[from] AwsComputeOptimizerTransportError),
    #[error("AWS Compute Optimizer provider definition drifted")]
    ProviderDrift,
    #[error("AWS Compute Optimizer provider response failed integrity validation")]
    InvalidResponse,
    #[error("AWS Compute Optimizer pagination cursor is not bound to the request")]
    CursorBinding,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsComputeOptimizerReadRequest {
    scope: AwsComputeOptimizerScope,
    resource_kind: ResourceKind,
    cursor: Option<OpaquePageCursor>,
    request_digest: Digest,
}

impl AwsComputeOptimizerReadRequest {
    pub fn for_scope(
        scope: &AwsComputeOptimizerScope,
        resource_kind: ResourceKind,
        cursor: Option<OpaquePageCursor>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        scope
            .validate()
            .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
        if !scope
            .resources()
            .iter()
            .any(|resource| resource.kind() == resource_kind)
        {
            return Err(AwsComputeOptimizerProviderError::InvalidResponse);
        }
        if let Some(cursor) = &cursor {
            cursor
                .validate_against(scope, resource_kind)
                .map_err(|_| AwsComputeOptimizerProviderError::CursorBinding)?;
        }
        let request_digest = Digest::from_fields(
            "aws-compute-optimizer-read-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                resource_kind.as_str().to_owned(),
                cursor.as_ref().map_or_else(String::new, |value| {
                    value.token_digest().as_str().to_owned()
                }),
                cursor
                    .as_ref()
                    .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            resource_kind,
            cursor,
            request_digest,
        })
    }

    pub fn for_ec2_instance_recommendations(
        scope: &AwsComputeOptimizerScope,
        cursor: Option<OpaquePageCursor>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        Self::for_scope(scope, ResourceKind::Ec2Instance, cursor)
    }

    pub fn for_auto_scaling_group_recommendations(
        scope: &AwsComputeOptimizerScope,
        cursor: Option<OpaquePageCursor>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        Self::for_scope(scope, ResourceKind::AutoScalingGroup, cursor)
    }

    #[must_use]
    pub fn scope(&self) -> &AwsComputeOptimizerScope {
        &self.scope
    }

    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaquePageCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn page_number(&self) -> u16 {
        self.cursor
            .as_ref()
            .map_or(1, OpaquePageCursor::page_number)
    }

    #[must_use]
    pub fn operation(&self) -> AwsComputeOptimizerOperation {
        match self.resource_kind {
            ResourceKind::Ec2Instance => {
                AwsComputeOptimizerOperation::GetEc2InstanceRecommendations
            }
            ResourceKind::AutoScalingGroup => {
                AwsComputeOptimizerOperation::GetAutoScalingGroupRecommendations
            }
        }
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: self.operation(),
            scope_digest: self.scope.scope_digest().clone(),
            resource_allowlist_digest: self.scope.resource_allowlist_digest(),
            resource_kind: self.resource_kind,
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            request_digest: self.request_digest.clone(),
        }
    }
}

impl fmt::Debug for AwsComputeOptimizerReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsComputeOptimizerReadRequest")
            .field("scope_digest", self.scope.scope_digest())
            .field("resource_kind", &self.resource_kind)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetEC2InstanceRecommendationsRequest {
    inner: AwsComputeOptimizerReadRequest,
}

impl GetEC2InstanceRecommendationsRequest {
    pub fn for_scope(
        scope: &AwsComputeOptimizerScope,
        cursor: Option<OpaquePageCursor>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        Ok(Self {
            inner: AwsComputeOptimizerReadRequest::for_ec2_instance_recommendations(scope, cursor)?,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &AwsComputeOptimizerReadRequest {
        &self.inner
    }
}

impl Deref for GetEC2InstanceRecommendationsRequest {
    type Target = AwsComputeOptimizerReadRequest;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for GetEC2InstanceRecommendationsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

pub type GetEc2InstanceRecommendationsRequest = GetEC2InstanceRecommendationsRequest;

#[derive(Clone, Eq, PartialEq)]
pub struct GetAutoScalingGroupRecommendationsRequest {
    inner: AwsComputeOptimizerReadRequest,
}

impl GetAutoScalingGroupRecommendationsRequest {
    pub fn for_scope(
        scope: &AwsComputeOptimizerScope,
        cursor: Option<OpaquePageCursor>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        Ok(Self {
            inner: AwsComputeOptimizerReadRequest::for_auto_scaling_group_recommendations(
                scope, cursor,
            )?,
        })
    }

    #[must_use]
    pub fn inner(&self) -> &AwsComputeOptimizerReadRequest {
        &self.inner
    }
}

impl Deref for GetAutoScalingGroupRecommendationsRequest {
    type Target = AwsComputeOptimizerReadRequest;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for GetAutoScalingGroupRecommendationsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsComputeOptimizerOperation,
    pub scope_digest: Digest,
    pub resource_allowlist_digest: Digest,
    pub resource_kind: ResourceKind,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerRecommendationPage {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub resource_kind: ResourceKind,
    pub recommendations: Vec<ComputeOptimizerRecommendation>,
    pub next_page: Option<OpaquePageCursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub page_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
}

impl AwsComputeOptimizerRecommendationPage {
    pub fn new(
        request: &AwsComputeOptimizerReadRequest,
        recommendations: Vec<ComputeOptimizerRecommendation>,
        next_page: Option<OpaquePageCursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(AwsComputeOptimizerProviderError::InvalidResponse);
        }
        if recommendations.len() > MAX_RECOMMENDATIONS_PER_PAGE {
            return Err(AwsComputeOptimizerProviderError::InvalidResponse);
        }
        if let Some(cursor) = &next_page {
            cursor
                .validate_against(request.scope(), request.resource_kind())
                .map_err(|_| AwsComputeOptimizerProviderError::CursorBinding)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for recommendation in &recommendations {
            recommendation
                .validate_integrity(request.scope())
                .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
            if recommendation.resource.kind() != request.resource_kind()
                || !seen.insert(recommendation.digest().clone())
            {
                return Err(AwsComputeOptimizerProviderError::InvalidResponse);
            }
        }
        let mut page = Self {
            scope_digest: request.scope().scope_digest().clone(),
            request_digest: request.request_digest().clone(),
            resource_kind: request.resource_kind(),
            recommendations,
            next_page,
            response_bytes,
            provenance,
            page_digest: Digest::from_text("unsealed-compute-optimizer-page"),
            connected: false,
            native: false,
            provider_receipt: false,
        };
        page.page_digest = page.calculate_digest();
        Ok(page)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, page_digest: Digest) -> Self {
        self.page_digest = page_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &AwsComputeOptimizerReadRequest,
        provenance: TransportProvenance,
    ) -> Result<(), AwsComputeOptimizerProviderError> {
        if self.scope_digest != *request.scope().scope_digest()
            || self.request_digest != *request.request_digest()
            || self.resource_kind != request.resource_kind()
            || self.provenance != provenance
            || self.provenance.is_native()
            || self.connected
            || self.native
            || self.provider_receipt
            || self.recommendations.len() > MAX_RECOMMENDATIONS_PER_PAGE
            || self.page_digest != self.calculate_digest()
        {
            return Err(AwsComputeOptimizerProviderError::InvalidResponse);
        }
        if let Some(cursor) = &self.next_page {
            cursor
                .validate_against(request.scope(), request.resource_kind())
                .map_err(|_| AwsComputeOptimizerProviderError::CursorBinding)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for recommendation in &self.recommendations {
            recommendation
                .validate_integrity(request.scope())
                .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
            if recommendation.resource.kind() != request.resource_kind()
                || !seen.insert(recommendation.digest().clone())
            {
                return Err(AwsComputeOptimizerProviderError::InvalidResponse);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_page.is_some()
    }

    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        &self.page_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-page/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.request_digest.as_str().to_owned(),
                self.resource_kind.as_str().to_owned(),
                self.recommendations
                    .iter()
                    .map(|recommendation| recommendation.digest().as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.next_page.as_ref().map_or_else(String::new, |cursor| {
                    cursor.token_digest().as_str().to_owned()
                }),
                self.response_bytes.to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

pub type GetEC2InstanceRecommendationsResponse = AwsComputeOptimizerRecommendationPage;
pub type GetEc2InstanceRecommendationsResponse = AwsComputeOptimizerRecommendationPage;
pub type GetAutoScalingGroupRecommendationsResponse = AwsComputeOptimizerRecommendationPage;
pub type ComputeOptimizerRecommendationResponse = AwsComputeOptimizerRecommendationPage;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub contract_version: String,
    pub plugin_version: String,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub live_credential_resolution: bool,
}

impl AwsComputeOptimizerProviderDefinition {
    pub fn new(
        provider_revision: u64,
        provider_release: impl Into<String>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        let provider_release = provider_release.into();
        if provider_revision == 0 || !crate::model::valid_identifier_for_provider(&provider_release)
        {
            return Err(AwsComputeOptimizerProviderError::ProviderDrift);
        }
        let api_digest = Digest::from_fields(
            "aws-compute-optimizer-api-allowlist/v1",
            &[
                GET_EC2_INSTANCE_RECOMMENDATIONS_OPERATION.to_owned(),
                GET_AUTO_SCALING_GROUP_RECOMMENDATIONS_OPERATION.to_owned(),
                "POST".to_owned(),
            ],
        );
        let provider_digest = Digest::from_fields(
            "aws-compute-optimizer-provider/v1",
            &[
                PROVIDER_ID.to_owned(),
                PROVIDER_VERSION.to_owned(),
                provider_revision.to_string(),
                provider_release.clone(),
                PROVIDER_API_REVISION.to_owned(),
                CONTRACT_VERSION.to_owned(),
                PLUGIN_VERSION.to_owned(),
                api_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            provider_release,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            api_digest,
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            live_credential_resolution: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsComputeOptimizerProviderError> {
        let expected = Self::new(self.provider_revision, self.provider_release.clone())?;
        if &expected == self {
            Ok(())
        } else {
            Err(AwsComputeOptimizerProviderError::ProviderDrift)
        }
    }
}

pub trait AwsComputeOptimizerTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_ec2_instance_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError>;

    fn get_auto_scaling_group_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError>;
}

pub struct AwsComputeOptimizerProvider<T> {
    transport: T,
    definition: AwsComputeOptimizerProviderDefinition,
}

impl<T: AwsComputeOptimizerTransport> fmt::Debug for AwsComputeOptimizerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsComputeOptimizerProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsComputeOptimizerTransport> AwsComputeOptimizerProvider<T> {
    pub fn new(transport: T) -> Result<Self, AwsComputeOptimizerProviderError> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        provider_release: impl Into<String>,
    ) -> Result<Self, AwsComputeOptimizerProviderError> {
        let definition =
            AwsComputeOptimizerProviderDefinition::new(provider_revision, provider_release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &AwsComputeOptimizerProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_ec2_instance_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerProviderError> {
        if request.resource_kind() != ResourceKind::Ec2Instance {
            return Err(AwsComputeOptimizerProviderError::CursorBinding);
        }
        let response = self.transport.get_ec2_instance_recommendations(request)?;
        response.validate_integrity(request, self.provenance())?;
        Ok(response)
    }

    pub fn get_ec2_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerProviderError> {
        self.get_ec2_instance_recommendations(request)
    }

    pub fn get_auto_scaling_group_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerProviderError> {
        if request.resource_kind() != ResourceKind::AutoScalingGroup {
            return Err(AwsComputeOptimizerProviderError::CursorBinding);
        }
        let response = self
            .transport
            .get_auto_scaling_group_recommendations(request)?;
        response.validate_integrity(request, self.provenance())?;
        Ok(response)
    }

    pub fn get_asg_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerProviderError> {
        self.get_auto_scaling_group_recommendations(request)
    }

    pub fn read(
        &mut self,
        request: &AwsComputeOptimizerReadRequest,
    ) -> Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerProviderError> {
        match request.resource_kind() {
            ResourceKind::Ec2Instance => {
                self.get_ec2_instance_recommendations(&GetEC2InstanceRecommendationsRequest {
                    inner: request.clone(),
                })
            }
            ResourceKind::AutoScalingGroup => self.get_auto_scaling_group_recommendations(
                &GetAutoScalingGroupRecommendationsRequest {
                    inner: request.clone(),
                },
            ),
        }
    }

    /// Parse only bounded, digest-oriented fields from a documented response.
    /// Unknown payload fields (including utilization series) are discarded.
    pub fn parse_json_page(
        request: &AwsComputeOptimizerReadRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provider_revision: u64,
        provenance: TransportProvenance,
    ) -> Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerProviderError> {
        if status_code != 200 {
            return Err(AwsComputeOptimizerProviderError::Transport(
                transport_error_for_status(status_code),
            ));
        }
        if body.is_empty() || body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(AwsComputeOptimizerProviderError::InvalidResponse);
        }
        let value = serde_json::from_slice::<Value>(body).map_err(|_| {
            AwsComputeOptimizerProviderError::Transport(
                AwsComputeOptimizerTransportError::InvalidResponse,
            )
        })?;
        let body_revision = value
            .get("providerRevision")
            .and_then(Value::as_u64)
            .unwrap_or(provider_revision);
        if body_revision != provider_revision {
            return Err(AwsComputeOptimizerProviderError::ProviderDrift);
        }
        let key = match request.resource_kind() {
            ResourceKind::Ec2Instance => "instanceRecommendations",
            ResourceKind::AutoScalingGroup => "autoScalingGroupRecommendations",
        };
        let items = value
            .get(key)
            .and_then(Value::as_array)
            .ok_or(AwsComputeOptimizerProviderError::InvalidResponse)?;
        let mut recommendations = Vec::with_capacity(items.len());
        for item in items {
            let resource_id = item
                .get("resourceId")
                .and_then(Value::as_str)
                .ok_or(AwsComputeOptimizerProviderError::InvalidResponse)?;
            let selector = ResourceSelector::from_raw(request.resource_kind(), resource_id)
                .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
            let recommendation_id = item
                .get("recommendationId")
                .and_then(Value::as_str)
                .unwrap_or(resource_id);
            let status = item
                .get("status")
                .and_then(Value::as_str)
                .map_or(RecommendationStatus::Unknown, parse_status);
            let observed_at = item
                .get("observedAt")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<DateTime<Utc>>().ok())
                .ok_or(AwsComputeOptimizerProviderError::InvalidResponse)?;
            let lookback_days = u16::try_from(
                item.get("lookbackDays")
                    .and_then(Value::as_u64)
                    .unwrap_or(14),
            )
            .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
            recommendations.push(
                ComputeOptimizerRecommendation::from_raw_id(
                    request.scope(),
                    selector,
                    recommendation_id,
                    status,
                    observed_at,
                    lookback_days,
                    item.get("currentConfiguration")
                        .and_then(Value::as_str)
                        .unwrap_or("redacted-current"),
                    item.get("recommendedConfiguration")
                        .and_then(Value::as_str)
                        .unwrap_or("redacted-recommended"),
                )
                .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?,
            );
        }
        let next_page = value
            .get("nextToken")
            .and_then(Value::as_str)
            .map(|token| {
                OpaquePageCursor::new(
                    token,
                    request.scope(),
                    request.resource_kind(),
                    page_number + 1,
                )
            })
            .transpose()
            .map_err(|_| AwsComputeOptimizerProviderError::InvalidResponse)?;
        AwsComputeOptimizerRecommendationPage::new(
            request,
            recommendations,
            next_page,
            body.len() as u64,
            provenance,
        )
    }
}

fn parse_status(value: &str) -> RecommendationStatus {
    match value.to_ascii_lowercase().as_str() {
        "optimized" => RecommendationStatus::Optimized,
        "overprovisioned" | "over_provisioned" => RecommendationStatus::Overprovisioned,
        "underprovisioned" | "under_provisioned" => RecommendationStatus::Underprovisioned,
        "not_optimized" | "notoptimized" => RecommendationStatus::NotOptimized,
        "not_available" | "notavailable" => RecommendationStatus::NotAvailable,
        _ => RecommendationStatus::Unknown,
    }
}

fn transport_error_for_status(status_code: u16) -> AwsComputeOptimizerTransportError {
    match status_code {
        400 => AwsComputeOptimizerTransportError::BadRequest,
        401 => AwsComputeOptimizerTransportError::Unauthorized,
        403 => AwsComputeOptimizerTransportError::Forbidden,
        404 => AwsComputeOptimizerTransportError::NotFound,
        409 => AwsComputeOptimizerTransportError::Conflict,
        429 => AwsComputeOptimizerTransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => AwsComputeOptimizerTransportError::ServerError {
            status: status_code,
        },
        _ => AwsComputeOptimizerTransportError::InvalidResponse,
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    ec2: VecDeque<Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError>>,
    auto_scaling_group: VecDeque<
        Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_ec2_response(
        &mut self,
        response: Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError>,
    ) {
        self.ec2.push_back(response);
    }

    pub fn push_auto_scaling_group_response(
        &mut self,
        response: Result<
            GetAutoScalingGroupRecommendationsResponse,
            AwsComputeOptimizerTransportError,
        >,
    ) {
        self.auto_scaling_group.push_back(response);
    }

    pub fn push_response(
        &mut self,
        kind: ResourceKind,
        response: Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError>,
    ) {
        match kind {
            ResourceKind::Ec2Instance => self.push_ec2_response(response),
            ResourceKind::AutoScalingGroup => self.push_auto_scaling_group_response(response),
        }
    }

    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn take(
        queue: &mut VecDeque<
            Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError>,
        >,
        request: &AwsComputeOptimizerReadRequest,
        requests: &mut Vec<RecordedRequest>,
    ) -> Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError> {
        requests.push(request.recorded_request());
        queue
            .pop_front()
            .unwrap_or(Err(AwsComputeOptimizerTransportError::InvalidResponse))
    }
}

impl AwsComputeOptimizerTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get_ec2_instance_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError> {
        Self::take(&mut self.ec2, request, &mut self.requests)
    }

    fn get_auto_scaling_group_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError> {
        Self::take(&mut self.auto_scaling_group, request, &mut self.requests)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsComputeOptimizerScope,
    now: DateTime<Utc>,
    pages: BTreeMap<
        ResourceKind,
        VecDeque<Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError>>,
    >,
}

impl FixtureTransport {
    #[must_use]
    pub fn for_scope(scope: &AwsComputeOptimizerScope, now: DateTime<Utc>) -> Self {
        let mut pages = BTreeMap::new();
        for kind in [ResourceKind::Ec2Instance, ResourceKind::AutoScalingGroup] {
            if scope
                .resources()
                .iter()
                .any(|resource| resource.kind() == kind)
            {
                let request = AwsComputeOptimizerReadRequest::for_scope(scope, kind, None)
                    .expect("fixture request");
                let observed_at = fixture_observed_at(scope, now);
                let recommendations = scope
                    .resources()
                    .iter()
                    .filter(|resource| resource.kind() == kind)
                    .enumerate()
                    .map(|(index, resource)| {
                        ComputeOptimizerRecommendation::from_raw_id(
                            scope,
                            resource.clone(),
                            format!("fixture-{kind:?}-{index}"),
                            if kind == ResourceKind::Ec2Instance {
                                RecommendationStatus::Overprovisioned
                            } else {
                                RecommendationStatus::Optimized
                            },
                            observed_at,
                            14,
                            format!("current-{kind:?}-{index}"),
                            format!("recommended-{kind:?}-{index}"),
                        )
                        .expect("fixture recommendation")
                    })
                    .collect::<Vec<_>>();
                let page = AwsComputeOptimizerRecommendationPage::new(
                    &request,
                    recommendations,
                    None,
                    2_048,
                    TransportProvenance::Fixture,
                )
                .expect("fixture page");
                pages.insert(kind, VecDeque::from([Ok(page)]));
            }
        }
        Self {
            scope: scope.clone(),
            now,
            pages,
        }
    }

    pub fn push_page(
        &mut self,
        kind: ResourceKind,
        page: Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError>,
    ) {
        self.pages.entry(kind).or_default().push_back(page);
    }

    #[must_use]
    pub fn scope(&self) -> &AwsComputeOptimizerScope {
        &self.scope
    }

    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }

    fn take(
        &mut self,
        request: &AwsComputeOptimizerReadRequest,
    ) -> Result<AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerTransportError> {
        self.pages
            .entry(request.resource_kind())
            .or_default()
            .pop_front()
            .unwrap_or(Err(AwsComputeOptimizerTransportError::InvalidResponse))
    }
}

impl AwsComputeOptimizerTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_ec2_instance_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError> {
        self.take(request)
    }

    fn get_auto_scaling_group_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError> {
        self.take(request)
    }
}

fn fixture_observed_at(scope: &AwsComputeOptimizerScope, now: DateTime<Utc>) -> DateTime<Utc> {
    let candidate = now - Duration::hours(1);
    if candidate < scope.recommendation_window().from {
        scope.recommendation_window().from + Duration::seconds(1)
    } else if candidate > scope.recommendation_window().to {
        scope.recommendation_window().to
    } else {
        candidate
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    #[must_use]
    pub fn from_response(response: AwsComputeOptimizerRecommendationPage) -> Self {
        let mut inner = RecordingTransport::default();
        inner.push_response(response.resource_kind, Ok(response));
        Self { inner }
    }

    #[must_use]
    pub fn from_responses(
        ec2: Vec<Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError>>,
        auto_scaling_group: Vec<
            Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError>,
        >,
    ) -> Self {
        let mut inner = RecordingTransport::default();
        for response in ec2 {
            inner.push_ec2_response(response);
        }
        for response in auto_scaling_group {
            inner.push_auto_scaling_group_response(response);
        }
        Self { inner }
    }

    #[must_use]
    pub fn inner(&self) -> &RecordingTransport {
        &self.inner
    }
}

impl AwsComputeOptimizerTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_ec2_instance_recommendations(
        &mut self,
        request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError> {
        self.inner.get_ec2_instance_recommendations(request)
    }

    fn get_auto_scaling_group_recommendations(
        &mut self,
        request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError> {
        self.inner.get_auto_scaling_group_recommendations(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsComputeOptimizerTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_ec2_instance_recommendations(
        &mut self,
        _request: &GetEC2InstanceRecommendationsRequest,
    ) -> Result<GetEC2InstanceRecommendationsResponse, AwsComputeOptimizerTransportError> {
        Err(AwsComputeOptimizerTransportError::BlockedEnv)
    }

    fn get_auto_scaling_group_recommendations(
        &mut self,
        _request: &GetAutoScalingGroupRecommendationsRequest,
    ) -> Result<GetAutoScalingGroupRecommendationsResponse, AwsComputeOptimizerTransportError> {
        Err(AwsComputeOptimizerTransportError::BlockedEnv)
    }
}

pub type AwsComputeOptimizerFixtureTransport = FixtureTransport;
pub type AwsComputeOptimizerRecordingTransport = RecordingTransport;
pub type AwsComputeOptimizerLoopbackTransport = LoopbackTransport;
pub type AwsComputeOptimizerBlockedEnvTransport = BlockedEnvTransport;
