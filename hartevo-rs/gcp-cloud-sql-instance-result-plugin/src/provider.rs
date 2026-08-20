//! Bounded, redacted GCP Cloud SQL Admin provider seams.
//!
//! This module intentionally has no HTTP client, credential resolver, signer,
//! or mutation method. Transports are recording/fixture/fake/loopback seams;
//! `BlockedEnv` is an explicit Layer-2 boundary.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AvailabilityType, BackupPolicySummary, CloudSqlInstanceSnapshot, CloudSqlOperationSnapshot,
    DatabaseEdition, DatabaseVersion, Digest, GcpCloudSqlInstanceScope, InstanceSnapshotInput,
    InstanceState, MAX_OPERATION_ERROR_CATEGORIES, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    MaintenancePolicySummary, ModelError, OpaquePageToken, OperationSnapshotInput, OperationStatus,
    OperationType, ProviderErrorKind, ProviderProvenance, SettingsVersion, StorageSummary,
};
use crate::{API_REVISION, PLUGIN_VERSION, PROVIDER_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("provider rejected the request")]
    InvalidRequest,
    #[error("provider authentication was not accepted")]
    Unauthorized,
    #[error("provider permission was denied")]
    Forbidden,
    #[error("provider resource was not found")]
    NotFound,
    #[error("provider reported a conflicting revision")]
    Conflict,
    #[error("provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider failed with status {status_code:?}")]
    ServerFailure { status_code: Option<u16> },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("native provider access is blocked in Layer 1")]
    BlockedEnv,
    #[error("provider returned an unknown transport failure")]
    Unknown,
}

impl TransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::MalformedResponse => ProviderErrorKind::MalformedResponse,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnvironment,
            Self::Unknown => ProviderErrorKind::Unknown,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout | Self::MalformedResponse | Self::BlockedEnv | Self::Unknown => None,
        }
    }

    pub fn provider_error_evidence(&self) -> crate::ProviderErrorEvidence {
        crate::ProviderErrorEvidence::new(self.kind(), self.status_code(), self.category())
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerFailure { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::MalformedResponse => "malformed_response",
            Self::BlockedEnv => "blocked_environment",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("Layer 1 cannot register a native provider")]
    NativeProviderForbidden,
    #[error("provider API revision does not match the contract")]
    ApiRevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlAdminProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GcpCloudSqlAdminProviderDefinition {
    pub fn for_provenance(provenance: ProviderProvenance) -> Result<Self, ProviderDefinitionError> {
        let provider_digest = Digest::from_parts(
            "gcp-cloud-sql-admin-provider/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("version", PLUGIN_VERSION.to_owned()),
                ("api", API_REVISION.to_owned()),
                ("provenance", provenance.as_str().to_owned()),
            ],
        );
        let api_digest = Digest::from_parts(
            "gcp-cloud-sql-admin-api-allowlist/v1",
            &[
                ("instances.get", "GET".to_owned()),
                ("instances.list", "GET".to_owned()),
                ("operations.get", "GET".to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PLUGIN_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PLUGIN_VERSION
            || self.api_revision != API_REVISION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(ProviderDefinitionError::ApiRevisionMismatch);
        }
        let expected = Self::for_provenance(self.provenance)?;
        if self.provider_digest != expected.provider_digest
            || self.api_digest != expected.api_digest
        {
            return Err(ProviderDefinitionError::ApiRevisionMismatch);
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
}

pub type GcpCloudSqlAdminProviderIdentity = GcpCloudSqlAdminProviderDefinition;
pub type GcpCloudSqlProviderDefinition = GcpCloudSqlAdminProviderDefinition;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudSqlAdminOperation {
    InstancesGet,
    InstancesList,
    OperationsGet,
}

impl GcpCloudSqlAdminOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstancesGet => "instances.get",
            Self::InstancesList => "instances.list",
            Self::OperationsGet => "operations.get",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: GcpCloudSqlAdminOperation,
    pub scope_digest: Digest,
    pub instance_digest: Digest,
    pub operation_digest: Digest,
    pub page_number: Option<u16>,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
}

impl RecordedRequest {
    fn validate(&self) -> Result<(), GcpCloudSqlAdminProviderError> {
        if !self.redacted {
            return Err(GcpCloudSqlAdminProviderError::TamperedResponse);
        }
        for digest in [
            &self.scope_digest,
            &self.instance_digest,
            &self.operation_digest,
            &self.request_digest,
            &self.path_digest,
        ] {
            digest.validate()?;
        }
        if let Some(digest) = &self.page_token_digest {
            digest.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetInstanceRequest {
    scope: GcpCloudSqlInstanceScope,
    request_digest: Digest,
}

impl GetInstanceRequest {
    pub fn for_scope(scope: &GcpCloudSqlInstanceScope) -> Result<Self, ModelError> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "gcp-cloud-sql-instances-get-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "project",
                        scope.cloud_project_id().digest().as_str().to_owned(),
                    ),
                    ("instance", scope.instance_id().digest().as_str().to_owned()),
                    ("region", scope.region().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &GcpCloudSqlInstanceScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpCloudSqlAdminOperation::InstancesGet,
            scope_digest: self.scope.digest().clone(),
            instance_digest: self.scope.instance_id().digest(),
            operation_digest: self.scope.operation().digest().clone(),
            page_number: None,
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(
                format!(
                    "instances.get/{}/{}",
                    &self.scope.cloud_project_id().digest().as_str()[..16],
                    &self.scope.instance_id().digest().as_str()[..16]
                )
                .as_bytes(),
            ),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetInstanceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetInstanceRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListInstancesRequest {
    scope: GcpCloudSqlInstanceScope,
    page_size: u16,
    page_number: u16,
    page_token: Option<OpaquePageToken>,
    request_digest: Digest,
}

impl ListInstancesRequest {
    pub fn new(
        scope: &GcpCloudSqlInstanceScope,
        page_size: u16,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || page_number == 0
            || page_number > MAX_PAGES
        {
            return Err(ModelError::InvalidBounds);
        }
        let binding = list_binding_digest(scope, page_size);
        if let Some(token) = &page_token
            && (token.binding_digest() != &binding || token.page_number() != page_number)
        {
            return Err(ModelError::InvalidPageToken);
        }
        let request_digest = Digest::from_parts(
            "gcp-cloud-sql-instances-list-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "page_token",
                    page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("filter", scope.instance_id().digest().as_str().to_owned()),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            page_token,
            request_digest,
        })
    }

    pub fn first(scope: &GcpCloudSqlInstanceScope, page_size: u16) -> Result<Self, ModelError> {
        Self::new(scope, page_size, 1, None)
    }

    pub fn next(
        scope: &GcpCloudSqlInstanceScope,
        page_size: u16,
        page_number: u16,
        page_token: OpaquePageToken,
    ) -> Result<Self, ModelError> {
        Self::new(scope, page_size, page_number, Some(page_token))
    }

    pub fn scope(&self) -> &GcpCloudSqlInstanceScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn binding_digest(&self) -> Digest {
        list_binding_digest(&self.scope, self.page_size)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpCloudSqlAdminOperation::InstancesList,
            scope_digest: self.scope.digest().clone(),
            instance_digest: self.scope.instance_id().digest(),
            operation_digest: self.scope.operation().digest().clone(),
            page_number: Some(self.page_number),
            page_token_digest: self.page_token.as_ref().map(|token| token.digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(
                format!(
                    "instances.list/{}/{}",
                    &self.scope.cloud_project_id().digest().as_str()[..16],
                    self.page_number
                )
                .as_bytes(),
            ),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListInstancesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListInstancesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("page_token", &self.page_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetOperationRequest {
    scope: GcpCloudSqlInstanceScope,
    request_digest: Digest,
}

impl GetOperationRequest {
    pub fn for_scope(scope: &GcpCloudSqlInstanceScope) -> Result<Self, ModelError> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "gcp-cloud-sql-operations-get-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("operation", scope.operation().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &GcpCloudSqlInstanceScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpCloudSqlAdminOperation::OperationsGet,
            scope_digest: self.scope.digest().clone(),
            instance_digest: self.scope.instance_id().digest(),
            operation_digest: self.scope.operation().digest().clone(),
            page_number: None,
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(
                format!(
                    "operations.get/{}",
                    &self.scope.operation().digest().as_str()[..16]
                )
                .as_bytes(),
            ),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetOperationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetOperationRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpCloudSqlAdminProviderError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("provider response was tampered with or no longer matches its request")]
    TamperedResponse,
    #[error("provider response belongs to a different revision")]
    ProviderDrift,
    #[error(transparent)]
    Definition(#[from] ProviderDefinitionError),
}

pub trait GcpCloudSqlAdminTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError>;

    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> Result<ListInstancesResponse, TransportError>;

    fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> Result<GetOperationResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInstanceResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub instance: CloudSqlInstanceSnapshot,
    pub response_bytes: u64,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_record: RecordedRequest,
}

impl GetInstanceResponse {
    pub fn new(
        request: &GetInstanceRequest,
        instance: CloudSqlInstanceSnapshot,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self, GcpCloudSqlAdminProviderError> {
        validate_response_bytes(response_bytes)?;
        instance.validate_against(request.scope())?;
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest().clone(),
            request_digest: request.request_digest().clone(),
            instance,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_record,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &GetInstanceRequest,
    ) -> Result<(), GcpCloudSqlAdminProviderError> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != *request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(GcpCloudSqlAdminProviderError::TamperedResponse);
        }
        self.instance.validate_against(request.scope())?;
        self.request_record.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-instances-get-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "instance",
                    self.instance.snapshot_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_record",
                    self.request_record.request_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListInstancesResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub instances: Vec<CloudSqlInstanceSnapshot>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_record: RecordedRequest,
}

impl ListInstancesResponse {
    pub fn new(
        request: &ListInstancesRequest,
        mut instances: Vec<CloudSqlInstanceSnapshot>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self, GcpCloudSqlAdminProviderError> {
        validate_response_bytes(response_bytes)?;
        if instances.len() > request.page_size() as usize {
            return Err(GcpCloudSqlAdminProviderError::Model(
                ModelError::InvalidBounds,
            ));
        }
        for instance in &instances {
            instance.validate_against(request.scope())?;
        }
        instances.sort_by(|left, right| left.instance_digest.cmp(&right.instance_digest));
        if instances
            .windows(2)
            .any(|window| window[0].instance_digest == window[1].instance_digest)
        {
            return Err(GcpCloudSqlAdminProviderError::Model(
                ModelError::DuplicateEvidence,
            ));
        }
        if let Some(token) = &next_page_token
            && (token.binding_digest() != &request.binding_digest()
                || token.page_number() != request.page_number().saturating_add(1))
        {
            return Err(GcpCloudSqlAdminProviderError::Model(
                ModelError::InvalidPageToken,
            ));
        }
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest().clone(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            instances,
            next_page_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_record,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &ListInstancesRequest,
    ) -> Result<(), GcpCloudSqlAdminProviderError> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != *request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.instances.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(GcpCloudSqlAdminProviderError::TamperedResponse);
        }
        for instance in &self.instances {
            instance.validate_against(request.scope())?;
        }
        if let Some(token) = &self.next_page_token
            && (token.binding_digest() != &request.binding_digest()
                || token.page_number() != request.page_number().saturating_add(1))
        {
            return Err(GcpCloudSqlAdminProviderError::Model(
                ModelError::InvalidPageToken,
            ));
        }
        self.request_record.validate()
    }

    pub fn has_more(&self) -> bool {
        self.next_page_token.is_some()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-instances-list-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "instances",
                    self.instances
                        .iter()
                        .map(|instance| instance.snapshot_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetOperationResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub operation: CloudSqlOperationSnapshot,
    pub response_bytes: u64,
    pub provenance: ProviderProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_record: RecordedRequest,
}

impl GetOperationResponse {
    pub fn new(
        request: &GetOperationRequest,
        operation: CloudSqlOperationSnapshot,
        response_bytes: u64,
        provenance: ProviderProvenance,
    ) -> Result<Self, GcpCloudSqlAdminProviderError> {
        validate_response_bytes(response_bytes)?;
        operation.validate_against(request.scope())?;
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest().clone(),
            request_digest: request.request_digest().clone(),
            operation,
            response_bytes,
            provenance,
            evidence_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_record,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &GetOperationRequest,
    ) -> Result<(), GcpCloudSqlAdminProviderError> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != *request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(GcpCloudSqlAdminProviderError::TamperedResponse);
        }
        self.operation.validate_against(request.scope())?;
        self.request_record.validate()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-operations-get-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "operation",
                    self.operation.snapshot_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

pub struct GcpCloudSqlAdminProvider<T> {
    transport: T,
    definition: GcpCloudSqlAdminProviderDefinition,
}

impl<T: GcpCloudSqlAdminTransport> fmt::Debug for GcpCloudSqlAdminProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSqlAdminProvider")
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}

impl<T: GcpCloudSqlAdminTransport> GcpCloudSqlAdminProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let definition =
            GcpCloudSqlAdminProviderDefinition::for_provenance(transport.provenance())?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &GcpCloudSqlAdminProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &GcpCloudSqlAdminProviderDefinition {
        self.definition()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, GcpCloudSqlAdminProviderError> {
        let response = self.transport.get_instance(request)?;
        self.validate_provenance(response.provenance)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> Result<ListInstancesResponse, GcpCloudSqlAdminProviderError> {
        let response = self.transport.list_instances(request)?;
        self.validate_provenance(response.provenance)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> Result<GetOperationResponse, GcpCloudSqlAdminProviderError> {
        let response = self.transport.get_operation(request)?;
        self.validate_provenance(response.provenance)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    fn validate_provenance(
        &self,
        provenance: ProviderProvenance,
    ) -> Result<(), GcpCloudSqlAdminProviderError> {
        if provenance != self.definition.provenance
            || provenance.connected()
            || provenance.native()
            || provenance.first_party()
        {
            Err(GcpCloudSqlAdminProviderError::ProviderDrift)
        } else {
            Ok(())
        }
    }

    /// Parse only the documented, bounded instance fields from an API-shaped
    /// JSON body. Raw IPs, connection names, networks, users, certificates,
    /// labels, descriptions, flags, values, and arbitrary properties are
    /// deliberately ignored.
    pub fn parse_instance_json(
        request: &GetInstanceRequest,
        status_code: u16,
        body: &[u8],
        observed_at: DateTime<Utc>,
        provenance: ProviderProvenance,
    ) -> Result<GetInstanceResponse, GcpCloudSqlAdminProviderError> {
        ensure_status(status_code)?;
        ensure_body(body)?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| TransportError::MalformedResponse)?;
        let input = parse_instance_value(&value, request.scope())?
            .ok_or(GcpCloudSqlAdminProviderError::TamperedResponse)?;
        let snapshot = CloudSqlInstanceSnapshot::new(
            request.scope(),
            InstanceSnapshotInput {
                observed_at,
                ..input
            },
        )?;
        GetInstanceResponse::new(request, snapshot, body.len() as u64, provenance)
    }

    pub fn parse_list_json(
        request: &ListInstancesRequest,
        status_code: u16,
        body: &[u8],
        observed_at: DateTime<Utc>,
        provenance: ProviderProvenance,
    ) -> Result<ListInstancesResponse, GcpCloudSqlAdminProviderError> {
        ensure_status(status_code)?;
        ensure_body(body)?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| TransportError::MalformedResponse)?;
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .ok_or(TransportError::MalformedResponse)?;
        if items.len() > request.page_size() as usize {
            return Err(ModelError::InvalidBounds.into());
        }
        let mut instances = Vec::new();
        for item in items {
            if let Some(input) = parse_instance_value(item, request.scope())? {
                instances.push(CloudSqlInstanceSnapshot::new(
                    request.scope(),
                    InstanceSnapshotInput {
                        observed_at,
                        ..input
                    },
                )?);
            }
        }
        let next_page_token = value
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(|token| {
                OpaquePageToken::new(
                    token,
                    request.binding_digest(),
                    request.page_number().saturating_add(1),
                )
            })
            .transpose()?;
        ListInstancesResponse::new(
            request,
            instances,
            next_page_token,
            body.len() as u64,
            provenance,
        )
    }

    pub fn parse_operation_json(
        request: &GetOperationRequest,
        status_code: u16,
        body: &[u8],
        observed_at: DateTime<Utc>,
        provenance: ProviderProvenance,
    ) -> Result<GetOperationResponse, GcpCloudSqlAdminProviderError> {
        ensure_status(status_code)?;
        ensure_body(body)?;
        let value =
            serde_json::from_slice::<Value>(body).map_err(|_| TransportError::MalformedResponse)?;
        let operation_name = value
            .get("name")
            .and_then(Value::as_str)
            .ok_or(TransportError::MalformedResponse)?;
        if operation_name.rsplit('/').next() != Some(request.scope().operation().id().as_str()) {
            return Err(GcpCloudSqlAdminProviderError::TamperedResponse);
        }
        let operation_type =
            parse_operation_type(value.get("operationType").and_then(Value::as_str));
        let status = parse_operation_status(value.get("status").and_then(Value::as_str));
        let start_time_digest = digest_timestamp(value.get("startTime").and_then(Value::as_str));
        let end_time_digest = digest_timestamp(value.get("endTime").and_then(Value::as_str));
        let error_category_digest = parse_error_category_digest(value.get("error"));
        let operation = CloudSqlOperationSnapshot::new(
            request.scope(),
            OperationSnapshotInput {
                operation_type,
                status,
                start_time_digest,
                end_time_digest,
                error_category_digest,
                observed_at,
            },
        )?;
        GetOperationResponse::new(request, operation, body.len() as u64, provenance)
    }
}

fn list_binding_digest(scope: &GcpCloudSqlInstanceScope, page_size: u16) -> Digest {
    Digest::from_parts(
        "gcp-cloud-sql-page-token-binding/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            (
                "organization",
                scope.organization_id().digest().as_str().to_owned(),
            ),
            (
                "project",
                scope.cloud_project_id().digest().as_str().to_owned(),
            ),
            (
                "instance_allowlist",
                scope.instance_id().digest().as_str().to_owned(),
            ),
            ("region", scope.region().digest().as_str().to_owned()),
            ("page_size", page_size.to_string()),
        ],
    )
}

fn validate_response_bytes(response_bytes: u64) -> Result<(), GcpCloudSqlAdminProviderError> {
    if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
        Err(GcpCloudSqlAdminProviderError::Model(
            ModelError::InvalidResponseBytes,
        ))
    } else {
        Ok(())
    }
}

fn ensure_body(body: &[u8]) -> Result<(), GcpCloudSqlAdminProviderError> {
    validate_response_bytes(body.len() as u64)
}

fn ensure_status(status_code: u16) -> Result<(), GcpCloudSqlAdminProviderError> {
    if status_code == 200 {
        Ok(())
    } else {
        Err(GcpCloudSqlAdminProviderError::Transport(
            transport_error_for_status(status_code),
        ))
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    match status_code {
        400 => TransportError::InvalidRequest,
        401 => TransportError::Unauthorized,
        403 => TransportError::Forbidden,
        404 => TransportError::NotFound,
        409 => TransportError::Conflict,
        429 => TransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => TransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => TransportError::Unknown,
    }
}

fn parse_instance_value(
    value: &Value,
    scope: &GcpCloudSqlInstanceScope,
) -> Result<Option<InstanceSnapshotInput>, GcpCloudSqlAdminProviderError> {
    let project = value.get("project").and_then(Value::as_str);
    let instance = value
        .get("name")
        .and_then(Value::as_str)
        .map(last_path_segment);
    let region = value.get("region").and_then(Value::as_str);
    if project.is_some_and(|project| project != scope.cloud_project_id().as_str())
        || instance.is_some_and(|instance| instance != scope.instance_id().as_str())
        || region.is_some_and(|region| region != scope.region().as_str())
    {
        return Ok(None);
    }
    let settings = value.get("settings").unwrap_or(&Value::Null);
    let state = parse_instance_state(value.get("state").and_then(Value::as_str));
    let database_version = value
        .get("databaseVersion")
        .and_then(Value::as_str)
        .map(DatabaseVersion::new)
        .transpose()?
        .unwrap_or_else(|| scope.database_version().clone());
    let settings_version = settings
        .get("settingsVersion")
        .and_then(Value::as_u64)
        .map(SettingsVersion::new)
        .transpose()?
        .unwrap_or(scope.settings_version());
    let edition = settings
        .get("edition")
        .and_then(Value::as_str)
        .map(DatabaseEdition::new)
        .transpose()?;
    let zone_digest = settings
        .get("locationPreference")
        .and_then(|value| value.get("zone"))
        .and_then(Value::as_str)
        .map(Digest::from_text);
    let availability_type =
        parse_availability_type(settings.get("availabilityType").and_then(Value::as_str));
    let replica_count = value
        .get("replicaNames")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or_default();
    if replica_count > u16::MAX as usize {
        return Err(ModelError::InvalidBounds.into());
    }
    let backup_configuration = settings.get("backupConfiguration").unwrap_or(&Value::Null);
    let retained_backup_count = backup_configuration
        .get("backupRetentionSettings")
        .and_then(|value| value.get("retainedBackups"))
        .and_then(Value::as_u64)
        .map(u16::try_from)
        .transpose()
        .map_err(|_| ModelError::InvalidBounds)?;
    let backup = BackupPolicySummary {
        enabled: backup_configuration
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        point_in_time_recovery: backup_configuration
            .get("pointInTimeRecoveryEnabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        retained_backup_count,
    };
    let maintenance_window = settings.get("maintenanceWindow");
    let maintenance = MaintenancePolicySummary {
        window_present: maintenance_window.is_some_and(Value::is_object),
        version_digest: maintenance_window
            .and_then(|value| value.get("version"))
            .and_then(Value::as_str)
            .map(Digest::from_text),
    };
    let disk_size_bytes = settings
        .get("dataDiskSizeGb")
        .and_then(Value::as_u64)
        .map(|gb| gb.saturating_mul(1024 * 1024 * 1024));
    let storage = StorageSummary {
        disk_size_bytes,
        storage_auto_resize: settings
            .get("storageAutoResize")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        storage_auto_resize_limit_bytes: settings
            .get("storageAutoResizeLimit")
            .and_then(Value::as_u64)
            .map(|gb| gb.saturating_mul(1024 * 1024 * 1024)),
    };
    Ok(Some(InstanceSnapshotInput {
        state,
        database_version,
        edition,
        zone_digest,
        availability_type,
        replica_count: u16::try_from(replica_count).map_err(|_| ModelError::InvalidBounds)?,
        read_replica_count: value
            .get("readReplicaNames")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default()
            .try_into()
            .map_err(|_| ModelError::InvalidBounds)?,
        high_availability: matches!(availability_type, AvailabilityType::Regional),
        settings_version,
        backup,
        maintenance,
        storage,
        observed_at: Utc::now(),
    }))
}

fn parse_instance_state(value: Option<&str>) -> InstanceState {
    match value.unwrap_or_default() {
        "RUNNABLE" => InstanceState::Runnable,
        "MAINTENANCE" => InstanceState::Maintenance,
        "SUSPENDED" => InstanceState::Suspended,
        "FAILED" => InstanceState::Failed,
        "PENDING_CREATE" => InstanceState::PendingCreate,
        "PENDING_DELETE" => InstanceState::PendingDelete,
        _ => InstanceState::Unknown,
    }
}

fn parse_availability_type(value: Option<&str>) -> AvailabilityType {
    match value.unwrap_or_default() {
        "REGIONAL" => AvailabilityType::Regional,
        "ZONAL" => AvailabilityType::Zonal,
        _ => AvailabilityType::Unknown,
    }
}

fn parse_operation_type(value: Option<&str>) -> OperationType {
    match value.unwrap_or_default() {
        "CREATE" => OperationType::Create,
        "UPDATE" => OperationType::Update,
        "DELETE" => OperationType::Delete,
        "RESTART" => OperationType::Restart,
        "FAILOVER" => OperationType::Failover,
        "BACKUP" => OperationType::Backup,
        "RESTORE" => OperationType::Restore,
        _ => OperationType::Unknown,
    }
}

fn parse_operation_status(value: Option<&str>) -> OperationStatus {
    match value.unwrap_or_default() {
        "PENDING" => OperationStatus::Pending,
        "RUNNING" => OperationStatus::Running,
        "DONE" => OperationStatus::Done,
        "FAILED" => OperationStatus::Failed,
        _ => OperationStatus::Unknown,
    }
}

fn digest_timestamp(value: Option<&str>) -> Option<Digest> {
    value
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(Digest::from_text)
}

fn parse_error_category_digest(value: Option<&Value>) -> Option<Digest> {
    let errors = value?.get("errors")?.as_array()?;
    let mut categories = errors
        .iter()
        .filter_map(|error| {
            error
                .get("code")
                .or_else(|| error.get("kind"))
                .and_then(Value::as_str)
        })
        .take(MAX_OPERATION_ERROR_CATEGORIES)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    categories.sort();
    categories.dedup();
    if categories.is_empty() {
        Some(Digest::from_text("operation-error-present"))
    } else {
        Some(Digest::from_text(categories.join(",").as_bytes()))
    }
}

fn last_path_segment(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    instance_responses: VecDeque<Result<GetInstanceResponse, TransportError>>,
    list_responses: VecDeque<Result<ListInstancesResponse, TransportError>>,
    operation_responses: VecDeque<Result<GetOperationResponse, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl QueuedTransport {
    fn push_instance(&mut self, response: Result<GetInstanceResponse, TransportError>) {
        self.instance_responses.push_back(response);
    }

    fn push_list(&mut self, response: Result<ListInstancesResponse, TransportError>) {
        self.list_responses.push_back(response);
    }

    fn push_operation(&mut self, response: Result<GetOperationResponse, TransportError>) {
        self.operation_responses.push_back(response);
    }

    fn instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.instance_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    fn list(
        &mut self,
        request: &ListInstancesRequest,
    ) -> Result<ListInstancesResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }

    fn operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> Result<GetOperationResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.operation_responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            queue: QueuedTransport,
        }

        impl $name {
            pub fn new() -> Self {
                Self::default()
            }

            pub fn push_get_instance_response(
                &mut self,
                response: Result<GetInstanceResponse, TransportError>,
            ) {
                self.queue.push_instance(response);
            }

            pub fn push_list_instances_response(
                &mut self,
                response: Result<ListInstancesResponse, TransportError>,
            ) {
                self.queue.push_list(response);
            }

            pub fn push_get_operation_response(
                &mut self,
                response: Result<GetOperationResponse, TransportError>,
            ) {
                self.queue.push_operation(response);
            }

            pub fn requests(&self) -> &[RecordedRequest] {
                &self.queue.requests
            }
        }

        impl GcpCloudSqlAdminTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn get_instance(
                &mut self,
                request: &GetInstanceRequest,
            ) -> Result<GetInstanceResponse, TransportError> {
                self.queue.instance(request)
            }

            fn list_instances(
                &mut self,
                request: &ListInstancesRequest,
            ) -> Result<ListInstancesResponse, TransportError> {
                self.queue.list(request)
            }

            fn get_operation(
                &mut self,
                request: &GetOperationRequest,
            ) -> Result<GetOperationResponse, TransportError> {
                self.queue.operation(request)
            }
        }
    };
}

queued_transport!(RecordingGcpCloudSqlTransport, ProviderProvenance::Recording);
queued_transport!(FixtureGcpCloudSqlTransport, ProviderProvenance::Fixture);
queued_transport!(FakeGcpCloudSqlTransport, ProviderProvenance::Fake);
queued_transport!(LoopbackGcpCloudSqlTransport, ProviderProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpCloudSqlTransport;

impl GcpCloudSqlAdminTransport for BlockedEnvGcpCloudSqlTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_instances(
        &mut self,
        _request: &ListInstancesRequest,
    ) -> Result<ListInstancesResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_operation(
        &mut self,
        _request: &GetOperationRequest,
    ) -> Result<GetOperationResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpCloudSqlTransport;
pub type RecordingTransport = RecordingGcpCloudSqlTransport;
pub type FixtureTransport = FixtureGcpCloudSqlTransport;
pub type FakeTransport = FakeGcpCloudSqlTransport;
pub type LoopbackTransport = LoopbackGcpCloudSqlTransport;
pub type GcpCloudSqlAdminTransportError = TransportError;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Unauthorized | TransportError::Forbidden | TransportError::NotFound
    )
}

impl Serialize for GetInstanceRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetInstanceRequest", 2)?;
        state.serialize_field("scopeDigest", self.scope.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

impl Serialize for ListInstancesRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ListInstancesRequest", 5)?;
        state.serialize_field("scopeDigest", self.scope.digest())?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("pageToken", &self.page_token)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

impl Serialize for GetOperationRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetOperationRequest", 2)?;
        state.serialize_field("scopeDigest", self.scope.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}
