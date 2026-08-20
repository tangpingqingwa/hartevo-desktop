//! The bounded Spanner management-plane provider seam.
//!
//! There is intentionally no Google SDK, OAuth resolver, service-account
//! signer, HTTP client, SQL session, schema reader, row reader, IAM reader, or
//! mutation operation in this module.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, ser::SerializeStruct};

use crate::error::{GcpSpannerTransportError, Result};
use crate::model::{
    ConfigurationPosture, DatabaseListItem, DatabaseMetadata, DatabaseMetadataInput, Digest,
    GcpSpannerDatabaseScope, InstanceListItem, InstanceMetadata, InstanceMetadataInput,
    OpaquePageToken, OperationId, OperationMetadata, OperationMetadataInput, SpannerDatabaseState,
    SpannerInstanceState, SpannerOperationState, TransportProvenance, validate_page_size,
    validate_response_bytes,
};
use crate::{API_REVISION, LAYER1_PERMISSIONS, MAX_PAGE_SIZE, PLUGIN_VERSION, PROVIDER_ID};

pub const GET_INSTANCE_PATH: &str = "/v1/projects/{project}/instances/{instance}";
pub const GET_DATABASE_PATH: &str =
    "/v1/projects/{project}/instances/{instance}/databases/{database}";
pub const GET_OPERATION_PATH: &str =
    "/v1/projects/{project}/instances/{instance}/databases/{database}/operations/{operation}";
pub const LIST_INSTANCES_PATH: &str = "/v1/projects/{project}/instances";
pub const LIST_DATABASES_PATH: &str = "/v1/projects/{project}/instances/{instance}/databases";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum GcpSpannerOperation {
    GetInstance,
    GetDatabase,
    GetOperation,
    ListInstances,
    ListDatabases,
}

impl GcpSpannerOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetInstance => "GetInstance",
            Self::GetDatabase => "GetDatabase",
            Self::GetOperation => "GetOperation",
            Self::ListInstances => "ListInstances",
            Self::ListDatabases => "ListDatabases",
        }
    }

    #[must_use]
    pub const fn permission(self) -> &'static str {
        match self {
            Self::GetInstance => "spanner.instances.get",
            Self::GetDatabase => "spanner.databases.get",
            Self::GetOperation => "spanner.operations.get",
            Self::ListInstances => "spanner.instances.list",
            Self::ListDatabases => "spanner.databases.list",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpSpannerProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub operations: Vec<GcpSpannerOperation>,
    pub permissions: Vec<String>,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GcpSpannerProviderDefinition {
    #[must_use]
    pub fn baseline() -> Self {
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: 1,
            release: PLUGIN_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                GcpSpannerOperation::GetInstance,
                GcpSpannerOperation::GetDatabase,
                GcpSpannerOperation::GetOperation,
                GcpSpannerOperation::ListInstances,
                GcpSpannerOperation::ListDatabases,
            ],
            permissions: LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            provider_digest: Digest::from_text("unsealed-gcp-spanner-provider"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        definition.provider_digest = definition.calculate_digest();
        definition
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-provider-definition/v1",
            &[
                ("id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("api", self.api_revision.clone()),
                (
                    "operations",
                    self.operations
                        .iter()
                        .map(|operation| operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("permissions", self.permissions.join(",")),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        let baseline = Self::baseline();
        if self.provider_id != baseline.provider_id
            || self.provider_revision != baseline.provider_revision
            || self.release != baseline.release
            || self.api_revision != baseline.api_revision
            || self.operations != baseline.operations
            || self.permissions != baseline.permissions
            || self.provider_digest != self.calculate_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
        {
            return Err(crate::error::GcpSpannerError::ProviderDrift);
        }
        Ok(())
    }
}

/// The only transport trait exposed by this Layer-1 crate.
pub trait GcpSpannerTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError>;

    fn get_database(
        &mut self,
        request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError>;

    fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError>;

    fn list_instances(
        &mut self,
        _request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        Err(GcpSpannerTransportError::Unsupported {
            operation: GcpSpannerOperation::ListInstances.as_str().to_owned(),
        })
    }

    fn list_databases(
        &mut self,
        _request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        Err(GcpSpannerTransportError::Unsupported {
            operation: GcpSpannerOperation::ListDatabases.as_str().to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: GcpSpannerOperation,
    pub scope_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetInstanceRequest {
    scope: GcpSpannerDatabaseScope,
    request_digest: Digest,
}

impl GetInstanceRequest {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "gcp-spanner-get-instance-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("project", scope.project().digest().as_str().to_owned()),
                    ("instance", scope.instance().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/projects/{}/instances/{}",
            self.scope.project().digest().as_str(),
            self.scope.instance().digest().as_str()
        )
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpSpannerOperation::GetInstance,
            scope_digest: self.scope.digest(),
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
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

impl Serialize for GetInstanceRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetInstanceRequest", 3)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetDatabaseRequest {
    scope: GcpSpannerDatabaseScope,
    request_digest: Digest,
}

impl GetDatabaseRequest {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "gcp-spanner-get-database-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("project", scope.project().digest().as_str().to_owned()),
                    ("instance", scope.instance().digest().as_str().to_owned()),
                    ("database", scope.database().digest().as_str().to_owned()),
                    ("dialect", scope.dialect().as_str().to_owned()),
                ],
            ),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/projects/{}/instances/{}/databases/{}",
            self.scope.project().digest().as_str(),
            self.scope.instance().digest().as_str(),
            self.scope.database().digest().as_str()
        )
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpSpannerOperation::GetDatabase,
            scope_digest: self.scope.digest(),
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetDatabaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetDatabaseRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetDatabaseRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetDatabaseRequest", 3)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetOperationRequest {
    scope: GcpSpannerDatabaseScope,
    operation: OperationId,
    request_digest: Digest,
}

impl GetOperationRequest {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope) -> Result<Self> {
        let operation = scope
            .operation()
            .cloned()
            .ok_or(crate::error::GcpSpannerError::ForbiddenOperation)?;
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "gcp-spanner-get-operation-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("operation", operation.digest().as_str().to_owned()),
                ],
            ),
            operation,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/projects/{}/instances/{}/databases/{}/operations/{}",
            self.scope.project().digest().as_str(),
            self.scope.instance().digest().as_str(),
            self.scope.database().digest().as_str(),
            self.operation.digest().as_str()
        )
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpSpannerOperation::GetOperation,
            scope_digest: self.scope.digest(),
            page_token_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetOperationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetOperationRequest")
            .field("scope_digest", &self.scope.digest())
            .field("operation_digest", &self.operation.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for GetOperationRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GetOperationRequest", 4)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("operationDigest", &self.operation.digest())?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListInstancesRequest {
    scope: GcpSpannerDatabaseScope,
    page_size: u16,
    page_token: Option<OpaquePageToken>,
    request_digest: Digest,
    parent_digest: Digest,
}

impl ListInstancesRequest {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let parent_digest = Digest::from_parts(
            "gcp-spanner-instance-list-parent/v1",
            &[
                (
                    "organization",
                    scope.organization().digest().as_str().to_owned(),
                ),
                ("folder", scope.folder().digest().as_str().to_owned()),
                ("project", scope.project().digest().as_str().to_owned()),
            ],
        );
        if let Some(token) = &page_token {
            token.validate_against(scope, &parent_digest, token.page_number())?;
        }
        let request_digest = Digest::from_parts(
            "gcp-spanner-list-instances-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("parent", parent_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                (
                    "page_token",
                    page_token.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    page_token
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_token,
            request_digest,
            parent_digest,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        match &self.page_token {
            Some(token) => token.page_number(),
            None => 1,
        }
    }

    #[must_use]
    pub fn parent_digest(&self) -> &Digest {
        &self.parent_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/projects/{}/instances?pageSize={}&pageTokenDigest={}",
            self.scope.project().digest().as_str(),
            self.page_size,
            self.page_token
                .as_ref()
                .map_or_else(String::new, |token| token
                    .token_digest()
                    .as_str()
                    .to_owned())
        )
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpSpannerOperation::ListInstances,
            scope_digest: self.scope.digest(),
            page_token_digest: self
                .page_token
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListInstancesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListInstancesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListInstancesRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ListInstancesRequest", 5)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field(
            "pageTokenDigest",
            &self.page_token.as_ref().map(OpaquePageToken::token_digest),
        )?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListDatabasesRequest {
    scope: GcpSpannerDatabaseScope,
    page_size: u16,
    page_token: Option<OpaquePageToken>,
    request_digest: Digest,
    parent_digest: Digest,
}

impl ListDatabasesRequest {
    pub fn new(
        scope: &GcpSpannerDatabaseScope,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let parent_digest = Digest::from_parts(
            "gcp-spanner-database-list-parent/v1",
            &[
                ("project", scope.project().digest().as_str().to_owned()),
                ("instance", scope.instance().digest().as_str().to_owned()),
            ],
        );
        if let Some(token) = &page_token {
            token.validate_against(scope, &parent_digest, token.page_number())?;
        }
        let request_digest = Digest::from_parts(
            "gcp-spanner-list-databases-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("parent", parent_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                (
                    "page_token",
                    page_token.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    page_token
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_token,
            request_digest,
            parent_digest,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpSpannerDatabaseScope {
        &self.scope
    }

    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub const fn page_number(&self) -> u16 {
        match &self.page_token {
            Some(token) => token.page_number(),
            None => 1,
        }
    }

    #[must_use]
    pub fn parent_digest(&self) -> &Digest {
        &self.parent_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/projects/{}/instances/{}/databases?pageSize={}&pageTokenDigest={}",
            self.scope.project().digest().as_str(),
            self.scope.instance().digest().as_str(),
            self.page_size,
            self.page_token
                .as_ref()
                .map_or_else(String::new, |token| token
                    .token_digest()
                    .as_str()
                    .to_owned())
        )
    }

    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: GcpSpannerOperation::ListDatabases,
            scope_digest: self.scope.digest(),
            page_token_digest: self
                .page_token
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListDatabasesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListDatabasesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_token", &self.page_token)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ListDatabasesRequest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ListDatabasesRequest", 5)?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field(
            "pageTokenDigest",
            &self.page_token.as_ref().map(OpaquePageToken::token_digest),
        )?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.serialize_field("pathDigest", &Digest::from_text(self.path_and_query()))?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetInstanceResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: InstanceMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetInstanceResponse {
    pub fn new(
        request: &GetInstanceRequest,
        metadata: InstanceMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-instance-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetInstanceRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::error::GcpSpannerError::EvidenceTampered);
        }
        validate_response_bytes(self.response_bytes)?;
        self.metadata.validate_against(request.scope())?;
        self.metadata.validate_integrity()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-get-instance-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDatabaseResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: DatabaseMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetDatabaseResponse {
    pub fn new(
        request: &GetDatabaseRequest,
        metadata: DatabaseMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-database-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetDatabaseRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::error::GcpSpannerError::EvidenceTampered);
        }
        validate_response_bytes(self.response_bytes)?;
        self.metadata.validate_against(request.scope())?;
        self.metadata.validate_integrity()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-get-database-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
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
    pub metadata: OperationMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetOperationResponse {
    pub fn new(
        request: &GetOperationRequest,
        metadata: OperationMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-operation-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetOperationRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self.provenance.provider_receipt()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::error::GcpSpannerError::EvidenceTampered);
        }
        validate_response_bytes(self.response_bytes)?;
        self.metadata.validate_against(request.scope())?;
        self.metadata.validate_integrity()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-get-operation-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
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
    pub instances: Vec<InstanceListItem>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListInstancesResponse {
    pub fn new(
        request: &ListInstancesRequest,
        instances: Vec<InstanceListItem>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if instances.len() > request.page_size() as usize {
            return Err(crate::error::GcpSpannerError::PaginationExceeded);
        }
        if let Some(token) = &next_page_token {
            token.validate_against(
                request.scope(),
                request.parent_digest(),
                request.page_number().saturating_add(1),
            )?;
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            instances,
            next_page_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-instance-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListInstancesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.instances.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::error::GcpSpannerError::EvidenceTampered);
        }
        validate_response_bytes(self.response_bytes)?;
        for item in &self.instances {
            item.validate_integrity()?;
        }
        if let Some(token) = &self.next_page_token {
            token.validate_against(
                request.scope(),
                request.parent_digest(),
                request.page_number().saturating_add(1),
            )?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-list-instances-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "instances",
                    self.instances
                        .iter()
                        .map(|value| value.item_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDatabasesResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub databases: Vec<DatabaseListItem>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListDatabasesResponse {
    pub fn new(
        request: &ListDatabasesRequest,
        databases: Vec<DatabaseListItem>,
        next_page_token: Option<OpaquePageToken>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if databases.len() > request.page_size() as usize {
            return Err(crate::error::GcpSpannerError::PaginationExceeded);
        }
        if let Some(token) = &next_page_token {
            token.validate_against(
                request.scope(),
                request.parent_digest(),
                request.page_number().saturating_add(1),
            )?;
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            databases,
            next_page_token,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-gcp-spanner-database-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_evidence_digest(mut self, digest: Digest) -> Self {
        self.evidence_digest = digest;
        self
    }

    pub fn validate_integrity(&self, request: &ListDatabasesRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.databases.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(crate::error::GcpSpannerError::EvidenceTampered);
        }
        validate_response_bytes(self.response_bytes)?;
        for item in &self.databases {
            item.validate_integrity()?;
        }
        if let Some(token) = &self.next_page_token {
            token.validate_against(
                request.scope(),
                request.parent_digest(),
                request.page_number().saturating_add(1),
            )?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-spanner-list-databases-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "databases",
                    self.databases
                        .iter()
                        .map(|value| value.item_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct GcpSpannerAdminProvider<T: GcpSpannerTransport> {
    transport: T,
    definition: GcpSpannerProviderDefinition,
}

impl<T: GcpSpannerTransport> GcpSpannerAdminProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = GcpSpannerProviderDefinition::baseline();
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn with_definition(transport: T, definition: GcpSpannerProviderDefinition) -> Result<Self> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GcpSpannerProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.definition.provider_id
    }

    #[must_use]
    pub fn api_revision(&self) -> &str {
        &self.definition.api_revision
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        self.transport.get_instance(request)
    }

    pub fn get_database(
        &mut self,
        request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        self.transport.get_database(request)
    }

    pub fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        self.transport.get_operation(request)
    }

    pub fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        self.transport.list_instances(request)
    }

    pub fn list_databases(
        &mut self,
        request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        self.transport.list_databases(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    instance_responses:
        VecDeque<std::result::Result<GetInstanceResponse, GcpSpannerTransportError>>,
    database_responses:
        VecDeque<std::result::Result<GetDatabaseResponse, GcpSpannerTransportError>>,
    operation_responses:
        VecDeque<std::result::Result<GetOperationResponse, GcpSpannerTransportError>>,
    instance_list_responses:
        VecDeque<std::result::Result<ListInstancesResponse, GcpSpannerTransportError>>,
    database_list_responses:
        VecDeque<std::result::Result<ListDatabasesResponse, GcpSpannerTransportError>>,
}

impl RecordingTransport {
    pub fn push_get_instance_response(
        &mut self,
        response: std::result::Result<GetInstanceResponse, GcpSpannerTransportError>,
    ) {
        self.instance_responses.push_back(response);
    }

    pub fn push_get_database_response(
        &mut self,
        response: std::result::Result<GetDatabaseResponse, GcpSpannerTransportError>,
    ) {
        self.database_responses.push_back(response);
    }

    pub fn push_get_operation_response(
        &mut self,
        response: std::result::Result<GetOperationResponse, GcpSpannerTransportError>,
    ) {
        self.operation_responses.push_back(response);
    }

    pub fn push_list_instances_response(
        &mut self,
        response: std::result::Result<ListInstancesResponse, GcpSpannerTransportError>,
    ) {
        self.instance_list_responses.push_back(response);
    }

    pub fn push_list_databases_response(
        &mut self,
        response: std::result::Result<ListDatabasesResponse, GcpSpannerTransportError>,
    ) {
        self.database_list_responses.push_back(response);
    }
}

impl GcpSpannerTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        self.instance_responses.pop_front().unwrap_or_else(|| {
            Err(GcpSpannerTransportError::provider_unknown(
                GcpSpannerOperation::GetInstance.as_str(),
                b"recording response missing",
            ))
        })
    }

    fn get_database(
        &mut self,
        _request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        self.database_responses.pop_front().unwrap_or_else(|| {
            Err(GcpSpannerTransportError::provider_unknown(
                GcpSpannerOperation::GetDatabase.as_str(),
                b"recording response missing",
            ))
        })
    }

    fn get_operation(
        &mut self,
        _request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        self.operation_responses.pop_front().unwrap_or_else(|| {
            Err(GcpSpannerTransportError::provider_unknown(
                GcpSpannerOperation::GetOperation.as_str(),
                b"recording response missing",
            ))
        })
    }

    fn list_instances(
        &mut self,
        _request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        self.instance_list_responses.pop_front().unwrap_or_else(|| {
            Err(GcpSpannerTransportError::provider_unknown(
                GcpSpannerOperation::ListInstances.as_str(),
                b"recording response missing",
            ))
        })
    }

    fn list_databases(
        &mut self,
        _request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        self.database_list_responses.pop_front().unwrap_or_else(|| {
            Err(GcpSpannerTransportError::provider_unknown(
                GcpSpannerOperation::ListDatabases.as_str(),
                b"recording response missing",
            ))
        })
    }
}

fn fixture_recording(
    scope: &GcpSpannerDatabaseScope,
    observed_at: DateTime<Utc>,
    provenance: TransportProvenance,
) -> Result<RecordingTransport> {
    let configuration = ConfigurationPosture::from_raw(
        true,
        Some("fixture-key-name"),
        "fixture-instance-configuration",
        scope.instance_config(),
    )?;
    let instance_request = GetInstanceRequest::for_scope(scope)?;
    let instance = InstanceMetadata::new(
        scope,
        InstanceMetadataInput {
            instance: scope.instance().clone(),
            state: SpannerInstanceState::Ready,
            created_at: observed_at - Duration::days(2),
            updated_at: observed_at - Duration::hours(1),
            configuration: configuration.clone(),
        },
    )?;
    let database_request = GetDatabaseRequest::for_scope(scope)?;
    let database = DatabaseMetadata::new(
        scope,
        DatabaseMetadataInput {
            project: scope.project().clone(),
            instance: scope.instance().clone(),
            database: scope.database().clone(),
            dialect: scope.dialect(),
            state: SpannerDatabaseState::Ready,
            created_at: observed_at - Duration::days(1),
            updated_at: observed_at - Duration::minutes(10),
            configuration,
        },
    )?;
    let mut transport = RecordingTransport::default();
    transport.push_get_instance_response(Ok(GetInstanceResponse::new(
        &instance_request,
        instance,
        512,
        provenance,
    )?));
    transport.push_get_database_response(Ok(GetDatabaseResponse::new(
        &database_request,
        database,
        768,
        provenance,
    )?));
    if let Some(operation) = scope.operation() {
        let operation_request = GetOperationRequest::for_scope(scope)?;
        let operation_metadata = OperationMetadata::new(
            scope,
            OperationMetadataInput::new(
                operation.clone(),
                scope.database().clone(),
                SpannerOperationState::Done,
                observed_at - Duration::minutes(20),
                Some(observed_at - Duration::minutes(15)),
                None,
            )?,
        )?;
        transport.push_get_operation_response(Ok(GetOperationResponse::new(
            &operation_request,
            operation_metadata,
            256,
            provenance,
        )?));
    }
    let list_instances_request = ListInstancesRequest::new(scope, MAX_PAGE_SIZE, None)?;
    let instance_item =
        InstanceListItem::new(scope, scope.instance().clone(), SpannerInstanceState::Ready)?;
    transport.push_list_instances_response(Ok(ListInstancesResponse::new(
        &list_instances_request,
        vec![instance_item],
        None,
        256,
        provenance,
    )?));
    let list_databases_request = ListDatabasesRequest::new(scope, MAX_PAGE_SIZE, None)?;
    let database_item = DatabaseListItem::new(
        scope,
        scope.project().clone(),
        scope.instance().clone(),
        scope.database().clone(),
        scope.dialect(),
        SpannerDatabaseState::Ready,
    )?;
    transport.push_list_databases_response(Ok(ListDatabasesResponse::new(
        &list_databases_request,
        vec![database_item],
        None,
        256,
        provenance,
    )?));
    Ok(transport)
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    inner: RecordingTransport,
}

impl FixtureTransport {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            inner: fixture_recording(scope, observed_at, TransportProvenance::Fixture)?,
        })
    }
}

impl Default for FixtureTransport {
    fn default() -> Self {
        Self {
            inner: RecordingTransport::default(),
        }
    }
}

impl GcpSpannerTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        self.inner.get_instance(request)
    }

    fn get_database(
        &mut self,
        request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        self.inner.get_database(request)
    }

    fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        self.inner.get_operation(request)
    }

    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        self.inner.list_instances(request)
    }

    fn list_databases(
        &mut self,
        request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        self.inner.list_databases(request)
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: RecordingTransport,
}

impl FakeTransport {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            inner: fixture_recording(scope, observed_at, TransportProvenance::Fake)?,
        })
    }
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self {
            inner: RecordingTransport::default(),
        }
    }
}

impl GcpSpannerTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        self.inner.get_instance(request)
    }

    fn get_database(
        &mut self,
        request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        self.inner.get_database(request)
    }

    fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        self.inner.get_operation(request)
    }

    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        self.inner.list_instances(request)
    }

    fn list_databases(
        &mut self,
        request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        self.inner.list_databases(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: RecordingTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &GcpSpannerDatabaseScope, observed_at: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            inner: fixture_recording(scope, observed_at, TransportProvenance::Loopback)?,
        })
    }
}

impl Default for LoopbackTransport {
    fn default() -> Self {
        Self {
            inner: RecordingTransport::default(),
        }
    }
}

impl GcpSpannerTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        self.inner.get_instance(request)
    }

    fn get_database(
        &mut self,
        request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        self.inner.get_database(request)
    }

    fn get_operation(
        &mut self,
        request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        self.inner.get_operation(request)
    }

    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpSpannerTransportError> {
        self.inner.list_instances(request)
    }

    fn list_databases(
        &mut self,
        request: &ListDatabasesRequest,
    ) -> std::result::Result<ListDatabasesResponse, GcpSpannerTransportError> {
        self.inner.list_databases(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpSpannerTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpSpannerTransportError> {
        Err(GcpSpannerTransportError::provider_unknown(
            GcpSpannerOperation::GetInstance.as_str(),
            b"BLOCKED_ENV",
        ))
    }

    fn get_database(
        &mut self,
        _request: &GetDatabaseRequest,
    ) -> std::result::Result<GetDatabaseResponse, GcpSpannerTransportError> {
        Err(GcpSpannerTransportError::provider_unknown(
            GcpSpannerOperation::GetDatabase.as_str(),
            b"BLOCKED_ENV",
        ))
    }

    fn get_operation(
        &mut self,
        _request: &GetOperationRequest,
    ) -> std::result::Result<GetOperationResponse, GcpSpannerTransportError> {
        Err(GcpSpannerTransportError::provider_unknown(
            GcpSpannerOperation::GetOperation.as_str(),
            b"BLOCKED_ENV",
        ))
    }
}

pub type BlockedEnvGcpSpannerTransport = BlockedEnvTransport;
pub type GcpSpannerFixtureTransport = FixtureTransport;
pub type GcpSpannerFakeTransport = FakeTransport;
pub type GcpSpannerLoopbackTransport = LoopbackTransport;
