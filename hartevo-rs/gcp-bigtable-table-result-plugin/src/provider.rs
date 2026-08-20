//! Offline-only Bigtable Admin provider boundary.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    GCP_BIGTABLE_API_REVISION, GCP_BIGTABLE_CLUSTER_GET_OPERATION, GCP_BIGTABLE_CLUSTER_PERMISSION,
    GCP_BIGTABLE_SCOPE_PERMISSION, GCP_BIGTABLE_TABLE_GET_OPERATION, GCP_BIGTABLE_TABLE_PERMISSION,
    GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID, GCP_BIGTABLE_TABLE_RESULT_PROVIDER_SCHEMA,
    GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION,
    model::{
        ClusterConfiguration, ClusterResource, ClusterState, ClusterStorageType, ColumnFamily,
        Digest, GarbageCollectionRule, GcpBigtableTableScope, MAX_CLUSTERS, MAX_FAMILIES,
        MAX_POLICY_AGE_MILLIS, MAX_RESPONSE_BYTES, ModelError, PermissionFence, ProviderErrorKind,
        Revision, SecretReference, TableClusterState, TableClusterStateEntry, TableConfiguration,
        TableGranularity, TableResource,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }
    #[must_use]
    pub const fn first_party(self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 accepts no native, connected, or first-party provider")]
    NativeProviderForbidden,
    #[error("transport provenance does not match provider definition")]
    ProvenanceMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBigtableProviderDefinition {
    pub schema_version: String,
    pub provider_schema: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub get_table_schema: bool,
    pub get_cluster_posture: bool,
    pub row_reads: bool,
    pub external_writes: bool,
    pub live_execution: bool,
    pub native: bool,
    pub first_party: bool,
    pub connected: bool,
}

impl GcpBigtableProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.native() || provenance.connected() || provenance.first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let api_digest = Self::expected_api_digest();
        let permission_digest = Self::expected_permission_digest();
        let provider_digest = Self::expected_provider_digest(
            &provider_version,
            provenance,
            &api_digest,
            &permission_digest,
        );
        Ok(Self {
            schema_version: GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION.to_owned(),
            provider_schema: GCP_BIGTABLE_TABLE_RESULT_PROVIDER_SCHEMA.to_owned(),
            provider_id: GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: GCP_BIGTABLE_API_REVISION.to_owned(),
            api_digest,
            permission_digest,
            provider_digest,
            provenance,
            get_table_schema: true,
            get_cluster_posture: true,
            row_reads: false,
            external_writes: false,
            live_execution: false,
            native: false,
            first_party: false,
            connected: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let api = Self::expected_api_digest();
        let permissions = Self::expected_permission_digest();
        let provider = Self::expected_provider_digest(
            &self.provider_version,
            self.provenance,
            &api,
            &permissions,
        );
        if self.schema_version != GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION
            || self.provider_schema != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_SCHEMA
            || self.provider_id != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            || self.api_revision != GCP_BIGTABLE_API_REVISION
            || self.api_digest != api
            || self.permission_digest != permissions
            || self.provider_digest != provider
            || !self.get_table_schema
            || !self.get_cluster_posture
            || self.row_reads
            || self.external_writes
            || self.live_execution
            || self.native
            || self.first_party
            || self.connected
        {
            Err(ProviderDefinitionError::ProvenanceMismatch)
        } else {
            Ok(())
        }
    }

    fn expected_api_digest() -> Digest {
        Digest::from_fields(
            "gcp-bigtable-admin-api-allow-list/v1",
            &[
                GCP_BIGTABLE_API_REVISION.to_owned(),
                GCP_BIGTABLE_TABLE_GET_OPERATION.to_owned(),
                GCP_BIGTABLE_CLUSTER_GET_OPERATION.to_owned(),
                "GET".to_owned(),
                "empty_request_body=true".to_owned(),
                "unpaged=true".to_owned(),
            ],
        )
    }

    fn expected_permission_digest() -> Digest {
        Digest::from_fields(
            "gcp-bigtable-admin-permission-set/v1",
            &[
                GCP_BIGTABLE_TABLE_PERMISSION.to_owned(),
                GCP_BIGTABLE_CLUSTER_PERMISSION.to_owned(),
                GCP_BIGTABLE_SCOPE_PERMISSION.to_owned(),
            ],
        )
    }

    fn expected_provider_digest(
        version: &str,
        provenance: ProviderProvenance,
        api: &Digest,
        permissions: &Digest,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-admin-provider-definition/v1",
            &[
                GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID.to_owned(),
                version.to_owned(),
                GCP_BIGTABLE_API_REVISION.to_owned(),
                api.as_str().to_owned(),
                permissions.as_str().to_owned(),
                format!("{provenance:?}"),
                "get_table_schema=true".to_owned(),
                "get_cluster_posture=true".to_owned(),
                "row_reads=false".to_owned(),
                "external_writes=false".to_owned(),
                "live_execution=false".to_owned(),
                "native=false".to_owned(),
                "first_party=false".to_owned(),
                "connected=false".to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GCP Bigtable provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    #[must_use]
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            retryable: matches!(
                kind,
                ProviderErrorKind::RateLimited
                    | ProviderErrorKind::ServerFailure
                    | ProviderErrorKind::Timeout
            ),
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }
    #[must_use]
    pub fn bad_request() -> Self {
        Self::new(ProviderErrorKind::BadRequest, Some(400), "bad-request")
    }
    #[must_use]
    pub fn unauthenticated() -> Self {
        Self::new(
            ProviderErrorKind::Unauthenticated,
            Some(401),
            "unauthenticated",
        )
    }
    #[must_use]
    pub fn permission_denied() -> Self {
        Self::new(
            ProviderErrorKind::PermissionDenied,
            Some(403),
            "permission-denied",
        )
    }
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }
    #[must_use]
    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }
    #[must_use]
    pub fn server_failure() -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(500),
            "server-failure",
        )
    }
    #[must_use]
    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }
    #[must_use]
    pub fn malformed_response() -> Self {
        Self::new(
            ProviderErrorKind::MalformedResponse,
            None,
            "malformed-response",
        )
    }
    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }
    #[must_use]
    pub fn unknown() -> Self {
        Self::new(ProviderErrorKind::Unknown, None, "unknown")
    }
    #[must_use]
    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperation {
    GetTableSchema,
    GetClusterPosture,
}

impl ProviderOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetTableSchema => "get_table_schema",
            Self::GetClusterPosture => "get_cluster_posture",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: ProviderOperation,
    pub scope_digest: Digest,
    pub resource_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
    pub redacted: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetTableRequest {
    scope: GcpBigtableTableScope,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub instance_digest: Digest,
    pub table_digest: Digest,
    pub view: TableView,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
    request_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TableView {
    SchemaView,
}

impl GetTableRequest {
    pub fn new(
        scope: &GcpBigtableTableScope,
        secret: &SecretReference,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest() || secret.is_revoked() {
            return Err(ModelError::InvalidScope);
        }
        let request_digest = Digest::from_fields(
            "gcp-bigtable-get-table-schema-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.table().digest().as_str().to_owned(),
                format!("{:?}", TableView::SchemaView),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            scope_digest: scope.scope_digest(),
            project_digest: scope.project().digest(),
            instance_digest: scope.instance().digest(),
            table_digest: scope.table().digest(),
            view: TableView::SchemaView,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        })
    }
    #[must_use]
    pub fn scope(&self) -> &GcpBigtableTableScope {
        &self.scope
    }
    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: ProviderOperation::GetTableSchema,
            scope_digest: self.scope_digest.clone(),
            resource_digest: self.table_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            request_digest: self.request_digest.clone(),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetTableRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetTableRequest")
            .field("scope_digest", &self.scope_digest)
            .field("project_digest", &self.project_digest)
            .field("instance_digest", &self.instance_digest)
            .field("table_digest", &self.table_digest)
            .field("view", &self.view)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetClusterRequest {
    scope: GcpBigtableTableScope,
    cluster: ClusterResource,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub instance_digest: Digest,
    pub table_digest: Digest,
    pub cluster_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub secret_reference_digest: Digest,
    request_digest: Digest,
}

impl GetClusterRequest {
    pub fn new(
        scope: &GcpBigtableTableScope,
        secret: &SecretReference,
        cluster: ClusterResource,
    ) -> Result<Self, ModelError> {
        if secret.scope_digest() != &scope.scope_digest()
            || secret.is_revoked()
            || cluster.project() != scope.project()
            || cluster.instance() != scope.instance()
        {
            return Err(ModelError::InvalidScope);
        }
        let request_digest = Digest::from_fields(
            "gcp-bigtable-get-cluster-posture-request/v1",
            &[
                scope.scope_digest().as_str().to_owned(),
                scope.table().digest().as_str().to_owned(),
                cluster.digest().as_str().to_owned(),
                scope.permission_digest().as_str().to_owned(),
                scope.consent_digest().as_str().to_owned(),
                secret.reference_digest().as_str().to_owned(),
                secret.credential_revision().get().to_string(),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            cluster: cluster.clone(),
            scope_digest: scope.scope_digest(),
            project_digest: scope.project().digest(),
            instance_digest: scope.instance().digest(),
            table_digest: scope.table().digest(),
            cluster_digest: cluster.digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret.credential_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            request_digest,
        })
    }
    #[must_use]
    pub fn scope(&self) -> &GcpBigtableTableScope {
        &self.scope
    }
    #[must_use]
    pub fn cluster(&self) -> &ClusterResource {
        &self.cluster
    }
    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    #[must_use]
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: ProviderOperation::GetClusterPosture,
            scope_digest: self.scope_digest.clone(),
            resource_digest: self.cluster_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            request_digest: self.request_digest.clone(),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetClusterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetClusterRequest")
            .field("scope_digest", &self.scope_digest)
            .field("project_digest", &self.project_digest)
            .field("instance_digest", &self.instance_digest)
            .field("table_digest", &self.table_digest)
            .field("cluster_digest", &self.cluster_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetTableResponse {
    pub configuration: TableConfiguration,
    pub observed_fence: PermissionFence,
    pub observed_credential_revision: Revision,
    pub response_bytes: usize,
    pub pagination_observed: bool,
    pub truncated: bool,
    response_digest: Digest,
}

impl GetTableResponse {
    #[must_use]
    pub fn new(
        configuration: TableConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        Self::with_metadata(
            configuration,
            observed_fence,
            observed_credential_revision,
            0,
            false,
            false,
        )
    }
    #[must_use]
    pub fn with_metadata(
        configuration: TableConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
        response_bytes: usize,
        pagination_observed: bool,
        truncated: bool,
    ) -> Self {
        let response_digest = Self::compute_digest(
            &configuration,
            &observed_fence,
            observed_credential_revision,
            response_bytes,
            pagination_observed,
            truncated,
        );
        Self {
            configuration,
            observed_fence,
            observed_credential_revision,
            response_bytes,
            pagination_observed,
            truncated,
            response_digest,
        }
    }
    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.configuration.validate_digest().is_err()
            || self.response_digest
                != Self::compute_digest(
                    &self.configuration,
                    &self.observed_fence,
                    self.observed_credential_revision,
                    self.response_bytes,
                    self.pagination_observed,
                    self.truncated,
                )
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
    fn compute_digest(
        configuration: &TableConfiguration,
        fence: &PermissionFence,
        revision: Revision,
        bytes: usize,
        pagination: bool,
        truncated: bool,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-table-response/v1",
            &[
                configuration.configuration_digest().as_str().to_owned(),
                fence.scope_digest.as_str().to_owned(),
                fence.permission_digest.as_str().to_owned(),
                fence.consent_digest.as_str().to_owned(),
                fence.work_product_revision.get().to_string(),
                revision.get().to_string(),
                bytes.to_string(),
                pagination.to_string(),
                truncated.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetClusterResponse {
    pub configuration: ClusterConfiguration,
    pub observed_fence: PermissionFence,
    pub observed_credential_revision: Revision,
    pub response_bytes: usize,
    pub pagination_observed: bool,
    pub truncated: bool,
    response_digest: Digest,
}

impl GetClusterResponse {
    #[must_use]
    pub fn new(
        configuration: ClusterConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
    ) -> Self {
        Self::with_metadata(
            configuration,
            observed_fence,
            observed_credential_revision,
            0,
            false,
            false,
        )
    }
    #[must_use]
    pub fn with_metadata(
        configuration: ClusterConfiguration,
        observed_fence: PermissionFence,
        observed_credential_revision: Revision,
        response_bytes: usize,
        pagination_observed: bool,
        truncated: bool,
    ) -> Self {
        let response_digest = Self::compute_digest(
            &configuration,
            &observed_fence,
            observed_credential_revision,
            response_bytes,
            pagination_observed,
            truncated,
        );
        Self {
            configuration,
            observed_fence,
            observed_credential_revision,
            response_bytes,
            pagination_observed,
            truncated,
            response_digest,
        }
    }
    #[must_use]
    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }
    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.configuration.validate_digest().is_err()
            || self.response_digest
                != Self::compute_digest(
                    &self.configuration,
                    &self.observed_fence,
                    self.observed_credential_revision,
                    self.response_bytes,
                    self.pagination_observed,
                    self.truncated,
                )
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }
    fn compute_digest(
        configuration: &ClusterConfiguration,
        fence: &PermissionFence,
        revision: Revision,
        bytes: usize,
        pagination: bool,
        truncated: bool,
    ) -> Digest {
        Digest::from_fields(
            "gcp-bigtable-cluster-response/v1",
            &[
                configuration.configuration_digest().as_str().to_owned(),
                fence.scope_digest.as_str().to_owned(),
                fence.permission_digest.as_str().to_owned(),
                fence.consent_digest.as_str().to_owned(),
                fence.work_product_revision.get().to_string(),
                revision.get().to_string(),
                bytes.to_string(),
                pagination.to_string(),
                truncated.to_string(),
            ],
        )
    }
}

pub trait GcpBigtableTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError>;
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError>;
}

pub trait GcpBigtableProviderApi: fmt::Debug {
    fn definition(&self) -> &GcpBigtableProviderDefinition;
    fn provenance(&self) -> ProviderProvenance;
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError>;
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError>;
}

pub struct GcpBigtableAdminProvider<T> {
    transport: T,
    definition: GcpBigtableProviderDefinition,
}

impl<T: GcpBigtableTransport> fmt::Debug for GcpBigtableAdminProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpBigtableAdminProvider")
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}

impl<T: GcpBigtableTransport> GcpBigtableAdminProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if transport.provenance() != provenance {
            return Err(ProviderDefinitionError::ProvenanceMismatch);
        }
        Ok(Self {
            transport,
            definition: GcpBigtableProviderDefinition::new(provider_version, provenance)?,
        })
    }
    pub fn from_transport(
        transport: T,
        provider_version: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        Self::new(transport, provider_version, provenance)
    }
    #[must_use]
    pub fn definition(&self) -> &GcpBigtableProviderDefinition {
        &self.definition
    }
    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn get_table(
        &mut self,
        request: &GetTableRequest,
    ) -> Result<GetTableResponse, TransportError> {
        self.transport.get_table(request)
    }
    pub fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.transport.get_cluster(request)
    }
}

impl<T: GcpBigtableTransport> GcpBigtableProviderApi for GcpBigtableAdminProvider<T> {
    fn definition(&self) -> &GcpBigtableProviderDefinition {
        self.definition()
    }
    fn provenance(&self) -> ProviderProvenance {
        self.provenance()
    }
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError> {
        self.get_table(request)
    }
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.get_cluster(request)
    }
}

pub type GcpBigtableProvider<T> = GcpBigtableAdminProvider<T>;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpBigtableTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
    fn get_table(
        &mut self,
        _request: &GetTableRequest,
    ) -> Result<GetTableResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
    fn get_cluster(
        &mut self,
        _request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

impl Default for GcpBigtableAdminProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(
            BlockedEnvTransport,
            crate::GCP_BIGTABLE_TABLE_RESULT_PROVIDER_VERSION_TEXT,
            ProviderProvenance::BlockedEnv,
        )
        .expect("static blocked provider")
    }
}

fn parse_status(status: u16) -> TransportError {
    let kind = match status {
        400 => ProviderErrorKind::BadRequest,
        401 => ProviderErrorKind::Unauthenticated,
        403 => ProviderErrorKind::PermissionDenied,
        404 => ProviderErrorKind::NotFound,
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::ServerFailure,
        _ => ProviderErrorKind::Unknown,
    };
    TransportError::new(kind, Some(status), format!("http-{status}"))
}

fn validate_body(body: &[u8]) -> Result<Value, TransportError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return Err(TransportError::malformed_response());
    }
    serde_json::from_slice(body).map_err(|_| TransportError::malformed_response())
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, TransportError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(TransportError::malformed_response)
}

fn optional_bool(value: &Value, key: &str) -> Result<Option<bool>, TransportError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(TransportError::malformed_response),
    }
}

fn parse_u32(value: Option<&Value>) -> Result<Option<u32>, TransportError> {
    value
        .map(|v| {
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(TransportError::malformed_response)
        })
        .transpose()
}

fn parse_table_granularity(value: Option<&Value>) -> TableGranularity {
    match value.and_then(Value::as_str) {
        Some("MILLIS") => TableGranularity::Millis,
        Some("MICROS") => TableGranularity::Micros,
        Some(_) => TableGranularity::Unknown,
        None => TableGranularity::Unspecified,
    }
}

fn parse_table_cluster_state(value: Option<&Value>) -> TableClusterState {
    // The REST Table ClusterState field is `replicationState`.
    match value.and_then(Value::as_str) {
        Some("STATE_NOT_KNOWN") => TableClusterState::StateNotKnown,
        Some("INITIALIZING" | "READY_OPTIMIZING") => TableClusterState::Creating,
        Some("READY") => TableClusterState::Ready,
        // Maintenance is deliberately not guessed as READY.
        Some("PLANNED_MAINTENANCE" | "UNPLANNED_MAINTENANCE" | _) | None => {
            TableClusterState::Unknown
        }
    }
}

fn parse_cluster_state(value: Option<&Value>) -> ClusterState {
    match value.and_then(Value::as_str) {
        Some("READY") => ClusterState::Ready,
        Some("CREATING") => ClusterState::Creating,
        Some("RESIZING") => ClusterState::Updating,
        Some("DISABLED") => ClusterState::Deleting,
        Some("STATE_NOT_KNOWN") => ClusterState::StateUnspecified,
        Some(_) | None => ClusterState::Unknown,
    }
}

fn parse_storage_type(value: Option<&Value>) -> ClusterStorageType {
    match value.and_then(Value::as_str) {
        Some("SSD") => ClusterStorageType::Ssd,
        Some("HDD") => ClusterStorageType::Hdd,
        Some("STORAGE_TYPE_UNSPECIFIED") => ClusterStorageType::Unspecified,
        Some(_) | None => ClusterStorageType::Unknown,
    }
}

fn parse_duration_millis(value: &Value) -> Result<u64, TransportError> {
    let text = value
        .as_str()
        .ok_or_else(TransportError::malformed_response)?;
    let text = text
        .strip_suffix('s')
        .ok_or_else(TransportError::malformed_response)?;
    let (whole, fraction) = text.split_once('.').map_or((text, ""), |parts| parts);
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 9
    {
        return Err(TransportError::malformed_response());
    }
    if fraction.len() > 3 && fraction.as_bytes()[3..].iter().any(|b| *b != b'0') {
        return Err(TransportError::malformed_response());
    }
    let seconds = whole
        .parse::<u64>()
        .map_err(|_| TransportError::malformed_response())?;
    let millis = if fraction.is_empty() {
        0
    } else {
        let mut value = fraction.to_owned();
        while value.len() < 3 {
            value.push('0');
        }
        value[..3]
            .parse::<u64>()
            .map_err(|_| TransportError::malformed_response())?
    };
    let total = seconds
        .checked_mul(1_000)
        .and_then(|v| v.checked_add(millis))
        .ok_or_else(TransportError::malformed_response)?;
    (total > 0 && total <= MAX_POLICY_AGE_MILLIS)
        .then_some(total)
        .ok_or_else(TransportError::malformed_response)
}

fn parse_gc_rule(value: Option<&Value>) -> Result<GarbageCollectionRule, TransportError> {
    let Some(value) = value else {
        return Ok(GarbageCollectionRule::Unspecified);
    };
    let rule = value
        .as_object()
        .ok_or_else(TransportError::malformed_response)?;
    if let Some(number) = rule.get("maxNumVersions") {
        let number = number
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(TransportError::malformed_response)?;
        return GarbageCollectionRule::MaxVersions(number)
            .validate()
            .map(|()| GarbageCollectionRule::MaxVersions(number))
            .map_err(|_| TransportError::malformed_response());
    }
    if let Some(age) = rule.get("maxAge") {
        let millis = parse_duration_millis(age)?;
        return GarbageCollectionRule::MaxAgeMillis(millis)
            .validate()
            .map(|()| GarbageCollectionRule::MaxAgeMillis(millis))
            .map_err(|_| TransportError::malformed_response());
    }
    if let Some(union) = rule.get("union") {
        let rules = union
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(TransportError::malformed_response)?;
        let count = u16::try_from(rules.len()).map_err(|_| TransportError::malformed_response())?;
        return GarbageCollectionRule::Union(count)
            .validate()
            .map(|()| GarbageCollectionRule::Union(count))
            .map_err(|_| TransportError::malformed_response());
    }
    if let Some(intersection) = rule.get("intersection") {
        let rules = intersection
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(TransportError::malformed_response)?;
        let count = u16::try_from(rules.len()).map_err(|_| TransportError::malformed_response())?;
        return GarbageCollectionRule::Intersection(count)
            .validate()
            .map(|()| GarbageCollectionRule::Intersection(count))
            .map_err(|_| TransportError::malformed_response());
    }
    Ok(GarbageCollectionRule::Unknown)
}

fn has_pagination_marker(value: &Value) -> bool {
    [
        "pageToken",
        "nextPageToken",
        "next_page_token",
        "page_token",
    ]
    .iter()
    .any(|key| value.get(*key).is_some())
}
fn is_truncated(value: &Value) -> bool {
    ["truncated", "partial", "isTruncated"]
        .iter()
        .any(|key| value.get(*key).and_then(Value::as_bool) == Some(true))
}

pub fn parse_table_json_response(
    request: &GetTableRequest,
    status_code: u16,
    body: &[u8],
    credential_revision: Revision,
) -> Result<GetTableResponse, TransportError> {
    if status_code != 200 {
        return Err(parse_status(status_code));
    }
    let value = validate_body(body)?;
    let resource = TableResource::from_name(
        string_field(&value, "name")?,
        request.scope().project(),
        request.scope().instance(),
    )
    .map_err(|_| TransportError::malformed_response())?;
    if resource.digest() != request.scope().table().digest() {
        return Err(TransportError::new(
            ProviderErrorKind::MalformedResponse,
            None,
            "table-scope-mismatch",
        ));
    }
    let families = match value.get("columnFamilies") {
        None | Some(Value::Null) => Vec::new(),
        Some(families) => {
            let object = families
                .as_object()
                .ok_or_else(TransportError::malformed_response)?;
            if object.len() > MAX_FAMILIES {
                return Err(TransportError::malformed_response());
            }
            let mut output = Vec::with_capacity(object.len());
            for (name, family) in object {
                let family = family
                    .as_object()
                    .ok_or_else(TransportError::malformed_response)?;
                let value_type_digest = match family.get("valueType") {
                    None | Some(Value::Null) => None,
                    Some(value_type) if value_type.is_object() => Some(Digest::from_bytes(
                        &serde_json::to_vec(value_type)
                            .map_err(|_| TransportError::malformed_response())?,
                    )),
                    Some(_) => return Err(TransportError::malformed_response()),
                };
                output.push(
                    ColumnFamily::new_with_value_type(
                        name.clone(),
                        parse_gc_rule(family.get("gcRule"))?,
                        value_type_digest,
                    )
                    .map_err(|_| TransportError::malformed_response())?,
                );
            }
            output
        }
    };
    let cluster_states = match value.get("clusterStates") {
        None | Some(Value::Null) => Vec::new(),
        Some(states) => {
            let object = states
                .as_object()
                .ok_or_else(TransportError::malformed_response)?;
            if object.len() > MAX_CLUSTERS {
                return Err(TransportError::malformed_response());
            }
            let mut output = Vec::with_capacity(object.len());
            for (name, state) in object {
                let cluster = ClusterResource::from_name(
                    name,
                    request.scope().project(),
                    request.scope().instance(),
                )
                .map_err(|_| TransportError::malformed_response())?;
                let state = state
                    .as_object()
                    .ok_or_else(TransportError::malformed_response)?;
                output.push(TableClusterStateEntry::new(
                    cluster,
                    parse_table_cluster_state(state.get("replicationState")),
                ));
            }
            output
        }
    };
    let configuration = TableConfiguration::new(
        resource,
        families,
        cluster_states,
        parse_table_granularity(value.get("granularity")),
        optional_bool(&value, "deletionProtection")?,
        value
            .get("changeStreamConfig")
            .and_then(Value::as_object)
            .is_some_and(|v| !v.is_empty()),
    )
    .map_err(|_| TransportError::malformed_response())?;
    Ok(GetTableResponse::with_metadata(
        configuration,
        request.scope().fence(),
        credential_revision,
        body.len(),
        has_pagination_marker(&value),
        is_truncated(&value),
    ))
}

pub fn parse_cluster_json_response(
    request: &GetClusterRequest,
    status_code: u16,
    body: &[u8],
    credential_revision: Revision,
) -> Result<GetClusterResponse, TransportError> {
    if status_code != 200 {
        return Err(parse_status(status_code));
    }
    let value = validate_body(body)?;
    let resource = ClusterResource::from_name(
        string_field(&value, "name")?,
        request.scope().project(),
        request.scope().instance(),
    )
    .map_err(|_| TransportError::malformed_response())?;
    if resource.digest() != request.cluster().digest() {
        return Err(TransportError::new(
            ProviderErrorKind::MalformedResponse,
            None,
            "cluster-scope-mismatch",
        ));
    }
    let location_digest = value
        .get("location")
        .and_then(Value::as_str)
        .map(Digest::from_text);
    let encryption_digest = value
        .get("encryptionConfig")
        .and_then(|v| v.get("kmsKeyName"))
        .and_then(Value::as_str)
        .map(Digest::from_text);
    let configuration = ClusterConfiguration::new(
        resource,
        location_digest,
        parse_cluster_state(value.get("state")),
        parse_u32(value.get("serveNodes"))?,
        parse_storage_type(value.get("defaultStorageType")),
        encryption_digest,
    )
    .map_err(|_| TransportError::malformed_response())?;
    Ok(GetClusterResponse::with_metadata(
        configuration,
        request.scope().fence(),
        credential_revision,
        body.len(),
        has_pagination_marker(&value),
        is_truncated(&value),
    ))
}

#[derive(Clone)]
pub struct RecordingGcpBigtableTransport {
    provenance: ProviderProvenance,
    table_responses: VecDeque<Result<GetTableResponse, TransportError>>,
    cluster_responses: VecDeque<Result<GetClusterResponse, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl fmt::Debug for RecordingGcpBigtableTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingGcpBigtableTransport")
            .field("provenance", &self.provenance)
            .field("queued_table_responses", &self.table_responses.len())
            .field("queued_cluster_responses", &self.cluster_responses.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl Default for RecordingGcpBigtableTransport {
    fn default() -> Self {
        Self::new(ProviderProvenance::Recording)
    }
}

impl RecordingGcpBigtableTransport {
    #[must_use]
    pub fn new(provenance: ProviderProvenance) -> Self {
        Self {
            provenance,
            table_responses: VecDeque::new(),
            cluster_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }
    pub fn push_table_response(&mut self, response: Result<GetTableResponse, TransportError>) {
        self.table_responses.push_back(response);
    }
    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.cluster_responses.push_back(response);
    }
    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
    #[must_use]
    pub fn table_calls(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| r.operation == ProviderOperation::GetTableSchema)
            .count()
    }
    #[must_use]
    pub fn cluster_calls(&self) -> usize {
        self.requests
            .iter()
            .filter(|r| r.operation == ProviderOperation::GetClusterPosture)
            .count()
    }
}

impl GcpBigtableTransport for RecordingGcpBigtableTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.table_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unknown()))
    }
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.cluster_responses
            .pop_front()
            .unwrap_or_else(|| Err(TransportError::unknown()))
    }
}

pub type FakeGcpBigtableTransport = RecordingGcpBigtableTransport;

#[derive(Clone, Debug)]
pub struct FixtureGcpBigtableTransport(RecordingGcpBigtableTransport);
impl Default for FixtureGcpBigtableTransport {
    fn default() -> Self {
        Self(RecordingGcpBigtableTransport::new(
            ProviderProvenance::Fixture,
        ))
    }
}
impl FixtureGcpBigtableTransport {
    pub fn push_table_response(&mut self, response: Result<GetTableResponse, TransportError>) {
        self.0.push_table_response(response);
    }
    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.0.push_cluster_response(response);
    }
    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        self.0.requests()
    }
}
impl GcpBigtableTransport for FixtureGcpBigtableTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError> {
        self.0.get_table(request)
    }
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.0.get_cluster(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport(RecordingGcpBigtableTransport);
impl Default for LoopbackTransport {
    fn default() -> Self {
        Self(RecordingGcpBigtableTransport::new(
            ProviderProvenance::Loopback,
        ))
    }
}
impl LoopbackTransport {
    pub fn push_table_response(&mut self, response: Result<GetTableResponse, TransportError>) {
        self.0.push_table_response(response);
    }
    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.0.push_cluster_response(response);
    }
    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        self.0.requests()
    }
}
impl GcpBigtableTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
    fn get_table(&mut self, request: &GetTableRequest) -> Result<GetTableResponse, TransportError> {
        self.0.get_table(request)
    }
    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.0.get_cluster(request)
    }
}
