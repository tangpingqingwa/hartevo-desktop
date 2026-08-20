//! Bounded Azure Resource Manager provider and non-native test transports.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    ApiVersion, AzureCosmosScope, BackupPolicy, ConsistencyPolicy, Digest, IndexingMode,
    ModelError, ProviderErrorCode, ProviderId, RegionName, ResourceDigestPair, ResourceId,
    SecretReference, ThroughputInheritance, ThroughputMode, ThroughputSummary, ThroughputTarget,
    TransportProvenance,
};
use crate::{
    AZURE_COSMOS_API_REVISION, AZURE_COSMOS_API_VERSION, AZURE_COSMOS_PLUGIN_VERSION,
    AZURE_COSMOS_PROVIDER_ID, AzureCosmosContainerResultContract, AzureCosmosContractError,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AzureCosmosOperation {
    DatabaseAccountsGet,
    SqlDatabasesGet,
    SqlContainersGet,
    ThroughputSettingsGet,
}

impl AzureCosmosOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DatabaseAccountsGet => "DatabaseAccounts_Get",
            Self::SqlDatabasesGet => "SqlDatabases_Get",
            Self::SqlContainersGet => "SqlContainers_Get",
            Self::ThroughputSettingsGet => "ThroughputSettings_Get",
        }
    }

    pub const fn permission(self) -> crate::model::PermissionAction {
        match self {
            Self::DatabaseAccountsGet => crate::model::PermissionAction::ReadDatabaseAccount,
            Self::SqlDatabasesGet => crate::model::PermissionAction::ReadSqlDatabase,
            Self::SqlContainersGet => crate::model::PermissionAction::ReadSqlContainer,
            Self::ThroughputSettingsGet => crate::model::PermissionAction::ReadThroughputSettings,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AzureCosmosProviderError {
    #[error("Azure Cosmos provider returned a bounded status code")]
    Status {
        code: ProviderErrorCode,
        status_code: Option<u16>,
        retry_after_seconds: Option<u32>,
    },
    #[error("Azure Cosmos provider response was malformed")]
    MalformedResponse,
    #[error("Azure Cosmos provider response exceeded the response bound")]
    ResponseTooLarge,
    #[error("Azure Cosmos transport is unavailable")]
    TransportUnavailable,
    #[error("Azure Cosmos native transport is BLOCKED_ENV")]
    BlockedEnv,
}

impl AzureCosmosProviderError {
    pub const fn code(&self) -> ProviderErrorCode {
        match self {
            Self::Status { code, .. } => *code,
            Self::MalformedResponse => ProviderErrorCode::MalformedResponse,
            Self::ResponseTooLarge => ProviderErrorCode::ResponseTooLarge,
            Self::TransportUnavailable => ProviderErrorCode::TransportUnavailable,
            Self::BlockedEnv => ProviderErrorCode::BlockedEnv,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Status { status_code, .. } => *status_code,
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Status {
                code: ProviderErrorCode::RateLimited | ProviderErrorCode::ServerFailure,
                ..
            } | Self::TransportUnavailable
                | Self::BlockedEnv
        )
    }

    pub const fn access_loss(&self) -> bool {
        matches!(
            self,
            Self::Status {
                code: ProviderErrorCode::Unauthorized | ProviderErrorCode::Forbidden,
                ..
            }
        )
    }

    pub const fn not_found(&self) -> bool {
        matches!(
            self,
            Self::Status {
                code: ProviderErrorCode::NotFound,
                ..
            }
        )
    }

    pub const fn revision_drift(&self) -> bool {
        matches!(
            self,
            Self::Status {
                code: ProviderErrorCode::Conflict,
                ..
            }
        )
    }

    pub fn from_status(status_code: u16) -> Self {
        let code = match status_code {
            400 => ProviderErrorCode::BadRequest,
            401 => ProviderErrorCode::Unauthorized,
            403 => ProviderErrorCode::Forbidden,
            404 => ProviderErrorCode::NotFound,
            409 => ProviderErrorCode::Conflict,
            429 => ProviderErrorCode::RateLimited,
            500..=599 => ProviderErrorCode::ServerFailure,
            _ => ProviderErrorCode::Unknown,
        };
        Self::Status {
            code,
            status_code: Some(status_code),
            retry_after_seconds: None,
        }
    }

    pub fn summary(&self, operation: AzureCosmosOperation) -> crate::model::ProviderErrorSummary {
        crate::model::ProviderErrorSummary {
            operation: operation.as_str().to_owned(),
            code: self.code(),
            status_code: self.status_code(),
            retryable: self.retryable(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosGetRequest {
    pub operation: AzureCosmosOperation,
    pub scope_digest: Digest,
    pub resource_id: ResourceId,
    pub api_version: ApiVersion,
    pub throughput_target: Option<ThroughputTarget>,
    pub method: String,
    pub request_digest: Digest,
    pub max_response_bytes: usize,
}

impl AzureCosmosGetRequest {
    pub fn for_scope(
        scope: &AzureCosmosScope,
        operation: AzureCosmosOperation,
        throughput_target: ThroughputTarget,
        max_response_bytes: usize,
    ) -> Result<Self, ModelError> {
        let (resource_id, target) = match operation {
            AzureCosmosOperation::DatabaseAccountsGet => (scope.account_resource_id(), None),
            AzureCosmosOperation::SqlDatabasesGet => (scope.database_resource_id(), None),
            AzureCosmosOperation::SqlContainersGet => (scope.container_resource_id(), None),
            AzureCosmosOperation::ThroughputSettingsGet => (
                scope.throughput_resource_id(throughput_target),
                Some(throughput_target),
            ),
        };
        if max_response_bytes == 0 || max_response_bytes > crate::model::MAX_RESPONSE_BYTES {
            return Err(ModelError::OutOfBounds {
                field: "maximum response bytes",
            });
        }
        let request_digest = crate::model::digest_serializable(&(
            operation,
            scope.digest(),
            resource_id.digest(),
            scope.api_version.clone(),
            target,
            max_response_bytes,
        ))?;
        Ok(Self {
            operation,
            scope_digest: scope.digest(),
            resource_id,
            api_version: scope.api_version.clone(),
            throughput_target: target,
            method: "GET".to_owned(),
            request_digest,
            max_response_bytes,
        })
    }

    pub fn path_and_query(&self) -> String {
        format!("{}?api-version={}", self.resource_id, self.api_version)
    }

    pub const fn is_data_plane(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountResourceProjection {
    pub resource: ResourceDigestPair,
    pub location: Option<RegionName>,
    pub replication: crate::model::ReplicationTopologySummary,
    pub consistency: ConsistencyPolicy,
    pub backup_policy: BackupPolicy,
    pub public_network_access: Option<bool>,
    pub network_filter_enabled: Option<bool>,
}

impl AccountResourceProjection {
    pub fn from_resource_id(
        resource_id: &ResourceId,
        revision: Digest,
        location: Option<RegionName>,
        replication: crate::model::ReplicationTopologySummary,
        consistency: ConsistencyPolicy,
        backup_policy: BackupPolicy,
        public_network_access: Option<bool>,
        network_filter_enabled: Option<bool>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            resource: ResourceDigestPair::new(resource_id.digest(), revision)?,
            location,
            replication,
            consistency,
            backup_policy,
            public_network_access,
            network_filter_enabled,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlDatabaseResourceProjection {
    pub resource: ResourceDigestPair,
}

impl SqlDatabaseResourceProjection {
    pub fn from_resource_id(
        resource_id: &ResourceId,
        revision: Digest,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            resource: ResourceDigestPair::new(resource_id.digest(), revision)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlContainerResourceProjection {
    pub resource: ResourceDigestPair,
    pub indexing_mode: IndexingMode,
    pub partition_key_digest: Option<Digest>,
}

impl SqlContainerResourceProjection {
    pub fn from_resource_id(
        resource_id: &ResourceId,
        revision: Digest,
        indexing_mode: IndexingMode,
        partition_key_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if let Some(digest) = &partition_key_digest {
            digest.validate("partition key digest")?;
        }
        Ok(Self {
            resource: ResourceDigestPair::new(resource_id.digest(), revision)?,
            indexing_mode,
            partition_key_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThroughputResourceProjection {
    pub resource: ResourceDigestPair,
    pub summary: ThroughputSummary,
}

impl ThroughputResourceProjection {
    pub fn from_resource_id(
        resource_id: &ResourceId,
        revision: Digest,
        summary: ThroughputSummary,
    ) -> Result<Self, ModelError> {
        summary.validate()?;
        Ok(Self {
            resource: ResourceDigestPair::new(resource_id.digest(), revision)?,
            summary,
        })
    }

    pub fn manual(
        resource_id: &ResourceId,
        revision: Digest,
        ru_per_second: u64,
        inheritance: ThroughputInheritance,
    ) -> Result<Self, ModelError> {
        Self::from_resource_id(
            resource_id,
            revision,
            ThroughputSummary {
                mode: ThroughputMode::Manual,
                inheritance,
                min_ru_per_second: Some(ru_per_second),
                max_ru_per_second: Some(ru_per_second),
            },
        )
    }

    pub fn autoscale(
        resource_id: &ResourceId,
        revision: Digest,
        max_ru_per_second: u64,
        inheritance: ThroughputInheritance,
    ) -> Result<Self, ModelError> {
        Self::from_resource_id(
            resource_id,
            revision,
            ThroughputSummary {
                mode: ThroughputMode::Autoscale,
                inheritance,
                min_ru_per_second: Some((max_ru_per_second / 10).max(1)),
                max_ru_per_second: Some(max_ru_per_second),
            },
        )
    }

    pub fn ambiguous(resource_id: &ResourceId, revision: Digest) -> Result<Self, ModelError> {
        Self::from_resource_id(
            resource_id,
            revision,
            ThroughputSummary {
                mode: ThroughputMode::Ambiguous,
                inheritance: ThroughputInheritance::Ambiguous,
                min_ru_per_second: None,
                max_ru_per_second: None,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AzureCosmosResourceProjection {
    Account(AccountResourceProjection),
    SqlDatabase(SqlDatabaseResourceProjection),
    SqlContainer(SqlContainerResourceProjection),
    Throughput(ThroughputResourceProjection),
}

impl AzureCosmosResourceProjection {
    pub fn resource(&self) -> &ResourceDigestPair {
        match self {
            Self::Account(value) => &value.resource,
            Self::SqlDatabase(value) => &value.resource,
            Self::SqlContainer(value) => &value.resource,
            Self::Throughput(value) => &value.resource,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AzureCosmosResourceResponse {
    pub operation: AzureCosmosOperation,
    pub request_digest: Digest,
    pub status_code: u16,
    pub body_bytes: usize,
    pub resource: AzureCosmosResourceProjection,
    pub provenance: TransportProvenance,
    pub declared_response_digest: Digest,
}

impl AzureCosmosResourceResponse {
    pub fn new(
        request: &AzureCosmosGetRequest,
        resource: AzureCosmosResourceProjection,
        body_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if body_bytes == 0 || body_bytes > request.max_response_bytes {
            return Err(ModelError::OutOfBounds {
                field: "provider response bytes",
            });
        }
        let mut response = Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            status_code: 200,
            body_bytes,
            resource,
            provenance,
            declared_response_digest: Digest::zero(),
        };
        response.declared_response_digest = response.recomputed_digest();
        Ok(response)
    }

    pub fn with_declared_response_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = digest;
        self
    }

    pub fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            self.operation,
            &self.request_digest,
            self.status_code,
            self.body_bytes,
            &self.resource,
            self.provenance,
        ))
        .expect("Cosmos response digest input is serializable")
    }

    pub fn validate_integrity(
        &self,
        request: &AzureCosmosGetRequest,
    ) -> Result<(), AzureCosmosProviderError> {
        if self.operation != request.operation
            || self.request_digest != request.request_digest
            || self.status_code != 200
            || self.body_bytes == 0
            || self.body_bytes > request.max_response_bytes
            || !self.resource_matches_operation()
            || self.declared_response_digest != self.recomputed_digest()
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
        {
            return Err(AzureCosmosProviderError::MalformedResponse);
        }
        Ok(())
    }

    fn resource_matches_operation(&self) -> bool {
        matches!(
            (&self.operation, &self.resource),
            (
                AzureCosmosOperation::DatabaseAccountsGet,
                AzureCosmosResourceProjection::Account(_)
            ) | (
                AzureCosmosOperation::SqlDatabasesGet,
                AzureCosmosResourceProjection::SqlDatabase(_)
            ) | (
                AzureCosmosOperation::SqlContainersGet,
                AzureCosmosResourceProjection::SqlContainer(_)
            ) | (
                AzureCosmosOperation::ThroughputSettingsGet,
                AzureCosmosResourceProjection::Throughput(_)
            )
        )
    }
}

pub trait AzureCosmosTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureCosmosProviderDefinition {
    pub id: ProviderId,
    pub version: String,
    pub api_version: ApiVersion,
    pub api_revision: String,
    pub allowlisted_operations: Vec<AzureCosmosOperation>,
    pub allowlisted_methods: Vec<String>,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub data_plane: bool,
    pub digest: Digest,
}

impl AzureCosmosProviderDefinition {
    pub fn baseline() -> Result<Self, AzureCosmosContractError> {
        let _ = AzureCosmosContainerResultContract::baseline()?;
        let id =
            ProviderId::new(AZURE_COSMOS_PROVIDER_ID).map_err(AzureCosmosContractError::Model)?;
        let api_version =
            ApiVersion::new(AZURE_COSMOS_API_VERSION).map_err(AzureCosmosContractError::Model)?;
        let mut definition = Self {
            id,
            version: AZURE_COSMOS_PLUGIN_VERSION.to_owned(),
            api_version,
            api_revision: AZURE_COSMOS_API_REVISION.to_owned(),
            allowlisted_operations: vec![
                AzureCosmosOperation::DatabaseAccountsGet,
                AzureCosmosOperation::SqlDatabasesGet,
                AzureCosmosOperation::SqlContainersGet,
                AzureCosmosOperation::ThroughputSettingsGet,
            ],
            allowlisted_methods: vec!["GET".to_owned()],
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            data_plane: false,
            digest: Digest::zero(),
        };
        definition.digest = definition.recomputed_digest();
        Ok(definition)
    }

    fn recomputed_digest(&self) -> Digest {
        crate::model::digest_serializable(&(
            &self.id,
            &self.version,
            &self.api_version,
            &self.api_revision,
            &self.allowlisted_operations,
            &self.allowlisted_methods,
            self.native,
            self.connected,
            self.first_party,
            self.external_writes,
            self.data_plane,
        ))
        .expect("provider definition is serializable")
    }

    pub fn validate(&self) -> Result<(), AzureCosmosContractError> {
        if self.id.as_str() != AZURE_COSMOS_PROVIDER_ID
            || self.version != AZURE_COSMOS_PLUGIN_VERSION
            || self.api_version.as_str() != AZURE_COSMOS_API_VERSION
            || self.api_revision != AZURE_COSMOS_API_REVISION
            || self.allowlisted_methods != ["GET"]
            || self.allowlisted_operations
                != [
                    AzureCosmosOperation::DatabaseAccountsGet,
                    AzureCosmosOperation::SqlDatabasesGet,
                    AzureCosmosOperation::SqlContainersGet,
                    AzureCosmosOperation::ThroughputSettingsGet,
                ]
            || self.native
            || self.connected
            || self.first_party
            || self.external_writes
            || self.data_plane
            || self.digest != self.recomputed_digest()
        {
            return Err(AzureCosmosContractError::ProviderBoundary(
                "provider definition drifted",
            ));
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug)]
pub struct AzureCosmosResourceProvider<T: AzureCosmosTransport> {
    transport: T,
    definition: AzureCosmosProviderDefinition,
}

impl<T: AzureCosmosTransport> AzureCosmosResourceProvider<T> {
    pub fn new(transport: T) -> Result<Self, AzureCosmosContractError> {
        let definition = AzureCosmosProviderDefinition::baseline()?;
        Self::with_definition(transport, definition)
    }

    pub fn with_definition(
        transport: T,
        definition: AzureCosmosProviderDefinition,
    ) -> Result<Self, AzureCosmosContractError> {
        definition.validate()?;
        if transport.provenance().connected()
            || transport.provenance().native()
            || transport.provenance().first_party()
        {
            return Err(AzureCosmosContractError::ProviderBoundary(
                "native or connected transport is not a Layer-1 provider",
            ));
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AzureCosmosProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &ProviderId {
        &self.definition.id
    }

    pub fn provider_revision(&self) -> &str {
        &self.definition.api_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        self.definition.provider_digest()
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        if request.method != "GET" || request.api_version.as_str() != AZURE_COSMOS_API_VERSION {
            return Err(AzureCosmosProviderError::Status {
                code: ProviderErrorCode::BadRequest,
                status_code: Some(400),
                retry_after_seconds: None,
            });
        }
        self.transport.get(request)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

fn parse_resource(
    request: &AzureCosmosGetRequest,
    value: &Value,
) -> Result<AzureCosmosResourceProjection, AzureCosmosProviderError> {
    match request.operation {
        AzureCosmosOperation::DatabaseAccountsGet => parse_account(request, value),
        AzureCosmosOperation::SqlDatabasesGet => parse_database(request, value),
        AzureCosmosOperation::SqlContainersGet => parse_container(request, value),
        AzureCosmosOperation::ThroughputSettingsGet => parse_throughput(request, value),
    }
}

fn parse_account(
    request: &AzureCosmosGetRequest,
    value: &Value,
) -> Result<AzureCosmosResourceProjection, AzureCosmosProviderError> {
    let resource_id = resource_id(value)?;
    let revision = revision_digest(value, &resource_id);
    let properties = value.get("properties").unwrap_or(&Value::Null);
    let location = value
        .get("location")
        .and_then(Value::as_str)
        .and_then(|value| RegionName::new(value).ok());
    let locations = properties
        .get("locations")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|entry| entry.get("locationName").and_then(Value::as_str))
                .filter_map(|value| RegionName::new(value).ok())
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty());
    let replication = if let Some(locations) = locations {
        crate::model::ReplicationTopologySummary::new(location.clone(), locations)
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)?
    } else if let Some(location) = location.clone() {
        crate::model::ReplicationTopologySummary::single(location)
    } else {
        crate::model::ReplicationTopologySummary {
            primary_location: None,
            region_count: 1,
            region_set_digest: Digest::from_text("unknown-region"),
            multi_region: false,
        }
    };
    let consistency = parse_consistency(properties);
    let backup_policy = parse_backup_policy(properties);
    let public_network_access = parse_public_network_access(properties);
    let network_filter_enabled = properties
        .get("isVirtualNetworkFilterEnabled")
        .and_then(Value::as_bool);
    let projection = AccountResourceProjection::from_resource_id(
        &resource_id,
        revision,
        location,
        replication,
        consistency,
        backup_policy,
        public_network_access,
        network_filter_enabled,
    )
    .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
    if projection.resource.identity_digest != request.resource_id.digest() {
        return Err(AzureCosmosProviderError::MalformedResponse);
    }
    Ok(AzureCosmosResourceProjection::Account(projection))
}

fn parse_database(
    request: &AzureCosmosGetRequest,
    value: &Value,
) -> Result<AzureCosmosResourceProjection, AzureCosmosProviderError> {
    let resource_id = resource_id(value)?;
    let projection = SqlDatabaseResourceProjection::from_resource_id(
        &resource_id,
        revision_digest(value, &resource_id),
    )
    .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
    if projection.resource.identity_digest != request.resource_id.digest() {
        return Err(AzureCosmosProviderError::MalformedResponse);
    }
    Ok(AzureCosmosResourceProjection::SqlDatabase(projection))
}

fn parse_container(
    request: &AzureCosmosGetRequest,
    value: &Value,
) -> Result<AzureCosmosResourceProjection, AzureCosmosProviderError> {
    let resource_id = resource_id(value)?;
    let resource = value
        .get("properties")
        .and_then(|properties| properties.get("resource"))
        .unwrap_or_else(|| value.get("properties").unwrap_or(&Value::Null));
    let indexing_mode = resource
        .get("indexingPolicy")
        .and_then(|policy| policy.get("indexingMode"))
        .and_then(Value::as_str)
        .map_or(IndexingMode::Unknown, parse_indexing_mode);
    let partition_key_digest = resource
        .get("partitionKey")
        .and_then(|partition_key| partition_key.get("paths"))
        .and_then(Value::as_array)
        .map(|paths| {
            let values = paths
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            Digest::from_parts("hartevo-azure-cosmosdb-partition-key/v1", &values)
        });
    let projection = SqlContainerResourceProjection::from_resource_id(
        &resource_id,
        revision_digest(value, &resource_id),
        indexing_mode,
        partition_key_digest,
    )
    .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
    if projection.resource.identity_digest != request.resource_id.digest() {
        return Err(AzureCosmosProviderError::MalformedResponse);
    }
    Ok(AzureCosmosResourceProjection::SqlContainer(projection))
}

fn parse_throughput(
    request: &AzureCosmosGetRequest,
    value: &Value,
) -> Result<AzureCosmosResourceProjection, AzureCosmosProviderError> {
    let resource_id = resource_id(value)?;
    let properties = value.get("properties").unwrap_or(&Value::Null);
    let manual = properties.get("throughput").and_then(Value::as_u64);
    let autoscale = properties
        .get("autoscaleSettings")
        .and_then(|settings| settings.get("maxThroughput"))
        .and_then(Value::as_u64);
    let inheritance = match request.throughput_target {
        Some(ThroughputTarget::Database) => ThroughputInheritance::Database,
        Some(ThroughputTarget::Container) => ThroughputInheritance::Container,
        Some(ThroughputTarget::ContainerOrDatabase) | None => ThroughputInheritance::SharedDatabase,
    };
    let projection = if let Some(ru) = manual {
        ThroughputResourceProjection::manual(
            &resource_id,
            revision_digest(value, &resource_id),
            ru,
            inheritance,
        )
    } else if let Some(ru) = autoscale {
        ThroughputResourceProjection::autoscale(
            &resource_id,
            revision_digest(value, &resource_id),
            ru,
            inheritance,
        )
    } else {
        ThroughputResourceProjection::ambiguous(&resource_id, revision_digest(value, &resource_id))
    }
    .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
    if projection.resource.identity_digest != request.resource_id.digest() {
        return Err(AzureCosmosProviderError::MalformedResponse);
    }
    Ok(AzureCosmosResourceProjection::Throughput(projection))
}

fn resource_id(value: &Value) -> Result<ResourceId, AzureCosmosProviderError> {
    value
        .get("id")
        .and_then(Value::as_str)
        .ok_or(AzureCosmosProviderError::MalformedResponse)
        .and_then(|value| {
            ResourceId::new(value).map_err(|_| AzureCosmosProviderError::MalformedResponse)
        })
}

fn revision_digest(value: &Value, resource_id: &ResourceId) -> Digest {
    value
        .get("etag")
        .and_then(Value::as_str)
        .or_else(|| value.get("_etag").and_then(Value::as_str))
        .or_else(|| {
            value
                .get("properties")
                .and_then(|properties| properties.get("resource"))
                .and_then(|resource| resource.get("_etag"))
                .and_then(Value::as_str)
        })
        .map_or_else(
            || {
                Digest::from_parts(
                    "hartevo-azure-cosmosdb-missing-etag/v1",
                    &[resource_id.as_str().to_owned()],
                )
            },
            Digest::from_text,
        )
}

fn parse_consistency(properties: &Value) -> ConsistencyPolicy {
    properties
        .get("consistencyPolicy")
        .and_then(|policy| policy.get("defaultConsistencyLevel"))
        .and_then(Value::as_str)
        .map_or(ConsistencyPolicy::Unknown, |value| {
            match value.to_ascii_lowercase().as_str() {
                "strong" => ConsistencyPolicy::Strong,
                "bound edstaleness" | "boundedstaleness" => ConsistencyPolicy::BoundedStaleness,
                "session" => ConsistencyPolicy::Session,
                "consistentprefix" | "consistent_prefix" => ConsistencyPolicy::ConsistentPrefix,
                "eventual" => ConsistencyPolicy::Eventual,
                _ => ConsistencyPolicy::Unknown,
            }
        })
}

fn parse_backup_policy(properties: &Value) -> BackupPolicy {
    properties
        .get("backupPolicy")
        .and_then(|policy| policy.get("type"))
        .and_then(Value::as_str)
        .map_or(BackupPolicy::Unknown, |value| {
            match value.to_ascii_lowercase().as_str() {
                "continuous" => BackupPolicy::Continuous,
                "periodic" => BackupPolicy::Periodic,
                "none" => BackupPolicy::None,
                _ => BackupPolicy::Unknown,
            }
        })
}

fn parse_public_network_access(properties: &Value) -> Option<bool> {
    match properties.get("publicNetworkAccess") {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("enabled") => Some(true),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("disabled") => Some(false),
        _ => None,
    }
}

fn parse_indexing_mode(value: &str) -> IndexingMode {
    match value.to_ascii_lowercase().as_str() {
        "consistent" => IndexingMode::Consistent,
        "lazy" => IndexingMode::Lazy,
        "none" => IndexingMode::None,
        _ => IndexingMode::Unknown,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecordedRequest {
    pub operation: AzureCosmosOperation,
    pub path_and_query: String,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAzureCosmosTransport {
    responses: VecDeque<Result<AzureCosmosResourceResponse, AzureCosmosProviderError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingAzureCosmosTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(
        &mut self,
        response: Result<AzureCosmosResourceResponse, AzureCosmosProviderError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn push_error(&mut self, error: AzureCosmosProviderError) {
        self.responses.push_back(Err(error));
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl AzureCosmosTransport for RecordingAzureCosmosTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        self.requests.push(RecordedRequest {
            operation: request.operation,
            path_and_query: request.path_and_query(),
            request_digest: request.request_digest.clone(),
        });
        self.responses
            .pop_front()
            .unwrap_or(Err(AzureCosmosProviderError::TransportUnavailable))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureAzureCosmosTransport {
    scope: AzureCosmosScope,
    observed_at: DateTime<Utc>,
}

impl FixtureAzureCosmosTransport {
    pub fn for_scope(scope: &AzureCosmosScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

impl AzureCosmosTransport for FixtureAzureCosmosTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        fixture_response(
            &self.scope,
            self.observed_at,
            request,
            TransportProvenance::Fixture,
        )
    }
}

#[derive(Clone, Debug)]
pub struct FakeAzureCosmosTransport {
    scope: AzureCosmosScope,
    observed_at: DateTime<Utc>,
}

impl FakeAzureCosmosTransport {
    pub fn for_scope(scope: &AzureCosmosScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

impl AzureCosmosTransport for FakeAzureCosmosTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        fixture_response(
            &self.scope,
            self.observed_at,
            request,
            TransportProvenance::Fake,
        )
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackAzureCosmosTransport {
    scope: AzureCosmosScope,
    observed_at: DateTime<Utc>,
}

impl LoopbackAzureCosmosTransport {
    pub fn for_scope(scope: &AzureCosmosScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }
}

impl AzureCosmosTransport for LoopbackAzureCosmosTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get(
        &mut self,
        request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        fixture_response(
            &self.scope,
            self.observed_at,
            request,
            TransportProvenance::Loopback,
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAzureCosmosTransport;

impl AzureCosmosTransport for BlockedEnvAzureCosmosTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &AzureCosmosGetRequest,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        Err(AzureCosmosProviderError::BlockedEnv)
    }
}

fn fixture_response(
    scope: &AzureCosmosScope,
    _observed_at: DateTime<Utc>,
    request: &AzureCosmosGetRequest,
    provenance: TransportProvenance,
) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
    let projection = match request.operation {
        AzureCosmosOperation::DatabaseAccountsGet => {
            let location = RegionName::new("eastus")
                .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
            let replication = crate::model::ReplicationTopologySummary::new(
                Some(location.clone()),
                [
                    location.clone(),
                    RegionName::new("westus").expect("fixture region"),
                ],
            )
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
            AzureCosmosResourceProjection::Account(
                AccountResourceProjection::from_resource_id(
                    &request.resource_id,
                    scope.account_revision_digest.clone(),
                    Some(location),
                    replication,
                    ConsistencyPolicy::Session,
                    BackupPolicy::Continuous,
                    Some(false),
                    Some(true),
                )
                .map_err(|_| AzureCosmosProviderError::MalformedResponse)?,
            )
        }
        AzureCosmosOperation::SqlDatabasesGet => AzureCosmosResourceProjection::SqlDatabase(
            SqlDatabaseResourceProjection::from_resource_id(
                &request.resource_id,
                scope.database_revision_digest.clone(),
            )
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)?,
        ),
        AzureCosmosOperation::SqlContainersGet => AzureCosmosResourceProjection::SqlContainer(
            SqlContainerResourceProjection::from_resource_id(
                &request.resource_id,
                scope.container_revision_digest.clone(),
                IndexingMode::Consistent,
                Some(Digest::from_text("/tenantId")),
            )
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)?,
        ),
        AzureCosmosOperation::ThroughputSettingsGet => {
            let inheritance = match request.throughput_target {
                Some(ThroughputTarget::Database) => ThroughputInheritance::Database,
                Some(ThroughputTarget::Container) => ThroughputInheritance::Container,
                Some(ThroughputTarget::ContainerOrDatabase) | None => {
                    ThroughputInheritance::Container
                }
            };
            AzureCosmosResourceProjection::Throughput(
                ThroughputResourceProjection::manual(
                    &request.resource_id,
                    scope
                        .throughput_revision_digest
                        .clone()
                        .unwrap_or_else(|| scope.container_revision_digest.clone()),
                    400,
                    inheritance,
                )
                .map_err(|_| AzureCosmosProviderError::MalformedResponse)?,
            )
        }
    };
    AzureCosmosResourceResponse::new(request, projection, 512, provenance)
        .map_err(|_| AzureCosmosProviderError::MalformedResponse)
}

pub fn is_access_loss(error: &AzureCosmosProviderError) -> bool {
    error.access_loss()
}

pub type ProviderProvenance = TransportProvenance;
pub type BlockedEnvTransport = BlockedEnvAzureCosmosTransport;
pub type FixtureTransport = FixtureAzureCosmosTransport;
pub type FakeTransport = FakeAzureCosmosTransport;
pub type LoopbackTransport = LoopbackAzureCosmosTransport;
pub type RecordingTransport = RecordingAzureCosmosTransport;
pub type AzureCosmosProviderErrorCode = ProviderErrorCode;
pub type AzureCosmosResourceProviderDefinition = AzureCosmosProviderDefinition;
pub type EntraSecretReference = SecretReference;

impl<T: AzureCosmosTransport> AzureCosmosResourceProvider<T> {
    pub fn parse_json_response(
        request: &AzureCosmosGetRequest,
        status_code: u16,
        body: &[u8],
        provenance: TransportProvenance,
    ) -> Result<AzureCosmosResourceResponse, AzureCosmosProviderError> {
        if body.len() > request.max_response_bytes {
            return Err(AzureCosmosProviderError::ResponseTooLarge);
        }
        if !(200..300).contains(&status_code) {
            return Err(AzureCosmosProviderError::from_status(status_code));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)?;
        let resource = parse_resource(request, &value)?;
        AzureCosmosResourceResponse::new(request, resource, body.len(), provenance)
            .map_err(|_| AzureCosmosProviderError::MalformedResponse)
    }
}
