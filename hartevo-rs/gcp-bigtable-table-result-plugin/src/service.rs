//! Bounded table-posture service, registration, and Layer-1 proposal.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_BIGTABLE_TABLE_RESULT_CONSUMER, GCP_BIGTABLE_TABLE_RESULT_CONTRACT_JSON,
    GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION, GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT,
    GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID, GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION,
    GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID, GcpBigtableProviderApi, Layer1Authority, contract_digest,
    model::{
        ClusterConfiguration, ClusterProjection, ClusterResource, ClusterState, ClusterStorageType,
        DatabaseProjection, Digest, EvidenceDigests, GarbageCollectionRule, GcpBigtableTableScope,
        MAX_CLUSTERS, MAX_RESPONSE_BYTES, ModelError, PermissionFence, ProviderErrorEvidence,
        ProviderErrorKind, ProviderResourceScopeProjection, Revision, SecretReference,
        TableClusterState, TableConfiguration, TableGranularity, TablePosture, TableProjection,
    },
    plugin_version_digest,
    provider::{
        GetClusterRequest, GetClusterResponse, GetTableRequest, GetTableResponse,
        ProviderDefinitionError, ProviderOperation, ProviderProvenance, TransportError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("service/provider/API/permission/secret/evidence/scope binding does not match")]
    BindingMismatch,
    #[error("provider evidence is tampered or stale")]
    TamperedEvidence,
    #[error("provider response is unexpectedly paginated")]
    Pagination,
    #[error("provider response is truncated")]
    Truncated,
    #[error("provider definition is unknown or drifted")]
    ProviderUnknown,
    #[error(transparent)]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransition {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBigtableRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub provider_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_definition_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub status: RegistrationStatus,
}

impl GcpBigtableRegistration {
    pub fn new<P: GcpBigtableProviderApi>(
        scope: &GcpBigtableTableScope,
        secret: &SecretReference,
        provider: &P,
    ) -> Result<Self, ServiceError> {
        if secret.scope_digest() != &scope.scope_digest()
            || secret.is_revoked()
            || provider.definition().provider_id != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            || provider.definition().native
            || provider.definition().first_party
            || provider.definition().connected
            || provider.definition().live_execution
            || provider.definition().row_reads
            || provider.definition().external_writes
        {
            return Err(ServiceError::BindingMismatch);
        }
        provider.definition().validate()?;
        let revision = Revision::new(1)?;
        let version_digest = plugin_version_digest();
        let contract = contract_digest();
        let evidence = evidence_policy_digest();
        let registration = registration_digest(
            &version_digest,
            &contract,
            &provider.definition().provider_digest,
            &provider.definition().api_digest,
            scope.permission_digest(),
            &scope.scope_digest(),
            secret.reference_digest(),
            &evidence,
            revision,
        );
        Ok(Self {
            schema_version: GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            service_id: GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_BIGTABLE_TABLE_RESULT_CONSUMER.to_owned(),
            provider_version: provider.definition().provider_version.clone(),
            version_digest,
            contract_digest: contract,
            provider_definition_digest: provider.definition().provider_digest.clone(),
            api_digest: provider.definition().api_digest.clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest(),
            secret_reference_digest: secret.reference_digest().clone(),
            evidence_digest: evidence,
            registration_digest: registration,
            revision,
            status: RegistrationStatus::Active,
        })
    }

    pub fn ensure_active(&self) -> Result<(), ServiceError> {
        (self.status == RegistrationStatus::Active)
            .then_some(())
            .ok_or(ServiceError::RegistrationRevoked)
    }

    pub fn validate<P: GcpBigtableProviderApi>(
        &self,
        scope: &GcpBigtableTableScope,
        secret: &SecretReference,
        provider: &P,
    ) -> Result<(), ServiceError> {
        provider.definition().validate()?;
        if self.schema_version != GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION
            || self.contract_version != GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION
            || self.plugin_version != GCP_BIGTABLE_TABLE_RESULT_PLUGIN_VERSION_TEXT
            || self.service_id != GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID
            || self.provider_id != GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID
            || self.consumer_id != GCP_BIGTABLE_TABLE_RESULT_CONSUMER
            || self.provider_version != provider.definition().provider_version
            || self.version_digest != plugin_version_digest()
            || self.contract_digest != contract_digest()
            || self.provider_definition_digest != provider.definition().provider_digest
            || self.api_digest != provider.definition().api_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != scope.scope_digest()
            || self.secret_reference_digest != *secret.reference_digest()
            || self.evidence_digest != evidence_policy_digest()
            || secret.scope_digest() != &scope.scope_digest()
            || secret.is_revoked()
        {
            return Err(ServiceError::BindingMismatch);
        }
        let expected = registration_digest(
            &self.version_digest,
            &self.contract_digest,
            &self.provider_definition_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.secret_reference_digest,
            &self.evidence_digest,
            self.revision,
        );
        (expected == self.registration_digest)
            .then_some(())
            .ok_or(ServiceError::TamperedEvidence)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.transition(RegistrationStatus::Revoked)
    }
    pub fn reverse(&mut self) -> Result<RegistrationTransition, ServiceError> {
        if self.status != RegistrationStatus::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.transition(RegistrationStatus::Reversed)
    }
    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransition, ServiceError> {
        if self.status != RegistrationStatus::Active && new_status == RegistrationStatus::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = new_status;
        let transition_digest = Digest::from_fields(
            "gcp-bigtable-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationTransition {
            previous_status,
            new_status,
            registration_digest: self.registration_digest.clone(),
            transition_digest,
        })
    }
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }
    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }
    #[must_use]
    pub const fn is_revocable() -> bool {
        true
    }
}

pub type GcpBigtableTableResultRegistration = GcpBigtableRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBigtableServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub rows_read: bool,
    pub external_writes: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for GcpBigtableServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}
impl GcpBigtableServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_BIGTABLE_TABLE_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_BIGTABLE_TABLE_RESULT_CONSUMER.to_owned(),
            contract_digest: Digest::from_text(GCP_BIGTABLE_TABLE_RESULT_CONTRACT_JSON),
            read_only: true,
            live_execution: false,
            rows_read: false,
            external_writes: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectionRequest {
    pub max_clusters: u8,
}
impl InspectionRequest {
    pub fn new(max_clusters: u8) -> Result<Self, ModelError> {
        (max_clusters != 0 && usize::from(max_clusters) <= MAX_CLUSTERS)
            .then_some(Self { max_clusters })
            .ok_or(ModelError::TooManyClusters)
    }
}
impl Default for InspectionRequest {
    fn default() -> Self {
        Self {
            max_clusters: MAX_CLUSTERS as u8,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBigtableResultEvidence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub work_product_revision: Revision,
    pub provider_resource_scope: ProviderResourceScopeProjection,
    pub database: DatabaseProjection,
    pub table: Option<TableProjection>,
    pub clusters: Vec<ClusterProjection>,
    pub request_digests: Vec<Digest>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub digests: EvidenceDigests,
    pub provenance: ProviderProvenance,
    pub authority: Layer1Authority,
    pub complete: bool,
    pub pagination_observed: bool,
    pub truncated: bool,
    pub rows_read: bool,
    pub writes_performed: bool,
    pub raw_values_retained: bool,
    pub credentials_retained: bool,
    pub pii_retained: bool,
    pub durable_provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpBigtableTableResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub posture: TablePosture,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub evidence: GcpBigtableResultEvidence,
    pub proposal_digest: Digest,
}
impl GcpBigtableTableResultProposal {
    #[must_use]
    pub const fn status(&self) -> TablePosture {
        self.posture
    }
    #[must_use]
    pub const fn is_adopted(&self) -> bool {
        false
    }
    #[must_use]
    pub const fn authority(&self) -> Layer1Authority {
        self.evidence.authority
    }
}
impl fmt::Display for GcpBigtableTableResultProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GcpBigtableTableResultProposal({:?})",
            self.posture
        )
    }
}

pub struct GcpBigtableTableResultService<P> {
    scope: GcpBigtableTableScope,
    secret_reference: SecretReference,
    provider: P,
    registration: GcpBigtableRegistration,
}

impl<P: GcpBigtableProviderApi> fmt::Debug for GcpBigtableTableResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpBigtableTableResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .finish()
    }
}

impl<P: GcpBigtableProviderApi> GcpBigtableTableResultService<P> {
    pub fn new(
        scope: GcpBigtableTableScope,
        secret_reference: SecretReference,
        provider: P,
    ) -> Result<Self, ServiceError> {
        let registration = GcpBigtableRegistration::new(&scope, &secret_reference, &provider)?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
        })
    }
    #[must_use]
    pub fn definition() -> GcpBigtableServiceDefinition {
        GcpBigtableServiceDefinition::new()
    }
    #[must_use]
    pub fn scope(&self) -> &GcpBigtableTableScope {
        &self.scope
    }
    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
    #[must_use]
    pub fn provider(&self) -> &P {
        &self.provider
    }
    #[must_use]
    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
    #[must_use]
    pub fn registration(&self) -> &GcpBigtableRegistration {
        &self.registration
    }
    #[must_use]
    pub fn registration_mut(&mut self) -> &mut GcpBigtableRegistration {
        &mut self.registration
    }
    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.revoke()
    }
    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.reverse()
    }
    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke().map_err(ServiceError::from)
    }
    pub fn inspect(&mut self) -> Result<GcpBigtableTableResultProposal, ServiceError> {
        self.propose(InspectionRequest::default())
    }

    pub fn propose(
        &mut self,
        request: InspectionRequest,
    ) -> Result<GcpBigtableTableResultProposal, ServiceError> {
        if request.max_clusters == 0 || usize::from(request.max_clusters) > MAX_CLUSTERS {
            return Ok(self.finish(
                TablePosture::Misconfigured,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
                false,
            ));
        }
        if self.registration.status != RegistrationStatus::Active
            || self.secret_reference.is_revoked()
        {
            return Ok(self.finish(
                TablePosture::Revoked,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
                false,
            ));
        }
        if let Err(error) =
            self.registration
                .validate(&self.scope, &self.secret_reference, &self.provider)
        {
            let posture = match error {
                ServiceError::TamperedEvidence => TablePosture::Tampered,
                ServiceError::ProviderDefinition(_) | ServiceError::ProviderUnknown => {
                    TablePosture::ProviderUnknown
                }
                _ => TablePosture::Stale,
            };
            return Ok(self.finish(
                posture,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                false,
                false,
                false,
            ));
        }
        let table_request = GetTableRequest::new(&self.scope, &self.secret_reference)?;
        let table_response = match self.provider.get_table(&table_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish(
                    posture_for_transport_error(&error),
                    None,
                    Vec::new(),
                    vec![table_request.request_digest().clone()],
                    vec![provider_error(ProviderOperation::GetTableSchema, &error)],
                    false,
                    false,
                    false,
                ));
            }
        };
        if let Err(posture) =
            validate_table_response(&table_response, &self.scope, &self.secret_reference)
        {
            return Ok(self.finish(
                posture,
                Some(&table_response.configuration),
                Vec::new(),
                vec![table_request.request_digest().clone()],
                Vec::new(),
                false,
                table_response.pagination_observed,
                table_response.truncated,
            ));
        }
        let entries = table_response.configuration.cluster_states();
        if entries.is_empty() || entries.len() > usize::from(request.max_clusters) {
            return Ok(self.finish(
                TablePosture::Partial,
                Some(&table_response.configuration),
                Vec::new(),
                vec![table_request.request_digest().clone()],
                Vec::new(),
                false,
                false,
                false,
            ));
        }
        let mut clusters = Vec::with_capacity(entries.len());
        let mut requests = vec![table_request.request_digest().clone()];
        let mut errors = Vec::new();
        let mut seen = BTreeSet::new();
        for entry in entries {
            if !seen.insert(entry.cluster().digest()) {
                return Ok(self.finish(
                    TablePosture::Tampered,
                    Some(&table_response.configuration),
                    clusters,
                    requests,
                    errors,
                    false,
                    false,
                    false,
                ));
            }
            let cluster_request = GetClusterRequest::new(
                &self.scope,
                &self.secret_reference,
                entry.cluster().clone(),
            )?;
            requests.push(cluster_request.request_digest().clone());
            let response = match self.provider.get_cluster(&cluster_request) {
                Ok(response) => response,
                Err(error) => {
                    errors.push(provider_error(ProviderOperation::GetClusterPosture, &error));
                    return Ok(self.finish(
                        posture_for_transport_error(&error),
                        Some(&table_response.configuration),
                        clusters,
                        requests,
                        errors,
                        false,
                        false,
                        false,
                    ));
                }
            };
            if let Err(posture) = validate_cluster_response(
                &response,
                entry.cluster(),
                &self.scope,
                &self.secret_reference,
            ) {
                return Ok(self.finish(
                    posture,
                    Some(&table_response.configuration),
                    clusters,
                    requests,
                    errors,
                    false,
                    response.pagination_observed,
                    response.truncated,
                ));
            }
            clusters.push(response.configuration);
        }
        let posture = posture_for_configuration(&table_response.configuration, &clusters);
        Ok(self.finish(
            posture,
            Some(&table_response.configuration),
            clusters,
            requests,
            errors,
            posture == TablePosture::Ready,
            false,
            false,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        posture: TablePosture,
        table: Option<&TableConfiguration>,
        clusters: Vec<ClusterConfiguration>,
        request_digests: Vec<Digest>,
        provider_errors: Vec<ProviderErrorEvidence>,
        complete: bool,
        pagination_observed: bool,
        truncated: bool,
    ) -> GcpBigtableTableResultProposal {
        let table_projection = table.map(TableConfiguration::projection);
        let cluster_projections = clusters
            .iter()
            .map(ClusterConfiguration::projection)
            .collect::<Vec<_>>();
        let database = self.scope.database_projection();
        let cluster_digest = (!cluster_projections.is_empty()).then(|| {
            Digest::from_fields(
                "gcp-bigtable-cluster-evidence-set/v1",
                &[cluster_projections
                    .iter()
                    .map(|v| v.configuration_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(",")],
            )
        });
        let evidence_digest = Digest::from_fields(
            "gcp-bigtable-table-evidence/v1",
            &[
                database.database_digest.as_str().to_owned(),
                table_projection
                    .as_ref()
                    .map_or_else(String::new, |v| v.configuration_digest.as_str().to_owned()),
                cluster_digest
                    .as_ref()
                    .map_or_else(String::new, |v| v.as_str().to_owned()),
                self.scope.permission_digest().as_str().to_owned(),
                self.scope.consent_digest().as_str().to_owned(),
                request_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                provider_errors
                    .iter()
                    .map(|v| v.error_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                complete.to_string(),
                pagination_observed.to_string(),
                truncated.to_string(),
            ],
        );
        let provider_definition = self.provider.definition();
        let result_digest = Digest::from_fields(
            "gcp-bigtable-table-result/v1",
            &[
                format!("{posture:?}"),
                self.scope.scope_digest().as_str().to_owned(),
                evidence_digest.as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
                provider_definition.provider_digest.as_str().to_owned(),
                provider_definition.api_digest.as_str().to_owned(),
                format!("{:?}", self.provider.provenance()),
            ],
        );
        let evidence = GcpBigtableResultEvidence {
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest().clone(),
            consent_digest: self.scope.consent_digest().clone(),
            work_product_revision: self.scope.work_product_revision(),
            provider_resource_scope: self.scope.provider_resource_projection(),
            database: database.clone(),
            table: table_projection.clone(),
            clusters: cluster_projections,
            request_digests,
            provider_errors,
            digests: EvidenceDigests {
                database_digest: database.database_digest.clone(),
                table_digest: table_projection
                    .as_ref()
                    .map(|v| v.configuration_digest.clone()),
                schema_digest: table.map(|v| v.schema_digest().clone()),
                family_digest: table.map(|v| v.family_digest().clone()),
                cluster_digest,
                permission_digest: self.scope.permission_digest().clone(),
                evidence_digest,
                result_digest: result_digest.clone(),
            },
            provenance: self.provider.provenance(),
            authority: Layer1Authority::offline(),
            complete,
            pagination_observed,
            truncated,
            rows_read: false,
            writes_performed: false,
            raw_values_retained: false,
            credentials_retained: false,
            pii_retained: false,
            durable_provider_receipt: false,
        };
        let proposal_digest = Digest::from_fields(
            "gcp-bigtable-table-proposal/v1",
            &[
                result_digest.as_str().to_owned(),
                self.scope.scope_digest().as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
                self.registration.revision.get().to_string(),
            ],
        );
        GcpBigtableTableResultProposal {
            service_id: GCP_BIGTABLE_TABLE_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_BIGTABLE_TABLE_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: GCP_BIGTABLE_TABLE_RESULT_CONSUMER.to_owned(),
            posture,
            scope_digest: self.scope.scope_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest: provider_definition.provider_digest.clone(),
            evidence,
            proposal_digest,
        }
    }
}

pub type GcpBigtableResultService<P> = GcpBigtableTableResultService<P>;
pub type GcpBigtableTableService<P> = GcpBigtableTableResultService<P>;
pub type GcpBigtableTableResult = GcpBigtableTableResultProposal;

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_fields(
        "gcp-bigtable-evidence-policy/v1",
        &[
            GCP_BIGTABLE_TABLE_RESULT_SCHEMA_VERSION.to_owned(),
            "database_digest".to_owned(),
            "table_schema_family_digests".to_owned(),
            "cluster_posture_digests".to_owned(),
            "raw_values=false".to_owned(),
            "rows=false".to_owned(),
            "credentials=false".to_owned(),
            "pii=false".to_owned(),
            "durable_provider_receipt=false".to_owned(),
        ],
    )
}

fn registration_digest(
    version: &Digest,
    contract: &Digest,
    provider: &Digest,
    api: &Digest,
    permission: &Digest,
    scope: &Digest,
    secret: &Digest,
    evidence: &Digest,
    revision: Revision,
) -> Digest {
    Digest::from_fields(
        "gcp-bigtable-registration/v1",
        &[
            version.as_str().to_owned(),
            contract.as_str().to_owned(),
            provider.as_str().to_owned(),
            api.as_str().to_owned(),
            permission.as_str().to_owned(),
            scope.as_str().to_owned(),
            secret.as_str().to_owned(),
            evidence.as_str().to_owned(),
            revision.get().to_string(),
        ],
    )
}

fn validate_fence(observed: &PermissionFence, scope: &GcpBigtableTableScope) -> bool {
    observed == &scope.fence()
}

fn validate_table_response(
    response: &GetTableResponse,
    scope: &GcpBigtableTableScope,
    secret: &SecretReference,
) -> Result<(), TablePosture> {
    if response.validate_digest().is_err()
        || response.configuration.resource().digest() != scope.table().digest()
        || !validate_fence(&response.observed_fence, scope)
        || response.observed_credential_revision != secret.credential_revision()
    {
        return Err(TablePosture::Tampered);
    }
    if response.pagination_observed {
        return Err(TablePosture::Pagination);
    }
    if response.truncated || response.response_bytes > MAX_RESPONSE_BYTES {
        return Err(TablePosture::Truncated);
    }
    if response.configuration.granularity() == TableGranularity::Unknown
        || response
            .configuration
            .families()
            .iter()
            .any(|f| matches!(f.gc_rule(), GarbageCollectionRule::Unknown))
    {
        return Err(TablePosture::ProviderUnknown);
    }
    Ok(())
}

fn validate_cluster_response(
    response: &GetClusterResponse,
    expected: &ClusterResource,
    scope: &GcpBigtableTableScope,
    secret: &SecretReference,
) -> Result<(), TablePosture> {
    if response.validate_digest().is_err()
        || response.configuration.resource().digest() != expected.digest()
        || !validate_fence(&response.observed_fence, scope)
        || response.observed_credential_revision != secret.credential_revision()
    {
        return Err(TablePosture::Tampered);
    }
    if response.pagination_observed {
        return Err(TablePosture::Pagination);
    }
    if response.truncated || response.response_bytes > MAX_RESPONSE_BYTES {
        return Err(TablePosture::Truncated);
    }
    Ok(())
}

fn posture_for_transport_error(error: &TransportError) -> TablePosture {
    match error.kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            TablePosture::AccessLost
        }
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::MalformedResponse => TablePosture::Misconfigured,
        ProviderErrorKind::RateLimited
        | ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::BlockedEnv
        | ProviderErrorKind::Unknown => TablePosture::ProviderUnknown,
    }
}

fn posture_for_configuration(
    table: &TableConfiguration,
    clusters: &[ClusterConfiguration],
) -> TablePosture {
    if table.cluster_states().iter().any(|e| {
        matches!(
            e.state(),
            TableClusterState::StateNotKnown | TableClusterState::Unknown
        )
    }) {
        return TablePosture::ProviderUnknown;
    }
    if clusters.iter().any(|c| {
        matches!(
            c.state(),
            ClusterState::StateUnspecified | ClusterState::Unknown
        ) || matches!(
            c.storage_type(),
            ClusterStorageType::Unspecified | ClusterStorageType::Unknown
        )
    }) {
        return TablePosture::ProviderUnknown;
    }
    if table
        .cluster_states()
        .iter()
        .any(|e| matches!(e.state(), TableClusterState::Deleting))
        || clusters
            .iter()
            .any(|c| matches!(c.state(), ClusterState::Deleting))
    {
        return TablePosture::Degraded;
    }
    if table.cluster_states().iter().any(|e| {
        matches!(
            e.state(),
            TableClusterState::Planned | TableClusterState::Creating
        )
    }) || clusters
        .iter()
        .any(|c| matches!(c.state(), ClusterState::Creating | ClusterState::Updating))
    {
        return TablePosture::Creating;
    }
    if table
        .cluster_states()
        .iter()
        .all(|e| e.state() == TableClusterState::Ready)
        && clusters.iter().all(|c| c.state() == ClusterState::Ready)
    {
        TablePosture::Ready
    } else {
        TablePosture::Degraded
    }
}

fn provider_error(operation: ProviderOperation, error: &TransportError) -> ProviderErrorEvidence {
    ProviderErrorEvidence {
        operation: operation.as_str().to_owned(),
        kind: error.kind,
        status_code: error.status_code,
        error_digest: error.diagnostic_digest().clone(),
    }
}
