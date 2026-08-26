use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    AzureMonitorLogsScope, Digest, Layer1Authority, ModelError, RegistrationState,
    RegistrationTransition, ResultStatus, Revision, SecretReference,
};
use crate::provider::{
    AzureMonitorLogsProviderDefinition, AzureMonitorLogsProviderPort, AzureMonitorLogsRequest,
    AzureMonitorLogsResponse, ProviderError, ProviderErrorKind, ProviderProvenance,
    result_status_for_error,
};
use crate::query::{QueryError, QueryPlan};
use crate::{
    AZURE_MONITOR_LOGS_CONTRACT_VERSION, AZURE_MONITOR_LOGS_PROVIDER_ID,
    AZURE_MONITOR_LOGS_SCHEMA_VERSION, AZURE_MONITOR_LOGS_SERVICE_ID,
    AZURE_MONITOR_LOGS_SERVICE_VERSION,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("service or provider definition is invalid")]
    InvalidDefinition,
    #[error("provider definition claims a forbidden Layer-1 authority")]
    ProviderAuthority,
    #[error("scope, query template, parameter, or Mission binding drifted")]
    ScopeMismatch,
    #[error("SecretReference is bound to a different scope")]
    SecretScopeMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration operation is not valid in the current state")]
    InvalidRegistrationTransition,
    #[error("registration or secret reference is revoked")]
    Revoked,
    #[error(transparent)]
    Query(#[from] QueryError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: crate::ServiceId,
    pub provider_id: crate::ProviderId,
    pub contract_digest: Digest,
    pub version: String,
    pub read_only: bool,
    pub endpoint: String,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
}

impl AzureMonitorLogsServiceDefinition {
    pub fn new() -> Result<Self, ServiceError> {
        Ok(Self {
            schema_version: AZURE_MONITOR_LOGS_SCHEMA_VERSION.to_owned(),
            contract_version: AZURE_MONITOR_LOGS_CONTRACT_VERSION.to_owned(),
            service_id: crate::ServiceId::new(AZURE_MONITOR_LOGS_SERVICE_ID)?,
            provider_id: crate::ProviderId::new(AZURE_MONITOR_LOGS_PROVIDER_ID)?,
            contract_digest: crate::contract_digest(),
            version: AZURE_MONITOR_LOGS_SERVICE_VERSION.to_owned(),
            read_only: true,
            endpoint: crate::AZURE_MONITOR_LOGS_QUERY_PATH.to_owned(),
            live_execution: false,
            connected: false,
            native: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
        })
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.schema_version != AZURE_MONITOR_LOGS_SCHEMA_VERSION
            || self.contract_version != AZURE_MONITOR_LOGS_CONTRACT_VERSION
            || self.service_id.as_str() != AZURE_MONITOR_LOGS_SERVICE_ID
            || self.provider_id.as_str() != AZURE_MONITOR_LOGS_PROVIDER_ID
            || self.version != AZURE_MONITOR_LOGS_SERVICE_VERSION
            || !self.read_only
            || self.endpoint != crate::AZURE_MONITOR_LOGS_QUERY_PATH
            || self.live_execution
            || self.connected
            || self.native
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
        {
            Err(ServiceError::InvalidDefinition)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub provider_api_revision: String,
    pub provider_digest: Digest,
    pub provider_provenance: ProviderProvenance,
    pub tenant_id: crate::TenantId,
    pub subscription_id: crate::SubscriptionId,
    pub workspace_id: crate::WorkspaceId,
    pub table: crate::TableName,
    pub scope_digest: Digest,
    pub query_template_digest: Digest,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub time_window_digest: Digest,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub state: RegistrationState,
    pub revision: Revision,
    pub registration_digest: Digest,
}

impl AzureMonitorLogsRegistration {
    fn new(
        scope: &AzureMonitorLogsScope,
        secret: &SecretReference,
        plan: &QueryPlan,
        provider: &AzureMonitorLogsProviderDefinition,
        service: &AzureMonitorLogsServiceDefinition,
    ) -> Result<Self, ServiceError> {
        if secret.scope_digest() != &scope.scope_digest()
            || plan.matches_scope(scope).is_err()
            || provider.validate().is_err()
            || service.validate().is_err()
        {
            return Err(ServiceError::InvalidRegistration);
        }
        let state = RegistrationState::Active;
        let revision = Revision::new(1)?;
        let mut registration = Self {
            plugin_version: service.version.clone(),
            contract_version: service.contract_version.clone(),
            contract_digest: service.contract_digest.clone(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_api_revision: provider.api_revision.clone(),
            provider_digest: provider.provider_digest(),
            provider_provenance: provider.provenance,
            tenant_id: scope.tenant_id.clone(),
            subscription_id: scope.subscription_id.clone(),
            workspace_id: scope.workspace_id.clone(),
            table: scope.table.clone(),
            scope_digest: scope.scope_digest(),
            query_template_digest: plan.template().template_digest.clone(),
            query_digest: plan.query_digest().clone(),
            parameter_digest: plan.parameter_digest().clone(),
            time_window_digest: plan.time_window().digest.clone(),
            project_id: scope.project_id.clone(),
            project_revision: scope.project_revision,
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            work_product_id: scope.work_product_id.clone(),
            work_product_revision: scope.work_product_revision,
            permission_digest: scope.permission_digest.clone(),
            consent_digest: scope.consent_digest.clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            state,
            revision,
            registration_digest: Digest::from_text("uninitialized"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "azure-monitor-logs-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.provider_api_revision.clone(),
                self.provider_digest.as_str().to_owned(),
                format!("{:?}", self.provider_provenance),
                self.tenant_id.as_str().to_owned(),
                self.subscription_id.as_str().to_owned(),
                self.workspace_id.as_str().to_owned(),
                self.table.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.query_template_digest.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.parameter_digest.as_str().to_owned(),
                self.time_window_digest.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                format!("{:?}", self.state),
                self.revision.get().to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.compute_digest() == self.registration_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransition, ServiceError> {
        if self.state != RegistrationState::Active {
            return Err(ServiceError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Reversed;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            revision: self.revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition, ServiceError> {
        if self.state != RegistrationState::Reversed {
            return Err(ServiceError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Active;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            revision: self.revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ServiceError> {
        if self.state == RegistrationState::Revoked {
            return Err(ServiceError::InvalidRegistrationTransition);
        }
        let previous = self.state;
        self.state = RegistrationState::Revoked;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransition {
            previous,
            current: self.state,
            revision: self.revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    fn matches(
        &self,
        scope: &AzureMonitorLogsScope,
        secret: &SecretReference,
        plan: &QueryPlan,
        provider: &AzureMonitorLogsProviderDefinition,
    ) -> bool {
        self.scope_digest == scope.scope_digest()
            && self.tenant_id == scope.tenant_id
            && self.subscription_id == scope.subscription_id
            && self.workspace_id == scope.workspace_id
            && self.table == scope.table
            && self.project_id == scope.project_id
            && self.project_revision == scope.project_revision
            && self.mission_id == scope.mission_id
            && self.mission_revision == scope.mission_revision
            && self.work_product_id == scope.work_product_id
            && self.work_product_revision == scope.work_product_revision
            && self.query_template_digest == plan.template().template_digest
            && self.query_digest == *plan.query_digest()
            && self.parameter_digest == *plan.parameter_digest()
            && self.time_window_digest == plan.time_window().digest
            && self.secret_reference_digest == *secret.reference_digest()
            && self.credential_revision == secret.credential_revision()
            && self.provider_id == provider.provider_id
            && self.provider_digest == provider.provider_digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorSummary {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub diagnostic_digest: Digest,
}

impl From<&ProviderError> for ProviderErrorSummary {
    fn from(error: &ProviderError) -> Self {
        Self {
            kind: error.kind,
            status_code: error.status_code,
            retryable: error.retryable,
            diagnostic_digest: error.diagnostic_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AzureMonitorLogsResult {
    pub status: ResultStatus,
    pub scope_digest: Digest,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub query_template_digest: Digest,
    pub query_digest: Digest,
    pub parameter_digest: Digest,
    pub time_window_digest: Digest,
    pub schema: Option<crate::AggregateSchema>,
    pub rows: Vec<crate::AggregateRow>,
    pub total_rows: Option<u64>,
    pub response_bytes: u64,
    pub duration_ms: u32,
    pub cost_microunits: u64,
    pub row_set_digest: Digest,
    pub provider_provenance: ProviderProvenance,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_error: Option<ProviderErrorSummary>,
    pub authority: Layer1Authority,
    pub result_digest: Digest,
}

impl AzureMonitorLogsResult {
    pub fn is_adopted(&self) -> bool {
        false
    }

    pub fn eligible_for_decision(&self) -> bool {
        matches!(self.status, ResultStatus::Complete | ResultStatus::Empty)
    }

    pub fn verify_digests(&self) -> Result<(), ModelError> {
        if let Some(schema) = &self.schema {
            schema.validate_digest()?;
            for row in &self.rows {
                row.validate_against(schema)?;
            }
        } else if !self.rows.is_empty() {
            return Err(ModelError::InvalidRow);
        }
        let mut canonical_rows = self
            .rows
            .iter()
            .map(crate::AggregateRow::canonical)
            .collect::<Vec<_>>();
        canonical_rows.sort();
        let mut row_fields = vec![self.schema.as_ref().map_or_else(
            || "-".to_owned(),
            |schema| schema.schema_digest.as_str().to_owned(),
        )];
        row_fields.extend(canonical_rows);
        let row_set_digest = Digest::from_fields("azure-monitor-logs-row-set/v1", &row_fields);
        if row_set_digest != self.row_set_digest {
            return Err(ModelError::DigestMismatch);
        }
        let expected = compute_result_digest(self);
        if expected == self.result_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

fn compute_result_digest(result: &AzureMonitorLogsResult) -> Digest {
    Digest::from_fields(
        "azure-monitor-logs-result/v1",
        &[
            format!("{:?}", result.status),
            result.scope_digest.as_str().to_owned(),
            result.project_id.as_str().to_owned(),
            result.project_revision.get().to_string(),
            result.mission_id.as_str().to_owned(),
            result.mission_revision.get().to_string(),
            result.work_product_id.as_str().to_owned(),
            result.work_product_revision.get().to_string(),
            result.query_template_digest.as_str().to_owned(),
            result.query_digest.as_str().to_owned(),
            result.parameter_digest.as_str().to_owned(),
            result.time_window_digest.as_str().to_owned(),
            result.schema.as_ref().map_or_else(
                || "-".to_owned(),
                |schema| schema.schema_digest.as_str().to_owned(),
            ),
            result.row_set_digest.as_str().to_owned(),
            result
                .total_rows
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            result.response_bytes.to_string(),
            result.duration_ms.to_string(),
            result.cost_microunits.to_string(),
            format!("{:?}", result.provider_provenance),
            result.provider_digest.as_str().to_owned(),
            result.connected.to_string(),
            result.native.to_string(),
            result.first_party.to_string(),
            result.registration_digest.as_str().to_owned(),
            result.registration_revision.get().to_string(),
            result.provider_error.as_ref().map_or_else(
                || "-".to_owned(),
                |error| format!("{:?}:{}", error.kind, error.diagnostic_digest.as_str()),
            ),
            format!("{:?}", result.authority),
        ],
    )
}

pub struct AzureMonitorLogsResultService<P> {
    scope: AzureMonitorLogsScope,
    secret_reference: SecretReference,
    provider: P,
    plan: QueryPlan,
    service_definition: AzureMonitorLogsServiceDefinition,
    registration: AzureMonitorLogsRegistration,
}

impl<P: AzureMonitorLogsProviderPort> fmt::Debug for AzureMonitorLogsResultService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureMonitorLogsResultService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("plan", &self.plan)
            .field("provider", self.provider.definition())
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

pub type AzureMonitorLogsOutcomeService<P> = AzureMonitorLogsResultService<P>;

impl<P: AzureMonitorLogsProviderPort> AzureMonitorLogsResultService<P> {
    pub fn new(
        scope: AzureMonitorLogsScope,
        secret_reference: SecretReference,
        provider: P,
        plan: QueryPlan,
    ) -> Result<Self, ServiceError> {
        let service_definition = AzureMonitorLogsServiceDefinition::new()?;
        service_definition.validate()?;
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(ServiceError::SecretScopeMismatch);
        }
        plan.validate_digest()?;
        plan.matches_scope(&scope)?;
        provider
            .definition()
            .validate()
            .map_err(|_| ServiceError::ProviderAuthority)?;
        let registration = AzureMonitorLogsRegistration::new(
            &scope,
            &secret_reference,
            &plan,
            provider.definition(),
            &service_definition,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            plan,
            service_definition,
            registration,
        })
    }

    pub fn service_definition(&self) -> &AzureMonitorLogsServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &AzureMonitorLogsProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &AzureMonitorLogsRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AzureMonitorLogsScope {
        &self.scope
    }

    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.restore()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransition, ServiceError> {
        self.registration.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret_reference.revoke()?;
        Ok(())
    }

    pub fn query(&mut self) -> Result<AzureMonitorLogsResult, ServiceError> {
        if !self.registration.is_active() || self.secret_reference.is_revoked() {
            return Ok(self.revoked_result());
        }
        if !self.registration.matches(
            &self.scope,
            &self.secret_reference,
            &self.plan,
            self.provider.definition(),
        ) {
            return Ok(self.tampered_result(None));
        }
        let request = AzureMonitorLogsRequest::from_plan(
            &self.scope,
            &self.secret_reference,
            &self.plan,
            self.registration.registration_digest.clone(),
            self.registration.revision,
        );
        let provider_provenance = self.provider.definition().provenance;
        let provider_digest = self.provider.definition().provider_digest();
        match self.provider.query(&request) {
            Err(error) => Ok(self.error_result(provider_provenance, provider_digest, &error)),
            Ok(response) => {
                if response.validate_integrity(&request).is_err()
                    || !self.plan.matches_schema(&response.schema)
                {
                    Ok(self.tampered_result(Some(provider_provenance)))
                } else {
                    Ok(self.project_response(provider_provenance, provider_digest, response))
                }
            }
        }
    }

    pub fn propose(&mut self) -> Result<AzureMonitorLogsResult, ServiceError> {
        self.query()
    }

    fn base_result(
        &self,
        status: ResultStatus,
        provider_provenance: ProviderProvenance,
        schema: Option<crate::AggregateSchema>,
        rows: Vec<crate::AggregateRow>,
        total_rows: Option<u64>,
        response_bytes: u64,
        duration_ms: u32,
        cost_microunits: u64,
        provider_error: Option<ProviderErrorSummary>,
        provider_digest: &Digest,
    ) -> AzureMonitorLogsResult {
        let mut canonical_rows = rows
            .iter()
            .map(crate::AggregateRow::canonical)
            .collect::<Vec<_>>();
        canonical_rows.sort();
        let mut row_fields = vec![schema.as_ref().map_or_else(
            || "-".to_owned(),
            |value| value.schema_digest.as_str().to_owned(),
        )];
        row_fields.extend(canonical_rows);
        let row_set_digest = Digest::from_fields("azure-monitor-logs-row-set/v1", &row_fields);
        let mut result = AzureMonitorLogsResult {
            status,
            scope_digest: self.scope.scope_digest(),
            project_id: self.scope.project_id.clone(),
            project_revision: self.scope.project_revision,
            mission_id: self.scope.mission_id.clone(),
            mission_revision: self.scope.mission_revision,
            work_product_id: self.scope.work_product_id.clone(),
            work_product_revision: self.scope.work_product_revision,
            query_template_digest: self.plan.template().template_digest.clone(),
            query_digest: self.plan.query_digest().clone(),
            parameter_digest: self.plan.parameter_digest().clone(),
            time_window_digest: self.plan.time_window().digest.clone(),
            schema,
            rows,
            total_rows,
            response_bytes,
            duration_ms,
            cost_microunits,
            row_set_digest,
            provider_provenance,
            provider_digest: provider_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_error,
            authority: Layer1Authority::layer_one(),
            result_digest: Digest::from_text("uninitialized"),
        };
        result.result_digest = compute_result_digest(&result);
        result
    }

    fn revoked_result(&self) -> AzureMonitorLogsResult {
        self.base_result(
            ResultStatus::Revoked,
            self.provider.definition().provenance,
            None,
            Vec::new(),
            None,
            0,
            0,
            0,
            None,
            &self.provider.definition().provider_digest(),
        )
    }

    fn tampered_result(&self, provenance: Option<ProviderProvenance>) -> AzureMonitorLogsResult {
        self.base_result(
            ResultStatus::Tampered,
            provenance.unwrap_or(self.provider.definition().provenance),
            None,
            Vec::new(),
            None,
            0,
            0,
            0,
            Some(ProviderErrorSummary::from(&ProviderError::malformed())),
            &self.provider.definition().provider_digest(),
        )
    }

    fn error_result(
        &self,
        provenance: ProviderProvenance,
        provider_digest: Digest,
        error: &ProviderError,
    ) -> AzureMonitorLogsResult {
        self.base_result(
            result_status_for_error(error),
            provenance,
            None,
            Vec::new(),
            None,
            0,
            0,
            0,
            Some(error.into()),
            &provider_digest,
        )
    }

    fn project_response(
        &self,
        provider_provenance: ProviderProvenance,
        provider_digest: Digest,
        response: AzureMonitorLogsResponse,
    ) -> AzureMonitorLogsResult {
        let bounds = self.plan.bounds();
        let mut rows = Vec::new();
        let mut bytes = 0_u64;
        let mut truncated = response.rows.len() > bounds.max_rows as usize
            || response.response_bytes > bounds.max_response_bytes;
        let provider_status = response.status();
        for row in response.rows.iter().cloned() {
            let row_size = row.estimated_size() as u64;
            if rows.len() >= bounds.max_rows as usize
                || bytes.saturating_add(row_size) > bounds.max_response_bytes
            {
                truncated = true;
                break;
            }
            bytes = bytes.saturating_add(row_size);
            rows.push(row);
        }
        let status = if response.duration_ms > bounds.max_duration_ms {
            rows.clear();
            ResultStatus::Timeout
        } else if truncated || response.cost_microunits > bounds.max_cost_microunits {
            ResultStatus::Truncated
        } else {
            provider_status
        };
        let schema = if matches!(status, ResultStatus::Timeout) {
            None
        } else {
            Some(response.schema)
        };
        let response_bytes = response.response_bytes.min(bounds.max_response_bytes);
        self.base_result(
            status,
            provider_provenance,
            schema,
            rows,
            response.total_rows,
            response_bytes,
            response.duration_ms,
            response.cost_microunits,
            None,
            &provider_digest,
        )
    }
}
