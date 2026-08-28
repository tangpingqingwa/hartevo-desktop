//! Workday provider definition, registration fence, and read projection.

use chrono::Utc;
use serde::Serialize;
use thiserror::Error;

use crate::model::{
    Digest, ModelError, ProviderErrorKind, ProviderRevision, RegistrationState, SecretReference,
    TransportProvenance, WorkdayBusinessProcessResultEvidence, WorkdayReadRequest, WorkdayScope,
};
use crate::transport::{TransportError, WorkdayHttpRequest, WorkdayHttpResponse, WorkdayTransport};
use crate::{
    WORKDAY_API_VERSION, WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_VERSION,
    WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_VERSION_TEXT,
    WORKDAY_BUSINESS_PROCESS_RESULT_SCHEMA_VERSION, WORKDAY_PROVIDER_ID, WORKDAY_PROVIDER_REVISION,
    WorkdayError, contract_digest,
};

pub type ProviderProvenance = TransportProvenance;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native Workday provider")]
    NativeProviderForbidden,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub events_read: bool,
    pub raas_read: bool,
    pub wql_read: bool,
    pub live_execution: bool,
    pub native: bool,
    pub mutating_operations: Vec<String>,
}

impl WorkdayProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.trim().is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_fields(
            "workday-provider-capabilities/v1",
            &[
                WORKDAY_BUSINESS_PROCESS_RESULT_SCHEMA_VERSION.to_owned(),
                WORKDAY_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                "businessProcess/events:GET".to_owned(),
                "RaaS:GET".to_owned(),
                "WQL:GET".to_owned(),
                "live_execution=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: WORKDAY_BUSINESS_PROCESS_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: WORKDAY_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision: ProviderRevision::new(WORKDAY_PROVIDER_REVISION)?,
            capability_digest,
            provenance,
            events_read: true,
            raas_read: true,
            wql_read: true,
            live_execution: false,
            native: false,
            mutating_operations: Vec::new(),
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "workday-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.provider_revision.as_str().to_owned(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.events_read.to_string(),
                self.raas_read.to_string(),
                self.wql_read.to_string(),
                self.live_execution.to_string(),
                self.native.to_string(),
                self.mutating_operations.join(","),
            ],
        )
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkdayRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub capability_digest: Digest,
    pub tenant_id: crate::model::TenantId,
    pub tenant_revision: crate::model::Revision,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub consent_revision: crate::model::Revision,
    pub secret_reference_digest: Digest,
    pub mission_id: crate::model::MissionId,
    pub mission_revision: crate::model::Revision,
    pub project_id: crate::model::ProjectId,
    pub project_revision: crate::model::Revision,
    pub work_product_id: crate::model::WorkProductId,
    pub work_product_revision: crate::model::Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl WorkdayRegistration {
    pub(crate) fn new(
        scope: &WorkdayScope,
        secret: &SecretReference,
        provider: &WorkdayProviderDefinition,
    ) -> Result<Self, WorkdayError> {
        if secret.is_revoked() || secret.scope_digest() != scope.scope_digest() {
            return Err(WorkdayError::RegistrationDrift(
                "secret reference is revoked or outside the Workday scope".to_owned(),
            ));
        }
        let mut registration = Self {
            plugin_version: WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            provider_version: provider.provider_version.clone(),
            provider_digest: provider.provider_digest(),
            capability_digest: provider.capability_digest.clone(),
            tenant_id: scope.tenant_id().clone(),
            tenant_revision: scope.tenant_revision(),
            scope_digest: scope.scope_digest().clone(),
            consent_digest: scope.consent().consent_digest().clone(),
            consent_revision: scope.consent().consent_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("uncomputed"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "workday-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.provider_digest.as_str().to_owned(),
                self.capability_digest.as_str().to_owned(),
                self.tenant_id.as_str().to_owned(),
                self.tenant_revision.get().to_string(),
                self.scope_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.consent_revision.get().to_string(),
                self.secret_reference_digest.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.mission_revision.get().to_string(),
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.work_product_id.as_str().to_owned(),
                self.work_product_revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn validate(
        &self,
        scope: &WorkdayScope,
        secret: &SecretReference,
        provider: &WorkdayProviderDefinition,
    ) -> Result<(), WorkdayError> {
        if self.state != RegistrationState::Active {
            return Err(WorkdayError::RegistrationRevoked);
        }
        if self.registration_digest != self.compute_digest() {
            return Err(WorkdayError::RegistrationDrift(
                "registration digest does not match its immutable fields".to_owned(),
            ));
        }
        if self.contract_digest != contract_digest()
            || self.contract_version != WORKDAY_BUSINESS_PROCESS_RESULT_CONTRACT_VERSION
            || self.plugin_version != WORKDAY_BUSINESS_PROCESS_RESULT_PLUGIN_VERSION_TEXT
        {
            return Err(WorkdayError::ContractDigestMismatch);
        }
        if self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_digest != provider.provider_digest()
            || self.capability_digest != provider.capability_digest
            || provider.native
            || provider.live_execution
        {
            return Err(WorkdayError::RegistrationDrift(
                "provider or capability definition drifted".to_owned(),
            ));
        }
        if self.scope_digest != *scope.scope_digest()
            || self.tenant_id != *scope.tenant_id()
            || self.tenant_revision != scope.tenant_revision()
            || self.consent_digest != *scope.consent().consent_digest()
            || self.consent_revision != scope.consent().consent_revision()
            || self.mission_id != *scope.mission_id()
            || self.mission_revision != scope.mission_revision()
            || self.project_id != *scope.project_id()
            || self.project_revision != scope.project_revision()
            || self.work_product_id != *scope.work_product_id()
            || self.work_product_revision != scope.work_product_revision()
        {
            return Err(WorkdayError::RegistrationDrift(
                "tenant, Mission, Project, consent, or scope fence drifted".to_owned(),
            ));
        }
        if self.secret_reference_digest != *secret.reference_digest()
            || secret.is_revoked()
            || secret.scope_digest() != scope.scope_digest()
        {
            return Err(WorkdayError::RegistrationDrift(
                "secret reference digest or scope drifted".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), WorkdayError> {
        if self.state == RegistrationState::Revoked {
            Err(WorkdayError::RegistrationRevoked)
        } else {
            self.state = RegistrationState::Revoked;
            self.registration_digest = self.compute_digest();
            Ok(())
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

#[derive(Debug)]
pub struct WorkdayProvider<T> {
    transport: T,
    definition: WorkdayProviderDefinition,
}

impl<T> WorkdayProvider<T>
where
    T: WorkdayTransport,
{
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let definition = WorkdayProviderDefinition::new(provider_version, provenance)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &WorkdayProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn register(
        &self,
        scope: &WorkdayScope,
        secret: &SecretReference,
    ) -> Result<WorkdayRegistration, WorkdayError> {
        WorkdayRegistration::new(scope, secret, &self.definition)
    }

    pub fn revoke_registration(
        &self,
        registration: &mut WorkdayRegistration,
    ) -> Result<(), WorkdayError> {
        registration.revoke()
    }

    pub fn read(
        &mut self,
        scope: &WorkdayScope,
        secret: &SecretReference,
        registration: &WorkdayRegistration,
        request: &WorkdayReadRequest,
    ) -> Result<WorkdayBusinessProcessResultEvidence, WorkdayError> {
        registration.validate(scope, secret, &self.definition)?;
        if request.scope_digest() != scope.scope_digest()
            || request.consent_digest() != scope.consent().consent_digest()
            || request.kind() != request.endpoint().read_kind()
        {
            return Err(WorkdayError::ScopeMismatch(
                "read request is outside the registration scope".to_owned(),
            ));
        }
        scope
            .accepts_request(request.kind(), request.bounds(), Utc::now())
            .map_err(WorkdayError::from)?;
        let http_request = WorkdayHttpRequest::from_read_request(request, secret);
        let response = match self.transport.read(&http_request) {
            Ok(response) => response,
            Err(error) if error.kind == ProviderErrorKind::AccessDenied => {
                return Ok(WorkdayBusinessProcessResultEvidence::access_lost(
                    scope,
                    &registration.registration_digest,
                    &self.definition.provider_digest(),
                    &self.definition.capability_digest,
                    self.receipt_for_error(&http_request, &error),
                ));
            }
            Err(error) if error.kind == ProviderErrorKind::BlockedEnv => {
                return Err(WorkdayError::BlockedEnv);
            }
            Err(error) => return Err(WorkdayError::Transport(error.to_string())),
        };
        self.project_response(scope, registration, request, &http_request, response)
    }

    fn project_response(
        &self,
        scope: &WorkdayScope,
        registration: &WorkdayRegistration,
        request: &WorkdayReadRequest,
        http_request: &WorkdayHttpRequest,
        response: WorkdayHttpResponse,
    ) -> Result<WorkdayBusinessProcessResultEvidence, WorkdayError> {
        if response.api_version.as_str() != WORKDAY_API_VERSION {
            return Err(WorkdayError::ApiVersionDrift {
                expected: WORKDAY_API_VERSION.to_owned(),
                actual: response.api_version.as_str().to_owned(),
            });
        }
        if response.response_size > request.bounds().max_response_bytes() {
            return Err(WorkdayError::ResponseTooLarge {
                size: response.response_size,
            });
        }
        if !(200..300).contains(&response.status_code) {
            if response.status_code == 403 {
                return Ok(WorkdayBusinessProcessResultEvidence::access_lost(
                    scope,
                    &registration.registration_digest,
                    &self.definition.provider_digest(),
                    &self.definition.capability_digest,
                    self.receipt_for_response(http_request, &response),
                ));
            }
            return Err(WorkdayError::UnexpectedStatus {
                status: response.status_code,
            });
        }
        let payload = response
            .body
            .as_ref()
            .ok_or_else(|| WorkdayError::Decode("successful response had no body".to_owned()))?;
        let receipt = self.receipt_for_response(http_request, &response);
        WorkdayBusinessProcessResultEvidence::from_payload(
            scope,
            &registration.registration_digest,
            &self.definition.provider_digest(),
            &self.definition.capability_digest,
            payload,
            receipt,
        )
        .map_err(WorkdayError::from)
    }

    fn receipt_for_response(
        &self,
        request: &WorkdayHttpRequest,
        response: &WorkdayHttpResponse,
    ) -> crate::model::WorkdayResponseReceipt {
        crate::model::WorkdayResponseReceipt {
            endpoint: request.endpoint,
            request_path_and_query: request.path_and_query.clone(),
            api_version: response.api_version.clone(),
            response_status: response.status_code,
            response_size: response.response_size,
            response_digest: response.response_digest.clone(),
            provider_revision: response.provider_revision.clone(),
            observed_at: response.observed_at,
            freshness_digest: Digest::from_fields(
                "workday-freshness/v1",
                &[
                    request.scope_digest.as_str().to_owned(),
                    response.observed_at.to_rfc3339(),
                    response.provider_revision.as_str().to_owned(),
                ],
            ),
            provenance: self.definition.provenance,
            raw_provider_payload: false,
            credential_material: false,
            native_receipt: false,
        }
    }

    fn receipt_for_error(
        &self,
        request: &WorkdayHttpRequest,
        error: &TransportError,
    ) -> crate::model::WorkdayResponseReceipt {
        let observed_at = Utc::now();
        let provider_revision = ProviderRevision::new(WORKDAY_PROVIDER_REVISION)
            .expect("checked-in provider revision is valid");
        crate::model::WorkdayResponseReceipt {
            endpoint: request.endpoint,
            request_path_and_query: request.path_and_query.clone(),
            api_version: request.api_version.clone(),
            response_status: error.status_code.unwrap_or(0),
            response_size: 0,
            response_digest: error.diagnostic_digest().clone(),
            provider_revision,
            observed_at,
            freshness_digest: Digest::from_fields(
                "workday-freshness/v1",
                &[
                    request.scope_digest.as_str().to_owned(),
                    observed_at.to_rfc3339(),
                    error.diagnostic_digest().as_str().to_owned(),
                ],
            ),
            provenance: self.definition.provenance,
            raw_provider_payload: false,
            credential_material: false,
            native_receipt: false,
        }
    }
}

impl<T> WorkdayProvider<T>
where
    T: WorkdayTransport,
{
    pub const fn native(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }
}
